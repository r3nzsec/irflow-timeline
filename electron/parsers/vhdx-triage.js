/**
 * parsers/vhdx-triage.js — open a KAPE `--vhdx` export (or any NTFS disk image in a VHDX)
 * as a triage collection.
 *
 * macOS cannot mount a VHDX, so instead of mounting we read the NTFS volume inside the
 * container directly (parsers/vhdx.js + parsers/ntfs-reader.js) and copy the files the
 * triage pipeline recognizes into a scratch folder that mirrors the collection's own
 * layout (`C\Windows\System32\winevt\logs\Security.evtx` → `<out>/C/Windows/…`). From
 * there "Open Triage Collection" proceeds exactly as it does for a folder: discovery,
 * host attribution, the Lateral Movement and Sigma lanes, `$MFT` / `$J` import.
 *
 * Only recognized artifacts are copied, not the whole image: a KAPE package is mostly
 * artifacts anyway, and a full-disk image would otherwise mean duplicating a system
 * drive onto the analyst's scratch volume. What was left behind is counted, and files the
 * reader cannot reproduce faithfully (NTFS-compressed, EFS-encrypted) are reported by
 * path rather than written as garbage.
 */

const fs = require("fs");
const path = require("path");
const { openVhdx } = require("./vhdx");
const { openFirstNtfsVolume } = require("./ntfs-reader");
const { classifyFile, EZ_CSV_RE } = require("./triage");

const HIVE_SIDECAR_KINDS = new Set([
  "registryHive", "userHive", "amcache", "srudb", "chromiumHistory", "chromiumAutofill", "webcache",
]);

// KAPE's own provenance logs (host attribution reads the console log; the copy log is
// the collection's inventory). They sit at the root of the package.
const KAPE_LOG_RE = /_(?:ConsoleLog\.txt|CopyLog\.csv|SkipLog\.csv(?:\.csv)?)$/i;

// Root folders that belong to the VHDX's own NTFS volume rather than the evidence.
const CONTAINER_ROOTS = new Set(["$extend", "system volume information"]);

const PROGRESS_INTERVAL_MS = 150;

/**
 * Decide whether a live file from the image belongs in the extracted collection.
 * Returns a kind string, or null to leave it in the image. Pure — testable without I/O.
 *
 * @param {{ segments: string[], path: string, isDir: boolean, entry: number }} file
 * @param {{ liveVolume: boolean }} ctx  liveVolume = the image is a real Windows volume
 *   (has \Windows at its root) rather than a KAPE package, so its own $MFT is evidence.
 */
function sidecarBaseName(base) {
  return String(base)
    .replace(/\.LOG\d*$/i, "")
    .replace(/-journal$/i, "")
    .replace(/-wal$/i, "")
    .replace(/-shm$/i, "")
    .replace(/\.jfm$/i, "")
    .replace(/\.jrs$/i, "");
}

function selectForTriage(file, ctx = { liveVolume: false }) {
  if (!file || file.isDir || !file.segments?.length) return null;
  const top = file.segments[0].toLowerCase();
  if (file.entry < 16) {
    // Reserved metafiles: only the volume's own $MFT, and only when the volume IS the
    // evidence. In a KAPE package the container's $MFT just indexes the package.
    return ctx.liveVolume && file.entry === 0 && file.segments.length === 1 ? "mft" : null;
  }
  if (CONTAINER_ROOTS.has(top)) return null;
  const base = file.segments[file.segments.length - 1];
  // KAPE packages live under drive-letter roots. Anything else at the VHDX volume
  // root (the examiner's $Recycle.Bin, System Volume Information, …) is the
  // destination disk, not the collected host.
  if (!ctx.liveVolume) {
    const isDrive = /^[a-z]$/i.test(file.segments[0]);
    const isKapeLog = file.segments.length === 1 && KAPE_LOG_RE.test(base);
    if (!isDrive && !isKapeLog && file.segments.length > 1) return null;
  }
  if (file.segments.length === 1 && KAPE_LOG_RE.test(base)) return "kapeLog";
  if (/\.csv$/i.test(base) && EZ_CSV_RE.test(base)) return "kapeCsv"; // header check happens after extraction
  // Classify the POSIX form: that is the path discovery will see once the file is on disk,
  // and the classifier's exact-basename rules ($MFT, hives, Amcache) split on the host
  // separator — a backslash path would never match them.
  const posix = file.segments.join("/");
  const kind = classifyFile(posix);
  if (kind) return kind;
  const stripped = sidecarBaseName(base);
  if (stripped && stripped !== base) {
    const parentKind = classifyFile([...file.segments.slice(0, -1), stripped].join("/"));
    if (HIVE_SIDECAR_KINDS.has(parentKind)) return parentKind;
  }
  return null;
}

/** Make an NTFS name safe as a single path segment on the host filesystem. */
function sanitizeSegment(seg) {
  let s = String(seg).replace(/[\x00-\x1f/]/g, "_");
  if (s === "." || s === ".." || s === "") s = `_${s}_`;
  return s;
}

function _human(bytes) {
  const b = Number(bytes) || 0;
  if (b >= 1073741824) return `${(b / 1073741824).toFixed(1)} GB`;
  if (b >= 1048576) return `${(b / 1048576).toFixed(1)} MB`;
  if (b >= 1024) return `${Math.round(b / 1024)} KB`;
  return `${b} B`;
}

function _freeBytes(dir) {
  try {
    const st = fs.statfsSync(dir);
    return Number(st.bavail) * Number(st.bsize);
  } catch {
    return -1; // unknown — do not block
  }
}

/**
 * Build the extraction plan for an opened volume: which files, how many bytes, what the
 * image looks like. Separated from the copy loop so the numbers can be reported (and
 * tested) before any bytes are written.
 */
function planExtraction(files) {
  const roots = new Set(files.filter((f) => f.segments.length === 1).map((f) => f.segments[0].toLowerCase()));
  const liveVolume = roots.has("windows") && !roots.has("c");
  const selected = [];
  const byKind = {};
  let bytes = 0;
  let liveFiles = 0;
  let dirs = 0;
  for (const f of files) {
    if (f.isDir) { dirs++; continue; }
    if (f.entry >= 16) liveFiles++;
    const kind = selectForTriage(f, { liveVolume });
    if (!kind) continue;
    selected.push({ file: f, kind });
    byKind[kind] = (byKind[kind] || 0) + 1;
    bytes += f.size;
  }
  return { selected, byKind, bytes, liveFiles, dirs, liveVolume, layout: liveVolume ? "volume" : "kape" };
}

/**
 * Extract the recognizable artifacts from a VHDX into `outDir`.
 *
 * @param {string} vhdxPath
 * @param {string} outDir  existing, empty directory owned by the caller
 * @param {{ onProgress?: (p: object) => void, isCancelled?: () => void, minFreeBytes?: number }} [opts]
 *   `isCancelled` should THROW to abort (the worker throws an error with `.cancelled`).
 */
async function extractVhdxCollection(vhdxPath, outDir, opts = {}) {
  const started = Date.now();
  const onProgress = typeof opts.onProgress === "function" ? opts.onProgress : () => {};
  const isCancelled = typeof opts.isCancelled === "function" ? opts.isCancelled : () => {};
  let lastEmit = 0;
  let lastPhase = "";
  // Throttled, except that a phase change always goes out — the UI keys its copy on it.
  const emit = (p, force = false) => {
    const now = Date.now();
    if (!force && p.phase === lastPhase && now - lastEmit < PROGRESS_INTERVAL_MS) return;
    lastEmit = now;
    lastPhase = p.phase;
    onProgress(p);
  };

  const disk = openVhdx(vhdxPath);
  try {
    emit({ phase: "opening", percent: 0, statusDetail: "Reading VHDX metadata" }, true);
    const { volume, volumes, chosen } = openFirstNtfsVolume(disk);
    const warnings = [...disk.warnings];
    const chosenVol = chosen || volumes[0];
    if (volumes.length > 1) {
      warnings.push(`The image has ${volumes.length} NTFS volumes; the largest (${_human(chosenVol.size)}) was read.`);
    }

    // ── Enumerate ────────────────────────────────────────────────────────────────
    const { files, orphans, records } = volume.listFiles({
      includeReserved: true,
      isCancelled,
      onProgress: (done, total) => emit({
        phase: "scanning",
        percent: total ? Math.round((done / total) * 100) : 0,
        recordsDone: done,
        recordsTotal: total,
        statusDetail: `Reading NTFS index · ${done.toLocaleString()} / ${total.toLocaleString()} records`,
      }),
    });
    if (orphans) warnings.push(`${orphans.toLocaleString()} file record${orphans === 1 ? "" : "s"} could not be placed in the folder tree and were skipped.`);

    const plan = planExtraction(files);
    if (!plan.selected.length) {
      return {
        outDir,
        empty: true,
        vhdx: _vhdxSummary(disk, vhdxPath),
        volume: _volumeSummary(volume, chosenVol, records, plan),
        extracted: { count: 0, bytes: 0, byKind: {} },
        skipped: { compressed: 0, encrypted: 0, failed: [] },
        notSelected: plan.liveFiles,
        warnings,
        elapsedMs: Date.now() - started,
      };
    }

    // ── Space check before the first write ───────────────────────────────────────
    const free = _freeBytes(outDir);
    const minFree = Number.isFinite(opts.minFreeBytes) ? opts.minFreeBytes : 256 * 1048576;
    if (free >= 0 && free < plan.bytes + minFree) {
      throw Object.assign(
        new Error(`Not enough free space to extract this collection: ${_human(plan.bytes)} needed, ${_human(free)} available at ${outDir}. Choose a larger scratch volume with File → Set Temp Storage Folder….`),
        { code: "VHDX_NO_SPACE" },
      );
    }

    // ── Copy ─────────────────────────────────────────────────────────────────────
    const written = new Set();
    const failed = [];
    let compressed = 0, encrypted = 0, failedCount = 0, count = 0, bytes = 0;
    const totalFiles = plan.selected.length;
    const pushFailure = (file, reason) => {
      failedCount++;
      if (failed.length < 200) failed.push({ path: file.path, size: file.size, reason });
    };

    for (let i = 0; i < totalFiles; i++) {
      isCancelled();
      const { file } = plan.selected[i];
      emit({
        phase: "extracting",
        percent: plan.bytes ? Math.min(99, Math.round((bytes / plan.bytes) * 100)) : 0,
        filesDone: i,
        filesTotal: totalFiles,
        bytesDone: bytes,
        bytesTotal: plan.bytes,
        current: file.path,
        statusDetail: `${i.toLocaleString()} / ${totalFiles.toLocaleString()} files · ${_human(bytes)} of ${_human(plan.bytes)}`,
      });
      if (file.compressed) { compressed++; pushFailure(file, "NTFS-compressed stream (not supported)"); continue; }
      if (file.encrypted) { encrypted++; pushFailure(file, "EFS-encrypted stream (not supported)"); continue; }
      if (!file.data) { pushFailure(file, "no primary data stream"); continue; }

      const segs = file.segments.map(sanitizeSegment);
      let rel = segs.join(path.sep);
      let key = rel.toLowerCase();
      if (written.has(key)) {
        const ext = path.extname(rel);
        const stem = ext ? rel.slice(0, -ext.length) : rel;
        rel = `${stem}~${file.entry}${ext}`;
        key = rel.toLowerCase();
      }
      written.add(key);
      const target = path.join(outDir, rel);
      let fd = null;
      try {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fd = fs.openSync(target, "w");
        volume.readFile(file, (chunk) => {
          let off = 0;
          while (off < chunk.length) {
            isCancelled();
            off += fs.writeSync(fd, chunk, off, chunk.length - off);
          }
          bytes += chunk.length;
        }, { isCancelled });
        fs.closeSync(fd); fd = null;
        count++;
      } catch (e) {
        if (fd != null) { try { fs.closeSync(fd); } catch { /* ignore */ } }
        if (e?.cancelled) throw e;
        try { fs.unlinkSync(target); } catch { /* ignore */ }
        pushFailure(file, e?.message || "read failed");
      }
    }

    if (disk.shortReads > 0) warnings.push(`${disk.shortReads} block read${disk.shortReads === 1 ? "" : "s"} came up short — the VHDX file appears truncated; affected data reads as zeros.`);
    if (compressed) warnings.push(`${compressed} NTFS-compressed file${compressed === 1 ? " was" : "s were"} skipped (decompression is not supported).`);
    if (encrypted) warnings.push(`${encrypted} EFS-encrypted file${encrypted === 1 ? " was" : "s were"} skipped.`);
    const otherFailures = failedCount - compressed - encrypted;
    if (otherFailures > 0) warnings.push(`${otherFailures} file${otherFailures === 1 ? "" : "s"} could not be read from the image.`);

    emit({ phase: "finalizing", percent: 100, filesDone: count, filesTotal: totalFiles, bytesDone: bytes, bytesTotal: plan.bytes, statusDetail: "Finishing" }, true);

    return {
      outDir,
      empty: false,
      vhdx: _vhdxSummary(disk, vhdxPath),
      volume: _volumeSummary(volume, chosenVol, records, plan),
      extracted: { count, bytes, byKind: plan.byKind },
      skipped: { compressed, encrypted, failed },
      notSelected: Math.max(0, plan.liveFiles - totalFiles),
      warnings,
      elapsedMs: Date.now() - started,
    };
  } finally {
    disk.close();
  }
}

function _vhdxSummary(disk, vhdxPath) {
  return {
    path: vhdxPath,
    name: path.basename(vhdxPath),
    fileSize: disk.fileSize,
    virtualSize: disk.virtualSize,
    allocatedBytes: disk.allocatedBytes,
    blockSize: disk.blockSize,
    creator: disk.creator,
    isFixed: disk.isFixed,
  };
}

function _volumeSummary(volume, vol, records, plan) {
  return {
    scheme: vol.scheme,
    offset: vol.offset,
    size: vol.size,
    clusterSize: volume.clusterSize,
    serial: volume.serial,
    records,
    files: plan.liveFiles,
    dirs: plan.dirs,
    layout: plan.layout,
  };
}

module.exports = { extractVhdxCollection, selectForTriage, planExtraction, sanitizeSegment, KAPE_LOG_RE };
