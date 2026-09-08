/**
 * triage-collection — turn a folder the analyst picked into a reviewable manifest.
 *
 * Discovery is `parsers/triage.js` (ported from the super-timeline tree); this module
 * adds the lateral-movement view on top: which lane each artifact belongs to, what is
 * pre-selected, what is present but has no parser on this branch, and who the collection
 * belongs to.
 *
 * Two lanes, deliberately independent (an analyst may want either, both, or neither):
 *
 *   lateralMovement — imports the LM-relevant EVTX channels as timeline tabs using the
 *                     app's own EVTX parser, then hands off to the Lateral Movement
 *                     Tracker. Pre-checked.
 *   evtxSigma       — hands the whole winevt directory to the existing Hayabusa/Sigma
 *                     flow. Heavy, opt-in, unchanged behaviour.
 */

const fs = require("fs");
const path = require("path");
const {
  scanTriageDir, detectModuleOutput, KIND_LABELS,
  lmEvtxRelevance, isLikelyEmptyEvtx,
} = require("../../parsers/triage");
const { attributeHost } = require("./host-attribution");

// Artifact kinds this branch can actually turn into a timeline tab.
const INGESTIBLE_KINDS = new Set(["evtx", "mft", "usn", "kapeCsv", "plaso"]);

// Present-but-unparseable kinds, with the tool that would produce something importable.
// Surfaced as information rather than silently dropped — "we saw 290 prefetch files and
// did nothing" is a worse answer than "run PECmd and import the CSV".
const NO_PARSER_HINTS = {
  prefetch: "PECmd",
  amcache: "AmcacheParser",
  srudb: "SrumECmd",
  registryHive: "RECmd (Kroll batch)",
  userHive: "RECmd / SBECmd",
  lnk: "LECmd",
  jumplist: "JLECmd",
  scheduledTask: "(task XML — not yet parsed)",
  rdp: "Tools → RDP Bitmap Cache",
  recyclebin: "RBCmd",
  logFile: "(NTFS $LogFile — not yet parsed)",
};

const _human = (bytes) => {
  const b = Number(bytes) || 0;
  if (b >= 1073741824) return `${(b / 1073741824).toFixed(1)} GB`;
  if (b >= 1048576) return `${(b / 1048576).toFixed(1)} MB`;
  if (b >= 1024) return `${Math.round(b / 1024)} KB`;
  return `${b} B`;
};

/** "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" -> "TS-LocalSessionManager/Operational" */
function evtxDisplayName(filePath) {
  let base = path.basename(filePath).replace(/\.evtx$/i, "");
  // KAPE keeps the channel's URL-escaped slash. decodeURIComponent() throws on "%4O",
  // so replace the token directly.
  base = base.replace(/%4/g, "/");
  base = base.replace(/^Microsoft-Windows-/i, "");
  base = base.replace(/^TerminalServices-/i, "TS-");
  base = base.replace(/^RemoteDesktopServices-/i, "RDS-");
  return base;
}

/**
 * Does this folder look like a KAPE/triage collection at all?
 * Cheapest signals first; used to give a useful error instead of an empty manifest.
 */
function looksLikeTriage(dir, scan) {
  if (scan.total > 0) return true;
  try {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isFile() && /_(ConsoleLog\.txt|CopyLog\.csv)$/i.test(e.name)) return true;
      if (e.isDirectory() && /^[A-Za-z]$/.test(e.name)) return true;
    }
  } catch { /* ignore */ }
  return false;
}

/** Record .zip / .vhdx siblings so the UI can say they were seen and deliberately not opened. */
function findZips(dir) {
  const out = [];
  try {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isFile() && /\.zip$/i.test(e.name)) {
        let size = 0;
        try { size = fs.statSync(path.join(dir, e.name)).size; } catch { /* ignore */ }
        out.push({ name: e.name, size, sizeLabel: _human(size) });
      }
    }
  } catch { /* ignore */ }
  return out;
}

function findVhdx(dir) {
  const out = [];
  try {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isFile() && /\.vhdx$/i.test(e.name)) {
        let size = 0;
        try { size = fs.statSync(path.join(dir, e.name)).size; } catch { /* ignore */ }
        out.push({ name: e.name, path: path.join(dir, e.name), size, sizeLabel: _human(size) });
      }
    }
  } catch { /* ignore */ }
  return out;
}

/**
 * Build the manifest for a triage folder.
 *
 * @param {string} root
 * @param {{onProgress?: function, scanOpts?: object}} [opts]
 */
async function discoverTriageCollection(root, opts = {}) {
  const started = Date.now();
  const warnings = [];

  const scan = scanTriageDir(root, {
    maxPathsPerKind: 4096,
    onProgress: opts.onProgress,
    isCancelled: opts.isCancelled,
    ...(opts.scanOpts || {}),
  });
  if (scan.truncated) warnings.push(`Scan stopped after ${scan.scanned.toLocaleString()} files; the manifest may be incomplete.`);
  if (scan.pathsTruncated) warnings.push("Some artifact kinds had more files than the per-kind cap; high-value logs were kept first.");

  if (!looksLikeTriage(root, scan)) {
    const probe = detectModuleOutput(root);
    if (probe.isModuleOutput) {
      return {
        rootPath: root,
        error: `This looks like KAPE Module output — ${probe.csvSeen} already-parsed EZ-Tools CSV${probe.csvSeen === 1 ? "" : "s"} (e.g. ${probe.sampleName}). Point the scan at the matching Targets folder for raw artifacts, or import the CSVs directly.`,
        isModuleOutput: true,
        csvKinds: probe.kinds,
      };
    }
    return { rootPath: root, error: "No recognizable Windows forensic artifacts were found in this folder." };
  }

  const host = await attributeHost(root, scan, opts);
  const moduleProbe = detectModuleOutput(root, { maxDepth: 6 });

  // ── Lateral Movement lane ────────────────────────────────────────────────────
  // Covers BOTH shapes of triage package: raw .evtx channels, and the EvtxECmd CSV that
  // a KAPE Modules run produces. A parsed-only collection has no .evtx at all, so
  // without the CSV arm this lane would come back empty on exactly the input the
  // "parsed KAPE triage" workflow is about.
  const evtxFiles = scan.files?.evtx || [];
  const lmItems = evtxFiles
    .map((f) => {
      const tier = lmEvtxRelevance(f.path);
      const empty = isLikelyEmptyEvtx(f.size);
      return {
        id: f.path,
        path: f.path,
        source: "raw-evtx",
        name: evtxDisplayName(f.path),
        fileName: path.basename(f.path),
        size: f.size,
        sizeLabel: _human(f.size),
        lmTier: tier,
        empty,
        // An empty stub contributes nothing and would just create a dead tab.
        defaultChecked: tier > 0 && !empty,
        note: empty ? "empty log (header only)" : (tier === 0 ? "not a lateral-movement channel" : ""),
      };
    });

  // Parsed arm: EvtxECmd output is every channel already merged into one CSV, so it is
  // graded tier 3 on its own.
  const { classifyKapeCsv } = require("../../parsers/triage");
  const evtxEcmdCsvs = (scan.files?.kapeCsv || []).filter((f) => {
    try { return classifyKapeCsv(f.path) === "evtxEcmd"; } catch { return false; }
  });
  const hasPopulatedRawSecurity = lmItems.some((x) => x.lmTier === 3 && !x.empty && /^security$/i.test(x.name));
  for (const f of evtxEcmdCsvs) {
    lmItems.push({
      id: f.path,
      path: f.path,
      source: "evtxecmd-csv",
      name: `EvtxECmd output (${path.basename(f.path)})`,
      fileName: path.basename(f.path),
      size: f.size,
      sizeLabel: _human(f.size),
      lmTier: 3,
      empty: false,
      // Importing both lanes for the same host double-counts the same events. Prefer the
      // raw channels when they carry data; otherwise this CSV is the only source.
      defaultChecked: !hasPopulatedRawSecurity,
      note: hasPopulatedRawSecurity
        ? "raw EVTX selected — importing both would duplicate the same events"
        : "parsed EVTX (all channels in one file)",
    });
  }

  lmItems.sort((a, b) => (b.lmTier - a.lmTier) || (b.size - a.size));

  const lmChecked = lmItems.filter((x) => x.defaultChecked);
  if (lmItems.length > 0 && lmChecked.length === 0) {
    warnings.push("Every lateral-movement channel in this collection is an empty stub — there is nothing to analyse from EVTX here.");
  }

  // ── Everything else, split into importable vs informational ──────────────────
  const artifacts = [];
  const info = [];
  for (const kind of Object.keys(scan.counts)) {
    if (kind === "evtx") continue; // owned by the lanes above
    const count = scan.counts[kind];
    const bytes = scan.bytes[kind] || 0;
    const entry = {
      kind,
      label: KIND_LABELS[kind] || kind,
      count,
      bytes,
      sizeLabel: _human(bytes),
      paths: scan.paths[kind] || [],
    };
    if (INGESTIBLE_KINDS.has(kind)) {
      // $MFT and $J are genuinely useful but heavy, so they are offered unchecked.
      artifacts.push({ ...entry, ingestible: true, heavy: kind === "mft" || kind === "usn", defaultChecked: false });
    } else {
      info.push({ ...entry, ingestible: false, hint: NO_PARSER_HINTS[kind] || "" });
    }
  }
  artifacts.sort((a, b) => b.bytes - a.bytes);
  info.sort((a, b) => b.count - a.count);

  const rawSignal = (scan.counts.evtx || 0) + (scan.counts.mft || 0) + (scan.counts.registryHive || 0);
  const kind = rawSignal > 0 && moduleProbe.isModuleOutput ? "both"
    : rawSignal > 0 ? "raw"
      : moduleProbe.isModuleOutput ? "parsed" : "unknown";

  const zips = findZips(root);
  if (zips.length) {
    warnings.push(zips.length === 1
      ? `The archive ${zips[0].name} was not opened.`
      : `${zips.length} .zip archives in this folder were not opened.`);
  }
  const vhdxFound = findVhdx(root);
  if (vhdxFound.length) {
    warnings.push(vhdxFound.length === 1
      ? `This folder also contains ${vhdxFound[0].name} (${vhdxFound[0].sizeLabel}). If the collection looks empty, open that VHDX instead.`
      : `This folder also contains ${vhdxFound.length} .vhdx images. If the collection looks empty, open one of those instead.`);
  }

  return {
    rootPath: root,
    rootLabel: path.basename(root),
    kind,
    host,
    kape: host.kape || null,
    lanes: {
      lateralMovement: {
        id: "lateralMovement",
        label: "Lateral Movement",
        items: lmItems,
        defaultCheckedCount: lmChecked.length,
        totalEvtx: evtxFiles.length,
      },
      evtxSigma: {
        id: "evtxSigma",
        label: "EVTX logs → Sigma scan",
        count: evtxFiles.length,
        dir: evtxFiles.length ? path.dirname(evtxFiles[0].path) : "",
        heavy: true,
        defaultChecked: false,
      },
    },
    artifacts,
    info,
    ignored: { zips, vhdx: vhdxFound },
    warnings,
    stats: {
      scanned: scan.scanned,
      classified: scan.total,
      elapsedMs: Date.now() - started,
      truncated: !!scan.truncated,
    },
  };
}

module.exports = { discoverTriageCollection, evtxDisplayName, INGESTIBLE_KINDS, NO_PARSER_HINTS };
