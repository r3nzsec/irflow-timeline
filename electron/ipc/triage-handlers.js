/**
 * ipc/triage-handlers.js — "Open Triage Collection".
 *
 * The analyst picks a KAPE/triage folder — or a KAPE `--vhdx` image, whose artifacts are
 * first copied out of the embedded NTFS volume into a scratch folder — reviews a manifest
 * of what is inside, and imports the artifacts they want as timeline tabs. The Lateral
 * Movement lane then hands off to the Lateral Movement Tracker.
 *
 * Security model (mirrors ipc/sigma-handlers.js): nothing on disk is readable unless the
 * user selected it. The folder dialog is the ONLY place a `triage-root` grant is issued,
 * and every path that comes back from the renderer afterwards is re-checked against that
 * grant. Because PathAuthorizer canonicalises through `fs.realpathSync.native`, a symlink
 * inside the collection that points outside it resolves outside and is rejected.
 */

const fs = require("fs");
const path = require("path");
const electron = require("electron");
const { PathAuthorizer } = require("../utils/path-authorizer");
const { dbg } = require("../logger");
const { discoverTriageCollection } = require("../analyzers/triage-collection");
const { isVhdxFile } = require("../parsers/vhdx");

const { dialog } = electron;

const TRIAGE_SCOPE = "triage-root";
// The scope sigma-handlers checks before it will scan a directory.
const SCAN_SCOPE = "scan-target";
// A VHDX image the user picked. Extraction reads it; nothing else does.
const VHDX_SCOPE = "triage-vhdx";
const VHDX_PROGRESS_CHANNEL = "triage-vhdx-progress";
const DISCOVER_PROGRESS_CHANNEL = "triage-discover-progress";

module.exports = function registerTriageHandlers(safeHandle, safeSend, ctx) {
  const { _activeWindow, enqueueImport, nextTabId } = ctx;
  // Shared with the other IPC modules (see main.js) so a path validated in one scope
  // can be granted in another; scope names keep them isolated otherwise.
  const pathAuthorizer = ctx.pathAuthorizer || new PathAuthorizer();

  // Scratch folders holding artifacts copied out of a VHDX. They are derived data (the
  // image is the evidence), so they are removed when the app quits.
  const extractedDirs = new Set();
  const vhdxJobs = new Set();
  const discoverJobs = new Set();
  const removeExtractedDir = (dir) => {
    extractedDirs.delete(dir);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { dbg("TRIAGE", "vhdx scratch cleanup failed", { dir, error: e?.message }); }
  };
  try {
    electron.app?.once?.("will-quit", () => { for (const d of [...extractedDirs]) removeExtractedDir(d); });
  } catch { /* tests stub electron without `app` */ }

  /**
   * Grant recursive read access to a folder the user just chose in a dialog.
   * Returns the CANONICAL path — authorize() hands back an entry object, and the
   * renderer needs the realpath'd string to pass back to discover/import.
   */
  function authorizeTriageRoot(dirPath) {
    const entry = pathAuthorizer.authorize(TRIAGE_SCOPE, dirPath, {
      recursive: true,
      label: "Selected triage collection",
    });
    return entry?.path || dirPath;
  }

  /** Throw unless `p` resolves inside a granted root. Returns the canonical path. */
  function assertInsideTriageRoot(p) {
    return pathAuthorizer.assertAuthorized([TRIAGE_SCOPE], p);
  }

  // ── Pick a folder or a VHDX image ───────────────────────────────────────────
  // macOS lets one dialog offer both. A folder is scanned in place; a `.vhdx` (KAPE's
  // `--vhdx` export) is granted under its own scope and handed to "triage-open-vhdx",
  // which copies the artifacts out of the image into a scratch folder that then becomes
  // the triage root.
  safeHandle("triage-select-root", async () => {
    const res = await dialog.showOpenDialog(_activeWindow(), {
      title: "Select a triage / KAPE collection folder or VHDX image",
      properties: ["openDirectory", "openFile"],
      filters: [{ name: "Triage folder or VHDX image", extensions: ["vhdx"] }],
      buttonLabel: "Scan",
    });
    if (res.canceled || !res.filePaths?.[0]) return { canceled: true };
    const picked = res.filePaths[0];
    let stat = null;
    try { stat = fs.statSync(picked); } catch { return { error: "That path could not be read." }; }
    if (stat.isFile()) {
      if (path.extname(picked).toLowerCase() !== ".vhdx" && !isVhdxFile(picked)) {
        return { error: "Select a triage collection folder, or a .vhdx image exported by KAPE." };
      }
      const entry = pathAuthorizer.authorize(VHDX_SCOPE, picked, { recursive: false, label: "Selected VHDX image" });
      const canonical = entry?.path || picked;
      dbg("TRIAGE", "vhdx selected", { file: canonical, size: stat.size });
      return { vhdx: canonical, size: stat.size };
    }
    const canonical = authorizeTriageRoot(picked);
    dbg("TRIAGE", "root selected", { dir: canonical });
    return { dir: canonical };
  });

  // ── Open a VHDX: extract its artifacts into a scratch folder ────────────────
  //
  // Resolves when extraction finishes (the modal awaits it); progress streams on
  // `triage-vhdx-progress` and carries the jobId so the renderer can cancel. On success
  // the scratch folder is granted as a triage root, so `triage-discover` / `triage-import`
  // work on it unchanged.
  safeHandle("triage-open-vhdx", async (event, { file } = {}) => {
    if (!file) return { error: "No VHDX specified." };
    let vhdxPath;
    try {
      vhdxPath = pathAuthorizer.assertAuthorized([VHDX_SCOPE], file);
    } catch (e) {
      return { error: e.message || "That image has not been authorized. Select it in the app first." };
    }
    if (!ctx.jobManager?.startWorkerJob) return { error: "Background jobs are not available in this window." };

    const { resolveTempDir } = require("../utils/temp-dir");
    let outDir;
    try {
      outDir = fs.mkdtempSync(path.join(resolveTempDir(), "tle_vhdx_"));
    } catch (e) {
      return { error: `Could not create a scratch folder for the extracted collection: ${e?.message || e}` };
    }
    extractedDirs.add(outDir);

    const { jobId, promise } = ctx.jobManager.startWorkerJob({
      type: "vhdx-extract",
      worker: "vhdx-extract-worker.js",
      workerData: { vhdxPath, outDir },
      channels: { progress: VHDX_PROGRESS_CHANNEL },
      metadata: { vhdxPath, outDir },
      resourceClass: "heavy",
    });
    vhdxJobs.add(jobId);
    // Let the renderer cancel before the worker's first progress tick.
    safeSend(VHDX_PROGRESS_CHANNEL, { jobId, phase: "starting", percent: 0, statusDetail: "Opening image" });
    dbg("TRIAGE", "vhdx extraction started", { jobId, vhdxPath, outDir });

    let result;
    try {
      result = await promise;
    } catch (e) {
      vhdxJobs.delete(jobId);
      removeExtractedDir(outDir);
      const cancelled = /cancel/i.test(e?.message || "");
      dbg("TRIAGE", "vhdx extraction ended", { jobId, cancelled, error: e?.message });
      return cancelled ? { cancelled: true } : { error: e?.message || "VHDX extraction failed." };
    }
    vhdxJobs.delete(jobId);
    if (!result || result.error) {
      removeExtractedDir(outDir);
      return { error: result?.error || "VHDX extraction failed." };
    }
    if (result.empty) {
      removeExtractedDir(outDir);
      return { error: "No recognizable Windows forensic artifacts were found in the NTFS volume inside this image." };
    }
    pathAuthorizer.authorize(TRIAGE_SCOPE, outDir, { recursive: true, label: "Artifacts extracted from a VHDX", appManaged: true });
    dbg("TRIAGE", "vhdx extraction complete", { jobId, files: result.extracted?.count, bytes: result.extracted?.bytes, ms: result.elapsedMs });
    return { dir: outDir, jobId, ...result };
  });

  safeHandle("triage-cancel-vhdx", async (event, { jobId } = {}) => {
    if (!jobId || !vhdxJobs.has(jobId)) return { ok: false, error: "No such extraction." };
    const r = ctx.jobManager?.cancel?.(jobId) || { ok: false };
    dbg("TRIAGE", "vhdx extraction cancel requested", { jobId, ok: r.ok });
    return r;
  });

  // ── Build the manifest ──────────────────────────────────────────────────────
  // Discovery walks the collection on a worker so a multi-hundred-thousand-file
  // tree does not freeze IPC (import progress, grid paging) on the main thread.
  // Tests and degraded windows without a job manager still run in-process.
  safeHandle("triage-discover", async (event, { dir } = {}) => {
    if (!dir) return { error: "No folder specified." };
    let root;
    try {
      root = assertInsideTriageRoot(dir);
    } catch (e) {
      return { error: e.message || "That folder has not been authorized. Select it in the app first." };
    }
    if (!ctx.jobManager?.startWorkerJob) {
      const manifest = await discoverTriageCollection(root);
      dbg("TRIAGE", "discover", {
        dir: root,
        kind: manifest.kind,
        classified: manifest.stats?.classified,
        ms: manifest.stats?.elapsedMs,
        error: manifest.error || null,
      });
      return manifest;
    }

    const { jobId, promise } = ctx.jobManager.startWorkerJob({
      type: "triage-discover",
      worker: "triage-discover-worker.js",
      workerData: { root },
      channels: { progress: DISCOVER_PROGRESS_CHANNEL },
      metadata: { root },
      resourceClass: "light",
    });
    discoverJobs.add(jobId);
    safeSend(DISCOVER_PROGRESS_CHANNEL, { jobId, phase: "starting", percent: 0, statusDetail: "Scanning collection" });
    dbg("TRIAGE", "discover started", { jobId, dir: root });
    let result;
    try {
      result = await promise;
    } catch (e) {
      discoverJobs.delete(jobId);
      const cancelled = /cancel/i.test(e?.message || "");
      dbg("TRIAGE", "discover ended", { jobId, cancelled, error: e?.message });
      return cancelled ? { cancelled: true } : { error: e?.message || "Triage discovery failed." };
    }
    discoverJobs.delete(jobId);
    if (!result || result.error) return { error: result?.error || "Triage discovery failed." };
    dbg("TRIAGE", "discover", {
      dir: root,
      kind: result.kind,
      classified: result.stats?.classified,
      ms: result.stats?.elapsedMs,
      error: result.error || null,
    });
    return result;
  });

  safeHandle("triage-cancel-discover", async (event, { jobId } = {}) => {
    if (!jobId || !discoverJobs.has(jobId)) return { ok: false, error: "No such discovery." };
    const r = ctx.jobManager?.cancel?.(jobId) || { ok: false };
    dbg("TRIAGE", "discover cancel requested", { jobId, ok: r.ok });
    return r;
  });

  // ── Import the selected artifacts ───────────────────────────────────────────
  //
  // Returns immediately with the tab ids it reserved. Progress and completion ride the
  // existing import-start / import-progress / import-complete / import-error channels,
  // so the renderer's normal import UI covers this with no new plumbing; the batchId
  // lets the caller tell which completions belong to this collection.
  safeHandle("triage-import", async (event, { dir, paths, analyzeAfter = false, hostLabel = "", sigmaEvtxDir = "" } = {}) => {
    if (!dir) return { error: "No folder specified." };
    if (!Array.isArray(paths) || paths.length === 0) return { error: "Nothing selected to import." };

    try {
      assertInsideTriageRoot(dir);
    } catch (e) {
      return { error: e.message || "That folder has not been authorized." };
    }

    const batchId = `triage_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    const items = [];
    const rejected = [];

    for (const p of paths) {
      let canonical;
      try {
        // Re-check EVERY path: the renderer supplied these, and only the canonicalised
        // result is ever handed to the import queue.
        canonical = assertInsideTriageRoot(p);
      } catch {
        rejected.push(p);
        continue;
      }
      let stat = null;
      try { stat = fs.statSync(canonical); } catch { /* ignore */ }
      if (!stat?.isFile?.()) { rejected.push(p); continue; }

      const tabId = nextTabId();
      // A readable tab name matters: these land in the Lateral Movement multi-source
      // picker, where "Security" and "TS-LocalSessionManager/Operational" are far more
      // useful than two identically-truncated file names.
      const displayName = buildTabName(hostLabel, canonical);
      const queued = enqueueImport(canonical, { tabId, skipRecent: true, displayName, batchId });
      if (!queued) { rejected.push(canonical); continue; }
      items.push({ tabId, path: canonical, displayName });
    }

    if (items.length === 0) {
      return {
        error: rejected.length
          ? "None of the selected artifacts could be queued (already importing, or not a file)."
          : "Nothing selected to import.",
        items: [],
        rejectedCount: rejected.length,
      };
    }

    if (rejected.length) {
      dbg("TRIAGE", "import rejected paths outside the authorized root", { count: rejected.length });
    }
    dbg("TRIAGE", "import queued", { batchId, count: items.length, analyzeAfter });

    // Sigma lane: hand the winevt directory to the existing Hayabusa flow. The dialog is
    // the usual source of a `scan-target` grant; here the user already selected an
    // ancestor of this directory, so granting it is legitimate — but only AFTER proving
    // it resolves inside that selection. Pre-computing the file summary means the Sigma
    // wizard opens ready to scan instead of asking the analyst to find the folder again.
    let sigma = null;
    if (sigmaEvtxDir) {
      try {
        const canonicalDir = assertInsideTriageRoot(sigmaEvtxDir);
        const st = fs.statSync(canonicalDir);
        if (!st.isDirectory()) throw new Error("not a directory");
        const { findEvtxFiles } = require("../analyzers/sigma/evtx-scanner");
        pathAuthorizer.authorize(SCAN_SCOPE, canonicalDir, {
          recursive: true,
          label: "EVTX directory from a triage collection",
        });
        const files = findEvtxFiles(canonicalDir);
        sigma = {
          dirPath: canonicalDir,
          fileCount: files.length,
          totalBytes: files.reduce((n, f) => n + (f.size || 0), 0),
          files: files.map((f) => ({ name: f.name, size: f.size })),
        };
        dbg("TRIAGE", "sigma lane prepared", { dir: canonicalDir, fileCount: files.length });
      } catch (e) {
        dbg("TRIAGE", "sigma lane rejected", { error: e?.message });
        sigma = null;
      }
    }

    return {
      batchId,
      items,
      rejectedCount: rejected.length,
      analyzeAfter: !!analyzeAfter,
      sigmaEvtxDir: sigma,
    };
  });

  // ── Cancel a queued batch ───────────────────────────────────────────────────
  // A collection can queue several multi-GB imports; without this the analyst has to
  // wait out a mis-click. Drops everything still queued and cancels whatever is running.
  safeHandle("triage-cancel-batch", async (event, { batchId, tabIds = [] } = {}) => {
    if (!batchId && tabIds.length === 0) return { error: "No batch specified." };
    // Queue items carry batchId (enqueueImport spreads its opts), so pending ones can be
    // dropped wholesale.
    const droppedItems = typeof ctx.removeQueuedImports === "function" && batchId
      ? ctx.removeQueuedImports((q) => q.batchId === batchId)
      : [];
    const droppedList = Array.isArray(droppedItems) ? droppedItems : [];
    const dropped = droppedList.length || (typeof droppedItems === "number" ? droppedItems : 0);
    // The RUNNING (or still-queued) job is matched on tabId rather than batchId:
    // import jobs are started deep inside importFile and already carry metadata.tabId.
    const wanted = new Set(tabIds.map(String));
    let cancelledJobs = 0;
    try {
      cancelledJobs = ctx.jobManager?.cancelWhere?.(
        (j) => (j?.status === "running" || j?.status === "queued") && wanted.has(String(j?.metadata?.tabId)),
      ) || 0;
    } catch (e) {
      dbg("TRIAGE", "cancel-batch job sweep failed", { error: e?.message });
    }
    // Dropped queue items never emit import-error on their own, so App.jsx would
    // wait forever for them and the "Cancel remaining" toast would never settle.
    const settleIds = new Set(droppedList.map((q) => String(q?.tabId || "")).filter(Boolean));
    for (const id of settleIds) {
      try { safeSend("import-error", { tabId: id, error: "cancelled" }); } catch { /* ignore */ }
    }
    dbg("TRIAGE", "batch cancelled", { batchId, dropped, cancelledJobs });
    return { dropped, cancelledJobs };
  });
};

/** "<HOST> · Security" — host prefix only when we actually know the host. */
function buildTabName(hostLabel, filePath) {
  const { evtxDisplayName } = require("../analyzers/triage-collection");
  const base = path.basename(filePath);
  const short = /\.evtx$/i.test(base) ? evtxDisplayName(filePath) : base;
  const host = String(hostLabel || "").trim();
  if (!host) return short;
  const name = `${host} · ${short}`;
  return name.length > 60 ? short : name;
}
