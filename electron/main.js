/**
 * main.js — Electron main process for IRFlow Timeline
 *
 * Coordinates between the renderer (React UI) and the backend
 * (SQLite DB + streaming parser). All data operations happen here
 * in the main process, with results sent to renderer via IPC.
 */

const { app, BrowserWindow, crashReporter, dialog, ipcMain, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const crypto = require("crypto");
const TimelineDB = require("./db");
const { getXLSXSheets, extractResidentData } = require("./parsers");
const { createUpdateController } = require("./updater");
const { JobManager } = require("./jobs/job-manager");
const { resolveTempDir } = require("./utils/temp-dir");
const { makeImportQueueKey, isDuplicatePendingImport } = require("./utils/import-queue");
const { shouldHideWindowOnClose, restoreOrCreateWindow } = require("./utils/app-lifecycle");
const { createFatalRecovery } = require("./utils/fatal-recovery");
const { buildMenu: _buildMenu } = require("./menu");
const packageMeta = require("../package.json");

// Raise V8 heap limit to 16GB — needed for importing large forensic images (20GB+)
// app.commandLine.appendSwitch only affects renderer processes; for the main process
// (where parsing runs), we must set the flag via v8 directly.
const v8 = require("v8");
v8.setFlagsFromString("--max-old-space-size=16384");
app.commandLine.appendSwitch("js-flags", "--max-old-space-size=16384");

let mainWindow;
let isQuitting = false;
const db = new TimelineDB();
let tabCounter = 0;
const _tabMeta = new Map(); // tabId -> { filePath, sourceFormat }

// ── Recent files persistence ──────────────────────────────────────
const RECENT_FILES_MAX = 10;
const _recentFilesPath = path.join(app.getPath("userData"), "recent-files.json");

function _loadRecentFiles() {
  try {
    if (fs.existsSync(_recentFilesPath)) return JSON.parse(fs.readFileSync(_recentFilesPath, "utf8")).slice(0, RECENT_FILES_MAX);
  } catch {}
  return [];
}

function _saveRecentFiles(files) {
  try { fs.writeFileSync(_recentFilesPath, JSON.stringify(files), "utf8"); } catch {}
}

let _menuRebuildTimer = null;
function addRecentFile(filePath) {
  const files = _loadRecentFiles().filter((f) => f !== filePath);
  files.unshift(filePath);
  if (files.length > RECENT_FILES_MAX) files.length = RECENT_FILES_MAX;
  _saveRecentFiles(files);
  // Debounce menu rebuild — batch imports can call addRecentFile rapidly
  if (_menuRebuildTimer) clearTimeout(_menuRebuildTimer);
  _menuRebuildTimer = setTimeout(() => { _menuRebuildTimer = null; _rebuildMenu(); }, 500);
  safeSend("recent-files-updated", files);
}

// ── Debug trace logger (shared singleton — see logger.js) ─────
const { dbg, debugLogPath, flushLogSync } = require("./logger");
dbg("INIT", `IRFlow Timeline starting, debug log: ${debugLogPath}`);

try {
  crashReporter.start({ uploadToServer: false, compress: true });
  dbg("INIT", "Local crash reporter enabled", { uploadToServer: false });
} catch (err) {
  dbg("INIT", "Local crash reporter unavailable", { message: err?.message });
}

// ── Safe IPC helpers ─────────────────────────────────────────────
function safeHandle(channel, handler) {
  ipcMain.handle(channel, async (event, ...args) => {
    dbg("IPC", `→ ${channel}`, args?.length > 0 ? { argKeys: typeof args[0] === "object" && args[0] ? Object.keys(args[0]) : undefined } : undefined);
    try {
      const result = await handler(event, ...args);
      dbg("IPC", `← ${channel} OK`);
      return result;
    } catch (err) {
      dbg("IPC", `← ${channel} ERROR`, { message: err?.message, stack: err?.stack });
      return { __ipcError: true, message: err?.message || "Unknown error" };
    }
  });
}

// Return mainWindow if it's still alive, otherwise null.
// Electron dialog APIs accept null/undefined — they show a parentless dialog.
function _activeWindow() {
  return (mainWindow && !mainWindow.isDestroyed()) ? mainWindow : null;
}

function safeSend(channel, data) {
  try {
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
      mainWindow.webContents.send(channel, data);
    }
  } catch (e) { /* window closed mid-send */ }
}

safeHandle("debug-log", (_event, payload = {}) => {
  const scope = typeof payload.scope === "string" && payload.scope.trim()
    ? payload.scope.trim().slice(0, 40)
    : "RENDERER";
  const message = typeof payload.message === "string" ? payload.message : "";
  dbg(scope, message, payload.data && typeof payload.data === "object" ? payload.data : undefined);
  return true;
});

// Open an external link in the system browser, never in-app. Only http(s)/mailto are
// allowed — anything else (file:, javascript:, etc.) is refused so a crafted link in
// forensic data can't be turned into a local-file open or script execution.
safeHandle("open-external", (_event, { url } = {}) => {
  const raw = String(url || "").trim();
  let parsed;
  try { parsed = new URL(raw); } catch { return { ok: false, error: "Invalid URL" }; }
  if (!["https:", "http:", "mailto:"].includes(parsed.protocol)) {
    return { ok: false, error: `Refusing to open ${parsed.protocol} link` };
  }
  shell.openExternal(raw);
  return { ok: true };
});

const jobManager = new JobManager({ safeSend, dbg });
const fatalRecovery = createFatalRecovery({
  app,
  dialog,
  jobManager,
  db,
  dbg,
  flushLogSync,
  debugLogPath,
});

// Continuing after an uncaught exception leaves Node/Electron in an undefined state.
// Perform synchronous cleanup, relaunch at most once, and then exit immediately.
process.on("uncaughtException", (err) => {
  fatalRecovery.handleFatal(err, "uncaughtException", { allowRelaunch: !isQuitting });
});

process.on("unhandledRejection", (reason) => {
  fatalRecovery.handleFatal(reason, "unhandledRejection", { allowRelaunch: !isQuitting });
});

const updateController = createUpdateController({
  getWindow: _activeWindow,
  sendStatus: (payload) => safeSend("updater-state", payload),
});

// ── Import queue — serialize file imports to prevent concurrent memory exhaustion ──
const _importQueue = [];
let _importRunning = false;
let _activeImportKey = null;
const _pendingIndexTabs = []; // tabs waiting for index/FTS build (deferred until queue drains)
const _indexBuildQueue = [];
const _queuedIndexTabs = new Set();
let _activeIndexBuilds = 0;
const MAX_CONCURRENT_INDEX_BUILDS = 2;

function _newTempDbPath(tabId) {
  // resolveTempDir(): user-chosen scratch folder → TLE_TEMP_DIR env → os.tmpdir(). Lets an
  // analyst working 30-50GB files put the DB + indexes on a volume with room, not the boot disk.
  return path.join(resolveTempDir(), `tle_${tabId}_${crypto.randomBytes(4).toString("hex")}.db`);
}

// Point SQLite's temp-file spill (temp_store=FILE merge sorts during index builds) at the
// same volume as the temp DBs. Set before workers spawn — they inherit process.env at spawn.
function _applyTempStorageEnv() {
  try { process.env.SQLITE_TMPDIR = resolveTempDir(); } catch {}
}

function _cleanupDbFiles(dbPath) {
  if (!dbPath) return;
  for (const p of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
    try { fs.unlinkSync(p); } catch {}
  }
}

function enqueueImport(filePath, opts) {
  const queueKey = makeImportQueueKey(filePath, opts);
  if (isDuplicatePendingImport(_importQueue, _activeImportKey, queueKey)) {
    dbg("QUEUE", "Skipped duplicate pending import", { filePath, sheetName: opts?.sheetName });
    return false;
  }

  let fileName;
  if (opts?.displayName) { fileName = opts.displayName; }
  else { try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); } }
  let fileSize = 0; try { fileSize = fs.statSync(filePath).size; } catch {}
  _importQueue.push({ filePath, fileName, fileSize, ...opts, queueKey });
  if (!opts?.skipRecent) addRecentFile(filePath);
  _broadcastQueue();
  _processQueue();
  return true;
}

/**
 * Drop still-queued imports matching `predicate`. Used by "Open Triage Collection" to
 * cancel the remainder of a batch — a collection can queue several multi-GB files, and
 * without this a mis-click has to be waited out. Returns how many were removed.
 */
function removeQueuedImports(predicate) {
  if (typeof predicate !== "function") return 0;
  const before = _importQueue.length;
  for (let i = _importQueue.length - 1; i >= 0; i--) {
    let hit = false;
    try { hit = !!predicate(_importQueue[i]); } catch { hit = false; }
    if (hit) _importQueue.splice(i, 1);
  }
  const removed = before - _importQueue.length;
  if (removed > 0) _broadcastQueue();
  return removed;
}

function _broadcastQueue() {
  const pending = _importQueue.map((q) => ({ fileName: q.fileName, fileSize: q.fileSize }));
  safeSend("import-queue", { pending, running: _importRunning });
}

async function _processQueue() {
  if (_importRunning || _importQueue.length === 0) return;
  _importRunning = true;

  while (_importQueue.length > 0) {
    const item = _importQueue.shift();
    _activeImportKey = item.queueKey;
    _broadcastQueue();

    // Log memory before import
    const memBefore = process.memoryUsage();
    dbg("QUEUE", `Starting import: ${item.fileName}`, { heapMB: Math.round(memBefore.heapUsed / 1048576), rssMB: Math.round(memBefore.rss / 1048576), queueRemaining: _importQueue.length });

    try {
      await importFile(item.filePath, item.tabId, item.sheetName, item);
    } catch (err) {
      dbg("QUEUE", `importFile failed for ${item.fileName}`, { error: err?.message });
      // Notify renderer so it can dismiss the loading state for this file
      safeSend("import-error", {
        tabId: item.tabId || null,
        fileName: item.fileName,
        error: err?.message || "Import failed",
      });
    }
    _activeImportKey = null;
    _broadcastQueue();

    if (_importQueue.length > 0) {
      // Always yield to the event loop (lets queued IPC/progress flush). Only the heavier 100ms +
      // forced GC bleed-off after a LARGE import — for a drop of many small files (KAPE) that pause
      // is pure dead time (~100ms × N), so skip it.
      await new Promise((r) => setImmediate(r));
      if ((item.fileSize || 0) > 2 * 1024 * 1024 * 1024 && global.gc) {
        await new Promise((r) => setTimeout(r, 100));
        try { global.gc(); } catch {}
      }
    }
  }

  _importRunning = false;
  _broadcastQueue();
  // Queue fully drained — now build deferred indexes/FTS
  _buildDeferredIndexes();
}

function _buildDeferredIndexes() {
  if (_pendingIndexTabs.length === 0) return;
  const tabs = _pendingIndexTabs.splice(0);
  dbg("QUEUE", `Building deferred indexes for ${tabs.length} tabs`);
  for (const tabId of tabs) scheduleIndexBuild(tabId);
}

function scheduleIndexBuild(tabId) {
  if (!db.getTabWorkerDescriptor(tabId)) return;
  if (_queuedIndexTabs.has(tabId)) return;
  _queuedIndexTabs.add(tabId);
  _indexBuildQueue.push(tabId);
  _processIndexBuildQueue();
}

function _processIndexBuildQueue() {
  while (_activeIndexBuilds < MAX_CONCURRENT_INDEX_BUILDS && _indexBuildQueue.length > 0) {
    const tabId = _indexBuildQueue.shift();
    _queuedIndexTabs.delete(tabId);
    if (!db.getTabWorkerDescriptor(tabId)) continue;
    _activeIndexBuilds++;
    _buildIndexesAndFtsInWorker(tabId)
      .catch((err) => {
        const message = err?.message || "Index build failed";
        console.error(`Index/FTS build failed for tab ${tabId}:`, message);
        // Emit terminal events for BOTH phases so the UI overlay dismisses.
        // Without index-progress done:true, VirtualGrid's overlay (gated on
        // !ct.indexesReady) would stay visible forever.
        safeSend("index-progress", { tabId, built: 0, total: 0, done: true, error: message });
        safeSend("fts-progress", { tabId, indexed: 0, total: 0, done: true, error: message });
      })
      .finally(() => {
        _activeIndexBuilds--;
        _processIndexBuildQueue();
      });
  }
}

async function _runIndexWorker(tabId, task) {
  const descriptor = db.getTabWorkerDescriptor(tabId);
  if (!descriptor) return { skipped: true };
  if (task === "indexes") db.markIndexesBuilding(tabId, true);
  if (task === "fts") db.markFtsBuilding(tabId, true);
  const { promise } = jobManager.startWorkerJob({
    type: `db-${task}`,
    worker: "index-worker.js",
    workerData: { tabId, descriptor, task },
    channels: { progress: task === "indexes" ? "index-progress" : "fts-progress" },
    metadata: { tabId, task },
    resourceClass: "heavy",
  });
  return promise;
}

async function _buildIndexesAndFtsInWorker(tabId) {
  let indexResult;
  try {
    indexResult = await _runIndexWorker(tabId, "indexes");
  } catch (err) {
    db.markIndexesBuilt(tabId, { error: err?.message || "Index job failed" });
    throw err;
  }
  db.markIndexesBuilt(tabId, indexResult?.descriptor || indexResult);
  if (indexResult?.error) throw new Error(indexResult.error);

  const tabInfo = _tabMeta.get(tabId);
  if (tabInfo?.sourceFormat === "raw-mft") {
    for (const [tid, tmeta] of _tabMeta) {
      if (tmeta.sourceFormat === "raw-usnjrnl") {
        const reResolve = db.resolveUsnPaths(tid, tabId);
        if (reResolve.resolved > 0) {
          safeSend("usn-paths-updated", { tabId: tid, resolveStats: reResolve });
        }
      }
    }
  }

  // Trigram FTS5 on a multi-GB file inflates the temp DB ~4-5x on disk (a 30GB CSV →
  // ~125-140GB FTS index) and is a multi-hour build that can fill os.tmpdir. Skip it for
  // large files: substring search still works via the LIKE path in query-store
  // _applySearch when ftsReady stays false — a perf, not a correctness, tradeoff. We leave
  // meta.ftsReady false (do NOT markFtsBuilt) and just dismiss the FTS overlay.
  const ftsDescriptor = db.getTabWorkerDescriptor(tabId);
  if (ftsDescriptor?.isLargeFile) {
    dbg("QUEUE", `Skipping trigram FTS build for large file ${tabId} — search uses LIKE fallback`);
    safeSend("fts-progress", { tabId, indexed: 0, total: 0, done: true, skipped: true });
    return;
  }

  let ftsResult;
  try {
    ftsResult = await _runIndexWorker(tabId, "fts");
  } catch (err) {
    db.markFtsBuilt(tabId, { error: err?.message || "FTS job failed" });
    throw err;
  }
  db.markFtsBuilt(tabId, ftsResult?.descriptor || ftsResult);
  if (ftsResult?.error) throw new Error(ftsResult.error);
}

async function runImportJob(filePath, tabId, sheetName, fileSize) {
  const dbPath = _newTempDbPath(tabId);
  const { promise } = jobManager.startWorkerJob({
    type: "import",
    worker: "import-worker.js",
    workerData: { filePath, tabId, sheetName, fileSize, dbPath },
    channels: { progress: "import-progress" },
    metadata: { tabId, filePath, fileName: path.basename(filePath), sheetName },
    resourceClass: "heavy",
  });

  try {
    const result = await promise;
    if (result?.error) throw new Error(result.error);
    db.adoptTabFromFile(tabId, {
      ...result,
      dbPath,
      headers: result.headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns || [],
    });
    return result;
  } catch (err) {
    _cleanupDbFiles(dbPath);
    throw err;
  }
}

// ── macOS lifecycle ────────────────────────────────────────────────
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    jobManager.terminateAll();
    db.closeAll();
    app.quit();
  }
});

app.on("activate", () => {
  restoreOrCreateWindow({ window: mainWindow, createWindow });
});

app.on("before-quit", () => {
  isQuitting = true;
  jobManager.terminateAll();
  db.closeAll();
  // VT cache DB cleanup is handled by vt-handlers module
});

app.on("child-process-gone", (_event, details) => {
  dbg("CRASH", "Electron child process gone", {
    type: details?.type,
    reason: details?.reason,
    exitCode: details?.exitCode,
    serviceName: details?.serviceName,
    name: details?.name,
  });
});

app.on("open-file", (event, filePath) => {
  event.preventDefault();
  if (mainWindow && mainWindow.webContents) {
    enqueueImport(filePath);
  } else {
    app.pendingFilePath = filePath;
  }
});

// ── Window ─────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1500,
    height: 950,
    minWidth: 900,
    minHeight: 600,
    titleBarStyle: "hiddenInset",
    trafficLightPosition: { x: 16, y: 16 },
    vibrancy: "under-window",
    backgroundColor: "#0f1114",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
    show: false,
  });

  const isDev = !app.isPackaged && process.env.TLE_DEV_SERVER === "1";

  // Security hardening: never let the renderer spawn in-app windows or navigate the main
  // window to remote content (which would run with the privileged preload attached).
  // External links go to the system browser instead.
  const openExternalSafe = (url) => { if (/^(https?|mailto):/i.test(url)) shell.openExternal(url); };
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    openExternalSafe(url);
    return { action: "deny" };
  });
  // Only the packaged renderer bundle may be navigated to in-app; any other file://
  // target would otherwise load with the privileged preload + IPC bridge attached.
  const { pathToFileURL } = require("url");
  const distRootUrl = pathToFileURL(path.join(__dirname, "..", "dist") + path.sep).href;
  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (isDev && url.startsWith("http://localhost:5173")) return; // allow Vite dev reload
    if (!isDev && url.startsWith(distRootUrl)) return;            // allow in-app navigation within the bundle
    event.preventDefault();
    openExternalSafe(url);
  });

  if (isDev) {
    mainWindow.loadURL("http://localhost:5173");
  } else {
    mainWindow.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }

  const wc = mainWindow.webContents;
  wc.on("render-process-gone", (_event, details) => {
    dbg("CRASH", "Renderer process gone", { reason: details?.reason, exitCode: details?.exitCode });
    if (isQuitting && ["clean-exit", "killed"].includes(details?.reason)) return;
    const err = new Error(`Renderer process stopped (${details?.reason || "unknown"}, code ${details?.exitCode ?? "unknown"})`);
    fatalRecovery.handleFatal(err, "render-process-gone", { allowRelaunch: !isQuitting });
  });
  wc.on("unresponsive", () => {
    dbg("CRASH", "Renderer became unresponsive");
  });
  wc.on("responsive", () => {
    dbg("CRASH", "Renderer responsive again");
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
    fatalRecovery.markStableStartup();
    if (app.pendingFilePath) {
      enqueueImport(app.pendingFilePath);
      delete app.pendingFilePath;
    }
    updateController.scheduleStartupCheck();
  });

  mainWindow.on("close", (event) => {
    if (!shouldHideWindowOnClose({ isQuitting })) return;
    event.preventDefault();
    mainWindow.hide();
  });

  mainWindow.on("closed", () => { mainWindow = null; });

  buildMenu();
}

// ── File import (delegated to electron/import.js) ──────────────────
const { importFile: _importFile } = require("./import");
async function importFile(filePath, preTabId, preSheetName, queueItem = {}) {
  return _importFile(filePath, preTabId, preSheetName, {
    mainWindow, safeSend, activeWindow: _activeWindow, db,
    getXLSXSheets, enqueueImport, runImportJob, scheduleIndexBuild,
    importQueue: _importQueue, pendingIndexTabs: _pendingIndexTabs,
    tabMeta: _tabMeta,
    nextTabId: () => `tab_${++tabCounter}_${Date.now()}`,
  }, queueItem);
}

function _descriptorsForTabs(tabIds) {
  const out = [];
  for (const tabId of tabIds || []) {
    const descriptor = db.getTabWorkerDescriptor(tabId);
    if (descriptor) out.push(descriptor);
  }
  return out;
}

function startAnalyzerJob(method, payload = {}, overrides = {}) {
  const ids = new Set();
  if (payload.tabId) ids.add(payload.tabId);
  for (const id of payload.tabIds || []) ids.add(id);
  if (payload.options?.usnTabId) ids.add(payload.options.usnTabId);
  if (payload.options?.mftTabId) ids.add(payload.options.mftTabId);
  if (payload.options?.evtxTabId) ids.add(payload.options.evtxTabId);
  const tabs = _descriptorsForTabs([...ids]);
  const legacyProgressChannel = method === "analyzeRansomware" || method === "scanRansomwareExtensions"
    ? "rw-progress"
    : method === "getFileActivityHeatmap"
      ? "hm-progress"
      : "analysis-progress";
  return jobManager.startWorkerJob({
    type: "analyzer",
    worker: "analyzer-worker.js",
    workerData: { method, payload, tabs },
    channels: { progress: legacyProgressChannel, ...(overrides.channels || {}) },
    metadata: { method, tabId: payload.tabId, tabIds: payload.tabIds, ...(overrides.metadata || {}) },
    resourceClass: "heavy",
    concurrencyKey: overrides.concurrencyKey || null,
    maxConcurrent: overrides.maxConcurrent || 0,
    retainResult: overrides.retainResult !== false,
  });
}

function runAnalyzerJob(method, payload = {}) {
  const { promise } = startAnalyzerJob(method, payload);
  return promise;
}

// ── IPC Handlers (extracted to electron/ipc/) ────────────────────
const { PathAuthorizer } = require("./utils/path-authorizer");
// One authorizer for the whole main process. Scopes are namespaced strings, so a grant
// under "triage-root" does NOT satisfy a "scan-target" check — sharing the instance only
// lets modules hand a path they already validated to another module, deliberately.
const _pathAuthorizer = new PathAuthorizer();
const { registerAll } = require("./ipc");
registerAll(safeHandle, safeSend, {
  db,
  _tabMeta,
  _activeWindow,
  enqueueImport,
  pathAuthorizer: _pathAuthorizer,
  removeQueuedImports,
  _loadRecentFiles,
  _saveRecentFiles,
  _rebuildMenu: () => _rebuildMenu(),
  _pendingIndexTabs,
  jobManager,
  runAnalyzerJob,
  startAnalyzerJob,
  scheduleIndexBuild,
  nextTabId: () => `tab_${++tabCounter}_${Date.now()}`,
  _newTempDbPath,
  extractResidentData,
  updateController,
  mainWindow: { isDestroyed() { return !mainWindow || mainWindow.isDestroyed(); } },
});

// ── Native macOS Menu (delegated to electron/menu.js) ─────────────
function _rebuildMenu() { buildMenu(); }

function buildMenu() {
  _buildMenu({
    mainWindow, loadRecentFiles: _loadRecentFiles, saveRecentFiles: _saveRecentFiles,
    enqueueImport, safeSend, activeWindow: _activeWindow, updateController,
    onTempDirChanged: _applyTempStorageEnv,
  });
}

// ── HTML Report Builder ──────────────────────────────────────────


// ── HTML Report Builder ──────────────────────────────────────────

app.whenReady().then(() => {
  app.setAboutPanelOptions({
    applicationName: "IRFlow Timeline",
    applicationVersion: packageMeta.version,
    version: packageMeta.version,
    credits: packageMeta.description,
    copyright: "Copyright © Renzon Cruz and contributors",
  });
  _applyTempStorageEnv();
  createWindow();
});
