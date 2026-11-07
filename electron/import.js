/**
 * import.js — File import pipeline
 *
 * Extracted from main.js. Handles file validation, sheet selection,
 * parse orchestration, post-import index/FTS scheduling, and USN path resolution.
 */

const path = require("path");
const fs = require("fs");
const os = require("os");
const { dialog } = require("electron");
const { dbg } = require("./logger");
const { resolveTempDir } = require("./utils/temp-dir");

// Align with db.js isLargeFile (>5GB): FTS skipped, timestamp-only eager indexes.
const LARGE_FILE_WARN_BYTES = 5 * 1024 * 1024 * 1024;
const LARGE_FILE_BLOCK_XLSX_BYTES = 10 * 1024 * 1024 * 1024;
// Main-process RSS already high + multi-GB import is a common crash recipe (renderer + SQLite).
const MEMORY_PRESSURE_RSS_BYTES = 3.5 * 1024 * 1024 * 1024;
const MEMORY_PRESSURE_MIN_FILE_BYTES = 2 * 1024 * 1024 * 1024;

/**
 * Import a file into the application.
 *
 * @param {string} filePath - Path to the file to import
 * @param {string|null} preTabId - Pre-assigned tab ID (for session restore)
 * @param {string|null} preSheetName - Pre-assigned sheet name (for XLSX)
 * @param {object} deps - Dependencies from main.js
 */
async function importFile(filePath, preTabId, preSheetName, deps, queueItem = {}) {
  const { mainWindow, safeSend, activeWindow, getXLSXSheets, enqueueImport, nextTabId } = deps;
  const { detectAiHistoryImport } = require("./parsers/ai-history-import");
  const { AI_HISTORY_TOOLS } = require("./parsers/ai-history/schema");

  const tabId = preTabId || nextTabId();
  let fileName;
  if (queueItem.displayName) {
    fileName = queueItem.displayName;
  } else {
    try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); }
  }

  const aiHistory = queueItem.aiHistoryTool
    ? {
      tool: queueItem.aiHistoryTool,
      target: filePath,
      includeSubagents: !!queueItem.aiHistoryIncludeSubagents,
    }
    : detectAiHistoryImport(filePath);
  if (aiHistory) {
    const tabLabel = AI_HISTORY_TOOLS[aiHistory.tool]?.tabPrefix;
    if (tabLabel) fileName = tabLabel;
    dbg("IMPORT", `importFile AI history`, { filePath: aiHistory.target, tabId, tool: aiHistory.tool });
  }

  const ext = path.extname(filePath).toLowerCase();
  dbg("IMPORT", `importFile called`, { filePath, tabId, ext, preSheetName, aiHistory: !!aiHistory });

  // Pre-flight check for very large files
  let fileSize = 0;
  try { fileSize = fs.statSync(filePath).size; } catch {}
  // XLSX/XLSM this large is not a practical import target for the current parser.
  if ((ext === ".xlsx" || ext === ".xlsm") && fileSize > LARGE_FILE_BLOCK_XLSX_BYTES) {
    const sizeGB = (fileSize / (1024 ** 3)).toFixed(1);
    const limitGB = (LARGE_FILE_BLOCK_XLSX_BYTES / (1024 ** 3)).toFixed(0);
    if (mainWindow) {
      await dialog.showMessageBox(activeWindow(), {
        type: "error",
        title: "XLSX Too Large",
        message: `This workbook is ${sizeGB} GB`,
        detail: `XLSX/XLSM imports above ${limitGB} GB are not supported in this build. Convert the workbook to CSV and import the CSV instead.`,
        buttons: ["OK"],
      });
    }
    dbg("IMPORT", `Blocked oversized XLSX import`, { filePath, sizeGB, limitGB });
    safeSend("import-error", {
      tabId,
      fileName,
      error: `XLSX/XLSM imports above ${limitGB} GB are not supported — convert to CSV first`,
    });
    return;
  }

  if (fileSize > LARGE_FILE_WARN_BYTES && mainWindow) {
    const sizeGB = (fileSize / (1024 ** 3)).toFixed(1);
    const ramGB = Math.round(os.totalmem() / (1024 ** 3));
    const { response } = await dialog.showMessageBox(activeWindow(), {
      type: "warning",
      title: "Large File Warning",
      message: `This file is ${sizeGB} GB`,
      detail: `Importing very large files needs significant disk space (roughly 2–3× the file size on your temp volume) and memory. The UI may stay busy for several minutes after import finishes.\n\nSystem RAM: ${ramGB} GB\n\nTips: quit and restart IRFlow before importing, close other large tabs, and wait for "indexes ready" before opening column filters. For Plaso files, consider exporting a filtered CSV with psort first.`,
      buttons: ["Import Anyway", "Cancel"],
      defaultId: 1,
      cancelId: 1,
    });
    if (response === 1) {
      dbg("IMPORT", `User cancelled large file import`, { filePath, sizeGB });
      safeSend("import-error", { tabId, fileName, error: `Import cancelled — file is ${sizeGB} GB` });
      return;
    }
    dbg("IMPORT", `User chose to proceed with large file`, { filePath, sizeGB, ramGB });
  }

  if (fileSize >= MEMORY_PRESSURE_MIN_FILE_BYTES && mainWindow) {
    const rssMB = Math.round(process.memoryUsage().rss / 1048576);
    if (process.memoryUsage().rss >= MEMORY_PRESSURE_RSS_BYTES) {
      const sizeGB = (fileSize / (1024 ** 3)).toFixed(1);
      const { response } = await dialog.showMessageBox(activeWindow(), {
        type: "warning",
        title: "High Memory Use",
        message: `IRFlow is already using about ${(rssMB / 1024).toFixed(1)} GB of memory`,
        detail: `Importing a ${sizeGB} GB file on top of that can make the app unstable or crash.\n\nQuit and restart IRFlow before importing, or close other large tabs first.`,
        buttons: ["Import Anyway", "Cancel"],
        defaultId: 1,
        cancelId: 1,
      });
      if (response === 1) {
        dbg("IMPORT", `User cancelled import due to memory pressure`, { filePath, rssMB, sizeGB });
        safeSend("import-error", { tabId, fileName, error: "Import cancelled — restart IRFlow to free memory, then try again" });
        return;
      }
      dbg("IMPORT", `User proceeding despite memory pressure`, { filePath, rssMB, sizeGB });
    }
  }

  // If sheetName is pre-assigned (from select-sheet or session restore), skip sheet detection
  let sheetName = preSheetName;
  if (sheetName && (ext === ".xlsx" || ext === ".xlsm") && !Number.isFinite(Number(sheetName))) {
    try {
      const sheets = await getXLSXSheets(filePath);
      const matched = sheets.find((s) => s.name === sheetName);
      if (matched) sheetName = matched.id;
    } catch (e) {
      dbg("IMPORT", `sheet name remap failed`, { filePath, sheetName, error: e.message });
    }
  }
  if (!sheetName && (ext === ".xlsx" || ext === ".xls" || ext === ".xlsm")) {
    try {
      dbg("IMPORT", `getXLSXSheets calling...`, { filePath });
      const sheets = await getXLSXSheets(filePath);
      dbg("IMPORT", `getXLSXSheets returned`, { sheetCount: sheets.length, sheets: sheets.map(s => s.name) });
      if (sheets.length > 1) {
        safeSend("sheet-selection", {
          tabId,
          fileName,
          filePath,
          sheets,
        });
        return;
      }
    } catch (e) {
      dbg("IMPORT", `getXLSXSheets failed`, { error: e.message, stack: e.stack });
    }
  }

  dbg("IMPORT", `calling startImport`, { tabId, sheetName });
  await startImport(filePath, tabId, fileName, sheetName, fileSize, deps);
}

async function startImport(filePath, tabId, fileName, sheetName, preFileSize, deps) {
  const { safeSend, db, runImportJob, scheduleIndexBuild, importQueue, pendingIndexTabs, tabMeta } = deps;

  dbg("IMPORT", `startImport begin`, { filePath, tabId, fileName, sheetName });
  let fileSize = preFileSize || 0;
  if (!fileSize) { try { fileSize = fs.statSync(filePath).size; } catch {} }
  dbg("IMPORT", `fileSize`, { fileSize });

  // ── Free-disk guardrail ──────────────────────────────────────────
  // The temp SQLite DB + per-column indexes (and, for files ≤5GB, the trigram FTS index)
  // live on the os.tmpdir() volume and can total several times the source size. Refuse up
  // front if the volume clearly lacks headroom, rather than failing with SQLITE_FULL
  // mid-build — which silently leaves a half-indexed DB and a stuffed system disk.
  if (fileSize > 0 && typeof fs.statfsSync === "function") {
    const tempDir = resolveTempDir(); // the volume the temp DB + indexes will be written to
    const FTS_GATE = 5 * 1024 * 1024 * 1024; // matches db.js isLargeFile (FTS is skipped above this)
    const ftsWillRun = fileSize <= FTS_GATE;
    // db (~1.2x) + all-column indexes (~1.5x) + WAL/temp slack, plus trigram FTS (~2.5x) when it runs.
    const requiredBytes = Math.round(fileSize * (ftsWillRun ? 5 : 2.5));
    let freeBytes = Infinity;
    try { const st = fs.statfsSync(tempDir); freeBytes = st.bavail * st.bsize; } catch {}
    if (freeBytes < requiredBytes) {
      const gb = (n) => (n / (1024 ** 3)).toFixed(0);
      dbg("IMPORT", `Refusing import — insufficient temp disk`, { fileSize, requiredBytes, freeBytes, tempDir });
      safeSend("import-error", {
        tabId, fileName,
        error: `Not enough free disk space to import this file. IRFlow needs roughly ${gb(requiredBytes)} GB free on the temp volume (${tempDir}) for the database and indexes, but only ${gb(freeBytes)} GB is available. Free up space, or choose a folder on a larger volume via Tools ▸ Set Temp Storage Folder…, and try again.`,
      });
      return;
    }
  }

  // Notify renderer that import has started
  safeSend("import-start", {
    tabId,
    fileName,
    filePath,
    fileSize,
  });

  try {
    dbg("IMPORT", `starting import worker...`);
    const result = await runImportJob(filePath, tabId, sheetName, fileSize);
    dbg("IMPORT", `parseFile complete`, { headers: result.headers?.length, rowCount: result.rowCount, tsColumns: result.tsColumns?.length });

    // Track original file path + format for features like resident data extraction
    tabMeta.set(tabId, { filePath, sourceFormat: result.sourceFormat || null, dirty: !!result.meta?.dirty });

    // A dirty registry hive (primary/secondary sequence mismatch) has unflushed transaction
    // logs — some values may be stale. Surface it so the analyst doesn't trust a partial view.
    const { buildAiHistoryImportNotice, buildAiHistoryImportWarning } = require("./parsers/ai-history/import-meta");
    const aiImportWarning = result.meta ? buildAiHistoryImportWarning(result.meta) : null;
    const aiImportNotice = result.importNotice || (result.meta ? buildAiHistoryImportNotice(result.meta) : null);
    const importWarning = result.importWarning ?? (result.meta?.dirty
      ? "This hive is dirty — its transaction logs (.LOG1/.LOG2) were not replayed, so some keys/values may be stale. Replay the logs (e.g. with RegRipper/yarp) for a complete view."
      : aiImportWarning);
    let importNotice = result.importNotice ?? aiImportNotice ?? null;
    if (result.meta?.subagentsSkipped && result.sourceFormat?.startsWith("ai-history-")) {
      const scopeNote = "Subagent session folders were skipped (main sessions only). Use Tools → AI Artifacts and choose “Include subagents” for full coverage.";
      importNotice = importNotice ? `${importNotice} ${scopeNote}` : scopeNote;
    }

    // ── USN Journal Rewind: resolve parent paths from the journal's own directory records ──
    let resolveStats = null;
    if (result.sourceFormat === "raw-usnjrnl") {
      let mftTabId = null;
      for (const [tid, tmeta] of tabMeta) {
        if (tmeta.sourceFormat === "raw-mft") { mftTabId = tid; break; }
      }
      dbg("IMPORT", `Resolving USN parent paths (rewind)`, { mftAvailable: !!mftTabId });
      resolveStats = db.resolveUsnPaths(tabId, mftTabId);
      dbg("IMPORT", `USN path resolution complete`, resolveStats);
    }

    // ── MFT imported: re-resolve any existing USN Journal tabs ──
    if (result.sourceFormat === "raw-mft") {
      for (const [tid, tmeta] of tabMeta) {
        if (tmeta.sourceFormat === "raw-usnjrnl") {
          dbg("IMPORT", `Re-resolving USN paths for ${tid} with new MFT data`);
          const reResolve = db.resolveUsnPaths(tid, tabId);
          dbg("IMPORT", `USN re-resolution complete`, reResolve);
          safeSend("usn-paths-updated", { tabId: tid, resolveStats: reResolve });
        }
      }
    }

    const isLargeFile = !!(result.isLargeFile || fileSize > LARGE_FILE_WARN_BYTES);
    const memAfter = process.memoryUsage();
    dbg("IMPORT", `import worker finished`, {
      rowCount: result.rowCount,
      isLargeFile,
      heapMB: Math.round(memAfter.heapUsed / 1048576),
      rssMB: Math.round(memAfter.rss / 1048576),
    });

    // Fetch initial window of data (windowed — not all rows)
    dbg("IMPORT", `querying initial rows...`);
    const initialLimit = isLargeFile ? 2500 : 5000;
    const initialData = db.queryRows(tabId, {
      offset: 0,
      limit: initialLimit,
      sortCol: null,
      sortDir: "asc",
    });
    dbg("IMPORT", `initial rows fetched`, { rowCount: initialData.rows?.length, totalFiltered: initialData.totalFiltered, initialLimit });

    const emptyColumns = db.getEmptyColumns(tabId);
    dbg("IMPORT", `sending import-complete`);

    safeSend("import-complete", {
      tabId,
      fileName,
      headers: result.headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns || [],
      dayFirstColumns: result.dayFirstColumns || [],
      initialRows: initialData.rows,
      totalFiltered: initialData.totalFiltered,
      emptyColumns,
      sourceFormat: result.sourceFormat || null,
      evtxMessageMode: result.evtxMessageMode || null,
      messagesDeferred: !!result.messagesDeferred,
      resolveStats,
      importWarning,
      importNotice,
      isLargeFile,
    });

    if (isLargeFile && global.gc) {
      setImmediate(() => {
        try { global.gc(); } catch {}
        const m = process.memoryUsage();
        dbg("IMPORT", `post-import GC`, { heapMB: Math.round(m.heapUsed / 1048576), rssMB: Math.round(m.rss / 1048576) });
      });
    }

    // Defer index/FTS builds when more imports are queued to avoid memory spikes
    if (importQueue.length > 0) {
      dbg("IMPORT", `Deferring index/FTS build for ${tabId} (${importQueue.length} imports queued)`);
      pendingIndexTabs.push(tabId);
    } else {
      // No more imports queued — build in the background worker pool immediately
      scheduleIndexBuild(tabId);
    }
  } catch (err) {
    dbg("IMPORT", `startImport FAILED`, { error: err.message, stack: err.stack });
    // Clean up partially-imported tab on failure
    try { db.closeTab(tabId); } catch (_) {}
    safeSend("import-error", {
      tabId,
      fileName,
      error: err.message,
    });
  }
}

module.exports = { importFile };
