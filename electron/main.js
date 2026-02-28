/**
 * main.js — Electron main process for IRFlow Timeline
 *
 * Coordinates between the renderer (React UI) and the backend
 * (SQLite DB + streaming parser). All data operations happen here
 * in the main process, with results sent to renderer via IPC.
 */

const { app, BrowserWindow, Menu, dialog, ipcMain, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const TimelineDB = require("./db");
const { parseFile, getXLSXSheets } = require("./parser");

let mainWindow;
const db = new TimelineDB();
let tabCounter = 0;

// ── Debug trace logger (writes to stderr + file) ────────────────
const debugLogPath = path.join(require("os").homedir(), "tle-debug.log");
let _logBuf = [];
function dbg(tag, msg, data) {
  const ts = new Date().toISOString();
  const line = `[${ts}] [${tag}] ${msg}${data !== undefined ? " " + JSON.stringify(data, null, 0) : ""}`;
  console.error(line);
  _logBuf.push(line);
  if (_logBuf.length >= 50) _flushLog();
}
function _flushLog() {
  if (!_logBuf.length) return;
  try { fs.appendFileSync(debugLogPath, _logBuf.join("\n") + "\n"); } catch {}
  _logBuf = [];
}
setInterval(_flushLog, 2000);
process.on("exit", _flushLog);
dbg("INIT", `IRFlow Timeline starting, debug log: ${debugLogPath}`);

// ── Global crash guards ──────────────────────────────────────────
process.on("uncaughtException", (err) => {
  dbg("CRASH", "Uncaught exception", { message: err?.message, stack: err?.stack });
  try {
    dialog.showErrorBox(
      "IRFlow Timeline Error",
      `An unexpected error occurred:\n\n${err.message}\n\nThe application will attempt to continue.`
    );
  } catch (_) {}
});

process.on("unhandledRejection", (reason) => {
  dbg("CRASH", "Unhandled rejection", { message: reason?.message || String(reason), stack: reason?.stack });
});

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

function safeSend(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
}

// ── Import queue — serialize file imports to prevent concurrent memory exhaustion ──
const _importQueue = [];
let _importRunning = false;
const _pendingIndexTabs = []; // tabs waiting for index/FTS build (deferred until queue drains)

function enqueueImport(filePath) {
  let fileName; try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); }
  let fileSize = 0; try { fileSize = fs.statSync(filePath).size; } catch {}
  _importQueue.push({ filePath, fileName, fileSize });
  _broadcastQueue();
  _processQueue();
}

function _broadcastQueue() {
  const pending = _importQueue.map((q) => ({ fileName: q.fileName, fileSize: q.fileSize }));
  safeSend("import-queue", { pending, running: _importRunning });
}

async function _processQueue() {
  if (_importRunning || _importQueue.length === 0) return;
  _importRunning = true;
  const item = _importQueue.shift();
  _broadcastQueue();

  // Log memory before import
  const memBefore = process.memoryUsage();
  dbg("QUEUE", `Starting import: ${item.fileName}`, { heapMB: Math.round(memBefore.heapUsed / 1048576), rssMB: Math.round(memBefore.rss / 1048576), queueRemaining: _importQueue.length });

  try {
    await importFile(item.filePath);
  } catch (err) {
    dbg("QUEUE", `importFile failed for ${item.fileName}`, { error: err?.message });
  }
  _importRunning = false;
  _broadcastQueue();

  if (_importQueue.length > 0) {
    // GC-friendly pause: yield to event loop + request GC before next import
    await new Promise((r) => setTimeout(r, 100));
    if (global.gc) { try { global.gc(); } catch {} }
    _processQueue();
  } else {
    // Queue fully drained — now build deferred indexes/FTS
    _buildDeferredIndexes();
  }
}

function _buildDeferredIndexes() {
  if (_pendingIndexTabs.length === 0) return;
  const tabs = _pendingIndexTabs.splice(0);
  dbg("QUEUE", `Building deferred indexes for ${tabs.length} tabs`);

  // Build indexes sequentially to avoid memory spikes
  let chain = Promise.resolve();
  for (const tabId of tabs) {
    chain = chain.then(() =>
      db.buildIndexesAsync(tabId, (progress) => {
        safeSend("index-progress", { tabId, ...progress });
      })
    ).then(() =>
      db.buildFtsAsync(tabId, (progress) => {
        safeSend("fts-progress", { tabId, ...progress });
      })
    ).catch((err) => {
      console.error(`Index/FTS build failed for tab ${tabId}:`, err?.message || err);
      safeSend("fts-progress", { tabId, indexed: 0, total: 0, done: true, error: err?.message });
    });
  }
}

// ── macOS lifecycle ────────────────────────────────────────────────
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    db.closeAll();
    app.quit();
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

app.on("before-quit", () => {
  db.closeAll();
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
    },
    show: false,
  });

  const isDev = !app.isPackaged;
  if (isDev) {
    mainWindow.loadURL("http://localhost:5173");
  } else {
    mainWindow.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
    if (app.pendingFilePath) {
      enqueueImport(app.pendingFilePath);
      delete app.pendingFilePath;
    }
  });

  mainWindow.on("closed", () => { mainWindow = null; });

  // Forward right-click coordinates to renderer via IPC.
  // On macOS with external trackpads, DOM contextmenu events may not reach the renderer,
  // so we forward from the main process where the event always fires.
  mainWindow.webContents.on("context-menu", (event, params) => {
    event.preventDefault();
    safeSend("native-context-menu", { x: params.x, y: params.y });
  });

  buildMenu();
}

// ── File import ────────────────────────────────────────────────────
async function importFile(filePath) {
  const tabId = `tab_${++tabCounter}_${Date.now()}`;
  let fileName; try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); }
  const ext = path.extname(filePath).toLowerCase();
  dbg("IMPORT", `importFile called`, { filePath, tabId, ext });

  // For XLSX, check for multiple sheets
  let sheetName = undefined;
  if (ext === ".xlsx" || ext === ".xls" || ext === ".xlsm") {
    try {
      dbg("IMPORT", `getXLSXSheets calling...`, { filePath });
      const sheets = await getXLSXSheets(filePath);
      dbg("IMPORT", `getXLSXSheets returned`, { sheetCount: sheets.length, sheets: sheets.map(s => s.name) });
      if (sheets.length > 1) {
        // Ask user which sheet
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
      // Continue with default sheet
    }
  }

  dbg("IMPORT", `calling startImport`, { tabId, sheetName });
  startImport(filePath, tabId, fileName, sheetName);
}

async function startImport(filePath, tabId, fileName, sheetName) {
  dbg("IMPORT", `startImport begin`, { filePath, tabId, fileName, sheetName });
  // Get file size for large-file warnings
  let fileSize = 0;
  try { fileSize = fs.statSync(filePath).size; } catch {}
  dbg("IMPORT", `fileSize`, { fileSize });

  // Notify renderer that import has started
  safeSend("import-start", {
    tabId,
    fileName,
    filePath,
    fileSize,
  });

  try {
    dbg("IMPORT", `calling parseFile...`);
    const result = await parseFile(filePath, tabId, db, (rows, bytesRead, totalBytes) => {
      safeSend("import-progress", {
        tabId,
        rowsImported: rows,
        bytesRead,
        totalBytes,
        percent: totalBytes > 0 ? Math.round((bytesRead / totalBytes) * 100) : 0,
      });
    }, sheetName);
    dbg("IMPORT", `parseFile complete`, { headers: result.headers?.length, rowCount: result.rowCount, tsColumns: result.tsColumns?.length });

    // Fetch initial window of data (windowed — not all rows)
    dbg("IMPORT", `querying initial rows...`);
    const initialData = db.queryRows(tabId, {
      offset: 0,
      limit: 5000,
      sortCol: null,
      sortDir: "asc",
    });
    dbg("IMPORT", `initial rows fetched`, { rowCount: initialData.rows?.length, totalFiltered: initialData.totalFiltered });

    const emptyColumns = db.getEmptyColumns(tabId);
    dbg("IMPORT", `sending import-complete`);

    safeSend("import-complete", {
      tabId,
      fileName,
      headers: result.headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns || [],
      initialRows: initialData.rows,
      totalFiltered: initialData.totalFiltered,
      emptyColumns,
    });

    // Defer index/FTS builds when more imports are queued to avoid memory spikes
    if (_importQueue.length > 0) {
      dbg("IMPORT", `Deferring index/FTS build for ${tabId} (${_importQueue.length} imports queued)`);
      _pendingIndexTabs.push(tabId);
    } else {
      // No more imports queued — build immediately
      db.buildIndexesAsync(tabId, (progress) => {
        safeSend("index-progress", { tabId, ...progress });
      }).then(() => {
        return db.buildFtsAsync(tabId, (progress) => {
          safeSend("fts-progress", { tabId, ...progress });
        });
      }).catch((err) => {
        console.error(`Index/FTS build failed for tab ${tabId}:`, err?.message || err);
        safeSend("fts-progress", { tabId, indexed: 0, total: 0, done: true, error: err?.message });
      });
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

// ── IPC Handlers ───────────────────────────────────────────────────

// Open file dialog
safeHandle("open-file-dialog", async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openFile", "multiSelections"],
    filters: [
      { name: "Timeline Files", extensions: ["csv", "tsv", "txt", "log", "xlsx", "xls", "plaso", "evtx"] },
      { name: "CSV Files", extensions: ["csv", "tsv", "txt", "log"] },
      { name: "Excel Files", extensions: ["xlsx", "xls", "xlsm"] },
      { name: "Plaso Files", extensions: ["plaso"] },
      { name: "EVTX Files", extensions: ["evtx"] },
      { name: "All Files", extensions: ["*"] },
    ],
  });
  if (result.canceled) return null;
  for (const fp of result.filePaths) enqueueImport(fp);
  return true;
});

// Query rows (the main data fetch for virtual scrolling)
safeHandle("query-rows", (event, { tabId, options }) => {
  return db.queryRows(tabId, options);
});

// Toggle bookmark
safeHandle("toggle-bookmark", (event, { tabId, rowId }) => {
  return db.toggleBookmark(tabId, rowId);
});

// Bulk set bookmarks
safeHandle("set-bookmarks", (event, { tabId, rowIds, add }) => {
  db.setBookmarks(tabId, rowIds, add);
  return true;
});

// Get bookmark count
safeHandle("get-bookmark-count", (event, { tabId }) => {
  return db.getBookmarkCount(tabId);
});

// Tag operations
safeHandle("add-tag", (event, { tabId, rowId, tag }) => {
  db.addTag(tabId, rowId, tag);
  return true;
});

safeHandle("remove-tag", (event, { tabId, rowId, tag }) => {
  db.removeTag(tabId, rowId, tag);
  return true;
});

safeHandle("get-all-tags", (event, { tabId }) => {
  return db.getAllTags(tabId);
});

safeHandle("get-all-tag-data", (event, { tabId }) => {
  return db.getAllTagData(tabId);
});

safeHandle("get-bookmarked-ids", (event, { tabId }) => {
  return db.getBookmarkedIds(tabId);
});

safeHandle("bulk-add-tags", (event, { tabId, tagMap }) => {
  db.bulkAddTags(tabId, tagMap);
  return true;
});

// IOC matching
safeHandle("load-ioc-file", async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openFile"],
    filters: [
      { name: "IOC Files", extensions: ["txt", "csv", "ioc", "tsv", "xlsx", "xls"] },
      { name: "All Files", extensions: ["*"] },
    ],
    title: "Open IOC List",
  });
  if (result.canceled || !result.filePaths.length) return null;
  const filePath = result.filePaths[0];
  const fileName = path.basename(filePath);
  const ext = path.extname(filePath).toLowerCase();
  // Common IOC value column names (lowercase for matching)
  const IOC_VALUE_HEADERS = new Set([
    "ioc_value", "ioc", "indicator", "value", "observable", "artifact",
    "indicator_value", "observable_value", "ioc_data", "data", "pattern",
  ]);

  // Detect IOC value column index from a header row
  function findIocColumn(headerRow) {
    if (!headerRow || headerRow.length === 0) return -1;
    for (let i = 0; i < headerRow.length; i++) {
      const h = String(headerRow[i]).trim().toLowerCase().replace(/[\s-]+/g, "_");
      if (IOC_VALUE_HEADERS.has(h)) return i;
    }
    return -1;
  }

  // Check if a row looks like a header (all cells are short non-IOC-like strings)
  function looksLikeHeader(row) {
    return row.length > 1 && row.every((c) => {
      const s = String(c).trim();
      return s.length < 30 && /^[a-zA-Z_\s-]+$/.test(s);
    });
  }

  try {
    if (ext === ".xlsx" || ext === ".xls") {
      const XLSX = require("xlsx");
      const wb = XLSX.readFile(filePath);
      const values = [];
      for (const sheetName of wb.SheetNames) {
        const sheet = wb.Sheets[sheetName];
        const rows = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: "" });
        if (rows.length === 0) continue;
        // Try to detect structured data with a header row
        const iocCol = looksLikeHeader(rows[0]) ? findIocColumn(rows[0]) : -1;
        if (iocCol >= 0) {
          // Structured: extract only the IOC value column, skip header
          for (let r = 1; r < rows.length; r++) {
            const v = String(rows[r][iocCol] || "").trim();
            if (v) values.push(v);
          }
        } else {
          // Flat list or unknown structure: extract all cells
          for (const row of rows) {
            for (const cell of row) {
              const v = String(cell).trim();
              if (v) values.push(v);
            }
          }
        }
      }
      return { content: values.join("\n"), fileName };
    }
    // Plain text formats: .txt, .csv, .ioc, .tsv
    let raw = fs.readFileSync(filePath, "utf-8");
    if (ext === ".csv" || ext === ".tsv") {
      const delim = ext === ".tsv" ? "\t" : ",";
      const lines = raw.split(/\r?\n/);
      if (lines.length > 1) {
        const headerCells = lines[0].split(delim).map((c) => c.trim().replace(/^"|"$/g, ""));
        const iocCol = looksLikeHeader(headerCells) ? findIocColumn(headerCells) : -1;
        if (iocCol >= 0) {
          // Structured CSV/TSV: extract only IOC value column, skip header
          const values = [];
          for (let i = 1; i < lines.length; i++) {
            const cells = lines[i].split(delim).map((c) => c.trim().replace(/^"|"$/g, ""));
            const v = (cells[iocCol] || "").trim();
            if (v) values.push(v);
          }
          raw = values.join("\n");
        } else {
          // No recognized header: split all cells onto separate lines
          raw = lines.map((l) => l.split(delim).map((c) => c.trim().replace(/^"|"$/g, "")).join("\n")).join("\n");
        }
      }
    }
    return { content: raw, fileName };
  } catch (e) {
    return { error: e.message };
  }
});

safeHandle("match-iocs", (event, { tabId, iocPatterns, batchSize }) => {
  return db.matchIocs(tabId, iocPatterns, batchSize || 200);
});

// Close tab
safeHandle("close-tab", (event, { tabId }) => {
  db.closeTab(tabId);
  return true;
});

// Get column stats
safeHandle("get-column-stats", (event, { tabId, colName, options }) => {
  return db.getColumnStats(tabId, colName, options);
});

// Get unique values for a column (checkbox filter dropdown)
safeHandle("get-column-unique-values", (event, { tabId, colName, options }) => {
  return db.getColumnUniqueValues(tabId, colName, options);
});

// Get columns that are entirely empty
safeHandle("get-empty-columns", (event, { tabId }) => {
  return db.getEmptyColumns(tabId);
});

// Get group values with counts (column grouping)
safeHandle("get-group-values", (event, { tabId, groupCol, options }) => {
  return db.getGroupValues(tabId, groupCol, options);
});

// Export filtered data (CSV, TSV, XLSX, XLS)
safeHandle("export-filtered", async (event, { tabId, options }) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: `filtered_export.csv`,
    filters: [
      { name: "CSV (Comma-separated)", extensions: ["csv"] },
      { name: "TSV (Tab-separated)", extensions: ["tsv"] },
      { name: "Excel Workbook (.xlsx)", extensions: ["xlsx"] },
      { name: "Excel 97-2003 (.xls)", extensions: ["xls"] },
    ],
  });
  if (result.canceled) return false;

  const exportData = db.exportQuery(tabId, options);
  if (!exportData) return false;

  const ext = path.extname(result.filePath).toLowerCase();

  // Excel export (XLSX or XLS)
  if (ext === ".xlsx" || ext === ".xls") {
    const ExcelJS = require("exceljs");
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet("Export");

    // Add header row
    sheet.addRow(exportData.headers);
    // Style header
    const headerRow = sheet.getRow(1);
    headerRow.font = { bold: true };
    headerRow.eachCell((cell) => {
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF161B22" } };
      cell.font = { bold: true, color: { argb: "FF58A6FF" } };
    });

    // Stream rows
    let count = 0;
    for (const rawRow of exportData.iterator) {
      const values = exportData.safeCols.map((sc) => rawRow[sc] || "");
      sheet.addRow(values);
      count++;
      if (count % 100000 === 0) {
        safeSend("export-progress", { count });
      }
    }

    // Auto-fit column widths (approximate)
    sheet.columns.forEach((col, i) => {
      const header = exportData.headers[i] || "";
      let maxLen = header.length;
      col.eachCell({ includeEmpty: false }, (cell) => {
        const len = cell.value ? String(cell.value).length : 0;
        if (len > maxLen) maxLen = len;
      });
      col.width = Math.min(Math.max(maxLen + 2, 8), 60);
    });

    if (ext === ".xls") {
      // XLS: write as XLSX buffer then save (ExcelJS outputs OOXML; .xls extension for compat)
      await workbook.xlsx.writeFile(result.filePath);
    } else {
      await workbook.xlsx.writeFile(result.filePath);
    }
    return { count, filePath: result.filePath };
  }

  // Delimited text export (CSV or TSV)
  const delimiter = ext === ".tsv" ? "\t" : ",";
  const writeStream = fs.createWriteStream(result.filePath, { encoding: "utf-8" });

  // Write header
  writeStream.write(exportData.headers.join(delimiter) + "\n");

  // Stream rows
  let count = 0;
  for (const rawRow of exportData.iterator) {
    const values = exportData.safeCols.map((sc) => {
      const val = rawRow[sc] || "";
      if (delimiter === "\t") {
        // TSV: escape tabs and newlines within values
        return val.includes("\t") || val.includes("\n") ? val.replace(/\t/g, " ").replace(/\n/g, " ") : val;
      }
      // CSV: quote fields containing comma, quote, or newline
      return val.includes(",") || val.includes('"') || val.includes("\n")
        ? `"${val.replace(/"/g, '""')}"`
        : val;
    });
    writeStream.write(values.join(delimiter) + "\n");
    count++;
    if (count % 100000 === 0) {
      safeSend("export-progress", { count });
    }
  }

  writeStream.end();
  return { count, filePath: result.filePath };
});

// Generate HTML report from bookmarked/tagged events
safeHandle("generate-report", async (event, { tabId, fileName, tagColors }) => {
  const reportData = db.getReportData(tabId);
  if (!reportData) return { error: "No data available" };

  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: `${fileName.replace(/\.[^.]+$/, "")}_report.html`,
    filters: [{ name: "HTML Report", extensions: ["html"] }],
  });
  if (result.canceled) return null;

  const html = buildReportHtml(reportData, fileName, tagColors);
  fs.writeFileSync(result.filePath, html, "utf-8");
  return { filePath: result.filePath };
});

// Sheet selection response (for multi-sheet XLSX)
safeHandle("select-sheet", (event, { filePath, tabId, fileName, sheetName }) => {
  startImport(filePath, tabId, fileName, sheetName);
});

// Get tab info
safeHandle("get-tab-info", (event, { tabId }) => {
  return db.getTabInfo(tabId);
});

// FTS build status check
safeHandle("get-fts-status", (event, { tabId }) => {
  return db.getFtsStatus(tabId);
});

// Search count across a tab (for cross-tab find)
safeHandle("search-count", (event, { tabId, searchTerm, searchMode, searchCondition }) => {
  return db.searchCount(tabId, searchTerm, searchMode, searchCondition);
});

// Histogram data for timeline visualization
safeHandle("get-histogram-data", (event, { tabId, colName, options }) => {
  return db.getHistogramData(tabId, colName, options);
});

safeHandle("get-stacking-data", (event, { tabId, colName, options }) => {
  return db.getStackingData(tabId, colName, options);
});

safeHandle("get-gap-analysis", (event, { tabId, colName, gapThresholdMinutes, options }) => {
  return db.getGapAnalysis(tabId, colName, gapThresholdMinutes, options);
});

safeHandle("get-log-source-coverage", (event, { tabId, sourceCol, tsCol, options }) => {
  return db.getLogSourceCoverage(tabId, sourceCol, tsCol, options);
});

safeHandle("get-burst-analysis", (event, { tabId, colName, windowMinutes, thresholdMultiplier, options }) => {
  return db.getBurstAnalysis(tabId, colName, windowMinutes, thresholdMultiplier, options);
});

safeHandle("get-process-tree", (event, { tabId, options }) => {
  return db.getProcessTree(tabId, options);
});

safeHandle("get-lateral-movement", (event, { tabId, options }) => {
  return db.getLateralMovement(tabId, options);
});

safeHandle("get-persistence-analysis", (event, { tabId, options }) => {
  return db.getPersistenceAnalysis(tabId, options);
});

safeHandle("bulk-tag-by-time-range", (event, { tabId, colName, ranges }) => {
  return db.bulkTagByTimeRange(tabId, colName, ranges);
});

safeHandle("bulk-tag-filtered", (event, { tabId, tag, options }) => {
  return db.bulkTagFiltered(tabId, tag, options);
});

safeHandle("bulk-bookmark-filtered", (event, { tabId, add, options }) => {
  return db.bulkBookmarkFiltered(tabId, add, options);
});

// Merge multiple tabs into a single chronological timeline
safeHandle("merge-tabs", async (event, { mergedTabId, sources }) => {
  try {
    safeSend("import-start", {
      tabId: mergedTabId,
      fileName: "Merged Timeline",
      filePath: "(merged)",
    });

    const result = db.mergeTabs(mergedTabId, sources, (progress) => {
      safeSend("import-progress", {
        tabId: mergedTabId,
        rowsImported: progress.current,
        bytesRead: progress.current,
        totalBytes: progress.total,
        percent: progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0,
      });
    });

    // Fetch initial window sorted by unified datetime
    const initialData = db.queryRows(mergedTabId, {
      offset: 0,
      limit: 5000,
      sortCol: "datetime",
      sortDir: "asc",
    });

    const emptyColumns = db.getEmptyColumns(mergedTabId);

    safeSend("import-complete", {
      tabId: mergedTabId,
      fileName: "Merged Timeline",
      headers: result.headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns || [],
      initialRows: initialData.rows,
      totalFiltered: initialData.totalFiltered,
      emptyColumns,
    });

    return { success: true, rowCount: result.rowCount };
  } catch (err) {
    try { db.closeTab(mergedTabId); } catch (_) {}
    safeSend("import-error", {
      tabId: mergedTabId,
      fileName: "Merged Timeline",
      error: err.message,
    });
    return { success: false, error: err.message };
  }
});

// Session save
safeHandle("save-session", async (event, { sessionData }) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: "session.tle",
    filters: [{ name: "TLE Session", extensions: ["tle"] }],
  });
  if (result.canceled) return null;
  fs.writeFileSync(result.filePath, JSON.stringify(sessionData, null, 2), "utf-8");
  return result.filePath;
});

// Session load
safeHandle("load-session", async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openFile"],
    filters: [{ name: "TLE Session", extensions: ["tle"] }],
  });
  if (result.canceled || !result.filePaths.length) return null;
  try {
    const raw = fs.readFileSync(result.filePaths[0], "utf-8");
    return JSON.parse(raw);
  } catch (e) {
    return { error: e.message };
  }
});

// Import file for session restore (no dialog)
// Import files by path (used for drag-and-drop)
safeHandle("import-files", async (event, { filePaths }) => {
  for (const fp of filePaths) { if (fs.existsSync(fp)) enqueueImport(fp); }
  return true;
});

safeHandle("import-file-for-restore", async (event, { filePath, sheetName }) => {
  if (!fs.existsSync(filePath)) return { error: `File not found: ${filePath}` };
  const tabId = `tab_${++tabCounter}_${Date.now()}`;
  let fileName; try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); }
  startImport(filePath, tabId, fileName, sheetName || undefined);
  return { tabId, fileName };
});

// ── Filter Presets (persistent storage) ─────────────────────────────
const presetsPath = path.join(app.getPath("userData"), "filter-presets.json");

safeHandle("load-filter-presets", () => {
  try { return JSON.parse(fs.readFileSync(presetsPath, "utf-8")); }
  catch { return []; }
});

safeHandle("save-filter-presets", (event, { presets }) => {
  fs.writeFileSync(presetsPath, JSON.stringify(presets, null, 2));
  return true;
});

// ── Native macOS Menu ──────────────────────────────────────────────
function buildMenu() {
  const template = [
    {
      label: "IRFlow Timeline",
      submenu: [
        { role: "about" },
        { type: "separator" },
        { role: "services" },
        { type: "separator" },
        { role: "hide" },
        { role: "hideOthers" },
        { role: "unhide" },
        { type: "separator" },
        { role: "quit" },
      ],
    },
    {
      label: "File",
      submenu: [
        {
          label: "Open...",
          accelerator: "CmdOrCtrl+O",
          click: () => mainWindow?.webContents.send("trigger-open"),
        },
        { type: "separator" },
        {
          label: "Save Session...",
          accelerator: "CmdOrCtrl+S",
          click: () => mainWindow?.webContents.send("trigger-save-session"),
        },
        {
          label: "Open Session...",
          accelerator: "CmdOrCtrl+Shift+O",
          click: () => mainWindow?.webContents.send("trigger-load-session"),
        },
        { type: "separator" },
        {
          label: "Export Filtered View...",
          accelerator: "CmdOrCtrl+E",
          click: () => mainWindow?.webContents.send("trigger-export"),
        },
        {
          label: "Generate Report...",
          accelerator: "CmdOrCtrl+Shift+R",
          click: () => mainWindow?.webContents.send("trigger-generate-report"),
        },
        { type: "separator" },
        {
          label: "Close Tab",
          accelerator: "CmdOrCtrl+W",
          click: () => mainWindow?.webContents.send("trigger-close-tab"),
        },
        {
          label: "Close All Tabs",
          accelerator: "CmdOrCtrl+Shift+Q",
          click: () => mainWindow?.webContents.send("trigger-close-all-tabs"),
        },
        { type: "separator" },
        { role: "close" },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" }, { role: "redo" }, { type: "separator" },
        { role: "cut" }, { role: "copy" }, { role: "paste" }, { role: "selectAll" },
        { type: "separator" },
        {
          label: "Find...",
          accelerator: "CmdOrCtrl+F",
          click: () => mainWindow?.webContents.send("trigger-search"),
        },
        {
          label: "Find in All Tabs...",
          accelerator: "CmdOrCtrl+Shift+F",
          click: () => mainWindow?.webContents.send("trigger-crossfind"),
        },
      ],
    },
    {
      label: "Tools",
      submenu: [
        {
          label: "Datetime Format",
          submenu: [
            { label: "Default (raw)", click: () => mainWindow?.webContents.send("set-datetime-format", "") },
            { label: "yyyy-MM-dd HH:mm:ss", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd HH:mm:ss") },
            { label: "yyyy-MM-dd HH:mm:ss.fff", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd HH:mm:ss.fff") },
            { label: "yyyy-MM-dd HH:mm:ss.fffffff", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd HH:mm:ss.fffffff") },
            { label: "MM/dd/yyyy HH:mm:ss", click: () => mainWindow?.webContents.send("set-datetime-format", "MM/dd/yyyy HH:mm:ss") },
            { label: "dd/MM/yyyy HH:mm:ss", click: () => mainWindow?.webContents.send("set-datetime-format", "dd/MM/yyyy HH:mm:ss") },
            { label: "yyyy-MM-dd", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd") },
          ],
        },
        {
          label: "Timezone",
          submenu: [
            { label: "UTC", click: () => mainWindow?.webContents.send("set-timezone", "UTC") },
            { label: "US/Eastern (EST/EDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/New_York") },
            { label: "US/Central (CST/CDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/Chicago") },
            { label: "US/Mountain (MST/MDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/Denver") },
            { label: "US/Pacific (PST/PDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/Los_Angeles") },
            { label: "Europe/London (GMT/BST)", click: () => mainWindow?.webContents.send("set-timezone", "Europe/London") },
            { label: "Europe/Berlin (CET/CEST)", click: () => mainWindow?.webContents.send("set-timezone", "Europe/Berlin") },
            { label: "Asia/Tokyo (JST)", click: () => mainWindow?.webContents.send("set-timezone", "Asia/Tokyo") },
            { label: "Asia/Shanghai (CST)", click: () => mainWindow?.webContents.send("set-timezone", "Asia/Shanghai") },
            { label: "Australia/Sydney (AEST/AEDT)", click: () => mainWindow?.webContents.send("set-timezone", "Australia/Sydney") },
            { label: "Local (system)", click: () => mainWindow?.webContents.send("set-timezone", "local") },
          ],
        },
        { type: "separator" },
        {
          label: "Font Size",
          submenu: [
            { label: "Increase", accelerator: "CmdOrCtrl+Plus", click: () => mainWindow?.webContents.send("set-font-size", "increase") },
            { label: "Decrease", accelerator: "CmdOrCtrl+-", click: () => mainWindow?.webContents.send("set-font-size", "decrease") },
            { type: "separator" },
            ...[9, 10, 11, 12, 13, 14, 16, 18].map((s) => ({
              label: `${s}px`, click: () => mainWindow?.webContents.send("set-font-size", s),
            })),
          ],
        },
        { type: "separator" },
        {
          label: "Reset Column Widths",
          accelerator: "CmdOrCtrl+R",
          click: () => mainWindow?.webContents.send("trigger-reset-columns"),
        },
        {
          label: "Toggle Histogram",
          click: () => mainWindow?.webContents.send("trigger-histogram"),
        },
        { type: "separator" },
        {
          label: "Theme",
          submenu: [
            { label: "Dark", click: () => mainWindow?.webContents.send("set-theme", "dark") },
            { label: "Light", click: () => mainWindow?.webContents.send("set-theme", "light") },
          ],
        },
      ],
    },
    {
      label: "View",
      submenu: [
        {
          label: "Toggle Bookmarked Only",
          accelerator: "CmdOrCtrl+B",
          click: () => mainWindow?.webContents.send("trigger-bookmark-toggle"),
        },
        {
          label: "Column Manager",
          accelerator: "CmdOrCtrl+Shift+C",
          click: () => mainWindow?.webContents.send("trigger-column-manager"),
        },
        {
          label: "Conditional Formatting",
          accelerator: "CmdOrCtrl+Shift+L",
          click: () => mainWindow?.webContents.send("trigger-color-rules"),
        },
        { type: "separator" },
        { role: "togglefullscreen" },
        { type: "separator" },
        { role: "zoomIn" }, { role: "zoomOut" }, { role: "resetZoom" },
        { type: "separator" },
        { role: "toggleDevTools" },
      ],
    },
    {
      label: "Window",
      submenu: [{ role: "minimize" }, { role: "zoom" }, { type: "separator" }, { role: "front" }],
    },
    {
      label: "Help",
      submenu: [
        {
          label: "Keyboard Shortcuts",
          accelerator: "CmdOrCtrl+/",
          click: () => mainWindow?.webContents.send("trigger-shortcuts"),
        },
        { type: "separator" },
        {
          label: "EZ Tools Website",
          click: () => shell.openExternal("https://ericzimmerman.github.io/"),
        },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ── HTML Report Builder ──────────────────────────────────────────
function buildReportHtml(data, fileName, tagColors = {}) {
  const esc = (s) => String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const now = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  // Filter out columns that are entirely empty across bookmarked+tagged rows
  const allReportRows = [...data.bookmarkedRows];
  for (const rows of Object.values(data.taggedGroups)) {
    for (const r of rows) allReportRows.push(r);
  }
  const usedHeaders = data.headers.filter((h) =>
    allReportRows.some((r) => r[h] && String(r[h]).trim())
  );

  const renderTable = (rows, headers) => {
    if (rows.length === 0) return '<p style="color:#9a9590;font-style:italic;">No events</p>';
    let html = '<div class="table-wrap"><table><thead><tr>';
    for (const h of headers) html += `<th>${esc(h)}</th>`;
    html += "</tr></thead><tbody>";
    for (const row of rows) {
      html += "<tr>";
      for (const h of headers) html += `<td>${esc(row[h])}</td>`;
      html += "</tr>";
    }
    html += "</tbody></table></div>";
    return html;
  };

  let body = "";

  // Header
  body += `<div class="report-header">
    <h1>IRFlow Timeline Report</h1>
    <div class="meta">
      <span>Source: <strong>${esc(fileName)}</strong></span>
      <span>Generated: <strong>${now}</strong></span>
    </div>
  </div>`;

  // Summary cards
  body += `<div class="cards">
    <div class="card"><div class="card-val">${data.totalRows.toLocaleString()}</div><div class="card-label">Total Rows</div></div>
    <div class="card"><div class="card-val">${data.bookmarkCount.toLocaleString()}</div><div class="card-label">Bookmarked</div></div>
    <div class="card"><div class="card-val">${data.taggedRowCount.toLocaleString()}</div><div class="card-label">Tagged Rows</div></div>
    <div class="card"><div class="card-val">${data.tagCount}</div><div class="card-label">Unique Tags</div></div>
  </div>`;

  // Timestamp range
  if (data.tsRange) {
    body += `<div class="ts-range">
      <strong>Timeline Span (${esc(data.tsRange.column)}):</strong>
      ${esc(data.tsRange.earliest)} &mdash; ${esc(data.tsRange.latest)}
    </div>`;
  }

  // Tag breakdown chips
  if (data.tagSummary.length > 0) {
    body += '<div class="section"><h2>Tag Breakdown</h2><div class="tag-chips">';
    for (const { tag, cnt } of data.tagSummary) {
      const color = tagColors[tag] || "#8b949e";
      body += `<span class="tag-chip" style="border-color:${color};color:${color};background:${color}22">${esc(tag)} <strong>${cnt}</strong></span>`;
    }
    body += "</div></div>";
  }

  // Bookmarked events table
  if (data.bookmarkedRows.length > 0) {
    body += `<div class="section"><h2>Bookmarked Events (${data.bookmarkCount})</h2>`;
    body += renderTable(data.bookmarkedRows, usedHeaders);
    body += "</div>";
  }

  // Tagged event tables (one per tag)
  for (const { tag, cnt } of data.tagSummary) {
    const rows = data.taggedGroups[tag] || [];
    if (rows.length === 0) continue;
    const color = tagColors[tag] || "#8b949e";
    body += `<div class="section">
      <h2><span class="tag-badge" style="background:${color}33;color:${color};border:1px solid ${color}66">${esc(tag)}</span> (${cnt} events)</h2>`;
    body += renderTable(rows, usedHeaders);
    body += "</div>";
  }

  // Empty report fallback
  if (data.bookmarkedRows.length === 0 && data.tagSummary.length === 0) {
    body += '<div class="section"><p style="color:#9a9590;font-style:italic;text-align:center;padding:40px 0;">No bookmarked or tagged events to include in report.<br>Bookmark events with the star icon or tag them to include in the report.</p></div>';
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IRFlow Report — ${esc(fileName)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f1114;color:#e0ddd8;font-family:-apple-system,'SF Pro Text','Segoe UI',sans-serif;font-size:13px;padding:30px;max-width:1400px;margin:0 auto}
.report-header{border-bottom:2px solid #E85D2A;padding-bottom:16px;margin-bottom:24px}
.report-header h1{font-size:22px;font-weight:700;color:#E85D2A}
.meta{display:flex;gap:24px;color:#9a9590;font-size:12px;margin-top:6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:#181b20;border:1px solid #2a2d33;border-radius:8px;padding:16px;text-align:center}
.card-val{font-size:24px;font-weight:700;color:#E85D2A}
.card-label{font-size:11px;color:#9a9590;text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
.ts-range{background:#181b20;border:1px solid #2a2d33;border-radius:6px;padding:10px 16px;margin-bottom:24px;font-size:12px;color:#9a9590}
.section{margin-bottom:32px}
.section h2{font-size:16px;font-weight:600;margin-bottom:12px;color:#e0ddd8;display:flex;align-items:center;gap:8px}
.tag-chips{display:flex;flex-wrap:wrap;gap:8px}
.tag-chip{padding:4px 12px;border:1px solid;border-radius:20px;font-size:12px}
.tag-chip strong{margin-left:4px}
.tag-badge{padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600}
.table-wrap{overflow-x:auto;border:1px solid #2a2d33;border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:11px;font-family:'SF Mono','Fira Code',Menlo,monospace}
th{position:sticky;top:0;background:#181b20;color:#E85D2A;padding:8px 10px;text-align:left;border-bottom:2px solid #2a2d33;white-space:nowrap;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.04em}
td{padding:5px 10px;border-bottom:1px solid #1a1d22;color:#e0ddd8;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:nth-child(even){background:#141720}
tr:hover{background:rgba(232,93,42,.08)}
footer{margin-top:40px;padding-top:16px;border-top:1px solid #2a2d33;color:#5c5752;font-size:10px;text-align:center}
@media print{body{background:#fff;color:#1c1917}th{background:#f7f5f3;color:#E85D2A}td{color:#1c1917;border-color:#e0dbd6}.card{border-color:#e0dbd6;background:#faf8f6}tr:nth-child(even){background:#faf8f6}.report-header{border-color:#E85D2A}.ts-range{background:#faf8f6;border-color:#e0dbd6}}
</style>
</head>
<body>
${body}
<footer>Generated by IRFlow Timeline &mdash; ${now}</footer>
</body>
</html>`;
}

app.whenReady().then(createWindow);
