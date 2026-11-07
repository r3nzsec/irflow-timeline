/**
 * sigma/kape-output-scanner.js — direct Sigma scan for validated EvtxECmd CSV/XLS/XLSX output.
 *
 * This builds a temporary `data` table using the existing import parsers,
 * scans it with the JS Sigma compatibility engine, then persists detections in
 * the normal SigmaResultStore format.
 *
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const Database = require("../../db/duckdb");

const { parseCSVLine, parseCSVStream, detectDelimiter } = require("../../parsers/csv");
const { parseXLSFile, parseXLSXStream } = require("../../parsers/xlsx");
const { scanSigmaRules } = require("./index");
const { SigmaResultStore, createTempResultPath } = require("./result-store");

const SUPPORTED_EXTS = new Set([".csv", ".tsv", ".xlsx", ".xls", ".xlsm"]);
const TEXT_EXTS = new Set([".csv", ".tsv"]);
const SPREADSHEET_EXTS = new Set([".xlsx", ".xls", ".xlsm"]);
const MAX_FILE_PREVIEW = 80;
const MAX_IGNORED_PREVIEW = 40;
const HEADER_READ_BYTES = 256 * 1024;

function safeFileName(filePath) {
  try { return decodeURIComponent(path.basename(filePath)); } catch { return path.basename(filePath); }
}

function fileSize(filePath) {
  try { return fs.statSync(filePath).size; } catch { return 0; }
}

function normalizeHeaderKey(header) {
  return String(header || "")
    .trim()
    .toLowerCase()
    .replace(/^\uFEFF/, "")
    .replace(/[^a-z0-9]/g, "");
}

function hasHeader(keys, aliases) {
  return aliases.some((alias) => keys.has(alias));
}

function classifyEvtxEcmdHeaders(headers = []) {
  const normalizedHeaders = (headers || []).map((h) => String(h || "").trim()).filter(Boolean);
  const keys = new Set(normalizedHeaders.map(normalizeHeaderKey).filter(Boolean));
  const specificKeys = normalizedHeaders
    .map(normalizeHeaderKey)
    .filter((key) => /^payloaddata\d+$/.test(key) || [
      "mapdescription",
      "executableinfo",
      "remotehost",
      "payload",
      "eventdata",
      "eventxml",
      "userid",
      "username",
    ].includes(key));

  const signals = {
    time: hasHeader(keys, ["timecreated", "timestamp", "datetime", "eventtime", "eventtimestamp", "timegenerated"]),
    eventId: hasHeader(keys, ["eventid", "eventidentifier", "eid", "id"]),
    provider: hasHeader(keys, ["provider", "providername", "sourcename"]),
    channel: hasHeader(keys, ["channel", "logname", "eventlog", "eventlogname"]),
    computer: hasHeader(keys, ["computer", "computername", "hostname", "machinename", "systemcomputer"]),
    evtxEcmdSpecific: specificKeys.length,
  };
  const coreCount = [signals.time, signals.eventId, signals.provider, signals.channel, signals.computer].filter(Boolean).length;
  const valid = signals.time
    && signals.eventId
    && coreCount >= 3
    && (signals.evtxEcmdSpecific > 0 || (signals.provider && signals.channel && signals.computer));

  let reason = "Valid EvtxECmd/event-log output header";
  if (!valid) {
    const missing = [];
    if (!signals.time) missing.push("timestamp column");
    if (!signals.eventId) missing.push("EventID column");
    if (coreCount < 3) missing.push("event-log context columns");
    if (signals.evtxEcmdSpecific === 0 && !(signals.provider && signals.channel && signals.computer)) {
      missing.push("EvtxECmd payload/header signature");
    }
    reason = `Missing ${missing.join(", ")}`;
  }

  return {
    valid,
    reason,
    headers: normalizedHeaders,
    signals,
  };
}

function readDelimitedHeader(filePath) {
  const fd = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.alloc(HEADER_READ_BYTES);
    const bytesRead = fs.readSync(fd, buffer, 0, HEADER_READ_BYTES, 0);
    if (bytesRead <= 0) return [];
    const checkLen = Math.min(bytesRead, 8192);
    for (let i = 0; i < checkLen; i++) {
      if (buffer[i] === 0) throw new Error("binary file");
    }
    let content = buffer.toString("utf8", 0, bytesRead);
    if (content.charCodeAt(0) === 0xFEFF) content = content.slice(1);
    const newline = content.search(/\r?\n/);
    const firstLine = newline >= 0 ? content.slice(0, newline).replace(/\r$/, "") : content.trim();
    if (!firstLine) return [];
    const delimiter = detectDelimiter(firstLine);
    return parseCSVLine(firstLine, delimiter).map((h) => String(h || "").trim());
  } finally {
    fs.closeSync(fd);
  }
}

function readSpreadsheetHeader(filePath) {
  const XLSX = require("xlsx");
  const workbook = XLSX.readFile(filePath, { sheetRows: 1, cellDates: false });
  const sheetName = workbook.SheetNames?.[0];
  if (!sheetName) return [];
  const worksheet = workbook.Sheets[sheetName];
  const rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, raw: false, blankrows: false });
  return (rows[0] || []).map((h) => String(h || "").trim());
}

function inspectKapeOutputFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const base = { path: filePath, name: safeFileName(filePath), size: fileSize(filePath), ext };
  if (!SUPPORTED_EXTS.has(ext)) {
    return { ...base, valid: false, reason: `Unsupported file type ${ext || "(none)"}` };
  }
  try {
    const headers = TEXT_EXTS.has(ext)
      ? readDelimitedHeader(filePath)
      : SPREADSHEET_EXTS.has(ext)
        ? readSpreadsheetHeader(filePath)
        : [];
    const classification = classifyEvtxEcmdHeaders(headers);
    return {
      ...base,
      valid: classification.valid,
      reason: classification.reason,
      headers: classification.headers,
      signals: classification.signals,
    };
  } catch (err) {
    return { ...base, valid: false, reason: `Could not read header: ${err.message || String(err)}` };
  }
}

function collectKapeOutputSelection(paths = []) {
  const files = [];
  const ignoredFiles = [];
  const seen = new Set();
  const stats = {
    scannedFileCount: 0,
    candidateFileCount: 0,
    rejectedCandidateCount: 0,
    unsupportedFileCount: 0,
  };

  const rememberIgnored = (filePath, reason, ext = path.extname(filePath).toLowerCase()) => {
    if (ignoredFiles.length < MAX_IGNORED_PREVIEW) {
      ignoredFiles.push({ path: filePath, name: safeFileName(filePath), size: fileSize(filePath), ext, reason });
    }
  };

  const addFile = (filePath) => {
    let real;
    try { real = fs.realpathSync.native(filePath); } catch { return; }
    if (seen.has(real)) return;
    seen.add(real);
    stats.scannedFileCount++;
    const ext = path.extname(real).toLowerCase();
    if (!SUPPORTED_EXTS.has(ext)) {
      stats.unsupportedFileCount++;
      rememberIgnored(real, `Unsupported file type ${ext || "(none)"}`, ext);
      return;
    }
    stats.candidateFileCount++;
    const inspected = inspectKapeOutputFile(real);
    if (inspected.valid) {
      files.push(inspected);
    } else {
      stats.rejectedCandidateCount++;
      rememberIgnored(real, inspected.reason, ext);
    }
  };

  const walk = (targetPath) => {
    let stat;
    try { stat = fs.statSync(targetPath); } catch { return; }
    if (stat.isFile()) {
      addFile(targetPath);
      return;
    }
    if (!stat.isDirectory()) return;
    let entries = [];
    try { entries = fs.readdirSync(targetPath, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;
      const fullPath = path.join(targetPath, entry.name);
      if (entry.isDirectory()) walk(fullPath);
      else if (entry.isFile()) addFile(fullPath);
    }
  };
  for (const targetPath of paths || []) walk(targetPath);
  files.sort((a, b) => a.path.localeCompare(b.path));
  ignoredFiles.sort((a, b) => a.path.localeCompare(b.path));
  return {
    paths,
    files,
    ignoredFiles,
    ignoredCount: Math.max(0, stats.scannedFileCount - files.length),
    ...stats,
  };
}

function collectKapeOutputFiles(paths = []) {
  return collectKapeOutputSelection(paths).files;
}

class TempScanDb {
  constructor() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-kape-scan-source-"));
    this.dbPath = path.join(dir, "source.duckdb");
    this.db = new Database(this.dbPath);
    this.databases = new Map();
  }

  createTab(tabId, headers) {
    const safeHeaders = (headers || []).map((h, i) => String(h || `Column_${i + 1}`).trim() || `Column_${i + 1}`);
    const safeCols = safeHeaders.map((h, i) => ({ original: h, safe: `c${i}` }));
    const colDefs = safeCols.map((col) => `${col.safe} VARCHAR`).join(", ");
    this.db.exec("DROP TABLE IF EXISTS data");
    this.db.exec(`CREATE TABLE data (rowid BIGINT${colDefs ? ", " + colDefs : ""})`);
    const meta = {
      tabId,
      db: this.db,
      headers: safeHeaders,
      safeCols,
      rowCount: 0,
      colMap: Object.fromEntries(safeCols.map((c) => [c.original, c.safe])),
      reverseColMap: Object.fromEntries(safeCols.map((c) => [c.safe, c.original])),
    };
    this.databases.set(tabId, meta);
    this.meta = meta;
    return { tabId, headers: safeHeaders, tsColumns: [] };
  }

  insertBatchArrays(tabId, rows) {
    const meta = this.databases.get(tabId);
    if (!meta) throw new Error(`Temp scan tab ${tabId} not found`);
    const colCount = meta.headers.length;
    const batch = rows || [];
    const out = new Array(batch.length);
    for (let i = 0; i < batch.length; i++) {
      const row = batch[i] || [];
      const values = new Array(colCount + 1);
      values[0] = meta.rowCount + i + 1;
      for (let c = 0; c < colCount; c++) values[c + 1] = row[c] ?? "";
      out[i] = values;
    }
    meta.db.appendRows("data", out);
    meta.rowCount += batch.length;
    return meta.rowCount;
  }

  finalizeImport(tabId) {
    const meta = this.databases.get(tabId) || this.meta;
    return {
      rowCount: meta?.rowCount || 0,
      headers: meta?.headers || [],
      tsColumns: [],
      numericColumns: [],
    };
  }

  getMeta(tabId) {
    return this.databases.get(tabId) || this.meta;
  }

  close() {
    try { this.db.close(); } catch {}
    for (const suffix of ["", ".wal"]) {
      try { if (fs.existsSync(`${this.dbPath}${suffix}`)) fs.unlinkSync(`${this.dbPath}${suffix}`); } catch {}
    }
    try { fs.rmdirSync(path.dirname(this.dbPath)); } catch {}
  }
}

function mergeMatches(target, matches = []) {
  for (const match of matches || []) {
    const key = match.ruleId || match.title;
    if (!key) continue;
    if (!target.has(key)) {
      target.set(key, {
        ...match,
        matchCount: 0,
        hosts: [],
        sampleRows: [],
      });
    }
    const existing = target.get(key);
    existing.matchCount += Number(match.matchCount || 0) || 0;
    if (match.firstSeen && (!existing.firstSeen || match.firstSeen < existing.firstSeen)) existing.firstSeen = match.firstSeen;
    if (match.lastSeen && (!existing.lastSeen || match.lastSeen > existing.lastSeen)) existing.lastSeen = match.lastSeen;
    existing.hosts = [...new Set([...(existing.hosts || []), ...((match.hosts || []).map(String))])].slice(0, 1000);
    existing.sampleRows = [...(existing.sampleRows || []), ...(match.sampleRows || [])].slice(0, 5);
  }
}

async function parseIntoTempDb(filePath, tabId, onProgress) {
  const tempDb = new TempScanDb();
  const ext = path.extname(filePath).toLowerCase();
  try {
    if (ext === ".xls") {
      await Promise.resolve(parseXLSFile(filePath, tabId, tempDb, onProgress));
    } else if (ext === ".xlsx" || ext === ".xlsm") {
      await parseXLSXStream(filePath, tabId, tempDb, onProgress);
    } else {
      await parseCSVStream(filePath, tabId, tempDb, onProgress);
    }
    return tempDb;
  } catch (err) {
    tempDb.close();
    throw err;
  }
}

function sortMatches(matches) {
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  return matches.sort((a, b) => (sevOrder[a.level] ?? 5) - (sevOrder[b.level] ?? 5) || (b.matchCount || 0) - (a.matchCount || 0));
}

async function scanKapeOutputs(paths, options = {}, onProgress) {
  const startedAt = Date.now();
  const selection = collectKapeOutputSelection(paths);
  const files = selection.files;
  if (files.length === 0) {
    const ignoredSuffix = selection.ignoredCount ? ` ${selection.ignoredCount.toLocaleString()} unrelated or invalid file${selection.ignoredCount === 1 ? "" : "s"} ignored.` : "";
    return { matches: [], stats: { ignoredFiles: selection.ignoredCount || 0 }, errors: [`No valid EvtxECmd CSV/XLS/XLSX output files found.${ignoredSuffix}`], eventRows: [], eventRowsPreview: [], eventRowCount: 0, files: [], ignoredFiles: selection.ignoredFiles };
  }

  const finalStore = new SigmaResultStore({ dbPath: createTempResultPath() });
  const preview = [];
  const matchMap = new Map();
  const errors = [];
  const warnings = [];
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  let totalRowsScanned = 0;
  let totalRules = 0;
  let ruleCompatibility = null;
  let ruleSnapshotHash = null;
  let skippedSuppressedRules = 0;
  let totalMatches = 0;
  let eventRowCount = 0;
  let truncatedGroups = 0;
  let eventRowsCapped = false;

  const isCancelled = typeof options.isCancelled === "function" ? options.isCancelled : () => false;
  const assertNotCancelled = () => {
    if (isCancelled()) throw Object.assign(new Error("Job cancelled"), { cancelled: true });
  };

  try {
    for (let index = 0; index < files.length; index++) {
      assertNotCancelled();
      const file = files[index];
      const tabId = `kape_${crypto.randomBytes(4).toString("hex")}`;
      const filePrefix = `${index + 1}/${files.length}`;
      onProgress?.({
        phase: "kape-importing",
        fileIndex: index + 1,
        fileCount: files.length,
        fileName: file.name,
        pct: Math.round((index / files.length) * 100),
        text: `Reading ${filePrefix}: ${file.name}`,
      });
      let tempDb = null;
      let tempResultPath = null;
      try {
        tempDb = await parseIntoTempDb(file.path, tabId, (rowsImported, bytesRead, totalBytes) => {
          onProgress?.({
            phase: "kape-importing",
            fileIndex: index + 1,
            fileCount: files.length,
            fileName: file.name,
            rowsImported,
            bytesRead,
            totalBytes,
            pct: Math.min(99, Math.round(((index + (totalBytes ? bytesRead / totalBytes : 0)) / files.length) * 100)),
            text: `Reading ${filePrefix}: ${file.name} (${rowsImported.toLocaleString()} rows)`,
          });
        });
        assertNotCancelled();
        const meta = tempDb.getMeta(tabId);
        tempResultPath = createTempResultPath("tle-kape-scan-part");
        const result = await scanSigmaRules(meta, {
          ...options,
          resultStorePath: tempResultPath,
          previewLimit: 0,
          isCancelled,
        }, (progress) => {
          onProgress?.({
            ...progress,
            phase: progress?.phase === "done" ? "kape-file-done" : "kape-scanning",
            fileIndex: index + 1,
            fileCount: files.length,
            fileName: file.name,
            pct: Math.min(99, Math.round(((index + 0.5) / files.length) * 100)),
            text: `Scanning ${filePrefix}: ${file.name}`,
          });
        });
        totalRowsScanned += Number(result.stats?.rowsScanned || 0) || 0;
        totalRules = Math.max(totalRules, Number(result.stats?.totalRules || 0) || 0);
        skippedSuppressedRules = Math.max(skippedSuppressedRules, Number(result.stats?.skippedSuppressedRules || 0) || 0);
        ruleCompatibility = ruleCompatibility || result.stats?.ruleCompatibility || null;
        ruleSnapshotHash = ruleSnapshotHash || result.stats?.ruleSnapshotHash || null;
        truncatedGroups += Number(result.stats?.truncatedGroups || 0) || 0;
        eventRowsCapped = eventRowsCapped || !!result.stats?.eventRowsCapped;
        mergeMatches(matchMap, result.matches || []);
        errors.push(...(result.errors || []).map((e) => `${file.name}: ${e}`));
        warnings.push(...(result.warnings || []).map((w) => `${file.name}: ${w}`));

        if (result.resultDbPath) {
          const partStore = SigmaResultStore.open(result.resultDbPath);
          const batch = [];
          try {
            for (const row of partStore.iterateRows()) {
              const mergedRow = { ...row, _SourceFile: file.path };
              delete mergedRow.SourceTabId;
              delete mergedRow.SourceRowId;
              batch.push(mergedRow);
              if (preview.length < 2000) preview.push(mergedRow);
              if (batch.length >= 1000) {
                finalStore.addRows(batch.splice(0, batch.length));
              }
              eventRowCount++;
            }
            if (batch.length) finalStore.addRows(batch);
          } finally {
            partStore.close();
          }
        }
        SigmaResultStore.destroy(tempResultPath);
        tempResultPath = null;
      } catch (err) {
        if (err?.cancelled) throw err;
        errors.push(`${file.name}: ${err.message || String(err)}`);
      } finally {
        try { tempDb?.close(); } catch {}
        if (tempResultPath) SigmaResultStore.destroy(tempResultPath);
      }
    }

    const matches = sortMatches([...matchMap.values()]);
    for (const match of matches) {
      const level = String(match.level || "").toLowerCase();
      if (Object.prototype.hasOwnProperty.call(bySeverity, level)) bySeverity[level]++;
      totalMatches += Number(match.matchCount || 0) || 0;
    }
    const persisted = finalStore.finalize({
      engine: "IRFlow Sigma Engine",
      sourceFormat: "EvtxECmd output files",
    });
    const stats = {
      totalRules,
      matchedRules: matches.length,
      totalMatches,
      rowsScanned: totalRowsScanned,
      truncatedGroups,
      maxRowsPerQuery: options.maxRowsPerQuery || null,
      eventRowsCapped,
      eventRowCap: null,
      skippedSuppressedRules,
      bySeverity,
      format: "EvtxECmd",
      sourceFiles: files.length,
      sourceBytes: files.reduce((sum, file) => sum + (file.size || 0), 0),
      ignoredFiles: selection.ignoredCount || 0,
      rejectedCandidateFiles: selection.rejectedCandidateCount || 0,
      unsupportedFiles: selection.unsupportedFileCount || 0,
      runtimeMs: Date.now() - startedAt,
      ruleCompatibility,
      ruleSnapshotHash,
    };
    onProgress?.({ phase: "done", pct: 100, text: "EvtxECmd output scan complete", ...stats });
    return {
      matches,
      stats,
      errors,
      warnings,
      files,
      resultDbPath: persisted.dbPath,
      resultHeaders: persisted.headers,
      eventRows: preview,
      eventRowsPreview: preview,
      eventRowCount: persisted.rowCount || eventRowCount,
    };
  } catch (err) {
    finalStore.close();
    SigmaResultStore.destroy(finalStore.dbPath);
    throw err;
  } finally {
    try { finalStore.close(); } catch {}
  }
}

function summarizeKapeSelection(paths = []) {
  const selection = collectKapeOutputSelection(paths);
  const files = selection.files;
  return {
    paths,
    fileCount: files.length,
    totalBytes: files.reduce((sum, file) => sum + (file.size || 0), 0),
    files: files.slice(0, MAX_FILE_PREVIEW).map((file) => ({ name: file.name, path: file.path, size: file.size, ext: file.ext })),
    overflow: Math.max(0, files.length - MAX_FILE_PREVIEW),
    ignoredCount: selection.ignoredCount,
    rejectedCandidateCount: selection.rejectedCandidateCount,
    unsupportedFileCount: selection.unsupportedFileCount,
    scannedFileCount: selection.scannedFileCount,
    candidateFileCount: selection.candidateFileCount,
    ignoredFiles: selection.ignoredFiles,
    ignoredOverflow: Math.max(0, selection.ignoredCount - selection.ignoredFiles.length),
  };
}

module.exports = {
  SUPPORTED_EXTS,
  classifyEvtxEcmdHeaders,
  inspectKapeOutputFile,
  collectKapeOutputSelection,
  collectKapeOutputFiles,
  scanKapeOutputs,
  summarizeKapeSelection,
};
