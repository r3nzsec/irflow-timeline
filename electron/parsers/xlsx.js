const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const unzipper = require("unzipper");

const { dbg } = require("../logger");
const { BATCH_SIZE_DEFAULT, BATCH_SIZE_MAX_BYTES } = require("./csv");

const XLSX_SHARED_STRING_FLUSH_BATCH = 2000;
const XLSX_SHARED_STRING_CACHE_LIMIT = 16384;

function decodeXmlAttribute(value) {
  return String(value || "")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function flattenRichText(richText) {
  if (!Array.isArray(richText) || richText.length === 0) return "";
  let out = "";
  for (const part of richText) {
    if (!part) continue;
    out += String(part.text || "");
  }
  return out;
}

function normalizeXlsxTextValue(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "object") {
    if (Array.isArray(value.richText)) return flattenRichText(value.richText);
    if (value.text != null) return String(value.text);
  }
  return String(value);
}

function normalizeXlsxCellValue(value, resolveSharedString) {
  if (value == null) return "";
  if (value instanceof Date) {
    return value.toISOString().replace("T", " ").replace("Z", "");
  }
  if (typeof value === "object") {
    if (value.sharedString != null && resolveSharedString) {
      return resolveSharedString(value.sharedString);
    }
    if (Array.isArray(value.richText)) {
      return flattenRichText(value.richText);
    }
    if (value.text != null) {
      return String(value.text);
    }
    if (value.result !== undefined) {
      return String(value.result);
    }
  }
  return String(value);
}

async function readZipEntryText(filePath, entryPath) {
  const directory = await unzipper.Open.file(filePath);
  const entry = directory.files.find((file) => file.path === entryPath);
  if (!entry) return null;
  const content = await entry.buffer();
  return content.toString("utf-8");
}

function createXlsxSharedStringStore() {
  const Database = require("better-sqlite3");
  const dbPath = path.join(
    os.tmpdir(),
    `tle_xlsx_shared_${crypto.randomBytes(4).toString("hex")}.db`
  );
  const db = new Database(dbPath);
  db.pragma("journal_mode = MEMORY");
  db.pragma("synchronous = OFF");
  db.pragma("temp_store = MEMORY");
  db.pragma("cache_size = -32768"); // 32MB
  db.exec("CREATE TABLE shared_strings (idx INTEGER PRIMARY KEY, value TEXT NOT NULL)");

  const insertStmt = db.prepare("INSERT INTO shared_strings (idx, value) VALUES (?, ?)");
  const lookupStmt = db.prepare("SELECT value FROM shared_strings WHERE idx = ?");
  const insertBatchTx = db.transaction((rows) => {
    for (const [idx, value] of rows) insertStmt.run(idx, value);
  });

  let pending = [];
  let count = 0;
  const cache = new Map();

  const remember = (idx, value) => {
    if (cache.has(idx)) cache.delete(idx);
    cache.set(idx, value);
    if (cache.size > XLSX_SHARED_STRING_CACHE_LIMIT) {
      cache.delete(cache.keys().next().value);
    }
  };

  const flush = () => {
    if (pending.length === 0) return;
    insertBatchTx(pending);
    pending = [];
  };

  return {
    add(index, value) {
      const normalized = normalizeXlsxTextValue(value);
      pending.push([index, normalized]);
      remember(index, normalized);
      if (index >= count) count = index + 1;
      if (pending.length >= XLSX_SHARED_STRING_FLUSH_BATCH) flush();
    },
    get(index) {
      const idx = Number(index);
      if (!Number.isInteger(idx) || idx < 0) return "";
      const cached = cache.get(idx);
      if (cached !== undefined) return cached;
      flush();
      const row = lookupStmt.get(idx);
      const value = row ? row.value : "";
      remember(idx, value);
      return value;
    },
    flush,
    size() {
      return count;
    },
    close() {
      try { flush(); } catch {}
      try { db.close(); } catch {}
      try { fs.unlinkSync(dbPath); } catch {}
    },
  };
}

async function populateXlsxSharedStringStore(filePath, sharedStringStore) {
  const directory = await unzipper.Open.file(filePath);
  const entry = directory.files.find((file) => file.path === "xl/sharedStrings.xml");
  if (!entry) return 0;

  const parseSax = require("exceljs/lib/utils/parse-sax");
  const iterateStream = require("exceljs/lib/utils/iterate-stream");

  let currentText = "";
  let inSharedString = false;
  let inTextNode = false;
  let index = 0;

  for await (const events of parseSax(iterateStream(entry.stream()))) {
    for (const { eventType, value } of events) {
      if (eventType === "opentag") {
        if (value.name === "si") {
          inSharedString = true;
          currentText = "";
        } else if (inSharedString && value.name === "t") {
          inTextNode = true;
        }
      } else if (eventType === "text") {
        if (inSharedString && inTextNode) currentText += value;
      } else if (eventType === "closetag") {
        if (value.name === "t") {
          inTextNode = false;
        } else if (value.name === "si") {
          sharedStringStore.add(index++, currentText);
          currentText = "";
          inSharedString = false;
          inTextNode = false;
        }
      }
    }
  }

  sharedStringStore.flush();
  return index;
}

/**
 * Stream-parse an XLSX file and insert into TimelineDB
 *
 * Uses ExcelJS streaming reader to avoid loading entire file into memory.
 *
 * @param {string} filePath - Path to the .xlsx file
 * @param {string} tabId - Tab identifier
 * @param {TimelineDB} db - Database instance
 * @param {Function} onProgress - Progress callback
 * @param {string|number} sheetName - Sheet name or 1-based index (default: 1)
 * @returns {Promise<{headers, rowCount, tsColumns}>}
 */
async function parseXLSXStream(filePath, tabId, db, onProgress, sheetName) {
  const ExcelJS = require("exceljs");
  dbg("XLSX", `parseXLSXStream start`, { filePath, tabId, sheetName });

  const sharedStringStore = createXlsxSharedStringStore();
  try {
    const sharedCount = await populateXlsxSharedStringStore(filePath, sharedStringStore);
    dbg("XLSX", `shared strings indexed`, { sharedCount });
  } catch (err) {
    sharedStringStore.close();
    throw err;
  }

  return new Promise((resolve, reject) => {
    let totalBytes = 0;
    try { totalBytes = fs.statSync(filePath).size; } catch { /* proceed with 0 */ }
    dbg("XLSX", `file size`, { totalBytes });
    let headers = null;
    let colCount = 0;
    let lineCount = 0;
    let batch = [];
    let batchSize = BATCH_SIZE_DEFAULT;
    let lastProgressTime = 0;
    let targetSheet = sheetName || 1;
    let sheetFound = false;
    let cleanedUp = false;
    const cleanup = () => {
      if (cleanedUp) return;
      cleanedUp = true;
      sharedStringStore.close();
    };

    const workbookReader = new ExcelJS.stream.xlsx.WorkbookReader(filePath, {
      sharedStrings: "ignore",
      hyperlinks: "ignore",
      styles: "cache",
      worksheets: "emit",
    });
    workbookReader.model = { sheets: [] };

    workbookReader.on("worksheet", (worksheet) => {
      dbg("XLSX", `worksheet event`, { name: worksheet.name, id: worksheet.id, targetSheet });
      // Match by name or index
      if (typeof targetSheet === "string" && !/^\d+$/.test(targetSheet)) {
        if (worksheet.name !== targetSheet) return;
      } else {
        if (String(worksheet.id) !== String(targetSheet)) return;
      }

      dbg("XLSX", `matched target sheet`, { name: worksheet.name });
      sheetFound = true;

      worksheet.on("error", (err) => {
        dbg("XLSX", `worksheet ERROR`, { sheet: worksheet.name, message: err.message });
        cleanup();
        reject(err);
      });

      worksheet.on("row", (row) => {
        try {
          const values = [];
          row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
            const val = normalizeXlsxCellValue(cell.value, (index) => sharedStringStore.get(index));
            // Ensure array is large enough
            while (values.length < colNumber) values.push("");
            values[colNumber - 1] = val;
          });

          if (!headers) {
            headers = values.map((v, i) => (v.trim() || `Column_${i + 1}`));
            // Deduplicate
            const seen = new Map();
            headers = headers.map((h) => {
              if (seen.has(h)) {
                const c = seen.get(h) + 1;
                seen.set(h, c);
                return `${h}_${c}`;
              }
              seen.set(h, 0);
              return h;
            });
            colCount = headers.length;
            batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
            dbg("XLSX", `headers parsed, calling db.createTab`, { colCount, headers: headers.slice(0, 10) });
            db.createTab(tabId, headers);
            dbg("XLSX", `db.createTab OK`);
            return;
          }

          // Pad or truncate to colCount
          while (values.length < colCount) values.push("");
          if (values.length > colCount) values.length = colCount;
          batch.push(values);
          lineCount++;

          if (batch.length >= batchSize) {
            db.insertBatchArrays(tabId, batch);
            batch = [];
            const now = Date.now();
            if (now - lastProgressTime >= 200) {
              lastProgressTime = now;
              // XLSX streaming doesn't expose byte position — estimate progress
              // using an assumed ~200 bytes/row average for compressed XLSX
              const estimatedBytes = Math.min(lineCount * 200, totalBytes - 1);
              if (onProgress) onProgress(lineCount, estimatedBytes, totalBytes);
            }
          }
        } catch (e) {
          dbg("XLSX", `row processing error`, { row: lineCount, message: e.message });
          cleanup();
          reject(e);
        }
      });
    });

    workbookReader.on("end", () => {
      dbg("XLSX", `workbookReader end event`, { lineCount, batchRemaining: batch.length, hasHeaders: !!headers });
      if (!sheetFound) {
        cleanup();
        reject(new Error(`Sheet "${targetSheet}" not found`));
        return;
      }
      if (batch.length > 0 && headers) {
        db.insertBatchArrays(tabId, batch);
      }
      if (!headers) {
        dbg("XLSX", `no headers found — rejecting`);
        cleanup();
        reject(new Error("No data found in sheet"));
        return;
      }
      if (onProgress) onProgress(lineCount, totalBytes, totalBytes);
      dbg("XLSX", `calling finalizeImport`);
      const result = db.finalizeImport(tabId);
      dbg("XLSX", `finalizeImport OK`, { rowCount: result.rowCount, tsColumns: result.tsColumns?.length });
      cleanup();
      resolve({
        headers,
        rowCount: result.rowCount,
        tsColumns: result.tsColumns,
        numericColumns: result.numericColumns,
        dayFirstColumns: result.dayFirstColumns || [],
      });
    });

    workbookReader.on("error", (err) => {
      dbg("XLSX", `workbookReader ERROR`, { message: err.message, stack: err.stack });
      cleanup();
      reject(err);
    });

    // Start reading
    workbookReader.read();
  });
}

// ── Legacy .xls (OLE2/BIFF) parser using SheetJS ────────────────────
/**
 * Parse a legacy .xls file (binary Excel format).
 * SheetJS reads the entire file into memory — fine for .xls (max ~65k rows).
 */
function parseXLSFile(filePath, tabId, db, onProgress, sheetName) {
  const XLSX = require("xlsx");
  dbg("XLS", `parseXLSFile start`, { filePath, tabId, sheetName });

  const workbook = XLSX.readFile(filePath, { dateNF: "yyyy-mm-dd hh:mm:ss" });
  const targetSheet = sheetName || workbook.SheetNames[0];
  const worksheet = workbook.Sheets[targetSheet];
  if (!worksheet) throw new Error(`Sheet "${targetSheet}" not found`);

  // Convert to array-of-arrays; raw:false converts dates to formatted strings
  const data = XLSX.utils.sheet_to_json(worksheet, { header: 1, raw: false, dateNF: "yyyy-mm-dd hh:mm:ss" });
  dbg("XLS", `sheet_to_json done`, { rows: data.length, sheet: targetSheet });
  if (data.length === 0) throw new Error("No data found in sheet");

  // First row = headers
  let headers = data[0].map((v, i) => (v ? String(v).trim() : `Column_${i + 1}`));
  // Deduplicate
  const seen = new Map();
  headers = headers.map((h) => {
    if (seen.has(h)) {
      const c = seen.get(h) + 1;
      seen.set(h, c);
      return `${h}_${c}`;
    }
    seen.set(h, 0);
    return h;
  });

  const colCount = headers.length;
  const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
  db.createTab(tabId, headers);

  let totalBytes = 0;
  try { totalBytes = fs.statSync(filePath).size; } catch {}

  let batch = [];
  let lineCount = 0;

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const values = [];
    for (let j = 0; j < colCount; j++) {
      values.push(row[j] != null ? String(row[j]) : "");
    }
    batch.push(values);
    lineCount++;

    if (batch.length >= batchSize) {
      db.insertBatchArrays(tabId, batch);
      batch = [];
      if (onProgress) onProgress(lineCount, Math.round((i / data.length) * totalBytes), totalBytes);
    }
  }

  if (batch.length > 0) {
    db.insertBatchArrays(tabId, batch);
  }

  if (onProgress) onProgress(lineCount, totalBytes, totalBytes);
  dbg("XLS", `parsing complete`, { lineCount });
  const result = db.finalizeImport(tabId);

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
    dayFirstColumns: result.dayFirstColumns || [],
  };
}

/**
 * Get list of sheet names from an Excel file (.xlsx or .xls)
 */
async function getXLSXSheets(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  dbg("XLSX", `getXLSXSheets start`, { filePath, ext });

  // Legacy .xls — use SheetJS
  if (ext === ".xls") {
    const XLSX = require("xlsx");
    const workbook = XLSX.readFile(filePath);
    const sheets = workbook.SheetNames.map((name, i) => {
      const sheet = workbook.Sheets[name];
      const range = sheet["!ref"] ? XLSX.utils.decode_range(sheet["!ref"]) : null;
      return { name, id: i + 1, rowCount: range ? range.e.r : 0 };
    });
    dbg("XLSX", `getXLSXSheets done (xls)`, { sheetCount: sheets.length });
    return sheets;
  }

  // .xlsx/.xlsm — read only workbook.xml from the ZIP central directory
  const workbookXml = await readZipEntryText(filePath, "xl/workbook.xml");
  if (!workbookXml) throw new Error("Workbook metadata not found");

  const sheets = [];
  const sheetTagRe = /<sheet\b([^>]*)\/?>/g;
  let match;
  while ((match = sheetTagRe.exec(workbookXml)) !== null) {
    const attrs = Object.create(null);
    const attrText = match[1];
    const attrRe = /\b([A-Za-z:]+)="([^"]*)"/g;
    let attrMatch;
    while ((attrMatch = attrRe.exec(attrText)) !== null) {
      attrs[attrMatch[1]] = decodeXmlAttribute(attrMatch[2]);
    }
    if (!attrs.name) continue;
    const id = Number(attrs.sheetId);
    sheets.push({
      name: attrs.name,
      id: Number.isFinite(id) ? id : sheets.length + 1,
      rowCount: "?",
    });
  }

  if (sheets.length === 0) throw new Error("No sheets found in workbook metadata");
  dbg("XLSX", `getXLSXSheets done`, { sheetCount: sheets.length });
  return sheets;
}

module.exports = { parseXLSXStream, parseXLSFile, getXLSXSheets };
