/**
 * parser.js — Streaming file parser for IRFlow Timeline
 *
 * Handles:
 *   - CSV (comma, tab, pipe delimited) via raw chunk processing
 *   - XLSX via ExcelJS streaming reader
 *   - Plaso (.plaso) SQLite databases via native reading
 *   - Progress callbacks for UI feedback
 *   - Batch insertion into SQLite (array-based, zero object allocation)
 */

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const BATCH_SIZE = 50000;

// ── CSV line parser (RFC 4180 compliant) ───────────────────────────
function parseCSVLine(line, delimiter = ",") {
  const fields = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === delimiter) {
        fields.push(current);
        current = "";
      } else {
        current += ch;
      }
    }
  }
  fields.push(current);
  return fields;
}

// ── Fast CSV field parser (returns array, no allocations beyond the fields array)
// For comma-delimited files that may use quoting.
function parseCSVLineToArray(line, delimiter, colCount) {
  const fields = new Array(colCount);
  let fi = 0;
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === delimiter) {
        fields[fi++] = current;
        current = "";
        if (fi >= colCount) return fields;
      } else {
        current += ch;
      }
    }
  }
  if (fi < colCount) fields[fi++] = current;
  // Fill remaining with empty strings
  while (fi < colCount) fields[fi++] = "";
  return fields;
}

function detectDelimiter(firstLine) {
  const tabCount = (firstLine.match(/\t/g) || []).length;
  const commaCount = (firstLine.match(/,/g) || []).length;
  const pipeCount = (firstLine.match(/\|/g) || []).length;
  if (tabCount > commaCount && tabCount > pipeCount) return "\t";
  if (pipeCount > commaCount) return "|";
  return ",";
}

/**
 * Fast split to pre-sized array (avoids String.split() allocating unknown-length array)
 */
function splitToArray(line, delimiter, colCount) {
  const result = new Array(colCount);
  let fi = 0;
  let start = 0;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === delimiter) {
      result[fi++] = line.substring(start, i);
      start = i + 1;
      if (fi >= colCount - 1) break;
    }
  }
  result[fi++] = line.substring(start);
  while (fi < colCount) result[fi++] = "";
  return result;
}

/**
 * Stream-parse a CSV/TSV file and insert into TimelineDB
 * Uses raw chunk processing instead of readline for maximum throughput.
 *
 * @param {string} filePath - Path to the file
 * @param {string} tabId - Tab identifier
 * @param {TimelineDB} db - Database instance
 * @param {Function} onProgress - Progress callback(rowsImported, fileBytes, totalBytes)
 * @returns {Promise<{headers, rowCount, tsColumns}>}
 */
async function parseCSVStream(filePath, tabId, db, onProgress) {
  return new Promise((resolve, reject) => {
    const stat = fs.statSync(filePath);
    const totalBytes = stat.size;
    let bytesRead = 0;
    let lineCount = 0;
    let headers = null;
    let colCount = 0;
    let delimiter = null;
    let batch = [];
    let lastProgress = 0;

    // Buffer-level leftover — avoids string concatenation between chunks
    let leftoverBuf = null;

    // Fast-path flag for tab/pipe delimiters (no quoting needed)
    let fastSplit = false;

    const stream = fs.createReadStream(filePath, {
      highWaterMark: 16 * 1024 * 1024, // 16MB chunks — fewer events, more work per event
    });

    stream.on("data", (chunk) => {
      bytesRead += chunk.length;

      // Combine leftover buffer from previous chunk (zero-copy when no leftover)
      const buf = leftoverBuf ? Buffer.concat([leftoverBuf, chunk]) : chunk;
      leftoverBuf = null;

      // Find last newline in buffer — only decode complete lines
      const lastNL = buf.lastIndexOf(10); // 10 = '\n'
      if (lastNL === -1) {
        // No complete line yet — save entire buffer
        leftoverBuf = buf;
        return;
      }

      // Save bytes after last newline as leftover (Buffer view, no copy)
      if (lastNL < buf.length - 1) {
        leftoverBuf = buf.subarray(lastNL + 1);
      }

      // Decode only the complete-lines portion
      const str = buf.toString("utf-8", 0, lastNL);
      const lines = str.split("\n");

      for (let li = 0; li < lines.length; li++) {
        let line = lines[li];
        // Strip trailing \r (CRLF files)
        if (line.length > 0 && line.charCodeAt(line.length - 1) === 13) {
          line = line.substring(0, line.length - 1);
        }
        if (line.length === 0) continue;

        if (!headers) {
          // First line = headers
          delimiter = detectDelimiter(line);
          fastSplit = delimiter === "\t" || delimiter === "|";
          const rawFields = fastSplit ? line.split(delimiter) : parseCSVLine(line, delimiter);
          headers = rawFields.map((h) => h.trim());

          // Deduplicate headers
          const seen = new Map();
          headers = headers.map((h) => {
            if (!h) h = "Column";
            if (seen.has(h)) {
              const count = seen.get(h) + 1;
              seen.set(h, count);
              return `${h}_${count}`;
            }
            seen.set(h, 0);
            return h;
          });

          colCount = headers.length;
          db.createTab(tabId, headers);
          continue;
        }

        // Parse data row directly into array (no row object allocation)
        const values = fastSplit
          ? splitToArray(line, delimiter, colCount)
          : parseCSVLineToArray(line, delimiter, colCount);

        batch.push(values);
        lineCount++;

        if (batch.length >= BATCH_SIZE) {
          db.insertBatchArrays(tabId, batch);
          batch = [];

          // Report progress every ~10k rows
          if (lineCount - lastProgress >= 10000) {
            lastProgress = lineCount;
            if (onProgress) onProgress(lineCount, bytesRead, totalBytes);
          }
        }
      }
    });

    stream.on("end", () => {
      // Process any leftover partial line (last line without trailing newline)
      if (leftoverBuf && leftoverBuf.length > 0 && headers) {
        let line = leftoverBuf.toString("utf-8");
        if (line.length > 0 && line.charCodeAt(line.length - 1) === 13) {
          line = line.substring(0, line.length - 1);
        }
        if (line.length > 0) {
          const values = fastSplit
            ? splitToArray(line, delimiter, colCount)
            : parseCSVLineToArray(line, delimiter, colCount);
          batch.push(values);
          lineCount++;
        }
      }

      // Insert remaining batch
      if (batch.length > 0) {
        db.insertBatchArrays(tabId, batch);
      }

      // Finalize
      if (onProgress) onProgress(lineCount, totalBytes, totalBytes);
      const result = db.finalizeImport(tabId);

      resolve({
        headers,
        rowCount: result.rowCount,
        tsColumns: result.tsColumns,
        numericColumns: result.numericColumns,
      });
    });

    stream.on("error", reject);
  });
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

  return new Promise((resolve, reject) => {
    const stat = fs.statSync(filePath);
    const totalBytes = stat.size;
    let headers = null;
    let colCount = 0;
    let lineCount = 0;
    let batch = [];
    let lastProgress = 0;
    let targetSheet = sheetName || 1;
    let currentSheet = null;
    let sheetFound = false;

    const workbookReader = new ExcelJS.stream.xlsx.WorkbookReader(filePath, {
      sharedStrings: "cache",
      hyperlinks: "ignore",
      styles: "ignore",
      worksheets: "emit",
    });

    workbookReader.on("worksheet", (worksheet) => {
      // Match by name or index
      if (typeof targetSheet === "string") {
        if (worksheet.name !== targetSheet) return;
      } else {
        if (worksheet.id !== targetSheet) return;
      }

      sheetFound = true;
      currentSheet = worksheet;

      worksheet.on("row", (row) => {
        const values = [];
        row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
          let val = "";
          if (cell.value !== null && cell.value !== undefined) {
            if (cell.value instanceof Date) {
              val = cell.value.toISOString().replace("T", " ").replace("Z", "");
            } else if (typeof cell.value === "object" && cell.value.text) {
              val = cell.value.text;
            } else if (typeof cell.value === "object" && cell.value.result !== undefined) {
              val = String(cell.value.result);
            } else {
              val = String(cell.value);
            }
          }
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
          db.createTab(tabId, headers);
          return;
        }

        // Pad to colCount
        while (values.length < colCount) values.push("");
        batch.push(values);
        lineCount++;

        if (batch.length >= BATCH_SIZE) {
          db.insertBatchArrays(tabId, batch);
          batch = [];
          if (lineCount - lastProgress >= 50000) {
            lastProgress = lineCount;
            if (onProgress) onProgress(lineCount, 0, totalBytes);
          }
        }
      });
    });

    workbookReader.on("end", () => {
      if (batch.length > 0 && headers) {
        db.insertBatchArrays(tabId, batch);
      }
      if (!headers) {
        reject(new Error("No data found in sheet"));
        return;
      }
      if (onProgress) onProgress(lineCount, totalBytes, totalBytes);
      const result = db.finalizeImport(tabId);
      resolve({
        headers,
        rowCount: result.rowCount,
        tsColumns: result.tsColumns,
        numericColumns: result.numericColumns,
      });
    });

    workbookReader.on("error", reject);

    // Start reading
    workbookReader.read();
  });
}

/**
 * Get list of sheet names from an XLSX file
 */
async function getXLSXSheets(filePath) {
  const ExcelJS = require("exceljs");
  const workbook = new ExcelJS.Workbook();
  // Read only metadata
  await workbook.xlsx.readFile(filePath, {
    sharedStrings: "ignore",
    hyperlinks: "ignore",
    styles: "ignore",
  });
  return workbook.worksheets.map((ws) => ({
    name: ws.name,
    id: ws.id,
    rowCount: ws.rowCount,
  }));
}

// ── Plaso (.plaso) SQLite parser ─────────────────────────────────────

/**
 * Validate that a file is a genuine Plaso SQLite database.
 * @returns {{ valid: boolean, formatVersion?: string, compressionFormat?: string }}
 */
function validatePlasoFile(filePath) {
  const Database = require("better-sqlite3");
  let plasoDb;
  try {
    plasoDb = new Database(filePath, { readonly: true, fileMustExist: true });
    const hasMeta = plasoDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'"
    ).get();
    if (!hasMeta) return { valid: false };
    const fmtRow = plasoDb.prepare(
      "SELECT value FROM metadata WHERE key = 'format_version'"
    ).get();
    if (!fmtRow) return { valid: false };
    const compRow = plasoDb.prepare(
      "SELECT value FROM metadata WHERE key = 'compression_format'"
    ).get();
    return {
      valid: true,
      formatVersion: String(fmtRow.value),
      compressionFormat: compRow ? String(compRow.value) : "none",
    };
  } catch {
    return { valid: false };
  } finally {
    try { plasoDb?.close(); } catch {}
  }
}

/**
 * Decompress and parse a Plaso event_data blob.
 * Handles both zlib-compressed BLOBs and plain-text JSON.
 */
function parsePlasoBlob(data, useZlib) {
  if (data == null) return {};
  try {
    let jsonStr;
    if (useZlib && Buffer.isBuffer(data)) {
      jsonStr = zlib.inflateSync(data).toString("utf-8");
    } else {
      jsonStr = typeof data === "string" ? data : data.toString("utf-8");
    }
    return JSON.parse(jsonStr);
  } catch {
    return {};
  }
}

/**
 * Parse a Plaso (.plaso) SQLite file and insert events into TimelineDB.
 *
 * Plaso schema:
 *   metadata: key/value pairs (format_version, compression_format)
 *   event: _timestamp (int64 microseconds), _timestamp_desc, _event_data_row_identifier
 *   event_data: _identifier (PK), _data (JSON text or zlib-compressed blob)
 *
 * @param {string} filePath
 * @param {string} tabId
 * @param {TimelineDB} db
 * @param {Function} onProgress
 * @returns {Promise<{headers, rowCount, tsColumns, numericColumns}>}
 */
async function parsePlasoFile(filePath, tabId, db, onProgress) {
  const Database = require("better-sqlite3");
  const plasoDb = new Database(filePath, { readonly: true, fileMustExist: true });
  plasoDb.pragma("mmap_size = 1073741824");
  plasoDb.pragma("cache_size = -256000");

  try {
    // Read compression setting
    const compRow = plasoDb.prepare(
      "SELECT value FROM metadata WHERE key = 'compression_format'"
    ).get();
    const useZlib = compRow?.value?.toString().toUpperCase() === "ZLIB";

    // Detect schema — check which tables exist
    const tables = plasoDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table'"
    ).all().map((r) => r.name);
    const hasEventData = tables.includes("event_data");
    const hasEvent = tables.includes("event");
    if (!hasEvent) throw new Error("Plaso file missing 'event' table");

    // Detect event table column names (varies between Plaso format versions)
    // Old format: _timestamp, _timestamp_desc, _event_data_row_identifier
    // New format (20230327+): timestamp, timestamp_desc, _event_data_identifier
    const eventCols = plasoDb.pragma("table_info(event)").map((c) => c.name);
    const tsCol = eventCols.includes("_timestamp") ? "_timestamp" : "timestamp";
    const tsDescCol = eventCols.includes("_timestamp_desc") ? "_timestamp_desc" : "timestamp_desc";
    const edRefCol = eventCols.includes("_event_data_row_identifier")
      ? "_event_data_row_identifier"
      : eventCols.includes("_event_data_identifier")
        ? "_event_data_identifier"
        : null;

    // Detect if the reference column uses "event_data.N" format (new) vs plain integer (old)
    let joinIsTextRef = false;
    if (edRefCol && hasEventData) {
      const sample = plasoDb.prepare(`SELECT ${edRefCol} FROM event LIMIT 1`).get();
      if (sample) {
        const val = String(sample[edRefCol]);
        joinIsTextRef = val.startsWith("event_data.");
      }
    }

    // Count events for progress
    const totalEvents = plasoDb.prepare("SELECT COUNT(*) as cnt FROM event").get().cnt;

    // Phase 1: Column discovery — sample event_data entries to find all field keys
    const FIXED_FIELDS = ["datetime", "timestamp_desc", "data_type"];
    const fieldSet = new Set();

    if (hasEventData) {
      // Sample from start
      for (const row of plasoDb.prepare("SELECT _data FROM event_data LIMIT 500").iterate()) {
        const obj = parsePlasoBlob(row._data, useZlib);
        for (const key of Object.keys(obj)) {
          if (!key.startsWith("__") && !key.startsWith("_")) fieldSet.add(key);
        }
      }
      // Sample from middle for broader coverage
      const edCount = plasoDb.prepare("SELECT COUNT(*) as cnt FROM event_data").get().cnt;
      const midOffset = Math.max(0, Math.floor(edCount / 2));
      for (const row of plasoDb.prepare("SELECT _data FROM event_data LIMIT 200 OFFSET ?").iterate(midOffset)) {
        const obj = parsePlasoBlob(row._data, useZlib);
        for (const key of Object.keys(obj)) {
          if (!key.startsWith("__") && !key.startsWith("_")) fieldSet.add(key);
        }
      }
    }

    // Remove fields handled in fixed positions
    fieldSet.delete("data_type");
    fieldSet.delete("timestamp_desc");
    const discoveredFields = [...fieldSet].sort();
    const headers = [...FIXED_FIELDS, ...discoveredFields];
    const colCount = headers.length;

    // Create the TLE tab with discovered headers
    db.createTab(tabId, headers);

    // Phase 2: Stream events in batches
    // For text-ref format ("event_data.N"), extract the integer and match against PK
    // to enable SEARCH USING INTEGER PRIMARY KEY instead of full table scan.
    // Skip ORDER BY — events are stored in chronological order; app sorts after import.
    let eventStmt;
    if (hasEventData && edRefCol) {
      // Text-ref: "event_data.N" → extract N via SUBSTR(col, 12) and match against integer PK
      const joinCondition = joinIsTextRef
        ? `ed._identifier = CAST(SUBSTR(e.${edRefCol}, 12) AS INTEGER)`
        : `e.${edRefCol} = ed._identifier`;
      eventStmt = plasoDb.prepare(`
        SELECT e.${tsCol} AS ts, e.${tsDescCol} AS ts_desc, ed._data
        FROM event e
        LEFT JOIN event_data ed ON ${joinCondition}
      `);
    } else {
      eventStmt = plasoDb.prepare(`
        SELECT ${tsCol} AS ts, ${tsDescCol} AS ts_desc, _data FROM event
      `);
    }

    let batch = [];
    let rowCount = 0;
    let lastProgress = 0;

    for (const row of eventStmt.iterate()) {
      // Convert microseconds → ISO string "YYYY-MM-DD HH:MM:SS.ffffff"
      let datetime = "";
      if (row.ts != null && row.ts !== 0) {
        try {
          const tsNum = Number(row.ts);
          const ms = tsNum / 1000;
          const d = new Date(ms);
          if (!isNaN(d.getTime())) {
            const iso = d.toISOString(); // YYYY-MM-DDTHH:MM:SS.mmmZ
            const micros = String(Math.abs(tsNum % 1000000)).padStart(6, "0");
            datetime = iso.slice(0, 10) + " " + iso.slice(11, 19) + "." + micros;
          }
        } catch { /* leave empty */ }
      }

      // Parse event_data JSON
      const eventObj = parsePlasoBlob(row._data, useZlib);

      // Build row array in header order
      const values = new Array(colCount);
      values[0] = datetime;
      values[1] = row.ts_desc || eventObj.timestamp_desc || "";
      values[2] = eventObj.data_type || "";
      for (let i = 3; i < colCount; i++) {
        const val = eventObj[headers[i]];
        if (val == null) {
          values[i] = "";
        } else if (typeof val === "object") {
          values[i] = JSON.stringify(val);
        } else {
          values[i] = String(val);
        }
      }

      batch.push(values);
      rowCount++;

      if (batch.length >= BATCH_SIZE) {
        db.insertBatchArrays(tabId, batch);
        batch = [];
        if (rowCount - lastProgress >= 10000) {
          lastProgress = rowCount;
          if (onProgress) onProgress(rowCount, rowCount, totalEvents);
        }
      }
    }

    // Insert remaining batch
    if (batch.length > 0) {
      db.insertBatchArrays(tabId, batch);
    }

    if (onProgress) onProgress(rowCount, totalEvents, totalEvents);
    const result = db.finalizeImport(tabId);

    return {
      headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns,
    };
  } finally {
    try { plasoDb.close(); } catch {}
  }
}

// ── EVTX (.evtx) parser ─────────────────────────────────────────

/**
 * Parse a Windows EVTX file using @ts-evtx/core.
 * ESM-only library loaded via dynamic import() since app is CJS.
 *
 * Single-pass approach: buffer first 500 events for schema discovery,
 * finalize schema, flush buffer, then continue streaming.
 *
 * @param {string} filePath
 * @param {string} tabId
 * @param {TimelineDB} db
 * @param {Function} onProgress
 * @returns {Promise<{headers, rowCount, tsColumns, numericColumns}>}
 */
async function parseEvtxFile(filePath, tabId, db, onProgress) {
  const { evtx } = await import("@ts-evtx/core");
  const stat = fs.statSync(filePath);
  const totalBytes = stat.size;

  const FIXED_FIELDS = ["datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer"];
  const FIXED_COUNT = FIXED_FIELDS.length;
  const SAMPLE_LIMIT = 500;

  const fieldSet = new Set();
  let earlyBuffer = [];
  let schemaFinalized = false;
  let headers = null;
  let colCount = 0;
  let batch = [];
  let rowCount = 0;
  let lastProgress = 0;

  // Extract fixed + data fields from a ResolvedEvent
  const extractEvent = (event) => {
    let datetime = "";
    if (event.timestamp) {
      try {
        const d = new Date(event.timestamp);
        if (!isNaN(d.getTime())) {
          datetime = d.toISOString().replace("T", " ").replace("Z", "");
        }
      } catch { /* leave empty */ }
    }

    // Flatten data.items array into a key-value map
    const dataMap = {};
    if (event.data?.items) {
      let paramIdx = 0;
      for (const item of event.data.items) {
        const key = item.name || `param${paramIdx}`;
        dataMap[key] = item.value != null ? String(item.value) : "";
        paramIdx++;
      }
    }

    return {
      fixed: [
        datetime,
        event.id != null ? String(event.id) : "",
        event.eventId != null ? String(event.eventId) : "",
        event.provider?.name || "",
        event.levelName || (event.level != null ? String(event.level) : ""),
        event.channel || "",
        event.computer || "",
      ],
      dataMap,
    };
  };

  const buildRow = (parsed) => {
    const values = new Array(colCount);
    for (let f = 0; f < FIXED_COUNT; f++) values[f] = parsed.fixed[f];
    for (let i = FIXED_COUNT; i < colCount; i++) {
      const val = parsed.dataMap[headers[i]];
      values[i] = val != null ? val : "";
    }
    return values;
  };

  const parser = evtx(filePath);
  await parser.forEach((event) => {
    rowCount++;
    const parsed = extractEvent(event);

    if (!schemaFinalized) {
      // Phase 1: collecting data field keys
      for (const key of Object.keys(parsed.dataMap)) {
        fieldSet.add(key);
      }
      earlyBuffer.push(parsed);

      if (rowCount >= SAMPLE_LIMIT) {
        // Finalize schema
        const discoveredFields = [...fieldSet].sort();
        headers = [...FIXED_FIELDS, ...discoveredFields];
        colCount = headers.length;
        db.createTab(tabId, headers);
        schemaFinalized = true;

        // Flush buffered events
        for (const buf of earlyBuffer) {
          batch.push(buildRow(buf));
        }
        earlyBuffer = null;

        if (batch.length >= BATCH_SIZE) {
          db.insertBatchArrays(tabId, batch);
          batch = [];
        }
        if (onProgress) onProgress(rowCount, 0, 0);
      }
      return;
    }

    // Phase 2: streaming insert
    batch.push(buildRow(parsed));
    if (batch.length >= BATCH_SIZE) {
      db.insertBatchArrays(tabId, batch);
      batch = [];
      if (rowCount - lastProgress >= 10000) {
        lastProgress = rowCount;
        if (onProgress) onProgress(rowCount, 0, 0);
      }
    }
  });

  // Handle files with fewer than SAMPLE_LIMIT events
  if (!schemaFinalized) {
    const discoveredFields = [...fieldSet].sort();
    headers = [...FIXED_FIELDS, ...discoveredFields];
    colCount = headers.length;
    db.createTab(tabId, headers);
    for (const buf of earlyBuffer) {
      batch.push(buildRow(buf));
    }
    earlyBuffer = null;
  }

  if (batch.length > 0) {
    db.insertBatchArrays(tabId, batch);
  }

  if (onProgress) onProgress(rowCount, totalBytes, totalBytes);
  const result = db.finalizeImport(tabId);

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
  };
}

/**
 * Auto-detect file type and parse accordingly
 */
async function parseFile(filePath, tabId, db, onProgress, sheetName) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".xlsx" || ext === ".xls" || ext === ".xlsm") {
    return parseXLSXStream(filePath, tabId, db, onProgress, sheetName);
  }
  if (ext === ".evtx") {
    return parseEvtxFile(filePath, tabId, db, onProgress);
  }
  if (ext === ".plaso") {
    const check = validatePlasoFile(filePath);
    if (!check.valid) throw new Error("Not a valid Plaso database (missing metadata table or format_version)");
    return parsePlasoFile(filePath, tabId, db, onProgress);
  }
  // Default to CSV parsing (handles .csv, .tsv, .txt, .log, etc.)
  return parseCSVStream(filePath, tabId, db, onProgress);
}

module.exports = {
  parseCSVStream,
  parseXLSXStream,
  parsePlasoFile,
  parseEvtxFile,
  validatePlasoFile,
  getXLSXSheets,
  parseFile,
  parseCSVLine,
  detectDelimiter,
};
