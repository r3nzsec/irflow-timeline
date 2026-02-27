/**
 * db.js — SQLite-backed data engine for IRFlow Timeline
 *
 * Architecture:
 *   1. Streaming import: CSV/XLSX rows are inserted in batches via transactions
 *   2. FTS5 full-text search index for global search
 *   3. SQL-based filtering, sorting, pagination (only visible rows in memory)
 *   4. Column metadata, stats, and type detection stored alongside data
 *   5. Temp database files auto-cleaned on close
 *
 * This enables handling 30-50GB+ files because:
 *   - Rows stream from disk → SQLite (never all in JS heap)
 *   - Queries use LIMIT/OFFSET (only ~10k rows in memory at once)
 *   - FTS5 handles full-text search natively
 *   - SQLite B-tree indexes handle sorting without in-memory sort
 */

const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");

// ── Debug trace logger (shared with main.js) ────────────────────
const debugLogPath = path.join(os.homedir(), "tle-debug.log");
function dbg(tag, msg, data) {
  const ts = new Date().toISOString();
  const line = `[${ts}] [${tag}] ${msg}${data !== undefined ? " " + JSON.stringify(data, null, 0) : ""}`;
  console.error(line);
  try { fs.appendFileSync(debugLogPath, line + "\n"); } catch {}
}

class TimelineDB {
  constructor() {
    this.databases = new Map(); // tabId -> { db, dbPath, headers, rowCount, tsColumns }
  }

  /**
   * Create a new database for a tab and prepare the schema
   */
  createTab(tabId, headers) {
    dbg("DB", `createTab start`, { tabId, headerCount: headers?.length });
    const dbPath = path.join(
      os.tmpdir(),
      `tle_${tabId}_${crypto.randomBytes(4).toString("hex")}.db`
    );

    const db = new Database(dbPath);
    dbg("DB", `Database opened`, { dbPath });

    try {
    // Register REGEXP function for regex search mode
    db.function("regexp", { deterministic: true }, (pattern, value) => {
      if (pattern == null || value == null) return 0;
      try { return new RegExp(pattern, "i").test(value) ? 1 : 0; } catch { return 0; }
    });

    // Register FUZZY_MATCH function for fuzzy/approximate search
    // Uses n-gram similarity: breaks search term into overlapping character chunks
    // and checks what fraction appear in the text. Fast O(n) per cell.
    db.function("fuzzy_match", { deterministic: true }, (text, term) => {
      if (text == null || term == null) return 0;
      const t = String(text).toLowerCase();
      const s = String(term).toLowerCase();
      if (t.includes(s)) return 1; // exact substring = always match
      if (s.length < 2) return 0;  // single char: exact only
      // Use bigrams for short terms (2-4 chars), trigrams for longer
      const n = s.length < 5 ? 2 : 3;
      const grams = [];
      for (let i = 0; i <= s.length - n; i++) grams.push(s.substring(i, i + n));
      if (grams.length === 0) return 0;
      let hits = 0;
      for (const g of grams) { if (t.includes(g)) hits++; }
      // Adaptive threshold: stricter for short terms, looser for long
      const threshold = s.length < 5 ? 0.7 : 0.6;
      return (hits / grams.length) >= threshold ? 1 : 0;
    });

    // Register extract_date function for histogram — normalizes any timestamp format to yyyy-MM-dd
    const MONTH_MAP = { jan: "01", feb: "02", mar: "03", apr: "04", may: "05", jun: "06", jul: "07", aug: "08", sep: "09", oct: "10", nov: "11", dec: "12" };
    db.function("extract_date", { deterministic: true }, (val) => {
      if (val == null) return null;
      const s = String(val).trim();
      // ISO: 2026-02-05... → substr
      if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.substring(0, 10);
      // US date: 02/05/2026 or 02-05-2026
      let m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
      if (m) return `${m[3]}-${m[1].padStart(2,"0")}-${m[2].padStart(2,"0")}`;
      // Month name: "Feb 5th 2026", "February 5, 2026", "5 Feb 2026", etc.
      m = s.match(/^([A-Za-z]+)\s+(\d{1,2})\w*[\s,]+(\d{4})/);
      if (m) { const mo = MONTH_MAP[m[1].substring(0,3).toLowerCase()]; if (mo) return `${m[3]}-${mo}-${m[2].padStart(2,"0")}`; }
      // "5 Feb 2026" or "05-Feb-2026"
      m = s.match(/^(\d{1,2})[\s\-]([A-Za-z]+)[\s\-](\d{4})/);
      if (m) { const mo = MONTH_MAP[m[2].substring(0,3).toLowerCase()]; if (mo) return `${m[3]}-${mo}-${m[1].padStart(2,"0")}`; }
      // Unix timestamp (seconds since epoch, 10 digits)
      if (/^\d{10}(\.\d+)?$/.test(s)) { const d = new Date(parseFloat(s) * 1000); if (!isNaN(d)) return d.toISOString().substring(0, 10); }
      // Unix timestamp (milliseconds, 13 digits)
      if (/^\d{13}$/.test(s)) { const d = new Date(parseInt(s)); if (!isNaN(d)) return d.toISOString().substring(0, 10); }
      // Excel serial date (e.g. 45566 = 2024-10-05, 37685.41 = 2003-03-10)
      if (/^\d{1,5}(\.\d+)?$/.test(s)) {
        const serial = parseFloat(s);
        if (serial >= 1 && serial <= 73050) {
          const d = new Date(Math.round((serial - 25569) * 86400000));
          if (!isNaN(d.getTime()) && d.getFullYear() >= 1900 && d.getFullYear() <= 2100) return d.toISOString().substring(0, 10);
        }
      }
      // Fallback: try JS Date parse
      const d = new Date(s);
      if (!isNaN(d) && d.getFullYear() > 1970 && d.getFullYear() < 2100) return d.toISOString().substring(0, 10);
      return null;
    });

    // Register extract_datetime_minute — normalizes any timestamp to yyyy-MM-dd HH:mm
    db.function("extract_datetime_minute", { deterministic: true }, (val) => {
      if (val == null) return null;
      const s = String(val).trim();
      // ISO: 2026-02-05 15:30:00 or 2026-02-05T15:30:00
      let m = s.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/);
      if (m) return `${m[1]} ${m[2]}`;
      // Excel serial date (e.g. 45566.833 = 2024-10-05 20:00)
      if (/^\d{1,5}(\.\d+)?$/.test(s)) {
        const serial = parseFloat(s);
        if (serial >= 1 && serial <= 73050) {
          const d = new Date((serial - 25569) * 86400000);
          if (!isNaN(d.getTime()) && d.getFullYear() >= 1900 && d.getFullYear() <= 2100) {
            const iso = d.toISOString();
            return `${iso.substring(0, 10)} ${iso.substring(11, 16)}`;
          }
        }
      }
      // Fallback: try JS Date parse
      const d = new Date(s);
      if (!isNaN(d) && d.getFullYear() > 1970 && d.getFullYear() < 2100) {
        const iso = d.toISOString();
        return `${iso.substring(0, 10)} ${iso.substring(11, 16)}`;
      }
      return null;
    });

    // Register sort_datetime — normalizes any timestamp format to sortable ISO string (yyyy-MM-dd HH:mm:ss.fff)
    // Used in ORDER BY for timestamp columns to ensure correct chronological sort regardless of input format
    db.function("sort_datetime", { deterministic: true }, (val) => {
      if (val == null || val === "") return null;
      const s = String(val).trim();
      // Fast path: ISO format (most common in forensic data) — already sortable
      if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s)) return s.replace("T", " ");
      // ISO date-only: 2026-02-05
      if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s + " 00:00:00";
      // US date: M/D/YYYY or MM/DD/YYYY with optional time
      let m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})\s*(.*)/);
      if (m) {
        const rest = m[4] ? " " + m[4].replace(/\s*[AP]M$/i, (ap) => {
          // Convert 12h to 24h
          const parts = m[4].replace(/\s*[AP]M$/i, "").trim().split(":");
          if (parts.length >= 2) {
            let h = parseInt(parts[0]);
            if (/PM$/i.test(ap) && h !== 12) h += 12;
            if (/AM$/i.test(ap) && h === 12) h = 0;
            return ""; // will be handled below
          }
          return "";
        }) : " 00:00:00";
        // Re-parse with AM/PM handling
        let timePart = m[4] || "00:00:00";
        const ampm = timePart.match(/\s*([AP]M)\s*$/i);
        timePart = timePart.replace(/\s*[AP]M\s*$/i, "").trim();
        if (ampm && timePart) {
          const tp = timePart.split(":");
          let h = parseInt(tp[0]) || 0;
          if (/PM/i.test(ampm[1]) && h !== 12) h += 12;
          if (/AM/i.test(ampm[1]) && h === 12) h = 0;
          tp[0] = String(h).padStart(2, "0");
          timePart = tp.join(":");
        }
        return `${m[3]}-${m[1].padStart(2,"0")}-${m[2].padStart(2,"0")} ${timePart || "00:00:00"}`;
      }
      // Unix timestamp (seconds, 10 digits)
      if (/^\d{10}(\.\d+)?$/.test(s)) {
        const d = new Date(parseFloat(s) * 1000);
        if (!isNaN(d)) return d.toISOString().replace("T", " ").replace("Z", "");
      }
      // Unix timestamp (milliseconds, 13 digits)
      if (/^\d{13}$/.test(s)) {
        const d = new Date(parseInt(s));
        if (!isNaN(d)) return d.toISOString().replace("T", " ").replace("Z", "");
      }
      // Excel serial date
      if (/^\d{1,5}(\.\d+)?$/.test(s)) {
        const serial = parseFloat(s);
        if (serial >= 1 && serial <= 73050) {
          const d = new Date(Math.round((serial - 25569) * 86400000));
          if (!isNaN(d.getTime()) && d.getFullYear() >= 1900 && d.getFullYear() <= 2100)
            return d.toISOString().replace("T", " ").replace("Z", "");
        }
      }
      // Fallback: JS Date parse
      const d = new Date(s);
      if (!isNaN(d) && d.getFullYear() > 1970 && d.getFullYear() < 2100)
        return d.toISOString().replace("T", " ").replace("Z", "");
      // Unparseable — return original so it still sorts somehow
      return s;
    });

    // page_size MUST be set before any tables are created
    // 64KB pages: fewer B-tree nodes, faster bulk writes & index creation
    db.pragma("page_size = 65536");

    // Performance pragmas for bulk import (maximise write throughput)
    db.pragma("journal_mode = OFF"); // no journal — fastest writes (temp DB, crash = re-import)
    db.pragma("synchronous = OFF");
    db.pragma("cache_size = -1048576"); // 1GB write cache — keep entire B-tree in memory
    db.pragma("temp_store = MEMORY");
    db.pragma("mmap_size = 0"); // disable mmap during import (write-only)
    db.pragma("locking_mode = EXCLUSIVE"); // single-user, avoid lock overhead
    db.pragma("threads = 4"); // parallel sort for internal operations

    // Sanitize headers for SQL column names
    const safeCols = headers.map((h, i) => ({
      original: h,
      safe: `c${i}`,
    }));

    // Create main data table
    const colDefs = safeCols.map((c) => `${c.safe} TEXT`).join(", ");
    db.exec(`CREATE TABLE data (rowid INTEGER PRIMARY KEY, ${colDefs})`);

    // FTS5 table created lazily on first search (avoid DDL overhead during import)

    // Create bookmarks table
    db.exec(`CREATE TABLE bookmarks (rowid INTEGER PRIMARY KEY)`);

    // Create tags table
    db.exec(`CREATE TABLE tags (rowid INTEGER, tag TEXT, PRIMARY KEY(rowid, tag))`);
    db.exec(`CREATE INDEX idx_tags_tag ON tags(tag)`);

    // Create color rules table
    db.exec(
      `CREATE TABLE color_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        col_name TEXT, condition TEXT, value TEXT,
        bg_color TEXT, fg_color TEXT
      )`
    );

    // Detect timestamp columns based on header names
    const tsColumns = new Set();
    headers.forEach((h) => {
      if (
        /(time|date|timestamp|created|modified|accessed|when|start|end|written)/i.test(h)
      ) {
        tsColumns.add(h);
      }
    });

    // Prepare bulk insert statement
    const colList = safeCols.map((c) => c.safe).join(", ");
    const placeholders = safeCols.map(() => "?").join(", ");
    const insertStmt = db.prepare(
      `INSERT INTO data (${colList}) VALUES (${placeholders})`
    );

    // Prepare multi-row INSERT for faster bulk loading
    // SQLite limit is 32766 host parameters — use full capacity (no artificial 1000 cap)
    const multiRowCount = Math.max(1, Math.floor(32766 / safeCols.length));
    let multiInsertStmt = null;
    if (multiRowCount > 1) {
      const singleRow = `(${placeholders})`;
      const multiValues = Array(multiRowCount).fill(singleRow).join(",");
      multiInsertStmt = db.prepare(
        `INSERT INTO data (${colList}) VALUES ${multiValues}`
      );
    }

    // Pre-allocate flat params array (reused across all insertBatchArrays calls)
    const insertFlat = multiRowCount > 1 ? new Array(multiRowCount * safeCols.length) : null;

    const meta = {
      tabId,
      db,
      dbPath,
      headers,
      safeCols,
      tsColumns,
      rowCount: 0,
      ftsReady: false,
      insertStmt,
      multiInsertStmt,
      multiRowCount,
      insertFlat,
      colMap: Object.fromEntries(safeCols.map((c) => [c.original, c.safe])),
      reverseColMap: Object.fromEntries(safeCols.map((c) => [c.safe, c.original])),
    };

    this.databases.set(tabId, meta);
    dbg("DB", `createTab OK`, { tabId, colCount: headers.length, tsColumns: [...tsColumns] });
    return { tabId, headers, tsColumns: [...tsColumns] };
    } catch (err) {
      dbg("DB", `createTab FAILED`, { tabId, error: err.message, stack: err.stack });
      // Clean up on failure — prevent leaked DB connections and orphaned temp files
      try { db.close(); } catch (_) {}
      try { fs.unlinkSync(dbPath); } catch (_) {}
      throw err;
    }
  }

  /**
   * Insert a batch of rows as arrays (fast path — used by parser)
   * Each row is a pre-built array of values in column order.
   * No object allocation or property lookup per row.
   */
  insertBatchArrays(tabId, rows) {
    const meta = this.databases.get(tabId);
    if (!meta) throw new Error(`Tab ${tabId} not found`);

    const singleStmt = meta.insertStmt;
    const multiStmt = meta.multiInsertStmt;
    const multiN = meta.multiRowCount;
    const colCount = meta.headers.length;
    const flat = meta.insertFlat; // pre-allocated in createTab, reused across all calls

    const tx = meta.db.transaction(() => {
      let i = 0;

      if (multiStmt && multiN > 1 && flat) {
        while (i + multiN <= rows.length) {
          for (let r = 0; r < multiN; r++) {
            const row = rows[i + r];
            const off = r * colCount;
            for (let c = 0; c < colCount; c++) {
              flat[off + c] = row[c];
            }
          }
          multiStmt.run(flat);
          i += multiN;
        }
      }

      // Remainder with single-row inserts
      while (i < rows.length) {
        singleStmt.run(rows[i]);
        i++;
      }
    });
    tx();

    meta.rowCount += rows.length;
    return meta.rowCount;
  }

  /**
   * Insert a batch of rows as objects (legacy — used by session restore)
   */
  insertBatch(tabId, rows) {
    const meta = this.databases.get(tabId);
    if (!meta) throw new Error(`Tab ${tabId} not found`);

    const stmt = meta.insertStmt;
    const hdrs = meta.headers;
    const tx = meta.db.transaction(() => {
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const values = new Array(hdrs.length);
        for (let c = 0; c < hdrs.length; c++) {
          values[c] = row[hdrs[c]] || "";
        }
        stmt.run(values);
      }
    });
    tx();

    meta.rowCount += rows.length;
    return meta.rowCount;
  }

  /**
   * Finalize import: detect column types, switch to query mode.
   * Indexes, FTS, and ANALYZE are all deferred to async background builds
   * so the UI becomes interactive immediately after import completes.
   */
  finalizeImport(tabId) {
    dbg("DB", `finalizeImport start`, { tabId });
    const meta = this.databases.get(tabId);
    if (!meta) { dbg("DB", `finalizeImport: no meta for tab`); return; }

    const db = meta.db;

    // FTS index is built lazily on first search — skip here for fast import.
    meta.ftsReady = false;

    // Sort indexes are built asynchronously after import — skip here.
    meta.indexedCols = new Set();
    meta.indexesReady = false;
    meta.indexesBuilding = false;

    // Detect numeric columns (fast — only samples 100 rows)
    const sampleRows = db
      .prepare(
        `SELECT ${meta.safeCols.map((c) => c.safe).join(", ")} FROM data LIMIT 100`
      )
      .all();

    meta.numericColumns = new Set();
    meta.safeCols.forEach((col) => {
      // Skip columns already detected as timestamps — parseFloat("2026-01-17 01:26:27")
      // returns 2026 (the year), falsely classifying timestamps as numeric.
      if (meta.tsColumns.has(col.original)) return;
      const values = sampleRows
        .map((r) => r[col.safe])
        .filter((v) => v && v.trim());
      if (values.length > 0) {
        // Use Number() instead of parseFloat() — Number() requires the ENTIRE string
        // to be a valid number, preventing false positives like "2026-01-17" → 2026
        const numCount = values.filter((v) => v.trim() !== "" && !isNaN(Number(v.trim()))).length;
        if (numCount / values.length > 0.8) {
          meta.numericColumns.add(col.original);
        }
      }
    });

    // Minimal pragmas so initial queries work while background builds run.
    // buildIndexesAsync/buildFtsAsync set their own aggressive pragmas and
    // restore full query mode (WAL + mmap + 256MB cache) when they finish.
    db.pragma("journal_mode = WAL"); // need WAL for concurrent reads during build
    db.pragma("synchronous = NORMAL");
    db.pragma("cache_size = -262144"); // 256MB cache for queries

    // Skip ANALYZE here — run after async index build completes

    return {
      rowCount: meta.rowCount,
      headers: meta.headers,
      tsColumns: [...meta.tsColumns],
      numericColumns: [...meta.numericColumns],
    };
  }

  /**
   * Build column sort index on demand (called on first sort of that column).
   * Deferred from import to keep file open near-instant.
   */
  _ensureIndex(tabId, colName) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    const safeCol = meta.colMap[colName];
    if (!safeCol || meta.indexedCols.has(safeCol)) return;
    try {
      meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${safeCol} ON data(${safeCol})`);
    } catch (e) {
      // Ignore index creation failures
    }
    meta.indexedCols.add(safeCol);
  }

  /**
   * Build FTS index on demand (called on first search).
   * If the async chunked build is in progress, this is a no-op (search
   * falls back to LIKE until FTS is ready). If it was never started
   * (e.g. session restore), builds synchronously as a fallback.
   */
  _ensureFts(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta || meta.ftsReady) return;
    // If async build is in progress, don't block — search will use LIKE fallback
    if (meta.ftsBuilding) return;

    const colList = meta.safeCols.map((c) => c.safe).join(", ");

    // Create FTS5 table if it doesn't exist yet
    if (!meta.ftsCreated) {
      meta.db.exec(
        `CREATE VIRTUAL TABLE IF NOT EXISTS data_fts USING fts5(${colList}, content=data, content_rowid=rowid)`
      );
      meta.ftsCreated = true;
    }

    meta.db.exec(
      `INSERT INTO data_fts(rowid, ${colList}) SELECT rowid, ${colList} FROM data`
    );
    meta.db.exec(`INSERT INTO data_fts(data_fts) VALUES('optimize')`);
    meta.ftsReady = true;
  }

  /**
   * Build FTS index asynchronously in chunks.
   * Yields to the event loop between chunks so IPC queries remain responsive.
   * Called automatically after finalizeImport — no UI hang.
   *
   * @param {string} tabId
   * @param {Function} onProgress - ({ indexed, total, done }) callback per chunk
   * @returns {Promise<void>}
   */
  buildFtsAsync(tabId, onProgress) {
    const meta = this.databases.get(tabId);
    if (!meta || meta.ftsReady || meta.ftsBuilding) return Promise.resolve();
    meta.ftsBuilding = true;

    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    const db = meta.db;

    // Create FTS5 virtual table
    if (!meta.ftsCreated) {
      db.exec(
        `CREATE VIRTUAL TABLE IF NOT EXISTS data_fts USING fts5(${colList}, content=data, content_rowid=rowid)`
      );
      meta.ftsCreated = true;
    }

    const totalRows = meta.rowCount || db.prepare("SELECT COUNT(*) as cnt FROM data").get().cnt;
    // 200k rows per chunk — keeps each blocking segment ~1-3s so UI stays responsive
    const CHUNK = 200000;
    let lastRowid = 0;

    // Aggressive pragmas for FTS build (temp DB — crash = re-import)
    db.pragma("journal_mode = OFF");
    db.pragma("synchronous = OFF");
    db.pragma("cache_size = -1048576"); // 1GB — keep data pages in memory for fast SELECT
    db.pragma("temp_store = MEMORY"); // FTS merge temp in memory
    db.pragma("threads = 8"); // parallel sort/merge

    // Send initial progress so the UI can show the FTS overlay immediately
    if (onProgress) onProgress({ indexed: 0, total: totalRows, done: false });

    return new Promise((resolve) => {
      const insertChunk = () => {
        // Tab may have been closed while building
        if (!this.databases.has(tabId)) { resolve(); return; }

        const inserted = db.prepare(
          `INSERT INTO data_fts(rowid, ${colList}) SELECT rowid, ${colList} FROM data WHERE rowid > ? ORDER BY rowid LIMIT ?`
        ).run(lastRowid, CHUNK);

        lastRowid += CHUNK;
        const indexed = Math.min(lastRowid, totalRows);

        if (inserted.changes < CHUNK) {
          // All rows indexed — switch back to query mode
          db.pragma("journal_mode = WAL");
          db.pragma("synchronous = NORMAL");
          db.pragma("cache_size = -262144"); // 256MB for queries
          db.pragma("mmap_size = 536870912"); // 512MB mmap for reads
          try { db.pragma("wal_checkpoint(PASSIVE)"); } catch (e) { /* ignore */ }
          meta.ftsReady = true;
          meta.ftsBuilding = false;
          if (onProgress) onProgress({ indexed: totalRows, total: totalRows, done: true });
          resolve();
        } else {
          if (onProgress) onProgress({ indexed, total: totalRows, done: false });
          // Yield to event loop before next chunk — keeps UI responsive
          setImmediate(insertChunk);
        }
      };

      // Defer first chunk — let the UI render the FTS overlay first
      setImmediate(insertChunk);
    });
  }

  /**
   * Build column indexes asynchronously after import.
   * Yields to the event loop between each index so IPC queries remain responsive.
   * Called automatically after finalizeImport — the UI is already interactive.
   *
   * @param {string} tabId
   * @param {Function} onProgress - ({ built, total, done, currentCol }) callback per index
   * @returns {Promise<void>}
   */
  buildIndexesAsync(tabId, onProgress) {
    const meta = this.databases.get(tabId);
    if (!meta || meta.indexesReady || meta.indexesBuilding) return Promise.resolve();
    meta.indexesBuilding = true;

    const cols = meta.safeCols.filter((c) => !meta.indexedCols.has(c.safe));
    const total = cols.length;
    let built = 0;

    dbg("DB", `buildIndexesAsync start`, { tabId, total });

    // Aggressive pragmas for index build (temp DB — crash = re-import)
    meta.db.pragma("journal_mode = OFF"); // no journal overhead during CREATE INDEX
    meta.db.pragma("synchronous = OFF");
    meta.db.pragma("cache_size = -1048576"); // 1GB — keep entire table + index pages in memory
    meta.db.pragma("temp_store = MEMORY"); // sort temp files in memory
    meta.db.pragma("threads = 8"); // parallel sort for CREATE INDEX
    meta.db.pragma("mmap_size = 0"); // disable mmap — rely on cache (write-heavy)

    // Send initial progress so the UI overlay renders immediately
    if (onProgress) onProgress({ built: 0, total, done: false, currentCol: cols[0]?.original });

    return new Promise((resolve) => {
      const buildNext = () => {
        // Tab may have been closed while building
        if (!this.databases.has(tabId)) { resolve(); return; }

        if (built >= cols.length) {
          // Run ANALYZE for query optimizer stats
          try {
            meta.db.exec("ANALYZE");
          } catch (e) {
            dbg("DB", `ANALYZE failed`, { error: e.message });
          }

          // Switch back to query mode
          meta.db.pragma("journal_mode = WAL");
          meta.db.pragma("synchronous = NORMAL");
          meta.db.pragma("cache_size = -262144"); // 256MB for queries
          meta.db.pragma("mmap_size = 536870912"); // 512MB mmap for reads
          try { meta.db.pragma("wal_checkpoint(PASSIVE)"); } catch (e) { /* ignore */ }

          meta.indexesReady = true;
          meta.indexesBuilding = false;
          dbg("DB", `buildIndexesAsync complete`, { tabId, total });
          if (onProgress) onProgress({ built: total, total, done: true, currentCol: null });
          resolve();
          return;
        }

        // Build ONE index per yield — each CREATE INDEX on 1M+ rows takes 1-3s,
        // yielding after each keeps the event loop responsive for UI updates
        const col = cols[built];
        try {
          meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${col.safe} ON data(${col.safe})`);
          meta.indexedCols.add(col.safe);
        } catch (e) {
          dbg("DB", `index creation failed for ${col.original}`, { error: e.message });
        }
        built++;

        if (onProgress) onProgress({ built, total, done: false, currentCol: col.original });

        // Yield to event loop after each index — keeps UI responsive
        setImmediate(buildNext);
      };

      // Defer first index — let the UI render the overlay first
      setImmediate(buildNext);
    });
  }

  /**
   * Check if background builds (indexes/FTS) are running on a tab.
   * While builds run, the DB uses aggressive pragmas (journal_mode=OFF)
   * that make concurrent queries unsafe.
   */
  _isBuilding(tabId) {
    const meta = this.databases.get(tabId);
    return meta && (meta.indexesBuilding || meta.ftsBuilding);
  }

  /**
   * Query rows with filtering, sorting, and pagination
   * This is the main query method — only fetches the visible window
   */
  queryRows(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { rows: [], totalFiltered: 0 };

    const {
      offset = 0,
      limit = -1,
      sortCol = null,
      sortDir = "asc",
      searchTerm = "",
      searchMode = "mixed",
      searchCondition = "contains",
      columnFilters = {},
      checkboxFilters = {},
      bookmarkedOnly = false,
      tagFilter = null,
      groupCol = null,
      groupValue = undefined,
      groupFilters = [],
      dateRangeFilters = {},
      advancedFilters = [],
    } = options;

    const db = meta.db;
    const params = [];
    let whereConditions = [];
    let usesFts = false;

    // ── Column filters ─────────────────────────────────────────
    for (const [colName, filterVal] of Object.entries(columnFilters)) {
      if (!filterVal) continue;
      const safeCol = meta.colMap[colName];
      if (!safeCol) continue;
      whereConditions.push(`${safeCol} LIKE ?`);
      params.push(`%${filterVal}%`);
    }

    // ── Checkbox filters (exact value match) ──────────────────
    for (const [colName, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const safeCol = meta.colMap[colName];
      if (!safeCol) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${safeCol} IS NULL OR ${safeCol} = '')`);
      if (nonNull.length === 1) { parts.push(`${safeCol} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${safeCol} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }

    // ── Group filter (single - legacy) ───────────────────────
    if (groupCol && groupValue !== undefined) {
      const safeCol = meta.colMap[groupCol];
      if (safeCol) {
        whereConditions.push(`${safeCol} = ?`);
        params.push(groupValue);
      }
    }

    // ── Multi-level group filters ────────────────────────────
    for (const gf of groupFilters) {
      const safeCol = meta.colMap[gf.col];
      if (safeCol) {
        whereConditions.push(`${safeCol} = ?`);
        params.push(gf.value);
      }
    }

    // ── Date range filters ─────────────────────────────────────
    for (const [colName, range] of Object.entries(dateRangeFilters)) {
      const safeCol = meta.colMap[colName];
      if (!safeCol) continue;
      if (range.from) { whereConditions.push(`${safeCol} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${safeCol} <= ?`); params.push(range.to); }
    }

    // ── Bookmarked only ────────────────────────────────────────
    if (bookmarkedOnly) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    }

    // ── Tag filter (any tagged, single tag, or multi-tag) ──
    if (tagFilter === "__any__") {
      whereConditions.push(`data.rowid IN (SELECT DISTINCT rowid FROM tags)`);
    } else if (Array.isArray(tagFilter) && tagFilter.length > 0) {
      const ph = tagFilter.map(() => "?").join(",");
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag IN (${ph}))`);
      params.push(...tagFilter);
    } else if (tagFilter && typeof tagFilter === "string") {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag = ?)`);
      params.push(tagFilter);
    }

    // ── Advanced filters (Edit Filter multi-condition) ────────
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    // ── Global search ──────────────────────────────────────────
    if (searchTerm.trim()) {
      this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    }

    const whereClause =
      whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")}`
        : "";

    // ── Count total filtered rows (cached by filter signature) ──
    const filterSig = whereClause + "|" + params.join("|");
    let totalFiltered;
    if (meta._countCache && meta._countCache.sig === filterSig) {
      totalFiltered = meta._countCache.cnt;
    } else {
      const countSql = `SELECT COUNT(*) as cnt FROM data ${whereClause}`;
      totalFiltered = db.prepare(countSql).get(...params).cnt;
      meta._countCache = { sig: filterSig, cnt: totalFiltered };
    }

    // ── Sort ───────────────────────────────────────────────────
    let orderClause = "ORDER BY data.rowid";
    if (sortCol) {
      const safeCol = meta.colMap[sortCol];
      if (safeCol) {
        // Lazy-build index on first sort for this column
        this._ensureIndex(tabId, sortCol);
        const dir = sortDir === "desc" ? "DESC" : "ASC";
        // Timestamp columns checked first (takes priority over numeric — prevents
        // false-positive numeric detection from breaking timestamp sorting)
        if (meta.tsColumns.has(sortCol)) {
          orderClause = `ORDER BY sort_datetime(${safeCol}) ${dir}`;
        } else if (meta.numericColumns.has(sortCol)) {
          orderClause = `ORDER BY CAST(${safeCol} AS REAL) ${dir}`;
        } else {
          orderClause = `ORDER BY ${safeCol} COLLATE NOCASE ${dir}`;
        }
      }
    }

    // ── Fetch window ───────────────────────────────────────────
    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    const querySql = `SELECT data.rowid as _rowid, ${colList} FROM data ${whereClause} ${orderClause} LIMIT ? OFFSET ?`;
    const queryParams = [...params, limit, offset];

    const rawRows = db.prepare(querySql).all(...queryParams);

    // Map back to original column names — tight loop, no closures
    const colCount = meta.safeCols.length;
    const rows = new Array(rawRows.length);
    for (let r = 0; r < rawRows.length; r++) {
      const raw = rawRows[r];
      const row = { __idx: raw._rowid };
      for (let c = 0; c < colCount; c++) {
        row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] || "";
      }
      rows[r] = row;
    }

    // Get bookmark + tag data for fetched rows in batches
    // (SQLite max variable limit is ~32766, so batch large sets)
    const rowIds = rawRows.map((r) => r._rowid);
    const bookmarkedSet = new Set();
    const rowTags = {};
    const BATCH = 5000;
    for (let i = 0; i < rowIds.length; i += BATCH) {
      const batch = rowIds.slice(i, i + BATCH);
      const placeholders = batch.map(() => "?").join(",");
      const bm = db.prepare(`SELECT rowid FROM bookmarks WHERE rowid IN (${placeholders})`).all(...batch);
      for (const b of bm) bookmarkedSet.add(b.rowid);
      const tags = db.prepare(`SELECT rowid, tag FROM tags WHERE rowid IN (${placeholders})`).all(...batch);
      for (const t of tags) {
        if (!rowTags[t.rowid]) rowTags[t.rowid] = [];
        rowTags[t.rowid].push(t.tag);
      }
    }

    return {
      rows,
      totalFiltered,
      totalRows: meta.rowCount,
      bookmarkedRows: [...bookmarkedSet],
      rowTags,
    };
  }

  /**
   * Apply global search conditions to a WHERE clause.
   * Handles FTS, regex, and column-specific search uniformly.
   */
  _applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition = "contains") {
    if (!searchTerm.trim()) return;

    // Fuzzy search — uses custom fuzzy_match() SQLite function
    if (searchCondition === "fuzzy" && searchMode !== "regex") {
      const terms = searchMode === "exact" ? [searchTerm.trim()] : searchTerm.trim().split(/\s+/).filter(Boolean);
      const joinOp = searchMode === "or" ? " OR " : " AND ";
      const termConditions = terms.map((term) => {
        const colConds = meta.safeCols.map((c) => {
          params.push(term);
          return `fuzzy_match(${c.safe}, ?)`;
        });
        return `(${colConds.join(" OR ")})`;
      });
      whereConditions.push(`(${termConditions.join(joinOp)})`);
      return;
    }

    // Non-default conditions bypass FTS — use direct SQL LIKE/=
    if (searchCondition !== "contains" && searchMode !== "regex") {
      const terms = searchMode === "exact" ? [searchTerm.trim()] : searchTerm.trim().split(/\s+/).filter(Boolean);
      const joinOp = searchMode === "or" ? " OR " : " AND ";
      const termConditions = terms.map((term) => {
        const colConds = meta.safeCols.map((c) => {
          if (searchCondition === "startswith") { params.push(`${term}%`); return `${c.safe} LIKE ?`; }
          if (searchCondition === "like") { params.push(term); return `${c.safe} LIKE ?`; }
          if (searchCondition === "equals") { params.push(term); return `${c.safe} = ?`; }
          params.push(`%${term}%`); return `${c.safe} LIKE ?`;
        });
        return `(${colConds.join(" OR ")})`;
      });
      whereConditions.push(`(${termConditions.join(joinOp)})`);
      return;
    }

    if (searchMode === "regex") {
      const regexConds = meta.safeCols.map((c) => `${c.safe} REGEXP ?`);
      whereConditions.push(`(${regexConds.join(" OR ")})`);
      for (let i = 0; i < meta.safeCols.length; i++) params.push(searchTerm.trim());
      return;
    }
    // If FTS is not ready yet (async build in progress), fall back to LIKE search
    if (!meta.ftsReady) {
      const terms = searchMode === "exact" ? [searchTerm.trim()] : searchTerm.trim().split(/\s+/).filter(Boolean);
      const joinOp = (searchMode === "or") ? " OR " : " AND ";
      const termConditions = terms.map((term) => {
        const colConds = meta.safeCols.map((c) => {
          params.push(`%${term}%`);
          return `${c.safe} LIKE ?`;
        });
        return `(${colConds.join(" OR ")})`;
      });
      whereConditions.push(`(${termConditions.join(joinOp)})`);
      return;
    }
    const { ftsQuery, colConditions } = this._buildSearchQuery(searchTerm, searchMode, meta);
    if (ftsQuery) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM data_fts WHERE data_fts MATCH ?)`);
      params.push(ftsQuery);
    }
    for (const cc of colConditions) {
      whereConditions.push(cc.sql);
      params.push(cc.param);
    }
  }

  /**
   * Apply advanced multi-condition filters (Edit Filter feature).
   * Groups conditions by AND/OR logic with correct SQL precedence:
   *   A AND B OR C AND D  →  (A AND B) OR (C AND D)
   */
  _applyAdvancedFilters(advancedFilters, meta, whereConditions, params) {
    if (!advancedFilters || advancedFilters.length === 0) return;

    // Filter out incomplete conditions
    const valid = advancedFilters.filter((f) => {
      if (!f.column || !f.operator) return false;
      if (f.operator !== "is_empty" && f.operator !== "is_not_empty" && !f.value && f.value !== 0) return false;
      const sc = meta.colMap[f.column];
      return !!sc;
    });
    if (valid.length === 0) return;

    // Build SQL for a single condition
    const buildCondition = (f) => {
      const sc = meta.colMap[f.column];
      switch (f.operator) {
        case "contains":
          params.push(`%${f.value}%`);
          return `${sc} LIKE ?`;
        case "not_contains":
          params.push(`%${f.value}%`);
          return `${sc} NOT LIKE ?`;
        case "equals":
          params.push(f.value);
          return `${sc} = ?`;
        case "not_equals":
          params.push(f.value);
          return `${sc} != ?`;
        case "starts_with":
          params.push(`${f.value}%`);
          return `${sc} LIKE ?`;
        case "ends_with":
          params.push(`%${f.value}`);
          return `${sc} LIKE ?`;
        case "greater_than":
          params.push(f.value);
          return `CAST(${sc} AS REAL) > CAST(? AS REAL)`;
        case "less_than":
          params.push(f.value);
          return `CAST(${sc} AS REAL) < CAST(? AS REAL)`;
        case "is_empty":
          return `(${sc} IS NULL OR ${sc} = '')`;
        case "is_not_empty":
          return `(${sc} IS NOT NULL AND ${sc} != '')`;
        case "regex":
          params.push(f.value);
          return `${sc} REGEXP ?`;
        default:
          params.push(`%${f.value}%`);
          return `${sc} LIKE ?`;
      }
    };

    // Group consecutive AND-linked conditions, join groups with OR
    const groups = [];
    let currentGroup = [buildCondition(valid[0])];

    for (let i = 1; i < valid.length; i++) {
      if (valid[i].logic === "OR") {
        groups.push(currentGroup);
        currentGroup = [buildCondition(valid[i])];
      } else {
        currentGroup.push(buildCondition(valid[i]));
      }
    }
    groups.push(currentGroup);

    // Build final expression
    const expr = groups
      .map((g) => (g.length > 1 ? `(${g.join(" AND ")})` : g[0]))
      .join(" OR ");

    whereConditions.push(groups.length > 1 ? `(${expr})` : expr);
  }

  /**
   * Build search query from search term and mode.
   * Returns { ftsQuery, colConditions } where:
   *   - ftsQuery: FTS5 MATCH string (or null if no FTS terms)
   *   - colConditions: array of { sql, param } for column-specific Col:value filters
   */
  _buildSearchQuery(searchTerm, searchMode, meta) {
    // Lazy-build FTS index on first search
    this._ensureFts(meta.tabId);
    const result = { ftsQuery: null, colConditions: [] };
    try {
      if (searchMode === "exact") {
        const cleaned = searchTerm.replace(/"/g, "").trim();
        result.ftsQuery = `"${cleaned}"`;
        return result;
      }

      if (searchMode === "or") {
        const terms = searchTerm.trim().split(/\s+/).filter(Boolean);
        result.ftsQuery = terms.map((t) => `"${t.replace(/"/g, "")}"`).join(" OR ");
        return result;
      }

      if (searchMode === "and") {
        const terms = searchTerm.trim().split(/\s+/).filter(Boolean);
        result.ftsQuery = terms.map((t) => `"${t.replace(/"/g, "")}"`).join(" AND ");
        return result;
      }

      // Mixed mode — parse +AND, -EXCLUDE, "phrases", Column:value
      const tokens = [];
      const regex = /"([^"]+)"|(\S+)/g;
      let m;
      while ((m = regex.exec(searchTerm)) !== null) {
        tokens.push(m[1] ? `"${m[1]}"` : m[2]);
      }

      const ftsTerms = [];
      for (const token of tokens) {
        if (token.startsWith('"')) {
          ftsTerms.push(token);
        } else if (token.includes(":")) {
          // Column-specific filter: Col:value → WHERE colSafe LIKE %value%
          const colonIdx = token.indexOf(":");
          const colPart = token.substring(0, colonIdx);
          const valPart = token.substring(colonIdx + 1);
          if (valPart) {
            // Find matching column (case-insensitive)
            const matchCol = meta.headers.find((h) => h.toLowerCase() === colPart.toLowerCase());
            const safeCol = matchCol ? meta.colMap[matchCol] : null;
            if (safeCol) {
              result.colConditions.push({ sql: `${safeCol} LIKE ?`, param: `%${valPart}%` });
            }
          }
        } else if (token.startsWith("-")) {
          const term = token.slice(1);
          if (term) ftsTerms.push(`NOT "${term}"`);
        } else if (token.startsWith("+")) {
          const term = token.slice(1);
          if (term) ftsTerms.push(`"${term}"`);
        } else {
          ftsTerms.push(`"${token}"`);
        }
      }

      if (ftsTerms.length > 0) {
        const hasOperator = tokens.some((t) => t.startsWith("+") || t.startsWith("-"));
        // Default to AND for multi-word (DFIR analysts want all terms to match)
        result.ftsQuery = ftsTerms.join(hasOperator ? " AND " : (ftsTerms.length > 1 ? " AND " : ""));
      }

      return result;
    } catch (e) {
      result.ftsQuery = `"${searchTerm.replace(/"/g, "").trim()}"`;
      return result;
    }
  }

  /**
   * Toggle bookmark on a row
   */
  _invalidateCountCache(tabId) {
    const meta = this.databases.get(tabId);
    if (meta) meta._countCache = null;
  }

  toggleBookmark(tabId, rowId) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    this._invalidateCountCache(tabId);
    const exists = meta.db
      .prepare("SELECT rowid FROM bookmarks WHERE rowid = ?")
      .get(rowId);
    if (exists) {
      meta.db.prepare("DELETE FROM bookmarks WHERE rowid = ?").run(rowId);
      return false;
    } else {
      meta.db
        .prepare("INSERT OR IGNORE INTO bookmarks (rowid) VALUES (?)")
        .run(rowId);
      return true;
    }
  }

  /**
   * Bulk toggle bookmarks
   */
  setBookmarks(tabId, rowIds, add = true) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    this._invalidateCountCache(tabId);
    const stmt = add
      ? meta.db.prepare("INSERT OR IGNORE INTO bookmarks (rowid) VALUES (?)")
      : meta.db.prepare("DELETE FROM bookmarks WHERE rowid = ?");
    const tx = meta.db.transaction((ids) => {
      for (const id of ids) stmt.run(id);
    });
    tx(rowIds);
  }

  /**
   * Get bookmark count
   */
  getBookmarkCount(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return 0;
    return meta.db.prepare("SELECT COUNT(*) as cnt FROM bookmarks").get().cnt;
  }

  /**
   * Get all bookmarked row IDs
   */
  getBookmarkedIds(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    return meta.db
      .prepare("SELECT rowid FROM bookmarks")
      .all()
      .map((r) => r.rowid);
  }

  // ── Tag operations ─────────────────────────────────────────────

  addTag(tabId, rowId, tag) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    meta.db.prepare("INSERT OR IGNORE INTO tags (rowid, tag) VALUES (?, ?)").run(rowId, tag);
  }

  removeTag(tabId, rowId, tag) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    meta.db.prepare("DELETE FROM tags WHERE rowid = ? AND tag = ?").run(rowId, tag);
  }

  getTagsForRows(tabId, rowIds) {
    const meta = this.databases.get(tabId);
    if (!meta) return {};
    const result = {};
    for (let i = 0; i < rowIds.length; i += 500) {
      const batch = rowIds.slice(i, i + 500);
      const placeholders = batch.map(() => "?").join(",");
      const rows = meta.db.prepare(`SELECT rowid, tag FROM tags WHERE rowid IN (${placeholders})`).all(...batch);
      for (const r of rows) {
        if (!result[r.rowid]) result[r.rowid] = [];
        result[r.rowid].push(r.tag);
      }
    }
    return result;
  }

  getAllTags(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    return meta.db.prepare("SELECT tag, COUNT(*) as cnt FROM tags GROUP BY tag ORDER BY cnt DESC").all();
  }

  getAllTagData(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    return meta.db.prepare("SELECT rowid, tag FROM tags").all();
  }

  /**
   * Gather all data needed for HTML report generation.
   * Returns bookmarked rows, tagged rows grouped by tag, and summary stats.
   */
  getReportData(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const d = meta.db;
    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    const mapRow = (raw) => {
      const row = {};
      for (let c = 0; c < meta.safeCols.length; c++) {
        row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] || "";
      }
      return row;
    };

    // Bookmarked rows (full data)
    const bookmarkedRows = d.prepare(
      `SELECT ${colList} FROM data WHERE rowid IN (SELECT rowid FROM bookmarks) ORDER BY rowid`
    ).all().map(mapRow);

    // Tags: unique tags with counts
    const tagSummary = d.prepare(
      "SELECT tag, COUNT(*) as cnt FROM tags GROUP BY tag ORDER BY cnt DESC"
    ).all();

    // Tagged rows grouped by tag (single JOIN query instead of per-tag N+1)
    const taggedGroups = {};
    if (tagSummary.length > 0) {
      const allTaggedRows = d.prepare(
        `SELECT t.tag, ${colList} FROM data d INNER JOIN tags t ON d.rowid = t.rowid ORDER BY t.tag, d.rowid`
      ).all();
      for (const row of allTaggedRows) {
        const tag = row.tag;
        if (!taggedGroups[tag]) taggedGroups[tag] = [];
        const mapped = {};
        for (let c = 0; c < meta.safeCols.length; c++) {
          mapped[meta.safeCols[c].original] = row[meta.safeCols[c].safe] || "";
        }
        taggedGroups[tag].push(mapped);
      }
    }

    // Summary stats
    const totalRows = meta.rowCount;
    const bookmarkCount = d.prepare("SELECT COUNT(*) as cnt FROM bookmarks").get().cnt;
    const tagCount = d.prepare("SELECT COUNT(DISTINCT tag) as cnt FROM tags").get().cnt;
    const taggedRowCount = d.prepare("SELECT COUNT(DISTINCT rowid) as cnt FROM tags").get().cnt;

    // Timestamp range (from first ts column if available)
    let tsRange = null;
    if (meta.tsColumns && meta.tsColumns.size > 0) {
      const firstTsCol = [...meta.tsColumns][0];
      const safeCol = meta.colMap[firstTsCol];
      if (safeCol) {
        const range = d.prepare(
          `SELECT MIN(${safeCol}) as earliest, MAX(${safeCol}) as latest FROM data WHERE ${safeCol} IS NOT NULL AND ${safeCol} != ''`
        ).get();
        if (range?.earliest) tsRange = { column: firstTsCol, earliest: range.earliest, latest: range.latest };
      }
    }

    return {
      headers: meta.headers,
      totalRows,
      bookmarkCount,
      bookmarkedRows,
      tagSummary,
      taggedGroups,
      tagCount,
      taggedRowCount,
      tsRange,
    };
  }

  bulkAddTags(tabId, tagMap) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    const ins = meta.db.prepare("INSERT OR IGNORE INTO tags (rowid, tag) VALUES (?, ?)");
    const tx = meta.db.transaction(() => {
      for (const [rowId, tags] of Object.entries(tagMap)) {
        for (const tag of tags) ins.run(Number(rowId), tag);
      }
    });
    tx();
  }

  /**
   * Bulk-tag rows within specific time ranges directly in SQL.
   * ranges = [{ from, to, tag }] — e.g. [{ from: "2024-01-15 08:30", to: "2024-01-15 10:45", tag: "Session 1" }]
   * Never materializes rowIds in JS — pure SQL INSERT...SELECT.
   */
  bulkTagByTimeRange(tabId, colName, ranges) {
    const meta = this.databases.get(tabId);
    if (!meta || ranges.length === 0) return { taggedCount: 0 };
    const safeCol = meta.colMap[colName];
    if (!safeCol) return { taggedCount: 0 };
    const db = meta.db;
    let taggedCount = 0;
    const tx = db.transaction(() => {
      for (const { from, to, tag } of ranges) {
        const fromTs = from.length === 16 ? from + ":00" : from;
        const toTs = to.length === 16 ? to + ":59" : to;
        const result = db.prepare(`
          INSERT OR IGNORE INTO tags (rowid, tag)
          SELECT rowid, ? FROM data
          WHERE ${safeCol} >= ? AND ${safeCol} <= ?
            AND ${safeCol} IS NOT NULL AND ${safeCol} != ''
        `).run(tag, fromTs, toTs);
        taggedCount += result.changes;
      }
    });
    tx();
    return { taggedCount };
  }

  /**
   * Bulk tag all rows matching current filters.
   * Uses INSERT...SELECT — never materializes rowIds in JS.
   */
  bulkTagFiltered(tabId, tag, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta || !tag) return { tagged: 0 };

    const {
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, tagFilter = null,
      dateRangeFilters = {}, advancedFilters = [],
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`);
      params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [colName, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[colName];
      if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    }
    if (tagFilter === "__any__") {
      whereConditions.push(`data.rowid IN (SELECT DISTINCT rowid FROM tags)`);
    } else if (Array.isArray(tagFilter) && tagFilter.length > 0) {
      const ph = tagFilter.map(() => "?").join(",");
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag IN (${ph}))`);
      params.push(...tagFilter);
    } else if (tagFilter && typeof tagFilter === "string") {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag = ?)`);
      params.push(tagFilter);
    }
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);
    if (searchTerm.trim()) {
      this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const result = db.prepare(`INSERT OR IGNORE INTO tags (rowid, tag) SELECT data.rowid, ? FROM data ${whereClause}`).run(tag, ...params);
    this._invalidateCountCache(tabId);
    return { tagged: result.changes };
  }

  /**
   * Bulk bookmark (or un-bookmark) all rows matching current filters.
   * Uses INSERT...SELECT / DELETE...SELECT — never materializes rowIds in JS.
   */
  bulkBookmarkFiltered(tabId, add, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { affected: 0 };

    const {
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, tagFilter = null,
      dateRangeFilters = {}, advancedFilters = [],
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`);
      params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [colName, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[colName];
      if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    }
    if (tagFilter === "__any__") {
      whereConditions.push(`data.rowid IN (SELECT DISTINCT rowid FROM tags)`);
    } else if (Array.isArray(tagFilter) && tagFilter.length > 0) {
      const ph = tagFilter.map(() => "?").join(",");
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag IN (${ph}))`);
      params.push(...tagFilter);
    } else if (tagFilter && typeof tagFilter === "string") {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag = ?)`);
      params.push(tagFilter);
    }
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);
    if (searchTerm.trim()) {
      this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    let result;
    if (add) {
      result = db.prepare(`INSERT OR IGNORE INTO bookmarks (rowid) SELECT data.rowid FROM data ${whereClause}`).run(...params);
    } else {
      result = db.prepare(`DELETE FROM bookmarks WHERE rowid IN (SELECT data.rowid FROM data ${whereClause})`).run(...params);
    }
    this._invalidateCountCache(tabId);
    return { affected: result.changes };
  }

  /**
   * Match IOC patterns against all columns using REGEXP.
   * Returns matched rowIds and per-IOC hit counts.
   */
  matchIocs(tabId, iocPatterns, batchSize = 200) {
    const meta = this.databases.get(tabId);
    if (!meta || iocPatterns.length === 0) return { matchedRowIds: [], perIocCounts: {} };

    const db = meta.db;
    const colList = meta.safeCols.map((c) => c.safe);

    // Phase 1: batched REGEXP alternation scan for matching rowIds
    const matchedSet = new Set();
    for (let i = 0; i < iocPatterns.length; i += batchSize) {
      const batch = iocPatterns.slice(i, i + batchSize);
      const altPattern = batch.join("|");
      const colConds = colList.map((c) => `${c} REGEXP ?`).join(" OR ");
      const params = [];
      for (let j = 0; j < colList.length; j++) params.push(altPattern);
      const rows = db.prepare(`SELECT rowid FROM data WHERE ${colConds}`).all(...params);
      for (const r of rows) matchedSet.add(r.rowid);
    }

    const matchedRowIds = [...matchedSet];
    if (matchedRowIds.length === 0) {
      const perIocCounts = {};
      for (const p of iocPatterns) perIocCounts[p] = 0;
      return { matchedRowIds, perIocCounts };
    }

    // Phase 2: per-IOC hit counts on matched rows only
    const allMatchedRows = [];
    for (let i = 0; i < matchedRowIds.length; i += 500) {
      const batch = matchedRowIds.slice(i, i + 500);
      const ph = batch.map(() => "?").join(",");
      const rows = db.prepare(`SELECT ${colList.join(", ")} FROM data WHERE rowid IN (${ph})`).all(...batch);
      for (const r of rows) allMatchedRows.push(r);
    }

    const perIocCounts = {};
    for (const pattern of iocPatterns) {
      let count = 0;
      let re;
      try { re = new RegExp(pattern, "i"); } catch { perIocCounts[pattern] = 0; continue; }
      for (const row of allMatchedRows) {
        if (colList.some((c) => re.test(row[c] || ""))) count++;
      }
      perIocCounts[pattern] = count;
    }

    return { matchedRowIds, perIocCounts };
  }

  /**
   * Export filtered data as streaming CSV
   */
  exportQuery(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;

    const {
      sortCol = null,
      sortDir = "asc",
      searchTerm = "",
      searchMode = "mixed",
      searchCondition = "contains",
      columnFilters = {},
      checkboxFilters = {},
      bookmarkedOnly = false,
      visibleHeaders = null,
      dateRangeFilters = {},
      advancedFilters = [],
    } = options;

    const headers = visibleHeaders || meta.headers;
    const safeCols = headers.map((h) => meta.colMap[h]).filter(Boolean);
    const colList = safeCols.join(", ");

    const params = [];
    let whereConditions = [];

    for (const [colName, filterVal] of Object.entries(columnFilters)) {
      if (!filterVal) continue;
      const safeCol = meta.colMap[colName];
      if (!safeCol) continue;
      whereConditions.push(`${safeCol} LIKE ?`);
      params.push(`%${filterVal}%`);
    }

    for (const [colName, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const safeCol = meta.colMap[colName];
      if (!safeCol) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${safeCol} IS NULL OR ${safeCol} = '')`);
      if (nonNull.length === 1) { parts.push(`${safeCol} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${safeCol} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }

    // Date range filters
    for (const [colName, range] of Object.entries(dateRangeFilters)) {
      const safeCol = meta.colMap[colName];
      if (!safeCol) continue;
      if (range.from) { whereConditions.push(`${safeCol} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${safeCol} <= ?`); params.push(range.to); }
    }

    if (bookmarkedOnly) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    }

    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    if (searchTerm.trim()) {
      this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    }

    const whereClause =
      whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")}`
        : "";

    let orderClause = "ORDER BY data.rowid";
    if (sortCol) {
      const safeCol = meta.colMap[sortCol];
      if (safeCol) {
        const dir = sortDir === "desc" ? "DESC" : "ASC";
        if (meta.tsColumns.has(sortCol)) {
          orderClause = `ORDER BY sort_datetime(${safeCol}) ${dir}`;
        } else if (meta.numericColumns.has(sortCol)) {
          orderClause = `ORDER BY CAST(${safeCol} AS REAL) ${dir}`;
        } else {
          orderClause = `ORDER BY ${safeCol} COLLATE NOCASE ${dir}`;
        }
      }
    }

    const sql = `SELECT ${colList} FROM data ${whereClause} ${orderClause}`;
    const stmt = meta.db.prepare(sql);
    const iter = stmt.iterate(...params);

    return {
      headers,
      iterator: iter,
      safeCols,
      reverseMap: meta.reverseColMap,
    };
  }

  /**
   * Get column statistics (unique values, min/max for numerics)
   */
  getColumnStats(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const safeCol = meta.colMap[colName];
    if (!safeCol) return null;

    const {
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, dateRangeFilters = {},
      advancedFilters = [],
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Build WHERE clause (same pattern as getGroupValues/getStackingData)
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`); params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    if (bookmarkedOnly) whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    if (searchTerm.trim()) this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn]; if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    try {
      const totalRows = db.prepare(`SELECT COUNT(*) as cnt FROM data ${whereClause}`).get(...params).cnt;

      // Non-empty count — append condition to existing WHERE
      const neWhere = whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")} AND ${safeCol} IS NOT NULL AND ${safeCol} != ''`
        : `WHERE ${safeCol} IS NOT NULL AND ${safeCol} != ''`;
      const nonEmptyCount = db.prepare(`SELECT COUNT(*) as cnt FROM data ${neWhere}`).get(...params).cnt;
      const emptyCount = totalRows - nonEmptyCount;
      const uniqueCount = db.prepare(`SELECT COUNT(DISTINCT ${safeCol}) as cnt FROM data ${whereClause}`).get(...params).cnt;
      const fillRate = totalRows > 0 ? Math.round((nonEmptyCount / totalRows) * 10000) / 100 : 0;

      // Top 25 values
      const topValues = db.prepare(
        `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${neWhere} GROUP BY ${safeCol} ORDER BY cnt DESC LIMIT 25`
      ).all(...params);

      const result = { totalRows, nonEmptyCount, emptyCount, uniqueCount, fillRate, topValues };

      // Timestamp stats
      if (meta.tsColumns.has(colName)) {
        const tsRange = db.prepare(
          `SELECT MIN(sort_datetime(${safeCol})) as earliest, MAX(sort_datetime(${safeCol})) as latest FROM data ${neWhere}`
        ).get(...params);
        if (tsRange && tsRange.earliest) {
          result.tsStats = { earliest: tsRange.earliest, latest: tsRange.latest };
          try {
            const e = new Date(tsRange.earliest.replace(" ", "T"));
            const l = new Date(tsRange.latest.replace(" ", "T"));
            const diffMs = l.getTime() - e.getTime();
            if (!isNaN(diffMs) && diffMs >= 0) result.tsStats.timespanMs = diffMs;
          } catch { /* non-parseable */ }
        }
      }

      // Numeric stats
      if (meta.numericColumns && meta.numericColumns.has(colName)) {
        const numStats = db.prepare(
          `SELECT MIN(CAST(${safeCol} AS REAL)) as minVal, MAX(CAST(${safeCol} AS REAL)) as maxVal, AVG(CAST(${safeCol} AS REAL)) as avgVal FROM data ${neWhere}`
        ).get(...params);
        if (numStats) {
          result.numStats = {
            min: numStats.minVal,
            max: numStats.maxVal,
            avg: Math.round(numStats.avgVal * 100) / 100,
          };
        }
      }

      return result;
    } catch (e) {
      return { totalRows: 0, nonEmptyCount: 0, emptyCount: 0, uniqueCount: 0, fillRate: 0, topValues: [], error: e.message };
    }
  }

  /**
   * Get columns that are entirely empty (NULL or '')
   */
  getEmptyColumns(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    const db = meta.db;
    const empty = [];
    for (const h of meta.headers) {
      const safeCol = meta.colMap[h];
      if (!safeCol) continue;
      const row = db.prepare(`SELECT 1 FROM data WHERE ${safeCol} IS NOT NULL AND ${safeCol} != '' LIMIT 1`).get();
      if (!row) empty.push(h);
    }
    return empty;
  }

  /**
   * Get tab metadata
   */
  getTabInfo(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    return {
      headers: meta.headers,
      rowCount: meta.rowCount,
      tsColumns: [...meta.tsColumns],
      numericColumns: meta.numericColumns ? [...meta.numericColumns] : [],
    };
  }

  /**
   * Get unique values for a column (for checkbox filter dropdowns)
   * Respects all active filters except the checkbox filter for this column.
   */
  getColumnUniqueValues(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];

    const safeCol = meta.colMap[colName];
    if (!safeCol) return [];

    const {
      searchTerm = "",
      searchMode = "mixed",
      searchCondition = "contains",
      columnFilters = {},
      checkboxFilters = {},
      bookmarkedOnly = false,
      filterText = "",
      filterRegex = false,
      limit = 1000,
      dateRangeFilters = {},
      advancedFilters = [],
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Column LIKE filters
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`);
      params.push(`%${fv}%`);
    }

    // Checkbox filters for OTHER columns (exclude self)
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (cn === colName || !values || values.length === 0) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }

    if (bookmarkedOnly) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    }

    if (searchTerm.trim()) {
      this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    }

    // Date range filters
    for (const [colName, range] of Object.entries(dateRangeFilters)) {
      const safeCol = meta.colMap[colName];
      if (!safeCol) continue;
      if (range.from) { whereConditions.push(`${safeCol} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${safeCol} <= ?`); params.push(range.to); }
    }

    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    // Filter values list by search text (supports regex mode)
    if (filterText.trim()) {
      if (filterRegex) {
        whereConditions.push(`${safeCol} REGEXP ?`);
        params.push(filterText);
      } else {
        whereConditions.push(`${safeCol} LIKE ?`);
        params.push(`%${filterText}%`);
      }
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const sql = `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${safeCol} ORDER BY cnt DESC LIMIT ?`;
    params.push(limit);

    return db.prepare(sql).all(...params);
  }

  /**
   * Get group values with counts (for column grouping display)
   * Respects all active filters.
   */
  getGroupValues(tabId, groupCol, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];

    const safeCol = meta.colMap[groupCol];
    if (!safeCol) return [];

    const {
      searchTerm = "",
      searchMode = "mixed",
      searchCondition = "contains",
      columnFilters = {},
      checkboxFilters = {},
      bookmarkedOnly = false,
      parentFilters = [],
      dateRangeFilters = {},
      advancedFilters = [],
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Parent group filters (for multi-level grouping)
    for (const pf of parentFilters) {
      const sc = meta.colMap[pf.col];
      if (sc) {
        whereConditions.push(`${sc} = ?`);
        params.push(pf.value);
      }
    }

    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`);
      params.push(`%${fv}%`);
    }

    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }

    if (bookmarkedOnly) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    }

    if (searchTerm.trim()) {
      this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    }

    // Date range filters
    for (const [colName, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[colName];
      if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const sql = `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${safeCol} ORDER BY cnt DESC`;

    return db.prepare(sql).all(...params);
  }

  /**
   * Count rows matching a search term (for cross-tab find)
   */
  searchCount(tabId, searchTerm, searchMode = "mixed", searchCondition = "contains") {
    const meta = this.databases.get(tabId);
    if (!meta) return 0;
    if (!searchTerm.trim()) return 0;

    const conditions = [];
    const params = [];
    this._applySearch(searchTerm, searchMode, meta, conditions, params, searchCondition);
    if (conditions.length === 0) return 0;
    const sql = `SELECT COUNT(*) as cnt FROM data WHERE ${conditions.join(" AND ")}`;
    return meta.db.prepare(sql).get(...params).cnt;
  }

  /**
   * Get histogram data for a timestamp column (event density over time).
   * Groups by day (first 10 chars = YYYY-MM-DD) and respects all active filters.
   */
  getHistogramData(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    const safeCol = meta.colMap[colName];
    if (!safeCol) return [];
    const {
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, dateRangeFilters = {},
      advancedFilters = [],
      granularity = "day",
    } = options;
    const db = meta.db;
    const params = [];
    const whereConditions = [`${safeCol} IS NOT NULL`, `${safeCol} != ''`];
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`);
      params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn];
      if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    if (searchTerm.trim()) this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);
    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;
    const extractFn = granularity === "hour" ? `substr(extract_datetime_minute(${safeCol}), 1, 13)` : `extract_date(${safeCol})`;
    const sql = `SELECT ${extractFn} as day, COUNT(*) as cnt FROM data ${whereClause} GROUP BY day HAVING day IS NOT NULL ORDER BY day`;
    try { return db.prepare(sql).all(...params); } catch { return []; }
  }

  /**
   * Gap Analysis — detect quiet periods and activity sessions.
   * Buckets timestamps by minute, finds gaps > threshold, segments into sessions.
   * Returns { gaps, sessions, totalEvents }.
   */
  getGapAnalysis(tabId, colName, gapThresholdMinutes = 60, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { gaps: [], sessions: [], totalEvents: 0 };
    const safeCol = meta.colMap[colName];
    if (!safeCol) return { gaps: [], sessions: [], totalEvents: 0 };
    const {
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, dateRangeFilters = {},
      advancedFilters = [],
    } = options;
    const db = meta.db;
    const params = [];
    const whereConditions = [`${safeCol} IS NOT NULL`, `${safeCol} != ''`];
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`);
      params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn];
      if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    if (searchTerm.trim()) this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);
    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;
    const sql = `SELECT extract_datetime_minute(${safeCol}) as mb, COUNT(*) as cnt FROM data ${whereClause} GROUP BY mb HAVING mb IS NOT NULL ORDER BY mb`;
    try {
      const buckets = db.prepare(sql).all(...params);
      if (buckets.length === 0) return { gaps: [], sessions: [], totalEvents: 0 };
      const totalEvents = buckets.reduce((s, b) => s + b.cnt, 0);
      const thresholdMs = gapThresholdMinutes * 60000;
      const parseMin = (mb) => new Date(mb.replace(" ", "T") + ":00Z").getTime();
      const gaps = [];
      const sessions = [];
      let sStart = 0;
      let sEvents = buckets[0].cnt;
      for (let i = 1; i < buckets.length; i++) {
        const prevMs = parseMin(buckets[i - 1].mb);
        const currMs = parseMin(buckets[i].mb);
        const gapMs = currMs - prevMs;
        if (gapMs > thresholdMs) {
          sessions.push({
            idx: sessions.length + 1,
            from: buckets[sStart].mb,
            to: buckets[i - 1].mb,
            eventCount: sEvents,
            durationMinutes: Math.round((parseMin(buckets[i - 1].mb) - parseMin(buckets[sStart].mb)) / 60000),
          });
          gaps.push({
            from: buckets[i - 1].mb,
            to: buckets[i].mb,
            durationMinutes: Math.round(gapMs / 60000),
          });
          sStart = i;
          sEvents = buckets[i].cnt;
        } else {
          sEvents += buckets[i].cnt;
        }
      }
      sessions.push({
        idx: sessions.length + 1,
        from: buckets[sStart].mb,
        to: buckets[buckets.length - 1].mb,
        eventCount: sEvents,
        durationMinutes: Math.round((parseMin(buckets[buckets.length - 1].mb) - parseMin(buckets[sStart].mb)) / 60000),
      });
      return { gaps, sessions, totalEvents };
    } catch (e) {
      return { gaps: [], sessions: [], totalEvents: 0, error: e.message };
    }
  }

  /**
   * Log Source Coverage Map — shows which log sources are present,
   * their time span (earliest→latest), event count, and coverage.
   */
  getLogSourceCoverage(tabId, sourceCol, tsCol, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { sources: [], globalEarliest: null, globalLatest: null, totalEvents: 0, totalSources: 0 };
    const safeSourceCol = meta.colMap[sourceCol];
    const safeTsCol = meta.colMap[tsCol];
    if (!safeSourceCol || !safeTsCol) return { sources: [], globalEarliest: null, globalLatest: null, totalEvents: 0, totalSources: 0 };

    const {
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, dateRangeFilters = {},
      advancedFilters = [],
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [
      `${safeSourceCol} IS NOT NULL`, `${safeSourceCol} != ''`,
      `${safeTsCol} IS NOT NULL`, `${safeTsCol} != ''`,
    ];

    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`); params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn]; if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    if (searchTerm.trim()) this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;

    try {
      const sql = `SELECT ${safeSourceCol} as source, COUNT(*) as cnt, MIN(${safeTsCol}) as earliest, MAX(${safeTsCol}) as latest FROM data ${whereClause} GROUP BY ${safeSourceCol} ORDER BY cnt DESC`;
      const sources = db.prepare(sql).all(...params);

      if (sources.length === 0) {
        return { sources: [], globalEarliest: null, globalLatest: null, totalEvents: 0, totalSources: 0 };
      }

      const totalEvents = sources.reduce((s, r) => s + r.cnt, 0);
      let globalEarliest = sources[0].earliest;
      let globalLatest = sources[0].latest;
      for (const s of sources) {
        if (s.earliest < globalEarliest) globalEarliest = s.earliest;
        if (s.latest > globalLatest) globalLatest = s.latest;
      }

      return { sources, globalEarliest, globalLatest, totalEvents, totalSources: sources.length };
    } catch (e) {
      return { sources: [], globalEarliest: null, globalLatest: null, totalEvents: 0, totalSources: 0, error: e.message };
    }
  }

  /**
   * Event Burst Detection — find windows with abnormally high event density.
   * Groups timestamps into windows, calculates median baseline, flags
   * windows exceeding baseline × multiplier, merges adjacent burst windows.
   */
  getBurstAnalysis(tabId, colName, windowMinutes = 5, thresholdMultiplier = 5, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { bursts: [], baseline: 0, windowMinutes, totalEvents: 0, totalWindows: 0 };
    const safeCol = meta.colMap[colName];
    if (!safeCol) return { bursts: [], baseline: 0, windowMinutes, totalEvents: 0, totalWindows: 0 };

    const {
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, dateRangeFilters = {},
      advancedFilters = [],
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [`${safeCol} IS NOT NULL`, `${safeCol} != ''`];

    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`); params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn]; if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    if (searchTerm.trim()) this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;

    try {
      // Step 1: Get minute-level buckets (same as gap analysis)
      const sql = `SELECT extract_datetime_minute(${safeCol}) as mb, COUNT(*) as cnt FROM data ${whereClause} GROUP BY mb HAVING mb IS NOT NULL ORDER BY mb`;
      const minuteBuckets = db.prepare(sql).all(...params);

      if (minuteBuckets.length === 0) {
        return { bursts: [], baseline: 0, windowMinutes, totalEvents: 0, totalWindows: 0 };
      }

      const totalEvents = minuteBuckets.reduce((s, b) => s + b.cnt, 0);
      const parseMin = (mb) => new Date(mb.replace(" ", "T") + ":00Z").getTime();

      // Step 2: Aggregate minute buckets into windows
      let windows;
      if (windowMinutes === 1) {
        windows = minuteBuckets.map((b) => ({ ts: b.mb, tsMs: parseMin(b.mb), cnt: b.cnt }));
      } else {
        const firstMs = parseMin(minuteBuckets[0].mb);
        const windowMs = windowMinutes * 60000;
        const windowMap = new Map();
        for (const b of minuteBuckets) {
          const bMs = parseMin(b.mb);
          const windowStart = firstMs + Math.floor((bMs - firstMs) / windowMs) * windowMs;
          if (windowMap.has(windowStart)) {
            windowMap.get(windowStart).cnt += b.cnt;
          } else {
            const d = new Date(windowStart);
            const ts = d.toISOString().slice(0, 16).replace("T", " ");
            windowMap.set(windowStart, { ts, tsMs: windowStart, cnt: b.cnt });
          }
        }
        windows = [...windowMap.values()].sort((a, b) => a.tsMs - b.tsMs);
      }

      const totalWindows = windows.length;

      // Step 3: Calculate median baseline
      const sortedCounts = windows.map((w) => w.cnt).sort((a, b) => a - b);
      const mid = Math.floor(sortedCounts.length / 2);
      const rawBaseline = sortedCounts.length % 2 === 0
        ? (sortedCounts[mid - 1] + sortedCounts[mid]) / 2
        : sortedCounts[mid];
      const baseline = rawBaseline || 1; // guard against zero
      const threshold = baseline * thresholdMultiplier;

      // Step 4: Identify burst windows
      const burstFlags = windows.map((w) => w.cnt > threshold);

      // Step 5: Merge adjacent burst windows into contiguous periods
      const bursts = [];
      let i = 0;
      while (i < windows.length) {
        if (!burstFlags[i]) { i++; continue; }
        const burstStart = i;
        let burstEvents = 0;
        let peakRate = 0;
        while (i < windows.length && burstFlags[i]) {
          burstEvents += windows[i].cnt;
          if (windows[i].cnt > peakRate) peakRate = windows[i].cnt;
          i++;
        }
        const burstEnd = i - 1;
        const fromTs = windows[burstStart].ts;
        const toMs = windows[burstEnd].tsMs + windowMinutes * 60000;
        const toDate = new Date(toMs);
        const toTs = toDate.toISOString().slice(0, 16).replace("T", " ");

        bursts.push({
          from: fromTs, to: toTs,
          eventCount: burstEvents, peakRate,
          burstFactor: Math.round((burstEvents / ((burstEnd - burstStart + 1) * baseline)) * 10) / 10,
          windowCount: burstEnd - burstStart + 1,
          durationMinutes: (burstEnd - burstStart + 1) * windowMinutes,
        });
      }

      // Step 6: Build sparkline data
      const sparkline = windows.map((w) => ({ ts: w.ts, cnt: w.cnt, isBurst: w.cnt > threshold }));

      return {
        bursts, baseline: Math.round(baseline * 10) / 10, threshold: Math.round(threshold * 10) / 10,
        windowMinutes, totalEvents, totalWindows,
        peakRate: windows.length > 0 ? Math.max(...windows.map((w) => w.cnt)) : 0,
        sparkline,
      };
    } catch (e) {
      return { bursts: [], baseline: 0, windowMinutes, totalEvents: 0, totalWindows: 0, error: e.message };
    }
  }

  /**
   * Stacking / Value Frequency Analysis
   * Returns all unique values for a column with counts, percentages, and totals.
   * Respects all active filters. No row limit — returns complete frequency distribution.
   */
  getStackingData(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { totalRows: 0, totalUnique: 0, values: [] };
    const safeCol = meta.colMap[colName];
    if (!safeCol) return { totalRows: 0, totalUnique: 0, values: [] };
    const {
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, dateRangeFilters = {},
      filterText = "", sortBy = "count",
      advancedFilters = [],
    } = options;
    const db = meta.db;
    const params = [];
    const whereConditions = [];
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`); params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn]; if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    if (searchTerm.trim()) this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);
    if (filterText.trim()) {
      whereConditions.push(`${safeCol} LIKE ?`); params.push(`%${filterText}%`);
    }
    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const orderBy = sortBy === "value" ? `val ASC` : `cnt DESC, val ASC`;
    const MAX_STACKING_VALUES = 10000;
    try {
      const totalRow = db.prepare(`SELECT COUNT(*) as total FROM data ${whereClause}`).get(...params);
      const totalRows = totalRow?.total || 0;
      const uniqueRow = db.prepare(`SELECT COUNT(DISTINCT ${safeCol}) as cnt FROM data ${whereClause}`).get(...params);
      const totalUnique = uniqueRow?.cnt || 0;
      const sql = `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${safeCol} ORDER BY ${orderBy} LIMIT ${MAX_STACKING_VALUES}`;
      const values = db.prepare(sql).all(...params);
      return { totalRows, totalUnique, values, truncated: totalUnique > MAX_STACKING_VALUES };
    } catch { return { totalRows: 0, totalUnique: 0, values: [], truncated: false }; }
  }

  /**
   * Build a process tree from Sysmon EventID 1 (Process Create) events.
   * Auto-detects columns, queries filtered rows, builds parent-child map.
   */
  getProcessTree(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { processes: [], stats: {}, columns: {}, error: "No database" };

    const {
      pidCol: userPidCol, ppidCol: userPpidCol,
      guidCol: userGuidCol, parentGuidCol: userParentGuidCol,
      imageCol: userImageCol, cmdLineCol: userCmdLineCol,
      userCol: userUserCol, tsCol: userTsCol, eventIdCol: userEventIdCol,
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, dateRangeFilters = {},
      advancedFilters = [],
      eventIdValue = "1",
      maxRows = 200000,
    } = options;

    // Auto-detect columns (case-insensitive)
    const detect = (patterns) => {
      for (const pat of patterns) {
        const found = meta.headers.find((h) => pat.test(h));
        if (found) return found;
      }
      return null;
    };

    // Detect EvtxECmd format (KAPE output)
    const isEvtxECmdPT = meta.headers.some((h) => /^PayloadData1$/i.test(h)) && meta.headers.some((h) => /^ExecutableInfo$/i.test(h));

    const columns = {
      pid:         userPidCol        || detect([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
      ppid:        userPpidCol       || detect([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^parent_pid$/i, /^CreatorProcessId$/i]),
      guid:        userGuidCol       || detect([/^ProcessGuid$/i, /^process_guid$/i]),
      parentGuid:  userParentGuidCol || detect([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
      image:       userImageCol      || detect([/^Image$/i, /^process_name$/i, /^exe$/i, /^FileName$/i, /^ImagePath$/i, /^NewProcessName$/i]),
      parentImage: detect([/^ParentImage$/i, /^ParentProcessName$/i]),
      cmdLine:     userCmdLineCol    || detect([/^CommandLine$/i, /^command_line$/i, /^cmd$/i, /^cmdline$/i, /^ProcessCommandLine$/i]),
      user:        userUserCol       || detect([/^User$/i, /^UserName$/i, /^user_name$/i, /^SubjectUserName$/i, /^TargetUserName$/i]),
      ts:          userTsCol         || detect([/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i, /^timestamp$/i]),
      eventId:     userEventIdCol    || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/]),
      elevation:   detect([/^TokenElevationType$/i, /^Token_Elevation_Type$/i]),
      integrity:   detect([/^MandatoryLabel$/i, /^Mandatory_Label$/i, /^IntegrityLevel$/i]),
    };

    // EvtxECmd: OVERRIDE columns — ProcessId in CSV header is the logging service PID (e.g., Sysmon 5464),
    // NOT the created process PID. Real PID/GUID is inside PayloadData1/PayloadData5.
    // PayloadData1: "ProcessID: N, ProcessGUID: {guid}"
    // PayloadData5: "ParentProcessID: N, ParentProcessGUID: {guid}"
    // ExecutableInfo: full command line (image path extractable from first token)
    if (isEvtxECmdPT) {
      columns.pid = detect([/^PayloadData1$/i]) || columns.pid;       // MUST override — CSV ProcessId is service PID
      columns.ppid = detect([/^PayloadData5$/i]) || columns.ppid;     // MUST override
      columns.guid = detect([/^PayloadData1$/i]) || columns.guid;     // GUID parsed from same field as PID
      columns.parentGuid = detect([/^PayloadData5$/i]) || columns.parentGuid; // parent GUID from same field as PPID
      columns.image = detect([/^ExecutableInfo$/i]) || columns.image; // image extracted from command line
      columns.cmdLine = detect([/^ExecutableInfo$/i]) || columns.cmdLine;
    }
    columns._isEvtxECmd = isEvtxECmdPT;

    const useGuid = !!(columns.guid && columns.parentGuid) || isEvtxECmdPT;
    if (!columns.pid && !columns.guid && !isEvtxECmdPT) return { processes: [], stats: {}, columns, error: "Cannot detect ProcessId or ProcessGuid column" };
    if (!columns.ppid && !columns.parentGuid && !isEvtxECmdPT) return { processes: [], stats: {}, columns, error: "Cannot detect ParentProcessId or ParentProcessGuid column" };

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Filter to EventID value(s) — supports comma-separated (e.g., "1,4688")
    if (columns.eventId && eventIdValue) {
      const safeEid = meta.colMap[columns.eventId];
      if (safeEid) {
        const eids = eventIdValue.split(",").map(s => s.trim()).filter(Boolean);
        if (eids.length === 1) { whereConditions.push(`${safeEid} = ?`); params.push(eids[0]); }
        else if (eids.length > 1) { whereConditions.push(`${safeEid} IN (${eids.map(() => "?").join(",")})`); params.push(...eids); }
      }
    }

    // Standard filter application
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`); params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn]; if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    if (searchTerm.trim()) this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    // Build SELECT — deduplicate when multiple keys map to the same column (e.g., EvtxECmd: pid+guid both from PayloadData1)
    const selectParts = ["data.rowid as _rowid"];
    const selectedCols = new Set();
    for (const [key, colName] of Object.entries(columns)) {
      if (key.startsWith("_")) continue;  // skip internal flags
      if (colName && meta.colMap[colName] && !selectedCols.has(colName)) {
        selectParts.push(`${meta.colMap[colName]} as [${key}]`);
        selectedCols.add(colName);
      }
    }

    const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
    const orderClause = orderCol ? `ORDER BY ${orderCol} ASC` : "ORDER BY data.rowid ASC";

    try {
      const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
      const rows = db.prepare(sql).all(...params);

      // Build parent-child map
      const processes = [];
      const byKey = new Map();
      const childrenOf = new Map();

      for (const row of rows) {
        let pid = row.pid || "";
        let ppid = row.ppid || "";
        let guid = row.guid || "";
        let parentGuid = row.parentGuid || "";
        let imagePath = row.image || "";
        let cmdLine = row.cmdLine || "";

        // EvtxECmd: parse structured PayloadData fields
        if (isEvtxECmdPT) {
          // PayloadData1: "ProcessID: 5668, ProcessGUID: 7bf9956e-0a95-6931-a700-000000000700"
          // row.pid holds PayloadData1 (may also be aliased as guid due to same column)
          const pd1 = row.pid || row.guid || "";
          const pidMatch = pd1.match(/ProcessID:\s*(\d+)/i);
          const guidMatch = pd1.match(/ProcessGUID:\s*([0-9a-f-]+)/i);
          if (pidMatch) pid = pidMatch[1];
          if (guidMatch) guid = guidMatch[1];

          // PayloadData5: "ParentProcessID: 4408, ParentProcessGUID: 7bf9956e-..."
          const pd5 = row.ppid || row.parentGuid || "";
          const ppidMatch = pd5.match(/ParentProcessID:\s*(\d+)/i);
          const pguidMatch = pd5.match(/ParentProcessGUID:\s*([0-9a-f-]+)/i);
          if (ppidMatch) ppid = ppidMatch[1];
          if (pguidMatch) parentGuid = pguidMatch[1];

          // ExecutableInfo: full command line — may be aliased as image or cmdLine depending on dedup order
          const execInfo = row.image || row.cmdLine || "";
          cmdLine = execInfo;
          // Extract image path from command line (first token, may be quoted)
          if (execInfo) {
            const qm = execInfo.match(/^"([^"]+)"/);
            imagePath = qm ? qm[1] : execInfo.split(/\s/)[0];
          }
        }

        // Hex PID conversion (Security 4688 format: "0x1a2c")
        if (typeof pid === "string" && /^0x[0-9a-f]+$/i.test(pid.trim())) pid = String(parseInt(pid.trim(), 16));
        if (typeof ppid === "string" && /^0x[0-9a-f]+$/i.test(ppid.trim())) ppid = String(parseInt(ppid.trim(), 16));

        const key = useGuid && guid
          ? guid
          : `pid:${pid}:${row._rowid}`;
        const parentKey = useGuid && parentGuid
          ? parentGuid
          : `pid:${ppid}`;

        const processName = imagePath.split("\\").pop().split("/").pop() || "(unknown)";

        const node = {
          key, parentKey, rowid: row._rowid,
          pid, ppid, guid, parentGuid,
          image: imagePath, processName, parentImage: row.parentImage || "",
          cmdLine, user: row.user || "", ts: row.ts || "",
          elevation: row.elevation || "", integrity: row.integrity || "",
          childCount: 0, depth: 0,
        };
        processes.push(node);
        byKey.set(key, node);
        if (!childrenOf.has(parentKey)) childrenOf.set(parentKey, []);
        childrenOf.get(parentKey).push(key);
      }

      // Child counts
      for (const node of processes) node.childCount = (childrenOf.get(node.key) || []).length;

      // Compute depth via BFS from roots
      const roots = processes.filter((p) => !byKey.has(p.parentKey));
      const visited = new Set();
      const queue = roots.map((r) => ({ key: r.key, depth: 0 }));
      while (queue.length > 0) {
        const { key, depth } = queue.shift();
        if (visited.has(key)) continue; // guard against cycles
        visited.add(key);
        const node = byKey.get(key);
        if (node) node.depth = depth;
        for (const ck of (childrenOf.get(key) || [])) queue.push({ key: ck, depth: depth + 1 });
      }

      return {
        processes, columns, useGuid,
        stats: {
          totalProcesses: processes.length,
          rootCount: roots.length,
          maxDepth: processes.length > 0 ? Math.max(...processes.map((p) => p.depth)) : 0,
          truncated: rows.length >= maxRows,
        },
      };
    } catch (e) {
      return { processes: [], stats: {}, columns, error: e.message };
    }
  }

  getLateralMovement(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { nodes: [], edges: [], chains: [], stats: {}, columns: {}, error: "No database" };

    const {
      sourceCol: userSourceCol, targetCol: userTargetCol,
      userCol: userUserCol, logonTypeCol: userLogonTypeCol,
      eventIdCol: userEventIdCol, tsCol: userTsCol, domainCol: userDomainCol,
      eventIds = ["4624", "4625", "4648", "4778"],
      excludeLocalLogons = true,
      excludeServiceAccounts = true,
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, dateRangeFilters = {},
      advancedFilters = [],
      maxRows = 500000,
    } = options;

    const detect = (patterns) => {
      for (const pat of patterns) {
        const found = meta.headers.find((h) => pat.test(h));
        if (found) return found;
      }
      return null;
    };

    // Detect EvtxECmd format (KAPE output): RemoteHost, PayloadData1-6
    const isEvtxECmd = meta.headers.some((h) => /^RemoteHost$/i.test(h)) && meta.headers.some((h) => /^PayloadData1$/i.test(h));

    const columns = {
      source:      userSourceCol    || detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^Source_Network_Address$/i, /^RemoteHost$/i]),
      workstation: detect([/^WorkstationName$/i, /^Workstation_Name$/i, /^SourceHostname$/i, /^SourceComputerName$/i]),
      target:      userTargetCol    || detect([/^Computer$/i, /^ComputerName$/i, /^computer_name$/i, /^Hostname$/i]),
      user:        userUserCol      || detect([/^TargetUserName$/i, /^Target_User_Name$/i, /^UserName$/i, ...(isEvtxECmd ? [/^PayloadData1$/i] : [])]),
      logonType:   userLogonTypeCol || detect([/^LogonType$/i, /^Logon_Type$/i, ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]),
      eventId:     userEventIdCol   || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/]),
      ts:          userTsCol        || detect([/^datetime$/i, /^UtcTime$/i, /^TimeCreated$/i, /^timestamp$/i]),
      domain:      userDomainCol    || detect([/^TargetDomainName$/i, /^Target_Domain_Name$/i, /^SubjectDomainName$/i]),
      // 4778 session reconnect columns (RDP lateral movement — attacker hostname/IP)
      clientName:    detect([/^ClientName$/i, /^Client_Name$/i]),
      clientAddress: detect([/^ClientAddress$/i, /^Client_Address$/i, /^ClientIP$/i]),
      // EvtxECmd extra columns for value parsing
      _remoteHost: isEvtxECmd ? detect([/^RemoteHost$/i]) : null,
      _payloadData1: isEvtxECmd ? detect([/^PayloadData1$/i]) : null,
      _payloadData2: isEvtxECmd ? detect([/^PayloadData2$/i]) : null,
    };
    columns._isEvtxECmd = isEvtxECmd;

    if (!columns.source && !columns.workstation) return { nodes: [], edges: [], chains: [], stats: {}, columns, error: "Cannot detect source host column (IpAddress, WorkstationName, or RemoteHost)" };
    if (!columns.target) return { nodes: [], edges: [], chains: [], stats: {}, columns, error: "Cannot detect target host column (Computer)" };

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    if (columns.eventId && eventIds.length > 0) {
      const safeEid = meta.colMap[columns.eventId];
      if (safeEid) {
        whereConditions.push(`${safeEid} IN (${eventIds.map(() => "?").join(",")})`);
        params.push(...eventIds);
      }
    }

    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`); params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn]; if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    if (searchTerm.trim()) this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    const selectParts = ["data.rowid as _rowid"];
    for (const [key, colName] of Object.entries(columns)) {
      if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
    }

    const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
    const orderClause = orderCol ? `ORDER BY ${orderCol} ASC` : "ORDER BY data.rowid ASC";

    try {
      const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
      const rows = db.prepare(sql).all(...params);

      const EXCLUDED_IPS = new Set(["-", "::1", "127.0.0.1", "0.0.0.0", ""]);
      const SERVICE_RE = /^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON)$/i;

      const edgeMap = new Map();
      const hostSet = new Map();
      const timeOrdered = [];

      for (const row of rows) {
        const targetHost = (row.target || "").toUpperCase().trim();
        if (!targetHost) continue;

        const eventId = row.eventId || "";

        // 4778: Session reconnected — ClientName is attacker hostname, ClientAddress is attacker IP
        let clientName = "";
        let clientAddress = "";
        let sourceHost = "";

        if (eventId === "4778") {
          clientName = (row.clientName || "").trim();
          clientAddress = (row.clientAddress || "").trim();
          // For EvtxECmd, ClientName/ClientAddress may be in PayloadData fields
          if (isEvtxECmd && !clientName && row._payloadData1) {
            const cnMatch = row._payloadData1.match(/ClientName:\s*(.+?)(?:\s*$|,)/i);
            if (cnMatch) clientName = cnMatch[1].trim();
          }
          if (isEvtxECmd && !clientAddress && row._payloadData2) {
            const caMatch = row._payloadData2.match(/ClientAddress:\s*(.+?)(?:\s*$|,)/i);
            if (caMatch) clientAddress = caMatch[1].trim();
          }
          // Use ClientName as source host (attacker hostname), fall back to ClientAddress
          sourceHost = clientName ? clientName.toUpperCase() : clientAddress ? clientAddress.toUpperCase() : "";
        } else {
          sourceHost = (row.workstation || "").toUpperCase().trim();
          if (!sourceHost || sourceHost === "-") sourceHost = (row.source || "").toUpperCase().trim();

          // EvtxECmd: RemoteHost format is "WorkstationName (IpAddress)" e.g. "- (::1)" or "WKST01 (10.0.0.5)"
          if (isEvtxECmd && row.source) {
            const rh = row.source.trim();
            // Skip non-host values from firewall/other events: *:, *: 445, LOCALSUBNET:*, LOCAL, etc.
            if (/^\*/.test(rh) || /^LOCALSUBNET/i.test(rh) || /^LOCAL$/i.test(rh)) { continue; }
            const rhMatch = rh.match(/^(.+?)\s*\(([^)]+)\)$/);
            if (rhMatch) {
              const wkst = rhMatch[1].trim();
              const ip = rhMatch[2].trim();
              sourceHost = (wkst && wkst !== "-") ? wkst.toUpperCase() : ip.toUpperCase();
            } else {
              sourceHost = rh.toUpperCase();
            }
          }
        }

        if (!sourceHost || EXCLUDED_IPS.has(sourceHost)) continue;
        if (excludeLocalLogons && sourceHost === targetHost) continue;

        // EvtxECmd: PayloadData1 format is "Target: DOMAIN\User" — only parse if it matches, else clear
        let user = row.user || "";
        if (isEvtxECmd && user) {
          const pdMatch = user.match(/^Target:\s*(?:([^\\]+)\\)?(.+)$/i);
          if (pdMatch) user = pdMatch[2].trim();
          else user = "";  // Not a logon event — PayloadData1 has unrelated data
        }
        if (excludeServiceAccounts && user && (SERVICE_RE.test(user) || user.endsWith("$"))) continue;

        // EvtxECmd: PayloadData2 format is "LogonType N" — only parse if it matches, else clear
        let logonType = row.logonType || "";
        if (isEvtxECmd && logonType) {
          const ltMatch = logonType.match(/LogonType\s+(\d+)/i);
          if (ltMatch) logonType = ltMatch[1];
          else logonType = "";  // Not a logon event — PayloadData2 has unrelated data
        }

        const ts = row.ts || "";
        const isFailure = eventId === "4625";

        if (!hostSet.has(sourceHost)) hostSet.set(sourceHost, { isSource: false, isTarget: false, eventCount: 0 });
        if (!hostSet.has(targetHost)) hostSet.set(targetHost, { isSource: false, isTarget: false, eventCount: 0 });
        hostSet.get(sourceHost).isSource = true;
        hostSet.get(sourceHost).eventCount++;
        hostSet.get(targetHost).isTarget = true;
        hostSet.get(targetHost).eventCount++;

        const edgeKey = `${sourceHost}->${targetHost}`;
        if (!edgeMap.has(edgeKey)) {
          edgeMap.set(edgeKey, { source: sourceHost, target: targetHost, count: 0, users: new Set(), logonTypes: new Set(), firstSeen: ts, lastSeen: ts, hasFailures: false, clientNames: new Set(), clientAddresses: new Set() });
        }
        const edge = edgeMap.get(edgeKey);
        edge.count++;
        if (user) edge.users.add(user);
        if (logonType) edge.logonTypes.add(logonType);
        if (ts && ts < edge.firstSeen) edge.firstSeen = ts;
        if (ts && ts > edge.lastSeen) edge.lastSeen = ts;
        if (isFailure) edge.hasFailures = true;
        if (clientName) edge.clientNames.add(clientName);
        if (clientAddress && clientAddress !== "LOCAL") edge.clientAddresses.add(clientAddress);

        timeOrdered.push({ source: sourceHost, target: targetHost, user, ts, logonType });
      }

      // Chain detection: time-ordered DFS for multi-hop paths
      const adjByTime = new Map();
      for (const evt of timeOrdered) {
        if (!adjByTime.has(evt.source)) adjByTime.set(evt.source, []);
        adjByTime.get(evt.source).push({ target: evt.target, ts: evt.ts, user: evt.user });
      }

      const chains = [];
      const MAX_CHAINS = 50;
      const MIN_HOPS = 2;

      const originHosts = [...hostSet.entries()].filter(([, info]) => info.isSource).map(([host]) => host);

      for (const origin of originHosts) {
        if (chains.length >= MAX_CHAINS) break;
        const stack = [{ host: origin, path: [{ host: origin, ts: "", user: "" }], visited: new Set([origin]) }];
        while (stack.length > 0 && chains.length < MAX_CHAINS) {
          const { host, path, visited } = stack.pop();
          const lastTs = path[path.length - 1].ts;
          const neighbors = adjByTime.get(host) || [];
          let extended = false;
          for (const edge of neighbors) {
            if (lastTs && edge.ts && edge.ts < lastTs) continue;
            if (visited.has(edge.target)) continue;
            const newPath = [...path, { host: edge.target, ts: edge.ts, user: edge.user }];
            const newVisited = new Set(visited);
            newVisited.add(edge.target);
            extended = true;
            stack.push({ host: edge.target, path: newPath, visited: newVisited });
          }
          if (!extended && path.length >= MIN_HOPS + 1) {
            chains.push({
              path: path.map((p) => p.host),
              timestamps: path.map((p) => p.ts),
              users: [...new Set(path.slice(1).map((p) => p.user).filter(Boolean))],
              hops: path.length - 1,
            });
          }
        }
      }
      chains.sort((a, b) => b.hops - a.hops);

      // Outlier host detection — flag default/generic/suspicious hostnames
      // Threat actor machines typically use default OS install names or pentest distro defaults
      const OUTLIER_PATS = [
        [/^DESKTOP-[A-Z0-9]{5,}$/, "Default Windows hostname"],
        [/^WIN-[A-Z0-9]{5,}$/, "Default Windows hostname"],
        [/^KALI$/i, "Kali Linux default"],
        [/^PARROT$/i, "Parrot OS default"],
        [/^(USER-?PC|YOURNAME|ADMIN|TEST|PC|WIN10|WIN11|OWNER-?PC|USER|WINDOWS|LOCALHOST|HACKER|ATTACKER|ROOT)$/i, "Generic hostname"],
        [/[^\x00-\x7F]/, "Non-ASCII hostname"],
      ];
      const detectOutlier = (hostname) => {
        for (const [pat, reason] of OUTLIER_PATS) {
          if (pat.test(hostname)) return reason;
        }
        return null;
      };

      return {
        nodes: [...hostSet.entries()].map(([id, info]) => {
          const outlierReason = detectOutlier(id);
          return {
            id, label: id, eventCount: info.eventCount,
            isSource: info.isSource, isTarget: info.isTarget,
            isBoth: info.isSource && info.isTarget,
            isOutlier: !!outlierReason, outlierReason: outlierReason || "",
          };
        }),
        edges: [...edgeMap.values()].map((e) => ({
          ...e, users: [...e.users], logonTypes: [...e.logonTypes], clientNames: [...e.clientNames], clientAddresses: [...e.clientAddresses],
        })),
        chains,
        stats: {
          totalEvents: timeOrdered.length, uniqueHosts: hostSet.size,
          uniqueUsers: new Set(timeOrdered.map((e) => e.user).filter(Boolean)).size,
          uniqueConnections: edgeMap.size,
          failedLogons: timeOrdered.filter((e) => e.logonType === "4625" || rows.find((r) => r._rowid && r.eventId === "4625")).length,
          longestChain: chains.length > 0 ? chains[0].hops : 0,
          chainCount: chains.length,
        },
        columns, error: null,
      };
    } catch (e) {
      return { nodes: [], edges: [], chains: [], stats: {}, columns, error: e.message };
    }
  }

  /**
   * Persistence Analyzer — scans EVTX or registry data for persistence mechanisms
   */
  getPersistenceAnalysis(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { items: [], stats: {}, error: "Tab not found" };
    const { db, headers } = meta;
    const detect = (pats) => { for (const p of pats) { const f = headers.find(h => p.test(h)); if (f) return f; } return null; };

    // Auto-detect data mode
    const hasEventId = detect([/^EventI[dD]$/i, /^event_id$/i]);
    const hasKeyPath = detect([/^KeyPath$/i, /^Key ?Path$/i]);
    const hasValueName = detect([/^ValueName$/i, /^Value ?Name$/i]);

    let mode = options.mode || "auto";
    if (mode === "auto") {
      mode = (hasKeyPath && hasValueName) ? "registry" : hasEventId ? "evtx" : null;
    }
    if (!mode) return { items: [], stats: {}, error: "Cannot detect data type. Need EventID column (EVTX) or KeyPath column (Registry)." };

    // --- Detection rules ---
    // Regex helper: match "Key: Value" in EvtxECmd PayloadData (pipe-delimited haystack)
    // EvtxECmd formats vary: "Name: Svc", "Task: \Path", "ServiceName: Svc", "Image: C:\..."
    const P = (key) => new RegExp(key + ":\\s*(.+?)(?:\\s*$|\\s*\\|)", "i"); // match until end or pipe
    const EVTX_RULES = [
      // --- Services ---
      { category: "Services", name: "Service Installed", eventIds: ["7045"], channels: ["system"], severity: "high",
        // EvtxECmd 7045 (System): PD2="Name: SvcName", PD3="StartType:", PD4="Account:", ExecutableInfo=ImagePath
        extractors: { serviceName: [P("Name"), P("ServiceName")], startType: [P("StartType")], account: [P("Account"), P("AccountName")] },
        topFields: ["serviceName", "imagePath", "account"], useExecInfo: "imagePath", payloadFilter: null },
      { category: "Services", name: "Service Installed", eventIds: ["4697"], channels: ["security"], severity: "high",
        extractors: { serviceName: [P("ServiceName")], serviceFile: [P("ServiceFileName")], serviceType: [P("ServiceType")], startType: [P("ServiceStartType")], account: [P("ServiceAccount")] },
        topFields: ["serviceName", "serviceFile", "account"], payloadFilter: null },
      // --- Scheduled Tasks ---
      { category: "Scheduled Tasks", name: "Scheduled Task Created", eventIds: ["4698"], channels: ["security"], severity: "high",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Task Name")], command: [P("Command"), P("Arguments"), P("Actions")] },
        topFields: ["taskName", "command", "executable"], useExecInfo: "executable", payloadFilter: null },
      { category: "Scheduled Tasks", name: "Scheduled Task Deleted", eventIds: ["4699"], channels: ["security"], severity: "medium",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Task Name")] },
        topFields: ["taskName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Task Registered", eventIds: ["106"], channels: ["taskscheduler"], severity: "medium",
        // EvtxECmd 106 (TaskScheduler/Operational): PD2="Task: \Name", ExecutableInfo=empty for this event
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")] },
        topFields: ["taskName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Task Updated", eventIds: ["140"], channels: ["taskscheduler"], severity: "medium",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")] },
        topFields: ["taskName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Task Process Created", eventIds: ["129"], channels: ["taskscheduler"], severity: "high",
        // EvtxECmd 129 (TaskScheduler/Operational): PD2="Task: \Name", PD3="ProcessID:", ExecutableInfo=exe path
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], processId: [P("ProcessID"), P("ProcessId")] },
        topFields: ["taskName", "executable", "processId"], useExecInfo: "executable", payloadFilter: null },
      { category: "Scheduled Tasks", name: "Task Action Started", eventIds: ["200"], channels: ["taskscheduler"], severity: "medium",
        // EvtxECmd 200 (TaskScheduler/Operational): PD2="Task: \Name", ExecutableInfo=action/handler name
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], instanceId: [P("Instance Id"), P("TaskInstanceId")] },
        topFields: ["taskName", "executable"], useExecInfo: "executable", payloadFilter: null },
      // --- WMI ---
      { category: "WMI Persistence", name: "WMI Event Subscription", eventIds: ["5861"], channels: ["wmi-activity"], severity: "critical",
        extractors: { namespace: [P("Namespace")], operation: [P("Operation")], query: [P("Query")], consumer: [P("Consumer")], poss_command: [P("PossibleCause"), P("Command")] },
        topFields: ["operation", "query", "consumer"], payloadFilter: null },
      { category: "WMI Persistence", name: "WMI EventFilter Created", eventIds: ["19"], channels: ["sysmon"], severity: "critical",
        extractors: { name: [P("Name")], query: [P("Query")], eventNamespace: [P("EventNamespace")], operation: [P("Operation")] },
        topFields: ["name", "query", "operation"], payloadFilter: null },
      { category: "WMI Persistence", name: "WMI EventConsumer Created", eventIds: ["20"], channels: ["sysmon"], severity: "critical",
        extractors: { name: [P("Name")], type: [P("Type")], destination: [P("Destination")], operation: [P("Operation")] },
        topFields: ["name", "destination", "type"], payloadFilter: null },
      { category: "WMI Persistence", name: "WMI Binding Created", eventIds: ["21"], channels: ["sysmon"], severity: "critical",
        extractors: { consumer: [P("Consumer")], filter: [P("Filter")], operation: [P("Operation")] },
        topFields: ["consumer", "filter"], payloadFilter: null },
      // --- Registry (Sysmon) ---
      { category: "Registry Autorun", name: "Registry Value Set", eventIds: ["13"], channels: ["sysmon"], severity: "high",
        extractors: { targetObject: [P("TargetObject"), P("TgtObj")], details: [P("Details")], image: [P("Image")] },
        topFields: ["targetObject", "details", "image"],
        payloadFilter: /\\(?:Run|RunOnce|RunServices|Services\\[^\\]*\\(?:ImagePath|Parameters)|Winlogon\\(?:Shell|Userinit|Notify)|AppInit_DLLs|Image File Execution Options\\[^\\]*\\Debugger|CurrentVersion\\Explorer\\(?:Shell|User Shell)|Session Manager\\(?:BootExecute|SetupExecute)|InprocServer32|LocalServer32|ShellIconOverlay|ContextMenuHandler|Browser Helper|Active Setup|Print\\Monitors|NetworkProvider|Lsa\\)/i },
      { category: "Registry Modification", name: "Registry Key Created/Deleted", eventIds: ["12"], channels: ["sysmon"], severity: "medium",
        extractors: { targetObject: [P("TargetObject"), P("TgtObj")], eventType: [P("EventType")], image: [P("Image")] },
        topFields: ["eventType", "targetObject", "image"],
        payloadFilter: /\\(?:Run|RunOnce|Services\\|Winlogon|AppInit_DLLs|Image File Execution Options|Session Manager\\BootExecute|Active Setup|Print\\Monitors|NetworkProvider|Lsa\\)/i },
      { category: "Registry Rename", name: "Registry Key/Value Renamed", eventIds: ["14"], channels: ["sysmon"], severity: "medium",
        extractors: { targetObject: [P("TargetObject")], newName: [P("NewName")], eventType: [P("EventType")] },
        topFields: ["targetObject", "newName"],
        payloadFilter: /\\(?:Run|RunOnce|Services\\|Winlogon|Image File Execution Options)/i },
      // --- File system (Sysmon) ---
      { category: "Startup Folder", name: "File Created in Startup", eventIds: ["11"], channels: ["sysmon"], severity: "high",
        extractors: { targetFilename: [P("TargetFilename")], image: [P("Image")], creationTime: [P("CreationUtcTime")] },
        topFields: ["targetFilename", "image"],
        payloadFilter: /Start Menu\\Programs\\Startup|ProgramData\\Microsoft\\Windows\\Start Menu|\\Startup\\[^\\]*\.(exe|dll|bat|cmd|ps1|vbs|js|lnk|url)$/i },
      { category: "DLL Hijacking", name: "Unsigned DLL Loaded", eventIds: ["7"], channels: ["sysmon"], severity: "medium",
        extractors: { imageLoaded: [P("ImageLoaded")], signed: [P("Signed")], signatureStatus: [P("SignatureStatus")], image: [P("Image")] },
        topFields: ["imageLoaded", "image", "signatureStatus"],
        payloadFilter: /Signed:\s*false/i },
      { category: "Driver Loading", name: "Suspicious Driver Loaded", eventIds: ["6"], channels: ["sysmon"], severity: "critical",
        extractors: { imageLoaded: [P("ImageLoaded")], signed: [P("Signed")], signatureStatus: [P("SignatureStatus")], signer: [P("Signer")] },
        topFields: ["imageLoaded", "signatureStatus", "signer"],
        payloadFilter: /Signed:\s*false|SignatureStatus:\s*(?:Expired|Revoked|Invalid|Unavailable)/i },
      { category: "Process Tampering", name: "Process Tampering Detected", eventIds: ["25"], channels: ["sysmon"], severity: "critical",
        extractors: { type: [P("Type")], image: [P("Image")] },
        topFields: ["image", "type"], payloadFilter: null },
      // --- Task Scheduler lifecycle (anti-forensics / trigger tracking) ---
      { category: "Scheduled Tasks", name: "Task Deleted", eventIds: ["141"], channels: ["taskscheduler"], severity: "high",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], userName: [P("UserName"), P("User")] },
        topFields: ["taskName", "userName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Boot Trigger Fired", eventIds: ["118"], channels: ["taskscheduler"], severity: "medium",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")] },
        topFields: ["taskName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Logon Trigger Fired", eventIds: ["119"], channels: ["taskscheduler"], severity: "medium",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], userName: [P("UserName"), P("User")] },
        topFields: ["taskName", "userName"], payloadFilter: null },
      // --- Account Persistence (DFIR report-derived: 7/11 reports) ---
      { category: "Account Persistence", name: "User Account Created", eventIds: ["4720"], channels: ["security"], severity: "high",
        extractors: { targetUser: [P("TargetUserName"), P("Target_User_Name")], subjectUser: [P("SubjectUserName")], samAccountName: [P("SamAccountName"), P("SAMAccountName")] },
        topFields: ["targetUser", "subjectUser", "samAccountName"], payloadFilter: null },
      { category: "Account Persistence", name: "Member Added to Global Security Group", eventIds: ["4728"], channels: ["security"], severity: "critical",
        extractors: { groupName: [P("TargetUserName")], memberName: [P("MemberName"), P("Member_Name")], subjectUser: [P("SubjectUserName")] },
        topFields: ["groupName", "memberName", "subjectUser"], payloadFilter: null },
      { category: "Account Persistence", name: "Member Added to Local Security Group", eventIds: ["4732"], channels: ["security"], severity: "high",
        extractors: { groupName: [P("TargetUserName")], memberName: [P("MemberName")], subjectUser: [P("SubjectUserName")] },
        topFields: ["groupName", "memberName", "subjectUser"], payloadFilter: null },
      { category: "Account Persistence", name: "Member Added to Universal Security Group", eventIds: ["4756"], channels: ["security"], severity: "critical",
        extractors: { groupName: [P("TargetUserName")], memberName: [P("MemberName")], subjectUser: [P("SubjectUserName")] },
        topFields: ["groupName", "memberName", "subjectUser"], payloadFilter: null },
      { category: "Account Persistence", name: "User Password Reset", eventIds: ["4724"], channels: ["security"], severity: "medium",
        extractors: { targetUser: [P("TargetUserName")], subjectUser: [P("SubjectUserName")] },
        topFields: ["targetUser", "subjectUser"], payloadFilter: null },
    ];

    const REGISTRY_RULES = [
      { category: "Run Keys", name: "Run/RunOnce Autostart", severity: "high", description: "Standard autorun registry key",
        keyPathPattern: /\\(?:Software|SOFTWARE)\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunOnceEx)(?:\\|$)/i, valueNameFilter: null },
      { category: "Services", name: "Service ImagePath/ServiceDll", severity: "high", description: "Service executable or DLL path",
        keyPathPattern: /\\(?:SYSTEM|System)\\(?:CurrentControlSet|ControlSet\d+)\\Services\\[^\\]+(?:\\Parameters)?$/i,
        valueNameFilter: /^(ImagePath|ServiceDll|FailureCommand)$/i },
      { category: "Winlogon", name: "Winlogon Shell/Userinit", severity: "critical", description: "Login-triggered execution via Winlogon",
        keyPathPattern: /\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon$/i, valueNameFilter: /^(Shell|Userinit|Notify|VmApplet|AppSetup)$/i },
      { category: "AppInit DLLs", name: "AppInit_DLLs", severity: "critical", description: "DLL injection on every user-mode process",
        keyPathPattern: /\\Microsoft\\Windows NT\\CurrentVersion\\Windows$/i, valueNameFilter: /^(AppInit_DLLs|LoadAppInit_DLLs)$/i },
      { category: "IFEO", name: "Image File Execution Options Debugger", severity: "critical", description: "Debugger hijacking of executable launch",
        keyPathPattern: /\\Image File Execution Options\\[^\\]+$/i, valueNameFilter: /^(Debugger|GlobalFlag)$/i },
      { category: "COM Hijacking", name: "COM Object Server", severity: "high", description: "COM object DLL/executable hijacking",
        keyPathPattern: /\\(?:InprocServer32|LocalServer32|InprocHandler32)$/i, valueNameFilter: null },
      { category: "Shell Extensions", name: "Shell Extension Handler", severity: "medium", description: "Explorer shell extension persistence",
        keyPathPattern: /\\(?:ShellIconOverlayIdentifiers|ContextMenuHandlers|PropertySheetHandlers|ColumnHandlers|CopyHookHandlers|DragDropHandlers|ShellExecuteHooks)\\[^\\]+$/i, valueNameFilter: null },
      { category: "Boot Execute", name: "Session Manager BootExecute", severity: "critical", description: "Pre-boot execution before Windows starts",
        keyPathPattern: /\\(?:Session Manager)$/i, valueNameFilter: /^(BootExecute|SetupExecute|Execute)$/i },
      { category: "BHO", name: "Browser Helper Object", severity: "medium", description: "Browser helper object (IE/Edge extension)",
        keyPathPattern: /\\Browser Helper Objects\\{[0-9a-fA-F-]+}$/i, valueNameFilter: null },
      { category: "LSA", name: "LSA Security/Auth Packages", severity: "critical", description: "Credential interception via LSA packages",
        keyPathPattern: /\\(?:Control\\)?Lsa$/i, valueNameFilter: /^(Security Packages|Authentication Packages|Notification Packages)$/i },
      { category: "Print Monitors", name: "Print Monitor DLL", severity: "high", description: "Spooler-based persistence via print monitor",
        keyPathPattern: /\\Print\\Monitors\\[^\\]+$/i, valueNameFilter: /^Driver$/i },
      { category: "Active Setup", name: "Active Setup StubPath", severity: "high", description: "Per-user execution on first login",
        keyPathPattern: /\\Active Setup\\Installed Components\\{[0-9a-fA-F-]+}$/i, valueNameFilter: /^StubPath$/i },
      { category: "Startup Folder", name: "Startup Folder Registry Path", severity: "high", description: "Startup folder path redirection",
        keyPathPattern: /\\Explorer\\(?:User Shell Folders|Shell Folders)$/i, valueNameFilter: /Startup/i },
      { category: "Scheduled Tasks (Reg)", name: "Scheduled Task in Registry", severity: "medium", description: "Task definition stored in registry",
        keyPathPattern: /\\Schedule\\TaskCache\\(?:Tasks|Tree)\\?/i, valueNameFilter: null },
      { category: "Network Providers", name: "Network Provider Order", severity: "high", description: "Network login interception via custom provider",
        keyPathPattern: /\\NetworkProvider\\Order$/i, valueNameFilter: /^ProviderOrder$/i },
    ];

    // --- Apply user rule customization ---
    const disabledRules = new Set(options.disabledRules || []);
    let activeEvtxRules = EVTX_RULES.filter((_, i) => !disabledRules.has(`evtx-${i}`));
    let activeRegRules = REGISTRY_RULES.filter((_, i) => !disabledRules.has(`reg-${i}`));

    if (options.customRules?.length) {
      for (const cr of options.customRules) {
        if (cr.type === "evtx") {
          activeEvtxRules.push({
            category: cr.category || "Custom",
            name: cr.name || "Custom Rule",
            eventIds: (cr.eventIds || "").split(",").map(s => s.trim()).filter(Boolean),
            channels: (cr.channels || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean),
            severity: cr.severity || "medium",
            extractors: {},
            topFields: [],
            payloadFilter: cr.payloadFilter ? new RegExp(cr.payloadFilter, "i") : null,
          });
        } else if (cr.type === "registry") {
          activeRegRules.push({
            category: cr.category || "Custom",
            name: cr.name || "Custom Rule",
            severity: cr.severity || "medium",
            description: cr.description || "User-defined rule",
            keyPathPattern: new RegExp(cr.keyPathPattern || ".*", "i"),
            valueNameFilter: cr.valueNameFilter ? new RegExp(cr.valueNameFilter, "i") : null,
          });
        }
      }
    }

    // --- Column mapping ---
    const userCols = options.columns || {};
    let columns;
    if (mode === "evtx") {
      columns = {
        eventId: userCols.eventId || detect([/^EventI[dD]$/i, /^event_id$/i]),
        channel: userCols.channel || detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
        ts: userCols.ts || detect([/^TimeCreated$/i, /^datetime$/i, /^UtcTime$/i, /^Timestamp$/i]),
        computer: userCols.computer || detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i]),
        payload: detect([/^PayloadData1$/i]),
        payload2: detect([/^PayloadData2$/i]),
        payload3: detect([/^PayloadData3$/i]),
        payload4: detect([/^PayloadData4$/i]),
        payload5: detect([/^PayloadData5$/i]),
        payload6: detect([/^PayloadData6$/i]),
        mapDesc: detect([/^MapDescription$/i]),
        execInfo: detect([/^ExecutableInfo$/i]),
        details: detect([/^Details$/i]),
        ruleTitle: detect([/^RuleTitle$/i]),
        user: userCols.user || detect([/^UserName$/i, /^User$/i]),
      };
    } else {
      columns = {
        keyPath: userCols.keyPath || detect([/^KeyPath$/i, /^Key ?Path$/i]),
        valueName: userCols.valueName || detect([/^ValueName$/i, /^Value ?Name$/i]),
        valueData: userCols.valueData || detect([/^ValueData$/i, /^Value ?Data$/i]),
        valueData2: detect([/^ValueData2$/i]),
        valueData3: detect([/^ValueData3$/i]),
        valueType: detect([/^ValueType$/i, /^Value ?Type$/i]),
        hivePath: detect([/^HivePath$/i, /^Hive ?Path$/i]),
        ts: userCols.ts || detect([/^LastWriteTimestamp$/i, /^Timestamp$/i, /^datetime$/i, /^TimeCreated$/i]),
      };
    }

    // --- Build SQL query ---
    const { columnFilters = {}, checkboxFilters = {}, dateRangeFilters = {}, bookmarkedOnly = false, searchTerm = "", searchMode = "contains", searchCondition = "AND", advancedFilters = [] } = options;
    const params = [];
    const whereConditions = [];

    // EVTX pre-filter: only relevant Event IDs
    const ALL_EVTX_EIDS = [...new Set(activeEvtxRules.flatMap(r => r.eventIds))];
    if (mode === "evtx" && columns.eventId) {
      const safeEid = meta.colMap[columns.eventId];
      if (safeEid) {
        whereConditions.push(`${safeEid} IN (${ALL_EVTX_EIDS.map(() => "?").join(",")})`);
        params.push(...ALL_EVTX_EIDS);
      }
    }

    // Apply standard filters (same pattern as getLateralMovement)
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`); params.push(`%${fv}%`);
    }
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      const sc = meta.colMap[cn]; if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn]; if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
    if (bookmarkedOnly) whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    if (searchTerm.trim()) this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    const selectParts = ["data.rowid as _rowid"];
    for (const [key, colName] of Object.entries(columns)) {
      if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
    }

    const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
    const orderClause = orderCol ? `ORDER BY ${orderCol} ASC` : "ORDER BY data.rowid ASC";

    try {
      const maxRows = 500000;
      const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
      const rows = db.prepare(sql).all(...params);

      let items = [];

      if (mode === "evtx") {
        for (const row of rows) {
          const eid = String(row.eventId || "").trim();
          const haystack = [row.payload, row.payload2, row.payload3, row.payload4, row.payload5, row.payload6, row.mapDesc, row.execInfo, row.details, row.ruleTitle].filter(Boolean).join(" | ");

          const channelLower = String(row.channel || "").toLowerCase();
          for (const rule of activeEvtxRules) {
            if (!rule.eventIds.includes(eid)) continue;
            // Channel filter: rule.channels contains substrings to match (e.g., "system", "security", "taskscheduler", "sysmon")
            if (rule.channels && !rule.channels.some((ch) => channelLower.includes(ch))) continue;
            if (rule.payloadFilter && !rule.payloadFilter.test(haystack)) continue;

            const details = {};
            for (const [field, patterns] of Object.entries(rule.extractors || {})) {
              for (const pat of patterns) {
                const m = haystack.match(pat);
                if (m) { details[field] = m[1].trim(); break; }
              }
            }

            // Pull ExecutableInfo column directly into named field as fallback
            // useExecInfo can be true (maps to "executable") or a string (specific field name)
            if (rule.useExecInfo && row.execInfo) {
              const targetField = typeof rule.useExecInfo === "string" ? rule.useExecInfo : "executable";
              if (!details[targetField]) {
                details[targetField] = row.execInfo.trim();
              }
            }

            // Build summary from topFields (most relevant info first), fall back to raw payload
            let detailsSummary = "";
            const topFields = rule.topFields || Object.keys(rule.extractors || {});
            const topParts = topFields.map((f) => details[f] ? `${f}: ${details[f]}` : null).filter(Boolean);
            if (topParts.length > 0) {
              detailsSummary = topParts.join(" | ");
            } else {
              // No extractors matched — show raw payload data for context
              detailsSummary = [row.payload, row.payload2, row.payload3, row.payload4, row.payload5].filter(Boolean).join(" | ");
            }

            // RMM tool detection for service installs (seen in 7/11 DFIR reports)
            const RMM_PATTERNS = /anydesk|splashtop|rustdesk|atera|screenconnect|teamviewer|supremo|connectwise|bomgar|logmein/i;
            const rmmMatch = (eid === "7045") && (RMM_PATTERNS.test(details.serviceName || "") || RMM_PATTERNS.test(details.imagePath || "") || RMM_PATTERNS.test(row.execInfo || ""));
            const tags = rmmMatch ? ["RMM Tool"] : [];

            items.push({
              rowid: row._rowid,
              category: rule.category,
              name: rule.name,
              severity: rule.severity,
              description: rule.description,
              timestamp: row.ts || "",
              computer: row.computer || "",
              user: row.user || "",
              source: `EventID ${eid}`,
              details,
              detailsSummary: detailsSummary.substring(0, 400),
              mode: "evtx",
              tags,
              rmmTool: rmmMatch,
            });
          }
        }
      } else {
        // Registry mode
        for (const row of rows) {
          const kp = row.keyPath || "";
          const vn = row.valueName || "";
          const vd = [row.valueData, row.valueData2, row.valueData3].filter(Boolean).join(" ");

          for (const rule of activeRegRules) {
            if (!rule.keyPathPattern.test(kp)) continue;
            if (rule.valueNameFilter && !rule.valueNameFilter.test(vn)) continue;

            items.push({
              rowid: row._rowid,
              category: rule.category,
              name: rule.name,
              severity: rule.severity,
              description: rule.description,
              timestamp: row.ts || "",
              computer: "",
              user: "",
              source: "Registry",
              details: { keyPath: kp, valueName: vn, valueData: vd, hivePath: row.hivePath || "" },
              detailsSummary: `${vn}: ${vd}`.substring(0, 300),
              mode: "registry",
            });
          }
        }
      }

      // --- Cross-event correlation: enrich Task Registered/Updated with executable from Task Process Created/Action Started ---
      if (mode === "evtx") {
        const taskExecMap = {};
        for (const item of items) {
          if ((item.name === "Task Process Created" || item.name === "Task Action Started") && item.details.executable && item.details.taskName) {
            const tn = item.details.taskName;
            if (!taskExecMap[tn] || item.name === "Task Process Created") taskExecMap[tn] = item.details.executable;
          }
        }
        for (const item of items) {
          if ((item.name === "Task Registered" || item.name === "Task Updated") && !item.details.executable && item.details.taskName) {
            const exec = taskExecMap[item.details.taskName];
            if (exec) {
              item.details.executable = exec;
              // Rebuild summary with executable
              const topParts = ["taskName", "executable"].map((f) => item.details[f] ? `${f}: ${item.details[f]}` : null).filter(Boolean);
              if (topParts.length > 0) item.detailsSummary = topParts.join(" | ").substring(0, 400);
            }
          }
        }
      }

      // --- Compute artifact + command columns from details ---
      for (const item of items) {
        const d = item.details;
        if (item.mode === "evtx") {
          item.artifact = d.taskName || d.serviceName || d.targetObject || d.targetFilename || d.name || d.imageLoaded || "";
          item.command = d.executable || d.command || d.serviceFile || d.imagePath || d.image || d.query || d.destination || d.details || "";
        } else {
          item.artifact = d.keyPath || "";
          item.command = d.valueData || "";
        }
      }

      // --- Known AV/EDR whitelist: suppress legitimate security products from expected paths ---
      const AV_EDR_WHITELIST = [
        // Palo Alto / Cortex XDR / Traps
        { namePattern: /^(?:cyvrmtgn|cyverak|cyvrfsfd|tedrdrv|tdevflt|telam|Cortex\s*XDR|Cortex\s*XDR\s*Health\s*Helper|CyMemDef|CyProtectDrv|CyOpticsRuntimeDriver|TrapsSupervisor|PanGPS|PanUpdater)$/i,
          pathPattern: /(?:Palo\s*Alto\s*Networks|Cortex\s*XDR)/i },
        // Microsoft Defender / MpKsl* drivers / MsMpEng / NisSrv
        { namePattern: /^(?:Microsoft\s*Defender|MpDefender|WinDefend|MsMpSvc|NisSrv|MpKsl[0-9a-f]+|WdNisSvc|WdNisDrv|WdFilter|WdBoot|SecurityHealthService|Sense|MsSecCore|Microsoft\s*Defender\s*Core\s*Service)$/i,
          pathPattern: /(?:Windows\s*Defender|Microsoft\s*Defender|Microsoft\\Windows\s*Defender|ProgramData\\Microsoft\\Windows\s*Defender)/i },
        // CrowdStrike Falcon
        { namePattern: /^(?:CSFalcon|CsFalconService|csagent|CSAgent|csdevicecontrol|CrowdStrike|CsInstallerService|CsDisk[A-Z]|CsBoot|CsEFW)$/i,
          pathPattern: /CrowdStrike/i },
        // SentinelOne
        { namePattern: /^(?:SentinelAgent|SentinelOne|SentinelMonitor|SentinelStaticEngine|LogProcessorService|SentinelStaticEngineScanner|SentinelHelperService)$/i,
          pathPattern: /SentinelOne/i },
        // Carbon Black (VMware/Broadcom)
        { namePattern: /^(?:CbDefense|CbDefenseSensor|CarbonBlack|cb\.exe|RepMgr|CbStream|carbonblackk|CbSensor)$/i,
          pathPattern: /(?:CarbonBlack|Carbon\s*Black|Cb\\)/i },
        // Sophos
        { namePattern: /^(?:Sophos|SAVService|SAVAdminService|SophosHealth|SophosCleanup|SophosFileScanner|SophosFS|SophosNtpService|hmpalert|SophosUI)$/i,
          pathPattern: /Sophos/i },
        // Symantec / Broadcom / Norton
        { namePattern: /^(?:SepMaster|SepScan|ccSvcHst|SymCorpUI|SymEFA|Norton|NortonSecurity|smc|SmcService|Symantec|SylinkDrop|ccEvtMgr)$/i,
          pathPattern: /(?:Symantec|Norton|Broadcom)/i },
        // McAfee / Trellix
        { namePattern: /^(?:McAfee|McShield|mfemms|mfefire|mfevtp|TrellixENS|TrellixEDR|masvc|macmnsvc|mfewc|mfetp)$/i,
          pathPattern: /(?:McAfee|Trellix)/i },
        // Kaspersky
        { namePattern: /^(?:AVP|avp|kavsvc|kavfs|klnagent|KAVFS|KESCapability|KLSysEvLog)$/i,
          pathPattern: /Kaspersky/i },
        // ESET
        { namePattern: /^(?:ekrn|ESET|EsetService|ERAAgent|eamonm|ehdrv|epfwwfp|epfw)$/i,
          pathPattern: /ESET/i },
        // Trend Micro
        { namePattern: /^(?:TrendMicro|Ntrtscan|tmlisten|TmFilter|TmPreFilter|ds_agent|Apex\s*One)$/i,
          pathPattern: /(?:Trend\s*Micro|TrendMicro)/i },
        // Bitdefender
        { namePattern: /^(?:EPSecurityService|EPProtectedService|EPUpdateService|EPIntegrationService|EPRedline|BDAuxSrv|TRUFOS|bdservicehost)$/i,
          pathPattern: /Bitdefender/i },
        // Cylance (BlackBerry)
        { namePattern: /^(?:CylanceSvc|CylanceUI|CylanceDrv|CylanceProtect|CyOptics)$/i,
          pathPattern: /Cylance/i },
        // Elastic Agent / Endpoint Security
        { namePattern: /^(?:elastic-agent|elastic-endpoint|ElasticEndpoint|winlogbeat|filebeat)$/i,
          pathPattern: /(?:Elastic|elastic)/i },
        // Fortinet FortiClient / FortiEDR
        { namePattern: /^(?:FortiClient|FortiEDR|FortiGate|FA_Scheduler|FortiClientProductUpdate)$/i,
          pathPattern: /Fortinet/i },
      ];

      // Check if a service item matches a known AV/EDR product from expected path
      const isWhitelistedAV = (serviceName, commandPath) => {
        if (!serviceName && !commandPath) return false;
        const sn = serviceName || "";
        const cp = commandPath || "";
        for (const entry of AV_EDR_WHITELIST) {
          if (entry.namePattern.test(sn) && entry.pathPattern.test(cp)) return true;
        }
        return false;
      };

      // --- Known browser services: downgrade to low if running from expected paths ---
      const BROWSER_WHITELIST = [
        // Google Chrome
        { namePattern: /^(?:Google\s*Chrome|gupdate|gupdatem|GoogleChromeElevationService|ChromeElevation)$/i,
          legitimatePath: /(?:Program\s*Files(?:\s*\(x86\))?\\Google\\Chrome|Program\s*Files(?:\s*\(x86\))?\\Google\\Update)/i },
        // Microsoft Edge
        { namePattern: /^(?:Microsoft\s*Edge|edge\s*update|MicrosoftEdgeElevationService|edgeupdatem?|MsEdge)$/i,
          legitimatePath: /(?:Program\s*Files(?:\s*\(x86\))?\\Microsoft\\Edge|Program\s*Files(?:\s*\(x86\))?\\Microsoft\\EdgeUpdate)/i },
        // Mozilla Firefox
        { namePattern: /^(?:Mozilla\s*Firefox|MozillaMaintenance|Firefox)$/i,
          legitimatePath: /(?:Program\s*Files(?:\s*\(x86\))?\\Mozilla\s*Firefox|Program\s*Files(?:\s*\(x86\))?\\Mozilla\s*Maintenance)/i },
        // Brave Browser
        { namePattern: /^(?:Brave|BraveUpdate|brave\s*update|BraveElevationService)$/i,
          legitimatePath: /(?:Program\s*Files(?:\s*\(x86\))?\\Brave(?:Software)?\\)/i },
        // Opera
        { namePattern: /^(?:Opera|OperaUpdate|opera\s*update)$/i,
          legitimatePath: /(?:Program\s*Files(?:\s*\(x86\))?\\Opera\\)/i },
        // Vivaldi
        { namePattern: /^(?:Vivaldi|VivaldiUpdate)$/i,
          legitimatePath: /(?:Program\s*Files(?:\s*\(x86\))?\\Vivaldi\\)/i },
      ];

      const checkBrowserService = (serviceName, commandPath) => {
        const sn = serviceName || "";
        const cp = commandPath || "";
        for (const entry of BROWSER_WHITELIST) {
          if (entry.namePattern.test(sn)) {
            // Name matches a browser — check if path is legitimate
            if (entry.legitimatePath.test(cp)) return "legitimate";
            return "suspicious"; // browser name but wrong path — possible mimicry
          }
        }
        return null; // not a browser service
      };

      // --- Known malicious tools: auto-escalate severity ---
      const MALICIOUS_TOOLS = [
        { namePattern: /^PSEXE[SC]SVC$/i, severity: "critical", reasons: ["PsExec remote execution tool — commonly abused for lateral movement"] },
        { namePattern: /^(?:DVCEMUMANAGER|anydesk|TeamViewer|ScreenConnect|SimpleHelp|RustDesk|meshagent)$/i, severity: "high", reasons: ["Remote access tool — verify legitimacy"] },
      ];

      // --- Risk scoring + suspicious detection ---
      const SUSPICIOUS_PATHS = /\\(?:Temp|AppData|Downloads|Users\\Public|ProgramData\\[^\\]*$|Recycle)/i;
      const SUSPICIOUS_CMDS = /(?:powershell|pwsh|cmd\.exe\s*\/c|certutil|bitsadmin|mshta|regsvr32|wscript|cscript|rundll32|msiexec.*\/q)/i;
      const ENCODING_INDICATORS = /(?:base64|frombase64|-[eE]nc\s|-[eE]\s|iex|invoke-expression|downloadstring|downloadfile|webclient|bitstransfer)/i;
      const SEVERITY_SCORES = { critical: 8, high: 6, medium: 4, low: 2 };
      // Known-legitimate task name prefixes (not suspicious)
      const LEGIT_TASK_PREFIXES = /^\\(?:Microsoft\\|Apple\\|Google\\|Adobe\\|Mozilla\\)/i;

      // Known-legitimate Windows task executables and action handlers (noisy FPs)
      const LEGIT_TASK_EXECUTABLES = /^(?:taskhostw\.exe|InputToCdsTaskHandler|svchost\.exe|conhost\.exe|backgroundTaskHost\.exe|RuntimeBroker\.exe|MusNotification\.exe|devicecensus\.exe|AppHostRegistrationVerifier\.exe|dstokenclean\.exe|UsoClient\.exe|OfficeBackgroundTaskHandlerRegistration|OfficeBackgroundTaskHandlerLogon|WaaSMedicAgent\.exe)$/i;

      // Known-legitimate browser scheduled tasks (task name patterns)
      const LEGIT_BROWSER_TASKS = /^\\?(?:MicrosoftEdgeUpdate|GoogleUpdate|Google(?:Chrome)?Update|ChromeUpdate|BraveSoftwareUpdate|MozillaUpdate|OperaSoftwareUpdate|VivaldiUpdate|Firefox\s*Default\s*Browser\s*Agent)/i;
      // Known-legitimate browser executables (expected paths)
      const LEGIT_BROWSER_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Microsoft\\Edge|Google\\(?:Chrome|Update)|Mozilla\s*Firefox|BraveSoftware|Opera|Vivaldi)|\\AppData\\Local\\(?:Microsoft\\Edge|Google\\Chrome|BraveSoftware|Mozilla\s*Firefox)\\)/i;

      // Filter out whitelisted items
      items = items.filter((item) => {
        // AV/EDR services from expected paths
        if (item.category === "Services" && item.name === "Service Installed") {
          const sn = item.artifact || item.details?.serviceName || "";
          const cp = item.command || item.details?.imagePath || item.details?.serviceFile || "";
          if (isWhitelistedAV(sn, cp)) return false;
        }
        // Scheduled Tasks: suppress known legitimate tasks
        if (item.category === "Scheduled Tasks") {
          const art = item.artifact || item.details?.taskName || "";
          const cmd = item.command || item.details?.executable || "";
          // Legitimate Windows system tasks with known system executables
          if ((item.name === "Task Process Created" || item.name === "Task Action Started")
            && LEGIT_TASK_PREFIXES.test(art) && LEGIT_TASK_EXECUTABLES.test(cmd.split("\\").pop())) return false;
          // Browser update tasks from expected paths (all task event types)
          if (LEGIT_BROWSER_TASKS.test(art) && (!cmd || LEGIT_BROWSER_PATHS.test(cmd))) return false;
        }
        return true;
      });

      for (const item of items) {
        let score = SEVERITY_SCORES[item.severity] || 4;
        const blob = item.detailsSummary + " " + JSON.stringify(item.details);
        if (SUSPICIOUS_PATHS.test(blob)) score += 1;
        if (SUSPICIOUS_CMDS.test(blob)) score += 1;
        if (ENCODING_INDICATORS.test(blob)) score += 1;

        // Check for known malicious tools — escalate severity
        const art = item.artifact || "";
        if (item.category === "Services" && art) {
          for (const mt of MALICIOUS_TOOLS) {
            if (mt.namePattern.test(art)) {
              item.severity = mt.severity;
              score = Math.max(score, SEVERITY_SCORES[mt.severity] || 6);
              item.isSuspicious = true;
              item.suspiciousReasons = (item.suspiciousReasons || []).concat(mt.reasons);
            }
          }
          // Browser services: downgrade if legitimate path, escalate if mimicked
          const browserCheck = checkBrowserService(art, item.command || "");
          if (browserCheck === "legitimate") {
            item.severity = "low";
            score = SEVERITY_SCORES.low;
          } else if (browserCheck === "suspicious") {
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high);
            item.isSuspicious = true;
            (item.suspiciousReasons = item.suspiciousReasons || []).push("Browser service name from unexpected path — possible mimicry");
          }
        }

        // Suspicious artifact/task indicators
        const reasons = item.suspiciousReasons || [];
        if (art && item.category === "Scheduled Tasks") {
          if (art.startsWith("\\") && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Non-standard task path");
            score += 1;
          }
          if (/^\\{[0-9a-f-]+}$/i.test(art)) {
            reasons.push("GUID-named task");
            score += 1;
          }
        }
        // LOLBin execution in non-Microsoft context
        if (item.command && /powershell|pwsh|cmd\.exe|mshta|wscript|cscript/i.test(item.command) && art && !LEGIT_TASK_PREFIXES.test(art)) {
          reasons.push("LOLBin execution");
        }
        // Living off the land: tasks/services executing from user-writable paths
        if (item.command && /\\Users\\|\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\/i.test(item.command)) {
          reasons.push("User-writable path");
        }
        // Anti-forensics: task deletion
        if (item.name === "Task Deleted" && art && !LEGIT_TASK_PREFIXES.test(art)) {
          reasons.push("Non-standard task deleted");
          score += 1;
        }

        item.riskScore = Math.min(score, 10);
        item.isSuspicious = reasons.length > 0;
        item.suspiciousReasons = reasons;
      }

      items.sort((a, b) => b.riskScore - a.riskScore || (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));

      // --- Build stats ---
      const byCategory = {};
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const item of items) {
        byCategory[item.category] = (byCategory[item.category] || 0) + 1;
        bySeverity[item.severity] = (bySeverity[item.severity] || 0) + 1;
      }

      return {
        items,
        stats: {
          total: items.length,
          byCategory,
          bySeverity,
          suspicious: items.filter(i => i.isSuspicious).length,
          uniqueComputers: new Set(items.map(i => i.computer).filter(Boolean)).size,
          categoriesFound: Object.keys(byCategory).length,
        },
        columns,
        detectedMode: mode,
        error: null,
      };
    } catch (e) {
      return { items: [], stats: {}, columns, detectedMode: mode, error: e.message };
    }
  }

  /**
   * Get FTS build status for a tab (used by renderer to show indexing progress)
   */
  getFtsStatus(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return { ready: false, building: false };
    return { ready: !!meta.ftsReady, building: !!meta.ftsBuilding };
  }

  closeTab(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    try {
      meta.db.pragma("analysis_limit = 1000");
      meta.db.pragma("optimize");
      meta.db.close();
    } catch (e) {}
    try {
      fs.unlinkSync(meta.dbPath);
    } catch (e) {}
    // Clean WAL/SHM files too
    try {
      fs.unlinkSync(meta.dbPath + "-wal");
    } catch (e) {}
    try {
      fs.unlinkSync(meta.dbPath + "-shm");
    } catch (e) {}
    this.databases.delete(tabId);
  }

  /**
   * Merge multiple tabs into a single chronological timeline.
   * Reads from each source DB via its own connection (avoids EXCLUSIVE lock conflicts)
   * and inserts into the merged DB in batches.
   *
   * @param {string} mergedTabId - New tab ID for the merged result
   * @param {Array<{tabId, tabName, tsCol}>} sources - Source tabs with timestamp column mapping
   * @param {Function} onProgress - callback({ phase, current, total, sourceName })
   * @returns {{ headers, rowCount, tsColumns, numericColumns }}
   */
  mergeTabs(mergedTabId, sources, onProgress) {
    // Collect metadata from all source tabs
    const sourceMetas = [];
    for (const src of sources) {
      const meta = this.databases.get(src.tabId);
      if (!meta) throw new Error(`Source tab "${src.tabName}" (${src.tabId}) not found`);
      sourceMetas.push({ ...src, meta });
    }

    // Build unified header list: _Source + datetime + union of all other headers
    const headerSet = new Set();
    for (const src of sourceMetas) {
      for (const h of src.meta.headers) headerSet.add(h);
    }
    const restHeaders = [...headerSet].filter((h) => h !== "_Source" && h !== "datetime").sort();
    const unifiedHeaders = ["_Source", "datetime", ...restHeaders];
    const colCount = unifiedHeaders.length;

    // Create the merged tab
    this.createTab(mergedTabId, unifiedHeaders);
    const mergedMeta = this.databases.get(mergedTabId);

    let totalInserted = 0;
    const totalRows = sourceMetas.reduce((sum, s) => sum + s.meta.rowCount, 0);
    const MERGE_BATCH = 50000;

    for (let si = 0; si < sourceMetas.length; si++) {
      const src = sourceMetas[si];
      const srcMeta = src.meta;

      if (onProgress) onProgress({ phase: "copying", current: totalInserted, total: totalRows, sourceName: src.tabName });

      // Build column index mapping: for each unified header, find the source safe column index
      // This avoids per-row object lookups
      const srcSelectCols = [];
      for (const uh of unifiedHeaders) {
        if (uh === "_Source" || uh === "datetime") {
          srcSelectCols.push(null); // handled specially
        } else {
          srcSelectCols.push(srcMeta.colMap[uh] || null);
        }
      }
      const tsSafeCol = srcMeta.colMap[src.tsCol] || null;

      // Build SELECT for source — read all columns from source DB
      const srcCols = srcMeta.safeCols.map((c) => c.safe).join(", ");
      const selectStmt = srcMeta.db.prepare(`SELECT ${srcCols} FROM data`);

      // Stream rows from source, map to unified schema, batch insert into merged
      let batch = [];
      for (const srcRow of selectStmt.iterate()) {
        const values = new Array(colCount);
        values[0] = src.tabName; // _Source
        values[1] = tsSafeCol ? (srcRow[tsSafeCol] || "") : ""; // datetime

        for (let i = 2; i < colCount; i++) {
          const sc = srcSelectCols[i];
          values[i] = sc ? (srcRow[sc] || "") : "";
        }

        batch.push(values);

        if (batch.length >= MERGE_BATCH) {
          this.insertBatchArrays(mergedTabId, batch);
          totalInserted += batch.length;
          batch = [];
          if (onProgress) onProgress({ phase: "copying", current: totalInserted, total: totalRows, sourceName: src.tabName });
        }
      }

      // Insert remaining rows
      if (batch.length > 0) {
        this.insertBatchArrays(mergedTabId, batch);
        totalInserted += batch.length;
        batch = [];
      }

      if (onProgress) onProgress({ phase: "copying", current: totalInserted, total: totalRows, sourceName: src.tabName });
    }

    // Finalize (creates indexedCols Set, detects types)
    if (onProgress) onProgress({ phase: "indexing", current: totalInserted, total: totalRows, sourceName: "" });
    const result = this.finalizeImport(mergedTabId);

    // Index the unified datetime and _Source columns
    const mergedDb = mergedMeta.db;
    const dtSafe = mergedMeta.colMap["datetime"];
    if (dtSafe && !mergedMeta.indexedCols.has(dtSafe)) {
      mergedDb.exec(`CREATE INDEX IF NOT EXISTS idx_${dtSafe} ON data(${dtSafe})`);
      mergedMeta.indexedCols.add(dtSafe);
    }
    const srcColSafe = mergedMeta.colMap["_Source"];
    if (srcColSafe && !mergedMeta.indexedCols.has(srcColSafe)) {
      mergedDb.exec(`CREATE INDEX IF NOT EXISTS idx_${srcColSafe} ON data(${srcColSafe})`);
      mergedMeta.indexedCols.add(srcColSafe);
    }

    return {
      headers: unifiedHeaders,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns,
    };
  }

  /**
   * Close all databases
   */
  closeAll() {
    for (const tabId of this.databases.keys()) {
      this.closeTab(tabId);
    }
  }
}

module.exports = TimelineDB;
