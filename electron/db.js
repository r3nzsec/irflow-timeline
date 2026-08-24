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

// ── Debug trace logger (shared singleton — see logger.js) ─────────
const { dbg } = require("./logger");
const { registerRuntimeFunctions } = require("./db/runtime-functions");
const { safeRegexTester } = require("./utils/safe-regex");

/**
 * Attach the tab's write statements to `meta` as memoized lazy properties.
 *
 * Each one compiles on first access and then replaces itself with a plain data property,
 * so callers keep using `meta.insertStmt` / `meta.tagInsertStmt` unchanged and a tab that
 * only ever reads never compiles them at all. Properties stay writable and configurable
 * so tests can substitute stubs.
 */
function lazyWriteStatements(meta, { colList, placeholders }) {
  const hasCols = meta.safeCols.length > 0;
  const define = (name, build) => {
    Object.defineProperty(meta, name, {
      configurable: true,
      enumerable: true,
      get() {
        const value = build();
        Object.defineProperty(meta, name, { value, writable: true, configurable: true, enumerable: true });
        return value;
      },
      set(value) {
        Object.defineProperty(meta, name, { value, writable: true, configurable: true, enumerable: true });
      },
    });
  };

  define("insertStmt", () => (hasCols
    ? meta.db.prepare(`INSERT INTO data (${colList}) VALUES (${placeholders})`)
    : null));
  define("multiInsertStmt", () => {
    if (!hasCols || meta.multiRowCount <= 1) return null;
    const singleRow = `(${placeholders})`;
    return meta.db.prepare(`INSERT INTO data (${colList}) VALUES ${Array(meta.multiRowCount).fill(singleRow).join(",")}`);
  });
  // Sized against multiInsertStmt: null whenever there is no multi-row insert to fill.
  define("insertFlat", () => (hasCols && meta.multiRowCount > 1
    ? new Array(meta.multiRowCount * meta.safeCols.length)
    : null));
  define("bmCheckStmt", () => meta.db.prepare("SELECT rowid FROM bookmarks WHERE rowid = ?"));
  define("bmInsertStmt", () => meta.db.prepare("INSERT OR IGNORE INTO bookmarks (rowid) VALUES (?)"));
  define("bmDeleteStmt", () => meta.db.prepare("DELETE FROM bookmarks WHERE rowid = ?"));
  define("bmCountStmt", () => meta.db.prepare("SELECT COUNT(*) as cnt FROM bookmarks"));
  define("tagInsertStmt", () => meta.db.prepare("INSERT OR IGNORE INTO tags (rowid, tag) VALUES (?, ?)"));
  define("tagDeleteStmt", () => meta.db.prepare("DELETE FROM tags WHERE rowid = ? AND tag = ?"));
  return meta;
}

class TimelineDB {
  constructor() {
    this.databases = new Map(); // tabId -> { db, dbPath, headers, rowCount, tsColumns }
    // Periodic WAL checkpoint — prevent unbounded WAL growth on long sessions
    this._walInterval = setInterval(() => {
      for (const [, meta] of this.databases) {
        try { if (meta.db?.open) meta.db.pragma("wal_checkpoint(PASSIVE)"); } catch {}
      }
    }, 5 * 60 * 1000); // every 5 minutes
  }

  // ── EVTX field utilities (delegated to analyzers/evtx-utils.js) ──
  _isHayabusaDataset(...a) { return require('./analyzers/evtx-utils')._isHayabusaDataset(...a); }
  _isChainsawDataset(...a) { return require('./analyzers/evtx-utils')._isChainsawDataset(...a); }
  _isChainsawProcessDataset(...a) { return require('./analyzers/evtx-utils')._isChainsawProcessDataset(...a); }
  _isChainsawLogonDataset(...a) { return require('./analyzers/evtx-utils')._isChainsawLogonDataset(...a); }
  _cleanWrappedField(...a) { return require('./analyzers/evtx-utils')._cleanWrappedField(...a); }
  _normalizeCompactKey(...a) { return require('./analyzers/evtx-utils')._normalizeCompactKey(...a); }
  _parseCompactKeyValues(...a) { return require('./analyzers/evtx-utils')._parseCompactKeyValues(...a); }
  _compactGet(...a) { return require('./analyzers/evtx-utils')._compactGet(...a); }
  _extractFirstInteger(...a) { return require('./analyzers/evtx-utils')._extractFirstInteger(...a); }
  _compactGetInt(...a) { return require('./analyzers/evtx-utils')._compactGetInt(...a); }
  _normalizeEvtxChannel(...a) { return require('./analyzers/evtx-utils')._normalizeEvtxChannel(...a); }
  _resolveEventChannel(...a) { return require('./analyzers/evtx-utils')._resolveEventChannel(...a); }
  _evtxChannelMatches(...a) { return require('./analyzers/evtx-utils')._evtxChannelMatches(...a); }
  _buildCompactAliasBlob(...a) { return require('./analyzers/evtx-utils')._buildCompactAliasBlob(...a); }
  _buildChainsawAliasBlob(...a) { return require('./analyzers/evtx-utils')._buildChainsawAliasBlob(...a); }
  _buildEvtxHaystack(...a) { return require('./analyzers/evtx-utils')._buildEvtxHaystack(...a); }

  /**
   * Create a new database for a tab and prepare the schema
   */
  createTab(tabId, headers) {
    dbg("DB", `createTab start`, { tabId, headerCount: headers?.length });
    const dbPath = this._dbPathHint || path.join(
      os.tmpdir(),
      `tle_${tabId}_${crypto.randomBytes(4).toString("hex")}.db`
    );
    this._dbPathHint = null;

    const db = new Database(dbPath);
    dbg("DB", `Database opened`, { dbPath });

    try {
    registerRuntimeFunctions(db);

    // page_size MUST be set before any tables are created
    // 64KB pages: fewer B-tree nodes, faster bulk writes & index creation
    db.pragma("page_size = 65536");

    // Scale pragmas based on file size — reduce memory for very large files to prevent OOM
    const fileSize = this._fileSizeHint || 0;
    const isLargeFile = fileSize > 5 * 1024 * 1024 * 1024; // >5GB
    this._fileSizeHint = 0; // consume the hint

    // Performance pragmas for bulk import (maximise write throughput)
    db.pragma("journal_mode = OFF"); // no journal — fastest writes (temp DB, crash = re-import)
    db.pragma("synchronous = OFF");
    // Size the write cache by FILE SIZE (~1.5× the file, clamped) instead of a flat 1GB — a 5MB
    // KAPE artifact does not need a 1GB cache, and this is the real per-import RSS governor (lower
    // RSS also unblocks safe concurrent imports later). Large files cap at 256MB to avoid OOM.
    const cacheKiB = isLargeFile ? 262144 : Math.min(1048576, Math.max(16384, Math.ceil((fileSize / 1024) * 1.5)));
    db.pragma(`cache_size = ${-cacheKiB}`); // negative = KiB
    db.pragma(`temp_store = ${isLargeFile ? "FILE" : "MEMORY"}`); // disk temp for large files
    db.pragma("mmap_size = 0"); // disable mmap during import (write-only)
    // EXCLUSIVE locking is only safe in a worker thread, which closes its connection
    // cleanly after import (releasing the lock). In the main process, in-process imports
    // (sigma "Open as Tab", mergeTabs, diffTabs) keep the connection open for queries, so the
    // lock would never release and the index/FTS worker (separate worker_threads
    // connection) would hang at "database is locked". Detected via isMainThread.
    const { isMainThread } = require("worker_threads");
    if (!isMainThread) {
      db.pragma("locking_mode = EXCLUSIVE"); // single-user, avoid lock overhead
    }
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
    db.exec(`CREATE INDEX idx_tags_tag ON tags(tag, rowid)`);
    db.exec(`CREATE INDEX idx_tags_rowid ON tags(rowid)`);

    // Create color rules table
    db.exec(
      `CREATE TABLE color_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        col_name TEXT, condition TEXT, value TEXT,
        bg_color TEXT, fg_color TEXT
      )`
    );

    // Detect timestamp columns based on header names.
    // Exclusion: names containing "elapsed" or "duration" are durations (integers), not timestamps.
    const tsColumns = new Set();
    headers.forEach((h) => {
      if (
        /(time|date|timestamp|created|modified|accessed|when|start|end|written)/i.test(h) &&
        !/elapsed|duration/i.test(h)
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

    // Pre-cache bookmark/tag prepared statements (avoids re-prepare per operation)
    const bmCheckStmt = db.prepare("SELECT rowid FROM bookmarks WHERE rowid = ?");
    const bmInsertStmt = db.prepare("INSERT OR IGNORE INTO bookmarks (rowid) VALUES (?)");
    const bmDeleteStmt = db.prepare("DELETE FROM bookmarks WHERE rowid = ?");
    const bmCountStmt = db.prepare("SELECT COUNT(*) as cnt FROM bookmarks");
    const tagInsertStmt = db.prepare("INSERT OR IGNORE INTO tags (rowid, tag) VALUES (?, ?)");
    const tagDeleteStmt = db.prepare("DELETE FROM tags WHERE rowid = ? AND tag = ?");

    const meta = {
      tabId,
      db,
      dbPath,
      headers,
      safeCols,
      tsColumns,
      numericColumns: new Set(),
      indexedCols: new Set(),
      rowCount: 0,
      ftsReady: false,
      isLargeFile,
      insertStmt,
      multiInsertStmt,
      multiRowCount,
      insertFlat,
      bmCheckStmt, bmInsertStmt, bmDeleteStmt, bmCountStmt,
      tagInsertStmt, tagDeleteStmt,
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
          values[c] = row[hdrs[c]] ?? "";
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
  finalizeImport(tabId, options = {}) {
    dbg("DB", `finalizeImport start`, { tabId });
    const meta = this.databases.get(tabId);
    if (!meta) { dbg("DB", `finalizeImport: no meta for tab`); return; }
    const skipWalPromotion = !!options.skipWalPromotion;

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

    // Refine timestamp classification with actual values. The name-based detection in
    // createTab is over-broad ("start"/"end"/"written" also match StartType/BytesWritten),
    // which wastes a sort_datetime() expression index per false positive (and, for large
    // files, an eager column index — see buildIndexesAsync). Validate against the SAME
    // sort_datetime UDF used for sorting, over the first 5000 rows: demote a column only
    // when it has enough non-empty values AND almost none are sortable as dates. Genuine
    // timestamp columns parse and are never demoted (which would break chronological sort).
    for (const col of meta.safeCols) {
      if (!meta.tsColumns.has(col.original)) continue;
      try {
        const r = db.prepare(
          `SELECT COUNT(*) AS total, COUNT(sort_datetime(s.v)) AS parsed
             FROM (SELECT ${col.safe} AS v FROM data LIMIT 5000) s
            WHERE TRIM(COALESCE(s.v,'')) != ''`
        ).get();
        if (r && r.total >= 10 && r.parsed / r.total < 0.25) {
          meta.tsColumns.delete(col.original);
          dbg("DB", `demoted misnamed non-timestamp column`, { col: col.original, parseRate: Number((r.parsed / r.total).toFixed(2)) });
        }
      } catch (e) { dbg("DB", `ts validation skipped for ${col.original}`, { error: e.message }); }
    }

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

    // Workers skip WAL promotion here — adoptTabFromFile on the main process sets WAL/mmap.
    // Avoids a full checkpoint on close when the temp DB used journal_mode=OFF during ingest.
    if (!skipWalPromotion) {
      db.pragma("journal_mode = WAL"); // need WAL for concurrent reads during build
      db.pragma("synchronous = NORMAL");
      db.pragma("cache_size = -262144"); // 256MB cache for queries
    }

    // Skip ANALYZE here — run after async index build completes

    return {
      rowCount: meta.rowCount,
      headers: meta.headers,
      tsColumns: [...meta.tsColumns],
      numericColumns: [...meta.numericColumns],
    };
  }

  /**
   * Re-open a tab database created by an import worker. The worker owns parsing
   * and finalization; the main process adopts the completed SQLite file here so
   * existing query/analyzer/tag APIs keep using the TimelineDB facade.
   */
  adoptTabFromFile(tabId, descriptor = {}) {
    const {
      dbPath,
      headers = [],
      rowCount = 0,
      tsColumns = [],
      numericColumns = [],
      isLargeFile = false,
      ftsReady = false,
      ftsCreated = false,
      indexesReady = false,
      indexedCols = [],
    } = descriptor;
    if (!dbPath) throw new Error("Cannot adopt tab without dbPath");
    if (this.databases.has(tabId)) this.closeTab(tabId);

    const db = new Database(dbPath);
    registerRuntimeFunctions(db);

    try {
      db.pragma("journal_mode = WAL");
      db.pragma("synchronous = NORMAL");
      db.pragma("cache_size = -262144");
      db.pragma("mmap_size = 536870912");
    } catch (e) {
      dbg("DB", `adoptTabFromFile pragma setup failed`, { tabId, error: e.message });
    }

    const safeCols = headers.map((h, i) => ({ original: h, safe: `c${i}` }));
    const colList = safeCols.map((c) => c.safe).join(", ");
    const placeholders = safeCols.map(() => "?").join(", ");
    const multiRowCount = safeCols.length > 0 ? Math.max(1, Math.floor(32766 / safeCols.length)) : 1;

    let detectedFtsCreated = !!ftsCreated;
    try {
      const fts = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'data_fts'").get();
      detectedFtsCreated = detectedFtsCreated || !!fts;
    } catch {}

    const meta = {
      tabId,
      db,
      dbPath,
      headers,
      safeCols,
      tsColumns: new Set(tsColumns),
      numericColumns: new Set(numericColumns),
      rowCount,
      ftsReady: !!ftsReady,
      ftsCreated: detectedFtsCreated,
      ftsBuilding: false,
      indexesReady: !!indexesReady,
      indexesBuilding: false,
      indexedCols: new Set(indexedCols),
      isLargeFile: !!isLargeFile,
      multiRowCount,
      colMap: Object.fromEntries(safeCols.map((c) => [c.original, c.safe])),
      reverseColMap: Object.fromEntries(safeCols.map((c) => [c.safe, c.original])),
    };

    // Write statements are prepared on first use, not on adopt. Adoption is not only the
    // main process taking over an imported tab — every scroll-window query spawns a
    // worker that adopts the same tab, runs one SELECT, and exits. Preparing the whole
    // write surface there compiled an INSERT with up to 32,766 placeholders (a SQL string
    // tens of KB wide) plus six bookmark/tag statements for a connection that never
    // writes, paying that cost on the latency path of every fetch during a fast scroll.
    lazyWriteStatements(meta, { colList, placeholders });

    this.databases.set(tabId, meta);
    dbg("DB", `adoptTabFromFile OK`, { tabId, dbPath, rowCount, headerCount: headers.length });
    return meta;
  }

  getTabWorkerDescriptor(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    return {
      tabId,
      dbPath: meta.dbPath,
      headers: meta.headers,
      rowCount: meta.rowCount,
      tsColumns: [...(meta.tsColumns || [])],
      numericColumns: [...(meta.numericColumns || [])],
      isLargeFile: !!meta.isLargeFile,
      ftsReady: !!meta.ftsReady,
      ftsCreated: !!meta.ftsCreated,
      indexesReady: !!meta.indexesReady,
      indexedCols: [...(meta.indexedCols || [])],
    };
  }

  markIndexesBuilding(tabId, building) {
    const meta = this.databases.get(tabId);
    if (meta) meta.indexesBuilding = !!building;
  }

  markIndexesBuilt(tabId, result = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    meta.indexesBuilding = false;
    meta.indexesReady = !result.error;
    if (Array.isArray(result.indexedCols)) meta.indexedCols = new Set(result.indexedCols);
  }

  markFtsBuilding(tabId, building) {
    const meta = this.databases.get(tabId);
    if (meta) meta.ftsBuilding = !!building;
  }

  markFtsBuilt(tabId, result = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    meta.ftsBuilding = false;
    meta.ftsReady = !result.error;
    meta.ftsCreated = meta.ftsCreated || !result.error;
  }

  /**
   * Close a database connection without deleting its files. Used by workers
   * after handing an imported SQLite file back to the main process.
   */
  releaseTab(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    this.databases.delete(tabId);
    try { meta.db.close(); } catch {}
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
      // Temporarily tune pragmas for fast index build (same as buildIndexesAsync)
      meta.db.pragma("synchronous = OFF");
      meta.db.pragma("threads = 8");
      meta.db.pragma("mmap_size = 0");
      const isLarge = meta.rowCount > 5000000;
      meta.db.pragma(`cache_size = ${isLarge ? -262144 : -1048576}`);

      const collation = (meta.numericColumns && meta.numericColumns.has(colName)) ? "BINARY" : "NOCASE";
      meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${safeCol} ON data(${safeCol} COLLATE ${collation})`);
      // Timestamp columns: expression index so ORDER BY sort_datetime(col)
      // uses the index instead of calling JS per-row.
      if (meta.tsColumns.has(colName)) {
        meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_sort_${safeCol} ON data(sort_datetime(${safeCol}))`);
      }

      // Restore normal query pragmas
      meta.db.pragma("synchronous = NORMAL");
      meta.db.pragma("cache_size = -262144");
      meta.db.pragma("mmap_size = 536870912");
    } catch (e) {
      // Restore pragmas even on failure
      try { meta.db.pragma("synchronous = NORMAL"); } catch (_) {}
      try { meta.db.pragma("mmap_size = 536870912"); } catch (_) {}
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
        // trigram tokenizer → MATCH does case-insensitive SUBSTRING matching (3+ chars),
        // matching the substring semantics of the LIKE fallback (issue #8: b4ckd00r must
        // match crackb4ckd00r). Used as an indexed prefilter in query-store _applySearch.
        `CREATE VIRTUAL TABLE IF NOT EXISTS data_fts USING fts5(${colList}, content=data, content_rowid=rowid, tokenize='trigram')`
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
    if (!meta || meta.ftsReady || meta.ftsBuilding) return Promise.resolve({ skipped: true });
    meta.ftsBuilding = true;

    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    const db = meta.db;

    // Create FTS5 virtual table
    if (!meta.ftsCreated) {
      db.exec(
        // trigram tokenizer → MATCH does case-insensitive SUBSTRING matching (3+ chars),
        // matching the substring semantics of the LIKE fallback (issue #8: b4ckd00r must
        // match crackb4ckd00r). Used as an indexed prefilter in query-store _applySearch.
        `CREATE VIRTUAL TABLE IF NOT EXISTS data_fts USING fts5(${colList}, content=data, content_rowid=rowid, tokenize='trigram')`
      );
      meta.ftsCreated = true;
    }

    const totalRows = meta.rowCount || db.prepare("SELECT COUNT(*) as cnt FROM data").get().cnt;
    // Smaller chunks give the renderer visible progress while keeping large
    // imports efficient. The worker owns the blocking work, so responsiveness
    // now matters more than minimizing chunk count.
    const CHUNK = totalRows <= 1000000 ? 50000 : (totalRows <= 5000000 ? 100000 : 250000);
    let lastRowid = 0;

    // Aggressive pragmas for FTS build — keep WAL mode so concurrent reads
    // (queryRows, histogram, etc.) remain safe during the build.
    // Scale down for large files to prevent OOM
    const large = meta.isLargeFile;
    db.pragma("synchronous = OFF");
    db.pragma(`cache_size = ${large ? -262144 : -1048576}`); // 256MB or 1GB
    db.pragma(`temp_store = ${large ? "FILE" : "MEMORY"}`);
    db.pragma("threads = 8"); // parallel sort/merge

    // Send initial progress so the UI can show the FTS overlay immediately
    if (onProgress) onProgress({ indexed: 0, total: totalRows, done: false });

    return new Promise((resolve) => {
      const insertChunk = () => {
        // Tab may have been closed while building — check both map and flag
        if (meta.closed || !this.databases.has(tabId)) {
          meta.ftsBuilding = false;
          resolve({ cancelled: true });
          return;
        }

        try {
          const inserted = db.prepare(
            `INSERT INTO data_fts(rowid, ${colList}) SELECT rowid, ${colList} FROM data WHERE rowid > ? ORDER BY rowid LIMIT ?`
          ).run(lastRowid, CHUNK);

          // Track actual last rowid inserted (not fixed increment) —
          // handles non-contiguous rowids correctly
          if (inserted.changes > 0) {
            const last = db.prepare(`SELECT MAX(rowid) as m FROM data_fts`).get();
            lastRowid = last?.m || lastRowid + CHUNK;
          }
          const indexed = Math.min(lastRowid, totalRows);

          if (inserted.changes < CHUNK) {
            if (onProgress) onProgress({ indexed: totalRows, total: totalRows, done: false, optimizing: true });
            // All rows indexed — run ANALYZE now that all indexes + FTS exist
            try { db.exec("ANALYZE"); } catch (e) { dbg("DB", `ANALYZE failed`, { error: e.message }); }

            // Restore conservative query-mode pragmas
            db.pragma("synchronous = NORMAL");
            db.pragma("cache_size = -262144"); // 256MB for queries
            db.pragma("mmap_size = 536870912"); // 512MB mmap for reads
            try { db.pragma("wal_checkpoint(PASSIVE)"); } catch (e) { /* ignore */ }
            meta.ftsReady = true;
            meta.ftsBuilding = false;
            if (onProgress) onProgress({ indexed: totalRows, total: totalRows, done: true });
            resolve({ indexed: totalRows, total: totalRows, done: true });
          } else {
            if (onProgress) onProgress({ indexed, total: totalRows, done: false });
            // Yield to event loop before next chunk — keeps UI responsive
            setImmediate(insertChunk);
          }
        } catch (e) {
          // DB handle was closed, or a disk-full / I/O error hit mid-INSERT. Drop the
          // partial FTS table and checkpoint so a half-built trigram index (potentially
          // tens of GB) is reclaimed immediately instead of stranding disk until the tab
          // closes. Search falls back to LIKE because ftsReady stays false.
          dbg("DB", `buildFtsAsync chunk failed`, { tabId, error: e.message });
          meta.ftsBuilding = false;
          meta.ftsReady = false;
          try {
            db.exec("DROP TABLE IF EXISTS data_fts");
            meta.ftsCreated = false;
            db.pragma("wal_checkpoint(TRUNCATE)");
          } catch (_) { /* db likely closed — temp files reclaimed on tab close */ }
          resolve({ error: e.message });
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
    if (!meta || meta.indexesReady || meta.indexesBuilding) return Promise.resolve({ skipped: true });
    meta.indexesBuilding = true;

    const allCols = meta.safeCols.filter((c) => !meta.indexedCols.has(c.safe));

    // Prioritize timestamp columns first — users typically sort by time immediately
    const tsSet_ = meta.tsColumns || new Set();
    allCols.sort((a, b) => {
      const aTs = tsSet_.has(a.original) ? 0 : 1;
      const bTs = tsSet_.has(b.original) ? 0 : 1;
      return aTs - bTs;
    });

    // For large files, eagerly index timestamp columns plus EventID/Channel (JS Sigma
    // logsource pre-filters). Other columns are indexed lazily on first sort via
    // _ensureIndex — this avoids the ~30-50GB all-column index footprint on huge imports.
    // Deferred columns are intentionally NOT added to indexedCols, so _ensureIndex still
    // builds them on demand. (Small files keep eager all-column indexing for snappy filters.)
    const isSigmaFilterCol = (name) => /^(EventID|EventId|event_id|eventid|id|Channel|SourceName|Provider)$/i.test(String(name || ""));
    const eagerCols = meta.isLargeFile
      ? allCols.filter((c) => tsSet_.has(c.original) || isSigmaFilterCol(c.original))
      : allCols;

    // Pre-filter: skip columns with uniform values (cardinality ≤ 1)
    // Sample-based: check first + middle + last 100 rows instead of full DISTINCT scan
    const cols = [];
    const skippedCols = [];
    const midOffset = Math.max(0, Math.floor(meta.rowCount / 2));
    for (const col of eagerCols) {
      try {
        const distinct = meta.db
          .prepare(`SELECT COUNT(*) AS c FROM (SELECT DISTINCT ${col.safe} FROM (SELECT ${col.safe} FROM (SELECT * FROM data LIMIT 100) UNION ALL SELECT ${col.safe} FROM (SELECT * FROM data LIMIT 100 OFFSET ${midOffset}) UNION ALL SELECT ${col.safe} FROM (SELECT * FROM data ORDER BY rowid DESC LIMIT 100)))`)
          .get();
        if (distinct && distinct.c <= 1) {
          skippedCols.push(col.original);
          meta.indexedCols.add(col.safe); // Mark as "done" so _ensureIndex won't rebuild
          continue;
        }
      } catch { /* If check fails, build the index anyway */ }
      cols.push(col);
    }
    if (skippedCols.length > 0) {
      dbg("DB", `buildIndexesAsync skipping uniform columns`, { skipped: skippedCols });
    }

    // Determine collation per column: binary for numeric/timestamp, NOCASE for text
    const numericSet = meta.numericColumns || new Set();
    const tsSet = meta.tsColumns || new Set();

    const total = cols.length;
    let built = 0;

    dbg("DB", `buildIndexesAsync start`, { tabId, total, skipped: skippedCols.length });

    // Aggressive pragmas for index build — keep WAL mode so concurrent reads
    // (queryRows, histogram, etc.) remain safe during the build.
    // Scale down for large files to prevent OOM
    const large = meta.isLargeFile;
    meta.db.pragma("synchronous = OFF");
    meta.db.pragma(`cache_size = ${large ? -262144 : -1048576}`); // 256MB or 1GB
    meta.db.pragma(`temp_store = ${large ? "FILE" : "MEMORY"}`);
    meta.db.pragma("threads = 8"); // parallel sort for CREATE INDEX
    meta.db.pragma("mmap_size = 0"); // disable mmap — rely on cache (write-heavy)

    // Send initial progress so the UI overlay renders immediately
    if (onProgress) onProgress({ built: 0, total, done: false, currentCol: cols[0]?.original });

    return new Promise((resolve) => {
      const buildNext = () => {
        // Tab may have been closed while building — check both map and flag
        if (meta.closed || !this.databases.has(tabId)) {
          meta.indexesBuilding = false;
          resolve({ cancelled: true, indexedCols: [...meta.indexedCols] });
          return;
        }

        if (built >= cols.length) {
          try {
            // Bounded ANALYZE so the query planner actually USES the indexes just built. This MUST
            // run here (not only in buildFtsAsync): FTS is skipped for large files (>5GB), so
            // otherwise a freshly-imported large DB has indexes but ZERO planner stats and the first
            // sort/filter full-scans (the #1 import-speed pain point). analysis_limit=1000 keeps it
            // to seconds even on 100M+ rows.
            meta.db.pragma("analysis_limit = 1000");
            try { meta.db.exec("ANALYZE"); } catch (e) { dbg("DB", `buildIndexesAsync ANALYZE failed`, { tabId, error: e.message }); }
            // Restore conservative query-mode pragmas
            meta.db.pragma("synchronous = NORMAL");
            meta.db.pragma("cache_size = -262144"); // 256MB for queries
            meta.db.pragma("mmap_size = 536870912"); // 512MB mmap for reads
            try { meta.db.pragma("wal_checkpoint(PASSIVE)"); } catch (e) { /* ignore */ }
          } catch (e) {
            dbg("DB", `buildIndexesAsync pragma restore failed (tab likely closed)`, { tabId, error: e.message });
          }

          meta.indexesReady = true;
          meta.indexesBuilding = false;
          dbg("DB", `buildIndexesAsync complete`, { tabId, total });
          if (onProgress) onProgress({ built: total, total, done: true, currentCol: null });
          resolve({ built: total, total, done: true, indexedCols: [...meta.indexedCols], skippedCols });
          return;
        }

        try {
          // Build up to 5 indexes per yield — each CREATE INDEX on 1M+ rows takes 1-3s,
          // batching reduces total build time ~50% while keeping UI responsive
          const BATCH = 5;
          for (let b = 0; b < BATCH && built < cols.length; b++) {
            if (meta.closed) break; // re-check between indexes
            const col = cols[built];
            try {
              // Use binary collation for numeric/timestamp columns (faster sort),
              // COLLATE NOCASE for text columns (case-insensitive filter/sort)
              const useBinary = numericSet.has(col.original) || tsSet.has(col.original);
              if (useBinary) {
                meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${col.safe} ON data(${col.safe})`);
              } else {
                meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${col.safe} ON data(${col.safe} COLLATE NOCASE)`);
              }
              // Timestamp columns: add expression index on sort_datetime() so
              // ORDER BY sort_datetime(col) can use the index instead of calling
              // the JS function per-row during sort.
              if (tsSet.has(col.original)) {
                meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_sort_${col.safe} ON data(sort_datetime(${col.safe}))`);
              }
              meta.indexedCols.add(col.safe);
            } catch (e) {
              // A disk-full / I/O error won't recover on the next column — abort the whole
              // build so it is surfaced (instead of silently producing a half-indexed DB
              // that looks identical to success). Other per-column failures are skipped.
              if (/SQLITE_(FULL|IOERR)/.test(e?.code || "") || /disk (is )?full|out of memory|I\/O error|SQLITE_FULL/i.test(e?.message || "")) {
                throw e;
              }
              dbg("DB", `index creation failed for ${col.original}`, { error: e.message });
            }
            built++;
          }
        } catch (e) {
          // DB handle was closed between our check and the operation
          dbg("DB", `buildIndexesAsync batch failed (tab likely closed)`, { tabId, error: e.message });
          meta.indexesBuilding = false;
          resolve({ error: e.message, indexedCols: [...meta.indexedCols] });
          return;
        }

        if (onProgress) onProgress({ built, total, done: false, currentCol: cols[Math.min(built, cols.length) - 1]?.original });

        // Yield to event loop after each batch — keeps UI responsive
        setImmediate(buildNext);
      };

      // Defer first index — let the UI render the overlay first
      setImmediate(buildNext);
    });
  }

  /**
   * Check if background builds (indexes/FTS) are running on a tab.
   *
   * NOTE: this must NOT be used to block bookmark/tag writes. Both builds run on
   * THIS connection, on the main thread, chunked between event-loop turns, and
   * they only touch `data`/`data_fts` — a write to the tiny `tags`/`bookmarks`
   * tables in between chunks is safe. Gating on it silently discarded everything
   * an analyst tagged during the minutes-long index build that follows a large
   * import, while the UI showed the tag as applied.
   */
  _isBuilding(tabId) {
    const meta = this.databases.get(tabId);
    return meta && (meta.indexesBuilding || meta.ftsBuilding);
  }

  /**
   * Query rows with filtering, sorting, and pagination
   * This is the main query method — only fetches the visible window
   */
  // Query/filter methods are mixed in from electron/db/query-store.js.

  // Bookmark/tag methods are mixed in from electron/db/tag-store.js.

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
    // Concatenate columns with COALESCE/|| in SQL so REGEXP is called once per row
    // instead of once per column×row — reduces function calls by ~Nx for N columns
    const concatExpr = colList.map((c) => `COALESCE(${c},'')`).join(" || ' ' || ");
    const matchedSet = new Set();
    for (let i = 0; i < iocPatterns.length; i += batchSize) {
      const batch = iocPatterns.slice(i, i + batchSize);
      const altPattern = batch.join("|");
      const rows = db.prepare(`SELECT rowid FROM data WHERE (${concatExpr}) REGEXP ?`).all(altPattern);
      for (const r of rows) matchedSet.add(r.rowid);
    }

    const matchedRowIds = [...matchedSet];
    if (matchedRowIds.length === 0) {
      const perIocCounts = {};
      for (const p of iocPatterns) perIocCounts[p] = 0;
      return { matchedRowIds, perIocCounts };
    }

    // Pre-compile all regex patterns once. IOC patterns are user/feed-supplied, so
    // route them through the ReDoS-safe compiler — the bounded tester also caps the
    // per-row concatenation length below. A rejected (unsafe/invalid) pattern is skipped.
    const compiled = [];
    const perIocCounts = {};
    for (let pi = 0; pi < iocPatterns.length; pi++) {
      const pattern = iocPatterns[pi];
      const test = safeRegexTester(pattern, "i");
      if (test) compiled.push({ test, pi, pattern });
      else perIocCounts[pattern] = 0;
    }
    for (const c of compiled) perIocCounts[c.pattern] = 0;

    // Phase 2: per-IOC hit counts AND per-row IOC mapping.
    // Load matched rows in batches and test-and-discard each batch instead of materializing
    // every matched row's full column data at once. A broad IOC (e.g. a short substring or
    // ".") can match millions of rows; holding all their full payloads in a single array was
    // the dominant OOM driver in the analyzer worker. matchedRowIds/perRowIocs are part of
    // the result contract (the renderer tags every hit), but the full row payloads are
    // internal and only needed transiently for attribution, so they're freed per batch.
    const colJoined = colList.join(", ");
    const perRowIocs = {}; // rowId -> [patternIndex, ...]
    for (let i = 0; i < matchedRowIds.length; i += 500) {
      const batch = matchedRowIds.slice(i, i + 500);
      const ph = batch.map(() => "?").join(",");
      const rows = db.prepare(`SELECT rowid, ${colJoined} FROM data WHERE rowid IN (${ph})`).all(...batch);
      for (const row of rows) {
        // Concatenate all column values once per row for fast regex testing
        let concat = "";
        for (let ci = 0; ci < colList.length; ci++) {
          const v = row[colList[ci]];
          if (v) { concat += v; concat += " "; }
        }
        for (const { test, pi, pattern } of compiled) {
          if (test(concat)) {
            perIocCounts[pattern]++;
            if (!perRowIocs[row.rowid]) perRowIocs[row.rowid] = [];
            perRowIocs[row.rowid].push(pi);
          }
        }
      }
    }

    return { matchedRowIds, perIocCounts, perRowIocs };
  }

  // Export/query utility methods are mixed in from electron/db/query-store.js.

  // Timeline analytics methods are mixed in from electron/db/timeline-analytics.js.

  /**
   * Build a process tree from Sysmon EventID 1 (Process Create) events.
   */
  getProcessTree(tabId, options = {}) {
    const { getProcessTree: _fn } = require("./analyzers/process-tree");
    const meta = this.databases.get(tabId);
    if (!meta) return { processes: [], stats: {}, columns: {}, error: "No database" };
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
      ensureIndex: (...args) => this._ensureIndex(...args),
    };
    return _fn(meta, options, ctx);
  }

  /**
   * Lightweight preview for Process Inspector config.
   */
  previewProcessTree(tabId, options = {}) {
    const { previewProcessTree: _fn } = require("./analyzers/process-tree");
    const meta = this.databases.get(tabId);
    if (!meta) return { eventCounts: {}, columnQuality: {}, linkingQuality: {}, error: "No database" };
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
      ptPreviewCache: this._ptPreviewCache,
    };
    return _fn(meta, options, ctx);
  }

  /**
   * Process Inspector — enriched inspection view for a selected process node.
   */
  getProcessInspectorContext(tabId, options = {}) {
    const { getProcessInspectorContext: _fn } = require("./analyzers/process-tree");
    const meta = this.databases.get(tabId);
    if (!meta) return { selected: null, timeline: [], groups: [], enrichmentChips: [], error: "No database" };
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
      ensureIndex: (...args) => this._ensureIndex(...args),
    };
    return _fn(meta, options, ctx);
  }

  previewLateralMovement(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { eventCounts: {}, columnQuality: {}, error: "No database" };
    const {
      sourceCol, targetCol, userCol, logonTypeCol, eventIdCol, tsCol, domainCol,
      syntheticTargetHost = "",
      excludeLocalLogons = false, excludeServiceAccounts = false,
    } = options;
    const detect = (patterns) => { for (const p of patterns) { const f = meta.headers.find((h) => p.test(h)); if (f) return f; } return null; };
    const isEvtxECmd = meta.headers.some((h) => /^RemoteHost$/i.test(h)) && meta.headers.some((h) => /^PayloadData1$/i.test(h));
    const isHayabusa = this._isHayabusaDataset(meta);
    const isChainsaw = this._isChainsawLogonDataset(meta);
    const detailsCol = isHayabusa ? detect([/^Details$/i]) : null;
    const extraCol = isHayabusa ? detect([/^ExtraFieldInfo$/i]) : null;
    const cols = {
      source: sourceCol || detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^Source_Network_Address$/i, /^RemoteHost$/i, ...(isChainsaw ? [/^source_ip$/i] : [])]) || detailsCol,
      target: targetCol || detect([/^Computer$/i, /^ComputerName$/i, /^computer_name$/i, /^Hostname$/i]),
      user: userCol || detect([/^TargetUserName$/i, /^Target_User_Name$/i, ...(isEvtxECmd ? [/^PayloadData1$/i] : []), /^UserName$/i, ...(isChainsaw ? [/^target_username$/i] : [])]) || detailsCol,
      logonType: logonTypeCol || detect([/^LogonType$/i, /^Logon_Type$/i, ...(isChainsaw ? [/^logon_type$/i] : []), ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]) || detailsCol,
      eventId: eventIdCol || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
      ts: tsCol || detect([/^datetime$/i, /^UtcTime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
      domain: domainCol || detect([/^TargetDomainName$/i, /^Target_Domain_Name$/i, /^SubjectDomainName$/i]) || extraCol || detailsCol,
      details: detailsCol,
      extra: extraCol,
    };
    cols._isChainsaw = isChainsaw;
    cols._syntheticTarget = !cols.target && (syntheticTargetHost || isChainsaw) ? (syntheticTargetHost || "LOCAL_HOST") : "";
    try {
      const db = meta.db;
      const params = [];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);
      // Scope exclusions matching the analyzer's in-memory filters (getLateralMovement lines ~3127-3128)
      if (excludeLocalLogons && cols.source && meta.colMap[cols.source] && cols.target && meta.colMap[cols.target]) {
        // Analyzer skips when parsed sourceHost === targetHost but keeps rows where either is null/blank.
        // Use OR NULL guards so SQL doesn't drop null-source/null-target rows.
        const sc = meta.colMap[cols.source], tc = meta.colMap[cols.target];
        whereConditions.push(`(${sc} IS NULL OR TRIM(${sc}) = '' OR ${tc} IS NULL OR TRIM(${tc}) = '' OR UPPER(TRIM(${sc})) != UPPER(TRIM(${tc})))`);
      }
      if (excludeServiceAccounts && cols.user && meta.colMap[cols.user]) {
        // Match SERVICE_RE from analyzer: SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM-*, UMFD-*, ANONYMOUS LOGON, plus machine accounts (*$)
        const uc = meta.colMap[cols.user];
        whereConditions.push(`(${uc} IS NULL OR (${uc} NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') AND ${uc} NOT LIKE 'DWM-%' AND ${uc} NOT LIKE 'UMFD-%' AND ${uc} NOT LIKE '%$'))`);
      }
      const wc = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

      // Cache key — return cached result if inputs unchanged
      const cacheKey = JSON.stringify([tabId, cols, wc, params]);
      if (!this._lmPreviewCache) this._lmPreviewCache = new Map();
      if (this._lmPreviewCache.size > 50) { const first = this._lmPreviewCache.keys().next().value; this._lmPreviewCache.delete(first); }
      const cached = this._lmPreviewCache.get(cacheKey);
      if (cached) return cached;

      // Event ID counts — single grouped query, only EIDs shown in the UI
      const eventCounts = {};
      let trackedEvents = 0;
      if (cols.eventId && meta.colMap[cols.eventId]) {
        const eidSafe = meta.colMap[cols.eventId];
        // Derived from the detector registry so the pre-flight count can never advertise
        // events the analysis will not request (or miss ones it will).
        const { PREVIEW_EVENT_IDS } = require("./analyzers/lateral-movement/detector-registry");
        const uiEids = PREVIEW_EVENT_IDS;
        const eidWhere = wc ? `${wc} AND` : "WHERE";
        const eidRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${eidSafe}`).all(...params, ...uiEids);
        for (const r of eidRows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = r.cnt; trackedEvents += r.cnt; } }
      }

      // Column quality — single batched query sampling 2000 rows
      const columnQuality = {};
      const mappedCols = Object.entries(cols).filter(([, cn]) => cn && meta.colMap[cn]);
      if (mappedCols.length > 0) {
        const caseParts = [];
        for (const [key, cn] of mappedCols) {
          const safe = meta.colMap[cn];
          caseParts.push(`SUM(CASE WHEN ${safe} IS NULL OR TRIM(${safe}) = '' OR ${safe} = '-' THEN 1 ELSE 0 END) as null_${key}`);
        }
        // Source IP-only check: count IP-pattern values inline
        const srcSafe = cols.source && meta.colMap[cols.source] ? meta.colMap[cols.source] : null;
        if (srcSafe) {
          caseParts.push(`SUM(CASE WHEN ${srcSafe} IS NOT NULL AND TRIM(${srcSafe}) != '' AND ${srcSafe} != '-' AND ${srcSafe} GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' THEN 1 ELSE 0 END) as src_ip`);
          caseParts.push(`SUM(CASE WHEN ${srcSafe} IS NOT NULL AND TRIM(${srcSafe}) != '' AND ${srcSafe} != '-' THEN 1 ELSE 0 END) as src_nonnull`);
        }
        const batchSql = `SELECT COUNT(*) as total, ${caseParts.join(", ")} FROM (SELECT * FROM data ${wc} LIMIT 2000)`;
        const qr = db.prepare(batchSql).get(...params);
        const sampleTotal = qr ? qr.total : 0;
        for (const [key, cn] of mappedCols) {
          const nulls = qr ? (qr[`null_${key}`] || 0) : 0;
          const qi = { mapped: true, nullRate: sampleTotal > 0 ? Math.round((nulls / sampleTotal) * 100) : 0 };
          if (key === "source" && srcSafe && qr && qr.src_nonnull > 0) {
            qi.ipOnlyRate = Math.round(((qr.src_ip || 0) / qr.src_nonnull) * 100);
          }
          columnQuality[key] = qi;
        }
        // Mark unmapped columns
        for (const [key, cn] of Object.entries(cols)) {
          if (!cn || !meta.colMap[cn]) columnQuality[key] = { mapped: false };
        }
      } else {
        for (const key of Object.keys(cols)) columnQuality[key] = { mapped: false };
      }

      const result = { eventCounts, columnQuality, trackedEvents, resolvedColumns: cols, isHayabusa, isEvtxECmd, isChainsaw };
      this._lmPreviewCache.set(cacheKey, result);
      // Opportunistically create eventId index after returning — speeds up future queries
      if (cols.eventId) setImmediate(() => { try { this._ensureIndex(tabId, cols.eventId); } catch (_) {} });
      return result;
    } catch (e) {
      return { eventCounts: {}, columnQuality: {}, error: e.message };
    }
  }

  /**
   * Detect the KAPE collection host from a tab's Computer column distribution.
   */
  detectKapeCollectionHost(tabId) {
    const { detectKapeCollectionHost: _fn } = require("./analyzers/lateral-movement/kape-host");
    const meta = this.databases.get(tabId);
    if (!meta) return { collectionHost: null, confidence: "none", hostDistribution: [], format: null };
    return _fn(meta);
  }

  getLateralMovement(tabId, options = {}) {
    const { getLateralMovement: _getLM } = require("./analyzers/lateral-movement");
    const meta = this.databases.get(tabId);
    if (!meta) return { nodes: [], edges: [], chains: [], stats: {}, columns: {}, error: "No database" };
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
      ensureIndex: (...args) => this._ensureIndex(...args),
      lmPreviewCache: this._lmPreviewCache,
    };
    return _getLM(meta, options, ctx);
  }

  /**
   * Multi-source lateral movement — merges logon events from multiple tabs.
   */
  getMultiSourceLateralMovement(tabIds, options = {}) {
    const { getMultiSourceLateralMovement: _fn } = require("./analyzers/lateral-movement/multi-source");
    const tabLabels = options._tabLabels || {};
    const metas = tabIds.map(id => {
      const meta = this.databases.get(id);
      if (!meta) return null;
      const label = tabLabels[id] || id;
      return { meta, tabId: id, label };
    }).filter(Boolean);
    if (metas.length === 0) return { nodes: [], edges: [], chains: [], stats: {}, columns: {}, error: "No valid tabs" };
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
      ensureIndex: (...args) => this._ensureIndex(...args),
      lmPreviewCache: this._lmPreviewCache,
    };
    return _fn(metas, options, ctx);
  }

  /**
   * Preview for multi-source lateral movement — event counts per tab.
   */
  previewMultiSourceLateralMovement(tabIds, options = {}) {
    const { previewMultiSourceLateralMovement: _fn } = require("./analyzers/lateral-movement/multi-source");
    const tabLabels = options._tabLabels || {};
    const metas = tabIds.map(id => {
      const meta = this.databases.get(id);
      if (!meta) return null;
      const label = tabLabels[id] || id;
      return { meta, tabId: id, label };
    }).filter(Boolean);
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
    };
    return _fn(metas, options, ctx);
  }

  /**
   * Lightweight persistence preview — event counts + column quality for the config screen
   */
  previewPersistenceAnalysis(tabId, options = {}) {
    const { previewPersistenceAnalysis: _preview } = require("./analyzers/persistence");
    const meta = this.databases.get(tabId);
    if (!meta) return { eventCounts: {}, columnQuality: {}, error: "No database" };
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
    };
    return _preview(meta, options, ctx);
  }

  /**
   * Persistence Analyzer — scans EVTX or registry data for persistence mechanisms
   */
  getPersistenceAnalysis(tabId, options = {}) {
    const { getPersistenceAnalysis: _analyze } = require("./analyzers/persistence");
    const meta = this.databases.get(tabId);
    if (!meta) return { items: [], stats: {}, error: "Tab not found" };
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
    };
    return _analyze(meta, options, ctx);
  }

  /**
   * Multi-source persistence — merges EVTX + registry evidence from several tabs so a
   * finding in one file can be corroborated by events in another (a 7045 in System.evtx
   * against 4688 in Security.evtx and 4104 in PowerShell%4Operational.evtx).
   */
  getMultiSourcePersistence(tabIds, options = {}) {
    const { getMultiSourcePersistence: _fn } = require("./analyzers/persistence/multi-source");
    const metas = this._persistenceMetas(tabIds, options);
    if (metas.length === 0) return { items: [], incidents: [], warnings: [], stats: {}, error: "No valid tabs" };
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
      ensureIndex: (...args) => this._ensureIndex(...args),
    };
    return _fn(metas, options, ctx);
  }

  /**
   * Preview for multi-source persistence — what each selected tab contributes.
   */
  previewMultiSourcePersistence(tabIds, options = {}) {
    const { previewMultiSourcePersistence: _fn } = require("./analyzers/persistence/multi-source");
    const metas = this._persistenceMetas(tabIds, options);
    if (metas.length === 0) return { tabs: [], totalEvents: 0, error: "No valid tabs" };
    const ctx = {
      applyStandardFilters: (...args) => this._applyStandardFilters(...args),
    };
    return _fn(metas, options, ctx);
  }

  /**
   * Persistence ⇄ lateral movement join. Runs both analyses over the same tabs and returns
   * lateral movement's graph with each node annotated by what persistence found there, plus
   * the pivot edges persistence can prove (a logon that LEFT something behind).
   */
  getPersistencePivotJoin(tabIds, options = {}) {
    const { joinPersistenceToLateralMovement } = require("./analyzers/persistence/lm-handoff");
    const ids = Array.isArray(tabIds) ? tabIds : [tabIds].filter(Boolean);
    if (ids.length === 0) return { nodes: [], pivotEdges: [], byHost: {}, stats: {}, error: "No tabs selected" };

    const persistence = ids.length > 1
      ? this.getMultiSourcePersistence(ids, options)
      : this.getPersistenceAnalysis(ids[0], options);
    if (persistence?.error) return { nodes: [], pivotEdges: [], byHost: {}, stats: {}, error: persistence.error };

    let lateral = null;
    try {
      lateral = ids.length > 1
        ? this.getMultiSourceLateralMovement(ids, options)
        : this.getLateralMovement(ids[0], options);
    } catch (err) {
      lateral = { nodes: [], edges: [], error: err.message };
    }

    const joined = joinPersistenceToLateralMovement(lateral || {}, persistence);
    return {
      ...joined,
      // A lateral-movement failure must not hide the persistence half: the per-host rollup
      // and pivot edges are derived from persistence alone and stay valid without a graph.
      lateralMovementError: lateral?.error || null,
      persistenceStats: persistence.stats || {},
      error: null,
    };
  }

  _persistenceMetas(tabIds, options = {}) {
    const tabLabels = options._tabLabels || {};
    return (tabIds || []).map((id) => {
      const meta = this.databases.get(id);
      if (!meta) return null;
      return { meta, tabId: id, label: tabLabels[id] || id };
    }).filter(Boolean);
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
    // Signal async builders (FTS/index) to stop — they check this flag
    meta.closed = true;
    // Remove from map so concurrent async operations bail out on databases.has() check
    this.databases.delete(tabId);
    // Purge caches for this tab
    if (this._countCache) this._countCache.delete(tabId);
    if (this._filterCache) this._filterCache.delete(tabId);
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
  async mergeTabs(mergedTabId, sources, onProgress) {
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

    // createTab now sizes the write cache from _fileSizeHint, which the merge path never sets
    // (it streams from sibling DBs, not a file) — so without this it would pin to the 16MB floor
    // and a multi-million-row merge would flush dirty pages far too often (journal_mode=OFF here).
    // Size a transient bulk cache by the merged row volume (~200 B/row est.), floored 64MB / capped
    // 1GB; finalizeImport restores the conservative query cache after the inserts.
    const mergeCacheKiB = Math.min(1048576, Math.max(65536, Math.ceil((totalRows * 200) / 1024 * 1.5)));
    mergedMeta.db.pragma(`cache_size = ${-mergeCacheKiB}`); // negative = KiB

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

      // Build SELECT for source — read all columns from source DB.
      // Page through the source by rowid (keyset pagination) rather than holding one
      // .iterate() cursor open for the whole table: this keeps each read fully consumed
      // before its insert, so we can yield to the event loop between pages. The merge runs
      // on the main process, and a synchronous multi-million-row copy blocks the event
      // loop long enough that macOS flags the app "not responding" and the user force-quits.
      const srcCols = srcMeta.safeCols.map((c) => c.safe).join(", ");
      const selectPage = srcMeta.db.prepare(
        `SELECT rowid AS _mrid, ${srcCols} FROM data WHERE rowid > ? ORDER BY rowid LIMIT ?`
      );

      let lastRowid = 0;
      for (;;) {
        const page = selectPage.all(lastRowid, MERGE_BATCH);
        if (page.length === 0) break;

        const batch = new Array(page.length);
        for (let r = 0; r < page.length; r++) {
          const srcRow = page[r];
          lastRowid = srcRow._mrid;
          const values = new Array(colCount);
          values[0] = src.tabName; // _Source
          values[1] = tsSafeCol ? (srcRow[tsSafeCol] || "") : ""; // datetime
          for (let i = 2; i < colCount; i++) {
            const sc = srcSelectCols[i];
            values[i] = sc ? (srcRow[sc] || "") : "";
          }
          batch[r] = values;
        }

        this.insertBatchArrays(mergedTabId, batch);
        totalInserted += batch.length;
        if (onProgress) onProgress({ phase: "copying", current: totalInserted, total: totalRows, sourceName: src.tabName });

        // Yield so the event loop can service IPC / paint a progress frame before the next
        // batch — keeps the window responsive during long merges.
        await new Promise((resolve) => setImmediate(resolve));
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

  // ── Delegated analyzers (extracted to electron/analyzers/) ────────

  scanRansomwareExtensions(tabId, progressCb) {
    const analyzers = require("./analyzers");
    return analyzers.scanRansomwareExtensions(this.databases.get(tabId), progressCb);
  }

  analyzeRansomware(tabId, opts) {
    const analyzers = require("./analyzers");
    // Resolve usnTabId to meta before delegating
    const meta = this.databases.get(tabId);
    if (opts && opts.usnTabId) {
      opts = { ...opts, usnMeta: this.databases.get(opts.usnTabId) };
    }
    if (opts && opts.evtxTabId) {
      opts = { ...opts, evtxMeta: this.databases.get(opts.evtxTabId) };
    }
    return analyzers.analyzeRansomware(meta, opts);
  }

  detectTimestomping(tabId, opts) {
    const analyzers = require("./analyzers");
    let o = { ...(opts || {}) };
    // Resolve companion tab IDs to metas before delegating (Tier 2 cross-artifact corroboration —
    // mirrors analyzeADS / getFileActivityHeatmap).
    if (o.usnTabId) o = { ...o, usnMeta: this.databases.get(o.usnTabId) };
    if (o.evtxTabId) o = { ...o, evtxMeta: this.databases.get(o.evtxTabId) };
    return analyzers.detectTimestomping(this.databases.get(tabId), o);
  }

  getFileActivityHeatmap(tabId, opts) {
    const analyzers = require("./analyzers");
    // Back-compat: a bare function 2nd arg is the legacy progressCb.
    let o = typeof opts === "function" ? { progressCb: opts } : (opts || {});
    // Resolve companion tab IDs to metas before delegating (mirrors analyzeRansomware).
    if (o.usnTabId) o = { ...o, usnMeta: this.databases.get(o.usnTabId) };
    if (o.evtxTabId) o = { ...o, evtxMeta: this.databases.get(o.evtxTabId) };
    return analyzers.getFileActivityHeatmap(this.databases.get(tabId), o);
  }

  analyzeADS(tabId, opts) {
    const analyzers = require("./analyzers");
    let o = typeof opts === "function" ? { progressCb: opts } : (opts || {});
    if (o.usnTabId) o = { ...o, usnMeta: this.databases.get(o.usnTabId) };
    if (o.evtxTabId) o = { ...o, evtxMeta: this.databases.get(o.evtxTabId) };
    return analyzers.analyzeADS(this.databases.get(tabId), o);
  }

  analyzeUsnJournal(tabId, opts) {
    const analyzers = require("./analyzers");
    const getDatabaseMeta = (id) => this.databases.get(id);
    return analyzers.analyzeUsnJournal(this.databases.get(tabId), opts, getDatabaseMeta);
  }

  analyzeAiHistory(tabId, opts) {
    const analyzers = require("./analyzers");
    const o = typeof opts === "function" ? { progressCb: opts } : (opts || {});
    return analyzers.analyzeAiHistory(this.databases.get(tabId), o);
  }

  resolveUsnPaths(tabId, mftTabId) {
    const analyzers = require("./analyzers");
    const getDatabaseMeta = (id) => this.databases.get(id);
    return analyzers.resolveUsnPaths(this.databases.get(tabId), mftTabId, getDatabaseMeta);
  }


  /**
   * Close all databases
   */
  closeAll() {
    if (this._walInterval) { clearInterval(this._walInterval); this._walInterval = null; }
    for (const tabId of this.databases.keys()) {
      this.closeTab(tabId);
    }
  }
}

function applyMixin(target, source) {
  for (const name of Object.getOwnPropertyNames(source)) {
    if (name === "constructor") continue;
    Object.defineProperty(target, name, Object.getOwnPropertyDescriptor(source, name));
  }
}

applyMixin(TimelineDB.prototype, require("./db/query-store"));
applyMixin(TimelineDB.prototype, require("./db/tag-store"));
applyMixin(TimelineDB.prototype, require("./db/timeline-analytics"));
TimelineDB.prototype.diffTabs = require("./db/diff-tabs").diffTabs;

module.exports = TimelineDB;
