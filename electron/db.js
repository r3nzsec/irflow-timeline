/**
 * db.js — DuckDB-backed data engine for IRFlow Timeline
 *
 * Tabs are stored and queried with DuckDB (see electron/db/duckdb/). Rows are bulk-loaded with
 * DuckDB's appender, there are no column or FTS5 indexes (DuckDB scans columns in parallel),
 * and the background "index" build stores each timestamp column's sort key instead.
 *
 * Architecture:
 *   1. Streaming import: CSV/XLSX rows are appended in batches
 *   2. SQL-based filtering, sorting, pagination (only visible rows in memory)
 *   3. Column metadata, stats, and type detection stored alongside data
 *   4. Temp database files auto-cleaned on close
 *
 * This enables handling 30-50GB+ files because:
 *   - Rows stream from disk → DuckDB (never all in JS heap)
 *   - Queries use LIMIT/OFFSET (only ~10k rows in memory at once)
 *   - DuckDB's columnar, multi-threaded scans handle search, sorting and aggregation
 */

const Database = require("./db/duckdb");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");

// ── Debug trace logger (shared singleton — see logger.js) ─────────
const { dbg } = require("./logger");
const { registerRuntimeFunctions } = require("./db/runtime-functions");
const { safeRegexTester } = require("./utils/safe-regex");
const { regexCondition } = require("./db/sql-match");

// Suffix of the column that stores sort_datetime(<col>) once the background build has run.
const SORT_KEY_SUFFIX = "__sdt";

/**
 * Attach the tab's write statements to `meta` as memoized lazy properties.
 *
 * Each one compiles on first access and then replaces itself with a plain data property,
 * so callers keep using `meta.bmInsertStmt` / `meta.tagInsertStmt` unchanged and a tab that
 * only ever reads never compiles them at all. Properties stay writable and configurable
 * so tests can substitute stubs.
 */
function lazyWriteStatements(meta) {
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

  // Rows go in through DuckDB's appender (insertBatchArrays), not prepared INSERTs.
  define("bmCheckStmt", () => meta.db.prepare("SELECT rowid FROM bookmarks WHERE rowid = ?"));
  define("bmInsertStmt", () => meta.db.prepare("INSERT OR IGNORE INTO bookmarks (rowid) VALUES (?)"));
  define("bmDeleteStmt", () => meta.db.prepare("DELETE FROM bookmarks WHERE rowid = ?"));
  define("bmCountStmt", () => meta.db.prepare("SELECT COUNT(*) as cnt FROM bookmarks"));
  define("tagInsertStmt", () => meta.db.prepare("INSERT OR IGNORE INTO tags (rowid, tag) VALUES (?, ?)"));
  define("tagDeleteStmt", () => meta.db.prepare("DELETE FROM tags WHERE rowid = ? AND tag = ?"));
  return meta;
}

/** Column names that hold stored sort keys (e.g. c3__sdt → c3). */
function sortKeyColsFromTable(db) {
  try {
    return db.pragma("table_info(data)")
      .map((c) => c.name)
      .filter((n) => n.endsWith(SORT_KEY_SUFFIX))
      .map((n) => n.slice(0, -SORT_KEY_SUFFIX.length));
  } catch {
    return [];
  }
}

/** Let the tab's SQL read stored sort keys instead of calling sort_datetime() per row. */
function applySortKeys(meta) {
  const map = new Map();
  for (const safe of meta.sortKeyCols || []) map.set(safe, `${safe}${SORT_KEY_SUFFIX}`);
  meta.db.setComputedColumns("sort_datetime", map);
}

class TimelineDB {
  constructor() {
    this.databases = new Map(); // tabId -> { db, dbPath, headers, rowCount, tsColumns }
    // DuckDB checkpoints its own WAL; nothing to schedule here.
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

    // DuckDB sizes its own memory and threads (electron/db/duckdb/host.js); the file size
    // only decides which background work is worth doing.
    const fileSize = this._fileSizeHint || 0;
    const isLargeFile = fileSize > 5 * 1024 * 1024 * 1024; // >5GB
    this._fileSizeHint = 0; // consume the hint


    // Sanitize headers for SQL column names
    const safeCols = headers.map((h, i) => ({
      original: h,
      safe: `c${i}`,
    }));

    // Create main data table. rowid is an ordinary column numbered by insertBatchArrays
    // (1, 2, 3, … in import order, like SQLite's implicit rowid); no primary key, because
    // DuckDB's zone maps already find rowid ranges and a key index would slow the load.
    const colDefs = safeCols.map((c) => `${c.safe} VARCHAR`).join(", ");
    db.exec(`CREATE TABLE data (rowid BIGINT${colDefs ? ", " + colDefs : ""})`);

    // Create bookmarks table
    db.exec(`CREATE TABLE bookmarks (rowid BIGINT PRIMARY KEY)`);

    // Create tags table
    db.exec(`CREATE TABLE tags (rowid BIGINT, tag VARCHAR, PRIMARY KEY(rowid, tag))`);

    // Create color rules table
    db.exec(`CREATE SEQUENCE color_rules_id_seq START 1`);
    db.exec(
      `CREATE TABLE color_rules (
        id BIGINT PRIMARY KEY DEFAULT nextval('color_rules_id_seq'),
        col_name VARCHAR, condition VARCHAR, value VARCHAR,
        bg_color VARCHAR, fg_color VARCHAR
      )`
    );

    // Detect timestamp columns based on header names.
    // Exclude duration fields and timestamp metadata such as basis, precision, offset, and zone.
    const tsColumns = new Set();
    headers.forEach((h) => {
      if (
        /(time|date|timestamp|created|modified|accessed|when|start|end|written)/i.test(h) &&
        !/elapsed|duration|basis|precision|offset|timezone/i.test(h)
      ) {
        tsColumns.add(h);
      }
    });

    const meta = {
      tabId,
      db,
      dbPath,
      headers,
      safeCols,
      tsColumns,
      numericColumns: new Set(),
      indexedCols: new Set(),
      sortKeyCols: new Set(),
      rowCount: 0,
      ftsReady: false,
      isLargeFile,
      colMap: Object.fromEntries(safeCols.map((c) => [c.original, c.safe])),
      reverseColMap: Object.fromEntries(safeCols.map((c) => [c.safe, c.original])),
    };

    lazyWriteStatements(meta);
    applySortKeys(meta);
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
   * Rows are numbered rowid = 1, 2, 3, … across batches and handed to DuckDB's appender,
   * which loads them without parsing any SQL, on the DuckDB thread while the parser
   * reads the next batch.
   */
  insertBatchArrays(tabId, rows) {
    const meta = this.databases.get(tabId);
    if (!meta) throw new Error(`Tab ${tabId} not found`);
    if (!rows || rows.length === 0) return meta.rowCount;

    meta.db.appendRows("data", rows, { firstRowid: meta.rowCount + 1 });

    meta.rowCount += rows.length;
    return meta.rowCount;
  }

  /**
   * Insert a batch of rows as objects (legacy — used by session restore)
   */
  insertBatch(tabId, rows) {
    const meta = this.databases.get(tabId);
    if (!meta) throw new Error(`Tab ${tabId} not found`);
    const hdrs = meta.headers;
    const arrays = new Array(rows.length);
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const values = new Array(hdrs.length);
      for (let c = 0; c < hdrs.length; c++) values[c] = row[hdrs[c]] ?? "";
      arrays[i] = values;
    }
    return this.insertBatchArrays(tabId, arrays);
  }

  /**
   * Finalize import: detect column types, switch to query mode.
   * The timestamp sort keys are stored later by a background build (buildIndexesAsync)
   * so the UI becomes interactive immediately after import completes.
   */
  finalizeImport(tabId, _options = {}) {
    dbg("DB", `finalizeImport start`, { tabId });
    const meta = this.databases.get(tabId);
    if (!meta) { dbg("DB", `finalizeImport: no meta for tab`); return; }

    const db = meta.db;

    // Wait for the batches still loading on the DuckDB thread (and surface a failed one)
    // before the type detection below reads the rows.
    db.flush();

    // No full-text index: search scans the columns (query-store _applySearch).
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

    // Write the appended rows into the database file so the next thread to open it
    // starts from a compact file rather than replaying the WAL.
    try { db.checkpoint(); } catch (e) { dbg("DB", `checkpoint after import failed`, { tabId, error: e.message }); }

    return {
      rowCount: meta.rowCount,
      headers: meta.headers,
      tsColumns: [...meta.tsColumns],
      numericColumns: [...meta.numericColumns],
    };
  }

  /**
   * Re-open a tab database created by an import worker. The worker owns parsing
   * and finalization; the main process adopts the completed database file here so
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

    const safeCols = headers.map((h, i) => ({ original: h, safe: `c${i}` }));

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
      ftsCreated: !!ftsCreated,
      ftsBuilding: false,
      indexesReady: !!indexesReady,
      indexesBuilding: false,
      indexedCols: new Set(indexedCols),
      // Read from the file, not the descriptor: another thread may have stored them since.
      sortKeyCols: new Set(sortKeyColsFromTable(db)),
      isLargeFile: !!isLargeFile,
      colMap: Object.fromEntries(safeCols.map((c) => [c.original, c.safe])),
      reverseColMap: Object.fromEntries(safeCols.map((c) => [c.safe, c.original])),
    };

    // Write statements are prepared on first use, not on adopt. Adoption is not only the
    // main process taking over an imported tab — every scroll-window query spawns a
    // worker that adopts the same tab, runs one SELECT, and exits, and preparing the
    // bookmark/tag statements there would only add latency to every fetch.
    lazyWriteStatements(meta);
    applySortKeys(meta);

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
      sortKeyCols: [...(meta.sortKeyCols || [])],
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
    if (Array.isArray(result.sortKeyCols)) {
      meta.sortKeyCols = new Set(result.sortKeyCols);
      applySortKeys(meta);
    }
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
   * after handing an imported database file back to the main process.
   */
  releaseTab(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    this.databases.delete(tabId);
    try { meta.db.close(); } catch {}
  }

  /**
   * Called by query-store before it sorts on a column. SQLite needed a B-tree index here;
   * DuckDB sorts without one, so this only records that the column has been used.
   */
  _ensureIndex(tabId, colName) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    const safeCol = meta.colMap[colName];
    if (safeCol) meta.indexedCols.add(safeCol);
  }

  /**
   * There is no full-text index any more: search scans the columns with ILIKE
   * (query-store _applySearch), which DuckDB runs in parallel over the column data.
   */
  _ensureFts(_tabId) {}

  buildFtsAsync(_tabId, _onProgress) {
    return Promise.resolve({ skipped: true });
  }

  /**
   * Store sort_datetime(col) for every timestamp column in a hidden `<col>__sdt` column,
   * in the background after import (this is the old index-build step and keeps its
   * progress events). sort_datetime() is JavaScript for zoned and non-ISO timestamps
   * (Hayabusa's "+09:00", Plaso, US-style dates), so without the stored key every sort or
   * time-range filter on such a column would run it over every row again. Once a column
   * is done, the tab's SQL reads the stored key instead (applySortKeys).
   *
   * @param {string} tabId
   * @param {Function} onProgress - ({ built, total, done, currentCol }) callback per column
   * @returns {Promise<object>}
   */
  buildIndexesAsync(tabId, onProgress) {
    const meta = this.databases.get(tabId);
    if (!meta || meta.indexesReady || meta.indexesBuilding) return Promise.resolve({ skipped: true });
    meta.indexesBuilding = true;

    const cols = meta.safeCols.filter((c) => meta.tsColumns.has(c.original) && !meta.sortKeyCols.has(c.safe));
    const total = cols.length;
    let built = 0;
    const snapshot = () => ({ indexedCols: [...meta.indexedCols], sortKeyCols: [...meta.sortKeyCols] });

    dbg("DB", `buildIndexesAsync start`, { tabId, total });
    if (onProgress) onProgress({ built: 0, total, done: false, currentCol: cols[0]?.original });

    return new Promise((resolve) => {
      const buildNext = () => {
        // Tab may have been closed while building — check both map and flag
        if (meta.closed || !this.databases.has(tabId)) {
          meta.indexesBuilding = false;
          resolve({ cancelled: true, ...snapshot() });
          return;
        }

        if (built >= total) {
          try { meta.db.checkpoint(); } catch (e) { dbg("DB", `checkpoint after sort keys failed`, { tabId, error: e.message }); }
          // query-store samples the value lists of "unindexed" columns on very large tabs
          // until this build is done; afterwards DuckDB groups whole columns cheaply.
          for (const c of meta.safeCols) meta.indexedCols.add(c.safe);
          meta.indexesReady = true;
          meta.indexesBuilding = false;
          dbg("DB", `buildIndexesAsync complete`, { tabId, total });
          if (onProgress) onProgress({ built: total, total, done: true, currentCol: null });
          resolve({ built: total, total, done: true, ...snapshot(), skippedCols: [] });
          return;
        }

        const col = cols[built];
        try {
          this._storeSortKey(meta, col.safe);
        } catch (e) {
          // A full disk or I/O error will not recover on the next column; stop and report.
          if (/disk|no space|I\/O|out of memory/i.test(e?.message || "")) {
            dbg("DB", `buildIndexesAsync failed`, { tabId, error: e.message });
            meta.indexesBuilding = false;
            resolve({ error: e.message, ...snapshot() });
            return;
          }
          dbg("DB", `sort key failed for ${col.original}`, { error: e.message });
        }
        built++;
        if (onProgress) onProgress({ built, total, done: false, currentCol: col.original });
        setImmediate(buildNext);
      };

      // Defer the first column — let the UI render the overlay first
      setImmediate(buildNext);
    });
  }

  /** Fill `<safe>__sdt` with sort_datetime(<safe>), a million rows per transaction. */
  _storeSortKey(meta, safe) {
    const key = `${safe}${SORT_KEY_SUFFIX}`;
    // Another thread may be writing this table (USN path resolution); DuckDB reports a
    // conflict rather than waiting, so retry the schema change briefly.
    for (let attempt = 0; ; attempt++) {
      try {
        meta.db.exec(`ALTER TABLE data ADD COLUMN IF NOT EXISTS ${key} VARCHAR`);
        break;
      } catch (e) {
        if (attempt >= 20 || !/conflict/i.test(e?.message || "")) throw e;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
      }
    }
    const maxRow = meta.db.prepare("SELECT COALESCE(MAX(rowid), 0) AS m FROM data").get().m;
    const STEP = 1000000;
    const update = meta.db.prepare(`UPDATE data SET ${key} = sort_datetime(${safe}) WHERE rowid > ? AND rowid <= ?`);
    for (let lo = 0; lo < maxRow; lo += STEP) {
      if (meta.closed) throw new Error("Tab closed");
      update.run(lo, lo + STEP);
    }
    meta.sortKeyCols.add(safe);
    applySortKeys(meta);
  }

  /**
   * Check if background builds (indexes/FTS) are running on a tab.
   *
   * NOTE: this must NOT be used to block bookmark/tag writes. The build only
   * touches `data` — a write to the tiny `tags`/`bookmarks` tables meanwhile is safe. Gating on it silently discarded everything
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

    // Phase 1: batched regexp alternation scan for matching rowIds
    // Concatenate columns with COALESCE/|| in SQL so regexp() is called once per row
    // instead of once per column×row — reduces function calls by ~Nx for N columns
    const concatExpr = colList.map((c) => `COALESCE(${c},'')`).join(" || ' ' || ");
    const matchedSet = new Set();
    for (let i = 0; i < iocPatterns.length; i += batchSize) {
      const batch = iocPatterns.slice(i, i + batchSize);
      const altPattern = batch.join("|");
      const cond = regexCondition(db, `(${concatExpr})`, altPattern);
      const rows = db.prepare(`SELECT rowid FROM data WHERE ${cond.sql}`).all(...cond.params);
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
      meta.db.close();
    } catch (e) {}
    try {
      fs.unlinkSync(meta.dbPath);
    } catch (e) {}
    // DuckDB's write-ahead log, plus SQLite's WAL/SHM names in case an old temp file is around
    for (const suffix of [".wal", "-wal", "-shm"]) {
      try { fs.unlinkSync(meta.dbPath + suffix); } catch (e) {}
    }
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
