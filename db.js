/**
 * db.js — SQLite-backed data engine for Timeline Explorer
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

class TimelineDB {
  constructor() {
    this.databases = new Map(); // tabId -> { db, dbPath, headers, rowCount, tsColumns }
  }

  /**
   * Create a new database for a tab and prepare the schema
   */
  createTab(tabId, headers) {
    const dbPath = path.join(
      os.tmpdir(),
      `tle_${tabId}_${crypto.randomBytes(4).toString("hex")}.db`
    );

    const db = new Database(dbPath);

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

    // page_size MUST be set before any tables are created
    db.pragma("page_size = 32768");

    // Performance pragmas for bulk import
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = OFF");
    db.pragma("cache_size = -512000"); // 500MB cache
    db.pragma("temp_store = MEMORY");
    db.pragma("mmap_size = 2147483648"); // 2GB mmap
    db.pragma("locking_mode = EXCLUSIVE"); // single-user, avoid lock overhead
    db.pragma("wal_autocheckpoint = 0"); // disable auto-checkpoint during import

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
    // SQLite limit is 32766 host parameters — size batch to stay under that
    const multiRowCount = Math.max(1, Math.min(1000, Math.floor(32000 / safeCols.length)));
    let multiInsertStmt = null;
    if (multiRowCount > 1) {
      const singleRow = `(${placeholders})`;
      const multiValues = Array(multiRowCount).fill(singleRow).join(",");
      multiInsertStmt = db.prepare(
        `INSERT INTO data (${colList}) VALUES ${multiValues}`
      );
    }

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
      colMap: Object.fromEntries(safeCols.map((c) => [c.original, c.safe])),
      reverseColMap: Object.fromEntries(safeCols.map((c) => [c.safe, c.original])),
    };

    this.databases.set(tabId, meta);
    return { tabId, headers, tsColumns: [...tsColumns] };
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

    const tx = meta.db.transaction(() => {
      let i = 0;

      if (multiStmt && multiN > 1) {
        // Pre-allocate flat params array — reused every iteration
        const flat = new Array(multiN * colCount);

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
   * Finalize import: detect column types (indexes + FTS deferred to first use)
   */
  finalizeImport(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return;

    const db = meta.db;

    // FTS index is built lazily on first search — skip here for fast import.
    meta.ftsReady = false;

    // Sort indexes are built lazily on first sort — skip here for fast import.
    meta.indexedCols = new Set();

    // Detect numeric columns (fast — only samples 100 rows)
    const sampleRows = db
      .prepare(
        `SELECT ${meta.safeCols.map((c) => c.safe).join(", ")} FROM data LIMIT 100`
      )
      .all();

    meta.numericColumns = new Set();
    meta.safeCols.forEach((col) => {
      const values = sampleRows
        .map((r) => r[col.safe])
        .filter((v) => v && v.trim());
      if (values.length > 0) {
        const numCount = values.filter((v) => !isNaN(parseFloat(v))).length;
        if (numCount / values.length > 0.8) {
          meta.numericColumns.add(col.original);
        }
      }
    });

    // Switch to normal sync mode for querying
    db.pragma("synchronous = NORMAL");
    db.pragma("wal_autocheckpoint = 5000"); // re-enable auto-checkpoint (larger = fewer interrupts during queries)
    db.pragma("wal_checkpoint(TRUNCATE)"); // flush WAL to main DB

    // Pre-build indexes on timestamp columns (used by sort, date range filters, gap analysis)
    for (const tsCol of meta.tsColumns) {
      const safeCol = meta.colMap[tsCol];
      if (safeCol && !meta.indexedCols.has(safeCol)) {
        try {
          db.exec(`CREATE INDEX IF NOT EXISTS idx_${safeCol} ON data(${safeCol})`);
          meta.indexedCols.add(safeCol);
        } catch (e) { /* ignore */ }
      }
    }

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
    const CHUNK = 100000; // 100k rows per chunk — ~200-500ms each
    let lastRowid = 0;

    return new Promise((resolve) => {
      const insertChunk = () => {
        // Tab may have been closed while building
        if (!this.databases.has(tabId)) { resolve(); return; }

        const inserted = db.prepare(
          `INSERT INTO data_fts(rowid, ${colList}) SELECT rowid, ${colList} FROM data WHERE rowid > ? ORDER BY rowid LIMIT ?`
        ).run(lastRowid, CHUNK);

        lastRowid += CHUNK;
        const indexed = Math.min(lastRowid, totalRows);

        if (onProgress) onProgress({ indexed, total: totalRows, done: false });

        if (inserted.changes < CHUNK) {
          // All rows indexed — optimize and finalize
          try { db.exec(`INSERT INTO data_fts(data_fts) VALUES('optimize')`); } catch (e) { /* ignore */ }
          meta.ftsReady = true;
          meta.ftsBuilding = false;
          if (onProgress) onProgress({ indexed: totalRows, total: totalRows, done: true });
          resolve();
        } else {
          // Yield to event loop before next chunk
          setImmediate(insertChunk);
        }
      };

      insertChunk();
    });
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
        // If numeric or timestamp, cast for proper sorting
        if (meta.numericColumns.has(sortCol)) {
          orderClause = `ORDER BY CAST(${safeCol} AS REAL) ${dir}`;
        } else if (meta.tsColumns.has(sortCol)) {
          orderClause = `ORDER BY ${safeCol} ${dir}`;
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

    // Get bookmark + tag data for fetched rows in single passes
    const rowIds = rawRows.map((r) => r._rowid);
    const bookmarkedSet = new Set();
    const rowTags = {};
    if (rowIds.length > 0) {
      const placeholders = rowIds.map(() => "?").join(",");
      const bm = db.prepare(`SELECT rowid FROM bookmarks WHERE rowid IN (${placeholders})`).all(...rowIds);
      for (const b of bm) bookmarkedSet.add(b.rowid);
      const tags = db.prepare(`SELECT rowid, tag FROM tags WHERE rowid IN (${placeholders})`).all(...rowIds);
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
    if (!meta) return;
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
    if (!meta) return;
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
    if (!meta) return;
    meta.db.prepare("INSERT OR IGNORE INTO tags (rowid, tag) VALUES (?, ?)").run(rowId, tag);
  }

  removeTag(tabId, rowId, tag) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
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
        orderClause = `ORDER BY ${safeCol} ${dir}`;
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
          `SELECT MIN(${safeCol}) as earliest, MAX(${safeCol}) as latest FROM data ${neWhere}`
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
    const sql = `SELECT substr(${safeCol}, 1, 10) as day, COUNT(*) as cnt FROM data ${whereClause} GROUP BY day HAVING day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' ORDER BY day`;
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
    const sql = `SELECT substr(${safeCol}, 1, 16) as mb, COUNT(*) as cnt FROM data ${whereClause} GROUP BY mb HAVING mb GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]' ORDER BY mb`;
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
      const sql = `SELECT substr(${safeCol}, 1, 16) as mb, COUNT(*) as cnt FROM data ${whereClause} GROUP BY mb HAVING mb GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]' ORDER BY mb`;
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
   * Close a tab and clean up its database
   */
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
