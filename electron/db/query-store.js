const { dbg } = require("../logger");
const { normalizeTimestamp } = require("../utils/forensic-normalize");
const { AI_HISTORY_TOOLS } = require("../parsers/ai-history/schema");

/** Max rows scanned for checkbox filter values on large, non-indexed columns. */
const LARGE_FILE_UNIQUE_SAMPLE_ROWS = 500_000;
/** Row-count floor before sampling kicks in (below this, full GROUP BY is fine). */
const LARGE_FILE_UNIQUE_SAMPLE_MIN_ROWS = 250_000;
/** Bound-parameter IN lists stay under SQLite's variable cap (~32k). */
const BIND_IN_MAX = 500;
/** Chunk size for inlined IN lists when the value set is too large to bind. */
const SQL_IN_CHUNK = 400;

function sqlQuote(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function sqlInPredicate(expr, values) {
  const chunks = [];
  for (let i = 0; i < values.length; i += SQL_IN_CHUNK) {
    const slice = values.slice(i, i + SQL_IN_CHUNK);
    chunks.push(`${expr} IN (${slice.map(sqlQuote).join(",")})`);
  }
  if (chunks.length === 0) return "0";
  return chunks.length === 1 ? chunks[0] : `(${chunks.join(" OR ")})`;
}
const AI_HISTORY_TOOL_LABELS = [...new Set(Object.values(AI_HISTORY_TOOLS).map((t) => t.label))];
const AI_HISTORY_TOOL_LABEL_SQL = AI_HISTORY_TOOL_LABELS
  .map((v) => `'${String(v).replace(/'/g, "''")}'`)
  .join(", ");

function looksLikeAiHistoryMeta(meta) {
  const cm = meta?.colMap || {};
  return Boolean((cm.InvokedTool || cm.ToolName) && cm.Tool && cm.RecordType && cm.Summary && cm.SessionId);
}

function normalizedColumnExpr(meta, colName) {
  const safeCol = meta?.colMap?.[colName];
  if (!safeCol) return null;
  const isInvokedToolCol = colName === "InvokedTool" || colName === "ToolName";
  if (!isInvokedToolCol || !looksLikeAiHistoryMeta(meta) || !meta.colMap.Tool) return safeCol;
  const toolCol = meta.colMap.Tool;
  return `CASE WHEN TRIM(COALESCE(${safeCol}, '')) = TRIM(COALESCE(${toolCol}, '')) `
    + `AND TRIM(COALESCE(${toolCol}, '')) IN (${AI_HISTORY_TOOL_LABEL_SQL}) `
    + `THEN '' ELSE ${safeCol} END`;
}

/**
 * Characters SQLite should treat as blank padding. Bare TRIM() strips spaces only, so a
 * tab- or newline-only cell would survive as its own value — rendering blank in the grid
 * and as a second blank-looking row in the filter list. This set mirrors what JS .trim()
 * removes on the renderer side, so both ends of the filter agree on what "empty" means.
 */
const SQL_BLANK_CHARS = "char(32)||char(9)||char(10)||char(13)||char(11)||char(12)||char(160)";

/**
 * SQL predicate for "this cell reads as empty".
 *
 * NULL, the empty string and whitespace-only all render as a blank cell, so the value list
 * and the filter that consumes it have to agree they are one bucket. When they disagreed,
 * GROUP BY produced a separate row per representation — the dropdown showed two entries
 * both labelled "(empty)", and unchecking the one you could see left the other's rows on
 * screen. Whitespace-only was worse still: it grouped under a label that rendered blank but
 * was not "(empty)", so it stayed selected and looked like the filter had been ignored.
 */
function emptyValuePredicate(expr) {
  return `TRIM(COALESCE(${expr}, ''), ${SQL_BLANK_CHARS}) = ''`;
}

/**
 * The same rule as a value expression: every empty-reading cell collapses to '' so they
 * group as a single "(empty)" entry that the checkbox filter can actually act on.
 */
function emptyBucketedExpr(expr) {
  return `CASE WHEN ${emptyValuePredicate(expr)} THEN '' ELSE ${expr} END`;
}

function truncateRowStrings(row, truncateColumns) {
  for (const [col, maxLen] of Object.entries(truncateColumns)) {
    const v = row[col];
    if (typeof v !== "string" || v.length <= maxLen) continue;
    row[col] = maxLen > 1 ? `${v.slice(0, maxLen - 1)}…` : "";
  }
}

/**
 * Query/filter methods mixed into TimelineDB.
 */
class QueryStoreMethods {
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

    // ── Standard filters (column, checkbox, date range, bookmarks, tags, advanced, search) ──
    this._applyStandardFilters(options, meta, whereConditions, params);

    // ── Group filter (single - legacy) — queryRows-specific ──
    if (groupCol && groupValue !== undefined) {
      const safeCol = meta.colMap[groupCol];
      if (safeCol) {
        const expr = normalizedColumnExpr(meta, groupCol);
        whereConditions.push(`${expr} = ?`);
        params.push(groupValue);
      }
    }

    // ── Multi-level group filters — queryRows-specific ──────
    for (const gf of groupFilters) {
      const safeCol = meta.colMap[gf.col];
      if (safeCol) {
        const expr = normalizedColumnExpr(meta, gf.col);
        whereConditions.push(`${expr} = ?`);
        params.push(gf.value);
      }
    }

    const whereClause =
      whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")}`
        : "";

    // ── Count total filtered rows (cached by filter signature) ──
    const filterSig = whereClause + "|" + JSON.stringify(params);
    let totalFiltered;
    if (meta._countCache && meta._countCache.sig === filterSig) {
      totalFiltered = meta._countCache.cnt;
    } else if (whereClause === "" && Number.isFinite(meta.rowCount)) {
      // No filters → the count is the whole table, already known from import. Skip the
      // full COUNT(*) scan that otherwise freezes the open for 10-40s on a 100M+ row
      // table (the data table is append-only — rows are never deleted — so rowCount holds).
      totalFiltered = meta.rowCount;
      meta._countCache = { sig: filterSig, cnt: totalFiltered };
    } else {
      const countSql = `SELECT COUNT(*) as cnt FROM data ${whereClause}`;
      totalFiltered = db.prepare(countSql).get(...params).cnt;
      meta._countCache = { sig: filterSig, cnt: totalFiltered };
    }

    const orderClause = this._buildOrderClause(meta, tabId, sortCol, sortDir);

    // ── Fetch window ───────────────────────────────────────────
    // Defensive cap: SQLite treats LIMIT -1 (the legacy default) as "no limit", so a
    // missing/invalid limit would stream the entire — possibly 100M-row — result set into
    // memory and OOM the process. Every real caller passes an explicit positive window
    // (including the intentional "load all in group" path), so an explicit non-negative
    // limit is honored as-is; only a missing/invalid one falls back to a bounded default.
    const effectiveLimit = Number.isInteger(limit) && limit >= 0 ? limit : 10000;
    const omitSet = new Set(options.omitHeaders || []);
    const colsForSelect = meta.safeCols.filter((c) => !omitSet.has(c.original));
    const colList = colsForSelect.map((c) => {
      const expr = normalizedColumnExpr(meta, c.original);
      return expr === c.safe ? c.safe : `${expr} AS ${c.safe}`;
    }).join(", ");
    const truncateColumns = options.truncateColumns || null;
    const querySql = `SELECT data.rowid as _rowid, ${colList} FROM data ${whereClause} ${orderClause} LIMIT ? OFFSET ?`;
    const queryParams = [...params, effectiveLimit, offset];

    const rawRows = db.prepare(querySql).all(...queryParams);

    // Map back to original column names — tight loop, no closures
    const colCount = colsForSelect.length;
    const rows = new Array(rawRows.length);
    for (let r = 0; r < rawRows.length; r++) {
      const raw = rawRows[r];
      const row = { __idx: raw._rowid };
      for (let c = 0; c < colCount; c++) {
        row[colsForSelect[c].original] = raw[colsForSelect[c].safe] ?? "";
      }
      for (const h of omitSet) row[h] = "";
      if (truncateColumns) truncateRowStrings(row, truncateColumns);
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
      try {
        const combined = db.prepare(
          `SELECT rowid, 'b' as t, '' as tag FROM bookmarks WHERE rowid IN (${placeholders})` +
          ` UNION ALL SELECT rowid, 't', tag FROM tags WHERE rowid IN (${placeholders})`
        ).all(...batch, ...batch);
        for (const r of combined) {
          if (r.t === "b") bookmarkedSet.add(r.rowid);
          else { if (!rowTags[r.rowid]) rowTags[r.rowid] = []; rowTags[r.rowid].push(r.tag); }
        }
      } catch (e) {
        // Fail gracefully — return rows without bookmark/tag decoration
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
   * Return stable SQLite row IDs for an absolute range in the current filtered
   * and sorted view. This is used by Shift+Click and row navigation so neither
   * workflow is limited to the renderer's 10,000-row cache.
   */
  getRowIdsInRange(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { rowIds: [] };

    const offset = Math.max(0, Number.isSafeInteger(options.offset) ? options.offset : 0);
    const requestedLimit = Number.isSafeInteger(options.limit) ? options.limit : 1;
    const limit = Math.max(0, requestedLimit);
    if (limit === 0) return { rowIds: [] };

    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);
    const whereClause = whereConditions.length > 0
      ? `WHERE ${whereConditions.join(" AND ")}`
      : "";
    const orderExpression = this._buildOrderExpression(
      meta,
      tabId,
      options.sortCol || null,
      options.sortDir || "asc",
    );
    const rows = meta.db.prepare(
      `SELECT data.rowid AS _rowid FROM data ${whereClause} ORDER BY ${orderExpression} LIMIT ? OFFSET ?`
    ).all(...params, limit, offset);
    return { rowIds: rows.map((row) => Number(row._rowid)).filter(Number.isSafeInteger) };
  }

  /**
   * Count how many explicit selected row IDs are still visible under the
   * current filters. The renderer uses this to disclose hidden selections.
   */
  countRowsByIdsMatching(tabId, rowIds, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { matching: 0 };

    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);
    this._applyRowIdFilter(rowIds, whereConditions);
    const whereClause = whereConditions.length > 0
      ? `WHERE ${whereConditions.join(" AND ")}`
      : "";
    const matching = meta.db.prepare(
      `SELECT COUNT(*) AS cnt FROM data ${whereClause}`
    ).get(...params)?.cnt || 0;
    return { matching };
  }

  /**
   * Find the next/previous global-search match in a highlighted (unfiltered)
   * view. SQLite ranks the full filtered result set, so F3 can cross renderer
   * cache boundaries and returns both the absolute row index and match count.
   */
  findSearchMatch(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { index: -1, rowId: null, position: -1, totalMatches: 0 };

    const matchSearchTerm = String(options.matchSearchTerm || "").trim();
    if (!matchSearchTerm) {
      return { index: -1, rowId: null, position: -1, totalMatches: 0 };
    }

    const baseOptions = { ...options, searchTerm: "" };
    const baseParams = [];
    const baseConditions = [];
    this._applyStandardFilters(baseOptions, meta, baseConditions, baseParams);
    const baseWhere = baseConditions.length > 0
      ? `WHERE ${baseConditions.join(" AND ")}`
      : "";

    const matchParams = [];
    const matchConditions = [];
    this._applySearch(
      matchSearchTerm,
      options.matchSearchMode || options.searchMode || "mixed",
      meta,
      matchConditions,
      matchParams,
      options.matchSearchCondition || options.searchCondition || "contains",
    );
    if (matchConditions.length === 0) {
      return { index: -1, rowId: null, position: -1, totalMatches: 0 };
    }

    const orderExpression = this._buildOrderExpression(
      meta,
      tabId,
      options.sortCol || null,
      options.sortDir || "asc",
    );
    const currentIndex = Number.isSafeInteger(options.currentIndex)
      ? options.currentIndex
      : -1;
    const backwards = Number(options.direction) < 0;
    const comparator = backwards ? "<" : ">";
    const resultOrder = backwards ? "DESC" : "ASC";
    const rankedSql = `
      WITH ranked AS (
        SELECT data.rowid AS _rowid,
               ROW_NUMBER() OVER (ORDER BY ${orderExpression}) - 1 AS _index
        FROM data
        ${baseWhere}
      ),
      matches AS (
        SELECT ranked._rowid,
               ranked._index,
               ROW_NUMBER() OVER (ORDER BY ranked._index) - 1 AS _position,
               COUNT(*) OVER () AS _total
        FROM ranked
        JOIN data ON data.rowid = ranked._rowid
        WHERE ${matchConditions.join(" AND ")}
      )
      SELECT _rowid, _index, _position, _total
      FROM matches
      WHERE _index ${comparator} ?
      ORDER BY _index ${resultOrder}
      LIMIT 1`;
    const args = [...baseParams, ...matchParams, currentIndex];
    let row = meta.db.prepare(rankedSql).get(...args);

    // Wrap at either end, matching common F3 navigation behavior.
    if (!row) {
      const wrapSql = rankedSql.replace(
        `WHERE _index ${comparator} ?`,
        "WHERE ? IS NOT NULL",
      );
      row = meta.db.prepare(wrapSql).get(...baseParams, ...matchParams, currentIndex);
    }
    if (!row) return { index: -1, rowId: null, position: -1, totalMatches: 0 };
    return {
      index: Number(row._index),
      rowId: Number(row._rowid),
      position: Number(row._position),
      totalMatches: Number(row._total),
    };
  }

  _buildOrderExpression(meta, tabId, sortCol = null, sortDir = "asc") {
    const dir = sortDir === "desc" ? "DESC" : "ASC";
    if (sortCol === "__vt__") {
      return `COALESCE((SELECT MIN(CASE tag WHEN 'VT: Malicious' THEN 1 WHEN 'VT: Suspicious' THEN 2 WHEN 'VT: Clean' THEN 3 ELSE 4 END) FROM tags WHERE tags.rowid = data.rowid AND tag LIKE 'VT:%'), 5) ${dir}, data.rowid ASC`;
    }

    const safeCol = sortCol ? meta.colMap[sortCol] : null;
    if (!safeCol) return "data.rowid ASC";

    this._ensureIndex(tabId, sortCol);
    if (meta.tsColumns.has(sortCol)) {
      return `sort_datetime(${safeCol}) ${dir}, data.rowid ASC`;
    }
    if (meta.numericColumns.has(sortCol)) {
      return `CAST(${safeCol} AS REAL) ${dir}, data.rowid ASC`;
    }
    return `${safeCol} COLLATE NOCASE ${dir}, data.rowid ASC`;
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
      // Concatenate all columns with separator and run single REGEXP — avoids
      // pushing N identical params and N separate REGEXP calls per row.
      const concat = meta.safeCols.map((c) => `COALESCE(${c.safe},'')`).join(" || ' ' || ");
      whereConditions.push(`(${concat}) REGEXP ?`);
      params.push(searchTerm.trim());
      return;
    }

    // ── Contains-mode search (the default): use LIKE substring matching for
    // consistency with column filters and column-qualified `Col:value` searches.
    //
    // Previously this path used FTS5 phrase queries, but FTS5's whole-token
    // semantics produced false negatives for substrings embedded in larger
    // alphanumeric tokens (issue #8): e.g. `b4ckd00r` would not match a row
    // containing `crackb4ckd00r` because unicode61 indexes the latter as a
    // single token. Column filter `LIKE %b4ckd00r%` matched correctly, so the
    // global search was inconsistent with the rest of the filtering UI.
    //
    // LIKE on a concatenated column expression is slower than FTS on very
    // large datasets, but DFIR analysts need correct substring semantics —
    // partial IOC matches must work. Mixed-mode operators (+, -, "phrase",
    // Col:value) are translated to LIKE conditions per token below.
    const concat = meta.safeCols.map((c) => `COALESCE(${c.safe},'')`).join(" || ' ' || ");

    // FTS5 trigram prefilter: when the trigram index is ready, narrow candidate rows by the
    // required >=3-char substrings via an indexed MATCH, then let the LIKE conditions above
    // re-confirm exact semantics. For a >=3-char substring, trigram MATCH "x" is equivalent
    // to a per-column LIKE %x% (the concat's ' ' separators prevent cross-column substrings),
    // so the prefilter is a safe SUPERSET and the LIKE re-check guarantees correctness. Terms
    // <3 chars can't be trigram-indexed, so they fall through to LIKE alone. This restores
    // the index speed lost when the default search moved to substring-LIKE (issue #8).
    const _addFtsPrefilter = (requiredTerms, joiner = " AND ") => {
      if (!meta.ftsReady) return;
      const terms = (requiredTerms || []).filter((t) => typeof t === "string" && t.length >= 3);
      if (terms.length === 0) return;
      const matchQuery = terms.map((t) => `"${t.replace(/"/g, '""')}"`).join(joiner);
      whereConditions.push(`data.rowid IN (SELECT rowid FROM data_fts WHERE data_fts MATCH ?)`);
      params.push(matchQuery);
    };

    if (searchMode === "exact") {
      whereConditions.push(`(${concat}) LIKE ?`);
      params.push(`%${searchTerm.trim()}%`);
      _addFtsPrefilter([searchTerm.trim()]);
      return;
    }

    if (searchMode === "or" || searchMode === "and") {
      const terms = searchTerm.trim().split(/\s+/).filter(Boolean);
      if (terms.length === 0) return;
      const joinOp = searchMode === "or" ? " OR " : " AND ";
      const conds = terms.map(() => `(${concat}) LIKE ?`);
      whereConditions.push(`(${conds.join(joinOp)})`);
      for (const t of terms) params.push(`%${t}%`);
      // AND: every term is required → prefilter on the >=3-char subset. OR: only safe when
      // EVERY term is trigram-indexable (>=3 chars), else a <3-char term's rows would be
      // wrongly excluded by the prefilter (it must remain a superset of the LIKE result).
      if (searchMode === "and") _addFtsPrefilter(terms);
      else if (terms.every((t) => t.length >= 3)) _addFtsPrefilter(terms, " OR ");
      return;
    }

    // Mixed mode — parse tokens (+include, -exclude, "phrase", Col:value, bare)
    // and translate each to a LIKE condition. Preserves all the operator
    // semantics that the FTS path used to handle.
    const tokens = [];
    const tokenRegex = /"([^"]+)"|(\S+)/g;
    let mt;
    while ((mt = tokenRegex.exec(searchTerm)) !== null) {
      tokens.push(mt[1] != null ? { kind: "phrase", value: mt[1] } : { kind: "raw", value: mt[2] });
    }

    const sqlParts = [];
    // Positive substrings that EVERY matching row must contain (tokens are ANDed below).
    // Excludes -negations. Used to build the FTS trigram prefilter (a safe superset).
    const requiredTerms = [];
    for (const tok of tokens) {
      if (tok.kind === "phrase") {
        sqlParts.push(`(${concat}) LIKE ?`);
        params.push(`%${tok.value}%`);
        requiredTerms.push(tok.value);
        continue;
      }
      const v = tok.value;
      // Column-qualified `Col:value` — direct LIKE on the matched column
      const colonIdx = v.indexOf(":");
      if (colonIdx > 0 && !v.startsWith("-") && !v.startsWith("+")) {
        const colPart = v.substring(0, colonIdx);
        const valPart = v.substring(colonIdx + 1);
        if (valPart) {
          const matchCol = meta.headers.find((h) => h.toLowerCase() === colPart.toLowerCase());
          const safeCol = matchCol ? meta.colMap[matchCol] : null;
          if (safeCol) {
            sqlParts.push(`${normalizedColumnExpr(meta, matchCol)} LIKE ?`);
            params.push(`%${valPart}%`);
            // The value must appear in a specific column, so it appears in the row →
            // including it as a required term keeps the prefilter a valid superset.
            requiredTerms.push(valPart);
            continue;
          }
        }
      }
      if (v.startsWith("-")) {
        const term = v.slice(1);
        if (term) {
          sqlParts.push(`NOT ((${concat}) LIKE ?)`);
          params.push(`%${term}%`);
        }
        continue;
      }
      if (v.startsWith("+")) {
        const term = v.slice(1);
        if (term) {
          sqlParts.push(`(${concat}) LIKE ?`);
          params.push(`%${term}%`);
          requiredTerms.push(term);
        }
        continue;
      }
      // Bare term
      sqlParts.push(`(${concat}) LIKE ?`);
      params.push(`%${v}%`);
      requiredTerms.push(v);
    }

    if (sqlParts.length > 0) {
      whereConditions.push(`(${sqlParts.join(" AND ")})`);
      _addFtsPrefilter(requiredTerms);
    }
  }

  // ── Shared filter helpers (used by queryRows, preview*, getLateralMovement, etc.) ──

  _applyColumnFilters(columnFilters, meta, whereConditions, params) {
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      if (cn === "__tags__") {
        whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag LIKE ?)`);
        params.push(`%${fv}%`);
        continue;
      }
      if (cn === "__vt__") {
        whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag LIKE 'VT:%' AND tag LIKE ? COLLATE NOCASE)`);
        params.push(`%${fv}%`);
        continue;
      }
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const expr = normalizedColumnExpr(meta, cn);
      whereConditions.push(`${expr} LIKE ?`);
      params.push(`%${fv}%`);
    }
  }

  _normalizeCheckboxFilterValues(values) {
    if (!values) return [];
    if (Array.isArray(values)) return values;
    if (values instanceof Set) return [...values];
    return [];
  }

  _applyCheckboxFilters(checkboxFilters, meta, whereConditions, params) {
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      const list = this._normalizeCheckboxFilterValues(values);
      if (list.length === 0) continue;
      if (cn === "__vt__") {
        if (list.length <= BIND_IN_MAX) {
          const ph = list.map(() => "?").join(",");
          whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag IN (${ph}))`);
          params.push(...list);
        } else {
          whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE ${sqlInPredicate("tag", list)})`);
        }
        continue;
      }
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const expr = normalizedColumnExpr(meta, cn);
      // A selected value that is itself blank means "the (empty) bucket". Match it with the
      // same rule the value list groups by, so checking (empty) selects every cell that
      // renders blank — and unchecking it excludes every one of them.
      const hasNull = list.some((v) => v === null || String(v).trim() === "");
      const nonNull = list.filter((v) => v !== null && String(v).trim() !== "");
      const parts = [];
      if (hasNull) parts.push(`(${emptyValuePredicate(expr)})`);
      if (nonNull.length === 1) {
        parts.push(`${expr} = ?`);
        params.push(nonNull[0]);
      } else if (nonNull.length > 1 && nonNull.length <= BIND_IN_MAX) {
        parts.push(`${expr} IN (${nonNull.map(() => "?").join(",")})`);
        params.push(...nonNull);
      } else if (nonNull.length > BIND_IN_MAX) {
        // Timestamp columns are nearly unique (100-ns EvtxECmd values). Binding
        // 200k+ timestamps exceeds SQLITE_MAX_VARIABLE_NUMBER; inline+chunk instead.
        parts.push(sqlInPredicate(expr, nonNull));
      }
      if (parts.length) whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
  }

  /**
   * Normalize a date-range bound to the same canonical UTC sort key as sort_datetime().
   */
  _dateRangeBoundKey(value) {
    if (value == null || value === "") return value;
    const s = String(value).trim();
    const ms = normalizeTimestamp(s);
    if (Number.isFinite(ms)) {
      const iso = new Date(ms).toISOString();
      return iso.slice(0, 10) + " " + iso.slice(11, 23);
    }
    return s.replace("T", " ");
  }

  _applyDateRangeFilters(dateRangeFilters, meta, whereConditions, params) {
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn];
      if (!sc) continue;
      // datetime-local inputs use "T" while most forensic imports use a space.
      // Raw TEXT comparison therefore excludes valid rows at the lower bound.
      // Use the same canonical UDF as timestamp sorting so ranges also honor
      // explicit offsets and mixed input formats.
      const comparable = meta.tsColumns?.has(cn) ? `sort_datetime(${sc})` : sc;
      if (range.from) {
        whereConditions.push(`${comparable} >= sort_datetime(?)`);
        params.push(range.from);
      }
      if (range.to) {
        whereConditions.push(`${comparable} <= sort_datetime(?)`);
        params.push(range.to);
      }
    }
  }

  _applyBookmarkFilter(bookmarkedOnly, whereConditions) {
    if (bookmarkedOnly) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    }
  }

  _applyTagFilter(tagFilter, whereConditions, params) {
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
  }

  _normalizeRowIdFilter(rowIdFilter) {
    if (!Array.isArray(rowIdFilter)) return null;
    const ids = [];
    const seen = new Set();
    for (const value of rowIdFilter) {
      const id = Number(value);
      if (!Number.isSafeInteger(id) || id <= 0 || seen.has(id)) continue;
      seen.add(id);
      ids.push(id);
    }
    return ids;
  }

  _applyRowIdFilter(rowIdFilter, whereConditions) {
    const ids = this._normalizeRowIdFilter(rowIdFilter);
    if (!ids) return;
    if (ids.length === 0) {
      whereConditions.push("0");
      return;
    }

    // Source row IDs are sanitized integers, so inline them to avoid SQLite's
    // variable limit when a rule has many matches.
    const chunks = [];
    const CHUNK_SIZE = 5000;
    for (let i = 0; i < ids.length; i += CHUNK_SIZE) {
      chunks.push(`data.rowid IN (${ids.slice(i, i + CHUNK_SIZE).join(",")})`);
    }
    whereConditions.push(chunks.length === 1 ? chunks[0] : `(${chunks.join(" OR ")})`);
  }

  _applyExcludedRowIds(excludedRowIds, whereConditions) {
    const ids = this._normalizeRowIdFilter(excludedRowIds);
    if (!ids || ids.length === 0) return;

    const chunks = [];
    const CHUNK_SIZE = 5000;
    for (let i = 0; i < ids.length; i += CHUNK_SIZE) {
      chunks.push(`data.rowid NOT IN (${ids.slice(i, i + CHUNK_SIZE).join(",")})`);
    }
    whereConditions.push(chunks.length === 1 ? chunks[0] : `(${chunks.join(" AND ")})`);
  }

  /**
   * SQL sort key for a column (no ORDER BY / direction). Returns null if unknown.
   */
  _sortKeyExpression(meta, tabId, sortCol) {
    if (!sortCol || sortCol === "__vt__") return null;
    const safeCol = meta.colMap[sortCol];
    if (!safeCol) return null;
    this._ensureIndex(tabId, sortCol);
    if (meta.tsColumns.has(sortCol)) return `sort_datetime(${safeCol})`;
    if (meta.numericColumns.has(sortCol)) return `CAST(${safeCol} AS REAL)`;
    return `${normalizedColumnExpr(meta, sortCol)} COLLATE NOCASE`;
  }

  /**
   * ORDER BY clause matching the grid's current sort (shared by queryRows, export, column copy).
   */
  _buildOrderClause(meta, tabId, sortCol, sortDir) {
    return `ORDER BY ${this._buildOrderExpression(meta, tabId, sortCol, sortDir)}`;
  }

  /**
   * Apply the standard set of filters to a WHERE clause.
   * Centralizes the filter logic shared by queryRows, exportQuery,
   * getColumnStats, getHistogramData, and all analysis methods.
   */
  _applyStandardFilters(options, meta, whereConditions, params) {
    const {
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, tagFilter = null,
      dateRangeFilters = {}, advancedFilters = [],
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      rowIdFilter = null,
      excludedRowIds = null,
    } = options;
    this._applyRowIdFilter(rowIdFilter, whereConditions);
    this._applyExcludedRowIds(excludedRowIds, whereConditions);
    this._applyColumnFilters(columnFilters, meta, whereConditions, params);
    this._applyCheckboxFilters(checkboxFilters, meta, whereConditions, params);
    this._applyDateRangeFilters(dateRangeFilters, meta, whereConditions, params);
    this._applyBookmarkFilter(bookmarkedOnly, whereConditions);
    this._applyTagFilter(tagFilter, whereConditions, params);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);
    if (searchTerm.trim()) {
      this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
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
      const sc = normalizedColumnExpr(meta, f.column);
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
              result.colConditions.push({ sql: `${normalizedColumnExpr(meta, matchCol)} LIKE ?`, param: `%${valPart}%` });
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
   * Export filtered data as streaming CSV
   */
  exportQuery(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;

    const { sortCol = null, sortDir = "asc", visibleHeaders = null, includeTriage = false } = options;

    const headers = [...(visibleHeaders || meta.headers)];
    const safeCols = [];
    const selectCols = [];
    for (const h of headers.slice()) {
      const safe = meta.colMap[h];
      if (!safe) continue;
      safeCols.push(safe);
      const expr = normalizedColumnExpr(meta, h);
      selectCols.push(expr === safe ? safe : `${expr} AS ${safe}`);
    }

    // Tags and bookmarks ARE the analyst's work product — the grid shows both as
    // columns, but they used to vanish on export, so a triaged CSV came out
    // indistinguishable from an untriaged one. Appended only when the tab
    // actually carries triage, so untriaged exports keep their exact old shape.
    if (includeTriage) {
      let hasTriage = false;
      try {
        hasTriage = !!meta.db.prepare(
          "SELECT (EXISTS(SELECT 1 FROM tags) OR EXISTS(SELECT 1 FROM bookmarks)) AS any"
        ).get()?.any;
      } catch { /* tables missing on a partially built tab — skip the columns */ }
      if (hasTriage) {
        // group_concat's ORDER BY argument needs SQLite 3.44+; the nested ordered
        // subquery gives deterministic output on every version.
        selectCols.push(
          "(SELECT group_concat(t.tag, '; ') FROM (SELECT tag FROM tags WHERE tags.rowid = data.rowid ORDER BY tag) t) AS _tle_tags"
        );
        safeCols.push("_tle_tags");
        headers.push("Tags");
        selectCols.push(
          "(CASE WHEN EXISTS(SELECT 1 FROM bookmarks WHERE bookmarks.rowid = data.rowid) THEN 'Yes' ELSE '' END) AS _tle_bookmarked"
        );
        safeCols.push("_tle_bookmarked");
        headers.push("Bookmarked");
      }
    }

    const colList = selectCols.join(", ");

    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause =
      whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")}`
        : "";

    const orderClause = this._buildOrderClause(meta, tabId, sortCol, sortDir);

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
   * Distinct values for a column with row counts (for AI history source manifest).
   */
  getGroupedColumnCounts(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { groups: [], totalRows: 0 };

    const safeCol = meta.colMap[colName];
    if (!safeCol) return { groups: [], totalRows: 0 };

    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);
    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    const valExpr = normalizedColumnExpr(meta, colName);
    const groups = meta.db.prepare(
      `SELECT ${valExpr} AS val, COUNT(*) AS cnt FROM data ${whereClause} `
      + `GROUP BY ${valExpr} HAVING val IS NOT NULL AND val != '' ORDER BY cnt DESC`,
    ).all(...params);

    const totalRows = meta.db.prepare(`SELECT COUNT(*) AS cnt FROM data ${whereClause}`).get(...params).cnt;

    return {
      groups: groups.map((r) => ({ value: String(r.val), count: r.cnt })),
      totalRows,
    };
  }

  /**
   * Get column statistics (unique values, min/max for numerics)
   */
  getColumnStats(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const isTagCol = colName === "__tags__";
    const safeCol = isTagCol ? null : meta.colMap[colName];
    if (!isTagCol && !safeCol) return null;

    const db = meta.db;
    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    try {
      if (isTagCol) {
        // Tags column stats — query from tags table
        const totalRows = db.prepare(`SELECT COUNT(*) as cnt FROM data ${whereClause}`).get(...params).cnt;
        const joinWhere = whereClause ? `${whereClause} AND data.rowid = tags.rowid` : `WHERE data.rowid = tags.rowid`;
        const taggedRows = db.prepare(`SELECT COUNT(DISTINCT tags.rowid) as cnt FROM tags, data ${joinWhere}`).get(...params).cnt;
        const uniqueTags = db.prepare(`SELECT COUNT(DISTINCT tag) as cnt FROM tags, data ${joinWhere}`).get(...params).cnt;
        const topValues = db.prepare(`SELECT tag as val, COUNT(*) as cnt FROM tags, data ${joinWhere} GROUP BY tag ORDER BY cnt DESC LIMIT 25`).all(...params);
        return { totalRows, nonEmptyCount: taggedRows, emptyCount: totalRows - taggedRows, uniqueCount: uniqueTags, fillRate: totalRows > 0 ? Math.round((taggedRows / totalRows) * 10000) / 100 : 0, topValues };
      }

      // Combined stats query — 1 scan instead of 3 separate COUNT queries
      const isTs = meta.tsColumns.has(colName);
      const isNum = meta.numericColumns && meta.numericColumns.has(colName);
      const valExpr = normalizedColumnExpr(meta, colName);
      let statsSql = `SELECT COUNT(*) as total, SUM(CASE WHEN ${valExpr} IS NOT NULL AND ${valExpr} != '' THEN 1 ELSE 0 END) as nonEmpty, COUNT(DISTINCT CASE WHEN ${valExpr} IS NOT NULL AND ${valExpr} != '' THEN ${valExpr} END) as uniq`;
      if (isTs) statsSql += `, MIN(sort_datetime(${safeCol})) as earliest, MAX(sort_datetime(${safeCol})) as latest`;
      if (isNum) statsSql += `, MIN(CAST(${safeCol} AS REAL)) as minVal, MAX(CAST(${safeCol} AS REAL)) as maxVal, AVG(CAST(${safeCol} AS REAL)) as avgVal`;
      statsSql += ` FROM data ${whereClause}`;
      const stats = db.prepare(statsSql).get(...params);

      const totalRows = stats.total;
      const nonEmptyCount = stats.nonEmpty;
      const emptyCount = totalRows - nonEmptyCount;
      const uniqueCount = stats.uniq;
      const fillRate = totalRows > 0 ? Math.round((nonEmptyCount / totalRows) * 10000) / 100 : 0;

      // Top 25 values (still needs separate GROUP BY query)
      const neWhere = whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")} AND ${valExpr} IS NOT NULL AND ${valExpr} != ''`
        : `WHERE ${valExpr} IS NOT NULL AND ${valExpr} != ''`;
      const topValues = db.prepare(
        `SELECT ${valExpr} as val, COUNT(*) as cnt FROM data ${neWhere} GROUP BY ${valExpr} ORDER BY cnt DESC LIMIT 25`
      ).all(...params);

      const result = { totalRows, nonEmptyCount, emptyCount, uniqueCount, fillRate, topValues };

      // Timestamp stats (already computed in combined query)
      if (isTs && stats.earliest) {
        result.tsStats = { earliest: stats.earliest, latest: stats.latest };
        try {
          const e = new Date(stats.earliest.replace(" ", "T"));
          const l = new Date(stats.latest.replace(" ", "T"));
          const diffMs = l.getTime() - e.getTime();
          if (!isNaN(diffMs) && diffMs >= 0) result.tsStats.timespanMs = diffMs;
        } catch { /* non-parseable */ }
      }

      // Numeric stats (already computed in combined query)
      if (isNum && stats.minVal != null) {
        result.numStats = {
          min: stats.minVal,
          max: stats.maxVal,
          avg: Math.round(stats.avgVal * 100) / 100,
        };
      }

      return result;
    } catch (e) {
      return { totalRows: 0, nonEmptyCount: 0, emptyCount: 0, uniqueCount: 0, fillRate: 0, topValues: [], error: e.message };
    }
  }

  /**
   * Get columns that are entirely empty (NULL or '')
   */
  getEmptyColumns(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    const db = meta.db;
    const omitSet = new Set(options.omitHeaders || []);
    const colsToCheck = meta.safeCols.filter((c) => !omitSet.has(c.original));
    if (!colsToCheck.length) return [];

    // Sample-based: check first 25K + last 25K rows instead of full table scan.
    // On 30M+ row tables, a full scan blocks the main thread for 10-30s.
    const checks = colsToCheck.map((c) => `MAX(CASE WHEN ${c.safe} IS NOT NULL AND ${c.safe} != '' THEN 1 ELSE 0 END) as ${c.safe}`);
    const useFullScan = !options.forceSample && meta.rowCount <= 100000;
    const source = useFullScan
      ? "data"
      : `(SELECT * FROM (SELECT * FROM data LIMIT 25000) UNION ALL SELECT * FROM (SELECT * FROM data ORDER BY rowid DESC LIMIT 25000))`;
    const row = db.prepare(`SELECT ${checks.join(", ")} FROM ${source}`).get();
    if (!row) return [];
    return colsToCheck
      .filter((c) => !row[c.safe])
      .map((c) => c.original);
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
    if (!meta) return { values: [], totalDistinct: 0, truncated: false };

    const safeCol = meta.colMap[colName];
    if (!safeCol) return { values: [], totalDistinct: 0, truncated: false };

    const {
      filterText = "",
      filterRegex = false,
      limit,
      checkboxFilters = {},
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];
    const isTsCol = Boolean(meta.tsColumns && meta.tsColumns.has(colName));
    // No default cap: TimeCreated is nearly unique and a "top 1000" list hides
    // the forensic range. Callers that want a bound (find-duplicates) pass one.
    const hasLimit = Number.isInteger(limit) && limit > 0;
    const orderBy = isTsCol ? `sort_datetime(val) ASC, val ASC` : `cnt DESC`;

    // Exclude self-column from checkbox filters to avoid circular filtering
    const filteredOptions = checkboxFilters[colName]
      ? { ...options, checkboxFilters: Object.fromEntries(Object.entries(checkboxFilters).filter(([cn]) => cn !== colName)) }
      : options;
    this._applyStandardFilters(filteredOptions, meta, whereConditions, params);

    // Filter values list by search text (supports regex mode)
    const valExpr = normalizedColumnExpr(meta, colName);
    // Group on the bucketed expression so NULL, '' and whitespace-only collapse into the
    // one "(empty)" row the checkbox filter can act on. Search still matches the raw value.
    const groupExpr = emptyBucketedExpr(valExpr);
    if (filterText.trim()) {
      if (filterRegex) {
        whereConditions.push(`${valExpr} REGEXP ?`);
        params.push(filterText);
      } else {
        whereConditions.push(`${valExpr} LIKE ?`);
        params.push(`%${filterText}%`);
      }
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const colIndexed = meta.indexedCols && meta.indexedCols.has(safeCol);
    const rowCount = meta.rowCount || 0;
    const useSample = meta.isLargeFile && !colIndexed && rowCount >= LARGE_FILE_UNIQUE_SAMPLE_MIN_ROWS;

    let sql;
    if (useSample) {
      // Full-table GROUP BY on 6M+ rows can spike RSS and freeze the UI thread pool.
      // Sample the first N rowids (stable, fast) — still honors active filters.
      sql = `SELECT val, COUNT(*) as cnt FROM (
        SELECT ${groupExpr} as val FROM data ${whereClause} ORDER BY rowid LIMIT ${LARGE_FILE_UNIQUE_SAMPLE_ROWS}
      ) GROUP BY val ORDER BY ${orderBy}`;
      if (hasLimit) sql += " LIMIT ?";
    } else if (hasLimit) {
      // Return the size of the complete value set as metadata instead of making
      // the UI imply that the bounded result is exhaustive.
      sql = `
        SELECT val, cnt, COUNT(*) OVER() AS total_distinct
        FROM (
          SELECT ${groupExpr} AS val, COUNT(*) AS cnt
          FROM data ${whereClause}
          GROUP BY ${groupExpr}
        )
        ORDER BY ${orderBy}
        LIMIT ?
      `;
    } else {
      sql = `
        SELECT ${groupExpr} AS val, COUNT(*) AS cnt
        FROM data ${whereClause}
        GROUP BY ${groupExpr}
        ORDER BY ${orderBy}
      `;
    }
    if (hasLimit) params.push(limit);

    try {
      const rows = db.prepare(sql).all(...params);
      const totalDistinct = useSample || !hasLimit
        ? rows.length
        : Number(rows[0]?.total_distinct || 0);
      return {
        values: rows.map(({ val, cnt }) => ({ val, cnt })),
        totalDistinct,
        truncated: useSample || (hasLimit && totalDistinct > rows.length),
        ...(useSample ? { sampled: true } : {}),
      };
    } catch (e) {
      dbg("DB", `getColumnUniqueValues failed`, { tabId, colName, error: e.message });
      return { values: [], totalDistinct: 0, truncated: false, error: e.message };
    }
  }

  /**
   * Get every value of a single column for the current (filtered/searched) view —
   * for spreadsheet-style "copy column out". Honors all standard filters + search.
   * distinct:false → all values in row order (with duplicates); distinct:true →
   * unique values sorted (ready to dedup/paste). Returns { values, total } where
   * total is the row count scanned. Capped at `limit` (default 1M) to bound memory.
   */
  getColumnValues(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { values: [], total: 0, truncated: false };

    const isTagCol = colName === "__tags__";
    const safeCol = isTagCol ? null : meta.colMap[colName];
    if (!isTagCol && !safeCol) return { values: [], total: 0, truncated: false };

    const { distinct = false, limit = 1000000, sortCol = null, sortDir = "asc" } = options;
    const db = meta.db;
    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);
    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    // Tags live in a side table keyed by rowid; join so filters (on data) still apply.
    const fromExpr = isTagCol
      ? `data JOIN tags ON tags.rowid = data.rowid`
      : `data`;
    const valExpr = isTagCol ? `tags.tag` : normalizedColumnExpr(meta, colName);
    const orderClause = this._buildOrderClause(meta, tabId, sortCol, sortDir);
    const sortKey = this._sortKeyExpression(meta, tabId, sortCol);
    const sortDirSql = sortDir === "desc" ? "DESC" : "ASC";
    const isTsCol = !isTagCol && meta.tsColumns && meta.tsColumns.has(colName);
    let sql;
    if (distinct && isTsCol) {
      // Same instant can appear as ISO T/Z, space-separated, fractional seconds, etc.
      const rawTsKey = `sort_datetime(${safeCol})`;
      // Normalize representation-only trailing fractional zeroes without changing
      // sort_datetime() itself, whose fixed-width UTC output is part of the query API.
      const tsKey = `CASE WHEN INSTR(${rawTsKey}, '.') > 0 `
        + `THEN RTRIM(RTRIM(${rawTsKey}, '0'), '.') ELSE ${rawTsKey} END`;
      sql = `SELECT MIN(${valExpr}) AS val FROM ${fromExpr} ${whereClause} GROUP BY ${tsKey} ORDER BY MIN(${tsKey}) ${sortDirSql} LIMIT ?`;
    } else if (distinct && sortKey) {
      // Text: trim + case-insensitive group; order follows the grid sort column.
      sql = `SELECT MIN(${valExpr}) AS val FROM ${fromExpr} ${whereClause} GROUP BY TRIM(${valExpr}) COLLATE NOCASE ORDER BY MIN(${sortKey}) ${sortDirSql} LIMIT ?`;
    } else if (distinct) {
      sql = `SELECT MIN(${valExpr}) AS val FROM ${fromExpr} ${whereClause} GROUP BY TRIM(${valExpr}) COLLATE NOCASE ORDER BY MIN(${valExpr}) COLLATE NOCASE LIMIT ?`;
    } else {
      sql = `SELECT ${valExpr} AS val FROM ${fromExpr} ${whereClause} ${orderClause} LIMIT ?`;
    }
    params.push(limit + 1); // fetch one extra to detect truncation

    try {
      const rows = db.prepare(sql).all(...params);
      const truncated = rows.length > limit;
      const values = (truncated ? rows.slice(0, limit) : rows).map((r) => r.val == null ? "" : String(r.val));
      return { values, total: values.length, truncated };
    } catch (e) {
      dbg("DB", `getColumnValues failed`, { tabId, colName, error: e.message });
      return { values: [], total: 0, truncated: false, error: e.message };
    }
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

    const { parentFilters = [] } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Parent group filters (for multi-level grouping)
    for (const pf of parentFilters) {
      const sc = meta.colMap[pf.col];
      if (sc) {
        const expr = normalizedColumnExpr(meta, pf.col);
        whereConditions.push(`${expr} = ?`);
        params.push(pf.value);
      }
    }

    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const valExpr = normalizedColumnExpr(meta, groupCol);
    const sql = `SELECT ${valExpr} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${valExpr} ORDER BY cnt DESC`;

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

}

const proto = QueryStoreMethods.prototype;
proto.LARGE_FILE_UNIQUE_SAMPLE_ROWS = LARGE_FILE_UNIQUE_SAMPLE_ROWS;
proto.LARGE_FILE_UNIQUE_SAMPLE_MIN_ROWS = LARGE_FILE_UNIQUE_SAMPLE_MIN_ROWS;
module.exports = proto;
