/**
 * Bookmark/tag methods mixed into TimelineDB.
 *
 * Contract notes (these are load-bearing — the renderer relies on them):
 *  - Every mutator returns a structured result. `null` means "no such tab".
 *    A resolved value is never a silent no-op: callers can always tell whether
 *    the write landed, and how many rows it touched.
 *  - Tag names are normalized (whitespace-collapsed, trimmed, length-capped) at
 *    EVERY write boundary, so "Suspicious", " Suspicious" and "Suspicious  "
 *    are the same tag instead of three look-alike entries in the palette.
 *  - Writes are NOT gated on the deferred index/FTS build. Those builds run on
 *    this same connection on the main thread, chunked between event-loop turns,
 *    and they only touch `data`/`data_fts`. Refusing tag writes while they ran
 *    silently dropped everything an analyst tagged in the minutes after a large
 *    import while the UI happily showed the tag.
 */
const { dbg } = require("../logger");

// Long enough for "IOC: <sha256>" and Sigma rule titles, short enough that a
// pasted blob can't become a tag.
const MAX_TAG_LENGTH = 200;

/**
 * Canonical form of a tag name. Returns "" for anything unusable.
 */
function normalizeTagName(tag) {
  if (typeof tag !== "string" && typeof tag !== "number") return "";
  return String(tag).replace(/\s+/g, " ").trim().slice(0, MAX_TAG_LENGTH);
}

/**
 * A tag name used to REFERENCE an existing stored value (remove, rename-from,
 * delete). It must match what is in the table byte for byte: normalizing here
 * would make a legacy tag stored as "C2 " unmatchable — which is exactly the
 * tag that most needs removing or merging. Returns "" for anything unusable.
 */
function existingTagName(tag) {
  if (typeof tag !== "string" && typeof tag !== "number") return "";
  const raw = String(tag);
  return raw.trim() ? raw : "";
}

/**
 * De-duplicated list of positive integer SQLite row IDs.
 */
function normalizeRowIdList(rowIds) {
  if (!Array.isArray(rowIds)) return [];
  const seen = new Set();
  for (const value of rowIds) {
    const id = Number(value);
    if (!Number.isSafeInteger(id) || id <= 0) continue;
    seen.add(id);
  }
  return [...seen];
}

class TagStoreMethods {
  _invalidateCountCache(tabId) {
    const meta = this.databases.get(tabId);
    if (meta) { meta._countCache = null; meta._histoCache = null; }
    // Also clear analysis preview caches — they depend on filtered/tagged data
    if (this._ptPreviewCache) {
      const prefix = JSON.stringify(tabId);
      for (const k of this._ptPreviewCache.keys()) { if (k.startsWith("[" + prefix + ",")) this._ptPreviewCache.delete(k); }
    }
    if (this._lmPreviewCache) {
      const prefix = JSON.stringify(tabId);
      for (const k of this._lmPreviewCache.keys()) { if (k.startsWith("[" + prefix + ",")) this._lmPreviewCache.delete(k); }
    }
  }

  /**
   * Toggle bookmark on a row. Returns the new state, or null if the tab is gone.
   */
  toggleBookmark(tabId, rowId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const id = Number(rowId);
    if (!Number.isSafeInteger(id) || id <= 0) return null;
    this._invalidateCountCache(tabId);
    const exists = meta.bmCheckStmt.get(id);
    if (exists) {
      meta.bmDeleteStmt.run(id);
      return false;
    }
    meta.bmInsertStmt.run(id);
    return true;
  }

  /**
   * Bulk add/remove bookmarks for an explicit row-ID list.
   * Returns { requested, changed } so the caller can report real counts.
   */
  setBookmarks(tabId, rowIds, add = true) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const ids = normalizeRowIdList(rowIds);
    if (ids.length === 0) return { requested: 0, changed: 0 };
    const stmt = add ? meta.bmInsertStmt : meta.bmDeleteStmt;
    let changed = 0;
    const tx = meta.db.transaction((batch) => {
      for (const id of batch) changed += stmt.run(id).changes || 0;
    });
    for (let i = 0; i < ids.length; i += 5000) tx(ids.slice(i, i + 5000));
    this._invalidateCountCache(tabId);
    return { requested: ids.length, changed };
  }

  /**
   * Get bookmark count
   */
  getBookmarkCount(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return 0;
    return meta.bmCountStmt.get().cnt;
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
    return this.setTagOnRows(tabId, [rowId], tag, true);
  }

  removeTag(tabId, rowId, tag) {
    return this.setTagOnRows(tabId, [rowId], tag, false);
  }

  /**
   * Add or remove ONE tag across an explicit row-ID list, in a single
   * transaction. This is the primitive the grid's multi-row tagging uses:
   * the renderer must never loop `addTag` over a selection (one IPC round trip
   * and one implicit transaction per row hangs the UI on large selections and
   * leaves a half-applied tag if anything fails midway).
   *
   * `add` is decided ONCE by the caller and applied uniformly. Deciding
   * per-row (toggle semantics) on a mixed selection tags some rows and untags
   * others from a single click.
   */
  setTagOnRows(tabId, rowIds, tag, add = true) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    // Adding CREATES the name, so it is canonicalized. Removing REFERENCES an
    // existing one, so it is matched verbatim.
    const name = add ? normalizeTagName(tag) : existingTagName(tag);
    if (!name) return { ok: false, tag: "", requested: 0, changed: 0, error: "Empty tag name" };
    const ids = normalizeRowIdList(rowIds);
    if (ids.length === 0) return { ok: true, tag: name, requested: 0, changed: 0 };

    const stmt = add ? meta.tagInsertStmt : meta.tagDeleteStmt;
    let changed = 0;
    try {
      const tx = meta.db.transaction((batch) => {
        for (const id of batch) {
          changed += (add ? stmt.run(id, name) : stmt.run(id, name)).changes || 0;
        }
      });
      for (let i = 0; i < ids.length; i += 5000) tx(ids.slice(i, i + 5000));
    } catch (e) {
      dbg("DB", `setTagOnRows error`, { tabId, tag: name, add, error: e.message });
      return { ok: false, tag: name, requested: ids.length, changed, error: e.message };
    }
    this._invalidateCountCache(tabId);
    return { ok: true, tag: name, requested: ids.length, changed };
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
   * Rename a tag across every row it is applied to. If `to` already exists the
   * two tags MERGE (rows carrying both collapse to one entry) rather than
   * failing on the (rowid, tag) primary key.
   */
  renameTag(tabId, fromTag, toTag) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const from = existingTagName(fromTag);
    const to = normalizeTagName(toTag);
    if (!from || !to) return { ok: false, renamed: 0, merged: 0, error: "Empty tag name" };
    if (from === to) return { ok: true, renamed: 0, merged: 0, from, to };
    try {
      const db = meta.db;
      let renamed = 0;
      let merged = 0;
      const tx = db.transaction(() => {
        // Rows that already carry the destination tag would violate PRIMARY KEY(rowid, tag).
        // UPDATE OR IGNORE skips them; the leftover source rows are then dropped, which is
        // exactly "merge into the destination".
        renamed = db.prepare("UPDATE OR IGNORE tags SET tag = ? WHERE tag = ?").run(to, from).changes || 0;
        merged = db.prepare("DELETE FROM tags WHERE tag = ?").run(from).changes || 0;
      });
      tx();
      this._invalidateCountCache(tabId);
      return { ok: true, from, to, renamed, merged };
    } catch (e) {
      dbg("DB", `renameTag error`, { tabId, from, to, error: e.message });
      return { ok: false, renamed: 0, merged: 0, error: e.message };
    }
  }

  /**
   * Remove a tag from every row that carries it. Deleting a tag from the
   * palette alone leaves the rows tagged in SQLite: still filterable, still in
   * the report, and no longer removable from the row menu (the palette no
   * longer lists it). Callers that mean "forget this tag" must call this.
   */
  deleteTag(tabId, tag) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const name = existingTagName(tag);
    if (!name) return { ok: false, removed: 0, error: "Empty tag name" };
    try {
      const removed = meta.db.prepare("DELETE FROM tags WHERE tag = ?").run(name).changes || 0;
      this._invalidateCountCache(tabId);
      return { ok: true, tag: name, removed };
    } catch (e) {
      dbg("DB", `deleteTag error`, { tabId, tag: name, error: e.message });
      return { ok: false, removed: 0, error: e.message };
    }
  }

  /**
   * Collapse tags that differ only by case/whitespace into the most-used
   * spelling. Returns the merges that were performed.
   */
  mergeDuplicateTags(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const all = this.getAllTags(tabId); // already ordered by count DESC
    const canonicalByKey = new Map();
    const merges = [];
    for (const { tag } of all) {
      const key = normalizeTagName(tag).toLowerCase();
      if (!key) continue;
      const canonical = canonicalByKey.get(key);
      if (!canonical) { canonicalByKey.set(key, normalizeTagName(tag)); continue; }
      if (canonical === tag) continue;
      const res = this.renameTag(tabId, tag, canonical);
      if (res?.ok) merges.push({ from: tag, to: canonical, rows: (res.renamed || 0) + (res.merged || 0) });
    }
    return { ok: true, merges };
  }

  /**
   * Fetch raw rows by SQLite rowid, preserving the requested order.
   * Returns rows mapped back to original header names plus `__idx`.
   */
  getRowsByIds(tabId, rowIds) {
    const meta = this.databases.get(tabId);
    if (!meta || !Array.isArray(rowIds) || rowIds.length === 0) return [];
    const ids = normalizeRowIdList(rowIds);
    if (ids.length === 0) return [];

    const rowsById = new Map();
    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    for (let i = 0; i < ids.length; i += 500) {
      const batch = ids.slice(i, i + 500);
      const placeholders = batch.map(() => "?").join(",");
      const sql = `SELECT data.rowid as _rowid, ${colList} FROM data WHERE data.rowid IN (${placeholders})`;
      const rawRows = meta.db.prepare(sql).all(...batch);
      for (const raw of rawRows) {
        const row = { __idx: raw._rowid };
        for (let c = 0; c < meta.safeCols.length; c++) {
          row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] ?? "";
        }
        rowsById.set(raw._rowid, row);
      }
    }

    return ids.map((id) => rowsById.get(id)).filter(Boolean);
  }

  /**
   * Gather all data needed for HTML report generation.
   * Returns bookmarked rows, tagged rows grouped by tag, and summary stats.
   */
  getReportData(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;

    try {
      const d = meta.db;
      const colList = meta.safeCols.map((c) => c.safe).join(", ");
      const mapRow = (raw) => {
        const row = {};
        for (let c = 0; c < meta.safeCols.length; c++) {
          row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] ?? "";
        }
        return row;
      };

      // Cap the number of detail rows materialized into the report. A bulk bookmark/tag
      // operation (e.g. Sigma "tag all imported rows") can mark millions of rows; loading
      // every one's full column data into JS objects and then building one giant HTML
      // string can blow past the V8 heap and OOM-kill the process. Counts/summaries below
      // still reflect true totals — only the per-row detail tables are bounded.
      const MAX_REPORT_ROWS = 50000;

      // Bookmarked rows (full data, capped)
      const bookmarkedRows = d.prepare(
        `SELECT ${colList} FROM data WHERE rowid IN (SELECT rowid FROM bookmarks) ORDER BY rowid LIMIT ?`
      ).all(MAX_REPORT_ROWS).map(mapRow);

      // Tags: unique tags with counts
      const tagSummary = d.prepare(
        "SELECT tag, COUNT(*) as cnt FROM tags GROUP BY tag ORDER BY cnt DESC"
      ).all();

      // Tagged rows grouped by tag (single JOIN query instead of per-tag N+1, capped)
      const taggedGroups = {};
      let taggedTruncated = false;
      if (tagSummary.length > 0) {
        const allTaggedRows = d.prepare(
          `SELECT t.tag, ${colList} FROM data d INNER JOIN tags t ON d.rowid = t.rowid ORDER BY t.tag, d.rowid LIMIT ?`
        ).all(MAX_REPORT_ROWS + 1);
        if (allTaggedRows.length > MAX_REPORT_ROWS) {
          taggedTruncated = true;
          allTaggedRows.length = MAX_REPORT_ROWS;
        }
        for (const row of allTaggedRows) {
          const tag = row.tag;
          if (!taggedGroups[tag]) taggedGroups[tag] = [];
          const mapped = {};
          for (let c = 0; c < meta.safeCols.length; c++) {
            mapped[meta.safeCols[c].original] = row[meta.safeCols[c].safe] ?? "";
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
        maxReportRows: MAX_REPORT_ROWS,
        bookmarkedTruncated: bookmarkCount > bookmarkedRows.length,
        taggedTruncated,
      };
    } catch (e) {
      dbg("DB", `getReportData error`, { tabId, error: e.message });
      return null;
    }
  }

  bulkAddTags(tabId, tagMap) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    let changed = 0;
    const tx = meta.db.transaction(() => {
      for (const [rowId, tags] of Object.entries(tagMap || {})) {
        const id = Number(rowId);
        if (!Number.isSafeInteger(id) || id <= 0) continue;
        for (const tag of tags || []) {
          const name = normalizeTagName(tag);
          if (!name) continue;
          changed += meta.tagInsertStmt.run(id, name).changes || 0;
        }
      }
    });
    tx();
    this._invalidateCountCache(tabId);
    return { ok: true, changed };
  }

  bulkAddTagToRows(tabId, rowIds, tag) {
    const res = this.setTagOnRows(tabId, rowIds, tag, true);
    return { tagged: res?.changed || 0, ...(res?.error ? { error: res.error } : {}) };
  }

  /**
   * Bulk-tag rows within specific time ranges directly in SQL.
   * ranges = [{ from, to, tag }] — e.g. [{ from: "2024-01-15 08:30", to: "2024-01-15 10:45", tag: "Session 1" }]
   * Never materializes rowIds in JS — pure SQL INSERT...SELECT.
   */
  bulkTagByTimeRange(tabId, colName, ranges) {
    const meta = this.databases.get(tabId);
    if (!meta || !Array.isArray(ranges) || ranges.length === 0) return { taggedCount: 0 };
    const safeCol = meta.colMap[colName];
    if (!safeCol) return { taggedCount: 0 };
    this._invalidateCountCache(tabId);
    const db = meta.db;
    let taggedCount = 0;
    const tx = db.transaction(() => {
      for (const { from, to, tag } of ranges) {
        // Guard against null/undefined bounds — Heatmap suspicious-window
        // builders can produce null bucket fields when timestamps fail to parse.
        // Skipping silently is safer than throwing in the middle of a transaction.
        const name = normalizeTagName(tag);
        if (typeof from !== "string" || typeof to !== "string" || !name) continue;
        const fromTs = from.length === 16 ? from + ":00" : from;
        const toTs = to.length === 16 ? to + ":59" : to;
        // Normalize the column with sort_datetime() so the range compares
        // chronologically regardless of stored format (US M/D/YYYY h:mm AM/PM, epoch,
        // ISO). The bounds are already ISO-lexical ("YYYY-MM-DD HH:MM:SS"), which is
        // exactly sort_datetime()'s output space. A raw text compare mis-tags or tags
        // nothing for non-ISO columns. Matches the sort/histogram/gap query paths.
        const result = db.prepare(`
          INSERT OR IGNORE INTO tags (rowid, tag)
          SELECT rowid, ? FROM data
          WHERE sort_datetime(${safeCol}) >= ? AND sort_datetime(${safeCol}) <= ?
            AND ${safeCol} IS NOT NULL AND ${safeCol} != ''
        `).run(name, fromTs, toTs);
        taggedCount += result.changes;
      }
    });
    tx();
    return { taggedCount };
  }

  /**
   * Count the rows a filtered bulk tag/bookmark would touch, WITHOUT writing.
   * The renderer uses this to confirm before an operation that would sweep the
   * whole tab, and to label the action with a real number instead of the grid's
   * current `totalFiltered` (which is not always the same population).
   */
  countFiltered(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    try {
      const params = [];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);
      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      const count = meta.db.prepare(`SELECT COUNT(*) AS cnt FROM data ${whereClause}`).get(...params)?.cnt || 0;
      return { count, scoped: whereConditions.length > 0, totalRows: meta.rowCount };
    } catch (e) {
      dbg("DB", `countFiltered error`, { tabId, error: e.message });
      return { count: 0, scoped: false, totalRows: meta.rowCount, error: e.message };
    }
  }

  /**
   * Bulk tag all rows matching current filters.
   * Uses INSERT...SELECT — never materializes rowIds in JS.
   *
   * `options.confirmWholeTab` must be set when the filter set resolves to the
   * ENTIRE tab. Without it an all-empty filter object (the default state of the
   * Bulk Actions modal, and any caller that forgets to pass its scope) silently
   * tags every row in the file.
   */
  bulkTagFiltered(tabId, tag, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { tagged: 0, error: "Unknown tab" };
    const name = normalizeTagName(tag);
    if (!name) return { tagged: 0, error: "Empty tag name" };

    try {
      const db = meta.db;
      const params = [];
      const whereConditions = [];
      const { confirmWholeTab = false, ...filterOptions } = options || {};
      this._applyStandardFilters(filterOptions, meta, whereConditions, params);

      // Guard against silently tagging EVERY row when a caller passes an UNRECOGNIZED filter shape
      // (e.g. a typo'd `{ filters: [...] }`) that _applyStandardFilters drops, or when the caller
      // simply never scoped the operation at all.
      if (whereConditions.length === 0) {
        const RECOGNIZED = new Set(["columnFilters", "checkboxFilters", "bookmarkedOnly", "tagFilter", "dateRangeFilters", "advancedFilters", "searchTerm", "searchMode", "searchCondition", "rowIdFilter", "excludedRowIds"]);
        const unknown = Object.keys(filterOptions || {}).filter((k) => !RECOGNIZED.has(k));
        if (unknown.length > 0) {
          return { tagged: 0, error: `Refused to tag: unrecognized filter option(s) [${unknown.join(", ")}] matched no rows (would have tagged the entire tab).` };
        }
        if (!confirmWholeTab) {
          return {
            tagged: 0,
            wholeTab: true,
            rowCount: meta.rowCount,
            error: `Refused to tag: no filter or selection is active, so this would tag all ${Number(meta.rowCount || 0).toLocaleString()} rows. Re-run with confirmWholeTab to proceed.`,
          };
        }
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      const result = db.prepare(`INSERT OR IGNORE INTO tags (rowid, tag) SELECT data.rowid, ? FROM data ${whereClause}`).run(name, ...params);
      this._invalidateCountCache(tabId);
      return { tagged: result.changes, tag: name };
    } catch (e) {
      dbg("DB", `bulkTagFiltered error`, { tabId, error: e.message });
      return { tagged: 0, error: e.message };
    }
  }

  /**
   * Remove one tag from all rows matching the current filters.
   * The mirror of bulkTagFiltered — without it, an over-broad bulk tag can only
   * be undone by deleting the tag everywhere.
   */
  bulkUntagFiltered(tabId, tag, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { untagged: 0, error: "Unknown tab" };
    const name = existingTagName(tag);
    if (!name) return { untagged: 0, error: "Empty tag name" };

    try {
      const db = meta.db;
      const params = [];
      const whereConditions = [];
      const { confirmWholeTab: _ignored, ...filterOptions } = options || {};
      this._applyStandardFilters(filterOptions, meta, whereConditions, params);
      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      // Removal is non-destructive to the underlying data and always recoverable by
      // re-tagging, so it does not need the whole-tab confirmation gate that adding does.
      const result = db.prepare(
        `DELETE FROM tags WHERE tag = ? AND rowid IN (SELECT data.rowid FROM data ${whereClause})`
      ).run(name, ...params);
      this._invalidateCountCache(tabId);
      return { untagged: result.changes, tag: name };
    } catch (e) {
      dbg("DB", `bulkUntagFiltered error`, { tabId, error: e.message });
      return { untagged: 0, error: e.message };
    }
  }

  /**
   * Bulk bookmark (or un-bookmark) all rows matching current filters.
   * Uses INSERT...SELECT / DELETE...SELECT — never materializes rowIds in JS.
   */
  bulkBookmarkFiltered(tabId, add, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { affected: 0 };

    try {
      const db = meta.db;
      const params = [];
      const whereConditions = [];
      const { confirmWholeTab = false, ...filterOptions } = options || {};
      this._applyStandardFilters(filterOptions, meta, whereConditions, params);

      // Adding bookmarks to an unscoped view marks the entire file — same footgun as
      // bulkTagFiltered. Removing is always allowed (it is the recovery path).
      if (add && whereConditions.length === 0 && !confirmWholeTab) {
        return {
          affected: 0,
          wholeTab: true,
          rowCount: meta.rowCount,
          error: `Refused to bookmark: no filter or selection is active, so this would bookmark all ${Number(meta.rowCount || 0).toLocaleString()} rows. Re-run with confirmWholeTab to proceed.`,
        };
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
    } catch (e) {
      dbg("DB", `bulkBookmarkFiltered error`, { tabId, error: e.message });
      return { affected: 0, error: e.message };
    }
  }

}

module.exports = TagStoreMethods.prototype;
module.exports.normalizeTagName = normalizeTagName;
module.exports.normalizeRowIdList = normalizeRowIdList;
module.exports.existingTagName = existingTagName;
