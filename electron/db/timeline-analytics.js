const { parseTimestampMs } = require("../utils/parse-timestamp");
const { fillHistogramGaps } = require("./histogram-buckets");

/**
 * Timeline analytics methods mixed into TimelineDB.
 */
class TimelineAnalyticsMethods {
  /**
   * Get histogram data for a timestamp column (event density over time).
   * Groups by UTC day/hour via extract_date / extract_datetime_minute (which
   * drop Windows FILETIME-epoch sentinels) and fills empty buckets so the
   * x-axis matches the TimeCreated span instead of a sparse date list.
   */
  getHistogramData(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    const safeCol = meta.colMap[colName];
    if (!safeCol) return [];
    const { granularity = "day" } = options;
    const db = meta.db;
    const params = [];
    const whereConditions = [`${safeCol} IS NOT NULL`, `${safeCol} != ''`];
    this._applyStandardFilters(options, meta, whereConditions, params);
    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;
    const extractFn = granularity === "hour" ? `substr(extract_datetime_minute(${safeCol}), 1, 13)` : `extract_date(${safeCol})`;
    // Keep the NULL bucket so FILETIME-epoch rows can be counted as omittedUnset
    // instead of silently disappearing from the histogram.
    const sql = `SELECT ${extractFn} as day, COUNT(*) as cnt FROM data ${whereClause} GROUP BY day ORDER BY day`;
    // Cache histogram results — same filters often redraw without data changes
    const histoSig = safeCol + "|" + granularity + "|" + whereClause + "|" + JSON.stringify(params);
    if (meta._histoCache && meta._histoCache.sig === histoSig) return meta._histoCache.data;
    try {
      const raw = db.prepare(sql).all(...params);
      let omittedUnset = 0;
      const dated = [];
      for (const r of raw) {
        if (r.day == null || r.day === "") omittedUnset += r.cnt;
        else dated.push(r);
      }
      const data = fillHistogramGaps(dated, granularity);
      data.omittedUnset = omittedUnset;
      meta._histoCache = { sig: histoSig, data };
      return data;
    } catch (err) { console.error(`Histogram query failed: ${err.message}`); return []; }
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
    const db = meta.db;
    const params = [];
    const whereConditions = [`${safeCol} IS NOT NULL`, `${safeCol} != ''`];
    this._applyStandardFilters(options, meta, whereConditions, params);
    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;
    const sql = `SELECT extract_datetime_minute(${safeCol}) as mb, COUNT(*) as cnt FROM data ${whereClause} GROUP BY mb HAVING mb IS NOT NULL ORDER BY mb`;
    try {
      const buckets = db.prepare(sql).all(...params);
      if (buckets.length === 0) return { gaps: [], sessions: [], totalEvents: 0 };
      const totalEvents = buckets.reduce((s, b) => s + b.cnt, 0);
      const thresholdMs = gapThresholdMinutes * 60000;
      // Minute bucket strings (`YYYY-MM-DD HH:MM`) are naive — treat as UTC
      // for consistency with rest of analyzer pipeline.
      const parseMin = (mb) => parseTimestampMs(mb + ":00");
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

    const db = meta.db;
    const params = [];
    const whereConditions = [
      `${safeSourceCol} IS NOT NULL`, `${safeSourceCol} != ''`,
      `${safeTsCol} IS NOT NULL`, `${safeTsCol} != ''`,
    ];
    this._applyStandardFilters(options, meta, whereConditions, params);

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

    const db = meta.db;
    const params = [];
    const whereConditions = [`${safeCol} IS NOT NULL`, `${safeCol} != ''`];
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;

    try {
      // Step 1: Get minute-level buckets (same as gap analysis)
      const sql = `SELECT extract_datetime_minute(${safeCol}) as mb, COUNT(*) as cnt FROM data ${whereClause} GROUP BY mb HAVING mb IS NOT NULL ORDER BY mb`;
      const minuteBuckets = db.prepare(sql).all(...params);

      if (minuteBuckets.length === 0) {
        return { bursts: [], baseline: 0, windowMinutes, totalEvents: 0, totalWindows: 0 };
      }

      const totalEvents = minuteBuckets.reduce((s, b) => s + b.cnt, 0);
      // Minute bucket strings (`YYYY-MM-DD HH:MM`) are naive — treat as UTC
      // for consistency with rest of analyzer pipeline.
      const parseMin = (mb) => parseTimestampMs(mb + ":00");

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
    const isTagCol = colName === "__tags__";
    const safeCol = isTagCol ? null : meta.colMap[colName];
    if (!isTagCol && !safeCol) return { totalRows: 0, totalUnique: 0, values: [] };
    const { filterText = "", sortBy = "count" } = options;
    const db = meta.db;
    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);
    if (!isTagCol && filterText.trim()) {
      whereConditions.push(`${safeCol} LIKE ?`); params.push(`%${filterText}%`);
    }
    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const orderBy = sortBy === "value" ? `val ASC` : `cnt DESC, val ASC`;
    const MAX_STACKING_VALUES = 10000;
    try {
      if (isTagCol) {
        // Tags stacking: query from tags table joined with data filters
        const filterParams = [...params];
        const joinWhere = whereClause ? `${whereClause} AND data.rowid = tags.rowid` : `WHERE data.rowid = tags.rowid`;
        let tagWhere = joinWhere;
        if (filterText.trim()) {
          tagWhere = `${joinWhere} AND tag LIKE ?`;
          filterParams.push(`%${filterText}%`);
        }
        // Single GROUP BY query with LIMIT+1 to detect truncation
        const sql = `SELECT tag as val, COUNT(*) as cnt FROM tags, data ${tagWhere} GROUP BY tag ORDER BY ${orderBy} LIMIT ${MAX_STACKING_VALUES + 1}`;
        const rawValues = db.prepare(sql).all(...filterParams);
        const truncated = rawValues.length > MAX_STACKING_VALUES;
        const values = truncated ? rawValues.slice(0, MAX_STACKING_VALUES) : rawValues;
        let totalRows = 0;
        for (let i = 0; i < values.length; i++) totalRows += values[i].cnt;
        let totalUnique = values.length;
        if (truncated) {
          // Rare case: >10K unique tags — need exact counts
          const stats = db.prepare(`SELECT COUNT(DISTINCT data.rowid) as totalRows, COUNT(DISTINCT tag) as totalUnique FROM tags, data ${tagWhere}`).get(...filterParams);
          totalRows = stats?.totalRows || totalRows;
          totalUnique = stats?.totalUnique || totalUnique;
        }
        return { totalRows, totalUnique, values, truncated };
      }
      // Single GROUP BY query with LIMIT+1 to detect truncation — avoids 2 extra COUNT scans
      const sql = `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${safeCol} ORDER BY ${orderBy} LIMIT ${MAX_STACKING_VALUES + 1}`;
      const rawValues = db.prepare(sql).all(...params);
      const truncated = rawValues.length > MAX_STACKING_VALUES;
      const values = truncated ? rawValues.slice(0, MAX_STACKING_VALUES) : rawValues;
      let totalRows = 0;
      for (let i = 0; i < values.length; i++) totalRows += values[i].cnt;
      let totalUnique = values.length;
      if (truncated) {
        // Rare case: >10K unique values — need exact counts (single scan instead of 2)
        const stats = db.prepare(`SELECT COUNT(*) as totalRows, COUNT(DISTINCT ${safeCol}) as totalUnique FROM data ${whereClause}`).get(...params);
        totalRows = stats?.totalRows || totalRows;
        totalUnique = stats?.totalUnique || totalUnique;
      }
      return { totalRows, totalUnique, values, truncated };
    } catch { return { totalRows: 0, totalUnique: 0, values: [], truncated: false }; }
  }

}

module.exports = TimelineAnalyticsMethods.prototype;
