const { dbg } = require("../logger");
const { servicingChurnSqlClause, classifyPath } = require("../utils/path-class");

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Synthesize an incident verdict from the assembled heatmap result. PURE (no DB/clock) so it is
 * unit-testable and deterministic.
 *
 * DESIGN — the $SI activity axis is forgeable, so this never asserts more than the evidence supports:
 *   • `severity` reflects the IMPACT of the most suspicious activity (volume + content + deletions).
 *   • `confidence` reflects EVIDENTIARY STRENGTH and is gated separately: 'corroborated' only when a
 *     forgery-resistant USN/EVTX companion backs a flagged window; 'low' when timestomping is suspected
 *     (the $SI driving this view may be forged); 'weak' when companions are loaded but don't corroborate;
 *     'observed' for single-source $SI with no companion. The narrative always states this.
 *   • MITRE entries are candidate techniques tagged with their own confidence, not assertions.
 *
 * @param o {{ suspiciousWindows, usnDeletionWindows, correlation, bucketSize }}
 */
function _buildActivityVerdict(o) {
  const wins = (o && o.suspiciousWindows) || [];
  const usnDel = (o && o.usnDeletionWindows) || [];
  const corr = (o && o.correlation) || {};
  const tz = "UTC";

  if (wins.length === 0 && usnDel.length === 0) {
    return {
      severity: "info", severityScore: 0, confidence: "none",
      headline: "No anomalous file-activity bursts detected above threshold.",
      narrative: "File creation/modification activity shows no statistically anomalous bursts in the analyzed $MFT timeline. This view is built on $STANDARD_INFORMATION ($SI) timestamps, which are user-settable — the absence of a burst here does not rule out timestomped or low-volume activity. Corroborate with the USN journal and EVTX.",
      factors: [], mitre: [],
    };
  }

  const top = wins[0] || null;
  const anyTimestomp = wins.some((w) => w.timestompSuspected);
  const isCorr = (w) => !!(w && w.corroboration && (w.corroboration.level === "strong" || w.corroboration.level === "corroborated"));
  // Confidence must reflect the HEADLINE (top) window's backing — a corroborated LOWER-ranked window
  // must never launder a single-source $SI top burst as "corroborated".
  const topCorroborated = isCorr(top);
  const lowerCorroborated = !topCorroborated && wins.some((w) => w !== top && isCorr(w));
  // Base the freed-records signal on the TOP window (consistent with risky-ext) rather than summing
  // across windows — created and modified windows overlap on the same files and would double-count.
  const topFreed = top ? (top.deletedCount || 0) : 0;
  const usnDeleteTotal = usnDel.reduce((s, w) => s + (w.count || 0), 0);

  const factors = [];
  const mitre = [];
  let score = 0;

  if (top) {
    const cnt = top.count || 0;
    const mode = top.mode || "modified";
    score += Math.min(30, cnt / 50);
    if (top.weekend || top.offHours) {
      const when = [top.weekend ? "weekend" : null, top.offHours ? "off-hours" : null].filter(Boolean).join(" / ");
      score += 8;
      factors.push({ label: `Off-hours burst (${when})`, detail: `${cnt.toLocaleString()} ${mode} files in ${top.bucket} ${tz}`, severity: "medium" });
    } else {
      factors.push({ label: "Activity burst", detail: `${cnt.toLocaleString()} ${mode} files in ${top.bucket} ${tz}`, severity: "low" });
    }
    if (cnt > 0 && (top.riskyExtensionCount || 0) > 0) {
      const ratio = top.riskyExtensionCount / cnt;
      score += Math.min(20, ratio * 30);
      factors.push({ label: "Executable / script concentration", detail: `${top.riskyExtensionCount.toLocaleString()} risky-extension files (${Math.round(ratio * 100)}%) in the top window`, severity: ratio >= 0.3 ? "high" : "medium" });
      // Ingress/staging are creation-time behaviors — only emit for a creation-axis window (modified
      // executables are not ingress). Tagged as candidates, observed-confidence.
      if (mode === "created") {
        mitre.push({ technique: "T1105", name: "Ingress Tool Transfer", confidence: "observed", evidence: "executable/script files created in a concentrated burst (candidate)" });
        if (cnt >= 200) mitre.push({ technique: "T1074", name: "Data Staged", confidence: "observed", evidence: "large file-creation burst in a single window (candidate)" });
      }
    }
  }

  if (anyTimestomp) {
    score += 12;
    factors.push({ label: "Possible timestomping", detail: "Elevated zeroed-sub-second / SI<FN density — the $SI timestamps driving this view may be forged", severity: "high" });
    mitre.push({ technique: "T1070.006", name: "Indicator Removal: Timestomp", confidence: "observed", evidence: "zeroed sub-second $SI timestamps in a flagged window" });
  }

  if (usnDeleteTotal > 0) {
    // USN FileDelete is forgery-resistant and stamped at the deletion moment, so mass destruction is
    // high-impact even when the (deletion-blind) $SI axis surfaced no burst.
    score += Math.min(20, usnDeleteTotal / 100);
    if (usnDeleteTotal >= 1000) score += 35;          // mass destruction (corroborated T1485) → at least high
    if (usnDeleteTotal >= 50000) score += 20;         // catastrophic volume → critical
    factors.push({ label: "Deletion activity (USN-confirmed)", detail: `${usnDeleteTotal.toLocaleString()} FileDelete events across ${usnDel.length} window(s) — timestamped at the moment of deletion`, severity: "high" });
    mitre.push({ technique: "T1070.004", name: "Indicator Removal: File Deletion", confidence: "corroborated", evidence: "USN journal FileDelete events" });
    if (usnDeleteTotal >= 1000) mitre.push({ technique: "T1485", name: "Data Destruction", confidence: "corroborated", evidence: "mass USN FileDelete activity" });
  } else if (topFreed > 0) {
    score += Math.min(8, topFreed / 100);
    factors.push({ label: "Freed MFT records", detail: `${topFreed.toLocaleString()} not-in-use records whose $SI falls in the top window — NOT confirmed in-window deletions (true deletion time lives in the USN journal)`, severity: "low" });
  }

  if (topCorroborated) {
    factors.push({ label: "Cross-artifact corroboration", detail: "The top window is backed by forgery-resistant USN/EVTX evidence", severity: "info" });
  } else if (lowerCorroborated) {
    factors.push({ label: "Corroboration (lower-ranked window)", detail: "A lower-ranked window is USN/EVTX-corroborated; the top window remains single-source $SI", severity: "info" });
  }

  score = Math.min(100, Math.round(score));
  const severity = score >= 70 ? "critical" : score >= 45 ? "high" : score >= 25 ? "medium" : score >= 10 ? "low" : "info";

  // Confidence reflects the trustworthiness of the HEADLINE claim — the top window, or the USN deletion
  // lane when there is no $SI burst. Timestomping caps it at 'low' (the $SI may be forged).
  const usnOnly = !top && usnDeleteTotal > 0;
  let confidence, confNote;
  if (anyTimestomp) { confidence = "low"; confNote = "the $SI timestamps in the top window may be forged (possible timestomping)"; }
  else if (topCorroborated) { confidence = "corroborated"; confNote = "the top window is corroborated by forgery-resistant USN/EVTX evidence"; }
  else if (usnOnly) { confidence = "corroborated"; confNote = "this verdict rests on forgery-resistant USN journal FileDelete events"; }
  else if (corr.usnAvailable || corr.evtxAvailable) { confidence = "weak"; confNote = "companion USN/EVTX tabs are loaded but do not corroborate the top window"; }
  else { confidence = "observed"; confNote = "single-source $SI only — load a USN ($J) or EVTX companion tab to corroborate"; }

  const cap = severity.toUpperCase();
  const topCnt = top ? (top.count || 0) : 0;
  const topMode = top ? (top.mode || "modified") : "";
  const topDesc = top
    ? `${topCnt.toLocaleString()} ${topMode} files in ${top.bucket} ${tz}${(top.riskyExtensionCount || 0) > 0 && topCnt > 0 ? ` (${Math.round((top.riskyExtensionCount / topCnt) * 100)}% risky-ext)` : ""}`
    : `${usnDeleteTotal.toLocaleString()} USN deletions`;
  const headline = `${cap} (${confidence}): ${top ? (top.weekend || top.offHours ? "off-hours file-activity burst" : "file-activity burst") : "USN deletion activity"} — ${topDesc}.`;

  const bits = [];
  bits.push(top
    ? `Top window: ${top.bucket} ${tz} with ${topCnt.toLocaleString()} ${topMode} files (suspicion score ${top.score ?? "n/a"}).`
    : `USN journal recorded ${usnDeleteTotal.toLocaleString()} deletions across ${usnDel.length} window(s) — the $SI activity axis is deletion-blind and shows no corresponding burst.`);
  if (top && top.corroboration) {
    const c = top.corroboration;
    if (c.usn && c.usn.total > 0) bits.push(`USN corroborates this window with ${c.usn.total.toLocaleString()} operation(s) (${c.usn.fileDelete} delete, ${c.usn.contentWrite} content-write, ${c.usn.fileCreate} create).`);
    if (c.evtx && c.evtx.processCreations > 0) bits.push(`${c.evtx.processCreations.toLocaleString()} EVTX process-creation event(s) occur in the same window.`);
  }
  if (lowerCorroborated) bits.push("A lower-ranked window is USN/EVTX-corroborated, but the top window above is not — treat the headline as single-source $SI.");
  if (usnDeleteTotal > 0 && top) bits.push(`Separately, the USN journal shows ${usnDeleteTotal.toLocaleString()} forgery-resistant FileDelete event(s) the $SI axis cannot time.`);
  bits.push(`Confidence is ${confidence} — ${confNote}. Activity timings are derived from $SI timestamps, which are user-settable; corroborate flagged windows with the Timestomping Detector ($SI vs $FN), the USN journal, and EVTX before relying on them.`);

  return { severity, severityScore: score, confidence, headline, narrative: bits.join(" "), factors, mitre };
}

/**
 * File Activity Heatmap — analyzes file creation and modification patterns
 * across the MFT, returning hourly/daily buckets and a day-of-week × hour matrix.
 *
 * @param meta  the raw-MFT tab meta ({ db, colMap, rowCount, ... }).
 * @param opts  either a bare progress callback (legacy) or an options bag
 *              { progressCb, usnMeta, evtxMeta }. usnMeta/evtxMeta are companion
 *              tab metas used for forgery-resistant cross-artifact corroboration (Tier 4).
 */
function getFileActivityHeatmap(meta, opts) {
  const o = typeof opts === "function" ? { progressCb: opts } : (opts || {});
  const _p = typeof o.progressCb === "function" ? o.progressCb : () => {};
  const usnMeta = o.usnMeta || null;
  const evtxMeta = o.evtxMeta || null;
  const zeroMatrix = () => Array.from({ length: 7 }, () => new Array(24).fill(0));
  const empty = {
    createdBuckets: [],
    modifiedBuckets: [],
    combinedBuckets: [],
    totalCreated: 0,
    totalModified: 0,
    timeRange: {
      earliest: null,
      latest: null,
      createdEarliest: null,
      createdLatest: null,
      modifiedEarliest: null,
      modifiedLatest: null,
      focusEarliest: null,
      focusLatest: null,
    },
    bucketSize: "hourly",
    peakCreated: null,
    peakModified: null,
    peakCombined: null,
    dowHourMatrix: zeroMatrix(),
    dowHourByMonth: {},
    createdDowHourMatrix: zeroMatrix(),
    modifiedDowHourMatrix: zeroMatrix(),
    combinedDowHourMatrix: zeroMatrix(),
    createdDowHourByMonth: {},
    modifiedDowHourByMonth: {},
    combinedDowHourByMonth: {},
    suspiciousWindows: [],
    usnDeletionWindows: [],
    correlation: { usnAvailable: false, evtxAvailable: false },
    // Always carry a verdict (the no-activity verdict carries the $SI caveat) so the caveat is never
    // absent from any non-error result shape.
    verdict: _buildActivityVerdict({ suspiciousWindows: [], usnDeletionWindows: [], correlation: { usnAvailable: false, evtxAvailable: false } }),
  };
  if (!meta) return empty;

  const db = meta.db;
  const col = (name) => meta.colMap[name];
  const created = col("Created0x10"), modified = col("LastModified0x10"), isDir = col("IsDirectory");
  const pp = col("ParentPath"), ext = col("Extension"), inUse = col("InUse");
  const siFn = col("SI<FN"), uSec = col("uSecZeros");
  if (!created && !modified) return { ...empty, error: "No timestamp columns found (Created0x10, LastModified0x10)." };

  const notDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";
  // Pad an hourly/daily window's upper bound so the final second's sub-second rows (MFT/USN/EVTX
  // timestamps carry .fffffff) are included by the inclusive string BETWEEN in window enrichment.
  const padHi = (t) => (t && !String(t).includes(".") ? t + ".9999999" : t);

  try {
    // Row-count preflight: surface dataset scale up front so a scan over a 30-50GB $MFT never
    // reads as a hang (progress otherwise only ticks between phases).
    const totalRows = meta.rowCount || 0;
    _p({ stage: "range", pct: 0, detail: totalRows ? `Scanning ${totalRows.toLocaleString()} MFT records` : "Detecting time range" });
    // MFT timestamps are emitted already-canonical and lexically sortable (parsers/mft.js
    // filetimeToIso → "yyyy-MM-dd HH:MM:SS.fffffff"), so the sort_datetime() UDF is a verified
    // no-op here (runtime-functions.js returns the string unchanged for this format). Operating on
    // the raw column avoids hundreds of millions of per-row C++/JS UDF crossings across the scans.
    const norm19 = (s) => (s ? String(s).slice(0, 19) : null);
    const getRangeFor = (tsSafe) => tsSafe
      ? (db.prepare(`SELECT MIN(${tsSafe}) as earliest, MAX(${tsSafe}) as latest FROM data WHERE ${tsSafe} IS NOT NULL AND ${tsSafe} != '' ${notDir}`).get() || {})
      : {};
    const createdRange = getRangeFor(created);
    const modifiedRange = getRangeFor(modified);
    const earliest = norm19([createdRange?.earliest, modifiedRange?.earliest].filter(Boolean).sort()[0] || null);
    const latest = norm19([createdRange?.latest, modifiedRange?.latest].filter(Boolean).sort().slice(-1)[0] || null);

    // Determine bucket size based on time span
    let bucketSize = "hourly";
    if (earliest && latest) {
      const spanDays = (new Date(latest) - new Date(earliest)) / 86400000;
      if (spanDays > 90) bucketSize = "daily";
    }
    const subLen = bucketSize === "daily" ? 10 : 13; // "yyyy-MM-dd" or "yyyy-MM-dd HH"

    const bucketToRange = (bucket) => {
      if (!bucket) return { from: null, to: null };
      if (bucketSize === "daily") {
        return { from: `${bucket} 00:00:00`, to: `${bucket} 23:59:59` };
      }
      return { from: `${bucket}:00:00`, to: `${bucket}:59:59` };
    };
    const bucketMeta = (bucket) => {
      const { from, to } = bucketToRange(bucket);
      const iso = bucketSize === "daily" ? `${bucket}T00:00:00Z` : `${bucket.replace(" ", "T")}:00:00Z`;
      const dt = new Date(iso);
      const dow = Number.isFinite(dt.getTime()) ? dt.getUTCDay() : null;
      const hour = bucketSize === "hourly" && Number.isFinite(dt.getTime()) ? dt.getUTCHours() : null;
      return {
        from,
        to,
        dow,
        hour,
        month: bucket ? bucket.slice(0, 7) : "",
        weekend: dow === 0 || dow === 6,
        offHours: hour !== null ? (hour < 6 || hour >= 22) : false,
      };
    };
    const mergeBucketSeries = (seriesList) => {
      const merged = new Map();
      for (const series of seriesList) {
        for (const row of series || []) {
          const cur = merged.get(row.bucket) || { bucket: row.bucket, count: 0 };
          cur.count += row.count || 0;
          merged.set(row.bucket, cur);
        }
      }
      return Array.from(merged.values()).sort((a, b) => a.bucket.localeCompare(b.bucket));
    };
    const addMatrixInto = (target, source) => {
      for (let dow = 0; dow < 7; dow++) {
        for (let hour = 0; hour < 24; hour++) {
          target[dow][hour] += source[dow][hour];
        }
      }
    };
    const buildMatrix = (tsSafe) => {
      const matrix = zeroMatrix();
      const byMonth = {};
      if (!tsSafe) return { matrix, byMonth };
      // Group by the hour-prefix of the raw (canonical) column, then derive month / hour and the
      // day-of-week in JS via getUTCDay() — the SAME path bucketMeta uses — so the matrix and the
      // suspicious-window timing never diverge, and we avoid strftime()-over-UDF per row.
      const rows = db.prepare(
        `SELECT SUBSTR(${tsSafe}, 1, 13) as hb, COUNT(*) as count FROM data WHERE ${tsSafe} IS NOT NULL AND ${tsSafe} != '' ${notDir} GROUP BY hb`
      ).all();
      for (const r of rows) {
        const hb = r.hb;
        if (!hb || hb.length < 13) continue;
        const hour = parseInt(hb.slice(11, 13), 10);
        if (!(hour >= 0 && hour < 24)) continue;
        const dt = new Date(hb.slice(0, 10) + "T00:00:00Z");
        if (!Number.isFinite(dt.getTime())) continue;
        const dow = dt.getUTCDay();
        if (dow < 0 || dow > 6) continue;
        const ym = hb.slice(0, 7);
        matrix[dow][hour] += r.count;
        if (!byMonth[ym]) byMonth[ym] = zeroMatrix();
        byMonth[ym][dow][hour] += r.count;
      }
      return { matrix, byMonth };
    };
    const combineByMonth = (left, right) => {
      const months = new Set([...Object.keys(left || {}), ...Object.keys(right || {})]);
      const out = {};
      for (const month of months) {
        out[month] = zeroMatrix();
        if (left?.[month]) addMatrixInto(out[month], left[month]);
        if (right?.[month]) addMatrixInto(out[month], right[month]);
      }
      return out;
    };
    const median = (values) => {
      if (!values || values.length === 0) return 0;
      const sorted = [...values].sort((a, b) => a - b);
      const mid = Math.floor(sorted.length / 2);
      return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
    };
    const buildFocusRange = (buckets) => {
      if (!earliest || !latest || !buckets || buckets.length < 6) return { focusEarliest: earliest, focusLatest: latest };
      const total = buckets.reduce((sum, b) => sum + (b.count || 0), 0);
      if (total <= 0) return { focusEarliest: earliest, focusLatest: latest };
      const lowTarget = total * 0.02;
      const highTarget = total * 0.98;
      let acc = 0;
      let lowBucket = buckets[0].bucket;
      let highBucket = buckets[buckets.length - 1].bucket;
      let lowSet = false;
      for (const bucket of buckets) {
        acc += bucket.count || 0;
        if (!lowSet && acc >= lowTarget) {
          lowBucket = bucket.bucket;
          lowSet = true;
        }
        if (acc >= highTarget) {
          highBucket = bucket.bucket;
          break;
        }
      }
      return {
        focusEarliest: bucketToRange(lowBucket).from || earliest,
        focusLatest: bucketToRange(highBucket).to || latest,
      };
    };

    _p({ stage: "created", pct: 15, detail: "Aggregating created timestamps" });
    // Q2: Created activity buckets
    let createdBuckets = [];
    let totalCreated = 0;
    if (created) {
      createdBuckets = db.prepare(`SELECT SUBSTR(${created}, 1, ${subLen}) as bucket, COUNT(*) as count FROM data WHERE ${created} IS NOT NULL AND ${created} != '' ${notDir} GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`).all();
      const tc = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${created} IS NOT NULL AND ${created} != '' ${notDir}`).get();
      totalCreated = tc?.cnt || 0;
    }

    _p({ stage: "modified", pct: 35, detail: "Aggregating modified timestamps" });
    // Q3: Modified activity buckets
    let modifiedBuckets = [];
    let totalModified = 0;
    if (modified) {
      modifiedBuckets = db.prepare(`SELECT SUBSTR(${modified}, 1, ${subLen}) as bucket, COUNT(*) as count FROM data WHERE ${modified} IS NOT NULL AND ${modified} != '' ${notDir} GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`).all();
      const tm = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${modified} IS NOT NULL AND ${modified} != '' ${notDir}`).get();
      totalModified = tm?.cnt || 0;
    }

    const combinedBuckets = mergeBucketSeries([createdBuckets, modifiedBuckets]);
    const focusRange = buildFocusRange(combinedBuckets);

    _p({ stage: "matrix", pct: 55, detail: "Building day-of-week patterns" });
    // Q4: Day-of-week × hour-of-day matrices
    const createdMatrixData = buildMatrix(created);
    const modifiedMatrixData = buildMatrix(modified);
    const combinedDowHourMatrix = zeroMatrix();
    addMatrixInto(combinedDowHourMatrix, createdMatrixData.matrix);
    addMatrixInto(combinedDowHourMatrix, modifiedMatrixData.matrix);
    const combinedDowHourByMonth = combineByMonth(createdMatrixData.byMonth, modifiedMatrixData.byMonth);

    _p({ stage: "suspicious", pct: 75, detail: "Analyzing suspicious windows" });
    // Q5: Rank suspicious windows with analyst context
    const riskyExts = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".jar",".com",".lnk"];
    const riskyExtPlaceholders = riskyExts.map(() => "LOWER(?)").join(",");
    const churnClause = servicingChurnSqlClause(pp);
    const buildSuspiciousWindows = (mode, buckets, tsSafe) => {
      if (!tsSafe || !buckets || buckets.length === 0) return [];
      const counts = buckets.map((b) => b.count || 0);
      const med = median(counts);
      const mad = median(counts.map((v) => Math.abs(v - med))) || 1;
      const maxCount = Math.max(...counts, 1);
      // Tier 2 correctness floors: on a quiet/sparse MFT the median is ~0 and MAD clamps to 1, so
      // robust-Z explodes and tiny buckets flood the list. Require an absolute minimum volume per
      // window, bail out entirely when even the busiest bucket is below it, and gate the non-Z
      // admission on an absolute files/minute rate rather than a fraction of the (often benign) max.
      const MIN_WINDOW_FILES = bucketSize === "daily" ? 50 : 10;
      // High-volume safety valve, expressed per-bucket so it scales with bucket width (a per-minute
      // rate divided by 1440 made the daily branch unreachable). baseScore is the primary gate.
      const HIGH_VOLUME_FILES = bucketSize === "daily" ? 2000 : 480;
      if (maxCount < MIN_WINDOW_FILES) return [];
      const dirStmt = pp ? db.prepare(`SELECT ${pp} as path, COUNT(*) as count FROM data WHERE ${tsSafe} BETWEEN ? AND ? ${notDir} GROUP BY ${pp} ORDER BY count DESC, path LIMIT 3`) : null;
      const extStmt = ext ? db.prepare(`SELECT COALESCE(NULLIF(${ext}, ''), '(no extension)') as ext, COUNT(*) as count FROM data WHERE ${tsSafe} BETWEEN ? AND ? ${notDir} GROUP BY COALESCE(NULLIF(${ext}, ''), '(no extension)') ORDER BY count DESC, ext LIMIT 5`) : null;
      const riskyStmt = ext ? db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${tsSafe} BETWEEN ? AND ? AND LOWER(COALESCE(${ext}, '')) IN (${riskyExtPlaceholders}) ${notDir}`) : null;
      const deletedStmt = inUse ? db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${tsSafe} BETWEEN ? AND ? AND ${inUse} = 'False' ${notDir}`) : null;
      // Tier 5: $SI-vs-$FN tamper signal — the precomputed SI<FN / uSecZeros flags reveal whether the
      // very $SI timestamps driving this chart may be forged inside the window.
      const tamperStmt = (siFn || uSec) ? db.prepare(`SELECT ${siFn ? `SUM(CASE WHEN ${siFn} = 'True' THEN 1 ELSE 0 END)` : "0"} AS siFnCount, ${uSec ? `SUM(CASE WHEN ${uSec} = 'True' THEN 1 ELSE 0 END)` : "0"} AS uSecCount FROM data WHERE ${tsSafe} BETWEEN ? AND ? ${notDir}`) : null;
      // Tier 6: count files in the window that live in OS/servicing-churn trees (WinSxS, Windows
      // Update, etc.) so the score can be down-weighted — Windows Update bursts must not out-rank attacker activity.
      const systemStmt = pp ? db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${tsSafe} BETWEEN ? AND ? AND ${churnClause} ${notDir}`) : null;
      // Phase 1: Base scoring (robustZ + timing)
      const candidates = buckets.map((bucket) => {
        const metaInfo = bucketMeta(bucket.bucket);
        const robustZ = ((bucket.count || 0) - med) / (1.4826 * mad || 1);
        let baseScore = Math.max(0, robustZ);
        if (metaInfo.weekend) baseScore += 0.6;
        if (metaInfo.offHours) baseScore += 0.4;
        if ((bucket.count || 0) >= maxCount * 0.5) baseScore += 0.25;
        return {
          mode,
          column: mode === "created" ? "Created0x10" : "LastModified0x10",
          bucket: bucket.bucket,
          count: bucket.count || 0,
          baseScore,
          zScore: Math.round(robustZ * 100) / 100,
          weekend: metaInfo.weekend,
          offHours: metaInfo.offHours,
          from: metaInfo.from,
          to: metaInfo.to,
          month: metaInfo.month,
        };
      }).filter((w) => {
        if (w.count < MIN_WINDOW_FILES) return false;          // absolute floor — kills quiet-MFT noise
        return w.baseScore >= 1.25 || w.count >= HIGH_VOLUME_FILES;
      });

      // Phase 2: Enrich with context + incorporate into final score
      return candidates.map((window) => {
        const hi = padHi(window.to);
        const riskyExtensionCount = riskyStmt ? (riskyStmt.get(window.from, hi, ...riskyExts)?.cnt || 0) : 0;
        const deletedCount = deletedStmt ? (deletedStmt.get(window.from, hi)?.cnt || 0) : 0;
        const tc = tamperStmt ? (tamperStmt.get(window.from, hi) || {}) : {};
        const siFnCount = tc.siFnCount || 0;
        const uSecZerosCount = tc.uSecCount || 0;
        const systemChurnCount = systemStmt ? (systemStmt.get(window.from, hi)?.cnt || 0) : 0;
        const r2 = (n) => Math.round(n * 100) / 100;
        let siFnRatio = 0, systemRatio = 0, uSecRatio = 0, riskyBoost = 0, deletedBoost = 0, siFnBoost = 0, churnFactor = 1;
        if (window.count > 0) {
          siFnRatio = siFnCount / window.count;
          uSecRatio = uSecZerosCount / window.count;
          systemRatio = systemChurnCount / window.count;
          riskyBoost = r2((riskyExtensionCount / window.count) * 0.5);
          deletedBoost = r2((deletedCount / window.count) * 0.3);
          siFnBoost = r2(siFnRatio * 0.4);                     // timestomping in the window raises suspicion
          churnFactor = r2(1 - 0.85 * systemRatio);
        }
        // Tier 7: a self-consistent, analyst-addable score decomposition. Every operand is rounded and the
        // totals are derived FROM those rounded operands, so the printed equation closes exactly. Servicing/
        // OS-update churn down-weights ONLY the benign baseline; independent malice signals (risky exts,
        // freed records, timestomping) are added AFTER dampening, so a payload masquerading in a servicing
        // tree is never buried by its location.
        const zContribution = Math.max(0, window.zScore);     // z only contributes when above the median
        const weekendBonus = window.weekend ? 0.6 : 0;
        const offHoursBonus = window.offHours ? 0.4 : 0;
        const volumeBonus = window.count >= maxCount * 0.5 ? 0.25 : 0;
        const baseline = r2(zContribution + weekendBonus + offHoursBonus + volumeBonus);
        const baselineDamped = r2(baseline * churnFactor);
        const total = r2(baselineDamped + riskyBoost + deletedBoost + siFnBoost);
        // Zeroed sub-seconds are the stronger timestomp signal (tools often write whole-second times),
        // so gate the alert on uSecZeros density; bare SI<FN density alone is expected from benign
        // bulk-copy / archive extraction (copied files preserve their original $SI modified time).
        const timestompSuspected = window.count > 0 && (uSecRatio >= 0.25 || (siFnRatio >= 0.5 && uSecZerosCount > 0));
        const dirs = dirStmt ? dirStmt.all(window.from, hi) : [];
        const scoreBreakdown = {
          robustZ: window.zScore,
          zContribution,
          weekendBonus, offHoursBonus, volumeBonus,
          baseline, churnFactor, baselineDamped,
          riskyBoost, deletedBoost, siFnBoost,
          total,
          admissionThreshold: 1.25,
          admittedBy: window.baseScore >= 1.25 ? "statistical-outlier" : "high-volume",
        };
        return {
          ...window,
          score: total,
          topDirectories: dirs.map((dd) => ({ ...dd, class: classifyPath(dd.path) })),
          topExtensions: extStmt ? extStmt.all(window.from, hi) : [],
          riskyExtensionCount,
          deletedCount,
          siFnCount,
          uSecZerosCount,
          timestompSuspected,
          systemChurnCount,
          systemRatio: r2(systemRatio),
          scoreBreakdown,
        };
      }).sort((a, b) => b.score - a.score || b.count - a.count)
        .slice(0, 8)
        .map(({ baseScore, ...rest }) => rest);
    };
    const suspiciousWindows = [
      ...buildSuspiciousWindows("created", createdBuckets, created),
      ...buildSuspiciousWindows("modified", modifiedBuckets, modified),
    ].sort((a, b) => b.score - a.score || b.count - a.count).slice(0, 12);

    // Tier 7: minute-level burst profile for the top windows — turns a coarse "busy hour/day" into
    // "peak N files/min at HH:MM, active over M minutes" so the analyst can localize the actual burst.
    const PROFILE_TOP = 8;
    for (let i = 0; i < suspiciousWindows.length && i < PROFILE_TOP; i++) {
      const win = suspiciousWindows[i];
      const tsForMode = win.mode === "created" ? created : modified;
      if (!tsForMode) continue;
      try {
        const minuteRows = db.prepare(
          `SELECT extract_datetime_minute(${tsForMode}) as m, COUNT(*) as count FROM data WHERE ${tsForMode} BETWEEN ? AND ? ${notDir} GROUP BY m HAVING m IS NOT NULL ORDER BY m`
        ).all(win.from, padHi(win.to));
        if (minuteRows.length) {
          const peak = minuteRows.reduce((a, b) => (b.count > a.count ? b : a), minuteRows[0]);
          win.minuteProfile = { peakPerMin: peak.count, peakMinute: peak.m, activeMinutes: minuteRows.length };
        }
      } catch { /* minute profile is best-effort (UDF may be absent) */ }
    }

    // Anchor focus range to top suspicious windows (so benign churn doesn't dominate)
    if (suspiciousWindows.length > 0) {
      const topWins = suspiciousWindows.slice(0, 3);
      const winFrom = topWins.map((w) => w.from).filter(Boolean).sort()[0];
      const winTo = topWins.map((w) => w.to).filter(Boolean).sort().slice(-1)[0];
      if (winFrom && focusRange.focusEarliest && winFrom < focusRange.focusEarliest) focusRange.focusEarliest = winFrom;
      if (winTo && focusRange.focusLatest && winTo > focusRange.focusLatest) focusRange.focusLatest = winTo;
    }

    // ── Tier 4: cross-artifact corroboration. The $SI activity axis is forgeable, so corroborate
    // each top suspicious window against the forgery-resistant USN journal ($J) and EVTX
    // process-creation events when companion tabs are open. Companion timestamps may carry
    // fractional seconds, so queries wrap both sides in sort_datetime() and pad the upper bound.
    // Every companion access is wrapped in try/catch — a companion failure never breaks the MFT result.
    let usnDeletionWindows = [];
    const correlation = { usnAvailable: false, evtxAvailable: false };

    let usnCtx = null;
    if (usnMeta && usnMeta.db && usnMeta.colMap) {
      const uTs = usnMeta.colMap["UpdateTimestamp"], uReasons = usnMeta.colMap["UpdateReasons"];
      if (uTs && uReasons) {
        usnCtx = { db: usnMeta.db, ts: uTs, reasons: uReasons, srcInfo: usnMeta.colMap["SourceInfo"], attrs: usnMeta.colMap["FileAttributes"] };
        correlation.usnAvailable = true;
      }
    }
    let evtxCtx = null;
    if (evtxMeta && evtxMeta.db) {
      try {
        const { _rwResolveEvtxCols } = require("./ransomware");
        const cols = _rwResolveEvtxCols(evtxMeta);
        if (cols && cols.ts && cols.eid) { evtxCtx = { db: evtxMeta.db, ...cols }; correlation.evtxAvailable = true; }
      } catch { /* ransomware helper unavailable — skip EVTX */ }
    }

    if (usnCtx || evtxCtx) {
      _p({ stage: "correlate", pct: 90, detail: "Corroborating windows against USN/EVTX" });

      let usnWindowStmt = null;
      if (usnCtx) {
        try {
          usnWindowStmt = usnCtx.db.prepare(
            `SELECT
               SUM(CASE WHEN ${usnCtx.reasons} LIKE '%FileCreate%' THEN 1 ELSE 0 END) AS fileCreate,
               SUM(CASE WHEN (${usnCtx.reasons} LIKE '%DataOverwrite%' OR ${usnCtx.reasons} LIKE '%DataExtend%') THEN 1 ELSE 0 END) AS contentWrite,
               SUM(CASE WHEN ${usnCtx.reasons} LIKE '%FileDelete%' THEN 1 ELSE 0 END) AS fileDelete,
               SUM(CASE WHEN ${usnCtx.reasons} LIKE '%RenameNewName%' THEN 1 ELSE 0 END) AS renameNew,
               COUNT(*) AS total
             FROM data WHERE sort_datetime(${usnCtx.ts}) BETWEEN sort_datetime(?) AND sort_datetime(?)`
          );
        } catch { usnWindowStmt = null; }
      }
      let evtxWindowStmt = null, evtxSampleStmt = null;
      if (evtxCtx) {
        const chanClause = evtxCtx.channel ? ` AND (LOWER(${evtxCtx.channel}) LIKE '%sysmon%' OR LOWER(${evtxCtx.channel}) LIKE '%sec%')` : "";
        const blob = (evtxCtx.textCols && evtxCtx.textCols.length)
          ? evtxCtx.textCols.map((c) => `COALESCE(${c},'')`).join("||' '||")
          : (evtxCtx.proc && evtxCtx.proc.image ? `COALESCE(${evtxCtx.proc.image},'')` : "''");
        try {
          evtxWindowStmt = evtxCtx.db.prepare(
            `SELECT COUNT(*) AS cnt FROM data WHERE CAST(${evtxCtx.eid} AS TEXT) IN ('1','4688')${chanClause} AND sort_datetime(${evtxCtx.ts}) BETWEEN sort_datetime(?) AND sort_datetime(?)`
          );
          evtxSampleStmt = evtxCtx.db.prepare(
            `SELECT SUBSTR(${blob}, 1, 200) AS text FROM data WHERE CAST(${evtxCtx.eid} AS TEXT) IN ('1','4688')${chanClause} AND sort_datetime(${evtxCtx.ts}) BETWEEN sort_datetime(?) AND sort_datetime(?) ORDER BY sort_datetime(${evtxCtx.ts}) ASC, rowid LIMIT 5`
          );
        } catch { evtxWindowStmt = null; evtxSampleStmt = null; }
      }

      const CORRELATE_TOP = 8;
      for (let i = 0; i < suspiciousWindows.length && i < CORRELATE_TOP; i++) {
        const win = suspiciousWindows[i];
        const fromB = win.from, toB = padHi(win.to);
        let usn = null, evtx = null;
        if (usnWindowStmt && fromB && toB) {
          try {
            const r = usnWindowStmt.get(fromB, toB) || {};
            usn = { fileCreate: r.fileCreate || 0, contentWrite: r.contentWrite || 0, fileDelete: r.fileDelete || 0, renameNew: r.renameNew || 0, total: r.total || 0 };
          } catch { usn = null; }
        }
        if (evtxWindowStmt && fromB && toB) {
          try {
            const c = evtxWindowStmt.get(fromB, toB) || {};
            const processCreations = c.cnt || 0;
            let sampleProcesses = [];
            if (processCreations > 0 && evtxSampleStmt) {
              try { sampleProcesses = evtxSampleStmt.all(fromB, toB).map((x) => (x.text || "").trim()).filter(Boolean); } catch { /* sample best-effort */ }
            }
            evtx = { processCreations, sampleProcesses };
          } catch { evtx = null; }
        }
        // USN is the forgery-resistant cross-check (its timestamps reflect the actual NTFS
        // operations); EVTX process-creation adds an execution signal. A window the $SI axis
        // flagged but neither artifact corroborates is explicitly marked 'uncorroborated'.
        let level = "none";
        if (usnCtx || evtxCtx) {
          const usnHit = !!(usn && usn.total > 0);
          const evtxHit = !!(evtx && evtx.processCreations > 0);
          level = usnHit && evtxHit ? "strong" : (usnHit || evtxHit ? "corroborated" : "uncorroborated");
        }
        win.corroboration = { usn, evtx, level };
      }

      // Deletion lane: the $SI axis cannot show WHEN files were deleted (a deleted record keeps its
      // original $SI times). USN FileDelete events ARE stamped at the deletion moment, so surface
      // deletion-activity windows straight from the journal. SourceInfo='' / non-directory gates cut
      // OS/defrag/replication noise.
      if (usnCtx) {
        try {
          const srcGate = usnCtx.srcInfo ? `AND (${usnCtx.srcInfo} IS NULL OR ${usnCtx.srcInfo} = '')` : "";
          const dirGate = usnCtx.attrs ? `AND (${usnCtx.attrs} IS NULL OR ${usnCtx.attrs} NOT LIKE '%Directory%')` : "";
          const delRows = usnCtx.db.prepare(
            `SELECT SUBSTR(${usnCtx.ts}, 1, ${subLen}) AS bucket, COUNT(*) AS count
             FROM data WHERE ${usnCtx.reasons} LIKE '%FileDelete%' AND ${usnCtx.ts} IS NOT NULL AND ${usnCtx.ts} != '' ${srcGate} ${dirGate}
             GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY count DESC, bucket LIMIT 8`
          ).all();
          usnDeletionWindows = delRows
            .map((r) => { const range = bucketToRange(r.bucket); return { bucket: r.bucket, from: range.from, to: range.to, count: r.count, userDriven: !!usnCtx.srcInfo }; })
            .sort((a, b) => (a.bucket < b.bucket ? -1 : a.bucket > b.bucket ? 1 : 0));
        } catch { usnDeletionWindows = []; }
      }
    }

    _p({ stage: "peaks", pct: 95, detail: "Computing results" });
    // Find peaks
    const peakCreated = createdBuckets.reduce((best, b) => (!best || b.count > best.count) ? b : best, null);
    const peakModified = modifiedBuckets.reduce((best, b) => (!best || b.count > best.count) ? b : best, null);
    const peakCombined = combinedBuckets.reduce((best, b) => (!best || b.count > best.count) ? b : best, null);

    return {
      createdBuckets,
      modifiedBuckets,
      combinedBuckets,
      totalCreated,
      totalModified,
      timeRange: {
        earliest,
        latest,
        createdEarliest: norm19(createdRange?.earliest) || null,
        createdLatest: norm19(createdRange?.latest) || null,
        modifiedEarliest: norm19(modifiedRange?.earliest) || null,
        modifiedLatest: norm19(modifiedRange?.latest) || null,
        focusEarliest: focusRange.focusEarliest,
        focusLatest: focusRange.focusLatest,
      },
      bucketSize,
      peakCreated,
      peakModified,
      peakCombined,
      dowHourMatrix: createdMatrixData.matrix,
      dowHourByMonth: createdMatrixData.byMonth,
      createdDowHourMatrix: createdMatrixData.matrix,
      modifiedDowHourMatrix: modifiedMatrixData.matrix,
      combinedDowHourMatrix,
      createdDowHourByMonth: createdMatrixData.byMonth,
      modifiedDowHourByMonth: modifiedMatrixData.byMonth,
      combinedDowHourByMonth,
      suspiciousWindows,
      usnDeletionWindows,
      correlation,
      verdict: _buildActivityVerdict({ suspiciousWindows, usnDeletionWindows, correlation, bucketSize }),
    };
  } catch (err) {
    return { ...empty, error: err.message };
  }
}

module.exports = { getFileActivityHeatmap, _buildActivityVerdict };
