/** Runtime measurements attached to every qualified AI-history extraction. */

const PERFORMANCE_METRICS_VERSION = 1;

function finiteNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function createPerformanceMeter({ tool = "", sourceCoverage = [], sampleIntervalMs = 25 } = {}) {
  const startedNs = process.hrtime.bigint();
  const startedRss = process.memoryUsage().rss;
  let peakRss = startedRss;
  let firstResultNs = null;
  let rowsObserved = 0;
  let stopped = false;
  const sampler = setInterval(() => {
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
  }, Math.max(10, Number(sampleIntervalMs) || 25));
  sampler.unref?.();

  function observeRows(rows) {
    const count = Array.isArray(rows) ? rows.length : finiteNumber(rows);
    if (count <= 0) return;
    if (firstResultNs == null) firstResultNs = process.hrtime.bigint();
    rowsObserved += count;
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
  }

  function finish({ parseStats = {}, rows = 0, canceled = false } = {}) {
    if (!stopped) clearInterval(sampler);
    stopped = true;
    observeRows(rows);
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
    const endedNs = process.hrtime.bigint();
    const wallTimeMs = Number(endedNs - startedNs) / 1e6;
    const sourceBytesEligible = (sourceCoverage || []).reduce(
      (sum, entry) => sum + finiteNumber(entry?.sizeBytes),
      0,
    );
    const bytesReadObserved = finiteNumber(parseStats.bytesRead);
    const seconds = Math.max(wallTimeMs / 1000, 0.000001);
    return {
      version: PERFORMANCE_METRICS_VERSION,
      tool,
      canceled: !!canceled,
      wallTimeMs: Math.round(wallTimeMs * 1000) / 1000,
      firstResultLatencyMs: firstResultNs == null
        ? null
        : Math.round((Number(firstResultNs - startedNs) / 1e6) * 1000) / 1000,
      rows: rowsObserved,
      rowsPerSecond: Math.round((rowsObserved / seconds) * 1000) / 1000,
      bytesReadObserved,
      sourceBytesEligible,
      mibPerSecond: Math.round(((bytesReadObserved / (1024 * 1024)) / seconds) * 1000) / 1000,
      rssStartBytes: startedRss,
      rssEndBytes: process.memoryUsage().rss,
      peakRssBytes: peakRss,
      peakRssDeltaBytes: Math.max(0, peakRss - startedRss),
      sourceCount: (sourceCoverage || []).length,
      rssSampleIntervalMs: Math.max(10, Number(sampleIntervalMs) || 25),
    };
  }

  return { observeRows, finish };
}

function mergePerformanceMetrics(metrics) {
  const entries = (metrics || []).filter(Boolean);
  if (!entries.length) return null;
  const wallTimeMs = entries.reduce((sum, item) => sum + finiteNumber(item.wallTimeMs), 0);
  const rows = entries.reduce((sum, item) => sum + finiteNumber(item.rows), 0);
  const bytesReadObserved = entries.reduce((sum, item) => sum + finiteNumber(item.bytesReadObserved), 0);
  return {
    version: PERFORMANCE_METRICS_VERSION,
    scopes: entries.length,
    wallTimeMs: Math.round(wallTimeMs * 1000) / 1000,
    firstResultLatencyMs: entries.reduce((min, item) => {
      const value = item.firstResultLatencyMs;
      return value == null ? min : (min == null ? value : Math.min(min, value));
    }, null),
    rows,
    rowsPerSecond: wallTimeMs > 0 ? Math.round((rows / (wallTimeMs / 1000)) * 1000) / 1000 : 0,
    bytesReadObserved,
    mibPerSecond: wallTimeMs > 0
      ? Math.round(((bytesReadObserved / (1024 * 1024)) / (wallTimeMs / 1000)) * 1000) / 1000
      : 0,
    sourceBytesEligible: entries.reduce((sum, item) => sum + finiteNumber(item.sourceBytesEligible), 0),
    peakRssBytes: Math.max(...entries.map((item) => finiteNumber(item.peakRssBytes))),
    peakRssDeltaBytes: Math.max(...entries.map((item) => finiteNumber(item.peakRssDeltaBytes))),
    sourceCount: entries.reduce((sum, item) => sum + finiteNumber(item.sourceCount), 0),
    children: entries,
  };
}

module.exports = {
  PERFORMANCE_METRICS_VERSION,
  createPerformanceMeter,
  mergePerformanceMetrics,
};
