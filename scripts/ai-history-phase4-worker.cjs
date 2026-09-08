"use strict";

const crypto = require("node:crypto");
const { parentPort, workerData } = require("node:worker_threads");

const { extractAiHistory } = require("../electron/parsers/ai-history");
const { AiHistoryExtractAbortedError } = require("../electron/parsers/ai-history/extract-abort");

const cancelView = workerData.cancelBuffer ? new Int32Array(workerData.cancelBuffer) : null;

function checkAbort() {
  if (cancelView && Atomics.load(cancelView, 0) === 1) throw new AiHistoryExtractAbortedError();
}

function hashRows(hash, rows) {
  for (const row of rows || []) hash.update(JSON.stringify(row)).update("\n");
}

(async () => {
  const startedNs = process.hrtime.bigint();
  const rssStart = process.memoryUsage().rss;
  let peakRss = rssStart;
  let firstResultNs = null;
  let rowCount = 0;
  const rowHash = crypto.createHash("sha256");
  const coverage = [];
  const parserMetrics = [];
  const acquisitions = [];
  const sample = setInterval(() => { peakRss = Math.max(peakRss, process.memoryUsage().rss); }, 20);
  sample.unref?.();
  const observe = (rows) => {
    if (!rows?.length) return;
    if (firstResultNs == null) firstResultNs = process.hrtime.bigint();
    rowCount += rows.length;
    hashRows(rowHash, rows);
    checkAbort();
  };

  try {
    for (const item of workerData.cases || []) {
      checkAbort();
      const rows = await extractAiHistory(item.tool, item.target, { user: "phase4", host: "reference" }, {
        includeSubagents: true,
        skipSubagents: false,
        skipFinalize: true,
        onExtractedRows: observe,
        checkAbort,
        findLocalAttachments: item.findLocalAttachments === true,
        includeUserFolders: item.includeUserFolders === true,
        home: item.home,
      });
      if (rows?.length) observe(rows);
      if (rows?._sourceCoverage) coverage.push(...rows._sourceCoverage);
      if (rows?._performance) parserMetrics.push(rows._performance);
      if (Array.isArray(rows?._cursorComposerStats?.acquisitions)) {
        acquisitions.push(...rows._cursorComposerStats.acquisitions);
      }
      for (const stats of [rows?._codexStateSqliteStats, rows?._codexThreadHistoryStats]) {
        if (stats?.acquisition) acquisitions.push(stats.acquisition);
      }
    }
    clearInterval(sample);
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
    const endedNs = process.hrtime.bigint();
    const wallTimeMs = Number(endedNs - startedNs) / 1e6;
    const coverageHash = crypto.createHash("sha256")
      .update(JSON.stringify(coverage.map((entry) => ({
        sourceFile: entry.sourceFile,
        status: entry.status,
        rows: entry.rows,
        errors: entry.errors,
        sizeBytes: entry.sizeBytes,
      })).sort((a, b) => a.sourceFile.localeCompare(b.sourceFile))))
      .digest("hex");
    parentPort.postMessage({
      ok: true,
      runtime: process.versions.electron ? `electron-${process.versions.electron}` : `node-${process.versions.node}`,
      wallTimeMs,
      firstResultLatencyMs: firstResultNs == null ? null : Number(firstResultNs - startedNs) / 1e6,
      rowCount,
      rowsPerSecond: rowCount / Math.max(wallTimeMs / 1000, 0.000001),
      rowHashSha256: rowHash.digest("hex"),
      coverageHashSha256: coverageHash,
      coverageCount: coverage.length,
      coverageStatusCounts: coverage.reduce((acc, entry) => {
        acc[entry.status] = (acc[entry.status] || 0) + 1;
        return acc;
      }, {}),
      bytesReadObserved: parserMetrics.reduce((sum, item) => sum + Number(item.bytesReadObserved || 0), 0),
      sourceBytesEligible: parserMetrics.reduce((sum, item) => sum + Number(item.sourceBytesEligible || 0), 0),
      rssStartBytes: rssStart,
      rssEndBytes: process.memoryUsage().rss,
      peakRssBytes: peakRss,
      peakRssDeltaBytes: Math.max(0, peakRss - rssStart),
      parserMetrics,
      acquisitions,
    });
  } catch (error) {
    clearInterval(sample);
    parentPort.postMessage({
      ok: false,
      canceled: !!(error?.canceled || error?.cancelled),
      error: error?.message || String(error),
      wallTimeMs: Number(process.hrtime.bigint() - startedNs) / 1e6,
      peakRssBytes: Math.max(peakRss, process.memoryUsage().rss),
      peakRssDeltaBytes: Math.max(0, Math.max(peakRss, process.memoryUsage().rss) - rssStart),
    });
  }
})();
