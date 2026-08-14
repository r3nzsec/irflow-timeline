const { parentPort, workerData } = require("worker_threads");
const TimelineDB = require("../db");
const { sendWorkerResult } = require("./worker-result");

let cancelled = false;

parentPort.on("message", (message = {}) => {
  if (message.type === "cancel") cancelled = true;
});

function assertNotCancelled() {
  if (cancelled) throw Object.assign(new Error("Query cancelled"), { cancelled: true });
}

function runQuery(db, method, payload = {}) {
  const { tabId, options = {} } = payload;
  switch (method) {
    case "queryRows":
      return db.queryRows(tabId, options);
    case "getRowsByIds":
      return db.getRowsByIds(tabId, payload.rowIds);
    case "getBookmarkedIds":
      return db.getBookmarkedIds(tabId);
    case "getColumnStats":
      return db.getColumnStats(tabId, payload.colName, options);
    case "getColumnUniqueValues":
      return db.getColumnUniqueValues(tabId, payload.colName, options);
    case "getColumnValues":
      return db.getColumnValues(tabId, payload.colName, options);
    case "getEmptyColumns":
      return db.getEmptyColumns(tabId, options);
    case "getGroupValues":
      return db.getGroupValues(tabId, payload.groupCol, options);
    case "searchCount":
      return db.searchCount(tabId, payload.searchTerm, payload.searchMode, payload.searchCondition);
    case "getHistogramData":
      return db.getHistogramData(tabId, payload.colName, options);
    case "getStackingData":
      return db.getStackingData(tabId, payload.colName, options);
    case "getGapAnalysis":
      return db.getGapAnalysis(tabId, payload.colName, payload.gapThresholdMinutes, options);
    case "getLogSourceCoverage":
      return db.getLogSourceCoverage(tabId, payload.sourceCol, payload.tsCol, options);
    case "getBurstAnalysis":
      return db.getBurstAnalysis(tabId, payload.colName, payload.windowMinutes, payload.thresholdMultiplier, options);
    default:
      throw new Error(`Unknown query method: ${method}`);
  }
}

(async () => {
  const { method, payload = {}, tabs = [] } = workerData;
  const db = new TimelineDB();
  try {
    for (const descriptor of tabs) {
      db.adoptTabFromFile(descriptor.tabId, descriptor);
    }

    assertNotCancelled();
    const result = runQuery(db, method, payload);
    assertNotCancelled();

    const descriptors = tabs
      .map((descriptor) => db.getTabWorkerDescriptor(descriptor.tabId))
      .filter(Boolean);

    for (const descriptor of tabs) {
      try { db.releaseTab(descriptor.tabId); } catch {}
    }
    db.closeAll();

    sendWorkerResult(parentPort, { result, descriptors });
  } catch (err) {
    for (const descriptor of tabs) {
      try { db.releaseTab(descriptor.tabId); } catch {}
    }
    try { db.closeAll(); } catch {}
    if (err?.cancelled) {
      process.exit(1);
      return;
    }
    sendWorkerResult(parentPort, { error: err?.message || "Query failed", stack: err?.stack });
  }
})();
