const { PathAuthorizer } = require("../utils/path-authorizer");

function hasOwnValues(obj) {
  return obj && typeof obj === "object" && Object.keys(obj).length > 0;
}

function hasHeavyQueryOptions(options = {}) {
  return Boolean(
    options.sortCol ||
    String(options.searchTerm || "").trim() ||
    hasOwnValues(options.columnFilters) ||
    hasOwnValues(options.checkboxFilters) ||
    hasOwnValues(options.dateRangeFilters) ||
    (Array.isArray(options.advancedFilters) && options.advancedFilters.length > 0) ||
    (Array.isArray(options.groupFilters) && options.groupFilters.length > 0) ||
    (Array.isArray(options.rowIdFilter) && options.rowIdFilter.length > 0) ||
    options.bookmarkedOnly ||
    options.tagFilter ||
    options.groupCol ||
    options.groupValue !== undefined
  );
}

function applyWorkerDescriptors(db, descriptors = []) {
  for (const descriptor of descriptors) {
    const meta = db.databases?.get?.(descriptor.tabId);
    if (!meta) continue;
    if (Array.isArray(descriptor.indexedCols)) meta.indexedCols = new Set(descriptor.indexedCols);
    if (typeof descriptor.indexesReady === "boolean") meta.indexesReady = descriptor.indexesReady;
    if (typeof descriptor.ftsReady === "boolean") meta.ftsReady = descriptor.ftsReady;
    if (typeof descriptor.ftsCreated === "boolean") meta.ftsCreated = descriptor.ftsCreated;
  }
}

const QUERY_WORKER_CONCURRENCY = 2;

module.exports = function registerQueryHandlers(safeHandle, safeSend, { db, runAnalyzerJob, startAnalyzerJob, jobManager, _activeWindow }) {
  const analyze = (method, payload, fallback) => {
    if (runAnalyzerJob) return runAnalyzerJob(method, payload);
    return fallback();
  };

  const runQueryJob = async (method, payload, fallback, opts = {}) => {
    const tabIds = new Set();
    if (payload?.tabId) tabIds.add(payload.tabId);
    for (const id of payload?.tabIds || []) tabIds.add(id);
    const tabs = [...tabIds].map((tabId) => db.getTabWorkerDescriptor(tabId)).filter(Boolean);
    if (!jobManager || tabs.length === 0) return fallback();

    if (opts.cancelPrevious && payload?.tabId) {
      jobManager.cancelWhere((job) => (
        job.type === "query" &&
        job.metadata?.method === method &&
        job.metadata?.tabId === payload.tabId
      ));
    }

    const { promise } = jobManager.startWorkerJob({
      type: "query",
      worker: "query-worker.js",
      workerData: { method, payload, tabs },
      metadata: { method, tabId: payload?.tabId, tabIds: [...tabIds] },
      concurrencyKey: "query",
      maxConcurrent: QUERY_WORKER_CONCURRENCY,
      resourceClass: "light",
      // Row windows can contain tens of MB. The IPC caller owns the result after resolution;
      // retaining it in JobManager history caused completed scroll queries to exhaust V8 heap.
      retainResult: false,
    });
    const out = await promise;
    if (out?.error) throw new Error(out.error);
    applyWorkerDescriptors(db, out?.descriptors || []);
    return out?.result;
  };

  // Folders become scannable only by being chosen in a dialog — the renderer cannot name
  // an arbitrary path and have it read.
  const persistencePathAuthorizer = new PathAuthorizer();

  safeHandle("query-rows", (event, { tabId, options }) => {
    if (hasHeavyQueryOptions(options || {})) {
      return runQueryJob("queryRows", { tabId, options }, () => db.queryRows(tabId, options), { cancelPrevious: true });
    }
    return db.queryRows(tabId, options);
  });

  safeHandle("get-rows-by-ids", (event, { tabId, rowIds }) => {
    return runQueryJob("getRowsByIds", { tabId, rowIds }, () => db.getRowsByIds(tabId, rowIds));
  });

  safeHandle("get-row-ids-in-range", (event, { tabId, options }) => {
    return db.getRowIdsInRange(tabId, options);
  });

  safeHandle("count-rows-by-ids-matching", (event, { tabId, rowIds, options }) => {
    return db.countRowsByIdsMatching(tabId, rowIds, options);
  });

  safeHandle("find-search-match", (event, { tabId, options }) => {
    return db.findSearchMatch(tabId, options);
  });

  safeHandle("get-bookmarked-ids", (event, { tabId }) => {
    // This is a small indexed lookup used by the 30-second session autosave.
    // Running it in a fresh V8 isolate per tab creates needless worker churn.
    return db.getBookmarkedIds(tabId);
  });

  safeHandle("get-column-stats", (event, { tabId, colName, options }) => {
    return runQueryJob("getColumnStats", { tabId, colName, options }, () => db.getColumnStats(tabId, colName, options));
  });

  safeHandle("get-column-unique-values", (event, { tabId, colName, options }) => {
    return runQueryJob("getColumnUniqueValues", { tabId, colName, options }, () => db.getColumnUniqueValues(tabId, colName, options));
  });

  safeHandle("get-column-values", (event, { tabId, colName, options }) => {
    return runQueryJob("getColumnValues", { tabId, colName, options }, () => db.getColumnValues(tabId, colName, options));
  });

  safeHandle("get-empty-columns", (event, { tabId }) => {
    return runQueryJob("getEmptyColumns", { tabId }, () => db.getEmptyColumns(tabId));
  });

  safeHandle("get-group-values", (event, { tabId, groupCol, options }) => {
    return runQueryJob("getGroupValues", { tabId, groupCol, options }, () => db.getGroupValues(tabId, groupCol, options), { cancelPrevious: true });
  });

  safeHandle("get-tab-info", (event, { tabId }) => {
    return db.getTabInfo(tabId);
  });

  safeHandle("get-fts-status", (event, { tabId }) => {
    return db.getFtsStatus(tabId);
  });

  safeHandle("search-count", (event, { tabId, searchTerm, searchMode, searchCondition }) => {
    return runQueryJob("searchCount", { tabId, searchTerm, searchMode, searchCondition }, () => db.searchCount(tabId, searchTerm, searchMode, searchCondition), { cancelPrevious: true });
  });

  safeHandle("get-histogram-data", (event, { tabId, colName, options }) => {
    return runQueryJob("getHistogramData", { tabId, colName, options }, () => db.getHistogramData(tabId, colName, options), { cancelPrevious: true });
  });

  safeHandle("get-stacking-data", (event, { tabId, colName, options }) => {
    return runQueryJob("getStackingData", { tabId, colName, options }, () => db.getStackingData(tabId, colName, options));
  });

  safeHandle("get-gap-analysis", (event, { tabId, colName, gapThresholdMinutes, options }) => {
    return runQueryJob("getGapAnalysis", { tabId, colName, gapThresholdMinutes, options }, () => db.getGapAnalysis(tabId, colName, gapThresholdMinutes, options));
  });

  safeHandle("get-log-source-coverage", (event, { tabId, sourceCol, tsCol, options }) => {
    return runQueryJob("getLogSourceCoverage", { tabId, sourceCol, tsCol, options }, () => db.getLogSourceCoverage(tabId, sourceCol, tsCol, options));
  });

  safeHandle("get-burst-analysis", (event, { tabId, colName, windowMinutes, thresholdMultiplier, options }) => {
    return runQueryJob("getBurstAnalysis", { tabId, colName, windowMinutes, thresholdMultiplier, options }, () => db.getBurstAnalysis(tabId, colName, windowMinutes, thresholdMultiplier, options));
  });

  safeHandle("get-process-tree", (event, { tabId, options }) => {
    return analyze("getProcessTree", { tabId, options }, () => db.getProcessTree(tabId, options));
  });

  safeHandle("start-process-tree", (event, { tabId, options }) => {
    if (!startAnalyzerJob) {
      return { result: db.getProcessTree(tabId, options) };
    }

    const { jobId, promise } = startAnalyzerJob("getProcessTree", { tabId, options }, {
      metadata: { feature: "processTree" },
    });
    promise
      .then((result) => safeSend("process-tree-complete", { jobId, result }))
      .catch((err) => safeSend("process-tree-complete", {
        jobId,
        error: err?.message || "Process tree analysis failed",
        cancelled: !!err?.cancelled || /cancelled/i.test(String(err?.message || "")),
      }));
    return { jobId };
  });

  safeHandle("preview-process-tree", (event, { tabId, options }) => {
    return analyze("previewProcessTree", { tabId, options }, () => db.previewProcessTree(tabId, options));
  });

  safeHandle("get-process-inspector-context", (event, { tabId, options }) => {
    return analyze("getProcessInspectorContext", { tabId, options }, () => db.getProcessInspectorContext(tabId, options));
  });

  safeHandle("preview-lateral-movement", (event, { tabId, options }) => {
    return analyze("previewLateralMovement", { tabId, options }, () => db.previewLateralMovement(tabId, options));
  });

  safeHandle("detect-kape-collection-host", (event, { tabId }) => {
    return analyze("detectKapeCollectionHost", { tabId }, () => db.detectKapeCollectionHost(tabId));
  });

  safeHandle("get-lateral-movement", (event, { tabId, options }) => {
    return analyze("getLateralMovement", { tabId, options }, () => db.getLateralMovement(tabId, options));
  });

  safeHandle("get-multi-source-lateral-movement", (event, { tabIds, options }) => {
    return analyze("getMultiSourceLateralMovement", { tabIds, options }, () => db.getMultiSourceLateralMovement(tabIds, options));
  });

  safeHandle("preview-multi-source-lateral-movement", (event, { tabIds, options }) => {
    return analyze("previewMultiSourceLateralMovement", { tabIds, options }, () => db.previewMultiSourceLateralMovement(tabIds, options));
  });

  safeHandle("lateral-movement-load-triage", (event, { scope } = {}) => {
    const store = require("../analyzers/lateral-movement/triage-store");
    return store.loadLateralMovementTriage(scope || {});
  });

  safeHandle("lateral-movement-save-triage", (event, { scope, triageState } = {}) => {
    const store = require("../analyzers/lateral-movement/triage-store");
    return store.saveLateralMovementTriage(scope || {}, triageState || {});
  });

  safeHandle("lateral-movement-clear-triage", (event, { scope } = {}) => {
    const store = require("../analyzers/lateral-movement/triage-store");
    return store.clearLateralMovementTriage(scope || {});
  });

  safeHandle("preview-persistence-analysis", (event, { tabId, options }) => {
    return analyze("previewPersistenceAnalysis", { tabId, options }, () => db.previewPersistenceAnalysis(tabId, options));
  });

  safeHandle("get-persistence-analysis", (event, { tabId, options }) => {
    return analyze("getPersistenceAnalysis", { tabId, options }, () => db.getPersistenceAnalysis(tabId, options));
  });

  // Persistence ⇄ lateral-movement join: the graph, with each host annotated by what
  // persistence found there and by the pivot edges persistence can prove.
  safeHandle("get-persistence-pivot-join", (event, { tabIds, options }) => {
    return analyze("getPersistencePivotJoin", { tabIds, options }, () => db.getPersistencePivotJoin(tabIds, options));
  });

  // ── KAPE collection scans ────────────────────────────────────────────────
  // A folder the analyst picks in a dialog becomes an authorized scope; nothing else can
  // be scanned. Every path the scanner yields is additionally realpath-checked to be
  // inside that root (see analyzers/persistence/kape-collection.js), so a symlink planted
  // in evidence cannot walk out of it.
  safeHandle("select-kape-collection", async () => {
    const { dialog } = require("electron");
    const result = await dialog.showOpenDialog(_activeWindow ? _activeWindow() : null, {
      title: "Select a KAPE collection folder",
      properties: ["openDirectory"],
      buttonLabel: "Analyze Collection",
    });
    if (result.canceled || !result.filePaths[0]) return { canceled: true };
    const dir = result.filePaths[0];
    persistencePathAuthorizer.authorize("kape-collection", dir, { recursive: true, label: "KAPE collection", mustExist: true });
    const { scanCollection } = require("../analyzers/persistence/kape-collection");
    return { canceled: false, dir, scan: scanCollection(dir) };
  });

  safeHandle("scan-kape-collection", (event, { dir } = {}) => {
    const root = persistencePathAuthorizer.assertAuthorized("kape-collection", dir, { mustExist: true });
    const { scanCollection } = require("../analyzers/persistence/kape-collection");
    return scanCollection(root);
  });

  safeHandle("analyze-kape-collection", (event, { dir, options } = {}) => {
    const root = persistencePathAuthorizer.assertAuthorized("kape-collection", dir, { mustExist: true });
    if (!startAnalyzerJob) {
      const { analyzeCollection } = require("../analyzers/persistence/collection-analysis");
      return { result: analyzeCollection(root, options || {}, {}) };
    }
    const { jobId, promise } = startAnalyzerJob("analyzeKapeCollection", { dir: root, options }, {
      metadata: { feature: "persistence" },
    });
    promise
      .then((result) => safeSend("persistence-analysis-complete", { jobId, result }))
      .catch((err) => safeSend("persistence-analysis-complete", {
        jobId,
        error: err?.message || "Collection analysis failed",
        cancelled: !!err?.cancelled || /cancelled/i.test(String(err?.message || "")),
      }));
    return { jobId };
  });

  safeHandle("preview-multi-source-persistence", (event, { tabIds, options }) => {
    return analyze("previewMultiSourcePersistence", { tabIds, options }, () => db.previewMultiSourcePersistence(tabIds, options));
  });

  safeHandle("get-multi-source-persistence", (event, { tabIds, options }) => {
    return analyze("getMultiSourcePersistence", { tabIds, options }, () => db.getMultiSourcePersistence(tabIds, options));
  });

  // Job-handle variant for the multi-tab scan — same Cancel wiring as the single-tab one.
  safeHandle("start-multi-source-persistence", (event, { tabIds, options }) => {
    if (!startAnalyzerJob) {
      return { result: db.getMultiSourcePersistence(tabIds, options) };
    }

    const { jobId, promise } = startAnalyzerJob("getMultiSourcePersistence", { tabIds, options }, {
      metadata: { feature: "persistence" },
    });
    promise
      .then((result) => safeSend("persistence-analysis-complete", { jobId, result }))
      .catch((err) => safeSend("persistence-analysis-complete", {
        jobId,
        error: err?.message || "Persistence analysis failed",
        cancelled: !!err?.cancelled || /cancelled/i.test(String(err?.message || "")),
      }));
    return { jobId };
  });

  // Job-handle variant of the above. runAnalyzerJob() discards the job id, so a renderer
  // that used it had no way to stop the worker — "Cancel" could only hide the modal while
  // a full scan of a 500K-row tab ran to completion and threw its result away. Returning
  // the id lets the modal call jobs-cancel, exactly like start-process-tree.
  safeHandle("start-persistence-analysis", (event, { tabId, options }) => {
    if (!startAnalyzerJob) {
      return { result: db.getPersistenceAnalysis(tabId, options) };
    }

    const { jobId, promise } = startAnalyzerJob("getPersistenceAnalysis", { tabId, options }, {
      metadata: { feature: "persistence" },
    });
    promise
      .then((result) => safeSend("persistence-analysis-complete", { jobId, result }))
      .catch((err) => safeSend("persistence-analysis-complete", {
        jobId,
        error: err?.message || "Persistence analysis failed",
        cancelled: !!err?.cancelled || /cancelled/i.test(String(err?.message || "")),
      }));
    return { jobId };
  });

};
