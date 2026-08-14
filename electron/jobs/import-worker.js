const { parentPort, workerData } = require("worker_threads");
const TimelineDB = require("../db");
const { parseFile } = require("../parsers");
const { sendWorkerResult } = require("./worker-result");

let cancelled = false;

parentPort.on("message", (message = {}) => {
  if (message.type === "cancel") cancelled = true;
});

function progress(payload) {
  parentPort.postMessage({ type: "progress", progress: { jobId: workerData.jobId, tabId: workerData.tabId, ...payload } });
}

function cleanupAndExit(db, tabId) {
  try { db.releaseTab(tabId); } catch {}
  try { db.closeAll(); } catch {}
}

(async () => {
  const {
    filePath,
    tabId,
    sheetName,
    fileSize,
    dbPath,
  } = workerData;

  const db = new TimelineDB();
  try {
    if (cancelled) throw Object.assign(new Error("Import cancelled"), { cancelled: true });
    db._dbPathHint = dbPath;
    progress({ phase: "parsing", rowsImported: 0, bytesRead: 0, totalBytes: fileSize || 0, percent: 0 });

    const parsed = await parseFile(filePath, tabId, db, (rows, bytesRead, totalBytes, meta = {}) => {
      if (cancelled) throw Object.assign(new Error("Import cancelled"), { cancelled: true });
      const percent = Number.isFinite(meta.percentHint)
        ? Math.max(0, Math.min(100, meta.percentHint))
        : (totalBytes > 0 ? Math.round((bytesRead / totalBytes) * 100) : 0);
      progress({
        phase: meta.phase || "parsing",
        rowsImported: rows,
        bytesRead,
        totalBytes,
        percent,
        statusDetail: meta.statusDetail || "",
      });
    }, sheetName, fileSize);

    if (cancelled) throw Object.assign(new Error("Import cancelled"), { cancelled: true });
    progress({ phase: "finalizing", percent: 100 });
    const finalized = db.finalizeImport(tabId);
    const descriptor = db.getTabWorkerDescriptor(tabId);
    cleanupAndExit(db, tabId);

    sendWorkerResult(parentPort, {
      ...parsed,
      ...finalized,
      dbPath: descriptor.dbPath,
      isLargeFile: descriptor.isLargeFile,
      ftsReady: descriptor.ftsReady,
      indexesReady: descriptor.indexesReady,
      indexedCols: descriptor.indexedCols,
    });
  } catch (err) {
    cleanupAndExit(db, tabId);
    if (err?.cancelled) {
      progress({ phase: "cancelled", done: true });
      process.exit(1);
      return;
    }
    sendWorkerResult(parentPort, { error: err?.message || "Import failed", stack: err?.stack });
  }
})();
