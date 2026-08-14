const { parentPort, workerData } = require("worker_threads");
const TimelineDB = require("../db");
const { sendWorkerResult } = require("./worker-result");

let cancelled = false;

parentPort.on("message", (message = {}) => {
  if (message.type === "cancel") cancelled = true;
});

function progress(payload) {
  parentPort.postMessage({ type: "progress", progress: { jobId: workerData.jobId, tabId: workerData.tabId, ...payload } });
}

(async () => {
  const { tabId, descriptor, task } = workerData;
  const db = new TimelineDB();
  try {
    db.adoptTabFromFile(tabId, descriptor);
    if (cancelled) throw Object.assign(new Error("Job cancelled"), { cancelled: true });

    let result;
    if (task === "indexes") {
      result = await db.buildIndexesAsync(tabId, (p) => progress({ phase: "indexes", ...p }));
    } else if (task === "fts") {
      result = await db.buildFtsAsync(tabId, (p) => progress({ phase: "fts", ...p }));
    } else {
      throw new Error(`Unknown index task: ${task}`);
    }

    const out = {
      task,
      tabId,
      ...(result || {}),
      descriptor: db.getTabWorkerDescriptor(tabId),
    };
    db.releaseTab(tabId);
    db.closeAll();
    sendWorkerResult(parentPort, out);
  } catch (err) {
    try { db.releaseTab(tabId); } catch {}
    try { db.closeAll(); } catch {}
    if (err?.cancelled) {
      process.exit(1);
      return;
    }
    sendWorkerResult(parentPort, { task, tabId, error: err?.message || "Index job failed" });
  }
})();
