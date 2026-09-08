/**
 * triage-discover-worker.js — walk a KAPE/triage folder off the main thread.
 * Started by ipc/triage-handlers.js ("triage-discover").
 *
 * workerData: { root, jobId, cancelBuffer }
 * Progress rides `triage-discover-progress`; the terminal result is the manifest.
 */
const { parentPort, workerData } = require("worker_threads");
const { discoverTriageCollection } = require("../analyzers/triage-collection");
const { sendWorkerResult } = require("./worker-result");

let cancelled = false;
parentPort.on("message", (message = {}) => {
  if (message.type === "cancel") cancelled = true;
});
const cancelView = workerData.cancelBuffer ? new Int32Array(workerData.cancelBuffer) : null;

function isCancelled() {
  if (cancelled || (cancelView && Atomics.load(cancelView, 0) === 1)) {
    throw Object.assign(new Error("Triage discovery cancelled"), { cancelled: true });
  }
}

function progress(payload) {
  parentPort.postMessage({ type: "progress", progress: { jobId: workerData.jobId, ...payload } });
}

(async () => {
  try {
    isCancelled();
    const result = await discoverTriageCollection(workerData.root, {
      onProgress: (p) => progress({
        phase: p.phase || "scanning",
        scanned: p.scanned || 0,
        classified: p.classified || 0,
        percent: p.scanned ? Math.min(99, Math.round((p.classified / Math.max(p.scanned, 1)) * 100)) : 0,
        statusDetail: p.scanned
          ? `Scanned ${Number(p.scanned).toLocaleString()} files · ${Number(p.classified || 0).toLocaleString()} artifacts`
          : "Scanning collection",
      }),
      isCancelled,
    });
    sendWorkerResult(parentPort, result);
  } catch (err) {
    if (err?.cancelled) {
      progress({ phase: "cancelled", done: true });
      process.exit(1);
      return;
    }
    sendWorkerResult(parentPort, { error: err?.message || "Triage discovery failed", stack: err?.stack });
  }
})();
