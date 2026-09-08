/**
 * vhdx-extract-worker.js — copy the recognizable artifacts out of a VHDX image into a
 * scratch folder, off the main thread. Started by ipc/triage-handlers.js ("triage-open-vhdx").
 *
 * workerData: { vhdxPath, outDir, jobId, cancelBuffer }
 * Progress rides the job's `channels.progress` ("triage-vhdx-progress"); the terminal
 * result is the extractor's summary, or { error } on failure.
 */
const { parentPort, workerData } = require("worker_threads");
const { extractVhdxCollection } = require("../parsers/vhdx-triage");
const { sendWorkerResult } = require("./worker-result");

let cancelled = false;
parentPort.on("message", (message = {}) => {
  if (message.type === "cancel") cancelled = true;
});
const cancelView = workerData.cancelBuffer ? new Int32Array(workerData.cancelBuffer) : null;

function isCancelled() {
  if (cancelled || (cancelView && Atomics.load(cancelView, 0) === 1)) {
    throw Object.assign(new Error("VHDX extraction cancelled"), { cancelled: true });
  }
}

function progress(payload) {
  parentPort.postMessage({ type: "progress", progress: { jobId: workerData.jobId, ...payload } });
}

(async () => {
  try {
    isCancelled();
    const result = await extractVhdxCollection(workerData.vhdxPath, workerData.outDir, {
      onProgress: progress,
      isCancelled,
    });
    sendWorkerResult(parentPort, result);
  } catch (err) {
    if (err?.cancelled) {
      progress({ phase: "cancelled", done: true });
      process.exit(1);
      return;
    }
    sendWorkerResult(parentPort, { error: err?.message || "VHDX extraction failed", code: err?.code || null, stack: err?.stack });
  }
})();
