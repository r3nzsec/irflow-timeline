/**
 * Send the terminal result for a one-shot worker and release its parent port.
 *
 * Every job worker installs a cancellation listener on parentPort. Leaving the
 * port referenced after the result keeps the worker's OS thread and V8 isolate
 * alive indefinitely, so terminal result delivery must also close the port.
 */
function sendWorkerResult(parentPort, result) {
  parentPort.postMessage({ type: "result", result });
  parentPort.close();
}

module.exports = { sendWorkerResult };
