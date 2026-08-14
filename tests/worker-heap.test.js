"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const { Worker } = require("node:worker_threads");

const { JobManager } = require("../electron/jobs/job-manager");
const { workerResourceLimits, workerHeapMb, DEFAULT_WORKER_HEAP_MB } = require("../electron/utils/worker-heap");

async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`Condition was not met within ${timeoutMs}ms`);
}

test("workerResourceLimits sets a generous old-space cap for worker threads", () => {
  const prev = process.env.TLE_WORKER_HEAP_MB;
  delete process.env.TLE_WORKER_HEAP_MB;
  try {
    assert.deepEqual(workerResourceLimits(), { maxOldGenerationSizeMb: DEFAULT_WORKER_HEAP_MB });
    assert.equal(workerHeapMb(), DEFAULT_WORKER_HEAP_MB);
  } finally {
    if (prev != null) process.env.TLE_WORKER_HEAP_MB = prev;
    else delete process.env.TLE_WORKER_HEAP_MB;
  }
});

test("TLE_WORKER_HEAP_MB overrides default worker heap", () => {
  const prev = process.env.TLE_WORKER_HEAP_MB;
  process.env.TLE_WORKER_HEAP_MB = "12288";
  try {
    assert.deepEqual(workerResourceLimits(), { maxOldGenerationSizeMb: 12288 });
  } finally {
    if (prev != null) process.env.TLE_WORKER_HEAP_MB = prev;
    else delete process.env.TLE_WORKER_HEAP_MB;
  }
});

test("JobManager starts workers with resourceLimits instead of invalid execArgv heap flags", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-heap-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "ok-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort } = require("worker_threads");',
      'parentPort.postMessage({ type: "result", result: { ok: true } });',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const { promise } = manager.startWorkerJob({ type: "heap-smoke", worker: workerPath });
  assert.deepEqual(await promise, { ok: true });
});

test("JobManager rejects a worker that exits cleanly without a terminal result", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-no-result-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "no-result-worker.js");
  fs.writeFileSync(workerPath, '"use strict";\n');

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const { jobId, promise } = manager.startWorkerJob({ type: "no-result", worker: workerPath });

  await assert.rejects(promise, /before sending a terminal result \(code 0\)/);
  const job = manager.jobs.get(jobId);
  assert.equal(job?.status, "failed");
  assert.equal(job?.worker, null);
});

test("JobManager treats a non-zero exit without a result as failure, not cancellation", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-exit-failure-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "exit-failure-worker.js");
  fs.writeFileSync(workerPath, '"use strict";\nprocess.exit(7);\n');

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const { jobId, promise } = manager.startWorkerJob({ type: "exit-failure", worker: workerPath });

  await assert.rejects(promise, /before sending a terminal result \(code 7\)/);
  const job = manager.jobs.get(jobId);
  assert.equal(job?.status, "failed");
  assert.doesNotMatch(job?.error || "", /cancel/i);
});

test("JobManager rejects worker startup failures and never leaves them running", async () => {
  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const missingWorker = path.join(os.tmpdir(), `irflow-missing-worker-${Date.now()}.js`);
  const { jobId, promise } = manager.startWorkerJob({ type: "missing-worker", worker: missingWorker });

  await assert.rejects(promise, /Cannot find module|MODULE_NOT_FOUND/i);
  await waitFor(() => manager.jobs.get(jobId)?.worker === null);
  assert.equal(manager.jobs.get(jobId)?.status, "failed");
});

test("JobManager cancellation wins over a racing worker result", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-cancel-race-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "cancel-race-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort } = require("worker_threads");',
      'parentPort.on("message", () => {',
      '  parentPort.postMessage({ type: "result", result: { tooLate: true } });',
      '});',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const { jobId, promise } = manager.startWorkerJob({ type: "cancel-race", worker: workerPath });
  assert.deepEqual(manager.cancel(jobId), { ok: true });

  await assert.rejects(promise, (err) => err?.cancelled === true);
  assert.equal(manager.jobs.get(jobId)?.status, "cancelled");
});

test("JobManager exposes cancellation through a shared flag to synchronous workers", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-shared-cancel-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "shared-cancel-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { workerData } = require("worker_threads");',
      'const cancel = new Int32Array(workerData.cancelBuffer);',
      'while (Atomics.load(cancel, 0) === 0) {}',
      'process.exit(1);',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const { jobId, promise } = manager.startWorkerJob({ type: "shared-cancel", worker: workerPath });
  assert.deepEqual(manager.cancel(jobId), { ok: true });
  await assert.rejects(promise, (err) => err?.cancelled === true);
  assert.equal(manager.jobs.get(jobId)?.status, "cancelled");
});

test("JobManager delivers transient results without retaining the completed payload", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-transient-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "result-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort } = require("worker_threads");',
      'parentPort.on("message", () => {});',
      'parentPort.postMessage({ type: "result", result: { rows: ["large-query-payload"] } });',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const { jobId, promise } = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    retainResult: false,
  });

  assert.deepEqual(await promise, { rows: ["large-query-payload"] });
  await waitFor(() => !manager.jobs.has(jobId));
  assert.equal(manager.jobs.has(jobId), false);
  assert.equal(manager.list().some((job) => job.id === jobId), false);
});

test("sendWorkerResult closes a persistent parent port and exits cleanly", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-result-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "closing-worker.js");
  const resultHelperPath = path.join(__dirname, "../electron/jobs/worker-result.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort } = require("worker_threads");',
      `const { sendWorkerResult } = require(${JSON.stringify(resultHelperPath)});`,
      'parentPort.on("message", () => {});',
      'sendWorkerResult(parentPort, { ok: true });',
      "",
    ].join("\n"),
  );

  const worker = new Worker(workerPath);
  const exitPromise = once(worker, "exit");
  const [message] = await once(worker, "message");
  const [exitCode] = await exitPromise;

  assert.deepEqual(message, { type: "result", result: { ok: true } });
  assert.equal(exitCode, 0);
});

test("every cancellable one-shot worker closes its parent port through sendWorkerResult", () => {
  const jobsDir = path.join(__dirname, "../electron/jobs");
  const workerFiles = fs.readdirSync(jobsDir).filter((name) => name.endsWith("-worker.js"));

  for (const name of workerFiles) {
    const source = fs.readFileSync(path.join(jobsDir, name), "utf8");
    if (!source.includes('parentPort.on("message"')) continue;
    assert.match(source, /sendWorkerResult\(parentPort,/, `${name} must close parentPort after a terminal result`);
  }
});

test("JobManager queues workers when a concurrency limit is reached", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-queue-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "delay-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort, workerData } = require("worker_threads");',
      'setTimeout(() => parentPort.postMessage({ type: "result", result: { id: workerData.id } }), 40);',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const first = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    workerData: { id: "first" },
    concurrencyKey: "query",
    maxConcurrent: 1,
  });
  const second = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    workerData: { id: "second" },
    concurrencyKey: "query",
    maxConcurrent: 1,
  });

  const statuses = new Map(manager.list().map((job) => [job.id, job.status]));
  assert.equal(statuses.get(first.jobId), "running");
  assert.equal(statuses.get(second.jobId), "queued");

  assert.deepEqual(await first.promise, { id: "first" });
  assert.deepEqual(await second.promise, { id: "second" });
  assert.equal(manager.list().find((job) => job.id === second.jobId)?.status, "completed");
});

test("JobManager can cancel a queued worker before it starts", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-queue-cancel-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "delay-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort, workerData } = require("worker_threads");',
      'setTimeout(() => parentPort.postMessage({ type: "result", result: { id: workerData.id } }), 40);',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const first = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    workerData: { id: "first" },
    concurrencyKey: "query",
    maxConcurrent: 1,
  });
  const second = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    workerData: { id: "second" },
    concurrencyKey: "query",
    maxConcurrent: 1,
  });

  assert.deepEqual(manager.cancel(second.jobId), { ok: true });
  await assert.rejects(second.promise, /Job cancelled/);
  assert.deepEqual(await first.promise, { id: "first" });
  assert.equal(manager.list().find((job) => job.id === second.jobId)?.status, "cancelled");
});

test("JobManager enforces global and heavy-worker budgets across job types", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-budget-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "budget-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort, workerData } = require("worker_threads");',
      'setTimeout(() => parentPort.postMessage({ type: "result", result: { id: workerData.id } }), 60);',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({
    safeSend: () => {},
    dbg: () => {},
    maxWorkers: 2,
    maxHeavyWorkers: 1,
  });
  const heavyOne = manager.startWorkerJob({
    type: "import",
    worker: workerPath,
    workerData: { id: "heavy-one" },
    resourceClass: "heavy",
  });
  const heavyTwo = manager.startWorkerJob({
    type: "analyzer",
    worker: workerPath,
    workerData: { id: "heavy-two" },
    resourceClass: "heavy",
  });
  const light = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    workerData: { id: "light" },
    resourceClass: "light",
  });

  const statuses = new Map(manager.list().map((job) => [job.id, job.status]));
  assert.equal(statuses.get(heavyOne.jobId), "running");
  assert.equal(statuses.get(heavyTwo.jobId), "queued");
  assert.equal(statuses.get(light.jobId), "running");
  assert.deepEqual(manager.metrics(), {
    limits: { maxWorkers: 2, maxHeavyWorkers: 1, source: "constructor" },
    liveWorkers: 2,
    liveHeavyWorkers: 1,
    queuedWorkers: 1,
    queuedHeavyWorkers: 1,
  });

  assert.deepEqual(await light.promise, { id: "light" });
  assert.deepEqual(await heavyOne.promise, { id: "heavy-one" });
  await waitFor(() => manager.list().find((job) => job.id === heavyTwo.jobId)?.status === "running");
  assert.deepEqual(await heavyTwo.promise, { id: "heavy-two" });
});

test("JobManager global ceiling queues work even when per-type keys differ", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-global-budget-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "global-worker.js");
  fs.writeFileSync(
    workerPath,
    'const { parentPort } = require("worker_threads"); setTimeout(() => parentPort.postMessage({ type: "result", result: true }), 40);\n',
  );
  const manager = new JobManager({ safeSend: () => {}, dbg: () => {}, maxWorkers: 1, maxHeavyWorkers: 1 });
  const first = manager.startWorkerJob({ type: "import", worker: workerPath, concurrencyKey: "import", maxConcurrent: 1 });
  const second = manager.startWorkerJob({ type: "query", worker: workerPath, concurrencyKey: "query", maxConcurrent: 2, resourceClass: "light" });

  assert.equal(manager.list().find((job) => job.id === first.jobId)?.status, "running");
  assert.equal(manager.list().find((job) => job.id === second.jobId)?.status, "queued");
  assert.equal(await first.promise, true);
  assert.equal(await second.promise, true);
});
