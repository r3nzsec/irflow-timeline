const path = require("path");
const { Worker } = require("worker_threads");
const { workerResourceLimits } = require("../utils/worker-heap");
const { deriveWorkerBudget } = require("../utils/worker-budget");

class JobManager {
  constructor({ safeSend, dbg, maxWorkers, maxHeavyWorkers } = {}) {
    this.safeSend = safeSend || (() => {});
    this.dbg = dbg || (() => {});
    this.jobs = new Map();
    this.pending = [];
    this.counter = 0;
    this._pruneTimer = null;
    const derived = deriveWorkerBudget();
    this.maxWorkers = Number.isFinite(maxWorkers) && maxWorkers > 0
      ? Math.floor(maxWorkers)
      : derived.maxWorkers;
    this.maxHeavyWorkers = Math.min(
      Number.isFinite(maxHeavyWorkers) && maxHeavyWorkers > 0
        ? Math.floor(maxHeavyWorkers)
        : derived.maxHeavyWorkers,
      this.maxWorkers,
    );
    this.budgetSource = Number.isFinite(maxWorkers) || Number.isFinite(maxHeavyWorkers)
      ? "constructor"
      : derived.source;
    this.dbg("JOB", "Worker budget initialized", this.metrics());
  }

  startWorkerJob({
    type,
    worker,
    workerData = {},
    channels = {},
    metadata = {},
    concurrencyKey = null,
    maxConcurrent = 0,
    retainResult = true,
    resourceClass = "heavy",
  }) {
    const jobId = workerData.jobId || `${type || "job"}_${++this.counter}_${Date.now()}`;
    const startedAt = Date.now();
    const workerPath = path.isAbsolute(worker) ? worker : path.join(__dirname, worker);
    const limit = Number.isFinite(maxConcurrent) && maxConcurrent > 0 ? Math.floor(maxConcurrent) : 0;
    const queueKey = limit > 0 ? (concurrencyKey || type || workerPath) : null;
    const cancelBuffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
    const cancelView = new Int32Array(cancelBuffer);

    const job = {
      id: jobId,
      type,
      status: "queued",
      startedAt,
      updatedAt: startedAt,
      metadata,
      worker: null,
      workerPath,
      workerData: { ...workerData, jobId, type, cancelBuffer },
      cancelView,
      channels,
      concurrencyKey: queueKey,
      maxConcurrent: limit,
      resourceClass: resourceClass === "light" ? "light" : "heavy",
      retainResult: retainResult !== false,
      result: null,
      error: null,
      _resolve: null,
      _reject: null,
      _settled: false,
      _cancelTimer: null,
      _retireTimer: null,
    };
    this.jobs.set(jobId, job);

    const promise = new Promise((resolve, reject) => {
      job._resolve = resolve;
      job._reject = reject;
      this._schedule(job);
    }).finally(() => {
      if (job.retainResult) this._schedulePrune();
    });

    job.promise = promise;
    return { jobId, promise };
  }

  cancel(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return { ok: false, error: "Job not found" };
    if (job.status === "queued") {
      this._removeQueued(job);
      job.status = "cancelled";
      job.updatedAt = Date.now();
      this._emitJob(job, { phase: "cancelled", done: true });
      this._settleJob(job, "reject", this._cancelError());
      this._releaseTransientJob(job);
      return { ok: true };
    }
    if (!job.worker || job.status !== "running") return { ok: false, status: job.status };
    job.status = "cancelling";
    job.updatedAt = Date.now();
    try { Atomics.store(job.cancelView, 0, 1); } catch {}
    this._emitJob(job, { phase: "cancelling" });
    try { job.worker.postMessage({ type: "cancel" }); } catch {}
    job._cancelTimer = setTimeout(() => {
      job._cancelTimer = null;
      if (job.worker && job.status === "cancelling") {
        try {
          const termination = job.worker.terminate();
          termination?.catch?.(() => {});
        } catch {}
      }
    }, 250);
    job._cancelTimer.unref?.();
    return { ok: true };
  }

  cancelWhere(predicate) {
    let cancelled = 0;
    for (const job of this.jobs.values()) {
      if (!predicate(job)) continue;
      const result = this.cancel(job.id);
      if (result.ok) cancelled++;
    }
    return cancelled;
  }

  terminateAll() {
    for (const job of this.jobs.values()) {
      if (job.status === "queued") this._removeQueued(job);
      if (!job.worker && job.status !== "queued") continue;
      job.status = "cancelled";
      job.updatedAt = Date.now();
      try { job.worker?.terminate(); } catch {}
    }
  }

  list() {
    return [...this.jobs.values()].map((job) => this._serialize(job));
  }

  metrics() {
    const jobs = [...this.jobs.values()];
    const live = jobs.filter((job) => job.worker);
    const queued = jobs.filter((job) => job.status === "queued");
    return {
      limits: {
        maxWorkers: this.maxWorkers,
        maxHeavyWorkers: this.maxHeavyWorkers,
        source: this.budgetSource,
      },
      liveWorkers: live.length,
      liveHeavyWorkers: live.filter((job) => job.resourceClass === "heavy").length,
      queuedWorkers: queued.length,
      queuedHeavyWorkers: queued.filter((job) => job.resourceClass === "heavy").length,
    };
  }

  _emitJob(job, progress = {}) {
    const normalizedProgress = this._normalizeProgress(job, progress);
    const payload = {
      job: this._serialize(job),
      progress: {
        jobId: job.id,
        type: job.type,
        ...normalizedProgress,
      },
    };
    try { this.safeSend("job-progress", payload); } catch {}
  }

  _schedule(job) {
    if (this._canStart(job)) {
      this._startThread(job);
      return;
    }

    this.pending.push(job);
    this._emitJob(job, { phase: "queued", progress: 0 });
    this.dbg("JOB", "Worker queued by resource budget", {
      jobId: job.id,
      type: job.type,
      resourceClass: job.resourceClass,
      ...this.metrics(),
    });
  }

  _startThread(job) {
    job.status = "running";
    job.updatedAt = Date.now();
    let thread;
    try {
      thread = new Worker(job.workerPath, {
        workerData: job.workerData,
        resourceLimits: workerResourceLimits(),
      });
    } catch (err) {
      job.status = "failed";
      job.updatedAt = Date.now();
      job.error = err?.message || String(err);
      this.dbg("JOB", "Worker failed to start", { jobId: job.id, type: job.type, error: job.error });
      this._emitJob(job, { phase: "failed", error: job.error, done: true });
      this._settleJob(job, "reject", err);
      this._releaseTransientJob(job);
      queueMicrotask(() => this._drainQueues());
      return;
    }
    job.worker = thread;

    this._emitJob(job, { phase: "started", progress: 0 });
    this.dbg("JOB", "Worker started", {
      jobId: job.id,
      type: job.type,
      resourceClass: job.resourceClass,
      ...this.metrics(),
    });

    thread.on("message", (message = {}) => {
      if (message.type === "progress") {
        const normalizedProgress = this._normalizeProgress(job, message.progress || {});
        job.updatedAt = Date.now();
        this._emitJob(job, normalizedProgress);
        if (job.channels.progress) this.safeSend(job.channels.progress, normalizedProgress);
        return;
      }

      if (message.type === "event" && message.channel) {
        this.safeSend(message.channel, message.payload);
        return;
      }

      if (message.type === "result") {
        if (job._settled) return;
        if (job.status === "cancelling") {
          // Once cancellation is acknowledged by the manager, a racing result cannot
          // turn the job back into a success. Retire the worker and let exit settle it.
          this._scheduleWorkerRetirement(job, thread);
          return;
        }
        job.status = "completed";
        job.updatedAt = Date.now();
        if (job.retainResult) job.result = message.result;
        this._emitJob(job, { phase: "completed", progress: 100, done: true });
        if (job.channels.complete) this.safeSend(job.channels.complete, message.result);
        this._settleJob(job, "resolve", message.result);
        this._releaseTransientJob(job);
        this._scheduleWorkerRetirement(job, thread);
      }
    });

    thread.on("error", (err) => {
      this._clearWorkerRetirement(job);
      if (job._settled) {
        this.dbg("JOB", "Worker emitted an error after settlement", {
          jobId: job.id,
          type: job.type,
          status: job.status,
          error: err?.message || String(err),
        });
        return;
      }
      job.status = job.status === "cancelling" ? "cancelled" : "failed";
      job.updatedAt = Date.now();
      job.error = err?.message || String(err);
      this._emitJob(job, { phase: job.status, error: job.error, done: true });
      const rejection = job.status === "cancelled" ? this._cancelError() : err;
      this._settleJob(job, "reject", rejection);
      this._releaseTransientJob(job);
    });

    thread.on("exit", (code) => {
      this._clearWorkerRetirement(job);
      this._clearCancelTimer(job);
      job.worker = null;
      if (!job._settled) {
        if (job.status === "cancelling" || job.status === "cancelled") {
          job.status = "cancelled";
          job.updatedAt = Date.now();
          this._emitJob(job, { phase: "cancelled", done: true });
          this._settleJob(job, "reject", this._cancelError());
        } else {
          job.status = "failed";
          job.updatedAt = Date.now();
          job.error = `Worker exited before sending a terminal result (code ${code})`;
          this._emitJob(job, { phase: "failed", error: job.error, done: true });
          this._settleJob(job, "reject", new Error(job.error));
        }
      } else if (job.status === "completed" && code !== 0) {
        this.dbg("JOB", "Worker exited non-zero after delivering its result", {
          jobId: job.id,
          type: job.type,
          code,
        });
      }
      this._releaseTransientJob(job);
      this.dbg("JOB", "Worker exited", { jobId: job.id, type: job.type, code, ...this.metrics() });
      this._drainQueues();
    });
  }

  _canStart(job) {
    const metrics = this.metrics();
    if (metrics.liveWorkers >= this.maxWorkers) return false;
    if (job.resourceClass === "heavy" && metrics.liveHeavyWorkers >= this.maxHeavyWorkers) return false;
    if (job.concurrencyKey && this._runningCount(job.concurrencyKey) >= job.maxConcurrent) return false;
    return true;
  }

  _runningCount(key) {
    let count = 0;
    for (const job of this.jobs.values()) {
      // A worker still consumes an OS thread and a V8 isolate until its exit event,
      // even after it has posted a terminal result. Count the live Worker object so
      // the concurrency limit cannot be bypassed during retirement.
      if (job.concurrencyKey === key && job.worker) {
        count++;
      }
    }
    return count;
  }

  _removeQueued(job) {
    this.pending = this.pending.filter((queued) => queued.id !== job.id);
  }

  _drainQueues() {
    let started = true;
    while (started) {
      started = false;
      const index = this.pending.findIndex((job) => job.status === "queued" && this._canStart(job));
      if (index < 0) break;
      const [next] = this.pending.splice(index, 1);
      this._startThread(next);
      started = true;
    }
  }

  /**
   * Query jobs return large, short-lived row windows. Their awaiting IPC handler still receives
   * the result, but the manager must not retain the fulfilled Promise/result graph for the normal
   * ten-minute job-history window.
   */
  _releaseTransientJob(job) {
    if (!job || job.retainResult) return;
    job.result = null;
    job.promise = null;
    job._resolve = null;
    job._reject = null;
    // Keep the lightweight job record until the Worker actually exits. Removing it
    // on the result message made completed-but-live workers invisible to concurrency
    // accounting and allowed hundreds of V8 isolates to accumulate.
    if (!job.worker) this.jobs.delete(job.id);
  }

  _scheduleWorkerRetirement(job, thread) {
    if (!job || !thread || job.worker !== thread || job._retireTimer) return;
    // Workers should close parentPort after their terminal result. This fallback
    // enforces the one-shot job contract if a current or future worker forgets.
    job._retireTimer = setTimeout(() => {
      job._retireTimer = null;
      if (job.worker !== thread) return;
      try {
        const termination = thread.terminate();
        termination?.catch?.(() => {});
      } catch {}
    }, 250);
    job._retireTimer.unref?.();
  }

  _clearWorkerRetirement(job) {
    if (!job?._retireTimer) return;
    clearTimeout(job._retireTimer);
    job._retireTimer = null;
  }

  _clearCancelTimer(job) {
    if (!job?._cancelTimer) return;
    clearTimeout(job._cancelTimer);
    job._cancelTimer = null;
  }

  _cancelError() {
    const err = new Error("Job cancelled");
    err.cancelled = true;
    return err;
  }

  _settleJob(job, outcome, value) {
    if (!job || job._settled) return false;
    job._settled = true;
    const resolve = job._resolve;
    const reject = job._reject;
    job._resolve = null;
    job._reject = null;
    if (outcome === "resolve") resolve?.(value);
    else reject?.(value);
    return true;
  }

  _schedulePrune() {
    if (this._pruneTimer) return;
    this._pruneTimer = setTimeout(() => {
      this._pruneTimer = null;
      this._prune();
    }, 10 * 60 * 1000);
    this._pruneTimer.unref?.();
  }

  _normalizeProgress(job, progress = {}) {
    const metadata = job?.metadata || {};
    return {
      ...(metadata.tabId && !progress.tabId ? { tabId: metadata.tabId } : null),
      ...(metadata.fileName && !progress.fileName ? { fileName: metadata.fileName } : null),
      ...progress,
    };
  }

  _serialize(job) {
    return {
      id: job.id,
      type: job.type,
      status: job.status,
      startedAt: job.startedAt,
      updatedAt: job.updatedAt,
      metadata: job.metadata,
      resourceClass: job.resourceClass,
      error: job.error,
    };
  }

  _prune() {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [id, job] of this.jobs) {
      if (job.worker) continue;
      if (job.updatedAt < cutoff) this.jobs.delete(id);
    }
  }
}

module.exports = { JobManager };
