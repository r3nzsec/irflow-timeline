// Synchronous access to the DuckDB host thread.
//
// The timeline engine was written against better-sqlite3, whose calls are synchronous, and
// DuckDB's Node API is asynchronous only. Instead of rewriting ~340 call sites to async, every
// call is sent to host.js over a MessagePort and the calling thread sleeps on a shared flag
// (Atomics.wait) until the host has posted the reply, which receiveMessageOnPort then reads
// synchronously. The calling thread blocks exactly as it did inside a better-sqlite3 call,
// while DuckDB itself runs multi-threaded on the host thread.
//
// One host per process: the thread that loads this first (normally the Electron main
// thread) starts it, and worker threads receive a dedicated port to the same host through
// workerData (see createWorkerPort and job-manager.js), so every thread sees one DuckDB
// instance and a database file is never opened twice.
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { Worker, MessageChannel, receiveMessageOnPort, isMainThread, threadId, workerData } = require("worker_threads");

const WORKER_DATA_KEY = "__irflowDuckdbPort";
const WAIT_SLICE_MS = 1000;
const TRACE = !!process.env.IRFLOW_DUCKDB_TRACE;

let host = null; // { worker, status }
let channel = null;

function hostPath() {
  // Inside a packaged app this file lives in app.asar; the worker loads the same path.
  return path.join(__dirname, "host.js");
}

function startHost() {
  if (host) return host;
  const status = new Int32Array(new SharedArrayBuffer(4));
  const settings = hostSettings();
  if (!settings.tempDirectory) {
    // A worker that had to start its own host (no port handed over) gets its own folder.
    const suffix = isMainThread ? `${process.pid}` : `${process.pid}-${threadId}`;
    settings.tempDirectory = path.join(os.tmpdir(), `irflow-duckdb-${suffix}`);
  }
  const spillDir = settings.tempDirectory;
  process.once("exit", () => {
    try { fs.rmSync(spillDir, { recursive: true, force: true }); } catch {}
  });
  const worker = new Worker(hostPath(), {
    workerData: { settings },
    stdout: false,
    stderr: false,
  });
  worker.unref();
  worker.on("error", (err) => {
    Atomics.store(status, 0, 2);
    host.error = err;
    try { process.emitWarning(`DuckDB host stopped: ${err?.message || err}`); } catch {}
  });
  worker.on("exit", () => { Atomics.store(status, 0, 2); });
  host = { worker, status, error: null };
  return host;
}

let tempDirectory = null;

/**
 * Where DuckDB writes spill files. Applies to the running host too, so changing the
 * app's temp folder takes effect without a restart.
 */
function setTempDirectory(dir) {
  if (!dir) return;
  tempDirectory = path.join(dir, `irflow-duckdb-${process.pid}`);
  if (host) getChannel().call({ op: "setTempDirectory", dir: tempDirectory });
}

function hostSettings() {
  const s = {};
  if (tempDirectory) s.tempDirectory = tempDirectory;
  const mem = Number(process.env.IRFLOW_DUCKDB_MEMORY_MB);
  if (Number.isFinite(mem) && mem > 0) s.memoryLimitMb = mem;
  const threads = Number(process.env.IRFLOW_DUCKDB_THREADS);
  if (Number.isFinite(threads) && threads > 0) s.threads = threads;
  return s;
}

class Channel {
  constructor(port, flag, status) {
    this.port = port;
    this.flag = flag; // [0] reply ready, [1] async operations completed
    this.status = status; // Int32Array shared with startHost(); null in worker threads
    this.asyncSent = 0;
    this.port.unref?.();
  }

  /**
   * Queue an operation without waiting for it (bulk appends). The host runs a client's
   * operations in order, so a later call() sees its effects; an error is reported by the
   * next call(). At most `maxOutstanding` may be in flight: the caller blocks beyond that,
   * so parsing the next batch overlaps with DuckDB loading the previous one without
   * queueing the whole file in memory.
   */
  post(message, maxOutstanding = 2) {
    this.port.postMessage({ ...message, async: true });
    this.asyncSent++;
    this.waitAsync(maxOutstanding);
  }

  waitAsync(maxOutstanding = 0) {
    for (;;) {
      const done = Atomics.load(this.flag, 1);
      if (this.asyncSent - done <= maxOutstanding) return;
      const r = Atomics.wait(this.flag, 1, done, WAIT_SLICE_MS);
      if (r === "timed-out" && this.status && Atomics.load(this.status, 0) === 2) {
        throw new Error(`DuckDB host is not running${host?.error ? `: ${host.error.message}` : ""}`);
      }
    }
  }

  call(message) {
    if (TRACE) process.stderr.write(`[duckdb] ${message.op} ${message.sql ? message.sql.slice(0, 160).replace(/\s+/g, " ") : ""}\n`);
    if (Atomics.load(this.flag, 0) !== 0) Atomics.store(this.flag, 0, 0);
    this.port.postMessage(message);
    for (;;) {
      const r = Atomics.wait(this.flag, 0, 0, WAIT_SLICE_MS);
      if (r !== "timed-out") break;
      if (this.status && Atomics.load(this.status, 0) === 2) {
        throw new Error(`DuckDB host is not running${host?.error ? `: ${host.error.message}` : ""}`);
      }
    }
    Atomics.store(this.flag, 0, 0);
    const received = receiveMessageOnPort(this.port);
    if (!received) throw new Error("DuckDB host reply was lost");
    const reply = received.message;
    if (!reply.ok) {
      const err = new Error(reply.error);
      err.code = "DUCKDB_ERROR";
      throw err;
    }
    return reply.value;
  }

  send(message) {
    // Fire-and-forget (statement finalization). The host does not reply.
    try { this.port.postMessage({ ...message, noReply: true }); } catch {}
  }
}

function connectPort(port, sab, status) {
  return new Channel(port, new Int32Array(sab), status);
}

function newHostPort() {
  const h = startHost();
  const { port1, port2 } = new MessageChannel();
  const sab = new SharedArrayBuffer(8);
  h.worker.postMessage({ type: "client", port: port2, sab }, [port2]);
  return { port: port1, sab, status: h.status };
}

function getChannel() {
  if (channel) return channel;
  const handoff = !isMainThread && workerData && workerData[WORKER_DATA_KEY];
  if (handoff && handoff.port) {
    channel = connectPort(handoff.port, handoff.sab, null);
  } else {
    const { port, sab, status } = newHostPort();
    channel = connectPort(port, sab, status);
  }
  return channel;
}

/**
 * Create a port to this process's DuckDB host for a worker thread. Pass the returned
 * object in the worker's workerData under WORKER_DATA_KEY and list `transfer` in its
 * transferList. Call it from the thread that owns the host (the main thread).
 */
function createWorkerPort() {
  const { port, sab } = newHostPort();
  return { data: { port, sab }, transfer: [port] };
}

module.exports = { getChannel, createWorkerPort, setTempDirectory, WORKER_DATA_KEY };
