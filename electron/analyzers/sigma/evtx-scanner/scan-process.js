/**
 * sigma/evtx-scanner/scan-process.js — Hayabusa subprocess lifecycle + cancellation.
 *
 * This module deliberately depends only on Node core + the (pure) progress parser
 * — NOT on the SQLite result store or Electron — so the spawn/cancel/crash paths
 * can be unit-tested under plain `node --test` with a fake binary.
 *
 * The single source of truth for "is this scan cancelled" lives here in
 * `_activeProcs`; scan-runner.js re-exports these symbols for compatibility.
 */

const fs = require("fs");
const { spawn } = require("child_process");
const { stripAnsi } = require("./progress-parser");

const DEFAULT_TERMINATE_GRACE_MS = 2000;
const DEFAULT_KILL_WAIT_MS = 2000;
const MAX_CAPTURED_STDERR_BYTES = 256 * 1024;

const _activeProcs = new Map();

function isProcessRunning(proc) {
  return !!proc
    && typeof proc.pid === "number"
    && proc.exitCode === null
    && proc.signalCode === null;
}

function createProcessEntry(proc, tempFiles, cancelled = false) {
  const entry = {
    proc: proc || null,
    tempFiles: tempFiles || [],
    cancelled: !!cancelled,
    closed: !proc,
    closeOutcome: proc ? null : { code: null, signal: null },
    closePromise: null,
    terminationPromise: null,
  };

  entry.closePromise = proc
    ? new Promise((resolve) => {
      proc.once("close", (code, signal) => {
        entry.closed = true;
        entry.closeOutcome = { code, signal: signal || null };
        resolve(entry.closeOutcome);
      });
    })
    : Promise.resolve(entry.closeOutcome);

  return entry;
}

function registerScanProc(scanJobId, proc, tempFiles) {
  const existing = scanJobId ? _activeProcs.get(scanJobId) : null;
  const entry = createProcessEntry(proc, tempFiles, existing?.cancelled);
  if (scanJobId) _activeProcs.set(scanJobId, entry);

  // If a cancel request raced ahead of the spawn, honour it immediately. The
  // returned promise is intentionally retained so later cancel calls share the
  // same TERM -> close -> KILL lifecycle instead of sending duplicate signals.
  if (entry.cancelled && proc) {
    void terminateEntry(entry);
  }
  return entry;
}

function unregisterScanProc(scanJobId) {
  if (!scanJobId) return;
  _activeProcs.delete(scanJobId);
}

function isCancelled(scanJobId) {
  return !!(scanJobId && _activeProcs.get(scanJobId)?.cancelled);
}

function throwIfCancelled(scanJobId) {
  if (isCancelled(scanJobId)) {
    throw Object.assign(new Error("Scan cancelled"), { cancelled: true });
  }
}

async function waitForClose(entry, timeoutMs) {
  if (entry.closed) return { closed: true, outcome: entry.closeOutcome };
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => finish({ closed: false, outcome: null }), timeoutMs);
    timer.unref?.();
    entry.closePromise.then((outcome) => finish({ closed: true, outcome }));
  });
}

function sendSignalIfRunning(entry, signal) {
  if (!isProcessRunning(entry.proc)) return false;
  try {
    return entry.proc.kill(signal);
  } catch {
    return false;
  }
}

function cleanupTempFiles(tempFiles) {
  for (const file of tempFiles || []) {
    try {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    } catch {}
  }
}

function terminateEntry(entry, {
  graceMs = DEFAULT_TERMINATE_GRACE_MS,
  killWaitMs = DEFAULT_KILL_WAIT_MS,
  cleanup = true,
} = {}) {
  if (entry.terminationPromise) return entry.terminationPromise;

  entry.terminationPromise = (async () => {
    let forced = false;
    let closeResult = await waitForClose(entry, 0);

    if (!closeResult.closed && isProcessRunning(entry.proc)) {
      sendSignalIfRunning(entry, "SIGTERM");
      closeResult = await waitForClose(entry, Math.max(0, graceMs));
    }

    // `proc.killed` only means a signal was sent. The process is still alive
    // until exitCode/signalCode changes and the close event drains stdio.
    if (!closeResult.closed && isProcessRunning(entry.proc)) {
      forced = sendSignalIfRunning(entry, "SIGKILL") || forced;
      closeResult = await waitForClose(entry, Math.max(0, killWaitMs));
    }

    // An exit can be observed through exitCode/signalCode just before Node emits
    // `close`. Still wait for `close` so stdio is drained before cleanup/return.
    if (!closeResult.closed && entry.proc && !isProcessRunning(entry.proc)) {
      closeResult = await waitForClose(entry, Math.max(0, killWaitMs));
    }

    if (cleanup) {
      if (closeResult.closed) {
        cleanupTempFiles(entry.tempFiles);
      } else {
        // Never unlink a file while a stubborn process may still be writing it.
        // If it eventually closes, perform the deferred cleanup then.
        void entry.closePromise.then(() => cleanupTempFiles(entry.tempFiles));
      }
    }

    return {
      closed: closeResult.closed,
      forced,
      exitCode: entry.proc?.exitCode ?? closeResult.outcome?.code ?? null,
      signal: entry.proc?.signalCode || closeResult.outcome?.signal || null,
    };
  })();

  return entry.terminationPromise;
}

async function cancelScan(scanJobId, terminationOptions) {
  const entry = _activeProcs.get(scanJobId);
  if (!entry) return { cancelled: false, reason: "unknown jobId" };
  entry.cancelled = true;

  // Cancellation can arrive during discovery or result parsing, when no child
  // is running. The cancelled flag remains registered so those phases can stop.
  if (!entry.proc) {
    cleanupTempFiles(entry.tempFiles);
    return { cancelled: true, terminated: true, forced: false };
  }

  const termination = await terminateEntry(entry, terminationOptions);
  return {
    cancelled: true,
    terminated: termination.closed,
    forced: termination.forced,
    exitCode: termination.exitCode,
    signal: termination.signal,
  };
}

function appendBoundedTail(current, chunk, maxBytes = MAX_CAPTURED_STDERR_BYTES) {
  const incoming = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
  if (incoming.length >= maxBytes) return incoming.subarray(incoming.length - maxBytes);
  if (current.length + incoming.length <= maxBytes) return Buffer.concat([current, incoming]);
  const keep = maxBytes - incoming.length;
  return Buffer.concat([current.subarray(current.length - keep), incoming]);
}

/**
 * Spawn Hayabusa and resolve once it exits, reporting the lifecycle outcome.
 *
 * Resolves:
 *   { cancelled: true }                                    — scan was cancelled
 *   { cancelled: false, exitCode, signal, errorLines }     — process finished
 *
 * Rejects only when the process fails to start, its progress parser fails, or
 * it exits non-zero AND produced no output file at all (a hard failure). A
 * non-zero exit that still left an output file resolves with the exit code so
 * the caller can flag the results as partial/truncated.
 *
 * @param {object} p
 * @param {string} p.hayabusaPath      path to the hayabusa binary
 * @param {string[]} p.args            CLI args
 * @param {string} p.cwd               working directory for the process
 * @param {string|null} p.scanJobId    cancellation key (registered in _activeProcs)
 * @param {object} p.progressParser    { handleChunk, startTicker }
 * @param {string[]} p.tempFiles       files to clean up if cancelled
 * @param {string|null} p.actualOutput output path used to distinguish hard failure
 */
function runScanProcess({ hayabusaPath, args, cwd, scanJobId, progressParser, tempFiles, actualOutput }) {
  return new Promise((resolve, reject) => {
    const proc = spawn(hayabusaPath, args, {
      cwd,
      stdio: ["ignore", "ignore", "pipe"],
    });
    const processEntry = registerScanProc(scanJobId, proc, tempFiles || []);

    let ticker = null;
    let settled = false;
    let startError = null;
    let progressError = null;
    let capturedStderr = Buffer.alloc(0);
    let capturedStderrBytes = 0;

    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      if (ticker) clearInterval(ticker);
      fn(value);
    };

    const failProgress = (err) => {
      if (progressError) return;
      progressError = err instanceof Error ? err : new Error(String(err));
      void terminateEntry(processEntry, { cleanup: false });
    };

    if (proc.stderr) {
      proc.stderr.on("data", (chunk) => {
        capturedStderrBytes += Buffer.byteLength(chunk);
        capturedStderr = appendBoundedTail(capturedStderr, chunk);
        if (!progressParser?.handleChunk || progressError) return;
        try {
          progressParser.handleChunk(chunk);
        } catch (err) {
          failProgress(err);
        }
      });
    }

    try {
      ticker = progressParser?.startTicker ? progressParser.startTicker(failProgress) : null;
    } catch (err) {
      failProgress(err);
    }

    proc.once("error", (err) => {
      startError = err;
    });

    proc.once("close", (code, signal) => {
      if (isCancelled(scanJobId) || processEntry.cancelled) {
        settle(resolve, { cancelled: true });
        return;
      }
      if (startError) {
        settle(reject, new Error(`Failed to start Hayabusa: ${startError.message}`));
        return;
      }
      if (progressError) {
        settle(reject, new Error(`Failed to process Hayabusa progress: ${progressError.message}`));
        return;
      }

      const cleanStderr = stripAnsi(capturedStderr.toString("utf8"));
      const errorLines = cleanStderr
        .split("\n")
        .filter((line) => /\[ERROR\]|error:/i.test(line));
      const outputExists = actualOutput ? fs.existsSync(actualOutput) : false;
      if (code !== 0 && !outputExists) {
        settle(reject, new Error(
          `Hayabusa exited with code ${code}${signal ? ` (signal ${signal})` : ""}: ${errorLines.slice(0, 3).join("; ") || "unknown error"}`
        ));
        return;
      }
      settle(resolve, {
        cancelled: false,
        exitCode: code,
        signal: signal || null,
        errorLines: errorLines.slice(0, 5),
        stderrTruncated: capturedStderrBytes > MAX_CAPTURED_STDERR_BYTES,
      });
    });
  });
}

// A non-zero numeric exit OR a signal-kill means the process did not finish
// cleanly — any output it produced may be incomplete/truncated.
function isAbnormalExit(outcome) {
  if (!outcome || outcome.cancelled) return false;
  return (typeof outcome.exitCode === "number" && outcome.exitCode !== 0) || !!outcome.signal;
}

module.exports = {
  DEFAULT_TERMINATE_GRACE_MS,
  DEFAULT_KILL_WAIT_MS,
  MAX_CAPTURED_STDERR_BYTES,
  _activeProcs,
  registerScanProc,
  unregisterScanProc,
  isCancelled,
  throwIfCancelled,
  cancelScan,
  runScanProcess,
  isAbnormalExit,
};
