"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_RELAUNCH_GUARD_MS = 30_000;
const DEFAULT_STABLE_START_MS = 30_000;

function _asError(reason) {
  if (reason instanceof Error) return reason;
  return new Error(typeof reason === "string" ? reason : String(reason));
}

function createFatalRecovery({
  app,
  dialog,
  jobManager,
  db,
  dbg = () => {},
  flushLogSync = () => {},
  debugLogPath = "",
  userDataPath,
  now = () => Date.now(),
  relaunchGuardMs = DEFAULT_RELAUNCH_GUARD_MS,
  stableStartMs = DEFAULT_STABLE_START_MS,
  fsImpl = fs,
  setTimeoutImpl = setTimeout,
} = {}) {
  if (!app) throw new Error("Fatal recovery requires the Electron app instance");
  const markerPath = path.join(userDataPath || app.getPath("userData"), "fatal-recovery.json");
  let handlingFatal = false;

  function _readMarker() {
    try { return JSON.parse(fsImpl.readFileSync(markerPath, "utf8")); } catch { return null; }
  }

  function _writeMarker(payload) {
    try {
      fsImpl.mkdirSync(path.dirname(markerPath), { recursive: true });
      const temporaryPath = `${markerPath}.tmp`;
      fsImpl.writeFileSync(temporaryPath, JSON.stringify(payload), "utf8");
      fsImpl.renameSync(temporaryPath, markerPath);
    } catch (err) {
      dbg("CRASH", "Could not persist fatal recovery marker", { message: err?.message });
    }
  }

  function markStableStartup() {
    const timer = setTimeoutImpl(() => {
      try { fsImpl.unlinkSync(markerPath); } catch (err) {
        if (err?.code !== "ENOENT") dbg("CRASH", "Could not clear fatal recovery marker", { message: err?.message });
      }
    }, stableStartMs);
    timer?.unref?.();
    return timer;
  }

  function handleFatal(reason, origin = "uncaughtException", { allowRelaunch = true } = {}) {
    const err = _asError(reason);
    if (handlingFatal) {
      try { flushLogSync(); } catch {}
      try { app.exit(1); } catch {}
      return { relaunching: false, duplicate: true };
    }
    handlingFatal = true;

    const timestamp = now();
    const previous = _readMarker();
    const recentlyRelaunched = Number.isFinite(previous?.timestamp) && timestamp - previous.timestamp < relaunchGuardMs;
    const relaunching = Boolean(allowRelaunch && !recentlyRelaunched);
    const message = String(err.message || "Unknown fatal error").slice(0, 2048);
    const diagnostic = {
      timestamp,
      isoTime: new Date(timestamp).toISOString(),
      version: app.getVersion?.(),
      origin,
      message,
      stack: String(err.stack || "").slice(0, 8192),
      relaunching,
    };

    dbg("CRASH", "Fatal application error", diagnostic);
    _writeMarker(diagnostic);

    // Only synchronous, best-effort cleanup is safe after an uncaught exception.
    try { jobManager?.terminateAll?.(); } catch (cleanupError) {
      dbg("CRASH", "Worker shutdown failed during fatal recovery", { message: cleanupError?.message });
    }
    try { db?.closeAll?.(); } catch (cleanupError) {
      dbg("CRASH", "Database shutdown failed during fatal recovery", { message: cleanupError?.message });
    }
    try { flushLogSync(); } catch {}

    const action = relaunching
      ? "The application will restart. Your last autosave will be offered on startup."
      : "Automatic restart was suppressed to prevent a crash loop. Reopen the application manually.";
    try {
      dialog?.showErrorBox?.(
        "IRFlow Timeline — Recovery Required",
        `IRFlow Timeline encountered a fatal error and cannot safely continue.\n\n${message}\n\n${action}${debugLogPath ? `\n\nDebug log: ${debugLogPath}` : ""}`,
      );
    } catch {}

    if (relaunching) {
      try { app.relaunch(); } catch (relaunchError) {
        dbg("CRASH", "Application relaunch request failed", { message: relaunchError?.message });
      }
    }
    try { flushLogSync(); } catch {}
    try { app.exit(1); } catch {}
    return { relaunching, duplicate: false };
  }

  return { handleFatal, markStableStartup, markerPath };
}

module.exports = {
  createFatalRecovery,
  DEFAULT_RELAUNCH_GUARD_MS,
  DEFAULT_STABLE_START_MS,
};
