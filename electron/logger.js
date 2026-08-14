/**
 * logger.js — Shared debug trace logger for IRFlow Timeline
 *
 * Single instance: one buffer, one flush timer, one exit hook.
 * All modules (main.js, db.js, parser.js) share this to avoid
 * 3 independent timers racing on the same log file.
 */

const path = require("path");
const fs = require("fs");
const os = require("os");

const debugLogPath = path.join(os.homedir(), "tle-debug.log");

// Rotate on startup: truncate if >5 MB to prevent unbounded growth
try { if (fs.existsSync(debugLogPath) && fs.statSync(debugLogPath).size > 5 * 1024 * 1024) fs.writeFileSync(debugLogPath, ""); } catch {}

let _logBuf = [];
let _flushPending = false;

function dbg(tag, msg, data) {
  const ts = new Date().toISOString();
  const line = `[${ts}] [${tag}] ${msg}${data !== undefined ? " " + JSON.stringify(data, null, 0) : ""}`;
  console.error(line);
  _logBuf.push(line);
  if (_logBuf.length >= 50) _flushLog();
}

function _flushLog() {
  if (!_logBuf.length || _flushPending) return;
  _flushPending = true;
  const chunk = _logBuf.join("\n") + "\n";
  _logBuf = [];
  fs.appendFile(debugLogPath, chunk, () => { _flushPending = false; });
}

function _flushLogSync() {
  if (!_logBuf.length) return;
  try { fs.appendFileSync(debugLogPath, _logBuf.join("\n") + "\n"); } catch {}
  _logBuf = [];
}

// unref() so the flush timer never blocks process shutdown — critical for tests
// running under `node --test`, and harmless in Electron where the main process
// exits via app.quit().
setInterval(_flushLog, 2000).unref();
process.on("exit", _flushLogSync);

module.exports = { dbg, debugLogPath, flushLogSync: _flushLogSync };
