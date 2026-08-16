/**
 * grok-runtime.js — Grok Build runtime artifacts that sit OUTSIDE the session directories.
 *
 * `grok-build.js` reconstructs conversations from `sessions/<encoded-cwd>/<session-id>/`. Three
 * stores live elsewhere under `$GROK_HOME` and survive independently of those directories, which is
 * what makes them worth parsing: deleting a session tree does not delete the search index that
 * mirrors its text, the log that timestamped its tool calls, or the record that it was open.
 *
 *   sessions/session_search.sqlite   FTS5 index over session transcripts — `session_docs` carries
 *                                    session_id, cwd, title, updated_at and the indexed body. The
 *                                    same artifact class as Cursor's conversation-search.db.
 *   logs/unified.jsonl               structured app log: per-session tool executions with timing
 *                                    and success, turn phase transitions, warnings.
 *   active_sessions.json             session_id → pid, cwd, opened_at for sessions open at capture.
 *
 * Measured on Grok Build 1.0.3: 23 indexed sessions (one body 198 KB), 19,567 log records spanning
 * ten days across 15 session ids, of which 4,117 were tool executions.
 *
 * Deliberately NOT parsed: `memtrace/*.jsonl`. The name suggests agent memory; it is a memory
 * PROFILER trace (`kind: "sample"`, `rss_bytes`, `footprint_bytes`, `alloc`) — 59 MB of allocation
 * samples with no conversation content. Its only evidentiary use is process lifetime, which
 * `active_sessions.json` and the unified log already carry.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { TOOL_GROK_BUILD } = require("./schema");
const { openVscdbReadOnly } = require("./vscdb-kv");
const { copySqliteFamilyToTemp } = require("./codex-state-sqlite");
const { readJsonlBounded } = require("./jsonl-reader");
const { formatTimestampUtc, makeRow, truncateSummary } = require("./row-utils");

const SESSION_SEARCH_DB = "session_search.sqlite";
const ACTIVE_SESSIONS_FILE = "active_sessions.json";
const UNIFIED_LOG_REL = ["logs", "unified.jsonl"];

/** Bound on indexed conversations pulled from the FTS store. */
const MAX_SESSION_SEARCH_ROWS = 5000;
/** Bound on log records projected into rows — the log is unbounded and mostly debug noise. */
const MAX_UNIFIED_LOG_ROWS = 20000;

/**
 * Log messages worth a timeline row. The log is ~55% debug chatter; these are the records that
 * carry evidence rather than progress. `shell.tool.exec_done` is the valuable one: it timestamps a
 * tool execution with its outcome even when the session transcript is gone.
 */
const LOGGED_EVENTS = new Map([
  ["shell.tool.exec_done", { role: "tool", recordType: "log_tool_exec" }],
  ["shell.turn.inference_start", { role: "metadata", recordType: "log_turn_start" }],
  ["shell.turn.inference_done", { role: "metadata", recordType: "log_turn_done" }],
]);

function grokRow(fields) {
  return makeRow({ ...fields, tool: TOOL_GROK_BUILD }, TOOL_GROK_BUILD);
}

/** Epoch seconds or milliseconds → ms. Grok writes seconds in session_search, ISO in the log. */
function epochToMs(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return null;
  if (n > 1e12) return n;
  if (n > 1e9) return n * 1000;
  return null;
}

/* ------------------------------------------------------- session_search.sqlite */

function findSessionSearchDb(grokRoot) {
  const p = path.join(grokRoot, "sessions", SESSION_SEARCH_DB);
  return fs.existsSync(p) ? p : null;
}

/**
 * Indexed session transcripts.
 *
 * `content` is the concatenated session body the FTS index was built from, so a row here can hold
 * the conversation text even where the session directory has been removed. `last_indexed_offset`
 * records how much of the source had been consumed — a value far below the body length means the
 * index is a partial view, and the row says so rather than implying completeness.
 */
function extractSessionSearchRows(dbPath, attribution = {}, options = {}) {
  const snapshot = copySqliteFamilyToTemp(dbPath);
  let db = null;
  const rows = [];
  try {
    db = openVscdbReadOnly(snapshot.dbPath);
    const tables = new Set(db.prepare(
      "SELECT name FROM sqlite_master WHERE type IN ('table','view')",
    ).all().map((r) => r.name));
    if (!tables.has("session_docs")) return rows;

    const maxRows = Math.max(
      1,
      Math.min(Number(options.maxSessionSearchRows) || MAX_SESSION_SEARCH_ROWS, 20000),
    );
    const records = db.prepare(`
      SELECT session_id, cwd, updated_at, title, content, content_hash, last_indexed_offset
      FROM session_docs
      ORDER BY updated_at ASC, session_id ASC
      LIMIT ?
    `).all(maxRows);

    for (const rec of records) {
      const title = String(rec.title || "").trim();
      const body = String(rec.content || "").trim();
      const sessionId = String(rec.session_id || "").trim();
      const cwd = String(rec.cwd || "").trim();
      const summary = title || `Grok indexed session ${sessionId || "(unknown)"}`;
      rows.push(grokRow({
        timestamp: formatTimestampUtc(epochToMs(rec.updated_at)),
        role: "conversation",
        recordType: "session_search",
        summary,
        fullText: body || JSON.stringify({
          sessionId, cwd, title, bodyPresent: false, contentHash: rec.content_hash || "",
        }, null, 2),
        sessionId,
        workspace: cwd,
        toolDescription: `Grok session search index. content_hash=${rec.content_hash || "-"}; `
          + `indexed ${body.length} chars at offset ${rec.last_indexed_offset ?? "-"}. `
          + "Indexed copy of the session transcript — it survives deletion of the session "
          + "directory, and may be a partial view of it.",
        sourceFile: dbPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }
  } finally {
    try { db?.close(); } catch { /* ignore */ }
    snapshot.cleanup();
  }
  return rows;
}

/* ---------------------------------------------------------- active_sessions.json */

function extractActiveSessions(grokRoot, attribution = {}) {
  const filePath = path.join(grokRoot, ACTIVE_SESSIONS_FILE);
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { return []; }
  if (!Array.isArray(parsed)) return [];

  const rows = [];
  for (const entry of parsed) {
    if (!entry || typeof entry !== "object") continue;
    const sessionId = String(entry.session_id || entry.sessionId || "").trim();
    const cwd = String(entry.cwd || "").trim();
    const openedMs = Date.parse(entry.opened_at || entry.openedAt || "");
    rows.push(grokRow({
      timestamp: formatTimestampUtc(Number.isFinite(openedMs) ? openedMs : null),
      role: "metadata",
      recordType: "session_open",
      summary: `Grok session open — pid ${entry.pid ?? "?"}${cwd ? ` in ${cwd}` : ""}`,
      fullText: JSON.stringify(entry, null, 2),
      sessionId,
      workspace: cwd,
      toolDescription: "Session recorded as OPEN at acquisition time. The timestamp is when the "
        + "session was opened, not when this file was written.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/* ------------------------------------------------------------ logs/unified.jsonl */

/**
 * Tool executions and turn boundaries from the structured app log.
 *
 * The log outlives the session directories and is written independently of them, so it can place a
 * tool call on the timeline after the transcript that described it is gone. It does NOT carry the
 * command string — that only ever lives in the session's `updates.jsonl` — so a row here evidences
 * that a named tool ran, when, for how long, and whether it succeeded.
 */
async function extractUnifiedLog(grokRoot, attribution = {}, options = {}) {
  const filePath = path.join(grokRoot, ...UNIFIED_LOG_REL);
  if (!fs.existsSync(filePath)) return [];

  const maxRows = Math.max(
    1,
    Math.min(Number(options.maxUnifiedLogRows) || MAX_UNIFIED_LOG_ROWS, 200000),
  );
  const rows = [];
  const parseStats = { errors: 0 };

  await readJsonlBounded(filePath, (obj, lineNumber) => {
    if (rows.length >= maxRows) return;
    if (!obj || typeof obj !== "object") return;
    const spec = LOGGED_EVENTS.get(String(obj.msg || ""));
    if (!spec) return;

    const ctx = obj.ctx && typeof obj.ctx === "object" ? obj.ctx : {};
    const toolName = String(ctx.tool_name || "").trim();
    const ok = ctx.success;
    const elapsed = Number(ctx.elapsed_ms);
    const ts = Date.parse(obj.ts || "");

    const callId = String(ctx.tool_call_id || "").trim();
    // The call id has to reach Summary, not just MessageId. The shared dedupe key is
    // (SessionId, Timestamp, Role, summary-slice), the log timestamps only to the second, and a
    // fast agent fires many identical-looking calls within one second — measured, 956 of 4,117
    // exec rows collapsed into their neighbours without this. It is also the join key back to the
    // matching tool_call in the session transcript, so an analyst wants it inline regardless.
    const detail = [
      toolName ? `tool=${toolName}` : "",
      ok === true ? "success" : ok === false ? "FAILED" : "",
      Number.isFinite(elapsed) ? `${elapsed}ms` : "",
      callId ? `[${callId}]` : "",
    ].filter(Boolean).join(" ");

    rows.push(grokRow({
      timestamp: formatTimestampUtc(Number.isFinite(ts) ? ts : null),
      role: spec.role,
      recordType: spec.recordType,
      summary: truncateSummary(`${obj.msg}${detail ? ` — ${detail}` : ""}`),
      fullText: JSON.stringify(obj, null, 2),
      toolName,
      sessionId: String(obj.sid || "").trim(),
      messageId: callId,
      toolDescription: "From the Grok application log, not the session transcript. It records "
        + "THAT a tool ran with what outcome; the command string is only in the session's "
        + "updates.jsonl and is not available here.",
      sourceFile: filePath,
      lineNumber,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }, { parseStats });

  if (rows.length >= maxRows) {
    dbg("AIHIST", "grok unified log row cap hit", { path: filePath, maxRows });
  }
  return rows;
}

/* ------------------------------------------------------------------ orchestration */

function countGrokRuntimeFiles(grokRoot) {
  let n = 0;
  if (findSessionSearchDb(grokRoot)) n += 1;
  if (fs.existsSync(path.join(grokRoot, ACTIVE_SESSIONS_FILE))) n += 1;
  if (fs.existsSync(path.join(grokRoot, ...UNIFIED_LOG_REL))) n += 1;
  return n;
}

/**
 * Every runtime artifact under a Grok root. Each store is independently guarded: a missing or
 * corrupt one must never lose the others, and an unavailable SQLite binding must not fail the
 * whole extraction.
 */
async function collectGrokRuntimeArtifacts(grokRoot, attribution = {}, options = {}) {
  const rows = [];

  const dbPath = findSessionSearchDb(grokRoot);
  if (dbPath && options.includeSessionSearch !== false) {
    try {
      rows.push(...extractSessionSearchRows(dbPath, attribution, options));
    } catch (e) {
      dbg("AIHIST", "grok session_search failed", { path: dbPath, err: e.message });
    }
  }

  try {
    rows.push(...extractActiveSessions(grokRoot, attribution));
  } catch (e) {
    dbg("AIHIST", "grok active_sessions failed", { path: grokRoot, err: e.message });
  }

  if (options.includeGrokLog !== false) {
    try {
      rows.push(...await extractUnifiedLog(grokRoot, attribution, options));
    } catch (e) {
      dbg("AIHIST", "grok unified log failed", { path: grokRoot, err: e.message });
    }
  }

  return rows;
}

module.exports = {
  SESSION_SEARCH_DB,
  ACTIVE_SESSIONS_FILE,
  UNIFIED_LOG_REL,
  LOGGED_EVENTS,
  MAX_SESSION_SEARCH_ROWS,
  MAX_UNIFIED_LOG_ROWS,
  epochToMs,
  findSessionSearchDb,
  extractSessionSearchRows,
  extractActiveSessions,
  extractUnifiedLog,
  countGrokRuntimeFiles,
  collectGrokRuntimeArtifacts,
};
