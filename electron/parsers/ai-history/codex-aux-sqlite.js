/**
 * codex-aux-sqlite.js — supplemental Codex evidence from the non-`state*.sqlite` stores.
 *
 * `codex-state-sqlite.js` covers `state*.sqlite` only. A live `~/.codex` carries several other
 * SQLite stores that hold evidence the rollout JSONL does not:
 *
 *   sqlite/codex-dev.db   local_thread_catalog — every thread the app knows about, including the
 *                         surface it ran on (`source_kind` cli | vscode) and `missing_candidate`,
 *                         which flags a catalogued thread whose backing rollout is gone. Rollout
 *                         files alone cannot tell you a thread was deleted; this table can.
 *                         automations / automation_runs — scheduled, recurring agent runs. Each
 *                         row carries the standing `prompt`, an RFC 5545 `rrule`, the working
 *                         directories it runs in, and next/last run times. That is an execution
 *                         persistence mechanism expressed entirely in application data.
 *
 *   logs*.sqlite          The Rust tracing log. `feedback_log_body` on
 *                         `codex_core::session::handlers` records each `Submission` verbatim,
 *                         including `op: UserInput` with the prompt text. This is a second copy of
 *                         prompt text on a different lifecycle from history.jsonl and the rollouts,
 *                         so it can survive their deletion (and vice versa).
 *
 * Live stores commonly use WAL, so each database is snapshotted with its -wal/-shm/-journal
 * companions before opening. SourceFile always points at the acquired artifact, never the copy.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { openVscdbReadOnly, listTables, safeCloseDb } = require("./vscdb-kv");
const { TOOL_CODEX } = require("./schema");
const { formatTimestampUtc, makeRow, sortAndNumberRows } = require("./row-utils");
const { copySqliteFamilyToTemp, parseFlexibleTimestamp } = require("./codex-state-sqlite");

/** Relative location of the app-server store inside a `.codex` root. */
const CODEX_DEV_DB_REL = ["sqlite", "codex-dev.db"];
/** `logs.sqlite` / `logs_2.sqlite` — the version suffix increments across releases. */
const LOGS_DB_RE = /^logs(?:_(\d+))?\.sqlite$/i;

const DEFAULT_MAX_CATALOG_ROWS = 500;
const DEFAULT_MAX_AUTOMATION_ROWS = 200;
const DEFAULT_MAX_SUBMISSION_ROWS = 2000;

function auxRow(fields) {
  return makeRow({ ...fields, tool: TOOL_CODEX, role: fields.role || "system" }, TOOL_CODEX);
}

/**
 * `local_thread_catalog` stores its epochs in REAL columns. The shared parser only accepts integral
 * digit strings, so a fractional second would fall through to the ISO branch and parse as null.
 * Round numerics to whole seconds before delegating.
 */
function parseStoreTimestamp(raw) {
  if (typeof raw === "number" && Number.isFinite(raw)) return parseFlexibleTimestamp(Math.round(raw));
  return parseFlexibleTimestamp(raw);
}

function asText(value) {
  if (value == null) return "";
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  return String(value);
}

function serializeSafe(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

/** `cwds` is stored as a JSON array string; fall back to the raw text when it is not parseable. */
function parseJsonArrayish(raw) {
  const text = asText(raw).trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed.map((v) => asText(v)).filter(Boolean);
    if (parsed && typeof parsed === "object") return [serializeSafe(parsed)];
    return [asText(parsed)].filter(Boolean);
  } catch {
    return [text];
  }
}

/* ------------------------------------------------------------------ *
 * Rust `Debug` string extraction
 * ------------------------------------------------------------------ */

/**
 * Decode the escape sequences `#[derive(Debug)]` emits for a Rust string literal.
 * Handles `\n` `\r` `\t` `\0` `\\` `\"` `\'` and `\u{...}`; leaves anything unrecognised intact.
 */
function unescapeRustString(raw) {
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch !== "\\") { out += ch; continue; }
    const next = raw[i + 1];
    if (next === undefined) { out += ch; break; }
    if (next === "n") { out += "\n"; i += 1; continue; }
    if (next === "r") { out += "\r"; i += 1; continue; }
    if (next === "t") { out += "\t"; i += 1; continue; }
    if (next === "0") { out += "\0"; i += 1; continue; }
    if (next === "\\" || next === '"' || next === "'") { out += next; i += 1; continue; }
    if (next === "u" && raw[i + 2] === "{") {
      const end = raw.indexOf("}", i + 3);
      if (end > 0) {
        const code = Number.parseInt(raw.slice(i + 3, end), 16);
        if (Number.isFinite(code)) {
          try { out += String.fromCodePoint(code); i = end; continue; } catch { /* fall through */ }
        }
      }
    }
    out += ch;
  }
  return out;
}

/**
 * Pull every `<field>: "<literal>"` value out of a Debug-formatted record.
 *
 * A regex cannot do this correctly: prompt text routinely contains `\"`, so the closing quote has
 * to be found by scanning while honouring backslash escapes.
 *
 * @returns {string[]} decoded literals, in source order
 */
function extractDebugStringFields(body, fieldName) {
  const out = [];
  const needle = `${fieldName}: "`;
  let idx = body.indexOf(needle);
  while (idx !== -1) {
    let i = idx + needle.length;
    let raw = "";
    let closed = false;
    while (i < body.length) {
      const ch = body[i];
      if (ch === "\\") {
        raw += ch + (body[i + 1] ?? "");
        i += 2;
        continue;
      }
      if (ch === '"') { closed = true; break; }
      raw += ch;
      i += 1;
    }
    if (closed) out.push(unescapeRustString(raw));
    idx = body.indexOf(needle, closed ? i + 1 : idx + needle.length);
  }
  return out;
}

/**
 * Parse one `codex_core::session::handlers` submission log body.
 * @returns {{ threadId: string, submissionId: string, op: string, texts: string[] }|null}
 */
function parseSubmissionLogBody(body) {
  const text = asText(body);
  if (!text.includes("Submission")) return null;
  const threadId = /thread_id=([0-9a-fA-F-]{8,})/.exec(text)?.[1] || "";
  const submissionId = extractDebugStringFields(text, "id")[0] || "";
  const op = /\bop:\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(text)?.[1] || "";
  const texts = extractDebugStringFields(text, "text").filter((t) => t.trim());
  if (!threadId && !submissionId && !texts.length) return null;
  return { threadId, submissionId, op, texts };
}

/* ------------------------------------------------------------------ *
 * sqlite/codex-dev.db
 * ------------------------------------------------------------------ */

function extractThreadCatalogRows(db, sourceFile, attribution, maxRows) {
  if (maxRows <= 0) return [];
  let records;
  try {
    records = db.prepare(
      `SELECT thread_id, display_title, cwd, source_kind, source_detail, model_provider,
              git_branch, source_created_at, source_updated_at, missing_candidate, thread_source
         FROM local_thread_catalog
        ORDER BY source_updated_at DESC, source_created_at DESC
        LIMIT ?`,
    ).all(maxRows);
  } catch (e) {
    dbg("AIHIST", "codex thread catalog query failed", { err: e.message });
    return [];
  }

  return records.map((rec) => {
    const title = asText(rec.display_title).trim();
    const surface = asText(rec.source_kind).trim();
    const missing = rec.missing_candidate === 1 || rec.missing_candidate === true;
    const createdMs = parseStoreTimestamp(rec.source_created_at);
    const updatedMs = parseStoreTimestamp(rec.source_updated_at);
    // `missing_candidate` is the deletion signal — surface it in Summary so it is visible in the
    // grid without expanding the row, and keep it out of the title text itself.
    const flag = missing ? " [rollout missing]" : "";
    const surfaceLabel = surface ? ` (${surface})` : "";
    return auxRow({
      timestamp: formatTimestampUtc(updatedMs ?? createdMs),
      recordType: missing ? "thread_catalog_missing" : "thread_catalog",
      summary: `${title || "(untitled thread)"}${surfaceLabel}${flag}`,
      fullText: serializeSafe({
        threadId: asText(rec.thread_id),
        title,
        cwd: asText(rec.cwd),
        sourceKind: surface,
        sourceDetail: asText(rec.source_detail),
        threadSource: asText(rec.thread_source),
        modelProvider: asText(rec.model_provider),
        gitBranch: asText(rec.git_branch),
        createdUtc: formatTimestampUtc(createdMs),
        updatedUtc: formatTimestampUtc(updatedMs),
        missingCandidate: missing,
      }),
      toolName: surface,
      sessionId: asText(rec.thread_id),
      workspace: asText(rec.cwd),
      gitBranch: asText(rec.git_branch),
      model: asText(rec.model_provider),
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

function extractAutomationRows(db, sourceFile, attribution, maxRows) {
  if (maxRows <= 0) return [];
  let records;
  try {
    records = db.prepare("SELECT * FROM automations ORDER BY updated_at DESC LIMIT ?").all(maxRows);
  } catch (e) {
    dbg("AIHIST", "codex automations query failed", { err: e.message });
    return [];
  }

  return records.map((rec) => {
    const name = asText(rec.name).trim();
    const prompt = asText(rec.prompt);
    const rrule = asText(rec.rrule).trim();
    const status = asText(rec.status).trim();
    const cwds = parseJsonArrayish(rec.cwds);
    const createdMs = parseStoreTimestamp(rec.created_at);
    const nextMs = parseStoreTimestamp(rec.next_run_at);
    const lastMs = parseStoreTimestamp(rec.last_run_at);
    return auxRow({
      // Timestamp is when the automation was last modified — the schedule itself is in ToolInput.
      timestamp: formatTimestampUtc(parseStoreTimestamp(rec.updated_at) ?? createdMs),
      recordType: "automation",
      summary: `Scheduled automation "${name || asText(rec.id)}"`
        + `${status ? ` [${status}]` : ""}${rrule ? ` — ${rrule}` : ""}`,
      fullText: prompt || serializeSafe(rec),
      toolName: name,
      // The standing prompt is what actually executes on each firing; keep it as tool evidence.
      toolCommand: prompt,
      toolInput: serializeSafe({
        rrule,
        status,
        cwds,
        model: asText(rec.model),
        reasoningEffort: asText(rec.reasoning_effort),
        targetType: asText(rec.target_type),
        projectId: asText(rec.project_id),
        createdUtc: formatTimestampUtc(createdMs),
        nextRunUtc: formatTimestampUtc(nextMs),
        lastRunUtc: formatTimestampUtc(lastMs),
      }),
      toolDescription: rrule,
      sessionId: asText(rec.id),
      workspace: cwds[0] || "",
      model: asText(rec.model),
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

function extractAutomationRunRows(db, sourceFile, attribution, maxRows) {
  if (maxRows <= 0) return [];
  let records;
  try {
    records = db.prepare("SELECT * FROM automation_runs ORDER BY rowid DESC LIMIT ?").all(maxRows);
  } catch (e) {
    dbg("AIHIST", "codex automation_runs query failed", { err: e.message });
    return [];
  }

  return records.map((rec) => {
    const startedMs = parseStoreTimestamp(rec.started_at ?? rec.created_at ?? rec.run_at);
    const status = asText(rec.status).trim();
    return auxRow({
      timestamp: formatTimestampUtc(startedMs),
      recordType: "automation_run",
      summary: `Automation run${status ? ` [${status}]` : ""}`
        + `${rec.automation_id ? ` — ${asText(rec.automation_id)}` : ""}`,
      fullText: serializeSafe(rec),
      sessionId: asText(rec.thread_id || rec.automation_id),
      parentId: asText(rec.automation_id),
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

/* ------------------------------------------------------------------ *
 * logs*.sqlite
 * ------------------------------------------------------------------ */

function listCodexLogsDbFiles(codexRoot) {
  let entries;
  try { entries = fs.readdirSync(codexRoot, { withFileTypes: true }); } catch { return []; }
  const files = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const match = LOGS_DB_RE.exec(entry.name);
    if (!match) continue;
    const filePath = path.join(codexRoot, entry.name);
    let mtimeMs = 0;
    try { mtimeMs = fs.statSync(filePath).mtimeMs; } catch { /* ignore */ }
    files.push({ path: filePath, version: match[1] == null ? 0 : Number(match[1]), mtimeMs });
  }
  files.sort((a, b) => (b.version - a.version) || (b.mtimeMs - a.mtimeMs) || a.path.localeCompare(b.path));
  return files.map((e) => e.path);
}

/**
 * Extract prompt submissions from the tracing log.
 *
 * The store reaches hundreds of MB, so the scan is narrowed to the one target that records
 * submissions and capped. Rows are ordered newest-first so a cap keeps the most recent activity.
 */
function extractSubmissionRows(db, sourceFile, attribution, maxRows) {
  if (maxRows <= 0) return [];
  let records;
  try {
    records = db.prepare(
      `SELECT id, ts, ts_nanos, thread_id, process_uuid, feedback_log_body
         FROM logs
        WHERE feedback_log_body LIKE '%op: UserInput%'
        ORDER BY ts DESC, ts_nanos DESC
        LIMIT ?`,
    ).all(maxRows);
  } catch (e) {
    dbg("AIHIST", "codex logs submission query failed", { err: e.message });
    return [];
  }

  const rows = [];
  for (const rec of records) {
    const parsed = parseSubmissionLogBody(rec.feedback_log_body);
    if (!parsed) continue;
    const text = parsed.texts.join("\n\n").trim();
    if (!text) continue;
    const tsMs = parseStoreTimestamp(rec.ts);
    rows.push(auxRow({
      timestamp: formatTimestampUtc(tsMs),
      // The submission carries the prompt the model received, so it reads as a user-role record
      // even when the app generated it; `recordType` keeps the provenance distinguishable.
      role: "user",
      recordType: "submission",
      summary: text,
      fullText: text,
      toolName: parsed.op,
      sessionId: parsed.threadId || asText(rec.thread_id),
      // Deliberately NOT MessageId. `isSessionRow()` treats any row carrying a MessageId as a
      // session/transcript row, and the loose-dedupe pass drops a history.jsonl row whenever a
      // session row matches it on (SessionId, Role, Summary) regardless of timestamp. Putting the
      // submission id here would therefore let the tracing log suppress the canonical prompt log.
      // Both stores should stay visible: that two independent stores evidence the same prompt is
      // the finding. Exact-key dedupe still collapses genuinely identical rows.
      toolInput: serializeSafe({
        submissionId: parsed.submissionId,
        processUuid: asText(rec.process_uuid),
        logId: rec.id,
      }),
      parentId: asText(rec.process_uuid),
      sourceFile,
      lineNumber: rec.id != null ? String(rec.id) : "",
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/* ------------------------------------------------------------------ *
 * Orchestration
 * ------------------------------------------------------------------ */

/** Snapshot, open, extract, and always clean up. Returns [] on any failure. */
function withSnapshot(dbPath, fn) {
  let snapshot;
  let db;
  try {
    snapshot = copySqliteFamilyToTemp(dbPath);
    db = openVscdbReadOnly(snapshot.dbPath);
    return fn(db, snapshot);
  } catch (e) {
    dbg("AIHIST", "codex aux sqlite snapshot/open failed", { dbPath, err: e.message });
    return [];
  } finally {
    safeCloseDb(db);
    if (snapshot) snapshot.cleanup();
  }
}

function extractCodexDevDbRows(codexRoot, attribution, options) {
  const dbPath = path.join(codexRoot, ...CODEX_DEV_DB_REL);
  if (!fs.existsSync(dbPath)) return { rows: [], acquired: null };

  const maxCatalog = options.maxThreadCatalogRows ?? DEFAULT_MAX_CATALOG_ROWS;
  const maxAutomations = options.maxAutomationRows ?? DEFAULT_MAX_AUTOMATION_ROWS;

  const rows = withSnapshot(dbPath, (db) => {
    const tables = new Set(listTables(db));
    const out = [];
    if (tables.has("local_thread_catalog")) {
      out.push(...extractThreadCatalogRows(db, dbPath, attribution, maxCatalog));
    }
    if (tables.has("automations")) {
      out.push(...extractAutomationRows(db, dbPath, attribution, maxAutomations));
    }
    if (tables.has("automation_runs")) {
      out.push(...extractAutomationRunRows(db, dbPath, attribution, maxAutomations));
    }
    return out;
  });

  return { rows, acquired: rows.length ? dbPath : null };
}

function extractCodexLogsDbRows(codexRoot, attribution, options) {
  const candidates = listCodexLogsDbFiles(codexRoot);
  if (!candidates.length) return { rows: [], acquired: null, candidates };

  const maxSubmissions = options.maxSubmissionRows ?? DEFAULT_MAX_SUBMISSION_ROWS;
  const dbPath = candidates[0];
  const rows = withSnapshot(dbPath, (db) => {
    const tables = new Set(listTables(db));
    if (!tables.has("logs")) return [];
    return extractSubmissionRows(db, dbPath, attribution, maxSubmissions);
  });

  return { rows, acquired: rows.length ? dbPath : null, candidates };
}

/**
 * Collect supplemental Codex rows from `sqlite/codex-dev.db` and `logs*.sqlite`.
 *
 * @returns {{ rows: object[], stats: object|null }}
 */
function supplementCodexFromAuxSqlite(codexRoot, attribution = {}, options = {}) {
  const devDb = extractCodexDevDbRows(codexRoot, attribution, options);
  const logsDb = extractCodexLogsDbRows(codexRoot, attribution, options);

  const all = [...devDb.rows, ...logsDb.rows];
  if (!all.length) return { rows: [], stats: null };

  // Key on the source row identity (Timestamp + LineNumber, which carries the originating row id)
  // as well as the text. Keying on text alone would collapse a prompt legitimately repeated inside
  // one thread — "Proceed with the fix" twice is two events, not one.
  const seen = new Set();
  const unique = sortAndNumberRows(all).filter((r) => {
    const k = `${r.RecordType}:${r.SessionId}:${r.Timestamp}:${r.LineNumber}:${r.Summary.slice(0, 120)}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const counts = unique.reduce((acc, r) => {
    acc[r.RecordType] = (acc[r.RecordType] || 0) + 1;
    return acc;
  }, {});

  return {
    rows: unique,
    stats: {
      totalRows: unique.length,
      threadCatalogRows: (counts.thread_catalog || 0) + (counts.thread_catalog_missing || 0),
      missingRolloutThreads: counts.thread_catalog_missing || 0,
      automationRows: (counts.automation || 0) + (counts.automation_run || 0),
      submissionRows: counts.submission || 0,
      sources: [devDb.acquired, logsDb.acquired].filter(Boolean),
    },
  };
}

function buildCodexAuxSqliteNotice(stats) {
  if (!stats?.totalRows) return "";
  const parts = [];
  if (stats.threadCatalogRows) {
    parts.push(`${stats.threadCatalogRows} thread-catalog`
      + (stats.missingRolloutThreads ? ` (${stats.missingRolloutThreads} with no rollout on disk)` : ""));
  }
  if (stats.automationRows) parts.push(`${stats.automationRows} scheduled-automation`);
  if (stats.submissionRows) parts.push(`${stats.submissionRows} logged-submission`);
  const sources = stats.sources.map((p) => path.basename(p)).join(", ");
  return `OpenAI Codex: +${stats.totalRows} row(s) from auxiliary stores`
    + `${parts.length ? ` — ${parts.join(", ")}` : ""}${sources ? ` (${sources})` : ""}.`;
}

module.exports = {
  CODEX_DEV_DB_REL,
  LOGS_DB_RE,
  listCodexLogsDbFiles,
  unescapeRustString,
  extractDebugStringFields,
  parseSubmissionLogBody,
  supplementCodexFromAuxSqlite,
  buildCodexAuxSqliteNotice,
};
