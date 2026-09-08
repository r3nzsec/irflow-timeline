/**
 * codex-thread-history-sqlite.js — `~/.codex/thread_history*.sqlite`, the desktop app's SQL
 * projection of the rollout JSONL files.
 *
 * Verified on a live host (Codex 0.153, September 2026):
 *   thread_items  one row per transcript item — item_type ∈ userMessage, agentMessage,
 *                 commandExecution (command, cwd, pid, status, exit code, aggregated output),
 *                 fileChange (path + diff), mcpToolCall / dynamicToolCall (server, tool, arguments),
 *                 webSearch (query + the URL the agent opened), subAgentActivity, imageView,
 *                 reasoning, contextCompaction — with created_at_ms and the rollout ordinal.
 *   thread_turns  one row per turn: status (completed | failed), started/completed epoch seconds,
 *                 duration, error JSON.
 *
 * Why it matters: the rollouts are the primary transcript, but a rollout can be hundreds of MB
 * (one was 903 MB) and anything over the parse cap is inventoried, not read. The projection holds
 * the same items in queryable form, so a thread whose rollout is over the cap — or has been
 * deleted — can still be reconstructed here. It is NOT a full mirror: on the live host only 103 of
 * 316 threads were projected and the six largest rollouts had no rows at all, so it supplements
 * the rollouts rather than replacing them.
 *
 * Default mode is "supplement": only threads whose rollout is missing or over the cap are emitted,
 * so the timeline does not carry every item twice. `codexThreadHistoryMode: "all"` emits every
 * projected thread. `reasoning` and `contextCompaction` items carry no user-visible content on
 * this schema (empty summary/content arrays) and are skipped.
 *
 * Live stores use WAL; the database is snapshotted with its companions before opening. Rows are
 * read per thread with an iterator and can be streamed through `options.onRows`, so a 65K-item
 * projection never has to sit in the heap at once.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { openVscdbReadOnly, listTables, safeCloseDb } = require("./vscdb-kv");
const { copySqliteFamilyToTemp, parseFlexibleTimestamp } = require("./codex-state-sqlite");
const { TOOL_CODEX } = require("./schema");
const { formatTimestampUtc, makeRow, sortAndNumberRows, truncateSummary } = require("./row-utils");

const THREAD_HISTORY_DB_RE = /^thread_history(?:_(\d+))?\.sqlite$/i;
const ROLLOUT_THREAD_ID_RE = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$/i;
const DEFAULT_MAX_ITEMS_PER_THREAD = 20000;
const DEFAULT_MAX_TOTAL_ITEMS = 150000;
const MAX_BODY_CHARS = 8000;
const SKIPPED_ITEM_TYPES = new Set(["reasoning", "contextCompaction"]);

function historyRow(fields) {
  return makeRow({ ...fields, tool: TOOL_CODEX }, TOOL_CODEX);
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

function cap(text, max = MAX_BODY_CHARS) {
  const s = asText(text);
  return s.length > max ? `${s.slice(0, max)}\n…[truncated ${s.length - max} chars]` : s;
}

/** `[{type:"text", text}]`, `[{type:"inputText", text}]`, plain strings, or nested content. */
function textOfContent(content) {
  if (content == null) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content.map((part) => {
      if (part == null) return "";
      if (typeof part === "string") return part;
      if (typeof part === "object") {
        if (typeof part.text === "string") return part.text;
        if (part.content != null) return textOfContent(part.content);
      }
      return "";
    }).filter(Boolean).join("\n");
  }
  if (typeof content === "object") {
    if (typeof content.text === "string") return content.text;
    if (content.content != null) return textOfContent(content.content);
  }
  return "";
}

function listThreadHistoryDbFiles(codexRoot) {
  let entries;
  try { entries = fs.readdirSync(codexRoot, { withFileTypes: true }); } catch { return []; }
  const files = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const m = THREAD_HISTORY_DB_RE.exec(entry.name);
    if (!m) continue;
    const filePath = path.join(codexRoot, entry.name);
    let mtimeMs = 0;
    try { mtimeMs = fs.statSync(filePath).mtimeMs; } catch { /* ignore */ }
    files.push({ path: filePath, version: m[1] == null ? 0 : Number(m[1]), mtimeMs });
  }
  files.sort((a, b) => (b.version - a.version) || (b.mtimeMs - a.mtimeMs) || a.path.localeCompare(b.path));
  return files.map((f) => f.path);
}

/** thread id → { path, size } for every rollout under sessions/ and archived_sessions/. */
function buildRolloutIndex(codexRoot) {
  const { listRolloutFiles } = require("./codex");
  const index = new Map();
  for (const rolloutPath of listRolloutFiles(codexRoot)) {
    const m = ROLLOUT_THREAD_ID_RE.exec(path.basename(rolloutPath));
    if (!m) continue;
    let size = 0;
    try { size = fs.statSync(rolloutPath).size; } catch { continue; }
    index.set(m[1].toLowerCase(), { path: rolloutPath, size });
  }
  return index;
}

/**
 * Decide which projected threads to emit.
 * @returns {{ threadId: string, items: number, reason: string, rolloutPath: string, rolloutBytes: number|null }[]}
 */
function selectThreads(db, rolloutIndex, capBytes, mode, rolloutCoverage = new Map()) {
  let groups;
  try {
    groups = db.prepare("SELECT thread_id, COUNT(*) AS n FROM thread_items GROUP BY thread_id").all();
  } catch (e) {
    dbg("AIHIST", "codex thread_history group query failed", { err: e.message });
    return [];
  }
  const out = [];
  for (const g of groups) {
    const threadId = asText(g.thread_id);
    if (!threadId) continue;
    const rollout = rolloutIndex.get(threadId.toLowerCase());
    const coverage = rolloutCoverage.get(threadId.toLowerCase());
    let reason = "";
    if (!rollout) reason = "rollout missing";
    else if (coverage?.status === "partial") reason = "rollout parse incomplete";
    else if (coverage?.status === "unavailable") reason = "rollout unavailable";
    else if (!coverage && rollout.size > capBytes) reason = "rollout over parse cap";
    if (mode !== "all" && !reason) continue;
    out.push({
      threadId,
      items: Number(g.n) || 0,
      reason: reason || "all threads requested",
      rolloutPath: rollout?.path || "",
      rolloutBytes: rollout ? rollout.size : null,
      rolloutStatus: coverage?.status || "not observed",
    });
  }
  return out;
}

function baseFields(rec, ctx) {
  const tsMs = parseFlexibleTimestamp(rec.created_at_ms);
  return {
    timestamp: tsMs == null ? "" : formatTimestampUtc(tsMs),
    timestampBasis: tsMs == null ? "unavailable" : "thread_history created_at_ms",
    sessionId: asText(rec.thread_id),
    parentId: asText(rec.turn_id),
    sourceFile: ctx.dbPath,
    lineNumber: rec.rollout_ordinal != null ? String(rec.rollout_ordinal) : "",
    user: ctx.attribution.user || "",
    host: ctx.attribution.host || "",
  };
}

/** One projected transcript item → one timeline row (or null for content-free kinds). */
function itemRow(rec, ctx) {
  let item;
  try { item = JSON.parse(asText(rec.item_json)); } catch { item = null; }
  const type = asText(rec.item_type) || asText(item?.type);
  if (!type || SKIPPED_ITEM_TYPES.has(type)) return null;
  const base = { ...baseFields(rec, ctx), messageId: asText(item?.id) };
  if (!item || typeof item !== "object") {
    return historyRow({ ...base, role: "system", recordType: `item_${type}`, summary: `${type} (unparseable item_json)`, fullText: cap(rec.item_json) });
  }

  if (type === "userMessage") {
    const text = textOfContent(item.content);
    if (!text.trim()) return null;
    return historyRow({ ...base, role: "user", recordType: "user", summary: text, fullText: text });
  }
  if (type === "agentMessage") {
    const text = typeof item.text === "string" ? item.text : textOfContent(item.content);
    if (!text.trim()) return null;
    const phase = asText(item.phase);
    return historyRow({
      ...base,
      role: "assistant",
      recordType: "assistant",
      summary: text,
      fullText: text,
      toolDescription: phase && phase !== "final" ? `Agent message phase: ${phase}` : "",
    });
  }
  if (type === "commandExecution") {
    const command = asText(item.command);
    const exitCode = item.exitCode != null ? String(item.exitCode) : "";
    const status = asText(item.status);
    const actions = Array.isArray(item.commandActions) ? item.commandActions : [];
    return historyRow({
      ...base,
      role: "tool",
      recordType: "tool_call",
      toolName: "shell",
      toolCommand: command,
      workspace: asText(item.cwd),
      summary: `$ ${truncateSummary(command)}${exitCode ? ` → exit ${exitCode}` : status ? ` (${status})` : ""}`,
      fullText: `${command}${item.aggregatedOutput ? `\n\n${cap(item.aggregatedOutput)}` : ""}`,
      toolInput: serializeSafe({
        status,
        exitCode: item.exitCode ?? null,
        durationMs: item.durationMs ?? null,
        processId: item.processId ?? null,
        source: item.source ?? null,
        pluginId: item.pluginId ?? null,
        scriptPath: item.scriptPath ?? null,
        commandActions: actions.slice(0, 50),
      }),
      toolDescription: "Command the agent executed on this machine, from the thread_history projection "
        + "(cwd, pid, exit code and captured output retained).",
    });
  }
  if (type === "fileChange") {
    const changes = Array.isArray(item.changes) ? item.changes : [];
    const paths = changes.map((c) => asText(c?.path)).filter(Boolean);
    const diffs = changes.map((c) => `--- ${asText(c?.path)} (${asText(c?.kind?.type) || "change"})\n${asText(c?.diff)}`).join("\n\n");
    return historyRow({
      ...base,
      role: "tool",
      recordType: "file_change",
      toolName: "apply_patch",
      summary: `File change${item.status ? ` (${item.status})` : ""}: ${truncateSummary(paths.join(", ") || "(no path)")}`,
      fullText: cap(diffs),
      toolInput: serializeSafe({ status: item.status ?? null, changes: changes.slice(0, 50).map((c) => ({ path: c?.path ?? null, kind: c?.kind ?? null })) }),
      workspace: paths.length ? path.dirname(paths[0]) : "",
    });
  }
  if (type === "mcpToolCall" || type === "dynamicToolCall") {
    const server = asText(item.server ?? item.namespace);
    const tool = asText(item.tool);
    const name = server && tool ? `${server}/${tool}` : (tool || server || type);
    const result = textOfContent(item.contentItems ?? item.result ?? item.output);
    return historyRow({
      ...base,
      role: "tool",
      recordType: "tool_call",
      toolName: name,
      toolInput: serializeSafe(item.arguments ?? {}),
      summary: `${type === "mcpToolCall" ? "MCP" : "Tool"} ${name}${item.status ? ` (${item.status})` : ""}`,
      fullText: `${serializeSafe(item.arguments ?? {})}${result ? `\n\n${cap(result)}` : ""}`,
      toolDescription: serializeSafe({ status: item.status ?? null, success: item.success ?? null, durationMs: item.durationMs ?? null }),
    });
  }
  if (type === "webSearch") {
    const action = item.action && typeof item.action === "object" ? item.action : {};
    const url = asText(action.url);
    const query = asText(item.query);
    const results = textOfContent(item.results);
    return historyRow({
      ...base,
      role: "tool",
      recordType: "web_search",
      toolName: "webSearch",
      toolInput: serializeSafe(action),
      summary: url ? `Agent opened ${url}` : `Web search: ${truncateSummary(query)}`,
      fullText: `${query}${url && url !== query ? `\n${url}` : ""}${results ? `\n\n${cap(results)}` : ""}`,
      toolDescription: "Web access performed by the agent (search or page open) as recorded in the projection.",
    });
  }
  if (type === "collabAgentToolCall") {
    const tool = asText(item.tool) || "collab";
    const receivers = Array.isArray(item.receiverThreadIds) ? item.receiverThreadIds.map(asText) : [];
    const prompt = asText(item.prompt);
    return historyRow({
      ...base,
      role: "tool",
      recordType: "tool_call",
      toolName: `collab/${tool}`,
      toolInput: serializeSafe({ receiverThreadIds: receivers, model: item.model ?? null, reasoningEffort: item.reasoningEffort ?? null, status: item.status ?? null }),
      summary: `Collab ${tool}${item.status ? ` (${item.status})` : ""}${receivers.length ? ` → ${receivers.join(", ")}` : ""}${prompt ? `: ${truncateSummary(prompt)}` : ""}`,
      fullText: prompt ? `${prompt}\n\n${serializeSafe(item.agentsStates ?? {})}` : serializeSafe(item),
      toolDescription: "Multi-agent coordination call (spawn / send / wait) between Codex threads.",
    });
  }
  if (type === "subAgentActivity") {
    const agentThreadId = asText(item.agentThreadId);
    return historyRow({
      ...base,
      role: "system",
      recordType: "subagent_activity",
      summary: `Subagent ${asText(item.kind) || "activity"} — ${agentThreadId || "?"}${item.agentPath ? ` (${item.agentPath})` : ""}`,
      fullText: serializeSafe(item),
      toolInput: agentThreadId,
    });
  }
  if (type === "imageView") {
    const p = asText(item.path);
    return historyRow({
      ...base,
      role: "tool",
      recordType: "image_view",
      toolName: "imageView",
      toolInput: p,
      summary: `Agent viewed image ${p || "(no path)"}`,
      fullText: serializeSafe(item),
      toolDescription: "An image the agent looked at. Clipboard pastes land in $TMPDIR/codex-clipboard-*.png, outside the .codex root.",
    });
  }
  return historyRow({
    ...base,
    role: "system",
    recordType: `item_${type.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}`,
    summary: truncateSummary(serializeSafe(item)),
    fullText: cap(serializeSafe(item)),
  });
}

function turnRows(db, threadId, ctx) {
  let records;
  try {
    records = db.prepare(
      `SELECT thread_id, turn_id, rollout_ordinal, status, error_json, started_at, completed_at, duration_ms
         FROM thread_turns WHERE thread_id = ? ORDER BY started_at`,
    ).all(threadId);
  } catch { return []; }
  return records.map((rec) => {
    const startMs = parseFlexibleTimestamp(rec.started_at);
    const endMs = parseFlexibleTimestamp(rec.completed_at);
    const status = asText(rec.status);
    const error = asText(rec.error_json);
    return historyRow({
      timestamp: startMs == null ? "" : formatTimestampUtc(startMs),
      timestampBasis: startMs == null ? "unavailable" : "thread_turns started_at",
      role: "system",
      recordType: "turn",
      summary: `Turn ${status || "?"}${rec.duration_ms != null ? ` in ${rec.duration_ms} ms` : ""}${error ? ` — ${truncateSummary(error)}` : ""}`,
      fullText: serializeSafe({
        status,
        startedAt: startMs == null ? null : formatTimestampUtc(startMs),
        completedAt: endMs == null ? null : formatTimestampUtc(endMs),
        durationMs: rec.duration_ms ?? null,
        error: error || null,
      }),
      sessionId: asText(rec.thread_id),
      messageId: asText(rec.turn_id),
      sourceFile: ctx.dbPath,
      lineNumber: rec.rollout_ordinal != null ? String(rec.rollout_ordinal) : "",
      user: ctx.attribution.user || "",
      host: ctx.attribution.host || "",
    });
  });
}

/**
 * @param {string} codexRoot
 * @param {object} attribution
 * @param {object} options  codexThreadHistoryMode ("supplement" | "all"), onRows (streaming sink),
 *                          maxThreadHistoryItemsPerThread, maxThreadHistoryItems
 * @returns {{ rows: object[], stats: object|null }}
 */
function supplementCodexFromThreadHistory(codexRoot, attribution = {}, options = {}) {
  const candidates = listThreadHistoryDbFiles(codexRoot);
  if (!candidates.length) return { rows: [], stats: null };
  const dbPath = candidates[0];
  const mode = options.codexThreadHistoryMode === "all" ? "all" : "supplement";
  const perThreadCap = options.maxThreadHistoryItemsPerThread ?? DEFAULT_MAX_ITEMS_PER_THREAD;
  const totalCap = options.maxThreadHistoryItems ?? DEFAULT_MAX_TOTAL_ITEMS;
  const { MAX_CODEX_ROLLOUT_BYTES } = require("./codex");
  const rolloutIndex = buildRolloutIndex(codexRoot);
  const ctx = { dbPath, attribution };

  const collected = [];
  const stats = {
    totalRows: 0,
    dbPath,
    mode,
    threadsInProjection: 0,
    itemsInProjection: 0,
    threadsSupplemented: 0,
    threadsMissingRollout: 0,
    threadsOverCap: 0,
    threadsIncompleteRollout: 0,
    threadsUnavailableRollout: 0,
    itemsSkipped: 0,
    turnRows: 0,
    capped: false,
    threads: [],
  };
  const sink = typeof options.onRows === "function" ? options.onRows : null;
  const emit = (batch) => {
    if (!batch.length) return;
    stats.totalRows += batch.length;
    if (sink) sink(sortAndNumberRows(batch));
    else for (const r of batch) collected.push(r);
  };

  let snapshot;
  let db;
  try {
    snapshot = copySqliteFamilyToTemp(dbPath, { checkAbort: options.checkAbort });
    stats.acquisition = {
      method: snapshot.snapshotMethod,
      acquiredAtMs: snapshot.acquiredAtMs,
      integrityCheck: snapshot.integrityCheck,
      originalIdentity: snapshot.originalIdentity,
      snapshotIdentity: snapshot.snapshotIdentity,
    };
    db = openVscdbReadOnly(snapshot.dbPath);
    const tables = new Set(listTables(db));
    if (!tables.has("thread_items")) return { rows: [], stats: null };

    try {
      const totals = db.prepare("SELECT COUNT(DISTINCT thread_id) AS t, COUNT(*) AS n FROM thread_items").get();
      stats.threadsInProjection = Number(totals?.t) || 0;
      stats.itemsInProjection = Number(totals?.n) || 0;
    } catch { /* keep zeros */ }

    const selected = selectThreads(
      db,
      rolloutIndex,
      MAX_CODEX_ROLLOUT_BYTES,
      mode,
      options.rolloutCoverage instanceof Map ? options.rolloutCoverage : new Map(),
    );
    const itemStmt = db.prepare(
      `SELECT thread_id, turn_id, item_id, rollout_ordinal, created_at_ms, item_json, item_type
         FROM thread_items WHERE thread_id = ? ORDER BY rollout_ordinal, created_at_ms`,
    );
    let emittedItems = 0;
    for (const sel of selected) {
      options.checkAbort?.();
      if (emittedItems >= totalCap) { stats.capped = true; break; }
      const batch = [];
      let perThread = 0;
      for (const rec of itemStmt.iterate(sel.threadId)) {
        if (perThread >= perThreadCap || emittedItems >= totalCap) { stats.capped = true; break; }
        const row = itemRow(rec, ctx);
        if (!row) { stats.itemsSkipped += 1; continue; }
        batch.push(row);
        perThread += 1;
        emittedItems += 1;
      }
      if (tables.has("thread_turns")) {
        const turns = turnRows(db, sel.threadId, ctx);
        stats.turnRows += turns.length;
        batch.push(...turns);
      }
      stats.threadsSupplemented += 1;
      if (sel.reason === "rollout missing") stats.threadsMissingRollout += 1;
      else if (sel.reason === "rollout over parse cap") stats.threadsOverCap += 1;
      else if (sel.reason === "rollout parse incomplete") stats.threadsIncompleteRollout += 1;
      else if (sel.reason === "rollout unavailable") stats.threadsUnavailableRollout += 1;
      stats.threads.push({ threadId: sel.threadId, items: perThread, reason: sel.reason, rolloutBytes: sel.rolloutBytes });
      emit(batch);
    }

    if (stats.threadsInProjection) {
      const reasons = [
        stats.threadsMissingRollout ? `${stats.threadsMissingRollout} missing rollout` : "",
        stats.threadsOverCap ? `${stats.threadsOverCap} over legacy parse cap` : "",
        stats.threadsIncompleteRollout ? `${stats.threadsIncompleteRollout} partly parsed rollout` : "",
        stats.threadsUnavailableRollout ? `${stats.threadsUnavailableRollout} unreadable rollout` : "",
      ].filter(Boolean);
      emit([historyRow({
        timestamp: formatTimestampUtc(fs.statSync(dbPath).mtimeMs),
        timestampBasis: "thread_history database mtime",
        role: "metadata",
        recordType: "thread_history_coverage",
        summary: `Codex thread_history projection — ${stats.threadsInProjection} thread(s), ${stats.itemsInProjection} item(s); `
          + `${stats.threadsSupplemented} thread(s) reconstructed from it`
          + `${reasons.length ? ` (${reasons.join(", ")})` : ""}`,
        fullText: serializeSafe({ ...stats, dbPath }),
        toolDescription: "The projection is written by the desktop app alongside the rollouts and does not "
          + "cover every thread; threads listed here were emitted from it because their rollout JSONL was "
          + "missing, unreadable, or only partly parsed. Timestamp is the database mtime.",
        sourceFile: dbPath,
        lineNumber: 1,
        user: attribution.user || "",
        host: attribution.host || "",
      })]);
    }
  } catch (e) {
    dbg("AIHIST", "codex thread_history extract failed", { dbPath, err: e.message });
    return { rows: [], stats: null };
  } finally {
    safeCloseDb(db);
    if (snapshot) snapshot.cleanup();
  }

  return { rows: sink ? [] : sortAndNumberRows(collected), stats: stats.totalRows ? stats : null };
}

function buildCodexThreadHistoryNotice(stats) {
  if (!stats?.totalRows) return "";
  const reasons = [];
  if (stats.threadsOverCap) reasons.push(`${stats.threadsOverCap} whose rollout is over the parse cap`);
  if (stats.threadsMissingRollout) reasons.push(`${stats.threadsMissingRollout} whose rollout is missing`);
  if (stats.threadsIncompleteRollout) reasons.push(`${stats.threadsIncompleteRollout} whose rollout parsed partly`);
  if (stats.threadsUnavailableRollout) reasons.push(`${stats.threadsUnavailableRollout} whose rollout was unreadable`);
  return `OpenAI Codex: +${stats.totalRows} row(s) from the thread_history projection — `
    + `${stats.threadsSupplemented} thread(s) reconstructed${reasons.length ? ` (${reasons.join(", ")})` : ""}`
    + ` of ${stats.threadsInProjection} projected${stats.capped ? "; row cap reached" : ""}`
    + ` (${path.basename(stats.dbPath)}).`;
}

module.exports = {
  THREAD_HISTORY_DB_RE,
  SKIPPED_ITEM_TYPES,
  listThreadHistoryDbFiles,
  buildRolloutIndex,
  textOfContent,
  itemRow,
  supplementCodexFromThreadHistory,
  buildCodexThreadHistoryNotice,
};
