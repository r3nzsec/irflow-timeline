"use strict";

/**
 * thread_history*.sqlite — the desktop app's SQL projection of the rollouts. It must reconstruct
 * threads whose rollout is missing or over the parse cap, and must NOT duplicate threads whose
 * rollout was parsed in full.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  listThreadHistoryDbFiles,
  buildRolloutIndex,
  textOfContent,
  supplementCodexFromThreadHistory,
  buildCodexThreadHistoryNotice,
} = require("../electron/parsers/ai-history/codex-thread-history-sqlite");
const { extractCodexDir } = require("../electron/parsers/ai-history/codex");

function requireSqlite() {
  try { return require("better-sqlite3"); } catch (e) {
    if (e.code === "ERR_DLOPEN_FAILED") return null;
    throw e;
  }
}

const COVERED = "019fe579-5be6-7e32-ba52-f863f31a9c5c";
const MISSING = "01a066c8-c2c7-79d1-ae32-7e492bcbc1ad";

function item(threadId, turnId, ordinal, createdMs, obj) {
  return [threadId, turnId, obj.id, ordinal, createdMs, JSON.stringify(obj), obj.type];
}

function makeRoot(Database) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-th-"));
  const root = path.join(tmp, ".codex");
  const sessions = path.join(root, "sessions", "2026", "09", "03");
  fs.mkdirSync(sessions, { recursive: true });
  // A small rollout exists for COVERED; MISSING has none.
  fs.writeFileSync(path.join(sessions, `rollout-2026-09-03T14-20-28-${COVERED}.jsonl`), '{"type":"session_meta","payload":{"id":"x"}}\n');

  const db = new Database(path.join(root, "thread_history_1.sqlite"));
  db.exec(`CREATE TABLE thread_items (thread_id TEXT, turn_id TEXT, item_id TEXT, rollout_ordinal INTEGER, created_at_ms INTEGER, item_json TEXT, item_type TEXT, updated_at_ordinal INTEGER);
    CREATE TABLE thread_turns (thread_id TEXT, turn_id TEXT, rollout_ordinal INTEGER, status TEXT, error_json TEXT, started_at INTEGER, completed_at INTEGER, duration_ms INTEGER,
      first_user_item_id TEXT, final_agent_item_id TEXT, rollout_byte_offset INTEGER, rollout_end_ordinal INTEGER, rollout_end_byte_offset INTEGER);`);
  const ins = db.prepare("INSERT INTO thread_items (thread_id, turn_id, item_id, rollout_ordinal, created_at_ms, item_json, item_type) VALUES (?,?,?,?,?,?,?)");
  const t0 = 1788775209000;
  const rows = [
    item(MISSING, "turn-1", 1, t0, { type: "userMessage", id: "u-1", content: [{ type: "text", text: "download the report for me" }] }),
    item(MISSING, "turn-1", 2, t0 + 1000, { type: "reasoning", id: "rs-1", summary: [], content: [] }),
    item(MISSING, "turn-1", 3, t0 + 2000, { type: "commandExecution", id: "exec-1", command: "/bin/zsh -lc 'curl -O https://example.test/report.pdf'", cwd: "/Users/subject/Downloads", processId: "31485", source: "unifiedExecStartup", status: "completed", commandActions: [{ type: "read", command: "curl" }], aggregatedOutput: "saved report.pdf", exitCode: 0, durationMs: 1200 }),
    item(MISSING, "turn-1", 4, t0 + 3000, { type: "webSearch", id: "exec-2", query: "https://example.test/report", action: { type: "openPage", url: "https://example.test/report" }, results: [{ type: "text_result", text: "Report page" }] }),
    item(MISSING, "turn-1", 5, t0 + 4000, { type: "fileChange", id: "exec-3", status: "completed", changes: [{ path: "/Users/subject/notes.md", kind: { type: "update" }, diff: "@@ -1 +1 @@\n-a\n+b" }] }),
    item(MISSING, "turn-1", 6, t0 + 5000, { type: "mcpToolCall", id: "exec-4", server: "node_repl", tool: "js", status: "failed", arguments: { code: "1+1" }, contentItems: [{ type: "inputText", text: "SyntaxError" }] }),
    item(MISSING, "turn-1", 7, t0 + 6000, { type: "imageView", id: "exec-5", path: "/tmp/codex-clipboard-abc.png" }),
    item(MISSING, "turn-1", 8, t0 + 7000, { type: "subAgentActivity", id: "call-1", kind: "started", agentThreadId: "019feae4-6e4e-75b2-902f-a288344a76d3", agentPath: "/root/audit" }),
    item(MISSING, "turn-1", 9, t0 + 8000, { type: "collabAgentToolCall", id: "call-2", tool: "wait", status: "completed", senderThreadId: MISSING, receiverThreadIds: ["019feae4-6e4e-75b2-902f-a288344a76d3"] }),
    item(MISSING, "turn-1", 10, t0 + 9000, { type: "agentMessage", id: "msg-1", text: "Saved it to Downloads.", phase: "final" }),
    item(COVERED, "turn-9", 1, t0, { type: "userMessage", id: "u-9", content: [{ type: "text", text: "covered thread prompt" }] }),
  ];
  for (const r of rows) ins.run(...r);
  db.prepare("INSERT INTO thread_turns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(MISSING, "turn-1", 1, "failed", '{"message":"timeout"}', 1788775209, 1788775214, 5011, "u-1", "msg-1", 0, 10, 100);
  db.close();
  return { tmp, root };
}

test("textOfContent flattens text parts", () => {
  assert.equal(textOfContent([{ type: "text", text: "a" }, { type: "inputText", text: "b" }]), "a\nb");
  assert.equal(textOfContent("plain"), "plain");
  assert.equal(textOfContent(null), "");
});

test("supplement mode reconstructs only threads whose rollout is missing or over the cap", () => {
  const Database = requireSqlite();
  if (!Database) return;
  const { tmp, root } = makeRoot(Database);
  try {
    assert.equal(listThreadHistoryDbFiles(root).length, 1);
    const index = buildRolloutIndex(root);
    assert.ok(index.has(COVERED));
    assert.ok(!index.has(MISSING));

    const { rows, stats } = supplementCodexFromThreadHistory(root, { user: "subject" });
    assert.equal(stats.threadsInProjection, 2);
    assert.equal(stats.itemsInProjection, 11);
    assert.equal(stats.threadsSupplemented, 1);
    assert.equal(stats.threadsMissingRollout, 1);
    assert.equal(stats.itemsSkipped, 1, "reasoning has no content and is skipped");
    assert.ok(!rows.some((r) => r.SessionId === COVERED), "a thread with a parsed rollout is not duplicated");
    assert.ok(rows.every((r) => r.Tool === "OpenAI Codex" && r.User === "subject"));

    const user = rows.find((r) => r.RecordType === "user");
    assert.equal(user.Summary, "download the report for me");
    assert.equal(user.Timestamp, "2026-09-07 10:00:09");
    assert.equal(user.ParentId, "turn-1");
    assert.equal(user.MessageId, "u-1");

    const cmd = rows.find((r) => r.RecordType === "tool_call" && r.InvokedTool === "shell");
    assert.equal(cmd.ToolCommand, "/bin/zsh -lc 'curl -O https://example.test/report.pdf'");
    assert.equal(cmd.Workspace, "/Users/subject/Downloads");
    assert.match(cmd.Summary, /→ exit 0$/);
    assert.match(cmd.FullText, /saved report\.pdf/);
    assert.match(cmd.ToolInput, /"processId":"31485"/);

    const web = rows.find((r) => r.RecordType === "web_search");
    assert.equal(web.Summary, "Agent opened https://example.test/report");
    const change = rows.find((r) => r.RecordType === "file_change");
    assert.equal(change.Summary, "File change (completed): /Users/subject/notes.md");
    assert.match(change.FullText, /\+b/);
    const mcp = rows.find((r) => r.InvokedTool === "node_repl/js");
    assert.equal(mcp.Summary, "MCP node_repl/js (failed)");
    assert.match(mcp.FullText, /SyntaxError/);
    const collab = rows.find((r) => r.InvokedTool === "collab/wait");
    assert.match(collab.Summary, /^Collab wait \(completed\) → 019feae4/);
    assert.ok(rows.some((r) => r.RecordType === "image_view" && /codex-clipboard-abc\.png/.test(r.Summary)));
    assert.ok(rows.some((r) => r.RecordType === "subagent_activity" && /Subagent started — 019feae4/.test(r.Summary)));
    const reply = rows.find((r) => r.RecordType === "assistant");
    assert.equal(reply.Summary, "Saved it to Downloads.");

    const turn = rows.find((r) => r.RecordType === "turn");
    assert.equal(turn.Summary, 'Turn failed in 5011 ms — {"message":"timeout"}');
    assert.equal(turn.Timestamp, "2026-09-07 10:00:09");
    assert.equal(turn.MessageId, "turn-1");

    const coverage = rows.find((r) => r.RecordType === "thread_history_coverage");
    assert.match(coverage.Summary, /2 thread\(s\), 11 item\(s\); 1 thread\(s\) reconstructed from it \(1 missing rollout\)/);
    assert.match(buildCodexThreadHistoryNotice(stats), /\+11 row\(s\) from the thread_history projection — 1 thread\(s\) reconstructed \(1 whose rollout is missing\) of 2 projected \(thread_history_1\.sqlite\)/);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("partial rollout coverage triggers SQL projection recovery", () => {
  const Database = requireSqlite();
  if (!Database) return;
  const { tmp, root } = makeRoot(Database);
  try {
    const result = supplementCodexFromThreadHistory(root, {}, {
      rolloutCoverage: new Map([[COVERED, { status: "partial", errors: 1 }]]),
    });
    assert.equal(result.stats.threadsSupplemented, 2);
    assert.equal(result.stats.threadsIncompleteRollout, 1);
    assert.ok(result.rows.some((row) => row.SessionId === COVERED && row.Summary === "covered thread prompt"));
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("Codex directory extraction uses measured parse failure for SQL fallback", async () => {
  const Database = requireSqlite();
  if (!Database) return;
  const { tmp, root } = makeRoot(Database);
  try {
    const rollout = buildRolloutIndex(root).get(COVERED).path;
    fs.appendFileSync(rollout, "{malformed\n");
    const rows = await extractCodexDir(root);
    assert.ok(rows.some((row) => row.SessionId === COVERED && row.Summary === "covered thread prompt"));
    assert.equal(rows._codexThreadHistoryStats.threadsIncompleteRollout, 1);
    assert.ok(rows._parseErrors >= 1);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("mode 'all' emits every projected thread, and onRows streams instead of accumulating", () => {
  const Database = requireSqlite();
  if (!Database) return;
  const { tmp, root } = makeRoot(Database);
  try {
    const all = supplementCodexFromThreadHistory(root, {}, { codexThreadHistoryMode: "all" });
    assert.equal(all.stats.threadsSupplemented, 2);
    assert.ok(all.rows.some((r) => r.SessionId === COVERED && r.Summary === "covered thread prompt"));

    const streamed = [];
    const res = supplementCodexFromThreadHistory(root, {}, { onRows: (batch) => streamed.push(...batch) });
    assert.equal(res.rows.length, 0);
    assert.equal(streamed.length, res.stats.totalRows);
    assert.ok(streamed.some((r) => r.RecordType === "thread_history_coverage"));

    const capped = supplementCodexFromThreadHistory(root, {}, { maxThreadHistoryItemsPerThread: 2 });
    assert.equal(capped.stats.capped, true);
    assert.equal(capped.rows.filter((r) => r.SessionId === MISSING && r.RecordType !== "turn").length, 2);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
