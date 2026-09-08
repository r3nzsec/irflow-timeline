"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  grokEventRow,
  extractGrokSignalsFile,
  GROK_EVENT_TYPES,
  defaultGrokHome,
  isGrokBuildRoot,
  resolveGrokHome,
  isGrokBuildArtifactFile,
  listGrokSessionDirs,
  countGrokDataFiles,
  parseGrokPromptHistoryLine,
  extractGrokBuildDir,
  extractGrokBuildPath,
} = require("../electron/parsers/ai-history/grok-build");
const { detectAiHistoryImport, planImportPaths } = require("../electron/parsers/ai-history-import");

const FIXTURE_GROK = path.join(__dirname, "fixtures/ai-history/grok/.grok");
const WORKSPACE = path.join(FIXTURE_GROK, "sessions/%2Ftmp%2Fgrok-demo");
const SESSION = path.join(WORKSPACE, "grok-session-1");

test("Grok Build root discovery recognizes the official session layout", () => {
  assert.ok(defaultGrokHome().endsWith(".grok") || process.env.GROK_HOME);
  assert.equal(isGrokBuildRoot(FIXTURE_GROK), true);
  assert.equal(resolveGrokHome(path.join(SESSION, "updates.jsonl")), FIXTURE_GROK);
  assert.equal(isGrokBuildArtifactFile(path.join(SESSION, "summary.json")), true);
  assert.equal(listGrokSessionDirs(FIXTURE_GROK).length, 1);
  assert.equal(countGrokDataFiles(FIXTURE_GROK), 6, "summary, updates, hunks, events, signals + prompt history");
});

test("direct Grok shell history preserves the exact command", () => {
  const row = parseGrokPromptHistoryLine({
    timestamp: "2026-07-26T10:00:02.000Z",
    session_id: "grok-session-1",
    prompt: "whoami && id",
    is_bash: true,
  }, "prompt_history.jsonl", { user: "analyst" });
  assert.equal(row.Tool, "Grok Build");
  assert.equal(row.RecordType, "shell_command");
  assert.equal(row.InvokedTool, "shell");
  assert.equal(row.ToolCommand, "whoami && id");
  assert.equal(row.User, "analyst");
});

test("Grok updates parse exact run_terminal_command input and completion output", async () => {
  const rows = await extractGrokBuildDir(FIXTURE_GROK, { user: "analyst", host: "HOST1" });
  const call = rows.find((row) => row.RecordType === "tool_call");
  const result = rows.find((row) => row.RecordType === "tool_result");
  assert.ok(call);
  assert.equal(call.InvokedTool, "run_terminal_command");
  assert.equal(call.ToolCommand, "printf '%s\\n' \"quoted value\"");
  assert.equal(call.ToolDescription, "Print a quoted value");
  assert.equal(call.ToolInput, "{\"command\":\"printf '%s\\\\n' \\\"quoted value\\\"\",\"description\":\"Print a quoted value\"}");
  assert.ok(result);
  assert.equal(result.ParentId, "call-shell-1");
  assert.equal(result.ToolCommand, call.ToolCommand);
  assert.match(result.FullText, /Exit code: 0/);
  assert.match(result.FullText, /quoted value/);
  assert.ok(rows.some((row) => row.RecordType === "file_hunk_added"));
  assert.ok(rows.some((row) => row.RecordType === "turn_completed" && row.InputTokens === "123"));
  assert.ok(rows.every((row) => row.Tool === "Grok Build"));
  assert.ok(rows.every((row) => row.RecordId));
});

test("Grok prompt history and session message retain separate source provenance", async () => {
  const rows = await extractGrokBuildDir(FIXTURE_GROK);
  const promptRows = rows.filter((row) => row.Summary === "Inspect the suspicious process tree");
  assert.equal(promptRows.length, 2);
  assert.equal(new Set(promptRows.map((row) => row.SourceFile)).size, 2);
  assert.ok(rows.some((row) => row.RecordType === "shell_command" && row.ToolCommand === "whoami && id"));
});

test("Grok Build discovers orphan event stores and falls back after malformed updates", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grok-orphans-"));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const root = path.join(tmp, ".grok");
  const workspace = path.join(root, "sessions", "workspace");
  const orphan = path.join(workspace, "orphan-events");
  const fallback = path.join(workspace, "fallback-chat");
  fs.mkdirSync(orphan, { recursive: true });
  fs.mkdirSync(fallback, { recursive: true });
  fs.writeFileSync(path.join(orphan, "events.jsonl"), `${JSON.stringify({ type: "turn_started", ts: "2026-09-08T01:00:00Z", turn_number: 1 })}\n`);
  fs.writeFileSync(path.join(fallback, "updates.jsonl"), "{malformed\n");
  fs.writeFileSync(path.join(fallback, "chat_history.jsonl"), `${JSON.stringify({ type: "user", content: "recovered fallback prompt" })}\n`);

  assert.equal(listGrokSessionDirs(root).length, 2);
  const rows = await extractGrokBuildDir(root);
  assert.ok(rows.some((row) => row.RecordType === "turn_started"));
  assert.ok(rows.some((row) => row.Summary === "recovered fallback prompt"));
  assert.equal(rows._parseErrors, 1);
});

test("Grok Build import detection consolidates collected artifacts", async () => {
  assert.equal(detectAiHistoryImport(FIXTURE_GROK)?.tool, "grok-build");
  assert.equal(detectAiHistoryImport(path.join(SESSION, "updates.jsonl"))?.tool, "grok-build");
  const planned = planImportPaths([
    path.join(WORKSPACE, "prompt_history.jsonl"),
    path.join(SESSION, "updates.jsonl"),
  ]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "grok-build");
  assert.equal(planned[0].path, FIXTURE_GROK);

  const single = await extractGrokBuildPath(path.join(SESSION, "updates.jsonl"));
  assert.ok(single.some((row) => row.ToolCommand === "printf '%s\\n' \"quoted value\""));
});

test("Grok events.jsonl yields permission decisions, tool lifecycle, turns and MCP rows; phase noise is dropped", async () => {
  const rows = await extractGrokBuildDir(FIXTURE_GROK, { user: "analyst" });
  const fromEvents = rows.filter((row) => /events\.jsonl$/.test(row.SourceFile));
  const kinds = fromEvents.map((row) => row.RecordType);
  assert.ok(!kinds.some((k) => /phase|loop|first_token/.test(k)), "streaming chatter never reaches the timeline");

  const allow = fromEvents.find((row) => row.RecordType === "permission_allow");
  assert.equal(allow.InvokedTool, "run_terminal_command");
  assert.equal(allow.Timestamp, "2026-07-26 10:00:03");
  assert.match(allow.Summary, /\[Permission ALLOW\] run_terminal_command — decided after 4210ms/);
  assert.match(allow.ToolDescription, /Permission decision recorded/);
  const deny = fromEvents.find((row) => row.RecordType === "permission_deny");
  assert.equal(deny.InvokedTool, "write");
  assert.match(deny.ToolDescription, /under 50ms/, "an instant decision is flagged as likely automatic");
  assert.equal(fromEvents.filter((row) => row.RecordType === "permission_requested").length, 2);

  const done = fromEvents.find((row) => row.RecordType === "tool_completed");
  assert.equal(done.ParentId, "call-shell-1", "joins back to the updates.jsonl tool_call");
  assert.equal(done.MessageId, "call-shell-1:event", "distinct from the tool_result row id");
  assert.match(done.Summary, /success in 980ms/);
  const failed = fromEvents.find((row) => row.RecordType === "tool_completed_error");
  assert.equal(failed.InvokedTool, "read_file");
  assert.equal(fromEvents.filter((row) => row.RecordType === "tool_started").length, 2);

  const turn = fromEvents.find((row) => row.RecordType === "turn_started");
  assert.equal(turn.Model, "grok-4.5");
  assert.equal(turn.MessageId, "turn-1");
  assert.ok(!/YOLO/.test(turn.Summary));
  assert.equal(turn.IsSidechain, "false");
  assert.ok(fromEvents.some((row) => row.RecordType === "turn_ended" && /completed/.test(row.Summary)));

  const mcp = fromEvents.find((row) => row.RecordType === "mcp_server_starting");
  assert.match(mcp.Summary, /filesystem \(stdio\) → npx mcp-filesystem/);
  assert.equal(mcp.InvokedTool, "filesystem");
  assert.match(fromEvents.find((row) => row.RecordType === "mcp_server_connected").Summary, /2 tool\(s\) \(read_file, list_dir\)/);
  assert.match(fromEvents.find((row) => row.RecordType === "mcp_init_completed").Summary, /1\/1 server\(s\) up/);
  assert.ok(fromEvents.every((row) => row.SessionId === "grok-session-1"));
  assert.ok(fromEvents.every((row) => row.Workspace === "/tmp/grok-demo"));
});

test("grokEventRow flags yolo turns and subagent relationships", () => {
  const ctx = { sessionId: "s", workspace: "/w", isSidechain: false, gitBranch: "", model: "" };
  const yolo = grokEventRow({ ts: "2026-07-26T10:00:00Z", type: "turn_started", turn_number: 2, model_id: "grok-4.5", yolo_mode: true, session_relationship: "subagent" }, "events.jsonl", ctx);
  assert.match(yolo.Summary, /YOLO MODE \(tool approvals disabled\)/);
  assert.match(yolo.Summary, /subagent session/);
  assert.equal(yolo.IsSidechain, "true");
  assert.match(yolo.ToolDescription, /auto-approved/);
  assert.equal(grokEventRow({ ts: "2026-07-26T10:00:00Z", type: "phase_changed", phase: "streaming_text" }, "events.jsonl", ctx), null);
  assert.equal(grokEventRow({ type: "totally_new_type" }, "events.jsonl", ctx), null, "unknown types are skipped, not guessed");
  assert.ok(GROK_EVENT_TYPES.has("permission_resolved"));
});

test("signals.json becomes one metrics row plus a codebase-upload row when gcs counters are non-zero", () => {
  const ctx = {
    sessionId: "grok-session-1", workspace: "/tmp/grok-demo", isSidechain: false, gitBranch: "main", model: "grok-4.5",
    summary: { updated_at: "2026-07-26T10:00:09.000Z" },
  };
  const rows = extractGrokSignalsFile(path.join(SESSION, "signals.json"), ctx, { user: "analyst" });
  assert.equal(rows.length, 2);
  const [metrics, upload] = rows;
  assert.equal(metrics.RecordType, "session_signals");
  assert.equal(metrics.Timestamp, "2026-07-26 10:00:09", "dated from summary.json updated_at");
  assert.match(metrics.Summary, /1 turn\(s\), 1 user \/ 2 assistant message\(s\), 3 tool call\(s\) \(1 failed\), agent \+12\/-3 lines across 1 file\(s\)/);
  assert.match(metrics.Summary, /~9 min; tools: run_terminal_command, read_file; models: grok-4.5/);
  assert.match(metrics.FullText, /"timeSource": "summary.json updated_at"/);
  assert.equal(upload.RecordType, "codebase_upload_activity");
  assert.match(upload.Summary, /2 uploaded, 0 failed, 1 pending \(2048 bytes\), 3 enqueued in total/);
  assert.match(upload.ToolDescription, /xAI-run\s+cloud storage/);

  // Zero counters mean no upload row — absence of activity is not a finding.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grok-signals-"));
  try {
    const p = path.join(tmp, "signals.json");
    fs.writeFileSync(p, JSON.stringify({ turnCount: 1, gcsQueueUploaded: 0, gcsQueueEnqueued: 0 }));
    const quiet = extractGrokSignalsFile(p, { ...ctx, summary: {} }, {});
    assert.equal(quiet.length, 1);
    assert.match(quiet[0].FullText, /"timeSource": "signals.json mtime"/);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
