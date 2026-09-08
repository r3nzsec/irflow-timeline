"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  stripCodexUserText,
  parseCodexHistoryLine,
  parseRolloutEnvelope,
  extractCodexMediaReferences,
  isCodexForkedSession,
  extractCodexDir,
  extractCodexRolloutFile,
  MAX_CODEX_ROLLOUT_BYTES,
  isCodexDir,
  resolveCodexHome,
} = require("../electron/parsers/ai-history/codex");
const { filterSidechainRows } = require("../electron/parsers/ai-history/extract-plan");
const { detectAiHistoryImport, planImportPaths } = require("../electron/parsers/ai-history-import");

const FIXTURE_CODEX = path.join(__dirname, "fixtures/ai-history/codex/.codex");

test("stripCodexUserText extracts IDE prompt block", () => {
  const raw = "## My request for Codex:\nrun strings on sample.bin\n";
  assert.equal(stripCodexUserText(raw), "run strings on sample.bin");
  assert.equal(stripCodexUserText("<environment_context></environment_context>"), "");
});

test("parseCodexHistoryLine uses session_id and RecordType history", () => {
  const row = parseCodexHistoryLine(
    { session_id: "s1", ts: 1704067200, text: "hello codex" },
    "/home/u/.codex/history.jsonl",
    { user: "u" },
  );
  assert.ok(row);
  assert.equal(row.RecordType, "history");
  assert.equal(row.Tool, "OpenAI Codex");
  assert.equal(row.InvokedTool, "");
  assert.equal(row.SessionId, "s1");
});

test("isCodexForkedSession detects parent_session_id", () => {
  assert.equal(isCodexForkedSession({ id: "child", parent_session_id: "parent-1" }), true);
  assert.equal(isCodexForkedSession({ id: "child", parent_thread_id: "parent-2" }), true);
  assert.equal(isCodexForkedSession({ id: "child", forked_from_id: "parent-3" }), true);
  assert.equal(isCodexForkedSession({ id: "child", thread_source: "subagent" }), true);
  assert.equal(isCodexForkedSession({ id: "main" }), false);
});

test("parseRolloutEnvelope marks forked sessions as sidechain", () => {
  const ctx = { sessionId: "", workspace: "", model: "", threadIndex: new Map(), isSidechainSession: false };
  parseRolloutEnvelope({
    type: "session_meta",
    timestamp: "2026-01-01T12:00:00.000Z",
    payload: { id: "child", parent_session_id: "parent-1", cwd: "/proj" },
  }, "rollout.jsonl", ctx, {});
  assert.equal(ctx.isSidechainSession, true);

  const user = parseRolloutEnvelope({
    type: "event_msg",
    timestamp: "2026-01-01T12:00:01.000Z",
    payload: { type: "user_message", message: "forked prompt" },
  }, "rollout.jsonl", ctx, {});
  assert.equal(user.IsSidechain, "true");
  const mainOnly = filterSidechainRows([user], {});
  assert.equal(mainOnly.length, 0);
});

test("parseRolloutEnvelope handles messages and preserves exact function-call evidence", () => {
  const ctx = { sessionId: "", workspace: "", model: "", threadIndex: new Map(), isSidechainSession: false };
  const meta = parseRolloutEnvelope({
    type: "session_meta",
    timestamp: "2026-01-01T12:00:00.000Z",
    payload: { id: "s1", cwd: "/proj", cli_version: "1.0" },
  }, "rollout.jsonl", ctx, {});
  assert.ok(meta);
  assert.equal(ctx.sessionId, "s1");

  const user = parseRolloutEnvelope({
    type: "event_msg",
    timestamp: "2026-01-01T12:00:01.000Z",
    payload: { type: "user_message", message: "## My request for Codex:\ndo work\n" },
  }, "rollout.jsonl", ctx, {});
  assert.equal(user.Role, "user");
  assert.equal(user.Summary, "do work");

  const tool = parseRolloutEnvelope({
    type: "response_item",
    timestamp: "2026-01-01T12:00:02.000Z",
    payload: {
      type: "function_call",
      name: "shell",
      arguments: "{\"command\":[\"bash\",\"-lc\",\"printf '%s\\\\n' \\\"quoted value\\\"\"],\"description\":\"Run quoted command\"}",
      call_id: "c1",
    },
  }, "rollout.jsonl", ctx, {});
  assert.equal(tool.RecordType, "function_call");
  assert.equal(tool.InvokedTool, "shell");
  assert.equal(tool.ToolCommand, "[\"bash\",\"-lc\",\"printf '%s\\\\n' \\\"quoted value\\\"\"]");
  assert.equal(tool.ToolDescription, "Run quoted command");
  assert.equal(
    tool.ToolInput,
    "{\"command\":[\"bash\",\"-lc\",\"printf '%s\\\\n' \\\"quoted value\\\"\"],\"description\":\"Run quoted command\"}",
  );
});

test("Codex media references are independent, source-addressed, and omit embedded bodies", () => {
  const png = Buffer.from("forensic-image-bytes");
  const embedded = `data:image/png;base64,${png.toString("base64")}`;
  const ctx = { sessionId: "s-media", parentId: "", workspace: "/case", model: "gpt", gitBranch: "", isSidechainSession: false };
  const rows = extractCodexMediaReferences({
    type: "response_item",
    timestamp: "2026-09-08T02:03:04Z",
    payload: {
      id: "message-1",
      type: "message",
      role: "user",
      content: [
        { type: "input_image", image_url: embedded, detail: "original" },
        { type: "input_file", file_url: "https://evidence.invalid/sample.pdf?signature=SECRET", filename: "sample.pdf" },
      ],
    },
  }, "/evidence/rollout.jsonl", ctx, {}, { byteOffset: 4096 }, 12);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].RecordType, "media_reference");
  assert.equal(rows[0].LineNumber, "12");
  assert.equal(rows[0].SourceOffset, "4096#/payload/content/0");
  assert.match(rows[0].FullText, /"sha256": "[0-9a-f]{64}"/);
  assert.doesNotMatch(rows[0].FullText, /forensic-image-bytes|base64/);
  assert.match(rows[1].FullText, /sample\.pdf/);
  assert.match(rows[1].FullText, /signature/);
  assert.doesNotMatch(rows[1].FullText, /SECRET/);
});

test("parseRolloutEnvelope handles current custom tools, patches, context, and bounded outputs", () => {
  const ctx = {
    sessionId: "",
    parentId: "",
    workspace: "",
    model: "",
    gitBranch: "",
    threadIndex: new Map(),
    isSidechainSession: false,
  };
  const meta = parseRolloutEnvelope({
    type: "session_meta",
    timestamp: "2026-07-26T12:00:00.000Z",
    payload: {
      id: "child-thread",
      parent_thread_id: "parent-thread",
      thread_source: "subagent",
      cwd: "/repo",
      model_provider: "openai",
      git: { branch: "feature/current-schema" },
    },
  }, "rollout.jsonl", ctx, {});
  assert.equal(meta.ParentId, "parent-thread");
  assert.equal(meta.IsSidechain, "true");
  assert.equal(meta.GitBranch, "feature/current-schema");

  const customCall = parseRolloutEnvelope({
    type: "response_item",
    timestamp: "2026-07-26T12:00:01.000Z",
    payload: {
      type: "custom_tool_call",
      name: "apply_patch",
      input: "*** Begin Patch\n*** End Patch",
      call_id: "custom-1",
    },
  }, "rollout.jsonl", ctx, {});
  assert.equal(customCall.RecordType, "custom_tool_call");
  assert.equal(customCall.InvokedTool, "apply_patch");
  assert.equal(customCall.ToolInput, "*** Begin Patch\n*** End Patch");

  const output = "z".repeat((1024 * 1024) + 100);
  const customOutput = parseRolloutEnvelope({
    type: "response_item",
    timestamp: "2026-07-26T12:00:02.000Z",
    payload: { type: "custom_tool_call_output", call_id: "custom-1", output },
  }, "rollout.jsonl", ctx, {});
  assert.equal(customOutput.RecordType, "custom_tool_call_output");
  assert.equal(customOutput.InvokedTool, "apply_patch");
  assert.match(customOutput.FullText, /truncated 100 chars over 1048576-char cap/);

  const patch = parseRolloutEnvelope({
    type: "event_msg",
    timestamp: "2026-07-26T12:00:03.000Z",
    payload: {
      type: "patch_apply_end",
      call_id: "patch-1",
      success: true,
      status: "completed",
      stdout: "Done!",
      stderr: "",
      changes: { "/repo/app.js": { type: "update" } },
    },
  }, "rollout.jsonl", ctx, {});
  assert.equal(patch.InvokedTool, "apply_patch");
  assert.match(patch.FullText, /app\.js/);

  const turn = parseRolloutEnvelope({
    type: "turn_context",
    timestamp: "2026-07-26T12:00:04.000Z",
    payload: {
      turn_id: "turn-1",
      cwd: "/repo/new",
      model: "gpt-current",
      effort: "high",
      approval_policy: "never",
    },
  }, "rollout.jsonl", ctx, {});
  assert.equal(turn.Workspace, "/repo/new");
  assert.equal(turn.Model, "gpt-current");
  assert.match(turn.Summary, /effort=high/);

  const web = parseRolloutEnvelope({
    type: "response_item",
    timestamp: "2026-07-26T12:00:05.000Z",
    payload: {
      type: "web_search_call",
      status: "completed",
      action: { type: "search", query: "current Codex artifact schema" },
    },
  }, "rollout.jsonl", ctx, {});
  assert.equal(web.InvokedTool, "web_search");
  assert.match(web.Summary, /current Codex artifact schema/);
});

test("extractCodexDir reads fixture history and rollout", async () => {
  assert.ok(isCodexDir(FIXTURE_CODEX));
  const rows = await extractCodexDir(FIXTURE_CODEX, { user: "analyst", host: "HOST1" });
  assert.ok(rows.length >= 4, `expected several rows, got ${rows.length}`);
  const functionCall = rows.find((r) => r.RecordType === "function_call");
  assert.ok(functionCall);
  assert.equal(functionCall.ToolCommand, "[\"bash\",\"-lc\",\"file sample.bin\"]");
  assert.equal(functionCall.ToolInput, "{\"command\":[\"bash\",\"-lc\",\"file sample.bin\"]}");
  assert.ok(rows.some((r) => r.Summary.includes("static analysis")));
  const history = rows.filter((r) => r.RecordType === "history");
  assert.equal(history.length, 1, "history index occurrence retains its own provenance");
});

test("oversized Codex rollouts stream by default and can be inventoried explicitly", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-huge-"));
  try {
    const huge = path.join(tmp, "rollout-too-big.jsonl");
    fs.writeFileSync(huge, "{\"type\":\"session_meta\"}\n");
    fs.truncateSync(huge, MAX_CODEX_ROLLOUT_BYTES + 1);
    const rows = await extractCodexRolloutFile(huge, new Map(), { user: "u" });
    assert.ok(rows.some((row) => row.RecordType === "session_meta"));
    assert.ok(rows.every((row) => row.RecordType !== "oversized_rollout"));
    const inventory = await extractCodexRolloutFile(
      huge,
      new Map(),
      { user: "u" },
      null,
      { inventoryOnly: true },
    );
    assert.equal(inventory[0].RecordType, "oversized_rollout");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("detectAiHistoryImport and planImportPaths recognize .codex", () => {
  assert.equal(detectAiHistoryImport(FIXTURE_CODEX)?.tool, "codex");
  assert.equal(resolveCodexHome(FIXTURE_CODEX), FIXTURE_CODEX);
  const rollout = path.join(FIXTURE_CODEX, "sessions/2026/01/01/rollout-test-fixture.jsonl");
  const planned = planImportPaths([rollout, path.join(FIXTURE_CODEX, "history.jsonl")]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "codex");
});

test("streamed Codex VS Code supplement uses only explicitly supplied evidence roots", async (t) => {
  let Database;
  try {
    Database = require("better-sqlite3");
    const probe = path.join(os.tmpdir(), `irflow-codex-scope-probe-${process.pid}.db`);
    const db = new Database(probe);
    db.close();
    fs.unlinkSync(probe);
  } catch (e) {
    if (e.code === "ERR_DLOPEN_FAILED") {
      t.skip("better-sqlite3 not available for plain Node");
      return;
    }
    throw e;
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-scope-"));
  const codexRoot = path.join(tmp, ".codex");
  const userDir = path.join(tmp, "Code/User");
  const dbPath = path.join(userDir, "globalStorage/state.vscdb");
  fs.mkdirSync(codexRoot, { recursive: true });
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  fs.writeFileSync(path.join(codexRoot, "history.jsonl"), `${JSON.stringify({
    session_id: "scope-session",
    ts: 1704067200,
    text: "Scoped Codex prompt",
  })}\n`);

  const db = new Database(dbPath);
  db.exec("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)");
  db.prepare("INSERT INTO ItemTable (key, value) VALUES (?, ?)").run(
    "agentSessions.model.cache",
    JSON.stringify([{
      providerType: "openai-codex",
      providerLabel: "Codex",
      resource: "openai-codex://route/local/scoped-agent",
      label: "Scoped VS Code Codex prompt",
      timing: { created: 1704067201000 },
    }]),
  );
  db.close();

  try {
    const streamed = [];
    const result = await extractCodexDir(codexRoot, {}, {
      codexVsCodeUserDirs: [userDir],
      onExtractedRows: (batch) => streamed.push(...batch),
    });
    assert.equal(result.length, 0);
    assert.ok(streamed.some((row) => row.Summary === "Scoped Codex prompt"));
    assert.ok(streamed.some((row) => row.Summary === "Scoped VS Code Codex prompt"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
