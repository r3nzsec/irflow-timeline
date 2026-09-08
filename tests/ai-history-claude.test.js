"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  extractContentText,
  parseHistoryLine,
  parseSessionLine,
  extractClaudeDir,
  extractClaudeCodePath,
} = require("../electron/parsers/ai-history/claude-code");
const { formatTimestampUtc, detectActivity, dedupeAiHistoryRows } = require("../electron/parsers/ai-history/row-utils");

const FIXTURE_CLAUDE = path.join(__dirname, "fixtures/ai-history/claude/.claude");

test("extractContentText handles text, tools, and thinking", () => {
  const content = [
    { type: "text", text: "Hello" },
    { type: "tool_use", name: "Bash" },
    { type: "tool_result", content: "out" },
    { type: "thinking", thinking: "hidden" },
  ];
  assert.match(extractContentText(content), /Hello/);
  assert.match(extractContentText(content), /\[Tool: Bash\]/);
  assert.match(extractContentText(content), /\[Reasoning present\]/);
  assert.match(extractContentText(content), /out/);
});

test("parseSessionLine preserves bounded tool-result output and untimed state records", () => {
  const output = "x".repeat((1024 * 1024) + 200);
  const toolResult = parseSessionLine({
    type: "user",
    timestamp: "2026-07-26T12:00:00.000Z",
    sessionId: "sess-output",
    uuid: "tool-result-1",
    message: {
      role: "user",
      content: [{ type: "tool_result", tool_use_id: "call-1", content: output }],
    },
  }, "/sess.jsonl");
  assert.ok(toolResult);
  assert.match(toolResult.FullText, /^\[Tool Result\]/);
  assert.match(toolResult.FullText, /truncated 214 chars over 1048576-char cap/);

  const title = parseSessionLine({
    type: "ai-title",
    sessionId: "sess-output",
    aiTitle: "Untimed recovered title",
  }, "/sess.jsonl");
  assert.ok(title);
  assert.equal(title.Timestamp, "");
  assert.equal(title.Summary, "Untimed recovered title");
});

test("parseSessionLine records image and document blocks without embedding image bytes", () => {
  const row = parseSessionLine({
    type: "user",
    timestamp: "2026-07-26T12:00:00.000Z",
    sessionId: "sess-media",
    message: {
      role: "user",
      content: [
        { type: "image", source: { media_type: "image/png", data: "A".repeat(1000) } },
        { type: "document", title: "evidence.pdf" },
      ],
    },
  }, "/sess.jsonl");
  assert.match(row.FullText, /\[Image: image\/png\]/);
  assert.match(row.FullText, /\[Document: evidence\.pdf\]/);
  assert.doesNotMatch(row.FullText, /A{100}/);
});

test("parseHistoryLine sets RecordType history", () => {
  const row = parseHistoryLine(
    { display: "fix this bug please", timestamp: 1704067200000, sessionId: "s1", project: "/proj" },
    "/home/u/.claude/history.jsonl",
    { user: "u" },
  );
  assert.ok(row);
  assert.equal(row.Role, "user");
  assert.equal(row.RecordType, "history");
  assert.equal(row.Timestamp, formatTimestampUtc(1704067200000));
  assert.match(row.Description, /Bug Fix Request/);
});

test("parseSessionLine extracts assistant tokens, model, and exact tool evidence", () => {
  const row = parseSessionLine({
    type: "assistant",
    timestamp: "2024-06-15T10:30:00.000Z",
    uuid: "m1",
    parentUuid: "p0",
    sessionId: "sess-1",
    cwd: "/work",
    gitBranch: "main",
    isSidechain: false,
    message: {
      role: "assistant",
      model: "claude-sonnet-4",
      content: [
        { type: "text", text: "Done." },
        {
          type: "tool_use",
          name: "Bash",
          input: {
            command: "printf '%s\\n' \"quoted value\"",
            description: "Print a quoted test value",
          },
        },
      ],
      usage: { input_tokens: 10, output_tokens: 5 },
    },
  }, "/sess.jsonl");
  assert.ok(row);
  assert.equal(row.RecordType, "assistant");
  assert.equal(row.InputTokens, "10");
  assert.equal(row.OutputTokens, "5");
  assert.equal(row.Model, "claude-sonnet-4");
  assert.equal(row.InvokedTool, "Bash");
  assert.equal(row.ToolCommand, "printf '%s\\n' \"quoted value\"");
  assert.equal(row.ToolDescription, "Print a quoted test value");
  assert.deepEqual(JSON.parse(row.ToolInput), {
    command: "printf '%s\\n' \"quoted value\"",
    description: "Print a quoted test value",
  });
  assert.equal(row.GitBranch, "main");
  assert.equal(row.IsSidechain, "false");
});

test("parseSessionLine scales a numeric epoch-seconds timestamp to ms (B4)", () => {
  const row = parseSessionLine({
    type: "user",
    timestamp: 1718446200, // epoch SECONDS (2024-06-15), not ms
    uuid: "u-secs",
    sessionId: "sess-secs",
    message: { role: "user", content: [{ type: "text", text: "hello" }] },
  }, "/sess.jsonl");
  assert.ok(row);
  assert.equal(row.Timestamp, formatTimestampUtc(1718446200 * 1000));
  assert.match(row.Timestamp, /^2024-06-15 /);
});

test("parseSessionLine flags inline isSidechain rows", () => {
  const row = parseSessionLine({
    type: "user",
    timestamp: "2024-06-15T10:30:00.000Z",
    uuid: "sc-1",
    sessionId: "sess-1",
    isSidechain: true,
    message: { role: "user", content: [{ type: "text", text: "sub-agent prompt" }] },
  }, "/projects/p/sess.jsonl");
  assert.ok(row);
  assert.equal(row.IsSidechain, "true");
});

test("parseSessionLine includes file-history-snapshot rows", () => {
  const row = parseSessionLine({
    type: "file-history-snapshot",
    timestamp: "2024-01-01T12:00:10.000Z",
    uuid: "snap-1",
    sessionId: "sess-abc",
  }, "/sess.jsonl");
  assert.ok(row);
  assert.equal(row.RecordType, "file-history-snapshot");
  assert.match(row.Summary, /File history snapshot/);
});

test("dedupeAiHistoryRows preserves matching prompt occurrences from history and session sources", () => {
  const sessionRow = parseSessionLine({
    type: "user",
    timestamp: "2024-01-01T12:00:00.000Z",
    uuid: "u1",
    sessionId: "sess-1",
    message: { role: "user", content: [{ type: "text", text: "How do I list running processes?" }] },
  }, "/projects/p/sess.jsonl");
  const historyRow = parseHistoryLine({
    display: "How do I list running processes?",
    timestamp: 1704067200000,
    sessionId: "sess-1",
    project: "/tmp",
  }, "/home/u/.claude/history.jsonl");
  const out = dedupeAiHistoryRows([historyRow, sessionRow]);
  assert.equal(out.length, 2);
  assert.deepEqual(new Set(out.map((row) => row.SourceFile)), new Set([
    "/home/u/.claude/history.jsonl",
    "/projects/p/sess.jsonl",
  ]));
});

test("dedupeAiHistoryRows does not correlate cross-tool prompts whose full bodies differ", () => {
  const claude = {
    Role: "user",
    Summary: "How do I dump LSASS memory for analysis?",
    FullText: "How do I dump LSASS memory for analysis?",
    SessionId: "c1",
    Timestamp: "2024-01-01 12:00:00",
    Tool: "Claude Code",
  };
  const cursor = {
    Role: "user",
    Summary: "How do I dump LSASS memory for analysis?",
    FullText: "How do I dump LSASS memory for analysis? (extra detail in cursor)",
    SessionId: "u2",
    Timestamp: "",
    Tool: "Cursor",
  };
  const out = dedupeAiHistoryRows([claude, cursor], { crossTool: true });
  assert.equal(out.length, 2);
  assert.ok(out.every((row) => !row.AlsoInTools));
});

test("dedupeAiHistoryRows crossTool leaves AlsoInTools empty for single-tool prompts", () => {
  const a = {
    Role: "user", Summary: "How do I enumerate scheduled tasks on this host?",
    FullText: "How do I enumerate scheduled tasks on this host?",
    SessionId: "s1", Timestamp: "2024-01-01 12:00:00", Tool: "Claude Code",
  };
  const b = {
    Role: "user", Summary: "Completely different prompt about parsing the MFT records.",
    FullText: "Completely different prompt about parsing the MFT records.",
    SessionId: "s2", Timestamp: "2024-01-01 12:05:00", Tool: "Claude Code",
  };
  const out = dedupeAiHistoryRows([a, b], { crossTool: true });
  assert.equal(out.length, 2);
  assert.ok(out.every((r) => !r.AlsoInTools));
});

test("detectActivity classifies common user intents", () => {
  assert.equal(detectActivity("user", "fix this error"), "Bug Fix Request");
  assert.equal(detectActivity("user", "create a module"), "Feature Request");
  assert.equal(detectActivity("assistant", "ok"), "AI Response");
});

test("extractClaudeDir reads history and session JSONL from fixture tree", async () => {
  const rows = await extractClaudeDir(FIXTURE_CLAUDE, { user: "analyst", host: "HOST01" });
  assert.ok(rows.length >= 3, `expected history + session rows, got ${rows.length}`);
  const historyRow = rows.find((r) => r.Summary.includes("running processes"));
  assert.ok(historyRow, "history.jsonl row present");
  assert.equal(historyRow.User, "analyst");
  const sessionRow = rows.find((r) => r.MessageId === "msg-asst-1");
  assert.ok(sessionRow);
  assert.match(sessionRow.Summary, /Tool: Bash/);
  assert.equal(sessionRow.ToolInput, "{}");
  assert.equal(sessionRow.Host, "HOST01");
  assert.ok(rows.every((r) => r.RecordId), "record ids assigned");
});

test("extractClaudeCodePath accepts a single session file", async () => {
  const sessionFile = path.join(FIXTURE_CLAUDE, "projects/demo-app/sess-abc.jsonl");
  const rows = await extractClaudeCodePath(sessionFile);
  assert.equal(rows.length, 3);
});
