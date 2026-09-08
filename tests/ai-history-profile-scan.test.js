"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  getLocalAiHistoryCandidates,
  validateAiHistoryRoot,
  discoverLocalAiHistoryRoots,
  discoverAiHistoryInFolder,
  extractMergedAiHistoryRoots,
} = require("../electron/parsers/ai-history/profile-scan");

const FIXTURE_CLAUDE = path.join(__dirname, "fixtures/ai-history/claude/.claude");
const FIXTURE_COPILOT_STORAGE = path.join(
  __dirname,
  "fixtures/ai-history/copilot/Code/User/workspaceStorage",
);

test("getLocalAiHistoryCandidates includes all ten tool families", () => {
  const tools = new Set(getLocalAiHistoryCandidates().map((c) => c.tool));
  for (const tool of [
    "claude-code", "codex", "grok-build", "grok-bot", "chatgpt", "gemini-cli", "cursor", "copilot",
    "windsurf", "continue",
  ]) {
    assert.ok(tools.has(tool), `missing ${tool}`);
  }
});

test("validateAiHistoryRoot recognizes fixture paths", () => {
  assert.equal(validateAiHistoryRoot("claude-code", FIXTURE_CLAUDE), true);
  assert.equal(validateAiHistoryRoot("copilot", FIXTURE_COPILOT_STORAGE), true);
  assert.equal(validateAiHistoryRoot("claude-code", __dirname), false);
});

test("extractMergedAiHistoryRoots reports onProgress", async () => {
  const fixture = path.join(__dirname, "fixtures/ai-history/claude/.claude");
  const events = [];
  await extractMergedAiHistoryRoots(
    [{ tool: "claude-code", path: fixture, label: "Claude Code" }],
    {},
    { onProgress: (e) => events.push(e.phase) },
  );
  assert.ok(events.includes("extracting"));
  assert.ok(events.includes("merging"));
});

test("discoverAiHistoryInFolder finds Windows user artifacts in triage tree", async () => {
  const root = require("fs").mkdtempSync(require("path").join(require("os").tmpdir(), "irflow-profile-folder-"));
  const fs = require("fs");
  const path = require("path");
  const claudeDir = path.join(root, "C", "Users", "victim", ".claude");
  fs.mkdirSync(path.join(claudeDir, "projects", "p"), { recursive: true });
  fs.writeFileSync(path.join(claudeDir, "history.jsonl"), '{"display":"q","timestamp":1,"sessionId":"s"}\n');
  fs.writeFileSync(path.join(claudeDir, "projects", "p", "s1.jsonl"), "");

  const { roots, scanMode } = await discoverAiHistoryInFolder(root);
  assert.equal(scanMode, "folder");
  assert.ok(roots.some((r) => r.tool === "claude-code" && r.endpointUser === "victim"));
  fs.rmSync(root, { recursive: true, force: true });
});

test("discoverLocalAiHistoryRoots returns structured roots", async () => {
  const { roots, candidateCount } = await discoverLocalAiHistoryRoots();
  assert.ok(candidateCount >= 6);
  assert.ok(Array.isArray(roots));
  for (const r of roots) {
    assert.ok(r.tool);
    assert.ok(r.path);
    assert.ok(r.label);
  }
});

test("extractMergedAiHistoryRoots assigns RecordId once at merge (skipFinalize)", async () => {
  const roots = [{ tool: "claude-code", path: FIXTURE_CLAUDE, label: "Claude" }];
  const { rows } = await extractMergedAiHistoryRoots(roots, {}, { maxRows: 100 });
  assert.ok(rows.length > 0);
  assert.equal(rows[0].RecordId, "1");
  assert.equal(rows[rows.length - 1].RecordId, String(rows.length));
});

test("extractMergedAiHistoryRoots merges Claude fixture rows", async () => {
  const roots = [{ tool: "claude-code", path: FIXTURE_CLAUDE, label: "Claude Code" }];
  const { rows, importNotice } = await extractMergedAiHistoryRoots(roots, { user: "test" });
  assert.ok(rows.length >= 1);
  assert.equal(rows[0].Tool, "Claude Code");
  assert.ok(importNotice === null || typeof importNotice === "string");
});

test("extractMergedAiHistoryRoots honors a caller checkAbort token (G1)", async () => {
  const roots = [{ tool: "claude-code", path: FIXTURE_CLAUDE, label: "Claude Code" }];
  await assert.rejects(
    () => extractMergedAiHistoryRoots(roots, {}, {
      checkAbort: () => { throw Object.assign(new Error("canceled"), { canceled: true }); },
    }),
    /cancel/i,
  );
});

test("extractMergedAiHistoryRoots enforces maxRows cap (G2)", async () => {
  const roots = [{ tool: "claude-code", path: FIXTURE_CLAUDE, label: "Claude Code" }];
  const { rows, capped } = await extractMergedAiHistoryRoots(roots, {}, { maxRows: 1 });
  assert.equal(rows.length, 1);
  assert.equal(capped, true);
  assert.equal(rows[0].RecordId, "1");
});

test("extractMergedAiHistoryRoots counts malformed JSONL lines (G3)", async () => {
  const fs = require("node:fs");
  const os = require("node:os");
  const p = require("node:path");
  const root = fs.mkdtempSync(p.join(os.tmpdir(), "irflow-parseerr-"));
  const claudeDir = p.join(root, ".claude");
  fs.mkdirSync(p.join(claudeDir, "projects", "x"), { recursive: true });
  fs.writeFileSync(
    p.join(claudeDir, "history.jsonl"),
    '{"display":"good prompt","timestamp":1704067200000,"sessionId":"s"}\n{ this is not json\n',
  );
  const { parseErrors } = await extractMergedAiHistoryRoots(
    [{ tool: "claude-code", path: claudeDir, label: "Claude Code" }],
    {},
  );
  assert.ok(parseErrors >= 1, `expected >=1 parse error, got ${parseErrors}`);
  fs.rmSync(root, { recursive: true, force: true });
});
