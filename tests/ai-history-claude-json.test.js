"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  isClaudeJsonStateFile,
  claudeJsonFileKind,
  extractClaudeJsonFile,
  countClaudeJsonExtractFiles,
} = require("../electron/parsers/ai-history/claude-code-state");
const { extractClaudeCodePath, countClaudeExtractFiles } = require("../electron/parsers/ai-history/claude-code");
const { detectAiHistoryImport, planImportPaths } = require("../electron/parsers/ai-history-import");
const { scanAiArtifacts } = require("../electron/parsers/ai-artifacts");
const { validateAiHistoryRoot, getLocalAiHistoryCandidates } = require("../electron/parsers/ai-history/profile-scan");

const FIXTURE_DIR = path.join(__dirname, "fixtures/ai-history/claude-json");
const FIXTURE_JSON = path.join(FIXTURE_DIR, ".claude.json");

test("isClaudeJsonStateFile recognizes current and timestamped backups, not tmp", () => {
  assert.equal(claudeJsonFileKind(FIXTURE_JSON), "current");
  assert.equal(isClaudeJsonStateFile(FIXTURE_JSON), true);
  assert.equal(
    isClaudeJsonStateFile(path.join(FIXTURE_DIR, ".claude.json.backup.1700000000000")),
    true,
  );
  assert.equal(isClaudeJsonStateFile(path.join(FIXTURE_DIR, "not-claude.json")), false);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-claude-json-"));
  try {
    const tmpFile = path.join(tmp, ".claude.json.tmp.1234.abcd");
    fs.writeFileSync(tmpFile, "{}");
    assert.equal(isClaudeJsonStateFile(tmpFile), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("extractClaudeJsonFile emits identity, remote-control, projects, MCP, and backup-only workspaces", () => {
  const rows = extractClaudeJsonFile(FIXTURE_JSON, { user: "analyst" });
  assert.ok(rows.length >= 6);
  assert.ok(rows.every((r) => r.User === "analyst"));
  assert.ok(rows.every((r) => r.Tool === "Claude Code"));

  const identities = rows.filter((r) => r.RecordType === "cli_identity");
  assert.equal(identities.length, 1, "backups must not duplicate identity rows");
  const identity = identities[0];
  assert.match(identity.Summary, /analyst@example\.com/);
  assert.match(identity.Summary, /Remote Control used/);
  assert.match(identity.FullText, /"timeSource": "firstStartTime"/);

  const rc = rows.find((r) => r.RecordType === "remote_control_used");
  assert.ok(rc);

  const project = rows.find((r) => r.RecordType === "project_state");
  assert.ok(project);
  assert.equal(project.Workspace, "/Users/analyst/case");
  assert.equal(project.SessionId, "sess-current");
  assert.match(project.Summary, /trust accepted/);
  assert.match(project.FullText, /"timeSource": "projects\[\]\.lastStartTime"/);

  const removed = rows.find((r) => r.RecordType === "project_removed");
  assert.ok(removed, "workspace present only in the backup becomes project_removed");
  assert.equal(removed.Workspace, "/Users/analyst/gone");
  assert.equal(removed.SessionId, "sess-gone");

  const mcp = rows.find((r) => r.RecordType === "mcp_server_config");
  assert.ok(mcp);
  assert.equal(mcp.InvokedTool, "filesystem");
  assert.match(mcp.FullText, /"envKeys": \[\s*"FS_TOKEN"/);
  assert.ok(!/SHOULD-NEVER-APPEAR/.test(JSON.stringify(rows)), "tokens and env values stay out");
});

test("local candidates, import detection, and folder scan see ~/.claude.json", () => {
  assert.ok(getLocalAiHistoryCandidates().some((c) => c.tool === "claude-code" && c.path.endsWith(".claude.json")));
  assert.equal(validateAiHistoryRoot("claude-code", FIXTURE_JSON), true);
  const detect = detectAiHistoryImport(FIXTURE_JSON);
  assert.equal(detect.tool, "claude-code");
  assert.equal(detect.target, FIXTURE_JSON);
  const planned = planImportPaths([FIXTURE_JSON]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "claude-code");
  assert.ok(countClaudeExtractFiles(FIXTURE_JSON) >= 2);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-claude-json-scan-"));
  try {
    const userHome = path.join(root, "Users", "victim");
    fs.mkdirSync(userHome, { recursive: true });
    fs.copyFileSync(FIXTURE_JSON, path.join(userHome, ".claude.json"));
    const scan = scanAiArtifacts(root);
    assert.ok(scan.claudeCode.some((h) => h.path.endsWith(".claude.json") && h.username === "victim"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("extractClaudeCodePath reads .claude.json", async () => {
  const rows = await extractClaudeCodePath(FIXTURE_JSON, { host: "HOST1" });
  assert.ok(rows.length >= 1);
  assert.ok(rows.every((r) => r.Host === "HOST1"));
  assert.ok(rows.every((r) => r.RecordId));
});
