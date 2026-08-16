"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const {
  getLocalAiHistoryCandidates,
  listClaudeCodeCandidatePaths,
  listChatgptCandidatePaths,
  listCopilotWorkspaceStorageCandidates,
  COPILOT_PRODUCT_NAMES,
  ARTIFACT_PATH_REFERENCES,
  isClaudeCodeArtifactRoot,
  defaultCursorHome,
} = require("../electron/parsers/ai-history/artifact-paths");
const { discoverLocalAiHistoryRoots } = require("../electron/parsers/ai-history/profile-scan");

test("getLocalAiHistoryCandidates includes all ten tools", () => {
  const tools = new Set(getLocalAiHistoryCandidates().map((c) => c.tool));
  assert.deepEqual(tools, new Set([
    "claude-code", "codex", "grok-build", "gemini-cli", "cursor", "chatgpt", "copilot",
    "windsurf", "continue", "computer-history",
  ]));
});

test("computer-history candidates cover both the raw stream and the derived summaries", () => {
  const paths = getLocalAiHistoryCandidates()
    .filter((c) => c.tool === "computer-history")
    .map((c) => c.path);
  assert.equal(paths.length, 2);
  assert.ok(paths.some((p) => p.endsWith(path.join("Skysight", "segments"))));
  assert.ok(paths.some((p) => p.endsWith(path.join("skysight", "resources"))));
});

test("listClaudeCodeCandidatePaths includes CLI and Desktop roots", () => {
  const kinds = new Set(listClaudeCodeCandidatePaths().map((c) => c.kind));
  assert.ok(kinds.has("cli"));
  assert.ok(listClaudeCodeCandidatePaths().some((c) => c.path.endsWith(".claude")));
  // A desktop root is either the app-support directory itself or one of the session directories
  // below it. The parent is preferred when present, because pending-uploads/,
  // plan-usage-history.json and git-worktrees.json are siblings of claude-code-sessions and are
  // unreachable from a scan aimed at the session directories alone.
  const desktopPaths = listClaudeCodeCandidatePaths().filter((c) => c.kind === "desktop");
  for (const { path: p } of desktopPaths) {
    assert.match(p, /claude-code-sessions|local-agent-mode-sessions|[/\\]Claude$/);
  }
  // Never both: scanning the parent already covers the children, and listing both would parse
  // every transcript twice.
  const parents = desktopPaths.filter((c) => /[/\\]Claude$/.test(c.path));
  const children = desktopPaths.filter((c) => /sessions$/.test(c.path));
  assert.ok(!(parents.length && children.length), "parent and children are mutually exclusive");
});

test("listChatgptCandidatePaths is non-empty on every platform", () => {
  assert.ok(listChatgptCandidatePaths().length >= 2);
});

test("Copilot products include VSCodium", () => {
  assert.ok(COPILOT_PRODUCT_NAMES.includes("VSCodium"));
  assert.ok(listCopilotWorkspaceStorageCandidates().some((p) => p.includes("VSCodium")));
});

test("ARTIFACT_PATH_REFERENCES documents each tool", () => {
  for (const tool of ["claude-code", "codex", "grok-build", "chatgpt", "gemini-cli", "cursor", "copilot"]) {
    assert.ok(ARTIFACT_PATH_REFERENCES[tool]?.paths?.length >= 1);
  }
  assert.ok(ARTIFACT_PATH_REFERENCES.cursor.paths.some((entry) => (
    entry.path.includes("conversation-search.db")
  )));
  assert.ok(ARTIFACT_PATH_REFERENCES.copilot.paths.some((entry) => (
    entry.path.includes(".copilot") && entry.path.includes("events.jsonl")
  )));
  assert.match(ARTIFACT_PATH_REFERENCES.copilot.notes, /secret stores are deliberately excluded/i);
});

test("isClaudeCodeArtifactRoot accepts CLI fixture", () => {
  const fixture = path.join(__dirname, "fixtures/ai-history/claude/.claude");
  assert.equal(isClaudeCodeArtifactRoot(fixture), true);
});

test("defaultCursorHome ends with .cursor", () => {
  assert.ok(defaultCursorHome().endsWith(".cursor") || defaultCursorHome().includes("cursor"));
});

test("discoverLocalAiHistoryRoots returns structured roots", async () => {
  const { roots, candidateCount } = await discoverLocalAiHistoryRoots();
  assert.ok(candidateCount >= 8);
  for (const r of roots) {
    assert.ok(r.tool && r.path && r.label);
  }
});
