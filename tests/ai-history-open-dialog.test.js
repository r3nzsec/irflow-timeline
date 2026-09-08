"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  aiHistoryOpenDialogFilters,
  defaultAiHistoryOpenPath,
  defaultDecodeAiHistoryDialogPath,
} = require("../electron/parsers/ai-history/open-dialog-paths");

test("aiHistoryOpenDialogFilters lists per-tool AI artifact groups", () => {
  const filters = aiHistoryOpenDialogFilters();
  const names = filters.map((f) => f.name).join(" ");
  assert.match(names, /Claude Code/);
  assert.match(names, /ChatGPT Desktop/);
  assert.match(names, /Cursor/);
  assert.match(names, /Copilot/);
  assert.match(names, /Codex/);
  assert.match(names, /Grok Build/);
  assert.match(names, /Grok Bot/);
});

test("defaultDecodeAiHistoryDialogPath for grok-bot prefers a real root over home", () => {
  const os = require("os");
  const fs = require("fs");
  const { defaultGrokBotHome, defaultGrokBotAppDir } = require("../electron/parsers/ai-history/grok-bot");
  const p = defaultDecodeAiHistoryDialogPath("grok-bot");
  const home = os.homedir();
  if (fs.existsSync(defaultGrokBotHome()) || fs.existsSync(defaultGrokBotAppDir())) {
    assert.notEqual(p, home);
    assert.ok(p.endsWith(".grokbot") || p.endsWith("Grok Bot"));
  }
});

test("defaultAiHistoryOpenPath returns a string path", () => {
  const p = defaultAiHistoryOpenPath();
  assert.ok(typeof p === "string" && p.length > 0);
});

test("defaultDecodeAiHistoryDialogPath returns a path hint per tool", () => {
  for (const tool of [
    "claude-code", "codex", "grok-build", "grok-bot", "chatgpt", "gemini-cli", "cursor", "copilot", "windsurf", "continue",
  ]) {
    const p = defaultDecodeAiHistoryDialogPath(tool);
    assert.ok(typeof p === "string" && p.length > 0, tool);
  }
});
