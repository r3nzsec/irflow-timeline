"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("fs");
const os = require("os");

const {
  extractCursorComposerStores,
  isCursorUserDataDir,
} = require("../electron/parsers/ai-history/cursor-composer");
const {
  buildCursorComposerFixture,
  buildCursorConversationSearchFixture,
  buildCursorToolOnlyFixture,
} = require("./helpers/vscdb-builder");

const FIXTURE_CURSOR = path.join(__dirname, "fixtures/ai-history/cursor/.cursor");

test("extractCursorComposerStores reads bubble messages from state.vscdb", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-vscdb-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });

  const userDir = path.join(tmp, "Library", "Application Support", "Cursor", "User");
  const globalDb = path.join(userDir, "globalStorage", "state.vscdb");
  if (!buildCursorComposerFixture(globalDb)) {
    t.skip("better-sqlite3 not available in this Node runtime");
    return;
  }

  const agentHome = path.join(tmp, ".cursor");
  fs.mkdirSync(path.join(agentHome, "projects"), { recursive: true });

  const { rows, stats } = await extractCursorComposerStores(agentHome, { user: "analyst" }, {
    userDataDirs: [userDir],
  });
  assert.ok(stats.databases >= 1);
  assert.ok(rows.length >= 2);
  assert.equal(rows[0].Tool, "Cursor");
  assert.match(rows.find((r) => r.Role === "user")?.Summary || "", /composer DB/);
});

test("Cursor composer retains tool-only bubbles with exact timestamp and result", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-tool-only-"));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const root = path.join(tmp, ".cursor");
  const dbPath = path.join(root, "chats", "tool", "store.db");
  if (!buildCursorToolOnlyFixture(dbPath)) return t.skip("better-sqlite3 unavailable");
  fs.mkdirSync(path.join(root, "projects"), { recursive: true });
  const { rows } = await extractCursorComposerStores(root);
  const tool = rows.find((item) => item.RecordType === "composer_tool_evidence");
  assert.ok(tool);
  assert.equal(tool.Timestamp, "2026-09-08 01:02:03");
  assert.equal(tool.InvokedTool, "run_terminal_command");
  assert.equal(tool.ToolCommand, "whoami && id");
  assert.match(tool.FullText, /uid=501/);
  assert.equal(tool.MessageId, "tool-only-bubble");
});

test("Cursor accounts for more than the former 20/16 database limits", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-many-db-"));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const root = path.join(tmp, ".cursor");
  fs.mkdirSync(path.join(root, "projects"), { recursive: true });
  for (let i = 0; i < 25; i++) {
    if (!buildCursorComposerFixture(path.join(root, "chats", String(i).padStart(2, "0"), "store.db"))) {
      return t.skip("better-sqlite3 unavailable");
    }
  }
  const { rows, stats } = await extractCursorComposerStores(root);
  assert.equal(stats.eligibleDatabases, 25);
  assert.equal(stats.selectedDatabases, 25);
  assert.equal(stats.omittedDatabases, 0);
  assert.equal(stats.databases, 25);
  assert.equal(rows.length, 50);
});

test("extractCursorDir merges transcript and composer rows when vscdb present", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-merge-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });

  const globalDb = path.join(tmp, "globalStorage", "state.vscdb");
  if (!buildCursorComposerFixture(globalDb)) {
    t.skip("better-sqlite3 not available in this Node runtime");
    return;
  }

  const { extractCursorDir } = require("../electron/parsers/ai-history/cursor");
  const rows = await extractCursorDir(FIXTURE_CURSOR, { user: "u" });
  assert.ok(rows.length >= 2);
});

test("Cursor User root parses conversation-search.db FTS bodies with source metadata", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-search-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });

  const userDir = path.join(tmp, "Library", "Application Support", "Cursor", "User");
  const searchDb = path.join(userDir, "globalStorage", "conversation-search.db");
  if (!buildCursorConversationSearchFixture(searchDb)) {
    t.skip("better-sqlite3 not available in this Node runtime");
    return;
  }

  const { extractCursorPath, resolveCursorRoot } = require("../electron/parsers/ai-history/cursor");
  const { detectAiHistoryImport } = require("../electron/parsers/ai-history-import");
  assert.equal(isCursorUserDataDir(userDir), true);
  assert.equal(resolveCursorRoot(searchDb), userDir);
  assert.equal(detectAiHistoryImport(searchDb)?.target, userDir);

  const rows = await extractCursorPath(userDir, { user: "analyst" });
  const indexed = rows.find((row) => row.RecordType === "conversation_search");
  assert.ok(indexed);
  assert.equal(indexed.SessionId, "cursor-search-session-1");
  assert.equal(indexed.Summary, "Investigate persistence");
  assert.match(indexed.FullText, /suspicious PowerShell execution/);
  assert.equal(indexed.Timestamp, "2024-01-01 00:00:00");
  const metadataOnly = rows.find((row) => row.SessionId === "cursor-search-session-2");
  assert.match(metadataOnly?.Summary || "", /archived/i);
  assert.match(metadataOnly?.FullText || "", /"bodyPresent": false/);
  assert.equal(rows._cursorComposerStats.searchRows, 2);
});
