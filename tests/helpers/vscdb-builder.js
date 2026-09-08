"use strict";

const fs = require("fs");
const path = require("path");

function buildCursorComposerFixture(dbPath) {
  let Database;
  try {
    Database = require("better-sqlite3");
    // Probe load — may be built for Electron ABI, not plain Node test runner.
    const probe = path.join(require("os").tmpdir(), `irflow-sqlite-probe-${process.pid}.db`);
    const d = new Database(probe);
    d.close();
    try { fs.unlinkSync(probe); } catch { /* ignore */ }
  } catch (e) {
    if (e.code === "ERR_DLOPEN_FAILED") return false;
    throw e;
  }

  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);

  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);
    CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);
  `);

  const composerId = "fda95e1a-7d3a-4113-942f-7e033e454bef";
  const bubbleUser = "7dd300cc-6205-47ab-913e-fc921e68cef9";
  const bubbleAsst = "8ee411dd-7316-58bc-a24f-gd032e79df0a";

  const composerData = {
    composerId,
    createdAt: 1704067200000,
    lastUpdatedAt: 1704067260000,
    fullConversationHeadersOnly: [
      { bubbleId: bubbleUser, type: 1 },
      { bubbleId: bubbleAsst, type: 2 },
    ],
  };

  db.prepare("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)").run(
    `composerData:${composerId}`,
    JSON.stringify(composerData),
  );
  db.prepare("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)").run(
    `bubbleId:${composerId}:${bubbleUser}`,
    JSON.stringify({ type: 1, text: "Hello from composer DB", createdAt: 1704067200000 }),
  );
  db.prepare("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)").run(
    `bubbleId:${composerId}:${bubbleAsst}`,
    JSON.stringify({ type: 2, text: "Reply from composer DB", createdAt: 1704067260000 }),
  );
  db.close();
  return true;
}

function buildCursorConversationSearchFixture(dbPath) {
  let Database;
  try {
    Database = require("better-sqlite3");
    const probe = path.join(require("os").tmpdir(), `irflow-sqlite-probe-${process.pid}.db`);
    const d = new Database(probe);
    d.close();
    try { fs.unlinkSync(probe); } catch { /* ignore */ }
  } catch (e) {
    if (e.code === "ERR_DLOPEN_FAILED") return false;
    throw e;
  }

  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE conversations (
      fts_rowid INTEGER PRIMARY KEY,
      source TEXT NOT NULL,
      scope TEXT NOT NULL,
      id TEXT NOT NULL,
      title TEXT NOT NULL,
      updated_at INTEGER NOT NULL,
      is_archived INTEGER NOT NULL,
      root_fingerprint TEXT,
      cache_fingerprint TEXT
    );
    CREATE VIRTUAL TABLE conversation_fts USING fts5(title, body);
  `);
  db.prepare(`
    INSERT INTO conversations
      (fts_rowid, source, scope, id, title, updated_at, is_archived, root_fingerprint, cache_fingerprint)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    1,
    "local",
    "",
    "cursor-search-session-1",
    "Investigate persistence",
    1704067200000,
    0,
    "fingerprint",
    null,
  );
  db.prepare("INSERT INTO conversation_fts(rowid, title, body) VALUES (?, ?, ?)").run(
    1,
    "Investigate persistence",
    "Find scheduled tasks and explain the suspicious PowerShell execution.",
  );
  db.prepare(`
    INSERT INTO conversations
      (fts_rowid, source, scope, id, title, updated_at, is_archived, root_fingerprint, cache_fingerprint)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    2,
    "local",
    "",
    "cursor-search-session-2",
    "",
    1704067260000,
    1,
    "fingerprint-2",
    null,
  );
  db.prepare("INSERT INTO conversation_fts(rowid, title, body) VALUES (?, ?, ?)").run(
    2,
    "",
    "",
  );
  db.close();
  return true;
}

function buildCursorToolOnlyFixture(dbPath) {
  let Database;
  try {
    Database = require("better-sqlite3");
    const probe = path.join(require("os").tmpdir(), `irflow-cursor-tool-probe-${process.pid}.db`);
    const d = new Database(probe);
    d.close();
    try { fs.unlinkSync(probe); } catch { /* ignore */ }
  } catch (e) {
    if (e.code === "ERR_DLOPEN_FAILED") return false;
    throw e;
  }
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.exec("CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)");
  const composerId = "tool-only-composer";
  const bubbleId = "tool-only-bubble";
  db.prepare("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)").run(
    `composerData:${composerId}`,
    JSON.stringify({ composerId, fullConversationHeadersOnly: [{ bubbleId, type: 2 }] }),
  );
  db.prepare("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)").run(
    `bubbleId:${composerId}:${bubbleId}`,
    JSON.stringify({
      bubbleId,
      type: 2,
      createdAt: "2026-09-08T01:02:03.456Z",
      toolFormerData: {
        name: "run_terminal_command",
        status: "completed",
        rawArgs: JSON.stringify({ command: "whoami && id" }),
        result: JSON.stringify({ stdout: "analyst\nuid=501" }),
        toolCallId: "call-1",
        modelCallId: "model-1",
      },
    }),
  );
  db.close();
  return true;
}

module.exports = { buildCursorComposerFixture, buildCursorConversationSearchFixture, buildCursorToolOnlyFixture };
