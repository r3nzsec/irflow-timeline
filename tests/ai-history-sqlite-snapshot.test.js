"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { copySqliteFamilyToTemp } = require("../electron/parsers/ai-history/codex-state-sqlite");

test("live WAL acquisition produces one checked snapshot with separate source and export identities", (t) => {
  let Database;
  try { Database = require("better-sqlite3"); } catch (error) {
    if (error.code === "ERR_DLOPEN_FAILED") return;
    throw error;
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-phase4-wal-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dbPath = path.join(root, "active.db");
  const writer = new Database(dbPath);
  t.after(() => { try { writer.close(); } catch { /* ignore */ } });
  writer.pragma("journal_mode = WAL");
  writer.pragma("wal_autocheckpoint = 0");
  writer.exec("CREATE TABLE events(id INTEGER PRIMARY KEY, body TEXT)");
  const insert = writer.prepare("INSERT INTO events(body) VALUES (?)");
  writer.transaction(() => {
    for (let i = 0; i < 250; i++) insert.run(`event-${i}`);
  })();
  assert.ok(fs.existsSync(`${dbPath}-wal`), "writer has an active WAL companion");

  const snapshot = copySqliteFamilyToTemp(dbPath);
  try {
    assert.equal(snapshot.snapshotMethod, "sqlite_vacuum_into");
    assert.equal(snapshot.integrityCheck, "ok");
    assert.ok(snapshot.originalIdentity.some((entry) => entry.path.endsWith("-wal")));
    assert.ok(snapshot.originalIdentity.every((entry) => /^[0-9a-f]{64}$/.test(entry.sha256)));
    assert.ok(/^[0-9a-f]{64}$/.test(snapshot.snapshotIdentity.sha256));
    assert.notEqual(snapshot.originalIdentity[0].path, snapshot.snapshotIdentity.path);
    const acquired = new Database(snapshot.dbPath, { readonly: true, fileMustExist: true });
    try {
      assert.equal(acquired.prepare("SELECT COUNT(*) AS n FROM events").get().n, 250);
      assert.equal(acquired.pragma("quick_check", { simple: true }), "ok");
    } finally {
      acquired.close();
    }
  } finally {
    snapshot.cleanup();
  }
});
