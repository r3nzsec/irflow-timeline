"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  listCodexStateSqliteFiles,
  copySqliteFamilyToTemp,
  supplementCodexFromStateSqlite,
  buildCodexStateSqliteNotice,
  stripUrlSecrets,
} = require("../electron/parsers/ai-history/codex-state-sqlite");

test("Codex state discovery prefers the highest version and snapshots SQLite sidecars", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-state-files-"));
  const codexRoot = path.join(tmp, ".codex");
  fs.mkdirSync(codexRoot, { recursive: true });
  const legacy = path.join(codexRoot, "state.sqlite");
  const current = path.join(codexRoot, "state_5.sqlite");
  fs.writeFileSync(legacy, "legacy");
  fs.writeFileSync(current, "current");
  fs.writeFileSync(`${current}-wal`, "wal");
  fs.writeFileSync(`${current}-shm`, "shm");
  try {
    const files = listCodexStateSqliteFiles(codexRoot);
    assert.deepEqual(files, [current, legacy]);
    const snapshot = copySqliteFamilyToTemp(current);
    try {
      assert.equal(fs.readFileSync(snapshot.dbPath, "utf8"), "current");
      assert.equal(fs.readFileSync(`${snapshot.dbPath}-wal`, "utf8"), "wal");
      assert.equal(fs.readFileSync(`${snapshot.dbPath}-shm`, "utf8"), "shm");
      assert.deepEqual(snapshot.sidecars.sort(), [`${current}-shm`, `${current}-wal`].sort());
    } finally {
      snapshot.cleanup();
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("supplementCodexFromStateSqlite reads thread metadata table", () => {
  let Database;
  try {
    Database = require("better-sqlite3");
  } catch (e) {
    if (e.code === "ERR_DLOPEN_FAILED") return;
    throw e;
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-sqlite-"));
  const codexRoot = path.join(tmp, ".codex");
  fs.mkdirSync(codexRoot, { recursive: true });
  const dbPath = path.join(codexRoot, "state.sqlite");
  let db;
  try {
    db = new Database(dbPath);
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    if (e.code === "ERR_DLOPEN_FAILED") return;
    throw e;
  }
  db.exec(`CREATE TABLE threads (thread_id TEXT, title TEXT, updated_at TEXT);
    INSERT INTO threads VALUES ('t-1', 'Deploy script', '2024-01-15T12:00:00Z');`);
  db.close();

  const { rows, stats } = supplementCodexFromStateSqlite(codexRoot, { user: "alice", host: "HOST" });
  assert.ok(stats?.indexRows >= 1);
  const threadRow = rows.find((r) => r.RecordType === "thread_index" && /Deploy script/.test(r.Summary));
  assert.ok(threadRow);
  assert.equal(threadRow.Timestamp, "2024-01-15 12:00:00");
  assert.equal(buildCodexStateSqliteNotice(stats).includes("state.sqlite"), true);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("stripUrlSecrets keeps the relay endpoint and drops query strings", () => {
  assert.deepEqual(stripUrlSecrets("wss://relay.example.test/ws?token=abc#x"), { url: "wss://relay.example.test/ws", queryStripped: true });
  assert.deepEqual(stripUrlSecrets("wss://relay.example.test/ws"), { url: "wss://relay.example.test/ws", queryStripped: false });
  assert.deepEqual(stripUrlSecrets(""), { url: "", queryStripped: false });
  assert.deepEqual(stripUrlSecrets("not a url?x=1"), { url: "not a url", queryStripped: true });
});

test("remote_control_enrollments become typed rows with enabled state, relay host and last-change time", () => {
  let Database;
  try {
    Database = require("better-sqlite3");
  } catch (e) {
    if (e.code === "ERR_DLOPEN_FAILED") return;
    throw e;
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-rc-"));
  const codexRoot = path.join(tmp, ".codex");
  fs.mkdirSync(codexRoot, { recursive: true });
  const dbPath = path.join(codexRoot, "state_5.sqlite");
  let db;
  try {
    db = new Database(dbPath);
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    if (e.code === "ERR_DLOPEN_FAILED") return;
    throw e;
  }
  try {
    db.exec(`CREATE TABLE threads (id TEXT, title TEXT, updated_at INTEGER);
      CREATE TABLE remote_control_enrollments (
        websocket_url TEXT NOT NULL, account_id TEXT NOT NULL, app_server_client_name TEXT NOT NULL,
        server_id TEXT NOT NULL, environment_id TEXT NOT NULL, server_name TEXT NOT NULL,
        updated_at INTEGER NOT NULL, remote_control_enabled INTEGER,
        PRIMARY KEY (websocket_url, account_id, app_server_client_name));
      INSERT INTO remote_control_enrollments VALUES
        ('wss://relay.example.test/ws?token=SECRET', 'acct-1', 'codex-app', 'srv-1', 'env-1', 'dfir-mac', 1788721080, 1),
        ('wss://relay.example.test/ws', 'acct-1', 'codex-cli', 'srv-2', 'env-2', 'old-laptop', 1780000000, 0);`);
    db.close();

    const { rows, stats } = supplementCodexFromStateSqlite(codexRoot, { user: "alice" });
    const rc = rows.filter((r) => r.RecordType === "remote_control_enrollment");
    assert.equal(rc.length, 2);
    const enabled = rc.find((r) => /ENABLED/.test(r.Summary));
    assert.match(enabled.Summary, /server "dfir-mac" via codex-app, environment env-1 \(relay wss:\/\/relay\.example\.test\/ws\)/);
    assert.equal(enabled.Timestamp, "2026-09-06 18:58:00", "updated_at is epoch seconds");
    assert.equal(enabled.SessionId, "env-1");
    assert.equal(enabled.MessageId, "srv-1");
    assert.ok(!/SECRET/.test(enabled.FullText), "relay query string is stripped");
    assert.match(enabled.FullText, /"relayQueryStripped":true/);
    assert.match(enabled.ToolDescription, /Remote Control/);
    assert.ok(rc.some((r) => /disabled — server "old-laptop"/.test(r.Summary)));
    assert.equal(stats.remoteControlEnrollments, 2);
    assert.equal(stats.remoteControlEnabled, 1);
    assert.match(buildCodexStateSqliteNotice(stats), /^Codex REMOTE CONTROL: 2 enrollment\(s\), 1 enabled\./);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("projects and project_roots become project rows and thread metadata carries the new columns", () => {
  let Database;
  try { Database = require("better-sqlite3"); } catch (e) { if (e.code === "ERR_DLOPEN_FAILED") return; throw e; }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-proj-"));
  const codexRoot = path.join(tmp, ".codex");
  fs.mkdirSync(codexRoot, { recursive: true });
  const db = new Database(path.join(codexRoot, "state_5.sqlite"));
  try {
    db.exec(`CREATE TABLE threads (id TEXT, title TEXT, updated_at_ms INTEGER, cwd TEXT, git_origin_url TEXT, name TEXT, is_pinned INTEGER, history_mode TEXT, project_id TEXT, archived_at INTEGER);
      INSERT INTO threads VALUES ('t-1', 'Audit AD', 1788464419320, '/Users/subject/Downloads/AD_Audit', 'git@github.com:x/y.git', 'audit', 1, 'full', 'p-1', NULL);
      CREATE TABLE projects (id TEXT, name TEXT, metadata TEXT, position INTEGER, created_at_ms INTEGER, updated_at_ms INTEGER);
      CREATE TABLE project_roots (project_id TEXT, position INTEGER, path TEXT);
      INSERT INTO projects VALUES ('p-1', 'AD_Audit', '{}', 0, 1788464419320, 1788464419320);
      INSERT INTO project_roots VALUES ('p-1', 0, '/Users/subject/Downloads/AD_Audit');
      INSERT INTO project_roots VALUES ('p-1', 1, '/Volumes/Evidence/AD');`);
    db.close();
    const { rows, stats } = supplementCodexFromStateSqlite(codexRoot, { user: "subject" });
    const project = rows.find((r) => r.RecordType === "project");
    assert.equal(project.Summary, 'Codex project "AD_Audit" — /Users/subject/Downloads/AD_Audit, /Volumes/Evidence/AD');
    assert.equal(project.Timestamp, "2026-09-03 19:40:19");
    assert.equal(project.Workspace, "/Users/subject/Downloads/AD_Audit");
    assert.equal(project.MessageId, "p-1");
    assert.equal(stats.projectRows, 1);
    const thread = rows.find((r) => r.RecordType === "thread_index");
    assert.match(thread.FullText, /"gitOriginUrl":"git@github\.com:x\/y\.git"/);
    assert.match(thread.FullText, /"isPinned":true/);
    assert.match(thread.FullText, /"projectId":"p-1"/);
    assert.match(thread.FullText, /"historyMode":"full"/);
  } finally {
    try { db.close(); } catch { /* closed */ }
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
