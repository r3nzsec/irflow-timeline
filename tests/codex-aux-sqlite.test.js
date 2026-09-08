"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  listCodexLogsDbFiles,
  unescapeRustString,
  extractDebugStringFields,
  parseSubmissionLogBody,
  supplementCodexFromAuxSqlite,
  buildCodexAuxSqliteNotice,
} = require("../electron/parsers/ai-history/codex-aux-sqlite");

/** Skip when the native binding is built for Electron's ABI rather than this runtime. */
function requireSqlite() {
  try {
    return require("better-sqlite3");
  } catch (e) {
    if (e.code === "ERR_DLOPEN_FAILED") return null;
    throw e;
  }
}

test("unescapeRustString decodes Debug escape sequences", () => {
  assert.equal(unescapeRustString("line\\nnext"), "line\nnext");
  assert.equal(unescapeRustString("tab\\there"), "tab\there");
  assert.equal(unescapeRustString('say \\"hi\\"'), 'say "hi"');
  assert.equal(unescapeRustString("back\\\\slash"), "back\\slash");
  assert.equal(unescapeRustString("emoji \\u{1F600}"), "emoji \u{1F600}");
  // Unknown escapes survive rather than being silently dropped.
  assert.equal(unescapeRustString("keep\\qthis"), "keep\\qthis");
});

test("extractDebugStringFields honours escaped quotes inside the literal", () => {
  // The whole reason this is a scanner and not a regex: the prompt contains \" before its real
  // terminator, so a non-greedy regex would truncate at the embedded quote.
  const body = 'Text { text: "run grep \\"needle\\" ./src and report" }';
  assert.deepEqual(extractDebugStringFields(body, "text"), ['run grep "needle" ./src and report']);
});

test("extractDebugStringFields returns every occurrence in order", () => {
  const body = 'items: [Text { text: "first" }, Text { text: "second" }]';
  assert.deepEqual(extractDebugStringFields(body, "text"), ["first", "second"]);
});

test("extractDebugStringFields ignores an unterminated literal", () => {
  assert.deepEqual(extractDebugStringFields('text: "never closed', "text"), []);
});

test("parseSubmissionLogBody pulls thread, submission id, op and prompt text", () => {
  const body = 'session_loop{thread_id=019fed0e-d7ae-7a81-a957-0f2eea1fb820}: Submission '
    + 'sub=Submission { id: "019fed0e-d7de-7b80-8233-c1cc22d8c00a", op: UserInput '
    + '{ items: [Text { text: "check the crash report\\nthanks" }] } }';
  const parsed = parseSubmissionLogBody(body);
  assert.ok(parsed);
  assert.equal(parsed.threadId, "019fed0e-d7ae-7a81-a957-0f2eea1fb820");
  assert.equal(parsed.submissionId, "019fed0e-d7de-7b80-8233-c1cc22d8c00a");
  assert.equal(parsed.op, "UserInput");
  assert.deepEqual(parsed.texts, ["check the crash report\nthanks"]);
});

test("parseSubmissionLogBody rejects unrelated log bodies", () => {
  assert.equal(parseSubmissionLogBody("plain http trace line"), null);
  assert.equal(parseSubmissionLogBody(null), null);
});

test("listCodexLogsDbFiles prefers the highest version suffix", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-logs-files-"));
  try {
    const root = path.join(tmp, ".codex");
    fs.mkdirSync(root, { recursive: true });
    const legacy = path.join(root, "logs.sqlite");
    const current = path.join(root, "logs_2.sqlite");
    fs.writeFileSync(legacy, "legacy");
    fs.writeFileSync(current, "current");
    fs.writeFileSync(path.join(root, "state_5.sqlite"), "not-a-log");
    assert.deepEqual(listCodexLogsDbFiles(root), [current, legacy]);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("supplementCodexFromAuxSqlite reads the thread catalog, automations and logged submissions", () => {
  const Database = requireSqlite();
  if (!Database) return;

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-aux-"));
  const root = path.join(tmp, ".codex");
  fs.mkdirSync(path.join(root, "sqlite"), { recursive: true });

  let dev;
  try {
    dev = new Database(path.join(root, "sqlite", "codex-dev.db"));
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    if (e.code === "ERR_DLOPEN_FAILED") return;
    throw e;
  }

  try {
    // source_created_at / source_updated_at are REAL in the real schema.
    dev.exec(`
      CREATE TABLE local_thread_catalog (
        host_id TEXT, thread_id TEXT, display_title TEXT,
        source_created_at REAL, source_updated_at REAL, cwd TEXT,
        source_kind TEXT, source_detail TEXT, model_provider TEXT,
        git_branch TEXT, missing_candidate INTEGER DEFAULT 0, thread_source TEXT);
      INSERT INTO local_thread_catalog VALUES
        ('h','t-live','Investigate lateral movement',1782812190.0,1782812190.0,
         '/case/alpha','cli',NULL,'openai','main',0,NULL),
        ('h','t-gone','Deleted thread',1782812200.5,1782812200.5,
         '/case/beta','vscode',NULL,'openai',NULL,1,NULL);

      CREATE TABLE automations (
        id TEXT PRIMARY KEY, name TEXT, prompt TEXT, status TEXT,
        next_run_at INTEGER, last_run_at INTEGER, cwds TEXT, rrule TEXT,
        created_at INTEGER, updated_at INTEGER, model TEXT,
        reasoning_effort TEXT, target_type TEXT, project_id TEXT);
      INSERT INTO automations VALUES
        ('a-1','Nightly sweep','exfiltrate then report','ACTIVE',
         1782900000,1782810000,'["/case/alpha"]','FREQ=DAILY;INTERVAL=1',
         1782800000,1782812190,'gpt-x','high','local',NULL);
    `);
    dev.close();

    const logs = new Database(path.join(root, "logs_2.sqlite"));
    logs.exec(`
      CREATE TABLE logs (
        id INTEGER PRIMARY KEY, ts INTEGER, ts_nanos INTEGER, level TEXT,
        target TEXT, feedback_log_body TEXT, thread_id TEXT, process_uuid TEXT);
      INSERT INTO logs (id, ts, ts_nanos, level, target, feedback_log_body, thread_id, process_uuid)
      VALUES (7, 1782812190, 0, 'DEBUG', 'codex_core::session::handlers',
        'session_loop{thread_id=t-live}: Submission sub=Submission { id: "sub-9", op: UserInput { items: [Text { text: "delete the audit log" }] } }',
        't-live', 'proc-1');
      INSERT INTO logs (id, ts, ts_nanos, level, target, feedback_log_body, thread_id, process_uuid)
      VALUES (8, 1782812191, 0, 'INFO', 'codex_http_client::client', 'GET /v1/responses 200', NULL, 'proc-1');
    `);
    logs.close();

    const { rows, stats } = supplementCodexFromAuxSqlite(root, { user: "alice", host: "HOST" });

    assert.equal(stats.threadCatalogRows, 2);
    assert.equal(stats.missingRolloutThreads, 1);
    assert.equal(stats.submissionRows, 1);

    const live = rows.find((r) => r.SessionId === "t-live" && r.RecordType === "thread_catalog");
    assert.ok(live, "catalogued thread row present");
    assert.equal(live.Workspace, "/case/alpha");
    assert.equal(live.InvokedTool, "cli");
    // REAL epoch seconds must parse rather than falling through to the ISO branch.
    assert.equal(live.Timestamp, "2026-06-30 09:36:30");

    const gone = rows.find((r) => r.RecordType === "thread_catalog_missing");
    assert.ok(gone, "missing_candidate becomes its own record type");
    assert.match(gone.Summary, /rollout missing/);
    // Fractional REAL epochs round rather than parsing as null.
    assert.equal(gone.Timestamp, "2026-06-30 09:36:41");

    const auto = rows.find((r) => r.RecordType === "automation");
    assert.ok(auto, "scheduled automation row present");
    assert.match(auto.Summary, /Nightly sweep/);
    assert.match(auto.Summary, /FREQ=DAILY/);
    assert.equal(auto.ToolCommand, "exfiltrate then report");
    assert.match(auto.ToolInput, /"cwds":\["\/case\/alpha"\]/);

    const sub = rows.find((r) => r.RecordType === "submission");
    assert.ok(sub, "logged submission row present");
    assert.equal(sub.Summary, "delete the audit log");
    assert.equal(sub.Role, "user");
    assert.equal(sub.InvokedTool, "UserInput");
    assert.match(sub.ToolInput, /"submissionId":"sub-9"/);
    // Non-submission log targets must not be harvested.
    assert.equal(rows.filter((r) => r.RecordType === "submission").length, 1);

    const notice = buildCodexAuxSqliteNotice(stats);
    assert.match(notice, /1 with no rollout on disk/);
    assert.match(notice, /codex-dev\.db/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("submission rows leave MessageId empty so they cannot suppress history.jsonl rows", () => {
  const Database = requireSqlite();
  if (!Database) return;

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-aux-dedupe-"));
  const root = path.join(tmp, ".codex");
  fs.mkdirSync(root, { recursive: true });

  let logs;
  try {
    logs = new Database(path.join(root, "logs_2.sqlite"));
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    if (e.code === "ERR_DLOPEN_FAILED") return;
    throw e;
  }

  try {
    logs.exec(`
      CREATE TABLE logs (
        id INTEGER PRIMARY KEY, ts INTEGER, ts_nanos INTEGER, level TEXT,
        target TEXT, feedback_log_body TEXT, thread_id TEXT, process_uuid TEXT);
      INSERT INTO logs (id, ts, ts_nanos, level, target, feedback_log_body, thread_id, process_uuid)
      VALUES (1, 1782812190, 0, 'DEBUG', 'codex_core::session::handlers',
        'session_loop{thread_id=t-1}: Submission sub=Submission { id: "sub-1", op: UserInput { items: [Text { text: "same prompt" }] } }',
        't-1', 'proc-1');
    `);
    logs.close();

    const { rows } = supplementCodexFromAuxSqlite(root, {});
    const sub = rows.find((r) => r.RecordType === "submission");
    assert.ok(sub);
    // isSessionRow() keys off MessageId; a value here would let the tracing log drop the
    // canonical history.jsonl prompt through the loose-dedupe path.
    assert.equal(sub.MessageId, "");
    assert.match(sub.ToolInput, /sub-1/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("supplementCodexFromAuxSqlite is silent when no auxiliary stores exist", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-aux-empty-"));
  try {
    const root = path.join(tmp, ".codex");
    fs.mkdirSync(root, { recursive: true });
    const { rows, stats } = supplementCodexFromAuxSqlite(root, {});
    assert.deepEqual(rows, []);
    assert.equal(stats, null);
    assert.equal(buildCodexAuxSqliteNotice(stats), "");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("memories, goals and queue stores yield thread_memory, thread_goal and queued_prompt rows", () => {
  const Database = requireSqlite();
  if (!Database) return;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-aux-mem-"));
  const root = path.join(tmp, ".codex");
  fs.mkdirSync(root, { recursive: true });
  try {
    let db = new Database(path.join(root, "memories_1.sqlite"));
    db.exec(`CREATE TABLE stage1_outputs (thread_id TEXT, source_updated_at INTEGER, raw_memory TEXT, rollout_summary TEXT,
      rollout_slug TEXT, generated_at INTEGER, usage_count INTEGER, last_usage INTEGER, selected_for_phase2 INTEGER, selected_for_phase2_source_updated_at INTEGER);
      INSERT INTO stage1_outputs VALUES ('t-mem', 1780295000, 'User prefers rsync over scp.', '# Backend hardening\n\nRollout context: x', 'backend-hardening', 1780295796, 88, 1788000000, 1, NULL);`);
    db.close();
    db = new Database(path.join(root, "goals_1.sqlite"));
    db.exec(`CREATE TABLE thread_goals (thread_id TEXT, goal_id TEXT, objective TEXT, status TEXT, token_budget INTEGER, tokens_used INTEGER, time_used_seconds INTEGER, created_at_ms INTEGER, updated_at_ms INTEGER);
      INSERT INTO thread_goals VALUES ('t-goal', 'g-1', 'Ship the release', 'active', 100000, 2500, 90, 1788700000000, 1788700100000);`);
    db.close();
    db = new Database(path.join(root, "queue_1.sqlite"));
    db.exec(`CREATE TABLE queued_items (id INTEGER PRIMARY KEY, thread_id TEXT, payload_json TEXT, queue_order INTEGER, created_at_ms INTEGER, updated_at_ms INTEGER);
      INSERT INTO queued_items VALUES (7, 't-queue', '{"items":[{"type":"text","text":"also run the tests"}]}', 0, 1788700200000, 1788700200000);`);
    db.close();

    const { rows, stats } = supplementCodexFromAuxSqlite(root, { user: "subject" });
    const mem = rows.find((r) => r.RecordType === "thread_memory");
    assert.equal(mem.Timestamp, "2026-06-01 06:36:36");
    assert.equal(mem.SessionId, "t-mem");
    assert.match(mem.Summary, /Codex memory of thread — Backend hardening \(injected 88×, last 2026-08-29 10:40:00\)/);
    assert.match(mem.FullText, /rsync over scp/);
    assert.match(mem.ToolDescription, /Interpretation, not transcript/);
    const goal = rows.find((r) => r.RecordType === "thread_goal");
    assert.equal(goal.Summary, "Codex goal active — Ship the release");
    assert.equal(goal.MessageId, "g-1");
    const queued = rows.find((r) => r.RecordType === "queued_prompt");
    assert.equal(queued.Role, "user");
    assert.equal(queued.Summary, "also run the tests");
    assert.equal(queued.Timestamp, "2026-09-06 13:10:00");
    assert.equal(stats.threadMemoryRows, 1);
    assert.equal(stats.goalRows, 1);
    assert.equal(stats.queuedPromptRows, 1);
    assert.match(buildCodexAuxSqliteNotice(stats), /1 thread-memory, 1 goal, 1 queued-prompt \(memories_1\.sqlite, goals_1\.sqlite, queue_1\.sqlite\)/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
