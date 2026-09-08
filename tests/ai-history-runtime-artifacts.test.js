/**
 * Runtime/state artifacts that outlive the conversations they belong to.
 *
 * Grok Build keeps a search index, an app log and an open-session record outside the session tree;
 * Claude Desktop keeps deletion tombstones, staged attachments and a usage timeline beside its
 * transcripts. All of them survive deletion of the conversation, which is exactly why they matter.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");

const {
  findSessionSearchDb,
  extractSessionSearchRows,
  extractActiveSessions,
  extractUnifiedLog,
  collectGrokRuntimeArtifacts,
  epochToMs,
} = require("../electron/parsers/ai-history/grok-runtime");
const {
  collectDeletedSessions,
  collectPendingUploads,
  collectPlanUsageWindows,
  collectScheduledTasks,
  collectWorktreeAccess,
  collectRemoteBridgeState,
  collectDesktopConfigState,
  collectClaudeDesktopState,
  USAGE_SESSION_GAP_MS,
} = require("../electron/parsers/ai-history/claude-desktop-state");
const { dedupeAiHistoryRows } = require("../electron/parsers/ai-history/row-utils");

const FIXTURE_GROK = path.join(__dirname, "fixtures/ai-history/grok/.grok");
const FIXTURE_DESKTOP = path.join(__dirname, "fixtures/ai-history/claude-desktop");

/* ------------------------------------------------------------------ Grok Build */

test("epochToMs accepts seconds and milliseconds, rejects everything else", () => {
  assert.equal(epochToMs(1785788324), 1785788324000, "seconds are scaled");
  assert.equal(epochToMs(1785788324000), 1785788324000, "ms pass through");
  assert.equal(epochToMs(0), null);
  assert.equal(epochToMs(-5), null);
  assert.equal(epochToMs("nope"), null);
  assert.equal(epochToMs(null), null);
});

test("the Grok session search index yields conversation rows", (t) => {
  const dbPath = findSessionSearchDb(FIXTURE_GROK);
  assert.ok(dbPath, "fixture db is discoverable from the grok root");

  let rows;
  try {
    rows = extractSessionSearchRows(dbPath, { user: "subject" }, {});
  } catch (e) {
    if (/ERR_DLOPEN_FAILED|better-sqlite3/.test(e.message)) { t.skip("no SQLite binding"); return; }
    throw e;
  }

  assert.equal(rows.length, 2);
  const [indexed] = rows;
  assert.equal(indexed.RecordType, "session_search");
  assert.equal(indexed.Role, "conversation");
  assert.equal(indexed.SessionId, "019fa74f-8e10-7a12-88f9-4dd7c4bf912b");
  assert.equal(indexed.Workspace, "/Users/subject/Projects/Example");
  assert.equal(indexed.Timestamp, "2026-08-03 20:18:44", "updated_at is epoch SECONDS here");
  assert.match(indexed.Summary, /Sync docs/);
  assert.match(indexed.FullText, /please sync the docs/, "the indexed body is the evidence");
  // The index mirrors the transcript, so it must say what it is rather than implying completeness.
  assert.match(indexed.ToolDescription, /survives deletion of the session directory/);

  // A row with no title and no body still gets emitted — its existence is the finding.
  const empty = rows[1];
  assert.match(empty.Summary, /Grok indexed session 019fcb53/);
  assert.match(empty.FullText, /"bodyPresent": false/);
});

test("Grok open sessions are recorded with their real open time", () => {
  const rows = extractActiveSessions(FIXTURE_GROK, { user: "subject" });
  assert.equal(rows.length, 1);
  const [row] = rows;
  assert.equal(row.RecordType, "session_open");
  assert.equal(row.SessionId, "019ff6b6-eaf1-7411-a545-9635aa332f93");
  assert.equal(row.Timestamp, "2026-08-12 16:03:31");
  assert.equal(row.Workspace, "/Users/subject/Projects/Example");
  assert.match(row.Summary, /pid 74428/);
  assert.match(row.ToolDescription, /not when this file was written/);
});

test("the Grok app log projects tool executions and turn boundaries only", async () => {
  const rows = await extractUnifiedLog(FIXTURE_GROK, { user: "subject" }, {});
  const kinds = rows.map((r) => r.RecordType);

  assert.equal(kinds.filter((k) => k === "log_tool_exec").length, 3);
  assert.equal(kinds.filter((k) => k === "log_turn_start").length, 1);
  assert.equal(kinds.filter((k) => k === "log_turn_done").length, 1);
  // Debug chatter is the bulk of the log and carries no evidence; it must not reach the timeline.
  assert.ok(!rows.some((r) => /phase_transition/.test(r.Summary)), "phase noise stays out");

  const failed = rows.find((r) => /FAILED/.test(r.Summary));
  assert.equal(failed.InvokedTool, "run_terminal_command");
  assert.match(failed.Summary, /250ms/);
  // The log records the outcome, never the command — claiming otherwise would overstate it.
  assert.match(failed.ToolDescription, /command string is only in the session's/);
  assert.equal(failed.ToolCommand, "", "no command is invented");
});

test("same-second tool calls survive dedupe — the call id has to reach Summary", async () => {
  // The shared dedupe key is (SessionId, Timestamp, Role, summary-slice) and this log timestamps
  // only to the second. Two identical read_file calls in the same second would collapse into one
  // without the call id in Summary — measured on a live capture, 956 of 4,117 rows vanished.
  const rows = await extractUnifiedLog(FIXTURE_GROK, { user: "subject" }, {});
  const sameSecond = rows.filter((r) => r.Timestamp === "2026-08-12 16:03:32");
  assert.equal(sameSecond.length, 2, "the fixture has two calls in one second");
  assert.notEqual(sameSecond[0].Summary, sameSecond[1].Summary, "summaries must differ");
  assert.equal(dedupeAiHistoryRows(sameSecond).length, 2, "both survive dedupe");
  assert.equal(sameSecond[0].MessageId, "call-aaa-1");
  assert.equal(sameSecond[1].MessageId, "call-aaa-2");
});

test("collectGrokRuntimeArtifacts survives a missing store and honours its switches", async () => {
  const all = await collectGrokRuntimeArtifacts(FIXTURE_GROK, { user: "subject" }, {});
  assert.ok(all.some((r) => r.RecordType === "session_open"));
  assert.ok(all.some((r) => r.RecordType === "log_tool_exec"));

  const noLog = await collectGrokRuntimeArtifacts(FIXTURE_GROK, {}, { includeGrokLog: false });
  assert.ok(!noLog.some((r) => r.RecordType === "log_tool_exec"));

  // A root with none of these stores must return cleanly rather than throwing.
  assert.deepEqual(await collectGrokRuntimeArtifacts(path.join(__dirname, "fixtures"), {}, {}), []);
});

/* ------------------------------------------------------------- Claude Desktop */

test("a deletion tombstone dates the removal of a conversation", () => {
  const rows = collectDeletedSessions(FIXTURE_DESKTOP, { user: "subject" });
  assert.ok(rows.length >= 1);
  const row = rows.find((r) => r.SessionId.startsWith("a67b7b64"));
  assert.ok(row, "the session id comes from the filename");

  assert.equal(row.RecordType, "session_deleted");
  // 1786285407322 — the entire file content is the deletion time.
  assert.equal(row.Timestamp, "2026-08-09 14:23:27");
  assert.match(row.FullText, /"timeSource": "file content \(epoch ms\)"/);
  assert.match(row.ToolDescription, /DELETION EVIDENCE/);
  // It must not imply the content is recoverable, nor that this is the conversation's own time.
  assert.match(row.ToolDescription, /does not recover its content/);
  assert.match(row.ToolDescription, /not the conversation's activity/);
});

test("staged uploads are inventoried from the filename, never read", () => {
  const rows = collectPendingUploads(FIXTURE_DESKTOP, { user: "subject" });
  assert.equal(rows.length, 2);

  const shot = rows.find((r) => /Screenshot/.test(r.Summary));
  assert.equal(shot.RecordType, "pending_upload");
  assert.equal(shot.Role, "attachment");
  // 1771157643373 parsed out of `<uuid>-<epoch_ms>_<name>`.
  assert.equal(shot.Timestamp, "2026-02-15 12:14:03");
  assert.equal(shot.MessageId, "1547a6cc-22f0-495f-9919-857b36a4fd50");
  assert.match(shot.FullText, /"sizeBytes": 8/);
  assert.match(shot.ToolDescription, /INVENTORY ONLY/);
  // The bytes are evidence to preserve, not text to sweep into a timeline.
  assert.ok(!/PNGDATA/.test(shot.FullText), "file content is never ingested");
});

test("usage samples become contiguous windows, not thousands of rows", () => {
  const rows = collectPlanUsageWindows(FIXTURE_DESKTOP, { user: "subject" });
  // Three samples ~5 min apart, then one ~28h later: two windows, not four rows.
  assert.equal(rows.length, 2);
  assert.equal(rows[0].RecordType, "app_usage_window");
  assert.match(rows[0].Summary, /3 usage samples/);
  assert.match(rows[1].Summary, /1 usage samples/);
  assert.match(rows[0].FullText, /"gapThresholdMinutes": 30/);
  assert.equal(USAGE_SESSION_GAP_MS, 30 * 60 * 1000);
  // A window is inferred from sample spacing, so it must not read as a recorded session.
  assert.match(rows[0].ToolDescription, /DERIVED from usage-sample spacing/);
  assert.match(rows[0].ToolDescription, /survives\s+deletion of the conversations/);
});

test("scheduled tasks and workspace sightings are collected", () => {
  const tasks = collectScheduledTasks(FIXTURE_DESKTOP, {});
  assert.equal(tasks.length, 1);
  assert.equal(tasks[0].RecordType, "scheduled_task");
  assert.match(tasks[0].Summary, /Nightly repo audit/);
  assert.match(tasks[0].ToolDescription, /automation\/persistence surface/);

  const seen = collectWorktreeAccess(FIXTURE_DESKTOP, {});
  assert.equal(seen.length, 1);
  assert.equal(seen[0].RecordType, "workspace_seen");
  assert.equal(seen[0].Workspace, "/Users/subject/Projects/Example");
  assert.equal(seen[0].Timestamp, "2026-08-16 00:47:10");
});

test("an empty schedule is not reported as evidence", () => {
  const dir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "irflow-cds-"));
  try {
    fs.writeFileSync(path.join(dir, "scheduled-tasks.json"),
      JSON.stringify({ scheduledTasks: [], recordedSkips: {} }));
    assert.deepEqual(collectScheduledTasks(dir, {}), [], "no tasks means no rows");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("collectClaudeDesktopState gathers every store and tolerates a missing root", () => {
  const rows = collectClaudeDesktopState(FIXTURE_DESKTOP, { user: "subject" }, {});
  const kinds = new Set(rows.map((r) => r.RecordType));
  for (const k of ["session_deleted", "pending_upload", "app_usage_window",
    "scheduled_task", "workspace_seen", "remote_control_bridge", "trusted_folder",
    "remote_folder_grant", "mcp_server_config"]) {
    assert.ok(kinds.has(k), `expected ${k} rows`);
  }

  const noUploads = collectClaudeDesktopState(FIXTURE_DESKTOP, {}, { includePendingUploads: false });
  assert.ok(!noUploads.some((r) => r.RecordType === "pending_upload"));

  assert.deepEqual(collectClaudeDesktopState("/nope/does/not/exist", {}, {}), []);
});

test("bridge-state.json links a local session to its remote controller and records consent", () => {
  const rows = collectRemoteBridgeState(FIXTURE_DESKTOP, { user: "subject" });
  assert.equal(rows.length, 1);
  const [row] = rows;
  assert.equal(row.RecordType, "remote_control_bridge");
  assert.match(row.Summary, /Remote Control bridge ENABLED, user consented — local session local_demo-session-uuid ↔ remote session session_01REMOTEDEMO; 2 remote message\(s\) processed/);
  assert.equal(row.SessionId, "local_demo-session-uuid");
  assert.equal(row.MessageId, "session_01REMOTEDEMO");
  assert.match(row.FullText, /"environmentId": "env_demo"/);
  assert.match(row.FullText, /"scopeIds": \[/);
  // The file has no timestamp, so the row must say where its time came from.
  assert.match(row.FullText, /"timeSource": "bridge-state.json mtime/);
  assert.ok(row.Timestamp, "dated from mtime rather than left blank");
  assert.match(row.ToolDescription, /not a use of the bridge/);
});

test("claude_desktop_config.json yields trusted folders, remote grants, consent memory, prefs and MCP servers", () => {
  const rows = collectDesktopConfigState(FIXTURE_DESKTOP, { user: "subject" });
  const trusted = rows.filter((r) => r.RecordType === "trusted_folder");
  assert.deepEqual(trusted.map((r) => r.Workspace).sort(), ["/Users/subject/Downloads", "/Users/subject/Projects/Example"]);
  assert.match(trusted[0].ToolDescription, /without a further per-folder prompt/);

  const grants = rows.filter((r) => r.RecordType === "remote_folder_grant");
  assert.equal(grants.length, 2);
  assert.ok(grants.every((r) => r.SessionId === "session_01REMOTEDEMO"));
  assert.ok(grants.some((r) => r.Workspace === "/tmp/scratch"));

  const consent = rows.find((r) => r.RecordType === "remote_folder_consent");
  assert.equal(consent.Workspace, "/Users/subject/Projects/Example");
  const files = rows.find((r) => r.RecordType === "cowork_user_files_path");
  assert.equal(files.Workspace, "/Users/subject/Documents/Claude");

  const prefs = rows.find((r) => r.RecordType === "cowork_preferences");
  assert.match(prefs.Summary, /browser tools on \(chrome\), web search off, scheduled tasks on, bypass-permissions gate on for 1 account\(s\)/);
  assert.match(prefs.FullText, /"bypassPermissionsAccounts": \[\s*"b548fd3a-0000-4000-8000-000000000002"/);
  assert.ok(!/epitaxyPrefs|starred/.test(prefs.FullText), "UI-only preferences stay out");

  const mcp = rows.filter((r) => r.RecordType === "mcp_server_config");
  assert.equal(mcp.length, 2, "one from claude_desktop_config.json, one from config.json");
  const fsSrv = mcp.find((r) => r.InvokedTool === "filesystem");
  assert.equal(fsSrv.ToolCommand, "npx -y @modelcontextprotocol/server-filesystem /Users/subject/Projects");
  assert.match(fsSrv.FullText, /"envKeys": \[\s*"FS_TOKEN"/, "env NAMES are listed");
  const hex = mcp.find((r) => r.InvokedTool === "hexstrike-ai");
  assert.match(hex.SourceFile, /config\.json$/);
  assert.ok(!/SHOULD-NEVER-APPEAR/.test(JSON.stringify(rows)), "env VALUES are never emitted");
  assert.ok(rows.every((r) => r.Timestamp), "config rows are dated from the file mtime");
});
