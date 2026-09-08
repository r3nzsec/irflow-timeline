"use strict";

/**
 * Grok Bot — the always-on cloud-agent product whose desktop app installs a local exec daemon.
 * The evidence of interest is authorization (what a cloud agent was allowed to run here), not
 * just conversation text, and credential stores must be inventoried without ever being read.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  decodeSliceBlobName,
  encodeSliceBlobName,
  classifySliceName,
  isGrokBotDaemonRoot,
  isGrokBotAppRoot,
  isGrokBotRoot,
  resolveGrokBotRoot,
  listGrokBotExtractRoots,
  grokBotExtractTargets,
  isGrokBotArtifactFile,
  countGrokBotExtractFiles,
  extractGrokBotDir,
  extractGrokBotPath,
  buildGrokBotImportNotice,
} = require("../electron/parsers/ai-history/grok-bot");
const { AI_HISTORY_TOOLS, extractAiHistory } = require("../electron/parsers/ai-history");
const { detectAiHistoryImport, planImportPaths, parseAiHistoryImport } = require("../electron/parsers/ai-history-import");
const { scanAiArtifacts } = require("../electron/parsers/ai-artifacts");
const {
  getLocalAiHistoryCandidates,
  validateAiHistoryRoot,
  extractMergedAiHistoryRoots,
  extractMergedAiHistoryRootsToDb,
} = require("../electron/parsers/ai-history/profile-scan");

const FIXTURE = path.join(__dirname, "fixtures/ai-history/grok-bot");
const DAEMON = path.join(FIXTURE, ".grokbot");
const APP = path.join(FIXTURE, "Library", "Application Support", "Grok Bot");
const PERSIST = path.join(APP, "sand-client-persistence");

function makeFakeDb() {
  const inserted = [];
  return {
    databases: new Map(),
    createTab(tabId, headers) {
      this.databases.set(tabId, { headers, isLargeFile: false });
    },
    insertBatchArrays(_tabId, arrays) { inserted.push(...arrays); },
    finalizeImport() { return { rowCount: inserted.length, tsColumns: ["Timestamp"], numericColumns: [] }; },
    _inserted: inserted,
  };
}

function writeSlice(appRoot, sliceName, envelope) {
  const dir = path.join(appRoot, "sand-client-persistence");
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, encodeSliceBlobName(sliceName));
  fs.writeFileSync(filePath, JSON.stringify(envelope));
  return filePath;
}

test("slice blob names round-trip through the base32 codec and classify", () => {
  const name = "sand.client.slice.account.google-oauth2%7Cuser_X.transcript.replicas.0cba23ef-1";
  const blob = encodeSliceBlobName(name);
  assert.match(blob, /^[a-z2-7]+\.blob$/);
  assert.equal(decodeSliceBlobName(blob), name);
  assert.deepEqual(classifySliceName(name), {
    kind: "transcript", account: "google-oauth2|user_X", agentId: "0cba23ef-1",
  });
  assert.equal(classifySliceName("sand.client.slice.account.a.roster.last-roster").kind, "roster");
  assert.equal(classifySliceName("sand.client.slice.ui-layout").kind, "ui");
  assert.equal(decodeSliceBlobName("not base32!.blob"), null);
});

test("Grok Bot is a registered tool family with both roots as local candidates", () => {
  assert.equal(AI_HISTORY_TOOLS["grok-bot"].label, "Grok Bot");
  const cands = getLocalAiHistoryCandidates().filter((c) => c.tool === "grok-bot");
  assert.equal(cands.length, 2, "daemon home + app-support dir");
  assert.ok(cands.some((c) => c.path.endsWith(".grokbot")));
  assert.ok(cands.some((c) => c.path.endsWith("Grok Bot")));
});

test("root detection separates the daemon tree from the app tree", () => {
  assert.equal(isGrokBotDaemonRoot(DAEMON), true);
  assert.equal(isGrokBotAppRoot(DAEMON), false);
  assert.equal(isGrokBotAppRoot(APP), true);
  assert.equal(isGrokBotDaemonRoot(APP), false);
  assert.equal(isGrokBotRoot(FIXTURE), false, "the fixture parent is not a root");
  assert.equal(resolveGrokBotRoot(path.join(DAEMON, "local-exec-daemon.log")), DAEMON);
  assert.equal(resolveGrokBotRoot(fs.readdirSync(PERSIST).map((f) => path.join(PERSIST, f))[0]), APP);
  assert.equal(validateAiHistoryRoot("grok-bot", DAEMON), true);
  assert.equal(validateAiHistoryRoot("grok-bot", APP), true);
  assert.equal(isGrokBotArtifactFile(path.join(DAEMON, "settings.json")), true);
  // A settings.json from some other app must not be claimed.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grokbot-neg-"));
  try {
    fs.writeFileSync(path.join(tmp, "settings.json"), JSON.stringify({ theme: "dark" }));
    assert.equal(isGrokBotDaemonRoot(tmp), false);
    assert.equal(isGrokBotArtifactFile(path.join(tmp, "settings.json")), false);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  // settings + daemon files + one staged attachment; ui-only blobs are not data files.
  assert.equal(countGrokBotExtractFiles(DAEMON), 5);
  // markers (2) + Local State + sentry scope/session (2) + all persistence blobs (6) + link cache (1)
  assert.equal(countGrokBotExtractFiles(APP), 2 + 1 + 2 + 6 + 1);
  assert.equal(isGrokBotArtifactFile(path.join(APP, "sentry", "scope_v3.json")), true);
  assert.equal(isGrokBotArtifactFile(path.join(APP, "Local State")), true);
  assert.equal(isGrokBotArtifactFile(fs.readdirSync(path.join(APP, "link-preview-cache", "link-cache"))
    .map((f) => path.join(APP, "link-preview-cache", "link-cache", f))[0]), true);
});

test("daemon root: settings, daemon state and log rows; credentials inventoried but never read", async () => {
  const rows = await extractGrokBotDir(DAEMON, { user: "subject", host: "MAC1" });
  assert.ok(rows.every((r) => r.Tool === "Grok Bot"));
  assert.ok(rows.every((r) => r.User === "subject"));

  const settings = rows.find((r) => r.RecordType === "grokbot_settings");
  assert.match(settings.Summary, /local tool permission "ask-every-time"/);
  assert.match(settings.Summary, /egress tunnel on/);
  assert.match(settings.FullText, /"host": "mcp.example.test"/, "MCP URL reduced to its host");
  assert.ok(!/SECRET/.test(settings.FullText), "URL query string is dropped");
  assert.match(settings.FullText, /only read tables/, "custom MCP instructions are evidence");

  const daemon = rows.find((r) => r.RecordType === "local_exec_daemon");
  assert.equal(daemon.Timestamp, "2026-09-07 05:13:20");
  assert.equal(daemon.MessageId, "36911");
  assert.match(daemon.ToolDescription, /executes commands on this machine/);
  const sup = rows.find((r) => r.RecordType === "local_exec_supervisor");
  assert.equal(sup.Timestamp, "2026-09-07 05:15:00");

  const starts = rows.filter((r) => r.RecordType === "daemon_started");
  assert.equal(starts.length, 2, "one row per daemon (re)start");
  assert.deepEqual(starts.map((r) => r.MessageId).sort(), ["36911", "41869"]);
  assert.equal(starts[0].Timestamp, "", "log lines carry no timestamp — none is fabricated");
  assert.ok(starts.every((r) => r.LineNumber), "order is preserved through LineNumber");
  const shell = rows.find((r) => r.RecordType === "daemon_shell_exec");
  assert.equal(shell.InvokedTool, "shell-exec");
  assert.match(shell.ToolDescription, /command, request ID, process result and exit status are not logged/);
  assert.match(shell.FullText, /"correlationStatus": "unlinked"/);
  const logSummary = rows.find((r) => r.RecordType === "daemon_log_summary");
  assert.match(logSummary.Summary, /6 line\(s\)/);
  assert.match(logSummary.FullText, /"cli_unknown_command"/);
  assert.match(logSummary.FullText, /"user-computer-provider": 2/);

  const creds = rows.filter((r) => r.RecordType === "credential_store_inventory");
  assert.equal(creds.length, 2);
  assert.ok(creds.every((r) => /"contentParsed": false/.test(r.FullText)));
  const staged = rows.find((r) => r.RecordType === "attachment_staged");
  assert.equal(staged.Role, "attachment");
  assert.match(staged.Summary, /evidence\.png \(7 bytes\)/);

  const all = JSON.stringify(rows);
  assert.ok(!/SHOULD-NEVER-APPEAR/.test(all), "no credential content reaches any row");
  assert.ok(!/PNGDATA/.test(all), "staged attachment bytes are never read");
  assert.equal(rows._grokBotStats.daemonRoot, true);
  assert.equal(rows._grokBotStats.appRoot, false);
});

test("app root: roster names transcripts; local-tool-permission and automation entries are typed", async () => {
  const rows = await extractGrokBotDir(APP, { user: "subject" });
  const roster = rows.find((r) => r.RecordType === "agent_roster");
  assert.equal(roster.SessionId, "agent-1");
  assert.match(roster.Summary, /Agent "Triage Helper" — IR assistant/);
  assert.equal(roster.Timestamp, "2026-09-07 05:18:20", "last activity wins");
  assert.equal(roster.Workspace, "/home/box/agents/triage");
  assert.match(roster.FullText, /"accountScope": "google-oauth2\|user_DEMO"/);

  const user = rows.find((r) => r.RecordType === "user" && r.Role === "user");
  assert.equal(user.Summary, "Pull the auth logs from my laptop");
  assert.equal(user.SessionId, "agent-1");
  assert.equal(user.ParentId, "req-1");
  assert.equal(user.Timestamp, "2026-09-07 05:13:20");
  assert.equal(user.Workspace, "/home/box/agents/triage", "workspace comes from the roster");

  const perms = rows.filter((r) => r.RecordType === "local_tool_permission_request");
  assert.equal(perms.length, 3);
  const perm = perms[0];
  assert.equal(perm.Role, "system");
  assert.equal(perm.InvokedTool, "local-exec", "legacy content-only form keeps the generic tool name");
  assert.match(perm.Summary, /Run `cat \/var\/log\/auth\.log` on your Mac\? — permission state allowed; execution not established/);
  assert.match(perm.ToolDescription, /does not prove/);
  assert.match(perm.FullText, /"authorizationRecorded": true/);
  // Structured `ask` form: the exact command line lands in ToolCommand, a file read in ToolInput.
  const runCmd = perms.find((r) => r.InvokedTool === "run-command");
  assert.equal(runCmd.ToolCommand, 'ls -la "/Users/subject/Desktop/E01" && du -sh "/Users/subject/Desktop/E01"');
  assert.equal(runCmd.ToolInput, "");
  assert.match(runCmd.Summary, /^\[Local tool request\] run-command on MAC1 \(always\): ls -la/);
  assert.match(runCmd.Summary, /permission state persistent_policy; execution not established/);
  assert.match(runCmd.FullText, /"executionOutcome": "unknown"/);
  const readFile = perms.find((r) => r.InvokedTool === "read-file");
  assert.equal(readFile.ToolInput, "/Users/subject/Documents/app/Sidebar.tsx");
  assert.equal(readFile.ToolCommand, "");

  assert.ok(rows.some((r) => r.RecordType === "assistant" && r.Summary === "Here is what I found in the logs."));
  const widgets = rows.filter((r) => r.RecordType === "agent_widget");
  assert.match(widgets[0].Summary, /Archive the results\? → responded: yes/);
  assert.match(widgets[1].Summary, /^\[Widget\] Send the email now\? \[Draft it \| Send now \| Not yet\] → responded: Draft it for review/);
  assert.match(widgets[1].FullText, /Keeps the application open\./);

  const shot = rows.find((r) => r.RecordType === "user_attachment" && /shot\.png/.test(r.Summary));
  assert.equal(shot.Role, "attachment");
  assert.match(shot.Summary, /shot\.png \(4096 bytes, 800x600\) — no local copy found/);
  assert.match(shot.FullText, /"boxPath": "\/home\/box\/sand-data\/agents\/agent-1\/attachments\/0{64}\.png"/);
  assert.match(shot.FullText, /"referenceSha256": "0{64}"/);
  assert.equal(shot.Timestamp, "2026-09-07 05:13:20", "stamp-less attachment borrows the message sent in the same batch");
  assert.match(shot.FullText, /"timeSource": "message sent in the same batch"/);
  assert.match(shot.ToolDescription, /CLOUD box, not this machine/);

  // By default the finder stays inside the Grok Bot data folder, not Desktop/Downloads.
  const csv = rows.find((r) => r.RecordType === "user_attachment" && /evidence-export\.csv/.test(r.Summary));
  const downloaded = path.join(FIXTURE, "Downloads", "evidence-export.csv");
  assert.match(csv.Summary, /evidence-export\.csv \(35 bytes\) — no local copy found/);
  assert.notEqual(csv.ToolInput, downloaded);
  assert.equal(csv.Timestamp, "2026-09-07 05:15:00");

  const recovered = await extractGrokBotDir(APP, { user: "subject" }, { findLocalAttachments: true });
  const csvOptIn = recovered.find((r) => r.RecordType === "user_attachment" && /evidence-export\.csv/.test(r.Summary));
  assert.match(csvOptIn.Summary, /evidence-export\.csv \(35 bytes\) — original verified on disk: /);
  assert.equal(csvOptIn.ToolInput, downloaded);
  assert.match(csvOptIn.FullText, /"localCopyVerification": "name \+ size \+ SHA-256 match"/);
  assert.match(csvOptIn.FullText, /"computedLocalSha256": "[0-9a-f]{64}"/);
  assert.match(csvOptIn.FullText, /"hashMatchStatus": "reference equals computed hash of recovered local bytes"/);
  assert.ok(!csvOptIn.FullText.includes(path.join("Desktop", "evidence-export.csv")),
    "a same-name file with different bytes is not reported as the original");

  const agentImage = rows.find((r) => r.RecordType === "assistant" && /Here is the VPS panel\./.test(r.Summary));
  assert.match(agentImage.FullText, /\[Agent image\] hPanel VPS list showing srv1 running at 203\.0\.113\.9 — reference sha256 1{64}/);
  assert.match(agentImage.ToolDescription, /screenshot/);

  const agentFile = rows.find((r) => r.RecordType === "agent_attachment");
  assert.match(agentFile.Summary, /^\[Agent attachment\] report\.pdf — reference sha256 222222222222…/);
  assert.match(agentFile.FullText, /"referenceSha256": "2{64}"/);

  const box = rows.find((r) => r.RecordType === "agent_box_instruction");
  assert.equal(box.Summary, "[Box instruction] Sign in to Hostinger hPanel → handed_back");
  assert.match(box.ToolDescription, /Credentials entered there went to the box/);

  const identity = rows.find((r) => r.RecordType === "app_identity");
  assert.equal(identity.Timestamp, "2026-09-07 05:10:00");
  assert.equal(identity.Summary, "Grok Bot 1.4.2 signed in as subject@example.test on macOS 26.6.2, timezone Asia/Dubai; last open agent agent-1");
  assert.equal(identity.SessionId, "agent-1");
  assert.match(identity.FullText, /"accountId": "google-oauth2\|user_DEMO"/);
  assert.match(identity.FullText, /"deviceBootTime": "2026-09-07 04:00:00"/);
  const crashSession = rows.find((r) => r.RecordType === "app_crash_reporter_session");
  assert.equal(crashSession.Timestamp, "2026-09-07 05:13:20");
  assert.match(crashSession.Summary, /session ok — sand@1\.4\.2, last update 2026-09-07 05:21:40, 1 error\(s\)/);
  const installed = rows.find((r) => r.RecordType === "app_profile_created");
  assert.equal(installed.Timestamp, "2026-08-12 09:29:40");
  assert.match(installed.ToolDescription, /does not conclusively establish/);

  const link = rows.find((r) => r.RecordType === "link_preview");
  assert.equal(link.Timestamp, "2026-08-28 11:31:51");
  assert.equal(link.Summary, "Link preview fetched — GitHub - elastic/integrations (https://github.com/elastic/integrations)");
  assert.match(link.FullText, /"hostname": "github.com"/);
  assert.match(link.FullText, /"hasFavicon": true/);

  const auto = rows.find((r) => r.RecordType === "event_automation_changed");
  assert.match(auto.Summary, /Automation created — "Nightly log sweep" \(auto-9\)/);
  assert.match(auto.ToolDescription, /persistence/);
  assert.ok(rows.some((r) => r.RecordType === "feedback"));

  const replica = rows.find((r) => r.RecordType === "transcript_replica");
  assert.match(replica.Summary, /Transcript replica for agent "Triage Helper" — 14 entries, persisted 2026-09-07 05:20:00; oldest retained 2026-09-07 05:13:20/);
  assert.ok(!/CAP/.test(replica.Summary), "14 entries is under the app's cap");
  assert.match(replica.FullText, /"atEntryCap": false/);
  assert.match(replica.FullText, /"maxEntries": 200/);
  assert.match(replica.FullText, /"maxSerializedEntryChars": 786432/);
  assert.match(replica.FullText, /"maxAgeDays": 7/);
  assert.match(replica.ToolDescription, /last 200 entries or a 768 KB-equivalent JSON\.stringify character budget per agent, at most 24 agent replicas per account, and deletes any replica not refreshed for 7 days/);
  assert.match(buildGrokBotImportNotice(rows._grokBotStats), /replicas are bounded to the last 200 entries per agent/);

  const draft = rows.find((r) => r.RecordType === "composer_draft");
  assert.match(draft.Summary, /\[Unsent draft to "Triage Helper"\] also check the VPN logs/);
  assert.equal(draft.Timestamp, "2026-09-07 05:14:30");

  assert.ok(rows.some((r) => r.RecordType === "app_session" && /Grok Bot 1\.4\.2 started — pid 2271/.test(r.Summary)));
  assert.ok(rows.some((r) => r.RecordType === "app_update" && /1\.4\.1 → 1\.4\.2/.test(r.Summary)));
  assert.equal(rows.filter((r) => r.RecordType === "credential_store_inventory").length, 2);
  assert.ok(!/SHOULD-NEVER-APPEAR/.test(JSON.stringify(rows)), "no credential bytes and no favicon data URL reach a row");
  assert.ok(!rows.some((r) => /ui-layout|pinnedAgentIds/.test(r.Summary)), "UI-only slices stay out");

  const stats = rows._grokBotStats;
  assert.equal(stats.agents, 1);
  assert.equal(stats.transcripts, 1);
  assert.equal(stats.localToolPermissionRequests, 3);
  assert.equal(stats.drafts, 1);
  assert.equal(stats.attachments, 2);
  assert.equal(stats.attachmentsRecovered, 0, "Downloads is not searched unless opted in");
  assert.equal(stats.linkPreviews, 1);
  assert.equal(recovered._grokBotStats.attachmentsRecovered, 1);
  const notice = buildGrokBotImportNotice(stats);
  assert.match(notice, /3 LOCAL TOOL request/);
  assert.match(notice, /2 uploaded attachment reference\(s\), 0 with a SHA-256-verified original/);
});

test("a replica at Grok Bot's 200-entry boundary reports uncertainty without inventing deletion", async () => {
  const { REPLICA_ENTRY_CAP } = require("../electron/parsers/ai-history/grok-bot");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grokbot-cap-"));
  try {
    const app = path.join(tmp, "Library", "Application Support", "Grok Bot");
    const persist = path.join(app, "sand-client-persistence");
    fs.mkdirSync(persist, { recursive: true });
    const entries = Array.from({ length: REPLICA_ENTRY_CAP }, (_, i) => ({
      kind: "message", id: `m-${i}`, role: "user", content: `prompt ${i}`, timestampMs: 1788758000000 + i * 1000,
    }));
    fs.writeFileSync(path.join(persist, encodeSliceBlobName(
      "sand.client.slice.account.acct.transcript.replicas.agent-cap",
    )), JSON.stringify({ schemaVersion: 1, value: { entries, epochHint: null, acceptedSequenceHint: null, persistedAt: 1788758400000 } }));
    const rows = await extractGrokBotDir(app, {});
    const replica = rows.find((r) => r.RecordType === "transcript_replica");
    assert.match(replica.Summary, /200 entries, persisted 2026-09-07 05:20:00 — AT THE 200-ENTRY RETENTION LIMIT; earlier history availability unknown; oldest retained 2026-09-07 05:13:20/);
    assert.doesNotMatch(replica.Summary, /dropped|deleted/i);
    assert.match(replica.FullText, /"atEntryCap": true/);
    assert.match(replica.FullText, /"historicalDeletionProven": false/);
    assert.equal(rows._grokBotStats.replicasAtCap, 1);
    assert.match(buildGrokBotImportNotice(rows._grokBotStats), /1 replica\(s\) at\/near Grok Bot's 200-entry\/768 KB retention boundary/);
    assert.equal(rows.filter((r) => r.RecordType === "user").length, REPLICA_ENTRY_CAP, "every retained prompt is still emitted");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("permission negatives, typed tool/notice records, and account-scoped duplicate IDs stay distinct", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grokbot-semantics-"));
  try {
    const app = path.join(tmp, "Grok Bot");
    const now = Date.now();
    const entries = [
      ...["pending", "expired", "denied", "cancelled"].map((status, i) => ({
        kind: "send-message",
        id: `permission-${status}`,
        timestampMs: now + i,
        message: { type: "local-tool-permission", ask: { requestId: `request-${status}`, action: "run-command", target: "printf audit", status } },
      })),
      { kind: "tool-call", id: "tool-1", timestampMs: now + 10, status: "failed", name: "browser", input: { url: "https://example.test" } },
      { kind: "notice", id: "notice-1", timestampMs: now + 11, replyTo: "message-1", notice: { text: "Connection recovering" } },
      { kind: "message", id: "shared-id", timestampMs: now + 12, role: "user", content: "same native id, account A", channel: "slack", replyTo: "thread-1" },
    ];
    writeSlice(app, "sand.client.slice.account.acct-a.transcript.replicas.same-agent", {
      schemaVersion: 1,
      value: { entries, epochHint: null, acceptedSequenceHint: null, persistedAt: now },
    });
    writeSlice(app, "sand.client.slice.account.acct-b.transcript.replicas.same-agent", {
      schemaVersion: 1,
      value: { entries: [{ kind: "message", id: "shared-id", timestampMs: now + 13, role: "user", content: "same native id, account B" }], epochHint: null, acceptedSequenceHint: null, persistedAt: now },
    });

    const rows = await extractGrokBotDir(app, {});
    const permissions = rows.filter((r) => r.RecordType === "local_tool_permission_request");
    assert.equal(permissions.length, 4);
    for (const row of permissions) {
      assert.match(row.Summary, /execution not established/);
      assert.match(row.FullText, /"authorizationRecorded": false/);
      assert.match(row.FullText, /"executionObserved": false/);
      assert.ok(row.ParentId.startsWith("request-"), "nested native request ID is retained");
    }
    assert.deepEqual(rows._grokBotStats.permissionStates, { pending: 1, expired: 1, denied: 1, cancelled: 1 });
    assert.equal(rows._grokBotStats.localToolAuthorizationsRecorded, 0);
    assert.equal(rows._grokBotStats.localToolNonAuthorizations, 4);

    const tool = rows.find((r) => r.RecordType === "tool_call");
    assert.equal(tool.InvokedTool, "browser");
    assert.match(tool.ToolInput, /example\.test/);
    assert.match(tool.ToolDescription, /does not establish execution on the local endpoint/);
    const notice = rows.find((r) => r.RecordType === "notice");
    assert.equal(notice.ParentId, "message-1");
    assert.equal(rows.filter((r) => r.MessageId === "shared-id").length, 2, "same agent/message ID in separate account files is not collapsed");
    assert.ok(rows.filter((r) => r.MessageId === "shared-id").every((r) => r.SourceOffset === "/value/entries/6" || r.SourceOffset === "/value/entries/0"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("v2 send journal preserves native lifecycle, linkage, attachments, failures, and empty journals", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grokbot-journal-"));
  try {
    const app = path.join(tmp, "Grok Bot");
    const createdAtMs = 1788758000000;
    writeSlice(app, "sand.client.slice.account.acct.send-journal", {
      schemaVersion: 2,
      value: { records: [{
        nonce: "nonce-1",
        priorNonces: ["nonce-0"],
        accountSlot: "acct",
        agentId: "agent-1",
        digest: "digest-1",
        createdAtMs,
        queuedAtMs: createdAtMs + 1000,
        firstFlushAtMs: createdAtMs + 2000,
        failedAtMs: createdAtMs + 3000,
        phase: "queued",
        input: {
          agentId: "agent-1",
          prompt: "audit queued prompt",
          richText: "**audit queued prompt**",
          replyToId: "reply-1",
          isFork: true,
          sessionId: "session-1",
          automationWriteProvenance: "untrusted",
          attachmentPaths: ["/tmp/staged.txt"],
          attachmentNames: ["evidence.txt"],
        },
        attachments: [{ stagedPath: "/tmp/staged.txt", name: "evidence.txt" }],
        draftRecovery: null,
        authoredThreadRootId: "root-1",
        consumedDraftId: "draft-1",
      }] },
    });
    writeSlice(app, "sand.client.slice.account.empty.send-journal", { schemaVersion: 2, value: { records: [] } });
    writeSlice(app, "sand.client.slice.account.future.send-journal", {
      schemaVersion: 99,
      value: { records: [{ nonce: "future-1", agentId: "future-agent", phase: "future-phase", input: { agentId: "future-agent", prompt: "future raw record" }, futureField: { preserved: true } }] },
    });

    const rows = await extractGrokBotDir(app, {});
    const journal = rows.find((r) => r.RecordType === "send_journal");
    assert.equal(journal.Timestamp, "2026-09-07 05:13:20");
    assert.equal(journal.TimestampBasis, "send-journal.createdAtMs");
    assert.equal(journal.MessageId, "nonce-1");
    assert.equal(journal.SessionId, "agent-1");
    assert.equal(journal.ParentId, "reply-1");
    assert.equal(journal.SourceOffset, "/value/records/0");
    assert.match(journal.Summary, /Send journal queued — audit queued prompt; failed/);
    assert.match(journal.FullText, /"priorNonces"/);
    assert.match(journal.FullText, /"recordQualified": true/);
    assert.match(journal.FullText, /"committedPath": null/);
    assert.match(journal.FullText, /"sessionId": "session-1"/);
    assert.match(journal.ToolDescription, /do not independently prove server delivery/);
    const future = rows.find((r) => r.MessageId === "future-1");
    assert.match(future.FullText, /"schemaQualified": false/);
    assert.match(future.FullText, /"futureField"/);
    assert.match(future.ToolDescription, /Unqualified schema; raw-preserved/);
    assert.equal(rows._grokBotStats.sendJournalFiles, 3);
    assert.equal(rows._grokBotStats.emptySendJournals, 1);
    assert.equal(rows._grokBotStats.sendJournalRecords, 2);
    assert.equal(rows._grokBotStats.sendJournalUnknownSchema, 1);
    assert.deepEqual(rows._grokBotStats.sendJournalByPhase, { queued: 1, "future-phase": 1 });
    assert.deepEqual(rows._grokBotStats.sendJournalSchemaVersions, { 2: 2, 99: 1 });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("retention age, serialized-entry size, malformed blobs, and source inventory are explicit", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grokbot-coverage-"));
  try {
    const app = path.join(tmp, "Grok Bot");
    const persistedAt = Date.now() - 8 * 24 * 60 * 60 * 1000;
    writeSlice(app, "sand.client.slice.account.acct.transcript.replicas.near-byte", {
      schemaVersion: 1,
      value: {
        entries: [{ kind: "message", id: "large", role: "user", content: "x".repeat(710000), timestampMs: persistedAt }],
        epochHint: null,
        acceptedSequenceHint: null,
        persistedAt,
      },
    });
    const malformed = path.join(app, "sand-client-persistence", encodeSliceBlobName("sand.client.slice.account.acct.transcript.replicas.malformed"));
    fs.writeFileSync(malformed, "{broken");
    fs.writeFileSync(path.join(app, "sand-client-persistence", "not-base32!.blob"), "{}");

    const rows = await extractGrokBotDir(app, {});
    const replica = rows.find((r) => r.RecordType === "transcript_replica");
    assert.match(replica.Summary, /near the 768 KB serialized-entry limit/);
    assert.match(replica.Summary, /exceeds the 7-day restore TTL/);
    assert.match(replica.FullText, /"atByteCap": false/);
    assert.match(replica.FullText, /"nearByteCap": true/);
    assert.equal(rows._grokBotStats.replicasPastRestoreTtl, 1);
    assert.equal(rows._grokBotStats.replicasNearByteLimit, 1);
    assert.equal(rows._grokBotStats.unreadableBlobs, 1);
    assert.equal(rows._grokBotStats.persistenceBlobsSeen, 3);
    assert.equal(rows._grokBotStats.persistenceBlobsEligible, 2);
    assert.equal(rows._grokBotStats.persistenceBlobsUnknown, 1);
    assert.ok(rows.some((r) => r.RecordType === "persistence_blob_unreadable" && r.SourceFile === malformed));
    assert.ok(rows.some((r) => r.RecordType === "persistence_blob_inventory" && /not-base32/.test(r.SourceFile)));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("daemon rotated logs and independent row/byte omission counters are preserved", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grokbot-daemon-caps-"));
  try {
    const daemon = path.join(tmp, ".grokbot");
    fs.mkdirSync(daemon, { recursive: true });
    fs.writeFileSync(path.join(daemon, ".grokbot-data-root-v1"), "1");
    fs.writeFileSync(path.join(daemon, "local-exec-daemon.log.1"), "[daemon] started (pid 11)\n");
    const detailLines = Array.from({ length: 5010 }, (_, i) => `[shell-exec] request ${i}`).join("\n");
    fs.writeFileSync(path.join(daemon, "local-exec-daemon.log"), `${detailLines}\n[noise] ${"x".repeat(8 * 1024 * 1024)}`);

    const rows = await extractGrokBotDir(daemon, {});
    assert.ok(rows.some((r) => r.SourceFile.endsWith("local-exec-daemon.log.1") && r.RecordType === "daemon_started"));
    const currentSummary = rows.find((r) => r.RecordType === "daemon_log_summary" && r.SourceFile.endsWith("local-exec-daemon.log"));
    const parsed = JSON.parse(currentSummary.FullText);
    assert.equal(parsed.detailCandidates, 5010);
    assert.equal(parsed.detailRowsEmitted, 5000);
    assert.equal(parsed.detailRowsOmittedByLimit, 10);
    assert.equal(rows._grokBotStats.daemonLogFiles, 2);
    assert.equal(rows._grokBotStats.daemonLogDetailRowsOmitted, 10);
    assert.ok(rows._grokBotStats.daemonLogBytesOmitted > 0);
    assert.equal(rows._grokBotStats.daemonLogsReadCapped, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("Grok Bot statistics are order-independent in memory and agree with DB and single-import routes", async () => {
  const roots = [
    { tool: "grok-bot", path: DAEMON, label: "daemon" },
    { tool: "grok-bot", path: APP, label: "app" },
  ];
  const forward = await extractMergedAiHistoryRoots(roots, {}, {});
  const reverse = await extractMergedAiHistoryRoots([...roots].reverse(), {}, {});
  assert.deepEqual(forward.importMeta.grokBot, reverse.importMeta.grokBot);
  assert.equal(forward.importMeta.grokBot.daemonRoot, true);
  assert.equal(forward.importMeta.grokBot.appRoot, true);
  assert.equal(forward.importMeta.grokBot.perRoot.length, 2);
  assert.equal(forward.importMeta.grokBot.transcriptSourceEntries, 14);

  const db = makeFakeDb();
  const streamed = await extractMergedAiHistoryRootsToDb(db, "grok-merged", roots, {}, {});
  assert.deepEqual(streamed.importMeta.grokBot, forward.importMeta.grokBot);

  const singleDb = makeFakeDb();
  const single = await parseAiHistoryImport(APP, "grok-single", singleDb, null, { tool: "grok-bot", target: APP });
  assert.ok(single.meta.grokBot);
  assert.equal(single.meta.grokBot.daemonRoot, true, "single-tool picker pairs the companion daemon root");
  assert.equal(single.meta.grokBot.appRoot, true);
  assert.equal(single.meta.grokBot.transcriptSourceEntries, 14);
});

test("identical native agent/message IDs from different endpoints remain separate occurrences", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grokbot-endpoints-"));
  try {
    const roots = [];
    for (const endpoint of ["endpoint-a", "endpoint-b"]) {
      const app = path.join(tmp, endpoint, "Grok Bot");
      writeSlice(app, "sand.client.slice.account.acct.transcript.replicas.agent-1", {
        schemaVersion: 1,
        value: { entries: [{ kind: "message", id: "same-message", role: "user", content: "same retained prompt", timestampMs: 1788758000000 }], epochHint: null, acceptedSequenceHint: null, persistedAt: 1788758001000 },
      });
      roots.push({ tool: "grok-bot", path: app, label: endpoint, endpointHost: endpoint });
    }
    const merged = await extractMergedAiHistoryRoots(roots, {}, {});
    const occurrences = merged.rows.filter((r) => r.MessageId === "same-message");
    assert.equal(occurrences.length, 2);
    assert.deepEqual(new Set(occurrences.map((r) => r.Host)), new Set(["endpoint-a", "endpoint-b"]));
    assert.equal(merged.importMeta.grokBot.transcripts, 2);
    assert.equal(merged.importMeta.grokBot.transcriptSourceEntries, 2);
    assert.equal(merged.importMeta.grokBot.perRoot.length, 2);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("single sentry / Local State / link-cache files extract on their own; box hash helper", async () => {
  const { contentHashFromBoxPath, createLocalAttachmentFinder } = require("../electron/parsers/ai-history/grok-bot");
  assert.equal(contentHashFromBoxPath("file:///home/box/x/attachments/" + "a".repeat(64) + ".PNG"), "a".repeat(64));
  assert.equal(contentHashFromBoxPath("/Users/subject/Desktop/shot.png"), "");
  const scope = await extractGrokBotPath(path.join(APP, "sentry", "scope_v3.json"), { user: "subject" });
  assert.ok(scope.some((r) => r.RecordType === "app_identity"));
  const link = await extractGrokBotPath(fs.readdirSync(path.join(APP, "link-preview-cache", "link-cache"))
    .map((f) => path.join(APP, "link-preview-cache", "link-cache", f))[0], {});
  assert.equal(link.length, 1);
  assert.equal(link[0].RecordType, "link_preview");
  const state = await extractGrokBotPath(path.join(APP, "Local State"), {});
  assert.ok(state.some((r) => r.RecordType === "app_profile_created"));

  // The finder hashes only name+size candidates inside the roots it was given.
  const find = createLocalAttachmentFinder([FIXTURE]);
  const csvSha = require("node:crypto").createHash("sha256")
    .update(fs.readFileSync(path.join(FIXTURE, "Downloads", "evidence-export.csv"))).digest("hex");
  assert.deepEqual(find("evidence-export.csv", 35, csvSha), [path.join(FIXTURE, "Downloads", "evidence-export.csv")]);
  assert.deepEqual(find("evidence-export.csv", 36, csvSha), []);
  assert.deepEqual(find("evidence-export.csv", 35, "0".repeat(64)), []);
  assert.equal(createLocalAttachmentFinder(path.join(FIXTURE, "does-not-exist")), null);
  const daemonOnly = createLocalAttachmentFinder([DAEMON]);
  assert.deepEqual(daemonOnly("evidence-export.csv", 35, csvSha), [], "Desktop/Downloads are not searched from a Grok Bot data root");
  const optedIn = createLocalAttachmentFinder([DAEMON], { includeUserFolders: true, home: FIXTURE });
  assert.deepEqual(optedIn("evidence-export.csv", 35, csvSha), [path.join(FIXTURE, "Downloads", "evidence-export.csv")]);
  const abortError = new Error("cancelled");
  const cancellable = createLocalAttachmentFinder([path.join(FIXTURE, "Downloads")], {
    checkAbort: () => { throw abortError; },
  });
  assert.throws(() => cancellable("evidence-export.csv", 35, csvSha), (e) => e === abortError);
});

test("single-file extraction and the generic extractor entry point work", async () => {
  const blob = fs.readdirSync(PERSIST).map((f) => path.join(PERSIST, f))
    .find((p) => classifySliceName(decodeSliceBlobName(path.basename(p)))?.kind === "transcript");
  const rows = await extractGrokBotPath(blob, { user: "subject" });
  assert.ok(rows.some((r) => r.RecordType === "local_tool_permission_request"));
  assert.ok(rows.every((r) => r.Workspace === "/home/box/agents/triage"), "roster is consulted for a lone transcript");

  const viaIndex = await extractAiHistory("grok-bot", path.join(DAEMON, "local-exec-daemon.log"), {});
  assert.ok(viaIndex.some((r) => r.RecordType === "daemon_started"));
  await assert.rejects(() => extractGrokBotPath(path.join(__dirname, "fixtures")), /Not a Grok Bot data directory/);
});

test("import detection, planning and triage scanning recognise both roots", () => {
  assert.equal(detectAiHistoryImport(DAEMON)?.tool, "grok-bot");
  assert.equal(detectAiHistoryImport(APP)?.tool, "grok-bot");
  const log = path.join(DAEMON, "local-exec-daemon.log");
  assert.deepEqual(detectAiHistoryImport(log), { tool: "grok-bot", target: DAEMON });

  const planned = planImportPaths([log, path.join(DAEMON, "settings.json")]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "grok-bot");
  assert.equal(planned[0].path, DAEMON);

  const scan = scanAiArtifacts(FIXTURE);
  assert.equal(scan.grokBot.length, 2);
  assert.ok(scan.grokBot.some((h) => h.path === DAEMON && h.sessionCount === 5));
  assert.ok(scan.grokBot.some((h) => h.path === APP));
  assert.equal(scan.grokBuild.length, 0, ".grokbot is not mistaken for a Grok Build root");
});

test("picking a home-like parent finds ~/.grokbot and Application Support/Grok Bot", async () => {
  assert.equal(isGrokBotRoot(FIXTURE), false, "the parent itself is not a root");
  const found = listGrokBotExtractRoots(FIXTURE);
  assert.equal(found.length, 2);
  assert.ok(found.includes(DAEMON));
  assert.ok(found.includes(APP));
  assert.deepEqual(grokBotExtractTargets(FIXTURE).sort(), [DAEMON, APP].sort());

  const rows = await extractGrokBotDir(FIXTURE, { user: "subject" });
  assert.ok(rows.some((r) => r.RecordType === "grokbot_settings"), "daemon settings from nested .grokbot");
  assert.ok(rows.some((r) => r.RecordType === "agent_roster"), "roster from nested app dir");
  assert.equal(rows._grokBotStats.daemonRoot, true);
  assert.equal(rows._grokBotStats.appRoot, true);

  const viaPath = await extractGrokBotPath(FIXTURE, {});
  assert.ok(viaPath.length >= rows.length - 1);
});

test("extracting the daemon folder also pairs the sibling app root (prompts live there)", async () => {
  const fromDaemon = grokBotExtractTargets(DAEMON);
  assert.ok(fromDaemon.includes(DAEMON));
  assert.ok(fromDaemon.includes(APP), "Application Support/Grok Bot is the companion of ~/.grokbot");
  const rows = await extractGrokBotPath(DAEMON, { user: "subject" });
  assert.ok(rows.some((r) => r.RecordType === "grokbot_settings"));
  assert.ok(rows.some((r) => r.RecordType === "user" && r.Role === "user"), "user prompts come from the app replica");
  assert.equal(rows._grokBotStats.daemonRoot, true);
  assert.equal(rows._grokBotStats.appRoot, true);
});

test("a directory with no Grok Bot children is rejected with a pointer at the real roots", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-grokbot-empty-"));
  try {
    await assert.rejects(() => extractGrokBotPath(tmp), /~\/\.grokbot/);
    assert.deepEqual(listGrokBotExtractRoots(tmp), []);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
