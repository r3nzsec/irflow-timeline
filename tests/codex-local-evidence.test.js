"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  timestampFromSummaryName,
  parseRolloutSummary,
  listRolloutSummaryFiles,
  extractHookRows,
  supplementCodexFromLocalEvidence,
  buildCodexLocalEvidenceNotice,
} = require("../electron/parsers/ai-history/codex-local-evidence");

const SUMMARY_NAME = "2026-05-27T18-30-10-WBmr-agentic_ir_backend_hardening.md";

function makeCodexRoot() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-local-"));
  const root = path.join(tmp, ".codex");
  fs.mkdirSync(path.join(root, "memories", "rollout_summaries"), { recursive: true });
  return { tmp, root };
}

test("timestampFromSummaryName decodes the dash-separated time component", () => {
  const ms = timestampFromSummaryName(SUMMARY_NAME);
  assert.equal(new Date(ms).toISOString(), "2026-05-27T18:30:10.000Z");
  assert.equal(timestampFromSummaryName("not-a-summary.md"), null);
});

test("parseRolloutSummary splits the bare header block from the body", () => {
  const content = [
    "thread_id: 019e6ab3-84ee-79b3-a3b6-7482832e8673",
    "updated_at: 2026-05-28T08:04:27+00:00",
    "rollout_path: /home/u/.codex/sessions/2026/05/27/rollout-x.jsonl",
    "cwd: /case/alpha",
    "",
    "# Continued backend hardening",
    "",
    "Rollout context: the agent used live file timestamps.",
  ].join("\n");

  const { headers, title, body } = parseRolloutSummary(content);
  assert.equal(headers.thread_id, "019e6ab3-84ee-79b3-a3b6-7482832e8673");
  assert.equal(headers.cwd, "/case/alpha");
  assert.equal(headers.rollout_path, "/home/u/.codex/sessions/2026/05/27/rollout-x.jsonl");
  assert.equal(title, "Continued backend hardening");
  assert.match(body, /^# Continued backend hardening/);
  assert.match(body, /live file timestamps/);
  // The header block must not leak into the evidence body.
  assert.doesNotMatch(body, /thread_id:/);
});

test("parseRolloutSummary tolerates a file with no header block", () => {
  const { headers, title, body } = parseRolloutSummary("# Just a title\n\nbody text");
  assert.deepEqual(headers, {});
  assert.equal(title, "Just a title");
  assert.match(body, /body text/);
});

test("listRolloutSummaryFiles returns only markdown files", () => {
  const { tmp, root } = makeCodexRoot();
  try {
    const dir = path.join(root, "memories", "rollout_summaries");
    fs.writeFileSync(path.join(dir, SUMMARY_NAME), "x");
    fs.writeFileSync(path.join(dir, "notes.txt"), "x");
    const files = listRolloutSummaryFiles(dir);
    assert.equal(files.length, 1);
    assert.equal(path.basename(files[0]), SUMMARY_NAME);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("a summary whose rollout_path is gone is flagged as an orphan", () => {
  const { tmp, root } = makeCodexRoot();
  try {
    const dir = path.join(root, "memories", "rollout_summaries");
    const presentRollout = path.join(root, "sessions", "rollout-present.jsonl");
    fs.mkdirSync(path.dirname(presentRollout), { recursive: true });
    fs.writeFileSync(presentRollout, "{}\n");

    fs.writeFileSync(path.join(dir, SUMMARY_NAME), [
      "thread_id: t-present",
      "updated_at: 2026-05-28T08:04:27+00:00",
      `rollout_path: ${presentRollout}`,
      "cwd: /case/alpha",
      "",
      "# Thread that still has its transcript",
      "",
      "body",
    ].join("\n"));

    fs.writeFileSync(path.join(dir, "2026-05-29T09-00-00-ZZZZ-deleted_thread.md"), [
      "thread_id: t-gone",
      "updated_at: 2026-05-29T09:05:00+00:00",
      `rollout_path: ${path.join(root, "sessions", "rollout-deleted.jsonl")}`,
      "cwd: /case/beta",
      "",
      "# Thread whose transcript was deleted",
      "",
      "body",
    ].join("\n"));

    const { rows, stats } = supplementCodexFromLocalEvidence(root, { user: "alice", host: "HOST" });
    assert.equal(stats.summaryFiles, 2);
    assert.equal(stats.orphanedSummaries, 1);

    const present = rows.find((r) => r.SessionId === "t-present");
    assert.equal(present.RecordType, "thread_summary");
    assert.equal(present.Timestamp, "2026-05-28 08:04:27");
    assert.equal(present.Workspace, "/case/alpha");
    assert.doesNotMatch(present.Summary, /deleted/);

    const gone = rows.find((r) => r.SessionId === "t-gone");
    assert.equal(gone.RecordType, "thread_summary_orphaned");
    assert.match(gone.Summary, /rollout deleted/);
    assert.equal(gone.ToolDescription, path.join(root, "sessions", "rollout-deleted.jsonl"));

    assert.match(buildCodexLocalEvidenceNotice(stats), /1 whose rollout is deleted/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("a summary with no rollout_path header is not claimed as an orphan", () => {
  const { tmp, root } = makeCodexRoot();
  try {
    fs.writeFileSync(path.join(root, "memories", "rollout_summaries", SUMMARY_NAME), [
      "thread_id: t-1",
      "updated_at: 2026-05-28T08:04:27+00:00",
      "",
      "# No rollout path recorded",
    ].join("\n"));
    const { rows, stats } = supplementCodexFromLocalEvidence(root, {});
    assert.equal(stats.orphanedSummaries, 0);
    assert.equal(rows[0].RecordType, "thread_summary");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("extractHookRows emits one row per configured command", () => {
  const { tmp, root } = makeCodexRoot();
  try {
    fs.writeFileSync(path.join(root, "hooks.json"), JSON.stringify({
      hooks: {
        PreToolUse: [{ matcher: ".*", hooks: [{ type: "command", command: "/opt/watch.cjs" }] }],
        SessionStart: [{
          matcher: "shell",
          hooks: [
            { type: "command", command: "/opt/start.cjs" },
            { type: "command", command: "" },
          ],
        }],
      },
    }));

    const { rows, hooks } = extractHookRows(root, { user: "alice" });
    assert.equal(hooks, 2, "empty commands are skipped");

    const pre = rows.find((r) => r.InvokedTool === "PreToolUse");
    assert.equal(pre.RecordType, "hook_config");
    assert.equal(pre.ToolCommand, "/opt/watch.cjs");
    // A catch-all matcher is noise in the summary; a specific one is evidence.
    assert.doesNotMatch(pre.Summary, /\[\.\*\]/);

    const start = rows.find((r) => r.InvokedTool === "SessionStart");
    assert.equal(start.ToolInput, "shell");
    assert.match(start.Summary, /\[shell\]/);
    assert.ok(start.Timestamp, "hook rows are timestamped from the file mtime");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("extractHookRows survives malformed hooks.json", () => {
  const { tmp, root } = makeCodexRoot();
  try {
    fs.writeFileSync(path.join(root, "hooks.json"), "{ not json");
    assert.deepEqual(extractHookRows(root, {}), { rows: [], hooks: 0 });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("supplementCodexFromLocalEvidence is silent on a root with neither artifact", () => {
  const { tmp, root } = makeCodexRoot();
  try {
    const { rows, stats } = supplementCodexFromLocalEvidence(root, {});
    assert.deepEqual(rows, []);
    assert.equal(stats, null);
    assert.equal(buildCodexLocalEvidenceNotice(stats), "");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

/* ------------------------------------------------------------------ *
 * rules, shell snapshots, memory, ambient suggestions, global state, voice
 * ------------------------------------------------------------------ */

const {
  parseExecPolicyRules,
  extractExecPolicyRows,
  summarizeShellSnapshot,
  extractShellSnapshotRows,
  splitMarkdownSections,
  extractMemoryRows,
  extractAmbientSuggestionRows,
  extractGlobalStateRows,
  extractVoiceInputRows,
} = require("../electron/parsers/ai-history/codex-local-evidence");

const THREAD = "01a06dbe-0131-75d3-8a28-d5f654e32dc0";

function makeRichCodexRoot() {
  const { tmp, root } = makeCodexRoot();
  fs.mkdirSync(path.join(root, "rules"), { recursive: true });
  fs.writeFileSync(path.join(root, "rules", "default.rules"), [
    "# execpolicy",
    'prefix_rule(pattern=["docker", "run"], decision="allow")',
    'prefix_rule(pattern=["node", "-e", "const a = [1, 2]; console.log(a[0])"], decision="allow")',
    'prefix_rule(pattern=["rm", "-rf", "/"], decision="forbidden")',
    "",
  ].join("\n"));
  fs.mkdirSync(path.join(root, "shell_snapshots"), { recursive: true });
  fs.writeFileSync(path.join(root, "shell_snapshots", `${THREAD}.1788547563840492000.sh`), [
    "export HOME=/Users/subject",
    "export PATH=/usr/bin:/bin",
    "export MY_API_KEY='sk-SHOULD-NEVER-APPEAR'",
    'export APPLE_APP_SPECIFIC_PASSWORD="abcd-efgh-SHOULD-NEVER-APPEAR"',
    "export SSH_AUTH_SOCK=/tmp/agent.sock",
    "export EMPTY_TOKEN=",
    "alias ll='ls -la'",
    "deploy() {",
    "  echo deploy",
    "}",
    "",
  ].join("\n"));
  fs.mkdirSync(path.join(root, "memories", "extensions", "ad_hoc"), { recursive: true });
  fs.writeFileSync(path.join(root, "memories", "MEMORY.md"), "# User profile\n\nWorks on DFIR tooling.\n\n## Projects\n\n- irflow-timeline\n");
  fs.writeFileSync(path.join(root, "memories", "extensions", "ad_hoc", "notes"), "# Task Group: audit\n\nscope: coordination\n");
  fs.mkdirSync(path.join(root, "ambient-suggestions", "abc123"), { recursive: true });
  fs.writeFileSync(path.join(root, "ambient-suggestions", "abc123", "ambient-suggestions.json"), JSON.stringify({
    projectRoot: "/Users/subject/Downloads/31.57.201.201_80",
    generatedAtMs: 1783715423734,
    suggestions: [{ id: "s1", title: "Continue the report", description: "d", prompt: "Tighten findings", status: "pending", createdAtMs: 1776862153337 }],
  }));
  fs.writeFileSync(path.join(root, ".codex-global-state.json"), JSON.stringify({
    "electron-local-remote-control-installation-id": "inst-1",
    "electron-local-remote-control-environment-id": "env-1",
    "electron-mac-push-deregistration-token": "SHOULD-NEVER-APPEAR",
    "codex-mobile-has-connected-device": true,
    "host-id-remote-control-allowed": ["remote-ssh-codex-managed:924b"],
    "selected-remote-host-id": "remote-ssh-codex-managed:924b",
    "codex-managed-remote-connections": [{ hostId: "remote-ssh-codex-managed:924b", displayName: "Agentic-IR", hostname: "root@203.0.113.9", sshPort: 22, identity: "/Users/subject/.ssh/id_ed25519", source: "codex-managed" }],
    "remote-projects": [{ id: "rp1", hostId: "remote-ssh-codex-managed:924b", remotePath: "/opt/agentic-ir", label: "agentic-ir" }],
    "local-projects": { "local-1": { id: "local-1", name: "AD_Audit", rootPaths: ["/Users/subject/Downloads/AD_Audit"], createdAt: 1784910029457, updatedAt: 1784910029457 } },
  }));
  fs.writeFileSync(path.join(root, "transcription-history.jsonl"), JSON.stringify({ text: "open the case folder", ts: "2026-09-01T10:00:00Z", thread_id: THREAD }) + "\n{ bad json\n");
  return { tmp, root };
}

test("execpolicy rules become one allow/forbid row each, with the greedy pattern parse surviving ] inside a string", () => {
  const rules = parseExecPolicyRules('prefix_rule(pattern=["node", "-e", "a[0]"], decision="allow")\nother_rule(x=1, decision="prompt")');
  assert.equal(rules.length, 2);
  assert.deepEqual(rules[0].pattern, ["node", "-e", "a[0]"]);
  assert.equal(rules[0].decision, "allow");
  assert.equal(rules[1].kind, "other_rule");
  assert.equal(rules[1].decision, "prompt");

  const { tmp, root } = makeRichCodexRoot();
  try {
    const { rows } = extractExecPolicyRows(root, { user: "subject" });
    assert.equal(rows.length, 3);
    assert.equal(rows[0].RecordType, "exec_policy_rule");
    assert.equal(rows[0].Summary, "Exec policy allow: docker run");
    assert.equal(rows[0].ToolCommand, "docker run");
    assert.equal(rows[0].InvokedTool, "allow");
    assert.match(rows[0].ToolDescription, /WITHOUT an approval prompt/);
    assert.equal(rows[1].ToolCommand, "node -e const a = [1, 2]; console.log(a[0])");
    assert.equal(rows[2].InvokedTool, "forbidden");
    assert.equal(rows[2].LineNumber, "4");
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("shell snapshots report credential-like variable NAMES and never the values", () => {
  const info = summarizeShellSnapshot("export A=1\nexport MY_TOKEN=abc\nexport SSH_AUTH_SOCK=/x\nexport EMPTY_KEY=\nalias a=b\nf() {\n");
  assert.deepEqual(info.exported, ["A", "MY_TOKEN", "SSH_AUTH_SOCK", "EMPTY_KEY"]);
  assert.deepEqual(info.credentialLike, [{ name: "MY_TOKEN", valueLength: 3 }]);
  assert.equal(info.aliases, 1);
  assert.equal(info.functions, 1);

  const { tmp, root } = makeRichCodexRoot();
  try {
    const { rows, exposures } = extractShellSnapshotRows(root, { user: "subject" });
    assert.equal(rows.length, 1);
    assert.equal(exposures, 1);
    const row = rows[0];
    assert.equal(row.RecordType, "shell_snapshot");
    assert.equal(row.Timestamp, "2026-09-04 18:46:03", "nanosecond epoch in the file name");
    assert.equal(row.SessionId, THREAD);
    assert.match(row.Summary, /6 exported variable\(s\), 2 credential-like value\(s\) present in cleartext \(MY_API_KEY, APPLE_APP_SPECIFIC_PASSWORD\)/);
    assert.equal(row.ToolInput, "MY_API_KEY\nAPPLE_APP_SPECIFIC_PASSWORD");
    assert.match(row.FullText, /"valuesRedacted":true/);
    assert.ok(!/SHOULD-NEVER-APPEAR|sk-/.test(JSON.stringify(row)), "values are never copied");
    assert.ok(!/SSH_AUTH_SOCK/.test(row.ToolInput), "allow-listed names are not flagged");
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("memory files are emitted per section and tagged as model-written", () => {
  assert.deepEqual(splitMarkdownSections("intro\n# A\nbody a\n## B\nbody b").map((s) => s.heading), ["", "A", "B"]);
  const { tmp, root } = makeRichCodexRoot();
  try {
    const { rows, files } = extractMemoryRows(root, { user: "subject" });
    assert.equal(files, 2);
    const headings = rows.map((r) => r.Summary);
    assert.deepEqual(headings, [
      "[Codex memory: MEMORY.md] User profile",
      "[Codex memory: MEMORY.md] Projects",
      "[Codex memory: extensions/ad_hoc/notes] Task Group: audit",
    ]);
    assert.ok(rows.every((r) => r.RecordType === "agent_memory"));
    assert.match(rows[0].ToolDescription, /interpretation, not a verbatim record/);
    assert.match(rows[1].FullText, /irflow-timeline/);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("ambient suggestions, global state and voice input become rows; the push token is never read", () => {
  const { tmp, root } = makeRichCodexRoot();
  try {
    const ambient = extractAmbientSuggestionRows(root, {});
    assert.equal(ambient.rows.length, 1);
    assert.equal(ambient.rows[0].Timestamp, "2026-07-10 20:30:23");
    assert.equal(ambient.rows[0].Workspace, "/Users/subject/Downloads/31.57.201.201_80");
    assert.match(ambient.rows[0].Summary, /1 ambient suggestion\(s\): Continue the report/);

    const gs = extractGlobalStateRows(root, {});
    assert.equal(gs.remoteHosts, 1);
    const state = gs.rows.find((r) => r.RecordType === "remote_control_state");
    assert.match(state.Summary, /1 managed SSH host\(s\) \(root@203\.0\.113\.9\), Remote Control allowed for 1 host\(s\), mobile device paired: yes, 1 local project\(s\)/);
    assert.match(state.FullText, /"remoteControlEnvironmentId":"env-1"/);
    assert.match(state.FullText, /"AD_Audit"/);
    const host = gs.rows.find((r) => r.RecordType === "remote_ssh_host");
    assert.equal(host.Summary, 'Codex-managed SSH host "Agentic-IR" — root@203.0.113.9:22 (key /Users/subject/.ssh/id_ed25519); Remote Control allowed');
    assert.equal(host.Workspace, "root@203.0.113.9");
    assert.match(host.FullText, /"remotePath":"\/opt\/agentic-ir"/);
    assert.ok(!/SHOULD-NEVER-APPEAR/.test(JSON.stringify(gs.rows)), "push deregistration token never reaches a row");

    const voice = extractVoiceInputRows(root, {});
    assert.equal(voice.rows.length, 1, "malformed line is skipped");
    assert.equal(voice.rows[0].RecordType, "voice_transcription");
    assert.equal(voice.rows[0].Role, "user");
    assert.equal(voice.rows[0].Timestamp, "2026-09-01 10:00:00");
    assert.equal(voice.rows[0].SessionId, THREAD);

    const { rows, stats } = supplementCodexFromLocalEvidence(root, { user: "subject" });
    assert.equal(stats.execPolicyRules, 3);
    assert.equal(stats.shellSnapshots, 1);
    assert.equal(stats.shellSnapshotsWithCredentials, 1);
    assert.equal(stats.memoryRows, 3);
    assert.equal(stats.ambientSuggestionFiles, 1);
    assert.equal(stats.remoteSshHosts, 1);
    assert.equal(stats.voiceRows, 1);
    assert.ok(rows.every((r) => r.Tool === "OpenAI Codex" && r.User === "subject"));
    const notice = buildCodexLocalEvidenceNotice(stats);
    assert.match(notice, /3 exec-policy allow rule\(s\); 1 shell environment snapshot\(s\), 1 exposing credential-like variables in cleartext; 3 agent-memory section\(s\) from 2 file\(s\); 1 watched project root\(s\); 1 Codex-managed SSH host\(s\); 1 voice transcription\(s\)/);
    assert.ok(!/SHOULD-NEVER-APPEAR/.test(JSON.stringify(rows)));
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
