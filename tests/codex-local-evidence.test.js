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
