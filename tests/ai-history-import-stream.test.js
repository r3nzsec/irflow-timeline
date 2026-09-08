"use strict";

// parseAiHistoryImport now streams the extractor's output through the shared bounded sink instead
// of materializing the whole corpus. Drive it with a fake db (capturing insertBatchArrays) and a
// real Codex fixture — no better-sqlite3 binding required (no state.sqlite in the fixture).

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { parseAiHistoryImport } = require("../electron/parsers/ai-history-import");
const { AI_HISTORY_COLUMNS } = require("../electron/parsers/ai-history/schema");

function makeFakeDb() {
  const inserted = [];
  let headers = null;
  let created = false;
  return {
    createTab(_tabId, h) { headers = h; created = true; },
    insertBatchArrays(_tabId, arrays) { for (const a of arrays) inserted.push(a); },
    finalizeImport() { return { rowCount: inserted.length, tsColumns: ["Timestamp"], numericColumns: [] }; },
    _inserted: () => inserted,
    _headers: () => headers,
    _created: () => created,
  };
}

function writeCodexFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-import-stream-"));
  const root = path.join(dir, ".codex");
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "history.jsonl"), [
    JSON.stringify({ session_id: "s1", ts: 1700000000, text: "first prompt body" }),
    JSON.stringify({ session_id: "s1", ts: 1700000100, text: "second prompt body" }),
    JSON.stringify({ session_id: "s1", ts: 1700000000, text: "first prompt body" }), // exact dup
  ].join("\n") + "\n");
  return { dir, root };
}

test("parseAiHistoryImport streams every physical source occurrence and keeps FullText", async () => {
  const { dir, root } = writeCodexFixture();
  const db = makeFakeDb();
  try {
    const res = await parseAiHistoryImport(root, "tab-1", db, null, { tool: "codex", target: root });

    assert.equal(db._created(), true, "tab created");
    assert.deepEqual(db._headers(), AI_HISTORY_COLUMNS, "tab created with the unified schema");
    assert.equal(res.sourceFormat, "ai-history-codex");

    const rows = db._inserted();
    assert.equal(rows.length, 3, "repeated text at a different byte offset remains separate evidence");
    assert.equal(res.rowCount, 3);

    const tsIdx = AI_HISTORY_COLUMNS.indexOf("Timestamp");
    const recIdx = AI_HISTORY_COLUMNS.indexOf("RecordId");
    const ftIdx = AI_HISTORY_COLUMNS.indexOf("FullText");
    const offsetIdx = AI_HISTORY_COLUMNS.indexOf("SourceOffset");
    assert.deepEqual(rows.map((r) => r[recIdx]), ["1", "2", "3"], "contiguous RecordId from 1");
    assert.ok(rows.every((row, i) => i === 0 || rows[i - 1][tsIdx] <= row[tsIdx]), "rows sorted chronologically");
    assert.equal(new Set(rows.map((r) => r[offsetIdx])).size, 3, "physical source offsets are unique");
    assert.ok(rows.some((r) => r[ftIdx] && r[ftIdx].includes("prompt body")), "FullText retained for single-tool import");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parseAiHistoryImport streams Grok Build commands and output into the unified schema", async () => {
  const root = path.join(__dirname, "fixtures/ai-history/grok/.grok");
  const db = makeFakeDb();
  const res = await parseAiHistoryImport(root, "tab-grok", db, null, {
    tool: "grok-build",
    target: root,
  });
  assert.equal(res.sourceFormat, "ai-history-grok-build");
  const commandIdx = AI_HISTORY_COLUMNS.indexOf("ToolCommand");
  const invokedIdx = AI_HISTORY_COLUMNS.indexOf("InvokedTool");
  const recordTypeIdx = AI_HISTORY_COLUMNS.indexOf("RecordType");
  const fullTextIdx = AI_HISTORY_COLUMNS.indexOf("FullText");
  const rows = db._inserted();
  assert.ok(rows.some((row) =>
    row[invokedIdx] === "run_terminal_command"
    && row[commandIdx] === "printf '%s\\n' \"quoted value\""));
  assert.ok(rows.some((row) =>
    row[recordTypeIdx] === "tool_result"
    && /Exit code: 0/.test(row[fullTextIdx])));
});

test("parseAiHistoryImport reads copilot session stats from the extractor return, not the prepared rows", async () => {
  // Regression guard: meta.copilot.sessionsScanned/jsonlFiles/kind1Lines come from the _copilotStats
  // sidecar attached to the extractor's RETURN value. Reading them off the re-prepared rows (which
  // carry no sidecar) zeroed them out and suppressed the metadata-only warning.
  const ws = path.join(__dirname, "fixtures/ai-history/copilot/Code/User/workspaceStorage");
  const db = makeFakeDb();
  const res = await parseAiHistoryImport(ws, "tab-cp", db, null, { tool: "copilot", target: ws });
  assert.equal(res.sourceFormat, "ai-history-copilot");
  assert.ok(res.meta.copilot, "copilot stats present");
  assert.equal(res.meta.copilot.sessionsScanned, 2, "session-level stat sourced from the sidecar");
  assert.equal(res.meta.copilot.messageRows, db._inserted().length, "messageRows reflects stored rows");
});

test("parseAiHistoryImport rejects (never silently succeeds) on empty/unparseable input", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-import-empty-"));
  const root = path.join(dir, ".codex");
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "history.jsonl"), "null\n\n");
  const db = makeFakeDb();
  try {
    // Whether the extractor rejects the dir or our own "no messages" guard fires, the import must
    // throw rather than create a 0-row tab and report success.
    await assert.rejects(() => parseAiHistoryImport(root, "tab-2", db, null, { tool: "codex", target: root }));
    assert.equal(db._inserted().length, 0, "no rows written on a failed import");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
