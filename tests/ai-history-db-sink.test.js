"use strict";

// Unit tests for the shared row→SQLite sink. These cover the dedupe/cap/slim/batch logic that
// both the single-tool import and the merged streamed scan now share, using plain arrays and a
// fake db (no better-sqlite3 binding required).

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  prepareChunkRowsForDb,
  writeAiHistoryRowsToDb,
  filterAlreadySeenStreamedRows,
  makeSourceAccumulator,
} = require("../electron/parsers/ai-history/db-sink");
const { makeRow } = require("../electron/parsers/ai-history/row-utils");
const { AI_HISTORY_COLUMNS } = require("../electron/parsers/ai-history/schema");

const LONG = "fix the authentication bug in the login handler before the release deadline";

function sessionRow() {
  return makeRow({
    role: "user", summary: LONG, sessionId: "s1", messageId: "m1",
    sourceFile: "/x/projects/p/sess.jsonl", timestamp: "2024-01-01 00:00:00",
  }, "Claude Code");
}
function historyRow() {
  return makeRow({
    role: "user", summary: LONG, sessionId: "s1", recordType: "history",
    sourceFile: "/x/.claude/history.jsonl", timestamp: "2024-01-01 00:00:01",
  }, "Claude Code");
}

test("prepareChunkRowsForDb preserves history and session source occurrences", () => {
  const rows = prepareChunkRowsForDb([historyRow(), sessionRow()], 1, 1e6, 0);
  assert.equal(rows.length, 2);
  assert.deepEqual(new Set(rows.map((row) => row.SourceFile)), new Set([
    "/x/.claude/history.jsonl",
    "/x/projects/p/sess.jsonl",
  ]));
});

test("prepareChunkRowsForDb caps to the remaining budget and numbers from recordIdStart", () => {
  const many = Array.from({ length: 10 }, (_, i) =>
    makeRow({ role: "user", summary: `distinct prompt number ${i} with enough text`, sessionId: `s${i}` }, "Claude Code"));
  const rows = prepareChunkRowsForDb(many, 100, 4, 0); // maxRows 4, nothing written yet
  assert.equal(rows.length, 4, "sliced to the remaining budget");
  assert.deepEqual(rows.map((r) => r.RecordId), ["100", "101", "102", "103"]);
});

test("prepareChunkRowsForDb slims FullText by default but keeps it when asked", () => {
  const build = () => [makeRow({ role: "user", summary: "short", fullText: "the complete body" }, "Claude Code")];
  const slim = prepareChunkRowsForDb(build(), 1, 10, 0);
  assert.equal(slim[0].FullText, "", "merged streamed path blanks FullText for DB leanness");
  const kept = prepareChunkRowsForDb(build(), 1, 10, 0, { keepFullText: true });
  assert.equal(kept[0].FullText, "the complete body", "single-import path keeps FullText");
  const capped = prepareChunkRowsForDb(
    [makeRow({ role: "user", summary: "short", fullText: "x".repeat(100) }, "Claude Code")],
    1, 10, 0, { keepFullText: true, maxFullTextChars: 20 },
  );
  assert.equal(capped[0].FullText.startsWith("x".repeat(20)), true);
  assert.match(capped[0].FullText, /truncated 80 chars for merged import/);
});

test("prepareChunkRowsForDb retains exact tool evidence on streamed and single imports", () => {
  const build = () => [makeRow({
    role: "assistant",
    summary: "[Tool: Shell]",
    toolName: "Shell",
    toolCommand: "ls -la \"/tmp/evidence folder\"",
    toolInput: "{\"command\":\"ls -la \\\"/tmp/evidence folder\\\"\",\"description\":\"List evidence\"}",
    toolDescription: "List evidence",
  }, "Cursor")];
  const streamed = prepareChunkRowsForDb(build(), 1, 10, 0);
  const single = prepareChunkRowsForDb(build(), 1, 10, 0, { keepFullText: true });
  for (const row of [streamed[0], single[0]]) {
    assert.equal(row.ToolCommand, "ls -la \"/tmp/evidence folder\"");
    assert.equal(row.ToolDescription, "List evidence");
    assert.match(row.ToolInput, /evidence folder/);
  }
});

test("makeSourceAccumulator bounds a source to the remaining row budget", () => {
  const acc = makeSourceAccumulator(5);
  acc.add([1, 2, 3], 0);
  assert.equal(acc.rows.length, 3);
  assert.equal(acc.truncated, false);
  acc.add([4, 5, 6, 7], 0); // only 2 slots left (5 - 0 - 3)
  assert.equal(acc.rows.length, 5);
  assert.equal(acc.truncated, true);
});

test("writeAiHistoryRowsToDb maps rows to header arrays and batches inserts", () => {
  const calls = [];
  const fakeDb = { insertBatchArrays: (tabId, arrays) => calls.push({ tabId, count: arrays.length, first: arrays[0] }) };
  const rows = Array.from({ length: 12000 }, (_, i) =>
    makeRow({ role: "user", summary: `row ${i}`, sessionId: "s" }, "Claude Code"));
  writeAiHistoryRowsToDb(fakeDb, "tab-1", AI_HISTORY_COLUMNS, rows);
  assert.deepEqual(calls.map((c) => c.count), [5000, 5000, 2000], "batched at AI_HISTORY_DB_BATCH");
  assert.equal(calls[0].first.length, AI_HISTORY_COLUMNS.length, "each row mapped to a full header-ordered array");
});

test("filterAlreadySeenStreamedRows drops only the same physical occurrence", () => {
  const seen = new Set();
  const first = makeRow({
    role: "assistant",
    summary: "same Claude response body with enough text to be useful",
    sessionId: "sess-1",
    timestamp: "2026-06-01 10:00:00",
    sourceFile: "/evidence/source.jsonl",
  }, "Claude Code");
  const duplicate = { ...first };
  const otherSource = { ...first, SourceFile: "/other/source.jsonl" };
  const differentTool = { ...first, Tool: "Cursor" };

  let result = filterAlreadySeenStreamedRows([first], seen);
  assert.equal(result.rows.length, 1);
  assert.equal(result.dropped, 0);

  result = filterAlreadySeenStreamedRows([duplicate, otherSource, differentTool], seen);
  assert.equal(result.rows.length, 2);
  assert.ok(result.rows.includes(otherSource));
  assert.ok(result.rows.includes(differentTool));
  assert.equal(result.dropped, 1);
});
