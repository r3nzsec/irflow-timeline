"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("fs");
const os = require("os");

const { readTranscriptFile } = require("../electron/parsers/ai-history/cursor");
const { extractCursorDir } = require("../electron/parsers/ai-history/cursor");

test("readTranscriptFile uses embedded createdAt instead of file mtime spread", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-ts-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });

  const transcript = path.join(tmp, "agent-transcripts", "sess-1", "sess-1.jsonl");
  fs.mkdirSync(path.dirname(transcript), { recursive: true });
  const lines = [
    JSON.stringify({
      role: "user",
      createdAt: 1704067200000,
      message: { content: [{ type: "text", text: "Question with timestamp" }] },
    }),
    JSON.stringify({
      role: "assistant",
      createdAt: 1704067260000,
      message: { content: [{ type: "text", text: "Answer with timestamp" }] },
    }),
  ];
  fs.writeFileSync(transcript, `${lines.join("\n")}\n`, "utf8");

  const rows = await readTranscriptFile(transcript, { user: "u" });
  assert.equal(rows.length, 2);
  assert.equal(rows[0].Timestamp, "2024-01-01 00:00:00");
  assert.equal(rows[1].Timestamp, "2024-01-01 00:01:00");
  assert.ok(!rows._cursorSyntheticTimestamps);
  assert.ok(rows.every((row) => row.TimestampBasis === "source event timestamp"));
});

test("Cursor legacy text and null JSON records preserve valid neighbours and provenance", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-formats-"));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const sessionDir = path.join(tmp, ".cursor", "projects", "demo", "agent-transcripts", "session-1");
  fs.mkdirSync(sessionDir, { recursive: true });

  const textPath = path.join(sessionDir, "session-1.txt");
  fs.writeFileSync(textPath, "User: first question\ncontinued context\n\nAssistant: first answer\n");
  const textRows = await readTranscriptFile(textPath);
  assert.equal(textRows.length, 2);
  assert.deepEqual(textRows.map((row) => row.Role), ["user", "assistant"]);
  assert.ok(textRows.every((row) => row.TimestampBasis === "file metadata synthetic spread"));
  assert.equal(textRows[1].LineNumber, "4");
  assert.ok(Number(textRows[1].SourceOffset) > Number(textRows[0].SourceOffset));

  const jsonPath = path.join(sessionDir, "session-1.jsonl");
  fs.writeFileSync(jsonPath, `null\n${JSON.stringify({ role: "user", message: { content: [{ type: "text", text: "valid after null" }] } })}\n`);
  const jsonRows = await readTranscriptFile(jsonPath);
  assert.equal(jsonRows.length, 1);
  assert.equal(jsonRows[0].LineNumber, "2");
  assert.equal(jsonRows[0].SourceOffset, "5");

  const folderRows = await extractCursorDir(path.join(tmp, ".cursor"));
  assert.equal(folderRows._cursorSyntheticTimestamps, true);
  assert.ok(folderRows.every((row) => row.TimestampBasis === "file metadata synthetic spread"));
});
