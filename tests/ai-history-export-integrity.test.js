"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { encodeDelimitedField, writeDelimitedExportToPath } = require("../electron/ipc/export-handlers");
const { scanCSVRecords, parseCSVLine } = require("../electron/parsers/csv");

function parseRecords(content, delimiter) {
  const records = [];
  const tail = scanCSVRecords(content, (record) => records.push(parseCSVLine(record, delimiter)));
  if (tail) records.push(parseCSVLine(tail, delimiter));
  return records;
}

test("delimiter encoder quotes carriage returns and quotes", () => {
  assert.equal(encodeDelimitedField("progress 10%\rprogress 90%", ","), '"progress 10%\rprogress 90%"');
  assert.equal(encodeDelimitedField('a"b', ","), '"a""b"');
});

test("CSV and TSV exports round-trip forensic evidence fields", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-delimited-export-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const values = [
    "progress 10%\rprogress 90%",
    "line one\nline two",
    'a "quoted", value',
    "tab\tvalue",
    "مرحبا 😀",
    "nul\0byte",
    "",
  ];
  for (const [extension, delimiter] of [["csv", ","], ["tsv", "\t"]]) {
    const output = path.join(root, `evidence.${extension}`);
    await writeDelimitedExportToPath({
      headers: values.map((_, index) => `c${index}`),
      iterator: [values],
      safeCols: values.map((_, index) => index),
    }, output);
    const records = parseRecords(fs.readFileSync(output, "utf8"), delimiter);
    assert.equal(records.length, 2);
    assert.deepEqual(records[1], values);
  }
});
