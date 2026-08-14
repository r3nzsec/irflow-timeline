"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const {
  AiSecretResultWriter,
  AiSecretResultReader,
  removeStore,
} = require("../electron/analyzers/ai-history/result-store");

test("AI Secret result store pages redacted findings and enforces its retention cap", (t) => {
  const jobId = `result-store-test-${process.pid}-${Date.now()}`;
  const writer = new AiSecretResultWriter(jobId, { maxStoredFindings: 3 });
  const sentinel = "ghp_Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2";
  for (let i = 0; i < 7; i++) {
    writer.add({
      severity: i % 2 ? "high" : "critical",
      timestamp: `2026-01-01 00:00:0${i}`,
      fingerprint: `fingerprint-${i}`,
      rowId: String(i + 1),
      redacted: "ghp_••••••••••••J3I2 (44 chars)",
      snippet: "redacted evidence",
      match: sentinel,
    });
  }
  const stored = writer.finish();
  t.after(() => removeStore(stored.resultStorePath));

  assert.equal(stored.totalFindings, 7);
  assert.equal(stored.storedFindings, 3);
  assert.equal(stored.resultsTruncated, true);
  assert.equal(stored.uniqueSecrets, 7);
  assert.equal(stored.flaggedRows, 7);

  const reader = new AiSecretResultReader(stored.resultStorePath);
  const first = reader.page(0, 2);
  const second = reader.page(2, 2);
  assert.equal(first.findings.length, 2);
  assert.equal(first.hasMore, true);
  assert.equal(second.findings.length, 1);
  assert.equal(second.hasMore, false);
  assert.equal(first.findings.every((f) => !Object.prototype.hasOwnProperty.call(f, "match")), true);
  assert.equal(fs.readFileSync(stored.resultStorePath).includes(Buffer.from(sentinel)), false);
});

