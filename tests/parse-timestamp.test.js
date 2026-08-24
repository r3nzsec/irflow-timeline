// Regression test for parseTimestampMs epoch-string handling (release review L2).
//
// parseTimestampMs treated a value as epoch only when typeof === "number", so a 10/13-digit
// epoch STRING (SQLite TEXT columns are always strings) returned null — diverging from
// forensic-normalize.normalizeTimestamp and the sort_datetime SQL UDF, which both accept
// epoch strings. Analyzers (USN chains, PS4104 time-gap splitting) then silently dropped
// rows from bare-epoch-column datasets. Fix adds an epoch-string branch.

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseTimestampMs } = require("../electron/utils/parse-timestamp");

test("parseTimestampMs parses numeric epoch STRINGS (parity with normalizeTimestamp / sort_datetime)", () => {
  assert.equal(parseTimestampMs("1720000000000"), 1720000000000); // 13-digit ms epoch
  assert.equal(parseTimestampMs("1720000000"), 1720000000000);    // 10-digit seconds epoch
  assert.equal(parseTimestampMs("1720000000.5"), 1720000000500);  // fractional seconds
});

test("parseTimestampMs unchanged for existing inputs", () => {
  assert.equal(parseTimestampMs(1720000000000), 1720000000000);                          // number
  assert.equal(parseTimestampMs("2026-01-17 01:26:27"), Date.UTC(2026, 0, 17, 1, 26, 27)); // naive → UTC
  assert.equal(parseTimestampMs("2026-01-17T01:26:27Z"), Date.UTC(2026, 0, 17, 1, 26, 27)); // explicit Z
  assert.equal(parseTimestampMs("not a date"), null);
  assert.equal(parseTimestampMs(""), null);
  assert.equal(parseTimestampMs(null), null);
  // A 4-digit year alone must NOT be treated as a (too-short) epoch and must stay unparseable.
  assert.equal(parseTimestampMs("2026"), null);
  assert.equal(parseTimestampMs("1601-01-01 00:00:00"), null);
});
