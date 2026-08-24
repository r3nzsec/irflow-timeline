const test = require("node:test");
const assert = require("node:assert/strict");

const {
  fillHistogramGaps,
  isUnsetWindowsBucket,
  MAX_FILL_BUCKETS,
} = require("../electron/db/histogram-buckets");

test("isUnsetWindowsBucket flags FILETIME epoch and DateTime.MinValue", () => {
  assert.equal(isUnsetWindowsBucket("1601-01-01"), true);
  assert.equal(isUnsetWindowsBucket("1601-01-01 00:00"), true);
  assert.equal(isUnsetWindowsBucket("1600-12-31"), true);
  assert.equal(isUnsetWindowsBucket("0001-01-01"), true);
  assert.equal(isUnsetWindowsBucket("2025-04-02"), false);
  assert.equal(isUnsetWindowsBucket("1970-01-01"), false);
});

test("fillHistogramGaps drops 1601 sentinel and fills calendar days", () => {
  const filled = fillHistogramGaps([
    { day: "1601-01-01", cnt: 40 },
    { day: "2025-04-02", cnt: 5 },
    { day: "2025-04-05", cnt: 12 },
  ], "day");
  assert.deepEqual(filled.map((b) => b.day), [
    "2025-04-02", "2025-04-03", "2025-04-04", "2025-04-05",
  ]);
  assert.deepEqual(filled.map((b) => b.cnt), [5, 0, 0, 12]);
});

test("fillHistogramGaps fills hourly holes between first and last event", () => {
  const filled = fillHistogramGaps([
    { day: "2025-04-02 10", cnt: 3 },
    { day: "2025-04-02 12", cnt: 8 },
  ], "hour");
  assert.deepEqual(filled.map((b) => b.day), [
    "2025-04-02 10", "2025-04-02 11", "2025-04-02 12",
  ]);
  assert.deepEqual(filled.map((b) => b.cnt), [3, 0, 8]);
});

test("fillHistogramGaps leaves a single real day alone", () => {
  assert.deepEqual(
    fillHistogramGaps([{ day: "1601-01-01", cnt: 1 }, { day: "2025-04-22", cnt: 9 }], "day"),
    [{ day: "2025-04-22", cnt: 9 }],
  );
});

test("fillHistogramGaps does not explode across a multi-decade span", () => {
  const filled = fillHistogramGaps([
    { day: "1990-01-01", cnt: 1 },
    { day: "2025-04-22", cnt: 1 },
  ], "day");
  assert.ok(filled.length < MAX_FILL_BUCKETS);
  assert.equal(filled.length, 2);
});
