// Regression tests for the sort_datetime() SQL UDF (electron/db/runtime-functions.js).
//
// Locks in the timezone-consistency fix: sort_datetime must order timestamps on the same
// true-instant basis the grid display uses (naive = UTC; explicit Z / ±HH:MM offsets are
// honored and converted to UTC). The previous version returned the raw wall-clock string for
// any ISO-ish value, so a Forensic Timeliner export mixing naive EvtxECmd timestamps with
// offset-bearing Hayabusa timestamps sorted by raw local wall clock while the grid rendered
// the converted instant — making the timeline appear mis-sorted.
//
// Needs a live SQLite binding; skipped under a Node runtime without the native module built
// (CI rebuilds it). Run after `npm rebuild better-sqlite3`.

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { Database = require("better-sqlite3"); } catch { /* native module not built */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();
const skip = HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime";

const { registerRuntimeFunctions } = require("../electron/db/runtime-functions");

function sortKey(value) {
  const db = new Database(":memory:");
  registerRuntimeFunctions(db);
  const row = db.prepare("SELECT sort_datetime(?) AS k").get(value);
  db.close();
  return row.k;
}

// Order a list of raw timestamp strings the way the grid would (ORDER BY sort_datetime).
function orderBy(values) {
  const db = new Database(":memory:");
  registerRuntimeFunctions(db);
  db.exec("CREATE TABLE data (raw TEXT)");
  const ins = db.prepare("INSERT INTO data VALUES (?)");
  const tx = db.transaction((vs) => { for (const v of vs) ins.run(v); });
  tx(values);
  const rows = db.prepare("SELECT raw FROM data ORDER BY sort_datetime(raw) ASC").all();
  db.close();
  return rows.map((r) => r.raw);
}

test("sort_datetime keeps a naive timestamp as its wall clock (treated as UTC), full precision", { skip }, () => {
  assert.equal(sortKey("2026-04-01T01:54:17.8227428"), "2026-04-01 01:54:17.8227428");
  assert.equal(sortKey("2026-04-01 00:34:08"), "2026-04-01 00:34:08");
});

test("sort_datetime converts an explicit-offset timestamp to canonical UTC", { skip }, () => {
  // +05:00 local => 5 hours earlier in UTC
  assert.equal(sortKey("2026-04-01 00:34:08 +05:00"), "2026-03-31 19:34:08.000");
  assert.equal(sortKey("2026-04-01T00:34:08+05:00"), "2026-03-31 19:34:08.000");
  assert.equal(sortKey("2026-04-01T00:34:08-04:00"), "2026-04-01 04:34:08.000");
});

test("sort_datetime converts an explicit Z timestamp to canonical UTC", { skip }, () => {
  assert.equal(sortKey("2026-04-01T00:34:08Z"), "2026-04-01 00:34:08.000");
});

test("sort_datetime orders mixed naive + offset rows by true instant (Forensic Timeliner case)", { skip }, () => {
  // Hayabusa rows carry a +05:00 offset; EvtxECmd rows are naive UTC. By true instant the
  // offset rows (which map to the previous-day evening in UTC) must sort BEFORE the naive
  // 00:3x UTC rows — matching how the grid displays them once converted to one timezone.
  const ordered = orderBy([
    "2026-04-01T01:54:17.8227428",   // naive UTC  -> 01:54:17 UTC
    "2026-04-01 00:34:08 +05:00",    // offset     -> 2026-03-31 19:34:08 UTC
    "2026-04-01 00:42:22 +05:00",    // offset     -> 2026-03-31 19:42:22 UTC
    "2026-04-01T00:30:00",           // naive UTC  -> 00:30:00 UTC
  ]);
  assert.deepEqual(ordered, [
    "2026-04-01 00:34:08 +05:00",
    "2026-04-01 00:42:22 +05:00",
    "2026-04-01T00:30:00",
    "2026-04-01T01:54:17.8227428",
  ]);
});

test("sort_datetime treats FILETIME epoch as null (not a real event time)", { skip }, () => {
  assert.equal(sortKey("1601-01-01 00:00:00"), null);
  assert.equal(sortKey("1601-01-01T00:00:00.0000000Z"), null);
});

test("sort_datetime is monotonic between naive and equal-instant zoned rows", { skip }, () => {
  // A naive UTC time and the same instant expressed with Z must order adjacently/correctly.
  const ordered = orderBy([
    "2026-04-01T00:00:05",           // naive UTC 00:00:05
    "2026-04-01T00:00:00Z",          // UTC 00:00:00
    "2026-04-01T00:00:10Z",          // UTC 00:00:10
  ]);
  assert.deepEqual(ordered, [
    "2026-04-01T00:00:00Z",
    "2026-04-01T00:00:05",
    "2026-04-01T00:00:10Z",
  ]);
});
