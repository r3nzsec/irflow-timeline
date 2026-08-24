// extract_date / extract_datetime_minute must:
//   - treat naive timestamps as UTC wall clock
//   - convert explicit offsets to UTC (same instant the grid shows)
//   - drop Windows FILETIME-epoch sentinels (1601-01-01)
//
// Needs a live SQLite binding; skipped under a Node runtime without the native module.

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

function query(sql, value) {
  const db = new Database(":memory:");
  registerRuntimeFunctions(db);
  const row = db.prepare(sql).get(value);
  db.close();
  return row;
}

test("extract_date returns the UTC date of a naive ISO timestamp", { skip }, () => {
  assert.equal(query("SELECT extract_date(?) AS d", "2025-04-22 21:41:50.0000000").d, "2025-04-22");
});

test("extract_date converts an explicit offset to the UTC date", { skip }, () => {
  // +02:00 on 2025-04-23 01:00 is 2025-04-22 23:00 UTC
  assert.equal(query("SELECT extract_date(?) AS d", "2025-04-23T01:00:00+02:00").d, "2025-04-22");
  assert.equal(query("SELECT extract_date(?) AS d", "2026-04-01 00:34:08 +05:00").d, "2026-03-31");
});

test("extract_date drops Windows FILETIME epoch sentinels", { skip }, () => {
  assert.equal(query("SELECT extract_date(?) AS d", "1601-01-01 00:00:00.0000000").d, null);
  assert.equal(query("SELECT extract_date(?) AS d", "1601-01-01T00:00:00.0000000Z").d, null);
  assert.equal(query("SELECT extract_date(?) AS d", "0001-01-01 00:00:00").d, null);
});

test("extract_datetime_minute converts offset times to UTC and drops 1601", { skip }, () => {
  assert.equal(
    query("SELECT extract_datetime_minute(?) AS d", "2026-04-01 00:34:08 +05:00").d,
    "2026-03-31 19:34",
  );
  assert.equal(query("SELECT extract_datetime_minute(?) AS d", "1601-01-01 00:00:00").d, null);
});
