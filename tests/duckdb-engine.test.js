// The DuckDB layer under the timeline engine
// (electron/db/duckdb/ and electron/db/sql-match.js).
//
// The SQL rewrites and native fast paths must give exactly what the SQLite engine gave: the
// date helpers' SQL branch must equal the JavaScript functions, the fuzzy condition must equal
// fuzzy_match(), and the better-sqlite3-shaped API must behave like better-sqlite3 where the
// app relies on it.

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { Database = require("../electron/db/duckdb"); } catch { /* binding not installed */ }
const HAVE_DB = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();
const skip = HAVE_DB ? false : "DuckDB binding not available for this runtime";

const { translateSql } = require("../electron/db/duckdb/sql");
const { registerRuntimeFunctions } = require("../electron/db/runtime-functions");
const { regexCondition, fuzzyCondition } = require("../electron/db/sql-match");

function jsFunctions() {
  const fns = {};
  registerRuntimeFunctions({ function(name, _opts, fn) { fns[name] = fn; } });
  return fns;
}

test("SQLite idioms are rewritten for DuckDB outside literals and comments", () => {
  assert.equal(
    translateSql("SELECT * FROM data WHERE c1 LIKE ? AND c2 NOT LIKE 'LIKE' -- LIKE"),
    "SELECT * FROM data WHERE c1 ILIKE ? AND c2 NOT ILIKE 'LIKE' -- LIKE",
  );
  assert.equal(translateSql("SELECT CAST(x AS INTEGER), CAST(y AS REAL) FROM t"), "SELECT TRY_CAST(x AS BIGINT), TRY_CAST(y AS DOUBLE) FROM t");
  assert.equal(translateSql("SELECT c1 AS [Parent Image] FROM data"), 'SELECT c1 AS "Parent Image" FROM data');
  assert.equal(translateSql("BEGIN IMMEDIATE"), "BEGIN TRANSACTION");
  assert.match(translateSql("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT) WITHOUT ROWID"), /^CREATE TABLE t \(id BIGINT PRIMARY KEY\s*\)\s*$/);
  // a parameter argument is left to the JavaScript function
  assert.equal(translateSql("SELECT sort_datetime(?)"), "SELECT sort_datetime(?)");
});

const TIMESTAMPS = [
  null, "", "  ", "2024-01-02 03:04:05", "2024-01-02T03:04:05.1234567", "2024-01-02 03:04",
  "2024-01-02T03:04:05Z", "2024-01-02 03:04:05.123 +09:00", "2024-01-02T03:04:05-04:00",
  "2024-01-02", "1/2/2024 3:04:05 PM", "12/31/2023 11:59 AM", "Jul 3 2024 10:00", "3-Jul-2024",
  "1704164645", "1704164645123", "45000.5", "1601-01-01 00:00:00", "1600-12-31 23:00:00.000",
  "0001-01-01T00:00:00", "2024-01-02 03:04:05,123", " 2024-01-02 03:04:05", "2024-01-02 03:04:05\t",
  "2024-01-02T03:04:05.5+0530", "not a date", "2024-13-45 99:99:99", "2024/07/03 10:00:00",
];

test("the SQL branch of the date helpers equals the JavaScript functions", { skip }, () => {
  const fns = jsFunctions();
  const db = new Database(":memory:");
  try {
    db.exec("CREATE TABLE t (i BIGINT, v VARCHAR)");
    db.appendRows("t", TIMESTAMPS.map((v, i) => [i, v]));
    const rows = db.prepare(
      "SELECT i, sort_datetime(v) AS s, extract_date(v) AS d, extract_datetime_minute(v) AS m FROM t ORDER BY i",
    ).all();
    for (const r of rows) {
      const v = TIMESTAMPS[r.i];
      assert.equal(r.s, fns.sort_datetime(v), `sort_datetime(${JSON.stringify(v)})`);
      assert.equal(r.d, fns.extract_date(v), `extract_date(${JSON.stringify(v)})`);
      assert.equal(r.m, fns.extract_datetime_minute(v), `extract_datetime_minute(${JSON.stringify(v)})`);
    }
  } finally {
    db.close();
  }
});

test("the fuzzy condition equals fuzzy_match()", { skip }, () => {
  const fns = jsFunctions();
  const texts = [null, "", "powershell.exe -enc AAAA", "PowerShel", "C:\\Windows\\System32\\svchost.exe", "mimikatz", "mimi katz", "Local Settings", "abc"];
  const terms = ["", "p", "pw", "pwsh", "powershell", "svchost", "mimikatz", "mimkatz", "settngs", "xyz", "ab"];
  const db = new Database(":memory:");
  try {
    db.exec("CREATE TABLE t (i BIGINT, v VARCHAR)");
    db.appendRows("t", texts.map((v, i) => [i, v]));
    for (const term of terms) {
      const c = fuzzyCondition("v", term);
      const got = db.prepare(`SELECT i FROM t WHERE ${c.sql} ORDER BY i`).all(...c.params).map((r) => r.i);
      const want = texts.map((v, i) => [v, i]).filter(([v]) => fns.fuzzy_match(v, term) === 1).map(([, i]) => i);
      assert.deepEqual(got, want, `fuzzy ${JSON.stringify(term)}`);
    }
  } finally {
    db.close();
  }
});

test("regex conditions run natively and fall back to JavaScript for lookarounds", { skip }, () => {
  const db = new Database(":memory:");
  try {
    db.exec("CREATE TABLE t (i BIGINT, v VARCHAR)");
    db.appendRows("t", [[1, "cmd.exe /c whoami"], [2, "PowerShell -enc"], [3, null], [4, "notepad.exe"]]);
    const native = regexCondition(db, "v", "(?:cmd|power)shell?");
    assert.match(native.sql, /regexp_matches/);
    assert.deepEqual(db.prepare(`SELECT i FROM t WHERE ${native.sql} ORDER BY i`).all(...native.params).map((r) => r.i), [2]);
    const neg = db.prepare(`SELECT i FROM t WHERE NOT ${native.sql} ORDER BY i`).all(...native.params).map((r) => r.i);
    assert.deepEqual(neg, [1, 3, 4], "a NULL cell does not match, so NOT keeps it");
    const look = regexCondition(db, "v", "\\.exe(?! /c)");
    assert.match(look.sql, /^regexp\(/, "RE2 has no lookahead: use the JavaScript function");
    assert.deepEqual(db.prepare(`SELECT i FROM t WHERE ${look.sql} ORDER BY i`).all(...look.params).map((r) => r.i), [4]);
  } finally {
    db.close();
  }
});

test("the better-sqlite3-shaped API behaves as the engine expects", { skip }, () => {
  const db = new Database(":memory:");
  try {
    db.exec("CREATE TABLE tags (rowid INTEGER, tag TEXT, PRIMARY KEY (rowid, tag))");
    const ins = db.prepare("INSERT OR IGNORE INTO tags (rowid, tag) VALUES (?, ?)");
    db.transaction((items) => { for (const [r, t] of items) ins.run(r, t); })([[1, "a"], [1, "a"], [2, "b"]]);
    assert.deepEqual(db.prepare("SELECT rowid, tag FROM tags ORDER BY rowid").all(), [{ rowid: 1, tag: "a" }, { rowid: 2, tag: "b" }]);
    // a lookup that matches nothing returns undefined (and does not wait forever)
    assert.equal(db.prepare("SELECT tag FROM tags WHERE rowid = ?").get(99), undefined);
    // BIGINT → number, BOOLEAN → 1/0, numbers bound against text columns compare as text
    assert.deepEqual(db.prepare("SELECT COUNT(*) AS n, MAX(tag) LIKE 'B' AS m FROM tags").get(), { n: 2, m: 1 });
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM tags WHERE tag = ?").get(1).n, 0);
    // a failing transaction rolls back
    assert.throws(() => db.transaction(() => { ins.run(3, "c"); throw new Error("boom"); })(), /boom/);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM tags WHERE rowid = 3").get().n, 0);
    // iterate streams rows and can stop early
    const seen = [];
    for (const r of db.prepare("SELECT rowid FROM tags ORDER BY rowid").iterate()) { seen.push(r.rowid); break; }
    assert.deepEqual(seen, [1]);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM tags").get().n, 2, "the connection is usable after a broken-off iteration");
    // appendRows numbers rows, loads them before the next call, and reports failures
    db.exec("CREATE TABLE data (rowid BIGINT, c0 VARCHAR, c1 VARCHAR)");
    db.appendRows("data", [["x", 1], ["y", null]], { firstRowid: 1 });
    db.appendRows("data", [["z", "w"]], { firstRowid: 3 });
    assert.deepEqual(db.prepare("SELECT rowid, c0, c1 FROM data ORDER BY rowid").all(), [
      { rowid: 1, c0: "x", c1: "1" }, { rowid: 2, c0: "y", c1: null }, { rowid: 3, c0: "z", c1: "w" },
    ]);
    db.appendRows("no_such_table", [[1]]);
    assert.throws(() => db.flush(), /no_such_table/);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM data").get().n, 3, "the next call works again");
    // bulk reads: non-finite doubles read as null (SQLite's x / 0), NUL bytes survive,
    // booleans stay 1/0, duplicate column names still work
    const odd = db.prepare("SELECT 1.0 / 0.0 AS inf, CAST('nan' AS DOUBLE) AS nan, chr(0) || 'x' AS nul, 1 = 1 AS b, 2 AS n FROM data LIMIT 1").all();
    assert.deepEqual(odd, [{ inf: null, nan: null, nul: "\u0000x", b: 1, n: 2 }]);
    assert.deepEqual(db.prepare("SELECT d1.rowid, d2.rowid FROM data d1, data d2 WHERE d1.rowid = 1 AND d2.rowid = 2").all(), [{ rowid: 2 }]);
    // stored sort keys replace sort_datetime(col) for registered columns
    db.setComputedColumns("sort_datetime", new Map([["c0", "c1"]]));
    assert.deepEqual(db.prepare("SELECT sort_datetime(c0) AS k FROM data ORDER BY rowid").all().map((r) => r.k), ["1", null, "w"]);
  } finally {
    db.close();
  }
});
