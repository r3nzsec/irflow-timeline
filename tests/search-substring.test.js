// Tests for the default global search on the DuckDB engine.
//
// This used to test the trigram-FTS5 prefilter, which went away with SQLite. Search now scans
// the columns with ILIKE; these checks keep the substring semantics the prefilter had to
// preserve (issue #8: a term inside a longer token must match), and add case-insensitivity,
// which SQLite's LIKE gave for free and DuckDB's LIKE does not (the SQL layer turns LIKE into
// ILIKE).

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
let createTestDataTable = null;
try { ({ Database, createTestDataTable } = require("./helpers/duckdb-data-table")); } catch { /* DuckDB binding not installed */ }
const HAVE_DB = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();

const proto = require("../electron/db/query-store");

test("substring search matches inside tokens, ignores case and honors every search mode",
  { skip: HAVE_DB ? false : "DuckDB binding not available for this runtime" },
  () => {
    const db = new Database(":memory:");
    createTestDataTable(db, "c0, c1");
    const rows = [
      [1, "crackb4ckd00r detected", "HOST-A"],
      [2, "clean process started", "WORKSTATION01"],
      [3, "PowerShell -enc foobar", "host-a"],
      [4, "net use server share", "DC01"],
    ];
    const ins = db.prepare("INSERT INTO data(rowid,c0,c1) VALUES (?,?,?)");
    for (const r of rows) ins.run(...r);

    const headers = ["Message", "Computer"];
    const safeCols = [{ original: "Message", safe: "c0" }, { original: "Computer", safe: "c1" }];
    const colMap = { Message: "c0", Computer: "c1" };

    const run = (term, mode, cond) => {
      const meta = { safeCols, colMap, headers };
      const wc = [], params = [];
      proto._applySearch(term, mode, meta, wc, params, cond);
      const sql = `SELECT rowid FROM data${wc.length ? " WHERE " + wc.join(" AND ") : ""}`;
      return db.prepare(sql).all(...params).map((r) => r.rowid).sort((a, b) => a - b);
    };

    // issue #8: a substring embedded in a larger token must match (default mixed mode)
    assert.deepEqual(run("b4ckd00r", "mixed", "contains"), [1], "b4ckd00r must match crackb4ckd00r");

    // exact mode, substring containing a space and a special char; case differs from the data
    assert.deepEqual(run("powershell -enc", "exact", "contains"), [3]);

    // AND mode — all terms required
    assert.deepEqual(run("clean process", "and", "contains"), [2]);

    // OR mode
    assert.deepEqual(run("powershell server", "or", "contains"), [3, 4]);

    // mixed with exclusion — "host" required, "crack" excluded
    assert.deepEqual(run("host -crack", "mixed", "contains"), [3], "rows with 'host' but not 'crack'");

    // column-qualified Col:value, case-insensitive
    assert.deepEqual(run("Computer:HOST", "mixed", "contains"), [1, 3]);

    // short terms work too (no index minimum length any more)
    assert.deepEqual(run("en", "mixed", "contains"), [3], "'en' substring (in -enc)");

    // no-match sanity
    assert.deepEqual(run("zzzqqq", "mixed", "contains"), []);

    db.close();
  });
