const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { ({ Database } = require("./helpers/duckdb-data-table")); } catch { /* DuckDB binding not installed */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();

const TimelineDB = require("../electron/db");

test("getColumnValues follows grid sortCol/sortDir, not import rowid order",
  { skip: HAVE_SQLITE ? false : "DuckDB binding not available for this runtime" },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "sort-copy-tab";
    const headers = ["TimeCreated", "Channel"];
    db.createTab(tabId, headers);
    const meta = db.databases.get(tabId);
    meta.tsColumns = new Set(["TimeCreated"]);
    meta.indexedCols = new Set(["c0", "c1"]);

    const ins = meta.db.prepare("INSERT INTO data (c0, c1) VALUES (?, ?)");
    ins.run("2026-04-29 10:00:00", "A");
    ins.run("2026-04-29 08:00:00", "B");
    ins.run("2026-04-29 12:00:00", "C");
    meta.rowCount = 3;

    const byRowid = db.getColumnValues(tabId, "TimeCreated", {});
    assert.deepEqual(byRowid.values, [
      "2026-04-29 10:00:00",
      "2026-04-29 08:00:00",
      "2026-04-29 12:00:00",
    ]);

    const asc = db.getColumnValues(tabId, "TimeCreated", { sortCol: "TimeCreated", sortDir: "asc" });
    assert.deepEqual(asc.values, [
      "2026-04-29 08:00:00",
      "2026-04-29 10:00:00",
      "2026-04-29 12:00:00",
    ]);

    const desc = db.getColumnValues(tabId, "TimeCreated", { sortCol: "TimeCreated", sortDir: "desc" });
    assert.deepEqual(desc.values, [
      "2026-04-29 12:00:00",
      "2026-04-29 10:00:00",
      "2026-04-29 08:00:00",
    ]);
  });

test("getColumnValues distinct collapses timestamp format variants to one value",
  { skip: HAVE_SQLITE ? false : "DuckDB binding not available for this runtime" },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "distinct-ts-tab";
    db.createTab(tabId, ["TimeCreated"]);
    const meta = db.databases.get(tabId);
    meta.tsColumns = new Set(["TimeCreated"]);
    meta.indexedCols = new Set(["c0"]);

    const ins = meta.db.prepare("INSERT INTO data (c0) VALUES (?)");
    ins.run("2026-04-29T20:35:59Z");
    ins.run("2026-04-29 20:35:59");
    ins.run("2026-04-29 20:35:59.0000000");
    meta.rowCount = 3;

    const unique = db.getColumnValues(tabId, "TimeCreated", {
      distinct: true,
      sortCol: "TimeCreated",
      sortDir: "asc",
    });
    assert.equal(unique.values.length, 1);
  });
