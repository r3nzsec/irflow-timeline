const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { ({ Database } = require("./helpers/duckdb-data-table")); } catch { /* DuckDB binding not installed */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();

const TimelineDB = require("../electron/db");

test("date range filter matches timestamp format variants via sort_datetime",
  { skip: HAVE_SQLITE ? false : "DuckDB binding not available for this runtime" },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "date-range-tab";
    db.createTab(tabId, ["TimeCreated"]);
    const meta = db.databases.get(tabId);
    meta.tsColumns = new Set(["TimeCreated"]);

    const ins = meta.db.prepare("INSERT INTO data (c0) VALUES (?)");
    ins.run("2026-04-29T08:00:00Z");
    ins.run("2026-04-29 10:00:00");
    ins.run("2026-04-29T12:00:00Z");
    ins.run("2026-04-30 01:00:00");
    meta.rowCount = 4;

    const inRange = db.queryRows(tabId, {
      offset: 0,
      limit: 100,
      sortCol: "TimeCreated",
      sortDir: "asc",
      dateRangeFilters: {
        TimeCreated: { from: "2026-04-29 09:00:00", to: "2026-04-29 23:59:59" },
      },
    });
    assert.equal(inRange.totalFiltered, 2);
    assert.deepEqual(
      inRange.rows.map((r) => r.TimeCreated),
      ["2026-04-29 10:00:00", "2026-04-29T12:00:00Z"],
    );
  });
