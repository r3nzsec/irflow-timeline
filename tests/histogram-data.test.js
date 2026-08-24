const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { Database = require("better-sqlite3"); } catch { /* native module not built */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();
const skip = HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime";

const TimelineDB = require("../electron/db");

test("getHistogramData excludes 1601 FILETIME sentinels and fills the TimeCreated span",
  { skip },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "hist-1601";
    db.createTab(tabId, ["TimeCreated"]);
    const meta = db.databases.get(tabId);
    const ins = meta.db.prepare("INSERT INTO data (c0) VALUES (?)");
    ins.run("1601-01-01 00:00:00.0000000");
    ins.run("1601-01-01 00:00:00.0000000");
    ins.run("2025-04-02 02:37:03");
    ins.run("2025-04-02 08:44:44");
    ins.run("2025-04-05 21:41:50");
    meta.rowCount = 5;

    const rows = db.getHistogramData(tabId, "TimeCreated", { granularity: "day" });
    assert.equal(rows.some((r) => String(r.day).startsWith("1601")), false);
    assert.equal(rows.omittedUnset, 2);
    assert.deepEqual(rows.map((r) => r.day), [
      "2025-04-02", "2025-04-03", "2025-04-04", "2025-04-05",
    ]);
    assert.deepEqual(rows.map((r) => r.cnt), [2, 0, 0, 1]);
  });

test("getHistogramData reports omittedUnset when every TimeCreated is FILETIME epoch",
  { skip },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "hist-all-unset";
    db.createTab(tabId, ["TimeCreated"]);
    const meta = db.databases.get(tabId);
    const ins = meta.db.prepare("INSERT INTO data (c0) VALUES (?)");
    ins.run("1601-01-01 00:00:00");
    ins.run("1601-01-01 00:00:00.0000000");
    meta.rowCount = 2;

    const rows = db.getHistogramData(tabId, "TimeCreated", { granularity: "day" });
    assert.equal(rows.length, 0);
    assert.equal(rows.omittedUnset, 2);
  });

test("getHistogramData buckets zoned TimeCreated values on the UTC date",
  { skip },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "hist-tz";
    db.createTab(tabId, ["TimeCreated"]);
    const meta = db.databases.get(tabId);
    const ins = meta.db.prepare("INSERT INTO data (c0) VALUES (?)");
    // +05:00 on Apr 1 00:34 → Mar 31 19:34 UTC
    ins.run("2026-04-01 00:34:08 +05:00");
    ins.run("2026-04-01T00:30:00");
    meta.rowCount = 2;

    const rows = db.getHistogramData(tabId, "TimeCreated", { granularity: "day" });
    assert.deepEqual(rows.map((r) => r.day), ["2026-03-31", "2026-04-01"]);
    assert.deepEqual(rows.map((r) => r.cnt), [1, 1]);
  });
