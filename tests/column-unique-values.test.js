// Large-tab checkbox-filter values use a bounded row sample instead of a full-table GROUP BY.

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { Database = require("better-sqlite3"); } catch { /* native module not built */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();

const queryStore = require("../electron/db/query-store");
const TimelineDB = require("../electron/db");

test("getColumnUniqueValues samples unindexed columns on large tabs",
  { skip: HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime" },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "large-sample-tab";
    const headers = ["TimeCreated", "Channel"];
    db.createTab(tabId, headers);
    const meta = db.databases.get(tabId);
    meta.isLargeFile = true;
    meta.rowCount = 1_000_000;
    meta.indexedCols = new Set(["c0"]); // only timestamp indexed

    const ins = meta.db.prepare("INSERT INTO data (c0, c1) VALUES (?, ?)");
    for (let i = 0; i < 2000; i++) {
      ins.run(`2024-01-01 00:00:${String(i % 60).padStart(2, "0")}`, i % 3 === 0 ? "Security" : "Sysmon");
    }
    // Preserve the large-file population metadata while keeping the fixture small.
    meta.rowCount = 1_000_000;

    const full = db.getColumnUniqueValues(tabId, "Channel", { limit: 100 });
    assert.ok(full.sampled, "unindexed column on large tab should be sampled");
    assert.ok(full.values.some((r) => r.val === "Security"));
    assert.ok(full.values.some((r) => r.val === "Sysmon"));

    const indexed = db.getColumnUniqueValues(tabId, "TimeCreated", { limit: 100 });
    assert.equal(indexed.sampled, undefined, "indexed timestamp column uses full GROUP BY");
    assert.ok(Array.isArray(indexed.values));
  });

test("query-store exports sample tuning constants", () => {
  assert.equal(queryStore.LARGE_FILE_UNIQUE_SAMPLE_ROWS, 500_000);
  assert.equal(queryStore.LARGE_FILE_UNIQUE_SAMPLE_MIN_ROWS, 250_000);
});

test("getColumnUniqueValues accepts checkboxFilters as Set (AI history default Role filter)",
  { skip: HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime" },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "checkbox-set-tab";
    const headers = ["Role", "Tool"];
    db.createTab(tabId, headers);
    const meta = db.databases.get(tabId);
    const ins = meta.db.prepare("INSERT INTO data (c0, c1) VALUES (?, ?)");
    ins.run("user", "OpenAI Codex");
    ins.run("assistant", "OpenAI Codex");
    ins.run("user", "Claude Code");
    meta.rowCount = 3;

    const result = db.getColumnUniqueValues(tabId, "Tool", {
      checkboxFilters: { Role: new Set(["user"]) },
      limit: 100,
    });
    const vals = result.values;
    assert.ok(Array.isArray(vals));
    assert.equal(vals.length, 2);
    const tools = vals.map((r) => r.val).sort();
    assert.deepEqual(tools, ["Claude Code", "OpenAI Codex"]);
  });

test("getColumnUniqueValues has no default 1000 cap and orders timestamps chronologically",
  { skip: HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime" },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "ts-unique-unlimited";
    db.createTab(tabId, ["TimeCreated"]);
    const meta = db.databases.get(tabId);
    const ins = meta.db.prepare("INSERT INTO data (c0) VALUES (?)");
    const n = 1500;
    for (let i = 0; i < n; i++) {
      const sec = String(i % 60).padStart(2, "0");
      const min = String(Math.floor(i / 60) % 60).padStart(2, "0");
      const hour = String(Math.floor(i / 3600)).padStart(2, "0");
      ins.run(`2025-04-02 ${hour}:${min}:${sec}.1000000`);
    }
    // Duplicate the first timestamp so count-desc would put it first.
    ins.run("2025-04-02 00:00:00.1000000");
    meta.rowCount = n + 1;

    const all = db.getColumnUniqueValues(tabId, "TimeCreated");
    assert.equal(all.truncated, false);
    assert.equal(all.values.length, n);
    assert.equal(all.totalDistinct, n);
    assert.equal(all.values[0].val, "2025-04-02 00:00:00.1000000");
    assert.equal(all.values[0].cnt, 2);
    assert.equal(all.values[all.values.length - 1].val.startsWith("2025-04-02"), true);

    const bounded = db.getColumnUniqueValues(tabId, "TimeCreated", { limit: 1000 });
    assert.equal(bounded.values.length, 1000);
    assert.equal(bounded.totalDistinct, n);
    assert.equal(bounded.truncated, true);
  });

test("checkbox filter of many timestamps does not hit SQLite variable limits",
  { skip: HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime" },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "ts-filter-chunk";
    db.createTab(tabId, ["TimeCreated"]);
    const meta = db.databases.get(tabId);
    const ins = meta.db.prepare("INSERT INTO data (c0) VALUES (?)");
    const values = [];
    const n = 800;
    for (let i = 0; i < n; i++) {
      const ts = `2025-04-18 19:34:${String(i % 60).padStart(2, "0")}.${String(i).padStart(7, "0")}`;
      values.push(ts);
      ins.run(ts);
    }
    meta.rowCount = n;

    const result = db.queryRows(tabId, {
      offset: 0,
      limit: n + 10,
      checkboxFilters: { TimeCreated: values },
    });
    assert.equal(result.error, undefined);
    assert.equal(result.totalFiltered, n);
    assert.equal(result.rows.length, n);
  });
