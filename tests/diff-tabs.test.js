const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const {
  suggestMatchKeys,
  scoreIdentityColumn,
  schemaDelta,
  buildUnifiedHeaders,
  diffRowSets,
  compareRowFields,
  normalizeCell,
  isDiffMetaColumn,
  diffTabTitle,
} = require("../electron/db/diff-tabs");

const root = path.join(__dirname, "..");
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), "utf8");

test("identity scoring prefers record ids and hashes over payload text", () => {
  assert.equal(scoreIdentityColumn("EventRecordId"), 100);
  assert.equal(scoreIdentityColumn("RecordNumber"), 100);
  assert.ok(scoreIdentityColumn("SHA1") >= 88);
  assert.ok(scoreIdentityColumn("SourceFile") > scoreIdentityColumn("EventId"));
  assert.ok(scoreIdentityColumn("FullText") < 20);
  assert.equal(scoreIdentityColumn("_Diff"), 0);
});

test("suggestMatchKeys is generic across forensic schemas", () => {
  const evtx = suggestMatchKeys(
    ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Computer", "Payload"],
    ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Computer", "Payload"],
  );
  assert.ok(evtx.includes("EventRecordId"));

  const history = suggestMatchKeys(
    ["Timestamp", "EventKind", "Activity", "SourceFile", "Content", "App"],
    ["Timestamp", "EventKind", "Activity", "SourceFile", "Content", "App"],
  );
  assert.deepEqual(history, ["SourceFile", "Timestamp", "EventKind", "Activity"]);

  const hashed = suggestMatchKeys(
    ["Path", "SHA1", "Size"],
    ["Path", "SHA1", "Size"],
  );
  assert.deepEqual(hashed, ["SHA1"]);

  const weak = suggestMatchKeys(["Alpha", "Beta"], ["Alpha", "Beta"]);
  assert.deepEqual(weak, []);
});

test("schema delta reports mixed headers without treating diff meta as data", () => {
  const delta = schemaDelta(
    ["Name", "Value", "Timestamp", "_Diff"],
    ["Name", "Value", "Extra", "Timestamp"],
  );
  assert.deepEqual(delta.common, ["Name", "Timestamp", "Value"]);
  assert.deepEqual(delta.onlyA, []);
  assert.deepEqual(delta.onlyB, ["Extra"]);
  assert.equal(isDiffMetaColumn("_ChangedFields"), true);
});

test("unified headers lead with diff meta then the union of source columns", () => {
  const headers = buildUnifiedHeaders(["Name", "Value"], ["Name", "Extra"]);
  assert.equal(headers[0], "_Diff");
  assert.ok(headers.includes("datetime"));
  assert.ok(headers.includes("Name"));
  assert.ok(headers.includes("Value"));
  assert.ok(headers.includes("Extra"));
  assert.equal(headers.filter((h) => h === "Name").length, 1);
});

test("diffRowSets classifies Added, Removed, Changed, and Unchanged", () => {
  const headersA = ["Name", "Value", "Timestamp"];
  const headersB = ["Name", "Value", "Extra", "Timestamp"];
  const rowsA = [
    { Name: "alpha", Value: "1", Timestamp: "2024-01-01 00:00:00" },
    { Name: "beta", Value: "2", Timestamp: "2024-01-01 00:00:01" },
    { Name: "gone", Value: "9", Timestamp: "2024-01-01 00:00:02" },
  ];
  const rowsB = [
    { Name: "alpha", Value: "1", Extra: "x", Timestamp: "2024-01-01 00:00:00" },
    { Name: "beta", Value: "2", Extra: "", Timestamp: "2024-01-01 00:00:01" },
    { Name: "new", Value: "3", Extra: "y", Timestamp: "2024-01-01 00:00:03" },
  ];
  const result = diffRowSets(rowsA, rowsB, {
    headersA, headersB, matchKeys: ["Name"], includeUnchanged: true,
    tsColA: "Timestamp", tsColB: "Timestamp",
  });
  const byName = Object.fromEntries(result.rows.map((r) => [r.Name || r._MatchKey, r]));
  assert.equal(result.stats.added, 1);
  assert.equal(result.stats.removed, 1);
  assert.equal(result.stats.changed, 1);
  assert.equal(result.stats.unchanged, 1);
  assert.equal(byName.alpha._Diff, "Changed");
  assert.equal(byName.alpha._ChangedFields, "Extra");
  assert.match(byName.alpha._DiffSummary, /Extra/);
  assert.equal(byName.beta._Diff, "Unchanged");
  assert.equal(byName.new._Diff, "Added");
  assert.equal(byName.gone._Diff, "Removed");
  assert.equal(byName.alpha.datetime, "2024-01-01 00:00:00");
});

test("includeUnchanged false omits identical rows but still counts them", () => {
  const headers = ["Id", "Val"];
  const result = diffRowSets(
    [{ Id: "1", Val: "a" }, { Id: "2", Val: "b" }],
    [{ Id: "1", Val: "a" }, { Id: "2", Val: "B" }],
    { headersA: headers, headersB: headers, matchKeys: ["Id"], includeUnchanged: false },
  );
  assert.equal(result.stats.unchanged, 1);
  assert.equal(result.stats.changed, 1);
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0]._Diff, "Changed");
  assert.equal(result.rows[0].Val, "B");
});

test("empty match keys use entire-row hash so Changed never appears", () => {
  const headers = ["Name", "Value"];
  const result = diffRowSets(
    [{ Name: "a", Value: "1" }, { Name: "b", Value: "2" }],
    [{ Name: "a", Value: "1" }, { Name: "b", Value: "3" }],
    { headersA: headers, headersB: headers, matchKeys: [], includeUnchanged: true },
  );
  const statuses = result.rows.map((r) => r._Diff).sort();
  assert.deepEqual(statuses, ["Added", "Removed", "Unchanged"]);
  assert.equal(result.stats.changed, 0);
  assert.equal(result.stats.unchanged, 1);
});

test("duplicate identity keys match as a multiset", () => {
  const headers = ["Name", "Value"];
  const result = diffRowSets(
    [{ Name: "dup", Value: "1" }, { Name: "dup", Value: "2" }],
    [{ Name: "dup", Value: "1" }],
    { headersA: headers, headersB: headers, matchKeys: ["Name"], includeUnchanged: true },
  );
  assert.equal(result.stats.unchanged, 1);
  assert.equal(result.stats.removed, 1);
  assert.equal(result.stats.added, 0);
});

test("compareRowFields captures mixed-schema additions", () => {
  const cmp = compareRowFields(
    { Name: "x", Value: "old" },
    { Name: "x", Value: "new", Extra: "added" },
    ["Name", "Value", "Extra"],
  );
  assert.deepEqual(cmp.changedFields, ["Value", "Extra"]);
  const detail = JSON.parse(cmp.detail);
  assert.equal(detail.find((p) => p.f === "Extra").a, "");
  assert.equal(detail.find((p) => p.f === "Extra").b, "added");
});

test("normalizeCell strips NULs and trims", () => {
  assert.equal(normalizeCell("  a\0b\r\nc  "), "ab\nc");
});

test("diff tab title names both sides", () => {
  assert.match(diffTabTitle("computer_history_v2.csv", "computer_history_v3.csv"), /Diff:/);
  assert.match(diffTabTitle("a", "b"), /a → b/);
});

test("View menu, preload, and IPC expose Diff Tabs for every file type", () => {
  const menu = read("src/components/MenuBar.jsx");
  const preload = read("electron/preload.js");
  const ipc = read("electron/ipc/session-handlers.js");
  const app = read("src/App.jsx");
  assert.match(menu, /label: "Diff Tabs"/);
  assert.match(menu, /label: "Diff Explorer"/);
  assert.match(preload, /diffTabs:/);
  assert.match(ipc, /safeHandle\("diff-tabs"/);
  assert.match(app, /sourceFormat === "tab-diff"/);
  assert.match(app, /DiffBanner/);
  assert.doesNotMatch(menu, /Computer History only/);
});

let Database = null;
try { Database = require("better-sqlite3"); } catch { /* native module not built */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();
const skip = HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime";

test("TimelineDB.diffTabs writes Added/Removed/Changed rows for mixed schemas", { skip }, async () => {
  const TimelineDB = require("../electron/db");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-diff-"));
  const db = new TimelineDB();
  try {
    db._dbPathHint = path.join(dir, "a.sqlite");
    db.createTab("a", ["Name", "Value", "Timestamp"]);
    db.insertBatchArrays("a", [
      ["alpha", "1", "2024-01-01 00:00:00"],
      ["beta", "2", "2024-01-01 00:00:01"],
      ["gone", "9", "2024-01-01 00:00:02"],
    ]);
    db.finalizeImport("a");

    db._dbPathHint = path.join(dir, "b.sqlite");
    db.createTab("b", ["Name", "Value", "Extra", "Timestamp"]);
    db.insertBatchArrays("b", [
      ["alpha", "1", "x", "2024-01-01 00:00:00"],
      ["beta", "2", "", "2024-01-01 00:00:01"],
      ["new", "3", "y", "2024-01-01 00:00:03"],
    ]);
    db.finalizeImport("b");

    db._dbPathHint = path.join(dir, "diff.sqlite");
    const result = await db.diffTabs("d", {
      baseline: { tabId: "a", tabName: "v2", tsCol: "Timestamp" },
      compare: { tabId: "b", tabName: "v3", tsCol: "Timestamp" },
      matchKeys: ["Name"],
      includeUnchanged: true,
    });

    assert.equal(result.stats.added, 1);
    assert.equal(result.stats.removed, 1);
    assert.equal(result.stats.changed, 1);
    assert.equal(result.stats.unchanged, 1);
    assert.ok(result.schemaDelta.onlyB.includes("Extra"));
    assert.ok(result.headers.includes("_Diff"));
    assert.ok(result.headers.includes("Extra"));

    const queried = db.queryRows("d", { offset: 0, limit: 50, sortCol: "_Diff", sortDir: "asc" });
    const byStatus = {};
    for (const row of queried.rows) {
      byStatus[row._Diff] = (byStatus[row._Diff] || 0) + 1;
      if (row._Diff === "Changed") {
        assert.equal(row.Name, "alpha");
        assert.match(row._ChangedFields, /Extra/);
        assert.equal(row._Baseline, "v2");
        assert.equal(row._Compare, "v3");
      }
    }
    assert.equal(byStatus.Added, 1);
    assert.equal(byStatus.Removed, 1);
    assert.equal(byStatus.Changed, 1);
    assert.equal(byStatus.Unchanged, 1);
  } finally {
    db.closeAll();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
