// A header text filter has an operator. It is stored as a
// string (Contains, as before) or { op, value }, so every query that passes the tab's column
// filters (grid, stacking, bulk actions, analyzers) applies the same operator.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

let HAVE_SQLITE = false;
try { require("better-sqlite3")(":memory:").close(); HAVE_SQLITE = true; } catch { /* native module not built */ }
const skip = HAVE_SQLITE ? false : "better-sqlite3 native module is not built for this Node runtime";

const ROWS = [
  // FileName, Extension, FileSize, Created
  ["cmd.exe", ".exe", "289792", "2021-03-01 10:00:00"],
  ["CMD.EXE", ".EXE", "50", "2019-07-04 08:00:00"],
  ["notes.txt", ".txt", "1000", "2023-11-30 23:59:59"],
  ["README", "", "12", "2024-01-15 00:00:00"],
  ["evil.exe.txt", ".txt", "100", "2022-06-01 12:00:00"],
  ["data.bin", ".bin", "", "2020-02-29 06:30:00"],
];

test("every operator filters the grid from a header filter", { skip }, () => {
  const TimelineDB = require("../electron/db");
  const db = new TimelineDB();
  try {
    db.createTab("t", ["FileName", "Extension", "FileSize", "Created"]);
    db.insertBatchArrays("t", ROWS);
    db.finalizeImport("t");
    const names = (columnFilters) => db.queryRows("t", { offset: 0, limit: 50, columnFilters }).rows.map((r) => r.FileName).sort();
    assert.deepEqual(names({ FileName: "exe" }), ["CMD.EXE", "cmd.exe", "evil.exe.txt"], "a string is Contains, as before");
    assert.deepEqual(names({ FileName: { op: "contains", value: "exe" } }), ["CMD.EXE", "cmd.exe", "evil.exe.txt"]);
    assert.deepEqual(names({ FileName: { op: "not_contains", value: "exe" } }), ["README", "data.bin", "notes.txt"]);
    assert.deepEqual(names({ Extension: { op: "equals", value: ".exe" } }), ["cmd.exe"]);
    assert.deepEqual(names({ Extension: { op: "not_equals", value: ".txt" } }), ["CMD.EXE", "README", "cmd.exe", "data.bin"]);
    assert.deepEqual(names({ FileName: { op: "starts_with", value: "cmd" } }), ["CMD.EXE", "cmd.exe"]);
    assert.deepEqual(names({ FileName: { op: "ends_with", value: ".txt" } }), ["evil.exe.txt", "notes.txt"]);
    assert.deepEqual(names({ FileSize: { op: "greater_than", value: "100" } }), ["cmd.exe", "notes.txt"], "numbers compare as numbers");
    assert.deepEqual(names({ FileSize: { op: "less_than", value: "100" } }), ["CMD.EXE", "README"]);
    assert.deepEqual(names({ Extension: { op: "is_empty", value: "" } }), ["README"], "no value needed");
    assert.deepEqual(names({ FileSize: { op: "is_not_empty", value: "" } }), ["CMD.EXE", "README", "cmd.exe", "evil.exe.txt", "notes.txt"]);
    assert.deepEqual(names({ FileName: { op: "regex", value: "^[a-z]+\\.exe$" } }), ["CMD.EXE", "cmd.exe"]);
    assert.deepEqual(names({ FileName: { op: "equals", value: "" } }).length, ROWS.length, "an operator without its value doesn't filter");
    // Timestamp columns compare as instants, in header filters and Edit Filter alike.
    assert.deepEqual(names({ Created: { op: "greater_than", value: "2022-01-01" } }), ["README", "evil.exe.txt", "notes.txt"]);
    assert.deepEqual(names({ Created: { op: "less_than", value: "2020-03-01T00:00:00Z" } }), ["CMD.EXE", "data.bin"]);
    const adv = db.queryRows("t", { offset: 0, limit: 50, advancedFilters: [{ column: "Created", operator: "greater_than", value: "2023-06-01", logic: "AND" }] });
    assert.deepEqual(adv.rows.map((r) => r.FileName).sort(), ["README", "notes.txt"]);
    // Header filters combine with each other by AND.
    assert.deepEqual(names({ Extension: { op: "equals", value: ".txt" }, FileSize: { op: "greater_than", value: "500" } }), ["notes.txt"]);
  } finally {
    db.closeAll();
  }
});

test("header filter values encode and decode", async () => {
  const { columnFilterParts, encodeColumnFilter, isActiveColumnFilter, filterOperator, FILTER_OPERATORS } = await import("../src/utils/header-filters.js");
  assert.deepEqual(columnFilterParts(".exe"), { op: "contains", value: ".exe" });
  assert.deepEqual(columnFilterParts({ op: "equals", value: ".exe" }), { op: "equals", value: ".exe" });
  assert.deepEqual(columnFilterParts(undefined), { op: "contains", value: "" });
  assert.equal(encodeColumnFilter("contains", ".exe"), ".exe", "Contains stays a plain string");
  assert.deepEqual(encodeColumnFilter("greater_than", "100"), { op: "greater_than", value: "100" });
  assert.deepEqual(encodeColumnFilter("is_empty", "kept text"), { op: "is_empty", value: "" });
  assert.equal(isActiveColumnFilter(""), false);
  assert.equal(isActiveColumnFilter({ op: "equals", value: "" }), false);
  assert.equal(isActiveColumnFilter({ op: "is_empty", value: "" }), true);
  assert.equal(filterOperator("greater_than").symbol, ">");
  assert.deepEqual(FILTER_OPERATORS.map((o) => o.value), ["contains", "not_contains", "equals", "not_equals", "starts_with", "ends_with", "greater_than", "less_than", "is_empty", "is_not_empty", "regex"]);
  // The backend reads the same shapes.
  const qs = fs.readFileSync(path.join(__dirname, "..", "electron", "db", "query-store.js"), "utf8");
  assert.match(qs, /function columnFilterParts\(raw\) \{\n  if \(raw && typeof raw === "object"\) return \{ op: raw\.op \|\| "contains"/);
});

test("Edit Filter lists a header filter with its operator and saves it back", async () => {
  const { headerFilterRows, applyHeaderFilterRows } = await import("../src/utils/header-filters.js");
  const ct = { headers: ["FileSize", "Extension"], columnFilters: { FileSize: { op: "greater_than", value: "100" }, Extension: { op: "is_empty", value: "" } }, checkboxFilters: {}, dateRangeFilters: {} };
  const rows = headerFilterRows(ct);
  assert.deepEqual(rows.map((r) => [r.column, r.op, r.value]), [["FileSize", "greater_than", "100"], ["Extension", "is_empty", ""]]);
  const edited = rows.map((r) => (r.column === "Extension" ? { ...r, op: "is_not_empty" } : { ...r, op: "less_than" }));
  const saved = applyHeaderFilterRows(ct, rows, edited);
  assert.deepEqual(saved.columnFilters, { FileSize: { op: "less_than", value: "100" }, Extension: { op: "is_not_empty", value: "" } });
  const toContains = applyHeaderFilterRows(ct, rows, rows.map((r) => ({ ...r, op: "contains", value: r.value || "x" })));
  assert.deepEqual(toContains.columnFilters, { FileSize: "100", Extension: "x" });
});

test("the filter row's button opens the operator menu, as does right-clicking the box", () => {
  const vg = fs.readFileSync(path.join(__dirname, "..", "src", "components", "VirtualGrid.jsx"), "utf8");
  assert.equal((vg.match(/\{renderFilterText\(h, hasCbf, isDis\)\}/g) || []).length, 2, "pinned and scrolling filter cells");
  assert.match(vg, /onContextMenu=\{\(e\) => \{ e\.preventDefault\(\); e\.stopPropagation\(\); openMenu\(e\.clientX, e\.clientY\); \}\}/);
  assert.match(vg, /role="menuitemradio" aria-checked=\{o\.value === op\}/);
  assert.match(vg, /\{isDis \? "Turn filter on" : "Turn filter off"\}/);
});
