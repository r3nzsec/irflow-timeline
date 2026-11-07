// Edit Filter lists and saves the filters set under the
// column headers (src/utils/header-filters.js). Checked in the app over CDP; these pin the rules.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const load = () => import("../src/utils/header-filters.js");

const tab = () => ({
  headers: ["EntryNumber", "FileName", "IsDirectory", "Created0x10", "ParentPath"],
  columnFilters: { ParentPath: "Windows", FileName: ".exe", EntryNumber: "", __tags__: "Suspicious" },
  checkboxFilters: { IsDirectory: ["False"], ParentPath: new Set(["C:\\\\Windows"]), Created0x10: [] },
  dateRangeFilters: { Created0x10: { from: "2000-01-01T00:00", to: "" }, FileName: { from: "", to: "" } },
  disabledFilters: new Set(),
});

test("header filters are listed in column order: text, value list, date range", async () => {
  const { headerFilterRows, headerFilterColumnLabel } = await load();
  const rows = headerFilterRows(tab());
  assert.deepEqual(rows.map((r) => `${r.kind}:${r.column}`), [
    "text:__tags__", "text:FileName", "values:IsDirectory", "date:Created0x10", "text:ParentPath", "values:ParentPath",
  ]);
  assert.deepEqual(rows.find((r) => r.kind === "values" && r.column === "ParentPath").values, ["C:\\\\Windows"], "a Set of values");
  assert.equal(new Set(rows.map((r) => r.key)).size, rows.length, "keys are unique");
  assert.equal(headerFilterColumnLabel("__tags__"), "Tags");
  assert.equal(headerFilterColumnLabel("FileName"), "FileName");
});

test("a header filter switched off with its toggle isn't listed and is kept", async () => {
  const { headerFilterRows, applyHeaderFilterRows } = await load();
  const t = { ...tab(), disabledFilters: new Set(["FileName", "IsDirectory"]) };
  const rows = headerFilterRows(t);
  assert.ok(!rows.some((r) => r.column === "FileName" && r.kind === "text"));
  assert.ok(!rows.some((r) => r.column === "IsDirectory"));
  const saved = applyHeaderFilterRows(t, rows, []);
  assert.equal(saved.columnFilters.FileName, ".exe");
  assert.deepEqual(saved.checkboxFilters.IsDirectory, ["False"]);
});

test("saving keeps edited text, clears emptied and removed filters, and keeps the rest", async () => {
  const { headerFilterRows, applyHeaderFilterRows } = await load();
  const t = tab();
  const shown = headerFilterRows(t);
  const edited = shown
    .filter((r) => !(r.kind === "values" && r.column === "IsDirectory"))   // removed with ✕
    .filter((r) => !(r.kind === "date"))                                    // removed with ✕
    .map((r) => (r.kind === "text" && r.column === "FileName" ? { ...r, value: ".dll" } : r))
    .map((r) => (r.kind === "text" && r.column === "ParentPath" ? { ...r, value: "" } : r));
  const saved = applyHeaderFilterRows(t, shown, edited);
  assert.equal(saved.columnFilters.FileName, ".dll");
  assert.ok(!("ParentPath" in saved.columnFilters), "emptied text clears the filter");
  assert.equal(saved.columnFilters.__tags__, "Suspicious");
  assert.ok(!("IsDirectory" in saved.checkboxFilters));
  assert.ok("ParentPath" in saved.checkboxFilters);
  assert.ok(!("Created0x10" in saved.dateRangeFilters));
  assert.ok("FileName" in saved.dateRangeFilters, "an empty range wasn't listed, so it is left alone");
  assert.notEqual(saved.columnFilters, t.columnFilters, "new objects, the tab is not mutated");
  assert.equal(t.columnFilters.FileName, ".exe");
  // Clear All: nothing kept.
  const cleared = applyHeaderFilterRows(t, shown, []);
  assert.deepEqual(Object.keys(cleared.columnFilters).filter((k) => cleared.columnFilters[k]), []);
  assert.ok(!("IsDirectory" in cleared.checkboxFilters) && !("Created0x10" in cleared.dateRangeFilters));
});

test("the dialog saves its conditions and the header filters in one update, and Clear All clears both", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "src", "components", "modals", "EditFilterModal.jsx"), "utf8");
  assert.match(src, /useTabStore\.getState\(\)\.updateActiveTab\(\{\s*advancedFilters: valid\.map\(\(\{ id, \.\.\.rest \}\) => rest\),\s*\.\.\.applyHeaderFilterRows\(ct, shownHeaderRows, rows\),\s*\}\)/);
  assert.match(src, /const handleApply = \(\) => save\(conditions, headerRows\);/);
  assert.match(src, /const handleClear = \(\) => save\(\[\], \[\]\);/);
  assert.match(src, /Conditions \(AND with the filters above\)/);
});
