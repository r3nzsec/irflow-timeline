// View → Full-width cells / Narrow-width cells.
//
// computeCellWidths turns each column's longest value into a width, and getColumnLongestValues
// finds that value over the rows the grid shows. The database test needs the better-sqlite3
// binding and is skipped without it.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

let TimelineDB = null;
try {
  require("better-sqlite3")(":memory:").close();
  TimelineDB = require("../electron/db");
} catch { /* better-sqlite3 native module not built for this runtime */ }
const skip = TimelineDB ? false : "better-sqlite3 native module is not built for this Node runtime";

// Monospace stand-ins: cell text 7 px per character, header text 6 px per character.
const measureCell = (t) => t.length * 7;
const measureHeader = (t) => t.length * 6;
const BOX = 16 + 1 + 2; // padding, border, slack (see cell-widths.js)
const identity = (_h, v) => v;

async function widths(longest, mode, extra = {}) {
  const { computeCellWidths } = await import("../src/utils/cell-widths.js");
  return computeCellWidths({
    headers: Object.keys(longest), longest, mode, fmt: identity, measureCell, measureHeader, ...extra,
  });
}

test("full width fits the widest entry, however long", async () => {
  const w = await widths({ Path: { maxLen: 120, longest: "x".repeat(120) } }, "full");
  assert.equal(w.Path, 120 * 7 + BOX);
});

test("narrow width stops at 30 characters", async () => {
  const w = await widths({ Path: { maxLen: 120, longest: "x".repeat(120) } }, "narrow");
  assert.equal(w.Path, 30 * 7 + BOX);
});

test("narrow width leaves no unused space when the widest entry is shorter", async () => {
  const w = await widths({ Code: { maxLen: 10, longest: "0123456789" } }, "narrow");
  assert.equal(w.Code, 10 * 7 + BOX);
});

test("the header counts as an entry, up to the narrow limit", async () => {
  const short = await widths({ IsDirectory: { maxLen: 5, longest: "False" } }, "narrow");
  assert.equal(short.IsDirectory, "IsDirectory".length * 6 + BOX, "values are shorter than the name");
  const longName = "A".repeat(50);
  const capped = await widths({ [longName]: { maxLen: 1, longest: "x" } }, "narrow");
  assert.equal(capped[longName], 30 * 7 + BOX, "a long name is cut at the same limit");
});

test("timestamps are measured as displayed, not as stored", async () => {
  const { computeCellWidths } = await import("../src/utils/cell-widths.js");
  const w = computeCellWidths({
    headers: ["T"], longest: { T: { maxLen: 27, longest: "2022-02-05 21:47:59.1234567" } }, mode: "narrow",
    fmt: (_h, v) => v.slice(0, 19), measureCell, measureHeader, tsColumns: new Set(["T"]),
  });
  assert.equal(w.T, 19 * 7 + BOX);
});

test("a value too long to send is sized from its length; an empty column from its header", async () => {
  const w = await widths({ Blob: { maxLen: 10000, longest: null }, E: { maxLen: 0, longest: null } }, "full");
  assert.equal(w.Blob, 10000 * 7 + BOX);
  assert.equal(w.E, 40, "never narrower than the minimum");
});

test("the header's sort arrow, timestamp icon and pin are part of its width", async () => {
  const plain = await widths({ When: { maxLen: 1, longest: "x" } }, "full");
  const decorated = await widths({ When: { maxLen: 1, longest: "x" } }, "full", {
    tsColumns: new Set(["When"]), sortCol: "When", pinnedColumns: ["When"],
  });
  assert.equal(decorated.When - plain.When, (6 + 2) + (6 + 3) + 27);
});

test("getColumnLongestValues returns each column's longest value over the filtered rows", { skip }, () => {
  const db = new TimelineDB();
  try {
    db.createTab("t", ["Name", "Path", "Blob", "Empty"]);
    db.insertBatchArrays("t", [
      ["alpha", "C:\\Windows\\System32\\cmd.exe", "x".repeat(5000), ""],
      ["beta", "C:\\a.exe", "y", ""],
      ["gamma-delta", "C:\\Users\\beta\\Downloads\\x.exe", "z", ""],
    ]);
    db.finalizeImport("t");

    const all = db.getColumnLongestValues("t", {});
    assert.deepEqual(all.Name, { maxLen: 11, longest: "gamma-delta" });
    const longPath = "C:\\Users\\beta\\Downloads\\x.exe";
    assert.deepEqual(all.Path, { maxLen: longPath.length, longest: longPath });
    assert.deepEqual(all.Blob, { maxLen: 5000, longest: null }, "values over 4000 characters are not sent");
    assert.equal(all.Empty.maxLen, 0);

    // Only the rows the grid shows: a search for "cmd" leaves the first row.
    const filtered = db.getColumnLongestValues("t", { searchTerm: "cmd", searchMode: "mixed", searchCondition: "contains" });
    assert.deepEqual(filtered.Name, { maxLen: 5, longest: "alpha" });
    const cmdPath = "C:\\Windows\\System32\\cmd.exe";
    assert.deepEqual(filtered.Path, { maxLen: cmdPath.length, longest: cmdPath });
  } finally {
    db.closeAll();
  }
});

test("View menu has Full-width cells (⌥⌘F) and Narrow-width cells (⌥⌘N)", () => {
  const menu = fs.readFileSync(path.join(__dirname, "..", "electron", "menu.js"), "utf8");
  assert.match(menu, /label: "Full-width cells",\s*accelerator: "CmdOrCtrl\+Alt\+F"/);
  assert.match(menu, /label: "Narrow-width cells",\s*accelerator: "CmdOrCtrl\+Alt\+N"/);
  const bar = fs.readFileSync(path.join(__dirname, "..", "src", "components", "MenuBar.jsx"), "utf8");
  assert.match(bar, /label: "Full-width cells", shortcut: "⌥⌘F"/);
  assert.match(bar, /label: "Narrow-width cells", shortcut: "⌥⌘N"/);
});
