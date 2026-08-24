// The "(empty)" entry in a column's checkbox filter.
//
// A blank cell can be stored several ways — NULL, '', or whitespace-only — and all of them
// render identically in the grid. The value list and the filter that consumes it therefore
// have to agree they are one bucket.
//
// They did not. GROUP BY produced one row per representation, so the dropdown showed two
// entries both labelled "(empty)" plus a whitespace entry whose label rendered blank but
// was not "(empty)". Unchecking the one you could see left the others selected, and their
// rows stayed on screen — the filter looked like it had been ignored.
//
// Needs a live SQLite binding; skipped under a Node runtime without the native module built
// (CI rebuilds it). Run after `npm rebuild better-sqlite3`.

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

/** A tab whose AppClass column carries every way a cell can read as blank. */
function makeTab() {
  const db = new TimelineDB();
  db.createTab("t", ["AppClass", "Activity"]);
  db.insertBatchArrays("t", [
    ["Web", "web-1"],
    ["Web", "web-2"],
    ["Terminal", "term-1"],
    ["", "empty-string"],
    [null, "null-value"],
    ["   ", "spaces"],
    ["\t", "tab"],
    ["\n", "newline"],
  ]);
  db.finalizeImport("t");
  return db;
}

const activities = (result) => result.rows.map((r) => r.Activity).sort();
const BLANK_ROWS = ["empty-string", "newline", "null-value", "spaces", "tab"];

test("every blank representation collapses into one (empty) value-list entry", { skip }, () => {
  const db = makeTab();
  try {
    const { values } = db.getColumnUniqueValues("t", "AppClass", {});
    // What the dropdown would label "(empty)" — the renderer uses `val == null || val === ""`.
    const blanks = values.filter((v) => v.val == null || v.val === "");
    assert.equal(blanks.length, 1, `expected a single (empty) row, got ${JSON.stringify(values)}`);
    assert.equal(blanks[0].cnt, 5, "the (empty) count must cover NULL, '', spaces, tab and newline");

    // And nothing else in the list may render as a blank label — a whitespace-only entry
    // looks exactly like "(empty)" to the user but is a different checkbox.
    const blankLooking = values.filter((v) => v.val != null && v.val !== "" && String(v.val).trim() === "");
    assert.deepEqual(blankLooking, [], "a whitespace-only value is still its own filter entry");

    assert.deepEqual(values.map((v) => v.val).sort(), ["", "Terminal", "Web"]);
  } finally {
    db.closeAll();
  }
});

test("unchecking (empty) hides every blank row, whatever its stored shape", { skip }, () => {
  const db = makeTab();
  try {
    // Exactly what the UI sends after the user unchecks the one "(empty)" checkbox.
    const res = db.queryRows("t", { offset: 0, limit: 100, checkboxFilters: { AppClass: ["Web", "Terminal"] } });
    assert.deepEqual(activities(res), ["term-1", "web-1", "web-2"]);
    assert.equal(res.totalFiltered, 3, "totalFiltered must agree with the rows returned");
  } finally {
    db.closeAll();
  }
});

test("checking only (empty) selects every blank row, whatever its stored shape", { skip }, () => {
  const db = makeTab();
  try {
    const res = db.queryRows("t", { offset: 0, limit: 100, checkboxFilters: { AppClass: [""] } });
    assert.deepEqual(activities(res), BLANK_ROWS);
    assert.equal(res.totalFiltered, 5);
  } finally {
    db.closeAll();
  }
});

test("a null in the selected list means the same bucket as an empty string", { skip }, () => {
  // Session restore and the row context menu can both put a null in the list.
  const db = makeTab();
  try {
    assert.deepEqual(
      activities(db.queryRows("t", { offset: 0, limit: 100, checkboxFilters: { AppClass: [null] } })),
      BLANK_ROWS,
    );
  } finally {
    db.closeAll();
  }
});

test("selecting everything returns everything, and the two directions are complementary", { skip }, () => {
  const db = makeTab();
  try {
    const all = db.queryRows("t", { offset: 0, limit: 100, checkboxFilters: { AppClass: ["Web", "Terminal", ""] } });
    assert.equal(all.totalFiltered, 8);
    // The (empty) checkbox partitions the tab: on + off must reconstruct the whole set with
    // no row counted twice. That is the property the original bug broke.
    const withEmpty = db.queryRows("t", { offset: 0, limit: 100, checkboxFilters: { AppClass: [""] } });
    const withoutEmpty = db.queryRows("t", { offset: 0, limit: 100, checkboxFilters: { AppClass: ["Web", "Terminal"] } });
    assert.equal(withEmpty.totalFiltered + withoutEmpty.totalFiltered, all.totalFiltered);
    const overlap = activities(withEmpty).filter((a) => activities(withoutEmpty).includes(a));
    assert.deepEqual(overlap, []);
  } finally {
    db.closeAll();
  }
});

test("a value that merely has surrounding whitespace is not swallowed by the empty bucket", { skip }, () => {
  // Only whitespace-*only* cells are blank. " Web" is a real, distinct value and must stay
  // selectable on its own — collapsing it would silently merge two different findings.
  const db = new TimelineDB();
  try {
    db.createTab("t", ["AppClass", "Activity"]);
    db.insertBatchArrays("t", [[" Web", "padded"], ["Web", "plain"], ["", "blank"]]);
    db.finalizeImport("t");

    const vals = db.getColumnUniqueValues("t", "AppClass", {}).values.map((v) => v.val).sort();
    assert.deepEqual(vals, ["", " Web", "Web"]);

    const res = db.queryRows("t", { offset: 0, limit: 100, checkboxFilters: { AppClass: [" Web"] } });
    assert.deepEqual(activities(res), ["padded"]);
  } finally {
    db.closeAll();
  }
});

test("the empty bucket survives an unrelated active filter on another column", { skip }, () => {
  // The value list is built with the other columns' filters applied, so the bucketing has
  // to hold on the filtered subset too.
  const db = new TimelineDB();
  try {
    db.createTab("t", ["AppClass", "Host"]);
    db.insertBatchArrays("t", [
      ["Web", "h1"], ["", "h1"], [null, "h1"], ["  ", "h1"],
      ["Web", "h2"], ["", "h2"],
    ]);
    db.finalizeImport("t");

    const { values } = db.getColumnUniqueValues("t", "AppClass", { checkboxFilters: { Host: ["h1"] } });
    const blanks = values.filter((v) => v.val == null || v.val === "");
    assert.equal(blanks.length, 1);
    assert.equal(blanks[0].cnt, 3, "NULL, '' and spaces on host h1");

    const res = db.queryRows("t", {
      offset: 0, limit: 100,
      checkboxFilters: { Host: ["h1"], AppClass: ["Web"] },
    });
    assert.equal(res.totalFiltered, 1, "unchecking (empty) leaves only the real value on h1");
  } finally {
    db.closeAll();
  }
});
