const test = require("node:test");
const assert = require("node:assert/strict");
const TimelineDB = require("../electron/db");

function fixture(t) {
  const db = new TimelineDB();
  t.after(() => db.closeAll());
  db.createTab("tags", ["Level"]);
  db.insertBatchArrays("tags", [["crit"], ["info"], ["crit"]]);
  db.finalizeImport("tags");
  db.addTag("tags", 1, "Suspicious");
  db.addTag("tags", 1, "Unknown analyzer tag");
  db.addTag("tags", 2, "C2");
  db.addTag("tags", 3, "Suspicious");
  db.toggleBookmark("tags", 1);
  return db;
}

test("Clear removes all tags on the clicked row while retaining other rows and bookmarks", (t) => {
  const db = fixture(t);
  assert.deepEqual(db.clearTagsFiltered("tags", { rowIdFilter: [1] }), { ok: true, removed: 2 });
  assert.deepEqual(db.getTagsForRows("tags", [1, 2, 3]), { 2: ["C2"], 3: ["Suspicious"] });
  assert.deepEqual(db.getBookmarkedIds("tags"), [1]);
  assert.equal(db.queryRows("tags", { limit: 10 }).rows.length, 3);
});

test("Clear honors a filtered select-all scope and excluded rows", (t) => {
  const db = fixture(t);
  const result = db.clearTagsFiltered("tags", {
    columnFilters: { Level: "crit" }, excludedRowIds: [3],
  });
  assert.equal(result.removed, 2);
  assert.deepEqual(db.getTagsForRows("tags", [1, 2, 3]), { 2: ["C2"], 3: ["Suspicious"] });
});

test("Clear includes unknown tags on rows selected by a tag filter", (t) => {
  const db = fixture(t);
  const result = db.clearTagsFiltered("tags", { tagFilter: "Suspicious" });
  assert.deepEqual(result, { ok: true, removed: 3 });
  assert.deepEqual(db.getTagsForRows("tags", [1, 2, 3]), { 2: ["C2"] });
});

test("Clear fails closed for omitted scope and treats empty or invalid row IDs as no selection", (t) => {
  const db = fixture(t);
  for (const options of [{}, { unknownFilters: [] }, { rowIdFilter: null }]) {
    assert.equal(db.clearTagsFiltered("tags", options).ok, false);
  }
  for (const rowIdFilter of [[], [0, -1, "invalid"], [99999]]) {
    assert.deepEqual(db.clearTagsFiltered("tags", { rowIdFilter }), { ok: true, removed: 0 });
  }
  assert.equal(db.clearTagsFiltered("missing", { rowIdFilter: [1] }).ok, false);
  assert.equal(db.getAllTagData("tags").length, 4);
  assert.deepEqual(db.clearTagsFiltered("tags", { confirmWholeTab: true }), { ok: true, removed: 4 });
  assert.deepEqual(db.getAllTagData("tags"), []);
  assert.deepEqual(db.getBookmarkedIds("tags"), [1]);
});
