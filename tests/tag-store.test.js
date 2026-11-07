const test = require("node:test");
const assert = require("node:assert/strict");

const tagStore = require("../electron/db/tag-store");
const { normalizeTagName, normalizeRowIdList } = tagStore;

const Database = require("../electron/db/duckdb");

/**
 * A real tab: an in-memory DuckDB database with the production data/tags/bookmarks schema
 * and the bookmark/tag statements db.js prepares.
 */
function makeTab({ rowCount = 100, tags = [], bookmarks = [] } = {}) {
  const db = new Database(":memory:");
  db.exec("CREATE TABLE data (rowid BIGINT, c0 VARCHAR)");
  db.exec("CREATE TABLE bookmarks (rowid BIGINT PRIMARY KEY)");
  db.exec("CREATE TABLE tags (rowid BIGINT, tag VARCHAR, PRIMARY KEY(rowid, tag))");
  db.appendRows("data", Array.from({ length: rowCount }, (_, i) => [`row ${i + 1}`]), { firstRowid: 1 });
  for (const [id, t] of tags) db.prepare("INSERT INTO tags (rowid, tag) VALUES (?, ?)").run(id, t);
  for (const id of bookmarks) db.prepare("INSERT INTO bookmarks (rowid) VALUES (?)").run(id);

  const meta = {
    rowCount,
    db,
    indexesBuilding: true, // deliberately "mid index build" — writes must still land
    ftsBuilding: true,
    bmCheckStmt: db.prepare("SELECT rowid FROM bookmarks WHERE rowid = ?"),
    bmInsertStmt: db.prepare("INSERT OR IGNORE INTO bookmarks (rowid) VALUES (?)"),
    bmDeleteStmt: db.prepare("DELETE FROM bookmarks WHERE rowid = ?"),
    bmCountStmt: db.prepare("SELECT COUNT(*) as cnt FROM bookmarks"),
    tagInsertStmt: db.prepare("INSERT OR IGNORE INTO tags (rowid, tag) VALUES (?, ?)"),
    tagDeleteStmt: db.prepare("DELETE FROM tags WHERE rowid = ? AND tag = ?"),
    get tagSet() {
      return new Set(db.prepare("SELECT rowid, tag FROM tags").all().map((r) => `${r.rowid} ${r.tag}`));
    },
  };

  const store = Object.create(tagStore);
  store.databases = new Map([["tab", meta]]);
  // Stub for the filter builder the query-store mixin normally provides.
  store._applyStandardFilters = (options, _meta, where, params) => {
    if (Array.isArray(options.rowIdFilter) && options.rowIdFilter.length) {
      where.push(`data.rowid IN (${options.rowIdFilter.join(",")})`);
    }
    if (options.searchTerm) { where.push("c0 LIKE ?"); params.push(`%${options.searchTerm}%`); }
  };
  const has = (id, tag) => !!db.prepare("SELECT 1 AS x FROM tags WHERE rowid = ? AND tag = ?").get(id, tag);
  return { store, meta, has };
}

test("tag names are normalized at the write boundary", () => {
  assert.equal(normalizeTagName("  Suspicious  "), "Suspicious");
  assert.equal(normalizeTagName("Lateral\n Movement"), "Lateral Movement");
  assert.equal(normalizeTagName(""), "");
  assert.equal(normalizeTagName(null), "");
  assert.equal(normalizeTagName("x".repeat(500)).length, 200);
});

test("row ID lists drop junk and duplicates", () => {
  assert.deepEqual(normalizeRowIdList([3, "3", 0, -1, "bad", 7, null]), [3, 7]);
  assert.deepEqual(normalizeRowIdList("nope"), []);
});

test("tag writes are NOT dropped while indexes/FTS are building", () => {
  const { store, has, meta } = makeTab();
  assert.equal(meta.indexesBuilding && meta.ftsBuilding, true);
  const res = store.addTag("tab", 5, "Suspicious");
  assert.equal(res.ok, true);
  assert.equal(res.changed, 1);
  assert.equal(has(5, "Suspicious"), true);
  assert.equal(store.toggleBookmark("tab", 5), true);
  assert.equal(store.toggleBookmark("tab", 5), false);
});

test("setTagOnRows applies ONE direction uniformly across a mixed selection", () => {
  // Rows 1 and 3 already carry the tag; 2 and 4 do not. A single "apply" must
  // leave all four tagged, never untag the ones that already had it.
  const { store, has } = makeTab({ tags: [[1, "Suspicious"], [3, "Suspicious"]] });
  const res = store.setTagOnRows("tab", [1, 2, 3, 4], "Suspicious", true);
  assert.equal(res.ok, true);
  assert.equal(res.requested, 4);
  assert.equal(res.changed, 2); // only the two that were missing it
  for (const id of [1, 2, 3, 4]) assert.equal(has(id, "Suspicious"), true, `row ${id}`);

  const off = store.setTagOnRows("tab", [1, 2, 3, 4], "Suspicious", false);
  assert.equal(off.changed, 4);
  for (const id of [1, 2, 3, 4]) assert.equal(has(id, "Suspicious"), false, `row ${id}`);
});

test("setTagOnRows normalizes the tag and the row IDs", () => {
  const { store, has } = makeTab();
  const res = store.setTagOnRows("tab", [2, "2", 0, 9], "  C2  ", true);
  assert.equal(res.tag, "C2");
  assert.equal(res.requested, 2);
  assert.equal(has(2, "C2"), true);
  assert.equal(has(9, "C2"), true);
});

test("addTag/removeTag are single-row wrappers over setTagOnRows", () => {
  const { store, has } = makeTab();
  store.addTag("tab", 4, "Persistence");
  assert.equal(has(4, "Persistence"), true);
  const res = store.removeTag("tab", 4, "Persistence");
  assert.equal(res.changed, 1);
  assert.equal(has(4, "Persistence"), false);
});

test("bulkTagFiltered refuses an unscoped write unless it is confirmed", () => {
  const { store } = makeTab({ rowCount: 500 });
  const refused = store.bulkTagFiltered("tab", "Everything", {});
  assert.equal(refused.tagged, 0);
  assert.equal(refused.wholeTab, true);
  assert.match(refused.error, /all 500 rows/);

  const allowed = store.bulkTagFiltered("tab", "Everything", { confirmWholeTab: true });
  assert.equal(allowed.tagged, 500);
});

test("bulkTagFiltered writes normally when the options actually scope it", () => {
  const { store, has } = makeTab();
  const res = store.bulkTagFiltered("tab", "Session 1", { rowIdFilter: [1, 2] });
  assert.equal(res.tagged, 2);
  assert.equal(has(1, "Session 1"), true);
  assert.equal(has(3, "Session 1"), false);
});

test("bulkTagFiltered still rejects unrecognized filter shapes", () => {
  const { store } = makeTab();
  const res = store.bulkTagFiltered("tab", "Oops", { filters: [{ column: "x" }] });
  assert.equal(res.tagged, 0);
  assert.match(res.error, /unrecognized filter option/);
});

test("bulkUntagFiltered is the undo path and needs no confirmation", () => {
  const { store, has } = makeTab({ tags: [[1, "Encrypted"], [2, "Encrypted"]] });
  const res = store.bulkUntagFiltered("tab", "Encrypted", {});
  assert.equal(res.untagged, 2);
  assert.equal(has(1, "Encrypted"), false);
});

test("bulkBookmarkFiltered refuses an unscoped add but always allows removal", () => {
  const { store } = makeTab({ rowCount: 42 });
  const refused = store.bulkBookmarkFiltered("tab", true, {});
  assert.equal(refused.affected, 0);
  assert.equal(refused.wholeTab, true);
  assert.equal(store.bulkBookmarkFiltered("tab", true, { confirmWholeTab: true }).affected, 42);
  assert.equal(store.bulkBookmarkFiltered("tab", false, {}).wholeTab, undefined);
});

test("deleteTag removes the tag from every row", () => {
  const { store, has } = makeTab({ tags: [[1, "Noise"], [2, "Noise"], [3, "Keep"]] });
  const res = store.deleteTag("tab", "Noise");
  assert.equal(res.ok, true);
  assert.equal(res.removed, 2);
  assert.equal(has(1, "Noise"), false);
  assert.equal(has(3, "Keep"), true);
});

test("renameTag merges into an existing destination instead of failing on the PK", () => {
  // Row 2 carries BOTH spellings — after the merge it must hold exactly one.
  const { store, has, meta } = makeTab({
    tags: [[1, "suspicious"], [2, "suspicious"], [2, "Suspicious"], [3, "Suspicious"]],
  });
  const res = store.renameTag("tab", "suspicious", "Suspicious");
  assert.equal(res.ok, true);
  assert.equal(res.renamed, 1);  // row 1 moved
  assert.equal(res.merged, 1);   // row 2 collided and was dropped
  assert.equal(has(1, "Suspicious"), true);
  assert.equal(has(2, "Suspicious"), true);
  assert.equal([...meta.tagSet].filter((k) => k.endsWith(" suspicious")).length, 0);
});

test("mergeDuplicateTags collapses case/whitespace variants into the most-used spelling", () => {
  const { store } = makeTab({
    tags: [[1, "C2"], [2, "C2"], [3, "C2"], [4, "c2"], [5, "C2 "], [6, "Exfil"]],
  });
  const res = store.mergeDuplicateTags("tab");
  assert.equal(res.ok, true);
  const tags = store.getAllTags("tab").map((r) => r.tag).sort();
  assert.deepEqual(tags, ["C2", "Exfil"]);
  assert.equal(store.getAllTags("tab").find((r) => r.tag === "C2").cnt, 5);
});

test("bulkAddTags normalizes and reports what it wrote", () => {
  const { store, has } = makeTab();
  const res = store.bulkAddTags("tab", { 1: ["  Recon "], 2: ["Recon", ""], bad: ["Nope"] });
  assert.equal(res.ok, true);
  assert.equal(res.changed, 2);
  assert.equal(has(1, "Recon"), true);
  assert.equal(has(2, "Recon"), true);
});

test("setBookmarks reports counts and ignores junk IDs", () => {
  const { store } = makeTab();
  const res = store.setBookmarks("tab", [1, 2, "2", 0, -5], true);
  assert.deepEqual(res, { requested: 2, changed: 2 });
  assert.equal(store.getBookmarkCount("tab"), 2);
  assert.deepEqual(store.setBookmarks("tab", [1], false), { requested: 1, changed: 1 });
});

test("mutators return null for an unknown tab instead of pretending to succeed", () => {
  const { store } = makeTab();
  assert.equal(store.addTag("nope", 1, "X"), null);
  assert.equal(store.toggleBookmark("nope", 1), null);
  assert.equal(store.setBookmarks("nope", [1], true), null);
  assert.equal(store.renameTag("nope", "a", "b"), null);
  assert.equal(store.deleteTag("nope", "a"), null);
});

test("countFiltered previews the write population without writing", () => {
  const { store, meta } = makeTab({ rowCount: 900 });
  const before = meta.tagSet.size;
  assert.deepEqual(store.countFiltered("tab", {}), { count: 900, scoped: false, totalRows: 900 });
  assert.deepEqual(store.countFiltered("tab", { rowIdFilter: [1, 2] }), { count: 2, scoped: true, totalRows: 900 });
  assert.equal(meta.tagSet.size, before);
});

test("large selections are written in multi-row statements with exact counts", () => {
  // Selections past the small-batch size take the multi-row INSERT/DELETE path.
  const ids = Array.from({ length: 150 }, (_, i) => i + 1);
  const { store, has } = makeTab({ rowCount: 200, tags: [[10, "Bulk"]], bookmarks: [20] });
  assert.equal(store.setTagOnRows("tab", ids, "Bulk", true).changed, 149);
  assert.equal(has(150, "Bulk"), true);
  assert.equal(store.setTagOnRows("tab", ids.slice(0, 100), "Bulk", false).changed, 100);
  assert.equal(has(100, "Bulk"), false);
  assert.equal(has(101, "Bulk"), true);
  assert.deepEqual(store.setBookmarks("tab", ids, true), { requested: 150, changed: 149 });
  assert.deepEqual(store.setBookmarks("tab", ids, false), { requested: 150, changed: 150 });
  const tagMap = Object.fromEntries(ids.map((id) => [id, ["A", "B"]]));
  assert.deepEqual(store.bulkAddTags("tab", tagMap), { ok: true, changed: 300 });
});
