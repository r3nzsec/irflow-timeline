const test = require("node:test");
const assert = require("node:assert/strict");

const tagStore = require("../electron/db/tag-store");
const { normalizeTagName, normalizeRowIdList } = tagStore;

/**
 * In-memory stand-in for a tab's better-sqlite3 handle. `tagSet` holds
 * "rowid tag" keys so PRIMARY KEY(rowid, tag) semantics (INSERT OR IGNORE
 * reporting 0 changes on a duplicate) are reproduced faithfully.
 */
function makeTab({ rowCount = 100, tags = [], bookmarks = [] } = {}) {
  const tagSet = new Set(tags.map(([id, t]) => `${id} ${t}`));
  const bmSet = new Set(bookmarks);
  const sqlLog = [];

  const collapse = (sql) => sql.replace(/\s+/g, " ").trim();
  const tagOf = (key) => key.slice(key.indexOf(" ") + 1);
  const idOf = (key) => key.slice(0, key.indexOf(" "));

  const meta = {
    rowCount,
    tagSet,
    bmSet,
    sqlLog,
    indexesBuilding: true, // deliberately "mid index build" — writes must still land
    ftsBuilding: true,
    tagInsertStmt: {
      run(id, tag) {
        const key = `${id} ${tag}`;
        if (tagSet.has(key)) return { changes: 0 };
        tagSet.add(key);
        return { changes: 1 };
      },
    },
    tagDeleteStmt: {
      run(id, tag) {
        return { changes: tagSet.delete(`${id} ${tag}`) ? 1 : 0 };
      },
    },
    bmInsertStmt: { run(id) { if (bmSet.has(id)) return { changes: 0 }; bmSet.add(id); return { changes: 1 }; } },
    bmDeleteStmt: { run(id) { return { changes: bmSet.delete(id) ? 1 : 0 }; } },
    bmCheckStmt: { get(id) { return bmSet.has(id) ? { rowid: id } : undefined; } },
    bmCountStmt: { get() { return { cnt: bmSet.size }; } },
    db: {
      transaction(fn) { return (...args) => fn(...args); },
      prepare(sql) {
        const flat = collapse(sql);
        sqlLog.push(flat);
        return {
          run(...params) {
            if (/^INSERT OR IGNORE INTO tags/i.test(flat)) {
              // INSERT ... SELECT rowid, ? FROM data [WHERE ...]
              const tag = params[0];
              const targets = flat.includes("WHERE")
                ? [1, 2]
                : Array.from({ length: rowCount }, (_, i) => i + 1);
              let changes = 0;
              for (const id of targets) {
                const key = `${id} ${tag}`;
                if (!tagSet.has(key)) { tagSet.add(key); changes++; }
              }
              return { changes };
            }
            if (/^DELETE FROM tags WHERE tag = \?/i.test(flat)) {
              const tag = params[0];
              let changes = 0;
              for (const key of [...tagSet]) if (tagOf(key) === tag) { tagSet.delete(key); changes++; }
              return { changes };
            }
            if (/^UPDATE OR IGNORE tags SET tag = \? WHERE tag = \?$/i.test(flat)) {
              const [to, from] = params;
              let changes = 0;
              for (const key of [...tagSet]) {
                if (tagOf(key) !== from) continue;
                const next = `${idOf(key)} ${to}`;
                if (tagSet.has(next)) continue; // PK collision, IGNOREd; row left behind
                tagSet.delete(key);
                tagSet.add(next);
                changes++;
              }
              return { changes };
            }
            if (/INSERT OR IGNORE INTO bookmarks/i.test(flat)) {
              let changes = 0;
              for (let id = 1; id <= rowCount; id++) if (!bmSet.has(id)) { bmSet.add(id); changes++; }
              return { changes };
            }
            return { changes: 0 };
          },
          get() {
            if (/COUNT\(\*\) AS cnt FROM data/i.test(flat)) {
              return { cnt: flat.includes("WHERE") ? 2 : rowCount };
            }
            return { cnt: 0 };
          },
          all() {
            const counts = new Map();
            for (const key of tagSet) {
              const tag = tagOf(key);
              counts.set(tag, (counts.get(tag) || 0) + 1);
            }
            return [...counts.entries()]
              .map(([tag, cnt]) => ({ tag, cnt }))
              .sort((a, b) => b.cnt - a.cnt || a.tag.localeCompare(b.tag));
          },
        };
      },
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
  return { store, meta, has: (id, tag) => tagSet.has(`${id} ${tag}`) };
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
