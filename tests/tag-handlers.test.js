const test = require("node:test");
const assert = require("node:assert/strict");

const registerTagHandlers = require("../electron/ipc/tag-handlers");

function setupHandlers() {
  const handlers = {};
  const calls = [];
  const db = {
    toggleBookmark(...args) { calls.push(["toggleBookmark", args]); return true; },
    setBookmarks(...args) { calls.push(["setBookmarks", args]); return { requested: 2, changed: 2 }; },
    getBookmarkCount(...args) { calls.push(["getBookmarkCount", args]); return 7; },
    addTag(...args) { calls.push(["addTag", args]); return { ok: true, tag: "Important", requested: 1, changed: 1 }; },
    removeTag(...args) { calls.push(["removeTag", args]); return { ok: true, tag: "Important", requested: 1, changed: 1 }; },
    setTagOnRows(...args) { calls.push(["setTagOnRows", args]); return { ok: true, tag: "Important", requested: 3, changed: 2 }; },
    getAllTags(...args) { calls.push(["getAllTags", args]); return [{ tag: "Important", cnt: 2 }]; },
    getAllTagData(...args) { calls.push(["getAllTagData", args]); return [{ rowid: 1, tag: "Important" }]; },
    getTagsForRows(...args) { calls.push(["getTagsForRows", args]); return { 1: ["Important"] }; },
    renameTag(...args) { calls.push(["renameTag", args]); return { ok: true, renamed: 4, merged: 1 }; },
    deleteTag(...args) { calls.push(["deleteTag", args]); return { ok: true, removed: 9 }; },
    mergeDuplicateTags(...args) { calls.push(["mergeDuplicateTags", args]); return { ok: true, merges: [] }; },
    bulkAddTags(...args) { calls.push(["bulkAddTags", args]); return { ok: true, changed: 1 }; },
    bulkTagByTimeRange(...args) { calls.push(["bulkTagByTimeRange", args]); return { taggedCount: 3 }; },
    countFiltered(...args) { calls.push(["countFiltered", args]); return { count: 12, scoped: true, totalRows: 99 }; },
    bulkTagFiltered(...args) { calls.push(["bulkTagFiltered", args]); return { tagged: 4 }; },
    bulkUntagFiltered(...args) { calls.push(["bulkUntagFiltered", args]); return { untagged: 4 }; },
    bulkBookmarkFiltered(...args) { calls.push(["bulkBookmarkFiltered", args]); return { affected: 5 }; },
  };
  registerTagHandlers((channel, handler) => { handlers[channel] = handler; }, () => {}, { db });
  return { handlers, calls };
}

test("tag IPC handlers destructure preload object payloads", () => {
  const { handlers, calls } = setupHandlers();
  const options = { columnFilters: { EventId: "4624" } };
  const tagMap = { 1: ["Important"] };
  const ranges = [{ from: "2026-01-01 00:00", to: "2026-01-01 01:00", tag: "Session" }];

  assert.equal(handlers["toggle-bookmark"](null, { tabId: "tab-1", rowId: 10 }), true);
  assert.deepEqual(handlers["set-bookmarks"](null, { tabId: "tab-1", rowIds: [1, 2], add: true }), { requested: 2, changed: 2 });
  assert.equal(handlers["get-bookmark-count"](null, { tabId: "tab-1" }), 7);
  assert.deepEqual(handlers["add-tag"](null, { tabId: "tab-1", rowId: 11, tag: "Important" }), { ok: true, tag: "Important", requested: 1, changed: 1 });
  assert.deepEqual(handlers["remove-tag"](null, { tabId: "tab-1", rowId: 11, tag: "Important" }), { ok: true, tag: "Important", requested: 1, changed: 1 });
  assert.deepEqual(handlers["set-tag-on-rows"](null, { tabId: "tab-1", rowIds: [1, 2, 3], tag: "Important", add: true }), { ok: true, tag: "Important", requested: 3, changed: 2 });
  assert.deepEqual(handlers["get-all-tags"](null, { tabId: "tab-1" }), [{ tag: "Important", cnt: 2 }]);
  assert.deepEqual(handlers["get-all-tag-data"](null, { tabId: "tab-1" }), [{ rowid: 1, tag: "Important" }]);
  assert.deepEqual(handlers["get-tags-for-rows"](null, { tabId: "tab-1", rowIds: [1] }), { 1: ["Important"] });
  assert.deepEqual(handlers["rename-tag"](null, { tabId: "tab-1", from: "old", to: "new" }), { ok: true, renamed: 4, merged: 1 });
  assert.deepEqual(handlers["delete-tag"](null, { tabId: "tab-1", tag: "old" }), { ok: true, removed: 9 });
  assert.deepEqual(handlers["merge-duplicate-tags"](null, { tabId: "tab-1" }), { ok: true, merges: [] });
  assert.deepEqual(handlers["bulk-add-tags"](null, { tabId: "tab-1", tagMap }), { ok: true, changed: 1 });
  assert.deepEqual(handlers["bulk-tag-by-time-range"](null, { tabId: "tab-1", colName: "datetime", ranges }), { taggedCount: 3 });
  assert.deepEqual(handlers["count-filtered-rows"](null, { tabId: "tab-1", options }), { count: 12, scoped: true, totalRows: 99 });
  assert.deepEqual(handlers["bulk-tag-filtered"](null, { tabId: "tab-1", tag: "Important", options }), { tagged: 4 });
  assert.deepEqual(handlers["bulk-untag-filtered"](null, { tabId: "tab-1", tag: "Important", options }), { untagged: 4 });
  assert.deepEqual(handlers["bulk-bookmark-filtered"](null, { tabId: "tab-1", add: false, options }), { affected: 5 });

  assert.deepEqual(calls, [
    ["toggleBookmark", ["tab-1", 10]],
    ["setBookmarks", ["tab-1", [1, 2], true]],
    ["getBookmarkCount", ["tab-1"]],
    ["addTag", ["tab-1", 11, "Important"]],
    ["removeTag", ["tab-1", 11, "Important"]],
    ["setTagOnRows", ["tab-1", [1, 2, 3], "Important", true]],
    ["getAllTags", ["tab-1"]],
    ["getAllTagData", ["tab-1"]],
    ["getTagsForRows", ["tab-1", [1]]],
    ["renameTag", ["tab-1", "old", "new"]],
    ["deleteTag", ["tab-1", "old"]],
    ["mergeDuplicateTags", ["tab-1"]],
    ["bulkAddTags", ["tab-1", tagMap]],
    ["bulkTagByTimeRange", ["tab-1", "datetime", ranges]],
    ["countFiltered", ["tab-1", options]],
    ["bulkTagFiltered", ["tab-1", "Important", options]],
    ["bulkUntagFiltered", ["tab-1", "Important", options]],
    ["bulkBookmarkFiltered", ["tab-1", false, options]],
  ]);
});

test("set-tag-on-rows defaults to adding when `add` is omitted", () => {
  const { handlers, calls } = setupHandlers();
  handlers["set-tag-on-rows"](null, { tabId: "tab-1", rowIds: [4], tag: "C2" });
  assert.deepEqual(calls.at(-1), ["setTagOnRows", ["tab-1", [4], "C2", true]]);
});

test("bulk write handlers surface the store's refusal instead of swallowing it", () => {
  const handlers = {};
  registerTagHandlers((channel, handler) => { handlers[channel] = handler; }, () => {}, {
    db: {
      bulkTagFiltered: () => ({ tagged: 0, wholeTab: true, error: "Refused to tag: no filter or selection is active" }),
      bulkBookmarkFiltered: () => ({ affected: 0, wholeTab: true, error: "Refused to bookmark" }),
    },
  });
  const tagRes = handlers["bulk-tag-filtered"](null, { tabId: "t", tag: "x", options: {} });
  assert.equal(tagRes.tagged, 0);
  assert.equal(tagRes.wholeTab, true);
  assert.match(tagRes.error, /Refused to tag/);
  assert.match(handlers["bulk-bookmark-filtered"](null, { tabId: "t", add: true, options: {} }).error, /Refused to bookmark/);
});
