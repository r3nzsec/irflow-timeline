module.exports = function registerTagHandlers(safeHandle, safeSend, { db }) {
  safeHandle('toggle-bookmark', (_e, { tabId, rowId }) => {
    return db.toggleBookmark(tabId, rowId);
  });

  safeHandle('set-bookmarks', (_e, { tabId, rowIds, add }) => {
    return db.setBookmarks(tabId, rowIds, add) || { requested: 0, changed: 0 };
  });

  safeHandle('get-bookmark-count', (_e, { tabId }) => {
    return db.getBookmarkCount(tabId);
  });

  safeHandle('add-tag', (_e, { tabId, rowId, tag }) => {
    return db.addTag(tabId, rowId, tag);
  });

  safeHandle('remove-tag', (_e, { tabId, rowId, tag }) => {
    return db.removeTag(tabId, rowId, tag);
  });

  // One tag, many explicit rows, one transaction. The renderer uses this for
  // multi-row tagging instead of looping `add-tag` per row.
  safeHandle('set-tag-on-rows', (_e, { tabId, rowIds, tag, add = true }) => {
    return db.setTagOnRows(tabId, rowIds, tag, add);
  });

  safeHandle('get-all-tags', (_e, { tabId }) => {
    return db.getAllTags(tabId);
  });

  safeHandle('get-all-tag-data', (_e, { tabId }) => {
    return db.getAllTagData(tabId);
  });

  safeHandle('get-tags-for-rows', (_e, { tabId, rowIds }) => {
    return db.getTagsForRows(tabId, Array.isArray(rowIds) ? rowIds : []);
  });

  safeHandle('rename-tag', (_e, { tabId, from, to }) => {
    return db.renameTag(tabId, from, to);
  });

  safeHandle('delete-tag', (_e, { tabId, tag }) => {
    return db.deleteTag(tabId, tag);
  });

  safeHandle('merge-duplicate-tags', (_e, { tabId }) => {
    return db.mergeDuplicateTags(tabId);
  });

  safeHandle('bulk-add-tags', (_e, { tabId, tagMap }) => {
    return db.bulkAddTags(tabId, tagMap) || { ok: false, changed: 0 };
  });

  safeHandle('bulk-tag-by-time-range', (_e, { tabId, colName, ranges }) => {
    return db.bulkTagByTimeRange(tabId, colName, ranges);
  });

  safeHandle('count-filtered-rows', (_e, { tabId, options }) => {
    return db.countFiltered(tabId, options || {});
  });

  safeHandle('bulk-tag-filtered', (_e, { tabId, tag, options }) => {
    return db.bulkTagFiltered(tabId, tag, options);
  });

  safeHandle('bulk-untag-filtered', (_e, { tabId, tag, options }) => {
    return db.bulkUntagFiltered(tabId, tag, options);
  });

  safeHandle('bulk-bookmark-filtered', (_e, { tabId, add, options }) => {
    return db.bulkBookmarkFiltered(tabId, add, options);
  });
};
