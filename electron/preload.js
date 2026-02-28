const { contextBridge, ipcRenderer, webUtils } = require("electron");

contextBridge.exposeInMainWorld("tle", {
  // File operations
  openFileDialog: () => ipcRenderer.invoke("open-file-dialog"),
  importFiles: (filePaths) => ipcRenderer.invoke("import-files", { filePaths }),
  getPathForFile: (file) => webUtils.getPathForFile(file),

  // Data queries (SQLite-backed)
  queryRows: (tabId, options) => ipcRenderer.invoke("query-rows", { tabId, options }),
  toggleBookmark: (tabId, rowId) => ipcRenderer.invoke("toggle-bookmark", { tabId, rowId }),
  setBookmarks: (tabId, rowIds, add) => ipcRenderer.invoke("set-bookmarks", { tabId, rowIds, add }),
  getBookmarkCount: (tabId) => ipcRenderer.invoke("get-bookmark-count", { tabId }),
  closeTab: (tabId) => ipcRenderer.invoke("close-tab", { tabId }),
  getColumnStats: (tabId, colName, options) => ipcRenderer.invoke("get-column-stats", { tabId, colName, options }),
  getColumnUniqueValues: (tabId, colName, options) => ipcRenderer.invoke("get-column-unique-values", { tabId, colName, options }),
  getGroupValues: (tabId, groupCol, options) => ipcRenderer.invoke("get-group-values", { tabId, groupCol, options }),
  getTabInfo: (tabId) => ipcRenderer.invoke("get-tab-info", { tabId }),
  getFtsStatus: (tabId) => ipcRenderer.invoke("get-fts-status", { tabId }),
  exportFiltered: (tabId, options) => ipcRenderer.invoke("export-filtered", { tabId, options }),
  generateReport: (tabId, fileName, tagColors) => ipcRenderer.invoke("generate-report", { tabId, fileName, tagColors }),
  selectSheet: (data) => ipcRenderer.invoke("select-sheet", data),
  searchCount: (tabId, searchTerm, searchMode, searchCondition) => ipcRenderer.invoke("search-count", { tabId, searchTerm, searchMode, searchCondition }),
  getHistogramData: (tabId, colName, options) => ipcRenderer.invoke("get-histogram-data", { tabId, colName, options }),
  getStackingData: (tabId, colName, options) => ipcRenderer.invoke("get-stacking-data", { tabId, colName, options }),
  getGapAnalysis: (tabId, colName, gapThresholdMinutes, options) => ipcRenderer.invoke("get-gap-analysis", { tabId, colName, gapThresholdMinutes, options }),
  getLogSourceCoverage: (tabId, sourceCol, tsCol, options) => ipcRenderer.invoke("get-log-source-coverage", { tabId, sourceCol, tsCol, options }),
  getBurstAnalysis: (tabId, colName, windowMinutes, thresholdMultiplier, options) => ipcRenderer.invoke("get-burst-analysis", { tabId, colName, windowMinutes, thresholdMultiplier, options }),
  getProcessTree: (tabId, options) => ipcRenderer.invoke("get-process-tree", { tabId, options }),
  getLateralMovement: (tabId, options) => ipcRenderer.invoke("get-lateral-movement", { tabId, options }),
  getPersistenceAnalysis: (tabId, options) => ipcRenderer.invoke("get-persistence-analysis", { tabId, options }),
  bulkTagByTimeRange: (tabId, colName, ranges) => ipcRenderer.invoke("bulk-tag-by-time-range", { tabId, colName, ranges }),
  mergeTabs: (mergedTabId, sources) => ipcRenderer.invoke("merge-tabs", { mergedTabId, sources }),
  getEmptyColumns: (tabId) => ipcRenderer.invoke("get-empty-columns", { tabId }),

  // Tag operations
  addTag: (tabId, rowId, tag) => ipcRenderer.invoke("add-tag", { tabId, rowId, tag }),
  removeTag: (tabId, rowId, tag) => ipcRenderer.invoke("remove-tag", { tabId, rowId, tag }),
  getAllTags: (tabId) => ipcRenderer.invoke("get-all-tags", { tabId }),
  getAllTagData: (tabId) => ipcRenderer.invoke("get-all-tag-data", { tabId }),
  getBookmarkedIds: (tabId) => ipcRenderer.invoke("get-bookmarked-ids", { tabId }),
  bulkAddTags: (tabId, tagMap) => ipcRenderer.invoke("bulk-add-tags", { tabId, tagMap }),
  bulkTagFiltered: (tabId, tag, options) => ipcRenderer.invoke("bulk-tag-filtered", { tabId, tag, options }),
  bulkBookmarkFiltered: (tabId, add, options) => ipcRenderer.invoke("bulk-bookmark-filtered", { tabId, add, options }),

  // IOC matching
  loadIocFile: () => ipcRenderer.invoke("load-ioc-file"),
  matchIocs: (tabId, iocPatterns, batchSize) => ipcRenderer.invoke("match-iocs", { tabId, iocPatterns, batchSize }),

  // Session operations
  saveSession: (data) => ipcRenderer.invoke("save-session", { sessionData: data }),
  loadSession: () => ipcRenderer.invoke("load-session"),
  importFileForRestore: (filePath, sheetName) => ipcRenderer.invoke("import-file-for-restore", { filePath, sheetName }),

  // Filter presets (persistent)
  loadFilterPresets: () => ipcRenderer.invoke("load-filter-presets"),
  saveFilterPresets: (presets) => ipcRenderer.invoke("save-filter-presets", { presets }),

  // Event listeners from main process
  onImportStart: (cb) => ipcRenderer.on("import-start", (_, d) => cb(d)),
  onImportProgress: (cb) => ipcRenderer.on("import-progress", (_, d) => cb(d)),
  onImportComplete: (cb) => ipcRenderer.on("import-complete", (_, d) => cb(d)),
  onImportError: (cb) => ipcRenderer.on("import-error", (_, d) => cb(d)),
  onImportQueue: (cb) => ipcRenderer.on("import-queue", (_, d) => cb(d)),
  onExportProgress: (cb) => ipcRenderer.on("export-progress", (_, d) => cb(d)),
  onFtsProgress: (cb) => ipcRenderer.on("fts-progress", (_, d) => cb(d)),
  onIndexProgress: (cb) => ipcRenderer.on("index-progress", (_, d) => cb(d)),
  onSheetSelection: (cb) => ipcRenderer.on("sheet-selection", (_, d) => cb(d)),

  // Menu triggers
  onTriggerOpen: (cb) => ipcRenderer.on("trigger-open", () => cb()),
  onTriggerExport: (cb) => ipcRenderer.on("trigger-export", () => cb()),
  onTriggerGenerateReport: (cb) => ipcRenderer.on("trigger-generate-report", () => cb()),
  onTriggerSearch: (cb) => ipcRenderer.on("trigger-search", () => cb()),
  onTriggerBookmarkToggle: (cb) => ipcRenderer.on("trigger-bookmark-toggle", () => cb()),
  onTriggerColumnManager: (cb) => ipcRenderer.on("trigger-column-manager", () => cb()),
  onTriggerColorRules: (cb) => ipcRenderer.on("trigger-color-rules", () => cb()),
  onTriggerShortcuts: (cb) => ipcRenderer.on("trigger-shortcuts", () => cb()),
  onTriggerCrossFind: (cb) => ipcRenderer.on("trigger-crossfind", () => cb()),
  onTriggerSaveSession: (cb) => ipcRenderer.on("trigger-save-session", () => cb()),
  onTriggerLoadSession: (cb) => ipcRenderer.on("trigger-load-session", () => cb()),
  onTriggerCloseTab: (cb) => ipcRenderer.on("trigger-close-tab", () => cb()),
  onTriggerCloseAllTabs: (cb) => ipcRenderer.on("trigger-close-all-tabs", () => cb()),
  onNativeContextMenu: (cb) => ipcRenderer.on("native-context-menu", (_, d) => cb(d)),

  // Tools menu triggers
  onSetDatetimeFormat: (cb) => ipcRenderer.on("set-datetime-format", (_, fmt) => cb(fmt)),
  onSetTimezone: (cb) => ipcRenderer.on("set-timezone", (_, tz) => cb(tz)),
  onSetFontSize: (cb) => ipcRenderer.on("set-font-size", (_, val) => cb(val)),
  onTriggerResetColumns: (cb) => ipcRenderer.on("trigger-reset-columns", () => cb()),
  onSetTheme: (cb) => ipcRenderer.on("set-theme", (_, name) => cb(name)),
  onTriggerHistogram: (cb) => ipcRenderer.on("trigger-histogram", () => cb()),

  // Cleanup — remove all listeners for a channel
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel),
});
