import { create } from "zustand";
import { updateModal as buildModalUpdate } from "../modals/modalRegistry.js";

/**
 * useUIStore — Global UI preferences and transient menu/modal state.
 *
 * These are values that any component in the app might need to read
 * (e.g., theme, font size) or set (e.g., opening a modal).
 * Extracted from App.jsx to avoid prop-drilling.
 */
const useUIStore = create((set) => ({
  // ── Preferences ──────────────────────────────────────────────────
  themeName: "dark",
  fontSize: 12,
  timezone: "UTC",
  dateTimeFormat: "yyyy-MM-dd HH:mm:ss",

  setThemeName: (v) => set((s) => ({ themeName: typeof v === "function" ? v(s.themeName) : v })),
  setFontSize: (v) => set((s) => ({ fontSize: typeof v === "function" ? v(s.fontSize) : v })),
  setTimezone: (v) => set({ timezone: v }),
  setDateTimeFormat: (v) => set({ dateTimeFormat: v }),

  // ── Triage-collection hand-off ───────────────────────────────────
  // Set by TriageCollectionModal when it queues an import batch; App.jsx watches the
  // import-complete/-error events for these tab ids and, once they are all terminal,
  // launches the Lateral Movement Tracker across them.
  pendingTriageBatch: null,
  setPendingTriageBatch: (v) => set({ pendingTriageBatch: v }),

  // ── Menu open/close state ────────────────────────────────────────
  fileMenuOpen: false,
  viewMenuOpen: false,
  toolsOpen: false,
  toolsMenuExpanded: {},
  actionsMenuOpen: false,
  helpMenuOpen: false,

  setFileMenuOpen: (v) => set((s) => ({ fileMenuOpen: typeof v === "function" ? v(s.fileMenuOpen) : v })),
  setViewMenuOpen: (v) => set((s) => ({ viewMenuOpen: typeof v === "function" ? v(s.viewMenuOpen) : v })),
  setToolsOpen: (v) => set((s) => ({ toolsOpen: typeof v === "function" ? v(s.toolsOpen) : v })),
  setToolsMenuExpanded: (v) => set((s) => ({ toolsMenuExpanded: typeof v === "function" ? v(s.toolsMenuExpanded) : v })),
  setActionsMenuOpen: (v) => set((s) => ({ actionsMenuOpen: typeof v === "function" ? v(s.actionsMenuOpen) : v })),
  setHelpMenuOpen: (v) => set((s) => ({ helpMenuOpen: typeof v === "function" ? v(s.helpMenuOpen) : v })),

  // Close all menus at once (useful for blur/escape handlers)
  closeAllMenus: () => set({
    fileMenuOpen: false,
    viewMenuOpen: false,
    toolsOpen: false,
    actionsMenuOpen: false,
    helpMenuOpen: false,
  }),

  // ── Modal state ──────────────────────────────────────────────────
  modal: null,
  setModal: (v) => set(typeof v === "function" ? (s) => ({ modal: v(s.modal) }) : { modal: v }),
  updateModal: (type, updater) => set((s) => ({ modal: buildModalUpdate(type, updater)(s.modal) })),

  // ── Transient UI ─────────────────────────────────────────────────
  dragOver: false,
  setDragOver: (v) => set({ dragOver: v }),

  detailPanelOpen: true,
  setDetailPanelOpen: (v) => set({ detailPanelOpen: v }),

  detailPanelHeight: 200,
  setDetailPanelHeight: (v) => set({ detailPanelHeight: v }),

  histogramVisible: false,
  setHistogramVisible: (v) => set((s) => ({ histogramVisible: typeof v === "function" ? v(s.histogramVisible) : v })),

  histogramHeight: 160,
  setHistogramHeight: (v) => set({ histogramHeight: v }),

  histGranularity: "day",
  setHistGranularity: (v) => set({ histGranularity: v }),

  // ── Refresh callback (registered by App.jsx, called by modals) ────
  refreshCallback: null,
  setRefreshCallback: (fn) => set({ refreshCallback: fn }),

  // ── Row-metadata cache invalidator (registered by App.jsx) ────────
  // App caches each query window keyed by filter signature, and that cache
  // carries a SNAPSHOT of bookmarkedSet/rowTags. Anything that writes tags or
  // bookmarks must call this before refreshCallback, or the refresh serves the
  // pre-write snapshot back and the change appears to have been discarded.
  invalidateRowMeta: null,
  setInvalidateRowMeta: (fn) => set({ invalidateRowMeta: fn }),

  // ── Cross-tab search ──────────────────────────────────────────────
  crossFind: null,           // { term, results: [{tabId, name, count}] }
  crossTabCounts: null,      // auto inline: { term, mode, results }
  crossTabOpen: true,

  setCrossFind: (v) => set({ crossFind: v }),
  setCrossTabCounts: (v) => set({ crossTabCounts: v }),
  setCrossTabOpen: (v) => set({ crossTabOpen: v }),

  // ── Extract / Updater ─────────────────────────────────────────────
  extracting: false,
  extractProgress: null,
  checkingForUpdates: false,
  updaterPopup: null,
  recentFiles: [],

  setExtracting: (v) => set({ extracting: v }),
  setExtractProgress: (v) => set({ extractProgress: v }),
  setCheckingForUpdates: (v) => set({ checkingForUpdates: v }),
  setUpdaterPopup: (v) => set((s) => ({ updaterPopup: typeof v === "function" ? v(s.updaterPopup) : v })),
  setRecentFiles: (v) => set({ recentFiles: v }),

  // ── Filter / Search ───────────────────────────────────────────────
  filterDropdown: null,      // { colName, x, y, ... } — active filter dropdown
  dateRangeDropdown: null,   // { colName, x, y, from, to }
  proximityFilter: null,
  filterPresets: [],
  colMgrSearch: "",

  setFilterDropdown: (v) => set({ filterDropdown: v }),
  setDateRangeDropdown: (v) => set({ dateRangeDropdown: v }),
  setProximityFilter: (v) => set({ proximityFilter: v }),
  setFilterPresets: (v) => set({ filterPresets: v }),
  setColMgrSearch: (v) => set({ colMgrSearch: v }),

  // ── Histogram ─────────────────────────────────────────────────────
  histogramCol: null,
  histogramData: [],
  histogramLoaded: false,

  setHistogramCol: (v) => set({ histogramCol: v }),
  setHistogramData: (v) => set({ histogramData: v }),
  setHistogramLoaded: (v) => set({ histogramLoaded: v }),

  // ── Process Inspector profile ─────────────────────────────────────
  piAnalystProfile: null,
  setPiAnalystProfile: (v) => set((state) => ({
    piAnalystProfile: typeof v === "function" ? v(state.piAnalystProfile) : v,
  })),
}));

export default useUIStore;
