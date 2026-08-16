import { lazy, Suspense, useState, useEffect, useRef, useCallback, useMemo, Fragment } from "react";
import { createPortal } from "react-dom";
// ── Extracted constants ──────────────────────────────────────────
import { ROW_HEIGHT, HEADER_HEIGHT, FILTER_HEIGHT, OVERSCAN, VIRTUAL_WINDOW, VIRTUAL_AHEAD, QUERY_DEBOUNCE, DETAIL_PANEL_HEIGHT_DEFAULT, DETAIL_PANEL_MIN_HEIGHT, DETAIL_PANEL_MAX_HEIGHT, TAG_COL_WIDTH_DEFAULT, TAG_COL_WIDTH_MIN, BKMK_COL_WIDTH, CHECKBOX_COL_WIDTH, VT_COL_WIDTH, EVIDENCE_COL_WIDTH, VT_COMPATIBLE_RE, MAX_PHYSICAL_H } from "./constants/grid.js";
import { THEMES } from "./constants/themes.js";
import { DT_FORMATS, TIMEZONES } from "./constants/datetime.js";
import { TAG_PRESETS } from "./constants/presets.js";

// ── Extracted utilities ──────────────────────────────────────────
import { formatBytes, formatNumber } from "./utils/format.js";
import { formatDateTime } from "./utils/datetime.js";
import { isIpcCancelled, isIpcError, ipcErrorMessage } from "./utils/ipc-result";
import { compileColorRules, applyColors, buildTimelineColorRules } from "./utils/color-rules.js";
import { detectKapeProfile, isChainsawDataset, isChainsawProcessDataset, isChainsawLogonDataset } from "./utils/dataset-detect.js";
import {
  checkboxFilterActive,
  isAiHistorySourceFormat,
  aiHistoryQueryIpcOptions,
  normalizeCheckboxFilterValues,
  resolveAiWorkspacePath,
  buildWorkspaceCorrelationTargets,
} from "./utils/ai-history-profile.js";
import { handleOpenFileDialogResult } from "./utils/open-file-result.js";
import { IOC_CATEGORY_PATTERNS } from "./utils/ioc-parsing.js";
import { getGridBodyViewportHeight, getGridContentWidth, getRowScrollTarget, getVisibleRowRange } from "./utils/grid-layout.js";
import { getSelectedRowCount, isRowSelected, selectRowIds, toggleRowSelection } from "./utils/row-selection.js";
import { effectiveSearchTerm, isSearchTooShort } from "./utils/search.js";

// ── Extracted components ─────────────────────────────────────────
import { BkmkIcon, CheckboxIcon } from "./components/icons.jsx";
import TabBar from "./components/TabBar.jsx";
import FilterBar, { SearchOptionsBar } from "./components/FilterBar.jsx";
import StatusBar from "./components/StatusBar.jsx";
import SelectionBar from "./components/SelectionBar.jsx";
import { Overlay, ColorModal, ColModal, ShortModal, SheetModal, ImportProgress, makeModalStyles } from "./components/InlineModals.jsx";
import { ConfirmDialog, ToastContainer, Loading } from "./components/primitives/index.js";
import useToastStore, { toast } from "./store/useToastStore.js";
import { ProcessAnalyzerRoot } from "./components/process-analyzer/index.js";
import {
  openColumnStatsModal,
  openIocLoadModal,
  openLateralMovementModal,
	  openProximityModal,
	  openSigmaModal,
  openSimpleModal,
  openStackingModal,
  openAiWorkspaceCorrelateModal,
  openAiHistoryProfileScanModal,
  updateModal,
} from "./modals/modalRegistry.js";
import { HOME_CAPABILITY_LAUNCHERS, buildLateralMovementCols } from "./utils/analyzer-launch.js";

// ── Custom hooks ────────────────────────────────────────────────
import useColumnOps from "./hooks/useColumnOps.js";

// ── Zustand stores ───────────────────────────────────────────────
import useUIStore from "./store/useUIStore.js";
import useTabStore from "./store/useTabStore.js";
import useGridInteractionStore from "./store/useGridInteractionStore.js";
import packageJson from "../package.json";

const APP_VERSION = packageJson.version;
const APP_DESCRIPTION = packageJson.description;

const MenuBar = lazy(() => import("./components/MenuBar.jsx"));
const VirtualGrid = lazy(() => import("./components/VirtualGrid.jsx"));
const LateralMovementModal = lazy(() => import("./components/modals/LateralMovementModal.jsx"));
const TriageCollectionModal = lazy(() => import("./components/modals/TriageCollectionModal.jsx"));
const PersistenceModal = lazy(() => import("./components/modals/PersistenceModal.jsx"));
const RansomwareModal = lazy(() => import("./components/modals/RansomwareModal.jsx"));
const UsnAnalysisModal = lazy(() => import("./components/modals/UsnAnalysisModal.jsx"));
const IocModal = lazy(() => import("./components/modals/IocModal.jsx"));
const GapAnalysisModal = lazy(() => import("./components/modals/GapAnalysisModal.jsx"));
const LogSourceCoverageModal = lazy(() => import("./components/modals/LogSourceCoverageModal.jsx"));
const BurstAnalysisModal = lazy(() => import("./components/modals/BurstAnalysisModal.jsx"));
const TimestompingModal = lazy(() => import("./components/modals/TimestompingModal.jsx"));
const HeatmapModal = lazy(() => import("./components/modals/HeatmapModal.jsx"));
const AdsModal = lazy(() => import("./components/modals/AdsModal.jsx"));
const StackingModal = lazy(() => import("./components/modals/StackingModal.jsx"));
const ColumnStatsModal = lazy(() => import("./components/modals/ColumnStatsModal.jsx"));
const PresetsModal = lazy(() => import("./components/modals/PresetsModal.jsx"));
const EditFilterModal = lazy(() => import("./components/modals/EditFilterModal.jsx"));
const BulkActionsModal = lazy(() => import("./components/modals/BulkActionsModal.jsx"));
const QuickHelpModal = lazy(() => import("./components/modals/QuickHelpModal.jsx"));
const SigmaRuleModal = lazy(() => import("./components/modals/SigmaRuleModal.jsx"));
const RdpBitmapCacheModal = lazy(() => import("./components/modals/RdpBitmapCacheModal.jsx"));
const AiHistoryProfileScanModal = lazy(() => import("./components/modals/AiHistoryProfileScanModal.jsx"));
const AiHistoryExtractModal = lazy(() => import("./components/modals/AiHistoryExtractModal.jsx"));
const AiWorkspaceCorrelateModal = lazy(() => import("./components/modals/AiWorkspaceCorrelateModal.jsx"));
const AiHistoryScopeModal = lazy(() => import("./components/modals/AiHistoryScopeModal.jsx"));
const AiSecretsModal = lazy(() => import("./components/modals/AiSecretsModal.jsx"));

function ModalChunkFallback({ th }) {
  return (
    <Overlay th={th}>
      <Loading label="Loading tool…" size="md" />
    </Overlay>
  );
}

function ShellChunkFallback({ th, label = "Loading controls…" }) {
  return (
    <div style={{ height: 42, display: "flex", alignItems: "center", padding: "0 14px", borderBottom: `1px solid ${th.border}`, background: th.panelBg }}>
      <Loading label={label} variant="compact" />
    </div>
  );
}

const rowIdFilterSignature = (rowIdFilter) => {
  if (!Array.isArray(rowIdFilter) || rowIdFilter.length === 0) return "";
  const first = rowIdFilter[0];
  const mid = rowIdFilter[Math.floor(rowIdFilter.length / 2)];
  const last = rowIdFilter[rowIdFilter.length - 1];
  let checksum = 0;
  for (const value of rowIdFilter) {
    const id = Number(value) || 0;
    checksum = (checksum + ((id * 2654435761) >>> 0)) >>> 0;
  }
  return `${rowIdFilter.length}:${first}:${mid}:${last}:${checksum}`;
};

const debugRightClick = (message, data = {}) => {
  try {
    if (typeof window !== "undefined") {
      window.tle?.debugLog?.({ scope: "RIGHTCLICK", message, data });
    }
  } catch {}
};

/** Header-only widths — cheap first paint after a multi-GB import. */
function fastColumnWidths(headers) {
  const cw = {};
  for (const h of headers) {
    cw[h] = Math.max(80, Math.min(h.length * 8 + 36, 400));
  }
  return cw;
}

function measureColumnWidths(headers, initialRows) {
  const cw = {};
  const sampleRows = initialRows.slice(0, 100);
  headers.forEach((h) => {
    const hLen = h.length * 8 + 36;
    const lengths = sampleRows.map((r) => (r[h] || "").length).filter((l) => l > 0);
    const meanLen = lengths.length > 0 ? lengths.reduce((a, b) => a + b, 0) / lengths.length : 0;
    const meanPx = meanLen * 6.5 + 16;
    cw[h] = Math.max(80, Math.min(Math.max(hLen, Math.round(meanPx)), 400));
  });
  return cw;
}

const LARGE_TAB_HISTOGRAM_DEFER_MS = 60_000;

function fetchLimitForTab(tab) {
  return VIRTUAL_WINDOW;
}

function fetchAheadForLimit(limit) {
  return Math.max(100, Math.min(VIRTUAL_AHEAD, Math.floor((limit || VIRTUAL_WINDOW) / 3)));
}

function rowWindowCovers(rowOffset, rowCount, firstVisibleRow, visibleRowCount) {
  const start = rowOffset || 0;
  const end = start + (rowCount || 0);
  return firstVisibleRow >= start && firstVisibleRow + visibleRowCount <= end;
}

// ── Main App ───────────────────────────────────────────────────────
export default function App() {
  // ── Zustand: tab state ──────────────────────────────────────────
  const tabs = useTabStore((s) => s.tabs);
  const setTabs = useTabStore((s) => s.setTabs);
  const activeTab = useTabStore((s) => s.activeTab);
  const setActiveTab = useTabStore((s) => s.setActiveTab);
  const tabFilter = useTabStore((s) => s.tabFilter);
  const setTabFilter = useTabStore((s) => s.setTabFilter);
  const importingTabs = useTabStore((s) => s.importingTabs);
  const setImportingTabs = useTabStore((s) => s.setImportingTabs);
  const importQueue = useTabStore((s) => s.importQueue);
  const setImportQueue = useTabStore((s) => s.setImportQueue);

  // ── Zustand: UI state ───────────────────────────────────────────
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const setRefreshCallback = useUIStore((s) => s.setRefreshCallback);
  const dragOver = useUIStore((s) => s.dragOver);
  const setDragOver = useUIStore((s) => s.setDragOver);
  const themeName = useUIStore((s) => s.themeName);
  const setThemeName = useUIStore((s) => s.setThemeName);
  const fontSize = useUIStore((s) => s.fontSize);
  const setFontSize = useUIStore((s) => s.setFontSize);
  const timezone = useUIStore((s) => s.timezone);
  const setTimezone = useUIStore((s) => s.setTimezone);
  const dateTimeFormat = useUIStore((s) => s.dateTimeFormat);
  const setDateTimeFormat = useUIStore((s) => s.setDateTimeFormat);
  const detailPanelOpen = useUIStore((s) => s.detailPanelOpen);
  const setDetailPanelOpen = useUIStore((s) => s.setDetailPanelOpen);
  const detailPanelHeight = useUIStore((s) => s.detailPanelHeight);
  const setDetailPanelHeight = useUIStore((s) => s.setDetailPanelHeight);
  const histogramVisible = useUIStore((s) => s.histogramVisible);
  const setHistogramVisible = useUIStore((s) => s.setHistogramVisible);
  const histogramHeight = useUIStore((s) => s.histogramHeight);
  const setHistogramHeight = useUIStore((s) => s.setHistogramHeight);
  const histGranularity = useUIStore((s) => s.histGranularity);
  const setHistGranularity = useUIStore((s) => s.setHistGranularity);
  const fileMenuOpen = useUIStore((s) => s.fileMenuOpen);
  const setFileMenuOpen = useUIStore((s) => s.setFileMenuOpen);
  const viewMenuOpen = useUIStore((s) => s.viewMenuOpen);
  const setViewMenuOpen = useUIStore((s) => s.setViewMenuOpen);
  const toolsOpen = useUIStore((s) => s.toolsOpen);
  const setToolsOpen = useUIStore((s) => s.setToolsOpen);
  const toolsMenuExpanded = useUIStore((s) => s.toolsMenuExpanded);
  const setToolsMenuExpanded = useUIStore((s) => s.setToolsMenuExpanded);
  const actionsMenuOpen = useUIStore((s) => s.actionsMenuOpen);
  const setActionsMenuOpen = useUIStore((s) => s.setActionsMenuOpen);
  const helpMenuOpen = useUIStore((s) => s.helpMenuOpen);
  const setHelpMenuOpen = useUIStore((s) => s.setHelpMenuOpen);
  // ── Grid interaction state (from store) ──────────────────────────
  const selectedRows = useGridInteractionStore((s) => s.selectedRows);
  const setSelectedRows = useGridInteractionStore((s) => s.setSelectedRows);
  const allRowsSelected = useGridInteractionStore((s) => s.allRowsSelected);
  const setAllRowsSelected = useGridInteractionStore((s) => s.setAllRowsSelected);
  const selectionTabId = useGridInteractionStore((s) => s.selectionTabId);
  const setSelectionTabId = useGridInteractionStore((s) => s.setSelectionTabId);
  const selectAllScopeSignature = useGridInteractionStore((s) => s.selectAllScopeSignature);
  const setSelectAllScopeSignature = useGridInteractionStore((s) => s.setSelectAllScopeSignature);
  const lastClickedRow = useGridInteractionStore((s) => s.lastClickedRow);
  const setLastClickedRow = useGridInteractionStore((s) => s.setLastClickedRow);
  const detailPanelRef = useRef(null);
  const detailResizeStartY = useRef(0);
  const detailResizeStartH = useRef(0);
  const copiedMsg = useGridInteractionStore((s) => s.copiedMsg);
  const setCopiedMsg = useGridInteractionStore((s) => s.setCopiedMsg);
  const cellPopup = useGridInteractionStore((s) => s.cellPopup);
  const setCellPopup = useGridInteractionStore((s) => s.setCellPopup);
  const [searchMatchIdx, setSearchMatchIdx] = useState(-1);
  const searchMatchIdxRef = useRef(-1);
  const searchNavigationPendingRef = useRef(false);
  const [searchMatchPosition, setSearchMatchPosition] = useState(-1);
  const [highlightMatchCount, setHighlightMatchCount] = useState(0);
  const [hiddenSelectionCount, setHiddenSelectionCount] = useState(0);
  const resizingCol = useGridInteractionStore((s) => s.resizingCol);
  const setResizingCol = useGridInteractionStore((s) => s.setResizingCol);
  const resizeX = useGridInteractionStore((s) => s.resizeX);
  const setResizeX = useGridInteractionStore((s) => s.setResizeX);
  const resizeW = useGridInteractionStore((s) => s.resizeW);
  const setResizeW = useGridInteractionStore((s) => s.setResizeW);
  const justResizedRef = useRef(false);

  // ── Context menus + dropdowns (from stores) ────────────────────────
  const contextMenu = useGridInteractionStore((s) => s.contextMenu);
  const setContextMenu = useGridInteractionStore((s) => s.setContextMenu);
  const rowContextMenu = useGridInteractionStore((s) => s.rowContextMenu);
  const setRowContextMenu = useGridInteractionStore((s) => s.setRowContextMenu);
  const cellContextMenu = useGridInteractionStore((s) => s.cellContextMenu);
  const setCellContextMenu = useGridInteractionStore((s) => s.setCellContextMenu);
  const selectedColumn = useGridInteractionStore((s) => s.selectedColumn);
  const setSelectedColumn = useGridInteractionStore((s) => s.setSelectedColumn);
  const searchLoading = useGridInteractionStore((s) => s.searchLoading);
  const setSearchLoading = useGridInteractionStore((s) => s.setSearchLoading);
  // Track search elapsed seconds — used by StatusBar to show extended feedback
  // ("Searching N rows… 3s") for slow LIKE-on-concat scans on huge datasets.
  // Without this, multi-second searches look like a frozen app.
  const [searchElapsed, setSearchElapsed] = useState(0);
  useEffect(() => {
    if (!searchLoading) { setSearchElapsed(0); return; }
    const start = Date.now();
    const id = setInterval(() => setSearchElapsed(Math.floor((Date.now() - start) / 1000)), 500);
    return () => clearInterval(id);
  }, [searchLoading]);
  const tagColWidth = useGridInteractionStore((s) => s.tagColWidth);
  const setTagColWidth = useGridInteractionStore((s) => s.setTagColWidth);
  const [groupDragOver, setGroupDragOver] = useState(false);
  const [groupReorderDrag, setGroupReorderDrag] = useState(null);

  // ── UI state (from useUIStore) ─────────────────────────────────────
  const filterDropdown = useUIStore((s) => s.filterDropdown);
  const setFilterDropdown = useUIStore((s) => s.setFilterDropdown);
  const dateRangeDropdown = useUIStore((s) => s.dateRangeDropdown);
  const setDateRangeDropdown = useUIStore((s) => s.setDateRangeDropdown);
  const crossFind = useUIStore((s) => s.crossFind);
  const setCrossFind = useUIStore((s) => s.setCrossFind);
  const crossTabCounts = useUIStore((s) => s.crossTabCounts);
  const setCrossTabCounts = useUIStore((s) => s.setCrossTabCounts);
  const crossTabOpen = useUIStore((s) => s.crossTabOpen);
  const setCrossTabOpen = useUIStore((s) => s.setCrossTabOpen);
  const extracting = useUIStore((s) => s.extracting);
  const setExtracting = useUIStore((s) => s.setExtracting);
  const extractProgress = useUIStore((s) => s.extractProgress);
  const setExtractProgress = useUIStore((s) => s.setExtractProgress);
  const checkingForUpdates = useUIStore((s) => s.checkingForUpdates);
  const setCheckingForUpdates = useUIStore((s) => s.setCheckingForUpdates);
  const updaterPopup = useUIStore((s) => s.updaterPopup);
  const setUpdaterPopup = useUIStore((s) => s.setUpdaterPopup);
  const recentFiles = useUIStore((s) => s.recentFiles);
  const setRecentFiles = useUIStore((s) => s.setRecentFiles);
  const filterPresets = useUIStore((s) => s.filterPresets);
  const setFilterPresets = useUIStore((s) => s.setFilterPresets);
  const proximityFilter = useUIStore((s) => s.proximityFilter);
  const setProximityFilter = useUIStore((s) => s.setProximityFilter);
  const colMgrSearch = useUIStore((s) => s.colMgrSearch);
  const setColMgrSearch = useUIStore((s) => s.setColMgrSearch);
  const histogramCol = useUIStore((s) => s.histogramCol);
  const setHistogramCol = useUIStore((s) => s.setHistogramCol);
  const histogramData = useUIStore((s) => s.histogramData);
  const setHistogramData = useUIStore((s) => s.setHistogramData);
  const histogramLoaded = useUIStore((s) => s.histogramLoaded);
  const setHistogramLoaded = useUIStore((s) => s.setHistogramLoaded);
  const histogramCache = useRef({}); // { [tabId]: { sig, data } }
  const histDeferUntilRef = useRef({}); // tabId -> epoch ms — defer histogram after large import
  const searchCache = useRef({}); // { [tabId]: { [sig]: { rows, rowOffset, totalFiltered, bookmarkedSet, rowTags } } }
  const histResizeStartY = useRef(0);
  const histResizeStartH = useRef(0);
  const histBrushRef = useRef({ startIdx: null, endIdx: null, active: false });
  const histSvgRectRef = useRef(null);
  const histBrushOverlayRef = useRef(null); // DOM ref for brush overlay rect
  const histBrushLabelRef = useRef(null);   // DOM ref for brush label text
  const histBarGeomRef = useRef({ barW: 1, yAxisW: 44, chartPadT: 4, chartH: 100, len: 0 }); // cached bar geometry for DOM updates
  const [histContainerWidth, setHistContainerWidth] = useState(0);
  const histContainerRef = useRef(null);
  const headerDragOver = useGridInteractionStore((s) => s.headerDragOver);
  const setHeaderDragOver = useGridInteractionStore((s) => s.setHeaderDragOver);
  const [colMgrDragOver, setColMgrDragOver] = useState(null);

  // Filter dropdown internal state (stays local — ephemeral, reset on each open)
  const [fdValues, setFdValues] = useState([]);
  const [fdSampled, setFdSampled] = useState(false);
  const [fdLoading, setFdLoading] = useState(false);
  const [fdSearch, setFdSearch] = useState("");
  const [fdSelected, setFdSelected] = useState(new Set());
  const [fdRegex, setFdRegex] = useState(false);
  const [fdValueMeta, setFdValueMeta] = useState({ totalDistinct: 0, truncated: false });

  const scrollRef = useRef(null);
  const scrollTopRef = useRef(0);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(typeof window !== "undefined" ? window.innerHeight : 800);
  const rafScroll = useRef(null);
  // Mirrors the per-render scroll mapping (physical<->logical) so callbacks/effects
  // outside the render block can read the current scaleFactor without stale closures.
  const scrollMapRef = useRef({ scaleFactor: 1, logicalScrollTop: 0, pageOffset: 0, physicalH: 0, totalH: 0 });
  const handleScroll = useCallback((e) => {
    if (rafScroll.current) return;
    const top = e.target.scrollTop;
    scrollTopRef.current = top;
    rafScroll.current = requestAnimationFrame(() => {
      rafScroll.current = null;
      setScrollTop(scrollTopRef.current);
    });
  }, []);

  // Track window resize / zoom changes so the grid adapts
  useEffect(() => {
    const onResize = () => setViewportH(window.innerHeight);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);
  const queryTimer = useRef(null);
  const fetchId = useRef(0); // Monotonic counter to discard stale query results
  const ctRef = useRef(null);
  // Latest-closure refs for handlers invoked by the mount-only native-menu IPC effect
  // (deps [tle]). Without these, that effect captures the FIRST render's handlers (when
  // tabs=[]), so the native macOS menu's "Close Tab" wiped every tab and Save/Load
  // Session / Reset Columns / Check for Updates silently no-op'd. Updated each render.
  const closeTabRef = useRef(null);
  const handleSaveSessionRef = useRef(null);
  const handleLoadSessionRef = useRef(null);
  const resetColumnWidthsRef = useRef(null);
  const handleCheckForUpdatesRef = useRef(null);
  const displayRowsRef = useRef([]);
  const isGroupedRef = useRef(false);
  const gridLayoutRef = useRef({
    pinnedH: [],
    scrollH: [],
    pinnedOffsets: { offsets: {}, totalWidth: 0 },
    tagColWidth: TAG_COL_WIDTH_DEFAULT,
    hasEvidencePills: false,
  });
  const rightClickFired = useRef(false);
  const pendingModifiedRightClick = useRef(null);
  const [pendingRestores, setPendingRestores] = useState({});
  // Auto-restore: null = not yet checked; false = no autosave found; object = autosave available
  const [autoRestorable, setAutoRestorable] = useState(null);
  const pendingRestoresRef = useRef({});
  const autoSaveInFlightRef = useRef(false);
  const autoSaveQueuedRef = useRef(false);
  // Home-screen capability intent: set when the user clicks an analyzer tile, consumed
  // at import-complete to auto-open that analyzer. A ref (not state) so the import-complete
  // listener always reads the current value without re-registering.
  const pendingCapabilityRef = useRef(null);
  // Triage-collection hand-off. TriageCollectionModal queues a batch of imports and
  // records the tab ids; once every one of them is terminal (complete OR failed) we open
  // the Lateral Movement Tracker across the successful ones. Tracked here rather than in
  // the modal because the modal closes as soon as the batch is queued.
  const triageBatchRef = useRef(null);
  const pendingTriageBatch = useUIStore((s) => s.pendingTriageBatch);
  const setPendingTriageBatch = useUIStore((s) => s.setPendingTriageBatch);
  useEffect(() => {
    if (!pendingTriageBatch) return;
    triageBatchRef.current = {
      ...pendingTriageBatch,
      pending: new Set((pendingTriageBatch.items || []).map((i) => i.tabId)),
      succeeded: [],
    };
    setPendingTriageBatch(null);
  }, [pendingTriageBatch]);

  /**
   * Mark one tab of the active triage batch terminal. When the last one lands, launch the
   * Lateral Movement Tracker across every tab that imported successfully.
   */
  const _settleTriageBatch = (tabId, ok, tabInfo) => {
    const batch = triageBatchRef.current;
    if (!batch || !batch.pending.has(tabId)) return;
    batch.pending.delete(tabId);
    if (ok) batch.succeeded.push(tabInfo);
    if (batch.pending.size > 0) return;
    triageBatchRef.current = null;
    // The batch is done; retire its "Cancel remaining" toast so it cannot outlive the work.
    if (batch.toastId != null) useToastStore.getState().dismiss(batch.toastId);

    // Sigma lane. Both lanes can be selected, and two modals cannot occupy the screen at
    // once — so if lateral movement is also running, offer Sigma as a toast action rather
    // than stealing focus. The directory arrives pre-authorized and pre-counted, so the
    // wizard opens ready to scan.
    const offerSigma = (viaToast) => {
      if (!batch.sigmaEvtxDir) return;
      const open = () => setModal(openSigmaModal({ scanMode: "evtx-dir", evtxDir: batch.sigmaEvtxDir }));
      if (!viaToast) { open(); return; }
      toast.info("Sigma scan ready", {
        detail: `${batch.sigmaEvtxDir.fileCount} EVTX files from this collection.`,
        ttl: 0,
        actionLabel: "Run Sigma scan",
        onAction: open,
      });
    };

    if (!batch.analyzeAfter || batch.succeeded.length === 0) {
      if (batch.succeeded.length === 0) toast.error("Triage import failed", { detail: "No artifacts could be imported." });
      else offerSigma(false);
      return;
    }
    offerSigma(true);
    // Analyse the richest tab first and correlate the rest through multi-source; the
    // analyzer detects each tab's format independently, so raw EVTX and parsed EvtxECmd
    // can safely sit in the same run.
    const ranked = [...batch.succeeded].sort((a, b) => (b.rowCount || 0) - (a.rowCount || 0));
    const primary = ranked[0];
    const others = ranked.slice(1).map((t) => t.tabId);
    setActiveTab(primary.tabId);
    const { cols, chainsawSyntheticTarget } = buildLateralMovementCols(primary.headers || []);
    setModal(openLateralMovementModal(cols, {
      chainsawSyntheticTarget,
      autoStart: true,
      lmMultiSource: others.length > 0,
      lmSelectedTabIds: others,
    }));
    toast.info("Analyzing collection", {
      detail: `Lateral movement across ${ranked.length} artifact${ranked.length === 1 ? "" : "s"}.`,
    });
  };

  // tabId -> source filePath, captured at import-start so a failed import can offer one-click retry.
  const importPathsRef = useRef({});

  const ct = tabs.find((t) => t.id === activeTab);
  ctRef.current = ct;
  const tle = typeof window !== "undefined" ? window.tle : null;
  const runOpenFileDialog = useCallback(async () => {
    if (!tle) return null;
    const r = await tle.openFileDialog();
    handleOpenFileDialogResult(tle, setModal, r);
    return r;
  }, [tle, setModal]);
  const runImportPaths = useCallback(async (paths) => {
    if (!tle || !paths?.length) return;
    const r = await tle.importFiles(paths);
    if (r?.scopePending) handleOpenFileDialogResult(tle, setModal, r);
  }, [tle, setModal]);
  const th = THEMES[themeName];
  const isGrouped = ct?.groupByColumns?.length > 0;
  const handleCheckForUpdates = async () => {
    if (!tle?.checkForUpdates || checkingForUpdates) return;
    setUpdaterPopup({
      phase: "checking",
      message: "Looking for a newer IRFlow Timeline build...",
      detail: "",
      percent: 0,
      version: null,
      releaseNotes: "",
    });
    setCheckingForUpdates(true);
    try {
      await tle.checkForUpdates();
    } catch (err) {
      setUpdaterPopup({
        phase: "error",
        message: err?.message || "The update check failed.",
        detail: "",
        percent: 0,
        version: null,
        releaseNotes: "",
      });
    }
    finally {
      setCheckingForUpdates(false);
    }
  };
  const handleInstallUpdate = async () => {
    if (!tle?.installUpdate) return;
    setUpdaterPopup((prev) => prev ? {
      ...prev,
      phase: "installing",
      message: "Closing IRFlow Timeline to apply the update...",
      detail: "The app will restart if the update installer starts successfully.",
    } : prev);
    try {
      await tle.installUpdate();
    } catch (err) {
      setUpdaterPopup({
        phase: "error",
        message: err?.message || "The update could not be installed.",
        detail: "",
        percent: 0,
        version: null,
        releaseNotes: "",
      });
    }
  };

  useEffect(() => { pendingRestoresRef.current = pendingRestores; }, [pendingRestores]);

  // ── Tab updater ──────────────────────────────────────────────────
  const up = useTabStore((s) => s.up);

  const filterToAiSession = useCallback((sessionId) => {
    if (!ct?.id || !sessionId) return;
    const id = String(sessionId).trim();
    if (!id) return;
    up("columnFilters", { ...(ct.columnFilters || {}), SessionId: id });
    toast.success("Session filter applied", { detail: `Column filter: SessionId contains “${id.length > 48 ? `${id.slice(0, 48)}…` : id}”` });
  }, [ct, up]);

  const correlateAiWorkspace = useCallback((workspace, sourceFile) => {
    const pathStr = resolveAiWorkspacePath(workspace, sourceFile);
    if (!pathStr) {
      toast.warning("No workspace path", { detail: "This row has no resolvable Workspace path to correlate." });
      return;
    }
    const targets = buildWorkspaceCorrelationTargets(useTabStore.getState().tabs, pathStr);
    if (targets.length === 1) {
      const t = targets[0];
      useTabStore.getState().setActiveTab(t.tabId);
      useTabStore.getState().updateTab(t.tabId, {
        columnFilters: { [t.column]: t.value },
        searchHighlight: false,
      });
      toast.success("Correlation filter applied", { detail: `${t.kind}: ${t.hint}` });
      return;
    }
    setModal(openAiWorkspaceCorrelateModal({ path: pathStr, targets }));
  }, [setModal]);

  // ── Export helpers ────────────────────────────────────────────────
  const _downloadFile = (content, filename, mime) => {
    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const _toCSV = (rows) => {
    if (!rows.length) return "";
    const keys = Object.keys(rows[0]);
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    return [keys.join(","), ...rows.map((r) => keys.map((k) => esc(r[k])).join(","))].join("\n");
  };

  // ── Query backend ────────────────────────────────────────────────
  const activeFilters = useCallback((tab) => {
    const dis = tab.disabledFilters || new Set();
    const normalizeCbf = (cbf) => Object.fromEntries(
      Object.entries(cbf || {}).map(([k, v]) => [k, normalizeCheckboxFilterValues(v)]),
    );
    if (dis.size === 0) {
      return { columnFilters: tab.columnFilters, checkboxFilters: normalizeCbf(tab.checkboxFilters) };
    }
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: normalizeCbf(Object.fromEntries(
        Object.entries(tab.checkboxFilters || {}).filter(([k]) => !dis.has(k)),
      )),
    };
  }, []);

  // Canonical filter contract shared by the grid, selection actions, DB-backed
  // range selection, and search navigation. Sort is intentionally separate:
  // changing sort order must not change which rows "select all" refers to.
  const currentFilterOptions = useMemo(() => {
    if (!ct) return null;
    const { columnFilters, checkboxFilters } = activeFilters(ct);
    const rawSearch = ct.searchHighlight ? "" : (ct.searchTerm || "");
    const effectiveSearch = effectiveSearchTerm(rawSearch);
    return {
      searchTerm: effectiveSearch,
      searchMode: ct.searchMode,
      searchCondition: ct.searchCondition || "contains",
      columnFilters,
      checkboxFilters,
      bookmarkedOnly: !!ct.showBookmarkedOnly,
      tagFilter: (ct.disabledFilters || new Set()).has("__tags__")
        ? null
        : (ct.tagFilter || null),
      rowIdFilter: ct.rowIdFilter || null,
      dateRangeFilters: ct.dateRangeFilters || {},
      advancedFilters: ct.advancedFilters || [],
    };
  }, [
    ct?.id,
    ct?.searchHighlight,
    ct?.searchTerm,
    ct?.searchMode,
    ct?.searchCondition,
    ct?.columnFilters,
    ct?.checkboxFilters,
    ct?.showBookmarkedOnly,
    ct?.disabledFilters,
    ct?.tagFilter,
    ct?.rowIdFilter,
    ct?.dateRangeFilters,
    ct?.advancedFilters,
    activeFilters,
  ]);

  const currentFilterScopeSignature = useMemo(() => {
    if (!ct || !currentFilterOptions) return "";
    return JSON.stringify({
      tabId: ct.id,
      totalFiltered: ct.totalFiltered || 0,
      ...currentFilterOptions,
      rowIdFilter: rowIdFilterSignature(ct.rowIdFilter),
    });
  }, [ct?.id, ct?.totalFiltered, ct?.rowIdFilter, currentFilterOptions]);

  const clearRowSelection = useCallback(() => {
    setAllRowsSelected(false);
    setSelectionTabId(null);
    setSelectAllScopeSignature(null);
    setSelectedRows(new Set());
    setLastClickedRow(null);
    setHiddenSelectionCount(0);
  }, [
    setAllRowsSelected,
    setSelectionTabId,
    setSelectAllScopeSignature,
    setSelectedRows,
    setLastClickedRow,
  ]);

  // Programmatic tab changes (cross-tab search, closing a tab, import restore)
  // bypass TabBar's per-tab restoration. Never let stable row IDs from one
  // SQLite database silently become selections in another.
  useEffect(() => {
    if (selectionTabId && ct?.id && selectionTabId !== ct.id) clearRowSelection();
  }, [selectionTabId, ct?.id, clearRowSelection]);

  // Select-all is bound to the exact filter population that was visible when
  // it was activated. A later filter change clears it instead of silently
  // retargeting a different (potentially destructive) population.
  useEffect(() => {
    if (!allRowsSelected || !currentFilterScopeSignature) return;
    if (!selectAllScopeSignature) {
      setSelectAllScopeSignature(currentFilterScopeSignature);
      return;
    }
    if (selectAllScopeSignature !== currentFilterScopeSignature) {
      clearRowSelection();
      toast.info("Selection cleared because the filtered view changed.");
    }
  }, [
    allRowsSelected,
    selectAllScopeSignature,
    currentFilterScopeSignature,
    setSelectAllScopeSignature,
    clearRowSelection,
  ]);

  // Explicit selections persist across filters and sorts. Resolve their
  // visible/hidden split in SQLite so the UI never implies that hidden rows
  // were dropped from the selection.
  useEffect(() => {
    if (!tle || !ct || !currentFilterOptions || (selectionTabId && selectionTabId !== ct.id) || allRowsSelected || selectedRows.size === 0) {
      setHiddenSelectionCount(0);
      return;
    }
    let cancelled = false;
    tle.countRowsByIdsMatching(ct.id, [...selectedRows], currentFilterOptions)
      .then((result) => {
        if (cancelled || isIpcError(result)) return;
        const matching = Math.max(0, Math.min(selectedRows.size, Number(result?.matching) || 0));
        setHiddenSelectionCount(selectedRows.size - matching);
      })
      .catch(() => {
        if (!cancelled) setHiddenSelectionCount(0);
      });
    return () => { cancelled = true; };
  }, [
    tle,
    ct?.id,
    currentFilterOptions,
    currentFilterScopeSignature,
    selectionTabId,
    allRowsSelected,
    selectedRows,
  ]);

  const fetchData = useCallback(async (tab, centerRow = 0) => {
    if (!tle || !tab) return;
    // Stale request prevention: capture current fetch ID before async work
    const myFetchId = ++fetchId.current;
    // Skip query for single-character searches (too broad, expensive on large datasets)
    const rawSearch = tab.searchHighlight ? "" : tab.searchTerm;
    const effectiveSearch = effectiveSearchTerm(rawSearch);
    const { columnFilters, checkboxFilters } = activeFilters(tab);
    const rowIdSig = rowIdFilterSignature(tab.rowIdFilter);
    // Build cache key for this query configuration
    const cacheKey = `${effectiveSearch}|${tab.searchMode}|${tab.sortCol}|${tab.sortDir}|${tab.showBookmarkedOnly}|${tab.searchCondition || "contains"}|${tab.tagFilter || ""}|${rowIdSig}|${JSON.stringify(tab.dateRangeFilters)}|${JSON.stringify(tab.advancedFilters)}|${JSON.stringify(columnFilters)}|${JSON.stringify(checkboxFilters)}`;
    if (tab.groupByColumns?.length > 0) {
      const groupCol = tab.groupByColumns[0];
      const groupData = await tle.getGroupValues(tab.id, groupCol, {
        searchTerm: effectiveSearch, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters, checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        rowIdFilter: tab.rowIdFilter || null,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        parentFilters: [],
      });
      if (fetchId.current !== myFetchId) return; // Stale — newer fetch in flight
      if (isIpcCancelled(groupData)) {
        setSearchLoading(false);
        return;
      }
      if (isIpcError(groupData)) {
        toast.error("Group failed", { detail: ipcErrorMessage(groupData, "Could not load groups") });
        setSearchLoading(false);
        return;
      }
      const safeGroupData = Array.isArray(groupData) ? groupData : [];
      setTabs((prev) => prev.map((t) =>
        t.id === tab.id ? { ...t, groupData: safeGroupData, expandedGroups: {}, dataReady: true } : t
      ));
      setSearchLoading(false);
      return;
    }
    // Check search cache (instant FL/HL toggle and tab switching)
    const tabCache = searchCache.current[tab.id];
    if (tabCache && tabCache[cacheKey] && centerRow === 0) {
      const cached = tabCache[cacheKey];
      setTabs((prev) => prev.map((t) =>
        t.id === tab.id ? { ...t, rows: cached.rows, rowOffset: cached.rowOffset, totalFiltered: cached.totalFiltered, bookmarkedSet: cached.bookmarkedSet, rowTags: cached.rowTags, dataReady: true } : t
      ));
      setSearchLoading(false);
      return;
    }
    const aiHist = isAiHistorySourceFormat(tab.sourceFormat);
    const fetchLimit = fetchLimitForTab(tab);
    const knownTotal = Number.isFinite(tab.totalFiltered) && tab.totalFiltered > 0
      ? tab.totalFiltered
      : (Number.isFinite(tab.totalRows) ? tab.totalRows : 0);
    const maxOffset = knownTotal > fetchLimit ? knownTotal - fetchLimit : 0;
    const fetchOffset = Math.max(0, Math.min(maxOffset, centerRow - Math.floor(fetchLimit / 2)));
    const result = await tle.queryRows(tab.id, {
      offset: fetchOffset, limit: fetchLimit,
      ...(aiHist ? aiHistoryQueryIpcOptions() : {}),
      sortCol: tab.sortCol, sortDir: tab.sortDir,
      searchTerm: effectiveSearch, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
      columnFilters, checkboxFilters,
      bookmarkedOnly: tab.showBookmarkedOnly,
      tagFilter: (tab.disabledFilters || new Set()).has("__tags__") ? null : (tab.tagFilter || null),
      rowIdFilter: tab.rowIdFilter || null,
      dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
    });
    if (fetchId.current !== myFetchId) return; // Stale — newer fetch in flight
    if (isIpcCancelled(result)) {
      setSearchLoading(false);
      return;
    }
    // A worker/SQL failure resolves queryRows with {__ipcError} (it is NOT a rejection),
    // so guard before caching/writing tab state — otherwise the grid blanks to `undefined`
    // rows and the failed result poisons the filter-signature cache (re-shown on FL/HL
    // toggle), swallowing the message. Surface the error and keep the previously loaded rows.
    if (isIpcError(result) || !Array.isArray(result?.rows)) {
      setSearchLoading(false);
      toast.error("Query failed", { detail: ipcErrorMessage(result, "Could not load rows") });
      return;
    }
    // Cache only initial/filter loads (centerRow===0), NOT scroll-driven fetches,
    // to prevent stale offset data from being returned on scroll-back
    if (centerRow === 0) {
      if (!searchCache.current[tab.id]) searchCache.current[tab.id] = {};
      const tc = searchCache.current[tab.id];
      const keys = Object.keys(tc);
      if (keys.length >= 4) delete tc[keys[0]];
      tc[cacheKey] = { rows: result.rows, rowOffset: fetchOffset, totalFiltered: result.totalFiltered, bookmarkedSet: new Set(result.bookmarkedRows), rowTags: result.rowTags || {} };
    }
    setTabs((prev) => prev.map((t) =>
      t.id === tab.id ? { ...t, rows: result.rows, rowOffset: fetchOffset, totalFiltered: result.totalFiltered, bookmarkedSet: new Set(result.bookmarkedRows), rowTags: result.rowTags || {}, dataReady: true } : t
    ));
    setSearchLoading(false);
  }, [tle]);

  // Expose fetchData to extracted modals via the UI store
  useEffect(() => { setRefreshCallback(fetchData); }, [fetchData, setRefreshCallback]);

  const debouncedFetch = useCallback((tab) => {
    if (queryTimer.current) clearTimeout(queryTimer.current);
    queryTimer.current = setTimeout(() => fetchData(tab), QUERY_DEBOUNCE);
  }, [fetchData]);

  // Cleanup debounce timer on unmount to prevent stale callbacks
  useEffect(() => () => {
    if (queryTimer.current) clearTimeout(queryTimer.current);
    if (rafScroll.current) cancelAnimationFrame(rafScroll.current);
  }, []);

  // Debounced deps (typing: search term, column filters) — use useMemo to avoid JSON.stringify per render
  const debouncedDeps = useMemo(() => {
    const cf = ct?.columnFilters;
    return `${ct?.searchTerm}|${ct?.searchMode}|${cf ? Object.keys(cf).sort().map(k => `${k}=${cf[k]}`).join(",") : ""}`;
  }, [ct?.searchTerm, ct?.searchMode, ct?.columnFilters]);
  const prevDebouncedDeps = useRef(debouncedDeps);
  const lastFilterTabId = useRef(null); // distinguishes in-tab filter changes from tab switches

  // Immediate deps (discrete actions: sort, bookmark toggle, checkbox filters, grouping, date range, highlight)
  const immediateDeps = useMemo(() => {
    const cbf = ct?.checkboxFilters;
    // Signature must reflect the actual selected VALUES, not just how many — otherwise
    // changing a column's filter from one value to another of the same count (e.g. IP A → IP B)
    // produces an identical signature and the refetch effect never fires. Mirrors drfSig below.
    const cbfSig = cbf ? Object.keys(cbf).sort().map(k => `${k}:${[...(cbf[k] || [])].sort().join("|")}`).join(",") : "";
    const gbSig = ct?.groupByColumns ? ct.groupByColumns.join(",") : "";
    const drSig = ct?.dateRangeFilters ? Object.keys(ct.dateRangeFilters).sort().map(k => { const r = ct.dateRangeFilters[k]; return `${k}=${r.from || ""}-${r.to || ""}`; }).join(",") : "";
    const dfSig = ct?.disabledFilters ? [...ct.disabledFilters].sort().join(",") : "";
    const afSig = ct?.advancedFilters?.map(f => `${f.column}:${f.operator}:${f.value}:${f.logic}`).join(",") || "";
    const rowIdSig = rowIdFilterSignature(ct?.rowIdFilter);
    return `${ct?.sortCol}|${ct?.sortDir}|${ct?.showBookmarkedOnly}|${cbfSig}|${gbSig}|${drSig}|${ct?.searchHighlight}|${ct?.searchCondition}|${dfSig}|${ct?.tagFilter || ""}|${afSig}|${rowIdSig}`;
  }, [ct?.sortCol, ct?.sortDir, ct?.showBookmarkedOnly, ct?.checkboxFilters, ct?.groupByColumns, ct?.dateRangeFilters, ct?.searchHighlight, ct?.searchCondition, ct?.disabledFilters, ct?.tagFilter, ct?.advancedFilters, ct?.rowIdFilter]);

  useEffect(() => {
    if (!ct || !ct.dataReady) return;
    // A filter/search/sort change re-fetches with centerRow=0, resetting the window to
    // row 0. If the user had scrolled down and the result set shrinks, si/ei would point
    // past the now-smaller dataset → blank grid. Snap the scroll to top — but only for an
    // in-tab change, not a tab switch (TabBar restores per-tab scroll on switch).
    const sameTab = lastFilterTabId.current === ct.id;
    lastFilterTabId.current = ct.id;
    if (prevDebouncedDeps.current !== debouncedDeps) {
      prevDebouncedDeps.current = debouncedDeps;
      setSearchLoading(true);
      debouncedFetch(ct);
    } else {
      if (queryTimer.current) clearTimeout(queryTimer.current);
      setSearchLoading(true);
      fetchData(ct);
    }
    if (sameTab) {
      setScrollTop(0);
      scrollTopRef.current = 0;
      if (scrollRef.current) scrollRef.current.scrollTop = 0;
    }
  }, [debouncedDeps, immediateDeps]);

  // Histogram data fetch (with per-tab cache for instant tab switching)
  const histogramTimer = useRef(null);
  useEffect(() => {
    if (histogramTimer.current) clearTimeout(histogramTimer.current);
    if (!histogramVisible || !ct?.dataReady || !ct?.tsColumns?.size || !tle) { setHistogramData([]); setHistogramLoaded(false); return; }
    if (ct.isLargeFile && (histDeferUntilRef.current[ct.id] || 0) > Date.now()) {
      setHistogramLoaded(false);
      return;
    }
    const hCol = histogramCol && ct.tsColumns.has(histogramCol) ? histogramCol : [...ct.tsColumns][0];
    if (!hCol) return;
    const sig = `${ct.id}:${hCol}:${histGranularity}:${ct.totalFiltered}:${ct.searchTerm}:${ct.searchMode}:${ct.showBookmarkedOnly}:${rowIdFilterSignature(ct.rowIdFilter)}:${JSON.stringify(ct.dateRangeFilters)}:${JSON.stringify(ct.advancedFilters)}`;
    const cached = histogramCache.current[ct.id];
    if (cached && cached.sig === sig) { setHistogramData(cached.data); setHistogramLoaded(true); return; }
    if (cached) setHistogramData(cached.data); // show stale data while refreshing
    setHistogramLoaded(false);
    histogramTimer.current = setTimeout(async () => {
      const af = activeFilters(ct);
      const effectiveSearch = effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm);
      const data = await tle.getHistogramData(ct.id, hCol, {
        searchTerm: effectiveSearch, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly, rowIdFilter: ct.rowIdFilter || null,
        dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        granularity: histGranularity,
      });
      const result = isIpcError(data) || !Array.isArray(data) ? [] : data;
      if (isIpcCancelled(data)) return;
      histogramCache.current[ct.id] = { sig, data: result };
      setHistogramData(result);
      setHistogramLoaded(true);
    }, 400);
    return () => { if (histogramTimer.current) clearTimeout(histogramTimer.current); };
  }, [histogramVisible, histogramCol, histGranularity, ct?.id, ct?.totalFiltered, ct?.searchTerm, ct?.searchMode, ct?.showBookmarkedOnly, ct?.rowIdFilter, JSON.stringify(ct?.dateRangeFilters), JSON.stringify(ct?.advancedFilters)]); // eslint-disable-line

  // Histogram container width tracking via ResizeObserver
  useEffect(() => {
    const el = histContainerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = entry.contentRect.width;
        if (w > 0) setHistContainerWidth(w);
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [histogramVisible]);

  // ── Scroll-driven window fetch (server-side virtual scrolling) ──
  const scrollFetchTimer = useRef(null);
  useEffect(() => {
    if (!ct || !ct.dataReady || isGrouped) return;
    const scrollRow = Math.floor(scrollMapRef.current.logicalScrollTop / ROW_HEIGHT);
    const rowOffset = ct.rowOffset || 0;
    const loadedRows = ct.rows?.length || 0;
    const windowEnd = rowOffset + loadedRows;
    const visibleRows = Math.max(60, Math.ceil((scrollRef.current?.clientHeight || 0) / ROW_HEIGHT) + OVERSCAN);
    const fetchLimit = fetchLimitForTab(ct);
    const ahead = fetchAheadForLimit(Math.max(loadedRows, fetchLimit));
    const cacheCoversViewport = rowWindowCovers(rowOffset, loadedRows, scrollRow, visibleRows);
    const fullZeroBasedCache = rowOffset === 0 && loadedRows >= (ct.totalFiltered || 0);
    const needsFetch = !cacheCoversViewport
      || scrollRow < rowOffset + ahead
      || scrollRow + visibleRows > windowEnd - ahead;
    if (!needsFetch || fullZeroBasedCache) return;
    if (scrollFetchTimer.current) clearTimeout(scrollFetchTimer.current);
    scrollFetchTimer.current = setTimeout(() => fetchData(ct, scrollRow), 50);
  }, [scrollTop, ct?.rowOffset, ct?.rows?.length, ct?.totalFiltered, isGrouped]);

  // ── Group expand/collapse (multi-level) ─────────────────────────
  const expandGroup = useCallback(async (pathKey, parentFilters, depth) => {
    if (!tle || !ctRef.current) return;
    const tab = ctRef.current;
    const groupCols = tab.groupByColumns || [];
    const nextLevel = depth;

    if (nextLevel < groupCols.length) {
      // Expand into sub-groups
      const nextCol = groupCols[nextLevel];
      const af = activeFilters(tab);
      const subGroups = await tle.getGroupValues(tab.id, nextCol, {
        searchTerm: effectiveSearchTerm(tab.searchHighlight ? "" : tab.searchTerm), searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        rowIdFilter: tab.rowIdFilter || null,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        parentFilters,
      });
      setTabs((prev) => prev.map((t) => {
        if (t.id !== tab.id) return t;
        return { ...t, expandedGroups: { ...t.expandedGroups, [pathKey]: { subGroups: subGroups || [], depth: nextLevel } } };
      }));
    } else {
      // Leaf level — fetch actual rows (initial batch)
      const af = activeFilters(tab);
      const aiHistGroup = isAiHistorySourceFormat(tab.sourceFormat);
      const GROUP_BATCH = aiHistGroup ? fetchLimitForTab(tab) : 100000;
      const result = await tle.queryRows(tab.id, {
        offset: 0, limit: GROUP_BATCH,
        ...(aiHistGroup ? aiHistoryQueryIpcOptions() : {}),
        sortCol: tab.sortCol, sortDir: tab.sortDir,
        searchTerm: effectiveSearchTerm(tab.searchHighlight ? "" : tab.searchTerm), searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        rowIdFilter: tab.rowIdFilter || null,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        groupFilters: parentFilters,
      });
      if (!result || result.__ipcError || !Array.isArray(result.rows)) return;
      setTabs((prev) => prev.map((t) => {
        if (t.id !== tab.id) return t;
        const newBm = new Set(t.bookmarkedSet);
        (result.bookmarkedRows || []).forEach((id) => newBm.add(id));
        const newTags = { ...t.rowTags, ...(result.rowTags || {}) };
        return { ...t, bookmarkedSet: newBm, rowTags: newTags, expandedGroups: { ...t.expandedGroups, [pathKey]: { rows: result.rows, totalFiltered: result.totalFiltered, groupFilters: parentFilters } } };
      }));
    }
  }, [tle]);

  // Load more rows for an expanded group (append next batch or load all remaining)
  const loadMoreGroupRows = useCallback(async (pathKey, loadAll) => {
    if (!tle || !ctRef.current) return;
    const tab = ctRef.current;
    const existing = tab.expandedGroups?.[pathKey];
    if (!existing || !existing.rows || !existing.groupFilters) return;
    const aiHistGroup = isAiHistorySourceFormat(tab.sourceFormat);
    const GROUP_BATCH = aiHistGroup ? fetchLimitForTab(tab) : 100000;
    const loaded = existing.rows.length;
    const remaining = existing.totalFiltered - loaded;
    if (remaining <= 0) return;
    const af = activeFilters(tab);
    const result = await tle.queryRows(tab.id, {
      offset: loaded, limit: loadAll ? Math.min(remaining, aiHistGroup ? fetchLimitForTab(tab) : remaining) : GROUP_BATCH,
      ...(aiHistGroup ? aiHistoryQueryIpcOptions() : {}),
      sortCol: tab.sortCol, sortDir: tab.sortDir,
      searchTerm: effectiveSearchTerm(tab.searchHighlight ? "" : tab.searchTerm), searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: tab.showBookmarkedOnly,
      rowIdFilter: tab.rowIdFilter || null,
      dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
      groupFilters: existing.groupFilters,
    });
    if (!result || result.__ipcError || !Array.isArray(result.rows)) return;
    setTabs((prev) => prev.map((t) => {
      if (t.id !== tab.id) return t;
      const eg = t.expandedGroups[pathKey];
      if (!eg) return t;
      const newBm = new Set(t.bookmarkedSet);
      (result.bookmarkedRows || []).forEach((id) => newBm.add(id));
      const newTags = { ...t.rowTags, ...(result.rowTags || {}) };
      return { ...t, bookmarkedSet: newBm, rowTags: newTags, expandedGroups: { ...t.expandedGroups, [pathKey]: { ...eg, rows: [...eg.rows, ...result.rows] } } };
    }));
  }, [tle]);

  const collapseGroup = useCallback((pathKey) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      // Remove this key and all children
      const eg = {};
      for (const k of Object.keys(t.expandedGroups)) {
        if (k !== pathKey && !k.startsWith(pathKey + "|||")) eg[k] = t.expandedGroups[k];
      }
      return { ...t, expandedGroups: eg };
    }));
  }, [activeTab]);

  // ── Column operations (extracted to useColumnOps hook) ──────────
  const { pinColumn, unpinColumn, addGroupBy, removeGroupBy, resetColumnWidths, autoFitColumn, autoFitAllColumns, reorderColumn } = useColumnOps();

  // ── Cross-tab find ─────────────────────────────────────────────
  const handleCrossFind = useCallback(async (term) => {
    if (!tle || !term.trim() || tabs.length === 0) return;
    const results = [];
    for (const tab of tabs) {
      if (!tab.dataReady) continue;
      const count = await tle.searchCount(tab.id, term, "mixed");
      results.push({ tabId: tab.id, name: tab.name, count });
    }
    setCrossFind({ term, results });
  }, [tle, tabs]);

  // Auto cross-tab counts when searching with 2+ tabs
  const crossTabTimer = useRef(null);
  useEffect(() => {
    if (crossTabTimer.current) clearTimeout(crossTabTimer.current);
    const term = ct?.searchTerm?.trim();
    const readyTabs = tabs.filter((t) => t.dataReady);
    if (isSearchTooShort(term) || !term || readyTabs.length < 2 || !tle) { setCrossTabCounts(null); return; }
    setCrossTabOpen(true);
    crossTabTimer.current = setTimeout(async () => {
      const mode = ct?.searchMode || "mixed";
      const cond = ct?.searchCondition || "contains";
      const results = [];
      for (const tab of readyTabs) {
        const count = await tle.searchCount(tab.id, term, mode, cond);
        results.push({ tabId: tab.id, name: tab.name, count });
      }
      setCrossTabCounts({ term, mode, cond, results });
    }, 600);
    return () => { if (crossTabTimer.current) clearTimeout(crossTabTimer.current); };
  }, [ct?.searchTerm, ct?.searchMode, tabs.length, tle]); // eslint-disable-line

  // ── Electron IPC listeners (register once, clean up on unmount) ──
  useEffect(() => {
    if (!tle) return;
    const unsubs = [];
    const listen = (subscribe, cb) => {
      const unsub = subscribe?.(cb);
      if (typeof unsub === "function") unsubs.push(unsub);
    };

    // Load recent files on startup
    tle.getRecentFiles().then((files) => setRecentFiles(files || [])).catch(() => {});
    listen(tle.onRecentFilesUpdated, (files) => setRecentFiles(files || []));

    listen(tle.onImportStart, ({ tabId, fileName, filePath, fileSize }) => {
      if (filePath) importPathsRef.current[tabId] = filePath;
      setImportingTabs((prev) => ({ ...prev, [tabId]: { fileName, rowsImported: 0, percent: 0, status: "importing", fileSize: fileSize || 0 } }));
      setTabs((prev) => [...prev, {
        id: tabId, name: fileName, filePath, headers: [], rows: [], totalRows: 0, totalFiltered: 0,
        tsColumns: new Set(), numericColumns: new Set(), searchTerm: "", searchMode: "mixed", searchCondition: "contains",
        columnFilters: {}, checkboxFilters: {}, sortCol: null, sortDir: "asc", colorRules: [],
        hiddenColumns: new Set(), bookmarkedSet: new Set(), showBookmarkedOnly: false, rowOffset: 0,
        columnWidths: {}, columnOrder: [], pinnedColumns: [], groupByColumns: [], groupData: [], expandedGroups: {},
        rowTags: {}, tagColors: { ...TAG_PRESETS }, tagFilter: null, rowIdFilter: null, rowIdFilterLabel: null,
        dateRangeFilters: {}, searchHighlight: false, disabledFilters: new Set(),
        advancedFilters: [],
        usnResolveStats: null,
        evtxMessageMode: null,
        messagesDeferred: false,
        importing: true, dataReady: false,
      }]);
      setActiveTab(tabId);
      // Bind a home-screen capability intent (if armed and not yet bound) to THIS import,
      // so its analyzer opens on this exact tab even if other imports finish first.
      if (pendingCapabilityRef.current && pendingCapabilityRef.current.tabId == null) {
        pendingCapabilityRef.current.tabId = tabId;
      }
    });
    listen(tle.onImportProgress, ({ tabId, fileName, rowsImported, percent, phase, bytesRead, totalBytes, statusDetail }) => {
      if (!tabId) return;
      const normalizedPercent = Number.isFinite(percent) ? percent : 0;
      setImportingTabs((prev) => ({
        ...prev,
        [tabId]: {
          ...(prev[tabId] || { fileName: fileName || "", status: "importing" }),
          fileName: prev[tabId]?.fileName || fileName || "",
          rowsImported,
          percent: normalizedPercent,
          phase: phase || (normalizedPercent >= 100 ? "finalizing" : "parsing"),
          bytesRead,
          totalBytes,
          statusDetail: statusDetail || "",
          status: normalizedPercent >= 100 ? "indexing" : "importing",
        },
      }));
    });
    listen(tle.onImportComplete, ({ tabId, fileName, headers, rowCount, tsColumns, numericColumns, initialRows, totalFiltered, emptyColumns, sourceFormat, evtxMessageMode, messagesDeferred, resolveStats, bookmarkedRowIds, rowTags, tagColors, importWarning, importNotice, isLargeFile, initialRowsDeferred }) => {
      delete importPathsRef.current[tabId];
      if (importWarning) {
        const warnTitle = isAiHistorySourceFormat(sourceFormat) ? "AI history import"
          : (sourceFormat === "registry" || String(importWarning).includes("hive") ? "Dirty registry hive" : "Import warning");
        toast.warning(warnTitle, { detail: importWarning });
      }
      if (importNotice) toast.info("AI history import", { detail: importNotice });
      const largeTab = !!isLargeFile || rowCount >= 2_500_000 || (isAiHistorySourceFormat(sourceFormat) && rowCount >= 50_000);
      if (largeTab) {
        histDeferUntilRef.current[tabId] = Date.now() + LARGE_TAB_HISTOGRAM_DEFER_MS;
        toast.info("Large timeline loaded", {
          detail: `${formatNumber(rowCount)} rows ready. Wait for indexes to finish before heavy column filters; search uses LIKE until FTS is skipped on files over 5 GB.`,
          ttl: 12000,
        });
      }
      const cw = largeTab ? fastColumnWidths(headers) : measureColumnWidths(headers, initialRows);
      const saved = pendingRestoresRef.current[tabId];
      const applyTabImport = (columnWidths) => setTabs((prev) => prev.map((t) => {
        if (t.id !== tabId) return t;
        const base = { ...t, name: fileName, headers, rows: initialRows, rowOffset: 0, totalRows: rowCount, totalFiltered,
          tsColumns: new Set(tsColumns || []), numericColumns: new Set(numericColumns || []),
          columnWidths: saved ? { ...columnWidths, ...saved.columnWidths } : columnWidths, importing: false, dataReady: true, isLargeFile: largeTab,
          bookmarkedSet: new Set(bookmarkedRowIds || []),
          rowTags: rowTags || {},
          tagColors: tagColors ? { ...TAG_PRESETS, ...tagColors } : { ...TAG_PRESETS },
          sourceFormat: sourceFormat || null,
          evtxMessageMode: evtxMessageMode || null,
          messagesDeferred: !!messagesDeferred,
          aiSecretTriage: saved?.aiSecretTriage || {},
          aiSecretSalt: saved?.aiSecretSalt || "",
          usnResolveStats: sourceFormat === "raw-usnjrnl" ? (resolveStats || null) : null };
        if (!saved) {
          // Auto-detect KAPE / AI history profiles (including ai-history-* imports)
          const kp = detectKapeProfile(headers);
          const autoHidden = kp?.showAllColumns
            ? new Set()
            : new Set(emptyColumns || []);
          if (kp) {
            const order = (kp.columnOrder || []).filter((h) => headers.includes(h));
            const rest = headers.filter((h) => !order.includes(h));
            const autoRules = kp.autoColorColumn && headers.includes(kp.autoColorColumn)
              ? buildTimelineColorRules(initialRows, kp.autoColorColumn, true)
              : [];
            if (!kp.showAllColumns) {
              const kpHidden = (kp.hiddenColumns || []).filter((h) => headers.includes(h));
              kpHidden.forEach((h) => autoHidden.add(h));
            }
            const sortPatch = kp.defaultSortCol && headers.includes(kp.defaultSortCol)
              ? { sortCol: kp.defaultSortCol, sortDir: kp.defaultSortDir || "asc" }
              : {};
            return { ...base, _detectedProfile: kp.name,
              hiddenColumns: autoHidden,
              columnOrder: [...order, ...rest],
              colorRules: autoRules,
              ...sortPatch,
            };
          }
          // Raw binary parsers (MFT, USN Journal): show all columns, only hide empty
          if (sourceFormat) {
            return { ...base, hiddenColumns: autoHidden };
          }
          return { ...base, hiddenColumns: autoHidden };
        }
        return { ...base,
          tagColors: saved.tagColors || { ...TAG_PRESETS },
          columnFilters: saved.columnFilters || {},
          checkboxFilters: saved.checkboxFilters || {},
          colorRules: saved.colorRules || [],
          hiddenColumns: new Set(saved.hiddenColumns || []),
          pinnedColumns: saved.pinnedColumns || [], columnOrder: saved.columnOrder || [],
          sortCol: saved.sortCol, sortDir: saved.sortDir || "asc",
          searchTerm: saved.searchTerm || "", searchMode: saved.searchMode || "mixed", searchCondition: saved.searchCondition || "contains",
          groupByColumns: saved.groupByColumns || [],
          showBookmarkedOnly: saved.showBookmarkedOnly || false,
          rowIdFilter: null,
          rowIdFilterLabel: null,
          dateRangeFilters: saved.dateRangeFilters || {},
          advancedFilters: saved.advancedFilters || [],
          searchHighlight: saved.searchHighlight || false,
          vtEnrichment: saved.vtEnrichment || null,
          aiSecretTriage: saved.aiSecretTriage || {},
          aiSecretSalt: saved.aiSecretSalt || "",
        };
      }));
      applyTabImport(cw);
      if (initialRowsDeferred || (isAiHistorySourceFormat(sourceFormat) && rowCount > 0 && (!initialRows || initialRows.length === 0))) {
        const deferLimit = fetchLimitForTab({ sourceFormat });
        tle.queryRows(tabId, {
          offset: 0,
          limit: deferLimit,
          sortCol: null,
          sortDir: "asc",
          ...aiHistoryQueryIpcOptions(),
        }).then((result) => {
          if (!result || result.__ipcError) return;
          setTabs((prev) => prev.map((t) =>
            t.id === tabId ? {
              ...t,
              rows: result.rows,
              rowOffset: 0,
              totalFiltered: result.totalFiltered,
              bookmarkedSet: new Set(result.bookmarkedRows || []),
              rowTags: result.rowTags || {},
            } : t,
          ));
        }).catch(() => {});
      }
      if (largeTab && initialRows.length > 0) {
        const refine = () => {
          const refined = measureColumnWidths(headers, initialRows);
          setTabs((prev) => prev.map((t) => {
            if (t.id !== tabId) return t;
            return { ...t, columnWidths: saved ? { ...refined, ...saved.columnWidths } : refined };
          }));
        };
        if (typeof requestIdleCallback === "function") requestIdleCallback(refine, { timeout: 3000 });
        else setTimeout(refine, 0);
      }
      setImportingTabs((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
      // Restore bookmarks and tags from session
      if (saved) {
        (async () => {
          if (saved.bookmarkedRowIds?.length) await tle.setBookmarks(tabId, saved.bookmarkedRowIds, true);
          if (saved.tags && Object.keys(saved.tags).length > 0) await tle.bulkAddTags(tabId, saved.tags);
          setPendingRestores((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
        })().catch((err) => {
          console.error("Session restore error for tab", tabId, err);
          setPendingRestores((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
        });
      }

      // ── Home-screen capability launch ───────────────────────────────────────
      // If this import was kicked off from a home-screen capability tile, open that
      // analyzer now that the tab is ready (dataReady was set true above). This fires
      // at import-COMPLETE when dataReady is true. Column mappings are pre-detected so
      // analyzers that need them (Process Inspector, Lateral Movement) never open with
      // an empty schema. Format-specific analyzers fall back to a toast + the grid.
      // Triage batch bookkeeping — must run before the capability hand-off so a batch
      // launch and a home-tile launch can never both fire for the same tab.
      _settleTriageBatch(tabId, true, { tabId, headers, rowCount, sourceFormat: sourceFormat || null });

      const pendingCap = pendingCapabilityRef.current;
      if (pendingCap && pendingCap.tabId === tabId) {
        pendingCapabilityRef.current = null;
        const launcher = HOME_CAPABILITY_LAUNCHERS[pendingCap.capability];
        if (launcher) {
          const launchTab = { id: tabId, headers, sourceFormat: sourceFormat || null, dataReady: true };
          if (launcher.compatible(launchTab)) {
            setActiveTab(tabId);
            setModal(launcher.buildModal(launchTab));
          } else if (launcher.incompatibleHint) {
            toast.warning(launcher.incompatibleHint);
          }
        }
      }
    });
    listen(tle.onImportQueue, ({ pending }) => {
      setImportQueue(pending || []);
    });
    listen(tle.onImportError, ({ tabId, error }) => {
      const errText = String(error || "");
      const userCanceled = /job cancel|extraction cancel|canceled|cancelled/i.test(errText);
      // Drop the pending home-tile capability intent only if THIS (the bound) import failed.
      if (pendingCapabilityRef.current?.tabId === tabId) pendingCapabilityRef.current = null;
      // A failed member must still settle, or the batch would wait forever for it.
      _settleTriageBatch(tabId, false, null);
      setImportingTabs((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
      setTabs((prev) => prev.filter((t) => t.id !== tabId));
      if (userCanceled) return;
      // Offer one-click retry instead of silent data loss — the source path was captured at import-start.
      const failedPath = importPathsRef.current[tabId];
      delete importPathsRef.current[tabId];
      toast.error("Import failed", {
        detail: errText,
        dedupeKey: failedPath ? `import-error:${failedPath}` : `import-error:${errText}`,
        ...(failedPath ? { actionLabel: "Retry import", onAction: () => tle?.importFiles([failedPath]) } : {}),
      });
    });
    listen(tle.onIndexProgress, ({ tabId, built, total, done, currentCol, error }) => {
      if (!tabId) return;
      setTabs((prev) => prev.map((t) =>
        t.id === tabId ? { ...t, indexesReady: done, indexesBuilt: built, indexesTotal: total, indexCurrentCol: currentCol || null, indexError: error || null } : t
      ));
      // Surface background-build failure instead of silently dismissing the overlay.
      if (error) toast.warning("Column indexing didn't finish", { detail: `Sorting and filtering may be slower than usual.\n\n${String(error)}` });
    });
    listen(tle.onFtsProgress, ({ tabId, indexed, total, done, optimizing, error, skipped }) => {
      if (!tabId) return;
      setTabs((prev) => prev.map((t) =>
        t.id === tabId ? { ...t, ftsReady: done, ftsIndexed: indexed, ftsTotal: total, ftsOptimizing: !!optimizing, ftsError: error || null } : t
      ));
      if (error) toast.warning("Search index unavailable", { detail: `Full-text search falls back to a slower full-table scan.\n\n${String(error)}` });
      else if (skipped) toast.warning("Search index skipped (large file)", { detail: "Full-text search uses a substring scan (slower on very large datasets). Sorting and filtering still use column indexes." });
    });
    listen(tle.onExtractResidentProgress, ({ processed, total, percent }) => {
      setExtractProgress({ processed, total, percent });
    });
    listen(tle.onUsnPathsUpdated, ({ tabId, resolveStats }) => {
      // MFT was loaded after USN Journal — paths have been re-resolved
      delete searchCache.current[tabId];
      setTabs((prev) => prev.map((t) =>
        t.id === tabId ? { ...t, usnResolveStats: resolveStats || t.usnResolveStats || null } : t
      ));
      tle.queryRows(tabId, { offset: 0, limit: VIRTUAL_WINDOW, sortCol: null, sortDir: "asc" }).then((result) => {
        if (!result || result.__ipcError) return;
        setTabs((prev) => prev.map((t) =>
          t.id === tabId ? { ...t, rows: result.rows, rowOffset: 0, totalFiltered: result.totalFiltered, usnResolveStats: resolveStats || t.usnResolveStats || null } : t
        ));
      }).catch(() => {});
    });
    listen(tle.onRwProgress, (p) => {
      setModal(updateModal("ransomware", (prev) => (prev.phase === "scanning" || prev.phase === "loading") ? { rwProgress: p } : null));
    });
    listen(tle.onHmProgress, (p) => {
      setModal(updateModal("heatmap", (prev) => prev.loading ? { hmProgress: p } : null));
    });
    listen(tle.onUpdaterState, (state) => {
      setUpdaterPopup((prev) => ({
        phase: state?.phase || "idle",
        message: state?.message || "",
        detail: state?.detail || "",
        percent: Number.isFinite(state?.percent) ? state.percent : (prev?.percent || 0),
        transferred: Number.isFinite(state?.transferred) ? state.transferred : (prev?.transferred || 0),
        total: Number.isFinite(state?.total) ? state.total : (prev?.total || 0),
        bytesPerSecond: Number.isFinite(state?.bytesPerSecond) ? state.bytesPerSecond : (prev?.bytesPerSecond || 0),
        version: state?.version || null,
        releaseNotes: typeof state?.releaseNotes === "string" ? state.releaseNotes : "",
      }));
      if (state?.phase !== "checking") setCheckingForUpdates(false);
    });
    listen(tle.onSheetSelection, ({ tabId, fileName, filePath, sheets }) => {
      setModal(openSimpleModal("sheets", { tabId, fileName, filePath, sheets }));
    });
    listen(tle.onTriggerOpen, () => { runOpenFileDialog(); });
    listen(tle.onTriggerExport, () => {
      const cur = ctRef.current;
      if (cur) {
        const af = activeFilters(cur);
        tle.exportFiltered(cur.id, {
          searchTerm: effectiveSearchTerm(cur.searchHighlight ? "" : cur.searchTerm), searchMode: cur.searchMode, searchCondition: cur.searchCondition || "contains",
          columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
          bookmarkedOnly: cur.showBookmarkedOnly, sortCol: cur.sortCol, sortDir: cur.sortDir,
          tagFilter: (cur.disabledFilters || new Set()).has("__tags__") ? null : (cur.tagFilter || null),
          rowIdFilter: cur.rowIdFilter || null,
          dateRangeFilters: cur.dateRangeFilters || {},
          advancedFilters: cur.advancedFilters || [],
        });
      }
    });
    listen(tle.onTriggerGenerateReport, () => {
      const cur = ctRef.current;
      if (cur?.dataReady) tle.generateReport(cur.id, cur.name, cur.tagColors || {}, cur.vtEnrichment || null);
    });
    listen(tle.onTriggerSearch, () => document.getElementById("gs")?.focus());
    listen(tle.onTriggerBookmarkToggle, () => {
      const cur = ctRef.current;
      if (cur) setTabs((prev) => prev.map((t) => t.id === cur.id ? { ...t, showBookmarkedOnly: !t.showBookmarkedOnly } : t));
    });
    listen(tle.onTriggerColumnManager, () => { setColMgrSearch(""); setModal(openSimpleModal("columns")); });
    listen(tle.onTriggerColorRules, () => setModal(openSimpleModal("colors")));
    listen(tle.onTriggerShortcuts, () => setModal(openSimpleModal("shortcuts")));
    listen(tle.onTriggerCrossFind, () => setModal(openSimpleModal("crossfind")));
    listen(tle.onTriggerSaveSession, () => handleSaveSessionRef.current?.());
    listen(tle.onTriggerLoadSession, () => handleLoadSessionRef.current?.());
    listen(tle.onTriggerCloseTab, () => { const cur = ctRef.current; if (cur) closeTabRef.current?.(cur.id); });
    listen(tle.onTriggerCloseAllTabs, () => { setTabs((prev) => { prev.forEach((t) => tle.closeTab(t.id)); return []; }); setActiveTab(null); });
    listen(tle.onTriggerCheckForUpdates, () => {
      setHelpMenuOpen(false);
      handleCheckForUpdatesRef.current?.();
    });

    // Tools menu handlers
    listen(tle.onSetDatetimeFormat, (fmt) => setDateTimeFormat(fmt));
    listen(tle.onSetTimezone, (tz) => setTimezone(tz));
    listen(tle.onSetFontSize, (val) => {
      if (val === "increase") setFontSize((s) => Math.min(18, s + 1));
      else if (val === "decrease") setFontSize((s) => Math.max(9, s - 1));
      else if (typeof val === "number") setFontSize(val);
    });
    listen(tle.onTriggerResetColumns, () => resetColumnWidthsRef.current?.());
    listen(tle.onSetTheme, (name) => setThemeName(name));
    listen(tle.onTriggerHistogram, () => setHistogramVisible((v) => !v));
    listen(tle.onTriggerVtSettings, () => {
      const cur = ctRef.current;
      if (cur?.dataReady) setModal(openIocLoadModal({ vtConfigExpanded: true }));
    });

    // Load saved filter presets
    tle.loadFilterPresets().then((p) => setFilterPresets(p || [])).catch(() => {});

    return () => {
      for (const unsub of unsubs.splice(0)) {
        try { unsub(); } catch {}
      }
    };
  }, [tle]);

  const markRightClickHandled = useCallback(() => {
    rightClickFired.current = true;
    setTimeout(() => { rightClickFired.current = false; }, 500);
  }, []);

  const shouldCloseContextBackdrop = useCallback((e) => (
    e.button === 0 && !e.ctrlKey && !e.metaKey && !rightClickFired.current
  ), []);

  const renderContextPortal = useCallback((node) => {
    if (typeof document === "undefined" || !document.body) return node;
    return createPortal(node, document.body);
  }, []);

  const inferGridColumnAtPoint = useCallback((x) => {
    const scroller = scrollRef.current;
    const tab = ctRef.current;
    if (!scroller || !tab) return null;

    const rect = scroller.getBoundingClientRect();
    const relX = x - rect.left;
    if (relX < 0 || relX > rect.width) return null;

    const layout = gridLayoutRef.current || {};
    const fixedLeadingW = isGroupedRef.current
      ? (16 + 26 + CHECKBOX_COL_WIDTH)
      : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH);
    let stickyCursor = fixedLeadingW;

    if (relX < stickyCursor) return null;

    const tagW = layout.tagColWidth || TAG_COL_WIDTH_DEFAULT;
    if (relX >= stickyCursor && relX < stickyCursor + tagW) return "__tags__";
    stickyCursor += tagW;

    if (tab.vtEnrichment) stickyCursor += tab.columnWidths?.["__vt__"] || VT_COL_WIDTH;
    if (layout.hasEvidencePills) stickyCursor += tab.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH;

    for (const h of layout.pinnedH || []) {
      const left = layout.pinnedOffsets?.offsets?.[h];
      const w = tab.columnWidths?.[h] || 150;
      if (Number.isFinite(left) && relX >= left && relX < left + w) return h;
    }

    const contentX = scroller.scrollLeft + relX;
    let cursor = layout.pinnedOffsets?.totalWidth || stickyCursor;
    for (const h of layout.scrollH || []) {
      const w = tab.columnWidths?.[h] || 150;
      if (contentX >= cursor && contentX < cursor + w) return h;
      cursor += w;
    }

    return null;
  }, []);

  const openRowContextMenuFromIndex = useCallback((x, y, rowIndex, cellColumn = null) => {
    const tab = ctRef.current;
    if (!tab || rowIndex < 0) {
      debugRightClick("geometry row failed: no tab or invalid row index", { x, y, rowIndex, hasTab: !!tab });
      return false;
    }

    const dRows = displayRowsRef.current || [];
    const offset = isGroupedRef.current ? 0 : (tab.rowOffset || 0);
    const item = dRows[rowIndex - offset];
    if (!item) {
      debugRightClick("geometry row failed: no cached row", { x, y, rowIndex, offset, localIndex: rowIndex - offset, cachedRows: dRows.length });
      return false;
    }
    if (isGroupedRef.current && item.type && item.type !== "row") {
      debugRightClick("geometry row failed: non-row grouped item", { x, y, rowIndex, itemType: item.type });
      return false;
    }

    const row = isGroupedRef.current ? (item.data || item) : item;
    if (!row || row.__idx == null) {
      debugRightClick("geometry row failed: missing row id", { x, y, rowIndex });
      return false;
    }

    const rTags = (tab.rowTags || {})[row.__idx] || [];
    setContextMenu(null);
    setCellContextMenu(null);
    setRowContextMenu({
      x, y,
      rowId: row.__idx,
      rowIndex,
      currentTags: rTags,
      row,
      cellColumn,
      cellValue: cellColumn ? (row[cellColumn] || "") : "",
    });
    markRightClickHandled();
    debugRightClick("opened row context menu from geometry", { x, y, rowIndex, rowId: row.__idx, cellColumn });
    return true;
  }, [markRightClickHandled, setCellContextMenu, setContextMenu, setRowContextMenu]);

  const openGridContextMenuFromGeometry = useCallback((x, y) => {
    const scroller = scrollRef.current;
    if (!scroller) {
      debugRightClick("geometry failed: no scroller", { x, y });
      return false;
    }

    const rect = scroller.getBoundingClientRect();
    if (x < rect.left || x > rect.right || y < rect.top || y > rect.bottom) {
      debugRightClick("geometry failed: point outside scroller", {
        x, y,
        rect: { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom },
      });
      return false;
    }

    const relY = y - rect.top;
    if (relY >= 0 && relY <= HEADER_HEIGHT) {
      const colName = inferGridColumnAtPoint(x);
      if (!colName) {
        debugRightClick("geometry header failed: no column", { x, y, relY });
        return false;
      }
      setRowContextMenu(null);
      setCellContextMenu(null);
      setContextMenu({ x, y, colName });
      markRightClickHandled();
      debugRightClick("opened column context menu from geometry", { x, y, colName });
      return true;
    }

    if (relY <= HEADER_HEIGHT + FILTER_HEIGHT) {
      debugRightClick("geometry ignored filter row", { x, y, relY });
      return false;
    }

    const logicalTop = scrollMapRef.current.logicalScrollTop || scroller.scrollTop || 0;
    const rowIndex = Math.floor((logicalTop + relY - HEADER_HEIGHT - FILTER_HEIGHT) / ROW_HEIGHT);
    return openRowContextMenuFromIndex(x, y, rowIndex, inferGridColumnAtPoint(x));
  }, [inferGridColumnAtPoint, markRightClickHandled, openRowContextMenuFromIndex, setCellContextMenu, setContextMenu, setRowContextMenu]);

  // Shared handler for Command/Ctrl-click context menu shortcuts.
  // Returns true when the point resolves to a grid header/row and opens one of our menus.
  const handleNativeRightClick = useCallback((x, y, targetEl = null) => {
    const eventTarget = targetEl?.nodeType === 1 ? targetEl : targetEl?.parentElement;
    const pointEls = typeof document !== "undefined" && document.elementsFromPoint
      ? document.elementsFromPoint(x, y)
      : [];
    const candidates = [eventTarget, ...pointEls, document.elementFromPoint(x, y)].filter(Boolean);
    const targetName = eventTarget?.tagName || eventTarget?.nodeName || null;

    let headerEl = null;
    let rowEl = null;
    let cellEl = null;
    for (const candidate of candidates) {
      if (!candidate?.closest) continue;
      headerEl = candidate.closest("[data-col-header]");
      if (headerEl) break;
      rowEl = candidate.closest("[data-row-id]");
      if (rowEl) {
        cellEl = candidate.closest("[data-cell-col]");
        break;
      }
    }

    // Column header context shortcut
    if (headerEl) {
      setRowContextMenu(null);
      setCellContextMenu(null);
      setContextMenu({ x, y, colName: headerEl.dataset.colHeader });
      markRightClickHandled();
      debugRightClick("opened column context menu from dom target", {
        x, y,
        colName: headerEl.dataset.colHeader,
        targetName,
        candidateCount: candidates.length,
      });
      return true;
    }

    // Data row context shortcut
    if (!rowEl) {
      debugRightClick("dom target missed; falling back to geometry", { x, y, targetName, candidateCount: candidates.length });
      return openGridContextMenuFromGeometry(x, y);
    }

    const rowId = rowEl.dataset.rowId;
    const rowIndex = parseInt(rowEl.dataset.rowIndex, 10);
    const cellCol = cellEl ? cellEl.dataset.cellCol : null;

    const tab = ctRef.current;
    if (!tab) {
      debugRightClick("dom row failed: no active tab", { x, y, rowId, rowIndex, cellCol });
      return false;
    }

    const dRows = displayRowsRef.current;
    const tab2 = ctRef.current;
    const offset = isGroupedRef.current ? 0 : (tab2?.rowOffset || 0);
    const item = dRows[rowIndex - offset];
    if (!item) {
      debugRightClick("dom row failed: no cached row", { x, y, rowId, rowIndex, offset, localIndex: rowIndex - offset, cachedRows: dRows?.length || 0 });
      return false;
    }
    const row = isGroupedRef.current ? (item.data || item) : item;
    if (!row || String(row.__idx) !== String(rowId)) {
      debugRightClick("dom row failed: row id mismatch", { x, y, rowId, rowIndex, cachedRowId: row?.__idx });
      return false;
    }

    const rTags = (tab.rowTags || {})[row.__idx] || [];
    setContextMenu(null);
    setCellContextMenu(null);
    setRowContextMenu({
      x, y,
      rowId: row.__idx,
      rowIndex,
      currentTags: rTags,
      row,
      cellColumn: cellCol,
      cellValue: cellCol ? (row[cellCol] || "") : "",
    });
    markRightClickHandled();
    debugRightClick("opened row context menu from dom target", { x, y, rowId: row.__idx, rowIndex, cellCol });
    return true;
  }, [markRightClickHandled, openGridContextMenuFromGeometry, setCellContextMenu, setContextMenu, setRowContextMenu]);

  // Supported grid context-menu shortcut: Command-click on macOS (Ctrl-click elsewhere).
  // Plain secondary-click handling is intentionally disabled after unreliable
  // external-trackpad behavior; this path is explicit and stable.
  useEffect(() => {
    const onModifiedPrimaryPointer = (e) => {
      const modifiedPrimaryClick = e.button === 0 && (e.ctrlKey || e.metaKey);
      if (!modifiedPrimaryClick) return;

      if (rightClickFired.current) {
        e.preventDefault();
        e.stopPropagation();
        return;
      }

      const isDownEvent = e.type === "pointerdown" || e.type === "mousedown";
      const isUpEvent = e.type === "pointerup" || e.type === "mouseup";

      // Wait until pointerup/mouseup so the later synthetic click does not
      // overwrite or immediately close the native menu.
      if (modifiedPrimaryClick && isDownEvent) {
        pendingModifiedRightClick.current = { x: e.clientX, y: e.clientY, target: e.target, at: Date.now() };
        debugRightClick("document command context pending", {
          type: e.type,
          x: e.clientX,
          y: e.clientY,
          button: e.button,
          buttons: e.buttons,
          ctrlKey: e.ctrlKey,
          metaKey: e.metaKey,
          targetName: e.target?.tagName || e.target?.nodeName || null,
        });
        e.preventDefault();
        e.stopPropagation();
        return;
      }

      debugRightClick("document command context", {
        type: e.type,
        x: e.clientX,
        y: e.clientY,
        button: e.button,
        buttons: e.buttons,
        ctrlKey: e.ctrlKey,
        metaKey: e.metaKey,
        targetName: e.target?.tagName || e.target?.nodeName || null,
      });

      if (modifiedPrimaryClick && isUpEvent) {
        const pending = pendingModifiedRightClick.current;
        pendingModifiedRightClick.current = null;
        const x = Number.isFinite(pending?.x) ? pending.x : e.clientX;
        const y = Number.isFinite(pending?.y) ? pending.y : e.clientY;
        const target = pending?.target || e.target;
        markRightClickHandled();
        setTimeout(() => {
          debugRightClick("document command context open", { type: e.type, x, y });
          handleNativeRightClick(x, y, target);
        }, 0);
        e.preventDefault();
        e.stopPropagation();
        return;
      }
    };
    const eventTypes = ["pointerdown", "mousedown", "pointerup", "mouseup"];
    eventTypes.forEach((type) => document.addEventListener(type, onModifiedPrimaryPointer, true));
    return () => eventTypes.forEach((type) => document.removeEventListener(type, onModifiedPrimaryPointer, true));
  }, [handleNativeRightClick, markRightClickHandled]);

  useEffect(() => {
    const onClickAfterSecondary = (e) => {
      if (!rightClickFired.current) return;
      e.preventDefault();
      e.stopPropagation();
    };
    document.addEventListener("click", onClickAfterSecondary, true);
    return () => document.removeEventListener("click", onClickAfterSecondary, true);
  }, []);

  useEffect(() => {
    if (contextMenu) debugRightClick("column context menu render", { x: contextMenu.x, y: contextMenu.y, colName: contextMenu.colName });
  }, [contextMenu]);

  useEffect(() => {
    if (rowContextMenu) {
      debugRightClick("row context menu render", {
        x: rowContextMenu.x,
        y: rowContextMenu.y,
        rowId: rowContextMenu.rowId,
        rowIndex: rowContextMenu.rowIndex,
        cellColumn: rowContextMenu.cellColumn,
      });
    }
  }, [rowContextMenu]);

  useEffect(() => {
    if (cellContextMenu) debugRightClick("cell context menu render", { x: cellContextMenu.x, y: cellContextMenu.y, colName: cellContextMenu.colName });
  }, [cellContextMenu]);

  // ── Handlers ─────────────────────────────────────────────────────
  const sortTimerRef = useRef(null);
  const handleSort = (col) => {
    if (justResizedRef.current || !ct) return;
    // Delay sort so double-click (auto-fit) can cancel it
    clearTimeout(sortTimerRef.current);
    sortTimerRef.current = setTimeout(() => {
      if (ct.sortCol === col) up("sortDir", ct.sortDir === "asc" ? "desc" : "asc");
      else { up("sortCol", col); up("sortDir", "asc"); }
    }, 250);
  };
  const handleHeaderDblClick = (col) => {
    clearTimeout(sortTimerRef.current);
    autoFitColumn(col);
  };

  const handleBookmark = async (rowId) => {
    if (!tle || !ct) return;
    const isNowBookmarked = await tle.toggleBookmark(ct.id, rowId);
    const newSet = new Set(ct.bookmarkedSet);
    isNowBookmarked ? newSet.add(rowId) : newSet.delete(rowId);
    up("bookmarkedSet", newSet);
  };

  const handleExport = async () => {
    if (!tle || !ct) return;
    const visSet = new Set(ct.headers.filter((h) => !ct.hiddenColumns.has(h)));
    if (isAiHistorySourceFormat(ct.sourceFormat) && ct.headers.includes("FullText")) visSet.add("FullText");
    const visHeaders = ct.headers.filter((h) => visSet.has(h));
    const af = activeFilters(ct);
    await tle.exportFiltered(ct.id, {
      sortCol: ct.sortCol, sortDir: ct.sortDir, searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: ct.showBookmarkedOnly, visibleHeaders: visHeaders,
      tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
      rowIdFilter: ct.rowIdFilter || null,
      dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
    });
  };

  const handleExtractResident = async () => {
    if (!tle || !ct || extracting) return;
    setExtracting(true);
    setExtractProgress({ processed: 0, total: 0, percent: 0 });
    try {
      const result = await tle.extractResidentData(ct.id);
      if (result?.canceled) {
        // User cancelled the folder picker
      } else if (result?.error) {
        toast.error("Extraction failed", { detail: String(result.error) });
      } else if (result) {
        toast.success(`Extracted ${result.extractedCount.toLocaleString()} resident files`, { detail: `From ${result.totalRecords.toLocaleString()} MFT records.\n\nOutput: ${result.outputDir}${result.skippedErrors > 0 ? `\n\n${result.skippedErrors} records skipped due to errors.` : ""}`, ttl: 8000 });
      }
    } catch (err) {
      toast.error("Extraction failed", { detail: err?.message || String(err) });
    } finally {
      setExtracting(false);
      setExtractProgress(null);
    }
  };

  const closeTab = async (id) => {
    if (tle) await tle.closeTab(id);
    delete histogramCache.current[id];
    delete searchCache.current[id];
    delete histDeferUntilRef.current[id];
    const rem = tabs.filter((t) => t.id !== id);
    setTabs(rem);
    if (activeTab === id) setActiveTab(rem.length ? rem[rem.length - 1].id : null);
  };

  // ── Temporal Proximity Search ──────────────────────────────────
  const applyProximity = useCallback((tsCol, pivotRaw, windowMs, label) => {
    const normalized = (pivotRaw || "").replace(" ", "T");
    const pivotMs = Date.parse(normalized);
    if (isNaN(pivotMs)) return;
    const fmt = (ms) => {
      const d = new Date(ms);
      const pad = (n) => String(n).padStart(2, "0");
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    };
    up("dateRangeFilters", { ...(ct?.dateRangeFilters || {}), [tsCol]: { from: fmt(pivotMs - windowMs), to: fmt(pivotMs + windowMs) } });
    setProximityFilter({ tsCol, pivotRaw, windowMs, label });
    setModal(null);
  }, [ct, up]);

  // ── Session save/load ──────────────────────────────────────────
  // Build a session payload from the current tabs. Shared by save/auto-save.
  const buildSessionPayload = useCallback(async () => {
    const sessionTabs = [];
    for (const tab of tabs) {
      if (!tab.dataReady) continue;
      const bookmarkIds = await tle.getBookmarkedIds(tab.id);
      const tagData = await tle.getAllTagData(tab.id);
      const tags = {};
      for (const { rowid, tag } of tagData) {
        if (!tags[rowid]) tags[rowid] = [];
        tags[rowid].push(tag);
      }
      sessionTabs.push({
        filePath: tab.filePath, name: tab.name,
        bookmarkedRowIds: bookmarkIds, tags, tagColors: tab.tagColors || {},
        columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters,
        colorRules: tab.colorRules, hiddenColumns: [...tab.hiddenColumns],
        pinnedColumns: tab.pinnedColumns, columnWidths: tab.columnWidths, columnOrder: tab.columnOrder || [],
        sortCol: tab.sortCol, sortDir: tab.sortDir,
        searchTerm: tab.searchTerm, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        groupByColumns: tab.groupByColumns, showBookmarkedOnly: tab.showBookmarkedOnly,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [], searchHighlight: tab.searchHighlight || false,
        vtEnrichment: tab.vtEnrichment || null,
        aiSecretTriage: tab.aiSecretTriage || {},
        aiSecretSalt: tab.aiSecretSalt || "",
      });
    }
    return { version: 1, savedAt: new Date().toISOString(), activeTabIndex: tabs.findIndex((t) => t.id === activeTab), tabs: sessionTabs };
  }, [tle, tabs, activeTab]);

  // Restore an already-loaded session payload (shared by manual + auto-restore).
  const restoreFromSession = useCallback(async (session) => {
    if (!session || session.error) {
      if (session?.error) toast.error("Failed to load session", { detail: String(session.error) });
      return false;
    }
    if (session.version !== 1) { toast.error("Unsupported session version"); return false; }
    for (const tab of tabs) await tle.closeTab(tab.id);
    setTabs([]); setActiveTab(null);
    const restoreMap = {};
    for (const savedTab of session.tabs) {
      const result = await tle.importFileForRestore(savedTab.filePath, savedTab.sheetName);
      if (result.error) { toast.warning(`Skipping "${savedTab.name}"`, { detail: String(result.error) }); continue; }
      restoreMap[result.tabId] = savedTab;
    }
    setPendingRestores(restoreMap);
    return true;
  }, [tle, tabs]);

  const handleSaveSession = useCallback(async () => {
    if (!tle || tabs.length === 0) return;
    const payload = await buildSessionPayload();
    await tle.saveSession(payload);
  }, [tle, tabs, buildSessionPayload]);

  const handleLoadSession = useCallback(async () => {
    if (!tle) return;
    const session = await tle.loadSession();
    await restoreFromSession(session);
  }, [tle, restoreFromSession]);

  // Keep native-menu handler refs current so the mount-only IPC effect always invokes
  // the latest closures (never a stale tabs=[] version). See ref declarations above.
  useEffect(() => {
    closeTabRef.current = closeTab;
    handleSaveSessionRef.current = handleSaveSession;
    handleLoadSessionRef.current = handleLoadSession;
    resetColumnWidthsRef.current = resetColumnWidths;
    handleCheckForUpdatesRef.current = handleCheckForUpdates;
  });

  // ── Auto-save: every 30s, snapshot the in-flight investigation to userData/autosave.tle ──
  // Survives crashes; protects against losing tags/bookmarks/filters during a long forensic run.
  useEffect(() => {
    if (!tle?.autoSaveSession || tabs.length === 0) return;
    const dataReadyTabs = tabs.filter((t) => t.dataReady);
    if (dataReadyTabs.length === 0) return;
    let disposed = false;
    const runAutoSave = async () => {
      if (autoSaveInFlightRef.current) {
        autoSaveQueuedRef.current = true;
        return;
      }
      autoSaveInFlightRef.current = true;
      try {
        const payload = await buildSessionPayload();
        if (payload.tabs.length > 0) await tle.autoSaveSession(payload);
      } catch { /* swallow — autosave failures must never disrupt analysis */ }
      finally {
        autoSaveInFlightRef.current = false;
        const runQueuedSave = autoSaveQueuedRef.current;
        autoSaveQueuedRef.current = false;
        if (!disposed && runQueuedSave) {
          void runAutoSave();
        }
      }
    };
    const id = setInterval(() => { void runAutoSave(); }, 30000);
    return () => {
      disposed = true;
      autoSaveQueuedRef.current = false;
      clearInterval(id);
    };
  }, [tle, tabs, buildSessionPayload]);

  // ── Auto-restore prompt on launch ──
  // Check for an autosave file on first mount; expose it via `autoRestorable` so
  // the empty-state UI can offer a Restore button. Only triggers when there are
  // no current tabs (we don't want to prompt mid-investigation).
  useEffect(() => {
    if (!tle?.loadAutoSave) return;
    let cancelled = false;
    tle.loadAutoSave().then((data) => {
      if (cancelled) return;
      if (data && !data.error && Array.isArray(data.tabs) && data.tabs.length > 0) {
        setAutoRestorable(data);
      } else {
        setAutoRestorable(false);
      }
    }).catch(() => { if (!cancelled) setAutoRestorable(false); });
    return () => { cancelled = true; };
  }, [tle]);

  const handleAutoRestore = useCallback(async () => {
    if (!autoRestorable || autoRestorable === false) return;
    const ok = await restoreFromSession(autoRestorable);
    if (ok) {
      setAutoRestorable(false);
      try { await tle.clearAutoSave(); } catch { /* ignore */ }
    }
  }, [autoRestorable, restoreFromSession, tle]);

  const handleDismissAutoRestore = useCallback(async () => {
    setAutoRestorable(false);
    try { await tle?.clearAutoSave?.(); } catch { /* ignore */ }
  }, [tle]);

  // ── Computed headers ─────────────────────────────────────────────
  const allVisH = useMemo(() => {
    if (!ct) return [];
    const visSet = new Set(ct.headers.filter((h) => !ct.hiddenColumns.has(h)));
    if (ct.columnOrder?.length > 0) {
      const ordered = ct.columnOrder.filter((h) => visSet.has(h));
      const orderSet = new Set(ct.columnOrder);
      const rest = [...visSet].filter((h) => !orderSet.has(h));
      return [...ordered, ...rest];
    }
    return [...visSet];
  }, [ct?.headers, ct?.hiddenColumns, ct?.columnOrder]);

  const pinnedH = useMemo(() => {
    if (!ct) return [];
    const visSet = new Set(allVisH);
    return (ct.pinnedColumns || []).filter((h) => visSet.has(h));
  }, [ct?.pinnedColumns, allVisH]);

  const scrollH = useMemo(() => {
    const pinSet = new Set(pinnedH);
    return allVisH.filter((h) => !pinSet.has(h));
  }, [allVisH, pinnedH]);

  const hasEvidencePills = !!ct?.evidencePillsByRowid && Object.keys(ct.evidencePillsByRowid).length > 0;
  const pinnedOffsets = useMemo(() => {
    const offsets = {};
    const vtW = ct?.columnWidths?.["__vt__"] || VT_COL_WIDTH;
    const evW = ct?.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH;
    let x = (isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH)) + tagColWidth + (ct?.vtEnrichment ? vtW : 0) + (hasEvidencePills ? evW : 0); // after # + checkbox + Tags + VT + Evidence
    for (const h of pinnedH) {
      offsets[h] = x;
      x += (ct?.columnWidths[h] || 150);
    }
    return { offsets, totalWidth: x };
  }, [pinnedH, ct?.columnWidths, tagColWidth, isGrouped, ct?.vtEnrichment, hasEvidencePills]);

  gridLayoutRef.current = {
    pinnedH,
    scrollH,
    pinnedOffsets,
    tagColWidth,
    hasEvidencePills,
  };

  // ── Grouped items (multi-level) ─────────────────────────────────
  const groupedItems = useMemo(() => {
    if (!isGrouped || !ct?.groupData?.length) return null;
    const groupCols = ct.groupByColumns;
    const eg = ct.expandedGroups || {};
    const items = [];

    const buildLevel = (groups, depth, parentPath, parentFilters) => {
      const colName = groupCols[depth];
      for (const group of groups) {
        const pathKey = parentPath ? `${parentPath}|||${group.val}` : `${group.val}`;
        const filters = [...parentFilters, { col: colName, value: group.val }];
        items.push({ type: "group", value: group.val, count: group.cnt, depth, pathKey, filters, colName });
        const expanded = eg[pathKey];
        if (expanded) {
          if (expanded.subGroups) {
            // Sub-group level
            buildLevel(expanded.subGroups, depth + 1, pathKey, filters);
          } else if (expanded.rows) {
            // Leaf rows
            for (const row of expanded.rows) items.push({ type: "row", data: row, depth: depth + 1 });
            if (expanded.rows.length < expanded.totalFiltered)
              items.push({ type: "more", pathKey, loaded: expanded.rows.length, total: expanded.totalFiltered, depth: depth + 1 });
          }
        }
      }
    };

    buildLevel(ct.groupData, 0, "", []);
    return items;
  }, [isGrouped, ct?.groupData, ct?.expandedGroups, ct?.groupByColumns]);

  // ── Virtual scroll ───────────────────────────────────────────────
  const rows = ct?.rows || [];
  const displayRows = isGrouped && groupedItems ? groupedItems : rows;
  displayRowsRef.current = displayRows;
  isGroupedRef.current = isGrouped;

  // Get a row by absolute index (accounts for windowed offset in flat mode)
  const getRowAt = useCallback((absIdx) => {
    if (isGrouped) return displayRows[absIdx] || null;
    const localIdx = absIdx - (ct?.rowOffset || 0);
    return (localIdx >= 0 && localIdx < rows.length) ? rows[localIdx] : null;
  }, [isGrouped, displayRows, rows, ct?.rowOffset]);

  const getDataRowAt = useCallback((absIdx) => {
    const item = getRowAt(absIdx);
    if (!item) return null;
    if (isGrouped) return item.type === "row" ? item.data : null;
    return item;
  }, [getRowAt, isGrouped]);

  const getRowIdAt = useCallback((absIdx) => {
    const row = getDataRowAt(absIdx);
    const rowId = Number(row?.__idx);
    return Number.isInteger(rowId) && rowId > 0 ? rowId : null;
  }, [getDataRowAt]);

  const lastClickedRowData = useMemo(
    () => lastClickedRow === null ? null : getDataRowAt(lastClickedRow),
    [lastClickedRow, getDataRowAt],
  );
  const selectionBelongsToCurrentTab = !selectionTabId || selectionTabId === ct?.id;
  // The visual position can change after sorting; membership is keyed by row ID.
  const selectedRow = selectionBelongsToCurrentTab && lastClickedRow !== null
    && isRowSelected(selectedRows, allRowsSelected, lastClickedRowData?.__idx)
    ? lastClickedRow
    : null;
  const selectedRowData = selectedRow === null ? null : lastClickedRowData;

  const handleRowClick = async (ai, e) => {
    // Skip if this click was a Cmd+Click / Ctrl+Click that triggered the context menu
    if (rightClickFired.current) return;
    const rowId = getRowIdAt(ai);
    if (rowId === null) return;
    if (e.shiftKey && lastClickedRow !== null) {
      // Shift+Click: range select
      const from = Math.min(lastClickedRow, ai);
      const to = Math.max(lastClickedRow, ai);
      let rowIds = [];
      if (isGrouped) {
        for (let i = from; i <= to; i++) {
          const id = getRowIdAt(i);
          if (id !== null) rowIds.push(id);
        }
      } else {
        try {
          const result = await tle.getRowIdsInRange(ct.id, {
            ...currentFilterOptions,
            sortCol: ct.sortCol,
            sortDir: ct.sortDir,
            offset: from,
            limit: to - from + 1,
          });
          if (isIpcError(result) || !Array.isArray(result?.rowIds)) {
            throw new Error(ipcErrorMessage(result, "Could not resolve the selected range"));
          }
          rowIds = result.rowIds;
        } catch (err) {
          toast.error("Range selection failed", { detail: String(err?.message || err) });
          return;
        }
      }
      if (rowIds.length === 0) return;
      setSelectionTabId(ct.id);
      setSelectedRows((prev) => {
        return selectRowIds(prev, allRowsSelected, rowIds);
      });
    } else if (e.metaKey || e.ctrlKey) {
      // Cmd/Ctrl+Click: toggle individual
      setSelectionTabId(ct.id);
      setSelectedRows((prev) => toggleRowSelection(prev, allRowsSelected, rowId));
      setLastClickedRow(ai);
    } else {
      // Plain click: single select
      setAllRowsSelected(false);
      setSelectionTabId(ct.id);
      setSelectAllScopeSignature(null);
      setSelectedRows(new Set([rowId]));
      setLastClickedRow(ai);
    }
    setDetailPanelOpen(true);
  };

  const handleCheckboxToggle = (ai) => {
    const rowId = getRowIdAt(ai);
    if (rowId === null) return;
    setSelectionTabId(ct.id);
    setSelectedRows((prev) => toggleRowSelection(prev, allRowsSelected, rowId));
    setLastClickedRow(ai);
  };

  const handleGroupSelectAll = (groupHeaderAi) => {
    if (!displayRows) return;
    const groupItem = displayRows[groupHeaderAi];
    if (!groupItem || groupItem.type !== "group") return;
    const baseDepth = groupItem.depth;
    const rowIds = [];
    for (let j = groupHeaderAi + 1; j < displayRows.length; j++) {
      const child = displayRows[j];
      if (child.type === "group" && child.depth <= baseDepth) break;
      if (child.type === "row" && child.data?.__idx) rowIds.push(child.data.__idx);
    }
    if (rowIds.length === 0) return;
    setSelectionTabId(ct.id);
    const allSelected = rowIds.every((rowId) =>
      isRowSelected(selectedRows, allRowsSelected, rowId));
    setSelectedRows((prev) => {
      const next = new Set(prev);
      for (const value of rowIds) {
        const rowId = Number(value);
        if (allRowsSelected) {
          if (allSelected) next.add(rowId);
          else next.delete(rowId);
        } else if (allSelected) {
          next.delete(rowId);
        } else {
          next.add(rowId);
        }
      }
      return next;
    });
  };

  const getGroupCheckState = (groupAi, depth) => {
    if (!displayRows) return { total: 0, selected: 0 };
    let total = 0, selected = 0;
    for (let j = groupAi + 1; j < displayRows.length; j++) {
      const c = displayRows[j];
      if (c.type === "group" && c.depth <= depth) break;
      if (c.type === "row") {
        total++;
        if (isRowSelected(selectedRows, allRowsSelected, c.data?.__idx)) selected++;
      }
    }
    return { total, selected };
  };

  const detailVisible = detailPanelOpen && selectedRowData !== null;
  const totalCount = isGrouped ? displayRows.length : (ct?.totalFiltered || 0);
  const selectionCount = selectionBelongsToCurrentTab
    ? getSelectedRowCount(
      selectedRows,
      allRowsSelected,
      ct?.totalFiltered || 0,
    )
    : 0;
  const allFilteredRowsSelected = (ct?.totalFiltered || 0) > 0
    && selectionBelongsToCurrentTab
    && allRowsSelected
    && selectedRows.size === 0;
  const handleSelectAllRows = () => {
    if (isGrouped || !ct?.totalFiltered) return;
    const everyRowSelected = allFilteredRowsSelected;
    setAllRowsSelected(!everyRowSelected);
    setSelectionTabId(everyRowSelected ? null : ct.id);
    setSelectAllScopeSignature(everyRowSelected ? null : currentFilterScopeSignature);
    setSelectedRows(new Set());
    if (everyRowSelected) setLastClickedRow(null);
  };
  const selectionFilterOptions = useMemo(() => {
    if (selectionCount === 0 || !currentFilterOptions) return null;
    if (allRowsSelected) {
      return {
        ...currentFilterOptions,
        excludedRowIds: [...selectedRows],
      };
    }
    return { rowIdFilter: [...selectedRows] };
  }, [selectionCount, currentFilterOptions, allRowsSelected, selectedRows]);
  const rowOffset = ct?.rowOffset || 0;
  const totalH = totalCount * ROW_HEIGHT;
  // The scroll container has already shrunk around the detail panel. Only remove
  // the sticky header/filter rows to get the usable data-row viewport.
  const gridViewportH = scrollRef.current?.clientHeight || (viewportH - 190);
  const vh = getGridBodyViewportHeight(
    gridViewportH,
    HEADER_HEIGHT + FILTER_HEIGHT,
    ROW_HEIGHT,
  );
  // Physical container is clamped at MAX_PHYSICAL_H to stay below Chromium's ~16.7M LayoutUnit ceiling.
  // When totalH exceeds the cap, scaleFactor maps physical scrollTop -> logical scrollTop linearly.
  // pageOffset shifts each rendered row's `top` so it lands at the correct visual position
  // inside the (clamped) container, despite rows being keyed off logical indices.
  const physicalH = Math.min(totalH, MAX_PHYSICAL_H);
  const physMaxScroll = Math.max(1, physicalH - vh);
  const logMaxScroll = Math.max(1, totalH - vh);
  const scaleFactor = totalH > physicalH ? logMaxScroll / physMaxScroll : 1;
  const logicalScrollTop = scaleFactor === 1 ? scrollTop : Math.min(logMaxScroll, scrollTop * scaleFactor);
  const pageOffset = logicalScrollTop - scrollTop;
  scrollMapRef.current = { scaleFactor, logicalScrollTop, pageOffset, physicalH, totalH };
  const { start: visibleRowStart, end: visibleRowEnd } = getVisibleRowRange({
    totalCount,
    logicalScrollTop,
    viewportHeight: vh,
    rowHeight: ROW_HEIGHT,
  });
  const si = Math.max(0, Math.floor(logicalScrollTop / ROW_HEIGHT) - OVERSCAN);
  const ei = Math.min(totalCount, Math.ceil((logicalScrollTop + vh) / ROW_HEIGHT) + OVERSCAN);
  // For grouped mode: direct slice. For flat mode: map to windowed cache via rowOffset.
  const visible = useMemo(() => isGrouped
    ? displayRows.slice(si, ei)
    : rows.slice(Math.max(0, si - rowOffset), Math.max(0, ei - rowOffset)),
    [isGrouped, displayRows, rows, si, ei, rowOffset]);

  // Skeleton rows for positions outside the cached window (shown during fast scroll)
  const skeletonIndices = useMemo(() => {
    if (isGrouped || visible.length >= (ei - si)) return [];
    const cacheStart = rowOffset;
    const cacheEnd = rowOffset + rows.length;
    const indices = [];
    for (let i = si; i < ei; i++) {
      if (i < cacheStart || i >= cacheEnd) indices.push(i);
    }
    return indices;
  }, [isGrouped, visible.length, si, ei, rowOffset, rows.length]);

  const compiledColors = useMemo(() => compileColorRules(ct?.colorRules || []), [ct?.colorRules]);
  const gw = (col) => ct?.columnWidths[col] || 150;
  const fmtCell = (h, val) => (dateTimeFormat && ct?.tsColumns?.has(h)) ? formatDateTime(val, dateTimeFormat, timezone) : (val || "");
  const copyCell = useCallback((val, colName) => {
    const text = colName != null && colName !== "" ? fmtCell(colName, val) : (val || "");
    navigator.clipboard?.writeText(text);
    setCopiedMsg(true);
    setTimeout(() => setCopiedMsg(false), 1200);
  }, [dateTimeFormat, timezone, ct?.tsColumns]);
  const hlTerm = ct?.searchHighlight ? (effectiveSearchTerm(ct?.searchTerm).trim() || null) : null;
  const hlRegex = useMemo(() => {
    if (!hlTerm) return null;
    try {
      if (ct?.searchMode === "regex") return new RegExp(`(${hlTerm})`, "gi");
      // For multi-word mixed/AND, highlight each word separately
      const words = hlTerm.split(/\s+/).filter(Boolean).map((w) =>
        w.replace(/^[+\-"]|"$/g, "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
      ).filter(Boolean);
      if (words.length === 0) return null;
      return new RegExp(`(${words.join("|")})`, "gi");
    } catch { return null; }
  }, [hlTerm, ct?.searchMode]);
  // IOC highlight regex — built from matched IOC values stored after IOC scan
  const iocRegex = useMemo(() => {
    const patterns = ct?.iocHighlights;
    if (!patterns || patterns.length === 0) return null;
    try {
      // Sort longest first so longer IOCs match before shorter substrings
      const sorted = [...patterns].sort((a, b) => b.length - a.length);
      const escaped = sorted.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      return new RegExp(`(${escaped.join("|")})`, "gi");
    } catch { return null; }
  }, [ct?.iocHighlights]);
  const iocTestRegex = useMemo(() => iocRegex ? new RegExp(iocRegex.source, "i") : null, [iocRegex]);
  // Pre-built combined regex for when both highlight + IOC are active (avoids per-cell RegExp creation)
  const combinedHlRegex = useMemo(() => {
    if (!hlRegex || !iocRegex) return null;
    try { return new RegExp(`${iocRegex.source}|${hlRegex.source}`, "gi"); } catch { return null; }
  }, [hlRegex, iocRegex]);
  const _hlStyle = { background: "rgba(210,153,34,0.5)", color: "inherit", borderRadius: 2, padding: "0 1px" };
  const _iocStyle = { background: "rgba(240,136,62,0.45)", color: "inherit", borderRadius: 2, padding: "0 1px", fontWeight: 600 };
  const renderCell = (h, val) => {
    const text = fmtCell(h, val);
    if (!text || (!hlRegex && !iocRegex)) return text;
    // Single highlight source — use fast split path
    if (hlRegex && !iocRegex) {
      const splits = text.split(hlRegex);
      if (splits.length <= 1) return text;
      return <>{splits.map((seg, i) => i % 2 === 1
        ? <mark key={i} style={_hlStyle}>{seg}</mark>
        : seg
      )}</>;
    }
    if (iocRegex && !hlRegex) {
      const splits = text.split(iocRegex);
      if (splits.length <= 1) return text;
      return <>{splits.map((seg, i) => i % 2 === 1
        ? <mark key={i} style={_iocStyle}>{seg}</mark>
        : seg
      )}</>;
    }
    // Both active — use pre-built combined regex, color by match type
    if (!combinedHlRegex) return text;
    combinedHlRegex.lastIndex = 0; // reset instead of cloning
    const parts = [];
    let lastIndex = 0;
    let m;
    while ((m = combinedHlRegex.exec(text)) !== null) {
      if (m.index > lastIndex) parts.push(text.slice(lastIndex, m.index));
      const isIoc = iocTestRegex.test(m[0]);
      parts.push(<mark key={m.index} style={isIoc ? _iocStyle : _hlStyle}>{m[0]}</mark>);
      lastIndex = combinedHlRegex.lastIndex;
      if (m[0].length === 0) { combinedHlRegex.lastIndex++; }
    }
    if (lastIndex === 0) return text;
    if (lastIndex < text.length) parts.push(text.slice(lastIndex));
    return <>{parts}</>;
  };
  const tw = useMemo(() => getGridContentWidth({
    visibleColumns: allVisH,
    columnWidths: ct?.columnWidths,
    leadingWidth: isGrouped
      ? (16 + 26 + CHECKBOX_COL_WIDTH)
      : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH),
    tagWidth: tagColWidth,
    vtWidth: ct?.vtEnrichment
      ? (ct?.columnWidths?.["__vt__"] || VT_COL_WIDTH)
      : 0,
    evidenceWidth: hasEvidencePills
      ? (ct?.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH)
      : 0,
  }), [
    allVisH,
    ct?.columnWidths,
    tagColWidth,
    isGrouped,
    ct?.vtEnrichment,
    hasEvidencePills,
  ]);

  // Reset search navigation whenever its result population changes.
  useEffect(() => {
    searchMatchIdxRef.current = -1;
    setSearchMatchIdx(-1);
    setSearchMatchPosition(-1);
  }, [
    ct?.searchTerm,
    ct?.totalFiltered,
    ct?.searchHighlight,
    ct?.searchMode,
    ct?.searchCondition,
    ct?.sortCol,
    ct?.sortDir,
    currentFilterScopeSignature,
  ]);

  // Highlight mode leaves the grid unfiltered, so its match total must be
  // counted separately. LIMIT 0 keeps all row data in SQLite.
  useEffect(() => {
    if (!tle || !ct?.searchHighlight || !effectiveSearchTerm(ct?.searchTerm) || isGrouped || !currentFilterOptions) {
      setHighlightMatchCount(0);
      return;
    }
    let cancelled = false;
    setHighlightMatchCount(-1);
    const timer = setTimeout(async () => {
      try {
        const result = await tle.queryRows(ct.id, {
          ...currentFilterOptions,
          offset: 0,
          limit: 0,
          searchTerm: ct.searchTerm,
          searchMode: ct.searchMode,
          searchCondition: ct.searchCondition || "contains",
        });
        if (!cancelled) {
          setHighlightMatchCount(
            isIpcError(result) ? 0 : Math.max(0, Number(result?.totalFiltered) || 0),
          );
        }
      } catch {
        if (!cancelled) setHighlightMatchCount(0);
      }
    }, QUERY_DEBOUNCE);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [
    tle,
    ct?.id,
    ct?.searchHighlight,
    ct?.searchTerm,
    ct?.searchMode,
    ct?.searchCondition,
    isGrouped,
    currentFilterOptions,
    currentFilterScopeSignature,
  ]);

  const scrollToRow = useCallback((idx) => {
    if (!scrollRef.current) return;
    const sf = scrollMapRef.current.scaleFactor || 1;
    const target = getRowScrollTarget({
      rowIndex: idx,
      rowHeight: ROW_HEIGHT,
      logicalScrollTop: scrollMapRef.current.logicalScrollTop || 0,
      viewportHeight: scrollRef.current.clientHeight,
      stickyHeight: HEADER_HEIGHT + FILTER_HEIGHT,
    });
    // Map the logical row target back to the capped physical scroll range.
    if (target !== null) scrollRef.current.scrollTop = target / sf;

    // Prefetch SQL window when jumping via keyboard/search (same margin as scroll-driven fetch).
    if (!isGrouped && ct?.dataReady) {
      const offset = ct.rowOffset || 0;
      const loadedRows = ct.rows?.length || 0;
      const windowEnd = offset + loadedRows;
      const visibleRows = Math.max(60, Math.ceil((scrollRef.current?.clientHeight || 0) / ROW_HEIGHT) + OVERSCAN);
      const ahead = fetchAheadForLimit(Math.max(loadedRows, fetchLimitForTab(ct)));
      const cacheCoversViewport = rowWindowCovers(offset, loadedRows, idx, visibleRows);
      const fullZeroBasedCache = offset === 0 && loadedRows >= (ct.totalFiltered || 0);
      const needsFetch = !cacheCoversViewport
        || idx < offset + ahead
        || idx + visibleRows > windowEnd - ahead;
      if (needsFetch && !fullZeroBasedCache) {
        fetchData(ct, idx);
      }
    }
  }, [ct, isGrouped, fetchData]);

  // Process Inspector grid pivot: after filters land, scroll/select the source create event.
  useEffect(() => {
    const focusId = ct?.pendingFocusRowId;
    if (!ct?.dataReady || !focusId || isGrouped) return;
    const rows = ct.rows || [];
    const local = rows.findIndex((r) => Number(r?.__idx) === Number(focusId));
    if (local < 0) return; // not in current window yet — wait for next fetch
    const absIdx = (ct.rowOffset || 0) + local;
    up("pendingFocusRowId", null);
    setSelectedRows(new Set([Number(focusId)]));
    setLastClickedRow(absIdx);
    requestAnimationFrame(() => scrollToRow(absIdx));
  }, [ct?.pendingFocusRowId, ct?.rows, ct?.rowOffset, ct?.dataReady, isGrouped]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectSingleRowAt = async (idx, knownRowId = null) => {
    let rowId = Number(knownRowId);
    if (!Number.isSafeInteger(rowId) || rowId <= 0) rowId = getRowIdAt(idx);
    const rowWasCached = getRowIdAt(idx) !== null;
    if (rowId === null) {
      try {
        const result = await tle.getRowIdsInRange(ct.id, {
          ...currentFilterOptions,
          sortCol: ct.sortCol,
          sortDir: ct.sortDir,
          offset: idx,
          limit: 1,
        });
        if (isIpcError(result) || !Array.isArray(result?.rowIds)) {
          throw new Error(ipcErrorMessage(result, "Could not resolve the row"));
        }
        rowId = Number(result.rowIds[0]);
      } catch (err) {
        toast.error("Row navigation failed", { detail: String(err?.message || err) });
        return false;
      }
    }
    if (!Number.isSafeInteger(rowId) || rowId <= 0) return false;
    if (!rowWasCached) await fetchData(ct, idx);
    setAllRowsSelected(false);
    setSelectionTabId(ct.id);
    setSelectAllScopeSignature(null);
    setSelectedRows(new Set([rowId]));
    setLastClickedRow(idx);
    setDetailPanelOpen(true);
    return true;
  };

  const navigateSearch = async (dir) => {
    const total = ct?.totalFiltered || 0;
    if (!effectiveSearchTerm(ct?.searchTerm) || isGrouped || searchNavigationPendingRef.current) return;
    searchNavigationPendingRef.current = true;
    try {
      if (ct.searchHighlight) {
        const result = await tle.findSearchMatch(ct.id, {
          ...currentFilterOptions,
          sortCol: ct.sortCol,
          sortDir: ct.sortDir,
          currentIndex: searchMatchIdxRef.current,
          direction: dir,
          matchSearchTerm: ct.searchTerm,
          matchSearchMode: ct.searchMode,
          matchSearchCondition: ct.searchCondition || "contains",
        });
        if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
        if (!Number.isSafeInteger(result?.index) || result.index < 0) {
          setHighlightMatchCount(0);
          return;
        }
        searchMatchIdxRef.current = result.index;
        setSearchMatchIdx(result.index);
        setSearchMatchPosition(result.position);
        setHighlightMatchCount(result.totalMatches);
        if (!await selectSingleRowAt(result.index, result.rowId)) return;
        requestAnimationFrame(() => scrollToRow(result.index));
        return;
      }
      if (total === 0) return;
      let next;
      const currentIndex = searchMatchIdxRef.current;
      if (dir === 1) next = currentIndex < total - 1 ? currentIndex + 1 : 0;
      else next = currentIndex > 0 ? currentIndex - 1 : total - 1;
      searchMatchIdxRef.current = next;
      setSearchMatchIdx(next);
      setSearchMatchPosition(next);
      if (!await selectSingleRowAt(next)) return;
      requestAnimationFrame(() => scrollToRow(next));
    } catch (err) {
      toast.error("Search navigation failed", { detail: String(err?.message || err) });
    } finally {
      searchNavigationPendingRef.current = false;
    }
  };

  // ── Column resize ────────────────────────────────────────────────
  useEffect(() => {
    if (!resizingCol || !ct) return;
    const onMove = (e) => {
      const nw = Math.max(60, resizeW + (e.clientX - resizeX));
      up("columnWidths", { ...ct.columnWidths, [resizingCol]: nw });
    };
    const onUp = () => { justResizedRef.current = true; setResizingCol(null); requestAnimationFrame(() => { justResizedRef.current = false; }); };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
  }, [resizingCol, resizeX, resizeW]);

  // ── Detail panel resize (DOM-direct for smooth dragging) ───────
  const onDetailResizeStart = (e) => {
    e.preventDefault();
    const startY = e.clientY;
    const startH = detailPanelHeight;
    detailResizeStartY.current = startY;
    detailResizeStartH.current = startH;
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    const panel = detailPanelRef.current;
    const scrollEl = scrollRef.current;
    const onMove = (ev) => {
      const delta = detailResizeStartY.current - ev.clientY;
      const newH = Math.min(DETAIL_PANEL_MAX_HEIGHT, Math.max(DETAIL_PANEL_MIN_HEIGHT, detailResizeStartH.current + delta));
      if (panel) panel.style.height = newH + "px";
      if (scrollEl) scrollEl.style.flex = "1";
    };
    const onUp = (ev) => {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      const delta = detailResizeStartY.current - ev.clientY;
      const finalH = Math.min(DETAIL_PANEL_MAX_HEIGHT, Math.max(DETAIL_PANEL_MIN_HEIGHT, detailResizeStartH.current + delta));
      setDetailPanelHeight(finalH);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // ── Histogram resize (DOM-direct for smooth dragging) ───────────
  const onHistResizeStart = (e) => {
    e.preventDefault();
    histResizeStartY.current = e.clientY;
    histResizeStartH.current = histogramHeight;
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    const onMove = (ev) => {
      const delta = ev.clientY - histResizeStartY.current;
      const newH = Math.min(500, Math.max(80, histResizeStartH.current + delta));
      // Direct DOM update for smoothness
      const el = document.getElementById("hist-container");
      if (el) el.style.height = newH + "px";
      const svg = el?.querySelector("svg");
      if (svg) svg.setAttribute("height", newH - 30);
    };
    const onUp = (ev) => {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      const delta = ev.clientY - histResizeStartY.current;
      const finalH = Math.min(500, Math.max(80, histResizeStartH.current + delta));
      setHistogramHeight(finalH);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // ── Filter dropdown data ─────────────────────────────────────────
  const loadFilterValues = useCallback(async (colName, searchText, preselectAll, useRegex = false) => {
    const tab = ctRef.current;
    if (!tle || !tab) return;
    if (tab.isLargeFile && !tab.indexesReady) {
      toast.warning("Indexes still building", {
        detail: "Column filter lists on large timelines are safest after the toolbar shows indexes ready. Showing values may use a row sample.",
        ttl: 8000,
      });
    }
    setFdLoading(true);
    setFdSampled(false);
    try {
      const af = activeFilters(tab);
      const result = await tle.getColumnUniqueValues(tab.id, colName, {
        searchTerm: effectiveSearchTerm(tab.searchHighlight ? "" : tab.searchTerm), searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly, filterText: searchText, filterRegex: useRegex,
        tagFilter: (tab.disabledFilters || new Set()).has("__tags__") ? null : (tab.tagFilter || null),
        rowIdFilter: tab.rowIdFilter || null,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
      });
      if (isIpcCancelled(result)) {
        setFdLoading(false);
        return;
      }
      const vals = isIpcError(result)
        ? []
        : Array.isArray(result) ? result : Array.isArray(result?.values) ? result.values : [];
      setFdSampled(Boolean(result?.sampled || vals.sampled));
      setFdValueMeta({
        totalDistinct: Array.isArray(result) ? vals.length : Number(result?.totalDistinct || vals.length),
        truncated: !Array.isArray(result) && Boolean(result?.truncated),
      });
      setFdValues(vals);
      // Pre-select all values when no existing filter (so user unchecks to exclude)
      if (preselectAll) {
        setFdSelected(new Set(vals.map((v) => v.val)));
      } else if (searchText) {
        // When searching, trim selection to only visible values so Apply works correctly
        const visible = new Set(vals.map((v) => v.val));
        setFdSelected((prev) => new Set([...prev].filter((v) => visible.has(v))));
      }
    } catch {
      setFdValues([]);
      setFdSampled(false);
      setFdValueMeta({ totalDistinct: 0, truncated: false });
    }
    setFdLoading(false);
  }, [tle]);

  useEffect(() => {
    if (!filterDropdown) {
      setFdValues([]);
      setFdSearch("");
      setFdSelected(new Set());
      setFdRegex(false);
      setFdSampled(false);
      setFdValueMeta({ totalDistinct: 0, truncated: false });
      return;
    }
    setFdSampled(false);
    if (filterDropdown.colName === "__tags__") {
      // Tags filter — load tags from DB
      const existing = ct?.tagFilter;
      // Handle both array tagFilter (checkbox selection) and string tagFilter ("Show Only IOC Matches" button)
      const hasExisting = existing && (Array.isArray(existing) ? existing.length > 0 : typeof existing === "string");
      const existingSet = hasExisting
        ? new Set(Array.isArray(existing) ? existing : [existing])
        : new Set();
      setFdSelected(existingSet);
      setFdSearch("");
      setFdRegex(false);
      (async () => {
        setFdLoading(true);
        const tags = await tle.getAllTags(ct.id);
        const vals = (tags || []).map((t) => ({ val: t.tag, cnt: t.cnt }));
        setFdValues(vals);
        setFdValueMeta({ totalDistinct: vals.length, truncated: false });
        setFdLoading(false);
      })().catch(() => { setFdLoading(false); });
      return;
    }
    if (filterDropdown.colName === "__vt__") {
      // VT verdict filter — load VT verdict tags from DB
      const existing = ct?.checkboxFilters?.["__vt__"];
      const hasExisting = existing?.length > 0;
      setFdSelected(hasExisting ? new Set(existing) : new Set());
      setFdSearch("");
      setFdRegex(false);
      (async () => {
        setFdLoading(true);
        const tags = await tle.getAllTags(ct.id);
        const vals = (tags || []).filter((t) => t.tag.startsWith("VT:")).map((t) => ({ val: t.tag, cnt: t.cnt }));
        setFdValues(vals);
        setFdValueMeta({ totalDistinct: vals.length, truncated: false });
        setFdLoading(false);
      })().catch(() => { setFdLoading(false); });
      return;
    }
    const existing = ct?.checkboxFilters?.[filterDropdown.colName];
    const hasExisting = checkboxFilterActive(existing);
    setFdSelected(hasExisting ? new Set(normalizeCheckboxFilterValues(existing)) : new Set());
    setFdSearch("");
    setFdRegex(false);
    loadFilterValues(filterDropdown.colName, "", !hasExisting, false);
  }, [filterDropdown?.colName]);

  useEffect(() => {
    if (!filterDropdown) return;
    if (filterDropdown.colName === "__tags__" || filterDropdown.colName === "__vt__") return; // Tags/VT don't support search-while-typing
    const t = setTimeout(() => loadFilterValues(filterDropdown.colName, fdSearch, false, fdRegex), 300);
    return () => clearTimeout(t);
  }, [fdSearch, fdRegex]);

  const applyCheckboxFilter = () => {
    if (!filterDropdown) return;
    const colName = filterDropdown.colName;
    // Tags filter — apply as tagFilter array
    // Unlike regular columns, "all tags selected" still means "show only tagged rows" (not all rows)
    if (colName === "__tags__") {
      setTabs((prev) => prev.map((t) => {
        if (t.id !== activeTab) return t;
        if (fdSelected.size === 0) return { ...t, tagFilter: null };
        return { ...t, tagFilter: [...fdSelected] };
      }));
      setFilterDropdown(null);
      return;
    }
    if (colName === "__vt__") {
      // VT filter — like tags, "all selected" still means "show only VT-tagged rows"
      setTabs((prev) => prev.map((t) => {
        if (t.id !== activeTab) return t;
        const newCbf = { ...t.checkboxFilters };
        if (fdSelected.size === 0) delete newCbf["__vt__"];
        else newCbf["__vt__"] = [...fdSelected];
        return { ...t, checkboxFilters: newCbf };
      }));
      setFilterDropdown(null);
      return;
    }
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const newCbf = { ...t.checkboxFilters };
      // "All selected = no filter" only when NOT searching (search narrows the list, so all-checked means the user wants only those values)
      if (fdSelected.size === 0 || (!fdSearch && fdSelected.size === fdValues.length)) delete newCbf[colName];
      else newCbf[colName] = [...fdSelected];
      return { ...t, checkboxFilters: newCbf };
    }));
    setFilterDropdown(null);
  };

  // ── Whole-column copy ────────────────────────────────────────────
  // Pull EVERY value of one column for the current filtered/searched view (full
  // dataset, not just the loaded window) and put it on the clipboard, one per line.
  // distinct:true → unique + sorted (ready to dedup/paste IPs, hostnames, etc.).
  // Defined BEFORE the keyboard-shortcuts effect that lists it in deps — a const
  // referenced in a dep array must be initialized first (else a TDZ crash at render).
  const copyColumnValues = useCallback(async (colName, { distinct = false } = {}) => {
    if (!tle || !ct || !colName) return;
    try {
      const af = activeFilters(ct);
      const res = await tle.getColumnValues(ct.id, colName, {
        searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly,
        tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
        rowIdFilter: ct.rowIdFilter || null,
        dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        sortCol: ct.sortCol || null,
        sortDir: ct.sortDir || "asc",
        distinct,
      });
      if (isIpcError(res)) throw new Error(ipcErrorMessage(res));
      const values = res?.values || [];
      if (values.length === 0) { toast.info("No values to copy in that column for the current view."); return; }
      let copyValues = (dateTimeFormat && ct.tsColumns?.has(colName))
        ? values.map((v) => formatDateTime(v, dateTimeFormat, timezone))
        : values;
      if (distinct) {
        const seen = new Set();
        copyValues = copyValues.filter((v) => {
          const key = String(v ?? "");
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
      }
      await navigator.clipboard?.writeText(copyValues.join("\n"));
      setCopiedMsg(true);
      setTimeout(() => setCopiedMsg(false), 1200);
      const label = distinct ? "unique value" : "value";
      toast.success(`Copied ${formatNumber(copyValues.length)} ${label}${copyValues.length === 1 ? "" : "s"} from "${colName}"${res?.truncated ? " (truncated at 1,000,000)" : ""}`);
    } catch (err) {
      toast.error("Couldn't copy column", { detail: String(err?.message || err) });
    }
  }, [tle, ct, activeFilters, setCopiedMsg, dateTimeFormat, timezone]);

  const copySelectedRows = useCallback(async () => {
    if (!tle || !ct || selectionCount === 0) return;
    const hdrs = ct.headers.filter((h) => !ct.hiddenColumns?.has(h));
    const maxClipboardRows = 100_000;
    let selectedData = [];
    let truncated = false;

    try {
      if (!allRowsSelected) {
        const requestedIds = [...selectedRows].slice(0, maxClipboardRows);
        selectedData = await tle.getRowsByIds(ct.id, requestedIds);
        if (isIpcError(selectedData) || !Array.isArray(selectedData)) {
          throw new Error(ipcErrorMessage(selectedData, "Could not load selected rows"));
        }
        truncated = selectionCount > selectedData.length;
      } else {
        const { columnFilters, checkboxFilters } = activeFilters(ct);
        const rawSearch = ct.searchHighlight ? "" : ct.searchTerm;
        const effectiveSearch = rawSearch && rawSearch.trim().length < 2 ? "" : rawSearch;
        const batchSize = 10_000;
        let offset = 0;

        while (offset < (ct.totalFiltered || 0) && selectedData.length < maxClipboardRows) {
          const result = await tle.queryRows(ct.id, {
            offset,
            limit: batchSize,
            sortCol: ct.sortCol,
            sortDir: ct.sortDir,
            searchTerm: effectiveSearch,
            searchMode: ct.searchMode,
            searchCondition: ct.searchCondition || "contains",
            columnFilters,
            checkboxFilters,
            bookmarkedOnly: ct.showBookmarkedOnly,
            tagFilter: (ct.disabledFilters || new Set()).has("__tags__")
              ? null
              : (ct.tagFilter || null),
            rowIdFilter: ct.rowIdFilter || null,
            dateRangeFilters: ct.dateRangeFilters || {},
            advancedFilters: ct.advancedFilters || [],
          });
          if (isIpcError(result) || !Array.isArray(result?.rows)) {
            throw new Error(ipcErrorMessage(result, "Could not load selected rows"));
          }
          if (result.rows.length === 0) break;
          for (const row of result.rows) {
            if (!selectedRows.has(Number(row.__idx))) selectedData.push(row);
            if (selectedData.length >= maxClipboardRows) break;
          }
          offset += result.rows.length;
        }
        truncated = selectionCount > selectedData.length;
      }

      const lines = [hdrs.join("\t")];
      for (const row of selectedData) {
        lines.push(hdrs.map((h) =>
          String(row[h] || "").replace(/\t/g, " ").replace(/\r?\n/g, " ")
        ).join("\t"));
      }
      await navigator.clipboard?.writeText(lines.join("\n"));
      setCopiedMsg(true);
      setTimeout(() => setCopiedMsg(false), 1200);
      toast.success(`Copied ${formatNumber(selectedData.length)} selected row${selectedData.length === 1 ? "" : "s"}${truncated ? " (clipboard limit: 100,000; use Export for the full view)" : ""}`);
    } catch (err) {
      toast.error("Couldn't copy selected rows", { detail: String(err?.message || err) });
    }
  }, [
    tle,
    ct,
    selectionCount,
    allRowsSelected,
    selectedRows,
    activeFilters,
    setCopiedMsg,
  ]);

  // ── Keyboard shortcuts ───────────────────────────────────────────
  useEffect(() => {
    const h = (e) => {
      const mod = e.metaKey || e.ctrlKey;
      const target = e.target;
      const isTextControl = target instanceof HTMLElement
        && (target.matches("input, textarea, select") || target.isContentEditable);
      if (mod && e.key === "w") { e.preventDefault(); const cur = ctRef.current; if (cur) closeTabRef.current?.(cur.id); return; }
      if (mod && e.key === "s") { e.preventDefault(); handleSaveSessionRef.current?.(); }
      if (mod && e.shiftKey && e.key === "O") { e.preventDefault(); handleLoadSessionRef.current?.(); }
      if (mod && e.key === "o") { e.preventDefault(); runOpenFileDialog(); }
      if (mod && e.key === "f" && !e.shiftKey) { e.preventDefault(); document.getElementById("gs")?.focus(); }
      if (mod && e.shiftKey && e.key === "f") { e.preventDefault(); setModal(openSimpleModal("crossfind")); }
      if (mod && e.key === "e") { e.preventDefault(); handleExport(); }
      if (mod && e.key === "b") { e.preventDefault(); if (ct) up("showBookmarkedOnly", !ct.showBookmarkedOnly); }
      if (mod && e.key === "r") { e.preventDefault(); resetColumnWidthsRef.current?.(); }
      if (mod && (e.key === "?" || e.key === "/")) { e.preventDefault(); setModal(openSimpleModal("shortcuts")); return; }
      // ⌘⇧A / Ctrl+Shift+A — select an entire column (toggle). Targets the open column
      // menu's column, else the sorted column, else the first visible column.
      if (mod && e.shiftKey && (e.key === "A" || e.key === "a") && ct) {
        e.preventDefault();
        const visible = (ct.headers || []).filter((h) => !ct.hiddenColumns?.has(h));
        const target = (contextMenu?.colName && contextMenu.colName !== "__tags__") ? contextMenu.colName
          : (ct.sortCol && visible.includes(ct.sortCol)) ? ct.sortCol
          : visible[0] || null;
        if (target) setSelectedColumn(selectedColumn === target ? null : target);
        return;
      }
      // ⌘C with a selected column but no selected rows → copy that whole column's values.
      if (mod && e.key === "c" && selectedColumn && selectionCount === 0 && ct) {
        const sel = window.getSelection();
        if (sel && sel.toString().trim().length > 0) return;
        e.preventDefault();
        copyColumnValues(selectedColumn, { distinct: false });
        return;
      }
      if (mod && e.key === "c" && selectionCount > 0 && ct) {
        // If user has text selected in the DOM (e.g., detail panel cell), let native copy handle it
        const sel = window.getSelection();
        if (sel && sel.toString().trim().length > 0) return;
        e.preventDefault();
        copySelectedRows();
        return;
      }
      if (e.key === "Escape") {
        if (cellPopup) { setCellPopup(null); return; }
        if (modal?.type === "aiSecrets") {
          if (modal.tagMenuGroup) setModal((prev) => (prev?.type === "aiSecrets" ? { ...prev, tagMenuGroup: null, tagDraft: "" } : prev));
          return;
        }
        if (modal) { setModal(null); return; }
        if (filterDropdown) { setFilterDropdown(null); return; }
        if (dateRangeDropdown) { setDateRangeDropdown(null); return; }
        if (contextMenu) { setContextMenu(null); return; }
        if (cellContextMenu) { setCellContextMenu(null); return; }
        if (rowContextMenu) { setRowContextMenu(null); return; }
        if (fileMenuOpen) { setFileMenuOpen(false); return; }
        if (viewMenuOpen) { setViewMenuOpen(false); return; }
        if (toolsOpen) { setToolsOpen(false); return; }
        if (actionsMenuOpen) { setActionsMenuOpen(false); return; }
        if (helpMenuOpen) { setHelpMenuOpen(false); return; }
        if (detailPanelOpen && selectionCount > 0) { setDetailPanelOpen(false); return; }
        if (selectedColumn) { setSelectedColumn(null); return; }
        if (selectionCount > 0) {
          clearRowSelection();
          return;
        }
      }
      // Open context menu for selected row (Shift+F10 = standard context menu key)
      if (e.key === "F10" && e.shiftKey && lastClickedRow !== null && ct) {
        e.preventDefault();
        const item = getRowAt(lastClickedRow);
        const row = isGrouped ? (item?.data || item) : item;
        if (row && row.__idx) {
          const rTags = (ct.rowTags || {})[row.__idx] || [];
          // Position near the selected row using the scroll container
          const scrollEl = scrollRef.current;
          const rect = scrollEl ? scrollEl.getBoundingClientRect() : { left: 200, top: 200 };
          const yPos = rect.top + (lastClickedRow * ROW_HEIGHT) - scrollMapRef.current.logicalScrollTop + HEADER_HEIGHT + FILTER_HEIGHT + ROW_HEIGHT / 2;
          setRowContextMenu({ x: rect.left + 100, y: Math.min(Math.max(yPos, rect.top + 40), window.innerHeight - 300), rowId: row.__idx, rowIndex: lastClickedRow, currentTags: rTags, row });
        }
      }
      // Find next/prev: Ctrl+Right/Left or F3/Shift+F3
      if ((mod && e.key === "ArrowRight") || (e.key === "F3" && !e.shiftKey)) { e.preventDefault(); navigateSearch(1); }
      if ((mod && e.key === "ArrowLeft") || (e.key === "F3" && e.shiftKey)) { e.preventDefault(); navigateSearch(-1); }
      if (!isGrouped && !isTextControl && e.key === "ArrowDown" && lastClickedRow !== null && !mod) {
        e.preventDefault();
        const total = ct?.totalFiltered || rows.length;
        const next = Math.min(total - 1, lastClickedRow + 1);
        void selectSingleRowAt(next).then((selected) => {
          if (selected) requestAnimationFrame(() => {
            scrollToRow(next);
            requestAnimationFrame(() => scrollRef.current?.querySelector(`[data-row-index="${next}"]`)?.focus({ preventScroll: true }));
          });
        });
      }
      if (!isGrouped && !isTextControl && e.key === "ArrowUp" && lastClickedRow !== null && !mod) {
        e.preventDefault();
        const next = Math.max(0, lastClickedRow - 1);
        void selectSingleRowAt(next).then((selected) => {
          if (selected) requestAnimationFrame(() => {
            scrollToRow(next);
            requestAnimationFrame(() => scrollRef.current?.querySelector(`[data-row-index="${next}"]`)?.focus({ preventScroll: true }));
          });
        });
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [ct, activeTab, selectedRows, allRowsSelected, selectionCount, lastClickedRow, ct?.totalFiltered, isGrouped, getRowAt, searchMatchIdx, navigateSearch, selectedColumn, setSelectedColumn, copyColumnValues, copySelectedRows, contextMenu, clearRowSelection]);



  // ── Modal styles (shared by all modals) ───────────────────────
  const ms = makeModalStyles(th);

  // ── Helper: compute row background ───────────────────────────────
  const getRowBg = (ai, _row, sel, cm, bm) => {
    if (sel) return th.selection;
    if (cm) return cm.bg;
    if (bm) return th.bookmark;
    return ai % 2 === 0 ? th.rowEven : th.rowOdd;
  };


  // ── Empty state ──────────────────────────────────────────────────
  if (tabs.length === 0) {
    // Launch a capability from the home screen: remember the user's intent, open the
    // file picker, and (on import-complete) auto-open the matching analyzer with
    // pre-detected columns. If the user cancels the dialog, drop the intent so it can't
    // fire on a later, unrelated import.
    const launchCapabilityFromHome = async (capKey) => {
      // Arm the intent unbound; onImportStart binds it to the first import that begins
      // after arming (the one this dialog kicks off), so a later/parallel import can't
      // consume it and fire the analyzer on the wrong tab.
      pendingCapabilityRef.current = { capability: capKey, tabId: null };
      try {
        const res = await runOpenFileDialog();
        if (res == null) pendingCapabilityRef.current = null; // null === user canceled
      } catch {
        pendingCapabilityRef.current = null;
      }
    };

    // Capability tiles for the command-center home canvas. Each analyzer tile picks a
    // file and then auto-opens its analyzer (via pendingCapabilityRef → import-complete
    // → HOME_CAPABILITY_LAUNCHERS). `chip` states the input the analyzer needs; `outcome`
    // is the bottom hint describing what you get. Sigma scans raw EVTX with no import;
    // Open & Explore just drops you in the grid.
    const homeTiles = [
      { title: "Process Inspector", desc: "Process-chain threat scoring & execution-tree analysis", color: th.accent, capability: "processInspector", chip: "Sysmon · 4688", outcome: "Open → process tree", onClick: () => launchCapabilityFromHome("processInspector"),
        icon: <><path d="M12 3v5"/><path d="M12 8L6 12v3"/><path d="M12 8l6 4v3"/><rect x="9" y="2" width="6" height="4" rx="1"/><rect x="3" y="15" width="6" height="4" rx="1"/><rect x="15" y="15" width="6" height="4" rx="1"/></> },
      { title: "Lateral Movement", desc: "Cross-host pivots · RDP, WinRM & remote execution", color: th.accent, capability: "lateralMovement", chip: "4624 / 4625", outcome: "Open → pivot graph", onClick: () => launchCapabilityFromHome("lateralMovement"),
        icon: <><circle cx="5" cy="12" r="2.4"/><circle cx="19" cy="5" r="2.4"/><circle cx="19" cy="19" r="2.4"/><path d="M7 11l10-5M7 13l10 5"/></> },
      { title: "Persistence", desc: "Autostart, services, tasks, WMI & COM hijacks", color: th.accent, capability: "persistence", chip: "7045 / 4698", outcome: "Open → autoruns", onClick: () => launchCapabilityFromHome("persistence"),
        icon: <><path d="M12 21V9"/><circle cx="12" cy="6" r="3"/><path d="M5 13H3m4.5 5L6 19.5M18 13h2m-3.5 5l1.5 1.5"/></> },
      { title: "Sigma · Hayabusa", desc: "Sigma detection over raw EVTX — no import needed", color: th.accent, outcome: "Scan a directory →", ready: true, onClick: () => setModal(openSigmaModal({ scanMode: "evtx-dir" })),
        icon: <><circle cx="12" cy="12" r="9"/><path d="M12 4v8l5 3"/></> },
      { title: "Collect AI Artifacts", desc: "Claude, Codex, Cursor, ChatGPT & more — scan this Mac or a triage folder into one AI history timeline.", color: th.accent, chip: "Mac / folder", outcome: "Scan → AI timeline", onClick: () => setModal(openAiHistoryProfileScanModal()),
        icon: <><path d="M11 3l1.7 4.4L17 9l-4.3 1.6L11 15l-1.7-4.4L5 9l4.3-1.6z"/><path d="M17.6 14l.7 1.8 1.7.7-1.7.7-.7 1.8-.7-1.8-1.7-.7 1.7-.7z"/></> },
      { title: "Master File Table", desc: "Ransomware mass-encryption, in-place rewrites & recovery-target deletion across the $MFT", color: th.accent, capability: "mft", chip: "Raw $MFT", outcome: "Open → ransomware scan", onClick: () => launchCapabilityFromHome("mft"),
        icon: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><rect x="10" y="11" width="4" height="4" rx="1"/><path d="M10.5 11V9.5a1.5 1.5 0 0 1 3 0V11"/></> },
      { title: "USN Journal", desc: "Renames, deletions, exfil staging & self-deletion from the $J journal", color: th.accent, capability: "usn", chip: "$J / USN", outcome: "Open → journal triage", onClick: () => launchCapabilityFromHome("usn"),
        icon: <><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></> },
      { title: "Open & Explore", desc: "Just browse a large CSV / TSV / XLSX in a fast grid — filter, search & sort. No analyzer needed.", color: th.accent, chip: "Any file", outcome: "Open any file →", onClick: () => runOpenFileDialog(),
        icon: <><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M3 15h18M9 3v18M15 3v18"/></> },
    ];
    return (
      <div onContextMenu={(e) => e.preventDefault()} style={{ display: "flex", height: "100vh", background: th.bg, fontFamily: "'SF Mono',Menlo,monospace", WebkitAppRegion: "drag", overflow: "hidden", position: "relative" }}
        onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; setDragOver(true); }}
        onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setDragOver(false); }}
        onDrop={(e) => { e.preventDefault(); setDragOver(false); pendingCapabilityRef.current = null; /* drag = "just open", not a tile launch → drop any armed capability so it can't fire on this import */ const files = [...e.dataTransfer.files]; if (files.length > 0 && tle) { const paths = files.map((f) => tle.getPathForFile(f)).filter(Boolean); if (paths.length > 0) runImportPaths(paths); } }}>
        <div style={{ width: 360, flexShrink: 0, display: "flex", flexDirection: "column", alignItems: "stretch", padding: "26px 24px 18px", borderRight: `1px solid ${th.border}`, background: th.panelBg, overflowY: "auto", WebkitAppRegion: "no-drag", zIndex: 2 }}>
          {/* IRFlow Logo — shield with timeline pulse */}
          <svg width="52" height="59" viewBox="0 0 64 72" fill="none" style={{ marginBottom: 14 }}>
            {/* Shield body */}
            <path d="M32 4L6 16v20c0 16.5 11.2 31.2 26 36 14.8-4.8 26-19.5 26-36V16L32 4z" fill={`${th.accent}18`} stroke={th.accent} strokeWidth="1.8" strokeLinejoin="round" />
            {/* Timeline pulse across shield */}
            <polyline points="14,40 22,40 25,28 29,48 33,22 37,44 40,34 42,40 50,40" fill="none" stroke={th.accent} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            {/* Clock tick marks at top of shield */}
            <circle cx="32" cy="20" r="6" fill="none" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="32" y1="15.5" x2="32" y2="17" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="32" y1="23" x2="32" y2="24.5" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="27.5" y1="20" x2="29" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="35" y1="20" x2="36.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            {/* Clock hands */}
            <line x1="32" y1="20" x2="32" y2="17.5" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
            <line x1="32" y1="20" x2="34.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
          </svg>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: th.text, margin: 0, fontFamily: "-apple-system, 'SF Pro Display', sans-serif", letterSpacing: "-0.01em" }}>IRFlow <span style={{ color: th.accent }}>Timeline</span></h1>
          <p style={{ color: th.textDim, fontSize: 14, letterSpacing: "0.14em", textTransform: "uppercase", margin: "10px 0 6px", fontWeight: 600 }}>DFIR Timeline Analysis for macOS</p>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "stretch", width: "100%", marginTop: 26, WebkitAppRegion: "no-drag" }}>
            <button onClick={() => runOpenFileDialog()} style={{ padding: "14px 48px", background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 8, fontSize: 16, fontWeight: 600, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}
              onMouseEnter={(e) => { e.currentTarget.style.filter = "brightness(1.1)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.filter = ""; }}>Open File</button>
	          </div>

          {/* Auto-restore prompt — shown when an autosave from a previous session is found */}
          {autoRestorable && autoRestorable !== false && (
            <div style={{ marginTop: 28, width: "100%", maxWidth: 480, padding: "12px 16px", background: th.warning + "12", border: `1px solid ${th.warning}55`, borderRadius: 10, display: "flex", alignItems: "center", gap: 12, WebkitAppRegion: "no-drag" }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={th.warning} strokeWidth="2" strokeLinecap="round" style={{ flexShrink: 0 }}>
                <path d="M12 8v4l3 2" /><circle cx="12" cy="12" r="9" />
              </svg>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ color: th.text, fontSize: 12, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>
                  Restore previous session?
                </div>
                <div style={{ color: th.textDim, fontSize: 11, fontFamily: "-apple-system, sans-serif", marginTop: 2 }}>
                  {autoRestorable.tabs?.length || 0} tab{autoRestorable.tabs?.length === 1 ? "" : "s"} · auto-saved {(() => { try { const d = new Date(autoRestorable.savedAt); const mins = Math.round((Date.now() - d.getTime()) / 60000); return mins < 1 ? "just now" : mins < 60 ? `${mins} min ago` : `${Math.round(mins/60)} hr ago`; } catch { return "recently"; } })()}
                </div>
              </div>
              <button onClick={handleAutoRestore} style={{ padding: "6px 14px", background: th.warning, color: "#fff", border: "none", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "-apple-system, sans-serif", transition: "background var(--m-base) var(--ease-out)", flexShrink: 0 }}>Restore</button>
              <button onClick={handleDismissAutoRestore} aria-label="Dismiss" style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "4px 6px", lineHeight: 1, flexShrink: 0 }}>✕</button>
            </div>
          )}

          {/* Recent Files */}
          {recentFiles.length > 0 && (
            <div style={{ marginTop: 24, width: "100%", maxWidth: 420, WebkitAppRegion: "no-drag" }}>
              <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8, fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>Recent Files</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 180, overflow: "auto" }}>
                {recentFiles.slice(0, 8).map((fp, i) => {
                  const fileName = fp.split("/").pop();
                  const dirPath = fp.substring(0, fp.lastIndexOf("/"));
                  return (
                    <button key={i} onClick={() => runImportPaths([fp])}
                      style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", background: "transparent", border: "none", borderRadius: 6, cursor: "pointer", textAlign: "left", transition: "background var(--m-fast)", width: "100%" }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = th.textMuted + "12"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ flexShrink: 0 }}>
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
                      </svg>
                      <div style={{ flex: 1, overflow: "hidden" }}>
                        <div style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{fileName}</div>
                        <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{dirPath}</div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <p style={{ color: th.textMuted, fontSize: 11, marginTop: "auto", paddingTop: 20 }}>⌘O open · ⌘F search · ⌘B bookmarks · ⌘E export</p>
          <p style={{ color: th.textMuted, fontSize: 11, marginTop: 20, fontFamily: "-apple-system, sans-serif" }}>Created by <span style={{ color: th.textDim }}>Renzon Cruz</span> | <span style={{ color: th.accent }}>@r3nzsec</span></p>
        </div>

        {/* ── MAIN CANVAS — capability command center over a faint, honest data motif ── */}
        <div style={{ flex: 1, position: "relative", overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <svg aria-hidden="true" style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none", zIndex: 0 }} viewBox="0 0 1000 700" preserveAspectRatio="xMidYMid slice">
            <line x1="56" y1="568" x2="944" y2="568" stroke={th.accent} strokeWidth="1" opacity="0.12" />
            {Array.from({ length: 44 }).map((_, i) => {
              const x = 56 + i * 20.4;
              const h = 14 + Math.round(78 * Math.abs(Math.sin(i * 0.7) * Math.cos(i * 0.31 + 0.6)));
              const burst = i > 19 && i < 26;
              return <rect key={i} x={x} y={568 - h} width="11" height={h} rx="2" fill={burst ? th.danger : th.accent} opacity={burst ? 0.16 : 0.08} />;
            })}
          </svg>
          {/* Lateral-movement host graph — a faint, on-brand motif. DOM-anchored to the
              bottom-right corner (NOT the slice-scaled full-canvas viewBox) so it stays in
              genuinely empty space and can't drift under the top-row tiles like the old
              network motif did. Decorative only: aria-hidden + pointer-events:none. */}
          <svg aria-hidden="true" width="460" height="340" viewBox="0 0 460 340" fill="none"
            style={{ position: "absolute", bottom: 64, right: 28, pointerEvents: "none", zIndex: 0, opacity: 0.6 }}>
            <g opacity="0.22">
              {/* edges — green = "active" pivot paths echoing the analyzer, rest muted */}
              {[
                ["60,95", "165,62", th.accent], ["60,95", "150,150", th.accent],
                ["150,150", "250,120", th.sev.clean], ["165,62", "250,120", th.sev.clean],
                ["72,215", "150,150", th.accent], ["72,215", "255,215", th.accent],
                ["250,120", "255,215", th.accent], ["250,120", "388,72", th.accent],
                ["250,120", "398,158", th.sev.clean], ["255,215", "384,248", th.accent],
              ].map(([a, b, c], i) => {
                const [x1, y1] = a.split(","), [x2, y2] = b.split(",");
                return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke={c} strokeWidth="1.3" />;
              })}
              {/* local hosts — rounded "machine" nodes */}
              {[[60, 95], [165, 62], [150, 150], [72, 215], [255, 215], [250, 120, true]].map(([cx, cy, hub], i) => {
                const w = hub ? 22 : 17, h = hub ? 17 : 13;
                return <rect key={i} x={cx - w / 2} y={cy - h / 2} width={w} height={h} rx="3"
                  fill={th.accent + "22"} stroke={th.accent} strokeWidth="1.3" />;
              })}
              {/* remote hosts — dashed targets with an alert tick, far right */}
              {[[388, 72], [398, 158], [384, 248]].map(([cx, cy], i) => (
                <g key={i}>
                  <circle cx={cx} cy={cy} r="13" fill="none" stroke={th.danger} strokeWidth="1.3" strokeDasharray="3 3" />
                  <rect x={cx - 5} y={cy - 4} width="10" height="8" rx="1.5" fill={th.danger + "33"} stroke={th.danger} strokeWidth="1" />
                  <path d={`M${cx + 9} ${cy - 14} l4 7 h-8 z`} fill={th.danger} opacity="0.8" />
                </g>
              ))}
            </g>
          </svg>
          <div style={{ position: "relative", zIndex: 1, flex: 1, overflowY: "auto", padding: "52px 52px 40px" }}>
            <div style={{ WebkitAppRegion: "no-drag", maxWidth: 980 }}>
              <h1 style={{ fontSize: 27, fontWeight: 700, color: th.text, margin: 0, fontFamily: "-apple-system, 'SF Pro Display', sans-serif", letterSpacing: "-0.015em" }}>Start an investigation</h1>
              <p style={{ fontSize: 13, color: th.textDim, margin: "9px 0 0", fontFamily: "-apple-system, sans-serif", maxWidth: 620, lineHeight: 1.55 }}>Drop a timeline anywhere in this window, or launch a capability below. SQLite-backed · built for 30–50GB+ files · CSV / TSV / XLSX / EVTX / Plaso / $MFT / $J.</p>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 14, marginTop: 26 }}>
                {homeTiles.map((t, i) => (
                  <button key={i} onClick={t.onClick}
                    style={{ textAlign: "left", display: "flex", flexDirection: "column", gap: 9, padding: "15px 16px 14px", background: th.glassBg, border: `1px solid ${th.glassBorder}`, borderRadius: 12, cursor: "pointer", transition: "all var(--m-base) var(--ease-out)", position: "relative", minHeight: 132 }}
                    onMouseEnter={(e) => { e.currentTarget.style.borderColor = t.color + "66"; e.currentTarget.style.background = t.color + "0e"; e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.boxShadow = `0 10px 28px ${t.color}1f`; }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = th.glassBorder; e.currentTarget.style.background = th.glassBg; e.currentTarget.style.transform = "none"; e.currentTarget.style.boxShadow = "none"; }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <div style={{ width: 36, height: 36, borderRadius: 10, background: t.color + "1a", border: `1px solid ${t.color}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke={t.color} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">{t.icon}</svg>
                      </div>
                      {t.ready
                        ? <span style={{ fontSize: 8, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.07em", color: th.sev.clean, background: th.sev.clean + "1a", border: `1px solid ${th.sev.clean}44`, borderRadius: 5, padding: "2px 6px" }}>Ready</span>
                        : t.chip && <span title="Input this analyzer needs" style={{ fontSize: 9, fontWeight: 600, color: th.textDim, background: th.textMuted + "14", border: `1px solid ${th.glassBorder}`, borderRadius: 5, padding: "2px 7px", whiteSpace: "nowrap", fontFamily: "-apple-system, sans-serif" }}>{t.chip}</span>}
                    </div>
                    <div style={{ fontSize: 13.5, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{t.title}</div>
                    <div style={{ fontSize: 11, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45, flex: 1 }}>{t.desc}</div>
                    <div style={{ fontSize: 10, color: t.color, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{t.outcome}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Drop overlay — shown across the whole window while dragging files */}
        {dragOver && (
          <div style={{ position: "absolute", inset: 0, zIndex: 20, display: "flex", alignItems: "center", justifyContent: "center", background: th.overlay, backdropFilter: "blur(3px)", WebkitBackdropFilter: "blur(3px)", pointerEvents: "none" }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12, padding: "36px 60px", border: `2px dashed ${th.borderAccent}`, borderRadius: 16, background: th.selection }}>
              <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              <div style={{ color: th.accent, fontSize: 18, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>Drop files to import</div>
              <div style={{ color: th.textDim, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>CSV · TSV · XLSX · EVTX · Plaso · $MFT · $J</div>
            </div>
          </div>
        )}
        {/* Modal overlay — must render even in empty state for EVTX scanning */}
        <Suspense fallback={<ModalChunkFallback th={th} />}>
          {modal?.type === "sigma" && <SigmaRuleModal />}
          {modal?.type === "rdpBitmapCache" && <RdpBitmapCacheModal />}
          {modal?.type === "aiHistoryProfileScan" && <AiHistoryProfileScanModal />}
          {modal?.type === "aiHistoryExtract" && <AiHistoryExtractModal />}
          {modal?.type === "aiWorkspaceCorrelate" && <AiWorkspaceCorrelateModal th={th} />}
          {modal?.type === "aiHistoryScope" && <AiHistoryScopeModal />}
          {modal?.type === "aiSecrets" && <AiSecretsModal th={th} />}
        </Suspense>
	      </div>
    );
  }

  // ── Main render ──────────────────────────────────────────────────
  const isImporting = ct?.importing && importingTabs[ct?.id];
  const activeCheckboxCount = ct
    ? Object.keys(ct.checkboxFilters || {}).filter((k) => checkboxFilterActive(ct.checkboxFilters[k])).length
    : 0;
  const activeColumnFilterCount = ct ? Object.values(ct.columnFilters || {}).filter(Boolean).length : 0;
  const activeDateFilterCount = ct ? Object.keys(ct.dateRangeFilters || {}).length : 0;
  const activeAdvFilterCount = ct?.advancedFilters?.length || 0;
  const hasSearch = ct?.searchTerm?.trim() && !ct?.searchHighlight;
  const hasBookmarkFilter = !!ct?.showBookmarkedOnly;
  const hasTagFilter = !!ct?.tagFilter;
  const hasRowIdFilter = Array.isArray(ct?.rowIdFilter) && ct.rowIdFilter.length > 0;
  const totalActiveFilters = activeCheckboxCount + activeColumnFilterCount + activeDateFilterCount + activeAdvFilterCount + (hasSearch ? 1 : 0) + (hasBookmarkFilter ? 1 : 0) + (hasTagFilter ? 1 : 0) + (hasRowIdFilter ? 1 : 0);
  const clearAllFilters = () => {
    setTabs((prev) => prev.map((t) => t.id !== ct.id ? t : {
      ...t, searchTerm: "", columnFilters: {}, checkboxFilters: {},
      dateRangeFilters: {}, advancedFilters: [], showBookmarkedOnly: false,
      tagFilter: null, rowIdFilter: null, rowIdFilterLabel: null,
      searchHighlight: false, disabledFilters: new Set(),
    }));
  };

  return (
    <div onContextMenu={(e) => e.preventDefault()}
      onDragOver={(e) => { if (!e.dataTransfer.types.includes("Files")) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; setDragOver(true); }}
      onDragLeave={(e) => { if (e.currentTarget.contains(e.relatedTarget)) return; setDragOver(false); }}
      onDrop={(e) => { if (!e.dataTransfer.types.includes("Files")) return; e.preventDefault(); setDragOver(false); const files = [...e.dataTransfer.files]; if (files.length > 0 && tle) { const paths = files.map((f) => tle.getPathForFile(f)).filter(Boolean); if (paths.length > 0) runImportPaths(paths); } }}
      style={{ display: "flex", flexDirection: "column", height: "100vh", background: th.bg, color: th.text, fontFamily: "'SF Mono','Fira Code',Menlo,monospace", fontSize: fontSize, overflow: "hidden" }}>
      <style>{`
        :root {
          --m-fast: 120ms;
          --m-base: 160ms;
          --m-slow: 240ms;
          --m-modal: 180ms;
          --ease-out: cubic-bezier(0.32, 0.72, 0, 1);
          --ease-out-soft: cubic-bezier(0.4, 0, 0.2, 1);
        }
        @keyframes tle-spin { to { transform: rotate(360deg) } }
        @keyframes tle-pulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.6; transform: scale(0.95); } }
        @keyframes tle-modal-in { from { opacity: 0; transform: scale(0.97) translateY(8px); } to { opacity: 1; transform: scale(1) translateY(0); } }
        @keyframes tle-overlay-in { from { opacity: 0; } to { opacity: 1; } }
        ::-webkit-scrollbar { width: 14px; height: 14px; }
        ::-webkit-scrollbar-track { background: ${th.bg}; }
        ::-webkit-scrollbar-thumb { background: ${th.textMuted}; border-radius: 7px; border: 3px solid ${th.bg}; }
        ::-webkit-scrollbar-thumb:hover { background: ${th.textDim}; }
        ::-webkit-scrollbar-corner { background: ${th.bg}; }
        .tle-tb { transition: background var(--m-base) var(--ease-out), color var(--m-base) var(--ease-out); }
        .tle-tb:hover { background: ${th.glassHover} !important; }
        .tle-tab { transition: background var(--m-base) var(--ease-out), box-shadow var(--m-base) var(--ease-out); }
        .tle-tab:hover { background: ${th.glassHover} !important; }
        .pt-row { transition: background var(--m-base) var(--ease-out); }
        .pt-row:not(.pt-sel):hover { background: ${th.glassHover} !important; }
        input, select, textarea { transition: box-shadow var(--m-base) var(--ease-out), border-color var(--m-base) var(--ease-out); }
        input:not([type="color"]):not([type="checkbox"]):not([type="radio"]):not([type="range"]):not([type="file"]):focus-visible,
        select:focus-visible,
        textarea:focus-visible { box-shadow: 0 0 0 2px ${th.accent}40; }
        /* Keyboard focus ring for buttons, links, and ARIA widgets. box-shadow is used
           (not outline) so it shows even on elements that set inline outline:none, and
           :focus-visible keeps mouse clicks ring-free. */
        button:focus-visible,
        a[href]:focus-visible,
        [role="button"]:focus-visible,
        [role="menuitem"]:focus-visible,
        [role="tab"]:focus-visible,
        [role="checkbox"]:focus-visible,
        [tabindex]:not([tabindex="-1"]):focus-visible { box-shadow: 0 0 0 2px ${th.accent}cc; border-radius: 4px; }
        .tle-settings-toggle,
        .tle-status-toggle { display: none !important; }
        @media (max-width: 1200px) {
          .tle-menubar-shell { gap: 6px !important; }
          .tle-menubar-left { min-width: 0; }
          .tle-toolbar-settings { display: none !important; }
          .tle-toolbar-settings[data-open="true"] {
            display: flex !important;
            position: absolute;
            top: calc(100% + 4px);
            right: 12px;
            z-index: 170;
            padding: 7px 8px !important;
            box-shadow: 0 12px 40px rgba(0,0,0,0.45);
          }
          .tle-settings-backdrop { display: block !important; }
          .tle-settings-toggle { display: inline-flex !important; }
          .tle-status-details { display: none !important; }
          .tle-status-details[data-open="true"] {
            display: flex !important;
            position: absolute;
            right: 8px;
            bottom: calc(100% + 5px);
            z-index: 170;
            max-width: calc(100vw - 16px);
            flex-wrap: wrap;
            padding: 8px 10px;
            background: ${th.modalBg}f2;
            border: 1px solid ${th.glassBorder};
            border-radius: 8px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.45);
          }
          .tle-status-toggle { display: inline-flex !important; }
          .tle-status-path { max-width: 260px !important; }
        }
        @media (max-width: 900px) {
          .tle-menubar-shell { flex-wrap: wrap; }
          .tle-search-slot {
            order: 3;
            flex: 1 0 100% !important;
            max-width: none !important;
          }
          .tle-search-slot > * { max-width: none !important; }
          .tle-indexing-indicator { margin-left: auto; }
          .tle-status-path { max-width: 150px !important; }
          .tle-search-options { gap: 6px 10px !important; }
          .tle-search-condition-options {
            flex: 1 1 100%;
            overflow-x: auto;
            padding-bottom: 2px;
          }
        }
        /* Respect the OS "reduce motion" setting — kill modal/toast/spin/pulse animations. */
        @media (prefers-reduced-motion: reduce) {
          *, *::before, *::after {
            animation-duration: 0.001ms !important;
            animation-iteration-count: 1 !important;
            transition-duration: 0.001ms !important;
          }
        }
      `}</style>

      {/* Drop overlay — shown when dragging files over the app */}
      {dragOver && (
        <div style={{ position: "fixed", inset: 0, zIndex: 9999, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none" }}>
          <div style={{ padding: "40px 60px", border: `3px dashed ${th.accent}`, borderRadius: 14, background: `${th.bg}DD`, textAlign: "center" }}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>+</div>
            <div style={{ color: th.accent, fontSize: 16, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Drop files to import</div>
            <div style={{ color: th.textMuted, fontSize: 11, marginTop: 4, fontFamily: "-apple-system, sans-serif" }}>CSV · TSV · XLSX · EVTX · Plaso · Raw $MFT · $J</div>
            <div style={{ color: th.textMuted, fontSize: 10, marginTop: 2, fontFamily: "-apple-system, sans-serif", opacity: 0.7 }}>Extensionless files auto-detected by content</div>
          </div>
        </div>
      )}

      {/* ── MenuBar + FilterBar ──────────────────────────────────── */}
      <Suspense fallback={<ShellChunkFallback th={th} />}>
        <MenuBar
          th={th} ct={ct} tabs={tabs} tle={tle}
          handleExport={handleExport} handleSaveSession={handleSaveSession} handleLoadSession={handleLoadSession}
          handleCheckForUpdates={handleCheckForUpdates} handleExtractResident={handleExtractResident}
          closeTab={closeTab} resetColumnWidths={resetColumnWidths} up={up} activeFilters={activeFilters}
          allFilteredRowsSelected={allFilteredRowsSelected} selectedRowData={selectedRowData} isGrouped={isGrouped}
          handleSelectAllRows={handleSelectAllRows}
          proximityFilter={proximityFilter} setProximityFilter={setProximityFilter}
          searchLoading={searchLoading} checkingForUpdates={checkingForUpdates} extracting={extracting}
          recentFiles={recentFiles} setRecentFiles={setRecentFiles}
          copiedMsg={copiedMsg} setCopiedMsg={setCopiedMsg}
          setColMgrSearch={setColMgrSearch}
          searchBar={
            <FilterBar th={th} ct={ct} up={up} isGrouped={isGrouped}
              searchLoading={searchLoading} searchMatchIdx={searchMatchIdx}
              searchMatchPosition={searchMatchPosition}
              highlightMatchCount={highlightMatchCount}
              navigateSearch={navigateSearch} />
          }
        />
      </Suspense>
      <SearchOptionsBar th={th} ct={ct} up={up} />


      {/* Cross-tab search results (auto-shown with 2+ tabs and active search) */}
      {crossTabCounts && crossTabOpen && crossTabCounts.results.length > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 12px", background: th.panelBg, borderBottom: `1px solid ${th.border}`, flexShrink: 0, overflowX: "auto" }}>
          <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap", marginRight: 4 }}>Across tabs:</span>
          {crossTabCounts.results.map((r) => (
            <button key={r.tabId} onClick={() => { if (r.count > 0) { setActiveTab(r.tabId); setTabs((prev) => prev.map((t) => t.id === r.tabId ? { ...t, searchTerm: crossTabCounts.term, searchMode: crossTabCounts.mode } : t)); } }}
              style={{ display: "flex", alignItems: "center", gap: 3, padding: "1px 8px", borderRadius: 10, border: `1px solid ${r.count > 0 ? th.borderAccent + "66" : th.border}`, background: r.tabId === activeTab ? th.selection : "transparent", cursor: r.count > 0 ? "pointer" : "default", fontSize: 10, color: r.count > 0 ? th.text : th.textMuted, whiteSpace: "nowrap" }}>
              <span style={{ maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis" }}>{r.name}</span>
              <span style={{ color: r.count > 0 ? th.success : th.textMuted, fontWeight: 600 }}>{formatNumber(r.count)}</span>
            </button>
          ))}
          <span style={{ color: th.textMuted, fontSize: 10, marginLeft: 4 }}>
            Total: {formatNumber(crossTabCounts.results.reduce((s, r) => s + r.count, 0))}
          </span>
          <button onClick={() => setCrossTabOpen(false)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, marginLeft: "auto", padding: "0 4px" }}>✕</button>
        </div>
      )}

      {/* ── TabBar ────────────────────────────────────────────── */}
      <TabBar
        th={th}
        scrollTop={scrollTop} selectedRows={selectedRows} allRowsSelected={allRowsSelected}
        selectionTabId={selectionTabId} selectAllScopeSignature={selectAllScopeSignature} lastClickedRow={lastClickedRow}
        setScrollTop={setScrollTop} setSelectedRows={setSelectedRows} setAllRowsSelected={setAllRowsSelected}
        setSelectionTabId={setSelectionTabId} setSelectAllScopeSignature={setSelectAllScopeSignature} setLastClickedRow={setLastClickedRow}
        setProximityFilter={setProximityFilter} scrollRef={scrollRef} closeTab={closeTab}
      />

      {/* Group Panel */}
      {ct && ct.dataReady && (
        <div
          onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; setGroupDragOver(true); }}
          onDragLeave={() => setGroupDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setGroupDragOver(false); const col = e.dataTransfer.getData("text/column-name"); if (col) addGroupBy(col); }}
          style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 12px",
            background: groupDragOver ? th.accentSubtle : th.panelBg,
            borderBottom: `1px solid ${th.border}`, minHeight: 28, flexShrink: 0, transition: "background var(--m-base)",
            border: groupDragOver ? `1px dashed ${th.accent}` : undefined,
            borderRadius: groupDragOver ? 4 : 0, margin: groupDragOver ? "2px 4px" : 0 }}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={groupDragOver ? th.accent : isGrouped ? th.accent : th.textMuted} strokeWidth="2" style={{ flexShrink: 0 }}>
            <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
          </svg>
          {groupDragOver && !isGrouped ? (
            <span style={{ color: th.accent, fontSize: 10, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Drop here to group by column</span>
          ) : isGrouped ? (<>
            {(ct.groupByColumns || []).map((col, i) => (
              <span key={col} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                {i > 0 && <span style={{ color: th.textMuted, fontSize: 9 }}>›</span>}
                <span draggable
                  onDragStart={(e) => { e.stopPropagation(); e.dataTransfer.setData("text/group-reorder", col); setGroupReorderDrag(col); }}
                  onDragEnd={() => setGroupReorderDrag(null)}
                  onDragOver={(e) => { if (groupReorderDrag && groupReorderDrag !== col) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; } }}
                  onDrop={(e) => { e.preventDefault(); e.stopPropagation(); const dragCol = e.dataTransfer.getData("text/group-reorder"); if (dragCol && dragCol !== col) { setTabs((prev) => prev.map((t) => { if (t.id !== ct.id) return t; const cols = [...(t.groupByColumns || [])]; const fromIdx = cols.indexOf(dragCol); const toIdx = cols.indexOf(col); if (fromIdx < 0 || toIdx < 0) return t; cols.splice(fromIdx, 1); cols.splice(toIdx, 0, dragCol); return { ...t, groupByColumns: cols, expandedGroups: {}, groupData: [] }; })); setGroupReorderDrag(null); } }}
                  style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", background: groupReorderDrag === col ? `${th.accent}44` : `${th.accent}22`, border: `1px solid ${th.accent}4D`, borderRadius: 4, color: th.accent, fontSize: 10, fontWeight: 500, fontFamily: "-apple-system, sans-serif", cursor: "grab" }}>
                  {col}
                  <button onClick={() => removeGroupBy(col)} style={{ background: "none", border: "none", color: th.accent, cursor: "pointer", fontSize: 9, padding: 0, lineHeight: 1, opacity: 0.7 }} title={`Remove ${col} grouping`}>✕</button>
                </span>
              </span>
            ))}
            <button onClick={() => setTabs((prev) => prev.map((t) => t.id === ct.id ? { ...t, groupByColumns: [], expandedGroups: {}, groupData: [] } : t))} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 9, padding: "1px 4px", fontFamily: "-apple-system, sans-serif" }} title="Clear all grouping">Clear</button>
          </>) : (
            <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>Drag a column header here to group</span>
          )}
          {totalActiveFilters > 0 && (
            <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 8, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
              <span style={{ color: th.borderAccent }}>
                {totalActiveFilters} filter{totalActiveFilters > 1 ? "s" : ""} active
                {activeCheckboxCount > 0 ? ` (${activeCheckboxCount} value)` : ""}
              </span>
              <button onClick={clearAllFilters} style={{ background: (th.danger) + "18", border: `1px solid ${(th.danger)}55`, borderRadius: 4, color: th.danger, cursor: "pointer", fontSize: 10, padding: "1px 8px", fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>Clear All</button>
            </span>
          )}
        </div>
      )}


      {/* EVTX fast-message mode notice */}
      {ct?.messagesDeferred && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 14px", background: `${th.warning}0d`, borderBottom: `1px solid ${(th.warning)}22`, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={th.warning} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>
          </svg>
          <span style={{ color: th.textDim }}>
            Large EVTX fast import is active. The Message column uses compact structured summaries; full analyzer fields are preserved.
          </span>
        </div>
      )}

      <SelectionBar
        th={th}
        selectionCount={selectionCount}
        hiddenSelectionCount={hiddenSelectionCount}
        allRowsSelected={allRowsSelected}
        onCopy={() => { void copySelectedRows(); }}
        onBulkActions={() => setModal({
          type: "bulkActions",
          scope: "selection",
          selectionFilterOptions,
          selectionCount,
        })}
        onClear={clearRowSelection}
      />

      {/* ── VirtualGrid (histogram + grid + detail panel) ──────── */}
      <Suspense fallback={<Loading label="Loading grid…" size="md" />}>
        <VirtualGrid
          th={th} ct={ct} tle={tle} up={up} tabs={tabs}
          isGrouped={isGrouped} isImporting={isImporting} importingTabs={importingTabs} importQueue={importQueue}
          displayRows={displayRows} rows={rows} visible={visible} skeletonIndices={skeletonIndices}
          totalCount={totalCount} totalH={totalH} physicalH={physicalH} pageOffset={pageOffset} si={si} tw={tw} rowOffset={rowOffset}
          allVisH={allVisH} pinnedH={pinnedH} scrollH={scrollH} pinnedOffsets={pinnedOffsets}
          selectedRows={selectedRows} allRowsSelected={allRowsSelected} selectionCount={selectionCount}
          lastClickedRow={lastClickedRow} setLastClickedRow={setLastClickedRow}
          selectedColumn={selectedColumn} setSelectedColumn={setSelectedColumn}
          selectedRow={selectedRow} selectedRowData={selectedRowData} detailVisible={detailVisible}
          compiledColors={compiledColors}
          handleScroll={handleScroll} scrollRef={scrollRef}
          handleSort={handleSort} handleHeaderDblClick={handleHeaderDblClick}
          handleBookmark={handleBookmark}
          handleRowClick={handleRowClick} handleCheckboxToggle={handleCheckboxToggle}
          handleSelectAllRows={handleSelectAllRows}
          openGridContextMenu={handleNativeRightClick}
          handleGroupSelectAll={handleGroupSelectAll} getGroupCheckState={getGroupCheckState}
          expandGroup={expandGroup} collapseGroup={collapseGroup}
          loadMoreGroupRows={loadMoreGroupRows} getRowAt={getRowAt}
          pinColumn={pinColumn} unpinColumn={unpinColumn}
          addGroupBy={addGroupBy} removeGroupBy={removeGroupBy}
          reorderColumn={reorderColumn} autoFitColumn={autoFitColumn}
          onDetailResizeStart={onDetailResizeStart} onHistResizeStart={onHistResizeStart}
          copyCell={copyCell}
          renderCell={renderCell} fmtCell={fmtCell} gw={gw} getRowBg={getRowBg}
          filterDropdown={filterDropdown} setFilterDropdown={setFilterDropdown}
          dateRangeDropdown={dateRangeDropdown} setDateRangeDropdown={setDateRangeDropdown}
          contextMenu={contextMenu} setContextMenu={setContextMenu}
          cellContextMenu={cellContextMenu} setCellContextMenu={setCellContextMenu}
          rowContextMenu={rowContextMenu} setRowContextMenu={setRowContextMenu}
          cellPopup={cellPopup} setCellPopup={setCellPopup}
          headerDragOver={headerDragOver} setHeaderDragOver={setHeaderDragOver}
          resizingCol={resizingCol} setResizingCol={setResizingCol}
          resizeX={resizeX} setResizeX={setResizeX}
          resizeW={resizeW} setResizeW={setResizeW}
          tagColWidth={tagColWidth} setTagColWidth={setTagColWidth}
          histogramVisible={histogramVisible} histogramCol={histogramCol} setHistogramCol={setHistogramCol}
          histogramData={histogramData} histogramLoaded={histogramLoaded}
          histContainerRef={histContainerRef} histContainerWidth={histContainerWidth}
          histBrushRef={histBrushRef} histSvgRectRef={histSvgRectRef}
          histBrushOverlayRef={histBrushOverlayRef} histBrushLabelRef={histBrushLabelRef}
          histBarGeomRef={histBarGeomRef}
          extracting={extracting} extractProgress={extractProgress}
          detailPanelRef={detailPanelRef} detailPanelHeight={detailPanelHeight}
          onFilterToSession={isAiHistorySourceFormat(ct?.sourceFormat) ? filterToAiSession : undefined}
          onCorrelateWorkspace={isAiHistorySourceFormat(ct?.sourceFormat) ? correlateAiWorkspace : undefined}
          ImportProgress={ImportProgress}
          sortTimerRef={sortTimerRef} justResizedRef={justResizedRef}
          searchLoading={searchLoading} fontSize={fontSize}
        />
      </Suspense>


      {/* ── StatusBar ─────────────────────────────────────────── */}
      <StatusBar
        th={th} ct={ct} isGrouped={isGrouped}
        selectionCount={selectionCount}
        copiedMsg={copiedMsg} setCopiedMsg={setCopiedMsg}
        pinnedH={pinnedH} allVisH={allVisH}
        searchLoading={searchLoading} searchElapsed={searchElapsed}
        visibleRowStart={visibleRowStart} visibleRowEnd={visibleRowEnd}
        activeCheckboxCount={activeCheckboxCount}
        totalActiveFilters={totalActiveFilters} clearAllFilters={clearAllFilters} up={up}
      />

      {updaterPopup && (() => {
        const phase = updaterPopup.phase || "checking";
        const progress = Math.max(0, Math.min(100, Number(updaterPopup.percent) || 0));
        const accent = phase === "error"
          ? (th.danger)
          : phase === "downloaded"
            ? (th.success)
            : th.accent;
        const title = phase === "checking"
          ? "Checking for Updates"
          : phase === "downloading"
            ? `Downloading ${updaterPopup.version || "Update"}`
            : phase === "downloaded"
              ? "Update Ready"
              : phase === "installing"
                ? "Installing Update"
                : phase === "no-update"
                  ? "No Updates Available"
                  : phase === "not-configured"
                    ? "Updates Not Configured"
                    : "Update Status";
        const detailText = phase === "downloading"
          ? [
              `${progress.toFixed(progress >= 10 ? 0 : 1)}% downloaded`,
              updaterPopup.total ? `${formatBytes(updaterPopup.transferred || 0)} of ${formatBytes(updaterPopup.total)}` : "",
              updaterPopup.bytesPerSecond ? `${formatBytes(updaterPopup.bytesPerSecond)}/s` : "",
            ].filter(Boolean).join("  •  ")
          : updaterPopup.detail || "";
        const releaseNotes = String(updaterPopup.releaseNotes || "").trim().slice(0, 500);
        return (
          <div style={{ position: "fixed", right: 18, bottom: 18, width: 360, maxWidth: "calc(100vw - 32px)", background: `linear-gradient(160deg, ${th.modalBg}f2, ${th.panelBg}f2)`, border: `1px solid ${accent}66`, borderRadius: 14, boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", zIndex: 160, overflow: "hidden", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
            <div style={{ padding: "12px 14px 10px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12, background: `linear-gradient(135deg, ${accent}14, transparent)` }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                <div style={{ width: 28, height: 28, borderRadius: 14, display: "flex", alignItems: "center", justifyContent: "center", background: `${accent}18`, color: accent, flexShrink: 0 }}>
                  {phase === "downloaded" ? (
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  ) : phase === "error" ? (
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="15" y1="9" x2="9" y2="15" />
                      <line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                  ) : (
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" style={{ animation: phase === "checking" || phase === "downloading" || phase === "installing" ? "tle-spin 1.1s linear infinite" : "none" }}>
                      <path d="M21 12a9 9 0 1 1-2.64-6.36" />
                      <polyline points="21 3 21 9 15 9" />
                    </svg>
                  )}
                </div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: th.text, fontSize: 14, fontWeight: 700, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{title}</div>
                  {updaterPopup.version && phase !== "no-update" && phase !== "checking" && (
                    <div style={{ color: th.textMuted, fontSize: 11, marginTop: 2, fontFamily: "'SF Mono', Menlo, monospace" }}>Version {updaterPopup.version}</div>
                  )}
                </div>
              </div>
              {["downloaded", "no-update", "not-configured", "error"].includes(phase) && (
                <button onClick={() => setUpdaterPopup(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, lineHeight: 1, padding: 0, flexShrink: 0 }}>✕</button>
              )}
            </div>

            <div style={{ padding: "12px 14px 14px" }}>
              <div style={{ color: th.text, fontSize: 13, lineHeight: 1.45, fontFamily: "-apple-system, sans-serif" }}>
                {updaterPopup.message || (phase === "checking" ? "Checking for updates..." : "")}
              </div>
              {detailText && <div style={{ color: th.textMuted, fontSize: 11, lineHeight: 1.45, marginTop: 6, fontFamily: "-apple-system, sans-serif" }}>{detailText}</div>}

              {phase === "downloading" && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ height: 8, borderRadius: 999, overflow: "hidden", background: `${th.border}44`, border: `1px solid ${th.border}22` }}>
                    <div style={{ width: `${progress}%`, height: "100%", background: `linear-gradient(90deg, ${th.accent}, ${th.accentHover || th.accent})`, transition: "width var(--m-base) ease" }} />
                  </div>
                </div>
              )}

              {phase === "downloaded" && (
                <div style={{ marginTop: 12, padding: "10px 11px", borderRadius: 10, background: `${th.success}14`, border: `1px solid ${(th.success)}33`, color: th.text, fontSize: 12, lineHeight: 1.45, fontFamily: "-apple-system, sans-serif" }}>
                  Restart required. Install the update to apply the new version to the app currently open.
                </div>
              )}

              {releaseNotes && phase !== "checking" && phase !== "installing" && (
                <div style={{ marginTop: 12, maxHeight: 112, overflow: "auto", padding: "10px 11px", borderRadius: 10, background: `${th.border}12`, border: `1px solid ${th.border}22`, color: th.textMuted, fontSize: 11, lineHeight: 1.45, whiteSpace: "pre-wrap", fontFamily: "-apple-system, sans-serif" }}>
                  {releaseNotes}
                </div>
              )}

              {["downloaded", "no-update", "not-configured", "error"].includes(phase) && (
                <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
                  {phase === "downloaded" ? (
                    <>
                      <button onClick={() => setUpdaterPopup(null)} style={ms.bs}>Later</button>
                      <button onClick={handleInstallUpdate} style={ms.bp}>Restart and Install</button>
                    </>
                  ) : (
                    <button onClick={() => setUpdaterPopup(null)} style={ms.bs}>Close</button>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {/* Modals */}
      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Stacking / Value Frequency Analysis */}
        {modal?.type === "stacking" && ct && <StackingModal />}
        {/* Column Stats Modal */}
        {modal?.type === "columnStats" && ct && <ColumnStatsModal />}
        {/* Filter Presets Modal */}
        {modal?.type === "presets" && ct && <PresetsModal />}
        {modal?.type === "colors" && ct && <ColorModal th={th} ct={ct} up={up} ms={ms} />}
        {modal?.type === "columns" && ct && <ColModal th={th} ct={ct} up={up} ms={ms} colMgrSearch={colMgrSearch} setColMgrSearch={setColMgrSearch} colMgrDragOver={colMgrDragOver} setColMgrDragOver={setColMgrDragOver} />}
        {modal?.type === "shortcuts" && <ShortModal th={th} ms={ms} />}
        {modal?.type === "quickHelp" && <QuickHelpModal />}
      </Suspense>
      {modal?.type === "about" && (
        <Overlay th={th}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 40, marginBottom: 8 }}>⌬</div>
            <h2 style={{ margin: "0 0 4px", fontSize: 20, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>IRFlow Timeline</h2>
            <div style={{ fontSize: 12, color: th.textMuted, marginBottom: 16, fontFamily: "-apple-system, sans-serif" }}>Version {APP_VERSION}</div>
            <div style={{ textAlign: "left", background: th.bgAlt, borderRadius: 8, padding: 16, marginBottom: 16 }}>
              <p style={{ margin: "0 0 8px", fontSize: 12, color: th.text, lineHeight: 1.6, fontFamily: "-apple-system, sans-serif" }}>
                {APP_DESCRIPTION}
              </p>
              <p style={{ margin: "0 0 8px", fontSize: 12, color: th.text, lineHeight: 1.6, fontFamily: "-apple-system, sans-serif" }}>
                Native ingestion covers CSV, TSV, XLS/XLSX, Plaso, raw $MFT and $UsnJrnl, plus EVTX through bounded 64 KiB chunk reads up to the format's approximately 4 GiB limit. AI evidence includes prompts, responses, tool calls, shell commands, and bounded tool output from supported assistants, plus ChatGPT Computer History — the macOS interaction-event stream, the activity summaries derived from it, and the consolidated memory those summaries feed.
              </p>
              <p style={{ margin: 0, fontSize: 12, color: th.text, lineHeight: 1.6, fontFamily: "-apple-system, sans-serif" }}>
                Built-in investigation includes Sigma and Hayabusa detection, process trees, lateral movement, persistence, ransomware and NTFS analytics, AI secret exposure hunting, IOC and VirusTotal enrichment, RDP bitmap recovery, tagging, and reporting. Computer History adds per-application capture-fidelity tiering, credential-entry and deletion detection, recovery of cleared summaries, and host attribution.
              </p>
            </div>
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: th.text, marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>Author</div>
              <div style={{ fontSize: 13, color: th.text, marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Renzon Cruz</div>
              <div style={{ display: "flex", justifyContent: "center", gap: 16 }}>
                <a href="#" onClick={(e) => { e.preventDefault(); window.tle?.openExternal("https://www.linkedin.com/in/renzoncruz"); }}
                  style={{ fontSize: 12, color: th.accent, textDecoration: "none", cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>LinkedIn</a>
                <a href="#" onClick={(e) => { e.preventDefault(); window.tle?.openExternal("https://x.com/r3nzsec"); }}
                  style={{ fontSize: 12, color: th.accent, textDecoration: "none", cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Twitter</a>
                <a href="#" onClick={(e) => { e.preventDefault(); window.tle?.openExternal("https://github.com/r3nzsec/irflow-timeline"); }}
                  style={{ fontSize: 12, color: th.accent, textDecoration: "none", cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>GitHub</a>
              </div>
            </div>
            <button onClick={() => setModal(null)} style={ms.bp}>OK</button>
          </div>
        </Overlay>
      )}
      {modal?.type === "sheets" && <SheetModal th={th} ms={ms} tle={tle} />}
      {modal?.type === "tags" && ct && (
        <Overlay th={th}>
          <h3 style={ms.mh}>Manage Tags</h3>
          <div style={{ maxHeight: "50vh", overflow: "auto", marginBottom: 12 }}>
            {Object.entries(ct.tagColors || {}).map(([tag, color]) => (
              <div key={tag} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 0", borderBottom: `1px solid ${th.bgAlt}` }}>
                <input type="color" value={color} onChange={(e) => up("tagColors", { ...ct.tagColors, [tag]: e.target.value })}
                  style={{ width: 20, height: 16, border: "none", cursor: "pointer", borderRadius: 3, padding: 0 }} />
                <span style={{ flex: 1, color: th.text, fontSize: 12 }}>{tag}</span>
                <button onClick={() => { const tc = { ...ct.tagColors }; delete tc[tag]; up("tagColors", tc); }}
                  style={{ background: "none", border: "none", color: th.danger, cursor: "pointer", fontSize: 12 }}>✕</button>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            <input id="new-tag-input" placeholder="New tag name..." style={ms.ip} onKeyDown={(e) => {
              if (e.key === "Enter" && e.target.value.trim()) {
                const name = e.target.value.trim();
                if (!ct.tagColors[name]) up("tagColors", { ...ct.tagColors, [name]: th.sev.low });
                e.target.value = "";
              }
            }} />
            <button onClick={() => {
              const inp = document.getElementById("new-tag-input");
              const name = inp?.value?.trim();
              if (name && !ct.tagColors[name]) { up("tagColors", { ...ct.tagColors, [name]: th.sev.low }); inp.value = ""; }
            }} style={ms.bp}>Add</button>
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
            <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
          </div>
        </Overlay>
      )}

      {/* Cross-tab Find */}
      {modal?.type === "crossfind" && (
        <Overlay th={th}>
          <h3 style={ms.mh}>Find Across All Tabs</h3>
          <div style={{ display: "flex", gap: 6, marginBottom: 12 }}>
            <input id="cf-input" autoFocus defaultValue={crossFind?.term || ""} placeholder="Search term..."
              onKeyDown={(e) => { if (e.key === "Enter") handleCrossFind(e.target.value); }}
              style={{ flex: 1, background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, padding: "8px 10px", outline: "none", fontFamily: "inherit" }} />
            <button onClick={() => { const v = document.getElementById("cf-input")?.value; if (v) handleCrossFind(v); }}
              style={ms.bp}>Search</button>
          </div>
          {crossFind?.results && (
            <div style={{ maxHeight: "50vh", overflow: "auto" }}>
              {crossFind.results.length === 0 && <p style={{ color: th.textMuted, fontSize: 12 }}>No tabs open</p>}
              {crossFind.results.map((r) => (
                <div key={r.tabId}
                  onClick={() => {
                    if (r.count > 0) {
                      setActiveTab(r.tabId);
                      setTabs((prev) => prev.map((t) => t.id === r.tabId ? { ...t, searchTerm: crossFind.term, searchMode: "mixed" } : t));
                      setModal(null);
                    }
                  }}
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 10px", borderBottom: `1px solid ${th.bgAlt}`,
                    cursor: r.count > 0 ? "pointer" : "default", borderRadius: 4 }}
                  onMouseEnter={(e) => { if (r.count > 0) e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                  <span style={{ color: r.count > 0 ? th.text : th.textMuted, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 300 }}>{r.name}</span>
                  <span style={{ color: r.count > 0 ? th.success : th.textMuted, fontSize: 12, fontWeight: 600, flexShrink: 0, marginLeft: 12 }}>
                    {r.count > 0 ? `${formatNumber(r.count)} hits` : "0"}
                  </span>
                </div>
              ))}
              <div style={{ marginTop: 8, color: th.textMuted, fontSize: 11 }}>
                Total: {formatNumber(crossFind.results.reduce((s, r) => s + r.count, 0))} matches across {crossFind.results.filter((r) => r.count > 0).length} tab{crossFind.results.filter((r) => r.count > 0).length !== 1 ? "s" : ""}
              </div>
            </div>
          )}
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
            <button onClick={() => setModal(null)} style={ms.bs}>Close</button>
          </div>
        </Overlay>
      )}

      {/* Temporal Proximity Search Modal */}
      {modal?.type === "proximity" && ct && (() => {
        const { pivotRow, pivotCol } = modal;
        const tsCols = [...(ct.tsColumns || new Set())];
        const selCol = modal.selCol ?? pivotCol ?? tsCols[0];
        const customN = modal.customN ?? 5;
        const customU = modal.customU ?? "m";
        const pivotVal = pivotRow?.[selCol] ?? "";
        const PROX_PRESETS = [
          { label: "±30s", ms: 30_000, short: "30s" },
          { label: "±1m", ms: 60_000, short: "1m" },
          { label: "±5m", ms: 300_000, short: "5m" },
          { label: "±15m", ms: 900_000, short: "15m" },
          { label: "±30m", ms: 1_800_000, short: "30m" },
          { label: "±1h", ms: 3_600_000, short: "1h" },
          { label: "±4h", ms: 14_400_000, short: "4h" },
          { label: "±1d", ms: 86_400_000, short: "1d" },
        ];
        const unitMs = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
        const customMs = (Number(customN) || 0) * (unitMs[customU] || 60_000);
        return (
          <Overlay th={th}>
            <h3 style={ms.mh}>Find Nearby Events</h3>
            <div style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 6, padding: "8px 10px", marginBottom: 12 }}>
              <div style={{ ...ms.lb, marginBottom: 2 }}>Pivot Timestamp</div>
              <div style={{ color: th.text, fontSize: 12, fontFamily: "'SF Mono',Menlo,monospace", wordBreak: "break-all" }}>
                {pivotVal || <span style={{ color: th.textMuted, fontStyle: "italic" }}>(empty — select a timestamp column)</span>}
              </div>
            </div>
            {tsCols.length > 1 && (
              <div style={ms.fg}>
                <label style={ms.lb}>Timestamp Column</label>
                <select value={selCol} onChange={(e) => setModal((p) => ({ ...p, selCol: e.target.value }))} style={ms.sl}>
                  {tsCols.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            )}
            <div style={ms.fg}>
              <label style={ms.lb}>Time Window</label>
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 4 }}>
                {PROX_PRESETS.map((p) => (
                  <button key={p.label} disabled={!pivotVal}
                    onClick={() => applyProximity(selCol, pivotVal, p.ms, p.short)}
                    onMouseEnter={(e) => { if (pivotVal) e.currentTarget.style.borderColor = th.accent; }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = th.btnBorder; }}
                    style={{ padding: "5px 12px", background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: pivotVal ? th.text : th.textMuted, fontSize: 12, cursor: pivotVal ? "pointer" : "not-allowed", fontFamily: "-apple-system,sans-serif", transition: "border-color var(--m-base)" }}>
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
            <div style={ms.fg}>
              <label style={ms.lb}>Custom Window</label>
              <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 4 }}>
                <span style={{ color: th.textDim, fontSize: 12 }}>±</span>
                <input type="number" min="1" value={customN}
                  onChange={(e) => setModal((p) => ({ ...p, customN: e.target.value }))}
                  style={{ ...ms.ip, width: 70 }} />
                <select value={customU} onChange={(e) => setModal((p) => ({ ...p, customU: e.target.value }))} style={{ ...ms.sl, width: 100 }}>
                  <option value="s">seconds</option>
                  <option value="m">minutes</option>
                  <option value="h">hours</option>
                  <option value="d">days</option>
                </select>
                <button disabled={!pivotVal || customMs <= 0}
                  onClick={() => applyProximity(selCol, pivotVal, customMs, `${customN}${customU}`)}
                  style={{ ...ms.bp, opacity: (!pivotVal || customMs <= 0) ? 0.5 : 1, cursor: (!pivotVal || customMs <= 0) ? "not-allowed" : "pointer" }}>
                  Apply
                </button>
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 6 }}>
              <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
            </div>
          </Overlay>
        );
      })()}

      {/* Find Duplicates Modal */}
      {modal?.type === "findDuplicates" && ct && (() => {
        const selCol = modal.selCol || ct.headers?.[0] || "";
        const result = modal.result;
        const loading = modal.loading;
        const handleFindDuplicates = async () => {
          setModal((p) => ({ ...p, loading: true, result: null }));
          const af = activeFilters(ct);
          const uniqueResult = await tle.getColumnUniqueValues(ct.id, selCol, {
            searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
            columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
            bookmarkedOnly: ct.showBookmarkedOnly, limit: 50000,
            tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
            rowIdFilter: ct.rowIdFilter || null,
            dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
          });
          const values = Array.isArray(uniqueResult) ? uniqueResult : (uniqueResult?.values || []);
          const dupes = values.filter((v) => v.cnt > 1);
          setModal((p) => ({
            ...p,
            loading: false,
            result: {
              dupes,
              totalValues: Number(uniqueResult?.totalDistinct || values.length),
              truncated: Boolean(uniqueResult?.truncated),
            },
          }));
        };
        return (
          <Overlay th={th}>
            <h3 style={ms.mh}>Find Duplicates</h3>
            <div style={ms.fg}>
              <label style={ms.lb}>Column</label>
              <select value={selCol} onChange={(e) => setModal((p) => ({ ...p, selCol: e.target.value, result: null }))} style={ms.sl}>
                {(ct.headers || []).filter((h) => !ct.hiddenColumns?.has(h)).map((h) => <option key={h} value={h}>{h}</option>)}
              </select>
            </div>
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <button onClick={handleFindDuplicates} disabled={loading} style={{ ...ms.bp, opacity: loading ? 0.6 : 1 }}>
                {loading ? "Scanning..." : "Find Duplicates"}
              </button>
            </div>
            {result && (
              <div style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 6, padding: "10px 12px", marginBottom: 12 }}>
                {result.truncated && (
                  <div role="status" style={{ fontSize: 11, color: th.warning, marginBottom: 8 }}>
                    Showing results from the top 50,000 of {formatNumber(result.totalValues)} distinct values. Narrow the timeline before treating this as exhaustive.
                  </div>
                )}
                {result.dupes.length > 0 ? (<>
                  <div style={{ fontSize: 12, color: th.text, marginBottom: 6 }}>
                    Found <b style={{ color: th.accent }}>{result.dupes.length}</b> values with duplicates
                    ({result.dupes.reduce((s, d) => s + d.cnt, 0)} total rows)
                  </div>
                  <div style={{ maxHeight: 200, overflow: "auto", fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace" }}>
                    {result.dupes.slice(0, 100).map((d, i) => (
                      <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "2px 0", borderBottom: `1px solid ${th.border}22` }}>
                        <span style={{ color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 320 }}>{d.val || "(empty)"}</span>
                        <span style={{ color: th.textMuted, flexShrink: 0, marginLeft: 8 }}>×{d.cnt}</span>
                      </div>
                    ))}
                    {result.dupes.length > 100 && <div style={{ color: th.textMuted, padding: "4px 0", fontStyle: "italic" }}>...and {result.dupes.length - 100} more</div>}
                  </div>
                </>) : (
                  <div style={{ fontSize: 12, color: th.success }}>No duplicates found — all values in this column are unique.</div>
                )}
              </div>
            )}
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
              {result && result.dupes.length > 0 && (
                <button onClick={() => {
                  const dupeVals = result.dupes.map((d) => d.val == null || d.val === "" ? "" : String(d.val));
                  const existing = { ...(ct.checkboxFilters || {}) };
                  existing[selCol] = dupeVals;
                  up("checkboxFilters", existing);
                  setModal(null);
                }} style={ms.bp}>Filter to Duplicates</button>
              )}
            </div>
          </Overlay>
        );
      })()}

      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Known-Bad IOC Matching Modal */}
        {modal?.type === "ioc" && ct && <IocModal />}

        {/* Gap Analysis Modal */}
        {modal?.type === "gapAnalysis" && ct && <GapAnalysisModal />}
      </Suspense>

      {/* Cell Detail Popup */}
      {cellPopup && (() => {
        // Timestamp converter: detect if value is a valid date
        const cpVal = cellPopup.value || "";
        const cpDate = cpVal ? new Date(cpVal) : null;
        const cpIsTs = cpDate && !isNaN(cpDate.getTime()) && ct?.tsColumns?.has(cellPopup.column);
        // PowerShell Base64 decoder: detect -enc/-EncodedCommand
        const cpEncMatch = cpVal.match(/(?:\s|^)(?:-e|-enc|-encodedcommand|-en|-ec)\s+([A-Za-z0-9+/=]{20,})/i);
        let cpDecoded = null;
        if (cpEncMatch) {
          try {
            const b64 = cpEncMatch[1];
            const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
            // PowerShell uses UTF-16LE encoding
            const decoded = new TextDecoder("utf-16le").decode(bytes);
            // Only accept if result is mostly printable ASCII/unicode
            if (decoded && /[\x20-\x7e]/.test(decoded)) cpDecoded = decoded;
          } catch { /* invalid base64 */ }
        }
        return (
        <div onClick={() => setCellPopup(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, backdropFilter: "blur(4px)" }}>
          <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 12, padding: 0, width: 560, maxWidth: "92vw", maxHeight: "80vh", display: "flex", flexDirection: "column", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${th.border}` }}>
              <span style={{ color: th.textDim, fontSize: 12, fontWeight: 600 }}>{cellPopup.column}</span>
              <div style={{ display: "flex", gap: 6 }}>
                <button onClick={() => copyCell(cellPopup.value, cellPopup.column)} style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 11, padding: "4px 10px", cursor: "pointer", display: "flex", alignItems: "center", gap: 4 }}>
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                  Copy
                </button>
                <button onClick={() => setCellPopup(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px", lineHeight: 1 }}>✕</button>
              </div>
            </div>
            <div style={{ padding: "16px", overflow: "auto", maxHeight: "calc(80vh - 50px)" }}>
              <pre style={{ color: th.text, fontSize: 12, fontFamily: "'SF Mono', Menlo, monospace", whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0, lineHeight: 1.5 }}>{fmtCell(cellPopup.column, cpVal) || <span style={{ color: th.textMuted, fontStyle: "italic" }}>(empty)</span>}</pre>
              {/* Timestamp Converter */}
              {cpIsTs && (() => {
                const epoch = Math.floor(cpDate.getTime() / 1000);
                const epochMs = cpDate.getTime();
                const utc = cpDate.toISOString();
                const localFull = cpDate.toLocaleString("en-US", { dateStyle: "full", timeStyle: "long" });
                const localIso = cpDate.toLocaleString("sv-SE", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).replace(" ", "T");
                const ms3 = String(cpDate.getMilliseconds()).padStart(3, "0");
                const dayOfWeek = cpDate.toLocaleDateString("en-US", { weekday: "long", timeZone: "UTC" });
                // NTFS filetime: 100-nanosecond intervals since 1601-01-01
                const ntfsEpochOffset = 11644473600n;
                const ntfsFiletime = (BigInt(epochMs) / 1000n + ntfsEpochOffset) * 10000000n;
                const formats = [
                  ["UTC (ISO 8601)", utc],
                  ["UTC", `${cpDate.toISOString().replace("T", " ").replace("Z", "")} UTC`],
                  ["Local", localFull],
                  ["Local (ISO)", localIso],
                  ["Unix Epoch", String(epoch)],
                  ["Unix Epoch (ms)", String(epochMs)],
                  ["NTFS Filetime", ntfsFiletime.toString()],
                  ["Day of Week (UTC)", dayOfWeek],
                ];
                // Add configured timezone if set
                if (timezone && timezone !== "local" && timezone !== "UTC") {
                  try {
                    const tzFmt = cpDate.toLocaleString("en-US", { timeZone: timezone, dateStyle: "medium", timeStyle: "long" });
                    formats.splice(3, 0, [timezone, tzFmt]);
                  } catch { /* invalid tz */ }
                }
                return (
                  <div style={{ marginTop: 12, padding: "10px 12px", background: th.accentSubtle, border: `1px solid ${th.accent}33`, borderRadius: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                      <span style={{ fontSize: 11, color: th.accent, fontWeight: 600, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>Timestamp Converter</span>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 12px", alignItems: "baseline" }}>
                      {formats.map(([label, val]) => (
                        <Fragment key={label}>
                          <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif", textAlign: "right", whiteSpace: "nowrap" }}>{label}</span>
                          <span onClick={() => { navigator.clipboard?.writeText(val); setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200); }}
                            style={{ color: th.text, fontSize: 11, fontFamily: "'SF Mono', Menlo, monospace", cursor: "pointer", padding: "1px 4px", borderRadius: 3, wordBreak: "break-all" }}
                            title="Click to copy"
                            onMouseEnter={(e) => { e.currentTarget.style.background = th.glassBg; }}
                            onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                            {val}
                          </span>
                        </Fragment>
                      ))}
                    </div>
                  </div>
                );
              })()}
              {/* Decoded PowerShell */}
              {cpDecoded && (
                <div style={{ marginTop: 12, padding: "10px 12px", background: `${th.danger}11`, border: `1px solid ${th.danger}33`, borderRadius: 8 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                    <span style={{ fontSize: 11, color: th.danger, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Decoded PowerShell (-enc)</span>
                    <button onClick={() => { navigator.clipboard?.writeText(cpDecoded); setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200); }}
                      style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 10, padding: "2px 8px", cursor: "pointer", display: "flex", alignItems: "center", gap: 3 }}>
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                      Copy
                    </button>
                  </div>
                  <pre style={{ color: th.text, fontSize: 11, fontFamily: "'SF Mono', Menlo, monospace", whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0, lineHeight: 1.5 }}>{cpDecoded}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
        );
      })()}

      {/* Filter Dropdown */}
      {filterDropdown && (
        <>
          <div aria-hidden="true" onClick={() => setFilterDropdown(null)} style={{ position: "fixed", inset: 0, zIndex: 199 }} />
          <div role="dialog" aria-modal="true" aria-label={`Filter values for ${filterDropdown.colName}`} onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "fixed", left: filterDropdown.dx ?? Math.min(filterDropdown.x, window.innerWidth - 400), top: filterDropdown.dy ?? Math.min(filterDropdown.y, window.innerHeight - 440), width: 380, height: 420, minWidth: 260, minHeight: 200, maxWidth: "90vw", maxHeight: "90vh", background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 10, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", boxShadow: "0 12px 40px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", zIndex: 200, display: "flex", flexDirection: "column", overflow: "hidden", resize: "both", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
            <div style={{ padding: "4px 8px", flexShrink: 0, display: "flex", alignItems: "center", gap: 6, borderBottom: `1px solid ${th.border}`, cursor: "grab", userSelect: "none" }}
              onMouseDown={(e) => {
                if (e.button !== 0) return;
                e.preventDefault();
                e.stopPropagation();
                const panel = e.currentTarget.parentElement;
                const rect = panel.getBoundingClientRect();
                const ox = e.clientX - rect.left, oy = e.clientY - rect.top;
                const onMove = (ev) => { ev.preventDefault(); panel.style.left = (ev.clientX - ox) + "px"; panel.style.top = (ev.clientY - oy) + "px"; };
                const onUp = (ev) => {
                  ev.stopPropagation();
                  document.removeEventListener("mousemove", onMove);
                  document.removeEventListener("mouseup", onUp, true);
                };
                document.addEventListener("mousemove", onMove);
                document.addEventListener("mouseup", onUp, true);
              }}>
              <span style={{ color: th.textDim, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif", flex: 1 }}>Filter — {filterDropdown.colName === "__tags__" ? "Tags" : filterDropdown.colName === "__vt__" ? "VT Verdict" : filterDropdown.colName}</span>
              <button aria-label="Close value filter" onClick={() => setFilterDropdown(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, width: 26, height: 26, padding: 0, lineHeight: 1 }}>✕</button>
            </div>
            <div style={{ padding: "8px 8px 4px", flexShrink: 0, display: "flex", gap: 4 }}>
              <input value={fdSearch} onChange={(e) => setFdSearch(e.target.value)} placeholder={fdRegex ? "Regex pattern..." : "Search values..."} autoFocus
                style={{ flex: 1, background: th.bgInput, border: `1px solid ${fdRegex && fdSearch ? (() => { try { new RegExp(fdSearch); return th.btnBorder; } catch { return th.danger; } })() : th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "5px 8px", outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} />
              <button onClick={() => setFdRegex((v) => !v)} title="Toggle regex mode"
                style={{ padding: "3px 7px", background: fdRegex ? th.accentSubtle : th.btnBg, border: `1px solid ${fdRegex ? th.accent : th.btnBorder}`, borderRadius: 4, color: fdRegex ? th.accent : th.textMuted, fontSize: 11, cursor: "pointer", fontFamily: "monospace", fontWeight: 600, flexShrink: 0 }}>.*</button>
            </div>
            <div style={{ display: "flex", gap: 4, padding: "2px 8px 4px", flexShrink: 0 }}>
              <button onClick={() => setFdSelected(new Set(fdValues.map((v) => v.val)))} style={ms.bsm}>Select All</button>
              <button onClick={() => setFdSelected(new Set())} style={ms.bsm}>Clear</button>
              <span style={{ flex: 1 }} />
              <span role="status" style={{ color: fdValueMeta.truncated ? th.warning : th.textMuted, fontSize: 11, alignSelf: "center" }}>
                {fdSampled
                  ? `${formatNumber(fdValues.length)} sampled values`
                  : fdValueMeta.truncated
                  ? `Top ${formatNumber(fdValues.length)} of ${formatNumber(fdValueMeta.totalDistinct)}${fdSearch ? " — refine search" : " — search for more"}`
                  : `${formatNumber(fdValueMeta.totalDistinct)} values`}
              </span>
            </div>
            <div style={{ flex: 1, overflow: "auto", padding: "0 4px" }}>
              {fdLoading ? (
                <Loading />
              ) : fdValues.length === 0 ? (
                <div style={{ padding: 16, textAlign: "center", color: th.textMuted, fontSize: 11 }}>No values found</div>
              ) : (
                fdValues.map((v) => (
                  <label key={v.val ?? "__empty"} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", cursor: "pointer", borderRadius: 3, fontSize: 11, color: th.text }}>
                    <input type="checkbox" checked={fdSelected.has(v.val)} onChange={() => { const s = new Set(fdSelected); s.has(v.val) ? s.delete(v.val) : s.add(v.val); setFdSelected(s); }}
                      style={{ accentColor: th.borderAccent, width: 18, height: 18, flexShrink: 0 }} />
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.val || "(empty)"}</span>
                    <span style={{ color: th.textMuted, fontSize: 10, flexShrink: 0 }}>{formatNumber(v.cnt)}</span>
                  </label>
                ))
              )}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, padding: "6px 8px", borderTop: `1px solid ${th.border}` }}>
              <button onClick={() => {
                if (filterDropdown.colName === "__tags__") { up("tagFilter", null); setFilterDropdown(null); return; }
                const newCbf = { ...ct.checkboxFilters }; delete newCbf[filterDropdown.colName]; up("checkboxFilters", newCbf); setFilterDropdown(null);
              }} style={ms.bsm}>Reset</button>
              <button onClick={() => setFilterDropdown(null)} style={ms.bsm}>Cancel</button>
              <button onClick={applyCheckboxFilter} style={{ padding: "4px 11px", minHeight: 26, background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 4, fontSize: 11, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Apply</button>
            </div>
          </div>
        </>
      )}

      {/* Date Range Dropdown */}
      {dateRangeDropdown && (
        <>
          <div aria-hidden="true" onClick={() => setDateRangeDropdown(null)} style={{ position: "fixed", inset: 0, zIndex: 199 }} />
          <div role="dialog" aria-modal="true" aria-label={`Date range for ${dateRangeDropdown.colName}`} onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "fixed", left: Math.min(dateRangeDropdown.x, window.innerWidth - 300), top: Math.min(dateRangeDropdown.y, window.innerHeight - 220), width: 290, background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 10, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", boxShadow: "0 12px 40px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", zIndex: 200, padding: 12, animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
            <div style={{ color: th.textDim, fontSize: 11, marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Date Range — {dateRangeDropdown.colName}</div>
            <div style={{ marginBottom: 8 }}>
              <label style={{ display: "block", color: th.textMuted, fontSize: 11, marginBottom: 2, fontFamily: "-apple-system, sans-serif" }}>From</label>
              <input type="datetime-local" value={dateRangeDropdown.from} onChange={(e) => setDateRangeDropdown({ ...dateRangeDropdown, from: e.target.value })}
                style={{ width: "100%", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "4px 6px", outline: "none", fontFamily: "inherit", boxSizing: "border-box", colorScheme: themeName }} />
            </div>
            <div style={{ marginBottom: 10 }}>
              <label style={{ display: "block", color: th.textMuted, fontSize: 11, marginBottom: 2, fontFamily: "-apple-system, sans-serif" }}>To</label>
              <input type="datetime-local" value={dateRangeDropdown.to} onChange={(e) => setDateRangeDropdown({ ...dateRangeDropdown, to: e.target.value })}
                style={{ width: "100%", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "4px 6px", outline: "none", fontFamily: "inherit", boxSizing: "border-box", colorScheme: themeName }} />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 6 }}>
              <button onClick={() => {
                const newDrf = { ...ct.dateRangeFilters };
                delete newDrf[dateRangeDropdown.colName];
                up("dateRangeFilters", newDrf);
                setDateRangeDropdown(null);
              }} style={ms.bsm}>Clear</button>
              <button onClick={() => setDateRangeDropdown(null)} style={ms.bsm}>Cancel</button>
              <button onClick={() => {
                const newDrf = { ...ct.dateRangeFilters };
                if (dateRangeDropdown.from || dateRangeDropdown.to) {
                  newDrf[dateRangeDropdown.colName] = {};
                  if (dateRangeDropdown.from) newDrf[dateRangeDropdown.colName].from = dateRangeDropdown.from;
                  if (dateRangeDropdown.to) newDrf[dateRangeDropdown.colName].to = dateRangeDropdown.to;
                } else {
                  delete newDrf[dateRangeDropdown.colName];
                }
                up("dateRangeFilters", newDrf);
                setDateRangeDropdown(null);
              }} style={{ padding: "4px 11px", minHeight: 26, background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 4, fontSize: 11, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Apply</button>
            </div>
          </div>
        </>
      )}

      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Log Source Coverage Map Modal */}
        {modal?.type === "logSourceCoverage" && ct && <LogSourceCoverageModal />}

        {/* Burst Detection Modal */}
        {modal?.type === "burstAnalysis" && ct && <BurstAnalysisModal />}
      </Suspense>

      {/* Merge Tabs Modal */}
      {modal?.type === "mergeTabs" && (() => {
        const tabOptions = modal.tabOptions || [];
        const checkedTabs = tabOptions.filter((t) => t.checked);
        const totalMergeRows = checkedTabs.reduce((s, t) => s + t.rowCount, 0);
        const canMerge = checkedTabs.length >= 2 && checkedTabs.every((t) => t.selectedTsCol);
        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 12, padding: 0, width: 560, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Merge Tabs</h3>
                  <p style={{ margin: "3px 0 0", color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>
                    Combine {checkedTabs.length} tab{checkedTabs.length !== 1 ? "s" : ""} into a unified timeline ({formatNumber(totalMergeRows)} rows)
                  </p>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}>{"\u2715"}</button>
              </div>
              <div style={{ flex: 1, overflow: "auto", padding: "12px 20px" }}>
                {tabOptions.map((t, i) => (
                  <div key={t.tabId} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 0", borderBottom: `1px solid ${th.border}22` }}>
                    <input type="checkbox" checked={t.checked}
                      onChange={() => setModal((p) => {
                        const opts = [...p.tabOptions];
                        opts[i] = { ...opts[i], checked: !opts[i].checked };
                        return { ...p, tabOptions: opts };
                      })}
                      style={{ accentColor: th.accent }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.tabName}</div>
                      <div style={{ fontSize: 10, color: th.textMuted }}>{formatNumber(t.rowCount)} rows</div>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <span style={{ fontSize: 10, color: th.textMuted }}>Timestamp:</span>
                      <select value={t.selectedTsCol}
                        onChange={(e) => setModal((p) => {
                          const opts = [...p.tabOptions];
                          opts[i] = { ...opts[i], selectedTsCol: e.target.value };
                          return { ...p, tabOptions: opts };
                        })}
                        disabled={!t.checked}
                        style={{ background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "2px 6px", outline: "none", maxWidth: 160 }}>
                        {t.tsColumns.length === 0 && <option value="">No timestamp columns</option>}
                        {t.tsColumns.map((c) => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </div>
                  </div>
                ))}
                {checkedTabs.length < 2 && (
                  <div style={{ padding: "12px 0", color: th.warning, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>
                    Select at least 2 tabs to merge.
                  </div>
                )}
              </div>
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
                <button disabled={!canMerge} onClick={async () => {
                  setModal(null);
                  const mergedTabId = `tab_merged_${Date.now()}`;
                  const srcs = checkedTabs.map((t) => ({ tabId: t.tabId, tabName: t.tabName, tsCol: t.selectedTsCol }));
                  await tle.mergeTabs(mergedTabId, srcs);
                }}
                  style={{ ...ms.bp, opacity: canMerge ? 1 : 0.5, cursor: canMerge ? "pointer" : "not-allowed" }}>
                  Merge {checkedTabs.length} Tabs ({formatNumber(totalMergeRows)} rows)
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Edit Filter Modal */}
        {modal?.type === "editFilter" && ct && <EditFilterModal />}

        {/* Bulk Actions Modal */}
        {modal?.type === "bulkActions" && ct && (
          <BulkActionsModal
            fetchData={fetchData}
            selectionFilterOptions={selectionFilterOptions}
            selectionCount={selectionCount}
          />
        )}
      </Suspense>

      {/* Process Analyzer (provider + modal) */}
      <ProcessAnalyzerRoot activeFilters={activeFilters} />

      {/* Themed confirm dialog (replaces window.confirm) */}
      <ConfirmDialog />

      {/* Themed toast notifications (replaces alert() and inline message flashes) */}
      <ToastContainer />

      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Lateral Movement Modal */}
        {modal?.type === "lateralMovement" && ct && <LateralMovementModal />}
        {modal?.type === "triageCollection" && <TriageCollectionModal />}

        {/* Persistence Analyzer Modal */}
        {modal?.type === "persistence" && ct && <PersistenceModal />}

        {/* Ransomware MFT Analysis Modal */}
        {modal?.type === "ransomware" && ct && <RansomwareModal />}

        {/* Timestomping Detector Modal */}
        {modal?.type === "timestomping" && ct && <TimestompingModal />}

        {/* File Activity Heatmap Modal */}
        {modal?.type === "heatmap" && ct && <HeatmapModal />}
        {modal?.type === "sigma" && <SigmaRuleModal />}
        {modal?.type === "rdpBitmapCache" && <RdpBitmapCacheModal />}
        {modal?.type === "aiHistoryProfileScan" && <AiHistoryProfileScanModal />}
        {modal?.type === "aiHistoryExtract" && <AiHistoryExtractModal />}
        {modal?.type === "aiWorkspaceCorrelate" && <AiWorkspaceCorrelateModal th={th} />}
        {modal?.type === "aiHistoryScope" && <AiHistoryScopeModal />}
        {modal?.type === "aiSecrets" && <AiSecretsModal th={th} />}

        {/* ADS Analyzer Modal */}
        {modal?.type === "ads" && ct && <AdsModal />}

        {/* USN Journal Analysis Modal */}
        {modal?.type === "usnAnalysis" && ct && <UsnAnalysisModal />}
      </Suspense>

      {/* Context Menu */}
      {contextMenu && renderContextPortal(
        <>
          <div onMouseDown={(e) => { if (shouldCloseContextBackdrop(e)) setContextMenu(null); }} onContextMenu={(e) => { e.preventDefault(); }} style={{ position: "fixed", inset: 0, zIndex: 99998 }} />
          <div onMouseDown={(e) => e.stopPropagation()} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }} style={{ position: "fixed", left: contextMenu.x, top: contextMenu.y, background: themeName === "dark" ? "rgba(28,31,36,0.97)" : "rgba(252,252,254,0.97)", backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", border: `1px solid ${themeName === "dark" ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.12)"}`, borderRadius: 10, padding: "5px 0", zIndex: 99999, boxShadow: themeName === "dark" ? "0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.06) inset" : "0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(255,255,255,0.5) inset", minWidth: 200, animation: "tle-modal-in var(--m-fast) var(--ease-out)" }}>
            {[
              ...(contextMenu.colName !== "__tags__" ? [
                { label: (ct?.pinnedColumns || []).includes(contextMenu.colName) ? "Unpin Column" : "Pin Column",
                  icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M12 17v5M9 11l-4 4h14l-4-4V5a2 2 0 0 0-2-2h-2a2 2 0 0 0-2 2v6z"/></svg>,
                  action: () => (ct?.pinnedColumns || []).includes(contextMenu.colName) ? unpinColumn(contextMenu.colName) : pinColumn(contextMenu.colName) },
                { label: "Hide Column",
                  icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>,
                  action: () => up("hiddenColumns", new Set([...(ct?.hiddenColumns || []), contextMenu.colName])) },
                null,
              ] : []),
              { label: "Best Fit",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M21 12H3M21 12l-4-4M21 12l-4 4M3 12l4-4M3 12l4 4"/></svg>,
                action: () => autoFitColumn(contextMenu.colName) },
              { label: "Best Fit (All Columns)",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M22 12H2M22 12l-3-3M22 12l-3 3M2 12l3-3M2 12l3 3M12 2v20"/></svg>,
                action: () => autoFitAllColumns() },
              { label: "Reset Column Widths",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>,
                action: () => resetColumnWidths() },
              null,
              { label: "Sort Ascending",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg>,
                action: () => { up("sortCol", contextMenu.colName); up("sortDir", "asc"); } },
              { label: "Sort Descending",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M12 5v14M19 12l-7 7-7-7"/></svg>,
                action: () => { up("sortCol", contextMenu.colName); up("sortDir", "desc"); } },
              null,
              { label: selectedColumn === contextMenu.colName ? "Deselect Column" : "Select Column",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="8" y="3" width="8" height="18" rx="1" fill={`${th.accent}22`}/><path d="M4 3v18M20 3v18" opacity="0.4"/></svg>,
                action: () => setSelectedColumn(selectedColumn === contextMenu.colName ? null : contextMenu.colName) },
              { label: "Copy Column Values",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>,
                action: () => copyColumnValues(contextMenu.colName, { distinct: false }) },
              { label: "Copy Unique Values",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M20 6L9 17l-5-5"/></svg>,
                action: () => copyColumnValues(contextMenu.colName, { distinct: true }) },
              null,
              { label: "Stack Values", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="3" y="3" width="18" height="4" rx="1"/><rect x="3" y="10" width="14" height="4" rx="1"/><rect x="3" y="17" width="8" height="4" rx="1"/></svg>, action: () => {
                setModal(openStackingModal(contextMenu.colName));
                const af = activeFilters(ct);
                tle.getStackingData(ct.id, contextMenu.colName, {
                  searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
                  columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
                  bookmarkedOnly: ct.showBookmarkedOnly,
                  tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
                  rowIdFilter: ct.rowIdFilter || null,
                  dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
                  sortBy: "count",
                }).then((result) => {
                  if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
                  setModal(updateModal("stacking", { data: result, loading: false, error: null }));
                })
                  .catch((err) => setModal(updateModal("stacking", { loading: false, data: null, error: String(err?.message || err || "Stacking analysis failed") })));
              }},
              null,
              { label: "Column Stats", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="3" y="12" width="4" height="9" rx="1"/><rect x="10" y="6" width="4" height="15" rx="1"/><rect x="17" y="3" width="4" height="18" rx="1"/></svg>, action: () => {
                setModal(openColumnStatsModal(contextMenu.colName));
                const af = activeFilters(ct);
                tle.getColumnStats(ct.id, contextMenu.colName, {
                  searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
                  columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
                  bookmarkedOnly: ct.showBookmarkedOnly,
                  tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
                  rowIdFilter: ct.rowIdFilter || null,
                  dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
                }).then((result) => {
                  if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
                  setModal(updateModal("columnStats", { data: result, loading: false, error: null }));
                })
                  .catch((err) => setModal(updateModal("columnStats", { loading: false, data: null, error: String(err?.message || err || "Column statistics failed") })));
              }},
            ].map((item, i) =>
              item === null ? (
                <div key={i} style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
              ) : (
                <button key={i} onClick={() => { item.action(); setContextMenu(null); }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)", letterSpacing: "-0.01em" }}>
                  <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{item.icon}</span>
                  {item.label}
                </button>
              )
            )}
          </div>
        </>
      )}

      {/* Row Context Menu (for tagging) */}
      {rowContextMenu && renderContextPortal(
        <>
          <div onMouseDown={(e) => { if (shouldCloseContextBackdrop(e)) setRowContextMenu(null); }} onContextMenu={(e) => { e.preventDefault(); }} style={{ position: "fixed", inset: 0, zIndex: 99998 }} />
          <div onMouseDown={(e) => e.stopPropagation()} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }} style={{ position: "fixed", left: Math.min(rowContextMenu.x, window.innerWidth - 220), top: Math.min(rowContextMenu.y, window.innerHeight - 300), background: themeName === "dark" ? "rgba(28,31,36,0.97)" : "rgba(252,252,254,0.97)", backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", border: `1px solid ${themeName === "dark" ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.12)"}`, borderRadius: 10, padding: "5px 0", zIndex: 99999, boxShadow: themeName === "dark" ? "0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.06) inset" : "0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(255,255,255,0.5) inset", minWidth: 200, animation: "tle-modal-in var(--m-fast) var(--ease-out)" }}>
            {rowContextMenu.cellColumn && (
              <button onClick={() => { copyCell(rowContextMenu.cellValue, rowContextMenu.cellColumn); setRowContextMenu(null); }}
                onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>📋</span>
                Copy Cell <span style={{ color: th.textMuted, fontSize: 10, marginLeft: "auto", maxWidth: 80, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{rowContextMenu.cellColumn}</span>
              </button>
            )}
            {selectionCount > 1 && (
              <button onClick={() => {
                setRowContextMenu(null);
                void copySelectedRows();
              }}
                onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>📑</span>
                Copy Selected Rows
                <span style={{ color: th.textMuted, fontSize: 10, marginLeft: "auto" }}>{formatNumber(selectionCount)}</span>
              </button>
            )}
            <button onClick={() => {
              if (rowContextMenu.row && ct) {
                const hdrs = ct.headers.filter((h) => !ct.hiddenColumns?.has(h));
                const line = hdrs.map((h) => fmtCell(h, rowContextMenu.row[h] || "").replace(/\t/g, " ")).join("\t");
                navigator.clipboard?.writeText(hdrs.join("\t") + "\n" + line);
                setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200);
              }
              setRowContextMenu(null);
            }}
              onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
              <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>📄</span>
              {selectionCount > 1 ? "Copy This Row" : "Copy Row"}
            </button>
            {/* Filter in / Filter out */}
            {rowContextMenu.cellColumn && (
              <>
                <div style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
                <div style={{ padding: "4px 14px 2px", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", textTransform: "uppercase", letterSpacing: "0.06em" }}>Filters</div>
                <button onClick={() => {
                  setTabs((prev) => prev.map((t) => {
                    if (t.id !== activeTab) return t;
                    const newCbf = { ...t.checkboxFilters };
                    newCbf[rowContextMenu.cellColumn] = [rowContextMenu.cellValue];
                    return { ...t, checkboxFilters: newCbf };
                  }));
                  setRowContextMenu(null);
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                  <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></span>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>Filter in {rowContextMenu.cellValue ? String(rowContextMenu.cellValue).slice(0, 40) : "(empty)"}</span>
                </button>
                <button onClick={() => {
                  setTabs((prev) => prev.map((t) => {
                    if (t.id !== activeTab) return t;
                    const af = [...(t.advancedFilters || [])];
                    af.push({ column: rowContextMenu.cellColumn, operator: "not_equals", value: rowContextMenu.cellValue, logic: "AND" });
                    return { ...t, advancedFilters: af };
                  }));
                  setRowContextMenu(null);
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                  <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.danger} strokeWidth="2" strokeLinecap="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/><line x1="4" y1="21" x2="20" y2="5"/></svg></span>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>Filter out {rowContextMenu.cellValue ? String(rowContextMenu.cellValue).slice(0, 40) : "(empty)"}</span>
                </button>
              </>
            )}
            <div style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
            {/* Tags — collapsible submenu */}
            {(() => {
              const tagEntries = Object.entries(ct?.tagColors || {});
              const hasExplicitMultiSelection = !allRowsSelected
                && selectionCount > 1
                && selectedRows.has(Number(rowContextMenu.rowId));
              return (
                <div style={{ position: "relative" }}
                  onMouseEnter={(e) => { const sub = e.currentTarget.querySelector("[data-tag-sub]"); if (sub) sub.style.display = "block"; }}
                  onMouseLeave={(e) => { const sub = e.currentTarget.querySelector("[data-tag-sub]"); if (sub) sub.style.display = "none"; }}>
                  <button
                    onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                    <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>🏷</span>
                    Tags{hasExplicitMultiSelection ? ` (${selectionCount} rows)` : ""}
                    <span style={{ marginLeft: "auto", color: th.textMuted, fontSize: 11 }}>▸</span>
                  </button>
                  {/* Tags submenu */}
                  <div data-tag-sub="" style={{ display: "none", position: "absolute", left: "100%", top: -5, background: themeName === "dark" ? "rgba(28,31,36,0.97)" : "rgba(252,252,254,0.97)", backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", border: `1px solid ${themeName === "dark" ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.12)"}`, borderRadius: 10, padding: "5px 0", boxShadow: themeName === "dark" ? "0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.06) inset" : "0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(255,255,255,0.5) inset", minWidth: 160, zIndex: 100000 }}>
                    {tagEntries.map(([tag, color]) => {
                      const hasTg = rowContextMenu.currentTags.includes(tag);
                      return (
                        <button key={tag} onClick={async () => {
                          // Collect target row IDs — all selected rows if multi-selected, otherwise just the clicked row
                          const targetIds = [];
                          if (hasExplicitMultiSelection) {
                            targetIds.push(...selectedRows);
                          } else {
                            targetIds.push(rowContextMenu.rowId);
                          }
                          const newTags = { ...ct.rowTags };
                          for (const rid of targetIds) {
                            const rowTags = newTags[rid] || [];
                            const rowHas = rowTags.includes(tag);
                            if (rowHas) {
                              await tle.removeTag(ct.id, rid, tag);
                              newTags[rid] = rowTags.filter((t) => t !== tag);
                            } else {
                              await tle.addTag(ct.id, rid, tag);
                              newTags[rid] = [...rowTags, tag];
                            }
                          }
                          up("rowTags", newTags);
                          setRowContextMenu(null);
                        }}
                          onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                          onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                          style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "5px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                          <span style={{ color, fontSize: 14 }}>{hasTg ? "●" : "○"}</span>
                          <span>{tag}</span>
                        </button>
                      );
                    })}
                    <div style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
                    <button onClick={() => { setRowContextMenu(null); setModal(openSimpleModal("tags")); }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                      style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "5px 14px", background: "none", border: "none", color: th.textDim, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                      Manage Tags...
                    </button>
                  </div>
                </div>
              );
            })()}
            {/* VT Lookup for cell value */}
            {rowContextMenu.cellValue && (() => {
              const val = String(rowContextMenu.cellValue).trim();
              let vtCat = null;
              for (const [cat, re] of IOC_CATEGORY_PATTERNS) {
                if (re.test(val) && VT_COMPATIBLE_RE.test(cat)) { vtCat = cat; break; }
              }
              if (!vtCat) {
                const domainRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?){1,}$/i;
                if (domainRe.test(val) && val.includes(".")) vtCat = "Domain_Name";
              }
              if (!vtCat) return null;
              return (<>
                <div style={{ height: 1, background: th.border, margin: "4px 0" }} />
                <button onClick={async () => {
                  setRowContextMenu(null);
                  const status = await tle.vtGetApiKey();
                  if (!status?.hasKey) {
                    setCopiedMsg("Set VT API key in IOC Matching"); setTimeout(() => setCopiedMsg(false), 2500);
                    return;
                  }
                  setCopiedMsg("Looking up on VT..."); setTimeout(() => setCopiedMsg(false), 2000);
                  const result = await tle.vtLookupSingle(val, vtCat);
                  if (result?.error) {
                    setCopiedMsg(`VT: ${result.error}`); setTimeout(() => setCopiedMsg(false), 3000);
                  } else if (result?.vtUrl) {
                    setCopiedMsg(`VT: ${result.score} (${result.verdict})`); setTimeout(() => setCopiedMsg(false), 3000);
                    window.open(result.vtUrl, "_blank");
                  } else {
                    setCopiedMsg(`VT: ${result?.score || "N/A"}`); setTimeout(() => setCopiedMsg(false), 3000);
                  }
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                  <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>🔍</span>
                  Lookup on VirusTotal
                </button>
              </>);
            })()}
            {/* Decode Base64 PowerShell */}
            {rowContextMenu.cellValue && (() => {
              const cv = String(rowContextMenu.cellValue);
              const encMatch = cv.match(/(?:\s|^)(?:-e|-enc|-encodedcommand|-en|-ec)\s+([A-Za-z0-9+/=]{20,})/i);
              if (!encMatch) return null;
              return (<>
                <div style={{ height: 1, background: th.border, margin: "4px 0" }} />
                <button onClick={() => {
                  try {
                    const bytes = Uint8Array.from(atob(encMatch[1]), (c) => c.charCodeAt(0));
                    const decoded = new TextDecoder("utf-16le").decode(bytes);
                    setRowContextMenu(null);
                    setCellPopup({ column: "Decoded PowerShell (-enc)", value: decoded });
                  } catch {
                    setCopiedMsg("Failed to decode Base64"); setTimeout(() => setCopiedMsg(false), 2000);
                    setRowContextMenu(null);
                  }
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.danger, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                  <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>{'</>'}</span>
                  Decode Base64 PowerShell
                </button>
              </>);
            })()}
            {ct?.tsColumns?.size > 0 && (<>
              <div style={{ height: 1, background: th.border, margin: "4px 0" }} />
              <button onClick={() => {
                const tsCols = [...(ct?.tsColumns || new Set())];
                const autoCol = (ct?.sortCol && ct.tsColumns.has(ct.sortCol)) ? ct.sortCol : tsCols[0];
                setRowContextMenu(null);
                setModal(openProximityModal({ pivotRow: rowContextMenu.row, pivotCol: autoCol }));
              }}
                onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>⏱</span>
                Find Nearby Events...
              </button>
            </>)}
          </div>
        </>
      )}

      {/* Cell Context Menu (Cmd+Click) — Filter in / Filter out / Hide column */}
      {cellContextMenu && renderContextPortal(
        <>
          <div onMouseDown={(e) => { if (shouldCloseContextBackdrop(e)) setCellContextMenu(null); }} onContextMenu={(e) => { e.preventDefault(); }} style={{ position: "fixed", inset: 0, zIndex: 99998 }} />
          <div onMouseDown={(e) => e.stopPropagation()} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }} style={{ position: "fixed", left: Math.min(cellContextMenu.x, window.innerWidth - 240), top: Math.min(cellContextMenu.y, window.innerHeight - 160), background: themeName === "dark" ? "rgba(28,31,36,0.97)" : "rgba(252,252,254,0.97)", backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", border: `1px solid ${themeName === "dark" ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.12)"}`, borderRadius: 10, padding: "5px 0", zIndex: 99999, boxShadow: themeName === "dark" ? "0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.06) inset" : "0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(255,255,255,0.5) inset", minWidth: 200, animation: "tle-modal-in var(--m-fast) var(--ease-out)" }}>
            <div style={{ padding: "4px 14px 2px", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", textTransform: "uppercase", letterSpacing: "0.06em" }}>Filters</div>
            {[
              { label: `Filter in ${cellContextMenu.cellValue ? String(cellContextMenu.cellValue).slice(0, 40) : "(empty)"}`,
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>,
                action: () => {
                  setTabs((prev) => prev.map((t) => {
                    if (t.id !== activeTab) return t;
                    const newCbf = { ...t.checkboxFilters };
                    newCbf[cellContextMenu.colName] = [cellContextMenu.cellValue];
                    return { ...t, checkboxFilters: newCbf };
                  }));
                }},
              { label: `Filter out ${cellContextMenu.cellValue ? String(cellContextMenu.cellValue).slice(0, 40) : "(empty)"}`,
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.danger} strokeWidth="2" strokeLinecap="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/><line x1="4" y1="21" x2="20" y2="5"/></svg>,
                action: () => {
                  setTabs((prev) => prev.map((t) => {
                    if (t.id !== activeTab) return t;
                    const af = [...(t.advancedFilters || [])];
                    af.push({ column: cellContextMenu.colName, operator: "not_equals", value: cellContextMenu.cellValue, logic: "AND" });
                    return { ...t, advancedFilters: af };
                  }));
                }},
            ].map((item, i) => (
              <button key={i} onClick={() => { item.action(); setCellContextMenu(null); }}
                onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)", letterSpacing: "-0.01em" }}>
                <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{item.icon}</span>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.label}</span>
              </button>
            ))}
            <div style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
            <div style={{ padding: "4px 14px 2px", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", textTransform: "uppercase", letterSpacing: "0.06em" }}>Columns</div>
            <button onClick={() => { up("hiddenColumns", new Set([...(ct?.hiddenColumns || []), cellContextMenu.colName])); setCellContextMenu(null); }}
              onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)", letterSpacing: "-0.01em" }}>
              <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              </span>
              Hide column
            </button>
          </div>
        </>
      )}
    </div>
  );
}
