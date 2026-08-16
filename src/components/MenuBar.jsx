import { Fragment, useEffect, useState } from "react";
import useUIStore from "../store/useUIStore.js";
import useTabStore from "../store/useTabStore.js";
import { toast } from "../store/useToastStore.js";
import { DT_FORMATS, TIMEZONES } from "../constants/datetime.js";
import { isIpcError, ipcErrorMessage } from "../utils/ipc-result.js";
import { handleOpenFileDialogResult } from "../utils/open-file-result.js";
import { isAiHistorySourceFormat, tabHasActiveExportFilters } from "../utils/ai-history-profile.js";
import { getNextEnabledIndex } from "../utils/keyboard-navigation.js";
import { Modal } from "./primitives/index.js";
// Shared analyzer column/format detection — the single source of truth, also used by
// the home-screen capability tiles in App.jsx so both launch paths resolve columns identically.
import { buildProcessInspectorCols, buildLateralMovementCols, buildPersistenceMode } from "../utils/analyzer-launch.js";
import {
  AiAppsGroupIcon,
  AiArtifactsGroupIcon,
  ChatGptMenuIcon,
  ClaudeCodeMenuIcon,
  CopilotMenuIcon,
  CursorMenuIcon,
  GeminiMenuIcon,
  GrokMenuIcon,
  OpenAiMenuIcon,
  ComputerHistoryMenuIcon,
  WindsurfMenuIcon,
  ContinueMenuIcon,
} from "./ai-artifact-icons.jsx";
import {
  openAdsModal,
  openBulkActionsModal,
  openBurstAnalysisModal,
  openFindDuplicatesModal,
  openGapAnalysisModal,
  openHeatmapModal,
  openIocLoadModal,
  openIocResultsModal,
  openLateralMovementModal,
  openTriageCollectionModal,
  openLogSourceCoverageModal,
  openMergeTabsModal,
	  openPersistenceModal,
	  openProcessTreeModal,
	  openProximityModal,
  openRdpBitmapCacheModal,
	  openRansomwareModal,
  openSigmaModal,
  openSimpleModal,
  openStackingModal,
  openTimestompingModal,
  openUsnAnalysisModal,
  openAiHistoryProfileScanModal,
  openAiHistoryExtractModal,
  openAiHistoryScopeModal,
  openAiSecretsModal,
  updateModal,
} from "../modals/modalRegistry.js";

/**
 * MenuBar — File/View/Tools/Actions/Help menus + settings capsule.
 *
 * This is a pure cut-and-paste extraction from App.jsx lines 2235-2815.
 * All action logic that depends on App state is passed in via props.
 */
export default function MenuBar({
  th,
  ct,
  tabs,
  tle,
  // Handlers
  handleExport,
  handleSaveSession,
  handleLoadSession,
  handleCheckForUpdates,
  handleExtractResident,
  handleInstallUpdate,
  closeTab,
  resetColumnWidths,
  up,
  activeFilters,
  // Selection state
  allFilteredRowsSelected,
  selectedRowData,
  isGrouped,
  handleSelectAllRows,
  // Misc state
  proximityFilter,
  setProximityFilter,
  searchLoading,
  checkingForUpdates,
  extracting,
  recentFiles,
  setRecentFiles,
  copiedMsg,
  setCopiedMsg,
  // Column manager
  setColMgrSearch,
  // Search bar slot (FilterBar component rendered by parent)
  searchBar,
}) {
  const buildAiHistoryExportOptions = (extra = {}) => {
    const visSet = new Set(ct.headers.filter((h) => !ct.hiddenColumns.has(h)));
    if (ct.headers.includes("FullText")) visSet.add("FullText");
    const visHeaders = ct.headers.filter((h) => visSet.has(h));
    const af = activeFilters(ct);
    return {
      sortCol: ct.sortCol,
      sortDir: ct.sortDir,
      searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
      searchMode: ct.searchMode,
      searchCondition: ct.searchCondition || "contains",
      columnFilters: af.columnFilters,
      checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: ct.showBookmarkedOnly,
      visibleHeaders: visHeaders,
      tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
      rowIdFilter: ct.rowIdFilter || null,
      dateRangeFilters: ct.dateRangeFilters || {},
      advancedFilters: ct.advancedFilters || [],
      filtersApplied: tabHasActiveExportFilters(ct, activeFilters),
      ...extra,
    };
  };

  const exportAiHistoryPackage = async (sourcesOnlyManifest = false) => {
    if (!ct?.dataReady || !tle?.exportAiHistoryPackage) return;
    const r = await tle.exportAiHistoryPackage(
      ct.id,
      buildAiHistoryExportOptions(sourcesOnlyManifest ? { sourcesOnlyManifest: true } : {}),
      ct.name,
      ct.sourceFormat,
    );
    if (r?.canceled) return;
    if (isIpcError(r)) {
      toast.error(sourcesOnlyManifest ? "Source manifest export failed" : "AI history export failed", { detail: ipcErrorMessage(r) });
      return;
    }
    toast.success(sourcesOnlyManifest ? "Source manifest exported" : "AI history package exported", {
      detail: sourcesOnlyManifest
        ? `${r.sourceFileCount || 0} source file(s) (no timeline CSV)\n${r.dirPath}`
        : `${(r.rowCount || 0).toLocaleString()} rows, ${r.sourceFileCount || 0} source file(s)\n${r.dirPath}`,
      ttl: 10000,
    });
  };

  const decodeAiHistory = async (tool, label) => {
    const r = await tle.decodeAiHistory(null, tool, { promptScope: true, prepareOnly: true });
    if (r?.canceled) return;
    if (r?.needsScopeChoice) {
      setModal(openAiHistoryScopeModal({
        tool: r.tool || tool,
        target: r.target,
        extractTarget: r.extractTarget,
        label: r.label || label,
      }));
      return;
    }
    if (isIpcError(r)) { toast.error(`${label} extraction failed`, { detail: ipcErrorMessage(r) }); return; }
    if (r?.error) { toast.warning(label, { detail: r.error }); return; }
    if (r?.prepared) {
      setModal(openAiHistoryExtractModal({
        tool: r.tool || tool,
        target: r.target,
        extractTarget: r.extractTarget,
        label: r.label || label,
        includeSubagents: false,
      }));
    }
  };

  /**
   * ChatGPT Computer History (Skysight) — OS activity telemetry with its own column schema.
   * Prepared like the AI-history tools (pick a path, then hand off to the verbose extract modal),
   * but there is no subagent scope choice: activity events have no sidechains.
   */
  const decodeComputerHistory = async () => {
    const label = "ChatGPT Computer History";
    const r = await tle.decodeComputerHistory(null, { prepareOnly: true });
    if (r?.canceled) return;
    if (isIpcError(r)) { toast.error(`${label} extraction failed`, { detail: ipcErrorMessage(r) }); return; }
    if (r?.error) { toast.warning(label, { detail: r.error }); return; }
    if (r?.prepared) {
      setModal(openAiHistoryExtractModal({
        tool: "computer-history",
        target: r.target,
        extractTarget: r.extractTarget,
        label,
      }));
    }
  };

  const scanAiHistoryProfile = () => {
    setModal(openAiHistoryProfileScanModal());
  };

  // Zustand selectors
  const setModal = useUIStore((s) => s.setModal);
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
  const themeName = useUIStore((s) => s.themeName);
  const setThemeName = useUIStore((s) => s.setThemeName);
  const ftsTotal = ct?.ftsTotal || 0;
  const ftsPct = ftsTotal > 0 ? Math.round(((ct?.ftsIndexed || 0) / ftsTotal) * 100) : 0;
  const fontSize = useUIStore((s) => s.fontSize);
  const setFontSize = useUIStore((s) => s.setFontSize);
  const timezone = useUIStore((s) => s.timezone);
  const setTimezone = useUIStore((s) => s.setTimezone);
  const dateTimeFormat = useUIStore((s) => s.dateTimeFormat);
  const setDateTimeFormat = useUIStore((s) => s.setDateTimeFormat);
  const histogramVisible = useUIStore((s) => s.histogramVisible);
  const setHistogramVisible = useUIStore((s) => s.setHistogramVisible);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState("");
  const [commandActiveIndex, setCommandActiveIndex] = useState(0);

  const setActiveTab = useTabStore((s) => s.setActiveTab);
  const setTabs = useTabStore((s) => s.setTabs);

  useEffect(() => {
    const onKeyDown = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setFileMenuOpen(false); setViewMenuOpen(false); setToolsOpen(false);
        setActionsMenuOpen(false); setHelpMenuOpen(false);
        setCommandQuery("");
        setCommandActiveIndex(0);
        setCommandPaletteOpen(true);
      }
      if (event.key === "Escape") setSettingsOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setActionsMenuOpen, setFileMenuOpen, setHelpMenuOpen, setToolsOpen, setViewMenuOpen]);

  const tb = { display: "flex", alignItems: "center", gap: 5, padding: "5px 12px", background: "transparent", color: th.textDim, border: "none", borderRadius: 8, fontSize: 13, fontWeight: 500, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" };

  // Icon helper used in View/Actions/Tools menus
  const ic = (d, color) => <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={color || th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>{d}</svg>;

  // ── Render a generic dropdown menu item ────────────────────────
  const renderMenuItem = (item, i, closeFn) => {
    if (item.type === "separator") return <div key={`sep-${i}`} style={{ height: 1, background: th.border, margin: "4px 12px" }} />;
    if (item.type === "section") return (
      <div key={item.label} style={{ padding: "6px 14px 4px", borderTop: `1px solid ${th.border}33`, marginTop: 2 }}>
        <span style={{ fontSize: 9, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.1em", fontFamily: "-apple-system, sans-serif" }}>{item.label}</span>
      </div>
    );
    return (
      <button key={item.label} role="menuitem" onClick={() => { closeFn(); item.action?.(); }} disabled={item.disabled}
        onMouseEnter={(e) => { if (!item.disabled) { e.currentTarget.style.background = `${th.accent}15`; e.currentTarget.style.borderLeft = `2px solid ${th.accent}`; e.currentTarget.style.paddingLeft = "12px"; } }}
        onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.borderLeft = "2px solid transparent"; e.currentTarget.style.paddingLeft = "12px"; }}
        style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "7px 14px 7px 12px", background: "none", border: "none", borderLeft: "2px solid transparent", color: item.disabled ? th.textMuted : th.text, fontSize: 13, cursor: item.disabled ? "default" : "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif", opacity: item.disabled ? 0.4 : 1, transition: "background var(--m-fast) var(--ease-out), border-color var(--m-fast) var(--ease-out)" }}>
        {item.icon}
        {item.label}
      </button>
    );
  };

  // ── Dropdown style ────────────────────────────────────────────
  // Menu panels are OPAQUE (th.modalBg, no alpha suffix) — a dropdown must be readable, never let the
  // bright grid text behind it bleed through. The blur+border keep the elevated-surface look.
  const ddStyle = { position: "absolute", top: "100%", left: 0, marginTop: 4, background: th.modalBg, backdropFilter: "blur(16px)", WebkitBackdropFilter: "blur(16px)", border: `1px solid ${th.glassBorder}`, borderRadius: 10, padding: "6px 0", zIndex: 150, boxShadow: `0 12px 40px rgba(0,0,0,0.4), 0 0 0 1px ${th.glassBorder}`, minWidth: 220, whiteSpace: "nowrap", animation: "tle-modal-in var(--m-fast) var(--ease-out)" };
  const backdrop = (closeFn) => <div onClick={closeFn} style={{ position: "fixed", inset: 0, zIndex: 149 }} />;

  // ── Keyboard navigation for open dropdown menus (WAI-ARIA menu pattern) ──
  const closeAllMenus = () => {
    setFileMenuOpen(false); setViewMenuOpen(false); setToolsOpen(false);
    setActionsMenuOpen(false); setHelpMenuOpen(false);
  };
  // Callback ref: when a dropdown mounts (menu opens), move focus to its first enabled item
  // so arrow-key navigation works immediately for keyboard users.
  const focusFirstMenuItem = (el) => {
    if (!el) return;
    const first = el.querySelector('button:not([disabled])');
    if (first) requestAnimationFrame(() => first.focus());
  };
  // Arrow/Home/End move focus between items; Escape/Tab close the menu and return focus to its opener.
  const menuKeyDown = (e) => {
    const menu = e.currentTarget;
    const items = Array.from(menu.querySelectorAll('button:not([disabled])'));
    if (items.length === 0) return;
    const idx = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); items[(idx + 1 + items.length) % items.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[(idx - 1 + items.length) % items.length].focus(); }
    else if (e.key === "Home") { e.preventDefault(); items[0].focus(); }
    else if (e.key === "End") { e.preventDefault(); items[items.length - 1].focus(); }
    else if (e.key === "Escape" || e.key === "Tab") {
      const opener = menu.parentElement?.querySelector(":scope > button");
      closeAllMenus();
      if (e.key === "Escape" && opener) { e.preventDefault(); opener.focus(); }
    }
  };
  // ArrowDown on a top-level menu button opens it (the button's own onClick toggles open state,
  // and focusFirstMenuItem then moves focus inside).
  const menuButtonKeyDown = (e) => {
    if (e.key === "ArrowDown" && e.currentTarget.getAttribute("aria-expanded") !== "true") {
      e.preventDefault(); e.currentTarget.click();
    }
  };

  // ── Build Tools menu items ────────────────────────────────────
  const buildToolsItems = () => {
    return [
      { section: "Analysis" },
      { label: "Stack Values", icon: ic(<><line x1="4" y1="6" x2="16" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="12" y2="18"/></>), action: () => {
        if (!ct?.headers?.length) return;
        const colName = ct.sortCol || ct.headers[0];
        setModal(openStackingModal(colName));
        const af = activeFilters(ct);
        tle.getStackingData(ct.id, colName, {
          searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
          columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
          bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
          sortBy: "count",
        }).then((result) => {
          if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
          setModal(updateModal("stacking", { data: result, loading: false, error: null }));
        })
          .catch((err) => setModal(updateModal("stacking", { loading: false, data: null, error: String(err?.message || err || "Stacking analysis failed") })));
      }},
      { label: "Gap Analysis", icon: ic(<><circle cx="12" cy="12" r="9"/><polyline points="12 6 12 12 16 14"/></>, th.textDim), action: () => { if (ct?.dataReady && ct?.tsColumns?.size) setModal(openGapAnalysisModal([...ct.tsColumns][0])); }, disabled: !ct?.dataReady || !ct?.tsColumns?.size },
      { label: "Log Sources", icon: ic(<><rect x="2" y="3" width="20" height="4" rx="1"/><rect x="2" y="10" width="20" height="4" rx="1"/><rect x="2" y="17" width="20" height="4" rx="1"/><circle cx="18" cy="5" r="1" fill={th.accent}/><circle cx="14" cy="12" r="1" fill={th.accent}/><circle cx="18" cy="19" r="1" fill={th.accent}/></>), action: () => {
        if (!ct?.dataReady) return;
        const sourcePatterns = /^(Provider|Channel|source|data_type|parser|log_source|EventLog|SourceName|Source|_Source|DataType|ArtifactName|sourcetype|SourceLong|SourceDescription)$/i;
        const sourceCols = ct.headers.filter((h) => sourcePatterns.test(h));
        const defaultSourceCol = sourceCols.length > 0 ? sourceCols[0] : ct.headers.find((h) => !ct.tsColumns?.has(h)) || ct.headers[0];
        const defaultTsCol = ct.tsColumns?.size ? [...ct.tsColumns][0] : null;
        if (!defaultTsCol) return;
        setModal(openLogSourceCoverageModal({ sourceCol: defaultSourceCol, tsCol: defaultTsCol, sourceCols }));
      }, disabled: !ct?.dataReady || !ct?.tsColumns?.size },
      { label: "Burst Detection", icon: ic(<><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" fill={th.accent+"33"}/></>, th.danger), action: () => {
        if (ct?.dataReady && ct?.tsColumns?.size) setModal(openBurstAnalysisModal([...ct.tsColumns][0]));
      }, disabled: !ct?.dataReady || !ct?.tsColumns?.size },
      // ── AI assistant artifacts — native extractors. Profile collection can merge multiple
      //    sources; these entries are the per-tool manual import path. ──
      { group: "AI Artifacts", icon: <AiArtifactsGroupIcon th={th} />, items: [
        { label: "Collect AI Artifacts", icon: ic(<><path d="M4 13v5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5" fill={(th.accent) + "14"} /><path d="M12 3.5v9.5" /><polyline points="8.5 9.5 12 13 15.5 9.5" /></>, th.accent), action: scanAiHistoryProfile },
        { group: "AI Apps", icon: <AiAppsGroupIcon th={th} />, items: [
          { label: "Claude Code", icon: <ClaudeCodeMenuIcon th={th} />, action: () => decodeAiHistory("claude-code", "Claude Code AI History") },
          // Codex ships two distinct artifact families: conversation transcripts (~/.codex sessions)
          // and Computer History activity telemetry (Skysight). Different schemas, different
          // extractors — nested so the split is visible rather than implied.
          { group: "OpenAI Codex", icon: <OpenAiMenuIcon th={th} />, items: [
            { label: "Codex AI History", icon: <OpenAiMenuIcon th={th} />, action: () => decodeAiHistory("codex", "OpenAI Codex AI History") },
            { label: "ChatGPT Computer History", icon: <ComputerHistoryMenuIcon th={th} />, action: () => decodeComputerHistory() },
          ] },
          { label: "Grok Build", icon: <GrokMenuIcon th={th} />, action: () => decodeAiHistory("grok-build", "Grok Build AI History") },
          { label: "ChatGPT Desktop", icon: <ChatGptMenuIcon th={th} />, action: () => decodeAiHistory("chatgpt", "ChatGPT AI History") },
          { label: "Gemini CLI", icon: <GeminiMenuIcon th={th} />, action: () => decodeAiHistory("gemini-cli", "Gemini CLI AI History") },
          { label: "Cursor", icon: <CursorMenuIcon th={th} />, action: () => decodeAiHistory("cursor", "Cursor AI History") },
          { label: "GitHub Copilot", icon: <CopilotMenuIcon th={th} />, action: () => decodeAiHistory("copilot", "GitHub Copilot AI History") },
          { label: "Windsurf", icon: <WindsurfMenuIcon th={th} />, action: () => decodeAiHistory("windsurf", "Windsurf AI History") },
          { label: "Continue", icon: <ContinueMenuIcon th={th} />, action: () => decodeAiHistory("continue", "Continue AI History") },
        ] },
      ] },
      // ── Detection — cross-platform threat detection. Sigma rules span Windows EVTX, Linux
      //    auditd, macOS & cloud, so this lives outside the Windows platform group. ──
      { section: "Detection" },
      { label: "Sigma Scan", icon: ic(<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={th.accent + "18"}/><path d="M9 12l2 2 4-4" stroke={th.accent} strokeWidth="2"/></>, th.accent), action: () => {
        // Smart default: if a timeline tab is loaded, pre-select it as the scan target
        // (1-click scan); otherwise open on EVTX Folder for a raw .evtx directory scan.
        setModal(openSigmaModal({ scanMode: ct?.dataReady ? "tab" : "evtx-dir" }));
      } },
      { label: "AI Secret Hunt", icon: ic(<><rect x="5" y="11" width="14" height="9" rx="2" fill={(th.accent) + "22"}/><path d="M8 11V8a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15" r="1.4" fill={th.accent} stroke="none"/></>, th.accent), action: () => { if (ct?.dataReady) setModal(openAiSecretsModal({ tabId: ct.id, tabName: ct.name })); }, disabled: !ct?.dataReady || !isAiHistorySourceFormat(ct?.sourceFormat) },
      // ── Platform-specific forensics. Each OS is a collapsible group; click to reveal its tools. ──
      { section: "Platforms" },
      { group: "Windows", icon: ic(<><rect x="3" y="3" width="8" height="8" rx="1" fill={th.accent+"33"}/><rect x="13" y="3" width="8" height="8" rx="1" fill={th.accent+"33"}/><rect x="3" y="13" width="8" height="8" rx="1" fill={th.accent+"33"}/><rect x="13" y="13" width="8" height="8" rx="1" fill={th.accent+"33"}/></>, th.accent), items: [
      { label: "Process Inspector", icon: ic(<><circle cx="10" cy="10" r="6" fill={(th.accent)+"14"} stroke={th.accent} strokeWidth="1.5"/><line x1="14.5" y1="14.5" x2="20" y2="20" stroke={th.accent} strokeWidth="2" strokeLinecap="round"/><path d="M8 8v4M8 10h4" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round"/></>, th.accent), action: () => {
        if (!ct?.dataReady) return;
        setModal(openProcessTreeModal(buildProcessInspectorCols(ct.headers || [])));
      }, disabled: !ct?.dataReady },
	      { label: "Lateral Movement Tracker", icon: ic(<><circle cx="5" cy="12" r="2.5" fill={(th.danger)+"33"}/><circle cx="19" cy="5" r="2.5" fill={(th.danger)+"33"}/><circle cx="19" cy="19" r="2.5" fill={(th.danger)+"33"}/><line x1="7.5" y1="11" x2="16.5" y2="6"/><line x1="7.5" y1="13" x2="16.5" y2="18"/><circle cx="12" cy="12" r="1.5" fill={(th.danger)+"55"}/></>, th.danger), action: () => {
        if (!ct?.dataReady) return;
        const { cols, chainsawSyntheticTarget } = buildLateralMovementCols(ct.headers || []);
        setModal(openLateralMovementModal(cols, { chainsawSyntheticTarget }));
      }, disabled: !ct?.dataReady },
	      { label: "Persistence Analyzer", icon: ic(<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.danger)+"22"} stroke={th.danger}/><path d="M12 8v4M12 16h.01" stroke={th.danger}/></>, th.danger), action: () => {
        if (!ct?.dataReady) return;
        setModal(openPersistenceModal({ mode: buildPersistenceMode(ct.headers || []) }));
      }, disabled: !ct?.dataReady },
      { label: "RDP Bitmap Cache", icon: ic(<><rect x="3" y="5" width="18" height="12" rx="2" fill={(th.accent)+"18"}/><path d="M7 19h10M10 17v2M14 17v2"/><path d="M7 9h4v3H7zM13 9h4v3h-4z" fill={(th.accent)+"33"}/></>, th.accent), action: () => {
        setModal(openRdpBitmapCacheModal());
      } },
      // NTFS artifacts (Master File Table / USN Journal) are Windows-platform tools — kept as
      // collapsible sub-groups nested inside Windows.
      { group: "Master File Table", icon: ic(<><path d="M3 3h18v18H3z" fill={(th.accent) + "12"} rx="2"/><path d="M7 7h10M7 11h10M7 15h6"/><circle cx="17" cy="15" r="2" fill={th.accent} stroke="none" opacity="0.6"/></>), items: [
        { label: "Extract Resident Data", icon: ic(<><path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8l-6 6v12a2 2 0 0 0 2 2z" fill={(th.accent) + "14"}/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h5"/><path d="M12 9v8" opacity="0.4"/></>), action: handleExtractResident, disabled: !ct?.dataReady || ct?.sourceFormat !== "raw-mft" || extracting },
        { label: "Ransomware Analysis", icon: ic(<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.danger) + "22"}/><rect x="10" y="9" width="4" height="5" rx="1"/><circle cx="12" cy="7.5" r="2.5" fill="none"/></>), action: () => {
          if (!ct?.dataReady) return;
          const autoUsnTab = tabs.find((t) => t.id !== ct.id && t.dataReady && t.sourceFormat === "raw-usnjrnl");
          setModal(openRansomwareModal({ usnTabId: autoUsnTab?.id || "__none__" }));
        }, disabled: !ct?.dataReady || ct?.sourceFormat !== "raw-mft" || !ct?.headers?.includes("Extension") || !ct?.headers?.includes("FileName") || !ct?.headers?.includes("ParentPath") || !ct?.headers?.includes("LastModified0x10") },
        { label: "Timestomping Detector", icon: ic(<><circle cx="12" cy="12" r="10" fill={(th.warning) + "18"}/><polyline points="12 6 12 12 16 14"/><path d="M18 5l2-2" strokeWidth="2.5"/><circle cx="20" cy="3" r="1.5" fill={th.danger} stroke="none"/></>), action: () => { if (ct?.dataReady) { setModal(openTimestompingModal()); tle.detectTimestomping(ct.id).then((r) => setModal(updateModal("timestomping", { loading: false, data: r, error: null, tsSelFiles: new Set(), tsSelDirs: new Set(), tsSort: null }))).catch((err) => setModal(updateModal("timestomping", { loading: false, data: null, error: String(err?.message || err || "Timestomping analysis failed") }))); } }, disabled: !ct?.dataReady || !ct?.headers?.includes("SI<FN") },
        { label: "File Activity Heatmap", icon: ic(<><rect x="3" y="3" width="4" height="4" rx="1" fill={(th.accent) + "44"}/><rect x="10" y="3" width="4" height="4" rx="1" fill={(th.accent) + "22"}/><rect x="17" y="3" width="4" height="4" rx="1" fill={(th.accent) + "66"}/><rect x="3" y="10" width="4" height="4" rx="1" fill={(th.accent) + "88"}/><rect x="10" y="10" width="4" height="4" rx="1" fill={(th.accent) + "33"}/><rect x="17" y="10" width="4" height="4" rx="1" fill={(th.accent) + "55"}/><rect x="3" y="17" width="4" height="4" rx="1" fill={(th.accent) + "11"}/><rect x="10" y="17" width="4" height="4" rx="1" fill={(th.accent) + "77"}/><rect x="17" y="17" width="4" height="4" rx="1" fill={(th.accent) + "99"}/></>), action: () => { if (ct?.dataReady) { setModal(openHeatmapModal()); tle.getFileActivityHeatmap(ct.id).then((r) => setModal(updateModal("heatmap", { loading: false, data: r, error: null }))).catch((err) => setModal(updateModal("heatmap", { loading: false, data: null, error: String(err?.message || err || "Heatmap analysis failed") }))); } }, disabled: !ct?.dataReady || ct?.sourceFormat !== "raw-mft" || (!ct?.headers?.includes("Created0x10") && !ct?.headers?.includes("LastModified0x10")) },
        { label: "ADS Analyzer", icon: ic(<><rect x="3" y="3" width="18" height="18" rx="2" fill={(th.accent) + "12"}/><path d="M7 8h10"/><path d="M7 12h10" opacity="0.6"/><path d="M7 16h6" opacity="0.3"/><circle cx="17" cy="16" r="2" fill={th.danger} stroke="none"/></>), action: () => { if (ct?.dataReady) { setModal(openAdsModal()); tle.analyzeADS(ct.id).then((r) => setModal(updateModal("ads", { loading: false, data: r, error: null, adSelExec: new Set(), adSelZone: new Set(), adSelAds: new Set(), adSortExec: null, adSortZone: null, adSortAds: null }))).catch((err) => setModal(updateModal("ads", { loading: false, data: null, error: String(err?.message || err || "ADS analysis failed") }))); } }, disabled: !ct?.dataReady || (!ct?.headers?.includes("HasAds") && !ct?.headers?.includes("ZoneIdContents")) },
      ] },
      { group: "USN Journal", icon: ic(<><rect x="3" y="3" width="18" height="18" rx="2" fill={(th.accent) + "12"}/><path d="M7 8h10M7 12h7" opacity="0.6"/><path d="M16 11v6" strokeWidth="2"/><path d="M13 14l3 3 3-3" fill="none"/></>), items: [
        { label: "USN Journal Analysis", icon: ic(<><rect x="3" y="3" width="18" height="18" rx="2" fill={(th.accent) + "14"}/><path d="M7 7h10M7 11h10M7 15h6"/><circle cx="17" cy="15" r="2" fill={th.warning} stroke="none" opacity="0.7"/></>), action: () => { if (ct?.dataReady) setModal(openUsnAnalysisModal()); }, disabled: !ct?.dataReady || ct?.sourceFormat !== "raw-usnjrnl" },
      ] },
      ] },
      { group: "Coming soon", badge: "3 platforms", comingSoon: true, icon: ic(<><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/></>, th.textMuted), items: [
        { label: "Linux artifact analyzers", detail: "auth, shell history, persistence, auditd, SSH", icon: ic(<><rect x="3" y="4" width="18" height="13" rx="2"/><polyline points="7 9 10 11.5 7 14"/><line x1="12" y1="14" x2="16" y2="14"/></>, th.textMuted), disabled: true, comingSoon: true },
        { label: "macOS artifact analyzers", detail: "unified logs, persistence, FSEvents, quarantine, TCC", icon: ic(<><circle cx="12" cy="12" r="8"/><path d="M12 8v8M8 12h8"/></>, th.textMuted), disabled: true, comingSoon: true },
        { label: "Cloud log analyzers", detail: "AWS, Azure, M365, GCP, Okta", icon: ic(<><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></>, th.textMuted), disabled: true, comingSoon: true },
      ] },
      { section: "Export" },
      { label: "Export AI History Package", icon: ic(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M12 11v6M9 14h6"/></>, th.accent), action: () => exportAiHistoryPackage(false), disabled: !ct?.dataReady || !isAiHistorySourceFormat(ct?.sourceFormat) },
      { label: "Export Source Manifest (sources only)", icon: ic(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/></>, th.accent), action: () => exportAiHistoryPackage(true), disabled: !ct?.dataReady || !isAiHistorySourceFormat(ct?.sourceFormat) },
      { label: "Generate Report", icon: ic(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="15" y2="17"/></>, th.success), action: async () => { if (ct?.dataReady) await tle.generateReport(ct.id, ct.name, ct.tagColors || {}, ct.vtEnrichment || null); }, disabled: !ct?.dataReady },
    ];
  };

  // ── Render tools menu item with nested groups ─────────────────
  const renderToolsBtn = (item, indent) => (
    <button key={item.label} role="menuitem" title={item.detail} onClick={() => { setToolsOpen(false); item.action?.(); }} disabled={item.disabled}
      onMouseEnter={(e) => { if (!item.disabled) { e.currentTarget.style.background = `${th.accent}15`; e.currentTarget.style.borderLeft = `2px solid ${th.accent}`; e.currentTarget.style.paddingLeft = `${indent}px`; } }}
      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.borderLeft = "2px solid transparent"; e.currentTarget.style.paddingLeft = `${indent}px`; }}
      style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: `7px 14px 7px ${indent}px`, background: "none", border: "none", borderLeft: "2px solid transparent", color: item.disabled ? th.textMuted : th.text, fontSize: 13, cursor: item.disabled ? "default" : "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif", opacity: item.disabled ? 0.4 : 1, transition: "background var(--m-fast) var(--ease-out), border-color var(--m-fast) var(--ease-out)" }}>
      <span style={{ flexShrink: 0, display: "flex" }}>{item.icon}</span>
      <span style={{ flex: 1, minWidth: 0 }}>
        <span style={{ display: "block", whiteSpace: "nowrap" }}>{item.label}</span>
        {item.detail && <span style={{ display: "block", marginTop: 2, color: th.textMuted, fontSize: 9, overflow: "hidden", textOverflow: "ellipsis" }}>{item.detail}</span>}
      </span>
    </button>
  );

  // ── Render a Tools node (section / collapsible group / leaf) recursively, so an OS group
  //    like Windows can nest the NTFS Artifacts (MFT / USN) sub-groups. Indent grows per depth. ──
  const renderToolsNode = (item, depth, isFirst) => {
    if (item.section) {
      return (
        <div key={`sec-${item.section}`} style={{ padding: isFirst ? "2px 14px 4px" : "6px 14px 4px", borderTop: isFirst ? "none" : `1px solid ${th.border}33`, marginTop: isFirst ? 0 : 2 }}>
          <span style={{ fontSize: 9, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.1em", fontFamily: "-apple-system, sans-serif" }}>{item.section}</span>
        </div>
      );
    }
    if (item.group) {
      const indent = 12 + depth * 16;
      const expanded = !!toolsMenuExpanded[item.group];
      return (
        <Fragment key={`grp-${item.group}`}>
          <button onClick={() => setToolsMenuExpanded((p) => ({ ...p, [item.group]: !p[item.group] }))}
            type="button" aria-expanded={expanded}
            onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}10`; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
            style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: `7px 14px 7px ${indent}px`, background: "none", border: "none", borderLeft: "2px solid transparent", color: th.text, fontSize: 13, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif", transition: "background var(--m-fast) var(--ease-out), border-color var(--m-fast) var(--ease-out)" }}>
            {item.icon}
            <span style={{ flex: 1, whiteSpace: "nowrap", overflow: "visible" }}>{item.group}</span>
            {item.badge && <span style={{ color: th.textMuted, fontSize: 9, padding: "1px 5px", border: `1px solid ${th.border}`, borderRadius: 8 }}>{item.badge}</span>}
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ transform: expanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform var(--m-base) ease", flexShrink: 0 }}>
              <polyline points="3,1 7,5 3,9" />
            </svg>
          </button>
          {expanded && item.items.map((sub) => renderToolsNode(sub, depth + 1, false))}
        </Fragment>
      );
    }
    return renderToolsBtn(item, 12 + depth * 16);
  };

  // ── Build Actions menu items ──────────────────────────────────
  const buildActionsItems = () => {
    return [
      { label: ct?.showBookmarkedOnly ? "Show All Rows" : "Show Flagged Only", icon: ic(ct?.showBookmarkedOnly ? <><path d="M1 4v10l7 7 10-10V1H8z" fill={th.accent+"22"}/><circle cx="13" cy="7" r="2"/><line x1="3" y1="18" x2="10" y2="11"/></> : <><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></>, ct?.showBookmarkedOnly ? th.accent : th.textDim), action: () => { if (ct) up("showBookmarkedOnly", !ct.showBookmarkedOnly); } },
      { type: "separator" },
      { label: allFilteredRowsSelected ? "Deselect All" : "Select All", icon: ic(<><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M8 12h8M12 8v8"/></>), action: handleSelectAllRows, disabled: !ct?.dataReady || isGrouped },
      { type: "separator" },
      { label: "IOC Matching", icon: ic(<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.warning)+"22"}/></>), action: () => {
        if (!ct?.dataReady) return;
        const vte = ct.vtEnrichment;
        if (vte?.perIocResults && vte.results) {
          const restoredIocTags = vte.allIocTags || vte.perIocResults.filter((r) => r.hits > 0).map((r) => `IOC: ${r.raw}`);
          setModal(openIocResultsModal({ parsedIocs: vte.parsedIocs || [],
            results: { matchedRowIds: [], matchedCount: vte.matchedCount ?? null, tagName: "", allIocTags: restoredIocTags, perIocResults: vte.perIocResults },
            vtResults: vte.results }));
        } else {
          setModal(openIocLoadModal());
        }
      }, disabled: !ct?.dataReady },
      { label: "Bulk Tag / Bookmark", icon: ic(<><rect x="3" y="3" width="18" height="18" rx="3" fill={th.accent+"14"}/><path d="M8 12h8M12 8v8"/></>, th.accent), action: () => { if (ct?.dataReady) setModal(openBulkActionsModal()); }, disabled: !ct?.dataReady },
      { type: "separator" },
      { label: "Pivot ±N Minutes", icon: ic(<><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></>, th.accent), action: () => {
        if (!selectedRowData || !ct?.tsColumns?.size) return;
        const tsCols = [...(ct.tsColumns || new Set())];
        const autoCol = (ct?.sortCol && ct.tsColumns.has(ct.sortCol)) ? ct.sortCol : tsCols[0];
        setModal(openProximityModal({ pivotRow: selectedRowData, pivotCol: autoCol }));
      }, disabled: !selectedRowData || !ct?.tsColumns?.size },
      { label: "Find Duplicates", icon: ic(<><rect x="4" y="4" width="12" height="12" rx="2"/><rect x="8" y="8" width="12" height="12" rx="2"/></>), action: () => {
        if (ct?.dataReady) setModal(openFindDuplicatesModal(ct.headers?.[0] || ""));
      }, disabled: !ct?.dataReady },
    ];
  };

  // ── Build View menu items ─────────────────────────────────────
  const buildViewItems = () => [
    { label: "Columns", icon: ic(<><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>), action: () => { setColMgrSearch(""); setModal(openSimpleModal("columns")); } },
    { label: "Color Rules", icon: ic(<><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18" fill={th.accent} opacity="0.3"/></>), action: () => setModal(openSimpleModal("colors")) },
    { label: "Tags", icon: ic(<><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><circle cx="7" cy="7" r="1" fill={th.accent}/></>), action: () => setModal(openSimpleModal("tags")) },
    { label: "Filter Presets", icon: ic(<><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></>), action: () => setModal(openSimpleModal("presets")) },
    { label: "Edit Filter", icon: ic(<><rect x="3" y="4" width="18" height="16" rx="2" fill="none"/><line x1="7" y1="9" x2="17" y2="9"/><line x1="7" y1="13" x2="14" y2="13"/><line x1="7" y1="17" x2="11" y2="17"/></>), action: () => { if (ct?.dataReady) setModal(openSimpleModal("editFilter")); }, disabled: !ct?.dataReady },
    { label: "Merge Tabs", icon: ic(<><rect x="4" y="4" width="16" height="6" rx="1"/><rect x="4" y="14" width="16" height="6" rx="1"/><line x1="12" y1="10" x2="12" y2="14" strokeDasharray="2,1"/></>), action: () => {
      const ready = tabs.filter((t) => t.dataReady && !t.importing);
      if (ready.length < 2) return;
      setModal(openMergeTabsModal(ready.map((t) => ({
        tabId: t.id, tabName: t.name, rowCount: t.totalRows,
        tsColumns: [...(t.tsColumns || new Set())],
        selectedTsCol: [...(t.tsColumns || new Set())][0] || "",
        checked: true,
      }))));
    }, disabled: tabs.filter((t) => t.dataReady && !t.importing).length < 2 },
  ];

  const flattenToolCommands = (items, trail = [], unavailable = false) => items.flatMap((item) => {
    if (item.section) return [];
    if (item.group) {
      return flattenToolCommands(item.items || [], [...trail, item.group], unavailable || item.comingSoon);
    }
    if (!item.label || unavailable || item.comingSoon) return [];
    return [{ ...item, category: ["Tools", ...trail].join(" › ") }];
  });
  const commandItems = [
    { category: "File", label: "Open", shortcut: "⌘O", action: () => tle?.openFileDialog() },
    { category: "File", label: "Open Triage Collection", action: () => setModal(openTriageCollectionModal()) },
    { category: "File", label: "Export", shortcut: "⌘E", action: handleExport, disabled: !ct?.dataReady },
    { category: "File", label: "Save Session", shortcut: "⌘S", action: handleSaveSession, disabled: tabs.length === 0 },
    { category: "File", label: "Load Session", shortcut: "⇧⌘O", action: handleLoadSession },
    { category: "File", label: "Close Tab", shortcut: "⌘W", action: () => { if (ct) closeTab(ct.id); }, disabled: !ct },
    ...buildViewItems().filter((item) => item.label).map((item) => ({ ...item, category: "View" })),
    ...buildActionsItems().filter((item) => item.label).map((item) => ({ ...item, category: "Actions" })),
    ...flattenToolCommands(buildToolsItems()),
    { category: "Help", label: "Quick Help", action: () => setModal(openSimpleModal("quickHelp")) },
    { category: "Help", label: "Keyboard Shortcuts", shortcut: "⌘/", action: () => setModal(openSimpleModal("shortcuts")) },
    { category: "Help", label: checkingForUpdates ? "Checking for Updates..." : "Check for Updates", action: handleCheckForUpdates, disabled: checkingForUpdates },
  ];
  const normalizedCommandQuery = commandQuery.trim().toLocaleLowerCase();
  const filteredCommands = commandItems.filter((item) => (
    !normalizedCommandQuery
    || `${item.category} ${item.label}`.toLocaleLowerCase().includes(normalizedCommandQuery)
  ));
  const resolvedCommandActiveIndex = (
    commandActiveIndex >= 0
    && commandActiveIndex < filteredCommands.length
    && !filteredCommands[commandActiveIndex]?.disabled
  )
    ? commandActiveIndex
    : filteredCommands.findIndex((command) => !command.disabled);
  useEffect(() => {
    if (!commandPaletteOpen || resolvedCommandActiveIndex < 0) return;
    document.getElementById(`command-option-${resolvedCommandActiveIndex}`)?.scrollIntoView({ block: "nearest" });
  }, [commandPaletteOpen, commandQuery, resolvedCommandActiveIndex]);
  const runCommand = (command) => {
    if (command.disabled) return;
    setCommandPaletteOpen(false);
    setCommandQuery("");
    command.action?.();
  };

  return (
    <>
    <div className="tle-menubar-shell" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 12px 6px 84px", background: th.toolbarBg, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", borderBottom: `1px solid ${th.glassBorder}`, gap: 10, flexShrink: 0, position: "relative", zIndex: 100, WebkitAppRegion: "drag" }}>
      <div className="tle-menubar-left" style={{ display: "flex", alignItems: "center", gap: 8, WebkitAppRegion: "no-drag" }}>
        {/* Menu capsule */}
        <div role="menubar" aria-label="Main menu" style={{ display: "flex", alignItems: "center", gap: 1, background: th.glassBg, border: `1px solid ${th.glassBorder}`, borderRadius: 10, padding: 2 }}>

        {/* File menu */}
        <div style={{ position: "relative" }}>
          <button className="tle-tb" role="menuitem" aria-haspopup="true" aria-expanded={fileMenuOpen} onKeyDown={menuButtonKeyDown} onClick={() => setFileMenuOpen((v) => !v)} style={{ ...tb, color: fileMenuOpen ? th.accent : th.textDim }}>File ▾</button>
          {fileMenuOpen && (<>
            {backdrop(() => setFileMenuOpen(false))}
            <div style={ddStyle} role="menu" ref={focusFirstMenuItem} onKeyDown={menuKeyDown}>
              {[
                { label: "Open", shortcut: "⌘O", action: async () => {
                  const r = await tle?.openFileDialog();
                  handleOpenFileDialogResult(tle, setModal, r);
                } },
                { label: "Open Triage Collection…", action: () => setModal(openTriageCollectionModal()) },
                { label: "Export", shortcut: "⌘E", action: handleExport, disabled: !ct?.dataReady },
                { type: "separator" },
                { label: "Save Session", shortcut: "⌘S", action: handleSaveSession, disabled: tabs.length === 0 },
                { label: "Load Session", shortcut: "⇧⌘O", action: handleLoadSession },
                { type: "separator" },
                { label: "Open Recent", submenu: true },
                { type: "separator" },
                { label: "Close Tab", shortcut: "⌘W", action: () => { if (ct) closeTab(ct.id); }, disabled: !ct },
                { label: "Close All Tabs", action: () => { setTabs((prev) => { prev.forEach((t) => tle.closeTab(t.id)); return []; }); setActiveTab(null); }, disabled: tabs.length === 0 },
                { type: "separator" },
                { label: "Exit", action: () => window.close() },
              ].map((item, i) => {
                if (item.type === "separator") return <div key={`sep-${i}`} style={{ height: 1, background: th.border, margin: "4px 12px" }} />;
                if (item.submenu) {
                  return (
                    <div key={item.label} style={{ position: "relative" }}
                      onMouseEnter={(e) => { const el = e.currentTarget; el.dataset.hover = "1"; el.querySelector("[data-submenu]")?.style.setProperty("display", "block"); }}
                      onMouseLeave={(e) => { const el = e.currentTarget; el.dataset.hover = ""; el.querySelector("[data-submenu]")?.style.setProperty("display", "none"); }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 16px", cursor: "default", fontSize: 13, fontFamily: "-apple-system, sans-serif", color: th.text }}>
                        <span>{item.label}</span>
                        <span style={{ fontSize: 10, color: th.textMuted, marginLeft: 12 }}>▶</span>
                      </div>
                      <div data-submenu style={{ display: "none", position: "absolute", left: "100%", top: -6, background: th.modalBg, border: `1px solid ${th.glassBorder}`, borderRadius: 10, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", padding: "6px 0", zIndex: 151, boxShadow: "0 12px 40px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", minWidth: 260, whiteSpace: "nowrap" }}>
                        {recentFiles.length > 0 ? (<>
                          {recentFiles.map((fp, ri) => (
                            <div key={ri} onClick={() => { setFileMenuOpen(false); tle?.openRecentFile(fp).then((r) => { if (r?.error) toast.error("Could not open file", { detail: `${r.error}\n${fp}` }); }); }}
                              title={fp}
                              style={{ padding: "6px 16px", cursor: "pointer", fontSize: 12, fontFamily: "-apple-system, sans-serif", color: th.text, overflow: "hidden", textOverflow: "ellipsis" }}
                              onMouseEnter={(e) => e.currentTarget.style.background = th.selection}
                              onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                              {fp.split("/").pop()}
                              <div style={{ fontSize: 10, color: th.textMuted, marginTop: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{fp}</div>
                            </div>
                          ))}
                          <div style={{ height: 1, background: th.border, margin: "4px 12px" }} />
                          <div onClick={() => { setFileMenuOpen(false); tle?.clearRecentFiles(); setRecentFiles([]); }}
                            style={{ padding: "6px 16px", cursor: "pointer", fontSize: 12, fontFamily: "-apple-system, sans-serif", color: th.textMuted }}
                            onMouseEnter={(e) => e.currentTarget.style.background = th.selection}
                            onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                            Clear Recent Files
                          </div>
                        </>) : (
                          <div style={{ padding: "6px 16px", fontSize: 12, fontFamily: "-apple-system, sans-serif", color: th.textMuted, fontStyle: "italic" }}>No recent files</div>
                        )}
                      </div>
                    </div>
                  );
                }
                return (
                  <button key={item.label} type="button" role="menuitem" disabled={item.disabled} onClick={() => { if (!item.disabled) { setFileMenuOpen(false); item.action?.(); } }}
                    style={{ width: "100%", border: "none", background: "transparent", textAlign: "left", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 16px", cursor: item.disabled ? "default" : "pointer", fontSize: 13, fontFamily: "-apple-system, sans-serif", color: item.disabled ? th.textMuted : th.text, opacity: item.disabled ? 0.5 : 1 }}
                    onMouseEnter={(e) => { if (!item.disabled) e.currentTarget.style.background = th.selection; }}
                    onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                    <span>{item.label}</span>
                    {item.shortcut && <span style={{ fontSize: 11, color: th.textMuted, marginLeft: 24 }}>{item.shortcut}</span>}
                  </button>
                );
              })}
            </div>
          </>)}
        </div>

        {/* View menu */}
        <div style={{ position: "relative" }}>
          <button className="tle-tb" role="menuitem" aria-haspopup="true" aria-expanded={viewMenuOpen} onKeyDown={menuButtonKeyDown} onClick={() => setViewMenuOpen((v) => !v)} style={{ ...tb, color: viewMenuOpen ? th.accent : th.textDim }}>View ▾</button>
          {viewMenuOpen && (<>
            {backdrop(() => setViewMenuOpen(false))}
            <div style={ddStyle} role="menu" ref={focusFirstMenuItem} onKeyDown={menuKeyDown}>
              {buildViewItems().map((item, i) => renderMenuItem(item, i, () => setViewMenuOpen(false)))}
            </div>
          </>)}
        </div>

        {/* Actions menu */}
        <div style={{ position: "relative" }}>
          <button className="tle-tb" role="menuitem" aria-haspopup="true" aria-expanded={actionsMenuOpen} onKeyDown={menuButtonKeyDown} onClick={() => setActionsMenuOpen((v) => !v)} style={{ ...tb, color: actionsMenuOpen ? th.accent : ct?.showBookmarkedOnly ? th.warning : th.textDim }}>Actions ▾</button>
          {actionsMenuOpen && (<>
            {backdrop(() => setActionsMenuOpen(false))}
            <div style={ddStyle} role="menu" ref={focusFirstMenuItem} onKeyDown={menuKeyDown}>
              {buildActionsItems().map((item, i) => renderMenuItem(item, i, () => setActionsMenuOpen(false)))}
            </div>
          </>)}
        </div>

        {/* Tools menu */}
        <div style={{ position: "relative" }}>
          <button className="tle-tb" role="menuitem" aria-haspopup="true" aria-expanded={toolsOpen} onKeyDown={menuButtonKeyDown} onClick={() => setToolsOpen((v) => !v)} style={{ ...tb, color: toolsOpen ? th.accent : th.textDim }}>Tools ▾</button>
          {toolsOpen && (<>
            {backdrop(() => setToolsOpen(false))}
            <div style={{ ...ddStyle, minWidth: 280, width: "max-content", maxWidth: "min(420px, 92vw)" }} role="menu" ref={focusFirstMenuItem} onKeyDown={menuKeyDown}>
              {buildToolsItems().map((item, i) => renderToolsNode(item, 0, i === 0))}
            </div>
          </>)}
        </div>

        {/* Help menu */}
        <div style={{ position: "relative" }}>
          <button className="tle-tb" role="menuitem" aria-haspopup="true" aria-expanded={helpMenuOpen} onKeyDown={menuButtonKeyDown} onClick={() => setHelpMenuOpen((v) => !v)} style={{ ...tb, color: helpMenuOpen ? th.accent : th.textDim }}>Help ▾</button>
          {helpMenuOpen && (<>
            {backdrop(() => setHelpMenuOpen(false))}
            <div style={ddStyle} role="menu" ref={focusFirstMenuItem} onKeyDown={menuKeyDown}>
              {[
                { label: "Command Palette", shortcut: "⌘K", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round"><circle cx="11" cy="11" r="7"/><line x1="16" y1="16" x2="21" y2="21"/></svg>, action: () => { setCommandQuery(""); setCommandActiveIndex(0); setCommandPaletteOpen(true); } },
                { label: "Quick Help", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>, action: () => setModal(openSimpleModal("quickHelp")) },
                { label: "Keyboard Shortcuts", shortcut: "⌘/", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 8h.01M10 8h.01M14 8h.01M18 8h.01M6 12h.01M18 12h.01M8 16h8"/></svg>, action: () => setModal(openSimpleModal("shortcuts")) },
                { label: checkingForUpdates ? "Checking for Updates" : "Check for Updates", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><polyline points="21 3 21 9 15 9"/></svg>, action: handleCheckForUpdates },
                { type: "separator" },
                { label: "Website", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>, action: () => window.open("https://r3nzsec.github.io/irflow-timeline/", "_blank") },
                { label: "About IRFlow Timeline", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>, action: () => setModal(openSimpleModal("about")) },
              ].map((item, i) => {
                if (item.type === "separator") return <div key={`sep-${i}`} style={{ height: 1, background: th.border, margin: "4px 12px" }} />;
                return (
                  <button key={item.label} type="button" role="menuitem" onClick={() => { setHelpMenuOpen(false); item.action?.(); }}
                    style={{ width: "100%", border: "none", background: "transparent", textAlign: "left", display: "flex", alignItems: "center", gap: 10, padding: "7px 14px", cursor: "pointer", fontSize: 13, fontFamily: "-apple-system, sans-serif", color: th.text }}
                    onMouseEnter={(e) => e.currentTarget.style.background = th.selection}
                    onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                    {item.icon}
                    <span style={{ flex: 1 }}>{item.label}</span>
                    {item.shortcut && <span style={{ fontSize: 11, color: th.textMuted }}>{item.shortcut}</span>}
                  </button>
                );
              })}
            </div>
          </>)}
        </div>
        </div>{/* end menu capsule */}

        <button type="button" className="tle-settings-toggle tle-tb" aria-expanded={settingsOpen} aria-controls="timeline-toolbar-settings"
          aria-label={`${settingsOpen ? "Close" : "Open"} display settings`}
          onClick={() => setSettingsOpen((open) => !open)}
          style={{ ...tb, display: "none", background: th.glassBg, border: `1px solid ${th.glassBorder}`, padding: "5px 8px" }}>
          ⚙ Settings
        </button>
        {settingsOpen && <div className="tle-settings-backdrop" onClick={() => setSettingsOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 149, display: "none" }} />}

        {/* Settings capsule */}
        <div id="timeline-toolbar-settings" className="tle-toolbar-settings" data-open={settingsOpen ? "true" : "false"}
          style={{ display: "flex", alignItems: "center", gap: 4, background: th.glassBg, border: `1px solid ${th.glassBorder}`, borderRadius: 10, padding: "2px 6px" }}>
        <span aria-hidden="true" style={{ color: th.textMuted, fontSize: 10 }}>⏱</span>
        <select aria-label="Timestamp display format" value={dateTimeFormat} onChange={(e) => setDateTimeFormat(e.target.value)} style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, color: th.textDim, fontSize: 10, padding: "3px 5px", borderRadius: 4, cursor: "pointer", outline: "none" }}>
          {DT_FORMATS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
        </select>
        <select aria-label="Timestamp timezone" value={timezone} onChange={(e) => setTimezone(e.target.value)} style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, color: th.textDim, fontSize: 10, padding: "3px 5px", borderRadius: 4, cursor: "pointer", outline: "none" }}>
          {TIMEZONES.map((tz) => <option key={tz.value} value={tz.value}>{tz.label}</option>)}
        </select>
        <span style={{ width: 1, height: 14, background: th.glassBorder, display: "inline-block" }} />
        <button className="tle-tb" aria-label={`Switch to ${themeName === "dark" ? "light" : "dark"} theme`} onClick={() => setThemeName((p) => p === "dark" ? "light" : "dark")} style={{ ...tb, padding: "4px 8px" }} title="Toggle theme">{themeName === "dark" ? "☀" : "🌙"}</button>
        <span style={{ width: 1, height: 14, background: th.glassBorder, display: "inline-block" }} />
        <span aria-hidden="true" style={{ color: th.textMuted, fontSize: 10 }}>A</span>
        <button className="tle-tb" aria-label="Decrease grid font size" onClick={() => setFontSize((s) => Math.max(9, s - 1))} style={{ ...tb, fontSize: 11, padding: "3px 5px" }} title="Decrease font size">−</button>
        <output aria-label="Grid font size" style={{ color: th.textDim, fontSize: 10, minWidth: 18, textAlign: "center" }}>{fontSize}</output>
        <button className="tle-tb" aria-label="Increase grid font size" onClick={() => setFontSize((s) => Math.min(18, s + 1))} style={{ ...tb, fontSize: 11, padding: "3px 5px" }} title="Increase font size">+</button>
        <span style={{ width: 1, height: 14, background: th.glassBorder, display: "inline-block" }} />
        <button className="tle-tb" aria-label="Toggle timeline histogram" aria-pressed={histogramVisible} onClick={() => setHistogramVisible((v) => !v)} style={{ ...tb, color: histogramVisible ? th.accent : th.textDim, padding: "4px 8px" }} title="Toggle timeline histogram">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="12" width="4" height="9" rx="1" /><rect x="10" y="6" width="4" height="15" rx="1" /><rect x="17" y="3" width="4" height="18" rx="1" /></svg>
        </button>
        </div>{/* end settings capsule */}

        {/* Proximity filter pill */}
        {proximityFilter && ct?.dateRangeFilters?.[proximityFilter.tsCol] && (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "3px 8px", background: `${th.warning}22`, border: `1px solid ${th.warning}4D`, borderRadius: 10, color: th.warning, fontSize: 10, fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}
            title={`Proximity: ±${proximityFilter.label} around ${proximityFilter.pivotRaw}`}>
            ⏱ ±{proximityFilter.label}
            <span style={{ color: th.textMuted, maxWidth: 80, overflow: "hidden", textOverflow: "ellipsis" }}>{" near "}{(proximityFilter.pivotRaw || "").slice(11, 19)}</span>
            <button onClick={() => { const next = { ...(ct?.dateRangeFilters || {}) }; delete next[proximityFilter.tsCol]; up("dateRangeFilters", next); setProximityFilter(null); }}
              aria-label="Clear proximity filter"
              style={{ background: "none", border: "none", color: th.warning, cursor: "pointer", fontSize: 10, padding: "0 0 0 2px", lineHeight: 1 }} title="Clear proximity filter">✕</button>
          </span>
        )}
      </div>

      {/* Search bar (FilterBar) — rendered via slot prop */}
      <div className="tle-search-slot" style={{ display: "flex", flex: 1, minWidth: 180, maxWidth: 560, WebkitAppRegion: "no-drag" }}>
        {searchBar}
      </div>

      {/* Background indexing indicator */}
      {ct && ct.dataReady && (!ct.indexesReady || (!ct.ftsReady && ct.ftsTotal > 0)) && (
        <div className="tle-indexing-indicator" style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 6px", flexShrink: 0 }}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={th.warning} strokeWidth="2.5" style={{ animation: "tle-spin 1s linear infinite", flexShrink: 0 }}>
            <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" /></svg>
          <span style={{ color: th.warning, fontSize: 9, fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
            {!ct.indexesReady && (!ct.ftsReady && ct.ftsTotal > 0)
              ? `Indexing cols ${ct.indexesBuilt || 0}/${ct.indexesTotal || "..."} + search ${ftsPct}%`
              : !ct.indexesReady
              ? `Indexing columns ${ct.indexesBuilt || 0}/${ct.indexesTotal || "..."}`
              : `Indexing search ${ftsPct}%`}
          </span>
        </div>
      )}
    </div>
    <Modal open={commandPaletteOpen} title="Command Palette" subtitle="Search actions across the application" width={620} maxHeight="78vh"
      zIndex={260} bodyPadding="12px" onClose={() => { setCommandPaletteOpen(false); setCommandQuery(""); }}>
      <input autoFocus role="combobox" aria-autocomplete="list" aria-expanded="true" aria-controls="command-palette-results"
        aria-activedescendant={resolvedCommandActiveIndex >= 0 ? `command-option-${resolvedCommandActiveIndex}` : undefined}
        value={commandQuery} onChange={(event) => { setCommandQuery(event.target.value); setCommandActiveIndex(0); }}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            const activeCommand = filteredCommands[resolvedCommandActiveIndex];
            if (activeCommand) runCommand(activeCommand);
          } else if (event.key === "ArrowDown") {
            event.preventDefault();
            setCommandActiveIndex(getNextEnabledIndex(filteredCommands, resolvedCommandActiveIndex, 1));
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            setCommandActiveIndex(getNextEnabledIndex(filteredCommands, resolvedCommandActiveIndex, -1));
          } else if (event.key === "Home") {
            event.preventDefault();
            setCommandActiveIndex(getNextEnabledIndex(filteredCommands, -1, 1));
          } else if (event.key === "End") {
            event.preventDefault();
            setCommandActiveIndex(getNextEnabledIndex(filteredCommands, -1, -1));
          }
        }}
        aria-label="Search commands" placeholder="Type a command, tool, or action…"
        style={{ width: "100%", boxSizing: "border-box", background: th.bgInput, color: th.text, border: `1px solid ${th.btnBorder}`, borderRadius: 7, padding: "9px 11px", fontSize: 13, outline: "none", marginBottom: 8 }} />
      <div id="command-palette-results" role="listbox" aria-label="Available commands" style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: "52vh", overflowY: "auto" }}>
        {filteredCommands.map((command, index) => (
          <button id={`command-option-${index}`} key={`${command.category}-${command.label}-${index}`} type="button" role="option" aria-selected={index === resolvedCommandActiveIndex} disabled={command.disabled}
            onClick={() => runCommand(command)}
            onMouseEnter={() => { if (!command.disabled) setCommandActiveIndex(index); }}
            style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "8px 10px", background: index === resolvedCommandActiveIndex ? th.selection : "transparent", border: "none", borderRadius: 6, color: command.disabled ? th.textMuted : th.text, opacity: command.disabled ? 0.45 : 1, cursor: command.disabled ? "default" : "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
            <span style={{ color: th.textMuted, fontSize: 10, minWidth: 92 }}>{command.category}</span>
            <span style={{ flex: 1, fontSize: 13 }}>{command.label}</span>
            {command.disabled && <span style={{ fontSize: 9, color: th.textMuted }}>Unavailable</span>}
            {command.shortcut && <span style={{ fontSize: 10, color: th.textMuted }}>{command.shortcut}</span>}
          </button>
        ))}
        {filteredCommands.length === 0 && (
          <div role="status" style={{ padding: "18px 10px", color: th.textMuted, fontSize: 12, textAlign: "center" }}>No matching commands</div>
        )}
      </div>
      {filteredCommands.length > 0 && <div role="status" style={{ padding: "7px 4px 0", color: th.textMuted, fontSize: 10 }}>{filteredCommands.filter((command) => !command.disabled).length} available · ↑↓ navigate · Enter run</div>}
    </Modal>
    </>
  );
}
