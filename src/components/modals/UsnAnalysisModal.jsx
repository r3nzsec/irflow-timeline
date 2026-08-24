import { useState } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { DraggableResizableModal } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";
import {
  openAdsModal,
  openPersistenceModal,
  openRansomwareModal,
  openTimestompingModal,
  updateModal,
} from "../../modals/modalRegistry.js";

export default function UsnAnalysisModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const ct = useCurrentTab();
  const { th } = useTheme();
  const tle = typeof window !== "undefined" ? window.tle : null;
  const tabs = useTabStore((s) => s.tabs);
  const setActiveTab = useTabStore((s) => s.setActiveTab);

  // Filter dropdown — separate from modal to avoid re-rendering all sections
  const [usnFd, setUsnFd] = useState(null);

  if (modal?.type !== "usnAnalysis" || !ct) return null;

  // ── Modal styles (mirrors App.jsx ms object) ──
  const ms = useModalChrome();

  const { phase, data, loading, error } = modal;
  const usnResolveStats = ct?.sourceFormat === "raw-usnjrnl" ? (ct.usnResolveStats || null) : null;
  const usnResolveTone = (() => {
    if (!usnResolveStats) return null;
    const pct = Number(usnResolveStats.resolvedPercent || 0);
    if (pct >= 90) return { label: "High confidence", color: th.success };
    if (pct >= 60) return { label: "Partial coverage", color: th.warning };
    return { label: "Low confidence", color: th.danger };
  })();

  const handleAnalyze = async () => {
    // Start time is OPTIONAL — empty means analyze the full journal (the analyzer defaults the
    // window to the journal start and reports the span in the coverage header).
    setModal((p) => ({ ...p, phase: "loading", loading: true, error: null }));
    try {
      const result = await tle.analyzeUsnJournal(
        ct.id,
        (modal.startTime || "").trim() || null,
        (modal.endTime || "").trim() || null,
        modal.analyses,
        (modal.pathFilter || "").trim() || null,
        modal.mftTabId || null
      );
      if (isIpcError(result)) {
        setModal((p) => p?.type === "usnAnalysis" ? { ...p, phase: "input", loading: false, error: ipcErrorMessage(result) } : p);
      } else {
        const nextExpanded = usnSections.reduce((acc, sec) => {
          acc[sec.key] = getUsnSectionCount(sec.key, result?.[sec.key]) > 0;
          return acc;
        }, {});
        setModal((p) => p?.type === "usnAnalysis" ? { ...p, phase: "results", loading: false, data: result, usnExpanded: nextExpanded, usnIncidentsExpanded: false, usnTimelineExpanded: false, usnLikelyFindingsExpanded: false, usnShowSuppressed: {} } : p);
      }
    } catch (e) {
      setModal((p) => p?.type === "usnAnalysis" ? { ...p, phase: "input", loading: false, error: e.message } : p);
    }
  };

  const toggleAnalysis = (key) => setModal((p) => p ? { ...p, analyses: { ...p.analyses, [key]: !p.analyses[key] } } : p);
  const toggleExpand = (key, canExpand = true) => {
    if (!canExpand) return;
    setModal((p) => p ? { ...p, usnExpanded: { ...p.usnExpanded, [key]: !p.usnExpanded[key] } } : p);
  };

  // Unit 42 warm monochrome palette — graduated from bright (critical) to muted (informational)
  const usnSections = [
    { key: "renames", label: "Rename Activity", desc: "Tracks old \u2192 new filename pairs \u2014 detects masquerading, staging, or anti-forensics", color: "#D4783A", icon: <><path d="M17 3a2.83 2.83 0 0 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></> },
    { key: "deletions", label: "Deletion Activity", desc: "Files removed from disk \u2014 evidence destruction, cleanup scripts, or ransomware traces", color: "#C44D1E", icon: <><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></> },
    { key: "creations", label: "File Creation", desc: "New files written to disk \u2014 payload drops, tool deployment, or lateral movement artifacts", color: "#E8A050", icon: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></> },
    { key: "exfil", label: "Data Exfiltration", desc: "Archive creation (zip/rar/7z) and staging directory activity \u2014 data collection before exfil", color: th.accent, icon: <><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M12 12v4"/><path d="M9 15l3 3 3-3" fill="none"/></> },
    { key: "execution", label: "Execution Artifacts", desc: "Executable files created or modified (.exe, .dll, .ps1, .bat, etc.) \u2014 malware deployment", color: "#FF6B35", icon: <><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></> },
    { key: "persistence", label: "Persistence Paths", desc: "Startup folders, scheduled tasks, GPO scripts, and WMI MOF paths \u2014 filesystem foothold locations", color: "#D45A2A", icon: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></> },
    { key: "suspiciousPaths", label: "Suspicious Paths", desc: "Payload-like files or tampering in Temp, Public, Recycle Bin, ProgramData, Recovery, and media folders", color: "#C96B3C", icon: <><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></> },
    { key: "securityChanges", label: "Security Changes", desc: "NTFS permission modifications \u2014 bulk changes indicate archive extraction or ACL tampering", color: "#B85C38", icon: <><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></> },
    { key: "dataOverwrite", label: "Data Overwrite", desc: "File content modified or extended \u2014 ransomware encryption, config changes, or log tampering", color: "#E87848", icon: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><line x1="9" y1="13" x2="15" y2="13" strokeWidth="2.5"/></> },
    { key: "streamChanges", label: "Stream Changes", desc: "Alternate Data Stream modifications \u2014 Zone.Identifier updates, hidden data, or MOTW changes", color: "#D4956A", icon: <><path d="M4 4h16v16H4z" rx="2"/><path d="M8 8h8M8 12h5" opacity="0.6"/><circle cx="16" cy="16" r="2.5" fill="#D4956A" stroke="none"/></> },
    { key: "closePatterns", label: "Close Patterns", desc: "Files opened then closed without modification \u2014 recon, enumeration, or directory listing", color: "#C8A882", icon: <><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/></> },
  ];
  const getUsnSectionCount = (secKey, sectionData) => {
    if (!sectionData) return 0;
    if (secKey === "exfil") return Number(sectionData.archiveCount || sectionData.archives?.length || 0);
    return Number(sectionData.count || sectionData.events?.length || 0);
  };

  // ── Column definitions per section ──
  const hasCorrelation = !!data?.correlation;
  const hasReasons = (k) => ["execution", "persistence", "suspiciousPaths", "securityChanges", "exfil", "dataOverwrite", "streamChanges", "closePatterns"].includes(k);
  const mftCols = () => hasCorrelation ? [
    { key: "_mftStatus", label: "Status", w: 70, get: (ev) => { const m = ev._mft; if (!m) return "\u2014"; const parts = []; if (m.matchMode === "exact") parts.push("EX"); else if (m.matchMode === "entry-only") parts.push("FB"); if (m.inUse === "False") parts.push("DEL"); if (m.siFn === "True") parts.push("TS"); else if (m.uSecZeros === "True") parts.push("µs0"); if (m.zoneId?.trim()) parts.push("DL"); return parts.length > 0 ? parts.join("|") : "OK"; } },
    { key: "_mftSize", label: "Size", w: 72, get: (ev) => { const s = ev._mft?.fileSize; if (!s || s === "0") return ""; const n = parseInt(s, 10); if (isNaN(n)) return s; if (n < 1024) return n + " B"; if (n < 1048576) return (n / 1024).toFixed(1) + " KB"; if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB"; return (n / 1073741824).toFixed(2) + " GB"; } },
  ] : [];
  const getColumns = (secKey) => {
    if (secKey === "renames") return [
      { key: "timestamp", label: "Timestamp", w: 150, get: (ev) => (ev.timestamp || "").slice(0, 19) },
      { key: "oldName", label: "Old Name", flex: 1, get: (ev) => ev.oldName, color: th.danger },
      { key: "arrow", label: "", w: 20, get: () => "\u2192", noSort: true, noResize: true },
      { key: "newName", label: "New Name", flex: 1, get: (ev) => ev.newName, color: th.success },
      { key: "parentPath", label: "Parent Path", flex: 1.5, get: (ev) => ev.parentPath },
      ...mftCols(),
    ];
    const cols = [
      { key: "timestamp", label: "Timestamp", w: 150, get: (ev) => (ev.timestamp || "").slice(0, 19) },
      { key: "name", label: "Name", flex: 1, get: (ev) => ev.name },
    ];
    if (secKey !== "exfil") cols.push({ key: "extension", label: "Ext", w: 60, get: (ev) => ev.extension });
    if ((secKey === "persistence" || secKey === "suspiciousPaths") && (data?.[secKey]?.categories?.length > 0 || data?.[secKey]?.suppressedCount > 0)) {
      cols.push({ key: "heuristicCategory", label: "Class", w: 150, get: (ev) => ev.heuristicCategory || "" });
    }
    cols.push({ key: "parentPath", label: "Parent Path", flex: 1.5, get: (ev) => ev.parentPath });
    if (hasReasons(secKey)) cols.push({ key: "reasons", label: "Reasons", w: 140, get: (ev) => ev.reasons });
    if ((secKey === "persistence" || secKey === "suspiciousPaths") && (data?.[secKey]?.suppressedCount || 0) > 0 && !!modal?.usnShowSuppressed?.[secKey]) {
      cols.push({ key: "suppressionReason", label: "Suppressed", w: 180, get: (ev) => ev.suppressionReason || "" });
    }
    cols.push(...mftCols());
    return cols;
  };

  const copyReport = () => {
    if (!data) return;
    const lines = [
      "=== USN Journal Analysis ===",
      `Time Range: ${data.summary?.startTime || modal.startTime || "journal start"} to ${data.summary?.endTime || modal.endTime || "Open-ended"}`,
      data.summary?.pathFilter ? `Path Filter: ${data.summary.pathFilter}` : null,
      `Total Events in Window: ${(data.summary?.totalEvents || 0).toLocaleString()}`, "",
    ];
    if (data.narrative?.length > 0) {
      lines.push("--- Investigator Summary ---");
      data.narrative.forEach((n) => lines.push(`  - ${n}`));
      lines.push("");
    }
    if (data.likelyFindings?.length > 0) {
      lines.push(`--- Likely Intrusion Findings: ${data.likelyFindings.length} ---`);
      data.likelyFindings.slice(0, 10).forEach((finding, idx) => {
        lines.push(`  ${idx + 1}. [${String(finding.severity || "info").toUpperCase()}] ${finding.title}`);
        if (finding.summary) lines.push(`    ${finding.summary}`);
        if (finding.rationale) lines.push(`    Why: ${finding.rationale}`);
        if (finding.primaryPath || finding.path) lines.push(`    Path: ${finding.primaryPath || finding.path}`);
        if (finding.start || finding.end) lines.push(`    Time: ${(finding.start || "").slice(0, 19)} -> ${(finding.end || "").slice(0, 19)}`);
        if (finding.evidence?.length) lines.push(`    Evidence: ${finding.evidence.join(", ")}`);
      });
      lines.push("");
    }
    if (data.directoryIncidents?.length > 0) {
      lines.push(`--- Directory Incidents: ${data.directoryIncidents.length} ---`);
      data.directoryIncidents.slice(0, 20).forEach((inc) => {
        lines.push(`  ${inc.title}`);
        lines.push(`    ${inc.start?.slice(0, 19)} -> ${inc.end?.slice(0, 19)} | ${inc.eventCount} events | ${inc.uniqueFiles} files | ${inc.path}`);
        if (inc.reasons?.length) lines.push(`    Reasons: ${inc.reasons.join(", ")}`);
        if (inc.tags?.length) lines.push(`    Tags: ${inc.tags.join(", ")}`);
      });
      lines.push("");
    }
    if (data.timeline?.length > 0) {
      lines.push("--- Merged Storyline ---");
      data.timeline.slice(0, 50).forEach((ev) => lines.push(`  ${ev.timestamp?.slice(0, 19)}\t${ev.reasonLabel}\t${ev.displayName || ev.name}\t${ev.parentPath}${ev.tags?.length ? `\t[${ev.tags.join(", ")}]` : ""}`));
      lines.push("");
    }
    if (data.correlation) {
      const c = data.correlation;
      lines.push("--- MFT Cross-Artifact Correlation ---");
      lines.push(`  MFT Matched: ${c.matched} of ${c.totalUsnEntries} unique file refs`);
      if (c.exactMatched != null || c.fallbackMatched != null) {
        lines.push(`  Exact vs fallback: ${c.exactMatched || 0} exact, ${c.fallbackMatched || 0} entry-only`);
      }
      lines.push(`  Unmatched: ${c.unmatched}`);
      lines.push(`  Deleted Files (InUse=False): ${c.deleted}`);
      lines.push(`  Timestomped (SI<FN): ${c.timestomped}`);
      if (c.timestompedUSec != null) lines.push(`  Sub-second-zero (µs0, weaker signal): ${c.timestompedUSec}`);
      lines.push(`  Downloaded (Zone.Identifier): ${c.downloaded}`);
      lines.push("");
    }
    if (data.renames) {
      lines.push(`--- Rename Activity: ${data.renames.count} events ---`);
      data.renames.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.oldName} -> ${r.newName}\t${r.parentPath}`));
      lines.push("");
    }
    if (data.deletions) {
      lines.push(`--- Deletion Activity: ${data.deletions.count} events ---`);
      data.deletions.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}`));
      lines.push("");
    }
    if (data.creations) {
      lines.push(`--- File Creation: ${data.creations.count} events ---`);
      data.creations.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}`));
      lines.push("");
    }
    if (data.exfil) {
      lines.push(`--- Data Exfiltration: ${data.exfil.archiveCount} archives ---`);
      data.exfil.archives.slice(0, 50).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}`));
      if (data.exfil.stagingDirectories?.length > 0) {
        lines.push("  Staging Directories:");
        data.exfil.stagingDirectories.forEach((d) => lines.push(`    ${d.directory} (${d.fileCount} files)`));
      }
      lines.push("");
    }
    if (data.execution) {
      lines.push(`--- Execution Artifacts: ${data.execution.count} events ---`);
      data.execution.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
      lines.push("");
    }
    if (data.persistence) {
      lines.push(`--- Persistence Paths: ${data.persistence.count} events ---`);
      if (data.persistence.suppressedCount > 0) {
        const summary = (data.persistence.suppressionSummary || []).map((s) => `${s.label} (${s.count})`).join(", ");
        lines.push(`  Suppressed likely-benign rows: ${data.persistence.suppressedCount}${summary ? ` [${summary}]` : ""}`);
      }
      data.persistence.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
      lines.push("");
    }
    if (data.suspiciousPaths) {
      lines.push(`--- Suspicious Paths: ${data.suspiciousPaths.count} events ---`);
      if (data.suspiciousPaths.suppressedCount > 0) {
        const summary = (data.suspiciousPaths.suppressionSummary || []).map((s) => `${s.label} (${s.count})`).join(", ");
        lines.push(`  Suppressed likely-benign rows: ${data.suspiciousPaths.suppressedCount}${summary ? ` [${summary}]` : ""}`);
      }
      data.suspiciousPaths.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
      lines.push("");
    }
    if (data.securityChanges) {
      lines.push(`--- Security Changes: ${data.securityChanges.count} events ---`);
      if (data.securityChanges.directoryBreakdown?.length > 0) {
        lines.push("  Hotspot Directories:");
        data.securityChanges.directoryBreakdown.slice(0, 20).forEach((d) => lines.push(`    ${d.path} (${d.count} events, ${d.uniqueFiles} unique files)`));
      }
      data.securityChanges.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
      lines.push("");
    }
    if (data.dataOverwrite) {
      lines.push(`--- Data Overwrite: ${data.dataOverwrite.count} events ---`);
      if (data.dataOverwrite.extensionBreakdown?.length > 0) {
        lines.push("  Extension Breakdown:");
        data.dataOverwrite.extensionBreakdown.slice(0, 10).forEach((e) => lines.push(`    ${e.ext} (${e.count})`));
      }
      data.dataOverwrite.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
      lines.push("");
    }
    if (data.streamChanges) {
      lines.push(`--- Stream Changes: ${data.streamChanges.count} events ---`);
      data.streamChanges.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
      lines.push("");
    }
    if (data.closePatterns) {
      lines.push(`--- Close Patterns: ${data.closePatterns.count} events ---`);
      if (data.closePatterns.directoryBreakdown?.length > 0) {
        lines.push("  Enumeration Hotspots:");
        data.closePatterns.directoryBreakdown.slice(0, 10).forEach((d) => lines.push(`    ${d.path} (${d.count})`));
      }
      data.closePatterns.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
      lines.push("");
    }
    navigator.clipboard?.writeText(lines.filter((l) => l !== null).join("\n"));
  };

  // ── Selection helpers ──
  const totalSelected = Object.values(modal.usnSelected || {}).reduce((sum, s) => sum + (s?.size || 0), 0);
  const usnScopeDir = modal.usnScopeDir || "";
  const usnSiblingDir = modal.usnSiblingDir || "";
  const usnFocusEntry = modal.usnFocusEntry ? String(modal.usnFocusEntry) : "";
  const timelineIncidentKey = modal.usnTimelineIncident || "";
  const likelyFindings = data?.likelyFindings || [];
  const parseUsnTsMs = (v) => {
    if (!v) return NaN;
    const normalized = String(v).replace(" ", "T").replace(/(\.\d{3})\d+/, "$1");
    const ms = Date.parse(normalized);
    return Number.isFinite(ms) ? ms : NaN;
  };
  const parentDirOf = (p) => {
    const s = String(p || "").replace(/[\\\/]+$/, "");
    if (!s) return "";
    const idx = Math.max(s.lastIndexOf("\\"), s.lastIndexOf("/"));
    return idx > 0 ? s.slice(0, idx) : "";
  };
  const withinSiblingScope = (path) => {
    if (!usnSiblingDir) return true;
    const parent = parentDirOf(usnSiblingDir);
    const candidate = String(path || "");
    return !!parent && candidate.startsWith(parent) && candidate !== usnSiblingDir;
  };
  const getUsnSectionView = (secKey) => {
    const sData = data?.[secKey];
    if (!sData) return null;
    const count = getUsnSectionCount(secKey, sData);
    const rawEvents = secKey === "exfil" ? (sData.archives || []) : (sData.events || []);
    const canShowSuppressed = (secKey === "persistence" || secKey === "suspiciousPaths") && Number(sData.suppressedCount || 0) > 0;
    const showSuppressed = canShowSuppressed && !!modal.usnShowSuppressed?.[secKey];
    const suppressedEvents = canShowSuppressed
      ? (sData.suppressedEvents || []).map((ev, idx) => ({ ...ev, _suppressed: true, _suppressedKey: `${secKey}:suppressed:${idx}` }))
      : [];
    const sourceEvents = showSuppressed ? [...rawEvents, ...suppressedEvents] : rawEvents;
    const displayedCount = showSuppressed ? sourceEvents.length : count;
    const cols = getColumns(secKey);

    const sort = modal.usnSort?.[secKey];
    let events = sourceEvents;
    if (usnScopeDir) {
      events = events.filter((ev) => (ev.parentPath || "").startsWith(usnScopeDir));
    }
    if (usnSiblingDir) {
      events = events.filter((ev) => withinSiblingScope(ev.parentPath || ""));
    }
    if (usnFocusEntry) {
      events = events.filter((ev) => String(ev.entryNumber || "") === usnFocusEntry);
    }
    if (modal.usnTriageFilter) {
      const tf = modal.usnTriageFilter;
      events = events.filter((ev) => {
        const m = ev._mft;
        if (tf === "deleted") return m?.inUse === "False";
        if (tf === "downloaded") return !!(m?.zoneId && m.zoneId.trim());
        if (tf === "timestomped") return m?.siFn === "True"; // matches the chip count (the primary SI<FN signal; µs0 is a separate marker)
        return true;
      });
    }
    if (sort) {
      const colDef = cols.find((c) => c.key === sort.col);
      if (colDef) {
        events = [...events].sort((a, b) => {
          const va = (colDef.get(a) || "").toString().toLowerCase();
          const vb = (colDef.get(b) || "").toString().toLowerCase();
          return sort.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
        });
      }
    }

    const cbFilters = modal.usnCheckboxFilters?.[secKey];
    let isFiltered = false;
    if (cbFilters) {
      Object.entries(cbFilters).forEach(([colKey, selectedSet]) => {
        if (selectedSet?.size > 0) {
          const colDef = cols.find((c) => c.key === colKey);
          if (colDef) {
            isFiltered = true;
            events = events.filter((ev) => selectedSet.has((colDef.get(ev) || "").toString()));
          }
        }
      });
    }

    return {
      sData,
      count,
      rawEvents,
      canShowSuppressed,
      showSuppressed,
      suppressedEvents,
      sourceEvents,
      displayedCount,
      cols,
      events,
      isFiltered,
    };
  };
  const copySelected = () => {
    if (!data || totalSelected === 0) return;
    const lines = ["=== USN Journal Analysis \u2014 Selected Events ===", ""];
    for (const sec of usnSections) {
      const sel = modal.usnSelected?.[sec.key];
      if (!sel || sel.size === 0) continue;
      const view = getUsnSectionView(sec.key);
      if (!view) continue;
      const visibleRows = view.events.slice(0, 500);
      const selectedRows = visibleRows.filter((_, idx) => sel.has(idx));
      if (selectedRows.length === 0) continue;
      lines.push(`--- ${sec.label} (${selectedRows.length} selected) ---`);
      selectedRows.forEach((ev) => {
        lines.push("  " + view.cols.map((c) => c.get(ev) || "").join("\t"));
      });
      lines.push("");
    }
    navigator.clipboard?.writeText(lines.join("\n"));
  };
  const scopedIncident = timelineIncidentKey ? (data?.directoryIncidents || []).find((d) => d.key === timelineIncidentKey) : null;
  const scopedIncidentStartMs = parseUsnTsMs(scopedIncident?.start);
  const scopedIncidentEndMs = parseUsnTsMs(scopedIncident?.end);
  const filteredTimeline = (data?.timeline || []).filter((ev) => {
    if (scopedIncident) {
      if (ev.parentPath !== scopedIncident.path) return false;
      if (Number.isFinite(scopedIncidentStartMs) && Number.isFinite(scopedIncidentEndMs)) {
        const evMs = parseUsnTsMs(ev.timestamp);
        if (!Number.isFinite(evMs) || evMs < scopedIncidentStartMs || evMs > scopedIncidentEndMs) return false;
      }
    }
    if (usnScopeDir && !(ev.parentPath || "").startsWith(usnScopeDir)) return false;
    if (!withinSiblingScope(ev.parentPath || "")) return false;
    if (usnFocusEntry && String(ev.entryNumber || "") !== usnFocusEntry) return false;
    return true;
  });
  const focusedChain = usnFocusEntry ? (data?.fileChains || []).find((c) => String(c.entryNumber || "") === usnFocusEntry || c.key === usnFocusEntry) : null;
  // Per-FRN lifecycle: one file's whole history consolidated chronologically (events are otherwise
  // scattered across the 11 sections). Built from the timeline (allEvents) filtered to the entry.
  const focusedLifecycle = usnFocusEntry
    ? (data?.timeline || []).filter((ev) => String(ev.entryNumber || "") === usnFocusEntry).slice().sort((a, b) => String(a.timestamp || "").localeCompare(String(b.timestamp || "")))
    : [];
  const visibleIncidents = (data?.directoryIncidents || []).filter((inc) => {
    if (usnScopeDir && inc.path !== usnScopeDir) return false;
    if (!withinSiblingScope(inc.path || "")) return false;
    if (usnFocusEntry) return inc.events?.some((ev) => String(ev.entryNumber || "") === usnFocusEntry);
    return true;
  }).slice(0, 12);
  const timelineRows = filteredTimeline.slice(0, modal.usnTimelineLimit || 120);
  const corrColor = (key) => ({
    downloaded: th.sev.info,
    timestomp: th.accent,
    "deleted-in-mft": "#C44D1E",
    "persistence-related": "#D4783A",
    "executable-or-script": "#E8A050",
    "archive-staging": "#D4956A",
    "acl-change-burst": "#B85C38",
    "overwrite-burst": "#E87848",
    "rename-burst": "#D4783A",
    "stream-activity": "#D4956A",
  }[key] || "#E8A050");
  const tagPill = (tag, color = "#E8A050") => ({ fontSize: 9, padding: "2px 7px", borderRadius: 999, background: `${color}16`, color, border: `1px solid ${color}28`, fontFamily: "-apple-system, sans-serif", fontWeight: 600 });
  const incidentSeverity = (score) => score >= 10 ? { label: "High", color: th.accent } : score >= 6 ? { label: "Medium", color: "#E8A050" } : { label: "Low", color: "#C8A882" };
  const likelyFindingSeverity = (finding) => ({
    critical: { label: "Critical", color: "#C44D1E" },
    high: { label: "High", color: th.accent },
    medium: { label: "Medium", color: "#E8A050" },
    low: { label: "Low", color: "#C8A882" },
  }[finding?.severity] || incidentSeverity(finding?.priorityScore || 0));
  const clearUsnFocus = () => setModal((p) => p ? { ...p, usnScopeDir: "", usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "" } : p);
  const focusUsnDirectory = (dir) => {
    if (!dir) return;
    setModal((p) => p ? { ...p, usnScopeDir: dir, usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "" } : p);
  };
  const focusUsnChain = (entryOrKey, incidentKey = "") => {
    if (!entryOrKey) return;
    setModal((p) => p ? { ...p, usnFocusEntry: String(entryOrKey), usnScopeDir: "", usnSiblingDir: "", usnTimelineIncident: incidentKey || "" } : p);
  };
  const focusUsnIncidentTimeline = (incidentKey) => {
    if (!incidentKey) return;
    setModal((p) => p ? { ...p, usnTimelineIncident: incidentKey, usnScopeDir: "", usnSiblingDir: "", usnFocusEntry: "" } : p);
  };
  const showUsnParentDirectory = (dir) => {
    const parent = parentDirOf(dir);
    if (!parent) return;
    setModal((p) => p ? { ...p, usnScopeDir: parent, usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "" } : p);
  };
  const showUsnSiblingActivity = (dir) => {
    if (!dir) return;
    setModal((p) => p ? { ...p, usnScopeDir: "", usnSiblingDir: dir, usnFocusEntry: "", usnTimelineIncident: "" } : p);
  };
  const copyVisibleUsnIncidentsJson = () => navigator.clipboard?.writeText(JSON.stringify(visibleIncidents, null, 2));
  const hasCorrTag = (tags, key) => Array.isArray(tags) && tags.some((t) => (typeof t === "string" ? t === key : t?.key === key));
  const correlatedMftTabId = data?.correlation?.mftTabId || modal.mftTabId || null;
  const correlatedMftTab = correlatedMftTabId ? tabs.find((t) => t.id === correlatedMftTabId && t.dataReady) : null;
  const adsCapable = correlatedMftTab && (correlatedMftTab.headers?.includes("HasAds") || correlatedMftTab.headers?.includes("ZoneIdContents"));
  const timestompCapable = correlatedMftTab && correlatedMftTab.headers?.includes("SI<FN");
  const ransomwareCapable = correlatedMftTab && correlatedMftTab.headers?.includes("Extension") && correlatedMftTab.headers?.includes("FileName") && correlatedMftTab.headers?.includes("ParentPath") && correlatedMftTab.headers?.includes("LastModified0x10");
  const persistenceTab = tabs.find((t) => t.id !== ct?.id && t.dataReady && (t.headers?.some((h) => /^KeyPath$/i.test(h)) || t.headers?.some((h) => /^EventI[dD]$/i.test(h))));
  const launchAdsFromUsn = () => {
    if (!adsCapable) return;
    setActiveTab(correlatedMftTab.id);
    setModal(openAdsModal());
    tle.analyzeADS(correlatedMftTab.id)
      .then((r) => setModal(updateModal("ads", { loading: false, data: r, error: null, adSelExec: new Set(), adSelZone: new Set(), adSelAds: new Set(), adSortExec: null, adSortZone: null, adSortAds: null })))
      .catch((err) => setModal(updateModal("ads", { loading: false, data: null, error: String(err?.message || err || "ADS analysis failed") })));
  };
  const launchTimestompFromUsn = () => {
    if (!timestompCapable) return;
    setActiveTab(correlatedMftTab.id);
    setModal(openTimestompingModal());
    tle.detectTimestomping(correlatedMftTab.id)
      .then((r) => setModal(updateModal("timestomping", { loading: false, data: r, error: null, tsSelFiles: new Set(), tsSelDirs: new Set(), tsSort: null })))
      .catch((err) => setModal(updateModal("timestomping", { loading: false, data: null, error: String(err?.message || err || "Timestomping analysis failed") })));
  };
  const launchPersistenceFromUsn = () => {
    if (!persistenceTab) return;
    const headers = persistenceTab.headers || [];
    let autoMode = "evtx";
    if (headers.some((h) => /^KeyPath$/i.test(h)) && headers.some((h) => /^ValueName$/i.test(h))) autoMode = "registry";
    else if (headers.some((h) => /^EventI[dD]$/i.test(h))) autoMode = "evtx";
    setActiveTab(persistenceTab.id);
    setModal(openPersistenceModal({ mode: autoMode }));
  };
  const launchRansomwareFromUsn = () => {
    if (!ransomwareCapable) return;
    setActiveTab(correlatedMftTab.id);
    setModal(openRansomwareModal({ usnTabId: ct.id }));
  };

  const renderSection = (sec) => {
    const sectionView = getUsnSectionView(sec.key);
    if (!sectionView) return null;
    const { sData, count, rawEvents, canShowSuppressed, showSuppressed, sourceEvents, displayedCount, cols, events, isFiltered } = sectionView;
    const secStats = data?.sectionStats?.[sec.key] || null;

    // Selection
    const selected = modal.usnSelected?.[sec.key] || new Set();
    const hasVisibleEvents = events.length > 0;
    const isExpanded = hasVisibleEvents ? !!modal.usnExpanded?.[sec.key] : false;
    const visibleCount = Math.min(events.length, 500);
    const allSelected = visibleCount > 0 && selected.size >= visibleCount;
    const toggleRow = (idx) => setModal((p) => {
      if (!p) return p;
      const s = new Set(p.usnSelected?.[sec.key] || []);
      s.has(idx) ? s.delete(idx) : s.add(idx);
      return { ...p, usnSelected: { ...p.usnSelected, [sec.key]: s } };
    });
    const toggleAll = () => setModal((p) => {
      if (!p) return p;
      const s = allSelected ? new Set() : new Set(Array.from({ length: visibleCount }, (_, i) => i));
      return { ...p, usnSelected: { ...p.usnSelected, [sec.key]: s } };
    });

    // Sort handler
    const handleSort = (colKey) => {
      if (cols.find((c) => c.key === colKey)?.noSort) return;
      setModal((p) => {
        if (!p) return p;
        const cur = p.usnSort?.[sec.key];
        const newDir = cur?.col === colKey && cur.dir === "asc" ? "desc" : "asc";
        return { ...p, usnSort: { ...p.usnSort, [sec.key]: { col: colKey, dir: newDir } } };
      });
    };

    // Column resize
    const getW = (colKey, def) => modal.usnColWidths?.[sec.key]?.[colKey] ?? def;
    const startColResize = (e, colKey, startW) => {
      e.preventDefault(); e.stopPropagation();
      const sx = e.clientX;
      const onMove = (ev) => {
        const nw = Math.max(36, startW + (ev.clientX - sx));
        setModal((p) => p ? { ...p, usnColWidths: { ...p.usnColWidths, [sec.key]: { ...(p.usnColWidths?.[sec.key] || {}), [colKey]: nw } } } : p);
      };
      const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
      window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
    };

    // Column style helper — supports custom widths on both fixed and flex columns
    const colStyle = (col, isHeader) => {
      const customW = modal.usnColWidths?.[sec.key]?.[col.key];
      const w = customW || (col.w ? getW(col.key, col.w) : undefined);
      return {
        width: w, flex: w ? undefined : (col.flex || undefined), flexShrink: w ? 0 : undefined,
        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        color: isHeader ? th.textMuted : (col.color || (col.key === "parentPath" || col.key === "timestamp" ? th.textDim : th.text)),
        fontSize: isHeader ? 9 : (col.key === "reasons" ? 9 : 11),
      };
    };

    // Filter dropdown button per column
    const filterBtn = (colKey) => {
      if (cols.find((c) => c.key === colKey)?.noSort) return null;
      const hasFilter = modal.usnCheckboxFilters?.[sec.key]?.[colKey]?.size > 0;
      return (
        <button onClick={(e) => {
          e.stopPropagation();
          // Toggle off if already open for this column
          if (usnFd?.secKey === sec.key && usnFd?.colKey === colKey) {
            setUsnFd(null); return;
          }
          // Precompute unique values once on open
          const colDef = cols.find((c) => c.key === colKey);
          const evts = showSuppressed ? sourceEvents : (rawEvents || []);
          let scopedEvts = evts;
          if (usnScopeDir) {
            scopedEvts = scopedEvts.filter((ev) => (ev.parentPath || "").startsWith(usnScopeDir));
          }
          if (usnSiblingDir) {
            scopedEvts = scopedEvts.filter((ev) => withinSiblingScope(ev.parentPath || ""));
          }
          if (usnFocusEntry) {
            scopedEvts = scopedEvts.filter((ev) => String(ev.entryNumber || "") === usnFocusEntry);
          }
          const valCounts = {};
          (scopedEvts || []).forEach((ev) => { const v = (colDef?.get(ev) || "").toString(); valCounts[v] = (valCounts[v] || 0) + 1; });
          const values = Object.entries(valCounts).map(([val, cnt]) => ({ val, cnt })).sort((a, b) => b.cnt - a.cnt);
          const existing = modal.usnCheckboxFilters?.[sec.key]?.[colKey];
          // Position: center on the column header, not on the button
          const hdrRect = e.currentTarget.parentElement.getBoundingClientRect();
          setUsnFd({ secKey: sec.key, colKey, x: Math.max(8, hdrRect.left - 100), y: hdrRect.bottom + 4, values, search: "", selected: existing ? new Set(existing) : new Set(values.map((v) => v.val)) });
        }}
          style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 3px",
            color: hasFilter ? sec.color : "#b0a8a0", fontSize: 11, flexShrink: 0, lineHeight: 1,
            fontWeight: hasFilter ? 700 : 400, transition: "color var(--m-base)" }}
          title="Filter by values">{"\u25BC"}</button>
      );
    };

    // Glass sub-section style
    const glassSub = { padding: "6px 12px", borderBottom: `1px solid ${th.border}15`, background: `linear-gradient(135deg, ${sec.color}06, transparent)` };
    const pillStyle = { fontSize: 10, padding: "2px 8px", borderRadius: 10, background: `${sec.color}15`, color: sec.color, fontFamily: "'SF Mono',Menlo,monospace", border: `1px solid ${sec.color}18` };

    const secSev = secStats ? incidentSeverity(secStats.priorityScore || 0) : { label: "Info", color: sec.color };
    return (
      <div key={sec.key} style={{ marginBottom: 10, borderRadius: 10, overflow: "hidden", border: `1px solid ${sec.color}18`, background: `linear-gradient(135deg, ${sec.color}04, ${th.modalBg}88)`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", boxShadow: `0 2px 12px ${sec.color}08, 0 0 0 1px rgba(255,255,255,0.02) inset` }}>
        <button onClick={() => toggleExpand(sec.key, hasVisibleEvents)} style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "11px 14px", background: `linear-gradient(135deg, ${sec.color}0a, ${sec.color}04)`, border: "none", borderBottom: isExpanded ? `1px solid ${sec.color}15` : "none", color: th.text, cursor: hasVisibleEvents ? "pointer" : "default", textAlign: "left", fontFamily: "-apple-system, sans-serif", backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)" }}>
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke={sec.color} strokeWidth="1.5" strokeLinecap="round" style={{ transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform var(--m-base) ease", flexShrink: 0, opacity: hasVisibleEvents ? 1 : 0.4 }}><polyline points="3,1 7,5 3,9" /></svg>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={sec.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ filter: `drop-shadow(0 0 3px ${sec.color}44)` }}>{sec.icon}</svg>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <div style={{ fontSize: 12, fontWeight: 600 }}>{sec.label}</div>
              {secStats && <span style={{ ...tagPill(secSev.label, secSev.color), textTransform: "uppercase" }}>{secSev.label}</span>}
              {secStats && <span style={tagPill(`${secStats.eventsPerMinute} evt/min`, "#D4956A")}>{secStats.eventsPerMinute} evt/min</span>}
              {secStats && <span style={tagPill(`${secStats.uniqueFiles} files`, "#E8A050")}>{secStats.uniqueFiles} files</span>}
              {Number(sData.suppressedCount || 0) > 0 && <span style={tagPill(`${sData.suppressedCount} suppressed`, "#C8A882")}>{sData.suppressedCount} suppressed</span>}
              {sData.truncated && <span style={tagPill(`first ${(sData.shown || 0).toLocaleString()} shown`, th.warning)} title="This table is truncated — see True File Activity Volume above for the real total">{"⚠"} first {(sData.shown || 0).toLocaleString()} shown</span>}
            </div>
            {sec.desc && <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 400, marginTop: 1, lineHeight: 1.3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{sec.desc}</div>}
            {secStats && (
              <div style={{ fontSize: 9, color: th.textDim, marginTop: 3, lineHeight: 1.35, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                Top hotspot: {secStats.topDirectory?.path || "(unknown)"} {"\u2022"} {secStats.topDirectory?.count || 0} events {"\u2022"} {secStats.uniqueDirs} dirs
              </div>
            )}
            {Number(sData.suppressedCount || 0) > 0 && (
              <div style={{ fontSize: 9, color: th.textDim, marginTop: 3, lineHeight: 1.35, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                Noise suppressed: {(sData.suppressionSummary || []).slice(0, 2).map((item) => `${item.label} \u00d7${item.count}`).join(", ") || `${sData.suppressedCount} likely-benign rows hidden`}
              </div>
            )}
          </div>
          {canShowSuppressed && (
            <span
              onClick={(e) => {
                e.stopPropagation();
                setModal((p) => {
                  if (!p) return p;
                  const nextShow = !p.usnShowSuppressed?.[sec.key];
                  const nextFilters = { ...(p.usnCheckboxFilters || {}) };
                  if (!nextShow && nextFilters[sec.key]?.suppressionReason) {
                    const secFilters = { ...(nextFilters[sec.key] || {}) };
                    delete secFilters.suppressionReason;
                    nextFilters[sec.key] = secFilters;
                  }
                  return {
                    ...p,
                    usnShowSuppressed: { ...p.usnShowSuppressed, [sec.key]: nextShow },
                    usnExpanded: {
                      ...p.usnExpanded,
                      [sec.key]: nextShow ? true : (count > 0 ? p.usnExpanded?.[sec.key] : false),
                    },
                    usnCheckboxFilters: nextFilters,
                    usnSelected: { ...p.usnSelected, [sec.key]: new Set() },
                  };
                });
                setUsnFd((p) => (p?.secKey === sec.key ? null : p));
              }}
              style={{
                background: showSuppressed ? `${sec.color}22` : `${th.panelBg}aa`,
                border: `1px solid ${showSuppressed ? `${sec.color}44` : `${th.border}33`}`,
                color: showSuppressed ? sec.color : th.textDim,
                cursor: "pointer",
                fontSize: 10,
                fontWeight: 600,
                padding: "5px 9px",
                borderRadius: 8,
                fontFamily: "-apple-system, sans-serif",
                flexShrink: 0,
              }}
              title={showSuppressed ? "Hide likely-benign suppressed rows" : "Reveal suppressed rows for audit"}
            >
              {showSuppressed ? "Hide Suppressed" : "Show Suppressed"}
            </span>
          )}
          {selected.size > 0 && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 8, background: `${th.accent}22`, color: th.accent, fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace" }}>{selected.size} sel</span>}
          <span style={{ fontSize: 10, padding: "2px 10px", borderRadius: 10, background: `linear-gradient(135deg, ${sec.color}28, ${sec.color}18)`, color: sec.color, fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace", border: `1px solid ${sec.color}22`, boxShadow: `0 0 8px ${sec.color}11` }}>{isFiltered ? `${events.length.toLocaleString()} / ${displayedCount.toLocaleString()}` : displayedCount.toLocaleString()}</span>
        </button>
        {isExpanded && (
          <div style={{ maxHeight: 360, overflow: "auto" }}>
            {secStats && (
              <div style={{ ...glassSub, display: "grid", gridTemplateColumns: "1.1fr 0.9fr 0.9fr 1fr", gap: 10, padding: "8px 12px" }}>
                <div>
                  <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>Top Directory</div>
                  <div style={{ fontSize: 10, color: th.text, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{secStats.topDirectory?.path || "(unknown)"}</div>
                </div>
                <div>
                  <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>Burst Rate</div>
                  <div style={{ fontSize: 10, color: th.text }}>{secStats.eventsPerMinute} events/min</div>
                </div>
                <div>
                  <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>Top Reasons</div>
                  <div style={{ fontSize: 10, color: th.text }}>{(secStats.topReasons || []).map((r) => `${r.label}\u00d7${r.count}`).join(", ") || "\u2014"}</div>
                </div>
                <div>
                  <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>Top Ext</div>
                  <div style={{ fontSize: 10, color: th.text }}>{(secStats.topExtensions || []).map((e) => `${e.ext || "(none)"}\u00d7${e.count}`).join(", ") || "\u2014"}</div>
                </div>
              </div>
            )}
            {/* Category-specific sub-sections */}
            {sec.key === "execution" && sData.extensionBreakdown?.length > 0 && (
              <div style={{ ...glassSub, display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 12px" }}>
                {sData.extensionBreakdown.slice(0, 10).map((eb) => (
                  <span key={eb.ext} style={pillStyle}>{eb.ext} ({eb.count})</span>
                ))}
              </div>
            )}
            {sec.key === "persistence" && sData.categories?.length > 0 && (
              <div style={{ ...glassSub, display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 12px" }}>
                {sData.categories.map((c) => (
                  <span key={c.name} style={pillStyle}>{c.name} ({c.count})</span>
                ))}
              </div>
            )}
            {(sec.key === "persistence" || sec.key === "suspiciousPaths") && sData.suppressedCount > 0 && (
              <div style={glassSub}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 4 }}>
                  <div style={{ fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>Noise Suppressed</div>
                  <span style={{ ...pillStyle, background: showSuppressed ? `${sec.color}24` : `${sec.color}15` }}>{showSuppressed ? "Suppressed rows visible" : "Suppressed rows hidden"}</span>
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <span style={pillStyle}>{sData.suppressedCount} likely-benign rows hidden</span>
                  {(sData.suppressionSummary || []).map((item) => (
                    <span key={item.label} style={pillStyle}>{item.label} ({item.count})</span>
                  ))}
                </div>
              </div>
            )}
            {sec.key === "suspiciousPaths" && sData.categories?.length > 0 && (
              <div style={{ ...glassSub, display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 12px" }}>
                {sData.categories.map((c) => (
                  <span key={c.name} style={pillStyle}>{c.name} ({c.count})</span>
                ))}
              </div>
            )}
            {sec.key === "suspiciousPaths" && sData.directoryBreakdown?.length > 0 && (
              <div style={glassSub}>
                {sData.directoryBreakdown.slice(0, 10).map((d, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'SF Mono',Menlo,monospace", color: th.textMuted }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                    <span style={{ flexShrink: 0, marginLeft: 12, color: sec.color, fontWeight: 600 }}>{d.count}</span>
                  </div>
                ))}
              </div>
            )}
            {sec.key === "securityChanges" && sData.directoryBreakdown?.length > 0 && (
              <div style={glassSub}>
                <div style={{ fontSize: 10, fontWeight: 600, color: th.textMuted, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>Hotspot Directories {sData.hotspotCount > 0 && <span style={{ color: sec.color }}>({sData.hotspotCount} with 5+ files)</span>}</div>
                {sData.directoryBreakdown.slice(0, 15).map((d, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'SF Mono',Menlo,monospace", color: d.uniqueFiles >= 5 ? sec.color : th.textMuted }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                    <span style={{ flexShrink: 0, marginLeft: 12, fontWeight: 600 }}>{d.count} events / {d.uniqueFiles} files</span>
                  </div>
                ))}
              </div>
            )}
            {sec.key === "exfil" && sData.stagingDirectories?.length > 0 && (
              <div style={glassSub}>
                <div style={{ fontSize: 10, fontWeight: 600, color: th.textMuted, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>Staging Directories</div>
                {sData.stagingDirectories.map((d, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'SF Mono',Menlo,monospace", color: th.textMuted }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.directory}</span>
                    <span style={{ flexShrink: 0, marginLeft: 12, color: sec.color, fontWeight: 600 }}>{d.fileCount} files</span>
                  </div>
                ))}
              </div>
            )}
            {sec.key === "dataOverwrite" && sData.extensionBreakdown?.length > 0 && (
              <div style={{ ...glassSub, display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 12px" }}>
                {sData.extensionBreakdown.slice(0, 12).map((eb) => (
                  <span key={eb.ext} style={pillStyle}>{eb.ext} ({eb.count})</span>
                ))}
              </div>
            )}
            {sec.key === "dataOverwrite" && sData.directoryBreakdown?.length > 0 && (
              <div style={glassSub}>
                {sData.directoryBreakdown.slice(0, 10).map((d, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'SF Mono',Menlo,monospace", color: th.textMuted }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                    <span style={{ flexShrink: 0, marginLeft: 12, color: sec.color, fontWeight: 600 }}>{d.count}</span>
                  </div>
                ))}
              </div>
            )}
            {sec.key === "streamChanges" && sData.directoryBreakdown?.length > 0 && (
              <div style={glassSub}>
                {sData.directoryBreakdown.slice(0, 10).map((d, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'SF Mono',Menlo,monospace", color: th.textMuted }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                    <span style={{ flexShrink: 0, marginLeft: 12, color: sec.color, fontWeight: 600 }}>{d.count}</span>
                  </div>
                ))}
              </div>
            )}
            {sec.key === "closePatterns" && sData.directoryBreakdown?.length > 0 && (
              <div style={glassSub}>
                <div style={{ fontSize: 10, fontWeight: 600, color: th.textMuted, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>Enumeration Hotspots {sData.hotspotCount > 0 && <span style={{ color: sec.color }}>({sData.hotspotCount} with 10+ events)</span>}</div>
                {sData.directoryBreakdown.slice(0, 15).map((d, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'SF Mono',Menlo,monospace", color: d.count >= 10 ? sec.color : th.textMuted }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                    <span style={{ flexShrink: 0, marginLeft: 12, fontWeight: 600 }}>{d.count}</span>
                  </div>
                ))}
              </div>
            )}
            {/* Column header — opaque sticky */}
            <div style={{ display: "flex", alignItems: "center", gap: 0, padding: "0 10px", fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", borderBottom: `1px solid ${th.border}30`, fontFamily: "-apple-system, sans-serif", background: th.modalBg || th.panelBg, position: "sticky", top: 0, zIndex: 2 }}>
              {/* Select-all checkbox */}
              <div onClick={toggleAll} style={{ width: 26, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", padding: "6px 0", cursor: "pointer" }}>
                <div style={{ width: 12, height: 12, borderRadius: 3, background: allSelected ? sec.color : "transparent", border: `1.5px solid ${allSelected ? sec.color : th.border}66`, display: "flex", alignItems: "center", justifyContent: "center", transition: "all var(--m-base)" }}>
                  {allSelected && <svg width="7" height="7" viewBox="0 0 8 8" fill="none" stroke="#fff" strokeWidth="1.5"><polyline points="1.5,4 3.5,6 6.5,2" /></svg>}
                </div>
              </div>
              {cols.map((col, ci) => (
                <div key={col.key} style={{ ...colStyle(col, true), display: "flex", alignItems: "center", padding: "6px 4px", cursor: col.noSort ? "default" : "pointer", position: "relative", userSelect: "none" }} onClick={() => handleSort(col.key)}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{col.label}</span>
                  <span style={{ flexShrink: 0, marginLeft: "auto" }}>{filterBtn(col.key)}</span>
                  {/* Resize handle — all columns except noResize and last column */}
                  {!col.noResize && ci < cols.length - 1 && (
                    <div onMouseDown={(e) => { const rect = e.currentTarget.parentElement.getBoundingClientRect(); startColResize(e, col.key, modal.usnColWidths?.[sec.key]?.[col.key] || (col.w ? getW(col.key, col.w) : Math.round(rect.width))); }} onClick={(e) => e.stopPropagation()}
                      style={{ position: "absolute", right: -2, top: 2, bottom: 2, width: 5, cursor: "col-resize", borderRight: `1px solid ${th.border}22` }}
                      onMouseEnter={(e) => { e.currentTarget.style.borderRight = `2px solid ${sec.color}66`; }}
                      onMouseLeave={(e) => { e.currentTarget.style.borderRight = `1px solid ${th.border}22`; }} />
                  )}
                </div>
              ))}
            </div>
            {/* Event rows */}
            {events.slice(0, 500).map((ev, i) => {
              const isSelected = selected.has(i);
              return (
                <div key={i} onClick={() => toggleRow(i)} style={{
                  display: "flex", alignItems: "center", gap: 0, padding: "0 10px", fontSize: 11, cursor: "pointer",
                  fontFamily: "'SF Mono',Menlo,monospace", borderBottom: `1px solid ${th.border}0c`,
                  background: isSelected ? `${sec.color}12` : (ev._suppressed ? `${th.warning}0d` : (i % 2 === 0 ? "transparent" : `${th.border}08`)),
                  opacity: ev._suppressed ? 0.86 : 1,
                  transition: "background var(--m-fast)",
                }}
                  onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = ev._suppressed ? `${th.warning}14` : `${sec.color}0a`; }}
                  onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = ev._suppressed ? `${th.warning}0d` : (i % 2 === 0 ? "transparent" : `${th.border}08`); }}
                >
                  <div style={{ width: 26, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", padding: "4px 0" }}>
                    <div style={{ width: 12, height: 12, borderRadius: 3, background: isSelected ? sec.color : "transparent", border: `1.5px solid ${isSelected ? sec.color : th.border}55`, display: "flex", alignItems: "center", justifyContent: "center", transition: "all var(--m-fast)" }}>
                      {isSelected && <svg width="7" height="7" viewBox="0 0 8 8" fill="none" stroke="#fff" strokeWidth="1.5"><polyline points="1.5,4 3.5,6 6.5,2" /></svg>}
                    </div>
                  </div>
                  {cols.map((col) => {
                    const val = col.get(ev) || "";
                    if (col.key === "_mftStatus" && val && val !== "\u2014") {
                      const badges = val.split("|");
                      const badgeColors = { EX: th.sev.info, FB: "#C8A882", DEL: "#C44D1E", TS: th.accent, "\u00b5s0": "#C8A882", DL: "#D4956A", OK: "#E8A050" };
                      // $SI-vs-$FN timestamp triangulation, surfaced on hover for timestomp-flagged rows.
                      const m = ev._mft;
                      const tsTip = (m && (m.siFn === "True" || m.uSecZeros === "True"))
                        ? `$SI created ${(m.created || "?").slice(0, 19)} | $FN created ${(m.created30 || "?").slice(0, 19)}\n$SI modified ${(m.modified10 || "?").slice(0, 19)} | $FN modified ${(m.modified30 || "?").slice(0, 19)}${m.uSecZeros === "True" ? "\n(sub-second timestamps are zero \u2014 \u00b5s0)" : ""}`
                        : undefined;
                      return (
                        <span key={col.key} title={tsTip} style={{ ...colStyle(col, false), padding: "4px 4px", display: "flex", gap: 3, alignItems: "center" }}>
                          {badges.map((b) => <span key={b} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 4, background: `${badgeColors[b] || th.textMuted}22`, color: badgeColors[b] || th.textMuted, fontWeight: 700, letterSpacing: "0.03em", border: `1px solid ${badgeColors[b] || th.textMuted}33` }}>{b}</span>)}
                        </span>
                      );
                    }
                    return <span key={col.key} style={{ ...colStyle(col, false), padding: "4px 4px" }}>{val}</span>;
                  })}
                </div>
              );
            })}
            {events.length === 0 && <div style={{ padding: "14px 14px", fontSize: 11, color: th.textMuted, fontStyle: "italic" }}>No events found</div>}
          </div>
        )}
      </div>
    );
  };

  return (
    <DraggableResizableModal
      key={phase}
      defaultWidth={phase === "results" ? 960 : 560}
      defaultHeight={phase === "results" ? Math.round(window.innerHeight * 0.88) : 540}
      minWidth={480}
      minHeight={300}
      onClose={() => setModal(null)}
    >
      {({ startDrag }) => (<>
        {/* Header */}
        <div onMouseDown={startDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, border: `1px solid ${th.accent}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round"><rect x="3" y="3" width="18" height="18" rx="2" fill={(th.accent) + "18"}/><path d="M7 7h10M7 11h10M7 15h6"/></svg>
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>USN Journal Analysis</h3>
              <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>Analyze file system activity within a time window</p>
            </div>
          </div>
          <button onClick={() => setModal(null)} style={{ background: `${th.border}22`, border: `1px solid ${th.border}33`, color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "4px 8px", borderRadius: 6, lineHeight: 1 }}>{"\u2715"}</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
          {usnResolveStats && (
            <div style={{ marginBottom: 14, padding: "12px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${usnResolveTone.color}12, ${th.modalBg}88)`, border: `1px solid ${usnResolveTone.color}2a`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
                <div>
                  <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Path Resolution</div>
                  <div style={{ fontSize: 12, color: th.text, fontWeight: 700 }}>{usnResolveTone.label}</div>
                </div>
                <span style={{ ...tagPill(`${Number(usnResolveStats.resolvedPercent || 0)}% resolved`, usnResolveTone.color), textTransform: "uppercase" }}>{Number(usnResolveStats.resolvedPercent || 0)}% resolved</span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 8, marginBottom: 8 }}>
                {[
                  { label: "Resolved", value: `${(usnResolveStats.resolved || 0).toLocaleString()} / ${(usnResolveStats.total || 0).toLocaleString()}` },
                  { label: "USN-only", value: (usnResolveStats.selfResolved || 0).toLocaleString() },
                  { label: "MFT-assisted", value: (usnResolveStats.mftResolved || 0).toLocaleString() },
                  { label: "Unresolved", value: (usnResolveStats.unresolved || 0).toLocaleString() },
                ].map((item) => (
                  <div key={item.label} style={{ padding: "8px 10px", borderRadius: 8, background: `${th.panelBg}88`, border: `1px solid ${th.border}18` }}>
                    <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>{item.label}</div>
                    <div style={{ fontSize: 12, color: th.text, fontWeight: 700, fontFamily: "'SF Mono',Menlo,monospace" }}>{item.value}</div>
                  </div>
                ))}
              </div>
              <div style={{ fontSize: 10, color: th.textDim, lineHeight: 1.45 }}>
                Directory incidents, path filters, and parent/sibling pivots rely on `ParentPath`. Unresolved rows stay visible in broad counts, but they may be absent from path-scoped views until enough directory history or MFT context is available.
              </div>
            </div>
          )}
          {/* Input phase */}
          {phase === "input" && (<>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 14 }}>
              <div style={ms.fg}>
                <label style={ms.lb}>Start Time (UTC) — optional</label>
                <input type="text" value={modal.startTime} onChange={(e) => setModal((p) => ({ ...p, startTime: e.target.value }))} placeholder="Blank = full journal" style={{ ...ms.ip, fontFamily: "'SF Mono',Menlo,monospace" }} autoFocus />
                <div style={{ fontSize: 9, color: th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif" }}>Leave blank to analyze the whole journal and see where activity is, then narrow.</div>
              </div>
              <div style={ms.fg}>
                <label style={ms.lb}>End Time (UTC) — optional</label>
                <input type="text" value={modal.endTime} onChange={(e) => setModal((p) => ({ ...p, endTime: e.target.value }))} placeholder="YYYY-MM-DD HH:MM:SS" style={{ ...ms.ip, fontFamily: "'SF Mono',Menlo,monospace" }} />
              </div>
            </div>
            <div style={ms.fg}>
              <label style={ms.lb}>Path Filter (optional)</label>
              <input value={modal.pathFilter} onChange={(e) => setModal((p) => ({ ...p, pathFilter: e.target.value }))} placeholder="e.g. \\Users\\admin" style={ms.ip} />
            </div>
            {/* MFT cross-correlation selector */}
            {(() => {
              const mftTabs = tabs.filter((t) => t.dataReady && t.sourceFormat === "raw-mft" && t.id !== ct?.id);
              if (mftTabs.length === 0) return null;
              return (
                <div style={{ ...ms.fg, marginTop: 8 }}>
                  <label style={ms.lb}>Correlate with MFT (optional)</label>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <select value={modal.mftTabId || ""} onChange={(e) => setModal((p) => ({ ...p, mftTabId: e.target.value || null }))}
                      style={{ ...ms.ip, flex: 1, cursor: "pointer", appearance: "none", backgroundImage: `url("data:image/svg+xml,%3Csvg width='10' height='6' viewBox='0 0 10 6' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%23888' stroke-width='1.5' stroke-linecap='round'/%3E%3C/svg%3E")`, backgroundRepeat: "no-repeat", backgroundPosition: "right 10px center", paddingRight: 28 }}>
                      <option value="">None — USN-only analysis</option>
                      {mftTabs.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                    </select>
                    {modal.mftTabId && (
                      <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "4px 8px", background: "#E8A05015", border: "1px solid #E8A05033", borderRadius: 6 }}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#E8A050" strokeWidth="2" strokeLinecap="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                        <span style={{ fontSize: 10, color: "#E8A050", fontWeight: 600 }}>Linked</span>
                      </div>
                    )}
                  </div>
                  <div style={{ fontSize: 9, color: th.textMuted, marginTop: 3 }}>Enrich USN events with MFT metadata: file size, deletion status, timestomping, Zone.Identifier</div>
                </div>
              );
            })()}
            <div style={{ marginTop: 14 }}>
              <label style={ms.lb}>Analyses to Run</label>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, marginTop: 4 }}>
                {usnSections.map((sec) => (
                  <button key={sec.key} onClick={() => toggleAnalysis(sec.key)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 10px", background: modal.analyses[sec.key] ? `${sec.color}12` : "transparent", border: `1px solid ${modal.analyses[sec.key] ? sec.color + "44" : th.border + "44"}`, borderRadius: 6, color: th.text, cursor: "pointer", fontSize: 11, fontFamily: "-apple-system, sans-serif", textAlign: "left", transition: "all var(--m-base)" }}>
                    <div style={{ width: 14, height: 14, borderRadius: 4, flexShrink: 0, background: modal.analyses[sec.key] ? sec.color : "transparent", border: `1.5px solid ${modal.analyses[sec.key] ? sec.color : th.border}`, display: "flex", alignItems: "center", justifyContent: "center", transition: "all var(--m-base)" }}>
                      {modal.analyses[sec.key] && <svg width="8" height="8" viewBox="0 0 8 8" fill="none" stroke="#fff" strokeWidth="1.5"><polyline points="1.5,4 3.5,6 6.5,2" /></svg>}
                    </div>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={sec.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">{sec.icon}</svg>
                    {sec.label}
                  </button>
                ))}
              </div>
            </div>
            {error && <div style={{ marginTop: 10, padding: "8px 12px", background: `${th.danger}15`, border: `1px solid ${th.danger}33`, borderRadius: 6, color: th.danger, fontSize: 11 }}>{error}</div>}
          </>)}

          {/* Loading phase */}
          {phase === "loading" && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 0", gap: 16 }}>
              <div style={{ width: 40, height: 40, border: `3px solid ${th.border}33`, borderTopColor: th.accent, borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
              <span style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>Analyzing USN Journal...</span>
            </div>
          )}

          {/* Results phase */}
          {phase === "results" && data && (<>
            {/* Summary — glass cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
              {[
                { label: "Total Events", value: (data.summary?.totalEvents || 0).toLocaleString(), accent: th.accent },
                { label: "Start Time", value: (data.summary?.startTime || "").slice(0, 19), accent: "#E8A050" },
                { label: "End Time", value: (!data.summary?.endTime || data.summary.endTime.startsWith("9999")) ? "Open-ended" : data.summary.endTime.slice(0, 19), accent: "#D4783A" },
                { label: "Path Filter", value: data.summary?.pathFilter || "All paths", accent: "#C96B3C" },
              ].map((s) => (
                <div key={s.label} style={{ padding: "10px 12px", background: `linear-gradient(135deg, ${s.accent}0a, ${th.modalBg}66)`, border: `1px solid ${s.accent}1a`, borderRadius: 10, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", boxShadow: `0 2px 8px ${s.accent}08, 0 0 0 1px rgba(255,255,255,0.02) inset` }}>
                  <div style={{ fontSize: 9, color: `${s.accent}bb`, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif", marginBottom: 3 }}>{s.label}</div>
                  <div style={{ fontSize: 13, color: th.text, fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.value}</div>
                </div>
              ))}
            </div>

            {/* Journal Coverage & Integrity — "what am I looking at, and can I trust it?" */}
            {data.summary?.coverage && (
              <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 12, background: `linear-gradient(135deg, #5a8dee12, ${th.modalBg}88)`, border: "1px solid #5a8dee2a", backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                  <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Journal Coverage &amp; Integrity</div>
                  {data.summary.coverage.windowCoversJournal
                    ? <span style={tagPill("Full journal analyzed", th.success)}>Full journal analyzed</span>
                    : <span style={tagPill("Window is a subset", "#E8A050")}>Analysis window is a subset of the journal</span>}
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
                  {[
                    { l: "Journal span", v: `${(data.summary.coverage.journalStart || "").slice(0, 19) || "—"}  →  ${(data.summary.coverage.journalEnd || "").slice(0, 19) || "—"}` },
                    { l: "Records (journal / window)", v: `${(data.summary.coverage.journalTotalEvents || 0).toLocaleString()} / ${(data.summary.coverage.windowEventCount || 0).toLocaleString()}` },
                    { l: "USN range", v: `${data.summary.coverage.usnMin != null ? Number(data.summary.coverage.usnMin).toLocaleString() : "—"} – ${data.summary.coverage.usnMax != null ? Number(data.summary.coverage.usnMax).toLocaleString() : "—"}` },
                    { l: "Integrity", v: data.summary.coverage.possibleGaps ? "Possible gaps (trimmed/wrapped)" : "Contiguous", warn: data.summary.coverage.possibleGaps },
                  ].map((c) => (
                    <div key={c.l}>
                      <div style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2, fontFamily: "-apple-system, sans-serif" }}>{c.l}</div>
                      <div style={{ fontSize: 11, color: c.warn ? th.warning : th.text, fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.v}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TRUE File Activity Volume — full-window aggregate, independent of the truncated tables below */}
            {data.summary?.volume && (data.summary.volume.destructiveTotal > 0 || data.summary.volume.create > 0 || data.summary.volume.streamChange > 0 || data.summary.volume.securityChange > 0 || data.summary.volume.systemDriven > 0) && (
              <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${th.danger}10, ${th.modalBg}88)`, border: `1px solid ${th.danger}22` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                  <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>True File Activity Volume</div>
                  <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>full-window counts, system/replication churn excluded {"—"} independent of the truncated tables below</span>
                  {data.summary.volume.peakDestructivePerMinute >= 100 && <span style={tagPill(`peak ${data.summary.volume.peakDestructivePerMinute.toLocaleString()}/min`, th.danger)}>{"▲"} peak {data.summary.volume.peakDestructivePerMinute.toLocaleString()}/min</span>}
                </div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {[
                    ["Overwrite", data.summary.volume.overwrite, "#E87848"],
                    ["Truncate", data.summary.volume.truncate, "#C44D1E"],
                    ["Delete", data.summary.volume.delete, "#C44D1E"],
                    ["Rename", data.summary.volume.rename, "#D4783A"],
                    ["Create", data.summary.volume.create, "#E8A050"],
                    ["Stream/ADS", data.summary.volume.streamChange, "#D4956A"],
                    ["Security", data.summary.volume.securityChange, "#B85C38"],
                    ["System-driven", data.summary.volume.systemDriven, th.textMuted],
                  ].filter(([, n]) => Number(n) > 0).map(([lbl, n, c]) => (
                    <span key={lbl} style={{ padding: "3px 9px", borderRadius: 8, background: `${c}18`, border: `1px solid ${c}33`, color: c, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>{lbl}: <strong style={{ fontFamily: "'SF Mono',Menlo,monospace" }}>{Number(n).toLocaleString()}</strong></span>
                  ))}
                </div>
              </div>
            )}
            {/* Activity Timeline histogram — canonical first-look + window picker (click a bar to zoom) */}
            {data.summary?.histogram?.buckets?.length > 0 && (() => {
              const hb = data.summary.histogram.buckets;
              const gran = data.summary.histogram.granularity;
              const maxTotal = hb.reduce((m, b) => Math.max(m, b.total || 0), 0);
              const many = hb.length > 100;
              const pickBucket = (bucket) => {
                let start = bucket, end = bucket;
                if (gran === "day") { start = `${bucket} 00:00:00`; end = `${bucket} 23:59:59`; }
                else if (gran === "hour") { start = `${bucket}:00:00`; end = `${bucket}:59:59`; }
                else { start = `${bucket}:00`; end = `${bucket}:59`; }
                setModal((p) => p?.type === "usnAnalysis" ? { ...p, startTime: start, endTime: end, phase: "input" } : p);
              };
              return (
                <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${th.accent}0a, ${th.modalBg}88)`, border: `1px solid ${th.border}33` }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
                    <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Activity Timeline (per {gran})</div>
                    <div style={{ fontSize: 9, color: th.textMuted, display: "flex", gap: 10, fontFamily: "-apple-system, sans-serif" }}>
                      <span><span style={{ color: th.danger }}>{"■"}</span> destructive</span>
                      <span><span style={{ color: "#E8A050" }}>{"■"}</span> created</span>
                      <span><span style={{ color: th.textMuted }}>{"■"}</span> other</span>
                      <span style={{ opacity: 0.7 }}>· dim = off-hours · click a bar to zoom</span>
                    </div>
                  </div>
                  <div style={{ display: "flex", alignItems: "flex-end", gap: 1, height: 84, overflowX: many ? "auto" : "visible" }}>
                    {hb.map((b) => {
                      const t = b.total || 0;
                      const h = maxTotal > 0 ? Math.max(2, Math.round((t / maxTotal) * 80)) : 2;
                      const dH = t > 0 ? Math.min(h, Math.round(((b.destructive || 0) / t) * h)) : 0;
                      const cH = t > 0 ? Math.min(Math.max(0, h - dH), Math.round(((b.created || 0) / t) * h)) : 0;
                      const oH = Math.max(0, h - dH - cH);
                      const hr = (gran !== "day" && (b.bucket || "").length >= 13) ? parseInt(b.bucket.slice(11, 13), 10) : null;
                      const offHours = hr != null && (hr < 8 || hr >= 18);
                      return (
                        <div key={b.bucket} onClick={() => pickBucket(b.bucket)} title={`${b.bucket}\n${t.toLocaleString()} events · ${(b.destructive || 0).toLocaleString()} destructive · ${(b.created || 0).toLocaleString()} created`}
                          style={{ flex: many ? "0 0 5px" : 1, minWidth: many ? 5 : 0, display: "flex", flexDirection: "column", justifyContent: "flex-end", cursor: "pointer", opacity: offHours ? 0.6 : 1 }}>
                          <div style={{ height: oH, background: `${th.textMuted}66` }} />
                          <div style={{ height: cH, background: "#E8A050" }} />
                          <div style={{ height: dH, background: th.danger }} />
                        </div>
                      );
                    })}
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4, fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>
                    <span>{hb[0]?.bucket}</span>
                    <span>{hb[hb.length - 1]?.bucket}</span>
                  </div>
                </div>
              );
            })()}

            {/* Breakdowns — reason families / top extensions / top directories by churn */}
            {data.summary?.volume && (() => {
              const vol = data.summary.volume || {};
              const reasonRows = [
                ["Create", vol.create, "#E8A050"], ["Delete", vol.delete, "#C44D1E"],
                ["Overwrite", vol.overwrite, "#E87848"], ["Truncate", vol.truncate, "#C44D1E"],
                ["Rename", vol.rename, "#D4783A"], ["Stream/ADS", vol.streamChange, "#D4956A"],
                ["Security", vol.securityChange, "#B85C38"], ["System", vol.systemDriven, th.textMuted],
              ].filter(([, n]) => (n || 0) > 0).sort((a, b) => (b[1] || 0) - (a[1] || 0));
              const exts = data.summary.breakdowns?.extensions || [];
              const dirs = data.summary.breakdowns?.directories || [];
              if (reasonRows.length === 0 && exts.length === 0 && dirs.length === 0) return null;
              const reasonMax = Math.max(1, ...reasonRows.map((r) => r[1] || 0));
              const extMax = Math.max(1, ...exts.map((e) => e.count || 0));
              const dirMax = Math.max(1, ...dirs.map((d) => d.count || 0));
              const barRow = (key, label, count, frac, color, sub) => (
                <div key={key} style={{ marginBottom: 4 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 6, fontSize: 9, marginBottom: 1 }}>
                    <span style={{ color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={label}>{label}</span>
                    <span style={{ color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", flexShrink: 0 }}>{Number(count).toLocaleString()}{sub || ""}</span>
                  </div>
                  <div style={{ height: 5, borderRadius: 3, background: `${th.textMuted}22` }}>
                    <div style={{ height: "100%", borderRadius: 3, width: `${Math.max(2, frac * 100)}%`, background: color }} />
                  </div>
                </div>
              );
              return (
                <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${th.accent}0a, ${th.modalBg}88)`, border: `1px solid ${th.border}33` }}>
                  <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700, marginBottom: 8 }}>Breakdowns</div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1.4fr", gap: 16 }}>
                    <div>
                      <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700, marginBottom: 6 }}>Reason families</div>
                      {reasonRows.map(([l, n, c]) => barRow(`r:${l}`, l, n, (n || 0) / reasonMax, c))}
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700, marginBottom: 6 }}>Top extensions</div>
                      {exts.length ? exts.map((e, i) => barRow(`e:${e.ext}:${i}`, e.ext || "(none)", e.count, (e.count || 0) / extMax, e.destructive > 0 ? "#C44D1E" : th.accent, e.destructive > 0 ? ` · ${e.destructive} dstr` : "")) : <div style={{ fontSize: 9, color: th.textMuted }}>no extension data</div>}
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700, marginBottom: 6 }}>Top directories by churn</div>
                      {dirs.length ? dirs.map((d, i) => barRow(`d:${d.path}:${i}`, d.path || "(unknown)", d.count, (d.count || 0) / dirMax, d.destructive > 0 ? "#C44D1E" : "#D4783A", ` · ${Number(d.entries || 0).toLocaleString()} files`)) : <div style={{ fontSize: 9, color: th.textMuted }}>no directory data</div>}
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* MFT Record Reuse — covert delete + replace (entry+sequence reuse) */}
            {data.fileReuse?.length > 0 && (
              <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 12, background: `linear-gradient(135deg, #B85C3810, ${th.modalBg}88)`, border: "1px solid #B85C3833" }}>
                <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700, marginBottom: 8 }}>MFT Record Reuse — covert delete + replace ({data.fileReuse.length})</div>
                <div style={{ display: "grid", gap: 6 }}>
                  {data.fileReuse.slice(0, 8).map((r) => (
                    <div key={r.entry} style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", display: "flex", gap: 8, alignItems: "baseline" }}>
                      <span style={{ fontFamily: "'SF Mono',Menlo,monospace", color: th.textMuted, flexShrink: 0 }}>#{r.entry}</span>
                      {r.hasExecutable && <span style={tagPill("exe", th.danger)}>exe</span>}
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{(r.generations || []).map((g) => g.name).filter(Boolean).join("  →  ") || r.summary}</span>
                    </div>
                  ))}
                  {data.fileReuse.length > 8 && <div style={{ fontSize: 9, color: th.textMuted }}>+{data.fileReuse.length - 8} more</div>}
                </div>
              </div>
            )}

            {/* Masquerading — disguised executable/archive payloads */}
            {data.masquerade?.length > 0 && (
              <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${th.danger}10, ${th.modalBg}88)`, border: `1px solid ${th.danger}33` }}>
                <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700, marginBottom: 8 }}>Masqueraded Payloads ({data.masquerade.length})</div>
                <div style={{ display: "grid", gap: 6 }}>
                  {data.masquerade.slice(0, 8).map((m, i) => (
                    <div key={`${m.parent}\\${m.name}:${i}`} style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", display: "flex", gap: 8, alignItems: "baseline", minWidth: 0 }}>
                      {(m.reasons || []).map((r) => <span key={r} style={tagPill(r, th.danger)}>{r}</span>)}
                      <span style={{ fontFamily: "'SF Mono',Menlo,monospace", color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.name}</span>
                      <span style={{ color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }}>{m.parent}</span>
                    </div>
                  ))}
                  {data.masquerade.length > 8 && <div style={{ fontSize: 9, color: th.textMuted }}>+{data.masquerade.length - 8} more</div>}
                </div>
              </div>
            )}

            {/* Self-deleting executables (drop + cleanup) */}
            {data.selfDeleted?.length > 0 && (
              <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${th.danger}10, ${th.modalBg}88)`, border: `1px solid ${th.danger}33` }}>
                <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700, marginBottom: 8 }}>Self-Deleting Executables ({data.selfDeleted.length})</div>
                <div style={{ display: "grid", gap: 6 }}>
                  {data.selfDeleted.slice(0, 8).map((s, i) => (
                    <div key={`${s.entry}:${s.seq}:${i}`} style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", display: "flex", gap: 8, alignItems: "baseline", minWidth: 0 }}>
                      {s.immediate && <span style={tagPill("immediate", th.danger)}>immediate</span>}
                      <span style={{ fontFamily: "'SF Mono',Menlo,monospace", color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.name}</span>
                      <span style={{ color: th.textMuted, flexShrink: 0 }}>{s.lifetimeMin != null ? `lived ${s.lifetimeMin}m` : ""}</span>
                      <span style={{ color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }}>{s.parent}</span>
                    </div>
                  ))}
                  {data.selfDeleted.length > 8 && <div style={{ fontSize: 9, color: th.textMuted }}>+{data.selfDeleted.length - 8} more</div>}
                </div>
              </div>
            )}

            {/* Mark-of-the-Web stripping (Zone.Identifier removed) */}
            {data.motwStripped?.length > 0 && (
              <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 12, background: `linear-gradient(135deg, #B85C3810, ${th.modalBg}88)`, border: "1px solid #B85C3833" }}>
                <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700, marginBottom: 8 }}>ADS / Stream Removal on Payloads ({data.motwStripped.length})</div>
                <div style={{ display: "grid", gap: 6 }}>
                  {data.motwStripped.slice(0, 8).map((m, i) => (
                    <div key={`${m.parent}\\${m.file}:${i}`} style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", display: "flex", gap: 8, alignItems: "baseline", minWidth: 0 }}>
                      <span style={tagPill(m.isZoneId ? "Zone.Id removed" : "stream removed", "#B85C38")}>{m.isZoneId ? "Zone.Id removed" : "stream removed"}</span>
                      <span style={{ fontFamily: "'SF Mono',Menlo,monospace", color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.file}</span>
                      <span style={{ color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }}>{m.parent}</span>
                    </div>
                  ))}
                  {data.motwStripped.length > 8 && <div style={{ fontSize: 9, color: th.textMuted }}>+{data.motwStripped.length - 8} more</div>}
                </div>
              </div>
            )}

            {/* MFT Correlation Summary */}
            {data.correlation && (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10, marginBottom: 16 }}>
                {[
                  { label: "MFT Matched", value: data.correlation.matched.toLocaleString(), accent: "#E8A050", sub: `${data.correlation.exactMatched || 0} exact / ${data.correlation.fallbackMatched || 0} entry-only of ${data.correlation.totalUsnEntries.toLocaleString()} file refs` },
                  { label: "Unmatched", value: data.correlation.unmatched.toLocaleString(), accent: th.textMuted, sub: "not in MFT" },
                  { label: "Deleted Files", value: data.correlation.deleted.toLocaleString(), accent: "#C44D1E", sub: "InUse = False" },
                  { label: "Timestomped", value: data.correlation.timestomped.toLocaleString(), accent: th.accent, sub: `SI<FN · +${(data.correlation.timestompedUSec ?? 0).toLocaleString()} µs-zero` },
                  { label: "Downloaded", value: data.correlation.downloaded.toLocaleString(), accent: "#D4956A", sub: "Zone.Identifier" },
                ].map((s) => (
                  <div key={s.label} style={{ padding: "10px 12px", background: `linear-gradient(135deg, ${s.accent}0a, ${th.modalBg}66)`, border: `1px solid ${s.accent}1a`, borderRadius: 10, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", boxShadow: `0 2px 8px ${s.accent}08, 0 0 0 1px rgba(255,255,255,0.02) inset` }}>
                    <div style={{ fontSize: 9, color: `${s.accent}bb`, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif", marginBottom: 3 }}>{s.label}</div>
                    <div style={{ fontSize: 15, color: th.text, fontWeight: 700, fontFamily: "'SF Mono',Menlo,monospace" }}>{s.value}</div>
                    <div style={{ fontSize: 8, color: th.textMuted, marginTop: 1 }}>{s.sub}</div>
                  </div>
                ))}
              </div>
            )}
            {(data.narrative?.length > 0 || usnScopeDir || usnSiblingDir || usnFocusEntry || timelineIncidentKey) && (
              <div style={{ marginBottom: 16, padding: "12px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${th.accent}10, ${th.modalBg}88)`, border: `1px solid ${(th.accent)}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                  <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Investigator Summary</div>
                  {(usnScopeDir || usnSiblingDir || usnFocusEntry || timelineIncidentKey) && <button onClick={clearUsnFocus} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Clear Focus</button>}
                </div>
                <div style={{ display: "grid", gap: 5 }}>
                  {(data.narrative || []).map((line, i) => <div key={i} style={{ fontSize: 12, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{"\u2022"} {line}</div>)}
                </div>
                {(usnScopeDir || usnSiblingDir || usnFocusEntry || timelineIncidentKey) && (
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
                    {usnScopeDir && <span style={tagPill(`Directory: ${usnScopeDir}`, "#C96B3C")}>Directory: {usnScopeDir}</span>}
                    {usnSiblingDir && <span style={tagPill(`Siblings of: ${usnSiblingDir}`, "#D4956A")}>Siblings of: {usnSiblingDir}</span>}
                    {usnFocusEntry && <span style={tagPill(`Entry: ${usnFocusEntry}`, "#E8A050")}>Entry: {usnFocusEntry}</span>}
                    {timelineIncidentKey && <span style={tagPill("Timeline scoped to incident", "#D4783A")}>Timeline scoped to incident</span>}
                  </div>
                )}
                {data.correlationSummary?.length > 0 && (
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
                    {data.correlationSummary.slice(0, 6).map((c) => <span key={c.key} style={tagPill(`${c.label} \u00d7${c.count}`, corrColor(c.key))}>{c.label} {"\u00d7"}{c.count}</span>)}
                  </div>
                )}
              </div>
            )}
            {likelyFindings.length > 0 && (
              <div style={{ marginBottom: 16, borderRadius: 12, background: `linear-gradient(135deg, ${(th.danger)}0c, ${th.modalBg}88)`, border: `1px solid ${(th.danger)}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", overflow: "hidden" }}>
                <button
                  onClick={() => setModal((p) => p ? { ...p, usnLikelyFindingsExpanded: !p.usnLikelyFindingsExpanded } : p)}
                  style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, width: "100%", padding: "12px 14px", background: "transparent", border: "none", color: th.text, cursor: "pointer", textAlign: "left" }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ transform: modal.usnLikelyFindingsExpanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform var(--m-base) ease", flexShrink: 0 }}><polyline points="3,1 7,5 3,9" /></svg>
                    <div>
                      <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Likely Intrusion Findings</div>
                      <div style={{ fontSize: 10, color: th.textDim }}>{likelyFindings.length} ranked starting points built from the strongest USN incidents and file chains</div>
                    </div>
                  </div>
                  <span style={tagPill(`${likelyFindings.length}`, th.danger)}>{likelyFindings.length}</span>
                </button>
                {modal.usnLikelyFindingsExpanded && (
                  <div style={{ display: "grid", gap: 10, padding: "0 14px 12px" }}>
                    {likelyFindings.map((finding) => {
                      const sev = likelyFindingSeverity(finding);
                      const findingPath = finding.path || finding.primaryPath || "";
                      const isIncident = finding.sourceType === "directoryIncident";
                      const typeLabel = isIncident ? "Directory Incident"
                        : finding.sourceType === "fileChain" ? "File Chain"
                        : finding.sourceType === "volume" ? "Volume"
                        : finding.sourceType === "fileReuse" ? "MFT Reuse"
                        : finding.sourceType === "masquerade" ? "Masquerade"
                        : finding.sourceType === "selfDelete" ? "Self-Delete"
                        : finding.sourceType === "motwStrip" ? "MOTW Strip"
                        : "Finding";
                      return (
                        <div key={finding.key} style={{ border: `1px solid ${sev.color}28`, borderRadius: 10, padding: "10px 12px", background: `linear-gradient(135deg, ${sev.color}0c, transparent)` }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
                            <span style={{ ...tagPill(sev.label, sev.color), textTransform: "uppercase" }}>{sev.label}</span>
                            <span style={tagPill(typeLabel, "#D4956A")}>{typeLabel}</span>
                            <span style={{ fontSize: 13, color: th.text, fontWeight: 700 }}>{finding.title}</span>
                            <span style={{ ...tagPill(`Score ${finding.priorityScore || 0}`, "#E8A050") }}>Score {finding.priorityScore || 0}</span>
                          </div>
                          <div style={{ fontSize: 11, color: th.text, marginBottom: 6, lineHeight: 1.45 }}>{finding.summary}</div>
                          <div style={{ fontSize: 10, color: th.textDim, marginBottom: 8, lineHeight: 1.45 }}>{finding.rationale}</div>
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                            {(finding.evidence || []).map((item) => <span key={item} style={tagPill(item, sev.color)}>{item}</span>)}
                            {(finding.correlationTags || []).slice(0, 4).map((t) => <span key={t.key} style={tagPill(t.label, corrColor(t.key))}>{t.label}</span>)}
                          </div>
                          <div style={{ display: "grid", gridTemplateColumns: "1.4fr 0.8fr", gap: 8, marginBottom: 8 }}>
                            <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{findingPath || "(path unresolved)"}</div>
                            <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", textAlign: "right" }}>{(finding.start || "").slice(0, 19)}{finding.end ? ` \u2192 ${(finding.end || "").slice(0, 19)}` : ""}</div>
                          </div>
                          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                            {isIncident ? (
                              <>
                                <button onClick={() => focusUsnIncidentTimeline(finding.sourceKey)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Incident Timeline</button>
                                <button onClick={() => focusUsnDirectory(finding.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!finding.path}>This Directory</button>
                                <button onClick={() => focusUsnChain(finding.entryNumber)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!finding.entryNumber}>File Chain</button>
                              </>
                            ) : (
                              <>
                                <button onClick={() => focusUsnChain(finding.entryNumber || finding.sourceKey)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!finding.entryNumber && !finding.sourceKey}>Open File Chain</button>
                                <button onClick={() => focusUsnDirectory(finding.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!finding.path}>This Directory</button>
                                <button onClick={() => showUsnParentDirectory(finding.path || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(finding.path || "")}>Parent Directory</button>
                                <button onClick={() => showUsnSiblingActivity(finding.path || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(finding.path || "")}>Sibling Activity</button>
                              </>
                            )}
                            <button onClick={() => navigator.clipboard?.writeText(JSON.stringify(finding, null, 2))} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Copy JSON</button>
                            {hasCorrTag(finding.correlationTags, "downloaded") && adsCapable && <button onClick={launchAdsFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open ADS</button>}
                            {hasCorrTag(finding.correlationTags, "timestomp") && timestompCapable && <button onClick={launchTimestompFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Timestomp</button>}
                            {hasCorrTag(finding.correlationTags, "persistence-related") && persistenceTab && <button onClick={launchPersistenceFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Persistence</button>}
                            {(hasCorrTag(finding.correlationTags, "archive-staging") || hasCorrTag(finding.correlationTags, "overwrite-burst") || hasCorrTag(finding.correlationTags, "deleted-in-mft")) && ransomwareCapable && <button onClick={launchRansomwareFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Ransomware</button>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {visibleIncidents.length > 0 && (
              <div style={{ marginBottom: 16, borderRadius: 12, background: `${th.panelBg}aa`, border: `1px solid ${th.border}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", overflow: "hidden" }}>
                <button
                  onClick={() => setModal((p) => p ? { ...p, usnIncidentsExpanded: !p.usnIncidentsExpanded } : p)}
                  style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, width: "100%", padding: "12px 14px", background: "transparent", border: "none", color: th.text, cursor: "pointer", textAlign: "left" }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ transform: modal.usnIncidentsExpanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform var(--m-base) ease", flexShrink: 0 }}><polyline points="3,1 7,5 3,9" /></svg>
                    <div>
                      <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Directory Incidents</div>
                      <div style={{ fontSize: 10, color: th.textDim }}>{visibleIncidents.length} clustered hotspots across the selected window</div>
                    </div>
                  </div>
                  <span style={tagPill(`${visibleIncidents.length}`, "#D4956A")}>{visibleIncidents.length}</span>
                </button>
                {modal.usnIncidentsExpanded && (
                  <div style={{ display: "grid", gap: 10, padding: "0 14px 12px" }}>
                    {visibleIncidents.map((inc) => {
                      const sev = incidentSeverity(inc.priorityScore || inc.riskScore || 0);
                      return (
                        <div key={inc.key} style={{ border: `1px solid ${sev.color}28`, borderRadius: 10, padding: "10px 12px", background: `linear-gradient(135deg, ${sev.color}0c, transparent)` }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
                            <span style={{ ...tagPill(sev.label, sev.color), textTransform: "uppercase" }}>{sev.label}</span>
                            <span style={{ fontSize: 13, color: th.text, fontWeight: 700 }}>{inc.title}</span>
                            <span style={{ ...tagPill(`${inc.eventCount} events / ${inc.uniqueFiles} files`, "#E8A050") }}>{inc.eventCount} events / {inc.uniqueFiles} files</span>
                            <span style={{ color: th.textDim, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>{inc.start?.slice(0, 19)} {"\u2192"} {inc.end?.slice(0, 19)}</span>
                          </div>
                          <div style={{ fontSize: 11, color: th.textDim, marginBottom: 8, fontFamily: "'SF Mono',Menlo,monospace" }}>{inc.path}</div>
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                            {(inc.reasons || []).slice(0, 4).map((r) => <span key={r} style={tagPill(r, sev.color)}>{r}</span>)}
                            {(inc.topExtensions || []).slice(0, 3).map((e) => <span key={e.ext} style={tagPill(`${e.ext || "(none)"} \u00d7${e.count}`, "#D4956A")}>{e.ext || "(none)"} {"\u00d7"}{e.count}</span>)}
                            {(inc.correlationTags || []).slice(0, 4).map((t) => <span key={t.key} style={tagPill(t.label, corrColor(t.key))}>{t.label}</span>)}
                          </div>
                          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                            <button onClick={() => focusUsnDirectory(inc.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Show Only This Directory</button>
                            <button onClick={() => focusUsnIncidentTimeline(inc.key)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Show All Events in Timeline</button>
                            <button onClick={() => {
                              const firstEntry = inc.events?.find((ev) => ev.entryNumber)?.entryNumber || "";
                              focusUsnChain(firstEntry);
                            }} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!inc.events?.some((ev) => ev.entryNumber)}>Show File Chain</button>
                            <button onClick={() => showUsnParentDirectory(inc.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(inc.path)}>Show Parent Directory</button>
                            <button onClick={() => showUsnSiblingActivity(inc.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(inc.path)}>Show Sibling Activity</button>
                            <button onClick={() => navigator.clipboard?.writeText(JSON.stringify(inc, null, 2))} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Copy JSON</button>
                            {hasCorrTag(inc.correlationTags, "downloaded") && adsCapable && <button onClick={launchAdsFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open ADS</button>}
                            {hasCorrTag(inc.correlationTags, "timestomp") && timestompCapable && <button onClick={launchTimestompFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Timestomp</button>}
                            {hasCorrTag(inc.correlationTags, "persistence-related") && persistenceTab && <button onClick={launchPersistenceFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Persistence</button>}
                            {(hasCorrTag(inc.correlationTags, "archive-staging") || hasCorrTag(inc.correlationTags, "overwrite-burst") || hasCorrTag(inc.correlationTags, "deleted-in-mft")) && ransomwareCapable && <button onClick={launchRansomwareFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Ransomware</button>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {focusedChain && (
              <div style={{ marginBottom: 16, padding: "12px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${(th.warning)}0f, ${th.modalBg}88)`, border: `1px solid ${(th.warning)}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                  <div>
                    <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Per-File Reconstruction</div>
                    <div style={{ fontSize: 13, color: th.text, fontWeight: 700 }}>{focusedChain.title}</div>
                  </div>
                  <button onClick={() => setModal((p) => p ? { ...p, usnFocusEntry: "" } : p)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Close</button>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 10 }}>
                  {[
                    { label: "Entry", value: focusedChain.entryNumber || "\u2014" },
                    { label: "First Seen", value: focusedChain.firstSeen?.slice(0, 19) || "\u2014" },
                    { label: "Last Seen", value: focusedChain.lastSeen?.slice(0, 19) || "\u2014" },
                    { label: "Events", value: String(focusedChain.eventCount || 0) },
                  ].map((s) => (
                    <div key={s.label} style={{ padding: "8px 10px", borderRadius: 8, background: `${th.panelBg}88`, border: `1px solid ${th.border}18` }}>
                      <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>{s.label}</div>
                      <div style={{ fontSize: 12, color: th.text, fontWeight: 700, fontFamily: "'SF Mono',Menlo,monospace" }}>{s.value}</div>
                    </div>
                  ))}
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr 1fr 1fr", gap: 10, marginBottom: 10 }}>
                  {[
                    { label: "Primary Directory", value: focusedChain.primaryDirectory || "\u2014" },
                    { label: "Path Variants", value: String(focusedChain.pathTransitions?.length || focusedChain.paths?.length || 0) },
                    { label: "Same-Dir Artifacts", value: String(focusedChain.sameDirectoryChainCount || 0) },
                    { label: "Primary Path", value: focusedChain.primaryPath || "\u2014" },
                  ].map((s) => (
                    <div key={s.label} style={{ padding: "8px 10px", borderRadius: 8, background: `${th.panelBg}88`, border: `1px solid ${th.border}18` }}>
                      <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>{s.label}</div>
                      <div style={{ fontSize: 11, color: th.text, fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.value}</div>
                    </div>
                  ))}
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
                  {(focusedChain.reasonBuckets || []).map((r) => <span key={r} style={tagPill(r, "#E8A050")}>{r}</span>)}
                  {(focusedChain.correlationTags || []).map((t) => <span key={t.key} style={tagPill(t.label, corrColor(t.key))}>{t.label}</span>)}
                  {(focusedChain.categories || []).map((c) => <span key={c} style={tagPill(c, "#D4783A")}>{c}</span>)}
                </div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
                  <button onClick={() => focusUsnDirectory(focusedChain.primaryDirectory || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!focusedChain.primaryDirectory}>This Directory</button>
                  <button onClick={() => showUsnParentDirectory(focusedChain.primaryDirectory || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(focusedChain.primaryDirectory || "")}>Parent Directory</button>
                  <button onClick={() => showUsnSiblingActivity(focusedChain.primaryDirectory || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(focusedChain.primaryDirectory || "")}>Sibling Activity</button>
                  <button onClick={() => navigator.clipboard?.writeText(JSON.stringify(focusedChain, null, 2))} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Copy JSON</button>
                  {hasCorrTag(focusedChain.correlationTags, "downloaded") && adsCapable && <button onClick={launchAdsFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open ADS</button>}
                  {hasCorrTag(focusedChain.correlationTags, "timestomp") && timestompCapable && <button onClick={launchTimestompFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Timestomp</button>}
                  {hasCorrTag(focusedChain.correlationTags, "persistence-related") && persistenceTab && <button onClick={launchPersistenceFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Persistence</button>}
                  {(hasCorrTag(focusedChain.correlationTags, "archive-staging") || hasCorrTag(focusedChain.correlationTags, "overwrite-burst") || hasCorrTag(focusedChain.correlationTags, "deleted-in-mft")) && ransomwareCapable && <button onClick={launchRansomwareFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Ransomware</button>}
                </div>
                {focusedChain.renamePairs?.length > 0 && (
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Rename Chain</div>
                    <div style={{ display: "grid", gap: 4 }}>
                      {focusedChain.renamePairs.slice(0, 20).map((r, i) => (
                        <div key={i} style={{ fontSize: 11, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{r.timestamp?.slice(0, 19)} {"\u2014"} {r.oldName} {"\u2192"} {r.newName}</div>
                      ))}
                    </div>
                  </div>
                )}
                {focusedChain.siblingArtifacts?.length > 0 && (
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Other High-Signal Artifacts In This Directory</div>
                    <div style={{ display: "grid", gap: 4 }}>
                      {focusedChain.siblingArtifacts.map((sib) => (
                        <button key={sib.key} onClick={() => setModal((p) => p ? { ...p, usnFocusEntry: sib.key, usnScopeDir: "", usnSiblingDir: "", usnTimelineIncident: "" } : p)} style={{ background: `${th.border}10`, border: `1px solid ${th.border}18`, borderRadius: 8, padding: "6px 8px", cursor: "pointer", color: th.text, textAlign: "left", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, fontSize: 11 }}>{sib.title}</span>
                          <span style={{ ...tagPill(`${sib.eventCount} ev`, "#D4956A"), flexShrink: 0 }}>{sib.eventCount} ev</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Event Sequence</div>
                <div style={{ display: "grid", gap: 4, maxHeight: 220, overflow: "auto" }}>
                  {(focusedChain.events || []).slice(0, 150).map((ev, i) => (
                    <div key={i} style={{ display: "grid", gridTemplateColumns: "160px 120px 1fr", gap: 8, fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace", color: th.text }}>
                      <span style={{ color: th.textDim }}>{ev.timestamp?.slice(0, 19)}</span>
                      <span style={{ color: "#E8A050" }}>{ev.reasonLabel}</span>
                      <span>{ev.displayName || ev.name}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {timelineRows.length > 0 && (
              <div style={{ marginBottom: 16, borderRadius: 12, background: `${th.panelBg}aa`, border: `1px solid ${th.border}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", overflow: "hidden" }}>
                <div style={{ display: "flex", alignItems: "stretch", justifyContent: "space-between", gap: 10, padding: "12px 14px" }}>
                  <button
                    onClick={() => setModal((p) => p ? { ...p, usnTimelineExpanded: !p.usnTimelineExpanded } : p)}
                    style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0, background: "transparent", border: "none", color: th.text, cursor: "pointer", textAlign: "left", padding: 0 }}
                  >
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ transform: modal.usnTimelineExpanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform var(--m-base) ease", flexShrink: 0 }}><polyline points="3,1 7,5 3,9" /></svg>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Merged USN Storyline</div>
                      <div style={{ fontSize: 10, color: th.textDim }}>{timelineRows.length.toLocaleString()} of {filteredTimeline.length.toLocaleString()} suspicious events shown</div>
                    </div>
                  </button>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                    <span style={tagPill(`${filteredTimeline.length}`, "#D4956A")}>{filteredTimeline.length}</span>
                    {modal.usnTimelineExpanded && filteredTimeline.length > timelineRows.length && <button onClick={() => setModal((p) => p ? { ...p, usnTimelineLimit: (p.usnTimelineLimit || 120) + 120 } : p)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Load More</button>}
                  </div>
                </div>
                {modal.usnTimelineExpanded && (
                  <div style={{ display: "grid", gap: 4, maxHeight: 280, overflow: "auto", padding: "0 14px 12px" }}>
                    {timelineRows.map((ev) => (
                      <div key={ev.key} style={{ display: "grid", gridTemplateColumns: "145px 125px 1fr 190px auto auto", gap: 8, alignItems: "center", padding: "6px 8px", borderRadius: 8, border: `1px solid ${th.border}12`, background: `${th.border}08`, color: th.text }}>
                        <span style={{ fontSize: 11, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace" }}>{ev.timestamp?.slice(0, 19)}</span>
                        <span style={{ fontSize: 10, color: "#E8A050", fontWeight: 700 }}>{ev.reasonLabel}</span>
                        <button onClick={() => setModal((p) => p ? { ...p, usnFocusEntry: String(ev.entryNumber || ""), usnScopeDir: "", usnSiblingDir: "", usnTimelineIncident: timelineIncidentKey } : p)} style={{ background: "none", border: "none", color: th.text, cursor: "pointer", textAlign: "left", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", padding: 0 }}>{ev.displayName || ev.name}</button>
                        <span style={{ fontSize: 10, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'SF Mono',Menlo,monospace" }}>{ev.parentPath}</span>
                        <span style={{ display: "flex", gap: 4, flexWrap: "wrap", justifyContent: "flex-end" }}>
                          {(ev.correlationTags || []).slice(0, 3).map((t) => <span key={t.key} style={tagPill(t.label, corrColor(t.key))}>{t.label}</span>)}
                        </span>
                        <span style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                          <button onClick={() => setModal((p) => p ? { ...p, usnFocusEntry: String(ev.entryNumber || ""), usnScopeDir: "", usnSiblingDir: "", usnTimelineIncident: timelineIncidentKey } : p)} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>File Chain</button>
                          <button onClick={() => setModal((p) => p ? { ...p, usnScopeDir: ev.parentPath || "", usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "" } : p)} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }} disabled={!ev.parentPath}>This Dir</button>
                          <button onClick={() => showUsnParentDirectory(ev.parentPath || "")} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }} disabled={!parentDirOf(ev.parentPath || "")}>Parent</button>
                          <button onClick={() => showUsnSiblingActivity(ev.parentPath || "")} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }} disabled={!parentDirOf(ev.parentPath || "")}>Siblings</button>
                          {hasCorrTag(ev.correlationTags, "downloaded") && adsCapable && <button onClick={launchAdsFromUsn} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>ADS</button>}
                          {hasCorrTag(ev.correlationTags, "timestomp") && timestompCapable && <button onClick={launchTimestompFromUsn} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>Timestomp</button>}
                          {hasCorrTag(ev.correlationTags, "persistence-related") && persistenceTab && <button onClick={launchPersistenceFromUsn} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>Persistence</button>}
                          {(hasCorrTag(ev.correlationTags, "archive-staging") || hasCorrTag(ev.correlationTags, "overwrite-burst") || hasCorrTag(ev.correlationTags, "deleted-in-mft")) && ransomwareCapable && <button onClick={launchRansomwareFromUsn} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>Ransomware</button>}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {/* Per-FRN file lifecycle — one file's whole history in chronological order */}
            {usnFocusEntry && focusedLifecycle.length > 0 && (
              <div style={{ marginBottom: 16, padding: "10px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${th.accent}0e, ${th.modalBg}88)`, border: `1px solid ${th.accent}33` }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                  <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>File Lifecycle — MFT entry {usnFocusEntry} ({focusedLifecycle.length} event{focusedLifecycle.length === 1 ? "" : "s"})</div>
                  <button onClick={clearUsnFocus} style={{ ...ms.bs, padding: "3px 8px", fontSize: 9 }}>Clear Focus</button>
                </div>
                <div style={{ display: "grid", gap: 3, maxHeight: 240, overflow: "auto" }}>
                  {focusedLifecycle.slice(0, 200).map((ev, i) => (
                    <div key={ev.key || i} style={{ display: "flex", gap: 8, alignItems: "baseline", fontSize: 10, fontFamily: "-apple-system, sans-serif", paddingLeft: 8, paddingBottom: 1 }}>
                      <span style={{ color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", fontSize: 9, flexShrink: 0, width: 132 }}>{(ev.timestamp || "").slice(0, 19)}</span>
                      <span style={{ color: th.accent, flexShrink: 0, minWidth: 92, fontWeight: 600 }}>{ev.reasonLabel || "Activity"}</span>
                      <span style={{ color: th.text, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 240 }}>{ev.displayName || ev.name || ""}</span>
                      <span style={{ color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }}>{ev.parentPath || ""}</span>
                    </div>
                  ))}
                  {focusedLifecycle.length > 200 && <div style={{ fontSize: 9, color: th.textMuted, paddingLeft: 8 }}>+{focusedLifecycle.length - 200} more events</div>}
                </div>
              </div>
            )}

            {/* Triage quick-filters — pre-filtered views over the MFT-correlated signals (filters all sections) */}
            {data.correlation && (
              <div style={{ marginBottom: 10, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                <span style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700 }}>Triage filter:</span>
                {[
                  { key: "deleted", label: "Deleted", count: data.correlation.deleted, color: "#C44D1E" },
                  { key: "downloaded", label: "Downloaded", count: data.correlation.downloaded, color: "#D4956A" },
                  { key: "timestomped", label: "Timestomped", count: data.correlation.timestomped, color: th.accent },
                ].map((chip) => {
                  const active = modal.usnTriageFilter === chip.key;
                  return (
                    <button key={chip.key} onClick={() => setModal((p) => p?.type === "usnAnalysis" ? { ...p, usnTriageFilter: active ? "" : chip.key } : p)}
                      style={{ padding: "3px 10px", borderRadius: 999, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system, sans-serif", background: active ? chip.color : `${chip.color}14`, color: active ? "#fff" : chip.color, border: `1px solid ${chip.color}${active ? "" : "44"}`, fontWeight: active ? 700 : 500 }}>
                      {chip.label} ({Number(chip.count || 0).toLocaleString()})
                    </button>
                  );
                })}
                {modal.usnTriageFilter && <button onClick={() => setModal((p) => p?.type === "usnAnalysis" ? { ...p, usnTriageFilter: "" } : p)} style={{ ...ms.bs, padding: "3px 8px", fontSize: 9 }}>Clear</button>}
                {modal.usnTriageFilter && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Showing only {modal.usnTriageFilter} files across all sections below</span>}
              </div>
            )}

            {/* Analysis sections */}
            {usnSections.map((sec) => renderSection(sec))}

            {/* Column filter dropdown panel — uses separate state (usnFd) to avoid re-rendering all sections */}
            {usnFd && (() => {
              const fd = usnFd;
              const fdSec = usnSections.find((s) => s.key === fd.secKey);
              if (!fd.values) return null;

              const fdSearch = fd.search || "";
              const fdValues = fdSearch
                ? fd.values.filter((v) => (v.val || "").toLowerCase().includes(fdSearch.toLowerCase()))
                : fd.values;
              const fdSelected = fd.selected || new Set(fd.values.map((v) => v.val));
              const fdLeft = fd.dx ?? Math.min(fd.x, window.innerWidth - 360);
              const fdTop = fd.dy ?? Math.min(fd.y, window.innerHeight - 400);
              // Cap rendered items; the rest are still in fdValues for Select All / count
              const RENDER_CAP = 200;
              const fdVisible = fdValues.slice(0, RENDER_CAP);

              return (
                <>
                  <div onClick={() => setUsnFd(null)} style={{ position: "fixed", inset: 0, zIndex: 199 }} />
                  <div ref={(el) => { if (el) el.__usnFdPanel = true; }} onClick={(e) => e.stopPropagation()} style={{
                    WebkitAppRegion: "no-drag", position: "fixed",
                    left: fdLeft, top: fdTop,
                    width: 340, height: 380, minWidth: 240, minHeight: 180, maxWidth: "90vw", maxHeight: "90vh",
                    background: th.modalBg, border: `1px solid ${fdSec?.color || th.accent}33`,
                    borderRadius: 10, boxShadow: `0 12px 28px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.03) inset`,
                    zIndex: 200, display: "flex", flexDirection: "column", overflow: "hidden", resize: "both",
                    backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)"
                  }}>
                    {/* Draggable header — uses direct DOM transform for zero-lag dragging */}
                    <div style={{ padding: "6px 10px", flexShrink: 0, display: "flex", alignItems: "center", gap: 6, borderBottom: `1px solid ${th.border}30`, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${fdSec?.color || th.accent}0a, transparent)` }}
                      onMouseDown={(e) => {
                        if (e.button !== 0) return;
                        e.preventDefault();
                        const panel = e.currentTarget.parentElement;
                        const startX = e.clientX, startY = e.clientY;
                        const startLeft = panel.offsetLeft, startTop = panel.offsetTop;
                        const onMove = (ev) => {
                          const nx = startLeft + (ev.clientX - startX);
                          const ny = startTop + (ev.clientY - startY);
                          panel.style.left = nx + "px";
                          panel.style.top = ny + "px";
                        };
                        const onUp = (ev) => {
                          document.removeEventListener("mousemove", onMove);
                          document.removeEventListener("mouseup", onUp);
                          // Persist final position to state
                          const nx = startLeft + (ev.clientX - startX);
                          const ny = startTop + (ev.clientY - startY);
                          setUsnFd((p) => p ? { ...p, dx: nx, dy: ny } : p);
                        };
                        document.addEventListener("mousemove", onMove);
                        document.addEventListener("mouseup", onUp);
                      }}>
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={fdSec?.color || th.accent} strokeWidth="1.8" strokeLinecap="round"><polygon points="22,3 2,3 10,12.46 10,19 14,21 14,12.46"/></svg>
                      <span style={{ color: th.textDim, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif", flex: 1 }}>Filter {"\u2014"} {(getColumns(fd.secKey).find((c) => c.key === fd.colKey)?.label) || fd.colKey}</span>
                      <button onClick={() => setUsnFd(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, padding: "0 2px", lineHeight: 1 }}>{"\u2715"}</button>
                    </div>
                    {/* Search input */}
                    <div style={{ padding: "8px 8px 4px", flexShrink: 0 }}>
                      <input value={fdSearch} onChange={(e) => setUsnFd((p) => p ? { ...p, search: e.target.value } : p)}
                        placeholder="Search values..." autoFocus
                        style={{ width: "100%", background: th.bgInput || `${th.border}22`, border: `1px solid ${th.border}66`, borderRadius: 6, color: th.text, fontSize: 11, padding: "5px 8px", outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} />
                    </div>
                    {/* Select All / Clear */}
                    <div style={{ display: "flex", gap: 4, padding: "2px 8px 4px", flexShrink: 0, alignItems: "center" }}>
                      <button onClick={() => setUsnFd((p) => p ? { ...p, selected: new Set(fdValues.map((v) => v.val)) } : p)}
                        style={{ padding: "2px 7px", background: "none", border: `1px solid ${th.border}44`, borderRadius: 4, color: th.textDim, fontSize: 9, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Select All</button>
                      <button onClick={() => setUsnFd((p) => p ? { ...p, selected: new Set() } : p)}
                        style={{ padding: "2px 7px", background: "none", border: `1px solid ${th.border}44`, borderRadius: 4, color: th.textDim, fontSize: 9, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Clear</button>
                      <span style={{ flex: 1 }} />
                      <span style={{ color: th.textMuted, fontSize: 9 }}>{fdValues.length} values</span>
                    </div>
                    {/* Checkbox list — capped at {RENDER_CAP} for performance */}
                    <div style={{ flex: 1, overflow: "auto", padding: "0 4px" }}>
                      {fdValues.length === 0 ? (
                        <div style={{ padding: 16, textAlign: "center", color: th.textMuted, fontSize: 11 }}>No values found</div>
                      ) : (<>
                        {fdVisible.map((v) => (
                          <label key={v.val ?? "__empty"} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 6px", cursor: "pointer", borderRadius: 4, fontSize: 11, color: th.text }}
                            onMouseEnter={(e) => { e.currentTarget.style.background = `${fdSec?.color || th.accent}0a`; }}
                            onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                            <input type="checkbox" checked={fdSelected.has(v.val)}
                              onChange={() => {
                                const s = new Set(fdSelected);
                                s.has(v.val) ? s.delete(v.val) : s.add(v.val);
                                setUsnFd((p) => p ? { ...p, selected: s } : p);
                              }}
                              style={{ accentColor: fdSec?.color || th.accent, flexShrink: 0 }} />
                            <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'SF Mono',Menlo,monospace", fontSize: 10 }}>{v.val || "(empty)"}</span>
                            <span style={{ color: th.textMuted, fontSize: 9, flexShrink: 0 }}>{v.cnt.toLocaleString()}</span>
                          </label>
                        ))}
                        {fdValues.length > RENDER_CAP && (
                          <div style={{ padding: "6px 6px", fontSize: 9, color: th.textMuted, textAlign: "center", fontStyle: "italic" }}>
                            Showing top {RENDER_CAP} of {fdValues.length} {"\u2014"} use search to narrow
                          </div>
                        )}
                      </>)}
                    </div>
                    {/* Footer buttons */}
                    <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, padding: "6px 8px", borderTop: `1px solid ${th.border}22` }}>
                      <button onClick={() => {
                        // Reset — remove this column's filter
                        setModal((p) => {
                          if (!p) return p;
                          const newF = { ...(p.usnCheckboxFilters || {}) };
                          const secF = { ...(newF[fd.secKey] || {}) };
                          delete secF[fd.colKey];
                          newF[fd.secKey] = secF;
                          return { ...p, usnCheckboxFilters: newF };
                        });
                        setUsnFd(null);
                      }} style={{ padding: "3px 10px", background: "none", border: `1px solid ${th.border}44`, borderRadius: 6, color: th.textDim, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Reset</button>
                      <button onClick={() => setUsnFd(null)} style={{ padding: "3px 10px", background: "none", border: `1px solid ${th.border}44`, borderRadius: 6, color: th.textDim, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Cancel</button>
                      <button onClick={() => {
                        // Apply — save selected values as filter, then close
                        const selSet = usnFd?.selected;
                        const totalUniqueCount = usnFd?.values?.length || 0;
                        setModal((p) => {
                          if (!p) return p;
                          const newF = { ...(p.usnCheckboxFilters || {}) };
                          if (!selSet || selSet.size === 0 || selSet.size >= totalUniqueCount) {
                            const secF = { ...(newF[fd.secKey] || {}) };
                            delete secF[fd.colKey];
                            newF[fd.secKey] = secF;
                          } else {
                            newF[fd.secKey] = { ...(newF[fd.secKey] || {}), [fd.colKey]: selSet };
                          }
                          return { ...p, usnCheckboxFilters: newF, usnSelected: { ...p.usnSelected, [fd.secKey]: new Set() } };
                        });
                        setUsnFd(null);
                      }} style={{ padding: "3px 12px", background: fdSec?.color || th.accent, color: "#fff", border: "none", borderRadius: 6, fontSize: 10, cursor: "pointer", fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Apply</button>
                    </div>
                  </div>
                </>
              );
            })()}
          </>)}
        </div>

        {/* Footer — glass bar */}
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}18`, display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 8, flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}aa, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)" }}>
          {phase === "input" && (<>
            <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
            <button onClick={handleAnalyze} disabled={!Object.values(modal.analyses).some(Boolean)} style={{ ...ms.bp, opacity: !Object.values(modal.analyses).some(Boolean) ? 0.5 : 1 }}>Analyze</button>
          </>)}
          {phase === "loading" && <span style={{ fontSize: 11, color: th.textMuted }}>Running queries...</span>}
          {phase === "results" && (<>
            {totalSelected > 0 && <span style={{ fontSize: 10, color: th.accent, fontFamily: "'SF Mono',Menlo,monospace", marginRight: "auto" }}>{totalSelected} selected</span>}
            <button onClick={() => { setModal((p) => ({ ...p, phase: "input", data: null, usnSelected: {}, usnSort: {}, usnCheckboxFilters: {}, usnLikelyFindingsExpanded: false, usnShowSuppressed: {}, usnScopeDir: "", usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "", usnTimelineLimit: 120 })); setUsnFd(null); }} style={ms.bs}>Back</button>
            {totalSelected > 0 && <button onClick={copySelected} style={{ ...ms.bs, borderColor: `${th.accent}44`, color: th.accent }}>Copy Selected ({totalSelected})</button>}
            {visibleIncidents.length > 0 && <button onClick={copyVisibleUsnIncidentsJson} style={ms.bs}>Copy Incidents JSON</button>}
            <button onClick={copyReport} style={ms.bs}>Copy Summary</button>
            <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
          </>)}
        </div>
      </>)}
    </DraggableResizableModal>
  );
}
