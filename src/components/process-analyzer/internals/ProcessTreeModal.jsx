import { useState, useRef, useEffect, useCallback } from "react";
import useUIStore from "../../../store/useUIStore.js";
import useTabStore from "../../../store/useTabStore.js";
import { toast } from "../../../store/useToastStore.js";
import useCurrentTab from "../../../hooks/useCurrentTab.js";
import useTheme from "../../../hooks/useTheme.js";
import { _integrityShort, _providerShort, _ptFormatDuration, PI_ALL_RULES, PI_TECHNIQUE_GROUPS } from "../../../utils/process-inspector.js";
import { analyzeCommandLine, tokenizeCommandLine } from "../../../utils/cmdline-decode.js";
import {
  buildByKeyMap,
  buildChildMap,
  buildPrevalenceSummary,
  buildSequenceMap,
  buildChainClusters,
  buildNodeClusterMap,
  buildIncidentStories,
  buildNodeStoryMap,
  consistentParentKey,
  makeDetMapRuleKey,
  customRuleErrors,
  validateCustomRulePattern,
  validateCustomRule,
} from "../../../utils/process-inspector-pipeline.js";
import { scoreProcessTree } from "../../../utils/process-tree-scoring.js";
import { PI_GRID_PIVOT_WINDOWS, detectTimestampColumn, detectHostnameColumn } from "../../../utils/process-grid-pivot.js";
import { buildProcessHandoff, publicVtUrlForHash, vtCategoryForHash } from "../../../utils/process-handoffs.js";
import { normalizeTimestamp, normalizeHost } from "../../../utils/forensic-normalize.js";
import { clearIpcSubscription, replaceIpcSubscription } from "../../../utils/ipc-subscriptions.js";
import { isIpcError, ipcErrorMessage } from "../../../utils/ipc-result.js";
import { processInspectorPaletteFor } from "../../../constants/presets.js";
import { PT_ICON_STYLE, PT_VIEW_MODES } from "../constants.js";
import { DraggableResizableModal } from "../../primitives/index.js";
import useModalChrome from "../../../hooks/useModalChrome.js";
import { useProcessAnalyzerContext } from "../ProcessAnalyzerContext.js";
import ProcessGraphView from "./ProcessGraphView.jsx";
import ProcessTreeVerdictHero from "./ProcessTreeVerdictHero.jsx";
import ProcessTreeConfigPhase from "./ProcessTreeConfigPhase.jsx";
import ProcessTreeLoadingPhase from "./ProcessTreeLoadingPhase.jsx";
import ProcessTreeResultsView from "./ProcessTreeResultsView.jsx";

export default function ProcessTreeModal() {
  const {
    piAnalystProfile,
    setPiAnalystProfile,
    activeFilters,
    openPiSourceEvent,
    makePiAnalystEntry,
    upsertPiAnalystEntry,
    removePiAnalystEntry,
  } = useProcessAnalyzerContext();
  const modal = useUIStore(s => s.modal);
  const setModal = useUIStore(s => s.setModal);
  const setProximityFilter = useUIStore(s => s.setProximityFilter);
  const ct = useCurrentTab();
  const { th } = useTheme();
  // Process Inspector uses one restrained theme-aware palette. Existing
  // call-sites keep their severity semantics while rendering orange/neutral.
  const piPalette = processInspectorPaletteFor(th);
  const SUS_COLORS = piPalette.severity;
  const INT_COLOR = piPalette.integrity;
  const PI_SEV_COLORS = piPalette.ruleSeverity;
  const tle = typeof window !== "undefined" ? window.tle : null;
  const updateActiveTab = useTabStore(s => s.updateActiveTab);

  // Local refs — only used by this modal
  const ptCacheRef = useRef({ flatNodes: [], byKeyMap: new Map(), deps: null, detMap: new Map(), detMapRuleKey: "", detMapData: null });
  const ptScrollRef = useRef(null);
  const ptHeaderRef = useRef(null);
  const ptRafRef = useRef(null);
  const ptResizingRef = useRef(false);
  const ptPreviewTimerRef = useRef(null);
  const ptScoreSignalRef = useRef({ cancelled: false, gen: 0 });
  // Holds the latest render values the keyboard handler needs, so the window
  // listener (attached once) never reads a stale closure. Updated each render below.
  const ptNavRef = useRef(null);
  const [ptScroll, setPtScroll] = useState({ top: 0, h: 600 });
  // Bumps when async detection scoring completes so derived maps re-read the cache.
  const [ptScoreTick, setPtScoreTick] = useState(0);

  // Modal styles (replicated from parent ms object)
  const ms = useModalChrome();

  // Export helpers (replicated from parent)
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

  // Shorthand for tab updates
  const up = (key, value) => updateActiveTab({ [key]: value });

  // One-click pivot: filter the main timeline grid to this process identity
  // (ProcessGuid preferred, else PID) ± time window, including child creates.
  // pendingFocusRowId scrolls to the create event once it lands in the window.
  const applyProcessGridPivot = useCallback((node, windowMinutes) => {
    if (!node || !ct) return;
    const mins = windowMinutes ?? modal?.ptGridPivotMinutes ?? 15;
    const handoff = buildProcessHandoff(node, modal?.columns || {}, ct.headers || [], "grid", {
      windowMinutes: mins,
      includeChildren: true,
    });
    if (!handoff.ok || !handoff.tabPatch) {
      toast.warning("Cannot filter grid", { detail: handoff.error || "No identity columns mapped for this process." });
      return;
    }
    updateActiveTab(handoff.tabPatch);
    if (handoff.proximity) setProximityFilter(handoff.proximity);
    else setProximityFilter(null);
    toast.success("Grid filtered to process", {
      detail: handoff.label + (handoff.notes?.length ? `\n${handoff.notes.join("\n")}` : "")
        + (handoff.focusRowId ? "\nJumping to create event when visible." : ""),
      ttl: 5000,
    });
    setModal(null);
  }, [ct, modal?.columns, modal?.ptGridPivotMinutes, updateActiveTab, setProximityFilter, setModal]);

  // Lateral Movement / Persistence / Sigma handoffs — host+time context on the tab, then open target.
  const applyProcessHandoff = useCallback((node, target) => {
    if (!node || !ct) return;
    const hash = ptExtractHash(node.hashes);
    const handoff = buildProcessHandoff(node, modal?.columns || {}, ct.headers || [], target, {
      windowMinutes: modal?.ptHandoffMinutes || 30,
      hash: hash || "",
      autoRun: true,
    });
    if (!handoff.ok || !handoff.modal) {
      toast.warning("Cannot open handoff", { detail: handoff.error || "Handoff failed." });
      return;
    }
    if (handoff.tabPatch) updateActiveTab(handoff.tabPatch);
    if (handoff.proximity) setProximityFilter(handoff.proximity);
    toast.info(target === "lateral" ? "Opening Lateral Movement…" : target === "persistence" ? "Opening Persistence…" : "Opening Sigma…", {
      detail: handoff.label + (handoff.notes?.length ? `\n${handoff.notes.join("\n")}` : ""),
      ttl: 4000,
    });
    setModal(handoff.modal);
  }, [ct, modal?.columns, modal?.ptHandoffMinutes, updateActiveTab, setProximityFilter, setModal]);

  // In-app VirusTotal when API key is present; public page fallback otherwise.
  const lookupProcessHash = useCallback(async (node) => {
    const hash = ptExtractHash(node?.hashes);
    if (!hash) {
      toast.warning("No file hash on this process");
      return;
    }
    const cat = vtCategoryForHash(hash);
    const publicUrl = publicVtUrlForHash(hash);
    if (!tle?.vtLookupSingle || !tle?.vtGetApiKey) {
      if (tle?.openExternal) tle.openExternal(publicUrl);
      else window.open(publicUrl, "_blank");
      return;
    }
    try {
      setModal((p) => p?.type === "processTree" ? { ...p, ptVtStatus: "Looking up…" } : p);
      const status = await tle.vtGetApiKey();
      if (!status?.hasKey) {
        setModal((p) => p?.type === "processTree" ? { ...p, ptVtStatus: null } : p);
        toast.info("No VT API key — opening public VirusTotal", { detail: "Set a key in IOC Matching for in-app verdicts." });
        if (tle.openExternal) tle.openExternal(publicUrl);
        else window.open(publicUrl, "_blank");
        return;
      }
      const result = await tle.vtLookupSingle(hash, cat || "SHA256_Hash");
      setModal((p) => p?.type === "processTree" ? { ...p, ptVtStatus: null, ptVtResult: result || null } : p);
      if (result?.error) {
        toast.warning(`VT: ${result.error}`, { detail: "Opening public page as fallback." });
        if (tle.openExternal) tle.openExternal(publicUrl);
        else window.open(publicUrl, "_blank");
        return;
      }
      const score = result?.score || "N/A";
      const verdict = result?.verdict || "";
      toast.success(`VirusTotal: ${score}`, {
        detail: [verdict, result?.threatLabel].filter(Boolean).join(" · ") || hash.slice(0, 16) + "…",
        ttl: 6000,
      });
    } catch (err) {
      setModal((p) => p?.type === "processTree" ? { ...p, ptVtStatus: null } : p);
      toast.error("VT lookup failed", { detail: err?.message || String(err) });
      if (tle?.openExternal) tle.openExternal(publicUrl);
    }
  }, [tle, setModal]);

  const refreshPtPreview = useCallback((colOverrides) => {
    if (!tle?.previewProcessTree || !ct) {
      setModal(p => p?.type === "processTree" ? { ...p, ptPreviewLoading: false } : p);
      return;
    }

    if (ptPreviewTimerRef.current) clearTimeout(ptPreviewTimerRef.current);
    ptPreviewTimerRef.current = setTimeout(() => {
      setModal(p => {
        if (!p || p.type !== "processTree") return p;
        const c = colOverrides || p.columns || {};
        const af = activeFilters(ct);
        const seq = (p._ptPreviewSeq || 0) + 1;
        tle.previewProcessTree(ct.id, {
          pidCol: c.pid, ppidCol: c.ppid, guidCol: c.guid, parentGuidCol: c.parentGuid,
          imageCol: c.image, cmdLineCol: c.cmdLine, userCol: c.user,
          tsCol: c.ts, eventIdCol: c.eventId, providerCol: c.provider,
          eventIdValue: p.eventIdValue == null ? "1,4688" : p.eventIdValue,
          searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode,
          searchCondition: ct.searchCondition || "contains",
          columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
          bookmarkedOnly: ct.showBookmarkedOnly,
          dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        }).then(prev => {
          setModal(q => q?.type === "processTree" && (q._ptPreviewSeq || 0) === seq ? { ...q, ptPreview: prev, ptPreviewLoading: false } : q);
        }).catch(() => {
          setModal(q => q?.type === "processTree" && (q._ptPreviewSeq || 0) === seq ? { ...q, ptPreviewLoading: false } : q);
        });
        return { ...p, ptPreviewLoading: true, _ptPreviewSeq: seq };
      });
    }, 600);
  }, [activeFilters, ct, setModal, tle]);

  useEffect(() => () => {
    if (ptPreviewTimerRef.current) clearTimeout(ptPreviewTimerRef.current);
    ptScoreSignalRef.current.cancelled = true;
  }, []);

  useEffect(() => {
    if (!modal || modal.type !== "processTree" || !modal._ptNeedsPreview) return;
    setModal(p => p?.type === "processTree" ? { ...p, _ptNeedsPreview: false } : p);
    refreshPtPreview();
  }, [modal?._ptNeedsPreview, modal?.type, refreshPtPreview, setModal]);

  // Chunked detection scoring — yields between batches on large trees.
  useEffect(() => {
    if (modal?.type !== "processTree" || modal?.phase !== "results" || !modal?.data?.processes?.length) return;
    const disabledRules = modal.ptDisabledRules || null;
    const customRules = modal.ptCustomRules || null;
    const ruleKey = makeDetMapRuleKey(disabledRules, customRules, piAnalystProfile);
    const c = ptCacheRef.current;
    if (c.detMapData === modal.data && c.detMapRuleKey === ruleKey && c.detMap?.size) {
      if (modal.ptScoring) setModal((p) => p?.type === "processTree" ? { ...p, ptScoring: false, ptScorePercent: 100 } : p);
      return;
    }
    const gen = ++ptScoreSignalRef.current.gen;
    ptScoreSignalRef.current.cancelled = false;
    setModal((p) => p?.type === "processTree" ? { ...p, ptScoring: true, ptScorePercent: 0 } : p);
    let cancelled = false;
    scoreProcessTree(
      modal.data,
      { disabledRules, customRules, analystProfile: piAnalystProfile },
      {
        signal: ptScoreSignalRef.current,
        onProgress: ({ percent }) => {
          if (cancelled || ptScoreSignalRef.current.gen !== gen) return;
          setModal((p) => p?.type === "processTree" && p.ptScoring
            ? { ...p, ptScorePercent: percent }
            : p);
        },
      },
    ).then((m) => {
      if (cancelled || ptScoreSignalRef.current.gen !== gen) return;
      c.detMap = m;
      c.detMapData = modal.data;
      c.detMapRuleKey = ruleKey;
      setModal((p) => p?.type === "processTree" ? { ...p, ptScoring: false, ptScorePercent: 100 } : p);
      setPtScoreTick((t) => t + 1);
    }).catch((err) => {
      if (err?.cancelled || cancelled) return;
      console.error("PI scoring failed", err);
      setModal((p) => p?.type === "processTree" ? { ...p, ptScoring: false } : p);
    });
    return () => {
      cancelled = true;
    };
  }, [
    modal?.type,
    modal?.phase,
    modal?.data,
    modal?.ptDisabledRules,
    modal?.ptCustomRules,
    piAnalystProfile,
    setModal,
  ]);

  // Keyboard navigation over the process list/tree. Attached once while the modal is
  // open; the handler reads ptNavRef.current (refreshed each render) to avoid stale state.
  useEffect(() => {
    if (modal?.type !== "processTree" || modal?.phase !== "results") return;
    const onKey = (e) => {
      const nav = ptNavRef.current;
      if (!nav || !nav.flatNodes.length) return;
      const tag = (e.target && e.target.tagName) || "";
      if (/^(INPUT|TEXTAREA|SELECT)$/.test(tag) || e.target?.isContentEditable) return; // don't hijack typing
      const { flatNodes, selectedKey, expandedNodes, byKeyMap, childMap, setModal: sm, ptScrollRef: sr } = nav;
      const idx = flatNodes.findIndex((n) => n.key === selectedKey);
      const PT_ROW_H = nav.rowH || 34;
      const ensureVisible = (i) => {
        const el = sr.current; if (!el) return;
        const top = i * PT_ROW_H, bot = top + PT_ROW_H;
        if (top < el.scrollTop) el.scrollTop = top;
        else if (bot > el.scrollTop + el.clientHeight) el.scrollTop = bot - el.clientHeight;
      };
      const select = (i) => { sm((p) => p ? { ...p, selectedKey: flatNodes[i].key } : p); ensureVisible(i); };
      if (e.key === "ArrowDown") { e.preventDefault(); select(idx < 0 ? 0 : Math.min(flatNodes.length - 1, idx + 1)); }
      else if (e.key === "ArrowUp") { e.preventDefault(); select(idx < 0 ? flatNodes.length - 1 : Math.max(0, idx - 1)); }
      else if (idx >= 0) {
        const node = flatNodes[idx];
        const hasKids = (childMap.get(node.key) || []).length > 0;
        if (e.key === "Enter" && hasKids) { e.preventDefault(); sm((p) => { const en = { ...p.expandedNodes }; if (en[node.key]) delete en[node.key]; else en[node.key] = true; return { ...p, expandedNodes: en }; }); }
        else if (e.key === "ArrowRight" && hasKids && !expandedNodes[node.key]) { e.preventDefault(); sm((p) => ({ ...p, expandedNodes: { ...p.expandedNodes, [node.key]: true } })); }
        else if (e.key === "ArrowLeft") {
          if (hasKids && expandedNodes[node.key]) { e.preventDefault(); sm((p) => { const en = { ...p.expandedNodes }; delete en[node.key]; return { ...p, expandedNodes: en }; }); }
          else if (node.parentKey && byKeyMap.has(node.parentKey)) {
            // Only jump to the parent if it is actually a visible row — in flat mode
            // (search/severity/susOnly) the parent isn't in flatNodes, so this is a no-op
            // rather than selecting an off-screen node and breaking Up/Down continuity.
            const pIdx = flatNodes.findIndex((n) => n.key === node.parentKey);
            if (pIdx >= 0) { e.preventDefault(); select(pIdx); }
          }
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [modal?.type, modal?.phase, setModal]);

  if (!modal || modal.type !== "processTree" || !ct) return null;

const { phase, columns: cols, eventIdValue, data, expandedNodes, searchText } = modal;
const hasCols = (cols.pid && cols.ppid) || (cols.guid && cols.parentGuid);

// Process type icons — inline 14x14 SVGs (uses hoisted PT_ICON_STYLE)
const ptIcon = (name) => {
  const n = (name || "").toLowerCase();
  if (/^explorer/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><path d="M2 3h12v2H2zm0 3h12v7H2z" fill={th.accent + "66"} stroke={th.accent} strokeWidth="1"/></svg>;
  if (/^(winword|excel|powerpnt|outlook|onenote|msaccess|acrobat|acrord32)/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><path d="M4 1h5l4 4v10H4z" fill={th.textDim} fillOpacity=".2" stroke={th.textDim} strokeWidth="1"/><path d="M9 1v4h4" stroke={th.textDim} strokeWidth="1"/></svg>;
  if (/^(cmd|powershell|pwsh|bash|sh|conhost)(\.exe)?$/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><rect x="1" y="2" width="14" height="12" rx="2" fill={th.text + "11"} stroke={th.textDim} strokeWidth="1"/><path d="M4 6l3 2.5L4 11" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><line x1="9" y1="11" x2="12" y2="11" stroke={th.textDim} strokeWidth="1.5" strokeLinecap="round"/></svg>;
  if (/^(svchost|services|lsass|csrss|smss|wininit|winlogon|spoolsv|lsm)(\.exe)?$/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="5" fill={th.textDim + "22"} stroke={th.textDim} strokeWidth="1"/><circle cx="8" cy="8" r="1.5" fill={th.textDim}/><path d="M8 2v2M8 12v2M2 8h2M12 8h2M3.8 3.8l1.4 1.4M10.8 10.8l1.4 1.4M3.8 12.2l1.4-1.4M10.8 5.2l1.4-1.4" stroke={th.textDim} strokeWidth="1"/></svg>;
  if (/^(chrome|firefox|msedge|iexplore|opera|brave|safari)(\.exe)?$/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" fill={th.textDim + "22"} stroke={th.textDim} strokeWidth="1"/><ellipse cx="8" cy="8" rx="2.5" ry="6" stroke={th.textDim} strokeWidth=".7"/><line x1="2" y1="6" x2="14" y2="6" stroke={th.textDim} strokeWidth=".7"/><line x1="2" y1="10" x2="14" y2="10" stroke={th.textDim} strokeWidth=".7"/></svg>;
  return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="3" fill={th.textDim + "33"} stroke={th.textDim} strokeWidth="1"/></svg>;
};

// Clickable MITRE ATT&CK technique badge. Opens the technique page in the system browser
// (T1003.001 -> attack.mitre.org/techniques/T1003/001/). Reused across both detail panels
// and the story/cluster cards so every technique ID in the modal is a live pivot.
const ptMitreBadge = (tid, key) => (
  <span
    key={key ?? tid}
    onClick={(e) => { e.stopPropagation(); window.tle?.openExternal?.(`https://attack.mitre.org/techniques/${String(tid).replace(".", "/")}/`); }}
    title={`Open ${tid} on attack.mitre.org`}
    style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}18`, color: th.accent, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${th.accent}33`, cursor: "pointer", fontWeight: 600, letterSpacing: "0.02em", transition: "all var(--m-base)" }}
    onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}30`; e.currentTarget.style.textDecoration = "underline"; }}
    onMouseLeave={(e) => { e.currentTarget.style.background = `${th.accent}18`; e.currentTarget.style.textDecoration = "none"; }}
  >{tid}</span>
);

// Pull the strongest file hash (SHA256 > SHA1 > MD5) out of a Sysmon/EvtxECmd Hashes
// field (e.g. "SHA1=...,MD5=...,SHA256=...,IMPHASH=...") for a VirusTotal pivot.
// Labeled keys are matched first so we never pivot on IMPHASH (an import hash, not a
// file hash, but also 32 hex). Falls back to length for an unlabeled single hash.
const ptExtractHash = (s) => {
  if (!s || typeof s !== "string") return null;
  for (const re of [/SHA256=([a-fA-F0-9]{64})/i, /SHA1=([a-fA-F0-9]{40})/i, /MD5=([a-fA-F0-9]{32})/i]) {
    const m = s.match(re);
    if (m) return m[1];
  }
  // A labeled field with only IMPHASH (also 32 hex) has no usable file hash — never pivot on it.
  if (/IMPHASH=/i.test(s)) return null;
  return (s.match(/\b[a-fA-F0-9]{64}\b/) || s.match(/\b[a-fA-F0-9]{40}\b/) || s.match(/\b[a-fA-F0-9]{32}\b/) || [null])[0];
};

// Inline command-line token highlighting (urls/ips/flags/paths/base64) for the
// detail-panel Command Line field — makes the interesting parts pop without leaving the row.
const _ptTokColor = { url: th.textDim, ip: th.sev.high, flag: th.accent, path: th.sev.med, base64: th.textDim };
const ptHighlightCmd = (cmd) => {
  if (!cmd) return "—";
  return tokenizeCommandLine(cmd).map((s, i) => {
    const col = _ptTokColor[s.type];
    return col ? <span key={i} style={{ color: col, fontWeight: s.type === "url" || s.type === "ip" ? 600 : 400 }}>{s.text}</span> : <span key={i}>{s.text}</span>;
  });
};

// "Decoded Command" panel: surfaces base64 / -EncodedCommand payloads (incl. nested
// layers and gzip flags) so the analyst sees the real intent without an external decoder.
const ptDecodePanel = (cmd, gLbl) => {
  const { decodings } = analyzeCommandLine(cmd);
  if (!decodings.length) return null;
  return (
    <div style={{ marginTop: 12, padding: "8px 10px", background: th.sev.high + "10", borderRadius: 6, border: `1px solid ${th.sev.high}2a` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
        <span style={{ ...gLbl, color: th.sev.high, paddingTop: 0 }}>Decoded Command</span>
        <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.high + "1a", color: th.sev.high, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600 }}>{decodings.length} layer{decodings.length !== 1 ? "s" : ""}</span>
      </div>
      {decodings.map((d, i) => (
        <div key={i} style={{ marginBottom: i < decodings.length - 1 ? 8 : 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3, flexWrap: "wrap" }}>
            <span style={{ fontSize: 9, color: th.textDim, fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>{d.source}</span>
            <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: th.textMuted + "18", color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace" }}>{d.encoding}</span>
            {d.decoded && <span onClick={() => navigator.clipboard?.writeText?.(d.decoded)} title="Copy decoded text" style={{ fontSize: 8, padding: "0px 5px", borderRadius: 2, background: th.btnBg, color: th.textMuted, border: `1px solid ${th.border}66`, fontFamily: "'SF Mono', Menlo, monospace", cursor: "pointer" }}>copy</span>}
          </div>
          {d.decoded
            ? <pre style={{ margin: 0, fontSize: 10.5, fontFamily: "'SF Mono', Menlo, monospace", color: th.danger, background: `${th.accent}08`, padding: "6px 8px", borderRadius: 4, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 220, overflow: "auto", lineHeight: 1.5 }}>{ptHighlightCmd(d.decoded)}{d.truncated ? `\n\n… ${d.truncated - d.decoded.length} more chars truncated` : ""}</pre>
            : <div style={{ fontSize: 10, color: th.textMuted, fontStyle: "italic", fontFamily: "-apple-system, sans-serif" }}>{d.note || "Could not decode to readable text."}</div>}
        </div>
      ))}
    </div>
  );
};

// Process tree column configuration
	const ptHeaders = ["Timestamp", "Detection", "Prevalence", "Parent Process", "Process", "Command Line", "PID", "PPID", "User", "Provider", "Event ID", "Integrity"];
	const ptDefWidths = { Timestamp: 195, Provider: 100, "Event ID": 65, "Parent Process": 170, Process: 280, Detection: 290, Prevalence: 150, PID: 75, PPID: 75, User: 150, "Command Line": 300, Integrity: 80 };
const ptColWidths = modal.ptColWidths || null;
const ptSortCol = modal.ptSortCol || "Timestamp";
const ptSortDir = modal.ptSortDir || "asc";
const ptColFilters = modal.ptColFilters || {};
// Detection map is scored asynchronously (chunked) for large trees so the UI
// stays responsive. Cache holds the last completed map; ptScoreTick forces a
// re-render when scoring finishes or rules change.
const _ptDetMapRuleKey = makeDetMapRuleKey(modal.ptDisabledRules || null, modal.ptCustomRules || null, piAnalystProfile);
const _ptDetMap = (() => {
  void ptScoreTick; // subscribe to scoring completions
  const c = ptCacheRef.current;
  if (c.detMapData === data && c.detMapRuleKey === _ptDetMapRuleKey && c.detMap) return c.detMap;
  return c.detMapData === data ? (c.detMap || new Map()) : new Map();
})();
const _ptScoring = !!(data?.processes?.length && (modal.ptScoring || (ptCacheRef.current.detMapRuleKey !== _ptDetMapRuleKey || ptCacheRef.current.detMapData !== data)));

const _ptPrevalenceSummary = (() => {
  const c = ptCacheRef.current;
  if (c.prevSummaryData === data && c.prevSummaryDetMap === _ptDetMap) return c.prevSummary;
  const summary = buildPrevalenceSummary(data, _ptDetMap, 10);
  c.prevSummary = summary;
  c.prevSummaryData = data;
  c.prevSummaryDetMap = _ptDetMap;
  return summary;
})();

// Dataset severity tally for the raw-view overview strip. Cached on data + detMap
// so it isn't recomputed on every selection click (one O(n) pass otherwise).
const _ptSevCounts = (() => {
  const c = ptCacheRef.current;
  if (c.sevCountsData === data && c.sevCountsDetMap === _ptDetMap) return c.sevCounts;
  let crit = 0, high = 0, med = 0, susTotal = 0;
  const hosts = new Set(), users = new Set();
  for (const p of (data?.processes || [])) {
    const lv = (_ptDetMap.get(p.key) || { level: 0 }).level;
    if (lv >= 3) crit++; else if (lv === 2) high++; else if (lv === 1) med++;
    if (lv > 0) susTotal++;
    if (p.hostname) hosts.add(p.hostname);
    if (p.user) users.add(p.user);
  }
  const result = { total: (data?.processes || []).length, crit, high, med, susTotal, hosts: hosts.size, users: users.size };
  c.sevCounts = result; c.sevCountsData = data; c.sevCountsDetMap = _ptDetMap;
  return result;
})();

// Short-window behavioral sequence detection (second pass over _ptDetMap).
// Sequence definitions and the windowing logic now live in the pipeline module
// — this is just the cache wrapper.
const _ptSeqMap = (() => {
  const c = ptCacheRef.current;
  if (c.seqDetMap === _ptDetMap) return c.seqMap;
  const seqMap = buildSequenceMap(data, _ptDetMap);
  c.seqMap = seqMap; c.seqDetMap = _ptDetMap;
  return seqMap;
})();

// Chain cluster computation (memoized on _ptDetMap reference). All cluster
// logic — gap windows, dominant parent/child, sequence-rank annotation —
// lives in the pipeline module.
const _ptChainClusters = (() => {
  const c = ptCacheRef.current;
  if (c.clusterDetMap === _ptDetMap) return c.chainClusters;
  const allClusters = buildChainClusters(data, _ptDetMap, _ptSeqMap);
  c.chainClusters = allClusters; c.clusterDetMap = _ptDetMap;
  return allClusters;
})();
// Reverse lookup: processKey -> cluster — uses allKeys (uncapped) for full coverage
const _ptNodeClusterMap = (() => {
  const c = ptCacheRef.current;
  if (c.nodeClusterDetMap === _ptDetMap) return c.nodeClusterMap;
  const m = buildNodeClusterMap(_ptChainClusters);
  c.nodeClusterMap = m; c.nodeClusterDetMap = _ptDetMap;
  return m;
})();
const ptCellVal = (node, col) => {
  // Parent Process falls back to the relinked parent node when the row carries
  // no parent image — keeps sort/filter consistent with the column display.
  if (col === "Parent Process") return node.parentProcessName || byKeyMap.get(node.parentKey)?.processName || "";
  if (col === "Process") return node.processName || "";
  if (col === "PID") return node.pid || "";
  if (col === "PPID") return node.ppid || "";
  if (col === "User") return node.user || "";
  if (col === "Timestamp") return node.ts || "";
  if (col === "Command Line") return node.cmdLine || "";
  if (col === "Provider") return node.provider || "";
	  if (col === "Event ID") return node.eventId || "";
	  if (col === "Integrity") return _integrityShort(node.integrity);
	  if (col === "Detection") return (_ptDetMap.get(node.key) || {}).reason || "";
	  if (col === "Prevalence") return (_ptDetMap.get(node.key) || {}).prevalence?.rarity || "";
	  return "";
	};
	const ptLinkMeta = (node) => {
	  const link = node?.link || {
	    source: node?.linkSource || "",
	    confidence: node?.linkConfidence || "",
	    reason: node?.linkReason || "",
	    warnings: node?.linkWarnings || [],
	  };
	  const source = link.source || "";
	  const confidence = link.confidence || "";
	  const labelMap = {
	    guid: "GUID",
	    "pid-logon": "PID+Logon",
	    "pid-session": "PID+Session",
	    "pid-host": "PID Host",
	    resolved: "Resolved",
	    unresolved: "Unresolved",
	    root: "Root",
	  };
	  const colorMap = {
	    high: th.success,
	    medium: th.sev.med,
	    low: th.sev.high,
	    none: th.textMuted,
	  };
	  const warnings = Array.isArray(link.warnings) ? link.warnings : [];
	  const title = [
	    link.reason || "",
	    confidence ? `confidence: ${confidence}` : "",
	    link.parentRowId ? `parent row: ${link.parentRowId}` : "",
	    link.childRowId ? `child row: ${link.childRowId}` : "",
	    Number.isFinite(link.timeDeltaMs) ? `delta: ${Math.round(link.timeDeltaMs / 1000)}s` : "",
	    warnings.length ? `warnings: ${warnings.join(", ")}` : "",
	  ].filter(Boolean).join("\n");
	  return {
	    link,
	    source,
	    confidence,
	    label: labelMap[source] || source || "Unknown",
	    color: colorMap[confidence] || th.textMuted,
	    title,
	    warnings,
	  };
	};
	const ptSortKey = (node, col) => {
	  if (col === "PID") return parseInt(node.pid) || 0;
	  if (col === "PPID") return parseInt(node.ppid) || 0;
	  if (col === "Event ID") return parseInt(node.eventId) || 0;
	  if (col === "Detection") return (_ptDetMap.get(node.key) || {}).level || 0;
	  if (col === "Prevalence") {
	    const prev = (_ptDetMap.get(node.key) || {}).prevalence || null;
	    const rank = prev?.rarity === "rare" ? 2 : prev?.rarity === "uncommon" ? 1 : 0;
	    return rank * 1000 + (prev?.scoreBoost || 0);
	  }
	  return ptCellVal(node, col);
	};
const togglePtSort = (col) => {
  if (ptResizingRef.current) return;  // skip sort if column was just resized
  setModal((p) => {
    if ((p.ptSortCol || "Timestamp") === col) return { ...p, ptSortDir: (p.ptSortDir || "asc") === "asc" ? "desc" : "asc" };
    // Detection and Prevalence default to descending so high-signal rows float first.
    return { ...p, ptSortCol: col, ptSortDir: (col === "Detection" || col === "Prevalence") ? "desc" : "asc" };
  });
};
const onPtResizeStart = (colName, e, displayedWidths = null) => {
  e.preventDefault(); e.stopPropagation();
  ptResizingRef.current = true;
  const startX = e.clientX;
  const baseWidths = displayedWidths || ptColWidths || ptDefWidths;
  const startW = baseWidths[colName] || ptDefWidths[colName];
  document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
  const move = (ev) => {
    const newW = Math.max(40, startW + ev.clientX - startX);
    setModal((p) => ({ ...p, ptColWidths: { ...baseWidths, ...(p.ptColWidths || {}), [colName]: newW } }));
  };
  const up = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); setTimeout(() => { ptResizingRef.current = false; }, 0); };
  document.addEventListener("mousemove", move); document.addEventListener("mouseup", up);
};
const openPtFilter = (colName, e) => {
  e.stopPropagation();
  const rect = e.currentTarget.getBoundingClientRect();
  const counts = {};
  for (const p of (data?.processes || [])) { const v = ptCellVal(p, colName); counts[v] = (counts[v] || 0) + 1; }
  const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  const current = ptColFilters[colName];
  const selected = new Set(current && current.length > 0 ? current : allVals);
  setModal((p) => ({ ...p, ptFilterOpen: colName, ptFilterPos: { x: rect.left, y: rect.bottom + 2 }, ptFilterVals: allVals, ptFilterCounts: counts, ptFilterSel: selected, ptFilterSearch: "" }));
};
const ptFilterOpen = modal.ptFilterOpen;
const ptFilterPos = modal.ptFilterPos || {};
const ptFilterVals = modal.ptFilterVals || [];
const ptFilterCounts = modal.ptFilterCounts || {};
const ptFilterSel = modal.ptFilterSel || new Set();
const ptFilterSearch = modal.ptFilterSearch || "";
const ptFilterDisplay = ptFilterSearch ? ptFilterVals.filter((v) => v.toLowerCase().includes(ptFilterSearch.toLowerCase())) : ptFilterVals;
const ptActiveFilterCount = Object.values(ptColFilters).filter((v) => v && v.length > 0).length;
const PT_CHK_W = 32;
const ptChecked = modal.ptChecked || new Set();
const ptCheckedCount = ptChecked.size;

// --- Process Inspector config constants ---
const PI_INTENTS = [
  { id: "low-noise", label: "Low-noise triage", desc: "High-confidence only \u2014 credential access, encoded PS, Office macros, service shells",
    disabled: new Set(["pi-8","pi-11","pi-15","pi-16","pi-17","pi-22","pi-23"]) },
  { id: "balanced", label: "Balanced", desc: "Recommended \u2014 all detection categories enabled", disabled: new Set() },
  { id: "broad", label: "Broad hunt", desc: "Maximum coverage \u2014 all chain rules + all standalone", disabled: new Set() },
];
// PI telemetry toggles live in ProcessTreeConfigPhase (config UI only).
// PI_TECHNIQUE_GROUPS / PI_SEV_COLORS / PI_ALL_RULES come from process-inspector.js.
const piDisabledSet = modal.ptDisabledRules || new Set();

// --- Warning functions ---
const ptSkipWarnings = (evCounts, candidateRows, fullScopeCandidateRows, autoGenericFallback) => {
  const w = [];
  if (!(evCounts["1"] > 0) && !(evCounts["4688"] > 0)) {
    if (autoGenericFallback && candidateRows > 0)
      w.push({ level: "info", text: `No Sysmon 1 / Security 4688 found - preview using ${candidateRows.toLocaleString()} generic process rows` });
    else if (candidateRows > 0)
      w.push({ level: "warn", text: `${candidateRows.toLocaleString()} generic process rows detected, but no Sysmon 1 / Security 4688 are in the current scope` });
    else if (fullScopeCandidateRows > 0)
      w.push({ level: "info", text: `${fullScopeCandidateRows.toLocaleString()} generic process rows exist in the full tab - current filters are excluding them here` });
    else
      w.push({ level: "error", text: "No process creation events (Sysmon 1 or Security 4688)" });
  }
  else if (!(evCounts["1"] > 0))
    w.push({ level: "info", text: "No Sysmon EID 1 \u2014 using Security 4688 only (no GUIDs, limited parent info)" });
  else if (!(evCounts["4688"] > 0))
    w.push({ level: "info", text: "No Security 4688 \u2014 Sysmon only" });
  return w;
};
const ptSanityWarnings = (colQuality, linkQuality) => {
  const w = [];
  if (!colQuality) return w;
  if (linkQuality?.guidCoverage === 0 && linkQuality?.pidCoverage === 0)
    w.push({ level: "error", text: "No PID or GUID coverage \u2014 tree reconstruction will fail" });
  else if (linkQuality?.guidCoverage === 0 && linkQuality?.pidCoverage > 0)
    w.push({ level: "warn", text: "No ProcessGuid fields \u2014 PID reuse may weaken long-range linking" });
  if ((linkQuality?.cmdLineCoverage || 0) < 30)
    w.push({ level: "warn", text: `Command line coverage ${linkQuality?.cmdLineCoverage || 0}% \u2014 standalone detections reduced` });
  if ((linkQuality?.parentImageCoverage || 0) < 30)
    w.push({ level: "warn", text: `Parent image coverage ${linkQuality?.parentImageCoverage || 0}% \u2014 chain rules may underperform` });
  for (const [key, q] of Object.entries(colQuality)) {
    if (q.mapped && q.nullRate > 70)
      w.push({ level: "info", text: `${key} column has ${q.nullRate}% null/empty values` });
  }
  return w;
};

// --- Intent + group helpers ---
const applyPiIntent = (intent) => setModal(p => ({ ...p, ptDisabledRules: new Set(intent.disabled), ptIntent: intent.id }));
const resetPiRules = () => setModal(p => ({ ...p, ptDisabledRules: new Set(), ptIntent: "balanced" }));
const piGroupState = (ruleIds, disSet) => {
  const off = ruleIds.filter(id => disSet.has(id)).length;
  return off === 0 ? "on" : off === ruleIds.length ? "off" : "partial";
};
const piCoverageInfo = (colMap) => {
  const pidLink = !!(colMap.pid && colMap.ppid);
  const guidLink = !!(colMap.guid && colMap.parentGuid);
  const required = [
    { key: "linkage", label: "PID/PPID or GUID pair", mapped: pidLink || guidLink },
    { key: "image", label: "Image / Exe", mapped: !!colMap.image },
  ];
  const recommended = [
    { key: "cmdLine", label: "Command Line", mapped: !!colMap.cmdLine },
    { key: "ts", label: "Timestamp", mapped: !!colMap.ts },
    { key: "eventId", label: "Event ID", mapped: !!colMap.eventId },
    { key: "parentImage", label: "Parent Image", mapped: !!colMap.parentImage },
    { key: "user", label: "User", mapped: !!colMap.user },
  ];
  const reqOk = required.filter((item) => item.mapped).length;
  const recOk = recommended.filter((item) => item.mapped).length;
  const level = reqOk === required.length ? (recOk >= 3 ? "high" : "medium") : "low";
  return { level, reqOk, recOk, required, recommended, pidLink, guidLink };
};
const togglePiGroup = (group) => setModal(p => {
  const s = new Set(p.ptDisabledRules || []);
  const state = piGroupState(group.ruleIds, s);
  if (state === "on") group.ruleIds.forEach(id => s.add(id));
  else group.ruleIds.forEach(id => s.delete(id));
  return { ...p, ptDisabledRules: s };
});

const applyProcessTreeResult = (payload, progInt) => {
  clearInterval(progInt);
  clearIpcSubscription("process-tree-complete");
  const result = payload?.result ?? payload;
  const error = payload?.error || result?.error || null;
  const cancelled = payload?.cancelled || /cancelled/i.test(String(error || ""));

  if (cancelled) {
    setModal((p) => p?.type === "processTree"
      ? { ...p, phase: "config", loading: false, ptProgress: 0, ptPhaseIdx: 0, _cancelled: true, _ptJobId: null }
      : p);
    return;
  }

  if (error) {
    setModal((p) => p?.type === "processTree" && !p._cancelled
      ? { ...p, phase: "config", loading: false, error, ptProgress: 0, ptPhaseIdx: 0, _ptJobId: null }
      : p);
    return;
  }

  setModal((p) => p?.type === "processTree" && !p._cancelled
    ? { ...p, ptProgress: 100, ptPhaseIdx: 5, _ptJobId: null }
    : p);
  setTimeout(() => {
    setModal((p) => p?.type === "processTree" && !p._cancelled
      ? { ...p, phase: "results", loading: false, data: result, expandedNodes: {}, searchText: "" }
      : p);
  }, 250);
};

const handleBuild = async (scopeOverrides = null) => {
  const t0 = Date.now();
  const ptPhases = ["Querying database...", "Parsing process events...", "Building parent-child relationships...", "Computing tree depth...", "Finalizing...", "Complete"];
  const progInt = setInterval(() => {
    setModal((p) => {
      if (!p || p.type !== "processTree" || p.phase !== "loading") { clearInterval(progInt); return p; }
      const el = (Date.now() - t0) / 1000;
      const prog = Math.min(92, 90 * (1 - Math.exp(-el / 6)));
      const pi = prog < 10 ? 0 : prog < 30 ? 1 : prog < 55 ? 2 : prog < 75 ? 3 : 4;
      return { ...p, ptProgress: prog, ptPhaseIdx: pi };
    });
  }, 120);
  // Invalidate prior detection map so async scoring re-runs for the new tree.
  ptCacheRef.current.detMap = new Map();
  ptCacheRef.current.detMapData = null;
  ptCacheRef.current.detMapRuleKey = "";
  ptScoreSignalRef.current.cancelled = true;
  setModal((p) => ({ ...p, phase: "loading", loading: true, error: null, ptProgress: 0, ptPhaseIdx: 0, _cancelled: false, _ptJobId: null, ptScoring: false, ptScorePercent: 0 }));
  try {
    const af = activeFilters(ct);
    const useGenericFallback = modal.ptPreview?.autoGenericFallback === true;
    const dateRangeFilters = { ...(ct.dateRangeFilters || {}) };
    const advancedFilters = [...(ct.advancedFilters || [])];
    // Scoped rebuild: host + time window on top of (or replacing) tab filters.
    if (scopeOverrides) {
      const tsCol = detectTimestampColumn(cols, ct.headers || []);
      const hostCol = detectHostnameColumn(cols, ct.headers || []);
      if (tsCol && (scopeOverrides.from || scopeOverrides.to)) {
        dateRangeFilters[tsCol] = {
          from: scopeOverrides.from || dateRangeFilters[tsCol]?.from || "",
          to: scopeOverrides.to || dateRangeFilters[tsCol]?.to || "",
        };
      }
      if (hostCol && scopeOverrides.host) {
        advancedFilters.push({
          column: hostCol,
          operator: "contains",
          value: scopeOverrides.host,
          logic: "AND",
        });
      }
    }
    const options = {
      pidCol: cols.pid, ppidCol: cols.ppid, guidCol: cols.guid, parentGuidCol: cols.parentGuid,
      imageCol: cols.image, cmdLineCol: cols.cmdLine, userCol: cols.user, tsCol: cols.ts, eventIdCol: cols.eventId, providerCol: cols.provider,
      eventIdValue: useGenericFallback ? null : (eventIdValue || null),
      searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
      searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters, advancedFilters,
      maxRows: modal.maxRows || 200000,
    };

    if (tle?.startProcessTree && tle?.onProcessTreeComplete) {
      replaceIpcSubscription("process-tree-complete", tle.onProcessTreeComplete, (payload = {}) => {
        const currentModal = useUIStore.getState?.().modal;
        if (currentModal?.type !== "processTree") return;
        if (currentModal._ptJobId && payload.jobId && currentModal._ptJobId !== payload.jobId) return;
        applyProcessTreeResult(payload, progInt);
      });
      const started = await tle.startProcessTree(ct.id, options);
      if (isIpcError(started)) throw new Error(ipcErrorMessage(started));
      if (started?.result || started?.error) {
        applyProcessTreeResult(started, progInt);
        return;
      }
      if (!started?.jobId) throw new Error("Process tree job did not start");
      setModal((p) => p?.type === "processTree" ? { ...p, _ptJobId: started.jobId } : p);
    } else {
      const result = await tle.getProcessTree(ct.id, options);
      if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
      applyProcessTreeResult({ result }, progInt);
    }
  } catch (e) {
    clearInterval(progInt);
    clearIpcSubscription("process-tree-complete");
    setModal((p) => p?.type === "processTree" && !p._cancelled ? { ...p, phase: "config", loading: false, error: e.message, ptProgress: 0, _ptJobId: null } : p);
  }
};

const handleCancelBuild = async () => {
  const currentModal = useUIStore.getState?.().modal;
  const jobId = currentModal?.type === "processTree" ? currentModal._ptJobId : modal._ptJobId;
  clearIpcSubscription("process-tree-complete");
  setModal((p) => p?.type === "processTree"
    ? { ...p, phase: "config", loading: false, ptProgress: 0, ptPhaseIdx: 0, _cancelled: true, _ptJobId: null }
    : p);
  if (jobId && tle?.cancelJob) {
    try { await tle.cancelJob(jobId); } catch {}
  }
};

// Cached childMap + byKey — shared across buildFlat, expand helpers, detail panel
const _cachedChildMap = (() => {
  const c = ptCacheRef.current;
  if (c.childMapData === data) return c.childMap;
  if (!data?.processes?.length) { c.childMap = new Map(); c.childMapData = data; return c.childMap; }
  const m = new Map();
  for (const p of data.processes) {
    if (!m.has(p.parentKey)) m.set(p.parentKey, []);
    m.get(p.parentKey).push(p.key);
  }
  c.childMap = m;
  c.childMapData = data;
  return m;
})();
const _cachedByKey = (() => {
  const c = ptCacheRef.current;
  if (c.byKeyData === data) return c.byKeyMap;
  if (!data?.processes?.length) { c.byKeyMap = new Map(); c.byKeyData = data; return c.byKeyMap; }
  const m = new Map(data.processes.map((p) => [p.key, p]));
  c.byKeyMap = m;
  c.byKeyData = data;
  return m;
})();

// Expose byKeyMap / childMap before buildFlat — buildFlat calls ptCellVal which
// reads byKeyMap, so the const must be initialized before the first call.
const byKeyMap = _cachedByKey;
const childMap = _cachedChildMap;

// Build flat visible list from tree data, with connector metadata
const buildFlat = () => {
  if (!data?.processes?.length) return [];
  const procs = data.processes;
  const byKey = _cachedByKey;
  const childMap = _cachedChildMap;
  const st = (searchText || "").toLowerCase();
  const susOnly = !!modal.susOnlyFilter;
  const sevFilter = Array.isArray(modal.ptSevFilter) ? modal.ptSevFilter : [];
  const clusterKeys = modal.ptClusterKeys || null;
  const hasColFilters = Object.values(ptColFilters).some((v) => v && v.length > 0);
  const siblingSort = (a, b) => {
    const av = ptSortKey(a, ptSortCol), bv = ptSortKey(b, ptSortCol);
    const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
    return ptSortDir === "asc" ? cmp : -cmp;
  };
  // Flat mode when search, column filters, suspicious-only, severity filter, cluster filter (non-context), or sorting by Detection
  const flatSort = ptSortCol === "Detection";
  const clusterContext = !!(clusterKeys && modal.ptClusterContext);
  if (st || hasColFilters || susOnly || sevFilter.length || (clusterKeys && !clusterContext) || flatSort) {
    let filtered = [...procs];
    if (clusterKeys && !clusterContext) {
      filtered = filtered.filter((p) => clusterKeys.has(p.key));
    }
    if (hasColFilters) {
      filtered = filtered.filter((p) => {
        for (const [col, vals] of Object.entries(ptColFilters)) {
          if (!vals || vals.length === 0) continue;
          if (!vals.includes(ptCellVal(p, col))) return false;
        }
        return true;
      });
    }
    if (st) {
      filtered = filtered.filter((p) =>
        (p.processName || "").toLowerCase().includes(st) ||
        (p.pid || "").toLowerCase().includes(st) ||
        (p.cmdLine || "").toLowerCase().includes(st) ||
        (p.user || "").toLowerCase().includes(st)
      );
    }
    if (susOnly) {
      filtered = filtered.filter((p) => (_ptDetMap.get(p.key) || { level: 0 }).level > 0);
    }
    if (sevFilter.length) {
      filtered = filtered.filter((p) => sevFilter.includes((_ptDetMap.get(p.key) || { level: 0 }).level));
    }
    filtered.sort(siblingSort);
    return filtered.map((p) => ({ ...p, depth: 0, connectors: [], isLast: false }));
  }
  // When clusterContext is active, auto-expand ancestors of cluster members
  const ctxExpanded = clusterContext ? (() => {
    const expanded = { ...expandedNodes };
    for (const ck of clusterKeys) {
      let cur = byKey.get(ck);
      while (cur) {
        // Stop at a PID-reuse mislinked edge (shared guard) so we expand only the member's
        // real ancestors, not an unrelated branch reached through a bad link.
        const pk = consistentParentKey(cur, byKey);
        if (!pk || !byKey.has(pk)) break;
        expanded[pk] = true;
        cur = byKey.get(pk);
      }
    }
    return expanded;
  })() : expandedNodes;
  const roots = procs.filter((p) => !byKey.has(p.parentKey));
  const flat = [];
  const activeLines = {};
  const visited = new Set();
  const MAX_DEPTH = 100;
  const dfs = (keys, depth) => {
    if (depth > MAX_DEPTH) return;
    const sorted = keys.map((k) => byKey.get(k)).filter(Boolean);
    sorted.sort(siblingSort);
    for (let si = 0; si < sorted.length; si++) {
      const node = sorted[si];
      if (visited.has(node.key)) continue;
      visited.add(node.key);
      const isLast = si === sorted.length - 1;
      const connectors = [];
      for (let d = 0; d < depth; d++) connectors.push(!!activeLines[d]);
      flat.push({ ...node, depth, connectors, isLast: depth > 0 && isLast });
      if (ctxExpanded[node.key]) {
        activeLines[depth] = !isLast;
        dfs(childMap.get(node.key) || [], depth + 1);
        delete activeLines[depth];
      }
    }
  };
  dfs(roots.map((r) => r.key), 0);
  return flat;
};

// Cached flat list + byKeyMap — only recompute when deps actually change (not on selectedKey click)
const flatNodes = (() => {
  if (phase !== "results") return [];
  const c = ptCacheRef.current;
  const susOnly = !!modal.susOnlyFilter;
  const sevFilter = modal.ptSevFilter || null; // reference-stable cache key (don't allocate a fresh [])
  const clusterKeys = modal.ptClusterKeys || null;
  const clusterCtx = !!modal.ptClusterContext;
  if (c.data === data && c.expandedNodes === expandedNodes && c.searchText === searchText &&
      c.ptColFilters === ptColFilters && c.ptSortCol === ptSortCol && c.ptSortDir === ptSortDir && c.susOnly === susOnly && c.sevFilter === sevFilter && c.clusterKeys === clusterKeys && c.clusterCtx === clusterCtx) {
    return c.flatNodes;
  }
  const result = buildFlat();
  Object.assign(c, { flatNodes: result, data, expandedNodes, searchText, ptColFilters, ptSortCol, ptSortDir, susOnly, sevFilter, clusterKeys, clusterCtx });
  return result;
})();
// Findings minimap: bucket the (ordered) flat list into severity bands so the rail
// beside the tree shows where the high-severity rows are. Cached on (flatNodes, detMap)
// so it never recomputes on scroll/selection — only when the visible list itself changes.
const _ptRail = (() => {
  const c = ptCacheRef.current;
  if (c.railFlat === flatNodes && c.railDetMap === _ptDetMap) return c.rail;
  const N = flatNodes.length;
  let rail = null;
  if (N > 0) {
    const B = Math.min(N, 240);
    const buckets = new Array(B).fill(0);
    for (let i = 0; i < N; i++) {
      const lv = (_ptDetMap.get(flatNodes[i].key) || { level: 0 }).level;
      if (lv > 0) { const b = Math.floor((i / N) * B); if (lv > buckets[b]) buckets[b] = lv; }
    }
    rail = buckets;
  }
  c.rail = rail; c.railFlat = flatNodes; c.railDetMap = _ptDetMap;
  return rail;
})();
// Incident-story synthesis. The grouping/anchor/finalize logic lives in the
// pipeline module — this wrapper is just the existing memoization layer.
const _ptIncidentStories = (() => {
  const c = ptCacheRef.current;
  if (c.storyData === data && c.storyDetMap === _ptDetMap && c.storySeqMap === _ptSeqMap) return c.storyList || [];
  const stories = buildIncidentStories(data, byKeyMap, _cachedChildMap, _ptDetMap, _ptSeqMap, _ptNodeClusterMap);
  c.storyList = stories;
  c.storyData = data;
  c.storyDetMap = _ptDetMap;
  c.storySeqMap = _ptSeqMap;
  return stories;
})();
const _ptNodeStoryMap = (() => {
  const c = ptCacheRef.current;
  if (c.storyNodeData === data && c.storyNodeStories === _ptIncidentStories) return c.storyNodeMap || new Map();
  const m = buildNodeStoryMap(_ptIncidentStories);
  c.storyNodeMap = m;
  c.storyNodeData = data;
  c.storyNodeStories = _ptIncidentStories;
  return m;
})();

// Chain highlight: walk from selected node to root (cycle-safe)
const selectedKey = modal.selectedKey || null;
// Refresh the keyboard handler's view of the current render (see the keydown useEffect above).
ptNavRef.current = { flatNodes, selectedKey, expandedNodes, byKeyMap, childMap, setModal, ptScrollRef, rowH: modal.ptDensity === "compact" ? 26 : 34 };
const chainKeys = new Set();
if (selectedKey && byKeyMap.size > 0) {
  let cur = selectedKey;
  while (cur && !chainKeys.has(cur)) {
    chainKeys.add(cur);
    const node = byKeyMap.get(cur);
    if (!node) break;
    // Highlight only the real execution chain — stop at a PID-reuse mislinked edge.
    const pk = consistentParentKey(node, byKeyMap);
    if (!pk || !byKeyMap.has(pk)) break;
    cur = pk;
  }
}
const expandAll = () => {
  const en = {};
  for (const p of (data?.processes || [])) { if (p.childCount > 0) en[p.key] = true; }
  setModal((p) => p ? { ...p, expandedNodes: en } : p);
};
const collapseAll = () => setModal((p) => p ? { ...p, expandedNodes: {} } : p);
const expandToDepth = (maxD) => {
  const en = {};
  for (const p of (data?.processes || [])) { if (p.childCount > 0 && p.depth < maxD) en[p.key] = true; }
  setModal((p) => p ? { ...p, expandedNodes: en } : p);
};

const selStyle = { background: th.bgInput, color: th.text, border: `1px solid ${th.border}`, borderRadius: 6, padding: "4px 8px", fontSize: 12, fontFamily: "monospace" };

return (
  <DraggableResizableModal
    defaultWidth={Math.round(window.innerWidth * 0.92)}
    defaultHeight={Math.round(window.innerHeight * 0.88)}
    minWidth={480}
    minHeight={300}
    onClose={() => setModal(null)}
  >
    {({ startDrag, width: pw }) => (<>
      {/* Header — draggable, gradient glass */}
      <div onMouseDown={startDrag} style={{ padding: "14px 20px 10px", borderBottom: `1px solid ${th.border}66`, cursor: "move", flexShrink: 0, userSelect: "none", background: `linear-gradient(180deg, ${th.headerBg}ee 0%, ${th.modalBg}cc 100%)`, backdropFilter: "blur(20px) saturate(1.4)", WebkitBackdropFilter: "blur(20px) saturate(1.4)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.fillAccent} 0%, ${th.fillAccentHover || th.fillAccent} 100%)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, fontWeight: 700, color: th.onAccent, boxShadow: `0 2px 8px ${th.accent}44`, flexShrink: 0 }}>{"\u25B3"}</div>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>
                <span style={{ color: th.accent }}>IRFlow</span> {"\u2014"} Process Inspector
              </h3>
              {phase === "results" && data?.stats && (() => {
                // Hostname display: show real hostnames only, never fall back to a
                // user's domain (was the same Finding #4 bug). If the dataset spans
                // multiple hosts show a count; if all rows are missing a hostname
                // show nothing rather than a fabricated label.
                const hostname = (() => {
                  const procs = data?.processes || [];
                  const hosts = new Set();
                  for (const p of procs) {
                    const h = (p.hostname || "").trim();
                    if (h) hosts.add(h);
                  }
                  if (hosts.size === 0) return "";
                  if (hosts.size === 1) return [...hosts][0];
                  return `${hosts.size} hosts`;
                })();
                const providers = [...new Set((data?.processes || []).map(p => _providerShort(p.provider)).filter(Boolean))].join(", ");
                const eids = [...new Set((data?.processes || []).map(p => p.eventId).filter(Boolean))].sort().join(", ");
                // Date range: walk processes once tracking min/max via canonical
                // epoch ms. Pin the display strings to whichever raw rows produced
                // the actual chronological extremes — never lex-sort the strings.
                const dateRange = (() => {
                  const procs = data?.processes || [];
                  let minMs = Number.POSITIVE_INFINITY;
                  let maxMs = Number.NEGATIVE_INFINITY;
                  let minStr = "";
                  let maxStr = "";
                  for (const p of procs) {
                    if (!p.ts) continue;
                    const t = normalizeTimestamp(p.ts);
                    if (!Number.isFinite(t)) continue;
                    if (t < minMs) { minMs = t; minStr = p.ts; }
                    if (t > maxMs) { maxMs = t; maxStr = p.ts; }
                  }
                  if (!minStr) return "";
                  // Trim "YYYY-MM-DD HH:MM:SS..." down to the date portion for header brevity.
                  // Falls back to the full string if the trim regex doesn't match a date.
                  const datePart = (s) => {
                    const m = String(s).match(/(\d{4}-\d{2}-\d{2})/);
                    if (m) return m[1];
                    const us = String(s).match(/(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})/);
                    return us ? us[1] : String(s).split(/[\sT]/)[0];
                  };
                  const first = datePart(minStr);
                  const last = datePart(maxStr);
                  return first === last ? first : `${first} \u2192 ${last}`;
                })();
                return (
                  <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginTop: 2, display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {hostname && <span style={{ color: th.text, fontWeight: 500 }}>{hostname}</span>}
                    {hostname && providers && <span>{"\u00B7"}</span>}
                    {providers && <span>{providers}</span>}
                    {eids && <span>{"\u00B7"} EID {eids}</span>}
                    <span>{"\u00B7"} {data.stats.totalProcesses.toLocaleString()} events</span>
                    {dateRange && <span>{"\u00B7"} {dateRange}</span>}
                    {data.useGuid && <span style={{ color: th.success }}>{"\u00B7"} GUID-linked</span>}
                    {data.stats.truncated && <span style={{ color: th.danger }}>{"\u00B7"} Truncated at {(data.stats.totalProcesses || 0).toLocaleString()} {"\u2014"} increase limit</span>}
                  </div>
                );
              })()}
            </div>
          </div>
          <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textDim, fontSize: 18, cursor: "pointer", padding: "0 4px", lineHeight: 1 }}>{"\u00D7"}</button>
        </div>
      </div>


      {/* Config phase */}
      {phase === "config" && (
        <ProcessTreeConfigPhase
          modal={modal}
          setModal={setModal}
          th={th}
          ms={ms}
          ct={ct}
          cols={cols}
          hasCols={hasCols}
          handleBuild={handleBuild}
          refreshPtPreview={refreshPtPreview}
          piAnalystProfile={piAnalystProfile}
          setPiAnalystProfile={setPiAnalystProfile}
          PI_SEV_COLORS={PI_SEV_COLORS}
          SUS_COLORS={SUS_COLORS}
          piCoverageInfo={piCoverageInfo}
          piGroupState={piGroupState}
          togglePiGroup={togglePiGroup}
          applyPiIntent={applyPiIntent}
          resetPiRules={resetPiRules}
          ptSkipWarnings={ptSkipWarnings}
          ptSanityWarnings={ptSanityWarnings}
          PI_INTENTS={PI_INTENTS}
          pw={pw}
        />
      )}

      {/* Loading phase */}
      {phase === "loading" && (
        <ProcessTreeLoadingPhase modal={modal} th={th} handleCancelBuild={handleCancelBuild} />
      )}

      {/* Results phase */}
      {phase === "results" && data && (
        <ProcessTreeResultsView
          modal={modal}
          setModal={setModal}
          th={th}
          ct={ct}
          data={data}
          cols={cols}
          SUS_COLORS={SUS_COLORS}
          INT_COLOR={INT_COLOR}
          PI_SEV_COLORS={PI_SEV_COLORS}
          _ptDetMap={_ptDetMap}
          _ptScoring={_ptScoring}
          _ptPrevalenceSummary={_ptPrevalenceSummary}
          _ptSevCounts={_ptSevCounts}
          _ptSeqMap={_ptSeqMap}
          _ptChainClusters={_ptChainClusters}
          _ptNodeClusterMap={_ptNodeClusterMap}
          _ptIncidentStories={_ptIncidentStories}
          _ptNodeStoryMap={_ptNodeStoryMap}
          _ptRail={_ptRail}
          flatNodes={flatNodes}
          byKeyMap={byKeyMap}
          childMap={childMap}
          chainKeys={chainKeys}
          selectedKey={selectedKey}
          ptScroll={ptScroll}
          setPtScroll={setPtScroll}
          ptScrollRef={ptScrollRef}
          ptHeaderRef={ptHeaderRef}
          ptRafRef={ptRafRef}
          ptIcon={ptIcon}
          ptMitreBadge={ptMitreBadge}
          ptExtractHash={ptExtractHash}
          ptHighlightCmd={ptHighlightCmd}
          ptDecodePanel={ptDecodePanel}
          ptHeaders={ptHeaders}
          ptDefWidths={ptDefWidths}
          ptColWidths={ptColWidths}
          ptSortCol={ptSortCol}
          ptSortDir={ptSortDir}
          ptColFilters={ptColFilters}
          ptCellVal={ptCellVal}
          togglePtSort={togglePtSort}
          onPtResizeStart={onPtResizeStart}
          openPtFilter={openPtFilter}
          ptFilterOpen={ptFilterOpen}
          ptFilterPos={ptFilterPos}
          ptFilterVals={ptFilterVals}
          ptFilterCounts={ptFilterCounts}
          ptFilterSel={ptFilterSel}
          ptFilterSearch={ptFilterSearch}
          ptFilterDisplay={ptFilterDisplay}
          ptActiveFilterCount={ptActiveFilterCount}
          ptChecked={ptChecked}
          ptCheckedCount={ptCheckedCount}
          PT_CHK_W={PT_CHK_W}
          expandAll={expandAll}
          collapseAll={collapseAll}
          expandToDepth={expandToDepth}
          applyProcessGridPivot={applyProcessGridPivot}
          applyProcessHandoff={applyProcessHandoff}
          lookupProcessHash={lookupProcessHash}
          openPiSourceEvent={openPiSourceEvent}
          makePiAnalystEntry={makePiAnalystEntry}
          upsertPiAnalystEntry={upsertPiAnalystEntry}
          removePiAnalystEntry={removePiAnalystEntry}
          handleBuild={handleBuild}
          _downloadFile={_downloadFile}
          _toCSV={_toCSV}
          piAnalystProfile={piAnalystProfile}
          updateActiveTab={updateActiveTab}
          pw={pw}
        />
      )}
    </>)}
  </DraggableResizableModal>
);
}
