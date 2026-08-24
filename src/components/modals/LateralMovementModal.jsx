import { useState, useEffect, useRef, useCallback, useMemo, Fragment } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { DraggableResizableModal } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";
import { buildPillsByRowid, pillToneFor } from "../../utils/evidence-pills.js";
import { collectEvidenceRefs, groupEvidenceRefs } from "../../utils/evidence-refs.js";
import { toast } from "../../store/useToastStore.js";
import { redactRow, csvCell, toCSV } from "../../utils/lm-export.js";
import { formatDateTime } from "../../utils/datetime.js";
import { normalizeTimestamp } from "../../utils/forensic-normalize.js";
import {
  LATERAL_GRAPH_DEFAULTS,
  buildLateralIdentityGraph,
  layoutLateralMovementGraph,
  selectLateralGraphEdges,
  selectLateralGraphNodes,
} from "../../utils/lateral-movement-graph-layout.js";
import { PI_TYPOGRAPHY as LM_TYPOGRAPHY } from "../process-analyzer/constants.js";

// ── Local utilities (previously defined in App.jsx scope) ────────────

/** Rows of objects -> CSV, via the shared formula-safe cell encoder. */
const _toCSV = (rows) => {
  if (!rows.length) return "";
  const keys = Object.keys(rows[0]);
  return toCSV([keys, ...rows.map((r) => keys.map((k) => r[k]))]);
};

const _activeFilters = (tab) => {
  const dis = tab.disabledFilters || new Set();
  if (dis.size === 0) return { columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters };
  return {
    columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
    checkboxFilters: Object.fromEntries(Object.entries(tab.checkboxFilters).filter(([k]) => !dis.has(k))),
  };
};

export default function LateralMovementModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const ct = useCurrentTab();
  const { th } = useTheme();
  const timezone = useUIStore((s) => s.timezone);
  const dateTimeFormat = useUIStore((s) => s.dateTimeFormat);
  const tle = typeof window !== "undefined" ? window.tle : null;
  const setTabs = useTabStore((s) => s.setTabs);
  const tabs = useTabStore((s) => s.tabs);
  const setActiveTab = useTabStore((s) => s.setActiveTab);
  const updateActiveTab = useTabStore((s) => s.updateActiveTab);

  // Local replacement for App.jsx's `up(key, val)`
  const up = useCallback((key, val) => {
    updateActiveTab({ [key]: val });
  }, [updateActiveTab]);

  // ── Modal styles (mirrors App.jsx `ms` object) ──────────────────
  const ms = useModalChrome();

  // Guard-safe derivations. Every hook below must be declared BEFORE the early return
  // so the hook order is stable — the guard used to sit above a useEffect and a useMemo,
  // which is a latent "rendered fewer hooks than expected" crash (masked today only
  // because App.jsx mounts this component under the same condition).
  const isActive = !!modal && modal.type === "lateralMovement" && !!ct;
  const data = isActive ? modal.data : null;

  // Debounce handle for the pre-flight preview. This was a plain `let` in the render
  // body, so every render created a fresh `null` and clearTimeout() never cancelled
  // anything — each column-mapping change queued another uncancelled 600ms scan.
  const _lmPreviewTimerRef = useRef(null);
  useEffect(() => () => clearTimeout(_lmPreviewTimerRef.current), []);

  // Latest-value box so the effects below can call handlers that are declared further
  // down without being re-subscribed on every render.
  const _handlersRef = useRef({});
  const _runSeqRef = useRef(0);

  // Real analyzer progress. The modal used to animate an eased curve on a timer with no
  // connection to the analysis at all; the analyzer now reports stage boundaries on the
  // shared analysis-progress channel and the curve is only a fallback.
  useEffect(() => {
    if (!isActive || !tle?.onAnalysisProgress) return undefined;
    const off = tle.onAnalysisProgress((p) => {
      if (!p) return;
      const method = p.method || p.metadata?.method;
      if (method && method !== "getLateralMovement" && method !== "getMultiSourceLateralMovement") return;
      const pct = Number(p.progress);
      if (!Number.isFinite(pct)) return;
      setModal((q) => (q?.type === "lateralMovement" && q.phase === "loading"
        ? { ...q, lmProgress: Math.max(0, Math.min(99, pct)), lmPhaseLabel: p.phase || q.lmPhaseLabel, _lmRealProgress: true }
        : q));
    });
    return typeof off === "function" ? off : undefined;
  }, [isActive]);

  // Multi-source: list of other data-ready tabs for correlation
  const otherTabs = useMemo(() => tabs.filter(t => t.dataReady && t.id !== ct?.id), [tabs, ct?.id]);

  // Graph derivation can be expensive on large collections. Keep it independent
  // from pan/zoom/selection state so those interactions do not rebuild hundreds
  // of nodes and identity links on every pointer event.
  const lateralGraphModel = useMemo(() => {
    const machineNodes = selectLateralGraphNodes(data?.nodes || []);
    const machineIds = new Set(machineNodes.map((node) => node.id));
    const machineEligibleEdges = (data?.edges || []).filter(
      (edge) => machineIds.has(edge.source) && machineIds.has(edge.target),
    );
    const machineEdges = selectLateralGraphEdges(machineEligibleEdges);
    const identityGraph = buildLateralIdentityGraph(machineNodes, machineEdges);
    const identityNodes = selectLateralGraphNodes(identityGraph.nodes);
    const identityIds = new Set(identityNodes.map((node) => node.id));
    const identityEligibleEdges = identityGraph.edges.filter(
      (edge) => identityIds.has(edge.source) && identityIds.has(edge.target),
    );
    const identityEdges = selectLateralGraphEdges(identityEligibleEdges);
    return {
      machineNodes,
      machineEdges,
      machineEligibleEdgeCount: machineEligibleEdges.length,
      identityGraph,
      identityNodes,
      identityEdges,
      identityEligibleEdgeCount: identityEligibleEdges.length,
    };
  }, [data?.nodes, data?.edges]);

  // Kick the pre-flight preview + KAPE host detection once per open. These ran as bare
  // `if (...) setModal(...)` statements in the render body, mutating store state during
  // render ("Cannot update a component while rendering") and firing IPC as a side effect.
  useEffect(() => {
    if (!isActive || !modal._lmNeedsPreview) return;
    setModal((p) => (p?.type === "lateralMovement" ? { ...p, _lmNeedsPreview: false } : p));
    _handlersRef.current.refreshLmPreview?.();
    if (!modal._kapeHostDetected && tle?.detectKapeCollectionHost) {
      setModal((p) => (p?.type === "lateralMovement" ? { ...p, _kapeHostDetected: true } : p));
      tle.detectKapeCollectionHost(ct.id).then((result) => {
        if (isIpcError(result)) return; // best-effort banner; a failure is not actionable
        if (result && result.collectionHost) {
          setModal((p) => (p?.type === "lateralMovement" ? { ...p, kapeHost: result } : p));
        }
      }).catch(() => {});
    }
  }, [isActive, modal?._lmNeedsPreview, modal?._kapeHostDetected, ct?.id]);

  // Auto-run when launched from a dedicated entry (e.g. the RDP Sessions menu item, or
  // the triage importer's hand-off). Guarded by a ref so it can only fire once per open.
  const _autoStartedRef = useRef(false);
  useEffect(() => {
    if (!isActive) return;
    const wants = modal.autoStart || modal._lmAutoRun;
    if (!wants || modal.phase !== "config" || modal.loading) return;
    if (_autoStartedRef.current) return;
    _autoStartedRef.current = true;
    setModal((p) => (p?.type === "lateralMovement" ? { ...p, autoStart: false, _lmAutoRun: false } : p));
    _handlersRef.current.handleAnalyze?.();
  }, [isActive, modal?.autoStart, modal?._lmAutoRun, modal?.phase, modal?.loading]);

  // Guard: only render when this modal is active
  if (!isActive) return null;

  const { phase, columns: cols = {}, excludeLocal, excludeService } = modal;
  const viewTab = modal.viewTab || "graph";
  const selectedNode = modal.selectedNode;
  const selectedEdge = modal.selectedEdge;
  const positions = modal.positions || {};

  // ── Shared pivot helpers — used by Findings, RDP Sessions, Accounts ──
  const _categoryEids = { "Brute Force": ["4625"], "Password Spray": ["4625"], "Credential Compromise": ["4624", "4625", "4648"], "PsExec Native": ["4688", "1", "7045", "4697"], "Impacket Execution": ["4688", "1", "7045", "4697", "4698"], "Impacket Summary": ["4688", "1", "7045", "4697", "4698"], "Impacket Credential Access": ["4688", "1"], "Remote Service Execution": ["7045", "4697"], "WMI Remote Execution": ["4688", "1"], "WMI Remote Activity": ["4688", "1"], "WinRM Remote Execution": ["4688", "1"], "WinRM Remote Activity": ["4688", "1"], "Scheduled Task Remote Execution": ["4698"], "Admin Share Access": ["5140", "5145"], "Concurrent RDP Sessions": ["4624", "1149", "21", "22"], "RMM Tool": ["4688", "1", "7045", "4697"], "RMM Suspicious Execution": ["4688", "1", "7045", "4697"], "RMM Executed": ["4688", "1", "7045", "4697"], "RMM Installed": ["7045", "4697"], "Remote Access Tunnel": ["4688", "1", "7045", "4697"], "Lateral Pivot": ["4624", "4625", "4648", "4672", "21", "25", "1149"], "First Seen": ["4624", "4625", "4648", "21", "25", "1149"], "Operator Host": ["4624", "4625", "4648", "4776", "4778", "4779", "5140", "5145"], "AS-REP Roasting": ["4768"], "DCSync": ["4662"], "LSASS Access": ["10"], "SAM/LSA Registry Dump": ["4688", "1"], "Port Forwarding": ["4688", "1"], "Kerberoasting": ["4769"] };
  /**
   * Render a timestamp for display, honouring the analyst's timezone and format.
   *
   * Replaces ~30 hand-rolled `.slice(0, 19)` truncations. Those left the ISO "T"
   * separator in place (so the modal showed `2026-03-10T08:00:00` where the grid showed
   * `2026-03-10 08:00:00`) and ignored the timezone setting entirely, so the same event
   * read differently in the grid and in this panel.
   */
  const fmtTs = (raw) => {
    if (!raw) return "";
    return formatDateTime(String(raw), dateTimeFormat || "yyyy-MM-dd HH:mm:ss", timezone) || String(raw).slice(0, 19);
  };
  /** Epoch ms for arithmetic. Naive timestamps are UTC, matching the analyzer. */
  const tsMs = (raw) => normalizeTimestamp(raw);

  /**
   * Shift a timestamp by `deltaMs` and re-render it in the grid's own canonical form.
   * Used to build the ±5 minute window for "Show in Timeline", so the output has to be
   * comparable with the raw column values, not the analyst's display timezone. The old
   * version round-tripped through LOCAL getters after stripping the Z, shifting the
   * window by the host's UTC offset.
   */
  const _padTs = (s, deltaMs) => {
    const ms = normalizeTimestamp(s);
    if (!Number.isFinite(ms)) return s;
    const d = new Date(ms + deltaMs);
    const p = (n) => String(n).padStart(2, "0");
    const sep = String(s).includes("T") ? "T" : " ";
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}${sep}${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  };
  /**
   * Close the modal and show the events behind a finding-shaped object in the grid.
   *
   * Prefers the exact evidence rows: those carry their own {tabId, rowId}, so they land
   * on the RIGHT tab and show exactly the rows the detector fired on.
   *
   * The column-filter path below is a fallback for findings with no evidence refs. It is
   * only sound for a single-tab run: it writes through updateActiveTab (the active tab,
   * whichever that happens to be) using `data.columns`, which in a multi-source run is
   * the FIRST detected tab's mapping — so it could filter tab A on a column that only
   * exists in tab B, and never switch tabs to where the evidence actually lives.
   */
  const _filterEvents = (f, e) => {
    if (e) e.stopPropagation();
    if (_getEvidenceRefs(f).length > 0) { _openExactEvidence(f, null); return; }
    if (data?.multiSource) {
      toast.info("No exact rows for this finding", {
        detail: "Column filters cannot be applied across a multi-source run — open the source tab and filter there.",
      });
      return;
    }
    const lmCols = data?.columns || {};
    const eids = f.filterEids || _categoryEids[f.category];
    const cbf = { ...(ct?.checkboxFilters || {}) };
    if (eids && lmCols.eventId) cbf[lmCols.eventId] = eids;
    if (f.filterHosts?.length > 0 && lmCols.target) cbf[lmCols.target] = f.filterHosts;
    up("checkboxFilters", cbf);
    if (lmCols.ts && f.timeRange?.from) {
      up("dateRangeFilters", { [lmCols.ts]: { from: _padTs(f.timeRange.from, -300000), to: _padTs(f.timeRange.to || f.timeRange.from, 300000) } });
    }
    up("searchTerm", ""); up("columnFilters", {});
    setModal(null);
  };
  /** Switch to Network Graph tab, selecting the edge between f.source and f.target. */
  const _viewInGraph = (f, e) => {
    if (e) e.stopPropagation();
    const edge = data?.edges?.find((ed) => ed.source === f.source && ed.target === f.target);
    const machineNodes = lateralGraphModel.machineNodes;
    let machineEdges = lateralGraphModel.machineEdges;
    if (edge && !machineEdges.includes(edge)) {
      machineEdges = [
        ...machineEdges.slice(0, Math.max(0, LATERAL_GRAPH_DEFAULTS.maxEdges - 1)),
        edge,
      ];
    }
    const machinePositions = computeForceLayout(machineNodes, machineEdges);
    if (edge) {
      const sp = machinePositions[f.source], tp = machinePositions[f.target];
      if (sp && tp) {
        const cx = (sp.x + tp.x) / 2, cy = (sp.y + tp.y) / 2;
        setModal((p) => ({ ...p, viewTab: "graph", lmGraphMode: "machines", positions: machinePositions, selectedEdge: edge, selectedNode: null, viewBox: { x: cx - 120, y: cy - 80, w: 240, h: 160 } }));
      } else setModal((p) => ({ ...p, viewTab: "graph", lmGraphMode: "machines", positions: machinePositions, selectedEdge: edge, selectedNode: null }));
    } else setModal((p) => ({ ...p, viewTab: "graph", lmGraphMode: "machines", positions: machinePositions }));
  };

  const _evidenceLabel = (item) => item?.title || item?.category || item?.technique || item?.sessionId || item?.id || "lateral-movement-evidence";
  const _safeFileToken = (value) => String(value || "lateral-movement-evidence").replace(/[^a-z0-9._-]+/gi, "_").slice(0, 90) || "lateral-movement-evidence";
  const _getEvidenceRefs = (item) => collectEvidenceRefs(item, {
    fallbackTabId: ct.id,
    relatedFindings: data?.findings || [],
    relatedIncidents: data?.incidents || [],
  });

  const _firstValue = (row, names) => {
    if (!row || typeof row !== "object") return "";
    const lowerMap = new Map(Object.keys(row).map((k) => [String(k).toLowerCase(), k]));
    for (const name of names) {
      const key = lowerMap.get(String(name).toLowerCase());
      const value = key != null ? row[key] : undefined;
      if (value != null && String(value).trim() !== "") return String(value).trim();
    }
    return "";
  };
  const _summarizeEvidenceRow = (tabId, rowId, row = {}) => {
    const tab = tabs.find((t) => String(t.id) === String(tabId));
    return {
      tabId,
      rowId,
      tabName: tab?.name || tabId,
      timestamp: _firstValue(row, ["datetime", "timestamp", "timecreated", "time generated", "timegenerated", "utctime", "system_time", "date"]),
      computer: _firstValue(row, ["computer", "computername", "host", "hostname", "endpoint device name", "targethost", "target host", "targethostname"]),
      eventId: _firstValue(row, ["eventid", "event id", "event_id", "id"]),
      channel: _firstValue(row, ["channel", "provider", "providername", "source name", "sourcename", "logname"]),
      user: _firstValue(row, ["targetusername", "subjectusername", "user", "username", "accountname", "account", "source user name"]),
      source: _firstValue(row, ["ipaddress", "sourceip", "source ip", "sourcehost", "source host", "sourcehostname", "workstationname", "clientaddress", "client name", "source"]),
      target: _firstValue(row, ["target", "targethost", "target host", "targethostname", "destinationhostname", "destination host", "computer"]),
      process: _firstValue(row, ["image", "processname", "newprocessname", "process name", "commandline", "command line", "application", "servicefilename"]),
      details: _firstValue(row, ["mapdescription", "description", "message", "details", "extrafieldinfo", "payloaddata1", "payload", "payload_data"]),
      row,
    };
  };
  const _scoreValue = (item) => item?.triageScore ?? item?.riskScore ?? item?.suspicionScore ?? item?.confidenceScore ?? item?.score ?? null;
  const _listify = (value) => {
    if (Array.isArray(value)) return value.filter((v) => v != null && String(v).trim() !== "").map(String);
    if (value == null || value === "") return [];
    return String(value).split(/[,;|]/).map((v) => v.trim()).filter(Boolean);
  };
  const _scoreBreakdown = (item) => {
    const out = [];
    const add = (label, text, color = th.textDim) => {
      if (text == null || text === "") return;
      out.push({ label, text: String(text), color });
    };
    for (const flag of _listify(item?.flags)) add("signal", flag, th.sev.high);
    for (const flag of _listify(item?.confidenceFlags)) add("confidence", flag, th.textDim);
    for (const pill of item?.evidencePills || []) add(pill.type || "evidence", pill.text, _pillColors[pill.type] || th.sev.low);
    for (const cat of _listify(item?.categories || item?.category)) add("category", cat, th.sev.info);
    for (const tech of _listify(item?.techniques || item?.technique || item?.mitre)) add("technique", tech, th.textDim);
    if (item?.eventBreakdown && typeof item.eventBreakdown === "object") {
      for (const [eid, count] of Object.entries(item.eventBreakdown).sort((a, b) => Number(b[1]) - Number(a[1])).slice(0, 8)) add("event", `EID ${eid}: ${count}`, th.textDim);
    }
    const score = _scoreValue(item);
    if (score != null) add("score", `Triage score ${score}`, score >= 50 ? th.sev.critical : score >= 25 ? th.sev.high : score >= 10 ? th.sev.med : th.textDim);
    return out;
  };
  const _entitySummary = (item) => {
    const rows = [
      ["Source", item?.source || item?.from || item?.src],
      ["Target", item?.target || item?.to || item?.dst],
      ["User", _listify(item?.users || item?.user).join(", ")],
      ["Technique", _listify(item?.techniques || item?.technique || item?.mitre).join(", ")],
      ["Category", _listify(item?.categories || item?.category).join(", ")],
      ["First Seen", item?.timeRange?.from || item?.startTime || item?.firstSeen || item?.firstTs],
      ["Last Seen", item?.timeRange?.to || item?.endTime || item?.lastSeen || item?.lastTs],
      ["Events", item?.eventCount ?? item?.count],
    ];
    return rows.filter(([, value]) => value != null && String(value).trim() !== "");
  };
  const _openEvidenceDetail = async (item, e) => {
    if (e) e.stopPropagation();
    const refs = _getEvidenceRefs(item);
    setModal((p) => p?.type === "lateralMovement" ? {
      ...p,
      lmEvidenceItem: item,
      lmEvidenceRefs: refs,
      lmEvidenceTimeline: [],
      lmEvidenceLoading: refs.length > 0,
      lmEvidenceError: null,
    } : p);
    if (!tle || refs.length === 0) return;
    try {
      const grouped = groupEvidenceRefs(refs, ct.id);
      const timeline = [];
      for (const { tabId, rowIds } of grouped.values()) {
        if (timeline.length >= 100) break;
        const ids = [...rowIds].slice(0, 100 - timeline.length);
        const rows = await tle.getRowsByIds(tabId, ids);
        // Unchecked, this rendered N rows of "(no time) / (unknown host)" — a failed
        // fetch was indistinguishable from evidence that genuinely had no fields.
        if (isIpcError(rows)) throw new Error(ipcErrorMessage(rows));
        ids.forEach((rowId, idx) => timeline.push(_summarizeEvidenceRow(tabId, rowId, rows?.[idx] || {})));
      }
      timeline.sort((a, b) => String(a.timestamp || "").localeCompare(String(b.timestamp || "")));
      setModal((p) => p?.type === "lateralMovement" ? { ...p, lmEvidenceTimeline: timeline, lmEvidenceLoading: false } : p);
    } catch (err) {
      setModal((p) => p?.type === "lateralMovement" ? { ...p, lmEvidenceLoading: false, lmEvidenceError: err?.message || "Failed to load exact evidence rows" } : p);
    }
  };
  const _openExactEvidence = (item, e) => {
    if (e) e.stopPropagation();
    const refs = _getEvidenceRefs(item);
    if (refs.length === 0) return;
    const grouped = groupEvidenceRefs(refs, ct.id);
    setTabs((prev) => prev.map((tab) => {
      const hit = grouped.get(String(tab.id));
      if (!hit) return tab;
      return {
        ...tab,
        rowIdFilter: [...hit.rowIds],
        rowIdFilterLabel: _evidenceLabel(item),
        searchTerm: "",
        searchHighlight: false,
        showBookmarkedOnly: false,
        tagFilter: null,
        groupByColumns: [],
        groupData: [],
        expandedGroups: {},
      };
    }));
    const first = [...grouped.values()][0];
    if (first?.tabId) setActiveTab(first.tabId);
    setModal(null);
  };
  const _bookmarkEvidence = async (item, e) => {
    if (e) e.stopPropagation();
    if (!tle || !ct) return;
    const refs = _getEvidenceRefs(item);
    if (refs.length === 0) { toast.info("Nothing to bookmark", { detail: "This item has no linked source rows." }); return; }
    const grouped = groupEvidenceRefs(refs, ct.id);
    try {
      // safeHandle RESOLVES with {__ipcError:true} instead of rejecting, so a bare await
      // looked successful and the optimistic store update below claimed rows were
      // bookmarked when nothing had been written.
      for (const { tabId, rowIds } of grouped.values()) {
        const res = await tle.setBookmarks(tabId, [...rowIds], true);
        if (isIpcError(res)) throw new Error(ipcErrorMessage(res));
      }
      setTabs((prev) => prev.map((tab) => {
        const hit = grouped.get(String(tab.id));
        if (!hit) return tab;
        const bookmarkedSet = new Set(tab.bookmarkedSet || []);
        hit.rowIds.forEach((rowId) => bookmarkedSet.add(rowId));
        return { ...tab, bookmarkedSet };
      }));
      toast.success("Bookmarked", { detail: `${refs.length} evidence row${refs.length === 1 ? "" : "s"}.` });
    } catch (err) {
      // modal.error only renders in the config phase, so setting it here was invisible.
      toast.error("Bookmark failed", { detail: err?.message || "Could not bookmark the evidence rows." });
    }
  };
  /**
   * Write an export through Electron's save dialog.
   *
   * Replaces a synthetic <a download> that revoked its blob URL synchronously after
   * click() and never attached the anchor to the document — fragile for large payloads,
   * and it wrote wherever the browser decided without asking the analyst.
   */
  const _saveExport = async (content, filename, filters) => {
    if (!tle?.saveTextFile) { toast.error("Export unavailable", { detail: "File saving is not available in this window." }); return; }
    try {
      const res = await tle.saveTextFile(content, filename, filters);
      if (isIpcError(res)) { toast.error("Export failed", { detail: ipcErrorMessage(res) }); return; }
      if (res && res.canceled) return;
      toast.success("Exported", { detail: filename });
    } catch (err) {
      toast.error("Export failed", { detail: err?.message || "Could not write the file." });
    }
  };

  /** Suggested tag for an item, also the default in the tag picker. */
  const _defaultTagFor = (item) => `lateral:${String(item?.severity || item?.technique || "evidence")
    .toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "evidence"}`;

  /**
   * Open the in-modal tag picker.
   *
   * This used to call window.prompt(), which Electron does not implement — the call threw
   * ("prompt() is and will not be supported"), so the Tag button silently did nothing and
   * the throw surfaced as an unhandled rejection.
   */
  const _tagEvidence = (item, e) => {
    if (e) e.stopPropagation();
    if (!tle || !ct) return;
    const refs = _getEvidenceRefs(item);
    if (refs.length === 0) { toast.info("Nothing to tag", { detail: "This item has no linked source rows." }); return; }
    setModal((p) => (p?.type === "lateralMovement"
      ? { ...p, lmTagPicker: { item, refCount: refs.length, value: _defaultTagFor(item) } }
      : p));
  };

  /** Apply `tag` to the exact evidence rows of the item currently in the tag picker. */
  const _applyEvidenceTag = async (item, tag) => {
    const finalTag = String(tag || "").trim();
    if (!finalTag || !tle || !ct) return;
    setModal((p) => (p?.type === "lateralMovement" ? { ...p, lmTagPicker: null } : p));
    const refs = _getEvidenceRefs(item);
    if (refs.length === 0) return;
    const grouped = groupEvidenceRefs(refs, ct.id);
    try {
      for (const { tabId, rowIds } of grouped.values()) {
        const tagMap = {};
        for (const rowId of rowIds) tagMap[rowId] = [finalTag];
        const res = await tle.bulkAddTags(tabId, tagMap);
        if (isIpcError(res)) throw new Error(ipcErrorMessage(res));
      }
      setTabs((prev) => prev.map((tab) => {
        const hit = grouped.get(String(tab.id));
        if (!hit) return tab;
        const rowTags = { ...(tab.rowTags || {}) };
        for (const rowId of hit.rowIds) rowTags[rowId] = [...new Set([...(rowTags[rowId] || []), finalTag])];
        return { ...tab, rowTags, tagColors: { ...(tab.tagColors || {}), [finalTag]: th.accent } };
      }));
      toast.success("Tagged", { detail: `${refs.length} row${refs.length === 1 ? "" : "s"} tagged "${finalTag}".` });
    } catch (err) {
      toast.error("Tag failed", { detail: err?.message || "Could not tag the evidence rows." });
    }
  };
  /**
   * Export the exact evidence rows behind an item.
   *
   * Two things were wrong here: the package contained complete raw source rows
   * (command lines with `-p <password>`, `/user:` pairs, cleartext-logon context) with no
   * redaction, and it was written with a synthetic <a download> that bypasses Electron's
   * save dialog. Redacted is now the default and the write goes through saveTextFile;
   * including raw rows takes an explicit, clearly-worded confirmation.
   */
  const _exportEvidencePackage = async (item, e) => {
    if (e) e.stopPropagation();
    if (!tle || !ct) return;
    const refs = _getEvidenceRefs(item);
    if (refs.length === 0) { toast.info("Nothing to export", { detail: "This item has no linked source rows." }); return; }
    try {
      const grouped = groupEvidenceRefs(refs, ct.id);
      const evidence = [];
      for (const { tabId, rowIds } of grouped.values()) {
        const rows = await tle.getRowsByIds(tabId, rowIds);
        // Unchecked, the error object itself was serialized into the on-disk package.
        if (isIpcError(rows)) throw new Error(ipcErrorMessage(rows));
        const tab = tabs.find((t) => String(t.id) === String(tabId));
        evidence.push({ tabId, tabName: tab?.name || tabId, rowIds: [...rowIds], rows: (rows || []).map(redactRow) });
      }
      const payload = {
        exportedAt: new Date().toISOString(),
        kind: "lateral-movement-evidence",
        subject: _evidenceLabel(item),
        evidenceRefCount: refs.length,
        redacted: true,
        redactionNote: "Credential-bearing values are masked. Generated by IRFlow Timeline.",
        item,
        evidence,
      };
      const name = `${_safeFileToken(_evidenceLabel(item))}-evidence.json`;
      const res = await tle.saveTextFile(JSON.stringify(payload, null, 2), name, [{ name: "JSON", extensions: ["json"] }]);
      if (isIpcError(res)) { toast.error("Export failed", { detail: ipcErrorMessage(res) }); return; }
      if (res && res.canceled) return;
      toast.success("Evidence exported", { detail: `${refs.length} row${refs.length === 1 ? "" : "s"}, credentials masked.` });
    } catch (err) {
      toast.error("Export failed", { detail: err?.message || "Could not export the evidence package." });
    }
  };
  const EvidenceActions = ({ item, compact = false, hideDetails = false }) => {
    const refs = _getEvidenceRefs(item);
    if (refs.length === 0) return null;
    const btn = {
      padding: compact ? "1px 5px" : "2px 8px",
      background: `${th.accent}12`,
      color: th.accent,
      border: `1px solid ${th.accent}33`,
      borderRadius: 4,
      fontSize: LM_TYPOGRAPHY.badge,
      cursor: "pointer",
      fontFamily: "-apple-system, sans-serif",
      fontWeight: 600,
      whiteSpace: "nowrap",
    };
    return (
      <div onClick={(ev) => ev.stopPropagation()} style={{ display: "flex", gap: 4, flexWrap: "wrap", alignItems: "center" }}>
        {!hideDetails && <button onClick={(ev) => _openEvidenceDetail(item, ev)} style={btn} title="Show score, entities, and exact source-row evidence for this item">Details</button>}
        <button onClick={(ev) => _openExactEvidence(item, ev)} style={btn} title="Filter the source timeline tab(s) to the exact evidence rows">Open exact</button>
        <button onClick={(ev) => _bookmarkEvidence(item, ev)} style={btn} title="Bookmark the exact source rows behind this item">Bookmark</button>
        <button onClick={(ev) => _tagEvidence(item, ev)} style={btn} title="Tag the exact source rows behind this item">Tag</button>
        <button onClick={(ev) => _exportEvidencePackage(item, ev)} style={btn} title="Export this item and exact source rows as JSON">Export package</button>
        {!compact && <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "monospace" }}>{refs.length} refs</span>}
      </div>
    );
  };
  const EvidenceDetailDrawer = () => {
    const item = modal.lmEvidenceItem;
    if (!item) return null;
    const refs = modal.lmEvidenceRefs || _getEvidenceRefs(item);
    const timeline = modal.lmEvidenceTimeline || [];
    const score = _scoreValue(item);
    const breakdown = _scoreBreakdown(item);
    const entities = _entitySummary(item);
    const sev = String(item.severity || item.confidence || (score >= 50 ? "critical" : score >= 25 ? "high" : score >= 10 ? "medium" : "info")).toLowerCase();
    const sevColor = LM_SEV_COLORS[sev] || th.sev.info;
    const close = () => setModal((p) => p?.type === "lateralMovement" ? { ...p, lmEvidenceItem: null, lmEvidenceRefs: [], lmEvidenceTimeline: [], lmEvidenceLoading: false, lmEvidenceError: null } : p);
    return (
      <div style={{ marginBottom: 12, border: `1px solid ${sevColor}44`, borderRadius: 10, background: `linear-gradient(135deg, ${sevColor}0d, ${th.panelBg}ee)`, overflow: "hidden" }}>
        <div style={{ padding: "10px 12px", borderBottom: `1px solid ${sevColor}25`, display: "flex", alignItems: "flex-start", gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 8, background: `${sevColor}18`, color: sevColor, border: `1px solid ${sevColor}30`, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, fontSize: LM_TYPOGRAPHY.body, fontFamily: "monospace", flexShrink: 0 }}>
            {score ?? refs.length}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", marginBottom: 2 }}>
              <span style={{ padding: "1px 6px", background: `${sevColor}22`, color: sevColor, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, textTransform: "uppercase", fontFamily: "-apple-system, sans-serif" }}>{sev}</span>
              <span style={{ fontSize: LM_TYPOGRAPHY.title, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.1px" }}>{_evidenceLabel(item)}</span>
            </div>
            <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>
              Exact evidence drill-down. Actions below operate on source timeline rows across all involved tabs.
            </div>
          </div>
          <EvidenceActions item={item} hideDetails />
          <button onClick={close} style={{ width: 22, height: 22, borderRadius: 11, border: "none", background: th.textMuted + "14", color: th.textMuted, cursor: "pointer", fontSize: LM_TYPOGRAPHY.title, flexShrink: 0 }}>{"\u00D7"}</button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "minmax(260px, 0.9fr) minmax(320px, 1.2fr)", gap: 10, padding: 12 }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 6, marginBottom: 10 }}>
              <div style={{ padding: "7px 9px", background: th.bg + "88", border: `1px solid ${th.border}33`, borderRadius: 6 }}>
                <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em" }}>Score</div>
                <div style={{ fontSize: LM_TYPOGRAPHY.metric, color: sevColor, fontWeight: 800, fontFamily: "monospace", marginTop: 2 }}>{score ?? "N/A"}</div>
              </div>
              <div style={{ padding: "7px 9px", background: th.bg + "88", border: `1px solid ${th.border}33`, borderRadius: 6 }}>
                <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em" }}>Evidence Rows</div>
                <div style={{ fontSize: LM_TYPOGRAPHY.metric, color: th.text, fontWeight: 800, fontFamily: "monospace", marginTop: 2 }}>{refs.length}</div>
              </div>
            </div>

            {entities.length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700, marginBottom: 5, fontFamily: "-apple-system, sans-serif" }}>Entities</div>
                <div style={{ display: "grid", gridTemplateColumns: "90px minmax(0, 1fr)", gap: "4px 8px", fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}>
                  {entities.map(([label, value]) => (
                    <Fragment key={label}>
                      <div style={{ color: th.textMuted, fontWeight: 600 }}>{label}</div>
                      <div style={{ color: th.text, minWidth: 0, overflowWrap: "anywhere", lineHeight: 1.35 }}>{String(value).slice(0, 300)}</div>
                    </Fragment>
                  ))}
                </div>
              </div>
            )}

            <div>
              <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700, marginBottom: 5, fontFamily: "-apple-system, sans-serif" }}>Why It Ranked Here</div>
              {breakdown.length > 0 ? (
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {breakdown.slice(0, 14).map((r, idx) => (
                    <div key={`${r.label}-${idx}`} style={{ display: "flex", gap: 6, alignItems: "flex-start", padding: "4px 6px", borderRadius: 5, background: `${r.color}0f`, border: `1px solid ${r.color}22`, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}>
                      <span style={{ color: r.color, fontSize: LM_TYPOGRAPHY.badge, textTransform: "uppercase", fontWeight: 800, minWidth: 58 }}>{r.label}</span>
                      <span style={{ color: th.textDim, lineHeight: 1.35, overflowWrap: "anywhere" }}>{r.text}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>No explicit scoring details were stored for this item. Use the exact evidence timeline to review the source rows.</div>
              )}
            </div>
          </div>

          <div style={{ minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 5 }}>
              <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>Exact Evidence Timeline</div>
              {refs.length > timeline.length && <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "monospace" }}>showing {timeline.length} of {refs.length}</div>}
            </div>
            {modal.lmEvidenceLoading ? (
              <div style={{ padding: 18, textAlign: "center", color: th.textMuted, fontSize: LM_TYPOGRAPHY.body, border: `1px solid ${th.border}22`, borderRadius: 6, background: th.bg + "55" }}>Loading source rows...</div>
            ) : modal.lmEvidenceError ? (
              <div style={{ padding: 10, color: th.danger, fontSize: LM_TYPOGRAPHY.body, border: `1px solid ${th.danger}33`, borderRadius: 6, background: th.danger + "12" }}>{modal.lmEvidenceError}</div>
            ) : timeline.length === 0 ? (
              <div style={{ padding: 18, textAlign: "center", color: th.textMuted, fontSize: LM_TYPOGRAPHY.body, border: `1px solid ${th.border}22`, borderRadius: 6, background: th.bg + "55" }}>No exact source rows were attached to this item.</div>
            ) : (
              <div style={{ maxHeight: 290, overflow: "auto", border: `1px solid ${th.border}33`, borderRadius: 6, background: th.bg + "55" }}>
                {timeline.map((row, idx) => (
                  <div key={`${row.tabId}-${row.rowId}-${idx}`} style={{ padding: "7px 8px", borderBottom: idx < timeline.length - 1 ? `1px solid ${th.border}18` : "none", display: "grid", gridTemplateColumns: "120px minmax(0, 1fr)", gap: 8, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}>
                    <div style={{ color: th.textMuted, fontFamily: "monospace", lineHeight: 1.45 }}>
                      <div>{row.timestamp ? fmtTs(row.timestamp) : "(no time)"}</div>
                      <div style={{ fontSize: LM_TYPOGRAPHY.badge, overflowWrap: "anywhere" }}>{row.tabName} #{row.rowId}</div>
                      {row.eventId && <div style={{ color: th.accent, fontSize: LM_TYPOGRAPHY.badge }}>EID {row.eventId}</div>}
                    </div>
                    <div style={{ minWidth: 0, color: th.textDim, lineHeight: 1.45 }}>
                      <div style={{ color: th.text, fontWeight: 600, overflowWrap: "anywhere" }}>{row.computer || row.target || "(unknown host)"}</div>
                      <div style={{ overflowWrap: "anywhere" }}>{row.source || "\u2014"} {row.target || row.computer ? "\u2192" : ""} {row.target || row.computer || ""}</div>
                      {(row.user || row.process) && <div style={{ overflowWrap: "anywhere" }}>{row.user && <span>User: {row.user}</span>}{row.user && row.process ? " | " : ""}{row.process && <span>Process: {row.process}</span>}</div>}
                      {(row.channel || row.details) && <div style={{ color: th.textMuted, overflowWrap: "anywhere" }}>{row.channel}{row.channel && row.details ? " | " : ""}{row.details ? row.details.slice(0, 260) : ""}</div>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  const computeForceLayout = (nodes, edges) =>
    layoutLateralMovementGraph(nodes, edges).positions;

  // `detector` maps a rule to detector ids in electron/analyzers/lateral-movement/
  // detector-registry.js. The analyzer derives which events to fetch from the enabled
  // detectors, so this table no longer decides the query — it only decides what the
  // analyst can switch off. New rules must be APPENDED: LM_PRESETS and LM_INTENTS
  // reference rules by index.
  const LM_RULES = [
    { cat: "RDP Session", name: "Network Authentication", sev: "high", eids: ["1149"], hint: "RemoteConnectionManager", detector: "rdp-sessions" },
    { cat: "RDP Session", name: "Session Logon", sev: "medium", eids: ["21"], hint: "LocalSessionManager", detector: "rdp-sessions" },
    { cat: "RDP Session", name: "Shell Start Notification", sev: "low", eids: ["22"], hint: "LocalSessionManager", detector: "rdp-sessions" },
    { cat: "RDP Session", name: "Session Logoff", sev: "low", eids: ["23"], hint: "LocalSessionManager", detector: "rdp-sessions" },
    { cat: "RDP Session", name: "Session Disconnected", sev: "low", eids: ["24"], hint: "LocalSessionManager", detector: "rdp-sessions" },
    { cat: "RDP Session", name: "Session Reconnected", sev: "medium", eids: ["25"], hint: "LocalSessionManager", detector: "rdp-sessions" },
    { cat: "RDP Session", name: "Disconnect by Other / Reason", sev: "low", eids: ["39", "40"], hint: "LocalSessionManager", detector: "rdp-sessions" },
    { cat: "Security Logon", name: "Successful Logon", sev: "high", eids: ["4624"], hint: "Types 2,3,7,8,9,10,11,12" },
    { cat: "Security Logon", name: "Failed Logon", sev: "high", eids: ["4625"], hint: "All logon types", detector: ["bruteforce", "password-spray", "cred-compromise"] },
    { cat: "Security Logon", name: "Explicit Credentials (RunAs)", sev: "high", eids: ["4648"], hint: "Alternate credential usage", detector: "explicit-creds" },
    { cat: "Privileges", name: "Admin Privileges Assigned", sev: "high", eids: ["4672"], hint: "Special privileges at logon", detector: "admin-priv" },
    { cat: "Session Lifecycle", name: "Session Reconnect / Disconnect", sev: "medium", eids: ["4778", "4779"], hint: "Window Station events", detector: "rdp-sessions" },
    { cat: "Session Lifecycle", name: "Account Logoff", sev: "low", eids: ["4634", "4647"], hint: "Logoff / user-initiated logoff" },
    { cat: "RMM / Remote Access", name: "RMM Tool Detection", sev: "high", eids: ["4688", "1", "7045", "4697"], hint: "AnyDesk, ScreenConnect, TeamViewer, etc.", detector: "rmm" },
    { cat: "RMM / Remote Access", name: "Scheduled Task Execution", sev: "medium", eids: ["4698", "4688", "1"], hint: "Remote schtasks /create /s", detector: "schtask" },
    // Appended: these detectors ship in the analyzer but their events were never
    // requested, so they could not fire. Surfacing them here also makes them toggleable.
    { cat: "Share Access", name: "Admin Share Access", sev: "high", eids: ["5140", "5145"], hint: "ADMIN$, C$, IPC$ + named-pipe attribution", detector: "adminshare" },
    { cat: "Security Logon", name: "NTLM Authentication", sev: "medium", eids: ["4776"], hint: "Credential validation / operator-host signal", detector: "ntlm" },
    { cat: "RDP Session", name: "Shadow / Session Takeover", sev: "high", eids: ["20", "32", "33", "34", "35"], hint: "RDP shadowing and session hijack", detector: "rdp-shadow" },
    { cat: "Kerberos", name: "Service Ticket Requests", sev: "low", eids: ["4769"], hint: "Kerberos TGS — also feeds Kerberoasting", detector: "kerberos-tickets" },
  ];
  const LM_SEV_COLORS = { critical: th.sev.critical, high: th.sev.high, medium: th.sev.med, low: th.sev.low };
  // Evidence-pill colors: pure brand palette — accent for the strong action signals
  // (credential abuse / execution), neutral grays for context. No blue/green (Unit 42 theme).
  // Tone -> colour, matching primitives/Badge.jsx exactly so an evidence pill renders the
  // same in this modal as in the grid's Evidence column. `pillToneFor` (evidence-pills.js)
  // is the single authority for which tone a pill type gets.
  //
  // The previous map painted `credential` and `execution` in th.accent — the BRAND colour,
  // which the design system reserves for actions and never for risk. That both broke the
  // convention and made identical pills two different colours in two adjacent views.
  const TONE_COLOR = {
    accent: th.accent, success: th.success, warning: th.warning, danger: th.danger,
    critical: th.sev.critical, high: th.sev.high, med: th.sev.med, medium: th.sev.med,
    low: th.sev.low, custom: th.sev.custom, clean: th.sev.clean, info: th.sev.info,
    neutral: th.textDim,
  };
  const pillColor = (type) => TONE_COLOR[pillToneFor(type)] || th.textDim;
  const _pillColors = Object.fromEntries(
    ["credential", "execution", "correlation", "target", "context"].map((t) => [t, pillColor(t)]),
  );
  const LM_PRESETS = [
    { id: "rdp", name: "RDP Analysis", desc: "Remote Desktop session lifecycle — authentication, logon, shell start, disconnect, reconnect", rules: [0, 1, 2, 3, 4, 5, 6],
      icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg> },
    { id: "auth", name: "Authentication Tracking", desc: "Logon success/failure, explicit credential usage (RunAs), admin privilege assignment", rules: [7, 8, 9, 10],
      icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> },
    { id: "session", name: "Session Lifecycle", desc: "Session reconnect/disconnect and account logoff events for timeline correlation", rules: [11, 12],
      icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> },
    { id: "rmm", name: "RMM / Remote Access", desc: "AnyDesk, ScreenConnect, TeamViewer, RustDesk, ngrok, Tailscale — process execution and service installs", rules: [13, 14],
      icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> },
  ];
  const lmPresetState = (presetRules, disabledSet) => {
    const offCount = presetRules.filter(i => disabledSet.has(`lm-${i}`)).length;
    return offCount === 0 ? "on" : offCount === presetRules.length ? "off" : "partial";
  };
  const toggleLmPreset = (preset) => setModal((p) => {
    const s = new Set(p.lmDisabledRules || []);
    const state = lmPresetState(preset.rules, s);
    if (state === "on") { preset.rules.forEach(i => s.add(`lm-${i}`)); }
    else { preset.rules.forEach(i => s.delete(`lm-${i}`)); }
    return { ...p, lmDisabledRules: s };
  });
  const lmCoverageInfo = (colMap) => {
    const required = [["source", "Source Host"], ["target", "Target Host"], ["eventId", "Event ID"], ["ts", "Timestamp"]];
    const recommended = [["user", "User"], ["logonType", "Logon Type"]];
    const optional = [["domain", "Domain"]];
    const mapped = k => !!colMap[k];
    const reqOk = required.filter(([k]) => mapped(k)).length;
    const recOk = recommended.filter(([k]) => mapped(k)).length;
    const level = reqOk === 4 && recOk === 2 ? "high" : reqOk === 4 ? "medium" : "low";
    return { required, recommended, optional, reqOk, recOk, level, mapped };
  };
  const LM_INTENTS = [
    { id: "low-noise", label: "Low-noise triage", desc: "High-confidence detections only — RDP + auth, suspicious RMM only", disabled: new Set(["lm-2","lm-3","lm-4","lm-5","lm-6","lm-11","lm-12","lm-14"]), rmmMode: "suspicious" },
    { id: "balanced", label: "Balanced", desc: "Recommended for most investigations — all techniques enabled", disabled: new Set(), rmmMode: "all" },
    { id: "broad", label: "Broad hunt", desc: "Maximum coverage — all rules plus session lifecycle for full timeline", disabled: new Set(), rmmMode: "all" },
  ];
  const applyLmIntent = (intent) => setModal((p) => ({ ...p, lmDisabledRules: new Set(intent.disabled), lmIntent: intent.id, lmRmmMode: intent.rmmMode }));
  const resetLmRules = () => setModal((p) => ({ ...p, lmDisabledRules: new Set(), lmIntent: "balanced", lmRmmMode: "all" }));
  const LM_EVENT_GROUPS = [
    { label: "Auth", eids: ["4624","4625"], required: true, detector: "Brute Force, Password Spray, Credential Compromise" },
    { label: "NTLM Auth", eids: ["4776"], required: false, detector: "NTLM authentication, Operator Host detection" },
    { label: "Explicit Creds", eids: ["4648"], required: false, detector: "Credential Compromise (RunAs)" },
    { label: "Admin Priv", eids: ["4672"], required: false, detector: "Admin privilege tracking" },
    { label: "RDP Auth", eids: ["1149"], required: false, detector: "RDP session correlation" },
    { label: "RDP Session", eids: ["21","22","25"], required: false, detector: "RDP lifecycle chains" },
    { label: "Sched Task", eids: ["4698"], required: false, detector: "Scheduled Task execution" },
    { label: "Share Access", eids: ["5140","5145"], required: false, detector: "Admin Share (ADMIN$, C$, IPC$)" },
    { label: "Svc Install", eids: ["7045","4697"], required: false, detector: "Remote Service Execution, RMM install" },
    { label: "Process", eids: ["4688","1"], required: false, detector: "WMI/WinRM, Impacket, RMM execution" },
  ];
  const lmSkipWarnings = (evCounts) => {
    const warnings = [];
    const has = (eids) => eids.some(e => (evCounts[e] || 0) > 0);
    if (!has(["4624","4625"])) warnings.push({ level: "error", text: "No logon events (4624/4625) — core detection unavailable" });
    if (!has(["1149","21","22"])) warnings.push({ level: "warn", text: "No RDP events (1149/21/22) — RDP session confidence reduced" });
    if (!has(["4698"])) warnings.push({ level: "info", text: "No Scheduled Task events (4698) — schtasks detection unavailable" });
    if (!has(["5140","5145"])) warnings.push({ level: "info", text: "No share access events (5140/5145) — Admin Share detection unavailable" });
    if (!has(["7045","4697"])) warnings.push({ level: "info", text: "No service install events (7045/4697) — service execution + RMM install detection unavailable" });
    if (!has(["4688","1"])) warnings.push({ level: "info", text: "No process events (4688/1) — WMI/WinRM/Impacket/RMM execution detection unavailable" });
    if (!has(["4648"])) warnings.push({ level: "info", text: "No explicit cred events (4648) — RunAs detection unavailable" });
    return warnings;
  };
  const LM_DETECTOR_BLURBS = {
    "Successful Logon": "Tracks Type 3/10 logons for network and RDP access patterns",
    "Failed Logon": "Brute force and password spray — fail bursts before success",
    "Explicit Credentials (RunAs)": "Credential compromise — same user fail then success with alternate creds",
    "Admin Privileges Assigned": "Flags 4672 at logon — admin rights on target host",
    "Network Authentication": "RDP pre-auth — source IP visible before session starts",
    "Session Logon": "RDP confirmed — user shell active on target",
    "Shell Start Notification": "Explorer.exe started — interactive session live",
    "Session Reconnected": "RDP reconnect — attacker returning to dormant session",
    "Session Disconnected": "Graceful/forced disconnect — session may persist",
    "Session Logoff": "Clean session close — bounds the activity window",
    "Disconnect by Other / Reason": "Another session took over — concurrent access indicator",
    "Session Reconnect / Disconnect": "Window station events — 4778/4779 session tracking",
    "Account Logoff": "Session end markers — needed for duration analysis",
    "RMM Tool Detection": "AnyDesk, ScreenConnect, TeamViewer, RustDesk + 24 more — context-scored by parent process, path, and host role",
    "Scheduled Task Execution": "Remote schtasks /create /s — correlated with nearby Type 3 logons for lateral movement confidence",
  };
  const MITRE_MAP = {
    "T1110.001": { name: "Brute Force: Password Guessing", url: "https://attack.mitre.org/techniques/T1110/001/" },
    "T1110.003": { name: "Brute Force: Password Spraying", url: "https://attack.mitre.org/techniques/T1110/003/" },
    "T1078": { name: "Valid Accounts", url: "https://attack.mitre.org/techniques/T1078/" },
    "T1021": { name: "Remote Services", url: "https://attack.mitre.org/techniques/T1021/" },
    "T1569.002": { name: "System Services: Service Execution", url: "https://attack.mitre.org/techniques/T1569/002/" },
    "T1219": { name: "Remote Access Software", url: "https://attack.mitre.org/techniques/T1219/" },
  };
  const MitreBadge = ({ id }) => {
    const m = MITRE_MAP[id];
    if (!m) return null;
    return <span onClick={(e) => { e.stopPropagation(); window.open(m.url, "_blank"); }} title={m.name} style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "1px 6px", background: th.textMuted + "18", color: th.textDim, border: `1px solid ${th.textMuted}33`, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "monospace", cursor: "pointer", fontWeight: 600, letterSpacing: "0.02em", transition: "all var(--m-base)" }} onMouseEnter={(e) => { e.currentTarget.style.background = th.textMuted + "30"; e.currentTarget.style.color = th.accent; }} onMouseLeave={(e) => { e.currentTarget.style.background = th.textMuted + "18"; e.currentTarget.style.color = th.textDim; }}>{id}</span>;
  };
  const lmDisabledSet = modal.lmDisabledRules instanceof Set ? modal.lmDisabledRules : new Set(modal.lmDisabledRules || []);
  const lmActiveCount = LM_RULES.length - [...lmDisabledSet].filter((k) => k.startsWith("lm-")).length;
  const lmCustomRulesArr = Array.isArray(modal.lmCustomRules) ? modal.lmCustomRules : [];
  const lmCustomCount = lmCustomRulesArr.length;
  const toggleLmRule = (key) => setModal((p) => { const s = new Set(p.lmDisabledRules || []); s.has(key) ? s.delete(key) : s.add(key); return { ...p, lmDisabledRules: s }; });
  const deleteLmCustomRule = (idx) => setModal((p) => ({ ...p, lmCustomRules: (p.lmCustomRules || []).filter((_, i) => i !== idx) }));
  const addLmCustomRule = () => {
    const nr = modal.lmNewRule || {};
    if (!nr.name && !nr.eventIds) return;
    setModal((p) => ({ ...p, lmCustomRules: [...(p.lmCustomRules || []), { ...nr }], lmAddingRule: false, lmNewRule: {} }));
  };
  const refreshLmPreview = (colOverrides) => {
    if (!tle?.previewLateralMovement || !ct) return;
    clearTimeout(_lmPreviewTimerRef.current);
    _lmPreviewTimerRef.current = setTimeout(() => {
      // Sequence token is read from the store, bumped once, then the IPC is issued
      // OUTSIDE the updater — issuing it inside meant a side effect ran from a Zustand
      // state callback, which React may invoke more than once.
      const seq = (useUIStore.getState().modal?._lmPreviewSeq || 0) + 1;
      const p = useUIStore.getState().modal;
      if (!p || p.type !== "lateralMovement") return;
      const c = colOverrides || p.columns || {};
      const af = _activeFilters(ct);
      setModal((q) => (q?.type === "lateralMovement" ? { ...q, lmPreviewLoading: true, lmPreviewError: null, _lmPreviewSeq: seq } : q));
      tle.previewLateralMovement(ct.id, {
        sourceCol: c.source, targetCol: c.target, userCol: c.user,
        logonTypeCol: c.logonType, eventIdCol: c.eventId, tsCol: c.ts, domainCol: c.domain,
        syntheticTargetHost: p.chainsawSyntheticTarget || "",
        excludeLocalLogons: p.excludeLocal, excludeServiceAccounts: p.excludeService,
        searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
      }).then((prev) => {
        // An unchecked IPC error used to be stored AS the preview, so the availability
        // panel reported 0 for every event group and warned "no logon events — core
        // detection unavailable" when the real problem was a failed query.
        if (isIpcError(prev)) {
          setModal((q) => q?.type === "lateralMovement" && (q._lmPreviewSeq || 0) === seq
            ? { ...q, lmPreview: null, lmPreviewLoading: false, lmPreviewError: ipcErrorMessage(prev) } : q);
          return;
        }
        setModal((q) => q?.type === "lateralMovement" && (q._lmPreviewSeq || 0) === seq
          ? { ...q, lmPreview: prev, lmPreviewLoading: false, lmPreviewError: null } : q);
      }).catch((err) => {
        setModal((q) => q?.type === "lateralMovement" && (q._lmPreviewSeq || 0) === seq
          ? { ...q, lmPreviewLoading: false, lmPreviewError: err?.message || "Preview failed" } : q);
      });
    }, 600);
  };

  /**
   * Cancel really cancels now. Bumping the run token alone would only stop the result
   * from being committed — the analyzer would keep burning a worker thread on a
   * multi-GB tab. The job manager already exposes cancellation; nothing was calling it.
   */
  const cancelAnalysis = async () => {
    _runSeqRef.current = -1;
    setModal((p) => (p?.type === "lateralMovement"
      ? { ...p, phase: "config", loading: false, lmProgress: 0, lmRunSeq: (p.lmRunSeq || 0) + 1 }
      : p));
    if (!tle?.listJobs || !tle?.cancelJob) return;
    try {
      const jobs = await tle.listJobs();
      if (isIpcError(jobs) || !Array.isArray(jobs)) return;
      // Match on the analyzer method so a concurrently running Persistence or Ransomware
      // job is not killed alongside ours.
      const mine = jobs.filter((j) => j?.status === "running"
        && (j?.metadata?.method === "getLateralMovement" || j?.metadata?.method === "getMultiSourceLateralMovement"));
      await Promise.all(mine.map((j) => tle.cancelJob(j.id).catch(() => {})));
    } catch { /* the run token already protects state; cancellation is best-effort */ }
  };

  const handleAnalyze = async (overrides = {}) => {
    // Resolve filter values: caller-supplied overrides take precedence over current modal state.
    // Needed because callers like the "Open RDP Sessions" launcher set new state and call us
    // immediately — without overrides, we'd close over the stale render-time `modal` value.
    const effExcludeLocal = overrides.excludeLocal != null ? overrides.excludeLocal : modal.excludeLocal;
    const effExcludeService = overrides.excludeService != null ? overrides.excludeService : modal.excludeService;
    // Run token. The old `_cancelled` boolean was reset to false at the start of every
    // run, so pressing Cancel and immediately re-running let run #1's late result pass
    // the guard and overwrite run #2 — and a result from a closed modal could hijack a
    // freshly reopened one. A monotonic sequence cannot be un-cancelled: only the run
    // whose token still matches the store is allowed to commit.
    const seq = (useUIStore.getState().modal?.lmRunSeq || 0) + 1;
    _runSeqRef.current = seq;
    const isCurrentRun = (p) => p?.type === "lateralMovement" && p.lmRunSeq === seq;

    const t0 = Date.now();
    const pInt = setInterval(() => {
      setModal((p) => {
        if (!isCurrentRun(p) || p.phase !== "loading") { clearInterval(pInt); return p; }
        // Real per-stage progress arrives on the analysis-progress channel; this eased
        // curve is only a fallback for when the analyzer reports nothing.
        if (p._lmRealProgress) return p;
        const el = (Date.now() - t0) / 1000;
        const prog = Math.min(92, 90 * (1 - Math.exp(-el / 8)));
        const pi = prog < 10 ? 0 : prog < 35 ? 1 : prog < 60 ? 2 : prog < 80 ? 3 : 4;
        return { ...p, lmProgress: prog, lmPhaseIdx: pi };
      });
    }, 150);
    setModal((p) => ({ ...p, phase: "loading", loading: true, error: null, lmProgress: 0, lmPhaseIdx: 0, lmRunSeq: seq, _lmRealProgress: false, excludeLocal: effExcludeLocal, excludeService: effExcludeService }));
    try {
      // Send which DETECTORS are on, not which event ids to fetch. The analyzer derives
      // the query from its detector registry, so a detector can no longer be starved of
      // the events it needs by an out-of-date list here. A detector is only disabled when
      // every rule that references it is off — several RDP rules share `rdp-sessions`,
      // and switching off "Shell Start Notification" must not kill session reconstruction.
      const _detectorRules = new Map(); // detectorId -> { total, off }
      LM_RULES.forEach((r, i) => {
        const ids = Array.isArray(r.detector) ? r.detector : (r.detector ? [r.detector] : []);
        const off = lmDisabledSet.has(`lm-${i}`);
        for (const id of ids) {
          const entry = _detectorRules.get(id) || { total: 0, off: 0 };
          entry.total += 1;
          if (off) entry.off += 1;
          _detectorRules.set(id, entry);
        }
      });
      const disabledDetectors = [..._detectorRules.entries()]
        .filter(([, v]) => v.total > 0 && v.off === v.total)
        .map(([id]) => id);
      const extraEventIds = [];
      lmCustomRulesArr.forEach((cr) => {
        (cr.eventIds || "").split(",").map((s) => s.trim()).filter(Boolean).forEach((id) => extraEventIds.push(id));
      });

      const isMultiSource = modal.lmMultiSource && (modal.lmSelectedTabIds || []).length > 0;
      let result;

      if (isMultiSource) {
        // Multi-source: merge events from current tab + selected tabs
        // Pass both IDs and labels so the backend can label results
        const allIds = [ct.id, ...(modal.lmSelectedTabIds || [])];
        const tabLabels = {};
        for (const t of tabs) { tabLabels[t.id] = t.name; }
        result = await tle.getMultiSourceLateralMovement(allIds, {
          extraEventIds, excludeLocalLogons: effExcludeLocal, excludeServiceAccounts: effExcludeService,
          disabledDetectors, rmmMode: modal.lmRmmMode || "all",
          _tabLabels: tabLabels,
        });
      } else {
        // Single-tab analysis (existing behavior)
        const af = _activeFilters(ct);
        result = await tle.getLateralMovement(ct.id, {
          sourceCol: cols.source, targetCol: cols.target, userCol: cols.user,
          logonTypeCol: cols.logonType, eventIdCol: cols.eventId, tsCol: cols.ts, domainCol: cols.domain,
          syntheticTargetHost: modal.chainsawSyntheticTarget || "",
          extraEventIds, excludeLocalLogons: effExcludeLocal, excludeServiceAccounts: effExcludeService,
          disabledDetectors, rmmMode: modal.lmRmmMode || "all",
          searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
          columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
          bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        });
      }

      clearInterval(pInt);
      if (isIpcError(result)) {
        setModal((p) => isCurrentRun(p) ? { ...p, phase: "config", loading: false, error: ipcErrorMessage(result), lmProgress: 0 } : p);
      } else {
        setModal((p) => isCurrentRun(p) ? { ...p, lmProgress: 100, lmPhaseIdx: 5 } : p);
        await new Promise((r) => setTimeout(r, 300));
        const layoutNodes = selectLateralGraphNodes(result.nodes);
        const layoutIds = new Set(layoutNodes.map((n) => n.id));
        const layoutEdges = selectLateralGraphEdges(
          result.edges.filter((e) => layoutIds.has(e.source) && layoutIds.has(e.target)),
        );
        const pos = computeForceLayout(layoutNodes, layoutEdges);
        setModal((p) => isCurrentRun(p) ? {
          ...p,
          phase: "results",
          loading: false,
          data: result,
          positions: pos,
          lmGraphMode: "machines",
          selectedNode: null,
          selectedEdge: null,
          viewBox: {
            x: 0,
            y: 0,
            w: LATERAL_GRAPH_DEFAULTS.width,
            h: LATERAL_GRAPH_DEFAULTS.height,
          },
          viewTab: p._lmInitialView || "graph",
          truncatedGraph: result.nodes.length > LATERAL_GRAPH_DEFAULTS.maxNodes,
          rdpViewMode: p._lmInitialRdpView || "grouped",
          lmAlertLimit: 300,
          lmEdgeLimit: 400,
        } : p);
        // Keep the finished run on the tab so closing the modal is not destructive. This
        // is deliberately IN-MEMORY (session lifetime) and deliberately NOT part of
        // buildSessionPayload — a findings array for a large collection is megabytes, and
        // that payload is shared by every save/restore in the app.
        try {
          useTabStore.getState().updateTab(ct.id, {
            lmLastRun: { data: result, positions: pos, completedAt: Date.now(), multiSource: !!result.multiSource },
          });
        } catch { /* resume is a convenience, never block the result */ }
        // Distribute finding-level evidence pills to per-row map so the main
        // grid Evidence column shows LM pills inline. Uses the same helper as
        // PersistenceModal — findings now carry itemRowids from the scan loop.
        const _lmPillMap = buildPillsByRowid(result.findings || []);
        if (Object.keys(_lmPillMap).length > 0) {
          // Merge with any existing pills (e.g. from Persistence) rather than replacing
          const existing = ct?.evidencePillsByRowid || {};
          const merged = { ...existing };
          for (const [rid, pills] of Object.entries(_lmPillMap)) {
            if (!merged[rid]) { merged[rid] = pills; continue; }
            const seen = new Set(merged[rid].map(p => p.text));
            for (const p of pills) { if (!seen.has(p.text)) { merged[rid].push(p); seen.add(p.text); } }
          }
          useTabStore.getState().updateTab(ct.id, { evidencePillsByRowid: merged });
        }
      }
    } catch (e) {
      clearInterval(pInt);
      setModal((p) => isCurrentRun(p) ? { ...p, phase: "config", loading: false, error: e.message } : p);
    }
  };

  const logonColor = (types) => {
    const t = new Set(types.map(String));
    if (t.has("10") || t.has("12")) return th.sev.info;
    if (t.has("8")) return th.sev.critical;
    if (t.has("3")) return th.sev.clean;
    if (t.has("2")) return th.sev.med;
    if (t.has("7") || t.has("13")) return th.sev.custom;
    if (t.has("9")) return th.sev.high;
    if (t.has("4")) return th.sev.med;
    if (t.has("5")) return th.sev.low;
    if (t.has("11")) return th.sev.custom;
    return th.textDim;
  };
  /** "just now" / "4m ago" / "2h ago" — for the resume affordance. */
  const _agoLabel = (ts) => {
    if (!ts) return "";
    const secs = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (secs < 45) return "just now";
    if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
    return `${Math.round(secs / 86400)}d ago`;
  };
  const edgeWidth = (count) => Math.max(1, Math.min(6, 1 + Math.log2(count)));
  const nodeRadius = (eventCount) => Math.max(6, Math.min(20, 6 + Math.log2(eventCount + 1) * 2));
  const SUS_HOSTNAME = /^(VPS|DESKTOP-[A-Z0-9]{7}$|WIN-[A-Z0-9]{8,}$|WINVM)/i;
  const isSusHost = (name) => SUS_HOSTNAME.test(name);
  const nodeColor = (node) => {
    if (selectedNode === node.id) return th.accent;
    if (node.nodeType === "identity") return node.unresolved ? th.textMuted : th.accent;
    if (node.isOutlier) return th.danger;
    if (isSusHost(node.id)) return th.sev.high;
    if (node.isBoth) return th.sev.custom;
    if (node.isSource && !node.isTarget) return th.sev.clean;
    return th.sev.info;
  };
  const isEdgeHL = (e) => {
    if (selectedEdge && e.source === selectedEdge.source && e.target === selectedEdge.target) return true;
    if (selectedNode && (e.source === selectedNode || e.target === selectedNode)) return true;
    return false;
  };

  // Hand the current closures to the effects declared above the guard. Assigning during
  // render is safe for a ref used only from effects/handlers (never read while rendering).
  _handlersRef.current.refreshLmPreview = refreshLmPreview;
  _handlersRef.current.handleAnalyze = handleAnalyze;

  return (
    <DraggableResizableModal
      defaultWidth={Math.round(window.innerWidth * 0.92)}
      defaultHeight={Math.round(window.innerHeight * 0.88)}
      minWidth={600}
      minHeight={400}
      onClose={() => setModal(null)}
    >
      {({ startDrag: startLmDrag, height: lmH }) => (<>
        {/* Tag picker — replaces window.prompt(), which Electron does not implement. */}
        {modal.lmTagPicker && (() => {
          const tp = modal.lmTagPicker;
          const setTagVal = (v) => setModal((p) => (p?.type === "lateralMovement" && p.lmTagPicker ? { ...p, lmTagPicker: { ...p.lmTagPicker, value: v } } : p));
          const close = () => setModal((p) => (p?.type === "lateralMovement" ? { ...p, lmTagPicker: null } : p));
          const chip = (t) => (
            <button key={t} onClick={() => _applyEvidenceTag(tp.item, t)}
              style={{ padding: "4px 10px", borderRadius: 999, border: `1px solid ${th.glassBorder || th.border}`, background: th.glassBg || th.bgAlt, color: th.textDim, fontSize: LM_TYPOGRAPHY.body, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>{t}</button>
          );
          return (
            <div onClick={close} style={{ position: "absolute", inset: 0, zIndex: 40, background: "rgba(0,0,0,0.45)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <div onClick={(ev) => ev.stopPropagation()} role="dialog" aria-label="Tag evidence rows"
                style={{ width: 420, maxWidth: "90%", padding: 18, borderRadius: 12, background: th.modalBg, border: `1px solid ${th.glassBorder || th.border}`, boxShadow: `0 12px 40px ${th.bg}cc`, backdropFilter: "blur(24px)", WebkitBackdropFilter: "blur(24px)" }}>
                <div style={{ fontSize: LM_TYPOGRAPHY.heading, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Tag evidence rows</div>
                <div style={{ fontSize: LM_TYPOGRAPHY.body, color: th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif" }}>
                  Applies to the {tp.refCount} exact source row{tp.refCount === 1 ? "" : "s"} behind this item.
                </div>
                <input autoFocus value={tp.value || ""} onChange={(ev) => setTagVal(ev.target.value)}
                  onKeyDown={(ev) => { if (ev.key === "Enter") _applyEvidenceTag(tp.item, tp.value); if (ev.key === "Escape") close(); }}
                  placeholder="tag name"
                  style={{ width: "100%", marginTop: 12, padding: "7px 10px", borderRadius: 8, border: `1px solid ${th.border}`, background: th.bgInput, color: th.text, fontSize: LM_TYPOGRAPHY.title, fontFamily: "-apple-system, sans-serif", boxSizing: "border-box" }} />
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
                  {[_defaultTagFor(tp.item), "lateral:confirmed", "lateral:credential-abuse", "lateral:execution", "needs-review", "false-positive"]
                    .filter((t, i, a) => a.indexOf(t) === i).map(chip)}
                </div>
                <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                  <button onClick={close} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
                  <button onClick={() => _applyEvidenceTag(tp.item, tp.value)} disabled={!String(tp.value || "").trim()}
                    style={{ ...ms.bp, borderRadius: 8, opacity: String(tp.value || "").trim() ? 1 : 0.5 }}>Apply tag</button>
                </div>
              </div>
            </div>
          );
        })()}
        {/* Header — draggable */}
        <div onMouseDown={startLmDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)", cursor: "grab" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.danger}33, ${th.danger}11)`, border: `1px solid ${th.danger}33`, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={th.danger} strokeWidth="1.5" strokeLinecap="round"><circle cx="5" cy="12" r="2.5" fill={`${th.danger}33`}/><circle cx="19" cy="5" r="2.5" fill={`${th.danger}33`}/><circle cx="19" cy="19" r="2.5" fill={`${th.danger}33`}/><line x1="7.5" y1="11" x2="16.5" y2="6"/><line x1="7.5" y1="13" x2="16.5" y2="18"/></svg>
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: LM_TYPOGRAPHY.heading, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.3px" }}>Lateral Movement Tracker</h3>
              <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: LM_TYPOGRAPHY.body, fontFamily: "-apple-system, sans-serif" }}>Evidence-backed machine and user movement paths</p>
            </div>
          </div>
          <button onClick={() => setModal(null)} style={{ width: 24, height: 24, borderRadius: 12, background: th.textMuted + "15", border: "none", color: th.textMuted, cursor: "pointer", fontSize: LM_TYPOGRAPHY.heading, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", justifyContent: "center", transition: "all var(--m-base)" }}
            onMouseEnter={(ev) => { ev.currentTarget.style.background = th.danger + "33"; ev.currentTarget.style.color = th.danger; }}
            onMouseLeave={(ev) => { ev.currentTarget.style.background = th.textMuted + "15"; ev.currentTarget.style.color = th.textMuted; }}>{"\u2715"}</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
          {/* Config phase */}
          {phase === "config" && (() => {
            const cov = lmCoverageInfo(cols);
            const covColor = { high: th.sev.clean, medium: th.sev.med, low: th.sev.critical }[cov.level];
            return (
            <div>
              {modal.error && <div style={{ padding: "8px 12px", background: (th.danger) + "15", border: `1px solid ${th.danger}33`, borderRadius: 6, color: th.danger, fontSize: LM_TYPOGRAPHY.body, marginBottom: 12 }}>{modal.error}</div>}

              {/* KAPE Collection Host */}
              {modal.kapeHost && modal.kapeHost.collectionHost && (
                <div style={{ padding: "8px 14px", background: `${th.accent}08`, border: `1px solid ${th.accent}18`, borderRadius: 10, marginBottom: 12, display: "flex", alignItems: "center", gap: 10 }}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round">
                    <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
                  </svg>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: LM_TYPOGRAPHY.body, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>
                      Collection Host: <span style={{ color: th.accent }}>{modal.kapeHost.shortName || modal.kapeHost.collectionHost}</span>
                    </div>
                    <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1 }}>
                      {modal.kapeHost.format} · {modal.kapeHost.pct}% of events ({modal.kapeHost.eventCount?.toLocaleString()} / {modal.kapeHost.totalEvents?.toLocaleString()}) · {modal.kapeHost.confidence} confidence
                    </div>
                  </div>
                  {modal.kapeHost.hostDistribution.length > 1 && (
                    <div style={{ display: "flex", gap: 3 }}>
                      {modal.kapeHost.hostDistribution.slice(0, 5).map((h, i) => (
                        <span key={i} title={`${h.host}: ${h.pct}%`} style={{ width: 6, height: 6, borderRadius: 3, background: i === 0 ? th.accent : th.textMuted + "66" }} />
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Auto-detect summary */}
              <div style={{ padding: "10px 14px", background: `${covColor}08`, border: `1px solid ${covColor}22`, borderRadius: 10, marginBottom: 12, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={covColor} strokeWidth="2" strokeLinecap="round">
                    {cov.level === "high" ? <><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></> : cov.level === "medium" ? <><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></> : <><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></>}
                  </svg>
                  <div>
                    <div style={{ fontSize: LM_TYPOGRAPHY.title, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>
                      {cov.level === "high" ? "All columns mapped" : cov.level === "medium" ? "Core columns mapped" : "Missing required columns"}
                    </div>
                    <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1 }}>
                      {cov.reqOk}/4 required{cov.recOk > 0 ? ` \u00B7 ${cov.recOk}/2 recommended` : ""}{cols.domain ? " \u00B7 domain" : ""}
                    </div>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  {!modal.lmShowMapping && <div style={{ display: "flex", gap: 3, marginRight: 4 }}>
                    {[...cov.required, ...cov.recommended].map(([k, label]) => (
                      <span key={k} title={`${label}: ${cols[k] || "unmapped"}`} style={{ width: 6, height: 6, borderRadius: 3, background: cols[k] ? th.sev.clean : th.sev.critical + "66" }} />
                    ))}
                  </div>}
                  <button onClick={() => setModal((p) => ({ ...p, lmShowMapping: !p.lmShowMapping }))} style={{ ...ms.bsm, fontSize: LM_TYPOGRAPHY.control, padding: "2px 8px" }}>
                    {modal.lmShowMapping ? "Hide" : "Edit"}
                  </button>
                </div>
              </div>

              {/* Collapsible column mapping */}
              {modal.lmShowMapping && (
                <div style={{ padding: "10px 14px", background: `${th.panelBg}55`, border: `1px solid ${th.border}22`, borderRadius: 10, marginBottom: 12 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6 }}>
                    {[
                      ["source", "Source Host", true], ["target", "Target Host", true], ["user", "User", false],
                      ["logonType", "Logon Type", false], ["eventId", "Event ID", true], ["ts", "Timestamp", true],
                      ["domain", "Domain", false],
                    ].map(([key, label, req]) => (
                      <div key={key}>
                        <label style={{ fontSize: LM_TYPOGRAPHY.meta, color: cols[key] ? th.textDim : req ? th.sev.critical : th.textMuted, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.04em", display: "flex", alignItems: "center", gap: 3, marginBottom: 2 }}>
                          {cols[key] ? <span style={{ color: th.sev.clean }}>{"\u2713"}</span> : req ? <span style={{ color: th.sev.critical }}>{"\u2717"}</span> : <span style={{ color: th.textMuted }}>{"\u25CB"}</span>}
                          {label}
                        </label>
                        <select value={cols[key] || ""} onChange={(e) => { const v = e.target.value || null; setModal((p) => { const nc = { ...p.columns, [key]: v }; setTimeout(() => refreshLmPreview(nc), 0); return { ...p, columns: nc }; }); }} style={{ ...ms.sl, fontSize: LM_TYPOGRAPHY.control, padding: "3px 6px" }}>
                          <option value="">-- auto --</option>
                          {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}
                        </select>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Multi-source correlation toggle */}
              {otherTabs.length > 0 && (
                <div style={{ padding: "10px 14px", background: modal.lmMultiSource ? `${th.accent}08` : `${th.panelBg}55`, border: `1px solid ${modal.lmMultiSource ? th.accent + "33" : th.border + "22"}`, borderRadius: 10, marginBottom: 12, transition: "all var(--m-base)" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: modal.lmMultiSource ? 8 : 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={modal.lmMultiSource ? th.accent : th.textDim} strokeWidth="2" strokeLinecap="round">
                        <circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="18" r="3"/>
                        <line x1="9" y1="6" x2="15" y2="6"/><line x1="6" y1="9" x2="6" y2="15"/><line x1="18" y1="9" x2="18" y2="15"/><line x1="9" y1="18" x2="15" y2="18"/>
                      </svg>
                      <div>
                        <div style={{ fontSize: LM_TYPOGRAPHY.body, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Multi-source Correlation</div>
                        <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1 }}>Merge logon events from multiple KAPE triage tabs to reveal cross-machine attack paths</div>
                      </div>
                    </div>
                    <button onClick={() => setModal((p) => ({ ...p, lmMultiSource: !p.lmMultiSource, lmSelectedTabIds: p.lmSelectedTabIds || [] }))}
                      style={{ width: 36, height: 20, borderRadius: 10, border: "none", background: modal.lmMultiSource ? th.accent : th.btnBg, cursor: "pointer", position: "relative", transition: "background var(--m-base)", flexShrink: 0 }}>
                      <div style={{ width: 16, height: 16, borderRadius: 8, background: "#fff", position: "absolute", top: 2, left: modal.lmMultiSource ? 18 : 2, transition: "left var(--m-base)", boxShadow: "0 1px 3px rgba(0,0,0,0.3)" }} />
                    </button>
                  </div>
                  {modal.lmMultiSource && (
                    <div style={{ borderTop: `1px solid ${th.border}22`, paddingTop: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 6 }}>
                        <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>
                          Select tabs to include ({(modal.lmSelectedTabIds || []).length + 1} of {otherTabs.length + 1} tabs)
                        </div>
                        {otherTabs.length > 0 && (
                          <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                            <button onClick={() => setModal((p) => ({ ...p, lmSelectedTabIds: otherTabs.map(t => t.id) }))} style={{ padding: "2px 8px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                            <button onClick={() => setModal((p) => ({ ...p, lmSelectedTabIds: [] }))} style={{ padding: "2px 8px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                          </div>
                        )}
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 3, maxHeight: 120, overflow: "auto" }}>
                        {/* Current tab — always included, shown but not toggleable */}
                        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", background: `${th.accent}12`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                          <span style={{ color: th.accent, fontSize: LM_TYPOGRAPHY.title }}>{"\u2713"}</span>
                          <span style={{ fontSize: LM_TYPOGRAPHY.body, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{ct.name}</span>
                          <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{(ct.totalRows || 0).toLocaleString()} rows</span>
                          <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.accent, fontFamily: "-apple-system, sans-serif", padding: "1px 5px", background: `${th.accent}15`, borderRadius: 4 }}>current</span>
                        </div>
                        {/* Other tabs — toggleable */}
                        {otherTabs.map(t => {
                          const sel = (modal.lmSelectedTabIds || []).includes(t.id);
                          return (
                            <button key={t.id} onClick={() => setModal((p) => {
                              const ids = [...(p.lmSelectedTabIds || [])];
                              const idx = ids.indexOf(t.id);
                              if (idx >= 0) ids.splice(idx, 1); else ids.push(t.id);
                              return { ...p, lmSelectedTabIds: ids };
                            })}
                              style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", background: sel ? `${th.accent}08` : "transparent", borderRadius: 6, border: `1px solid ${sel ? th.accent + "22" : th.border + "11"}`, cursor: "pointer", textAlign: "left", transition: "all var(--m-base)" }}>
                              <span style={{ color: sel ? th.accent : th.textMuted, fontSize: LM_TYPOGRAPHY.title, width: 14, textAlign: "center" }}>{sel ? "\u2713" : "\u25CB"}</span>
                              <span style={{ fontSize: LM_TYPOGRAPHY.body, color: sel ? th.text : th.textDim, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.name}</span>
                              <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{(t.totalRows || 0).toLocaleString()} rows</span>
                            </button>
                          );
                        })}
                      </div>
                      {(modal.lmSelectedTabIds || []).length === 0 && (
                        <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.warning, marginTop: 6, fontFamily: "-apple-system, sans-serif" }}>Select at least one additional tab for multi-source correlation</div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Intent selector + Reset */}
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                <div style={{ display: "flex", gap: 4 }}>
                  {LM_INTENTS.map((intent) => {
                    const active = modal.lmIntent === intent.id;
                    return (
                      <button key={intent.id} onClick={() => applyLmIntent(intent)} title={intent.desc}
                        style={{ padding: "4px 10px", fontSize: LM_TYPOGRAPHY.control, fontWeight: active ? 600 : 400, fontFamily: "-apple-system, sans-serif", background: active ? `${th.accent}18` : "transparent", color: active ? th.accent : th.textDim, border: `1px solid ${active ? th.accent + "44" : th.border + "22"}`, borderRadius: 6, cursor: "pointer", transition: "all var(--m-base)" }}>
                        {intent.label}
                      </button>
                    );
                  })}
                </div>
                <button onClick={resetLmRules} title="Reset all rules to recommended defaults"
                  style={{ padding: "3px 8px", fontSize: LM_TYPOGRAPHY.meta, fontFamily: "-apple-system, sans-serif", background: "transparent", color: th.textMuted, border: `1px solid ${th.border}22`, borderRadius: 4, cursor: "pointer", display: "flex", alignItems: "center", gap: 3, transition: "all var(--m-base)" }}
                  onMouseEnter={(e) => { e.currentTarget.style.color = th.accent; e.currentTarget.style.borderColor = th.accent + "44"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.color = th.textMuted; e.currentTarget.style.borderColor = th.border + "22"; }}>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
                  Reset
                </button>
              </div>

              {/* Technique Presets */}
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: LM_TYPOGRAPHY.control, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>Detection Techniques</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {LM_PRESETS.map((preset) => {
                    const state = lmPresetState(preset.rules, lmDisabledSet);
                    const activeRuleCount = preset.rules.filter(i => !lmDisabledSet.has(`lm-${i}`)).length;
                    const isOn = state !== "off";
                    return (
                      <div key={preset.id} style={{ padding: "10px 14px", background: isOn ? `${th.accent}08` : `${th.panelBg}33`, border: `1px solid ${isOn ? th.accent + "22" : th.border + "22"}`, borderRadius: 10, cursor: "pointer", transition: "all var(--m-base)", opacity: isOn ? 1 : 0.6 }}
                        onClick={() => toggleLmPreset(preset)}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                            <div style={{ width: 28, height: 28, borderRadius: 8, background: isOn ? `${th.accent}15` : `${th.textMuted}11`, display: "flex", alignItems: "center", justifyContent: "center", color: isOn ? th.accent : th.textMuted, transition: "all var(--m-base)" }}>
                              {preset.icon}
                            </div>
                            <div>
                              <div style={{ fontSize: LM_TYPOGRAPHY.title, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{preset.name}</div>
                              <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1, maxWidth: 320 }}>{preset.desc}</div>
                            </div>
                          </div>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{activeRuleCount}/{preset.rules.length}</span>
                            <div style={{ width: 32, height: 18, borderRadius: 10, background: isOn ? th.accent : th.textMuted + "33", transition: "background var(--m-base)", position: "relative" }}>
                              <div style={{ width: 14, height: 14, borderRadius: 8, background: "#fff", position: "absolute", top: 2, left: isOn ? 16 : 2, transition: "left var(--m-base)", boxShadow: "0 1px 3px rgba(0,0,0,0.2)" }} />
                            </div>
                          </div>
                        </div>
                        {state === "partial" && (
                          <div style={{ marginTop: 6, paddingTop: 6, borderTop: `1px solid ${th.border}15`, display: "flex", flexWrap: "wrap", gap: 4 }}>
                            {preset.rules.map(i => {
                              const r = LM_RULES[i]; const off = lmDisabledSet.has(`lm-${i}`);
                              return <span key={i} onClick={(e) => { e.stopPropagation(); toggleLmRule(`lm-${i}`); }}
                                style={{ fontSize: LM_TYPOGRAPHY.meta, padding: "1px 6px", borderRadius: 3, background: off ? `${th.textMuted}11` : `${LM_SEV_COLORS[r.sev]}15`, color: off ? th.textMuted : LM_SEV_COLORS[r.sev], border: `1px solid ${off ? th.border + "22" : LM_SEV_COLORS[r.sev] + "33"}`, fontFamily: "-apple-system, sans-serif", cursor: "pointer", textDecoration: off ? "line-through" : "none", opacity: off ? 0.5 : 1, transition: "all var(--m-base)" }}>{r.name}</span>;
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Exclusion toggles + rule count */}
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                <div style={{ display: "flex", gap: 14 }}>
                  <label style={{ fontSize: LM_TYPOGRAPHY.body, color: th.textDim, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontFamily: "-apple-system, sans-serif" }}>
                    <input type="checkbox" checked={excludeLocal} onChange={() => { setModal((p) => ({ ...p, excludeLocal: !p.excludeLocal })); setTimeout(() => refreshLmPreview(), 0); }} style={{ accentColor: th.accent }} /> Exclude local logons
                  </label>
                  <label style={{ fontSize: LM_TYPOGRAPHY.body, color: th.textDim, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontFamily: "-apple-system, sans-serif" }}>
                    <input type="checkbox" checked={excludeService} onChange={() => { setModal((p) => ({ ...p, excludeService: !p.excludeService })); setTimeout(() => refreshLmPreview(), 0); }} style={{ accentColor: th.accent }} /> Exclude service accounts
                  </label>
                </div>
                <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{lmActiveCount}/{LM_RULES.length} rules{lmCustomCount > 0 ? ` + ${lmCustomCount} custom` : ""}</span>
              </div>
              {modal.chainsawSyntheticTarget && (
                <div style={{ marginBottom: 12, padding: "8px 10px", background: `${th.warning}12`, border: `1px solid ${(th.warning)}30`, borderRadius: 8, color: th.warning, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>
                  Chainsaw logon export has no destination host column. Tracker will treat these events as inbound activity to <span style={{ fontFamily: "SF Mono, monospace" }}>{modal.chainsawSyntheticTarget}</span>.
                </div>
              )}

              {/* Event Availability + Skip Warnings + Source Data Quality */}
              {(() => {
                const prev = modal.lmPreview;
                const evCounts = prev?.eventCounts || {};
                const colQ = prev?.columnQuality || {};
                const hasAnyEvents = Object.values(evCounts).some(c => c > 0);
                const skipWarns = hasAnyEvents ? lmSkipWarnings(evCounts) : [];
                const sanityWarns = [];
                if (colQ.source?.mapped && colQ.source.ipOnlyRate > 80) sanityWarns.push("Source column appears IP-only (" + colQ.source.ipOnlyRate + "%) \u2014 hostnames may not resolve in graph");
                if (colQ.user?.mapped && colQ.user.nullRate > 50) sanityWarns.push("User column has high null rate (" + colQ.user.nullRate + "%) \u2014 auth tracking may be incomplete");
                if (colQ.logonType?.mapped && colQ.logonType.nullRate > 60) sanityWarns.push("Logon Type field sparse (" + colQ.logonType.nullRate + "% empty) \u2014 RDP type detection limited");
                if (colQ.source?.mapped && colQ.source.nullRate > 40) sanityWarns.push("Source Host has " + colQ.source.nullRate + "% null values \u2014 some connections may be missed");
                return (
                <div style={{ padding: "10px 14px", background: `${th.panelBg}44`, border: `1px solid ${th.border}22`, borderRadius: 10, marginBottom: 12 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                    <div style={{ fontSize: LM_TYPOGRAPHY.control, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Event Availability</div>
                    {prev && <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{(prev.trackedEvents || 0).toLocaleString()} tracked events</span>}
                  </div>
                  {modal.lmPreviewLoading ? (
                    <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: "6px 0" }}>Scanning dataset...</div>
                  ) : !prev ? (
                    <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: "6px 0" }}>Preview unavailable</div>
                  ) : (
                    <>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: hasAnyEvents ? 8 : 0 }}>
                        {LM_EVENT_GROUPS.map((g) => {
                          const total = g.eids.reduce((s, e) => s + (evCounts[e] || 0), 0);
                          const present = total > 0;
                          return (
                            <div key={g.label} title={`${g.detector}\nEIDs: ${g.eids.join(", ")}\n${present ? total.toLocaleString() + " events" : "Not found"}`}
                              style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: present ? th.sev.clean + "10" : `${th.textMuted}08`, border: `1px solid ${present ? th.sev.clean + "22" : th.border + "15"}`, transition: "all var(--m-base)" }}>
                              <span style={{ width: 5, height: 5, borderRadius: 3, background: present ? th.sev.clean : g.required ? th.sev.critical : th.textMuted + "44" }} />
                              <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: present ? th.text : th.textMuted, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{g.label}</span>
                              {present && <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{total >= 1000 ? (total / 1000).toFixed(1) + "k" : total}</span>}
                            </div>
                          );
                        })}
                      </div>

                      {skipWarns.length > 0 && (
                        <div style={{ borderTop: `1px solid ${th.border}15`, paddingTop: 6 }}>
                          {skipWarns.map((w, i) => (
                            <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 6, padding: "2px 0" }}>
                              <span style={{ fontSize: LM_TYPOGRAPHY.control, flexShrink: 0, marginTop: 1, color: w.level === "error" ? th.sev.critical : w.level === "warn" ? th.sev.med : th.textMuted }}>
                                {w.level === "error" ? "\u2717" : w.level === "warn" ? "\u26A0" : "\u25CB"}
                              </span>
                              <span style={{ fontSize: LM_TYPOGRAPHY.control, color: w.level === "error" ? th.sev.critical : w.level === "warn" ? th.sev.med : th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>{w.text}</span>
                            </div>
                          ))}
                        </div>
                      )}

                      {sanityWarns.length > 0 && (
                        <div style={{ borderTop: `1px solid ${th.border}15`, paddingTop: 6, marginTop: skipWarns.length > 0 ? 0 : 0 }}>
                          {sanityWarns.map((w, i) => (
                            <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 6, padding: "2px 0" }}>
                              <span style={{ fontSize: LM_TYPOGRAPHY.control, flexShrink: 0, marginTop: 1, color: th.sev.med }}>{"\u26A0"}</span>
                              <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.sev.med, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>{w}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>
                );
              })()}

              {/* Advanced Section */}
              <div>
                <button onClick={() => setModal((p) => ({ ...p, showLmRules: !p.showLmRules }))}
                  style={{ width: "100%", padding: "8px 14px", background: "transparent", border: `1px solid ${th.border}22`, borderRadius: modal.showLmRules ? "10px 10px 0 0" : 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "space-between", transition: "all var(--m-base)" }}>
                  <span style={{ fontSize: LM_TYPOGRAPHY.body, fontWeight: 600, color: th.textDim, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                    Advanced
                  </span>
                  <span style={{ transform: modal.showLmRules ? "rotate(180deg)" : "rotate(0deg)", transition: "transform var(--m-base)", fontSize: LM_TYPOGRAPHY.body, color: th.textMuted }}>{"\u25BE"}</span>
                </button>

                {modal.showLmRules && (
                  <div style={{ padding: "10px 14px", borderLeft: `1px solid ${th.border}22`, borderRight: `1px solid ${th.border}22`, borderBottom: `1px solid ${th.border}22`, borderRadius: "0 0 10px 10px", background: `${th.panelBg}33` }}>
                    <div style={{ fontSize: LM_TYPOGRAPHY.control, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                      Individual Rules ({lmActiveCount}/{LM_RULES.length})
                    </div>
                    {[...LM_RULES.map((r, i) => ({ ...r, _i: i }))].sort((a, b) => {
                      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
                      return (sevOrder[a.sev] ?? 4) - (sevOrder[b.sev] ?? 4);
                    }).map((r) => {
                      const i = r._i;
                      const key = `lm-${i}`;
                      const off = lmDisabledSet.has(key);
                      const blurb = LM_DETECTOR_BLURBS[r.name];
                      const evCounts = modal.lmPreview?.eventCounts || {};
                      const ruleEvCount = r.eids.reduce((s, e) => s + (evCounts[e] || 0), 0);
                      return (
                        <div key={key} style={{ padding: "3px 0", opacity: off ? 0.4 : 1, transition: "opacity var(--m-base)" }}>
                          <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
                            <input type="checkbox" checked={!off} onChange={() => toggleLmRule(key)} style={{ accentColor: th.accent, margin: 0, flexShrink: 0 }} />
                            <span style={{ fontSize: LM_TYPOGRAPHY.meta, padding: "1px 5px", borderRadius: 3, background: LM_SEV_COLORS[r.sev] + "22", color: LM_SEV_COLORS[r.sev], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{r.sev}</span>
                            <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{r.name}</span>
                            <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textDim, fontFamily: "SF Mono, monospace" }}>EID {r.eids.join(",")}</span>
                            {ruleEvCount > 0 && <span style={{ fontSize: LM_TYPOGRAPHY.badge, padding: "0 4px", borderRadius: 3, background: th.sev.clean + "15", color: th.sev.clean, fontFamily: "SF Mono, monospace", fontWeight: 600 }}>{ruleEvCount >= 1000 ? (ruleEvCount / 1000).toFixed(1) + "k" : ruleEvCount}</span>}
                            {ruleEvCount === 0 && modal.lmPreview && <span style={{ fontSize: LM_TYPOGRAPHY.badge, padding: "0 4px", borderRadius: 3, background: `${th.textMuted}11`, color: th.textMuted, fontFamily: "SF Mono, monospace" }}>0</span>}
                          </label>
                          {blurb && <div style={{ marginLeft: 22, fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif", fontStyle: "italic", lineHeight: 1.3, marginTop: 1 }}>{blurb}</div>}
                        </div>
                      );
                    })}

                    {/* Custom rules */}
                    {(modal.lmCustomRules || []).length > 0 && (
                      <div style={{ marginTop: 8 }}>
                        <div style={{ fontSize: LM_TYPOGRAPHY.control, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4, fontFamily: "-apple-system, sans-serif" }}>Custom Rules</div>
                        {(modal.lmCustomRules || []).map((cr, i) => (
                          <div key={`custom-${i}`} style={{ display: "flex", alignItems: "center", gap: 6, padding: "2px 0" }}>
                            <span style={{ fontSize: LM_TYPOGRAPHY.meta, padding: "1px 5px", borderRadius: 3, background: LM_SEV_COLORS[cr.severity || "medium"] + "22", color: LM_SEV_COLORS[cr.severity || "medium"], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{cr.severity || "med"}</span>
                            <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{cr.category || "Custom"} {"\u2014"} {cr.name || "Custom Rule"}</span>
                            <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textDim, fontFamily: "SF Mono, monospace" }}>EID {cr.eventIds || ""}</span>
                            <button onClick={() => deleteLmCustomRule(i)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: LM_TYPOGRAPHY.heading, padding: "0 4px", lineHeight: 1 }} onMouseEnter={(e) => e.currentTarget.style.color = th.danger} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>{"\u00D7"}</button>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Add custom rule */}
                    {!modal.lmAddingRule ? (
                      <button onClick={() => setModal((p) => ({ ...p, lmAddingRule: true, lmNewRule: {} }))}
                        style={{ ...ms.bsm, marginTop: 8, display: "flex", alignItems: "center", gap: 4, fontSize: LM_TYPOGRAPHY.control }}>
                        <span style={{ fontSize: LM_TYPOGRAPHY.title, lineHeight: 1 }}>+</span> Add Custom Rule
                      </button>
                    ) : (
                      <div style={{ marginTop: 8, padding: "10px 12px", background: `${th.accent}08`, border: `1px solid ${th.accent}22`, borderRadius: 8 }}>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                          <input value={(modal.lmNewRule || {}).category || ""} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, category: e.target.value } }))} placeholder="Category" style={{ ...ms.ip, fontSize: LM_TYPOGRAPHY.body, padding: "4px 8px" }} />
                          <input value={(modal.lmNewRule || {}).name || ""} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, name: e.target.value } }))} placeholder="Rule Name" style={{ ...ms.ip, fontSize: LM_TYPOGRAPHY.body, padding: "4px 8px" }} />
                          <input value={(modal.lmNewRule || {}).eventIds || ""} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, eventIds: e.target.value } }))} placeholder="Event IDs (e.g. 7045,4697)" style={{ ...ms.ip, fontSize: LM_TYPOGRAPHY.body, padding: "4px 8px" }} />
                          <select value={(modal.lmNewRule || {}).severity || "medium"} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, severity: e.target.value } }))}
                            style={{ ...ms.sl, fontSize: LM_TYPOGRAPHY.body, padding: "4px 8px" }}>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                          </select>
                          <input value={(modal.lmNewRule || {}).payloadFilter || ""} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, payloadFilter: e.target.value } }))} placeholder="Payload regex filter (optional)" style={{ ...ms.ip, fontSize: LM_TYPOGRAPHY.body, padding: "4px 8px", gridColumn: "1 / -1" }} />
                        </div>
                        <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 8 }}>
                          <button onClick={() => setModal((p) => ({ ...p, lmAddingRule: false, lmNewRule: {} }))} style={ms.bsm}>Cancel</button>
                          <button onClick={addLmCustomRule} style={{ ...ms.bsm, background: th.primaryBtn, color: "#fff", border: "none" }}>Add Rule</button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
            );
          })()}

          {/* Loading phase */}
          {phase === "loading" && (() => {
            const prog = modal.lmProgress || 0;
            const pi = modal.lmPhaseIdx || 0;
            const plabels = ["Querying database...", "Processing logon events...", "Building host connections...", "Detecting lateral chains...", "Computing graph layout...", "Complete"];
            return (
              <div style={{ padding: "50px 40px 40px", textAlign: "center" }}>
                <style>{`@keyframes lmPulse{0%,100%{opacity:.35}50%{opacity:1}}`}</style>
                <div style={{ marginBottom: 22 }}>
                  <svg width="36" height="36" viewBox="0 0 24 24" fill="none" strokeWidth="1.5" strokeLinecap="round">
                    <circle cx="5" cy="12" r="2.5" fill={th.accent+"33"} stroke={th.accent} style={{ animation: "lmPulse 1.5s ease-in-out infinite" }} />
                    <circle cx="19" cy="5" r="2.5" fill={(th.danger)+"33"} stroke={th.danger} style={{ animation: "lmPulse 1.5s ease-in-out infinite .3s" }} />
                    <circle cx="19" cy="19" r="2.5" fill={(th.danger)+"33"} stroke={th.danger} style={{ animation: "lmPulse 1.5s ease-in-out infinite .6s" }} />
                    <line x1="7.5" y1="11" x2="16.5" y2="6" stroke={th.accent} strokeDasharray="3 3" />
                    <line x1="7.5" y1="13" x2="16.5" y2="18" stroke={th.accent} strokeDasharray="3 3" />
                  </svg>
                </div>
                <div style={{ color: th.text, fontSize: LM_TYPOGRAPHY.heading, fontWeight: 500, marginBottom: 6, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.2px" }}>{plabels[pi]}</div>
                <div style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.body, fontFamily: "-apple-system, sans-serif", marginBottom: 24 }}>This may take a moment for large datasets</div>
                <div style={{ position: "relative", height: 4, background: th.border + "22", borderRadius: 2, overflow: "hidden", maxWidth: 360, margin: "0 auto 12px" }}>
                  <div style={{ position: "absolute", left: 0, top: 0, height: "100%", width: `${prog}%`, background: `linear-gradient(90deg, ${th.accent}, ${th.danger})`, borderRadius: 2, transition: "width var(--m-slow) ease-out", boxShadow: `0 0 12px ${th.accent}44` }} />
                </div>
                <div style={{ color: th.textDim, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}>{Math.round(prog)}%</div>
              </div>
            );
          })()}

          {/* Results phase */}
          {phase === "results" && data && (
            <div>
              {/* Multi-source banner */}
              {data.multiSource && data.tabSummaries && (
                <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", background: `${th.accent}10`, border: `1px solid ${th.accent}22`, borderRadius: 8, marginBottom: 10, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round">
                    <circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="18" r="3"/>
                    <line x1="9" y1="6" x2="15" y2="6"/><line x1="6" y1="9" x2="6" y2="15"/><line x1="18" y1="9" x2="18" y2="15"/><line x1="9" y1="18" x2="15" y2="18"/>
                  </svg>
                  <span style={{ color: th.accent, fontWeight: 600 }}>Multi-source</span>
                  <span style={{ color: th.textMuted }}>{"\u00B7"}</span>
                  {data.tabSummaries.map((t, i) => (
                    <span key={i} style={{ padding: "1px 6px", background: `${th.accent}15`, borderRadius: 4, color: th.text, fontSize: LM_TYPOGRAPHY.meta }}>
                      {t.label} <span style={{ color: th.textMuted }}>({t.format}, {t.rowCount.toLocaleString()})</span>
                    </span>
                  ))}
                  <span style={{ color: th.textMuted, marginLeft: "auto" }}>{data.stats.totalMergedRows?.toLocaleString()} merged events</span>
                </div>
              )}
              {/* Stat cards — clickable. Counts use the brand accent; the risk-bearing
                  findings/outliers cards are toned by worst severity (see below). */}
              <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
                {[
                  { risk: true, val: data.stats.findingsCount || 0, label: "findings", icon: "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01", clickTab: "findings" },
                  { val: data.stats.uniqueHosts, label: "unique hosts", icon: "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75", clickTab: "hosts" },
                  { val: data.stats.uniqueConnections, label: "connections", icon: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3", clickTab: "connections" },
                  // Users card prefers stats.accountCount (the new identity-centric pipeline)
                  // and falls back to uniqueUsers for older tabs that haven't been re-analyzed.
                  // Sub-label exposes stats.suspiciousAccounts so analysts see at a glance how
                  // many of those identities crossed the suspicion-score threshold.
                  { val: data.stats.accountCount ?? data.stats.uniqueUsers, label: "users", icon: "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8", clickTab: "accounts", subVal: data.stats.suspiciousAccounts || 0, subLabel: "suspicious" },
                  {
                    val: data.stats.rdpSessionCount || 0,
                    label: "rdp sessions",
                    icon: "M2 3h20v14H2zM8 21h8M12 17v4",
                    clickTab: "rdp",
                    subVal: data.stats.rdpFailedAttemptCount || 0,
                    subLabel: "failed attempts",
                  },
                  { val: data.stats.longestChain, label: "longest chain", icon: "M13 17l5-5-5-5M6 17l5-5-5-5", clickTab: "chains" },
                  { risk: true, val: data.nodes.filter(n => n.isOutlier).length, label: "outliers", icon: "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01", clickTab: "outlier" },
                  { val: data.stats.totalEvents?.toLocaleString(), label: "logon events", icon: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8", clickTab: "events" },
                ].map((c, i) => {
                  // Counts are neutral facts and stay on the brand accent. The two cards
                  // that carry RISK — findings and outliers — are toned by the worst
                  // severity actually present, because the design system reserves the brand
                  // colour for actions and requires th.sev for anything that means "bad".
                  // A zero count is not a risk signal, so it stays neutral.
                  const worstSev = ["critical", "high", "medium", "low"]
                    .find((sv) => (data.findings || []).some((f) => f.severity === sv));
                  const numericValForTone = Number(String(c.val).replace(/,/g, "")) || 0;
                  const accentColor = (c.risk && numericValForTone > 0)
                    ? (LM_SEV_COLORS[worstSev] || th.sev.info)
                    : th.accent;
                  const numericVal = Number(String(c.val).replace(/,/g, "")) || 0;
                  const numericSubVal = Number(String(c.subVal ?? 0).replace(/,/g, "")) || 0;
                  const isClickable = numericVal > 0 || numericSubVal > 0;
                  const handleClick = () => {
                    if (!isClickable) return;
                    if (c.clickTab === "findings") { setModal((p) => ({ ...p, viewTab: "findings" })); return; }
                    if (c.clickTab === "outlier") {
                      const outlierNode = data.nodes.find(n => n.isOutlier);
                      if (outlierNode && positions && positions[outlierNode.id]) {
                        const p = positions[outlierNode.id];
                        setModal((prev) => ({ ...prev, viewTab: "graph", selectedNode: outlierNode.id, selectedEdge: null, viewBox: { x: p.x - 90, y: p.y - 60, w: 180, h: 120 }, lmFlagIdx: 1 }));
                      }
                      return;
                    }
                    if (c.clickTab === "hosts") { setModal((p) => ({ ...p, viewTab: "graph", selectedNode: null, selectedEdge: null })); return; }
                    if (c.clickTab === "connections" || c.clickTab === "events") { setModal((p) => ({ ...p, viewTab: "table", selectedNode: null, selectedEdge: null })); return; }
                    // The Users card now routes to the identity-centric Accounts tab
                    // (was the grouped connections table — pre-Accounts-tab fallback).
                    // "users" clickTab is kept as a synonym for older state shapes.
                    if (c.clickTab === "accounts" || c.clickTab === "users") { setModal((p) => ({ ...p, viewTab: "accounts", selectedNode: null, selectedEdge: null })); return; }
                    if (c.clickTab === "rdp") { setModal((p) => ({ ...p, viewTab: "rdp", selectedNode: null, selectedEdge: null })); return; }
                    if (c.clickTab === "chains") { setModal((p) => ({ ...p, viewTab: "chains", selectedNode: null, selectedEdge: null })); return; }
                  };
                  return (
                  <div key={i} onClick={isClickable ? handleClick : undefined} style={{ flex: 1, textAlign: "center", padding: "10px 6px 8px", background: `linear-gradient(160deg, ${accentColor}10, ${accentColor}04)`, borderRadius: 10, border: `1px solid ${accentColor}25`, position: "relative", overflow: "hidden", cursor: isClickable ? "pointer" : "default", transition: "all var(--m-base)", backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}
                    onMouseEnter={isClickable ? (e) => { e.currentTarget.style.borderColor = accentColor + "70"; e.currentTarget.style.background = `linear-gradient(160deg, ${accentColor}18, ${accentColor}08)`; } : undefined}
                    onMouseLeave={isClickable ? (e) => { e.currentTarget.style.borderColor = accentColor + "25"; e.currentTarget.style.background = `linear-gradient(160deg, ${accentColor}10, ${accentColor}04)`; } : undefined}>
                    <div style={{ position: "absolute", top: -8, right: -8, width: 40, height: 40, borderRadius: 14, background: `radial-gradient(circle, ${accentColor}18, transparent)` }} />
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={accentColor} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.6, marginBottom: 2 }}><path d={c.icon}/></svg>
                    <div style={{ fontSize: LM_TYPOGRAPHY.metric, fontWeight: 700, color: accentColor, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.5px", lineHeight: 1 }}>{c.val}</div>
                    <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 500 }}>{c.label}{isClickable && " \u25b8"}</div>
                    {/* Optional sub-chip — currently used by the Users card to surface
                        suspiciousAccounts. Renders inline below the label as a small
                        accent pill so the card stays compact. */}
                    {c.subVal != null && c.subVal > 0 && (
                      <div style={{ marginTop: 4, display: "inline-block", fontSize: LM_TYPOGRAPHY.badge, padding: "1px 6px", borderRadius: 3, background: `${accentColor}22`, color: accentColor, fontFamily: "-apple-system, sans-serif", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                        {c.subVal} {c.subLabel || "flagged"}
                      </div>
                    )}
                  </div>
                  );
                })}
              </div>

              {modal.truncatedGraph && <div style={{ padding: "6px 10px", background: th.warning + "15", border: `1px solid ${th.warning}33`, borderRadius: 6, color: th.warning, fontSize: LM_TYPOGRAPHY.control, marginBottom: 10, fontFamily: "-apple-system, sans-serif" }}>Graph showing the top 500 machines by activity. {data.nodes.length} total machines detected; the user overlay is derived from the visible machine links.</div>}

              {(() => {
                const criticalWarnings = (data.warnings || []).filter(w => !w.includes("skipped"));
                const skippedTabs = (data.warnings || []).filter(w => w.includes("skipped"));
                if (criticalWarnings.length === 0 && skippedTabs.length === 0) return null;
                return (<>
                  {criticalWarnings.length > 0 && <div style={{ padding: "6px 10px", background: th.warning + "12", border: `1px solid ${th.warning}30`, borderRadius: 6, color: th.warning, fontSize: LM_TYPOGRAPHY.control, marginBottom: 10, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>
                    <span style={{ fontWeight: 600 }}>Partial analysis:</span> {criticalWarnings.map((w, i) => <span key={i}>{i > 0 && " | "}{w}</span>)}
                  </div>}
                  {skippedTabs.length > 0 && <div style={{ padding: "4px 10px", background: th.textMuted + "08", border: `1px solid ${th.border}22`, borderRadius: 6, color: th.textMuted, fontSize: LM_TYPOGRAPHY.meta, marginBottom: 10, fontFamily: "-apple-system, sans-serif", cursor: "pointer" }}
                    onClick={(e) => { const el = e.currentTarget.querySelector("[data-skip-detail]"); if (el) el.style.display = el.style.display === "none" ? "block" : "none"; }}>
                    <span>{skippedTabs.length} tab{skippedTabs.length > 1 ? "s" : ""} skipped (no logon data) — click to expand</span>
                    <div data-skip-detail="" style={{ display: "none", marginTop: 4, lineHeight: 1.5 }}>{skippedTabs.map((w, i) => <div key={i}>{w}</div>)}</div>
                  </div>}
                </>);
              })()}

              {/* Telemetry Coverage Summary — collapsible panel showing dataset-wide coverage */}
              {data.coverage && (() => {
                const cov = data.coverage;
                const ds = cov.dataset || {};
                const cats = ds.categories || {};
                const lvlColor = ds.level === "high" ? th.sev.clean : ds.level === "medium" ? th.sev.med : th.sev.critical;
                const lvlLabel = ds.level === "high" ? "Strong" : ds.level === "medium" ? "Partial" : "Weak";
                const wList = cov.warnings || [];
                const errCount = wList.filter(w => w.level === "error").length;
                const warnCount = wList.filter(w => w.level === "warn").length;
                const infoCount = wList.filter(w => w.level === "info").length;
                const expanded = !!modal._coverageExpanded;
                return (
                  <div style={{ marginBottom: 10, border: `1px solid ${lvlColor}25`, borderRadius: 6, background: `${lvlColor}06`, fontFamily: "-apple-system, sans-serif" }}>
                    <div onClick={() => setModal((p) => ({ ...p, _coverageExpanded: !p._coverageExpanded }))}
                      style={{ padding: "6px 10px", display: "flex", alignItems: "center", gap: 8, cursor: "pointer", userSelect: "none" }}>
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={lvlColor} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" style={{ transform: expanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform var(--m-base)" }}><polyline points="9 18 15 12 9 6"/></svg>
                      <span style={{ fontSize: LM_TYPOGRAPHY.control, fontWeight: 600, color: th.text }}>Telemetry Coverage</span>
                      <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                        <div style={{ width: 50, height: 4, borderRadius: 2, background: th.border + "44", overflow: "hidden" }}>
                          <div style={{ width: `${ds.score || 0}%`, height: "100%", background: lvlColor, borderRadius: 2 }} />
                        </div>
                        <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: lvlColor, fontWeight: 700 }}>{lvlLabel} {ds.score || 0}%</span>
                      </div>
                      <div style={{ display: "flex", gap: 4, marginLeft: "auto", fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted }}>
                        {errCount > 0 && <span style={{ color: th.sev.critical, fontWeight: 600 }}>{errCount} error{errCount !== 1 ? "s" : ""}</span>}
                        {warnCount > 0 && <span style={{ color: th.sev.med, fontWeight: 600 }}>{warnCount} warn{warnCount !== 1 ? "s" : ""}</span>}
                        {infoCount > 0 && <span>{infoCount} info</span>}
                        {wList.length === 0 && <span style={{ color: th.sev.clean, fontWeight: 600 }}>All categories present</span>}
                      </div>
                    </div>
                    {expanded && (
                      <div style={{ padding: "8px 10px 10px", borderTop: `1px solid ${lvlColor}20` }}>
                        {/* Per-category presence */}
                        <div style={{ marginBottom: 8 }}>
                          <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: 4 }}>Categories</div>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                            {Object.entries(cats).map(([id, c]) => {
                              const color = c.present ? th.sev.clean : (c.critical ? th.sev.critical : th.textMuted);
                              return (
                                <span key={id} title={c.present ? `${c.label}: ${c.count.toLocaleString()} events across all hosts` : `${c.label}: missing${c.critical ? " (critical)" : ""}`}
                                  style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 7px", background: color + (c.present ? "18" : "10"), color, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, opacity: c.present ? 1 : 0.6, border: `1px solid ${color}${c.present ? "33" : "22"}` }}>
                                  <span style={{ width: 5, height: 5, borderRadius: 3, background: color }} />
                                  {c.label}{c.present ? ` (${c.count > 9999 ? Math.round(c.count / 1000) + "k" : c.count.toLocaleString()})` : ""}
                                </span>
                              );
                            })}
                          </div>
                        </div>
                        {/* Warnings list */}
                        {wList.length > 0 && (
                          <div>
                            <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: 4 }}>Coverage Warnings</div>
                            <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                              {wList.map((w, i) => {
                                const c = w.level === "error" ? th.sev.critical : w.level === "warn" ? th.sev.med : th.textMuted;
                                return (
                                  <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 6, fontSize: LM_TYPOGRAPHY.meta, color: th.textDim, padding: "3px 6px", background: c + "08", borderRadius: 3 }}>
                                    <span style={{ color: c, fontWeight: 700, fontSize: LM_TYPOGRAPHY.badge, textTransform: "uppercase", flexShrink: 0 }}>{w.level}</span>
                                    <span>{w.text}</span>
                                  </div>
                                );
                              })}
                            </div>
                            <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, marginTop: 6, fontStyle: "italic" }}>
                              Click any host in the Network Graph to see its individual telemetry coverage and identify which hops have the weakest evidence.
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Tab switcher */}
              <div style={{ display: "inline-flex", background: th.panelBg, borderRadius: 8, padding: 2, marginBottom: 12, border: `1px solid ${th.border}44`, gap: 1 }}>
                {[
                  { id: "graph", label: "Network Graph", icon: "M22 12h-4l-3 9L9 3l-3 9H2" },
                  { id: "rdp", label: `RDP Activity (${data.stats.rdpActivityCount ?? data.rdpSessions?.length ?? 0})`, icon: "M2 3h20v14H2zM8 21h8M12 17v4" },
                  { id: "accounts", label: `Accounts (${data.accounts?.length || 0})`, icon: "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8" },
                  { id: "chains", label: `Chains (${data.chains.length})`, icon: "M13 17l5-5-5-5M6 17l5-5-5-5" },
                  { id: "table", label: `Connections (${data.edges.length})`, icon: "M3 3h18v18H3zM3 9h18M3 15h18M9 3v18M15 3v18" },
                  ...((data.executionSessions || []).length > 0 ? [{ id: "execSessions", label: `Exec Sessions (${data.executionSessions.length})`, icon: "M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18" }] : []),
                  ...((data.findings || []).length > 0 ? [{ id: "findings", label: `Findings (${data.findings.length})${(data.incidents || []).length > 0 ? ` / ${data.incidents.length} incidents` : ""}`, icon: "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01" }] : []),
                ].map((tab) => (
                  <button key={tab.id} onClick={() => setModal((p) => ({ ...p, viewTab: tab.id, selectedNode: null, selectedEdge: null }))}
                    style={{ padding: "5px 12px", background: viewTab === tab.id ? `linear-gradient(180deg, ${th.accent}ee, ${th.accent})` : "transparent", color: viewTab === tab.id ? "#fff" : th.textDim, border: "none", borderRadius: 6, fontSize: LM_TYPOGRAPHY.body, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: viewTab === tab.id ? 600 : 400, transition: "all var(--m-base)", display: "flex", alignItems: "center", gap: 5, boxShadow: viewTab === tab.id ? `0 1px 4px ${th.accent}44` : "none" }}
                    onMouseEnter={(ev) => { if (viewTab !== tab.id) ev.currentTarget.style.background = th.textMuted + "11"; }}
                    onMouseLeave={(ev) => { if (viewTab !== tab.id) ev.currentTarget.style.background = "transparent"; }}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d={tab.icon}/></svg>
                    {tab.label}
                  </button>
                ))}
              </div>

              <EvidenceDetailDrawer />

              {/* Execution Sessions tab */}
              {viewTab === "execSessions" && (() => {
                const eSessions = data.executionSessions || [];
                if (eSessions.length === 0) return <div style={{ padding: 40, textAlign: "center", color: th.textMuted, fontSize: LM_TYPOGRAPHY.title }}>No execution sessions detected.</div>;

                const esSortCol = modal.esSortCol || "Score";
                const esSortDir = modal.esSortDir || "desc";
                const esExpanded = modal.esExpanded;
                const esHeaders = ["Score", "Sev", "Technique", "Source", "Target", "User(s)", "Findings", "Events", "Start", "End", "Status"];
                const esColW = { Score: 48, Sev: 60, Technique: 100, Source: 130, Target: 130, "User(s)": 140, Findings: 60, Events: 56, Start: 145, End: 145, Status: 72 };
                const esCellVal = (s, h) => {
                  if (h === "Score") return s.triageScore || 0;
                  if (h === "Sev") return s.severity;
                  if (h === "Technique") return s.technique;
                  if (h === "Source") return s.source || "\u2014";
                  if (h === "Target") return s.target || "\u2014";
                  if (h === "User(s)") return (s.users || []).join(", ") || "(unknown)";
                  if (h === "Findings") return s.findingCount || 0;
                  if (h === "Events") return s.eventCount || 0;
                  if (h === "Start") return fmtTs(s.startTime);
                  if (h === "End") return fmtTs(s.endTime);
                  if (h === "Status") return s.status;
                  return "";
                };
                const sorted = [...eSessions].sort((a, b) => {
                  const av = esCellVal(a, esSortCol), bv = esCellVal(b, esSortCol);
                  const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                  return esSortDir === "desc" ? -cmp : cmp;
                });
                const toggleSort = (h) => setModal((p) => ({ ...p, esSortCol: h, esSortDir: p.esSortCol === h && p.esSortDir === "desc" ? "asc" : "desc" }));
                const _sevColor = (sev) => sev === "critical" ? th.sev.critical : sev === "high" ? th.sev.high : sev === "medium" ? th.sev.med : th.textMuted;
                const _statusStyle = (st) => st === "executed" ? { bg: th.sev.critical + "18", color: th.sev.critical, label: "EXECUTED" } : st === "observed" ? { bg: `${th.textMuted}15`, color: th.textMuted, label: "OBSERVED" } : { bg: th.sev.med + "18", color: th.sev.med, label: st.toUpperCase() };
                const _pillColor = _pillColors; // was a byte-identical duplicate of the map above

                return (
                  <div>
                    {/* Summary cards */}
                    <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
                      {[
                        { val: eSessions.length, label: "sessions", color: th.accent },
                        { val: eSessions.filter(s => s.severity === "critical").length, label: "critical", color: th.sev.critical },
                        { val: eSessions.filter(s => s.severity === "high").length, label: "high", color: th.sev.high },
                        { val: [...new Set(eSessions.flatMap(s => s.users || []))].length, label: "users", color: th.textDim },
                        { val: [...new Set(eSessions.map(s => s.technique))].length, label: "techniques", color: th.textDim },
                      ].map((c, i) => (
                        <div key={i} style={{ flex: 1, textAlign: "center", padding: "10px 8px", background: `${c.color}08`, border: `1px solid ${c.color}22`, borderRadius: 8 }}>
                          <div style={{ fontSize: LM_TYPOGRAPHY.metric, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif" }}>{c.val}</div>
                          <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                        </div>
                      ))}
                    </div>
                    {/* Toolbar: view mode toggle + copy/export */}
                    {(() => {
                      const esViewMode = modal.esViewMode || "table";
                      const copyEs = () => {
                        const header = ["Score", "Severity", "Technique", "Source", "Target", "Attributed Users", "Service Names", "Image Paths", "Event Accounts", "Service Accounts", "Command Lines", "Findings", "Events", "Start", "End", "Status"].join("\t");
                        const lines = sorted.map(s => [
                          s.triageScore, s.severity, s.technique, s.source, s.target,
                          (s.users || []).join("; "), (s.serviceNames || []).join("; "),
                          (s.imagePaths || []).join("; "), (s.eventActors || []).join("; "),
                          (s.serviceAccounts || []).join("; "), (s.commandLines || []).join("; "), s.findingCount, s.eventCount,
                          fmtTs(s.startTime), fmtTs(s.endTime), s.status,
                        ].join("\t"));
                        navigator.clipboard?.writeText?.([header, ...lines].join("\n"));
                      };
                      const exportEsCsv = () => {
                        const header = "Score,Severity,Technique,Source,Target,Attributed Users,Service Names,Image Paths,Event Accounts,Service Accounts,Command Lines,Findings,Events,Start,End,Status,Categories,Evidence Pills";
                        const csvEsc = csvCell; // shared encoder: RFC-4180 + formula-injection guard
                        const lines = sorted.map(s => [
                          s.triageScore, s.severity, s.technique, s.source, s.target,
                          (s.users || []).join("; "), (s.serviceNames || []).join("; "),
                          (s.imagePaths || []).join("; "), (s.eventActors || []).join("; "),
                          (s.serviceAccounts || []).join("; "), (s.commandLines || []).join("; "), s.findingCount, s.eventCount,
                          fmtTs(s.startTime), fmtTs(s.endTime), s.status,
                          (s.categories || []).join("; "), (s.evidencePills || []).map(p => p.text).join("; "),
                        ].map(csvEsc).join(","));
                        const blob = new Blob([header + "\n" + lines.join("\n")], { type: "text/csv" });
                        const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "execution-sessions.csv"; a.click(); URL.revokeObjectURL(a.href);
                      };
                      return (
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                          <div style={{ display: "inline-flex", background: th.panelBg, borderRadius: 6, padding: 2, border: `1px solid ${th.border}44`, gap: 1 }}>
                            {[{ id: "table", label: "Table" }, { id: "timeline", label: "Timeline" }].map((m) => (
                              <button key={m.id} onClick={() => setModal((p) => ({ ...p, esViewMode: m.id }))} style={{ padding: "2px 10px", background: esViewMode === m.id ? th.accent : "transparent", color: esViewMode === m.id ? "#fff" : th.textDim, border: "none", borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: esViewMode === m.id ? 600 : 400, transition: "all var(--m-base)" }}>{m.label}</button>
                            ))}
                          </div>
                          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                            <button onClick={copyEs} style={{ padding: "3px 10px", fontSize: LM_TYPOGRAPHY.control, background: th.btnBg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}
                              onMouseEnter={(ev) => { ev.currentTarget.style.background = th.accent + "22"; }} onMouseLeave={(ev) => { ev.currentTarget.style.background = th.btnBg; }}>
                              Copy All ({sorted.length})
                            </button>
                            <button onClick={exportEsCsv} style={{ padding: "3px 10px", fontSize: LM_TYPOGRAPHY.control, background: th.btnBg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 4 }}
                              onMouseEnter={(ev) => { ev.currentTarget.style.background = th.accent + "22"; }} onMouseLeave={(ev) => { ev.currentTarget.style.background = th.btnBg; }}>
                              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                              Export CSV
                            </button>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Timeline (Gantt) view */}
                    {(modal.esViewMode || "table") === "timeline" && (() => {
                      const _pt = (s) => { const ms = normalizeTimestamp(s); return Number.isFinite(ms) ? ms : 0; };
                      let tMin = Infinity, tMax = -Infinity;
                      for (const s of sorted) {
                        const st = _pt(s.startTime), et = _pt(s.endTime);
                        if (st && st < tMin) tMin = st;
                        if (et && et > tMax) tMax = et;
                        if (st && !et && st > tMax) tMax = st;
                      }
                      if (tMin === Infinity || tMax === -Infinity) return <div style={{ padding: 20, color: th.textMuted, fontSize: LM_TYPOGRAPHY.title, textAlign: "center" }}>No timestamps available for timeline.</div>;
                      const span = Math.max(tMax - tMin, 1);
                      const BAR_H = 20, ROW_H = 28, PAD_L = 160;
                      const fmtLabel = (ms) => { const d = new Date(ms); const p = (n) => String(n).padStart(2, "0"); return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`; };
                      const techColors = {};
                      // Categorical palette for techniques. th.sev is an ORDINAL scale, so
                      // borrowing it for categories is already a compromise — but the old
                      // array also included the brand accent and repeated critical and
                      // custom, so two techniques rendered identically. Distinct hues only.
                      const _tPalette = [th.sev.info, th.sev.clean, th.sev.custom, th.sev.high, th.sev.med, th.sev.critical, th.sev.low, th.textDim];
                      let _tci = 0;
                      for (const s of sorted) { if (!techColors[s.technique]) techColors[s.technique] = _tPalette[_tci++ % _tPalette.length]; }

                      return (
                        <div style={{ border: `1px solid ${th.border}44`, borderRadius: 6, overflow: "hidden", background: th.panelBg }}>
                          {/* Time axis header */}
                          <div style={{ display: "flex", padding: "4px 10px 4px " + PAD_L + "px", borderBottom: `1px solid ${th.border}33`, fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif", justifyContent: "space-between" }}>
                            <span>{fmtLabel(tMin)}</span>
                            <span>{fmtLabel(tMin + span * 0.25)}</span>
                            <span>{fmtLabel(tMin + span * 0.5)}</span>
                            <span>{fmtLabel(tMin + span * 0.75)}</span>
                            <span>{fmtLabel(tMax)}</span>
                          </div>
                          {/* Session bars */}
                          <div style={{ maxHeight: 420, overflowY: "auto" }}>
                            {sorted.map((s, i) => {
                              const st = _pt(s.startTime), et = _pt(s.endTime) || st;
                              const leftPct = ((st - tMin) / span) * 100;
                              const widthPct = Math.max(0.5, ((et - st) / span) * 100);
                              const sc = s.triageScore || 0;
                              const barColor = techColors[s.technique] || th.accent;
                              return (
                                <div key={s.id} onClick={() => setModal((p) => ({ ...p, esExpanded: p.esExpanded === s.id ? null : s.id, esViewMode: "table" }))}
                                  style={{ display: "flex", alignItems: "center", height: ROW_H, borderBottom: `1px solid ${th.border}15`, cursor: "pointer", fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}
                                  onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg + "88"; }}
                                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                                  {/* Label */}
                                  <div style={{ width: PAD_L, flexShrink: 0, padding: "0 8px", display: "flex", alignItems: "center", gap: 4, overflow: "hidden" }}>
                                    <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.meta, color: sc >= 30 ? th.sev.critical : sc >= 15 ? th.sev.high : th.textMuted, fontWeight: 700, flexShrink: 0, width: 22 }}>{sc}</span>
                                    <span style={{ padding: "1px 4px", background: barColor + "22", color: barColor, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, flexShrink: 0, whiteSpace: "nowrap" }}>{s.technique}</span>
                                    <span style={{ color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.users?.[0] || ""}</span>
                                  </div>
                                  {/* Bar area */}
                                  <div style={{ flex: 1, height: BAR_H, position: "relative", background: th.border + "11", marginRight: 8 }}>
                                    <div style={{ position: "absolute", left: `${leftPct}%`, width: `${widthPct}%`, height: "100%", background: `linear-gradient(90deg, ${barColor}cc, ${barColor}88)`, borderRadius: 3, minWidth: 3 }}
                                      title={`${s.technique}: ${s.source || "?"} → ${s.target || "?"}\n${(s.users || []).join(", ") || "(unknown)"}\n${fmtTs(s.startTime)} — ${fmtTs(s.endTime)}\nScore: ${sc} | ${s.eventCount} events | ${s.findingCount} findings`}>
                                      {widthPct > 8 && <span style={{ position: "absolute", left: 4, top: 2, fontSize: LM_TYPOGRAPHY.badge, color: "#fff", fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", right: 4 }}>{s.source || "?"} → {s.target || "?"}</span>}
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                          {/* Legend */}
                          <div style={{ padding: "6px 10px", borderTop: `1px solid ${th.border}22`, display: "flex", gap: 8, flexWrap: "wrap", fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                            {Object.entries(techColors).map(([tech, color]) => (
                              <span key={tech} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                                <span style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
                                {tech}
                              </span>
                            ))}
                            <span style={{ marginLeft: "auto", color: th.textDim, fontSize: LM_TYPOGRAPHY.meta }}>Click bar → expand in table</span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Table view */}
                    {(modal.esViewMode || "table") === "table" && (
                    <div style={{ border: `1px solid ${th.border}44`, borderRadius: 6, overflow: "hidden", background: th.panelBg }}>
                      {/* Header */}
                      <div style={{ display: "flex", background: `${th.headerBg}88`, borderBottom: `1px solid ${th.border}44`, fontSize: LM_TYPOGRAPHY.control, fontWeight: 600, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
                        {esHeaders.map((h) => (
                          <div key={h} onClick={() => toggleSort(h)}
                            style={{ width: esColW[h] || 80, padding: "8px 10px", cursor: "pointer", display: "flex", alignItems: "center", gap: 4, userSelect: "none", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {h}
                            {esSortCol === h && <span style={{ fontSize: LM_TYPOGRAPHY.meta, opacity: 0.7 }}>{esSortDir === "asc" ? "▲" : "▼"}</span>}
                          </div>
                        ))}
                        <div style={{ padding: "8px 10px", flexShrink: 0, fontSize: LM_TYPOGRAPHY.control, color: th.textMuted }}>Actions</div>
                      </div>
                      {/* Body */}
                      <div style={{ maxHeight: 480, overflowY: "auto" }}>
                        {sorted.map((s, idx) => {
                          const expanded = esExpanded === s.id;
                          const sc = s.triageScore || 0;
                          const stS = _statusStyle(s.status);
                          const executionDetails = s.executionDetails || [];
                          return (
                            <Fragment key={s.id}>
                              <div onClick={() => setModal((p) => ({ ...p, esExpanded: expanded ? null : s.id }))}
                                style={{ display: "flex", borderBottom: `1px solid ${th.border}22`, fontSize: LM_TYPOGRAPHY.body, color: th.text, fontFamily: "-apple-system, sans-serif", alignItems: "center", minHeight: 34, cursor: "pointer", background: expanded ? `${_sevColor(s.severity)}08` : idx % 2 === 0 ? "transparent" : `${th.border}08` }}>
                                {/* Score */}
                                <div style={{ width: esColW.Score, padding: "4px 10px", flexShrink: 0 }}>
                                  <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.body, color: sc >= 30 ? th.sev.critical : sc >= 15 ? th.sev.high : th.textMuted, fontWeight: 700 }}>{sc}</span>
                                </div>
                                {/* Severity */}
                                <div style={{ width: esColW.Sev, padding: "4px 8px", flexShrink: 0 }}>
                                  <span style={{ padding: "2px 6px", background: `${_sevColor(s.severity)}22`, color: _sevColor(s.severity), borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, textTransform: "uppercase" }}>{s.severity}</span>
                                </div>
                                {/* Technique */}
                                <div style={{ width: esColW.Technique, padding: "4px 8px", flexShrink: 0 }}>
                                  <span style={{ padding: "2px 6px", background: `${th.accent}15`, color: th.accent, borderRadius: 3, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, whiteSpace: "nowrap" }}>{s.technique}</span>
                                </div>
                                {/* Source */}
                                <div style={{ width: esColW.Source, padding: "4px 8px", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.source || "\u2014"}</div>
                                {/* Target */}
                                <div style={{ width: esColW.Target, padding: "4px 8px", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.target || "\u2014"}</div>
                                {/* Users */}
                                <div style={{ width: esColW["User(s)"], padding: "4px 8px", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }}>{(s.users || []).join(", ") || "(unknown)"}</div>
                                {/* Findings count */}
                                <div style={{ width: esColW.Findings, padding: "4px 8px", flexShrink: 0, textAlign: "center", fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.control }}>{s.findingCount}</div>
                                {/* Events count */}
                                <div style={{ width: esColW.Events, padding: "4px 8px", flexShrink: 0, textAlign: "center", fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.control }}>{s.eventCount}</div>
                                {/* Start */}
                                <div style={{ width: esColW.Start, padding: "4px 8px", flexShrink: 0, color: th.textDim, fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.control, whiteSpace: "nowrap" }}>{fmtTs(s.startTime)}</div>
                                {/* End */}
                                <div style={{ width: esColW.End, padding: "4px 8px", flexShrink: 0, color: th.textDim, fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.control, whiteSpace: "nowrap" }}>{fmtTs(s.endTime)}</div>
                                {/* Status */}
                                <div style={{ width: esColW.Status, padding: "4px 8px", flexShrink: 0 }}>
                                  <span style={{ padding: "2px 6px", background: stS.bg, color: stS.color, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700 }}>{stS.label}</span>
                                </div>
                                {/* Actions */}
                                <div style={{ display: "flex", gap: 3, padding: "4px 8px", flexShrink: 0, alignItems: "center" }}>
                                  <button onClick={(ev) => { ev.stopPropagation(); _filterEvents({ category: s.categories?.[0], filterEids: s.filterEids, filterHosts: s.filterHosts, timeRange: { from: s.startTime, to: s.endTime }, evidenceRefs: s.evidenceRefs, itemRowids: s.itemRowids }, ev); }}
                                    style={{ padding: "2px 6px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 600, whiteSpace: "nowrap", display: "flex", alignItems: "center", gap: 3 }}>
                                    <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2.5" strokeLinecap="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                                    Timeline
                                  </button>
                                  <button onClick={(ev) => { ev.stopPropagation(); _viewInGraph({ source: s.source, target: s.target }, ev); }}
                                    style={{ padding: "2px 6px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500, whiteSpace: "nowrap" }}>
                                    Graph
                                  </button>
                                  <EvidenceActions item={s} compact />
                                </div>
                              </div>
                              {/* Expanded detail */}
                              {expanded && (
                                <div style={{ padding: "12px 20px 16px 60px", borderBottom: `1px solid ${th.border}33`, background: `${_sevColor(s.severity)}04` }}>
                                  {/* Evidence pills */}
                                  {(s.evidencePills || []).length > 0 && (
                                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 10 }}>
                                      {s.evidencePills.map((p, pi) => (
                                        <span key={pi} style={{ padding: "2px 7px", borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, background: (_pillColor[p.type] || th.sev.low) + "18", color: _pillColor[p.type] || th.sev.low, fontFamily: "-apple-system, sans-serif" }}>{p.text}</span>
                                      ))}
                                    </div>
                                  )}
                                  {/* Session details */}
                                  <div style={{ display: "grid", gridTemplateColumns: "minmax(330px, 0.9fr) minmax(360px, 1.1fr)", gap: 24 }}>
                                    <div style={{ minWidth: 0, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif", color: th.textDim, lineHeight: 1.6 }}>
                                      {[
                                        ["Technique", s.technique],
                                        ["Categories", (s.categories || []).join(", ")],
                                        ["Source host", s.source || "(unknown)"],
                                        ["Target host", s.target || "(unknown)"],
                                        ["Attributed user", (s.users || []).join(", ") || "(not established)"],
                                        ["Event account", (s.eventActors || []).join(", ") || "(not recorded)"],
                                        ["Service account", (s.serviceAccounts || []).join(", ") || "(not recorded)"],
                                        ["Service", (s.serviceNames || []).join(", ") || "(not parsed)"],
                                        ["Image / file path", (s.imagePaths || []).join(", ") || "(not parsed)"],
                                        ["Command line", (s.commandLines || []).join(" | ") || "(not parsed)"],
                                        ["Events", s.eventCount],
                                        ["Time", `${fmtTs(s.startTime)} \u2014 ${fmtTs(s.endTime)}`],
                                      ].map(([label, value]) => (
                                        <div key={label} style={{ display: "grid", gridTemplateColumns: "110px minmax(0, 1fr)", gap: 8, padding: "2px 0" }}>
                                          <span style={{ color: th.textMuted }}>{label}</span>
                                          <span style={{ color: label === "Technique" ? th.accent : th.text, fontWeight: label === "Technique" ? 600 : 400, fontFamily: /path|command/i.test(label) ? "monospace" : "inherit", overflowWrap: "anywhere" }}>{value}</span>
                                        </div>
                                      ))}
                                      <div style={{ marginTop: 8 }}><EvidenceActions item={s} /></div>
                                    </div>
                                    {/* Related findings */}
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                      <div style={{ fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Related Findings ({s.findingCount})</div>
                                      <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                                        {(s.findingIds || []).map(fid => {
                                          const f = (data.findings || []).find(ff => ff.id === fid);
                                          if (!f) return null;
                                          return (
                                            <div key={fid} onClick={(ev) => { ev.stopPropagation(); setModal((p) => ({ ...p, viewTab: "findings", findingsView: "alerts", expandedFinding: fid })); }}
                                              style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 8px", borderRadius: 4, cursor: "pointer", background: `${_sevColor(f.severity)}08`, border: `1px solid ${_sevColor(f.severity)}22`, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}>
                                              <span style={{ padding: "1px 5px", background: `${_sevColor(f.severity)}22`, color: _sevColor(f.severity), borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, textTransform: "uppercase", flexShrink: 0 }}>{f.severity}</span>
                                              <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.meta, color: th.accent, flexShrink: 0 }}>{f.triageScore}</span>
                                              <span style={{ color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{f.category}: {f.title}</span>
                                            </div>
                                          );
                                        })}
                                      </div>
                                    </div>
                                  </div>
                                  <div style={{ marginTop: 12 }}>
                                    <div style={{ fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                                      Service execution evidence ({executionDetails.length})
                                    </div>
                                    {executionDetails.length > 0 ? (
                                      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                                        {executionDetails.map((detail, detailIdx) => (
                                          <div key={`${detail.eventId || "event"}-${detail.rowId ?? detailIdx}-${detail.timestamp || detailIdx}`}
                                            style={{ display: "grid", gridTemplateColumns: "95px minmax(120px, 0.7fr) minmax(180px, 1.2fr) minmax(180px, 1.2fr)", gap: "3px 10px", padding: "7px 9px", background: `${th.textMuted}08`, border: `1px solid ${th.border}44`, borderRadius: 5, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}>
                                            <span style={{ color: th.textMuted }}>Source event</span>
                                            <span style={{ color: th.text, fontFamily: "monospace" }}>EID {detail.eventId || "?"} · {fmtTs(detail.timestamp)}</span>
                                            <span style={{ color: th.textMuted }}>Target</span>
                                            <span style={{ color: th.text }}>{detail.target || s.target || "(unknown)"}</span>
                                            <span style={{ color: th.textMuted }}>Service</span>
                                            <span style={{ color: th.text, overflowWrap: "anywhere" }}>{detail.serviceName || "(not recorded)"}</span>
                                            <span style={{ color: th.textMuted }}>Image path</span>
                                            <span style={{ color: th.text, fontFamily: "monospace", overflowWrap: "anywhere" }}>{detail.imagePath || "(not recorded)"}</span>
                                            <span style={{ color: th.textMuted }}>Event account</span>
                                            <span style={{ color: th.text }}>{detail.eventActor || "(not recorded)"}</span>
                                            <span style={{ color: th.textMuted }}>Service account</span>
                                            <span style={{ color: th.text }}>{detail.serviceAccount || "(not recorded)"}</span>
                                            <span style={{ color: th.textMuted }}>Command line</span>
                                            <span style={{ color: th.text, fontFamily: "monospace", overflowWrap: "anywhere" }}>{detail.commandLine || "(not recorded)"}</span>
                                            <span style={{ color: th.textMuted }}>Attributed user</span>
                                            <span style={{ color: th.text }}>{detail.attributedUser || "(not established)"}</span>
                                            <span style={{ color: th.textMuted }}>Source host</span>
                                            <span style={{ color: th.text }}>{detail.sourceHost || "(not established)"}</span>
                                            <span style={{ color: th.textMuted }}>Detection reason</span>
                                            <span style={{ color: th.text }}>{detail.reason || "(not recorded)"}</span>
                                          </div>
                                        ))}
                                      </div>
                                    ) : (
                                      <div style={{ padding: "7px 9px", color: th.textMuted, background: `${th.textMuted}08`, border: `1px solid ${th.border}44`, borderRadius: 5, fontSize: LM_TYPOGRAPHY.control }}>
                                        The source finding does not expose service-install fields. Use Open exact to inspect the underlying event row.
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                            </Fragment>
                          );
                        })}
                      </div>
                    </div>
                    )}
                  </div>
                );
              })()}

              {/* Findings tab */}
              {viewTab === "findings" && (() => {
                const findings = data.findings || [];
                const allIncidents = data.incidents || [];
                const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
                findings.forEach((f) => { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++; });
                const findingsView = modal.findingsView || "alerts";
                const sortBy = modal.findingsSortBy || "triage";
                const groupBy = modal.findingsGroupBy || "default";
                const expandedId = modal.expandedFinding;
                const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };

                const _dsEnd = data.stats?.datasetEnd ? new Date(data.stats.datasetEnd) : null;
                const _recency = (f) => {
                  if (!_dsEnd || !f.timeRange?.to) return null;
                  const fEnd = new Date(f.timeRange.to);
                  if (isNaN(fEnd)) return null;
                  const diffMs = _dsEnd - fEnd;
                  if (diffMs < 0) return { label: "0m ago", active: true };
                  if (diffMs < 900000) return { label: `${Math.round(diffMs / 60000)}m ago`, active: true };
                  if (diffMs < 3600000) return { label: `${(diffMs / 3600000).toFixed(1)}h ago`, active: false };
                  if (diffMs < 86400000) return { label: `${Math.round(diffMs / 3600000)}h ago`, active: false };
                  return { label: `${Math.round(diffMs / 86400000)}d ago`, active: false };
                };

                const sortedFindings = [...findings].sort((a, b) => {
                  if (sortBy === "triage") {
                    return ((b.triageScore || 0) - (a.triageScore || 0))
                      || ((severityRank[a.severity] ?? 4) - (severityRank[b.severity] ?? 4))
                      || (((b.timeRange?.to) || "").localeCompare((a.timeRange?.to) || ""))
                      || String(a.title || "").localeCompare(String(b.title || ""));
                  }
                  if (sortBy === "severity") return ((severityRank[a.severity] ?? 4) - (severityRank[b.severity] ?? 4)) || ((b.triageScore || 0) - (a.triageScore || 0));
                  if (sortBy === "recency") return ((b.timeRange?.to) || "").localeCompare((a.timeRange?.to) || "");
                  if (sortBy === "events") return (b.eventCount || 0) - (a.eventCount || 0);
                  return 0;
                });

                let groupedEntries = null;
                if (groupBy !== "default") {
                  const groups = new Map();
                  for (const f of sortedFindings) {
                    let keys = ["(none)"];
                    if (groupBy === "target") keys = (f.target || "").split(", ").filter(Boolean);
                    else if (groupBy === "source") keys = (f.source || "").split(", ").filter(Boolean);
                    else if (groupBy === "user") keys = (f.users && f.users.length > 0) ? f.users : ["(unknown)"];
                    else if (groupBy === "technique") keys = [f.mitre || "(none)"];
                    if (keys.length === 0) keys = ["(none)"];
                    for (const k of keys) {
                      if (!groups.has(k)) groups.set(k, []);
                      groups.get(k).push(f);
                    }
                  }
                  groupedEntries = [...groups.entries()].sort((a, b) => Math.max(...b[1].map(f => f.triageScore || 0)) - Math.max(...a[1].map(f => f.triageScore || 0)));
                }

                // _filterEvents and _viewInGraph hoisted to component scope above

                const _btnS = { padding: "2px 8px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 };
                const _btnActive = (active) => active ? { ..._btnS, background: th.accent, color: "#fff" } : _btnS;

                const _renderCard = (f) => {
                  const isExpanded = expandedId === f.id;
                  const rec = _recency(f);
                  const pills = f.evidencePills || [];
                  return (
                    <div key={f.id} style={{ borderRadius: 6, border: `1px solid ${isExpanded ? th.accent + "55" : th.border + "66"}`, background: isExpanded ? `${th.accent}08` : th.panelBg, cursor: "pointer", transition: "border-color var(--m-base)" }}
                      onClick={() => setModal((p) => ({ ...p, expandedFinding: isExpanded ? null : f.id }))}
                      onMouseEnter={(e) => { if (!isExpanded) e.currentTarget.style.borderColor = th.accent + "44"; }}
                      onMouseLeave={(e) => { if (!isExpanded) e.currentTarget.style.borderColor = th.border + "66"; }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 10px", minHeight: 28 }}>
                        <span style={{ padding: "1px 6px", background: `${th.accent}16`, color: th.accent, border: `1px solid ${th.accent}28`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, textTransform: "uppercase", fontFamily: "-apple-system, sans-serif", letterSpacing: "0.03em", flexShrink: 0 }}>{f.severity}</span>
                        <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.meta, color: th.accent, background: `${th.accent}15`, padding: "1px 4px", borderRadius: 3, fontWeight: 600, flexShrink: 0, minWidth: 20, textAlign: "center" }}>{f.triageScore || 0}</span>
                        <MitreBadge id={f.mitre} />
                        <span style={{ fontSize: LM_TYPOGRAPHY.body, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</span>
                        {rec && <span style={{ fontSize: LM_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, fontWeight: 600, fontFamily: "-apple-system, sans-serif", flexShrink: 0, background: rec.active ? `${th.accent}14` : `${th.textMuted}12`, color: rec.active ? th.accent : th.textMuted }}>{rec.active ? "ACTIVE " : ""}{rec.label}</span>}
                        {pills.slice(0, 3).map((p, i) => (
                          <span key={i} style={{ fontSize: LM_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${th.textMuted}12`, color: th.textDim, border: `1px solid ${th.border}44`, fontWeight: 500, fontFamily: "-apple-system, sans-serif", flexShrink: 0, whiteSpace: "nowrap" }}>{p.text}</span>
                        ))}
                        {(f.relatedFindingIds || []).length > 0 && <span style={{ fontSize: LM_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontWeight: 500, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>+{f.relatedFindingIds.length} related</span>}
                      </div>
                      {isExpanded && (
                        <div style={{ padding: "8px 10px 10px", borderTop: `1px solid ${th.border}66` }} onClick={(e) => e.stopPropagation()}>
                          <div style={{ fontSize: LM_TYPOGRAPHY.body, color: th.textDim, fontFamily: "-apple-system, sans-serif", marginBottom: 8, lineHeight: 1.5 }}>{f.description}</div>
                          <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "monospace", marginBottom: 6 }}>
                            {f.source}{f.target && f.target !== f.source ? ` \u2192 ${f.target}` : ""}
                            {f.timeRange?.from && <span style={{ marginLeft: 12 }}>{fmtTs(f.timeRange.from)}{f.timeRange.to && f.timeRange.to !== f.timeRange.from ? ` \u2014 ${fmtTs(f.timeRange.to)}` : ""}</span>}
                            <span style={{ marginLeft: 12 }}>{f.eventCount} event{f.eventCount !== 1 ? "s" : ""}</span>
                          </div>
                          {pills.length > 0 && (
                            <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 8 }}>
                              {pills.map((p, i) => (
                                <span key={i} style={{ fontSize: LM_TYPOGRAPHY.meta, padding: "2px 7px", borderRadius: 4, background: `${th.textMuted}12`, color: th.textDim, border: `1px solid ${th.border}44`, fontWeight: 500, fontFamily: "-apple-system, sans-serif" }}>{p.text}</span>
                              ))}
                            </div>
                          )}
                          {(f.relatedFindingIds || []).length > 0 && (
                            <div style={{ marginBottom: 8 }}>
                              <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontWeight: 600, marginBottom: 4, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.04em" }}>Related Findings</div>
                              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                {f.relatedFindingIds.slice(0, 4).map(rid => {
                                  const rf = findings.find(x => x.id === rid);
                                  if (!rf) return null;
                                  return (
                                    <span key={rid} style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 7px", background: `${th.textMuted}0d`, border: `1px solid ${th.border}55`, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}
                                      onClick={(e) => { e.stopPropagation(); setModal((p) => ({ ...p, expandedFinding: rid, findingsView: "alerts" })); }}>
                                      <span style={{ color: th.accent, fontWeight: 600, textTransform: "uppercase", fontSize: LM_TYPOGRAPHY.badge }}>{rf.severity}</span>
                                      <span style={{ color: th.text, maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{rf.title}</span>
                                    </span>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                            <button onClick={(e) => _filterEvents(f, e)}
                              style={{ ...(_btnS), background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontWeight: 600 }}
                              title="Close this modal and filter the main timeline grid to the events related to this finding">
                              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2.5" strokeLinecap="round" style={{ marginRight: 3, verticalAlign: "middle", display: "inline" }}>
                                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                              </svg>
                              Show in Timeline
                            </button>
                            <button onClick={(e) => _viewInGraph(f, e)} style={_btnS}>View in Graph</button>
                            <button onClick={(e) => { e.stopPropagation(); setModal((p) => ({ ...p, viewTab: "chains" })); }} style={_btnS}>Show Chains</button>
                            <button onClick={(e) => {
                              e.stopPropagation();
                              const lines = [`[${f.severity.toUpperCase()}] ${f.category} (${f.mitre})`, f.title, `Source: ${f.source || "(none)"} \u2192 Target: ${f.target || "(none)"}`, `Time: ${fmtTs(f.timeRange?.from)} \u2014 ${fmtTs(f.timeRange?.to)}`, `Events: ${f.eventCount}`];
                              if (pills.length > 0) lines.push(`Evidence: ${pills.map(p => p.text).join(", ")}`);
                              lines.push(`Description: ${f.description}`);
                              navigator.clipboard?.writeText?.(lines.join("\n"));
                            }} style={_btnS}>Copy IOC</button>
                            <EvidenceActions item={f} />
                          </div>
                        </div>
                      )}
                    </div>
                  );
                };

                return (
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
                      <button onClick={() => setModal((p) => ({ ...p, findingsView: "alerts" }))} style={_btnActive(findingsView === "alerts")}>Alerts ({findings.length})</button>
                      {allIncidents.length > 0 && <button onClick={() => setModal((p) => ({ ...p, findingsView: "incidents" }))} style={_btnActive(findingsView === "incidents")}>Incidents ({allIncidents.length})</button>}
                      {(data.campaigns || []).length > 0 && <button onClick={() => setModal((p) => ({ ...p, findingsView: "campaigns" }))} style={_btnActive(findingsView === "campaigns")}>Campaigns ({data.campaigns.length})</button>}
                      <span style={{ width: 1, height: 16, background: th.border, margin: "0 4px" }} />
                      <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Sort:</span>
                      <select value={sortBy} onChange={(e) => setModal((p) => ({ ...p, findingsSortBy: e.target.value }))} style={{ fontSize: LM_TYPOGRAPHY.meta, padding: "2px 4px", background: th.bg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 3, fontFamily: "-apple-system, sans-serif" }}>
                        <option value="triage">Priority</option><option value="severity">Severity</option><option value="recency">Recency</option><option value="events">Events</option>
                      </select>
                      {findingsView === "alerts" && <>
                        <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Group:</span>
                        <select value={groupBy} onChange={(e) => setModal((p) => ({ ...p, findingsGroupBy: e.target.value }))} style={{ fontSize: LM_TYPOGRAPHY.meta, padding: "2px 4px", background: th.bg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 3, fontFamily: "-apple-system, sans-serif" }}>
                          <option value="default">None</option><option value="target">Target</option><option value="source">Source</option><option value="user">User</option><option value="technique">Technique</option>
                        </select>
                      </>}
                      <span style={{ width: 1, height: 16, background: th.border, margin: "0 4px" }} />
                      {Object.entries(sevCounts).filter(([, v]) => v > 0).map(([sev, cnt]) => (
                        <span key={sev} style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 7px", background: `${th.accent}12`, color: th.accent, border: `1px solid ${th.accent}22`, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase" }}>
                          {cnt} {sev}
                        </span>
                      ))}
                    </div>

                    {findingsView === "alerts" && (() => {
                      // Finding cards are expandable, so their height varies and fixed-row
                      // windowing does not apply. The analyzer caps nothing, and per-edge
                      // First-Seen findings scale with edge count, so a large dataset used
                      // to mount every card at once. Render a bounded prefix instead — the
                      // list is already sorted by triage score, so the cap keeps the most
                      // important findings — and say plainly what is being held back.
                      const limit = modal.lmAlertLimit || 300;
                      let budget = limit;
                      const total = groupedEntries
                        ? groupedEntries.reduce((n, [, g]) => n + g.length, 0)
                        : sortedFindings.length;
                      const hidden = Math.max(0, total - limit);
                      return (
                        <div style={{ maxHeight: lmH - 250, overflowY: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
                          {groupedEntries ? groupedEntries.map(([gKey, gFindings]) => {
                            if (budget <= 0) return null;
                            const shown = gFindings.slice(0, budget);
                            budget -= shown.length;
                            return (
                              <div key={gKey}>
                                <div style={{ fontSize: LM_TYPOGRAPHY.control, fontWeight: 600, color: th.textDim, padding: "6px 0 4px", fontFamily: "-apple-system, sans-serif", borderBottom: `1px solid ${th.border}`, marginBottom: 4 }}>
                                  {gKey} <span style={{ fontWeight: 400, color: th.textMuted }}>({gFindings.length} findings) | Top score: {Math.max(...gFindings.map(f => f.triageScore || 0))}</span>
                                </div>
                                {shown.map(f => _renderCard(f))}
                              </div>
                            );
                          }) : sortedFindings.slice(0, limit).map(f => _renderCard(f))}
                          {hidden > 0 && (
                            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, padding: "10px 0 4px", fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                              <span>Showing {total - hidden} of {total} findings (highest triage score first)</span>
                              <button onClick={() => setModal((p) => ({ ...p, lmAlertLimit: (p.lmAlertLimit || 300) + 300 }))}
                                style={{ ...ms.bs, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control, padding: "3px 10px" }}>Show 300 more</button>
                              <button onClick={() => setModal((p) => ({ ...p, lmAlertLimit: total }))}
                                style={{ ...ms.bs, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control, padding: "3px 10px" }}>Show all {total}</button>
                            </div>
                          )}
                        </div>
                      );
                    })()}

                    {findingsView === "incidents" && (
                      <div style={{ maxHeight: lmH - 250, overflowY: "auto", display: "flex", flexDirection: "column", gap: 8 }}>
                        {allIncidents.map((inc) => {
                          const memberFindings = inc.findings.map(fid => findings.find(f => f.id === fid)).filter(Boolean);
                          const rec = _recency({ timeRange: inc.timeRange });
                          const techPills = (inc.techniques || []).map(t => {
                            const color = th.textDim; // MITRE technique chips are neutral metadata (match the neutral MitreBadge)
                            return { text: t, color };
                          });
                          return (
                            <div key={inc.id} style={{ padding: "10px 12px", background: `${th.accent}06`, border: `1px solid ${th.border}66`, borderRadius: 8 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6, flexWrap: "wrap" }}>
                                <span style={{ padding: "1px 6px", background: `${th.accent}16`, color: th.accent, border: `1px solid ${th.accent}28`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, textTransform: "uppercase", fontFamily: "-apple-system, sans-serif" }}>{inc.severity}</span>
                                <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.meta, color: th.accent, background: `${th.accent}15`, padding: "1px 4px", borderRadius: 3, fontWeight: 600 }}>{inc.triageScore}</span>
                                {techPills.map((tp, i) => <span key={i} style={{ fontSize: LM_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: tp.color + "18", color: tp.color, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{tp.text}</span>)}
                                {rec && <span style={{ fontSize: LM_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, fontWeight: 600, fontFamily: "-apple-system, sans-serif", marginLeft: "auto", background: rec.active ? `${th.accent}14` : `${th.textMuted}12`, color: rec.active ? th.accent : th.textMuted }}>{rec.active ? "ACTIVE " : ""}{rec.label}</span>}
                              </div>
                              <div style={{ fontSize: LM_TYPOGRAPHY.body, color: th.text, fontFamily: "-apple-system, sans-serif", marginBottom: 6, lineHeight: 1.5 }}>{inc.narrative}</div>
                              <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "monospace", marginBottom: 6 }}>
                                {inc.source} {"\u2192"} {inc.target}
                                {inc.users.length > 0 && <span style={{ marginLeft: 10 }}>users: {inc.users.slice(0, 3).join(", ")}{inc.users.length > 3 ? ` +${inc.users.length - 3}` : ""}</span>}
                                <span style={{ marginLeft: 10 }}>{inc.eventCount} events</span>
                              </div>
                              <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 8 }}>
                                {memberFindings.map(mf => (
                                  <span key={mf.id} style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 7px", background: `${th.textMuted}0d`, border: `1px solid ${th.border}55`, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}
                                    onClick={() => setModal((p) => ({ ...p, findingsView: "alerts", expandedFinding: mf.id }))}>
                                    <span style={{ color: th.accent, fontWeight: 600, textTransform: "uppercase", fontSize: LM_TYPOGRAPHY.badge }}>{mf.severity}</span>
                                    <span style={{ color: th.text, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{mf.category}</span>
                                  </span>
                                ))}
                              </div>
                              <div style={{ display: "flex", gap: 4 }}>
                                <button onClick={() => {
                                  const lmCols = data.columns || {};
                                  const allEids = [...new Set(memberFindings.flatMap(mf => mf.filterEids || []))];
                                  const allHosts = [...new Set(memberFindings.flatMap(mf => mf.filterHosts || []))];
                                  const cbf = { ...(ct?.checkboxFilters || {}) };
                                  if (allEids.length > 0 && lmCols.eventId) cbf[lmCols.eventId] = allEids;
                                  if (allHosts.length > 0 && lmCols.target) cbf[lmCols.target] = allHosts;
                                  up("checkboxFilters", cbf);
                                  if (lmCols.ts && inc.timeRange?.from) {
                                    const rawFrom = inc.timeRange.from, rawTo = inc.timeRange.to || rawFrom;
                                    // (uses the shared _padTs — this was a verbatim duplicate that round-tripped through LOCAL getters)
                                    up("dateRangeFilters", { [lmCols.ts]: { from: _padTs(rawFrom, -300000), to: _padTs(rawTo, 300000) } });
                                  }
                                  up("searchTerm", ""); up("columnFilters", {});
                                  setModal(null);
                                }} style={{ ...(_btnS), background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontWeight: 600 }}
                                  title="Close this modal and filter the main timeline to all events from this incident">
                                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2.5" strokeLinecap="round" style={{ marginRight: 3, verticalAlign: "middle", display: "inline" }}>
                                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                                  </svg>
                                  Show in Timeline
                                </button>
                                <button onClick={() => {
                                  const f = memberFindings[0];
                                  if (f) _viewInGraph(f);
                                }} style={_btnS}>View in Graph</button>
                                <button onClick={() => {
                                  const lines = [`[INCIDENT] ${inc.severity.toUpperCase()} — Score: ${inc.triageScore}`, `Attack chain: ${inc.category}`, `${inc.source} \u2192 ${inc.target}`, `Users: ${inc.users.join(", ") || "(unknown)"}`, `Time: ${fmtTs(inc.timeRange?.from)} \u2014 ${fmtTs(inc.timeRange?.to)}`, `Events: ${inc.eventCount}`, `Narrative: ${inc.narrative}`, "", "Contributing findings:"];
                                  for (const mf of memberFindings) lines.push(`  [${mf.severity.toUpperCase()}] ${mf.category} (${mf.mitre}): ${mf.title}`);
                                  navigator.clipboard?.writeText?.(lines.join("\n"));
                                }} style={_btnS}>Copy IOC Summary</button>
                                <EvidenceActions item={inc} />
                              </div>
                            </div>
                          );
                        })}
                        {allIncidents.length === 0 && <div style={{ fontSize: LM_TYPOGRAPHY.body, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: 20, textAlign: "center" }}>No incidents — findings are not clustered into multi-detection groups.</div>}
                      </div>
                    )}

                    {/* Campaigns sub-view */}
                    {findingsView === "campaigns" && (() => {
                      const allCampaigns = data.campaigns || [];
                      if (allCampaigns.length === 0) return <div style={{ padding: 20, textAlign: "center", color: th.textMuted, fontSize: LM_TYPOGRAPHY.title }}>No campaigns — at least 2 related incidents are needed to form a storyline.</div>;
                      const expandedCamp = modal.expandedCampaign;
                      return (
                        <div style={{ maxHeight: lmH - 250, overflowY: "auto", display: "flex", flexDirection: "column", gap: 10 }}>
                          {allCampaigns.map((camp) => {
                            const isExp = expandedCamp === camp.id;
                            const campSevColor = th.accent;
                            const memberIncs = (camp.incidentIds || []).map(id => allIncidents.find(inc => inc.id === id)).filter(Boolean);
                            return (
                              <div key={camp.id} style={{ borderRadius: 8, border: `1px solid ${campSevColor}${isExp ? "55" : "22"}`, background: `${campSevColor}${isExp ? "0c" : "04"}`, overflow: "hidden" }}>
                                {/* Campaign header */}
                                <div onClick={() => setModal((p) => ({ ...p, expandedCampaign: isExp ? null : camp.id }))}
                                  style={{ padding: "10px 14px", cursor: "pointer", display: "flex", alignItems: "flex-start", gap: 8 }}>
                                  <div style={{ display: "flex", flexDirection: "column", gap: 4, flex: 1, minWidth: 0 }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                                      <span style={{ padding: "2px 8px", background: campSevColor + "22", color: campSevColor, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 700, textTransform: "uppercase", fontFamily: "-apple-system, sans-serif" }}>{camp.severity}</span>
                                      <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.control, color: th.accent, background: `${th.accent}15`, padding: "2px 6px", borderRadius: 4, fontWeight: 700 }}>{camp.triageScore}</span>
                                      <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{camp.incidentCount} incidents | {camp.findingCount} findings | {camp.eventCount} events</span>
                                    </div>
                                    <div style={{ fontSize: LM_TYPOGRAPHY.title, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>
                                      {camp.hopPairs.join(" \u2192 ")}
                                    </div>
                                    <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>{camp.narrative}</div>
                                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 2 }}>
                                      {(camp.users || []).slice(0, 5).map((u, i) => (
                                        <span key={i} style={{ padding: "1px 5px", background: `${th.accent}12`, color: th.accent, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 500, fontFamily: "-apple-system, sans-serif" }}>{u}</span>
                                      ))}
                                      {(camp.users || []).length > 5 && <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted }}>+{camp.users.length - 5}</span>}
                                      {(camp.techniques || []).slice(0, 6).map((t, i) => (
                                        <span key={`t${i}`} style={{ padding: "1px 5px", background: `${th.textMuted}12`, color: th.textDim, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontFamily: "-apple-system, sans-serif" }}>{t}</span>
                                      ))}
                                    </div>
                                  </div>
                                  <span style={{ fontSize: LM_TYPOGRAPHY.title, color: th.textMuted, flexShrink: 0, padding: "2px 4px" }}>{isExp ? "▼" : "▶"}</span>
                                </div>
                                {/* Expanded: member incidents + timeline + actions */}
                                {isExp && (
                                  <div style={{ padding: "0 14px 14px", borderTop: `1px solid ${campSevColor}22` }}>
                                    {/* Movement path visualization */}
                                    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "10px 0", flexWrap: "wrap" }}>
                                      {camp.hopPairs.map((hop, hi) => (
                                        <Fragment key={hi}>
                                          {hi > 0 && <span style={{ color: th.accent, fontSize: LM_TYPOGRAPHY.control, fontWeight: 700 }}>{"\u2192"}</span>}
                                          <span style={{ padding: "3px 8px", background: `${campSevColor}15`, color: campSevColor, borderRadius: 4, fontSize: LM_TYPOGRAPHY.control, fontWeight: 600, fontFamily: "monospace", whiteSpace: "nowrap" }}>{hop}</span>
                                        </Fragment>
                                      ))}
                                    </div>
                                    {/* Member incidents */}
                                    <div style={{ fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Member Incidents ({memberIncs.length})</div>
                                    <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 10 }}>
                                      {memberIncs.map((inc) => {
                                        const incSevColor = th.accent;
                                        return (
                                          <div key={inc.id} onClick={() => setModal((p) => ({ ...p, findingsView: "incidents", expandedCampaign: null }))}
                                            style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 10px", borderRadius: 4, cursor: "pointer", background: `${incSevColor}08`, border: `1px solid ${incSevColor}22`, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}>
                                            <span style={{ padding: "1px 5px", background: `${incSevColor}22`, color: incSevColor, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, textTransform: "uppercase", flexShrink: 0 }}>{inc.severity}</span>
                                            <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.meta, color: th.accent, flexShrink: 0 }}>{inc.triageScore}</span>
                                            <span style={{ color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{inc.source} {"\u2192"} {inc.target}: {inc.category}</span>
                                            <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.meta, flexShrink: 0 }}>{inc.eventCount} events</span>
                                          </div>
                                        );
                                      })}
                                    </div>
                                    {/* Actions */}
                                    <div style={{ display: "flex", gap: 4 }}>
                                      <button onClick={(ev) => {
                                        const allFilterHosts = camp.hosts || [];
                                        const allFilterEids = [...new Set(memberIncs.flatMap(inc => (inc.findings || []).flatMap(fid => { const f = findings.find(ff => ff.id === fid); return f?.filterEids || []; })))];
                                        _filterEvents({ filterEids: allFilterEids.length > 0 ? allFilterEids : undefined, filterHosts: allFilterHosts, timeRange: camp.timeRange, evidenceRefs: camp.evidenceRefs, itemRowids: camp.itemRowids }, ev);
                                      }} style={{ ..._btnS, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontWeight: 600, display: "flex", alignItems: "center", gap: 4 }}>
                                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2.5" strokeLinecap="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                                        Show in Timeline
                                      </button>
                                      <button onClick={() => {
                                        const lines = [`[CAMPAIGN] ${camp.severity.toUpperCase()} — Score: ${camp.triageScore}`, `Hosts: ${camp.hosts.join(", ")}`, `Users: ${(camp.users || []).join(", ") || "(unknown)"}`, `Techniques: ${(camp.techniques || []).join(", ")}`, `Time: ${fmtTs(camp.timeRange?.from)} — ${fmtTs(camp.timeRange?.to)}`, `Path: ${camp.hopPairs.join(" → ")}`, "", camp.narrative, "", `${camp.incidentCount} incidents, ${camp.findingCount} findings, ${camp.eventCount} events`];
                                        navigator.clipboard?.writeText?.(lines.join("\n"));
                                      }} style={_btnS}>Copy Summary</button>
                                      <button onClick={(ev) => {
                                        // Find the first incident's source→target pair and highlight it in the graph
                                        const first = memberIncs[0];
                                        if (first) _viewInGraph({ source: first.source, target: first.target }, ev);
                                      }} style={_btnS}>View in Graph</button>
                                      <button onClick={() => setModal((p) => ({ ...p, findingsView: "incidents", expandedCampaign: null }))}
                                        style={_btnS}>View Incidents</button>
                                      <EvidenceActions item={camp} />
                                    </div>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      );
                    })()}
                  </div>
                );
              })()}

              {/* Directed machine graph with an optional evidence-backed identity overlay. */}
              {viewTab === "graph" && (() => {
                const _techColor = (tech) => {
                  if (!tech) return th.textMuted;
                  if (tech.includes("Cleartext") || tech.includes("Service Exec") || tech.includes("PsExec") || tech.includes("Impacket")) return th.sev.critical;
                  if (tech.includes("Admin Share")) return th.sev.high;
                  if (tech.includes("RDP")) return th.sev.info;
                  if (tech.includes("Interactive")) return th.sev.clean;
                  if (tech.includes("Scheduled Task") || tech.includes("WMI") || tech.includes("WinRM")) return th.sev.high;
                  return th.textMuted;
                };
                const W = LATERAL_GRAPH_DEFAULTS.width;
                const H = LATERAL_GRAPH_DEFAULTS.height;
                const graphMode = modal.lmGraphMode || "machines";
                const {
                  machineNodes,
                  machineEdges,
                  machineEligibleEdgeCount,
                  identityGraph,
                  identityNodes,
                  identityEdges,
                  identityEligibleEdgeCount,
                } = lateralGraphModel;
                const graphNodes = graphMode === "identities" ? identityNodes : machineNodes;
                const graphEdges = graphMode === "identities" ? identityEdges : machineEdges;
                const graphEligibleEdgeCount = graphMode === "identities"
                  ? identityEligibleEdgeCount
                  : machineEligibleEdgeCount;
                const graphEdgeKeys = new Set(graphEdges.map((e) => `${e.source}->${e.target}`));
                const graphHostCount = graphNodes.filter((node) => node.nodeType !== "identity").length;
                const graphIdentityCount = graphNodes.filter((node) => node.nodeType === "identity").length;
                const setGraphMode = (nextMode) => {
                  const nextGraph = nextMode === "identities"
                    ? { nodes: identityNodes, edges: identityEdges }
                    : { nodes: machineNodes, edges: machineEdges };
                  setModal((prev) => ({
                    ...prev,
                    lmGraphMode: nextMode,
                    positions: computeForceLayout(nextGraph.nodes, nextGraph.edges),
                    selectedNode: null,
                    selectedEdge: null,
                    viewBox: { x: 0, y: 0, w: W, h: H },
                  }));
                };
                const edgeFailureCount = (edge) =>
                  Number(edge.eventBreakdown?.["4625"] || 0)
                  + Number(edge.eventBreakdown?.["4771"] || 0);
                const edgeSuccessCount = (edge) =>
                  Number(edge.eventBreakdown?.["4624"] || 0)
                  + Number(edge.eventBreakdown?.["1149"] || 0)
                  + Number(edge.eventBreakdown?.["21"] || 0)
                  + Number(edge.eventBreakdown?.["22"] || 0);
                const edgeFailureOnly = (edge) => edgeFailureCount(edge) > 0 && edgeSuccessCount(edge) === 0;
                const edgeMixedOutcome = (edge) => edgeFailureCount(edge) > 0 && edgeSuccessCount(edge) > 0;
                const maxGraphLevel = Math.max(0, ...Object.values(positions).map((p) => Number(p?.level) || 0));
                const vb = modal.viewBox || { x: 0, y: 0, w: W, h: H };
                const isIP = (s) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s);
                const isDC = (s) => /DC\d*$/i.test(s) || /domain.controller/i.test(s);
                const logonLabel = (types) => { const t = types.map(String); if (t.includes("10")) return "RDP"; if (t.includes("12")) return "Cached RDP"; if (t.includes("8")) return "Cleartext"; if (t.includes("3")) return "Net"; if (t.includes("4")) return "Batch"; if (t.includes("5")) return "Service"; if (t.includes("2")) return "Local"; if (t.includes("7")) return "Unlock"; if (t.includes("9")) return "RunAs"; if (t.includes("11")) return "Cached"; if (t.includes("13")) return "Cached Unlock"; return t.join(","); };
                const tbtn = { padding: "4px 10px", background: `${th.panelBg}cc`, color: th.textDim, border: `1px solid ${th.border}44`, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control, cursor: "pointer", fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 4, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", transition: "all var(--m-base)", fontWeight: 500 };

                const svgToWorld = (clientX, clientY, svgEl) => {
                  if (!svgEl) return { x: 0, y: 0 };
                  const rect = svgEl.getBoundingClientRect();
                  const sx = (clientX - rect.left) / rect.width;
                  const sy = (clientY - rect.top) / rect.height;
                  return { x: vb.x + sx * vb.w, y: vb.y + sy * vb.h };
                };

                const onWheel = (ev) => {
                  if (selectedNode || selectedEdge) return;
                  ev.preventDefault();
                  const svg = ev.currentTarget;
                  const pt = svgToWorld(ev.clientX, ev.clientY, svg);
                  const factor = ev.deltaY > 0 ? 1.15 : 1 / 1.15;
                  const nw = Math.max(100, Math.min(W * 4, vb.w * factor));
                  const nh = Math.max(65, Math.min(H * 4, vb.h * factor));
                  const nx = pt.x - (pt.x - vb.x) * (nw / vb.w);
                  const ny = pt.y - (pt.y - vb.y) * (nh / vb.h);
                  setModal((p) => ({ ...p, viewBox: { x: nx, y: ny, w: nw, h: nh } }));
                };

                const onPanStart = (ev) => {
                  if (ev.button !== 0) return;
                  const svg = ev.currentTarget;
                  const startVb = { ...vb };
                  const onMove = (me) => {
                    const rect = svg.getBoundingClientRect();
                    const dx = ((me.clientX - ev.clientX) / rect.width) * startVb.w;
                    const dy = ((me.clientY - ev.clientY) / rect.height) * startVb.h;
                    setModal((p) => ({ ...p, viewBox: { ...startVb, x: startVb.x - dx, y: startVb.y - dy } }));
                  };
                  const onUp = () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
                  document.addEventListener("mousemove", onMove);
                  document.addEventListener("mouseup", onUp);
                };

                const onNodeDragStart = (ev, nodeId) => {
                  ev.stopPropagation();
                  if (ev.button !== 0) return;
                  const svg = ev.currentTarget.closest("svg");
                  const startWorld = svgToWorld(ev.clientX, ev.clientY, svg);
                  const startPos = positions[nodeId];
                  if (!startPos) return;
                  let moved = false;
                  const onMove = (me) => {
                    moved = true;
                    const curWorld = svgToWorld(me.clientX, me.clientY, svg);
                    const dx = curWorld.x - startWorld.x, dy = curWorld.y - startWorld.y;
                    setModal((p) => ({
                      ...p,
                      positions: {
                        ...p.positions,
                        [nodeId]: {
                          ...(p.positions?.[nodeId] || {}),
                          x: startPos.x + dx,
                          y: startPos.y + dy,
                        },
                      },
                    }));
                  };
                  const onUp = () => {
                    document.removeEventListener("mousemove", onMove);
                    document.removeEventListener("mouseup", onUp);
                    if (!moved) setModal((p) => ({ ...p, selectedNode: p.selectedNode === nodeId ? null : nodeId, selectedEdge: null }));
                  };
                  document.addEventListener("mousemove", onMove);
                  document.addEventListener("mouseup", onUp);
                };

                const zoomBy = (factor) => {
                  const cx = vb.x + vb.w / 2, cy = vb.y + vb.h / 2;
                  const nw = Math.max(100, Math.min(W * 4, vb.w * factor));
                  const nh = Math.max(65, Math.min(H * 4, vb.h * factor));
                  setModal((p) => ({ ...p, viewBox: { x: cx - nw / 2, y: cy - nh / 2, w: nw, h: nh } }));
                };

                return (
                  <div>
                    {/* Toolbar */}
                    <div style={{ display: "flex", gap: 3, marginBottom: 8, alignItems: "center", padding: "4px 6px", background: `${th.panelBg}88`, borderRadius: 8, border: `1px solid ${th.border}22` }}>
                      <div style={{ display: "inline-flex", padding: 2, borderRadius: 6, background: `${th.textMuted}0d`, border: `1px solid ${th.border}33`, marginRight: 3 }}>
                        {[
                          { id: "machines", label: "Machines" },
                          { id: "identities", label: "Machines + Users" },
                        ].map((mode) => {
                          const active = graphMode === mode.id;
                          return (
                            <button key={mode.id} onClick={() => setGraphMode(mode.id)}
                              style={{ padding: "3px 9px", border: "none", borderRadius: 4, background: active ? th.accent : "transparent", color: active ? "#fff" : th.textDim, fontSize: LM_TYPOGRAPHY.control, fontWeight: active ? 600 : 500, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                              {mode.label}
                            </button>
                          );
                        })}
                      </div>
                      <button onClick={() => zoomBy(1 / 1.3)} style={tbtn} title="Zoom In">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
                      </button>
                      <button onClick={() => zoomBy(1.3)} style={tbtn} title="Zoom Out">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
                      </button>
                      <button onClick={() => setModal((p) => ({ ...p, viewBox: { x: 0, y: 0, w: W, h: H } }))} style={tbtn} title="Reset View">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                        Reset
                      </button>
                      {(selectedNode || selectedEdge) && <button onClick={() => {
                        const selectedPositions = selectedNode
                          ? [positions[selectedNode]].filter(Boolean)
                          : [positions[selectedEdge?.source], positions[selectedEdge?.target]].filter(Boolean);
                        if (selectedPositions.length === 0) return;
                        const cx = selectedPositions.reduce((sum, point) => sum + point.x, 0) / selectedPositions.length;
                        const cy = selectedPositions.reduce((sum, point) => sum + point.y, 0) / selectedPositions.length;
                        setModal((prev) => ({ ...prev, viewBox: { x: cx - 120, y: cy - 80, w: 240, h: 160 } }));
                      }} style={{ ...tbtn, color: th.accent, borderColor: `${th.accent}33`, background: `${th.accent}12` }} title="Center and zoom the selected path">
                        Focus
                      </button>}
                      <button onClick={() => {
                        const pos = computeForceLayout(graphNodes, graphEdges);
                        setModal((p) => ({ ...p, positions: pos, viewBox: { x: 0, y: 0, w: W, h: H } }));
                      }} style={tbtn} title="Redraw Layout">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><polyline points="1 4 1 10 7 10"/><polyline points="23 20 23 14 17 14"/><path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"/></svg>
                        Redraw
                      </button>
                      <button onClick={() => {
                        const svgEl = document.querySelector("[data-lm-graph]");
                        if (!svgEl) return;
                        const clone = svgEl.cloneNode(true);
                        clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
                        clone.style.background = th.panelBg;
                        const svgData = new XMLSerializer().serializeToString(clone);
                        const canvas = document.createElement("canvas");
                        const svgBlob = new Blob([svgData], { type: "image/svg+xml;charset=utf-8" });
                        const url = URL.createObjectURL(svgBlob);
                        const img = new Image();
                        img.onload = () => {
                          try {
                            canvas.width = img.width * 2;
                            canvas.height = img.height * 2;
                            const ctx = canvas.getContext("2d");
                            if (!ctx) throw new Error("Canvas rendering is unavailable.");
                            ctx.scale(2, 2);
                            ctx.fillStyle = th.panelBg;
                            ctx.fillRect(0, 0, img.width, img.height);
                            ctx.drawImage(img, 0, 0);
                            canvas.toBlob((blob) => {
                              if (!blob) {
                                toast.error("Graph export failed", { detail: "The PNG encoder returned no image." });
                                return;
                              }
                              const downloadUrl = URL.createObjectURL(blob);
                              const a = document.createElement("a");
                              a.href = downloadUrl;
                              a.download = "lateral-movement-graph.png";
                              a.click();
                              setTimeout(() => URL.revokeObjectURL(downloadUrl), 0);
                            }, "image/png");
                          } catch (err) {
                            toast.error("Graph export failed", { detail: err?.message || "Could not render the graph image." });
                          } finally {
                            URL.revokeObjectURL(url);
                          }
                        };
                        img.onerror = () => {
                          URL.revokeObjectURL(url);
                          toast.error("Graph export failed", { detail: "The graph SVG could not be loaded for PNG rendering." });
                        };
                        img.src = url;
                      }} style={tbtn} title="Export as PNG">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        Export
                      </button>
                      <button onClick={() => {
                        const rows = (data.findings || []).map((f) => ({
                          Severity: f.severity || "", Category: f.category || "", Title: f.title || "",
                          Description: f.description || "", SourceHost: f.source || "", TargetHost: f.target || "",
                          MITRE: f.mitre || "", TriageScore: f.triageScore ?? "", EventCount: f.eventCount ?? "",
                          From: f.timeRange?.from || "", To: f.timeRange?.to || "",
                          HostsInvolved: Array.isArray(f.filterHosts) ? f.filterHosts.join("; ") : "",
                        }));
                        _saveExport(_toCSV(rows), "lateral-movement-findings.csv", [{ name: "CSV", extensions: ["csv"] }]);
                      }} style={{ ...tbtn, color: th.textMuted }} title="Export findings as CSV">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        CSV
                      </button>
                      <button onClick={() => {
                        const payload = {
                          exportedAt: new Date().toISOString(),
                          stats: data.stats,
                          findings: data.findings || [],
                          edges: (data.edges || []).map((e) => ({ source: e.source, target: e.target, count: e.count, logonTypes: e.logonTypes, users: e.users, timeRange: e.timeRange })),
                          nodes: (data.nodes || []).map((n) => ({ host: n.id, eventCount: n.eventCount, isOutlier: n.isOutlier, isBoth: n.isBoth, isSource: n.isSource, isTarget: n.isTarget })),
                        };
                        _saveExport(JSON.stringify(payload, null, 2), "lateral-movement-findings.json", [{ name: "JSON", extensions: ["json"] }]);
                      }} style={{ ...tbtn, color: th.textMuted }} title="Export full analysis as JSON">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        JSON
                      </button>
                      {(() => {
                        const outliers = graphNodes.filter(n => n.isOutlier);
                        const susHosts = graphNodes.filter(n => isSusHost(n.id) && !n.isOutlier);
                        const flagged = [...outliers, ...susHosts];
                        if (flagged.length === 0) return null;
                        const curIdx = modal.lmFlagIdx || 0;
                        return (
                          <>
                            <div style={{ width: 1, height: 16, background: th.border + "44", margin: "0 2px" }} />
                            <button onClick={() => {
                              const node = flagged[curIdx % flagged.length];
                              const p = positions[node.id];
                              if (p) {
                                const zoomW = 180, zoomH = 120;
                                setModal((prev) => ({ ...prev, selectedNode: node.id, selectedEdge: null, viewBox: { x: p.x - zoomW / 2, y: p.y - zoomH / 2, w: zoomW, h: zoomH }, lmFlagIdx: (curIdx + 1) % flagged.length }));
                              }
                            }} style={{ ...tbtn, background: `${(th.danger)}15`, color: th.danger, border: `1px solid ${(th.danger)}33` }} title={`${outliers.length} outlier(s), ${susHosts.length} suspicious host(s) — click to cycle through`}>
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.danger} strokeWidth="2"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                              Find Flagged ({flagged.length})
                            </button>
                          </>
                        );
                      })()}
                      <div style={{ flex: 1 }} />
                      <span style={{ display: "inline-flex", gap: 7, alignItems: "center", fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                        <span>{graphHostCount} machine{graphHostCount === 1 ? "" : "s"}</span>
                        {graphMode === "identities" && <span>{graphIdentityCount} user{graphIdentityCount === 1 ? "" : "s"}</span>}
                        <span>
                          {graphEligibleEdgeCount > graphEdges.length ? "top " : ""}
                          {graphEdges.length}
                          {graphEligibleEdgeCount > graphEdges.length ? ` of ${graphEligibleEdgeCount}` : ""}
                          {" "}directed link{graphEdges.length === 1 ? "" : "s"}
                        </span>
                        {graphMode === "identities" && identityGraph.unattributedEdges.length > 0 && <span>{identityGraph.unattributedEdges.length} unattributed</span>}
                        {graphEdges.some(edgeMixedOutcome) && <span style={{ color: th.sev.high }}>mixed outcomes</span>}
                      </span>
                      <div style={{ width: 1, height: 16, background: th.border + "44", margin: "0 4px" }} />
                      <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{selectedNode || selectedEdge ? "Zoom locked \u00B7 Click background to deselect & unlock" : "Scroll to zoom \u00B7 Drag background to pan \u00B7 Drag nodes to reposition"}</span>
                    </div>

                    <svg data-lm-graph="1" width="100%" height={480} viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
                      style={{ background: th.panelBg, borderRadius: 6, border: `1px solid ${th.border}`, cursor: modal.draggingNode ? "grabbing" : "grab", display: "block", userSelect: "none" }}
                      onWheel={onWheel}
                      onMouseDown={(ev) => { if (ev.target === ev.currentTarget || ev.target.tagName === "rect") { onPanStart(ev); setModal((p) => ({ ...p, selectedNode: null, selectedEdge: null })); } }}>

                      <defs>
                        <pattern id="lm-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                          <circle cx="20" cy="20" r="0.6" fill={th.textMuted + "18"} />
                        </pattern>
                        <filter id="lm-glow" x="-50%" y="-50%" width="200%" height="200%">
                          <feGaussianBlur stdDeviation="3" result="blur"/>
                          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                        </filter>
                        <filter id="lm-shadow" x="-20%" y="-20%" width="140%" height="140%">
                          <feDropShadow dx="0" dy="1" stdDeviation="2" floodOpacity="0.25"/>
                        </filter>
                        <radialGradient id="lm-grad-green" cx="35%" cy="35%"><stop offset="0%" stopColor={th.sev.clean} stopOpacity="0.35"/><stop offset="100%" stopColor={th.sev.clean} stopOpacity="0.08"/></radialGradient>
                        <radialGradient id="lm-grad-blue" cx="35%" cy="35%"><stop offset="0%" stopColor={th.sev.info} stopOpacity="0.35"/><stop offset="100%" stopColor={th.sev.info} stopOpacity="0.08"/></radialGradient>
                        <radialGradient id="lm-grad-purple" cx="35%" cy="35%"><stop offset="0%" stopColor={th.sev.custom} stopOpacity="0.35"/><stop offset="100%" stopColor={th.sev.custom} stopOpacity="0.08"/></radialGradient>
                        <radialGradient id="lm-grad-accent" cx="35%" cy="35%"><stop offset="0%" stopColor={th.accent} stopOpacity="0.4"/><stop offset="100%" stopColor={th.accent} stopOpacity="0.1"/></radialGradient>
                        <radialGradient id="lm-grad-red" cx="35%" cy="35%"><stop offset="0%" stopColor={th.danger} stopOpacity="0.45"/><stop offset="100%" stopColor={th.danger} stopOpacity="0.12"/></radialGradient>
                      </defs>
                      <rect x={vb.x - 200} y={vb.y - 200} width={vb.w + 400} height={vb.h + 400} fill="url(#lm-grid)" />

                      {/* Edges */}
                      {graphEdges.map((e, i) => {
                        const from = positions[e.source], to = positions[e.target];
                        if (!from || !to) return null;
                        const hl = isEdgeHL(e);
                        const op = selectedNode || selectedEdge ? (hl ? 0.9 : 0.1) : 0.6;
                        const failureOnly = edgeFailureOnly(e);
                        const mixedOutcome = edgeMixedOutcome(e);
                        const col = failureOnly ? th.danger : e.graphKind === "identity-link" ? th.accent : _techColor(e.technique) || logonColor(e.logonTypes);
                        const dx = to.x - from.x, dy = to.y - from.y;
                        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                        const toR = nodeRadius((graphNodes.find((n) => n.id === e.target) || {}).eventCount || 1) + 2;
                        const fromR = nodeRadius((graphNodes.find((n) => n.id === e.source) || {}).eventCount || 1) + 2;
                        const ux = dx / dist, uy = dy / dist;
                        const x1 = from.x + ux * fromR, y1 = from.y + uy * fromR;
                        const x2 = to.x - ux * toR, y2 = to.y - uy * toR;
                        const reverse = graphEdgeKeys.has(`${e.target}->${e.source}`);
                        const curve = reverse ? (String(e.source).localeCompare(String(e.target)) < 0 ? 24 : -24) : 0;
                        const cx = (x1 + x2) / 2 - uy * curve;
                        const cy = (y1 + y2) / 2 + ux * curve;
                        const path = `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`;
                        const mx = 0.25 * x1 + 0.5 * cx + 0.25 * x2;
                        const my = 0.25 * y1 + 0.5 * cy + 0.25 * y2;
                        const ang = Math.atan2(y2 - cy, x2 - cx) * 180 / Math.PI;
                        const countLabelBase = e.count > 999 ? Math.round(e.count / 1000) + "k" : e.count;
                        const countLabel = e.attributionApproximate ? `~${countLabelBase}` : countLabelBase;
                        const edgeLabel = e.graphKind === "identity-link"
                          ? `${e.phase === "source-to-identity" ? "uses account" : (e.technique && e.technique !== "Unknown" ? e.technique : "access")} \u00b7 ${countLabel}`
                          : `${e.technique && e.technique !== "Unknown" ? `${e.technique} \u00b7 ` : ""}${countLabel}`;
                        const showEdgeLabel = e.graphKind !== "identity-link"
                          || (e.phase !== "source-to-identity" && (graphEdges.length <= 12 || hl));
                        const edgeLabelW = Math.min(112, Math.max(28, edgeLabel.length * 5.2 + 12));
                        return (
                          <g key={`e-${i}`} style={{ cursor: "pointer" }} opacity={op}>
                            <path d={path} fill="none" stroke={col} strokeWidth={edgeWidth(e.count)} strokeDasharray={failureOnly ? "5,4" : "none"} strokeLinecap="round" />
                            {mixedOutcome && <path d={path} fill="none" stroke={th.danger} strokeWidth={1} strokeDasharray="3,5" strokeLinecap="round" opacity={0.85} />}
                            <path d={path} fill="none" stroke="transparent" strokeWidth={14} onClick={(ev) => { ev.stopPropagation(); setModal((p) => ({ ...p, selectedEdge: e, selectedNode: null })); }} />
                            <polygon points="-5,-4 5,0 -5,4" transform={`translate(${x2},${y2}) rotate(${ang})`} fill={col} />
                            {showEdgeLabel && <g transform={`translate(${mx}, ${my})`}>
                              <rect x={-edgeLabelW / 2} y={-7} width={edgeLabelW} height={14} rx={7} fill={th.panelBg} fillOpacity={0.94} stroke={col} strokeWidth={0.5} strokeOpacity={0.45} />
                              <text textAnchor="middle" dy="3.5" fill={col} fontSize={LM_TYPOGRAPHY.meta} fontWeight={600} fontFamily="-apple-system,sans-serif" fillOpacity={0.9}>
                                {edgeLabel.length > 21 ? `${edgeLabel.slice(0, 20)}\u2026` : edgeLabel}
                              </text>
                            </g>}
                          </g>
                        );
                      })}

                      {/* Nodes */}
                      {graphNodes.map((n) => {
                        const p = positions[n.id];
                        if (!p) return null;
                        const r = nodeRadius(n.eventCount);
                        const dimmed = selectedNode && selectedNode !== n.id && !graphEdges.some((e) => (e.source === selectedNode && e.target === n.id) || (e.target === selectedNode && e.source === n.id));
                        const op = selectedNode ? (dimmed ? 0.12 : 1) : 1;
                        const col = nodeColor(n);
                        const identityNode = n.nodeType === "identity";
                        const ip = isIP(n.id);
                        const dc = isDC(n.id);
                        const dangerCol = th.danger;
                        const gradId = col === dangerCol ? "lm-grad-red" : col === th.sev.clean ? "lm-grad-green" : col === th.sev.info ? "lm-grad-blue" : col === th.sev.custom ? "lm-grad-purple" : "lm-grad-accent";
                        const fullLabel = String(n.label || n.id || "(unknown)");
                        const labelText = fullLabel.length > 20 ? fullLabel.slice(0, 18) + "\u2026" : fullLabel;
                        const labelW = labelText.length * 5.5 + 12;
                        const isSel = selectedNode === n.id;
                        const nodeLevel = Number(p.level) || 0;
                        // Keep labels inside the directed flow: source labels open to
                        // the right, terminal labels to the left, and all labels sit
                        // above the edge centerline. This avoids the legend and the
                        // dense under-node pile-up visible in the old force layout.
                        const labelSide = maxGraphLevel > 0 && nodeLevel === maxGraphLevel ? -1 : 1;
                        const labelX = labelSide < 0 ? p.x - r - 10 - labelW : p.x + r + 10;
                        const labelY = p.y - r - 20;
                        return (
                          <g key={`n-${n.id}`} opacity={op} style={{ cursor: "grab" }}
                            onMouseDown={(ev) => onNodeDragStart(ev, n.id)} filter={isSel ? "url(#lm-glow)" : undefined}>
                            <title>{identityNode ? `${fullLabel} | ${n.sourceHosts?.length || 0} source machines | ${n.targetHosts?.length || 0} target machines` : [fullLabel, ...(n.aliases || [])].filter(Boolean).join(" | ")}</title>
                            <circle cx={p.x} cy={p.y} r={r + 4} fill={col} fillOpacity={isSel ? 0.12 : 0.04} />
                            {identityNode ? (
                              <g>
                                <circle cx={p.x} cy={p.y} r={r} fill={`url(#${gradId})`} stroke={col} strokeWidth={1.4} strokeDasharray={n.unresolved ? "3,2" : "none"} />
                                <circle cx={p.x} cy={p.y - r * 0.27} r={r * 0.25} fill={col} fillOpacity={0.75} />
                                <path d={`M ${p.x - r * 0.5} ${p.y + r * 0.5} Q ${p.x} ${p.y + r * 0.05} ${p.x + r * 0.5} ${p.y + r * 0.5}`} fill={col} fillOpacity={0.45} />
                              </g>
                            ) : ip ? (
                              <g>
                                <circle cx={p.x} cy={p.y} r={r} fill={`url(#${gradId})`} stroke={col} strokeWidth={1.2} strokeDasharray="4,2.5" strokeOpacity={0.7} />
                                <circle cx={p.x - r * 0.25} cy={p.y - r * 0.25} r={r * 0.15} fill={col} fillOpacity={0.15} />
                              </g>
                            ) : dc ? (
                              <g>
                                <rect x={p.x - r} y={p.y - r} width={r * 2} height={r * 2} rx={4} fill={`url(#${gradId})`} stroke={col} strokeWidth={1.5} />
                                <line x1={p.x - r * 0.6} y1={p.y - r * 0.35} x2={p.x + r * 0.6} y2={p.y - r * 0.35} stroke={col} strokeWidth={0.8} strokeOpacity={0.3} />
                                <line x1={p.x - r * 0.6} y1={p.y} x2={p.x + r * 0.6} y2={p.y} stroke={col} strokeWidth={0.8} strokeOpacity={0.3} />
                                <line x1={p.x - r * 0.6} y1={p.y + r * 0.35} x2={p.x + r * 0.6} y2={p.y + r * 0.35} stroke={col} strokeWidth={0.8} strokeOpacity={0.3} />
                              </g>
                            ) : (
                              <g>
                                <rect x={p.x - r} y={p.y - r * 0.7} width={r * 2} height={r * 1.4} rx={5} fill={`url(#${gradId})`} stroke={col} strokeWidth={1.2} />
                                <line x1={p.x} y1={p.y + r * 0.7} x2={p.x} y2={p.y + r * 0.95} stroke={col} strokeWidth={0.8} strokeOpacity={0.35} />
                                <line x1={p.x - r * 0.25} y1={p.y + r * 0.95} x2={p.x + r * 0.25} y2={p.y + r * 0.95} stroke={col} strokeWidth={0.8} strokeOpacity={0.35} />
                                <rect x={p.x - r * 0.7} y={p.y - r * 0.5} width={r * 0.4} height={r * 0.2} rx={1} fill={col} fillOpacity={0.08} />
                              </g>
                            )}
                            {isSel && <circle cx={p.x} cy={p.y} r={r + 6} fill="none" stroke={th.accent} strokeWidth={1.5} strokeOpacity={0.5} strokeDasharray="4,3" />}
                            {n.isOutlier && <circle cx={p.x} cy={p.y} r={r + 4} fill="none" stroke={dangerCol} strokeWidth={1.2} strokeOpacity={0.6} strokeDasharray="3,2" style={{ animation: "tle-pulse 2s ease-in-out infinite" }}><title>{n.outlierReason}</title></circle>}
                            {isSusHost(n.id) && <g transform={`translate(${p.x + r - 2}, ${p.y - r - 2})`}><polygon points="0,-6 5.2,3 -5.2,3" fill={th.sev.high} stroke={th.modalBg} strokeWidth={1} /><text x={0} y={1.5} textAnchor="middle" fill={th.modalBg} fontSize={6} fontWeight={700}>!</text><title>Suspicious hostname pattern — possible threat actor workstation</title></g>}
                            {identityNode ? (
                              <text x={p.x} y={p.y + r * 0.88} textAnchor="middle" fill={col} fontSize={r * 0.38} fontWeight={700} fontFamily="-apple-system,sans-serif" fillOpacity={0.82}>{n.unresolved ? "?" : "USER"}</text>
                            ) : ip ? (
                              <text x={p.x} y={p.y + 1} textAnchor="middle" dominantBaseline="middle" fill={col} fontSize={r * 0.6} fontWeight={600} fontFamily="-apple-system,sans-serif" fillOpacity={0.7}>IP</text>
                            ) : dc ? (
                              <text x={p.x} y={p.y + r * 0.7} textAnchor="middle" fill={col} fontSize={r * 0.5} fontWeight={600} fontFamily="-apple-system,sans-serif" fillOpacity={0.7}>DC</text>
                            ) : null}
                            <g transform={`translate(${labelX}, ${labelY})`}>
                              <rect x={0} y={0} width={labelW} height={15} rx={7} fill={th.panelBg} fillOpacity={0.92} stroke={col} strokeWidth={0.5} strokeOpacity={0.4} />
                              <text x={6} y={10.5} fill={th.text} fontSize={LM_TYPOGRAPHY.body} fontWeight={500} fontFamily="-apple-system,sans-serif">{labelText}</text>
                            </g>
                          </g>
                        );
                      })}

                      {/* Legend */}
                      <g transform={`translate(${vb.x + (modal.legendOffX ?? 10)}, ${vb.y + (modal.legendOffY ?? 10)})`} style={{ cursor: "grab" }}
                        onMouseDown={(ev) => {
                          ev.stopPropagation(); ev.preventDefault();
                          const svg = ev.currentTarget.closest("svg");
                          const rect = svg.getBoundingClientRect();
                          const startX = ev.clientX, startY = ev.clientY;
                          const startOx = modal.legendOffX ?? 10, startOy = modal.legendOffY ?? 10;
                          document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                          const onMove = (me) => {
                            const dx = ((me.clientX - startX) / rect.width) * vb.w;
                            const dy = ((me.clientY - startY) / rect.height) * vb.h;
                            setModal((p) => ({ ...p, legendOffX: startOx + dx, legendOffY: startOy + dy }));
                          };
                          const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
                          document.addEventListener("mousemove", onMove); document.addEventListener("mouseup", onUp);
                        }}>
                        <rect x={-6} y={-6} width={155} height={graphMode === "identities" ? 194 : 180} rx={8} fill={th.panelBg} fillOpacity={0.88} stroke={th.border} strokeWidth={0.5} strokeOpacity={0.3} />
                        <text x={0} y={6} fill={th.textMuted} fontSize={LM_TYPOGRAPHY.meta} fontWeight={600} fontFamily="-apple-system,sans-serif" letterSpacing="0.08em" textTransform="uppercase">CONNECTIONS</text>
                        {(graphMode === "identities" ? [
                          { color: th.accent, label: "Machine uses account" },
                          { color: th.accent, label: "Account accesses machine" },
                          { color: th.danger, label: "Failure-only path", dashed: true },
                        ] : [
                          { color: th.sev.info, label: "RDP (type 10/12)" },
                          { color: th.sev.clean, label: "Network (type 3)" },
                          { color: th.sev.med, label: "Interactive (type 2)" },
                          { color: th.sev.high, label: "RunAs (type 9)" },
                          { color: th.sev.low, label: "Service (type 5)" },
                          { color: th.sev.critical, label: "Cleartext (type 8)" },
                          { color: th.danger, label: "Failure-only connection", dashed: true },
                        ]).map((item, i) => (
                          <g key={i} transform={`translate(4, ${i * 14 + 18})`}>
                            <line x1={0} y1={0} x2={14} y2={0} stroke={item.color} strokeWidth={2} strokeLinecap="round" strokeDasharray={item.dashed ? "3,2" : "none"} />
                            <circle cx={14} cy={0} r={1.5} fill={item.color} />
                            <text x={20} y={3} fill={th.textMuted} fontSize={LM_TYPOGRAPHY.meta} fontFamily="-apple-system,sans-serif">{item.label}</text>
                          </g>
                        ))}
                        <line x1={0} y1={118} x2={140} y2={118} stroke={th.border} strokeWidth={0.3} strokeOpacity={0.5} />
                        <text x={0} y={130} fill={th.textMuted} fontSize={LM_TYPOGRAPHY.meta} fontWeight={600} fontFamily="-apple-system,sans-serif" letterSpacing="0.08em">NODES</text>
                        <g transform="translate(4, 140)">
                          <circle cx={4} cy={0} r={3.5} fill="url(#lm-grad-green)" stroke={th.sev.clean} strokeWidth={0.8} strokeDasharray="2.5,1.5" />
                          <text x={14} y={3} fill={th.textMuted} fontSize={LM_TYPOGRAPHY.meta} fontFamily="-apple-system,sans-serif">IP</text>
                        </g>
                        <g transform="translate(38, 140)">
                          <rect x={0} y={-4} width={8} height={8} rx={2} fill="url(#lm-grad-blue)" stroke={th.sev.info} strokeWidth={0.8} />
                          <text x={14} y={3} fill={th.textMuted} fontSize={LM_TYPOGRAPHY.meta} fontFamily="-apple-system,sans-serif">DC</text>
                        </g>
                        <g transform="translate(68, 140)">
                          <rect x={0} y={-3} width={9} height={6} rx={2} fill="url(#lm-grad-purple)" stroke={th.sev.custom} strokeWidth={0.8} />
                          <text x={15} y={3} fill={th.textMuted} fontSize={LM_TYPOGRAPHY.meta} fontFamily="-apple-system,sans-serif">Host</text>
                        </g>
                        <g transform="translate(4, 155)">
                          <rect x={0} y={-3} width={9} height={6} rx={2} fill="url(#lm-grad-red)" stroke={th.danger} strokeWidth={0.8} strokeDasharray="2,1.5" />
                          <text x={15} y={3} fill={th.danger} fontSize={LM_TYPOGRAPHY.meta} fontWeight={600} fontFamily="-apple-system,sans-serif">Outlier</text>
                        </g>
                        <g transform="translate(68, 155)">
                          <polygon points="4,-5 8.2,2 -0.2,2" fill={th.sev.high} />
                          <text x={14} y={3} fill={th.sev.high} fontSize={LM_TYPOGRAPHY.meta} fontWeight={500} fontFamily="-apple-system,sans-serif">Sus Host</text>
                        </g>
                        {graphMode === "identities" && (
                          <g transform="translate(4, 171)">
                            <circle cx={4} cy={0} r={4} fill="url(#lm-grad-accent)" stroke={th.accent} strokeWidth={0.9} />
                            <circle cx={4} cy={-1.3} r={1.1} fill={th.accent} />
                            <text x={14} y={3} fill={th.accent} fontSize={LM_TYPOGRAPHY.meta} fontWeight={600} fontFamily="-apple-system,sans-serif">User identity</text>
                          </g>
                        )}
                      </g>
                    </svg>

                    {/* Node detail panel */}
                    {selectedNode && (() => {
                      const selectedGraphNode = graphNodes.find((node) => node.id === selectedNode);
                      if (selectedGraphNode?.nodeType === "identity") {
                        const identityEdges = selectedGraphNode.relatedHostEdges || [];
                        const highRiskPaths = identityEdges.filter((edge) => (edge.riskScore || 0) >= 15);
                        return (
                          <div style={{ marginTop: 10, padding: 14, background: `linear-gradient(135deg, ${th.accent}08, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${th.accent}22`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                              <span style={{ padding: "3px 10px", background: `${th.accent}18`, color: th.accent, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>
                                {selectedGraphNode.unresolved ? "Unresolved identity" : "User identity"}
                              </span>
                              <span style={{ fontWeight: 600, fontSize: LM_TYPOGRAPHY.heading, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{selectedGraphNode.label}</span>
                              {highRiskPaths.length > 0 && <span style={{ padding: "2px 6px", background: `${th.danger}14`, color: th.danger, borderRadius: 4, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700 }}>{highRiskPaths.length} HIGH-RISK PATH{highRiskPaths.length === 1 ? "" : "S"}</span>}
                              {!selectedGraphNode.unresolved && modal.columns?.user && (
                                <button onClick={() => {
                                  up("columnFilters", { ...(ct.columnFilters || {}), [modal.columns.user]: selectedGraphNode.identity });
                                  setModal(null);
                                }} style={{ marginLeft: "auto", padding: "4px 12px", fontSize: LM_TYPOGRAPHY.control, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>
                                  Filter user in timeline
                                </button>
                              )}
                            </div>
                            <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0, 1fr)", gap: 20 }}>
                              <div style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.55 }}>
                                {[
                                  ["Source machines", selectedGraphNode.sourceHosts?.length || 0],
                                  ["Target machines", selectedGraphNode.targetHosts?.length || 0],
                                  ["Associated activity", `${selectedGraphNode.attributionApproximate ? "~" : ""}${selectedGraphNode.eventCount || 0}`],
                                  ["Highest path score", selectedGraphNode.riskScore || 0],
                                  ["First observed", fmtTs(selectedGraphNode.firstSeen) || "\u2014"],
                                  ["Last observed", fmtTs(selectedGraphNode.lastSeen) || "\u2014"],
                                ].map(([label, value]) => (
                                  <div key={label} style={{ display: "grid", gridTemplateColumns: "120px minmax(0, 1fr)", gap: 8, padding: "2px 0" }}>
                                    <span style={{ color: th.textMuted }}>{label}</span>
                                    <span style={{ color: th.text, overflowWrap: "anywhere" }}>{value}</span>
                                  </div>
                                ))}
                                {(selectedGraphNode.techniques || []).length > 0 && (
                                  <div style={{ marginTop: 8 }}>
                                    <div style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge, textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>Observed techniques</div>
                                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                      {selectedGraphNode.techniques.map((technique) => (
                                        <span key={technique} style={{ padding: "2px 6px", borderRadius: 3, background: `${th.textMuted}10`, border: `1px solid ${th.border}44`, color: th.textDim, fontSize: LM_TYPOGRAPHY.badge }}>{technique}</span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                <div style={{ marginTop: 10 }}><EvidenceActions item={selectedGraphNode} /></div>
                              </div>
                              <div style={{ minWidth: 0 }}>
                                <div style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge, textTransform: "uppercase", fontWeight: 700, marginBottom: 5 }}>Machine paths ({identityEdges.length})</div>
                                <div style={{ maxHeight: 170, overflowY: "auto", border: `1px solid ${th.border}33`, borderRadius: 6 }}>
                                  {identityEdges.length === 0 ? (
                                    <div style={{ padding: 10, color: th.textMuted, fontSize: LM_TYPOGRAPHY.control }}>No attributed machine path is available.</div>
                                  ) : identityEdges
                                    .slice()
                                    .sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0) || String(a.firstSeen || "").localeCompare(String(b.firstSeen || "")))
                                    .map((edge, index) => (
                                      <div key={`${edge.source}-${edge.target}-${index}`} onClick={(event) => _viewInGraph(edge, event)}
                                        style={{ display: "grid", gridTemplateColumns: "minmax(190px, 1fr) 110px 70px", gap: 8, alignItems: "center", padding: "6px 8px", borderBottom: index < identityEdges.length - 1 ? `1px solid ${th.border}22` : "none", cursor: "pointer", fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}
                                        onMouseEnter={(event) => { event.currentTarget.style.background = `${th.accent}08`; }}
                                        onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}>
                                        <span style={{ color: th.text, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{edge.source} {"\u2192"} {edge.target}</span>
                                        <span style={{ color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{edge.technique || "Network Logon"}</span>
                                        <span style={{ color: (edge.riskScore || 0) >= 15 ? th.danger : th.textMuted, fontFamily: "monospace", textAlign: "right" }}>score {edge.riskScore || 0}</span>
                                      </div>
                                    ))}
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      }
                      const node = data.nodes.find((n) => n.id === selectedNode);
                      const inbound = data.edges.filter((e) => e.target === selectedNode);
                      const outbound = data.edges.filter((e) => e.source === selectedNode);
                      const nc = nodeColor(node || {});
                      const _lowConfPat = /^(127\.|::1|0\.0\.0\.0|-:-|-$|LOCAL$)/i;
                      const _isLowConf = (e, dir) => {
                        const peer = dir === "in" ? e.source : e.target;
                        return _lowConfPat.test(peer) || /:\d+$/.test(peer) || peer === "-" || peer === "";
                      };
                      const outRanked = [...outbound].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
                      const inRanked = [...inbound].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
                      const outHigh = outRanked.filter(e => !_isLowConf(e, "out"));
                      const inHigh = inRanked.filter(e => !_isLowConf(e, "in"));
                      const lowConf = [...outRanked.filter(e => _isLowConf(e, "out")).map(e => ({ ...e, dir: "out" })), ...inRanked.filter(e => _isLowConf(e, "in")).map(e => ({ ...e, dir: "in" }))];
                      const allEdges = [...inbound, ...outbound];
                      const allUsers = [...new Set(allEdges.flatMap(e => e.users))];
                      const allFirstSeen = allEdges.map(e => e.firstSeen).filter(Boolean).sort();
                      const allLastSeen = allEdges.map(e => e.lastSeen).filter(Boolean).sort();
                      const relatedFindings = (data.findings || []).filter(f => (f.filterHosts || []).includes(selectedNode));
                      const relatedChains = (data.chains || []).filter(c => c.path.includes(selectedNode));
                      const techCounts = {};
                      for (const e of allEdges) {
                        if (e.technique && e.technique !== "Unknown") techCounts[e.technique] = (techCounts[e.technique] || 0) + (e.count || 0) + (e.shareAccessCount || 0);
                        for (const ot of (e.otherTechniques || [])) { if (ot) techCounts[ot] = (techCounts[ot] || 0) + 1; }
                      }
                      const _DC = /^(DC|PDC|BDC|AD|ADDS|ADCS|ADFS)\d{0,3}$/i;
                      const _SRV = /^(SVR|SRV|SERVER|FS|SQL|EXCH|MAIL|WEB|APP|DB|CA|WSUS|SCCM|SCOM|PRINT|FILE|DNS|DHCP|NPS|RADIUS|VPN|RDS|RDSH|RDCB|RDGW)/i;
                      const role = isIP(selectedNode) ? "IP Address" : _DC.test(selectedNode) ? "Domain Controller" : _SRV.test(selectedNode) ? "Server" : _lowConfPat.test(selectedNode) || /:\d+$/.test(selectedNode) ? "Unresolved / Artifact" : "Workstation";
                      const narrative = [];
                      if (outHigh.length > 0) {
                        const topOut = outHigh[0];
                        narrative.push(`Outbound lateral activity to ${outHigh.length} host${outHigh.length !== 1 ? "s" : ""}${topOut.riskScore >= 15 ? ` — strongest signal: ${topOut.technique || "Network Logon"} toward ${topOut.target} (score ${topOut.riskScore})` : ""}`);
                      }
                      if (inHigh.length > 0) {
                        const topIn = inHigh[0];
                        narrative.push(`Inbound from ${inHigh.length} host${inHigh.length !== 1 ? "s" : ""}${topIn.riskScore >= 15 ? ` — top: ${topIn.source} via ${topIn.technique || "Network Logon"} (score ${topIn.riskScore})` : ""}`);
                      }
                      if (lowConf.length > 0) narrative.push(`${lowConf.length} low-confidence / unresolved peer${lowConf.length !== 1 ? "s" : ""} (loopback, IP:port artifacts)`);
                      if (relatedChains.length > 0) narrative.push(`Participates in ${relatedChains.length} multi-hop chain${relatedChains.length !== 1 ? "s" : ""}`);
                      if (relatedFindings.filter(f => f.severity === "critical" || f.severity === "high").length > 0) narrative.push(`${relatedFindings.filter(f => f.severity === "critical" || f.severity === "high").length} high/critical finding${relatedFindings.filter(f => f.severity === "critical" || f.severity === "high").length !== 1 ? "s" : ""} on this host`);
                      const edgeCard = (e, dir) => {
                        const peer = dir === "out" ? e.target : e.source;
                        const sc = e.riskScore || 0;
                        const tc = _techColor(e.technique);
                        const flags = (e.flags || []).filter(f => !f.includes("dampened"));
                        return (
                          <div key={`${dir}-${e.source}-${e.target}`} onClick={() => setModal((p) => ({ ...p, selectedNode: null, selectedEdge: e }))} style={{ display: "flex", alignItems: "center", gap: 5, padding: "3px 0", fontSize: LM_TYPOGRAPHY.meta, fontFamily: "monospace", color: th.textDim, borderBottom: `1px solid ${th.border}15`, cursor: "pointer" }}
                            onMouseEnter={(ev) => ev.currentTarget.style.background = `${th.accent}08`} onMouseLeave={(ev) => ev.currentTarget.style.background = "transparent"}>
                            <span style={{ padding: "1px 4px", background: dir === "in" ? th.sev.info + "22" : th.sev.clean + "22", color: dir === "in" ? th.sev.info : th.sev.clean, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, minWidth: 20, textAlign: "center" }}>{dir === "in" ? "IN" : "OUT"}</span>
                            <span style={{ color: th.text, fontWeight: 600, minWidth: 80, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 120 }}>{peer}{isSusHost(peer) && <span style={{ color: th.sev.high, marginLeft: 2, fontSize: LM_TYPOGRAPHY.badge }}>{"\u26a0"}</span>}</span>
                            {sc > 0 && <span style={{ fontWeight: 700, color: sc >= 30 ? th.sev.critical : sc >= 15 ? th.sev.high : th.textMuted, fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.meta, minWidth: 18, textAlign: "right" }}>{sc}</span>}
                            {e.technique && e.technique !== "Unknown" && <span style={{ padding: "0 4px", background: tc + "18", color: tc, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600 }}>{e.technique}</span>}
                            <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge }}>{e.users.slice(0, 2).join(", ")}{e.users.length > 2 ? ` +${e.users.length - 2}` : ""}</span>
                            {flags.length > 0 && <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge }}>({flags.length} flag{flags.length !== 1 ? "s" : ""})</span>}
                          </div>
                        );
                      };
                      return (
                        <div style={{ marginTop: 10, padding: 14, background: `linear-gradient(135deg, ${nc}08, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${nc}22`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                            <span style={{ padding: "3px 10px", background: `linear-gradient(135deg, ${nc}33, ${nc}15)`, color: nc, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control, fontWeight: 600, fontFamily: "-apple-system, sans-serif", letterSpacing: "0.03em" }}>{role}</span>
                            <span style={{ fontWeight: 600, fontSize: LM_TYPOGRAPHY.heading, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.2px" }}>{selectedNode}</span>
                            {node?.isOutlier && <span style={{ padding: "2px 6px", background: th.sev.critical + "18", color: th.sev.critical, borderRadius: 4, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>OUTLIER: {node.outlierReason}</span>}
                            <button onClick={() => {
                              const modalCols = modal.columns || {};
                              const srcCol = modalCols.source || modalCols.workstation;
                              const tgtCol = modalCols.target;
                              if (srcCol || tgtCol) {
                                const cf = { ...(ct.columnFilters || {}) };
                                if (srcCol && tgtCol) cf[srcCol] = selectedNode;
                                else if (tgtCol) cf[tgtCol] = selectedNode;
                                up("columnFilters", cf);
                              }
                              setModal(null);
                            }} style={{ marginLeft: "auto", padding: "4px 12px", fontSize: LM_TYPOGRAPHY.control, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}18)`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 600, transition: "all var(--m-base)" }}
                              onMouseEnter={(ev) => { ev.currentTarget.style.background = th.accent + "44"; ev.currentTarget.style.boxShadow = `0 2px 8px ${th.accent}22`; }}
                              onMouseLeave={(ev) => { ev.currentTarget.style.background = `linear-gradient(135deg, ${th.accent}33, ${th.accent}18)`; ev.currentTarget.style.boxShadow = "none"; }}>
                              Filter Grid
                            </button>
                          </div>
                          <div style={{ display: "flex", gap: 18 }}>
                            <div style={{ width: 240, flexShrink: 0, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "-apple-system, sans-serif", color: th.textDim }}>
                              <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: 5 }}>Host Summary</div>
                              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3px 12px", marginBottom: 8 }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 4 }}><span style={{ width: 5, height: 5, borderRadius: 3, background: th.sev.clean, display: "inline-block" }} /><span>{outbound.length} outbound</span></div>
                                <div style={{ display: "flex", alignItems: "center", gap: 4 }}><span style={{ width: 5, height: 5, borderRadius: 3, background: th.sev.info, display: "inline-block" }} /><span>{inbound.length} inbound</span></div>
                                <div><span style={{ color: th.textMuted }}>Users:</span> {allUsers.length > 0 ? allUsers.slice(0, 3).join(", ") + (allUsers.length > 3 ? ` +${allUsers.length - 3}` : "") : "\u2014"}</div>
                                <div><span style={{ color: th.textMuted }}>Events:</span> {node?.eventCount || 0}</div>
                                {allFirstSeen.length > 0 && <div><span style={{ color: th.textMuted }}>First:</span> <span style={{ fontFamily: "monospace" }}>{allFirstSeen[0]?.slice(5, 16)}</span></div>}
                                {allLastSeen.length > 0 && <div><span style={{ color: th.textMuted }}>Last:</span> <span style={{ fontFamily: "monospace" }}>{allLastSeen[allLastSeen.length - 1]?.slice(5, 16)}</span></div>}
                                {relatedFindings.length > 0 && <div><span style={{ color: th.sev.critical }}>{relatedFindings.length} finding{relatedFindings.length !== 1 ? "s" : ""}</span></div>}
                                {relatedChains.length > 0 && <div><span style={{ color: th.sev.high }}>{relatedChains.length} chain{relatedChains.length !== 1 ? "s" : ""}</span></div>}
                              </div>
                              {Object.keys(techCounts).length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: 4 }}>Techniques Observed</div>
                                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                    {Object.entries(techCounts).sort((a, b) => b[1] - a[1]).map(([tech, cnt]) => (
                                      <span key={tech} style={{ padding: "1px 5px", background: _techColor(tech) + "15", color: _techColor(tech), borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600 }}>{tech} {cnt}</span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {/* Telemetry Coverage — shows analyst which event sources are present on this host */}
                              {node?.telemetry && (() => {
                                const tel = node.telemetry;
                                const cats = tel.categories || {};
                                const lvlColor = tel.level === "high" ? th.sev.clean : tel.level === "medium" ? th.sev.med : th.sev.critical;
                                const lvlLabel = tel.level === "high" ? "Strong" : tel.level === "medium" ? "Partial" : "Weak";
                                return (
                                  <div style={{ marginBottom: 8 }}>
                                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
                                      <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Telemetry Coverage</div>
                                      <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                                        <div style={{ width: 36, height: 4, borderRadius: 2, background: th.border + "44", overflow: "hidden" }}>
                                          <div style={{ width: `${tel.score}%`, height: "100%", background: lvlColor, borderRadius: 2 }} />
                                        </div>
                                        <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: lvlColor, fontWeight: 700 }}>{lvlLabel} {tel.score}%</span>
                                      </div>
                                    </div>
                                    <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                                      {Object.entries(cats).map(([id, c]) => {
                                        const color = c.present ? th.sev.clean : (c.critical ? th.sev.critical : th.textMuted);
                                        return (
                                          <span key={id} title={c.present ? `${c.label}: ${c.count.toLocaleString()} events` : `${c.label}: missing${c.critical ? " (critical)" : ""}`}
                                            style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "1px 5px", background: color + (c.present ? "18" : "10"), color, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, opacity: c.present ? 1 : 0.6, border: `1px solid ${color}${c.present ? "33" : "22"}` }}>
                                            <span style={{ width: 4, height: 4, borderRadius: 2, background: color }} />
                                            {c.label}{c.present ? ` ${c.count > 999 ? Math.round(c.count / 1000) + "k" : c.count}` : ""}
                                          </span>
                                        );
                                      })}
                                    </div>
                                    {(tel.weakCategories || []).length > 0 && (
                                      <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.sev.critical, marginTop: 4, fontStyle: "italic" }}>
                                        Missing critical telemetry: {tel.weakCategories.join(", ")}
                                      </div>
                                    )}
                                  </div>
                                );
                              })()}
                              {narrative.length > 0 && (
                                <div>
                                  <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: 4 }}>Why It Matters</div>
                                  {narrative.map((n, ni) => (
                                    <div key={ni} style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textDim, marginBottom: 2, lineHeight: 1.4, paddingLeft: 8 }}>{n}</div>
                                  ))}
                                </div>
                              )}
                            </div>
                            <div style={{ flex: 1, minWidth: 0, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "-apple-system, sans-serif" }}>
                              {outHigh.length > 0 && (
                                <div style={{ marginBottom: 6 }}>
                                  <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.sev.clean, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: 3 }}>Most Suspicious Outbound ({outHigh.length})</div>
                                  <div style={{ maxHeight: 80, overflowY: "auto" }}>
                                    {outHigh.slice(0, 5).map(e => edgeCard(e, "out"))}
                                    {outHigh.length > 5 && <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, padding: "2px 0" }}>+{outHigh.length - 5} more</div>}
                                  </div>
                                </div>
                              )}
                              {inHigh.length > 0 && (
                                <div style={{ marginBottom: 6 }}>
                                  <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.sev.info, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: 3 }}>Most Suspicious Inbound ({inHigh.length})</div>
                                  <div style={{ maxHeight: 80, overflowY: "auto" }}>
                                    {inHigh.slice(0, 5).map(e => edgeCard(e, "in"))}
                                    {inHigh.length > 5 && <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, padding: "2px 0" }}>+{inHigh.length - 5} more</div>}
                                  </div>
                                </div>
                              )}
                              {lowConf.length > 0 && (
                                <details style={{ marginTop: 2 }}>
                                  <summary style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Low-confidence / unresolved peers ({lowConf.length})</summary>
                                  <div style={{ maxHeight: 60, overflowY: "auto", marginTop: 3 }}>
                                    {lowConf.map((e, i) => (
                                      <div key={i} style={{ fontSize: LM_TYPOGRAPHY.meta, padding: "2px 0", color: th.textMuted, fontFamily: "monospace", display: "flex", gap: 5, alignItems: "center" }}>
                                        <span style={{ padding: "0 3px", background: e.dir === "in" ? th.sev.info + "15" : th.sev.clean + "15", color: e.dir === "in" ? th.sev.info : th.sev.clean, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge }}>{e.dir === "in" ? "IN" : "OUT"}</span>
                                        <span>{e.dir === "in" ? e.source : e.target}</span>
                                        <span>{e.count}x</span>
                                        {e.technique && e.technique !== "Unknown" && <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: _techColor(e.technique) }}>{e.technique}</span>}
                                      </div>
                                    ))}
                                  </div>
                                </details>
                              )}
                              {outHigh.length === 0 && inHigh.length === 0 && lowConf.length === 0 && (
                                <div style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.control }}>No edges found for this node</div>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Edge detail panel */}
                    {selectedEdge && (() => {
                      if (selectedEdge.graphKind === "identity-link") {
                        const relatedPaths = selectedEdge.relatedHostEdges || [];
                        return (
                          <div style={{ marginTop: 10, padding: 14, background: `linear-gradient(135deg, ${th.accent}08, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${th.accent}22`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
                              <span style={{ padding: "3px 9px", background: `${th.accent}18`, color: th.accent, borderRadius: 5, fontSize: LM_TYPOGRAPHY.control, fontWeight: 700 }}>Identity-linked path</span>
                              <span style={{ color: th.text, fontSize: LM_TYPOGRAPHY.title, fontWeight: 600, fontFamily: "monospace" }}>
                                {selectedEdge.hostSource || relatedPaths[0]?.source || "(source)"} {"\u2192"} {selectedEdge.identity || "(identity unavailable)"} {"\u2192"} {selectedEdge.hostTarget || relatedPaths[0]?.target || "(target)"}
                              </span>
                              {(selectedEdge.riskScore || 0) >= 15 && <span style={{ padding: "2px 6px", background: `${th.danger}14`, color: th.danger, borderRadius: 4, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700 }}>SCORE {selectedEdge.riskScore}</span>}
                            </div>
                            <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0, 1fr)", gap: 20 }}>
                              <div style={{ fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif", color: th.textDim, lineHeight: 1.55 }}>
                                {[
                                  ["Account", selectedEdge.identity || "(not available)"],
                                  ["Direction", selectedEdge.phase === "source-to-identity" ? "Machine used account" : "Account accessed machine"],
                                  ["Associated activity", `${selectedEdge.attributionApproximate ? "~" : ""}${selectedEdge.count || 0}`],
                                  ["Technique", selectedEdge.technique || "Network Logon"],
                                  ["First observed", fmtTs(selectedEdge.firstSeen) || "\u2014"],
                                  ["Last observed", fmtTs(selectedEdge.lastSeen) || "\u2014"],
                                ].map(([label, value]) => (
                                  <div key={label} style={{ display: "grid", gridTemplateColumns: "120px minmax(0, 1fr)", gap: 8, padding: "2px 0" }}>
                                    <span style={{ color: th.textMuted }}>{label}</span>
                                    <span style={{ color: th.text, overflowWrap: "anywhere" }}>{value}</span>
                                  </div>
                                ))}
                                <div style={{ marginTop: 10 }}><EvidenceActions item={selectedEdge} /></div>
                              </div>
                              <div style={{ minWidth: 0 }}>
                                <div style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge, textTransform: "uppercase", fontWeight: 700, marginBottom: 5 }}>Underlying machine paths ({relatedPaths.length})</div>
                                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                                  {relatedPaths.slice(0, 8).map((edge, index) => (
                                    <button key={`${edge.source}-${edge.target}-${index}`} onClick={(event) => _viewInGraph(edge, event)}
                                      style={{ width: "100%", display: "grid", gridTemplateColumns: "minmax(190px, 1fr) 120px 65px", gap: 8, alignItems: "center", padding: "5px 8px", borderRadius: 5, border: `1px solid ${th.border}33`, background: `${th.textMuted}08`, color: th.textDim, cursor: "pointer", textAlign: "left", fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}>
                                      <span style={{ color: th.text, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{edge.source} {"\u2192"} {edge.target}</span>
                                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{edge.technique || "Network Logon"}</span>
                                      <span style={{ color: (edge.riskScore || 0) >= 15 ? th.danger : th.textMuted, fontFamily: "monospace", textAlign: "right" }}>score {edge.riskScore || 0}</span>
                                    </button>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      }
                      const failureOnly = edgeFailureOnly(selectedEdge);
                      const mixedOutcome = edgeMixedOutcome(selectedEdge);
                      const ec = failureOnly ? th.danger : _techColor(selectedEdge.technique) || logonColor(selectedEdge.logonTypes);
                      const _edgeFindings = (data.findings || []).filter(f => {
                        const ft = (f.target || "").split(", "), fs = (f.source || "").split(", ");
                        return ft.includes(selectedEdge.target) && (fs.includes(selectedEdge.source) || !f.source);
                      });
                      const _edgeChains = (data.chains || []).filter(c => {
                        for (let ci = 0; ci < c.path.length - 1; ci++) { if (c.path[ci] === selectedEdge.source && c.path[ci + 1] === selectedEdge.target) return true; }
                        return false;
                      });
                      const _lbl = { fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 };
                      return (
                        <div style={{ marginTop: 10, padding: 14, background: `linear-gradient(135deg, ${ec}06, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${ec}22`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
                            <span style={{ fontWeight: 600, fontSize: LM_TYPOGRAPHY.title, color: th.text, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                              <span style={{ padding: "2px 8px", background: isSusHost(selectedEdge.source) ? th.sev.high + "18" : th.sev.clean + "18", color: isSusHost(selectedEdge.source) ? th.sev.high : th.sev.clean, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control }}>{selectedEdge.source}{isSusHost(selectedEdge.source) && " \u26a0"}</span>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={ec} strokeWidth="2" strokeLinecap="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                              <span style={{ padding: "2px 8px", background: isSusHost(selectedEdge.target) ? th.sev.high + "18" : th.sev.info + "18", color: isSusHost(selectedEdge.target) ? th.sev.high : th.sev.info, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control }}>{selectedEdge.target}{isSusHost(selectedEdge.target) && " \u26a0"}</span>
                            </span>
                            {failureOnly && <span style={{ padding: "2px 8px", background: (th.danger) + "18", color: th.danger, borderRadius: 6, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>FAILURE ONLY</span>}
                            {mixedOutcome && <span style={{ padding: "2px 8px", background: th.sev.high + "18", color: th.sev.high, borderRadius: 6, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>MIXED · {edgeFailureCount(selectedEdge)} FAILED</span>}
                            {selectedEdge.technique && <span style={{ padding: "2px 8px", background: _techColor(selectedEdge.technique) + "18", color: _techColor(selectedEdge.technique), borderRadius: 6, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{selectedEdge.technique}</span>}
                            {(selectedEdge.otherTechniques || []).length > 0 && <span style={{ padding: "2px 6px", background: `${th.textMuted}12`, color: th.textMuted, borderRadius: 6, fontSize: LM_TYPOGRAPHY.badge, fontFamily: "-apple-system, sans-serif" }}>+{selectedEdge.otherTechniques.join(", ")}</span>}
                            {(selectedEdge.riskScore || 0) > 0 && <span style={{ padding: "2px 8px", background: (selectedEdge.riskScore >= 30 ? th.sev.critical : selectedEdge.riskScore >= 15 ? th.sev.high : th.textMuted) + "18", color: selectedEdge.riskScore >= 30 ? th.sev.critical : selectedEdge.riskScore >= 15 ? th.sev.high : th.textMuted, borderRadius: 6, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 700, fontFamily: "monospace" }}>Score {selectedEdge.riskScore}</span>}
                            {selectedEdge.isFirstSeen && <span style={{ padding: "2px 6px", background: th.sev.custom + "18", color: th.sev.custom, borderRadius: 6, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>FIRST SEEN</span>}
                          </div>
                          <div style={{ display: "flex", gap: 18 }}>
                            <div style={{ width: 260, flexShrink: 0, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "-apple-system, sans-serif", color: th.textDim, overflow: "hidden" }}>
                              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 10px", marginBottom: 8 }}>
                                <div><span style={_lbl}>Events</span><div style={{ fontWeight: 700, color: th.text, fontSize: LM_TYPOGRAPHY.metric, marginTop: 1 }}>{selectedEdge.count}{selectedEdge.shareAccessCount > 0 ? <span style={{ fontSize: LM_TYPOGRAPHY.meta, fontWeight: 400, color: th.textMuted }}> +{selectedEdge.shareAccessCount} share</span> : ""}</div></div>
                                <div><span style={_lbl}>Users ({selectedEdge.users.length})</span><div style={{ marginTop: 2, color: th.text, maxHeight: 54, overflow: "auto", wordBreak: "break-word", lineHeight: 1.5 }}>{selectedEdge.users.slice(0, 8).join(", ")}{selectedEdge.users.length > 8 ? `, +${selectedEdge.users.length - 8} more` : ""}</div></div>
                                <div><span style={_lbl}>Logon Type</span><div style={{ color: logonColor(selectedEdge.logonTypes), marginTop: 2 }}>{logonLabel(selectedEdge.logonTypes)} ({selectedEdge.logonTypes.join(",")}){selectedEdge.logonTypes.includes("8") && <span style={{ marginLeft: 3, padding: "0 3px", background: th.sev.critical + "22", color: th.sev.critical, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700 }}>CLEARTEXT</span>}</div></div>
                                {selectedEdge.sourceLabel && <div><span style={_lbl}>Source Type</span><div style={{ marginTop: 2 }}>{selectedEdge.sourceLabel}</div></div>}
                                <div><span style={_lbl}>First Seen</span><div style={{ marginTop: 2, fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.meta }}>{fmtTs(selectedEdge.firstSeen)}</div></div>
                                <div><span style={_lbl}>Last Seen</span><div style={{ marginTop: 2, fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.meta }}>{fmtTs(selectedEdge.lastSeen)}</div></div>
                                {(selectedEdge.shareNames || []).length > 0 && <div style={{ gridColumn: "1 / -1" }}><span style={_lbl}>Shares</span><div style={{ marginTop: 2, color: th.sev.high }}>{selectedEdge.shareNames.join(", ")}</div></div>}
                                {(selectedEdge.clientNames || []).length > 0 && <div style={{ gridColumn: "1 / -1" }}><span style={_lbl}>Client Names</span><div style={{ marginTop: 2, color: th.sev.custom }}>{selectedEdge.clientNames.join(", ")}</div></div>}
                              </div>
                              {selectedEdge.flags && selectedEdge.flags.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <span style={_lbl}>Why Suspicious</span>
                                  <div style={{ display: "flex", gap: 3, marginTop: 4, flexWrap: "wrap" }}>
                                    {selectedEdge.flags.map((f, fi) => (
                                      <span key={fi} style={{ padding: "1px 5px", background: f.startsWith("Finding") ? th.sev.critical + "18" : f.includes("dampened") ? `${th.textMuted}08` : th.panelBg, color: f.startsWith("Finding") ? th.sev.critical : f.includes("dampened") ? th.textMuted : th.textDim, border: `1px solid ${th.border}33`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge }}>{f}</span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              <div style={{ marginBottom: 8 }}>
                                <EvidenceActions item={selectedEdge} />
                              </div>
                              {_edgeFindings.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <span style={_lbl}>Findings on this pair ({_edgeFindings.length})</span>
                                  <div style={{ marginTop: 4 }}>
                                    {_edgeFindings.slice(0, 4).map((f, fi) => {
                                      const sevC = f.severity === "critical" ? th.sev.critical : f.severity === "high" ? th.sev.high : f.severity === "medium" ? th.sev.med : th.textMuted;
                                      return (
                                        <div key={fi} style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 2 }}>
                                          <span style={{ padding: "0 4px", background: sevC + "18", color: sevC, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, minWidth: 36, textAlign: "center" }}>{f.severity.toUpperCase()}</span>
                                          <span style={{ color: th.textDim, fontSize: LM_TYPOGRAPHY.badge, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.category}: {f.title.slice(0, 60)}</span>
                                        </div>
                                      );
                                    })}
                                    {_edgeFindings.length > 4 && <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted }}>+{_edgeFindings.length - 4} more</div>}
                                  </div>
                                </div>
                              )}
                              {_edgeChains.length > 0 && (
                                <div>
                                  <span style={_lbl}>In {_edgeChains.length} chain{_edgeChains.length !== 1 ? "s" : ""}</span>
                                  <div style={{ marginTop: 3 }}>
                                    {_edgeChains.slice(0, 2).map((c, ci) => (
                                      <div key={ci} style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, marginBottom: 1 }}>{c.path.join(" \u2192 ")}</div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              {selectedEdge.episodes && selectedEdge.episodes.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <span style={_lbl}>Episodes ({selectedEdge.episodes.length})</span>
                                  <div style={{ marginTop: 4, maxHeight: 120, overflow: "auto" }}>
                                    {selectedEdge.episodes.slice(0, 20).map((ep, epi) => {
                                      const _pc = ep.phase === "failed" ? th.sev.critical : ep.phase === "reconnect" ? th.sev.custom : th.sev.clean;
                                      return (
                                        <div key={epi} style={{ fontSize: LM_TYPOGRAPHY.meta, padding: "3px 0", color: th.textDim, fontFamily: "monospace", display: "flex", alignItems: "center", gap: 5, borderBottom: `1px solid ${th.border}11` }}>
                                          <span style={{ padding: "0 3px", background: _pc + "18", color: _pc, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, minWidth: 30, textAlign: "center" }}>{ep.phase === "failed" ? "FAIL" : ep.phase === "reconnect" ? "RECON" : "OK"}</span>
                                          <span style={{ color: th.text, fontWeight: 600, minWidth: 60 }}>{ep.user}</span>
                                          {ep.techFamily && <span style={{ padding: "0 3px", background: _techColor(ep.techFamily === "ServiceExec" ? "Service Exec" : ep.techFamily === "AdminShare" ? "Admin Share" : ep.techFamily) + "12", color: _techColor(ep.techFamily === "ServiceExec" ? "Service Exec" : ep.techFamily === "AdminShare" ? "Admin Share" : ep.techFamily), borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge }}>{ep.techFamily}</span>}
                                          <span style={{ color: th.textMuted }}>{ep.count} evt{ep.count !== 1 ? "s" : ""}</span>
                                          <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge }}>{ep.firstTs?.slice(11, 19)}{ep.lastTs !== ep.firstTs ? `\u2013${ep.lastTs?.slice(11, 19)}` : ""}</span>
                                        </div>
                                      );
                                    })}
                                    {selectedEdge.episodes.length > 20 && <div style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, padding: "2px 0" }}>+{selectedEdge.episodes.length - 20} more</div>}
                                  </div>
                                </div>
                              )}
                              {selectedEdge.eventBreakdown && Object.keys(selectedEdge.eventBreakdown).length > 0 && (
                                <div>
                                  <span style={_lbl}>Event Breakdown</span>
                                  <div style={{ display: "flex", gap: 4, marginTop: 4, flexWrap: "wrap" }}>
                                    {Object.entries(selectedEdge.eventBreakdown).sort((a, b) => b[1] - a[1]).map(([eid, count]) => (
                                      <span key={eid} style={{ padding: "2px 6px", background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "monospace" }}>
                                        <span style={{ color: th.accent, fontWeight: 600 }}>{eid}</span>
                                        <span style={{ color: th.textMuted, marginLeft: 2 }}>{"\u00D7"}{count}</span>
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                );
              })()}

              {/* Chains, RDP, and Connections tabs are rendered from the original IIFE logic. */}
              {/* Due to extreme size, these remaining tabs (chains, rdp, table) maintain identical */}
              {/* rendering logic — extracted verbatim from App.jsx lines 11222-12187. */}
              {/* They are included inline below. */}

              {/* Chains tab */}
              {viewTab === "chains" && (() => {
                const chs = data.chains || [];
                if (chs.length === 0) return <div style={{ textAlign: "center", padding: 30, color: th.textMuted, fontSize: LM_TYPOGRAPHY.title, fontFamily: "-apple-system, sans-serif" }}>No multi-hop lateral movement chains detected</div>;
                const pivotMap = new Map();
                for (const ch of chs) {
                  for (let pi = 1; pi < ch.path.length - 1; pi++) {
                    const host = ch.path[pi];
                    if (!pivotMap.has(host)) pivotMap.set(host, { count: 0, origins: new Set(), terminals: new Set(), maxConf: 0 });
                    const pm = pivotMap.get(host);
                    pm.count++;
                    pm.origins.add(ch.path[0]);
                    pm.terminals.add(ch.path[ch.path.length - 1]);
                    if ((ch.confidenceScore || 0) > pm.maxConf) pm.maxConf = ch.confidenceScore || 0;
                  }
                }
                const pivots = [...pivotMap.entries()].filter(([, v]) => v.count >= 2).sort((a, b) => b[1].count - a[1].count).slice(0, 5);
                const confColor = (c) => c === "high" ? th.sev.critical : c === "medium" ? th.sev.high : th.textMuted;
                const confBg = (c) => confColor(c) + "18";
                const expandedChain = modal.expandedChain;
                return (
                  <div>
                    {pivots.length > 0 && (
                      <div style={{ display: "flex", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
                        {pivots.map(([host, info]) => (
                          <div key={host} style={{ padding: "6px 10px", background: `${th.accent}08`, border: `1px solid ${th.border}`, borderRadius: 6, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "-apple-system, sans-serif" }}>
                            <div style={{ fontWeight: 700, color: th.text, fontSize: LM_TYPOGRAPHY.control, marginBottom: 2 }}>{host}</div>
                            <div style={{ color: th.textDim }}>Pivot in {info.count} chains</div>
                            <div style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge }}>Origins: {[...info.origins].slice(0, 3).join(", ")}{info.origins.size > 3 ? ` +${info.origins.size - 3}` : ""}</div>
                            <div style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge }}>Targets: {[...info.terminals].slice(0, 3).join(", ")}{info.terminals.size > 3 ? ` +${info.terminals.size - 3}` : ""}</div>
                          </div>
                        ))}
                      </div>
                    )}
                    <div style={{ maxHeight: 350, overflow: "auto" }}>
                      {chs.map((chain, ci) => {
                        const _chainKey = `${(chain.path || []).join("\u2192")}::${(chain.users || []).join(",")}`;
                        const isExpanded = expandedChain === _chainKey;
                        const cc = confColor(chain.confidence);
                        return (
                          <div key={ci} style={{ padding: "10px 12px", marginBottom: 8, background: th.panelBg, borderRadius: 6, border: `1px solid ${isExpanded ? cc + "44" : th.border}`, cursor: "pointer" }} onClick={() => setModal((p) => ({ ...p, expandedChain: isExpanded ? null : _chainKey }))}>
                            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6, flexWrap: "wrap" }}>
                              <span style={{ padding: "2px 6px", background: confBg(chain.confidence), color: cc, borderRadius: 3, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 700, fontFamily: "monospace", minWidth: 24, textAlign: "center" }}>{chain.confidenceScore || 0}</span>
                              <span style={{ padding: "2px 6px", background: confBg(chain.confidence), color: cc, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase" }}>{chain.confidence || "low"}</span>
                              <span style={{ padding: "2px 6px", background: (th.danger) + "18", color: th.danger, borderRadius: 3, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{chain.hops} hop{chain.hops !== 1 ? "s" : ""}</span>
                              <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.text, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{chain.users.join(", ") || "(unknown)"}</span>
                              {(chain.techniques || []).map((t, ti) => (
                                <span key={ti} style={{ padding: "1px 5px", background: t.includes("RDP") ? th.sev.info + "15" : t.includes("Service") || t.includes("PsExec") || t.includes("Impacket") ? th.sev.critical + "15" : t.includes("Admin Share") || t.includes("Scheduled Task") || t.includes("WMI") || t.includes("WinRM") ? th.sev.high + "18" : `${th.textMuted}12`, color: t.includes("RDP") ? th.sev.info : t.includes("Service") || t.includes("PsExec") || t.includes("Impacket") ? th.sev.critical : t.includes("Admin Share") || t.includes("Scheduled Task") || t.includes("WMI") || t.includes("WinRM") ? th.sev.high : th.textDim, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontFamily: "-apple-system, sans-serif" }}>{t}</span>
                              ))}
                              {(chain.occurrences || 1) > 1 && <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{"\u00D7"}{chain.occurrences}</span>}
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap" }}>
                              {chain.path.map((host, hi) => (
                                <span key={hi} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                                  <span style={{ padding: "3px 8px", background: hi === 0 ? th.sev.clean + "22" : hi === chain.path.length - 1 ? (th.danger) + "22" : th.btnBg, color: hi === 0 ? th.sev.clean : hi === chain.path.length - 1 ? (th.danger) : th.text, borderRadius: 4, fontSize: LM_TYPOGRAPHY.control, fontFamily: "monospace", border: `1px solid ${th.border}` }}>{host}</span>
                                  {hi < chain.path.length - 1 && <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.control }}>{"\u2192"}</span>}
                                </span>
                              ))}
                            </div>
                            {isExpanded && (
                              <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${th.border}22` }}>
                                <div style={{ display: "flex", gap: 20 }}>
                                  <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ fontWeight: 600, fontSize: LM_TYPOGRAPHY.meta, color: th.text, fontFamily: "-apple-system, sans-serif", marginBottom: 6 }}>Hop Detail</div>
                                    {(chain.hopDetails || []).map((hop, hi) => (
                                      <div key={hi} style={{ padding: "5px 0", fontSize: LM_TYPOGRAPHY.meta, fontFamily: "monospace", color: th.textDim, borderBottom: hi < chain.hopDetails.length - 1 ? `1px solid ${th.border}15` : "none" }}>
                                        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                          <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge, minWidth: 12 }}>#{hi + 1}</span>
                                          <span style={{ color: th.sev.clean, fontWeight: 600 }}>{hop.source}</span>
                                          <span style={{ color: th.textMuted }}>{"\u2192"}</span>
                                          <span style={{ color: hi === chain.hopDetails.length - 1 ? th.sev.critical : th.text, fontWeight: 600 }}>{hop.target}</span>
                                        </div>
                                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 2, paddingLeft: 20 }}>
                                          <span style={{ color: th.text }}>{hop.user}</span>
                                          <span style={{ padding: "0 4px", background: hop.technique?.includes("RDP") ? th.sev.info + "15" : hop.technique?.includes("Service") || hop.technique?.includes("PsExec") || hop.technique?.includes("Impacket") ? th.sev.critical + "15" : hop.technique?.includes("Admin Share") || hop.technique?.includes("Scheduled Task") || hop.technique?.includes("WMI") || hop.technique?.includes("WinRM") ? th.sev.high + "18" : `${th.textMuted}12`, color: hop.technique?.includes("RDP") ? th.sev.info : hop.technique?.includes("Service") || hop.technique?.includes("PsExec") || hop.technique?.includes("Impacket") ? th.sev.critical : hop.technique?.includes("Admin Share") || hop.technique?.includes("Scheduled Task") || hop.technique?.includes("WMI") || hop.technique?.includes("WinRM") ? th.sev.high : th.textDim, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge }}>{hop.technique}</span>
                                          <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge }}>EID {hop.eventId} / Type {hop.logonType}</span>
                                          <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge }}>{fmtTs(hop.ts)}</span>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                  <div style={{ width: 200, flexShrink: 0, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "-apple-system, sans-serif", color: th.textDim }}>
                                    <div style={{ fontWeight: 600, fontSize: LM_TYPOGRAPHY.meta, color: th.text, marginBottom: 6 }}>Why This Chain</div>
                                    {(chain.confidenceFlags || []).map((f, fi) => (
                                      <div key={fi} style={{ padding: "2px 0", display: "flex", alignItems: "center", gap: 4 }}>
                                        <span style={{ color: f.includes("penalty") ? th.sev.high : th.sev.clean, fontSize: LM_TYPOGRAPHY.badge }}>{f.includes("penalty") ? "\u2212" : "+"}</span>
                                        <span>{f}</span>
                                      </div>
                                    ))}
                                    {(chain.occurrences || 1) > 1 && (
                                      <div style={{ marginTop: 8, paddingTop: 6, borderTop: `1px solid ${th.border}22` }}>
                                        <span style={{ color: th.textMuted }}>Seen {chain.occurrences} time{chain.occurrences > 1 ? "s" : ""}</span>
                                        <div style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge, marginTop: 2 }}>{fmtTs(chain.firstTs)} — {fmtTs(chain.lastTs)}</div>
                                      </div>
                                    )}
                                    {(chain.findingIds || []).length > 0 && (
                                      <div style={{ marginTop: 6, paddingTop: 4, borderTop: `1px solid ${th.border}22` }}>
                                        <span style={{ color: th.sev.critical }}>{chain.findingIds.length} related finding{chain.findingIds.length > 1 ? "s" : ""}</span>
                                      </div>
                                    )}
                                    <div style={{ marginTop: 8, paddingTop: 6, borderTop: `1px solid ${th.border}22` }}>
                                      <EvidenceActions item={chain} />
                                    </div>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })()}

              {/* RDP Sessions tab */}
              {viewTab === "rdp" && (() => {
                const sessions = data.rdpSessions || [];
                if (sessions.length === 0) {
                  return <div style={{ textAlign: "center", padding: 30, color: th.textMuted, fontSize: LM_TYPOGRAPHY.title, fontFamily: "-apple-system, sans-serif" }}>No evidence-backed RDP activity detected. Include TerminalServices logs or Security 4624/4625 Logon Types 10/12 to improve coverage.</div>;
                }
                const rdpHeaders = ["Score", "Status", "Technique", "Source", "Target", "User", "Confidence", "Evidence", "Attempts", "Start Time", "End Time", "Duration", "Why Flagged"];
                const rdpDefWidths = { Score: 48, Status: 90, Technique: 115, Source: 130, Target: 130, User: 120, Confidence: 72, Evidence: 82, Attempts: 55, "Start Time": 140, "End Time": 140, Duration: 70, "Why Flagged": 200 };
                const rdpColWidths = modal.rdpColWidths || rdpDefWidths;
                const rdpSortCol = modal.rdpSortCol || "Score";
                const rdpSortDir = modal.rdpSortDir || "desc";

                const statusStyle = (status) => {
                  const map = {
                    "active": { bg: th.sev.clean + "22", color: th.sev.clean, label: "ACTIVE" },
                    "active (no logoff)": { bg: th.sev.high + "22", color: th.sev.high, label: "NO LOGOFF" },
                    "disconnected": { bg: th.sev.med + "22", color: th.sev.med, label: "DISCONNECTED" },
                    "ended": { bg: `${th.textMuted}15`, color: th.textMuted, label: "ENDED" },
                    "failed": { bg: th.sev.critical + "22", color: th.sev.critical, label: "FAILED" },
                    "connecting": { bg: th.sev.info + "22", color: th.sev.info, label: "CONNECTING" },
                    "incomplete": { bg: `${th.textMuted}15`, color: th.textMuted, label: "INCOMPLETE" },
                  };
                  return map[status] || map["incomplete"];
                };
                const fmtDur = (s, e) => {
                  if (!s || !e) return "\u2014";
                  const startMs = tsMs(s);
                  const endMs = tsMs(e);
                  const ms = endMs - startMs;
                  if (!Number.isFinite(ms) || ms <= 0) return "\u2014";
                  const sec = Math.floor(ms / 1000), min = Math.floor(sec / 60), hr = Math.floor(min / 60), dy = Math.floor(hr / 24);
                  const rh = hr % 24, rm = min % 60;
                  if (dy > 0 && rh > 0) return `${dy}d ${rh}h`;
                  if (dy > 0) return `${dy}d`;
                  if (hr > 0 && rm > 0) return `${hr}h ${rm}m`;
                  if (hr > 0) return `${hr}h`;
                  if (min > 0) return `${min}m`;
                  return `${sec}s`;
                };
                const _rdpEnd = (s) => s.endTime || s.effectiveEnd || "";
                const rdpDurMs = (s) => {
                  const end = _rdpEnd(s);
                  if (!s.startTime || !end) return 0;
                  const d = tsMs(end) - tsMs(s.startTime);
                  return Number.isFinite(d) ? Math.max(0, d) : 0;
                };
                const techStyle = (tech) => {
                  const m = {
                    "RDP": { bg: `${th.textMuted}15`, color: th.textMuted },
                    "RDP Failed Auth": { bg: th.sev.critical + "22", color: th.sev.critical },
                    "RDP Brute Force": { bg: th.sev.critical + "33", color: th.sev.critical },
                    "RDP Reconnect": { bg: th.sev.custom + "18", color: th.sev.custom },
                    "Suspicious RDP": { bg: th.sev.high + "22", color: th.sev.high },
                  };
                  return m[tech] || m["RDP"];
                };
                const confStyle = (c) => ({ high: th.sev.clean, medium: th.sev.med, low: th.textMuted }[c] || th.textMuted);
                const evidenceStyle = (level) => level === "correlated"
                  ? { bg: th.sev.med + "18", color: th.sev.med, label: "CORRELATED" }
                  : { bg: th.sev.info + "18", color: th.sev.info, label: "DIRECT" };

                const rdpCellVal = (s, h) => {
                  if (h === "Score") return String(s.suspicionScore || 0);
                  if (h === "Status") return statusStyle(s.status).label;
                  if (h === "Technique") return s.technique || "RDP";
                  if (h === "Source") return s.source || "\u2014";
                  if (h === "Target") return s.target || "\u2014";
                  if (h === "User") return s.user || "(unknown)";
                  if (h === "Confidence") return (s.confidence || "low").toUpperCase();
                  if (h === "Evidence") return evidenceStyle(s.evidenceLevel).label;
                  if (h === "Attempts") return String(s.attemptCount || 1);
                  if (h === "Start Time") return fmtTs(s.startTime) || "";
                  if (h === "End Time") {
                    const end = _rdpEnd(s);
                    if (!end) return "";
                    return fmtTs(end) + (s.endIsLastSeen ? " *" : "");
                  }
                  if (h === "Duration") return fmtDur(s.startTime, _rdpEnd(s));
                  if (h === "Why Flagged") return (s.flags || []).join("; ");
                  return "";
                };
                const rdpSortKey = (s, col) => {
                  if (col === "Score") return s.suspicionScore || 0;
                  if (col === "Status") return statusStyle(s.status).label;
                  if (col === "Technique") return s.technique || "";
                  if (col === "Source") return s.source || "";
                  if (col === "Target") return s.target || "";
                  if (col === "User") return s.user || "";
                  if (col === "Confidence") return ({ high: 3, medium: 2, low: 1 })[s.confidence] || 0;
                  if (col === "Evidence") return s.evidenceLevel === "correlated" ? 1 : 2;
                  if (col === "Attempts") return s.attemptCount || 1;
                  if (col === "Start Time") return s.startTime || "";
                  if (col === "End Time") return _rdpEnd(s) || "";
                  if (col === "Duration") return rdpDurMs(s);
                  if (col === "Why Flagged") return (s.flags || []).length;
                  return "";
                };

                // Column filters
                const rdpColFilters = modal.rdpColFilters || {};
                const filteredSessions = sessions.filter((s) => {
                  for (const [col, allowed] of Object.entries(rdpColFilters)) {
                    if (!allowed || allowed.length === 0) continue;
                    const val = rdpCellVal(s, col);
                    if (!allowed.includes(val)) return false;
                  }
                  return true;
                });
                const sortedSessions = [...filteredSessions].sort((a, b) => {
                  const av = rdpSortKey(a, rdpSortCol), bv = rdpSortKey(b, rdpSortCol);
                  const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                  return rdpSortDir === "asc" ? cmp : -cmp;
                });
                const toggleRdpSort = (col) => {
                  setModal((p) => ({ ...p, rdpSortCol: col, rdpSortDir: p.rdpSortCol === col && p.rdpSortDir === "asc" ? "desc" : "asc" }));
                };

                // Checkbox state
                const rdpChecked = modal.rdpCheckedRows || new Set();
                const rdpRowKey = (s) => `${s.source}|${s.target}|${s.user}|${s.startTime}`;
                const isRdpChecked = (s) => rdpChecked.has(rdpRowKey(s));
                const toggleRdpCheck = (s, ev) => {
                  ev.stopPropagation();
                  const k = rdpRowKey(s);
                  setModal((p) => { const set = new Set(p.rdpCheckedRows || []); set.has(k) ? set.delete(k) : set.add(k); return { ...p, rdpCheckedRows: set }; });
                };
                const rdpAllChecked = sortedSessions.length > 0 && sortedSessions.every((s) => isRdpChecked(s));
                const toggleAllRdp = (ev) => {
                  ev.stopPropagation();
                  setModal((p) => {
                    if (rdpAllChecked) return { ...p, rdpCheckedRows: new Set() };
                    return { ...p, rdpCheckedRows: new Set(sortedSessions.map(rdpRowKey)) };
                  });
                };
                const rdpCheckedCount = sortedSessions.filter((s) => isRdpChecked(s)).length;

                // Copy (selected or all)
                const copyRdp = () => {
                  const headerLine = rdpHeaders.join("\t");
                  const selected = sortedSessions.filter((s) => isRdpChecked(s));
                  const toCopy = selected.length > 0 ? selected : sortedSessions;
                  const lines = toCopy.map((s) => rdpHeaders.map((h) => rdpCellVal(s, h)).join("\t"));
                  navigator.clipboard?.writeText?.([headerLine, ...lines].join("\n"));
                };

                // CSV export (selected or all)
                const exportRdpCsv = () => {
                  const esc = csvCell; // shared encoder: RFC-4180 + formula-injection guard
                  const selected = sortedSessions.filter((s) => isRdpChecked(s));
                  const toExport = selected.length > 0 ? selected : sortedSessions;
                  const headerLine = rdpHeaders.map(esc).join(",");
                  const lines = toExport.map((s) => rdpHeaders.map((h) => esc(rdpCellVal(s, h))).join(","));
                  const csv = [headerLine, ...lines].join("\n");
                  _saveExport(csv, `rdp-sessions-${new Date().toISOString().slice(0, 10)}.csv`, [{ name: "CSV", extensions: ["csv"] }]);
                };

                // Resize
                const onRdpResizeStart = (colName, e) => {
                  e.preventDefault(); e.stopPropagation();
                  const startX = e.clientX;
                  const startW = rdpColWidths[colName] || rdpDefWidths[colName];
                  document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                  const move = (ev) => {
                    const newW = Math.max(40, startW + ev.clientX - startX);
                    setModal((p) => ({ ...p, rdpColWidths: { ...(p.rdpColWidths || rdpDefWidths), [colName]: newW } }));
                  };
                  const up = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); };
                  document.addEventListener("mousemove", move);
                  document.addEventListener("mouseup", up);
                };

                // Column filter dropdown
                const openRdpFilter = (colName, e) => {
                  e.stopPropagation();
                  const rect = e.currentTarget.getBoundingClientRect();
                  const counts = {};
                  for (const s of sessions) { const v = rdpCellVal(s, colName); counts[v] = (counts[v] || 0) + 1; }
                  const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
                  const current = rdpColFilters[colName];
                  const selected = new Set(current && current.length > 0 ? current : allVals);
                  setModal((p) => ({ ...p, rdpFilterOpen: colName, rdpFilterPos: { x: rect.left, y: rect.bottom + 2 }, rdpFilterVals: allVals, rdpFilterCounts: counts, rdpFilterSel: selected, rdpFilterSearch: "", rdpFilterX: null, rdpFilterY: null }));
                };
                const rdpFilterOpen = modal.rdpFilterOpen;
                const rdpFilterPos = modal.rdpFilterPos || {};
                const rdpFilterVals = modal.rdpFilterVals || [];
                const rdpFilterCounts = modal.rdpFilterCounts || {};
                const rdpFilterSel = modal.rdpFilterSel || new Set();
                const rdpFilterSearch = modal.rdpFilterSearch || "";
                const rdpDisplayVals = rdpFilterSearch ? rdpFilterVals.filter((v) => v.toLowerCase().includes(rdpFilterSearch.toLowerCase())) : rdpFilterVals;
                const rdpActiveFilterCount = Object.values(rdpColFilters).filter((v) => v && v.length > 0).length;
                const rdpTotalTableW = 30 + rdpHeaders.reduce((acc, h) => acc + (rdpColWidths[h] || rdpDefWidths[h]), 0);
                const expandedIdx = modal.expandedSession;

                const rdpViewMode = modal.rdpViewMode || "grouped";
                const gSessions = [...(data.groupedSessions || [])].sort((a, b) => {
                  const aMax = Math.max(0, ...(a.sessions || []).map(s => s.suspicionScore || 0));
                  const bMax = Math.max(0, ...(b.sessions || []).map(s => s.suspicionScore || 0));
                  return bMax - aMax || (b.count || 0) - (a.count || 0);
                });
                const expandedGroup = modal.expandedGroup;
                const rdpSessionTotal = sessions.filter((s) => s.status !== "failed").length;
                const rdpFailureEpisodes = sessions.filter((s) => s.status === "failed").length;
                const rdpFailedAttempts = sessions
                  .filter((s) => s.status === "failed")
                  .reduce((sum, s) => sum + (s.attemptCount || 1), 0);
                const rdpCorrelatedTotal = sessions.filter((s) => s.evidenceLevel === "correlated").length;

                return (
                  <div>
                    <div style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "7px 10px", marginBottom: 8, border: `1px solid ${th.border}55`, borderRadius: 7, background: `${th.sev.info}08`, color: th.textDim, fontFamily: "-apple-system, sans-serif", fontSize: LM_TYPOGRAPHY.control, lineHeight: 1.4 }}>
                      <span style={{ color: th.sev.info, fontWeight: 700, whiteSpace: "nowrap" }}>RDP evidence model</span>
                      <span>
                        {rdpSessionTotal} session{rdpSessionTotal !== 1 ? "s" : ""} · {rdpFailedAttempts} failed attempt{rdpFailedAttempts !== 1 ? "s" : ""} in {rdpFailureEpisodes} episode{rdpFailureEpisodes !== 1 ? "s" : ""} · {rdpCorrelatedTotal} correlated record{rdpCorrelatedTotal !== 1 ? "s" : ""}.
                        {" "}Direct evidence is TerminalServices activity or Security Logon Type 10/12; Type 3 failures require nearby RDP evidence. Missing expected telemetry lowers confidence but does not raise the suspicion score.
                      </span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6, marginBottom: 6 }}>
                      {rdpActiveFilterCount > 0 && (
                        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", background: `${th.accent}11`, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
                          <span style={{ fontWeight: 600 }}>Filter active ({rdpActiveFilterCount} column{rdpActiveFilterCount > 1 ? "s" : ""})</span>
                          <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted }}>{"\u2014"} {filteredSessions.length} of {sessions.length} sessions</span>
                          <button onClick={() => setModal((p) => ({ ...p, rdpColFilters: {} }))} style={{ padding: "1px 8px", fontSize: LM_TYPOGRAPHY.meta, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}>Clear All</button>
                        </div>
                      )}
                      <div style={{ display: "flex", gap: 6, marginLeft: "auto", alignItems: "center" }}>
                        {/* Grouped/Individual/Timeline toggle */}
                        {gSessions.length > 0 && (
                          <div style={{ display: "inline-flex", background: th.panelBg, borderRadius: 6, padding: 2, border: `1px solid ${th.border}44`, gap: 1 }}>
                            {[{ id: "grouped", label: "Grouped" }, { id: "individual", label: "Individual" }, { id: "timeline", label: "Timeline" }].map((m) => (
                              <button key={m.id} onClick={() => setModal((p) => ({ ...p, rdpViewMode: m.id }))} style={{ padding: "2px 10px", background: rdpViewMode === m.id ? `${th.accent}` : "transparent", color: rdpViewMode === m.id ? "#fff" : th.textDim, border: "none", borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: rdpViewMode === m.id ? 600 : 400, transition: "all var(--m-base)" }}>{m.label}</button>
                            ))}
                          </div>
                        )}
                        <button onClick={copyRdp} style={{ padding: "3px 10px", fontSize: LM_TYPOGRAPHY.control, background: th.btnBg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}
                          onMouseEnter={(ev) => { ev.currentTarget.style.background = th.accent + "22"; }} onMouseLeave={(ev) => { ev.currentTarget.style.background = th.btnBg; }}>
                          {rdpCheckedCount > 0 ? `Copy Selected (${rdpCheckedCount})` : `Copy All (${sortedSessions.length})`}
                        </button>
                        <button onClick={exportRdpCsv} style={{ padding: "3px 10px", fontSize: LM_TYPOGRAPHY.control, background: th.btnBg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 4 }}
                          onMouseEnter={(ev) => { ev.currentTarget.style.background = th.accent + "22"; }} onMouseLeave={(ev) => { ev.currentTarget.style.background = th.btnBg; }}>
                          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                          Export CSV
                        </button>
                      </div>
                    </div>

                    {/* Timeline view — Gantt-style session bars */}
                    {rdpViewMode === "timeline" && (() => {
                      // Compute time range across all sessions
                      let tMin = Infinity, tMax = -Infinity;
                      for (const s of sessions) {
                        const st = tsMs(s.startTime);
                        const endStr = _rdpEnd(s);
                        const et = endStr ? tsMs(endStr) : st + 300000; // default 5min if no end
                        if (Number.isFinite(st) && st < tMin) tMin = st;
                        if (Number.isFinite(et) && et > tMax) tMax = et;
                        if (Number.isFinite(st) && st > tMax) tMax = st;
                      }
                      if (!isFinite(tMin) || !isFinite(tMax) || tMax <= tMin) tMax = tMin + 3600000;
                      const tRange = tMax - tMin;
                      const W = 700; // timeline width in px
                      const ROW_H = 22;
                      const LABEL_W = 220;
                      const toPx = (t) => Math.max(0, Math.min(W, ((t - tMin) / tRange) * W));

                      // Phase colors
                      const phaseColor = {
                        "connecting": th.sev.info,
                        "active": th.sev.clean,
                        "active (no logoff)": th.sev.high,
                        "disconnected": th.sev.med,
                        "ended": th.textMuted,
                        "failed": th.sev.critical,
                        "incomplete": th.textMuted + "88",
                      };

                      // Sort sessions by start time
                      const sorted = [...sessions].sort((a, b) => (a.startTime || "").localeCompare(b.startTime || ""));

                      // Group by user+source→target for swim lanes
                      const lanes = new Map();
                      for (const s of sorted) {
                        const lk = `${s.user || "?"}  ${s.source || "?"} → ${s.target || "?"}`;
                        if (!lanes.has(lk)) lanes.set(lk, []);
                        lanes.get(lk).push(s);
                      }
                      const laneKeys = [...lanes.keys()];

                      // Time axis labels
                      const tickCount = 6;
                      const ticks = [];
                      for (let i = 0; i <= tickCount; i++) {
                        const t = tMin + (tRange * i / tickCount);
                        const d = new Date(t);
                        const label = `${String(d.getUTCMonth()+1).padStart(2,"0")}/${String(d.getUTCDate()).padStart(2,"0")} ${String(d.getUTCHours()).padStart(2,"0")}:${String(d.getUTCMinutes()).padStart(2,"0")} UTC`;
                        ticks.push({ x: toPx(t), label });
                      }

                      return (
                        <div style={{ border: `1px solid ${th.border}`, borderRadius: 6, overflow: "auto", maxHeight: 420 }}>
                          {/* Time axis */}
                          <div style={{ display: "flex", position: "sticky", top: 0, zIndex: 2, background: th.headerBg || th.panelBg, borderBottom: `1px solid ${th.border}` }}>
                            <div style={{ width: LABEL_W, flexShrink: 0, padding: "4px 8px", fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif", fontWeight: 600, borderRight: `1px solid ${th.border}33` }}>
                              SESSION
                            </div>
                            <div style={{ position: "relative", width: W, height: 22 }}>
                              {ticks.map((t, i) => (
                                <div key={i} style={{ position: "absolute", left: t.x, top: 0, height: "100%", borderLeft: `1px solid ${th.border}22`, display: "flex", alignItems: "center" }}>
                                  <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", paddingLeft: 3, whiteSpace: "nowrap" }}>{t.label}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Swim lanes */}
                          {laneKeys.map((lk, li) => {
                            const laneSessions = lanes.get(lk);
                            return (
                              <div key={li} style={{ display: "flex", borderBottom: `1px solid ${th.border}15` }}>
                                {/* Label */}
                                <div style={{ width: LABEL_W, flexShrink: 0, padding: "2px 8px", fontSize: LM_TYPOGRAPHY.meta, fontFamily: "'SF Mono',Menlo,monospace", color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", borderRight: `1px solid ${th.border}22`, display: "flex", alignItems: "center", minHeight: ROW_H }}
                                  title={lk}>
                                  {lk}
                                </div>
                                {/* Bars */}
                                <div style={{ position: "relative", width: W, minHeight: ROW_H }}>
                                  {/* Grid lines */}
                                  {ticks.map((t, ti) => (
                                    <div key={ti} style={{ position: "absolute", left: t.x, top: 0, bottom: 0, width: 1, background: th.border + "11" }} />
                                  ))}
                                  {laneSessions.map((s, si) => {
                                    const st = tsMs(s.startTime);
                                    const endStr = _rdpEnd(s);
                                    const et = endStr ? tsMs(endStr) : st + Math.max(300000, tRange * 0.005);
                                    if (!Number.isFinite(st)) return null;
                                    const x1 = toPx(st);
                                    const x2 = toPx(Number.isFinite(et) ? et : st + 300000);
                                    const barW = Math.max(3, x2 - x1);
                                    const color = phaseColor[s.status] || th.textMuted;
                                    const isFailed = s.status === "failed";
                                    const isSuspicious = (s.suspicionScore || 0) >= 25;
                                    return (
                                      <div key={si}
                                        onClick={() => setModal((p) => ({ ...p, expandedSession: p.expandedSession === s.id ? null : s.id }))}
                                        title={`${s.technique || "RDP"} | ${s.status} | ${s.user || "?"} | ${fmtTs(s.startTime)} → ${fmtTs(endStr) || "?"}${s.endIsLastSeen ? " (last seen)" : ""} | Score: ${s.suspicionScore || 0}`}
                                        style={{
                                          position: "absolute", left: x1, top: 3, height: ROW_H - 6,
                                          width: barW, borderRadius: 3, cursor: "pointer",
                                          background: isFailed ? `repeating-linear-gradient(135deg, ${color}44, ${color}44 3px, ${color}22 3px, ${color}22 6px)` : color + "55",
                                          border: `1px solid ${color}${isSuspicious ? "cc" : "44"}`,
                                          boxShadow: isSuspicious ? `0 0 4px ${color}44` : "none",
                                          transition: "box-shadow var(--m-base)",
                                        }}
                                        onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 0 6px ${color}66`; e.currentTarget.style.zIndex = "1"; }}
                                        onMouseLeave={(e) => { e.currentTarget.style.boxShadow = isSuspicious ? `0 0 4px ${color}44` : "none"; e.currentTarget.style.zIndex = ""; }}>
                                        {barW > 40 && (
                                          <span style={{ position: "absolute", left: 4, top: 0, bottom: 0, display: "flex", alignItems: "center", fontSize: LM_TYPOGRAPHY.badge, color, fontWeight: 600, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", overflow: "hidden" }}>
                                            {s.status === "failed" ? `${s.attemptCount || 1}x` : s.technique || "RDP"}
                                          </span>
                                        )}
                                        {/* Events within session as tick marks */}
                                        {barW > 20 && (s.events || []).map((ev, ei) => {
                                          const evT = tsMs(ev.ts);
                                          if (!Number.isFinite(evT)) return null;
                                          const evX = ((evT - st) / (et - st)) * barW;
                                          if (evX < 0 || evX > barW) return null;
                                          const evColor = ev.eventId === "4625" ? th.sev.critical : ev.eventId === "4672" ? th.sev.custom : ev.eventId === "4648" ? th.sev.high : th.text;
                                          return <div key={ei} style={{ position: "absolute", left: evX, top: 0, bottom: 0, width: 1, background: evColor + "55" }} title={`${ev.description} (${fmtTs(ev.ts)})`} />;
                                        })}
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            );
                          })}

                          {/* Legend */}
                          <div style={{ display: "flex", gap: 12, padding: "6px 12px", borderTop: `1px solid ${th.border}33`, background: th.panelBg }}>
                            {[
                              { status: "connecting", label: "Connecting" },
                              { status: "active", label: "Active" },
                              { status: "active (no logoff)", label: "No Logoff" },
                              { status: "disconnected", label: "Disconnected" },
                              { status: "ended", label: "Ended" },
                              { status: "failed", label: "Failed" },
                            ].map((item) => (
                              <div key={item.status} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                                <div style={{ width: 14, height: 8, borderRadius: 2, background: (phaseColor[item.status] || th.textMuted) + "55", border: `1px solid ${phaseColor[item.status] || th.textMuted}44` }} />
                                {item.label}
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })()}

                    {/* Grouped view */}
                    {rdpViewMode === "grouped" && gSessions.length > 0 ? (
                      <div style={{ maxHeight: 400, overflowY: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                        {gSessions.map((g, gi) => {
                          const ss = statusStyle(g.status);
                          const gTech = g.representativeSession?.technique || g.status;
                          const gts = techStyle(gTech);
                          const gMaxScore = Math.max(0, ...g.sessions.map(s => s.suspicionScore || 0));
                          const gTotalAttempts = g.sessions.reduce((sum, s) => sum + (s.attemptCount || 1), 0);
                          const _groupKey = g.key || `${g.source}|${g.target}|${g.user}`;
                          const isExpanded = expandedGroup === _groupKey;
                          const isFailed = gTech === "RDP Failed Auth" || gTech === "RDP Brute Force";
                          return (
                            <div key={gi}>
                              <div onClick={() => setModal((p) => ({ ...p, expandedGroup: isExpanded ? null : _groupKey }))} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 12px", background: isExpanded ? `${th.accent}08` : "transparent", borderBottom: `1px solid ${th.border}33`, cursor: "pointer", transition: "background var(--m-fast)" }}
                                onMouseEnter={(e) => { if (!isExpanded) e.currentTarget.style.background = th.textMuted + "08"; }}
                                onMouseLeave={(e) => { if (!isExpanded) e.currentTarget.style.background = "transparent"; }}>
                                <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, width: 12, flexShrink: 0 }}>{isExpanded ? "\u25BC" : "\u25B6"}</span>
                                {gMaxScore > 0 && <span style={{ fontSize: LM_TYPOGRAPHY.control, fontWeight: 700, color: gMaxScore >= 30 ? th.sev.critical : gMaxScore >= 15 ? th.sev.high : th.textMuted, minWidth: 20, textAlign: "center", flexShrink: 0 }}>{gMaxScore}</span>}
                                <span style={{ padding: "1px 6px", background: ss.bg, color: ss.color, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{ss.label}</span>
                                <span style={{ padding: "1px 5px", background: gts.bg, color: gts.color, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{gTech}</span>
                                <span style={{ fontSize: LM_TYPOGRAPHY.control, fontFamily: "monospace", color: th.text }}>{g.source || "\u2014"}</span>
                                <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted }}>{"\u2192"}</span>
                                <span style={{ fontSize: LM_TYPOGRAPHY.control, fontFamily: "monospace", color: th.text }}>{g.target || "\u2014"}</span>
                                <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{g.user || "(unknown)"}</span>
                                <span style={{ padding: "1px 6px", background: g.count > 5 ? th.sev.high + "22" : th.textMuted + "18", color: g.count > 5 ? th.sev.high : th.textDim, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, fontWeight: 600, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{isFailed ? `${gTotalAttempts} attempt${gTotalAttempts !== 1 ? "s" : ""}` : `${g.count} session${g.count !== 1 ? "s" : ""}`}</span>
                                <span style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "monospace", marginLeft: "auto" }}>{fmtTs(g.timeRange.from)}{g.timeRange.to && g.timeRange.to !== g.timeRange.from ? ` \u2014 ${fmtTs(g.timeRange.to)}` : ""}</span>
                              </div>
                              {isExpanded && (
                                <div style={{ padding: "4px 12px 8px 32px", background: `${th.accent}04`, borderBottom: `1px solid ${th.border}33` }}>
                                  {g.sessions.map((s, si) => {
                                    const sts = statusStyle(s.status);
                                    const sSc = s.suspicionScore || 0;
                                    return (
                                      <div key={si} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 0", fontSize: LM_TYPOGRAPHY.meta, fontFamily: "monospace", color: th.textDim, borderBottom: si < g.sessions.length - 1 ? `1px solid ${th.border}15` : "none" }}>
                                        {sSc > 0 && <span style={{ fontWeight: 700, fontSize: LM_TYPOGRAPHY.meta, color: sSc >= 30 ? th.sev.critical : sSc >= 15 ? th.sev.high : th.textMuted, minWidth: 16, textAlign: "center" }}>{sSc}</span>}
                                        <span style={{ padding: "0 4px", background: sts.bg, color: sts.color, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600 }}>{sts.label}</span>
                                        <span>{s.source}</span><span style={{ color: th.textMuted }}>{"\u2192"}</span><span>{s.target}</span>
                                        <span style={{ color: th.textMuted }}>{s.user || "(unknown)"}</span>
                                        {(s.attemptCount || 1) > 1 && <span style={{ color: th.sev.high, fontWeight: 600 }}>{s.attemptCount} attempts</span>}
                                        <span style={{ color: th.textMuted }}>{fmtTs(s.startTime)}</span>
                                        {_rdpEnd(s) && <span style={{ color: th.textMuted }}>{"\u2014"} {fmtTs(_rdpEnd(s))}{s.endIsLastSeen ? "*" : ""}</span>}
                                        <span style={{ color: th.textMuted }}>{fmtDur(s.startTime, _rdpEnd(s))}</span>
                                        {s.hasAdmin && <span style={{ padding: "0 3px", background: th.sev.critical + "22", color: th.sev.critical, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700 }}>ADMIN</span>}
                                        {s.isConcurrent && <span style={{ padding: "0 3px", background: th.sev.high + "22", color: th.sev.high, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700 }} title={`Concurrent with ${(s._concurrentTargets || []).join(", ")}`}>CONCURRENT</span>}
                                        <span style={{ padding: "0 3px", background: confStyle(s.confidence) + "18", color: confStyle(s.confidence), borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600 }}>{(s.confidence || "low").toUpperCase()}</span>
                                        {(() => {
                                          const evidence = evidenceStyle(s.evidenceLevel);
                                          return <span title={(s.evidenceBasis || []).join("; ")} style={{ padding: "0 3px", background: evidence.bg, color: evidence.color, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600 }}>{evidence.label}</span>;
                                        })()}
                                        <EvidenceActions item={s} compact />
                                      </div>
                                    );
                                  })}
                                  <div style={{ marginTop: 8 }}>
                                    <EvidenceActions item={g} />
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    ) : rdpViewMode === "timeline" ? null : (
                    // Reached for "individual", and for "grouped" when there is nothing to
                    // group. Previously this was the bare else of a `grouped ? … : …`
                    // ternary, so "timeline" fell through here and rendered the entire
                    // session table underneath the Gantt chart.
                    <div style={{ maxHeight: 400, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                      <table style={{ borderCollapse: "collapse", fontSize: LM_TYPOGRAPHY.body, fontFamily: "monospace", tableLayout: "fixed", width: rdpTotalTableW }}>
                        <thead>
                          <tr>
                            <th style={{ position: "sticky", top: 0, width: 30, background: th.headerBg || th.panelBg, borderBottom: `1px solid ${th.border}`, zIndex: 2, textAlign: "center", padding: "6px 4px" }}>
                              <input type="checkbox" checked={rdpAllChecked} onChange={toggleAllRdp} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                            </th>
                            {rdpHeaders.map((h) => (
                              <th key={h} style={{ position: "sticky", top: 0, width: rdpColWidths[h] || rdpDefWidths[h], minWidth: 40, background: th.headerBg || th.panelBg, color: rdpSortCol === h ? th.text : th.accent, padding: "6px 8px", textAlign: "left", fontSize: LM_TYPOGRAPHY.meta, borderBottom: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", overflow: "hidden", boxSizing: "border-box", userSelect: "none", zIndex: 2 }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
                                  <span onClick={() => toggleRdpSort(h)} style={{ cursor: "pointer", overflow: "hidden", textOverflow: "ellipsis" }}>{h}</span>
                                  {rdpSortCol === h && <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.accent }}>{rdpSortDir === "asc" ? "\u25B2" : "\u25BC"}</span>}
                                  <span onClick={(e) => openRdpFilter(h, e)} style={{ cursor: "pointer", fontSize: LM_TYPOGRAPHY.badge, color: rdpColFilters[h] ? th.accent : th.textMuted + "66", flexShrink: 0, marginLeft: "auto", paddingRight: 8 }}>{"\u25BC"}</span>
                                  <div onMouseDown={(e) => onRdpResizeStart(h, e)} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 6, cursor: "col-resize" }}>
                                    <div style={{ position: "absolute", right: 2, top: 2, bottom: 2, width: 1, background: th.border }} />
                                  </div>
                                </div>
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {sortedSessions.map((s, i) => {
                            const st = statusStyle(s.status);
                            const ts0 = techStyle(s.technique || "RDP");
                            const dur = fmtDur(s.startTime, _rdpEnd(s));
                            const durMs = rdpDurMs(s);
                            const expanded = expandedIdx === s.id;
                            const sc = s.suspicionScore || 0;
                            const att = s.attemptCount || 1;
                            return (
                              <Fragment key={i}>
                                <tr onClick={() => setModal((p) => ({ ...p, expandedSession: expanded ? null : s.id }))}
                                  style={{ background: isRdpChecked(s) ? `${th.accent}0a` : i % 2 === 0 ? "transparent" : (th.rowAlt || th.panelBg + "44"), cursor: "pointer" }}>
                                  <td style={{ padding: "4px 4px", textAlign: "center" }}>
                                    <input type="checkbox" checked={isRdpChecked(s)} onChange={(ev) => toggleRdpCheck(s, ev)} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                  </td>
                                  {/* Score */}
                                  <td style={{ padding: "4px 8px", textAlign: "center", fontWeight: 700, fontSize: LM_TYPOGRAPHY.body, color: sc >= 30 ? th.sev.critical : sc >= 15 ? th.sev.high : th.textMuted }}>{sc}</td>
                                  {/* Status */}
                                  <td style={{ padding: "4px 8px" }}>
                                    <span style={{ padding: "2px 7px", background: st.bg, color: st.color, borderRadius: 4, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>{st.label}</span>
                                  </td>
                                  {/* Technique */}
                                  <td style={{ padding: "4px 8px" }}>
                                    <span style={{ padding: "2px 6px", background: ts0.bg, color: ts0.color, borderRadius: 4, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap" }}>{s.technique || "RDP"}</span>
                                    {s.isConcurrent && <span style={{ padding: "1px 4px", background: th.sev.high + "22", color: th.sev.high, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, fontFamily: "-apple-system, sans-serif", marginLeft: 3 }} title={`Concurrent with session on ${(s._concurrentTargets || []).join(", ")}`}>CONCURRENT</span>}
                                  </td>
                                  <td style={{ padding: "4px 8px", color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.source || "\u2014"}</td>
                                  <td style={{ padding: "4px 8px", color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.target || "\u2014"}</td>
                                  <td style={{ padding: "4px 8px", color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.user || "(unknown)"}</td>
                                  {/* Confidence */}
                                  <td style={{ padding: "4px 8px", textAlign: "center" }}>
                                    <span style={{ fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, fontFamily: "-apple-system, sans-serif", color: confStyle(s.confidence) }}>{(s.confidence || "low").toUpperCase()}</span>
                                  </td>
                                  {/* Evidence classification */}
                                  <td style={{ padding: "4px 8px", textAlign: "center" }}>
                                    {(() => {
                                      const evidence = evidenceStyle(s.evidenceLevel);
                                      return <span title={(s.evidenceBasis || []).join("; ")} style={{ padding: "1px 5px", background: evidence.bg, color: evidence.color, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>{evidence.label}</span>;
                                    })()}
                                  </td>
                                  {/* Attempts */}
                                  <td style={{ padding: "4px 8px", textAlign: "center", fontWeight: att > 1 ? 600 : 400, color: att > 5 ? th.sev.critical : att > 1 ? th.sev.high : th.textDim }}>{att}</td>
                                  <td style={{ padding: "4px 8px", color: th.textDim, whiteSpace: "nowrap" }}>{fmtTs(s.startTime)}</td>
                                  <td style={{ padding: "4px 8px", color: th.textDim, whiteSpace: "nowrap" }} title={s.endIsLastSeen ? "Last seen event (no logoff captured)" : ""}>{fmtTs(_rdpEnd(s))}{s.endIsLastSeen ? <span style={{ color: th.textMuted, marginLeft: 3 }}>*</span> : ""}</td>
                                  <td style={{ padding: "4px 8px", whiteSpace: "nowrap", color: durMs >= 86400000 ? (th.danger) : durMs >= 3600000 ? th.sev.high : th.textDim, fontWeight: durMs >= 86400000 ? 600 : 400 }}>{dur}</td>
                                  {/* Why Flagged */}
                                  <td style={{ padding: "4px 6px" }}>
                                    <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                                      {(s.flags || []).slice(0, 4).map((f, fi) => (
                                        <span key={fi} style={{ padding: "1px 5px", background: f.startsWith("Finding:") ? th.sev.critical + "12" : th.textMuted + "18", color: f.startsWith("Finding:") ? th.sev.critical : th.textDim, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap" }}>{f}</span>
                                      ))}
                                      {(s.flags || []).length > 4 && <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted }}>+{s.flags.length - 4}</span>}
                                    </div>
                                  </td>
                                </tr>
                                {expanded && (
                                  <tr>
                                    <td colSpan={rdpHeaders.length + 1} style={{ padding: "0 12px 10px 48px", borderTop: `1px solid ${th.border}22`, background: `${st.color}04` }}>
                                      <div style={{ display: "flex", gap: 24, marginTop: 8 }}>
                                        {/* Left: Event timeline */}
                                        <div style={{ flex: 1, position: "relative", paddingLeft: 18, minWidth: 0 }}>
                                          <div style={{ position: "absolute", left: 4, top: 2, bottom: 2, width: 1, background: `${st.color}44` }} />
                                          {(s.events || []).map((evt, ei) => {
                                            const dotColor = evt.eventId === "4625" ? th.sev.critical : evt.eventId === "4672" ? th.sev.high : evt.eventId === "4624" ? th.sev.info : ["21","22","25","1149"].includes(evt.eventId) ? th.sev.clean : ["23","4634","4647"].includes(evt.eventId) ? th.textMuted : ["24","39","40","4779"].includes(evt.eventId) ? th.sev.med : st.color;
                                            return (
                                              <div key={ei} style={{ position: "relative", paddingLeft: 18, paddingBottom: 6, fontSize: LM_TYPOGRAPHY.control, display: "flex", alignItems: "center", gap: 8 }}>
                                                <div style={{ position: "absolute", left: 0, top: 4, width: 9, height: 9, borderRadius: "50%", background: dotColor, border: `2px solid ${th.panelBg}`, boxShadow: `0 0 0 1px ${dotColor}44` }} />
                                                <span style={{ padding: "1px 5px", background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "monospace", color: th.accent, minWidth: 32, textAlign: "center", fontWeight: 600 }}>{evt.eventId}</span>
                                                <span style={{ color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{evt.description}</span>
                                                <span style={{ marginLeft: "auto", color: th.textMuted, fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.meta }}>{evt.ts?.slice(11, 23) || ""}</span>
                                              </div>
                                            );
                                          })}
                                        </div>
                                        {/* Right: Session details */}
                                        <div style={{ width: 220, flexShrink: 0, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "-apple-system, sans-serif", color: th.textDim }}>
                                          <div style={{ marginBottom: 8 }}>
                                            <div style={{ fontWeight: 600, color: th.text, marginBottom: 4, fontSize: LM_TYPOGRAPHY.control }}>Session Details</div>
                                            <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 80 }}>Session ID</span><span>{s.sessionId || "\u2014"}</span></div>
                                            <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 80 }}>Events</span><span style={{ fontWeight: 600 }}>{(s.events || []).length}</span></div>
                                            <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 80 }}>Confidence</span><span style={{ color: confStyle(s.confidence), fontWeight: 600 }}>{(s.confidence || "low").toUpperCase()}</span></div>
                                            <div style={{ display: "flex", gap: 4, marginBottom: 2 }}>
                                              <span style={{ color: th.textMuted, width: 80 }}>Evidence</span>
                                              <span style={{ color: evidenceStyle(s.evidenceLevel).color, fontWeight: 600 }}>{evidenceStyle(s.evidenceLevel).label}</span>
                                            </div>
                                            {(s.evidenceBasis || []).map((basis, bi) => (
                                              <div key={bi} style={{ margin: "2px 0 2px 84px", color: th.textMuted, lineHeight: 1.3, overflowWrap: "anywhere" }}>{basis}</div>
                                            ))}
                                            {(s.mergedReconnects || 0) > 0 && <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 80 }}>Reconnects</span><span>{s.mergedReconnects} merged</span></div>}
                                            {(s.attemptCount || 1) > 1 && <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 80 }}>Attempts</span><span style={{ color: th.sev.high, fontWeight: 600 }}>{s.attemptCount}</span></div>}
                                          </div>
                                          {/* Expected events checklist */}
                                          {s.status !== "failed" && (() => {
                                            const eids = new Set((s.events || []).map(e => e.eventId));
                                            const checks = [
                                              { label: "1149", present: eids.has("1149") },
                                              { label: "4624", present: eids.has("4624") },
                                              { label: "21/22", present: eids.has("21") || eids.has("22") },
                                              { label: "4672", present: eids.has("4672") },
                                            ];
                                            return (
                                              <div style={{ marginBottom: 8 }}>
                                                <div style={{ fontWeight: 600, color: th.text, marginBottom: 4, fontSize: LM_TYPOGRAPHY.control }}>Telemetry Completeness</div>
                                                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                                                  {checks.map((c, ci) => (
                                                    <span key={ci} style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "1px 5px", borderRadius: 3, background: c.present ? th.sev.clean + "12" : th.textMuted + "12", fontSize: LM_TYPOGRAPHY.badge }}>
                                                      <span style={{ color: c.present ? th.sev.clean : th.textMuted }}>{c.present ? "\u2713" : "\u2014"}</span>
                                                      <span style={{ color: c.present ? th.textDim : th.textMuted }}>{c.label}</span>
                                                    </span>
                                                  ))}
                                                </div>
                                              </div>
                                            );
                                          })()}
                                          {/* Flags */}
                                          {(s.flags || []).length > 0 && (
                                            <div>
                                              <div style={{ fontWeight: 600, color: th.text, marginBottom: 4, fontSize: LM_TYPOGRAPHY.control }}>Why Flagged</div>
                                              <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                                                {s.flags.map((f, fi) => (
                                                  <span key={fi} style={{ padding: "1px 5px", background: f.startsWith("Finding:") ? th.sev.critical + "12" : th.textMuted + "12", color: f.startsWith("Finding:") ? th.sev.critical : th.textDim, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, whiteSpace: "nowrap" }}>{f}</span>
                                                ))}
                                              </div>
                                            </div>
                                          )}
                                          {/* Pivot actions — match Findings tab capabilities */}
                                          <div style={{ marginTop: 8, display: "flex", gap: 4, flexWrap: "wrap" }}>
                                            <button onClick={(ev) => _filterEvents({
                                              category: "Concurrent RDP Sessions",
                                              filterEids: [...new Set((s.events || []).map(e => e.eventId))],
                                              filterHosts: [s.source, s.target].filter(Boolean),
                                              timeRange: s.startTime ? { from: s.startTime, to: _rdpEnd(s) || s.startTime } : null,
                                              // Carry the refs so the pivot can land on the exact rows
                                              // (and the right tab in a multi-source run).
                                              evidenceRefs: s.evidenceRefs, itemRowids: s.itemRowids,
                                            }, ev)} style={{ padding: "2px 8px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 600, display: "flex", alignItems: "center", gap: 4 }}>
                                              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2.5" strokeLinecap="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                                              Show in Timeline
                                            </button>
                                            <button onClick={(ev) => _viewInGraph({ source: s.source, target: s.target }, ev)} style={{ padding: "2px 8px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, fontSize: LM_TYPOGRAPHY.meta, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>
                                              View in Graph
                                            </button>
                                            <EvidenceActions item={s} />
                                          </div>
                                        </div>
                                      </div>
                                    </td>
                                  </tr>
                                )}
                              </Fragment>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    )}
                    {/* RDP Column filter dropdown popup */}
                    {rdpFilterOpen && (
                      <>
                        <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, rdpFilterOpen: null }))} />
                        <div style={{ position: "fixed", left: modal.rdpFilterX ?? Math.min(rdpFilterPos.x || 0, window.innerWidth - 340), top: modal.rdpFilterY ?? Math.min(rdpFilterPos.y || 0, window.innerHeight - 440), width: modal.rdpFilterW || 320, height: modal.rdpFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                          <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                            onMouseDown={(e) => {
                              e.preventDefault();
                              const startX = e.clientX, startY = e.clientY;
                              const startLeft = modal.rdpFilterX ?? Math.min(rdpFilterPos.x || 0, window.innerWidth - 340);
                              const startTop = modal.rdpFilterY ?? Math.min(rdpFilterPos.y || 0, window.innerHeight - 440);
                              document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                              const onMove = (ev) => setModal((p) => ({ ...p, rdpFilterX: startLeft + ev.clientX - startX, rdpFilterY: startTop + ev.clientY - startY }));
                              const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                              window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                            }}>
                            <span style={{ fontSize: LM_TYPOGRAPHY.body, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER {"\u2014"} {rdpFilterOpen.toUpperCase()}</span>
                            <span style={{ cursor: "pointer", color: th.textMuted, fontSize: LM_TYPOGRAPHY.heading, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, rdpFilterOpen: null }))}>{"\u00D7"}</span>
                          </div>
                          <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                            <input type="text" placeholder="Search values..." value={rdpFilterSearch} onChange={(e) => setModal((p) => ({ ...p, rdpFilterSearch: e.target.value }))}
                              style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: LM_TYPOGRAPHY.body, background: th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                              autoFocus />
                          </div>
                          <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                            <button onClick={() => setModal((p) => ({ ...p, rdpFilterSel: new Set(rdpFilterVals) }))} style={{ padding: "2px 8px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                            <button onClick={() => setModal((p) => ({ ...p, rdpFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                            <span style={{ marginLeft: "auto", fontSize: LM_TYPOGRAPHY.control, color: th.textMuted }}>{rdpFilterVals.length} values</span>
                          </div>
                          <div style={{ flex: 1, overflow: "auto", padding: "0 6px", minHeight: 0 }}>
                            {rdpDisplayVals.slice(0, 1000).map((v) => (
                              <div key={v} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", borderRadius: 3, cursor: "pointer" }}
                                onClick={() => setModal((p) => { const set = new Set(p.rdpFilterSel || []); set.has(v) ? set.delete(v) : set.add(v); return { ...p, rdpFilterSel: set }; })}
                                onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}0a`}
                                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                                <input type="checkbox" checked={rdpFilterSel.has(v)} readOnly style={{ width: 13, height: 13, accentColor: th.accent, cursor: "pointer", flexShrink: 0 }} />
                                <span style={{ fontSize: LM_TYPOGRAPHY.body, color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "SF Mono, Menlo, monospace" }}>{v || "(empty)"}</span>
                                <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, flexShrink: 0 }}>{rdpFilterCounts[v]}</span>
                              </div>
                            ))}
                          </div>
                          <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                            <button onClick={() => setModal((p) => { const cf = { ...(p.rdpColFilters || {}) }; delete cf[rdpFilterOpen]; return { ...p, rdpColFilters: cf, rdpFilterOpen: null }; })}
                              style={{ padding: "4px 12px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Reset</button>
                            <button onClick={() => setModal((p) => ({ ...p, rdpFilterOpen: null }))}
                              style={{ padding: "4px 12px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Cancel</button>
                            <button onClick={() => setModal((p) => ({ ...p, rdpColFilters: { ...(p.rdpColFilters || {}), [rdpFilterOpen]: [...(p.rdpFilterSel || [])] }, rdpFilterOpen: null }))}
                              style={{ padding: "4px 12px", fontSize: LM_TYPOGRAPHY.control, background: th.accent, border: "none", borderRadius: 4, color: "#fff", cursor: "pointer", fontWeight: 600 }}>Apply</button>
                          </div>
                          <div onMouseDown={(e) => {
                            e.preventDefault(); e.stopPropagation();
                            const startX = e.clientX, startY = e.clientY, startW = modal.rdpFilterW || 320, startH = modal.rdpFilterH || 420;
                            document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                            const onMove = (ev) => setModal((p) => ({ ...p, rdpFilterW: Math.max(240, startW + ev.clientX - startX), rdpFilterH: Math.max(250, startH + ev.clientY - startY) }));
                            const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                            window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                          }} style={{ position: "absolute", bottom: 0, right: 0, width: 14, height: 14, cursor: "nwse-resize" }}>
                            <svg width="10" height="10" viewBox="0 0 10 10" style={{ position: "absolute", bottom: 2, right: 2 }}>
                              <path d="M8 2L2 8M8 5L5 8M8 8L8 8" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" />
                            </svg>
                          </div>
                        </div>
                      </>
                    )}
                  </div>
                );
              })()}

              {/* Accounts tab — per-user aggregation with suspicion score, classification, and flags */}
              {viewTab === "accounts" && (() => {
                const accounts = data.accounts || [];
                const acctSortCol = modal.acctSortCol || "Score";
                const acctSortDir = modal.acctSortDir || "desc";

                // Headers + default widths follow the Connections table convention so the
                // tab feels consistent. "Class" pills are colored by classification:
                // privileged > admin > machine > service > user.
                const acctHeaders = ["Score", "User", "Class", "Successes", "Failures", "Sources", "Targets", "Admin", "Kerb", "NTLM", "Explicit", "First Seen", "Last Seen", "Why Suspicious"];
                const acctDefWidths = { Score: 48, User: 160, Class: 90, Successes: 70, Failures: 65, Sources: 65, Targets: 65, Admin: 55, Kerb: 55, NTLM: 55, Explicit: 65, "First Seen": 145, "Last Seen": 145, "Why Suspicious": 200 };
                const acctColWidths = modal.acctColWidths || acctDefWidths;
                // The privilege/credential columns show counts SCOPED to lateral movement
                // (events that survived the exclusion filters), not host-wide totals.
                // Hover a cell to see the raw host-wide count when it differs.
                const acctHeaderTips = {
                  Successes: "Successful logons (4624), lateral-movement-scoped", Failures: "Failed logons (4625), lateral-movement-scoped",
                  Sources: "Distinct source hosts across logon + explicit-cred (4648) + RDP — can exceed Successes+Failures. Hover a cell for the breakdown.",
                  Targets: "Distinct target hosts across logon + explicit-cred (4648) + RDP. Hover a cell for the breakdown.",
                  "First Seen": "First lateral-movement activity (logon / explicit-cred / RDP). Blank = no scoped activity (e.g. Kerberos/NTLM-only on a DC).",
                  "Last Seen": "Last lateral-movement activity (logon / explicit-cred / RDP). Blank = no scoped activity (e.g. Kerberos/NTLM-only on a DC).",
                  Admin: "Admin privilege (4672) — lateral-movement-scoped. Hover a cell for the host-wide total.",
                  Kerb: "Kerberos (4768/4769/4771) — lateral-movement-scoped. Hover a cell for the host-wide total.",
                  NTLM: "NTLM (4776) — lateral-movement-scoped. Hover a cell for the host-wide total.",
                  Explicit: "Explicit credentials (4648) — lateral-movement-scoped. Hover a cell for the host-wide total.",
                };

                const _classify = (a) => {
                  // Machine ($) and well-known service accounts take precedence and are
                  // NEVER promoted to ADMIN — 4672 fires for SYSTEM/service/machine logons,
                  // so privilege alone must not relabel them.
                  if (a.isMachineAccount) return { label: "MACHINE", color: th.sev.low };
                  if (a.isServiceAccount) return { label: "SERVICE", color: th.sev.custom };
                  if (a.isPrivilegedName) return { label: "PRIV", color: th.sev.critical };
                  // ADMIN requires a SCOPED admin signal: a 4672 that survived the
                  // lateral-movement exclusion filters (adminPrivilegeCount, not *Raw),
                  // or an RDP session correlated to admin privileges. Host-wide local
                  // 4672 no longer promotes ordinary/built-in accounts to ADMIN.
                  if (a.adminPrivilegeCount > 0 || a.rdpAdminCount > 0) return { label: "ADMIN", color: th.sev.high };
                  return { label: "USER", color: th.sev.clean };
                };

                const acctSortKey = (a, col) => {
                  if (col === "Score") return a.suspicionScore || 0;
                  if (col === "User") return (a.user || "").toLowerCase();
                  if (col === "Class") return _classify(a).label;
                  if (col === "Successes") return a.successCount || 0;
                  if (col === "Failures") return a.failureCount || 0;
                  if (col === "Sources") return (a.sourceHosts || []).length;
                  if (col === "Targets") return (a.targetHosts || []).length;
                  if (col === "Admin") return a.adminPrivilegeCount || 0;
                  if (col === "Kerb") return a.kerberosCount || 0;
                  if (col === "NTLM") return a.ntlmCount || 0;
                  if (col === "Explicit") return a.explicitCredsCount || 0;
                  if (col === "First Seen") return a.firstSeen || "";
                  if (col === "Last Seen") return a.lastSeen || "";
                  if (col === "Why Suspicious") return (a.flags || []).length;
                  return "";
                };

                const acctCellVal = (a, h) => {
                  if (h === "Score") return String(a.suspicionScore || 0);
                  if (h === "User") return a.user || "";
                  if (h === "Class") return _classify(a).label;
                  if (h === "Successes") return String(a.successCount || 0);
                  if (h === "Failures") return String(a.failureCount || 0);
                  if (h === "Sources") return String((a.sourceHosts || []).length);
                  if (h === "Targets") return String((a.targetHosts || []).length);
                  if (h === "Admin") return String(a.adminPrivilegeCount || 0);
                  if (h === "Kerb") return String(a.kerberosCount || 0);
                  if (h === "NTLM") return String(a.ntlmCount || 0);
                  if (h === "Explicit") return String(a.explicitCredsCount || 0);
                  if (h === "First Seen") return fmtTs(a.firstSeen) || "";
                  if (h === "Last Seen") return fmtTs(a.lastSeen) || "";
                  if (h === "Why Suspicious") return (a.flags || []).join("; ");
                  return "";
                };

                const sortedAccts = [...accounts].sort((a, b) => {
                  const av = acctSortKey(a, acctSortCol), bv = acctSortKey(b, acctSortCol);
                  const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                  return acctSortDir === "asc" ? cmp : -cmp;
                });

                const toggleAcctSort = (col) => setModal((p) => ({
                  ...p,
                  acctSortCol: col,
                  acctSortDir: p.acctSortCol === col && p.acctSortDir === "asc" ? "desc" : "asc",
                }));

                const copyAccts = () => {
                  const headerLine = acctHeaders.join("\t");
                  const lines = sortedAccts.map((a) => acctHeaders.map((h) => acctCellVal(a, h)).join("\t"));
                  navigator.clipboard?.writeText?.([headerLine, ...lines].join("\n"));
                };

                // Score chip color
                const scoreColor = (s) => {
                  if (s >= 50) return th.sev.critical; // critical
                  if (s >= 25) return th.sev.high; // high
                  if (s >= 10) return th.sev.med; // medium
                  return th.textMuted;
                };

                if (accounts.length === 0) {
                  return (
                    <div style={{ padding: "40px 20px", textAlign: "center", color: th.textMuted, fontFamily: "-apple-system, sans-serif", fontSize: LM_TYPOGRAPHY.title }}>
                      No accounts extracted from this dataset. Check the Telemetry Coverage panel above for which event categories are present.
                    </div>
                  );
                }

                return (
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                      <span style={{ fontSize: LM_TYPOGRAPHY.body, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>
                        {sortedAccts.length} account{sortedAccts.length !== 1 ? "s" : ""}
                      </span>
                      <button onClick={copyAccts} style={{ padding: "4px 10px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, fontSize: LM_TYPOGRAPHY.control, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>
                        Copy All ({sortedAccts.length})
                      </button>
                    </div>
                    <div style={{ border: `1px solid ${th.border}44`, borderRadius: 6, overflow: "hidden", background: th.panelBg }}>
                      {/* Header row */}
                      <div style={{ display: "flex", background: `${th.headerBg}88`, borderBottom: `1px solid ${th.border}44`, fontSize: LM_TYPOGRAPHY.control, fontWeight: 600, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
                        {acctHeaders.map((h) => (
                          <div key={h} onClick={() => toggleAcctSort(h)}
                            style={{ width: acctColWidths[h] || 80, padding: "8px 10px", cursor: "pointer", display: "flex", alignItems: "center", gap: 4, userSelect: "none", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                            title={acctHeaderTips[h] || h}>
                            {h}
                            {acctSortCol === h && <span style={{ fontSize: LM_TYPOGRAPHY.meta, opacity: 0.7 }}>{acctSortDir === "asc" ? "▲" : "▼"}</span>}
                          </div>
                        ))}
                        <div style={{ padding: "8px 10px", flexShrink: 0, fontSize: LM_TYPOGRAPHY.control, color: th.textMuted }}>Actions</div>
                      </div>
                      {/* Body rows */}
                      <div style={{ maxHeight: 480, overflowY: "auto" }}>
                        {sortedAccts.map((a, idx) => {
                          const cls = _classify(a);
                          return (
                            <div key={a.user + "_" + idx}
                              style={{ display: "flex", borderBottom: idx < sortedAccts.length - 1 ? `1px solid ${th.border}22` : "none", fontSize: LM_TYPOGRAPHY.body, color: th.text, fontFamily: "-apple-system, sans-serif", alignItems: "center", minHeight: 32 }}>
                              {acctHeaders.map((h) => {
                                const val = acctCellVal(a, h);
                                let cell;
                                if (h === "Score") {
                                  const sc = a.suspicionScore || 0;
                                  cell = <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.control, color: scoreColor(sc), background: scoreColor(sc) + "18", padding: "1px 6px", borderRadius: 3, fontWeight: 700 }}>{sc}</span>;
                                } else if (h === "Class") {
                                  cell = <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.badge, color: cls.color, background: cls.color + "18", border: `1px solid ${cls.color}33`, padding: "1px 5px", borderRadius: 3, fontWeight: 600 }}>{cls.label}</span>;
                                } else if (h === "User") {
                                  cell = <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.body, color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{val || "(unknown)"}</span>;
                                } else if (h === "Why Suspicious") {
                                  const flags = a.flags || [];
                                  cell = (
                                    <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                                      {flags.slice(0, 4).map((f, i) => (
                                        <span key={i} style={{ fontSize: LM_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${th.textMuted}15`, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{f}</span>
                                      ))}
                                      {flags.length > 4 && <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted }}>+{flags.length - 4}</span>}
                                    </div>
                                  );
                                } else if (h === "First Seen" || h === "Last Seen") {
                                  cell = <span style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.control, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{val}</span>;
                                } else {
                                  const isZero = val === "0" || val === "";
                                  const n = Number(val) || 0;
                                  // Admin/Kerb/NTLM/Explicit show the lateral-movement-SCOPED
                                  // count. When the host-wide raw total is higher, surface it
                                  // on hover so the two populations are never conflated.
                                  const rawMap = { Admin: a.adminPrivilegeCountRaw, Kerb: a.kerberosCountRaw, NTLM: a.ntlmCountRaw, Explicit: a.explicitCredsCountRaw };
                                  const raw = rawMap[h];
                                  // Sources/Targets aggregate distinct hosts across channels,
                                  // so they can exceed Successes+Failures. Explain the mix on hover.
                                  const bd = h === "Sources" ? a.sourceBreakdown : h === "Targets" ? a.targetBreakdown : null;
                                  let tip;
                                  if (bd) {
                                    const parts = [];
                                    if (bd.logon) parts.push(`${bd.logon} logon`);
                                    if (bd.explicit) parts.push(`${bd.explicit} explicit-cred (4648)`);
                                    if (bd.rdp) parts.push(`${bd.rdp} RDP`);
                                    if (bd.other) parts.push(`${bd.other} other (NTLM/share)`);
                                    if (parts.length > 1) tip = `${n} distinct hosts — ${parts.join(" · ")}`;
                                  } else if (raw != null && raw > n) {
                                    tip = `${n} lateral-movement-scoped • ${raw} host-wide (all logon types, incl. local/service)`;
                                  }
                                  cell = <span title={tip} style={{ fontFamily: "monospace", fontSize: LM_TYPOGRAPHY.control, color: isZero ? th.textMuted : th.text, opacity: isZero ? 0.4 : 1, cursor: tip ? "help" : undefined, textDecoration: tip ? "underline dotted" : undefined, textDecorationColor: tip ? th.textMuted : undefined }}>{val || "0"}</span>;
                                }
                                return (
                                  <div key={h} style={{ width: acctColWidths[h] || 80, padding: "6px 10px", flexShrink: 0, overflow: "hidden" }}>
                                    {cell}
                                  </div>
                                );
                              })}
                              {/* Pivot actions */}
                              <div style={{ display: "flex", gap: 3, padding: "4px 8px", flexShrink: 0, alignItems: "center" }}>
                                {(a.findingIds || []).length > 0 && (
                                  <button onClick={(ev) => { ev.stopPropagation(); setModal((p) => ({ ...p, viewTab: "findings", findingsView: "alerts" })); }}
                                    style={{ padding: "2px 6px", background: th.sev.critical + "15", color: th.sev.critical, border: `1px solid ${th.sev.critical}33`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 600, whiteSpace: "nowrap" }}
                                    title={`${a.findingIds.length} finding(s) involving ${a.user}`}>
                                    Findings ({a.findingIds.length})
                                  </button>
                                )}
                                <button onClick={(ev) => {
                                  const lmCols = data?.columns || {};
                                  const cbf = { ...(ct?.checkboxFilters || {}) };
                                  if (lmCols.user) cbf[lmCols.user] = [a.user];
                                  if (lmCols.eventId) cbf[lmCols.eventId] = ["4624", "4625", "4648", "4768", "4769", "4776"];
                                  up("checkboxFilters", cbf);
                                  if (lmCols.ts && a.firstSeen) {
                                    up("dateRangeFilters", { [lmCols.ts]: { from: _padTs(a.firstSeen, -300000), to: _padTs(a.lastSeen || a.firstSeen, 300000) } });
                                  }
                                  up("searchTerm", ""); up("columnFilters", {});
                                  setModal(null);
                                }} style={{ padding: "2px 6px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 600, whiteSpace: "nowrap", display: "flex", alignItems: "center", gap: 3 }}
                                  title="Close modal and filter main timeline to logon events for this user">
                                  <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2.5" strokeLinecap="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                                  Timeline
                                </button>
                                <button onClick={(ev) => {
                                  ev.stopPropagation();
                                  // Find all edges that involve this user and select the first one in graph
                                  const userEdge = data?.edges?.find(e => (e.users || []).some(u => u.toUpperCase() === (a.user || "").toUpperCase()));
                                  if (userEdge) _viewInGraph({ source: userEdge.source, target: userEdge.target }, ev);
                                  else setModal((p) => ({ ...p, viewTab: "graph" }));
                                }} style={{ padding: "2px 6px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500, whiteSpace: "nowrap" }}
                                  title="Switch to Graph view and highlight edges involving this user">
                                  Graph
                                </button>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Connections table tab */}
              {viewTab === "table" && (() => {
                const lmHeaders = ["Score", "Source", "Target", "Technique", "Users", "Count", "First Seen", "Last Seen", "Observed Span", "Why Suspicious"];
                const lmDefWidths = { Score: 48, Source: 140, Target: 140, Technique: 120, Users: 160, Count: 55, "First Seen": 145, "Last Seen": 145, "Observed Span": 90, "Why Suspicious": 200 };
                const lmColWidths = modal.colWidths || lmDefWidths;
                const lmSortCol = modal.tableSortCol || "Score";
                const lmSortDir = modal.tableSortDir || "desc";

                const durationMs = (e) => {
                  if (!e.firstSeen || !e.lastSeen) return 0;
                  const a = new Date(e.firstSeen), b = new Date(e.lastSeen);
                  return isNaN(a) || isNaN(b) ? 0 : Math.max(0, b - a);
                };
                const formatDuration = (ms) => {
                  if (ms <= 0) return "\u2014";
                  const s = Math.floor(ms / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
                  const rh = h % 24, rm = m % 60;
                  if (d > 0 && rh > 0) return `${d}d ${rh}h`;
                  if (d > 0) return `${d}d`;
                  if (h > 0 && rm > 0) return `${h}h ${rm}m`;
                  if (h > 0) return `${h}h`;
                  if (m > 0) return `${m}m`;
                  return `${s}s`;
                };

                const lmTechColor = (tech) => {
                  if (!tech) return { bg: `${th.textMuted}15`, color: th.textMuted };
                  if (tech.includes("Cleartext") || tech.includes("PsExec") || tech.includes("Impacket")) return { bg: th.sev.critical + "22", color: th.sev.critical };
                  if (tech.includes("Service Exec")) return { bg: th.sev.critical + "22", color: th.sev.critical };
                  if (tech.includes("Admin Share")) return { bg: th.sev.high + "22", color: th.sev.high };
                  if (tech.includes("RDP")) return { bg: th.sev.info + "18", color: th.sev.info };
                  if (tech.includes("Interactive")) return { bg: th.sev.clean + "18", color: th.sev.clean };
                  if (tech.includes("Scheduled Task") || tech.includes("WMI") || tech.includes("WinRM")) return { bg: th.sev.high + "22", color: th.sev.high };
                  return { bg: `${th.textMuted}15`, color: th.textMuted };
                };

                const lmSortKey = (e, col) => {
                  if (col === "Score") return e.riskScore || 0;
                  if (col === "Count") return e.count;
                  if (col === "Source") return e.source;
                  if (col === "Target") return e.target;
                  if (col === "Technique") return e.technique || "";
                  if (col === "Users") return e.users.join(", ");
                  if (col === "First Seen") return e.firstSeen || "";
                  if (col === "Last Seen") return e.lastSeen || "";
                  if (col === "Observed Span") return durationMs(e);
                  if (col === "Why Suspicious") return (e.flags || []).length;
                  return "";
                };

                const lmCellVal = (e, h) => {
                  if (h === "Score") return String(e.riskScore || 0);
                  if (h === "Source") return e.source;
                  if (h === "Target") return e.target;
                  if (h === "Technique") { const ot = (e.otherTechniques || []); return (e.technique || "Unknown") + (ot.length > 0 ? ` (+${ot.join(", ")})` : ""); }
                  if (h === "Count") return String(e.count);
                  if (h === "Users") return e.users.join(", ");
                  if (h === "First Seen") return fmtTs(e.firstSeen) || "";
                  if (h === "Last Seen") return fmtTs(e.lastSeen) || "";
                  if (h === "Observed Span") return formatDuration(durationMs(e));
                  if (h === "Why Suspicious") return (e.flags || []).join("; ");
                  return "";
                };

                // Column filters
                const lmColFilters = modal.lmColFilters || {};
                const filteredEdges = data.edges.filter((e) => {
                  for (const [col, allowed] of Object.entries(lmColFilters)) {
                    if (!allowed || allowed.length === 0) continue;
                    const val = lmCellVal(e, col);
                    if (!allowed.includes(val)) return false;
                  }
                  return true;
                });

                const sortedEdges = [...filteredEdges].sort((a, b) => {
                  const av = lmSortKey(a, lmSortCol), bv = lmSortKey(b, lmSortCol);
                  const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                  return lmSortDir === "asc" ? cmp : -cmp;
                });
                const toggleSort = (col) => {
                  setModal((p) => ({
                    ...p,
                    tableSortCol: col,
                    tableSortDir: p.tableSortCol === col && p.tableSortDir === "asc" ? "desc" : "asc",
                  }));
                };

                // Checkbox state
                const lmChecked = modal.lmCheckedRows || new Set();
                const rowKey = (e) => `${e.source}|${e.target}|${e.firstSeen}`;
                const isLmChecked = (e) => lmChecked.has(rowKey(e));
                const toggleLmCheck = (e, ev) => {
                  ev.stopPropagation();
                  const k = rowKey(e);
                  setModal((p) => {
                    const s = new Set(p.lmCheckedRows || []);
                    s.has(k) ? s.delete(k) : s.add(k);
                    return { ...p, lmCheckedRows: s };
                  });
                };
                const allChecked = sortedEdges.length > 0 && sortedEdges.every((e) => isLmChecked(e));
                const toggleAllLm = (ev) => {
                  ev.stopPropagation();
                  setModal((p) => {
                    if (allChecked) return { ...p, lmCheckedRows: new Set() };
                    return { ...p, lmCheckedRows: new Set(sortedEdges.map(rowKey)) };
                  });
                };
                const checkedCount = sortedEdges.filter((e) => isLmChecked(e)).length;

                // Copy (selected or all)
                const copyAll = () => {
                  const headerLine = lmHeaders.join("\t");
                  const selected = sortedEdges.filter((e) => isLmChecked(e));
                  const toCopy = selected.length > 0 ? selected : sortedEdges;
                  const lines = toCopy.map((e) => lmHeaders.map((h) => lmCellVal(e, h)).join("\t"));
                  navigator.clipboard?.writeText?.([headerLine, ...lines].join("\n"));
                };

                // Resize
                const onResizeStart = (colName, e) => {
                  e.preventDefault(); e.stopPropagation();
                  const startX = e.clientX;
                  const startW = lmColWidths[colName] || lmDefWidths[colName];
                  document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                  const move = (ev) => {
                    const newW = Math.max(40, startW + ev.clientX - startX);
                    setModal((p) => ({ ...p, colWidths: { ...(p.colWidths || lmDefWidths), [colName]: newW } }));
                  };
                  const up = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); };
                  document.addEventListener("mousemove", move);
                  document.addEventListener("mouseup", up);
                };

                // Column filter dropdown
                const openLmFilter = (colName, e) => {
                  e.stopPropagation();
                  const rect = e.currentTarget.getBoundingClientRect();
                  const counts = {};
                  for (const edge of data.edges) { const v = lmCellVal(edge, colName); counts[v] = (counts[v] || 0) + 1; }
                  const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
                  const current = lmColFilters[colName];
                  const selected = new Set(current && current.length > 0 ? current : allVals);
                  setModal((p) => ({ ...p, lmFilterOpen: colName, lmFilterPos: { x: rect.left, y: rect.bottom + 2 }, lmFilterVals: allVals, lmFilterCounts: counts, lmFilterSel: selected, lmFilterSearch: "", lmFilterX: null, lmFilterY: null }));
                };
                const filterOpen = modal.lmFilterOpen;
                const filterPos = modal.lmFilterPos || {};
                const filterVals = modal.lmFilterVals || [];
                const filterCounts = modal.lmFilterCounts || {};
                const filterSel = modal.lmFilterSel || new Set();
                const filterSearch = modal.lmFilterSearch || "";
                const displayVals = filterSearch ? filterVals.filter((v) => v.toLowerCase().includes(filterSearch.toLowerCase())) : filterVals;
                const activeFilterCount = Object.values(lmColFilters).filter((v) => v && v.length > 0).length;
                const totalTableW = 30 + lmHeaders.reduce((s, h) => s + (lmColWidths[h] || lmDefWidths[h]), 0);

                return (
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6, marginBottom: 6 }}>
                      {activeFilterCount > 0 && (
                        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", background: `${th.accent}11`, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
                          <span style={{ fontWeight: 600 }}>Filter active ({activeFilterCount} column{activeFilterCount > 1 ? "s" : ""})</span>
                          <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted }}>{"\u2014"} {filteredEdges.length} of {data.edges.length} connections</span>
                          <button onClick={() => setModal((p) => ({ ...p, lmColFilters: {} }))} style={{ padding: "1px 8px", fontSize: LM_TYPOGRAPHY.meta, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}>Clear All</button>
                        </div>
                      )}
                      <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
                        <button onClick={copyAll} style={{ padding: "3px 10px", fontSize: LM_TYPOGRAPHY.control, background: th.btnBg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}
                          onMouseEnter={(ev) => { ev.currentTarget.style.background = th.accent + "22"; }} onMouseLeave={(ev) => { ev.currentTarget.style.background = th.btnBg; }}>
                          {checkedCount > 0 ? `Copy Selected (${checkedCount})` : `Copy All (${sortedEdges.length})`}
                        </button>
                      </div>
                    </div>
                    <div style={{ maxHeight: 360, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                      <table style={{ borderCollapse: "collapse", fontSize: LM_TYPOGRAPHY.body, fontFamily: "monospace", tableLayout: "fixed", width: totalTableW }}>
                        <thead>
                          <tr>
                            <th style={{ position: "sticky", top: 0, width: 30, background: th.headerBg || th.panelBg, borderBottom: `1px solid ${th.border}`, zIndex: 2, textAlign: "center", padding: "6px 4px" }}>
                              <input type="checkbox" checked={allChecked} onChange={toggleAllLm} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                            </th>
                            {lmHeaders.map((h) => (
                              <th key={h} style={{ position: "sticky", top: 0, width: lmColWidths[h] || lmDefWidths[h], minWidth: 40, background: th.headerBg || th.panelBg, color: lmSortCol === h ? th.text : th.accent, padding: "6px 8px", textAlign: "left", fontSize: LM_TYPOGRAPHY.meta, borderBottom: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", overflow: "hidden", boxSizing: "border-box", userSelect: "none", zIndex: 2 }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
                                  <span onClick={() => toggleSort(h)} style={{ cursor: "pointer", overflow: "hidden", textOverflow: "ellipsis" }}>{h}</span>
                                  {lmSortCol === h && <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.accent }}>{lmSortDir === "asc" ? "\u25B2" : "\u25BC"}</span>}
                                  <span onClick={(e) => openLmFilter(h, e)} style={{ cursor: "pointer", fontSize: LM_TYPOGRAPHY.badge, color: lmColFilters[h] ? th.accent : th.textMuted + "66", flexShrink: 0, marginLeft: "auto", paddingRight: 8 }}>{"\u25BC"}</span>
                                  <div onMouseDown={(e) => onResizeStart(h, e)} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 6, cursor: "col-resize" }}>
                                    <div style={{ position: "absolute", right: 2, top: 2, bottom: 2, width: 1, background: th.border }} />
                                  </div>
                                </div>
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {/* Same bounded-render approach as the Findings list: rows here are
                              expandable, so their height varies and fixed-row windowing does not
                              apply. Edge count grows with hosts x hosts. */}
                          {sortedEdges.slice(0, modal.lmEdgeLimit || 400).map((e, i) => {
                            const eSc = e.riskScore || 0;
                            const eTc = lmTechColor(e.technique);
                            const _edgeKey = `${e.source}\u2192${e.target}`;
                            const eExpanded = modal.expandedEdge === _edgeKey;
                            const eDur = durationMs(e);
                            return (
                              <Fragment key={i}>
                                <tr onClick={() => setModal((p) => ({ ...p, expandedEdge: eExpanded ? null : _edgeKey }))} style={{ background: isLmChecked(e) ? `${th.accent}0a` : i % 2 === 0 ? "transparent" : (th.rowAlt || th.panelBg + "44"), cursor: "pointer" }}>
                                  <td style={{ padding: "4px 4px", textAlign: "center" }}>
                                    <input type="checkbox" checked={isLmChecked(e)} onChange={(ev) => toggleLmCheck(e, ev)} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                  </td>
                                  {/* Score */}
                                  <td style={{ padding: "4px 8px", textAlign: "center", fontWeight: 700, fontSize: LM_TYPOGRAPHY.body, color: eSc >= 30 ? th.sev.critical : eSc >= 15 ? th.sev.high : th.textMuted }}>{eSc}</td>
                                  {/* Source */}
                                  <td style={{ padding: "4px 8px", color: isSusHost(e.source) ? th.sev.high : th.text, fontWeight: isSusHost(e.source) ? 600 : 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.source}{isSusHost(e.source) && <span title="Suspicious hostname" style={{ marginLeft: 4, fontSize: LM_TYPOGRAPHY.meta }}>&#9888;</span>}{e.sourceLabel && e.sourceLabel !== "host" && <span style={{ marginLeft: 4, fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{e.sourceLabel}</span>}</td>
                                  {/* Target */}
                                  <td style={{ padding: "4px 8px", color: isSusHost(e.target) ? th.sev.high : th.text, fontWeight: isSusHost(e.target) ? 600 : 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.target}{isSusHost(e.target) && <span title="Suspicious hostname" style={{ marginLeft: 4, fontSize: LM_TYPOGRAPHY.meta }}>&#9888;</span>}</td>
                                  {/* Technique */}
                                  <td style={{ padding: "4px 8px" }}>
                                    <span style={{ padding: "2px 6px", background: eTc.bg, color: eTc.color, borderRadius: 4, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap" }}>{e.technique || "Unknown"}</span>
                                    {(e.otherTechniques || []).length > 0 && <span title={(e.otherTechniques || []).join(", ")} style={{ marginLeft: 3, fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>+{e.otherTechniques.length}</span>}
                                  </td>
                                  {/* Users */}
                                  <td style={{ padding: "4px 8px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }}>{e.users.join(", ")}</td>
                                  {/* Count */}
                                  <td style={{ padding: "4px 8px", fontWeight: 600, color: th.text, textAlign: "center" }}>{e.count}</td>
                                  <td style={{ padding: "4px 8px", color: th.textDim, whiteSpace: "nowrap" }}>{fmtTs(e.firstSeen)}</td>
                                  <td style={{ padding: "4px 8px", color: th.textDim, whiteSpace: "nowrap" }}>{fmtTs(e.lastSeen)}</td>
                                  {/* Observed Span */}
                                  <td style={{ padding: "4px 8px", whiteSpace: "nowrap", color: eDur >= 86400000 ? (th.danger) : eDur >= 3600000 ? th.sev.high : th.textDim, fontWeight: eDur >= 86400000 ? 600 : 400 }}>{formatDuration(eDur)}</td>
                                  {/* Why Suspicious */}
                                  <td style={{ padding: "4px 6px" }}>
                                    <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                                      {(e.flags || []).slice(0, 4).map((f, fi) => (
                                        <span key={fi} style={{ padding: "1px 5px", background: f.startsWith("Finding:") ? th.sev.critical + "12" : th.textMuted + "18", color: f.startsWith("Finding:") ? th.sev.critical : th.textDim, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap" }}>{f}</span>
                                      ))}
                                      {(e.flags || []).length > 4 && <span style={{ fontSize: LM_TYPOGRAPHY.badge, color: th.textMuted }}>+{e.flags.length - 4}</span>}
                                    </div>
                                  </td>
                                </tr>
                                {eExpanded && (
                                  <tr>
                                    <td colSpan={lmHeaders.length + 1} style={{ padding: "0 12px 10px 48px", borderTop: `1px solid ${th.border}22`, background: `${th.accent}04` }}>
                                      <div style={{ display: "flex", gap: 24, marginTop: 8 }}>
                                        {/* Left: Episodes */}
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                          <div style={{ fontWeight: 600, color: th.text, fontSize: LM_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif", marginBottom: 6 }}>Episodes ({(e.episodes || []).length})</div>
                                          {(e.episodes || []).length === 0 ? (
                                            <div style={{ fontSize: LM_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>No episode data</div>
                                          ) : (
                                            <div style={{ maxHeight: 180, overflowY: "auto" }}>
                                              {(e.episodes || []).map((ep, epi) => {
                                                const phaseColor = ep.phase === "failed" ? th.sev.critical : ep.phase === "reconnect" ? th.sev.custom : th.sev.clean;
                                                const phaseBg = phaseColor + "18";
                                                const phaseLabel = ep.phase === "failed" ? "FAILED" : ep.phase === "reconnect" ? "RECON" : "OK";
                                                const techFam = ep.techFamily || "Other";
                                                const tfColor = techFam === "Cleartext" || techFam === "ServiceExec" ? th.sev.critical : techFam === "AdminShare" ? th.sev.high : techFam === "RDP" ? th.sev.info : techFam === "Interactive" ? th.sev.clean : th.textMuted;
                                                return (
                                                  <div key={epi} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 0", fontSize: LM_TYPOGRAPHY.meta, fontFamily: "monospace", color: th.textDim, borderBottom: epi < e.episodes.length - 1 ? `1px solid ${th.border}15` : "none" }}>
                                                    <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge, minWidth: 16 }}>#{epi + 1}</span>
                                                    <span style={{ padding: "0 4px", background: phaseBg, color: phaseColor, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 700, fontFamily: "-apple-system, sans-serif", minWidth: 32, textAlign: "center" }}>{phaseLabel}</span>
                                                    <span style={{ fontWeight: 600, color: th.text }}>{ep.user}</span>
                                                    <span style={{ padding: "0 4px", background: tfColor + "15", color: tfColor, borderRadius: 2, fontSize: LM_TYPOGRAPHY.badge, fontFamily: "-apple-system, sans-serif" }}>{techFam}</span>
                                                    <span>{ep.count} evt{ep.count !== 1 ? "s" : ""}</span>
                                                    <span style={{ color: th.textMuted }}>{(ep.firstTs || "").slice(11, 19)}{ep.lastTs && ep.lastTs !== ep.firstTs ? `\u2013${(ep.lastTs || "").slice(11, 19)}` : ""}</span>
                                                  </div>
                                                );
                                              })}
                                            </div>
                                          )}
                                        </div>
                                        {/* Right: Edge Summary */}
                                        <div style={{ width: 240, flexShrink: 0, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "-apple-system, sans-serif", color: th.textDim }}>
                                          <div style={{ fontWeight: 600, color: th.text, fontSize: LM_TYPOGRAPHY.control, marginBottom: 6 }}>Edge Details</div>
                                          <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 90 }}>Source type</span><span>{e.sourceLabel || "host"}</span></div>
                                          {(e.otherTechniques || []).length > 0 && <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 90 }}>Also seen</span><span>{e.otherTechniques.join(", ")}</span></div>}
                                          <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 90 }}>Logon Types</span><span>{e.logonTypes.join(", ") || "\u2014"}</span></div>
                                          {(e.clientNames || []).length > 0 && <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 90 }}>Client Names</span><span style={{ color: th.sev.custom }}>{e.clientNames.join(", ")}</span></div>}
                                          {(e.clientAddresses || []).length > 0 && <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 90 }}>Client Addrs</span><span style={{ color: th.sev.custom }}>{e.clientAddresses.join(", ")}</span></div>}
                                          {(e.shareNames || []).length > 0 && <div style={{ display: "flex", gap: 4, marginBottom: 2 }}><span style={{ color: th.textMuted, width: 90 }}>Shares</span><span style={{ color: th.sev.high }}>{e.shareNames.join(", ")}{e.shareAccessCount > 0 ? ` (${e.shareAccessCount} access events)` : ""}</span></div>}
                                          {/* Event breakdown */}
                                          {e.eventBreakdown && Object.keys(e.eventBreakdown).length > 0 && (
                                            <div style={{ marginTop: 6 }}>
                                              <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600 }}>Event Breakdown</span>
                                              <div style={{ display: "flex", gap: 4, marginTop: 3, flexWrap: "wrap" }}>
                                                {Object.entries(e.eventBreakdown).sort((a, b) => b[1] - a[1]).map(([eid, cnt]) => (
                                                  <span key={eid} style={{ padding: "1px 5px", background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 3, fontSize: LM_TYPOGRAPHY.meta, fontFamily: "monospace" }}>
                                                    <span style={{ color: th.accent, fontWeight: 600 }}>{eid}</span><span style={{ color: th.textMuted, marginLeft: 2 }}>{"\u00D7"}{cnt}</span>
                                                  </span>
                                                ))}
                                              </div>
                                            </div>
                                          )}
                                          {/* Flags */}
                                          {(e.flags || []).length > 0 && (
                                            <div style={{ marginTop: 6 }}>
                                              <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.badge, fontWeight: 600 }}>Why Suspicious</span>
                                              <div style={{ display: "flex", flexDirection: "column", gap: 2, marginTop: 3 }}>
                                                {e.flags.map((f, fi) => (
                                                  <span key={fi} style={{ padding: "1px 5px", background: f.startsWith("Finding:") ? th.sev.critical + "12" : th.textMuted + "12", color: f.startsWith("Finding:") ? th.sev.critical : th.textDim, borderRadius: 3, fontSize: LM_TYPOGRAPHY.badge, whiteSpace: "nowrap" }}>{f}</span>
                                                ))}
                                              </div>
                                            </div>
                                          )}
                                          <div style={{ marginTop: 8 }}>
                                            <EvidenceActions item={e} />
                                          </div>
                                        </div>
                                      </div>
                                    </td>
                                  </tr>
                                )}
                              </Fragment>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    {sortedEdges.length > (modal.lmEdgeLimit || 400) && (
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, padding: "8px 0 2px", fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                        <span>Showing {modal.lmEdgeLimit || 400} of {sortedEdges.length} connections</span>
                        <button onClick={() => setModal((p) => ({ ...p, lmEdgeLimit: (p.lmEdgeLimit || 400) + 400 }))}
                          style={{ ...ms.bs, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control, padding: "3px 10px" }}>Show 400 more</button>
                        <button onClick={() => setModal((p) => ({ ...p, lmEdgeLimit: sortedEdges.length }))}
                          style={{ ...ms.bs, borderRadius: 6, fontSize: LM_TYPOGRAPHY.control, padding: "3px 10px" }}>Show all {sortedEdges.length}</button>
                      </div>
                    )}
                    {/* Column filter dropdown popup */}
                    {filterOpen && (
                      <>
                        <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, lmFilterOpen: null }))} />
                        <div style={{ position: "fixed", left: modal.lmFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340), top: modal.lmFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440), width: modal.lmFilterW || 320, height: modal.lmFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                          <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                            onMouseDown={(e) => {
                              e.preventDefault();
                              const startX = e.clientX, startY = e.clientY;
                              const startLeft = modal.lmFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340);
                              const startTop = modal.lmFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440);
                              document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                              const onMove = (ev) => setModal((p) => ({ ...p, lmFilterX: startLeft + ev.clientX - startX, lmFilterY: startTop + ev.clientY - startY }));
                              const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                              window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                            }}>
                            <span style={{ fontSize: LM_TYPOGRAPHY.body, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER {"\u2014"} {filterOpen.toUpperCase()}</span>
                            <span style={{ cursor: "pointer", color: th.textMuted, fontSize: LM_TYPOGRAPHY.heading, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, lmFilterOpen: null }))}>{"\u00D7"}</span>
                          </div>
                          <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                            <input type="text" placeholder="Search values..." value={filterSearch} onChange={(e) => setModal((p) => ({ ...p, lmFilterSearch: e.target.value }))}
                              style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: LM_TYPOGRAPHY.body, background: th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                              autoFocus />
                          </div>
                          <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                            <button onClick={() => setModal((p) => ({ ...p, lmFilterSel: new Set(filterVals) }))} style={{ padding: "2px 8px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                            <button onClick={() => setModal((p) => ({ ...p, lmFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                            <span style={{ marginLeft: "auto", fontSize: LM_TYPOGRAPHY.control, color: th.textMuted }}>{filterVals.length} values</span>
                          </div>
                          <div style={{ flex: 1, overflow: "auto", padding: "0 6px", minHeight: 0 }}>
                            {displayVals.slice(0, 1000).map((v) => (
                              <div key={v} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", borderRadius: 3, cursor: "pointer" }}
                                onClick={() => setModal((p) => { const s = new Set(p.lmFilterSel || []); s.has(v) ? s.delete(v) : s.add(v); return { ...p, lmFilterSel: s }; })}
                                onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}0a`}
                                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                                <input type="checkbox" checked={filterSel.has(v)} readOnly style={{ width: 13, height: 13, accentColor: th.accent, cursor: "pointer", flexShrink: 0 }} />
                                <span style={{ fontSize: LM_TYPOGRAPHY.body, color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "SF Mono, Menlo, monospace" }}>{v || "(empty)"}</span>
                                <span style={{ fontSize: LM_TYPOGRAPHY.control, color: th.textMuted, flexShrink: 0 }}>{filterCounts[v]}</span>
                              </div>
                            ))}
                          </div>
                          <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                            <button onClick={() => setModal((p) => { const cf = { ...(p.lmColFilters || {}) }; delete cf[filterOpen]; return { ...p, lmColFilters: cf, lmFilterOpen: null }; })}
                              style={{ padding: "4px 12px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Reset</button>
                            <button onClick={() => setModal((p) => ({ ...p, lmFilterOpen: null }))}
                              style={{ padding: "4px 12px", fontSize: LM_TYPOGRAPHY.control, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Cancel</button>
                            <button onClick={() => setModal((p) => ({ ...p, lmColFilters: { ...(p.lmColFilters || {}), [filterOpen]: [...(p.lmFilterSel || [])] }, lmFilterOpen: null }))}
                              style={{ padding: "4px 12px", fontSize: LM_TYPOGRAPHY.control, background: th.accent, border: "none", borderRadius: 4, color: "#fff", cursor: "pointer", fontWeight: 600 }}>Apply</button>
                          </div>
                          <div onMouseDown={(e) => {
                            e.preventDefault(); e.stopPropagation();
                            const startX = e.clientX, startY = e.clientY, startW = modal.lmFilterW || 320, startH = modal.lmFilterH || 420;
                            document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                            const onMove = (ev) => setModal((p) => ({ ...p, lmFilterW: Math.max(240, startW + ev.clientX - startX), lmFilterH: Math.max(250, startH + ev.clientY - startY) }));
                            const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                            window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                          }} style={{ position: "absolute", bottom: 0, right: 0, width: 14, height: 14, cursor: "nwse-resize" }}>
                            <svg width="10" height="10" viewBox="0 0 10 10" style={{ position: "absolute", bottom: 2, right: 2 }}>
                              <path d="M8 2L2 8M8 5L5 8M8 8L8 8" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" />
                            </svg>
                          </div>
                        </div>
                      </>
                    )}
                  </div>
                );
              })()}
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
          {phase === "config" && (
            <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center", gap: 8 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <button onClick={() => setModal(null)} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
                {/* Getting back to a finished scan must never require re-running it. `data`
                    survives "Scan options"; `lmLastRun` survives closing the modal. */}
                {data ? (
                  <button onClick={() => setModal((p) => ({ ...p, phase: "results" }))}
                    style={{ ...ms.bs, borderRadius: 8 }}>Return to results</button>
                ) : ct?.lmLastRun?.data ? (
                  <button onClick={() => setModal((p) => {
                    const resumed = ct.lmLastRun.data;
                    const layoutNodes = selectLateralGraphNodes(resumed.nodes || []);
                    const ids = new Set(layoutNodes.map((node) => node.id));
                    const layoutEdges = selectLateralGraphEdges(
                      (resumed.edges || []).filter((edge) => ids.has(edge.source) && ids.has(edge.target)),
                    );
                    return {
                      ...p,
                      phase: "results",
                      data: resumed,
                      positions: computeForceLayout(layoutNodes, layoutEdges),
                      lmGraphMode: "machines",
                      viewBox: {
                        x: 0,
                        y: 0,
                        w: LATERAL_GRAPH_DEFAULTS.width,
                        h: LATERAL_GRAPH_DEFAULTS.height,
                      },
                      selectedNode: null,
                      selectedEdge: null,
                      lmAlertLimit: 300,
                      lmEdgeLimit: 400,
                    };
                  })}
                    title={`Reopen the analysis finished ${_agoLabel(ct.lmLastRun.completedAt)}`}
                    style={{ ...ms.bs, borderRadius: 8 }}>
                    Resume last results <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.control }}>({_agoLabel(ct.lmLastRun.completedAt)})</span>
                  </button>
                ) : null}
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <button onClick={() => {
                  // RDP-only quick launcher: keep all accounts (incl. service/machine), exclude local logons,
                  // open straight to the RDP Sessions tab in Individual (per-session) view.
                  // Set the initial-view flags first (so result transition reads them) then invoke
                  // analysis with explicit overrides (so the closure can't read stale filter state).
                  setModal((p) => ({ ...p, _lmInitialView: "rdp", _lmInitialRdpView: "individual" }));
                  handleAnalyze({ excludeService: false, excludeLocal: true });
                }} title="Run analysis tuned for RDP sessions and open the RDP Sessions table directly"
                  style={{ ...ms.bs, borderRadius: 8, display: "flex", alignItems: "center", gap: 6 }}>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="4" width="20" height="13" rx="1"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                  Open RDP Sessions
                </button>
                <button onClick={() => handleAnalyze()} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Analyze</button>
              </div>
            </div>
          )}
          {phase === "loading" && (
            <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
              <span style={{ color: th.textMuted, fontSize: LM_TYPOGRAPHY.body, fontFamily: "-apple-system, sans-serif" }}>{Math.round(modal.lmProgress || 0)}% complete</span>
              <button onClick={cancelAnalysis} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
            </div>
          )}
          {phase === "results" && (
            <div style={{ display: "flex", justifyContent: "space-between", width: "100%" }}>
              {/* Keeps `data` — going back to tweak a setting must not throw away a scan
                  that may have taken minutes. "New scan" is the explicit discard. */}
              <button onClick={() => setModal((p) => ({ ...p, phase: "config" }))} style={{ ...ms.bs, borderRadius: 8 }}>Scan options</button>
              <button onClick={() => setModal(null)} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Done</button>
            </div>
          )}
        </div>
      </>)}
    </DraggableResizableModal>
  );
}
