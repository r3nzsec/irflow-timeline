import ProcessGraphView from "./ProcessGraphView.jsx";
import ProcessTreeVerdictHero from "./ProcessTreeVerdictHero.jsx";
import ProcessTreeRuleHealthPanel from "./ProcessTreeRuleHealthPanel.jsx";
import { _integrityShort, _providerShort, _ptFormatDuration } from "../../../utils/process-inspector.js";
import { consistentParentKey } from "../../../utils/process-inspector-pipeline.js";
import { normalizeTimestamp } from "../../../utils/forensic-normalize.js";
import { toast } from "../../../store/useToastStore.js";
import { isIpcError, ipcErrorMessage } from "../../../utils/ipc-result.js";
import { PI_TYPOGRAPHY, PT_VIEW_MODES } from "../constants.js";
import { PI_GRID_PIVOT_WINDOWS } from "../../../utils/process-grid-pivot.js";
import {
  fitProcessRawColumnWidths,
  PI_RAW_TREE_LAYOUT,
  processRawGridWidth,
} from "../../../utils/process-raw-grid-layout.js";

/**
 * Process Inspector results phase — toolbar, hero, stories/clusters, graph, table, detail, footer.
 */
export default function ProcessTreeResultsView(p) {
  const {
    modal, setModal, th, ct, data, cols,
    SUS_COLORS, INT_COLOR, PI_SEV_COLORS,
    _ptDetMap, _ptScoring, _ptPrevalenceSummary, _ptSevCounts,
    _ptSeqMap, _ptChainClusters, _ptNodeClusterMap, _ptIncidentStories, _ptNodeStoryMap,
    _ptRail, flatNodes, byKeyMap, childMap, chainKeys, selectedKey,
    ptScroll, setPtScroll, ptScrollRef, ptHeaderRef, ptRafRef,
    ptIcon, ptMitreBadge, ptExtractHash, ptHighlightCmd, ptDecodePanel,
    ptHeaders, ptDefWidths, ptColWidths, ptSortCol, ptSortDir, ptColFilters,
    ptCellVal, togglePtSort, onPtResizeStart, openPtFilter,
    ptFilterOpen, ptFilterPos, ptFilterVals, ptFilterCounts, ptFilterSel, ptFilterSearch, ptFilterDisplay, ptActiveFilterCount,
    ptChecked, ptCheckedCount, PT_CHK_W,
    expandAll, collapseAll, expandToDepth,
    applyProcessGridPivot, applyProcessHandoff, lookupProcessHash,
    openPiSourceEvent, makePiAnalystEntry, upsertPiAnalystEntry, removePiAnalystEntry,
    handleBuild, _downloadFile, _toCSV,
    piAnalystProfile,
    updateActiveTab,
    pw,
  } = p;

        const tle = typeof window !== "undefined" ? window.tle : null;
        const searchText = modal.searchText || "";
        const expandedNodes = modal.expandedNodes || {};
        const ptViewMode = modal.ptViewMode || (_ptIncidentStories.length > 0 ? "story" : _ptChainClusters.some(c => c.level >= 3) ? "triage" : _ptChainClusters.some(c => c.level >= 2) ? "hunt" : "raw");
        const isHealthMode = ptViewMode === "health";
        const ptMode = isHealthMode ? { label: "Rules", filter: "all", clustered: false, health: true } : (PT_VIEW_MODES[ptViewMode] || PT_VIEW_MODES.raw);
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
        // Severity filter (toolbar): array of detection levels to show; empty = show all.
        const ptSevFilter = Array.isArray(modal.ptSevFilter) ? modal.ptSevFilter : [];
        const filteredClusters = (() => {
          let cls = [..._ptChainClusters];
          if (ptMode.filter === "suspicious") cls = cls.filter(c => c.level > 0);
          else if (ptMode.filter === "medium+") cls = cls.filter(c => c.level >= 2);
          if (ptSevFilter.length) cls = cls.filter(c => ptSevFilter.includes(c.level));
          const st = (searchText || "").toLowerCase();
          if (st) cls = cls.filter(c => c.reason.toLowerCase().includes(st) || c.hostname.toLowerCase().includes(st) || c.users.some(u => u.toLowerCase().includes(st)) || c.cmdVariants.some(cmd => cmd.toLowerCase().includes(st)));
          return cls;
        })();
        const filteredStories = (() => {
          let stories = [..._ptIncidentStories];
          if (ptMode.filter === "medium+") stories = stories.filter((s) => s.level >= 2);
          else if (ptMode.filter === "suspicious") stories = stories.filter((s) => s.level > 0);
          if (ptSevFilter.length) stories = stories.filter((s) => ptSevFilter.includes(s.level));
          const st = (searchText || "").toLowerCase().trim();
          if (st) stories = stories.filter((s) => s.searchBlob.includes(st));
          return stories;
        })();
        const filteredStats = {
          total: filteredClusters.length,
          critical: filteredClusters.filter(c => c.level === 3).length,
          high: filteredClusters.filter(c => c.level === 2).length,
          medium: filteredClusters.filter(c => c.level === 1).length,
          susProcesses: filteredClusters.reduce((s, c) => s + c.count, 0),
          hosts: new Set(filteredClusters.map(c => c.hostname).filter(Boolean)).size,
          users: new Set(filteredClusters.flatMap(c => c.users)).size,
        };
        const filteredStoryStats = {
          total: filteredStories.length,
          critical: filteredStories.filter((s) => s.level === 3).length,
          high: filteredStories.filter((s) => s.level === 2).length,
          medium: filteredStories.filter((s) => s.level === 1).length,
          susProcesses: filteredStories.reduce((sum, s) => sum + s.eventCount, 0),
          hosts: new Set(filteredStories.map((s) => s.hostname).filter(Boolean)).size,
          users: new Set(filteredStories.flatMap((s) => s.users)).size,
          sequences: filteredStories.reduce((sum, s) => sum + s.sequenceCount, 0),
        };
        const _ptPivotBtn = { padding: "2px 8px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, fontSize: PI_TYPOGRAPHY.control, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 };
        const _ptSevLabel = (lv) => lv >= 3 ? "CRIT" : lv >= 2 ? "HIGH" : lv >= 1 ? "MED" : "LOW";
        const _ptSevPill = (color) => ({ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 6px", borderRadius: 3, background: color + "22", color, fontWeight: 600 });
        const _ptCopyStory = (story) => {
          const lines = [
            `[${_ptSevLabel(story.level)}] ${story.hostname ? `${story.hostname} — ` : ""}${story.leadReason}`,
            `Story: ${story.title}`,
            story.users.length ? `Users: ${story.users.join(", ")}` : null,
            story.firstSeen ? `Time: ${(story.firstSeen || "").slice(0, 19)}${story.lastSeen && story.lastSeen !== story.firstSeen ? ` — ${(story.lastSeen || "").slice(0, 19)}` : ""}` : null,
            `Suspicious Events: ${story.eventCount} | Context Events: ${story.contextEventCount || story.eventCount} | Chains: ${story.chainCount}${story.sequenceCount ? ` | Sequences: ${story.sequenceCount}` : ""}`,
            story.techniques.length ? `ATT&CK: ${story.techniques.join(", ")}` : null,
            `Narrative: ${story.narrative}`,
            "",
            "Storyline:",
            ...story.steps.map((step) => `  ${(step.ts || "").slice(0, 19) || "Unknown time"}  ${step.parent} -> ${step.child} — ${step.reason}${step.isContext ? " [context]" : ""}`),
          ].filter(Boolean);
          navigator.clipboard?.writeText?.(lines.join("\n"));
        };
        return (
        <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
          {/* Toolbar: mode toggle + search + controls */}
          <div style={{ padding: "8px 20px", borderBottom: `1px solid ${th.border}55`, flexShrink: 0, display: "flex", alignItems: "center", gap: 8, background: `${th.headerBg}88`, backdropFilter: "blur(12px) saturate(1.3)", WebkitBackdropFilter: "blur(12px) saturate(1.3)" }}>
            {/* View mode toggle */}
            {Object.entries(PT_VIEW_MODES).map(([k, m]) => (
              <button key={k} onClick={() => setModal(p => ({ ...p, ptViewMode: k, _ptExpandedCluster: null, _ptExpandedIncident: null, ptClusterKeys: m.clustered ? null : p.ptClusterKeys, ptClusterContext: m.clustered ? false : p.ptClusterContext }))} title={m.incident ? `${m.label}: grouped into investigation stories` : m.graph ? `${m.label}: spatial parent-child node graph (multi-host)` : m.clustered ? `${m.label}: clustered by chain` : `${m.label}: full tree view`}
                style={{ padding: "4px 10px", fontSize: PI_TYPOGRAPHY.control, fontWeight: ptViewMode === k ? 700 : 500, background: ptViewMode === k ? th.accent : `${th.accent}15`, color: ptViewMode === k ? "#fff" : th.accent, border: `1px solid ${ptViewMode === k ? th.accent : th.accent + "33"}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>{m.label}</button>
            ))}
            <button
              type="button"
              onClick={() => setModal((p) => ({
                ...p,
                ptViewMode: isHealthMode ? (p._ptPrevViewMode || "story") : "health",
                _ptPrevViewMode: isHealthMode ? p._ptPrevViewMode : (p.ptViewMode && p.ptViewMode !== "health" ? p.ptViewMode : p._ptPrevViewMode),
              }))}
              title="Rule health & coverage report — which rules fired, stayed silent, or are disabled"
              style={{
                padding: "4px 10px", fontSize: PI_TYPOGRAPHY.control, fontWeight: isHealthMode ? 700 : 500,
                background: isHealthMode ? th.accent : `${th.accent}15`,
                color: isHealthMode ? "#fff" : th.accent,
                border: `1px solid ${isHealthMode ? th.accent : th.accent + "33"}`,
                borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif",
                whiteSpace: "nowrap", flexShrink: 0,
              }}
            >Rules</button>
            <div style={{ width: 1, height: 16, background: th.border, flexShrink: 0 }} />
            {!isHealthMode && <input value={searchText || ""} onChange={(e) => setModal((p) => ({ ...p, searchText: e.target.value }))} placeholder={ptMode.incident ? "Search stories by host, user, ATT&CK, process, or reason..." : ptMode.clustered ? "Search chains by name, host, user, command..." : ptMode.graph ? "Search does not filter the graph — select a node or use Sev filters..." : "Search by process name, PID, command line, or user..."} style={{ flex: 1, background: th.bgInput, color: th.text, border: `1px solid ${th.border}`, borderRadius: 6, padding: "6px 10px", fontSize: PI_TYPOGRAPHY.body, fontFamily: "monospace", outline: "none", boxSizing: "border-box" }} />}
            {isHealthMode && <div style={{ flex: 1, fontSize: PI_TYPOGRAPHY.body, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Built-in + custom rule coverage for this tree</div>}
            {!isHealthMode && !ptMode.clustered && !ptMode.graph && <button onClick={expandAll} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }} title="Expand all nodes">Expand All</button>}
            {!isHealthMode && !ptMode.clustered && !ptMode.graph && <button onClick={collapseAll} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }} title="Collapse all nodes">Collapse</button>}
            {!isHealthMode && !ptMode.clustered && !ptMode.graph && <button onClick={() => setModal((p) => p ? { ...p, ptDensity: p.ptDensity === "compact" ? undefined : "compact" } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: modal.ptDensity === "compact" ? (th.accent) + "22" : th.btnBg, color: modal.ptDensity === "compact" ? th.accent : th.textDim, border: `1px solid ${modal.ptDensity === "compact" ? (th.accent) + "55" : th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: modal.ptDensity === "compact" ? 600 : 400 }} title="Toggle compact row height">{modal.ptDensity === "compact" ? "Compact" : "Comfortable"}</button>}
            {!isHealthMode && !ptMode.clustered && !ptMode.graph && ptColWidths && <button onClick={() => setModal((p) => p ? { ...p, ptColWidths: null } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: PI_TYPOGRAPHY.control, cursor: "pointer", background: th.btnBg, color: th.accent, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }} title="Restore responsive column widths">Fit Columns</button>}
            {!isHealthMode && !ptMode.clustered && !ptMode.graph && <select onChange={(e) => { if (e.target.value) expandToDepth(parseInt(e.target.value)); }} value="" style={{ padding: "4px 4px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.bgInput, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>
              <option value="">Depth...</option>
              {[1, 2, 3, 4, 5].filter((d) => d <= (data.stats.maxDepth || 5)).map((d) => <option key={d} value={d}>Depth {d}</option>)}
            </select>}
            {!isHealthMode && !ptMode.clustered && !ptMode.graph && <button onClick={() => setModal((p) => p ? { ...p, susOnlyFilter: !p.susOnlyFilter } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: modal.susOnlyFilter ? (th.danger) + "22" : th.btnBg, color: modal.susOnlyFilter ? (th.danger) : th.textDim, border: `1px solid ${modal.susOnlyFilter ? (th.danger) + "55" : th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: modal.susOnlyFilter ? 600 : 400 }} title="Show only suspicious processes">{modal.susOnlyFilter ? "\u26A0 Suspicious Only" : "Suspicious Only"}</button>}
            {!isHealthMode && ptMode.graph && (
              <select
                value={modal.ptGraphMinLevel ?? (ptMode.filter === "medium+" ? 2 : ptMode.filter === "all" ? 0 : 1)}
                onChange={(e) => setModal((p) => p ? { ...p, ptGraphMinLevel: Number(e.target.value) } : p)}
                title="Minimum detection level for graph seeds (ancestors/children still included)"
                style={{ padding: "4px 6px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.bgInput, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}
              >
                <option value={1}>Seeds: Med+</option>
                <option value={2}>Seeds: High+</option>
                <option value={3}>Seeds: Critical</option>
                <option value={0}>Seeds: All</option>
              </select>
            )}
            {!isHealthMode && ptViewMode === "hunt" && _ptPrevalenceSummary.items.length > 0 && (
              <button
                type="button"
                aria-expanded={!!modal.ptRareOpen}
                onClick={() => setModal((p) => p ? { ...p, ptRareOpen: !p.ptRareOpen } : p)}
                title="Show prevalence-based rare process leads"
                style={{
                  padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer",
                  background: modal.ptRareOpen ? `${th.accent}22` : th.btnBg,
                  color: modal.ptRareOpen ? th.accent : th.textDim,
                  border: `1px solid ${modal.ptRareOpen ? th.accent + "55" : th.border}`,
                  fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0,
                }}
              >
                Rare processes {modal.ptRareOpen ? "▴" : "▾"}
              </button>
            )}
            {!isHealthMode && <div style={{ display: "flex", gap: 2, alignItems: "center", flexShrink: 0 }} title="Filter by detection severity (toggle; none selected = show all)">
              <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginRight: 1 }}>Sev</span>
              {[{ v: 3, l: "Crit" }, { v: 2, l: "High" }, { v: 1, l: "Med" }].map(({ v, l }) => {
                const on = ptSevFilter.includes(v);
                const col = SUS_COLORS[v] || th.danger;
                return <button key={v} onClick={() => setModal((p) => { const cur = Array.isArray(p.ptSevFilter) ? p.ptSevFilter : []; const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v]; return { ...p, ptSevFilter: next.length ? next : undefined }; })} style={{ padding: "4px 7px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: on ? col + "22" : th.btnBg, color: on ? col : th.textDim, border: `1px solid ${on ? col + "66" : th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: on ? 700 : 400 }}>{l}</button>;
              })}
            </div>}
            {!isHealthMode && !ptMode.clustered && selectedKey && <button onClick={() => setModal((p) => p ? { ...p, selectedKey: null } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: (th.accent) + "22", color: th.accent, border: `1px solid ${(th.accent)}55`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Clear Chain</button>}
            {!isHealthMode && !ptMode.clustered && modal.ptClusterKeys && <button onClick={() => setModal((p) => p ? { ...p, ptClusterKeys: null, ptClusterContext: false } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: (th.accent) + "22", color: th.accent, border: `1px solid ${(th.accent)}55`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: 600 }}>{"\u2716"} Cluster ({modal.ptClusterKeys.size})</button>}
            {!isHealthMode && !ptMode.clustered && modal.ptClusterKeys && <button onClick={() => setModal((p) => p ? { ...p, ptClusterContext: !p.ptClusterContext } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: modal.ptClusterContext ? (th.accent) + "22" : th.btnBg, color: modal.ptClusterContext ? (th.accent) : th.textDim, border: `1px solid ${modal.ptClusterContext ? (th.accent) + "55" : th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: modal.ptClusterContext ? 600 : 400 }}>{modal.ptClusterContext ? "Tree Context" : "Flat View"}</button>}
            {/* Separator */}
            {!isHealthMode && <div style={{ width: 1, height: 16, background: th.border, flexShrink: 0 }} />}
            {/* Raw mode: Copy Chain / Tree / CSV / Selected */}
            {!isHealthMode && !ptMode.clustered && selectedKey && <button onClick={() => {
              const lines = [];
              const chain = [];
              let cur = selectedKey;
              // Walk real ancestors via the shared guard so Copy Chain never splices an
              // unrelated process onto the chain through a PID-reuse mislinked edge.
              while (cur && byKeyMap.has(cur)) { const n = byKeyMap.get(cur); chain.unshift(n); cur = consistentParentKey(n, byKeyMap); }
              chain.forEach((n, i) => {
                const indent = "  ".repeat(i);
                const prefix = i === 0 ? "" : "\u2514\u2500 ";
                lines.push(`${indent}${prefix}${n.processName} (PID: ${n.pid}${n.user ? ", " + n.user : ""}${n.ts ? ", " + n.ts : ""})`);
                if (n.cmdLine) lines.push(`${indent}   ${n.cmdLine}`);
              });
              navigator.clipboard?.writeText?.(lines.join("\n"));
            }} title="Copy ancestry chain to clipboard" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.accent, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Copy Chain</button>}
            {!isHealthMode && !ptMode.clustered && <button onClick={() => {
              const lines = [];
              flatNodes.forEach((n) => {
                const indent = "  ".repeat(n.depth);
                const connector = n.depth > 0 ? (n.isLast ? "\u2514\u2500 " : "\u251C\u2500 ") : "";
                lines.push(`${indent}${connector}${n.processName} (PID: ${n.pid}, PPID: ${n.ppid}${n.user ? ", " + n.user : ""}${n.ts ? ", " + n.ts : ""})`);
                if (n.cmdLine) lines.push(`${indent}${n.depth > 0 ? "   " : ""}  ${n.cmdLine}`);
              });
              navigator.clipboard?.writeText?.(lines.join("\n"));
            }} title="Copy visible tree as text" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Copy Tree</button>}
            {!isHealthMode && !ptMode.clustered && <button onClick={() => {
              // Resolve parent name/path via the relinked tree when the row carries no
              // ParentImage — Security 4688 has none, EvtxECmd lacks a clean column.
              const _parentNameFor = (n) => n.parentProcessName || byKeyMap.get(n.parentKey)?.processName || "";
              const _parentImageFor = (n) => n.parentImage || byKeyMap.get(n.parentKey)?.image || "";
	              const header = ["Hostname", "LinkSource", "LinkConfidence", "LinkReason", "ParentProcessName", "ParentImagePath", "ProcessName", "PID", "PPID", "User", "Timestamp", "ImagePath", "CommandLine", "Provider", "EventID", "Elevation", "Integrity", "Depth"].join("\t");
	              const rows = flatNodes.map((n) => [
	                n.hostname || "", ptLinkMeta(n).source, ptLinkMeta(n).confidence, ptLinkMeta(n).link.reason || "", _parentNameFor(n), _parentImageFor(n), n.processName, n.pid, n.ppid, n.user || "", n.ts || "", n.image || "", n.cmdLine || "",
	                n.provider || "", n.eventId || "", n.elevation || "", n.integrity || "", n.depth
	              ].join("\t"));
	              navigator.clipboard?.writeText?.([header, ...rows].join("\n"));
	            }} title="Copy as tab-separated CSV" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Copy CSV</button>}
	            {!isHealthMode && !ptMode.clustered && ptCheckedCount > 0 && <button onClick={() => {
	              const _parentNameFor = (n) => n.parentProcessName || byKeyMap.get(n.parentKey)?.processName || "";
	              const header = ["Timestamp", "Detection", "LinkSource", "LinkConfidence", "LinkReason", "Provider", "EventID", "ParentProcess", "Process", "PID", "PPID", "User", "CommandLine", "ImagePath", "Integrity"].join("\t");
	              const rows = flatNodes.filter((n) => ptChecked.has(n.key)).map((n) => {
	                const det = (_ptDetMap.get(n.key) || {}).reason || "";
	                const lm = ptLinkMeta(n);
	                return [n.ts || "", det, lm.source, lm.confidence, lm.link.reason || "", _providerShort(n.provider), n.eventId || "", _parentNameFor(n), n.processName, n.pid, n.ppid, n.user || "", n.cmdLine || "", n.image || "", _integrityShort(n.integrity)].join("\t");
	              });
	              navigator.clipboard?.writeText?.([header, ...rows].join("\n"));
	            }} title="Copy selected rows as tab-separated" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: (th.accent) + "22", color: th.accent, border: `1px solid ${th.accent}55`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: 600 }}>Copy Selected ({ptCheckedCount})</button>}
            {/* Download CSV / JSON */}
            {!isHealthMode && !ptMode.clustered && <>
              <div style={{ width: 1, height: 14, background: th.border, flexShrink: 0 }} />
              <button onClick={() => {
                const _parentNameFor = (n) => n.parentProcessName || byKeyMap.get(n.parentKey)?.processName || "";
                const _parentImageFor = (n) => n.parentImage || byKeyMap.get(n.parentKey)?.image || "";
	                const rows = flatNodes.map((n) => {
	                  const det = _ptDetMap.get(n.key) || {};
	                  const lm = ptLinkMeta(n);
	                  return { Timestamp: n.ts || "", Hostname: n.hostname || "", Detection: det.reason || "", Severity: det.level >= 3 ? "Critical" : det.level >= 2 ? "High" : det.level >= 1 ? "Medium" : "", TriageScore: det.triageScore || "", Prevalence: det.prevalence?.rarity || "", PrevalenceSignals: det.prevalence?.signals?.join("; ") || "", LinkSource: lm.source, LinkConfidence: lm.confidence, LinkReason: lm.link.reason || "", LinkWarnings: lm.warnings.join("; "), ParentProcess: _parentNameFor(n), ParentImagePath: _parentImageFor(n), Process: n.processName || "", PID: n.pid ?? "", PPID: n.ppid ?? "", User: n.user || "", CommandLine: n.cmdLine || "", ImagePath: n.image || "", Provider: n.provider || "", EventID: n.eventId || "", Integrity: n.integrity || "" };
	                });
	                _downloadFile(_toCSV(rows), "process-inspector.csv", "text/csv");
	              }} title="Download process tree as CSV" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textMuted, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>↓ CSV</button>
              <button onClick={() => {
                const _parentNameFor = (n) => n.parentProcessName || byKeyMap.get(n.parentKey)?.processName || "";
                const _parentImageFor = (n) => n.parentImage || byKeyMap.get(n.parentKey)?.image || "";
	                const rows = flatNodes.map((n) => {
	                  const det = _ptDetMap.get(n.key) || {};
	                  return { timestamp: n.ts, hostname: n.hostname, detection: det.reason || null, severity: det.level >= 3 ? "critical" : det.level >= 2 ? "high" : det.level >= 1 ? "medium" : null, triageScore: det.triageScore || 0, prevalence: det.prevalence || null, behaviors: det.behaviors || [], link: n.link || null, parentProcess: _parentNameFor(n), parentImagePath: _parentImageFor(n), process: n.processName, pid: n.pid, ppid: n.ppid, user: n.user, commandLine: n.cmdLine, imagePath: n.image, provider: n.provider, eventId: n.eventId, integrity: n.integrity };
	                });
                _downloadFile(JSON.stringify({ exportedAt: new Date().toISOString(), processes: rows }, null, 2), "process-inspector.json", "application/json");
              }} title="Download process tree as JSON" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textMuted, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>↓ JSON</button>
            </>}
            {/* Clustered mode: Copy Chains */}
            {!isHealthMode && ptMode.clustered && <button onClick={() => {
              if (ptMode.incident) {
                navigator.clipboard?.writeText?.(filteredStories.map((s) => {
                  const lines = [
                    `[${_ptSevLabel(s.level)}] ${s.hostname ? `${s.hostname} — ` : ""}${s.leadReason}`,
                    `  Story: ${s.title}`,
                    `  Users: ${s.users.join(", ") || "—"}`,
                    `  Time: ${(s.firstSeen || "").slice(0, 19)}${s.lastSeen && s.lastSeen !== s.firstSeen ? ` — ${(s.lastSeen || "").slice(0, 19)}` : ""}`,
                    `  Events: ${s.eventCount} | Chains: ${s.chainCount}${s.sequenceCount ? ` | Sequences: ${s.sequenceCount}` : ""}`,
                  ];
                  return lines.join("\n");
                }).join("\n\n"));
                return;
              }
              navigator.clipboard?.writeText?.(filteredClusters.map(c => {
                const sev = c.level >= 3 ? "CRITICAL" : c.level >= 2 ? "HIGH" : "MEDIUM";
                return `[${sev}] ${c.reason}\n  Host: ${c.hostname} | Users: ${c.users.join(", ")}\n  Time: ${(c.firstSeen||"").slice(0,19)} \u2014 ${(c.lastSeen||"").slice(0,19)} | Count: ${c.count}\n  Cmd variants: ${c.cmdVariants.length}`;
              }).join("\n\n"));
            }} title={ptMode.incident ? "Copy all visible stories" : "Copy all visible chains"} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>{ptMode.incident ? "Copy Stories" : "Copy Chains"}</button>}
          </div>

          {isHealthMode ? (
            <ProcessTreeRuleHealthPanel
              detMap={_ptDetMap}
              seqMap={_ptSeqMap}
              disabledRules={modal.ptDisabledRules || new Set()}
              customRules={modal.ptCustomRules || []}
              th={th}
              onClose={() => setModal((p) => ({ ...p, ptViewMode: p._ptPrevViewMode || "story" }))}
              onCopy={(text) => {
                navigator.clipboard?.writeText?.(text);
                toast.success("Rule health report copied");
              }}
              onDownload={(text) => _downloadFile(text, "process-rule-health.txt", "text/plain")}
            />
          ) : (<>

          {/* Verdict-first hero — answer at a glance after build */}
          {(() => {
            const hostOptions = (() => {
              const s = new Set();
              for (const p of (data?.processes || [])) {
                const h = (p.hostname || "").trim();
                if (h) s.add(h);
              }
              return [...s].sort((a, b) => a.localeCompare(b)).slice(0, 200);
            })();
            return (
              <ProcessTreeVerdictHero
                data={data}
                detMap={_ptDetMap}
                stories={_ptIncidentStories}
                clusters={_ptChainClusters}
                th={th}
                ptMitreBadge={ptMitreBadge}
                scoring={!!modal.ptScoring || _ptScoring}
                scorePercent={modal.ptScorePercent || 0}
                truncated={!!data?.stats?.truncated}
                rebuildHost={modal.ptRebuildHost || ""}
                rebuildFrom={modal.ptRebuildFrom || ""}
                rebuildTo={modal.ptRebuildTo || ""}
                hostOptions={hostOptions}
                onRebuildChange={(patch) => setModal((p) => p ? {
                  ...p,
                  ...(patch.host != null ? { ptRebuildHost: patch.host } : {}),
                  ...(patch.from != null ? { ptRebuildFrom: patch.from } : {}),
                  ...(patch.to != null ? { ptRebuildTo: patch.to } : {}),
                } : p)}
                onRebuild={() => handleBuild({
                  host: modal.ptRebuildHost || "",
                  from: modal.ptRebuildFrom || "",
                  to: modal.ptRebuildTo || "",
                })}
              />
            );
          })()}

          {ptViewMode === "hunt" && modal.ptRareOpen && _ptPrevalenceSummary.items.length > 0 && (
            <div style={{ padding: "7px 20px", borderBottom: `1px solid ${th.border}44`, background: `${th.modalBg}aa`, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", flexShrink: 0 }}>
              <span style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700 }}>Rare Processes</span>
              <span style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace" }}>
                {_ptPrevalenceSummary.stats.rare.toLocaleString()} rare
                {_ptPrevalenceSummary.stats.uncommon ? ` · ${_ptPrevalenceSummary.stats.uncommon.toLocaleString()} uncommon` : ""}
                {_ptPrevalenceSummary.stats.rareDetected ? ` · ${_ptPrevalenceSummary.stats.rareDetected.toLocaleString()} detected` : ""}
              </span>
              {_ptPrevalenceSummary.items.slice(0, 5).map((item) => {
                const color = item.rarity === "rare" ? th.accent : th.textMuted;
                const reason = item.detectionReasons[0] || item.signals[0] || item.rarity;
                return (
                  <button key={item.key} onClick={() => setModal((p) => p ? { ...p, ptViewMode: "raw", selectedKey: item.key, ptClusterKeys: null, ptClusterContext: false } : p)}
                    title={[item.image, item.sampleCommandLine, ...item.signals].filter(Boolean).join("\n")}
                    style={{ maxWidth: 260, minWidth: 0, padding: "3px 7px", borderRadius: 4, border: `1px solid ${color}33`, background: `${color}12`, color, cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.processName}</span>
                    <span style={{ opacity: 0.75, flexShrink: 0 }}>{item.rarity}</span>
                    {item.maxDetectionLevel > 0 && <span style={{ opacity: 0.8, flexShrink: 0 }}>detected</span>}
                    {reason && <span style={{ opacity: 0.65, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 500 }}>{reason}</span>}
                  </button>
                );
              })}
              <button onClick={() => setModal((p) => p ? { ...p, ptViewMode: "raw", ptClusterKeys: null, ptClusterContext: false, ptColFilters: { ...(p.ptColFilters || {}), Prevalence: ["rare"] } } : p)} style={_ptPivotBtn}>Show Rare Only</button>
            </div>
          )}

          {/* Event Timeline — interactive dots (tree modes only) */}
          {!ptMode.graph && (() => {
            const times = flatNodes.filter(n => n.ts).map(n => ({ t: normalizeTimestamp(n.ts), key: n.key })).filter(d => Number.isFinite(d.t));
            if (times.length < 2) return null;
            const tVals = times.map(d => d.t);
            const tMin = Math.min(...tVals.slice(0, 10000));
            const tMax = Math.max(...tVals.slice(0, 10000));
            if (tMin === tMax) return null;
            const range = tMax - tMin || 1;
            // Limit dots to first 500 for rendering performance
            const dotEvents = times.slice(0, 500);
            return (
              <div style={{ padding: "8px 20px 4px", borderBottom: `1px solid ${th.border}44`, background: `${th.modalBg}99`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", flexShrink: 0 }}>
                <div style={{ fontSize: 9, color: th.textMuted, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "'SF Mono', Menlo, monospace" }}>Event Timeline</div>
                <div style={{ position: "relative", height: 40, background: `${th.bgInput}99`, borderRadius: 6, overflow: "hidden", border: `1px solid ${th.border}55` }}>
                  {/* Time axis labels */}
                  {[0, 0.25, 0.5, 0.75, 1].map((pct) => {
                    const t = new Date(tMin + range * pct);
                    return <span key={pct} style={{ position: "absolute", bottom: 2, left: `${pct * 100}%`, transform: "translateX(-50%)", fontSize: 8, color: th.textMuted + "88", fontFamily: "'SF Mono', Menlo, monospace", whiteSpace: "nowrap" }}>{t.toISOString().substr(11, 8)}</span>;
                  })}
                  {/* Event dots */}
                  {dotEvents.map((d) => {
                    const left = ((d.t - tMin) / range) * 100;
                    const nd = byKeyMap.get(d.key);
                    const pnd = nd ? byKeyMap.get(nd.parentKey) : null;
                    const isSus = nd ? (_ptDetMap.get(nd.key) || {level:0}).level > 0 : false;
                    const isSel = d.key === selectedKey;
                    return <div key={d.key} onClick={(e) => { e.stopPropagation(); setModal((p) => p ? { ...p, selectedKey: d.key } : p); }}
                      title={nd ? `${nd.processName} (PID: ${nd.pid}) \u2014 ${nd.ts}` : ""}
                      style={{ position: "absolute", left: `${left}%`, top: "38%", transform: "translate(-50%, -50%)", width: isSel ? 12 : 8, height: isSel ? 12 : 8, borderRadius: "50%", background: isSus ? (th.danger) : isSel ? (th.accent) : (th.success), border: isSel ? "2px solid #fff" : `1px solid rgba(255,255,255,0.2)`, cursor: "pointer", transition: "all var(--m-base) ease", boxShadow: isSus ? `0 0 8px ${th.danger}66` : isSel ? `0 0 8px ${th.accent}55` : "none", zIndex: isSel ? 10 : isSus ? 5 : 1 }} />;
                  })}
                </div>
              </div>
            );
          })()}

          {/* Overview strip (raw view): at-a-glance counts; severity chips toggle the severity filter */}
          {!ptMode.clustered && (
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 14px", borderTop: `1px solid ${th.border}33`, borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}66`, fontSize: 10, fontFamily: "-apple-system, sans-serif", flexShrink: 0, flexWrap: "wrap" }}>
              <span style={{ color: th.textMuted, fontWeight: 600 }}>{_ptSevCounts.total.toLocaleString()} processes</span>
              {[{ v: 3, l: "critical", n: _ptSevCounts.crit }, { v: 2, l: "high", n: _ptSevCounts.high }, { v: 1, l: "medium", n: _ptSevCounts.med }].map(({ v, l, n }) => {
                if (!n) return null;
                const col = SUS_COLORS[v] || th.danger;
                const on = ptSevFilter.includes(v);
                return (
                  <span key={v} onClick={() => setModal((p) => { const cur = Array.isArray(p.ptSevFilter) ? p.ptSevFilter : []; const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v]; return { ...p, ptSevFilter: next.length ? next : undefined }; })}
                    title={`Click to ${on ? "clear" : "show only"} ${l}`}
                    style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", borderRadius: 10, cursor: "pointer", background: on ? col + "2a" : col + "12", color: col, border: `1px solid ${col}${on ? "88" : "33"}`, fontWeight: on ? 700 : 500, transition: "all var(--m-base)" }}>
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: col }} />{n.toLocaleString()} {l}
                  </span>
                );
              })}
              <span style={{ color: th.textMuted, marginLeft: "auto", fontFamily: "'SF Mono', Menlo, monospace", fontSize: 9 }}>{_ptSevCounts.susTotal.toLocaleString()} suspicious · {_ptSevCounts.hosts} host{_ptSevCounts.hosts !== 1 ? "s" : ""} · {_ptSevCounts.users} user{_ptSevCounts.users !== 1 ? "s" : ""}</span>
            </div>
          )}

          {/* Main content: clustered card view OR tree + detail panel */}
          {ptMode.clustered ? (
          <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
            {/* Scrollable card list */}
            <div style={{ flex: 1, overflowY: "auto", padding: "8px 20px" }}>
              {ptMode.incident ? (
                <>
                  <div style={{ padding: "8px 14px", marginBottom: 8, background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22`, display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
                    <span style={{ fontWeight: 700, color: th.text }}>{filteredStories.length} stor{filteredStories.length !== 1 ? "ies" : "y"}</span>
                    {filteredStoryStats.critical > 0 && <span style={_ptSevPill(th.sev.critical)}>{filteredStoryStats.critical} critical</span>}
                    {filteredStoryStats.high > 0 && <span style={_ptSevPill(th.sev.high)}>{filteredStoryStats.high} high</span>}
                    {filteredStoryStats.medium > 0 && <span style={_ptSevPill(th.sev.med)}>{filteredStoryStats.medium} medium</span>}
                    <span style={{ color: th.textMuted }}>|</span>
                    <span style={{ color: th.textDim }}>{filteredStoryStats.susProcesses} suspicious events</span>
                    {filteredStoryStats.sequences > 0 && <span style={{ color: th.textDim }}>{filteredStoryStats.sequences} sequence hits</span>}
                    {filteredStoryStats.hosts > 0 && <span style={{ color: th.textDim }}>{filteredStoryStats.hosts} host{filteredStoryStats.hosts !== 1 ? "s" : ""}</span>}
                    {filteredStoryStats.users > 0 && <span style={{ color: th.textDim }}>{filteredStoryStats.users} user{filteredStoryStats.users !== 1 ? "s" : ""}</span>}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {filteredStories.map((story) => {
                      const isExp = modal._ptExpandedIncident === story.id;
                      const susColor = SUS_COLORS[story.level] || th.textMuted;
                      return (
                        <div key={story.id} style={{ borderRadius: 8, border: `1px solid ${susColor}${isExp ? "44" : "22"}`, background: `${susColor}${isExp ? "0c" : "04"}`, cursor: "pointer", transition: "border-color var(--m-base)" }}
                          onClick={() => setModal((p) => ({ ...p, _ptExpandedIncident: isExp ? null : story.id, selectedKey: story.anchorKey || p.selectedKey }))}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 10px", minHeight: 34, flexWrap: "wrap" }}>
                            <span style={{ padding: "1px 6px", background: susColor + "22", color: susColor, borderRadius: 3, fontSize: PI_TYPOGRAPHY.badge, fontWeight: 700, textTransform: "uppercase", fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{_ptSevLabel(story.level)}</span>
                            <span style={{ fontSize: PI_TYPOGRAPHY.title, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{story.title}</span>
                            <span style={{ fontSize: PI_TYPOGRAPHY.body, color: th.textDim, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={story.narrative}>{story.leadReason}</span>
                            {story.hostname && <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, flexShrink: 0 }}>{story.hostname}</span>}
	                            {story.users.length > 0 && <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, flexShrink: 0 }}>{story.users[0]}{story.users.length > 1 ? ` +${story.users.length - 1}` : ""}</span>}
	                            {story.prevalenceSignals?.length > 0 && <span title={story.prevalenceSignals.join("\n")} style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: th.accent + "18", color: th.accent, fontWeight: 600, flexShrink: 0 }}>rare</span>}
	                            <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontWeight: 600, flexShrink: 0 }}>{story.eventCount} suspicious</span>
                            {story.contextOnlyCount > 0 && <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontWeight: 500, flexShrink: 0 }}>{story.contextEventCount} with context</span>}
                            <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>{story.chainCount} chains{story.sequenceCount ? ` · ${story.sequenceCount} seq` : ""}</span>
                            {story.durationLabel && <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>{story.durationLabel}</span>}
                            <span style={{ fontSize: PI_TYPOGRAPHY.badge, color: th.textMuted, flexShrink: 0 }}>{isExp ? "\u25BC" : "\u25B6"}</span>
                          </div>
                          {isExp && (
                            <div style={{ padding: "8px 10px 10px", borderTop: `1px solid ${susColor}22` }} onClick={(e) => e.stopPropagation()}>
                              <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: 6, display: "flex", gap: 12, flexWrap: "wrap" }}>
                                <span>{story.hostname}{story.users.length ? ` (${story.users.join(", ")})` : ""}</span>
                                <span>{(story.firstSeen || "").slice(0, 19)}{story.lastSeen && story.lastSeen !== story.firstSeen ? ` \u2014 ${(story.lastSeen || "").slice(0, 19)}` : ""}</span>
                                <span>{story.eventCount} suspicious event{story.eventCount !== 1 ? "s" : ""}</span>
                                {story.contextOnlyCount > 0 && <span>{story.contextEventCount} total in context</span>}
	                                {story.rootNames.length > 0 && <span>Roots: {story.rootNames.slice(0, 2).join(", ")}{story.rootNames.length > 2 ? ` +${story.rootNames.length - 2}` : ""}</span>}
	                                {story.prevalenceSignals?.length > 0 && <span>Prevalence: {story.prevalenceSignals.slice(0, 2).join(", ")}{story.prevalenceSignals.length > 2 ? ` +${story.prevalenceSignals.length - 2}` : ""}</span>}
	                              </div>
                              <div style={{ marginBottom: 8, fontSize: PI_TYPOGRAPHY.body, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>
                                {story.narrative}
                              </div>
                              {story.steps.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>Storyline</div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                                    {story.steps.map((step) => (
                                      <div key={step.key} onClick={() => setModal((p) => ({ ...p, selectedKey: step.key }))}
                                        style={{ display: "flex", alignItems: "center", gap: 6, fontSize: PI_TYPOGRAPHY.control, fontFamily: "'SF Mono', Menlo, monospace", color: th.textDim, padding: "3px 5px", borderRadius: 4, background: step.key === selectedKey ? `${th.accent}15` : `${th.border}10`, cursor: "pointer", border: step.key === selectedKey ? `1px solid ${th.accent}33` : `1px solid ${th.border}11` }}>
                                        <span style={{ minWidth: 126, color: th.textMuted, flexShrink: 0 }}>{(step.ts || "").slice(0, 19) || "Unknown time"}</span>
                                        <span style={{ color: th.text, flexShrink: 0 }}>{step.parent} {"\u2192"} {step.child}</span>
                                        <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{step.reason}</span>
                                        {step.isContext && <span style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontWeight: 600, flexShrink: 0 }}>CTX</span>}
                                        {step.sequences?.length > 0 && <span style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: th.sev.critical + "18", color: th.sev.critical, fontWeight: 600, flexShrink: 0 }}>{step.sequences[0]}</span>}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {story.sequences.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>Behavioral Sequences</div>
                                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                    {story.sequences.map((seq) => (
                                      <span key={seq.seqId} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${seq.confidence === "high" ? th.sev.critical : th.sev.high}18`, color: seq.confidence === "high" ? th.sev.critical : th.sev.high, border: `1px solid ${seq.confidence === "high" ? th.sev.critical : th.sev.high}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>
                                        {seq.name} {seq.count > 1 ? `(${seq.count})` : ""}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {story.techniques.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>ATT&CK</div>
                                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                    {story.techniques.map((tid) => ptMitreBadge(tid))}
                                  </div>
                                </div>
                              )}
                              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                <button onClick={() => setModal((p) => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(story.allKeys), ptClusterContext: false, selectedKey: story.anchorKey || p.selectedKey }))} style={_ptPivotBtn}>View Flat</button>
                                <button onClick={() => setModal((p) => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(story.contextKeys || story.allKeys), ptClusterContext: true, selectedKey: story.anchorKey || p.selectedKey }))} style={_ptPivotBtn}>View in Context</button>
                                <button onClick={() => setModal((p) => ({ ...p, ptViewMode: "graph", searchText: "", ptClusterKeys: new Set(story.contextKeys || story.allKeys), selectedKey: story.anchorKey || p.selectedKey }))} style={_ptPivotBtn}>View Graph</button>
                                <button onClick={() => _ptCopyStory(story)} style={_ptPivotBtn}>Copy Story</button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                    {filteredStories.length === 0 && (
                      <div style={{ padding: "40px 20px", textAlign: "center", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.body }}>
                        No investigation stories built from current detections
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <>
                  {/* Summary strip */}
                  <div style={{ padding: "8px 14px", marginBottom: 8, background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22`, display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
                    <span style={{ fontWeight: 700, color: th.text }}>{filteredClusters.length} chain{filteredClusters.length !== 1 ? "s" : ""}</span>
                    {filteredStats.critical > 0 && <span style={_ptSevPill(th.sev.critical)}>{filteredStats.critical} critical</span>}
                    {filteredStats.high > 0 && <span style={_ptSevPill(th.sev.high)}>{filteredStats.high} high</span>}
                    {filteredStats.medium > 0 && <span style={_ptSevPill(th.sev.med)}>{filteredStats.medium} medium</span>}
                    <span style={{ color: th.textMuted }}>|</span>
                    <span style={{ color: th.textDim }}>{filteredStats.susProcesses} suspicious events</span>
                    {filteredStats.hosts > 0 && <span style={{ color: th.textDim }}>{filteredStats.hosts} host{filteredStats.hosts !== 1 ? "s" : ""}</span>}
                    {filteredStats.users > 0 && <span style={{ color: th.textDim }}>{filteredStats.users} user{filteredStats.users !== 1 ? "s" : ""}</span>}
                  </div>
                  {/* Cluster cards */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                    {filteredClusters.map(cl => {
                      const isExp = modal._ptExpandedCluster === cl.id;
                      const susColor = SUS_COLORS[cl.level] || th.textMuted;
                      return (
                        <div key={cl.id} style={{ borderRadius: 6, border: `1px solid ${susColor}${isExp ? "44" : "22"}`, background: `${susColor}${isExp ? "0a" : "04"}`, cursor: "pointer", transition: "border-color var(--m-base)" }}
                          onClick={() => setModal(p => ({ ...p, _ptExpandedCluster: isExp ? null : cl.id, selectedKey: cl.members[0]?.key || p.selectedKey }))}>
                          {/* Collapsed summary row */}
                          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 10px", minHeight: 28, flexWrap: "wrap" }}>
                            <span style={{ padding: "1px 6px", background: susColor + "22", color: susColor, borderRadius: 3, fontSize: PI_TYPOGRAPHY.badge, fontWeight: 700, textTransform: "uppercase", fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{_ptSevLabel(cl.level)}</span>
                            {cl.mitreId && <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 600, fontFamily: "SF Mono, monospace", flexShrink: 0 }}>{cl.mitreId}</span>}
                            <span style={{ fontSize: PI_TYPOGRAPHY.title, fontWeight: 600, color: th.text, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>{cl.displayParent} {"\u2192"} {cl.displayChild}</span>
                            <span style={{ fontSize: PI_TYPOGRAPHY.body, fontWeight: 500, color: th.textDim, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={cl.displayReason}>{cl.displayReason}</span>
                            {cl.cmdTemplate && <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 200 }} title={cl.cmdTemplate}>{cl.cmdTemplate}</span>}
                            {cl.hostname && <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, flexShrink: 0 }}>{cl.hostname}</span>}
	                            {cl.count > 1 && <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontWeight: 600, flexShrink: 0 }}>{cl.count}x</span>}
	                            {(cl.rareCount > 0 || cl.uncommonCount > 0) && <span title={(cl.prevalenceSignals || []).join("\n")} style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: th.accent + "18", color: th.accent, fontWeight: 600, flexShrink: 0 }}>{cl.rareCount > 0 ? `${cl.rareCount} rare` : `${cl.uncommonCount} uncommon`}</span>}
	                            {cl.users.length > 1 && <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, flexShrink: 0 }}>{cl.users.length} users</span>}
                            <span style={{ fontSize: PI_TYPOGRAPHY.badge, color: th.textMuted, flexShrink: 0 }}>{isExp ? "\u25BC" : "\u25B6"}</span>
                          </div>
                          {/* Expanded detail */}
                          {isExp && (
                            <div style={{ padding: "8px 10px 10px", borderTop: `1px solid ${susColor}22` }} onClick={e => e.stopPropagation()}>
                              {/* Meta row */}
                              <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: 6, display: "flex", gap: 12, flexWrap: "wrap" }}>
                                <span>{cl.hostname}{cl.users.length > 0 ? ` (${cl.users.join(", ")})` : ""}</span>
	                                <span>{(cl.firstSeen || "").slice(0, 19)}{cl.lastSeen && cl.lastSeen !== cl.firstSeen ? ` \u2014 ${cl.lastSeen.slice(0, 19)}` : ""}</span>
	                                <span>{cl.count} occurrence{cl.count !== 1 ? "s" : ""}</span>
	                                {cl.prevalenceSignals?.length > 0 && <span>Prevalence: {cl.prevalenceSignals.slice(0, 2).join(", ")}{cl.prevalenceSignals.length > 2 ? ` +${cl.prevalenceSignals.length - 2}` : ""}</span>}
	                              </div>
                              {/* Command variants */}
                              {cl.cmdVariants.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>Command Variants ({cl.cmdVariants.length})</div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 100, overflowY: "auto" }}>
                                    {cl.cmdVariants.map((cmd, ci) => (
                                      <div key={ci} style={{ fontSize: 9, fontFamily: "'SF Mono', Menlo, monospace", color: th.danger, padding: "2px 4px", borderRadius: 3, background: `${th.accent}08`, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={cmd}>{cmd}</div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {/* All occurrences */}
                              {cl.count > 1 && (() => {
                                const showLimit = modal._ptClusterShowAll === cl.id ? cl.members.length : 50;
                                const visible = cl.members.slice(0, showLimit);
                                const hasMore = cl.members.length > showLimit;
                                const hasHidden = cl.count > cl.members.length;
                                return (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>All Occurrences{cl.count > visible.length ? ` (showing ${visible.length} of ${cl.count})` : ""}</div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: 1, maxHeight: modal._ptClusterShowAll === cl.id ? 400 : 150, overflowY: "auto" }}>
                                    {visible.map((m, mi) => (
                                      <div key={m.key} onClick={e => { e.stopPropagation(); setModal(p => ({ ...p, selectedKey: m.key })); }}
                                        style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 9, fontFamily: "'SF Mono', Menlo, monospace", color: th.textDim, padding: "2px 4px", borderRadius: 3, background: m.key === selectedKey ? `${th.accent}15` : mi % 2 === 0 ? "transparent" : `${th.border}11`, cursor: "pointer", border: m.key === selectedKey ? `1px solid ${th.accent}33` : "1px solid transparent" }}>
                                        <span style={{ minWidth: 130, color: th.textMuted, flexShrink: 0 }}>{(m.ts || "").slice(0, 19)}</span>
                                        <span style={{ minWidth: 70, flexShrink: 0 }}>{m.user || ""}</span>
                                        <span style={{ color: th.text, flexShrink: 0 }}>{m.parentProcessName} {"\u2192"} {m.processName}</span>
                                        <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textMuted }}>{m.cmdLine || ""}</span>
                                      </div>
                                    ))}
                                  </div>
                                  {(hasMore || hasHidden) && (
                                    <div style={{ display: "flex", gap: 4, marginTop: 4 }}>
                                      {hasMore && <button onClick={e => { e.stopPropagation(); setModal(p => ({ ...p, _ptClusterShowAll: cl.id })); }} style={_ptPivotBtn}>Show All ({cl.members.length})</button>}
                                      {hasHidden && <button onClick={e => { e.stopPropagation(); setModal(p => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(cl.allKeys), ptClusterContext: true, selectedKey: cl.members[0]?.key || p.selectedKey })); }} style={_ptPivotBtn}>View All {cl.count} in Context</button>}
                                    </div>
                                  )}
                                </div>
                                );
                              })()}
                              {/* Pivot buttons */}
                              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                <button onClick={() => setModal(p => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(cl.allKeys), ptClusterContext: false, selectedKey: cl.members[0]?.key || p.selectedKey }))} style={_ptPivotBtn}>View Flat</button>
                                <button onClick={() => setModal(p => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(cl.allKeys), ptClusterContext: true, selectedKey: cl.members[0]?.key || p.selectedKey }))} style={_ptPivotBtn}>View in Context</button>
                                <button onClick={() => setModal(p => ({ ...p, ptViewMode: "graph", searchText: "", ptClusterKeys: new Set(cl.allKeys), selectedKey: cl.members[0]?.key || p.selectedKey }))} style={_ptPivotBtn}>View Graph</button>
                                <button onClick={() => {
                                  const sev = cl.level >= 3 ? "CRITICAL" : cl.level >= 2 ? "HIGH" : "MEDIUM";
                                  const lines = [`[${sev}] ${cl.reason}`, `Host: ${cl.hostname}`, `Users: ${cl.users.join(", ")}`, `Time: ${(cl.firstSeen || "").slice(0, 19)} \u2014 ${(cl.lastSeen || "").slice(0, 19)}`, `Occurrences: ${cl.count}`, "", "Command Variants:", ...cl.cmdVariants.map(c => `  ${c}`)];
                                  navigator.clipboard?.writeText?.(lines.join("\n"));
                                }} style={_ptPivotBtn}>Copy IOC</button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                    {filteredClusters.length === 0 && (
                      <div style={{ padding: "40px 20px", textAlign: "center", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.body }}>
                        No suspicious chains found{ptViewMode === "triage" ? " \u2014 try Hunt or Raw mode" : ""}
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
            {/* Right detail panel — reused for selected member node */}
            {(() => {
              const detailW = modal.ptDetailW || 380;
              const selNode = selectedKey ? byKeyMap.get(selectedKey) : null;
              if (!selNode) return (
                <div style={{ width: detailW, borderLeft: `1px solid ${th.border}44`, background: `${th.modalBg}cc`, flexShrink: 0, display: "flex", flexDirection: "column" }}>
                  <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}88`, fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace" }}>Event Details</div>
                  <div style={{ padding: 40, textAlign: "center", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.body }}>Click an occurrence to view details</div>
                </div>
              );
	              const parentNode = byKeyMap.get(selNode.parentKey);
	              const selSusInfo = _ptDetMap.get(selectedKey) || { level: 0, reason: null };
	              const selSusColor = SUS_COLORS[selSusInfo.level];
	              const selLink = ptLinkMeta(selNode);
	              const selPrev = selSusInfo.prevalence || null;
	              const nodeCluster = _ptNodeClusterMap.get(selectedKey);
              const gLbl = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.control, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", paddingTop: 2 };
              const gVal = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.body, color: th.text, wordBreak: "break-all", lineHeight: 1.5 };
              const fields = [
                ["Timestamp", selNode.ts ? selNode.ts.replace("T", " ").substring(0, 19) : ""],
                ["Process", selNode.processName], ["Full Path", selNode.image],
	                ["PID", selNode.pid], ["PPID", selNode.ppid],
	                ["Parent", parentNode ? parentNode.processName : ""],
	                ["Parent Link", `${selLink.label}${selLink.confidence ? ` (${selLink.confidence})` : ""}`],
	                ["Link Reason", selLink.link.reason],
	                ["Link Warnings", selLink.warnings.join(", ")],
	                ["Prevalence", selPrev ? `${selPrev.rarity}${selPrev.scoreBoost ? ` (+${selPrev.scoreBoost})` : ""}` : ""],
	                ["Prevalence Signals", selPrev?.signals?.join(", ")],
	                ["User", selNode.user], ["Command Line", selNode.cmdLine],
                ["Provider", _providerShort(selNode.provider)], ["Event ID", selNode.eventId],
              ].filter(([, v]) => v);
              return (
                <div style={{ width: detailW, borderLeft: `1px solid ${th.border}44`, background: `${th.modalBg}cc`, flexShrink: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                  <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}aa`, fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>Event Details</div>
                  <div style={{ padding: "12px 16px 8px", borderBottom: `1px solid ${th.border}33`, flexShrink: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
	                      {ptIcon(selNode.processName)}
	                      <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, fontSize: PI_TYPOGRAPHY.heading, color: selSusColor || th.text }}>{selNode.processName}</span>
	                      <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.body, color: th.textMuted }}> PID {selNode.pid}</span>
	                      <span title={selLink.title} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${selLink.color}18`, color: selLink.color, border: `1px solid ${selLink.color}33`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, textTransform: "uppercase" }}>{selLink.label}</span>
	                      {selPrev?.signals?.length > 0 && <span title={selPrev.signals.join("\n")} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: th.accent + "18", color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, textTransform: "uppercase" }}>{selPrev.rarity}</span>}
	                    </div>
                    {selSusInfo.reason && <div style={{ marginBottom: 6 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: 4, background: `${selSusColor}22`, color: selSusColor, padding: "2px 8px", borderRadius: 3, fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${selSusColor}44` }}>{"\u26A0"} {selSusInfo.reason}</span>
                        {selSusInfo.confidence && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: selSusInfo.confidence === "confirmed" ? th.sev.critical + "22" : selSusInfo.confidence === "likely" ? th.sev.high + "22" : th.sev.low + "22", color: selSusInfo.confidence === "confirmed" ? th.sev.critical : selSusInfo.confidence === "likely" ? th.sev.high : th.sev.low, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${selSusInfo.confidence === "confirmed" ? th.sev.critical + "44" : selSusInfo.confidence === "likely" ? th.sev.high + "44" : th.sev.low + "44"}`, textTransform: "uppercase", letterSpacing: "0.05em" }}>{selSusInfo.confidence}</span>}{selSusInfo.triageScore > 0 && <span title={`Triage score ${selSusInfo.triageScore} — composite priority: severity×100 + confidence + prevalence/lifetime/trust boosts. Higher = investigate first.`} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${selSusColor}1a`, color: selSusColor, border: `1px solid ${selSusColor}44`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, letterSpacing: "0.04em" }}>SCORE {selSusInfo.triageScore}</span>}
                        {selSusInfo.sanctioned && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.clean + "18", color: th.sev.clean, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${th.sev.clean}33`, letterSpacing: "0.03em" }}>SANCTIONED {selSusInfo.sanctioned.cat.toUpperCase()}</span>}
                        {(() => { const seqs = _ptSeqMap.get(selectedKey); if (!seqs?.length) return null; const best = seqs.reduce((a, b) => a.confidence === "high" ? a : b); const sc = best.confidence === "high" ? th.sev.critical : th.sev.high; return <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${sc}aa`, color: "#fff", fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, letterSpacing: "0.03em" }}>SEQ {best.confidence === "high" ? "\u2191" : "\u2193"}</span>; })()}
                        {(() => { const ev = selSusInfo.evidence; if (!ev || ev.length <= 1) return null; const pc = ev.filter(e => e.cat !== "context").length - 1; const cc = ev.filter(e => e.cat === "context").length; const parts = []; if (pc > 0) parts.push(`${pc} primary`); if (cc > 0) parts.push(`${cc} context`); return parts.length ? <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>+{parts.join(" + ")}</span> : null; })()}
                      </div>
                      {selSusInfo.evidence?.length > 1 && (() => {
                        const rest = selSusInfo.evidence.filter(e => e.reason !== selSusInfo.reason);
                        const prim = rest.filter(e => e.cat !== "context");
                        const ctxs = rest.filter(e => e.cat === "context");
                        return <div style={{ marginTop: 4, display: "flex", flexWrap: "wrap", gap: 3, alignItems: "center" }}>
                          {prim.map((e, i) => { const eColor = SUS_COLORS[e.level] || th.sev.low; return <span key={`p${i}`} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${eColor}14`, color: eColor, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${eColor}22` }}>{e.cat === "chain" ? "chain: " : ""}{e.reason}{e.tid?.length ? ` [${e.tid.join(", ")}]` : ""}</span>; })}
                          {prim.length > 0 && ctxs.length > 0 && <span style={{ color: th.border, fontSize: 10, margin: "0 2px" }}>{"\u00B7"}</span>}
                          {ctxs.map((e, i) => { const eColor = e.dampen ? th.textDim : th.sev.low; return <span key={`c${i}`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${eColor}0a`, color: eColor, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${eColor}18`, fontStyle: "italic" }}>{e.dampen ? "\u25BC " : ""}{e.reason}</span>; })}
                        </div>;
                      })()}
                      {selSusInfo.techniques?.length > 0 && <div style={{ marginTop: 3, display: "flex", gap: 3, flexWrap: "wrap" }}>
                        {selSusInfo.techniques.map((t) => ptMitreBadge(t))}
                      </div>}
                    </div>}
                  </div>
                  <div style={{ overflow: "auto", flex: 1, padding: 16 }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                      {fields.map(([label, value]) => (
                        <div key={label} style={{ display: "grid", gridTemplateColumns: "110px 1fr", padding: "6px 0", borderBottom: `1px solid ${th.border}22` }}>
                          <span style={gLbl}>{label}</span>
                          <span style={{ ...gVal, color: label === "Command Line" ? (th.danger) : th.text, background: label === "Command Line" ? `${th.accent}08` : "transparent", padding: label === "Command Line" ? "4px 6px" : "0", borderRadius: label === "Command Line" ? 3 : 0 }}>{label === "Command Line" ? ptHighlightCmd(value) : (value || "\u2014")}</span>
                        </div>
                      ))}
                    </div>
                    {ptDecodePanel(selNode.cmdLine, gLbl)}
                    {/* Behavioral Sequence */}
                    {(() => {
                      const seqs = _ptSeqMap.get(selectedKey);
                      if (!seqs?.length) return null;
                      const seqConfColor = { high: th.sev.critical, medium: th.sev.high };
                      return (
                        <div style={{ marginTop: 12, padding: "8px 10px", background: th.sev.critical + "12", borderRadius: 6, border: `1px solid ${th.sev.critical}22` }}>
                          <div style={{ ...gLbl, marginBottom: 4, color: th.sev.critical }}>Behavioral Sequence</div>
                          {seqs.map((s, i) => {
                            const sc = seqConfColor[s.confidence] || th.sev.low;
                            return (
                            <div key={i} style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: i < seqs.length - 1 ? 6 : 0 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                                <span style={{ color: sc, fontWeight: 600 }}>{s.seqName}</span>
                                <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: `${sc}18`, color: sc, border: `1px solid ${sc}33` }}>{s.stageName}</span>
                                <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: `${sc}18`, color: sc, border: `1px solid ${sc}33`, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>{s.confidence}</span>
                              </div>
                              <div style={{ marginTop: 2, fontSize: 9, color: th.textMuted }}>{s.confidence === "high" ? "same tree" : "same host/user"} \u2014 {s.peers.length} processes {s.tid?.length ? `\u2014 ${s.tid.join(", ")}` : ""}</div>
                            </div>
                          ); })}
                        </div>
                      );
                    })()}
                    {(() => {
                      const nodeStory = _ptNodeStoryMap.get(selectedKey);
                      if (!nodeStory) return null;
                      return (
                        <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                          <div style={{ ...gLbl, marginBottom: 4 }}>Investigation Story</div>
                          <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45, marginBottom: 6 }}>
                            {nodeStory.narrative}
                          </div>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                            <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.eventCount} events</span>
                            <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.chainCount} chains</span>
                            {nodeStory.sequenceCount > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.critical + "18", color: th.sev.critical, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.sequenceCount} seq</span>}
                          </div>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                            <button onClick={() => setModal((p) => ({ ...p, ptViewMode: "story", _ptExpandedIncident: nodeStory.id, selectedKey: nodeStory.anchorKey || selectedKey }))} style={_ptPivotBtn}>View Story</button>
                            <button onClick={() => _ptCopyStory(nodeStory)} style={_ptPivotBtn}>Copy Story</button>
                          </div>
                        </div>
                      );
                    })()}
                    {/* Chain Context */}
                    {nodeCluster && nodeCluster.count > 1 && (
                      <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                        <div style={{ ...gLbl, marginBottom: 4 }}>Chain Context</div>
                        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", display: "flex", flexDirection: "column", gap: 3 }}>
                          <div>Repeated <strong style={{ color: th.accent }}>{nodeCluster.count}x</strong> across {nodeCluster.users.length} user{nodeCluster.users.length !== 1 ? "s" : ""}</div>
                          <div>First: {(nodeCluster.firstSeen || "").slice(0, 19)} {"\u2014"} Last: {(nodeCluster.lastSeen || "").slice(0, 19)}</div>
                          <div>{nodeCluster.cmdVariants.length} command variant{nodeCluster.cmdVariants.length !== 1 ? "s" : ""}</div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
          ) : (
          <div style={{ display: "flex", flex: 1, minHeight: 0 }}>

          {/* Graph view — spatial parent-child layout (multi-host swimlanes) */}
          {ptMode.graph ? (
            <ProcessGraphView
              processes={data.processes}
              detMap={_ptDetMap}
              byKeyMap={byKeyMap}
              childMap={childMap}
              selectedKey={selectedKey}
              focusKeys={modal.ptClusterKeys || null}
              minLevel={modal.ptGraphMinLevel ?? (ptSevFilter.length ? Math.min(...ptSevFilter) : 1)}
              th={th}
              ptIcon={ptIcon}
              onSelect={(key) => setModal((p) => p ? { ...p, selectedKey: p.selectedKey === key ? null : key } : p)}
            />
          ) : (
          /* Column headers + Tree — virtualized */
          (() => {
            const PT_ROW_H = modal.ptDensity === "compact" ? 26 : 34, OVERSCAN = 8;
            const ptST = ptScroll.top;
            const ptCH = ptScroll.h;
            const totalRows = flatNodes.length;
            const totalH = totalRows * PT_ROW_H;
            const startIdx = Math.max(0, Math.floor(ptST / PT_ROW_H) - OVERSCAN);
            const endIdx = Math.min(totalRows, Math.ceil((ptST + ptCH) / PT_ROW_H) + OVERSCAN);
            const visibleSlice = flatNodes.slice(startIdx, endIdx);
            const hasFindingsRail = flatNodes.length > 40 && !!_ptRail;
            const rawDetailW = modal.ptDetailW || 380;
            const rawAvailableW = Math.max(
              480,
              (Number(pw) || 1200) - rawDetailW - 4 - (hasFindingsRail ? 11 : 0),
            );
            const rawColWidths = ptColWidths || fitProcessRawColumnWidths(
              ptDefWidths,
              ptHeaders,
              rawAvailableW,
              PT_CHK_W + 50,
            );
            const rawTotalPtW = processRawGridWidth(rawColWidths, ptHeaders, PT_CHK_W + 50);
            const rawColumnStyle = (header) => {
              const width = rawColWidths[header] || ptDefWidths[header];
              return {
                width,
                minWidth: width,
                maxWidth: width,
                flex: `0 0 ${width}px`,
                boxSizing: "border-box",
              };
            };

            return (
              <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0, minWidth: 0, overflow: "hidden" }}>
                {/* Fixed column header — OUTSIDE scroll container to prevent overlap */}
                <div ref={ptHeaderRef} style={{ flexShrink: 0, overflowX: "hidden", marginRight: hasFindingsRail ? 11 : 0, backgroundColor: th.modalBg, backgroundImage: `linear-gradient(180deg, ${th.accent}22 0%, transparent 100%)`, borderBottom: `2px solid ${th.accent}55`, boxShadow: `0 2px 8px ${th.accent}18` }}>
                  {/* Filter active indicator */}
                  {ptActiveFilterCount > 0 && (
                    <div style={{ padding: "4px 12px", display: "flex", alignItems: "center", gap: 8, borderBottom: `1px solid ${th.border}33`, boxShadow: `inset 3px 0 0 ${th.accent}`, width: rawTotalPtW, minWidth: rawTotalPtW, boxSizing: "border-box" }}>
                      <span style={{ fontSize: 10, fontWeight: 600, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>Filter active ({ptActiveFilterCount} column{ptActiveFilterCount > 1 ? "s" : ""})</span>
                      <span style={{ fontSize: 10, color: th.textDim }}>{"\u2014"} {flatNodes.length} of {data.stats.totalProcesses} processes</span>
                      <button onClick={() => setModal((p) => ({ ...p, ptColFilters: {} }))} style={{ padding: "1px 8px", fontSize: 9, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Clear All</button>
                    </div>
                  )}
                  {/* Column header row */}
                  <div style={{ display: "flex", width: rawTotalPtW, minWidth: rawTotalPtW }}>
                    {/* Select-all checkbox */}
                    <div style={{ width: PT_CHK_W, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", boxSizing: "border-box" }}>
                      <input type="checkbox" checked={flatNodes.length > 0 && ptCheckedCount === flatNodes.length} ref={(el) => { if (el) el.indeterminate = ptCheckedCount > 0 && ptCheckedCount < flatNodes.length; }}
                        onChange={() => { setModal((p) => { if (!p) return p; const cur = p.ptChecked || new Set(); if (cur.size === flatNodes.length) return { ...p, ptChecked: new Set() }; return { ...p, ptChecked: new Set(flatNodes.map((n) => n.key)) }; }); }}
                        style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} title="Select all" />
                    </div>
                    {ptHeaders.map((h) => (
                      <div key={h} onClick={() => togglePtSort(h)} style={{ ...rawColumnStyle(h), padding: h === "Process" ? `9px 8px 9px ${PI_RAW_TREE_LAYOUT.headerInset}px` : "9px 8px", fontSize: PI_TYPOGRAPHY.control, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, color: (ptSortCol || "Timestamp") === h ? th.accent : `${th.accent}99`, textTransform: "uppercase", letterSpacing: "0.08em", whiteSpace: "nowrap", overflow: "hidden", userSelect: "none", position: "relative", cursor: "pointer" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 3 }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{h}</span>
                          {(ptSortCol || "Timestamp") === h && <span style={{ fontSize: 7, color: th.accent }}>{(ptSortDir || "asc") === "asc" ? "\u25B2" : "\u25BC"}</span>}
                          <span onClick={(e) => { e.stopPropagation(); openPtFilter(h, e); }} style={{ cursor: "pointer", fontSize: 7, color: ptColFilters[h] ? (th.accent) : (th.textDim) + "66", flexShrink: 0, marginLeft: "auto", paddingRight: 8 }}>{"\u25BC"}</span>
                          <div onMouseDown={(e) => { e.stopPropagation(); onPtResizeStart(h, e, rawColWidths); }} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 6, cursor: "col-resize" }}>
                            <div style={{ position: "absolute", right: 2, top: 4, bottom: 4, width: 1, background: `${th.accent}44` }} />
                          </div>
                        </div>
                      </div>
                    ))}
                    <div style={{ width: 50, flexShrink: 0, padding: "6px 4px", fontSize: 9, fontFamily: "-apple-system, sans-serif", color: th.textDim, userSelect: "none" }} />
                  </div>
                </div>
                {/* Scrollable rows (+ findings minimap rail) — header stays fixed above */}
                <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
                <div ref={ptScrollRef} onScroll={(e) => {
                  const el = e.currentTarget;
                  const st = el.scrollTop;
                  const ch = el.clientHeight;
                  if (ptHeaderRef.current) ptHeaderRef.current.scrollLeft = el.scrollLeft;
                  if (ptRafRef.current) cancelAnimationFrame(ptRafRef.current);
                  ptRafRef.current = requestAnimationFrame(() => {
                    setPtScroll((p) => {
                      const oldStart = Math.floor(p.top / PT_ROW_H);
                      const newStart = Math.floor(st / PT_ROW_H);
                      if (newStart === oldStart && p.h === ch) return p;
                      return { top: st, h: ch };
                    });
                  });
                }} style={{ flex: 1, overflowY: "auto", overflowX: "auto", minHeight: 0, contain: "strict", willChange: "transform" }}>
                {/* Virtualized tree rows */}
                {flatNodes.length === 0 && (
                  <div style={{ padding: 20, textAlign: "center", color: th.textDim, fontSize: PI_TYPOGRAPHY.body }}>{searchText ? "No matching processes" : "No process creation events found"}</div>
                )}
                {flatNodes.length > 0 && (
                  <div style={{ height: totalH, position: "relative", width: rawTotalPtW, minWidth: rawTotalPtW, contain: "layout size" }}>
                    <div style={{ position: "absolute", top: startIdx * PT_ROW_H, left: 0, right: 0 }}>
                      {visibleSlice.map((node, vi) => {
                        const i = startIdx + vi;
                        const susInfo = _ptDetMap.get(node.key) || { level: 0, reason: null };
                        const sus = susInfo.level;
                        const susColor = SUS_COLORS[sus];
                        const hasChildren = node.childCount > 0;
                        const isExpanded = !!expandedNodes[node.key];
                        const tsDisplay = (node.ts || "").replace("T", " ").substring(0, 19);
                        const inChain = chainKeys.has(node.key);
                        const isSelected = node.key === selectedKey;
                        const lineColor = th.textMuted || th.textDim;
                        const chainColor = th.accent;
                        const INDENT = PI_RAW_TREE_LAYOUT.indent;
                        const LEFT_PAD = PI_RAW_TREE_LAYOUT.leftPad;

                        return (
                          <div key={node.key + ":" + i}
                            onClick={() => setModal((p) => p ? { ...p, selectedKey: p.selectedKey === node.key ? null : node.key } : p)}
                            className={isSelected ? "pt-row pt-sel" : "pt-row"}
                            style={{ display: "flex", width: rawTotalPtW, minWidth: rawTotalPtW, height: PT_ROW_H, boxSizing: "border-box", fontSize: PI_TYPOGRAPHY.body, fontFamily: "'SF Mono', Menlo, monospace", cursor: "pointer", background: isSelected ? (th.accent) + "10" : susColor && !inChain ? susColor + "06" : "transparent", borderBottom: `1px solid ${th.border}18`, boxShadow: `inset 2px 0 0 ${isSelected ? chainColor : susColor ? susColor + "55" : "transparent"}`, alignItems: "center", minHeight: PT_ROW_H, contain: "layout style" }}>

                            {/* Row checkbox */}
                            <div style={{ width: PT_CHK_W, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", boxSizing: "border-box" }}>
                              <input type="checkbox" checked={ptChecked.has(node.key)}
                                onClick={(e) => e.stopPropagation()}
                                onChange={() => { setModal((p) => { if (!p) return p; const s = new Set(p.ptChecked || []); if (s.has(node.key)) s.delete(node.key); else s.add(node.key); return { ...p, ptChecked: s }; }); }}
                                style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                            </div>

                            {/* Timestamp column */}
                            <div style={{ ...rawColumnStyle("Timestamp"), display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                              <span style={{ fontFamily: "monospace", color: th.textDim, fontSize: PI_TYPOGRAPHY.body, whiteSpace: "nowrap" }}>{tsDisplay}</span>
                            </div>

                            {/* Detection column — severity dot + reason + confidence + MITRE chips */}
	                            <div style={{ ...rawColumnStyle("Detection"), display: "flex", alignItems: "center", gap: 3, padding: "0 8px", overflow: "hidden" }}>
	                              {sus > 0 && <span title={sus >= 3 ? "Critical" : sus >= 2 ? "High" : "Medium"} style={{ width: 6, height: 6, borderRadius: "50%", background: susColor, flexShrink: 0 }} />}
	                              {susInfo.reason && <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 4, background: susColor + "22", color: susColor, border: `1px solid ${susColor}44`, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", flexShrink: 1, minWidth: 0 }} title={susInfo.reason}>{susInfo.reason}</span>}
	                              {susInfo.confidence && susInfo.confidence !== "context" && <span title={`Confidence: ${susInfo.confidence}`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, fontWeight: 700, flexShrink: 0, fontFamily: "'SF Mono', Menlo, monospace", background: (susInfo.confidence === "confirmed" ? th.sev.critical : susInfo.confidence === "likely" ? th.sev.high : th.sev.low) + "22", color: susInfo.confidence === "confirmed" ? th.sev.critical : susInfo.confidence === "likely" ? th.sev.high : th.sev.low }}>{susInfo.confidence === "confirmed" ? "✓✓" : susInfo.confidence === "likely" ? "✓" : "~"}</span>}
	                              {susInfo.techniques?.slice(0, 2).map((tid) => ptMitreBadge(tid, `dc-${node.key}-${tid}`))}
	                              {(() => { const cl = _ptNodeClusterMap.get(node.key); if (!cl || cl.count <= 1) return null; return <span style={{ fontSize: 9, padding: "1px 4px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontWeight: 600, flexShrink: 0, fontFamily: "SF Mono, monospace" }}>{cl.count}x</span>; })()}
	                              {(() => { const cl = _ptNodeClusterMap.get(node.key); if (!cl || cl.users.length <= 1) return null; return <span style={{ fontSize: 9, padding: "1px 4px", borderRadius: 3, background: th.sev.med + "15", color: th.sev.med, fontWeight: 500, flexShrink: 0, fontFamily: "SF Mono, monospace" }}>{cl.users.length}u</span>; })()}
	                            </div>

	                            {/* Trust column */}
	                            <div style={{ ...rawColumnStyle("Prevalence"), display: "flex", alignItems: "center", gap: 4, padding: "0 8px", overflow: "hidden" }}>
	                              {(() => {
	                                const prev = susInfo.prevalence || null;
	                                if (!prev || prev.rarity === "common" || !prev.signals?.length) return null;
	                                const color = prev.rarity === "rare" ? th.accent : th.textMuted;
	                                return (
	                                  <span title={prev.signals.join("\n")} style={{ display: "inline-flex", alignItems: "center", gap: 4, maxWidth: "100%", fontSize: 10, padding: "1px 6px", borderRadius: 4, background: `${color}18`, color, border: `1px solid ${color}33`, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontFamily: "SF Mono, monospace", fontWeight: 700 }}>
	                                    <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{prev.rarity}</span>
	                                    {prev.scoreBoost > 0 && <span style={{ opacity: 0.8, flexShrink: 0 }}>+{prev.scoreBoost}</span>}
	                                  </span>
	                                );
	                              })()}
	                            </div>

	                            {/* Parent Process column.
                                Falls back to the relinked parent node's processName when the row itself
                                has no parent image — this handles Security 4688 (no ParentImage field at
                                all), EvtxECmd, and any dataset where parent linkage exists via PID/GUID
                                but the parent's executable name lives on a different row. */}
                            <div style={{ ...rawColumnStyle("Parent Process"), display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                              {(() => {
                                const linked = byKeyMap.get(node.parentKey);
                                const display = node.parentProcessName || linked?.processName || "";
                                const titleAttr = node.parentImage || linked?.image || "";
                                return <span style={{ color: th.textDim, fontSize: PI_TYPOGRAPHY.body, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={titleAttr}>{display}</span>;
                              })()}
                            </div>

                            {/* Process column */}
                            <div style={{ ...rawColumnStyle("Process"), position: "relative", display: "flex", alignItems: "center", gap: 4, overflow: "hidden" }}>
                              {node.depth > 0 && (node.connectors || []).map((active, d) => (
                                active ? <div key={`vl${d}`} style={{ position: "absolute", left: LEFT_PAD + d * INDENT + INDENT / 2, top: 0, bottom: 0, width: 1, background: inChain && d >= 0 ? chainColor + "66" : lineColor + "44" }} /> : null
                              ))}
                              {node.depth > 0 && (
                                <>
                                  <div style={{ position: "absolute", left: LEFT_PAD + (node.depth - 1) * INDENT + INDENT / 2, top: 0, height: node.isLast ? PT_ROW_H / 2 : PT_ROW_H, width: 1, background: inChain ? chainColor + "88" : lineColor + "44" }} />
                                  <div style={{ position: "absolute", left: LEFT_PAD + (node.depth - 1) * INDENT + INDENT / 2, top: PT_ROW_H / 2, width: INDENT / 2 + 2, height: 1, background: inChain ? chainColor + "88" : lineColor + "44" }} />
                                </>
                              )}
                              <div style={{ width: LEFT_PAD + node.depth * INDENT, minWidth: LEFT_PAD + node.depth * INDENT, flexShrink: 0 }} />
                              <span onClick={(e) => { e.stopPropagation(); if (hasChildren) setModal((p) => { const en = { ...p.expandedNodes }; if (en[node.key]) delete en[node.key]; else en[node.key] = true; return { ...p, expandedNodes: en }; }); }}
                                style={{ width: 14, textAlign: "center", color: hasChildren ? (inChain ? chainColor : th.textDim) : "transparent", fontSize: 11, flexShrink: 0, userSelect: "none" }}>
                                {hasChildren ? (isExpanded ? "\u25BC" : "\u25B6") : "\u00B7"}
                              </span>
                              {inChain && <div style={{ width: 6, height: 6, borderRadius: "50%", background: chainColor, flexShrink: 0 }} />}
                              {ptIcon(node.processName)}
                              <span style={{ fontWeight: 600, color: isSelected ? chainColor : susColor || th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 }} title={node.image}>{node.processName}</span>
                              {node.childCount > 0 && <span style={{ fontSize: 11, color: th.accent, flexShrink: 0, paddingRight: 4 }}>({node.childCount})</span>}
                            </div>

                            {/* Command Line column */}
                            <div style={{ ...rawColumnStyle("Command Line"), display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                              <span style={{ color: th.textDim, fontSize: PI_TYPOGRAPHY.body, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={node.cmdLine}>{node.cmdLine}</span>
                            </div>

                            {/* PID column */}
                            <div style={{ ...rawColumnStyle("PID"), display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                              <span style={{ fontFamily: "monospace", color: inChain ? chainColor + "cc" : th.textDim, fontSize: PI_TYPOGRAPHY.body, whiteSpace: "nowrap" }}>{node.pid}</span>
                            </div>

                            {/* PPID column */}
                            <div style={{ ...rawColumnStyle("PPID"), display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                              <span style={{ fontFamily: "monospace", color: th.textDim, fontSize: PI_TYPOGRAPHY.body, whiteSpace: "nowrap" }}>{node.ppid || ""}</span>
                            </div>

                            {/* User column */}
                            <div style={{ ...rawColumnStyle("User"), display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                              <span style={{ color: th.textDim, fontSize: PI_TYPOGRAPHY.body, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{node.user || ""}</span>
                            </div>

                            {/* Provider column */}
                            <div style={{ ...rawColumnStyle("Provider"), display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                              <span style={{ fontSize: PI_TYPOGRAPHY.body, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{_providerShort(node.provider)}</span>
                            </div>

                            {/* Event ID column */}
                            <div style={{ ...rawColumnStyle("Event ID"), display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                              <span style={{ fontFamily: "monospace", color: th.textDim, fontSize: PI_TYPOGRAPHY.body, whiteSpace: "nowrap" }}>{node.eventId || ""}</span>
                            </div>

                            {/* Integrity column */}
                            <div style={{ ...rawColumnStyle("Integrity"), display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden" }}>
                              {(() => { const il = _integrityShort(node.integrity); const ic = INT_COLOR[il]; return il ? <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "2px 6px", borderRadius: 3, background: (ic || th.textDim) + "18", color: ic || th.textDim, fontWeight: 500, whiteSpace: "nowrap" }}>{il}</span> : null; })()}
                            </div>

                            {/* Filter grid: ProcessGuid/PID identity ± time window */}
                            <div style={{ width: 50, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
                              <button onClick={(e) => {
                                e.stopPropagation();
                                applyProcessGridPivot(node, modal.ptGridPivotMinutes || 15);
                              }} title={`Filter main grid to this process identity (GUID preferred) ±${modal.ptGridPivotMinutes || 15}m, including children`} style={{ background: "none", border: `1px solid ${th.border}`, borderRadius: 4, color: th.accent, fontSize: 10, padding: "2px 6px", cursor: "pointer", fontWeight: 600 }}>Grid</button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
              {hasFindingsRail && (
                <div
                  onClick={(e) => { const r = e.currentTarget.getBoundingClientRect(); const frac = Math.max(0, Math.min(1, (e.clientY - r.top) / r.height)); if (ptScrollRef.current) ptScrollRef.current.scrollTop = frac * Math.max(0, totalH - ptCH); }}
                  title="Findings overview — click to jump to that position"
                  style={{ width: 11, flexShrink: 0, position: "relative", cursor: "pointer", background: `${th.border}14`, borderLeft: `1px solid ${th.border}33` }}>
                  {_ptRail.map((lv, b) => lv > 0 ? (
                    <div key={b} style={{ position: "absolute", left: 1, right: 1, top: `${(b / _ptRail.length) * 100}%`, height: `${Math.max(100 / _ptRail.length, 0.6)}%`, minHeight: 2, background: SUS_COLORS[lv], opacity: lv >= 3 ? 1 : lv === 2 ? 0.8 : 0.55, borderRadius: 1 }} />
                  ) : null)}
                  {totalH > ptCH && (
                    <div style={{ position: "absolute", left: 0, right: 0, top: `${(ptST / totalH) * 100}%`, height: `${Math.min(100, (ptCH / totalH) * 100)}%`, background: `${th.accent}1f`, border: `1px solid ${th.accent}55`, borderRadius: 2, pointerEvents: "none", boxSizing: "border-box" }} />
                  )}
                </div>
              )}
              </div>
              </div>
            );
          })()
          )}

          {/* Column filter dropdown popup */}
          {ptFilterOpen && !ptMode.graph && (
            <>
              <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, ptFilterOpen: null }))} />
              <div style={{ position: "fixed", left: modal.ptFilterX ?? Math.min(ptFilterPos.x || 0, window.innerWidth - 340), top: modal.ptFilterY ?? Math.min(ptFilterPos.y || 0, window.innerHeight - 440), width: modal.ptFilterW || 320, height: modal.ptFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                  onMouseDown={(e) => {
                    e.preventDefault();
                    const startX = e.clientX, startY = e.clientY;
                    const startLeft = modal.ptFilterX ?? Math.min(ptFilterPos.x || 0, window.innerWidth - 340);
                    const startTop = modal.ptFilterY ?? Math.min(ptFilterPos.y || 0, window.innerHeight - 440);
                    document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                    const onMove = (ev) => setModal((p) => ({ ...p, ptFilterX: startLeft + ev.clientX - startX, ptFilterY: startTop + ev.clientY - startY }));
                    const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                  }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER {"\u2014"} {(ptFilterOpen || "").toUpperCase()}</span>
                  <span style={{ cursor: "pointer", color: th.textDim, fontSize: 14, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, ptFilterOpen: null }))}>{"\u00D7"}</span>
                </div>
                <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                  <input type="text" placeholder="Search values..." value={ptFilterSearch} onChange={(e) => setModal((p) => ({ ...p, ptFilterSearch: e.target.value }))}
                    style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: 11, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                    autoFocus />
                </div>
                <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                  <button onClick={() => setModal((p) => ({ ...p, ptFilterSel: new Set(ptFilterVals) }))} style={{ padding: "2px 8px", fontSize: 10, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                  <button onClick={() => setModal((p) => ({ ...p, ptFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: 10, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                  <span style={{ fontSize: 9, color: th.textDim, marginLeft: "auto" }}>{ptFilterSel.size} of {ptFilterVals.length}</span>
                </div>
                <div style={{ flex: 1, overflowY: "auto", minHeight: 0, padding: "0 4px" }}>
                  {ptFilterDisplay.map((val) => (
                    <label key={val} style={{ display: "flex", alignItems: "center", gap: 6, padding: "2px 6px", cursor: "pointer", fontSize: 11, fontFamily: "SF Mono, Menlo, monospace", color: th.text, borderRadius: 3 }}
                      onMouseEnter={(e) => e.currentTarget.style.background = th.bgHover || th.border + "22"}
                      onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                      <input type="checkbox" checked={ptFilterSel.has(val)} onChange={() => setModal((p) => {
                        const s = new Set(p.ptFilterSel || []);
                        if (s.has(val)) s.delete(val); else s.add(val);
                        return { ...p, ptFilterSel: s };
                      })} style={{ width: 13, height: 13, accentColor: th.accent }} />
                      <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{val || "(empty)"}</span>
                      <span style={{ fontSize: 9, color: th.textDim, flexShrink: 0 }}>{ptFilterCounts[val] || 0}</span>
                    </label>
                  ))}
                </div>
                <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                  <button onClick={() => setModal((p) => ({ ...p, ptFilterOpen: null }))} style={{ padding: "4px 12px", fontSize: 10, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}`, borderRadius: 4, color: th.textDim, cursor: "pointer" }}>Cancel</button>
                  <button onClick={() => {
                    const selected = [...ptFilterSel];
                    const all = ptFilterVals;
                    setModal((p) => {
                      const filters = { ...(p.ptColFilters || {}) };
                      if (selected.length === 0 || selected.length === all.length) { delete filters[ptFilterOpen]; }
                      else { filters[ptFilterOpen] = selected; }
                      return { ...p, ptColFilters: filters, ptFilterOpen: null };
                    });
                  }} style={{ padding: "4px 12px", fontSize: 10, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}>Apply</button>
                  <button onClick={() => {
                    setModal((p) => {
                      const filters = { ...(p.ptColFilters || {}) };
                      delete filters[ptFilterOpen];
                      return { ...p, ptColFilters: filters, ptFilterOpen: null };
                    });
                  }} style={{ padding: "4px 12px", fontSize: 10, background: "transparent", border: `1px solid ${th.border}`, borderRadius: 4, color: th.textDim, cursor: "pointer" }}>Reset</button>
                </div>
                {/* Resize grip */}
                <div onMouseDown={(e) => {
                  e.preventDefault(); e.stopPropagation();
                  const startX = e.clientX, startY = e.clientY;
                  const startW = modal.ptFilterW || 320, startH = modal.ptFilterH || 420;
                  document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                  const onMove = (ev) => setModal((p) => ({ ...p, ptFilterW: Math.max(200, startW + ev.clientX - startX), ptFilterH: Math.max(200, startH + ev.clientY - startY) }));
                  const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                  window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                }} style={{ position: "absolute", right: 0, bottom: 0, width: 16, height: 16, cursor: "nwse-resize" }}>
                  <svg width="16" height="16" viewBox="0 0 16 16" style={{ position: "absolute", right: 2, bottom: 2 }}>
                    <line x1="12" y1="4" x2="4" y2="12" stroke={th.textDim} strokeWidth="1" />
                    <line x1="12" y1="8" x2="8" y2="12" stroke={th.textDim} strokeWidth="1" />
                  </svg>
                </div>
              </div>
            </>
          )}

          {/* Right-side Detail Panel — prototype grid layout, resizable */}
          {(() => {
            const detailW = modal.ptDetailW || 380;
            const detailResizeHandle = (
              <div onMouseDown={(e) => {
                e.preventDefault(); e.stopPropagation();
                const startX = e.clientX;
                const startW = modal.ptDetailW || 380;
                document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                const onMove = (ev) => { const newW = Math.max(240, Math.min(700, startW - (ev.clientX - startX))); setModal((p) => p ? { ...p, ptDetailW: newW } : p); };
                const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
              }} style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize", zIndex: 3 }}>
                <div style={{ position: "absolute", left: 2, top: "50%", transform: "translateY(-50%)", width: 3, height: 40, borderRadius: 2, background: th.textMuted + "44", transition: "background var(--m-base)" }}
                  onMouseEnter={(e) => e.currentTarget.style.background = th.accent}
                  onMouseLeave={(e) => e.currentTarget.style.background = (th.textMuted) + "44"} />
              </div>
            );
            const selNode = selectedKey ? byKeyMap.get(selectedKey) : null;
            if (!selNode) return (
              <div style={{ width: detailW, position: "relative", borderLeft: `1px solid ${th.border}44`, background: `${th.modalBg}cc`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", flexShrink: 0, display: "flex", flexDirection: "column" }}>
                {detailResizeHandle}
                <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}88`, fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace" }}>Event Details</div>
                <div style={{ padding: 40, textAlign: "center", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.body }}>Select a process node to view details</div>
              </div>
            );
	            const parentNode = byKeyMap.get(selNode.parentKey);
	            const selSusInfo = _ptDetMap.get(selectedKey) || { level: 0, reason: null };
	            const selSus = selSusInfo.level;
	            const selSusColor = SUS_COLORS[selSus];
	            const selLink = ptLinkMeta(selNode);
	            const selPrev = selSusInfo.prevalence || null;
            const children = (childMap.get(selectedKey) || []).map((k) => byKeyMap.get(k)).filter(Boolean);
            const elevMap = { "%%1936": "Full (elevated)", "%%1937": "Limited (not elevated)", "%%1938": "Default" };
            const elevLabel = elevMap[selNode.elevation] || selNode.elevation || "";
            const integrityLabel = _integrityShort(selNode.integrity);
            const intCol = INT_COLOR[integrityLabel];
            const selSuppressed = selSusInfo.suppressed || null;
            const selBaselined = selSusInfo.baselined || null;
            const sourceEvent = modal.ptSourceEvent?.rowId === selNode.rowid && (!modal.ptSourceEvent?.tabId || modal.ptSourceEvent.tabId === ct.id) ? modal.ptSourceEvent.row : null;
            const relatedCtx = modal.ptRelatedEvents?.selected?.rowid === selNode.rowid ? modal.ptRelatedEvents : null;
            const relatedTimeline = relatedCtx?.timeline || [];
            const relatedGroups = relatedCtx?.groups || [];
            const relatedChips = relatedCtx?.enrichmentChips || [];
            const crossTelemetry = relatedCtx?.crossTelemetry || null;
            const crossPivots = crossTelemetry?.pivots || [];
            const crossRefs = crossTelemetry?.evidenceRefs || [];
            const groupRefsByTab = (refs) => {
              const grouped = new Map();
              for (const ref of refs || []) {
                const rowId = Number(ref?.rowId);
                if (!Number.isInteger(rowId) || rowId <= 0) continue;
                const tabId = ref.tabId || ct.id;
                if (!grouped.has(tabId)) grouped.set(tabId, []);
                grouped.get(tabId).push(rowId);
              }
              return grouped;
            };
            const filterLinkedRows = () => {
              const ids = [...new Set(crossRefs.filter((ref) => !ref.tabId || ref.tabId === ct.id).map((ref) => Number(ref.rowId)).filter(Boolean))];
              if (!ids.length) return;
              updateActiveTab({ rowIdFilter: ids, rowIdFilterLabel: `Process linked evidence (${ids.length})` });
              setModal(null);
            };
            const bookmarkLinkedRows = async () => {
              if (!tle?.setBookmarks || !crossRefs.length) return;
              try {
                for (const [tabId, rowIds] of groupRefsByTab(crossRefs)) await tle.setBookmarks(tabId, [...new Set(rowIds)], true);
                setModal((p) => p?.type === "processTree" ? { ...p, ptLinkedActionStatus: `Bookmarked ${crossRefs.length} linked evidence rows.` } : p);
              } catch (err) {
                toast.error("Bookmarking failed", { detail: err?.message || "Could not bookmark the linked evidence rows." });
              }
            };
            const tagLinkedRows = () => {
              if (!(tle?.setTagOnRows || tle?.addTag) || !crossRefs.length) return;
              setModal((p) => p?.type === "processTree" ? {
                ...p,
                ptLinkedTagKey: selectedKey,
                ptLinkedTagDraft: "PI:Linked Evidence",
              } : p);
            };
            const applyLinkedTag = async () => {
              const tag = String(modal.ptLinkedTagDraft || "").trim();
              if (!tag || !crossRefs.length) return;
              try {
                // One transaction per tab. The previous per-row `addTag` loop cost an
                // IPC round trip per evidence row and stalled on wide process trees.
                let tagged = 0;
                for (const [tabId, rowIds] of groupRefsByTab(crossRefs)) {
                  const ids = [...new Set(rowIds)];
                  const res = tle?.setTagOnRows
                    ? await tle.setTagOnRows(tabId, ids, tag, true)
                    : await Promise.all(ids.map((rowId) => tle.addTag(tabId, rowId, tag))).then(() => ({ requested: ids.length }));
                  if (isIpcError(res)) throw new Error(ipcErrorMessage(res));
                  if (res && res.ok === false) throw new Error(res.error || "Tag write failed");
                  tagged += res?.requested ?? ids.length;
                }
                setModal((p) => p?.type === "processTree" ? {
                  ...p,
                  ptLinkedTagKey: null,
                  ptLinkedTagDraft: "",
                  ptLinkedActionStatus: `Tagged ${tagged} linked evidence rows as ${tag}.`,
                } : p);
              } catch (err) {
                toast.error("Tagging failed", { detail: err?.message || "Could not tag the linked evidence rows." });
              }
            };
            const exportLinkedEvidence = () => {
              if (!crossTelemetry) return;
              const payload = {
                exportedAt: new Date().toISOString(),
                selectedProcess: {
                  tabId: ct.id,
                  rowId: selNode.rowid,
                  timestamp: selNode.ts,
                  host: selNode.hostname,
                  user: selNode.user,
                  process: selNode.processName,
                  image: selNode.image,
                  commandLine: selNode.cmdLine,
                },
                crossTelemetry,
              };
              const safeProc = (selNode.processName || "process").replace(/[^a-z0-9_.-]+/gi, "_").slice(0, 40);
              _downloadFile(JSON.stringify(payload, null, 2), `process-linked-evidence-${safeProc}.json`, "application/json");
            };
            const relatedMatchLabel = {
              hostWindow: "host window",
              samePid: "same PID",
              samePpid: "same PPID",
              sameGuid: "same GUID",
              sameParentGuid: "parent GUID",
              sameUser: "same user",
              sameLogon: "same logon",
              enrichment: "enrichment",
              telemetry: "telemetry",
              sameProcessImage: "same process",
            };
            const relatedTypeColor = (type) => ({
              powershell: th.textMuted,
              service: th.sev.high,
              task: th.sev.med,
              logon: th.textMuted,
              terminate: th.sev.critical,
              network: th.sev.high,
              dns: th.textMuted,
              detection: th.sev.critical,
            }[type] || th.textMuted);
            const sourceEventFields = sourceEvent
              ? Object.entries(sourceEvent).filter(([k, v]) => k !== "__idx" && String(v || "").trim() !== "")
              : [];
            const copyDetails = () => {
              const lines = [
                `Process: ${selNode.processName}`, `PID: ${selNode.pid}`, `PPID: ${selNode.ppid}`,
                selNode.user ? `User: ${selNode.user}` : null, selNode.ts ? `Timestamp: ${selNode.ts.replace("T", " ").substring(0, 19)}` : null,
	                selNode.image ? `Image: ${selNode.image}` : null, selNode.cmdLine ? `Command Line: ${selNode.cmdLine}` : null,
	                selNode.parentImage ? `Parent Image: ${selNode.parentImage}` : null,
	                parentNode ? `Parent: ${parentNode.processName} (PID ${parentNode.pid})` : null,
	                selLink.source ? `Parent Link: ${selLink.label} (${selLink.confidence || "none"})` : null,
	                selLink.link.reason ? `Link Reason: ${selLink.link.reason}` : null,
	                selLink.warnings.length ? `Link Warnings: ${selLink.warnings.join(", ")}` : null,
	                selPrev ? `Prevalence: ${selPrev.rarity}${selPrev.scoreBoost ? ` (+${selPrev.scoreBoost})` : ""}` : null,
	                selPrev?.signals?.length ? `Prevalence Signals: ${selPrev.signals.join(", ")}` : null,
	                elevLabel ? `Elevation: ${elevLabel}` : null, integrityLabel ? `Integrity: ${integrityLabel}` : null,
                selSus > 0 ? `Suspicious: ${selSusInfo.reason}` : null,
                selBaselined ? `Baselined: ${selBaselined.hostname || "global"}` : null,
                relatedCtx?.stats?.totalRelated ? `Related EVTX: ${relatedCtx.stats.totalRelated}` : null,
                crossTelemetry?.stats?.total ? `Cross-Telemetry: ${crossTelemetry.stats.total} pivots (${Object.entries(crossTelemetry.counts || {}).map(([k, v]) => `${k}:${v}`).join(", ")})` : null,
                children.length > 0 ? `Children (${children.length}): ${children.map((c) => `${c.processName} (${c.pid})`).join(", ")}` : null,
              ].filter(Boolean);
              navigator.clipboard?.writeText?.(lines.join("\n"));
            };
            const gLbl = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.control, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", paddingTop: 2 };
            const gVal = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.body, color: th.text, wordBreak: "break-all", lineHeight: 1.5 };
            const fields = [
              ["Timestamp", selNode.ts ? selNode.ts.replace("T", " ").substring(0, 19) : ""],
              ["Process", selNode.processName],
              ["Full Path", selNode.image],
              ["PID", selNode.pid],
	              ["PPID", selNode.ppid],
	              ["Parent", parentNode ? parentNode.processName : ""],
	              ["Parent Path", selNode.parentImage],
	              ["Parent Link", `${selLink.label}${selLink.confidence ? ` (${selLink.confidence})` : ""}`],
	              ["Link Reason", selLink.link.reason],
	              ["Link Warnings", selLink.warnings.join(", ")],
	              ["Prevalence", selPrev ? `${selPrev.rarity}${selPrev.scoreBoost ? ` (+${selPrev.scoreBoost})` : ""}` : ""],
	              ["Prevalence Signals", selPrev?.signals?.join(", ")],
	              ["User", selNode.user],
              ["Integrity", integrityLabel],
              ["Elevation", elevLabel],
              ["Command Line", selNode.cmdLine],
              ["Provider", _providerShort(selNode.provider)],
              ["Event ID", selNode.eventId],
              ["Hash", ptExtractHash(selNode.hashes)],
              ["Network (EID 3)", selNode.networkActivity?.eventCount
                ? `${selNode.networkActivity.eventCount} conn · ${selNode.networkActivity.destCount || 0} dest${selNode.networkActivity.rareDestCount ? ` · ${selNode.networkActivity.rareDestCount} external` : ""}${(selNode.networkActivity.destinations || []).length ? ` · ${(selNode.networkActivity.destinations || []).slice(0, 4).join(", ")}` : ""}`
                : ""],
              ["DNS (EID 22)", selNode.dnsActivity?.eventCount
                ? `${selNode.dnsActivity.eventCount} queries · ${selNode.dnsActivity.queryCount || 0} names${(selNode.dnsActivity.queries || []).length ? ` · ${(selNode.dnsActivity.queries || []).slice(0, 4).join(", ")}` : ""}`
                : ""],
              ["Image Loads (EID 7)", selNode.imageLoads?.eventCount
                ? `${selNode.imageLoads.eventCount} loads · ${selNode.imageLoads.unsignedCount || 0} unsigned · ${selNode.imageLoads.writablePathCount || 0} writable`
                : ""],
              ["File Creates (EID 11)", selNode.fileCreates?.eventCount
                ? `${selNode.fileCreates.eventCount} files · ${selNode.fileCreates.peCount || 0} PE · ${selNode.fileCreates.scriptCount || 0} script · ${selNode.fileCreates.writablePathCount || 0} writable`
                : ""],
            ].filter(([, v]) => v);
            return (
              <div style={{ width: detailW, position: "relative", borderLeft: `1px solid ${th.border}44`, background: `${th.modalBg}cc`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", flexShrink: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                {detailResizeHandle}
                {/* EVENT DETAILS header bar */}
                <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}aa`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>Event Details</div>
                {/* Process header + badges */}
                <div style={{ padding: "12px 16px 8px", borderBottom: `1px solid ${th.border}33`, flexShrink: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
	                    {ptIcon(selNode.processName)}
	                    <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, fontSize: PI_TYPOGRAPHY.heading, color: selSusColor || th.text }}>{selNode.processName}</span>
	                    <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontSize: PI_TYPOGRAPHY.body, color: th.textMuted, marginLeft: 4 }}>PID {selNode.pid}</span>
	                    <span title={selLink.title} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${selLink.color}18`, color: selLink.color, border: `1px solid ${selLink.color}33`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, textTransform: "uppercase" }}>{selLink.label}</span>
	                    {selPrev?.signals?.length > 0 && <span title={selPrev.signals.join("\n")} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: th.accent + "18", color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, textTransform: "uppercase" }}>{selPrev.rarity}</span>}
	                  </div>
                  {selSuppressed && (
                    <div style={{ marginBottom: 6, display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: th.sev.low + "22", color: th.sev.low, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${th.sev.low}44`, textTransform: "uppercase", letterSpacing: "0.05em" }}>Suppressed</span>
                      <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Analyst rule hid this detection from triage views.</span>
                    </div>
                  )}
                  {selSusInfo.reason && <div style={{ marginBottom: 6 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, background: `${selSusColor}22`, color: selSusColor, padding: "2px 8px", borderRadius: 3, fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${selSusColor}44`, letterSpacing: "0.02em" }}>{"\u26A0"} {selSusInfo.reason}</span>
                      {selSusInfo.confidence && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: selSusInfo.confidence === "confirmed" ? th.sev.critical + "22" : selSusInfo.confidence === "likely" ? th.sev.high + "22" : th.sev.low + "22", color: selSusInfo.confidence === "confirmed" ? th.sev.critical : selSusInfo.confidence === "likely" ? th.sev.high : th.sev.low, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${selSusInfo.confidence === "confirmed" ? th.sev.critical + "44" : selSusInfo.confidence === "likely" ? th.sev.high + "44" : th.sev.low + "44"}`, textTransform: "uppercase", letterSpacing: "0.05em" }}>{selSusInfo.confidence}</span>}{selSusInfo.triageScore > 0 && <span title={`Triage score ${selSusInfo.triageScore} — composite priority: severity×100 + confidence + prevalence/lifetime/trust boosts. Higher = investigate first.`} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${selSusColor}1a`, color: selSusColor, border: `1px solid ${selSusColor}44`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, letterSpacing: "0.04em" }}>SCORE {selSusInfo.triageScore}</span>}
                      {selSusInfo.sanctioned && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.clean + "18", color: th.sev.clean, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${th.sev.clean}33`, letterSpacing: "0.03em" }}>SANCTIONED {selSusInfo.sanctioned.cat.toUpperCase()}</span>}
                      {selBaselined && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${th.textMuted}33`, letterSpacing: "0.03em" }}>BASELINED {selBaselined.hostname || "GLOBAL"}</span>}
                      {(() => { const seqs = _ptSeqMap.get(selectedKey); if (!seqs?.length) return null; const best = seqs.reduce((a, b) => a.confidence === "high" ? a : b); const sc = best.confidence === "high" ? th.sev.critical : th.sev.high; return <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${sc}aa`, color: "#fff", fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, letterSpacing: "0.03em" }}>SEQ {best.confidence === "high" ? "\u2191" : "\u2193"}</span>; })()}
                      {(() => { const ev = selSusInfo.evidence; if (!ev || ev.length <= 1) return null; const pc = ev.filter(e => e.cat !== "context").length - 1; const cc = ev.filter(e => e.cat === "context").length; const parts = []; if (pc > 0) parts.push(`${pc} primary`); if (cc > 0) parts.push(`${cc} context`); return parts.length ? <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>+{parts.join(" + ")}</span> : null; })()}
                    </div>
                    {selSusInfo.evidence?.length > 1 && (() => {
                      const rest = selSusInfo.evidence.filter(e => e.reason !== selSusInfo.reason);
                      const prim = rest.filter(e => e.cat !== "context");
                      const ctxs = rest.filter(e => e.cat === "context");
                      return <div style={{ marginTop: 4, display: "flex", flexWrap: "wrap", gap: 3, alignItems: "center" }}>
                        {prim.map((e, i) => { const eColor = SUS_COLORS[e.level] || th.sev.low; return <span key={`p${i}`} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${eColor}14`, color: eColor, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${eColor}22` }}>{e.cat === "chain" ? "chain: " : ""}{e.reason}{e.tid?.length ? ` [${e.tid.join(", ")}]` : ""}</span>; })}
                        {prim.length > 0 && ctxs.length > 0 && <span style={{ color: th.border, fontSize: 10, margin: "0 2px" }}>{"\u00B7"}</span>}
                        {ctxs.map((e, i) => { const eColor = e.dampen ? th.textDim : th.sev.low; return <span key={`c${i}`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${eColor}0a`, color: eColor, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${eColor}18`, fontStyle: "italic" }}>{e.dampen ? "\u25BC " : ""}{e.reason}</span>; })}
                      </div>;
                    })()}
                    {selSusInfo.techniques?.length > 0 && <div style={{ marginTop: 3, display: "flex", gap: 3, flexWrap: "wrap" }}>
                      {selSusInfo.techniques.map((t) => ptMitreBadge(t))}
                    </div>}
                  </div>}
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                    <button
                      onClick={() => applyProcessGridPivot(selNode, modal.ptGridPivotMinutes || 15)}
                      title="Filter the main timeline to this ProcessGuid (or PID) ± time window, including child process creates"
                      style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}18)`, color: th.accent, border: `1px solid ${th.accent}44`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700 }}
                    >Filter Grid</button>
                    <select
                      value={modal.ptGridPivotMinutes || 15}
                      onChange={(e) => setModal((p) => p ? { ...p, ptGridPivotMinutes: Number(e.target.value) } : p)}
                      title="Time window for grid pivot"
                      style={{ padding: "2px 4px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.bgInput, color: th.textDim, border: `1px solid ${th.border}66`, fontFamily: "'SF Mono', Menlo, monospace" }}
                    >
                      {PI_GRID_PIVOT_WINDOWS.map((w) => (
                        <option key={w.minutes} value={w.minutes}>{w.label}</option>
                      ))}
                    </select>
                    <button onClick={() => setModal((p) => p ? { ...p, ptViewMode: "graph", selectedKey } : p)} title="Show this process in the spatial graph view" style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}66`, fontFamily: "'SF Mono', Menlo, monospace" }}>Graph</button>
                    <button onClick={() => applyProcessHandoff(selNode, "lateral")} title="Open Lateral Movement with host + ±30m time window from this process" style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: `${th.accent}12`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Lateral</button>
                    <button onClick={() => applyProcessHandoff(selNode, "persistence")} title="Open Persistence Analyzer near this process (host + time window)" style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: `${th.accent}12`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Persistence</button>
                    <button onClick={() => applyProcessHandoff(selNode, "sigma")} title="Open Sigma on this tab with host + time window around the process" style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: `${th.accent}12`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Sigma</button>
                    <button onClick={copyDetails} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}66`, fontFamily: "'SF Mono', Menlo, monospace" }}>Copy Details</button>
                    <button onClick={() => openPiSourceEvent(selNode.rowid)} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Source Event</button>
                    {ptExtractHash(selNode.hashes) && (
                      <button
                        onClick={() => lookupProcessHash(selNode)}
                        title="In-app VirusTotal lookup when an API key is set; otherwise opens the public VT page"
                        style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.accent + "15", color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}
                      >{modal.ptVtStatus || "VirusTotal"}</button>
                    )}
                    {modal.ptVtResult && !modal.ptVtResult.error && (
                      <span title={modal.ptVtResult.threatLabel || ""} style={{ fontSize: 9, padding: "2px 7px", borderRadius: 4, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, background: `${th.sev.high}18`, color: th.sev.high, border: `1px solid ${th.sev.high}33` }}>
                        VT {modal.ptVtResult.score || modal.ptVtResult.verdict || "done"}
                      </span>
                    )}
                    {selSusInfo.reason && !selBaselined && <button onClick={() => {
                      const entry = makePiAnalystEntry("baselines", selNode, parentNode, selSusInfo);
                      if (entry) upsertPiAnalystEntry("baselines", entry);
                    }} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.accent + "15", color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Baseline Host</button>}
                    {selBaselined && <button onClick={() => removePiAnalystEntry("baselines", selBaselined.id)} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}66`, fontFamily: "'SF Mono', Menlo, monospace" }}>Remove Baseline</button>}
                    {selSusInfo.reason && !selSuppressed && <button onClick={() => {
                      const entry = makePiAnalystEntry("suppressions", selNode, parentNode, selSusInfo);
                      if (entry) upsertPiAnalystEntry("suppressions", entry);
                    }} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.sev.low + "15", color: th.sev.low, border: `1px solid ${th.sev.low}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Suppress</button>}
                  </div>
                </div>
                {/* Grid fields — matching prototype */}
                <div style={{ overflow: "auto", flex: 1, padding: 16 }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {fields.map(([label, value]) => (
                      <div key={label} style={{ display: "grid", gridTemplateColumns: "110px 1fr", padding: "6px 0", borderBottom: `1px solid ${th.border}22` }}>
                        <span style={gLbl}>{label}</span>
                        <span style={{ ...gVal, color: label === "Command Line" ? (th.danger) : label === "Parent" ? (th.accent) : label === "Integrity" ? (intCol || th.text) : th.text, background: label === "Command Line" ? `${th.accent}08` : "transparent", padding: label === "Command Line" ? "4px 6px" : "0", borderRadius: label === "Command Line" ? 3 : 0, cursor: label === "Parent" && parentNode ? "pointer" : "default" }}
                          onClick={label === "Parent" && parentNode ? () => {
                            const en = { ...(modal.expandedNodes || {}) };
                            let cur = consistentParentKey(parentNode, byKeyMap);
                            while (cur && byKeyMap.has(cur)) { en[cur] = true; cur = consistentParentKey(byKeyMap.get(cur), byKeyMap); }
                            setModal((p) => p ? { ...p, selectedKey: parentNode.key, expandedNodes: en } : p);
                          } : undefined}>{label === "Command Line" ? ptHighlightCmd(value) : (value || "\u2014")}</span>
                      </div>
                    ))}
                  </div>
                  {ptDecodePanel(selNode.cmdLine, gLbl)}
                  {(modal.ptSourceEventLoading || sourceEvent) && (
                    <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.panelBg}66`, borderRadius: 6, border: `1px solid ${th.border}22` }}>
                      <div style={{ ...gLbl, marginBottom: 6 }}>Source Event</div>
                      {modal.ptSourceEventLoading ? (
                        <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Loading raw event...</div>
                      ) : sourceEvent ? (
                        <>
                          <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: 6 }}>Row ID {sourceEvent.__idx}</div>
                          <div style={{ display: "flex", flexDirection: "column", gap: 1, maxHeight: 260, overflowY: "auto" }}>
                            {sourceEventFields.slice(0, 40).map(([label, value]) => (
                              <div key={label} style={{ display: "grid", gridTemplateColumns: "110px 1fr", padding: "4px 0", borderBottom: `1px solid ${th.border}18` }}>
                                <span style={gLbl}>{label}</span>
                                <span style={{ ...gVal, color: th.textDim }}>{value}</span>
                              </div>
                            ))}
                          </div>
                          {sourceEventFields.length > 40 && <div style={{ marginTop: 6, fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{sourceEventFields.length - 40} more populated fields hidden.</div>}
                        </>
                      ) : (
                        <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Source event not available.</div>
                      )}
                    </div>
                  )}
                  {(modal.ptRelatedEventsLoading || relatedCtx || modal.ptRelatedEventsError) && (
                    <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                      <div style={{ ...gLbl, marginBottom: 6 }}>Related EVTX</div>
                      {modal.ptRelatedEventsLoading ? (
                        <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Loading related events...</div>
                      ) : modal.ptRelatedEventsError && !relatedCtx ? (
                        <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{modal.ptRelatedEventsError}</div>
                      ) : relatedCtx ? (
                        <>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                            {relatedGroups.map((group) => (
                              <span key={group.id} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>
                                {group.label} {group.count}
                              </span>
                            ))}
                          </div>
                          {relatedChips.length > 0 && (
                            <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 8 }}>
                              {relatedChips.map((chip) => {
                                const color = relatedTypeColor(chip.id);
                                return (
                                  <span key={chip.id} style={{ fontSize: 8, padding: "1px 6px", borderRadius: 3, background: `${color}18`, color, border: `1px solid ${color}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>
                                    {chip.label} {chip.count}
                                  </span>
                                );
                              })}
                            </div>
                          )}
                          {crossTelemetry?.stats?.total > 0 && (
                            <div style={{ marginBottom: 8, padding: "7px 8px", borderRadius: 6, background: `${th.panelBg}66`, border: `1px solid ${th.border}22` }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap", marginBottom: 6 }}>
                                <span style={{ ...gLbl, paddingTop: 0, color: th.accent }}>Cross-Telemetry Pivots</span>
                                {Object.entries(crossTelemetry.counts || {}).map(([type, count]) => {
                                  const color = relatedTypeColor(type);
                                  return <span key={type} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${color}18`, color, border: `1px solid ${color}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>{type} {count}</span>;
                                })}
                                <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{crossTelemetry.stats.evidenceRows} rows</span>
                              </div>
                              <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 150, overflowY: "auto", marginBottom: 7 }}>
                                {crossPivots.slice(0, 12).map((pivot) => {
                                  const color = relatedTypeColor(pivot.type);
                                  const ref = pivot.evidenceRefs?.[0] || null;
                                  return (
                                    <div key={pivot.id} style={{ padding: "4px 5px", borderRadius: 5, background: `${color}08`, border: `1px solid ${color}22` }}>
                                      <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                                        <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${color}18`, color, border: `1px solid ${color}33`, fontFamily: "'SF Mono', Menlo, monospace", textTransform: "uppercase" }}>{pivot.type}</span>
                                        <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}18`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{pivot.confidence}</span>
                                        <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{(pivot.timestamp || "").slice(0, 19)}</span>
                                        {ref?.rowId && <button onClick={() => openPiSourceEvent(ref)} style={{ marginLeft: "auto", padding: "1px 6px", borderRadius: 3, fontSize: 8, cursor: "pointer", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Open</button>}
                                      </div>
                                      <div style={{ marginTop: 2, fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.35, wordBreak: "break-word" }}>
                                        <strong style={{ color: th.text }}>{pivot.label}</strong>{pivot.summary ? ` - ${pivot.summary}` : ""}
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                              {modal.ptLinkedActionStatus && <div style={{ fontSize: 9, color: th.sev.clean, fontFamily: "-apple-system, sans-serif", marginBottom: 6 }}>{modal.ptLinkedActionStatus}</div>}
                              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                <button onClick={filterLinkedRows} style={_ptPivotBtn}>Open Linked Rows</button>
                                <button onClick={bookmarkLinkedRows} style={_ptPivotBtn}>Bookmark Linked</button>
                                <button onClick={tagLinkedRows} style={_ptPivotBtn}>Tag Linked</button>
                                <button onClick={exportLinkedEvidence} style={_ptPivotBtn}>Export Evidence</button>
                              </div>
                              {modal.ptLinkedTagKey === selectedKey && (
                                <div style={{ display: "flex", gap: 5, marginTop: 7, alignItems: "center" }}>
                                  <input
                                    autoFocus
                                    value={modal.ptLinkedTagDraft || ""}
                                    onChange={(ev) => setModal((p) => p?.type === "processTree" ? { ...p, ptLinkedTagDraft: ev.target.value } : p)}
                                    onKeyDown={(ev) => {
                                      if (ev.key === "Enter") applyLinkedTag();
                                      if (ev.key === "Escape") setModal((p) => p?.type === "processTree" ? { ...p, ptLinkedTagKey: null, ptLinkedTagDraft: "" } : p);
                                    }}
                                    placeholder="Tag name"
                                    style={{ minWidth: 0, flex: 1, padding: "4px 7px", borderRadius: 4, border: `1px solid ${th.border}`, background: th.bgInput, color: th.text, fontSize: PI_TYPOGRAPHY.control, fontFamily: "-apple-system, sans-serif" }}
                                  />
                                  <button onClick={applyLinkedTag} disabled={!String(modal.ptLinkedTagDraft || "").trim()} style={{ ..._ptPivotBtn, opacity: String(modal.ptLinkedTagDraft || "").trim() ? 1 : 0.5 }}>Apply</button>
                                  <button onClick={() => setModal((p) => p?.type === "processTree" ? { ...p, ptLinkedTagKey: null, ptLinkedTagDraft: "" } : p)} style={_ptPivotBtn}>Cancel</button>
                                </div>
                              )}
                            </div>
                          )}
                          {relatedTimeline.length > 0 ? (
                            <div style={{ display: "flex", flexDirection: "column", gap: 5, maxHeight: 260, overflowY: "auto" }}>
                              {relatedTimeline.map((evt) => {
                                const eColor = relatedTypeColor(evt.enrichmentType || evt.telemetryType);
                                return (
                                  <div key={evt.rowid} style={{ padding: "5px 6px", borderRadius: 6, background: evt.isSelected ? `${th.accent}12` : `${th.panelBg}55`, border: `1px solid ${evt.isSelected ? `${th.accent}33` : `${th.border}18`}` }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap", marginBottom: 3 }}>
                                      <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{(evt.timestamp || "").slice(0, 19) || "Unknown time"}</span>
                                      <span style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.border}22`, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace" }}>{evt.eventId || "?"}</span>
                                      {evt.provider && <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{_providerShort(evt.provider) || evt.provider}</span>}
                                      {evt.enrichmentType && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${eColor}18`, color: eColor, border: `1px solid ${eColor}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>{evt.eventLabel}</span>}
                                      {evt.telemetryType && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${eColor}18`, color: eColor, border: `1px solid ${eColor}33`, fontFamily: "'SF Mono', Menlo, monospace", textTransform: "uppercase" }}>{evt.telemetryType}</span>}
                                      {evt.isSelected && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}18`, color: th.accent, fontFamily: "'SF Mono', Menlo, monospace" }}>anchor</span>}
                                      {(evt.matchTypes || []).filter((m) => m !== "selected").slice(0, 4).map((m) => (
                                        <span key={`${evt.rowid}-${m}`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.border}18`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>
                                          {relatedMatchLabel[m] || m}
                                        </span>
                                      ))}
                                      {!evt.isSelected && evt.rowid > 0 && (
                                        <button onClick={() => openPiSourceEvent(evt.rowid)} style={{ marginLeft: "auto", padding: "1px 6px", borderRadius: 3, fontSize: 8, cursor: "pointer", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Open Raw</button>
                                      )}
                                    </div>
                                    <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>
                                      {evt.telemetrySummary || evt.summary || `${evt.processName || "Event"}${evt.cmdLine ? ` — ${evt.cmdLine}` : ""}`}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          ) : (
                            <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>No related EVTX pivots matched this process in the current tab.</div>
                          )}
                        </>
                      ) : null}
                    </div>
                  )}
                  {/* Behavioral Sequence */}
                  {(() => {
                    const seqs = _ptSeqMap.get(selectedKey);
                    if (!seqs?.length) return null;
                    const seqConfColor = { high: th.sev.critical, medium: th.sev.high };
                    return (
                      <div style={{ marginTop: 12, padding: "8px 10px", background: th.sev.critical + "12", borderRadius: 6, border: `1px solid ${th.sev.critical}22` }}>
                        <div style={{ ...gLbl, marginBottom: 4, color: th.sev.critical }}>Behavioral Sequence</div>
                        {seqs.map((s, i) => {
                          const sc = seqConfColor[s.confidence] || th.sev.low;
                          return (
                          <div key={i} style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: i < seqs.length - 1 ? 6 : 0 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                              <span style={{ color: sc, fontWeight: 600 }}>{s.seqName}</span>
                              <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: `${sc}18`, color: sc, border: `1px solid ${sc}33` }}>{s.stageName}</span>
                              <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: `${sc}18`, color: sc, border: `1px solid ${sc}33`, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>{s.confidence}</span>
                            </div>
                            <div style={{ marginTop: 2, fontSize: 9, color: th.textMuted }}>{s.confidence === "high" ? "same tree" : "same host/user"} {"\u2014"} {s.peers.length} processes {s.tid?.length ? `\u2014 ${s.tid.join(", ")}` : ""}</div>
                          </div>
                        ); })}
                      </div>
                    );
                  })()}
                  {(() => {
                    const nodeStory = _ptNodeStoryMap.get(selectedKey);
                    if (!nodeStory) return null;
                    return (
                      <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                        <div style={{ ...gLbl, marginBottom: 4 }}>Investigation Story</div>
                        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45, marginBottom: 6 }}>
                          {nodeStory.narrative}
                        </div>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                          <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.eventCount} events</span>
                          {nodeStory.contextOnlyCount > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.contextEventCount} with context</span>}
                          <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.chainCount} chains</span>
                          {nodeStory.sequenceCount > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.critical + "18", color: th.sev.critical, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.sequenceCount} seq</span>}
                        </div>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                          <button onClick={() => setModal((p) => ({ ...p, ptViewMode: "story", _ptExpandedIncident: nodeStory.id, selectedKey: nodeStory.anchorKey || selectedKey, ptClusterKeys: null, ptClusterContext: false, searchText: "", ptColFilters: {} }))} style={_ptPivotBtn}>View Story</button>
                          <button onClick={() => _ptCopyStory(nodeStory)} style={_ptPivotBtn}>Copy Story</button>
                        </div>
                      </div>
                    );
                  })()}
                  {/* Execution Timeline — selected process + its children on a shared time axis */}
                  {(() => {
                    const items = [selNode, ...children]
                      .map((p) => ({ p, start: normalizeTimestamp(p.ts), dur: Number.isFinite(p.durationMs) ? p.durationMs : null, lvl: (_ptDetMap.get(p.key) || { level: 0 }).level }))
                      .filter((x) => Number.isFinite(x.start));
                    if (items.length < 2) return null;
                    items.sort((a, b) => a.start - b.start);
                    const minT = items[0].start;
                    let maxT = minT;
                    for (const x of items) maxT = Math.max(maxT, x.start + (x.dur || 0));
                    const span = Math.max(1, maxT - minT);
                    return (
                      <div style={{ marginTop: 12 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                          <span style={{ ...gLbl, paddingTop: 0 }}>Execution Timeline</span>
                          <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{items.length} procs · {_ptFormatDuration(span)} span</span>
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                          {items.slice(0, 24).map((x, i) => {
                            const isSel = x.p.key === selectedKey;
                            const col = SUS_COLORS[x.lvl] || th.textDim;
                            const leftPct = ((x.start - minT) / span) * 100;
                            const widthPct = x.dur != null ? Math.max((x.dur / span) * 100, 1.5) : null;
                            return (
                              <div key={x.p.key + ":" + i}
                                onClick={() => { const en = { ...(modal.expandedNodes || {}), [selectedKey]: true }; setModal((p) => p ? { ...p, selectedKey: x.p.key, expandedNodes: en } : p); }}
                                title={`${x.p.processName} (PID ${x.p.pid}) — ${(x.p.ts || "").replace("T", " ").slice(0, 19)}${x.dur != null ? ` · ${_ptFormatDuration(x.dur)}` : " · no termination recorded"}`}
                                style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", padding: "1px 0" }}>
                                <span style={{ width: 92, flexShrink: 0, fontSize: 9, fontFamily: "'SF Mono', Menlo, monospace", color: isSel ? th.accent : th.textDim, fontWeight: isSel ? 700 : 400, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{x.p.processName}</span>
                                <div style={{ position: "relative", flex: 1, height: 10, background: `${th.border}18`, borderRadius: 2 }}>
                                  {widthPct != null
                                    ? <div style={{ position: "absolute", left: `${leftPct}%`, width: `${Math.min(widthPct, 100 - leftPct)}%`, top: 1, bottom: 1, background: col, opacity: isSel ? 1 : 0.7, borderRadius: 2, minWidth: 2, boxShadow: isSel ? `0 0 0 1px ${th.accent}` : "none" }} />
                                    : <div style={{ position: "absolute", left: `${leftPct}%`, top: 0, width: 4, height: 10, marginLeft: -2, borderRadius: "50%", background: col, opacity: isSel ? 1 : 0.7, boxShadow: isSel ? `0 0 0 1px ${th.accent}` : "none" }} />}
                                </div>
                              </div>
                            );
                          })}
                          {items.length > 24 && <span style={{ fontSize: 9, color: th.textMuted }}>+{items.length - 24} more</span>}
                        </div>
                      </div>
                    );
                  })()}
                  {/* Children chips */}
                  {children.length > 0 && <div style={{ marginTop: 12 }}>
                    <div style={{ ...gLbl, marginBottom: 6 }}>Children ({children.length})</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {children.slice(0, 20).map((c) => {
                        const cSusInfo = _ptDetMap.get(c.key) || { level: 0, reason: null };
                        const cColor = SUS_COLORS[cSusInfo.level];
                        return <span key={c.key} onClick={() => { const en = { ...(modal.expandedNodes || {}), [selectedKey]: true }; setModal((p) => p ? { ...p, selectedKey: c.key, expandedNodes: en } : p); }}
                          style={{ padding: "2px 8px", borderRadius: 4, background: (cColor || th.accent) + "14", color: cColor || th.textDim, fontSize: 10, cursor: "pointer", border: `1px solid ${(cColor || th.border)}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>{c.processName} ({c.pid})</span>;
                      })}
                      {children.length > 20 && <span style={{ fontSize: 9, color: th.textDim }}>+{children.length - 20} more</span>}
                    </div>
                  </div>}
                  {/* Chain Context — shows when this node belongs to a repeated cluster */}
                  {(() => {
                    const nodeCluster = _ptNodeClusterMap.get(selectedKey);
                    if (!nodeCluster || nodeCluster.count <= 1) return null;
                    return (
                      <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                        <div style={{ ...gLbl, marginBottom: 4 }}>Chain Context</div>
                        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", display: "flex", flexDirection: "column", gap: 3 }}>
                          <div>Repeated <strong style={{ color: th.accent }}>{nodeCluster.count}x</strong> across {nodeCluster.users.length} user{nodeCluster.users.length !== 1 ? "s" : ""}</div>
                          <div>First: {(nodeCluster.firstSeen || "").slice(0, 19)} {"\u2014"} Last: {(nodeCluster.lastSeen || "").slice(0, 19)}</div>
                          <div>{nodeCluster.cmdVariants.length} command variant{nodeCluster.cmdVariants.length !== 1 ? "s" : ""}</div>
                        </div>
                        <button onClick={() => setModal(p => ({ ...p, ptViewMode: "triage", _ptExpandedCluster: nodeCluster.id, ptClusterKeys: null, ptClusterContext: false, searchText: "", ptColFilters: {} }))} style={{ marginTop: 6, padding: "2px 8px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, fontSize: 9, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>View Cluster</button>
                      </div>
                    );
                  })()}
                </div>
              </div>
            );
          })()}
          </div>
          )}

          </>)}

          {/* Footer */}
          {(() => {
            const susCountFooter = flatNodes.filter(n => (_ptDetMap.get(n.key) || { level: 0 }).level > 0).length;
            let treeDepth = 0;
            for (const n of flatNodes) if ((n.depth || 0) > treeDepth) treeDepth = n.depth;
            const fProviders = [...new Set((data?.processes || []).map(p => _providerShort(p.provider)).filter(Boolean))].join(", ");
            const fEids = [...new Set((data?.processes || []).map(p => p.eventId).filter(Boolean))].sort().join(", ");
            return (
          <div style={{ padding: "8px 20px", borderTop: `1px solid ${th.border}44`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, fontSize: 10, color: th.textDim, background: `${th.headerBg}cc`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", fontFamily: "'SF Mono', Menlo, monospace" }}>
            <span>
              {isHealthMode
                ? `Rule health · ${(data?.stats?.totalProcesses || 0).toLocaleString()} processes scored`
                : ptMode.incident
                ? `${filteredStories.length} stor${filteredStories.length !== 1 ? "ies" : "y"} · ${filteredStoryStats.susProcesses} suspicious of ${(data?.stats?.totalProcesses || 0).toLocaleString()} total`
                : ptMode.clustered
                ? `${filteredClusters.length} chain${filteredClusters.length !== 1 ? "s" : ""} · ${filteredStats.susProcesses} suspicious of ${(data?.stats?.totalProcesses || 0).toLocaleString()} total`
                : ptMode.graph
                ? `Graph view · ${(data?.stats?.totalProcesses || 0).toLocaleString()} processes in tree · select a node for details / Filter Grid`
                : `${flatNodes.length.toLocaleString()} visible · ${susCountFooter} suspicious · Tree depth: ${treeDepth}`}
              {!isHealthMode && !ptMode.clustered && !ptMode.graph && selectedKey && ` · Chain: ${chainKeys.size}`}
              {!isHealthMode && ptMode.graph && selectedKey && ` · Selected: ${(byKeyMap.get(selectedKey)?.processName) || selectedKey}`}
            </span>
            <span style={{ opacity: 0.7 }}>
              Data: {fProviders || "Events"} EID {fEids || "—"} {"\u2192"} ProcessEvent {"\u2192"} {ptMode.graph ? "Graph by GUID/PID" : "Tree Index by PID/PPID"}
            </span>
          </div>
            );
          })()}
        </div>
      );

}
