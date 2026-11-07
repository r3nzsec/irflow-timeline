import { useEffect, useRef, useState } from "react";
import useUIStore from "../store/useUIStore.js";
import { formatNumber } from "../utils/format.js";
import { Tooltip } from "./primitives/index.js";

/**
 * StatusBar — bottom bar showing file path, row counts, filter summary, etc.
 *
 * Props:
 *   th                  – theme object
 *   ct                  – current tab object
 *   isGrouped           – whether grouping is active
 *   selectionCount      – total selected rows, including compact select-all mode
 *   copiedMsg           – boolean, true when "Copied!" should flash
 *   setCopiedMsg        – setter for copiedMsg
 *   pinnedH             – array of pinned header names
 *   allVisH             – array of all visible header names
 *   searchLoading       – boolean, search in progress
 *   activeCheckboxCount – number of active checkbox filters
 *   totalActiveFilters  – total active filter count
 *   clearAllFilters     – function to clear all filters
 *   up                  – function to update current tab field
 */
export default function StatusBar({
  th,
  ct,
  isGrouped,
  selectionCount,
  copiedMsg,
  setCopiedMsg,
  pinnedH,
  allVisH,
  searchLoading,
  searchElapsed = 0,
  visibleRowStart = 0,
  visibleRowEnd = 0,
  activeCheckboxCount,
  totalActiveFilters,
  clearAllFilters,
  up,
}) {
  const setModal = useUIStore((s) => s.setModal);
  const timezone = useUIStore((s) => s.timezone);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const statusRef = useRef(null);

  useEffect(() => setDetailsOpen(false), [ct?.id]);
  useEffect(() => {
    if (!detailsOpen) return undefined;
    const closeOnOutsidePointer = (event) => {
      if (!statusRef.current?.contains(event.target)) setDetailsOpen(false);
    };
    const closeOnEscape = (event) => {
      if (event.key === "Escape") setDetailsOpen(false);
    };
    window.addEventListener("pointerdown", closeOnOutsidePointer, true);
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      window.removeEventListener("pointerdown", closeOnOutsidePointer, true);
      window.removeEventListener("keydown", closeOnEscape);
    };
  }, [detailsOpen]);

  if (!ct || !ct.dataReady) return null;

  const Sdiv = () => <span aria-hidden="true" style={{ width: 1, height: 12, background: th.border, display: "inline-block" }} />;
  const actionStyle = {
    background: "none",
    border: "none",
    color: th.accent,
    cursor: "pointer",
    font: "inherit",
    padding: "2px 3px",
    minHeight: 24,
  };
  const filteredTotal = Math.max(0, Number(ct.totalFiltered) || 0);
  const rangeStart = filteredTotal > 0 ? Math.max(1, Math.min(filteredTotal, Number(visibleRowStart) || 1)) : 0;
  const rangeEnd = filteredTotal > 0 ? Math.max(rangeStart, Math.min(filteredTotal, Number(visibleRowEnd) || rangeStart)) : 0;

  return (
    <div ref={statusRef} className="tle-statusbar" aria-label="Timeline status" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "3px 12px", background: th.toolbarBg, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", borderTop: `1px solid ${th.glassBorder}`, fontSize: 12, color: th.textDim, flexShrink: 0, fontFamily: "-apple-system, sans-serif", position: "relative", minWidth: 0, gap: 10 }}>
      <div className="tle-status-primary" style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0, overflow: "hidden" }}>
        <Tooltip content={ct.filePath ? `Copy file path: ${ct.filePath}` : ct.name}>
          <button type="button" aria-label={ct.filePath ? "Copy timeline file path" : ct.name}
            className="tle-status-path"
            style={{ ...actionStyle, fontWeight: 500, maxWidth: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "inline-block", verticalAlign: "middle", textAlign: "left", flexShrink: 1 }}
            onClick={() => { if (ct.filePath) { navigator.clipboard?.writeText?.(ct.filePath); setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200); } }}>
            {ct.filePath || ct.name}
          </button>
        </Tooltip>
        {!isGrouped && <><Sdiv /><span>Filtered: <b style={{ color: ct.totalFiltered < ct.totalRows ? th.warning : th.success, opacity: searchLoading ? 0.5 : 1, transition: "opacity var(--m-base)" }}>{formatNumber(ct.totalFiltered)}</b>{searchLoading && <span style={{ color: th.accent, marginLeft: 3, fontFamily: "'SF Mono',Menlo,monospace" }}>{searchElapsed >= 2 ? ` searching ${formatNumber(ct.totalRows)} rows… ${searchElapsed}s` : "..."}</span>}</span></>}
        {!isGrouped && <><Sdiv /><span style={{ whiteSpace: "nowrap" }}>Rows <b>{formatNumber(rangeStart)}–{formatNumber(rangeEnd)}</b> of <b>{formatNumber(filteredTotal)}</b></span></>}
        {isGrouped && <><Sdiv /><span>Groups: <b style={{ color: th.accent }}>{ct.groupData?.length || 0}</b></span></>}
        {selectionCount > 0 && <><Sdiv /><span>{selectionCount === 1 ? "1 row selected" : `${formatNumber(selectionCount)} rows selected`}</span></>}
        {copiedMsg && <span role="status" aria-live="polite" style={{ color: th.success }}>Copied!</span>}
        {totalActiveFilters > 0 && (
          <Tooltip content={`Clear all ${totalActiveFilters} active filter${totalActiveFilters > 1 ? "s" : ""}`}>
            <button type="button" onClick={clearAllFilters} style={{ ...actionStyle, color: th.danger, fontWeight: 600, textDecoration: "underline", textDecorationStyle: "dotted", whiteSpace: "nowrap" }}>Clear All ({totalActiveFilters})</button>
          </Tooltip>
        )}
      </div>
      <button type="button" className="tle-status-toggle" aria-expanded={detailsOpen} aria-controls="timeline-status-details"
        onClick={() => setDetailsOpen((open) => !open)}
        style={{ ...actionStyle, display: "none", color: detailsOpen ? th.accent : th.textDim, border: `1px solid ${th.btnBorder}`, borderRadius: 5, padding: "2px 7px", whiteSpace: "nowrap", flexShrink: 0 }}>
        Details {detailsOpen ? "▾" : "▴"}
      </button>
      <div id="timeline-status-details" className="tle-status-details" data-open={detailsOpen ? "true" : "false"}
        style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
        <Tooltip content="Active timezone for timestamp display"><span>TZ: <b style={{ color: timezone === "UTC" ? th.textDim : th.warning }}>{timezone}</b></span></Tooltip>
        <span>Total: <b>{formatNumber(ct.totalRows)}</b></span>
        {ct.bookmarkedSet?.size > 0 && <span>Flagged: <b style={{ color: th.warning }}>{ct.bookmarkedSet.size}</b></span>}
        {ct.sortCol && ct.sortCol !== "__tags__" && <span>Sort: {ct.sortCol} {ct.sortDir === "asc" ? "↑" : "↓"}</span>}
        {pinnedH.length > 0 && <span>📌 {pinnedH.length}</span>}
        <span>{allVisH.length}/{ct.headers.length} cols</span>
        {ct.colorRules.length > 0 && <span>{ct.colorRules.length} color rule{ct.colorRules.length > 1 ? "s" : ""}</span>}
        {activeCheckboxCount > 0 && <span style={{ color: th.borderAccent }}>{activeCheckboxCount} value filter{activeCheckboxCount > 1 ? "s" : ""}</span>}
        {ct.tagFilter && <span style={{ color: th.danger }}>Tag filter ({Array.isArray(ct.tagFilter) ? ct.tagFilter.length : 1})</span>}
        {Array.isArray(ct.rowIdFilter) && ct.rowIdFilter.length > 0 && (
          <button type="button"
            onClick={() => { up("rowIdFilter", null); up("rowIdFilterLabel", null); }}
            style={actionStyle}
            title={ct.rowIdFilterLabel ? `Exact matched rows for: ${ct.rowIdFilterLabel}. Click to clear.` : "Exact matched rows. Click to clear."}
          >
            Matched rows ({formatNumber(ct.rowIdFilter.length)}) ✕
          </button>
        )}
        {Object.keys(ct.dateRangeFilters || {}).length > 0 && <span style={{ color: th.warning }}>{Object.keys(ct.dateRangeFilters).length} date filter{Object.keys(ct.dateRangeFilters).length > 1 ? "s" : ""}</span>}
        {(ct.advancedFilters?.length > 0) && <span style={{ color: th.accent }}>{ct.advancedFilters.length} advanced filter{ct.advancedFilters.length > 1 ? "s" : ""}</span>}
        {ct.searchHighlight && ct.searchTerm && <span style={{ color: th.warning }}>Highlight mode</span>}
        {ct.iocHighlights?.length > 0 && (
          <Tooltip content="IOC matches are highlighted — click to clear">
            <button type="button" onClick={() => up("iocHighlights", null)} style={{ ...actionStyle, color: th.warning }}>IOC Highlights ({ct.iocHighlights.length}) ✕</button>
          </Tooltip>
        )}
        {ct._detectedProfile && <span style={{ color: th.success }}>{ct._detectedProfile}</span>}
        <button type="button" disabled={!ct?.dataReady} onClick={() => setModal({ type: "editFilter" })}
          style={{ ...actionStyle, cursor: ct?.dataReady ? "pointer" : "default", color: ct?.advancedFilters?.length > 0 ? th.accent : th.textMuted, textDecoration: ct?.dataReady ? "underline" : "none" }}>Edit Filter</button>
        <span style={{ color: th.textMuted }}>DuckDB-backed</span>
      </div>
    </div>
  );
}
