import { memo } from "react";
import { BkmkIcon, CheckboxIcon } from "./icons.jsx";
import { applyColors } from "../utils/color-rules.js";
import { ROW_HEIGHT, BKMK_COL_WIDTH, CHECKBOX_COL_WIDTH, EVIDENCE_COL_WIDTH, EVIDENCE_COL_MIN_WIDTH } from "../constants/grid.js";
import { pillToneFor } from "../utils/evidence-pills.js";
import { Badge, Tooltip } from "./primitives/index.js";
import { UNSET_TIMESTAMP_TITLE } from "../utils/datetime.js";
import { isUnsetWindowsTimestamp } from "../utils/forensic-normalize.js";

/**
 * One data row of the timeline grid.
 *
 * Memoized, and that is the whole point of the file existing. The grid renders ~80 rows
 * and re-renders on every scroll frame; without a memo boundary here each frame rebuilt
 * every row and every one of its cells. Scrolling now only re-renders the rows entering
 * and leaving the viewport.
 *
 * For the memo to hold, everything this component reads has to keep a stable identity
 * across a scroll frame. That is why the shared state arrives as a single `ctx` object
 * built with useMemo in VirtualGrid, why the callbacks inside it are useCallback-wrapped
 * in App.jsx, and why the per-row facts that DO change (`sel`, `bm`, `tabIndex`) come in
 * as primitives — a selection change then re-renders only the rows whose own flag flipped.
 *
 * `ctx.ct` is the deliberate exception: it takes a new identity on every tab-state write,
 * so tagging or bookmarking re-renders all rendered rows. That is off the 60fps path and
 * keeps this body identical to the markup it was extracted from.
 */
function GridRowInner({ ctx, row, ai, sel, bm, tabIndex }) {
  const {
    th, ct, isGrouped, tagColWidth, leftBase, vtW, fontSize, selectedColumn,
    pinnedH, pinnedOffsets, compiledColors, pageOffset, tw,
    windowedScrollH, firstScrollColIndex, colWindow,
    gw, fmtCell, renderCell, getRowBg,
    handleRowClick, handleBookmark, handleCheckboxToggle,
    setCellPopup, setCellContextMenu, up, activateOnKey,
  } = ctx;

  const rTags = ct.rowTags[row.__idx] || EMPTY_TAGS;
  const cm = applyColors(row, compiledColors);
  const rowBg = getRowBg(ai, row, sel, cm, bm);

  // Evidence pill focus: dim rows that don't carry the active pill
  const _pillFilter = ct.evidencePillFilter;
  const _pillDimmed = _pillFilter && !(ct.evidencePillsByRowid?.[row.__idx] || EMPTY_TAGS).some(p => p.text === _pillFilter);

  // Opaque base for sticky cells (selection/bookmark overlays are semi-transparent)
  const stickyBase = cm ? cm.bg : (ai % 2 === 0 ? th.rowEven : th.rowOdd);
  const stickyOverlay = sel ? `inset 0 0 0 9999px ${th.selection}` : bm ? `inset 0 0 0 9999px ${th.bookmark}` : "none";

  // aria-colindex is 1-based across the whole row. The scrollable lane omits off-screen
  // cells, so its indices must be explicit — and ARIA requires that every cell in a row
  // carry one once any of them does. These mirror the arithmetic behind
  // firstScrollColIndex, which VirtualGrid derives from the same lane order.
  const colIdxVt = 4;
  const colIdxEvidence = 4 + (ct.vtEnrichment ? 1 : 0);
  const firstPinnedColIndex = firstScrollColIndex - pinnedH.length;

  return (
    <div data-row-id={row.__idx} data-row-index={ai} role="row" aria-rowindex={ai + 2} aria-selected={!!sel}
      tabIndex={tabIndex}
      onKeyDown={(e) => activateOnKey(e, (keyEvent) => handleRowClick(ai, keyEvent))}
      onClick={(e) => handleRowClick(ai, e)}
      onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
      style={{ display: "flex", height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT - (pageOffset || 0), width: tw, boxSizing: "border-box",
        background: rowBg, color: cm ? cm.fg : th.text, borderBottom: `1px solid ${th.cellBorder}`,
        boxShadow: sel ? `inset 2px 0 0 0 ${th.borderAccent}` : "none", cursor: "default",
        paddingLeft: isGrouped ? 16 : 0, opacity: _pillDimmed ? 0.25 : 1, transition: "opacity var(--m-base)" }}>
      {/* Bookmark - always sticky */}
      <div role="gridcell" aria-colindex={1} style={{ display: "flex", alignItems: "center", justifyContent: "center", width: isGrouped ? 26 : BKMK_COL_WIDTH, minWidth: isGrouped ? 26 : BKMK_COL_WIDTH, boxSizing: "border-box", position: "sticky", left: isGrouped ? 16 : 0, zIndex: 3, background: stickyBase, boxShadow: stickyOverlay }}>
        <button type="button" aria-label={`${bm ? "Remove" : "Add"} bookmark for row ${ai + 1}`} aria-pressed={!!bm}
          onClick={(e) => { e.stopPropagation(); handleBookmark(row.__idx); }}
          style={{ width: 26, height: 26, padding: 0, display: "flex", alignItems: "center", justifyContent: "center", background: "none", border: "none", cursor: "pointer" }}>
          <BkmkIcon filled={bm} />
        </button>
      </div>
      {/* Checkbox cell */}
      <div role="gridcell" aria-colindex={2} style={{ display: "flex", alignItems: "center", justifyContent: "center", width: CHECKBOX_COL_WIDTH, minWidth: CHECKBOX_COL_WIDTH, boxSizing: "border-box", position: "sticky", left: isGrouped ? 42 : BKMK_COL_WIDTH, zIndex: 3, background: stickyBase, boxShadow: stickyOverlay }}>
        <button type="button" aria-label={`${sel ? "Deselect" : "Select"} row ${ai + 1}`} aria-pressed={!!sel}
          onClick={(e) => { e.stopPropagation(); handleCheckboxToggle(ai); }}
          style={{ width: 26, height: 26, padding: 0, display: "flex", alignItems: "center", justifyContent: "center", background: "none", border: "none", cursor: "pointer" }}>
          <CheckboxIcon checked={sel} />
        </button>
      </div>
      {/* Tags cell — sticky */}
      <div role="gridcell" aria-colindex={3} style={{ display: "flex", alignItems: "center", gap: 2, width: tagColWidth, minWidth: tagColWidth, boxSizing: "border-box", padding: "0 4px", overflow: "hidden", borderRight: `1px solid ${th.cellBorder}`, position: "sticky", left: isGrouped ? 42 + CHECKBOX_COL_WIDTH : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH), zIndex: 2, background: stickyBase, boxShadow: stickyOverlay }}>
        {rTags.map((tag) => (
          <span key={tag} style={{ padding: "0 4px", borderRadius: 3, fontSize: 11, background: ((ct.tagColors || {})[tag] || th.textMuted) + "33", color: (ct.tagColors || {})[tag] || th.textDim, whiteSpace: "nowrap", lineHeight: "18px" }}>{tag}</span>
        ))}
      </div>
      {/* VT verdict cell — sticky, after tags */}
      {ct.vtEnrichment && (() => {
        const vte = ct.vtEnrichment;
        // Collect all IOC verdicts for this row + track worst for badge
        let worstVerdict = null, worstScore = "", worstUrl = null;
        const iocDetails = [];
        for (const tag of rTags) {
          if (!tag.startsWith("IOC: ")) continue;
          const iocRaw = tag.slice(5);
          const vtr = vte.results[iocRaw];
          if (!vtr) continue;
          iocDetails.push({ ioc: iocRaw, verdict: vtr.verdict, score: vtr.score, url: vtr.vtUrl, threatLabel: vtr.threatLabel });
          if (vtr.verdict === "malicious" && worstVerdict !== "malicious") { worstVerdict = "malicious"; worstScore = vtr.score; worstUrl = vtr.vtUrl; }
          else if (vtr.verdict === "suspicious" && worstVerdict !== "malicious" && worstVerdict !== "suspicious") { worstVerdict = "suspicious"; worstScore = vtr.score; worstUrl = vtr.vtUrl; }
          else if (vtr.verdict === "clean" && !worstVerdict) { worstVerdict = "clean"; worstScore = vtr.score; worstUrl = vtr.vtUrl; }
          else if (vtr.verdict === "not_found" && !worstVerdict) { worstVerdict = "not_found"; worstScore = vtr.score; worstUrl = vtr.vtUrl; }
          else if (vtr.verdict === "error" && !worstVerdict) { worstVerdict = "error"; worstScore = vtr.score || "Error"; worstUrl = vtr.vtUrl; }
          else if (vtr.verdict === "unsupported" && !worstVerdict) { worstVerdict = "unsupported"; worstScore = vtr.score || "N/A"; worstUrl = null; }
          else if (vtr.verdict === "private" && !worstVerdict) { worstVerdict = "private"; worstScore = vtr.score || "Private"; worstUrl = null; }
        }
        const vtColor = worstVerdict === "malicious" ? th.danger : worstVerdict === "suspicious" ? th.warning : worstVerdict === "clean" ? th.success : worstVerdict === "error" ? th.danger : th.textMuted;
        const tooltip = iocDetails.length > 0 ? iocDetails.map((d) => `${d.ioc} → ${d.verdict} (${d.score})${d.threatLabel ? ` [${d.threatLabel}]` : ""}`).join("\n") : "";
        const worstThreat = iocDetails.find((d) => d.verdict === worstVerdict && d.threatLabel)?.threatLabel || null;
        
        return (
          <div role="gridcell" aria-colindex={colIdxVt} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 3, width: vtW, minWidth: 40, boxSizing: "border-box", borderRight: `1px solid ${th.cellBorder}`, position: "sticky", left: (isGrouped ? 42 + CHECKBOX_COL_WIDTH : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH)) + tagColWidth, zIndex: 2, background: stickyBase, boxShadow: stickyOverlay, overflow: "hidden" }}>
            {worstVerdict && (
              <Tooltip content={tooltip} maxWidth={420}>
                <span
                  onClick={worstUrl ? (e) => { e.stopPropagation(); window.open(worstUrl, "_blank"); } : undefined}
                  style={{ fontSize: 11, padding: "1px 4px", borderRadius: 3, fontWeight: 700, fontFamily: "'SF Mono', Menlo, monospace",
                    background: `${vtColor}22`, color: vtColor, border: `1px solid ${vtColor}44`, lineHeight: "14px",
                    cursor: worstUrl ? "pointer" : "default", flexShrink: 0 }}>
                  {worstScore}
                </span>
              </Tooltip>
            )}
            {worstThreat && vtW > 90 && (
              <Tooltip content={worstThreat}>
                <span style={{ fontSize: 11, color: vtColor, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontStyle: "italic" }}>{worstThreat}</span>
              </Tooltip>
            )}
          </div>
        );
      })()}
      {/* Evidence pills cell — sticky, after VT */}
      {(() => {
        const pillsMap = ct.evidencePillsByRowid;
        if (!pillsMap || Object.keys(pillsMap).length === 0) return null;
        const evW = ct.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH;
        
        
        const rowPills = pillsMap[row.__idx];
        return (
          <div role="gridcell" aria-colindex={colIdxEvidence} style={{ display: "flex", alignItems: "center", gap: 3, width: evW, minWidth: EVIDENCE_COL_MIN_WIDTH, boxSizing: "border-box", padding: "0 6px", overflow: "hidden", borderRight: `1px solid ${th.cellBorder}`, position: "sticky", left: leftBase, zIndex: 2, background: stickyBase, boxShadow: stickyOverlay }}>
            {rowPills && rowPills.map((p, pi) => (
              <Badge key={pi} size="sm" tone={pillToneFor(p.type)} title={`${p.type} — click to highlight`}
                style={{ cursor: "pointer" }}
                onClick={(ev) => { ev.stopPropagation(); up("evidencePillFilter", ct.evidencePillFilter === p.text ? null : p.text); }}>
                {p.text}
              </Badge>
            ))}
          </div>
        );
      })()}
      {/* Pinned data cells */}
      {pinnedH.map((h, pi) => (
        <div key={h} data-cell-col={h} role="gridcell" aria-colindex={firstPinnedColIndex + pi} onDoubleClick={() => setCellPopup({ column: h, value: row[h] || "" })} title={ct.tsColumns?.has(h) && isUnsetWindowsTimestamp(row[h]) ? UNSET_TIMESTAMP_TITLE : fmtCell(h, row[h])}
          onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.stopPropagation(); setCellContextMenu({ x: e.clientX, y: e.clientY, colName: h, cellValue: row[h] || "" }); } }}
          onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
          style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", display: "flex", alignItems: "center", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}44` : `1px solid ${th.cellBorder}`, fontSize: fontSize - 0.5, position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 2, background: selectedColumn === h ? `linear-gradient(${th.accent}26, ${th.accent}26), ${stickyBase}` : stickyBase, boxShadow: stickyOverlay }}>
          {renderCell(h, row[h])}
        </div>
      ))}
      {/* Scrollable data cells — horizontally windowed; the spacers stand in for the
          columns off screen so the row keeps its full width and the scrollbar its extent. */}
      {colWindow.padLeft > 0 && <div aria-hidden="true" style={{ width: colWindow.padLeft, minWidth: colWindow.padLeft, flexShrink: 0 }} />}
      {windowedScrollH.map((h, wi) => (
        <div key={h} data-cell-col={h} role="gridcell" aria-colindex={firstScrollColIndex + wi} onDoubleClick={() => setCellPopup({ column: h, value: row[h] || "" })} title={ct.tsColumns?.has(h) && isUnsetWindowsTimestamp(row[h]) ? UNSET_TIMESTAMP_TITLE : fmtCell(h, row[h])}
          onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.stopPropagation(); setCellContextMenu({ x: e.clientX, y: e.clientY, colName: h, cellValue: row[h] || "" }); } }}
          onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
          style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", display: "flex", alignItems: "center", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", borderRight: `1px solid ${th.cellBorder}`, fontSize: fontSize - 0.5, background: selectedColumn === h ? `${th.accent}1f` : undefined }}>
          {renderCell(h, row[h])}
        </div>
      ))}
      {colWindow.padRight > 0 && <div aria-hidden="true" style={{ width: colWindow.padRight, minWidth: colWindow.padRight, flexShrink: 0 }} />}
    </div>
  );
}

/** Shared empty array — a fresh [] per row would allocate 80× per frame for no reason. */
const EMPTY_TAGS = [];

const GridRow = memo(GridRowInner);
export default GridRow;
