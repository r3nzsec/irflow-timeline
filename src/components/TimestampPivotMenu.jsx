import { useRef, useState } from "react";
import { createPortal } from "react-dom";
import { normalizeTimestamp } from "../utils/forensic-normalize.js";

const WINDOWS = [
  { label: "30s", ms: 30_000 },
  { label: "1m", ms: 60_000 },
  { label: "5m", ms: 300_000 },
  { label: "10m", ms: 600_000 },
];

/** Fast pivots use the clicked cell, independently of the current row selection. */
export default function TimestampPivotMenu({ th, tab, column, row, onPivot }) {
  const [open, setOpen] = useState(null);
  const rootRef = useRef(null);
  const popupRef = useRef(null);
  const buttons = useRef({});
  if (!tab?.tsColumns?.has(column)
    || !Number.isFinite(normalizeTimestamp(row?.[column]))) return null;

  const show = (clear, button, focusFirst = false) => {
    const rect = button.getBoundingClientRect();
    const width = 160, height = 142;
    const left = rect.right + width <= window.innerWidth - 8
      ? rect.right : Math.max(8, rect.left - width);
    setOpen({ clear, left, top: Math.max(8, Math.min(rect.top, window.innerHeight - height - 8)), focusFirst });
  };
  const leave = (e) => {
    const next = e.relatedTarget;
    if (next instanceof Node && (rootRef.current?.contains(next) || popupRef.current?.contains(next))) return;
    setOpen(null);
  };
  const itemStyle = {
    display: "flex", alignItems: "center", gap: 10, width: "calc(100% - 8px)",
    padding: "7px 12px", margin: "0 4px", background: "none", border: "none",
    color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left",
    fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6,
  };
  const hover = {
    onMouseEnter: (e) => { e.currentTarget.style.background = `${th.accent}22`; },
    onMouseLeave: (e) => { e.currentTarget.style.background = "transparent"; },
  };
  const label = (clear) => clear ? "Pivot and clear filters" : "Pivot with filters";
  return <div ref={rootRef} data-timestamp-pivot-menu="" onMouseLeave={leave}>
    {[false, true].map((clear) => <button key={String(clear)}
      ref={(el) => { buttons.current[String(clear)] = el; }}
      type="button" role="menuitem" aria-haspopup="menu" aria-expanded={open?.clear === clear}
      title="Show events before and after this timestamp"
      {...hover} style={itemStyle}
      onMouseEnter={(e) => { hover.onMouseEnter(e); show(clear, e.currentTarget); }}
      onClick={(e) => show(clear, e.currentTarget)}
      onKeyDown={(e) => {
        if (["ArrowRight", "ArrowDown", "Enter", " "].includes(e.key)) {
          e.preventDefault(); e.stopPropagation(); show(clear, e.currentTarget, true);
        }
      }}>
      <span aria-hidden="true">⏱</span>{label(clear)}<span aria-hidden="true" style={{ marginLeft: "auto" }}>▸</span>
    </button>)}
    {open && createPortal(<div
      ref={(el) => {
        popupRef.current = el;
        if (el && open.focusFirst) el.querySelector("button")?.focus();
      }}
      role="menu" aria-label={`${label(open.clear)} time windows`} data-timestamp-pivot-menu=""
      onMouseLeave={leave} onMouseDown={(e) => e.stopPropagation()}
      onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
      onKeyDown={(e) => {
        const items = [...e.currentTarget.querySelectorAll("button")];
        const index = items.indexOf(document.activeElement);
        if (["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) {
          e.preventDefault(); e.stopPropagation();
          const next = e.key === "Home" ? 0 : e.key === "End" ? items.length - 1
            : (index + (e.key === "ArrowUp" ? -1 : 1) + items.length) % items.length;
          items[next]?.focus();
        } else if (["Escape", "ArrowLeft"].includes(e.key)) {
          e.preventDefault(); e.stopPropagation(); setOpen(null); buttons.current[String(open.clear)]?.focus();
        }
      }}
      style={{ position: "fixed", left: open.left, top: open.top, width: 160, padding: "5px 0",
        zIndex: 100000, borderRadius: 10, background: th.modalBg, border: `1px solid ${th.modalBorder}`,
        boxShadow: "0 8px 28px rgba(0,0,0,0.25)", WebkitAppRegion: "no-drag" }}>
      {WINDOWS.map(({ label: windowLabel, ms }) => <button key={ms} type="button" role="menuitem"
        {...hover} style={itemStyle} onClick={() => onPivot(column, row, ms, windowLabel, open.clear)}>
        ±{windowLabel}
      </button>)}
    </div>, document.body)}
  </div>;
}
