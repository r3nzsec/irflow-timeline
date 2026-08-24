import { useState } from "react";
import useTheme from "../../hooks/useTheme.js";
import Modal from "./Modal.jsx";

/**
 * Draggable + resizable modal shell.
 *
 * Replaces the ~95-line copy of startDrag/startResize/edgeStyle/positioning
 * boilerplate that was previously duplicated across 11 analysis modals
 * (Heatmap, Ransomware, Persistence, LateralMovement, Timestomping,
 * Stacking, ADS, Usn, ColumnStats, ProcessTree, SigmaRule).
 *
 * Position state lives inside this component (useState) — matches the prior
 * behaviour where modal position resets on close/reopen, since per-modal
 * `modal.rwX/rwY/rwW/rwH` keys were never persisted across sessions.
 *
 * Children may be a render-prop receiving `{ startDrag, width, height }`.
 * Attach `startDrag` to whatever element should be the drag handle (typically
 * the modal header). `width`/`height` are the current modal pixel dimensions —
 * useful for inner scroll-panes that need to size relative to the modal.
 *
 * Props:
 *   defaultWidth   default modal width (px)
 *   defaultHeight  default modal height (px); falls back to 88% of viewport
 *   minWidth       minimum width while resizing
 *   minHeight      minimum height while resizing
 *   onClose        ESC / close-button handler
 *   closeOnOverlay default false (matches prior behaviour for analysis modals)
 *   closeOnEscape  default true; set false for result modals that should not be lost on Esc
 *   zIndex         default 100
 *   children       function `({ startDrag }) => JSX` — or plain JSX (no drag handle)
 */
export default function DraggableResizableModal({
  defaultWidth = 720,
  defaultHeight,
  defaultX,
  defaultY,
  minWidth = 420,
  minHeight = 280,
  onClose,
  closeOnOverlay = false,
  closeOnEscape = true,
  zIndex = 100,
  clickThrough = false,
  ariaLabel = "Analysis dialog",
  ariaLabelledBy,
  children,
}) {
  const { th } = useTheme();
  const [rect, setRect] = useState(() => {
    const w = defaultWidth;
    const h = defaultHeight ?? Math.round((typeof window !== "undefined" ? window.innerHeight : 800) * 0.88);
    const vw = typeof window !== "undefined" ? window.innerWidth : 1200;
    const vh = typeof window !== "undefined" ? window.innerHeight : 800;
    return {
      w, h,
      x: defaultX != null ? defaultX : Math.round((vw - w) / 2),
      y: defaultY != null ? defaultY : Math.round((vh - h) / 2),
    };
  });

  const startDrag = (e) => {
    if (e.button !== 0) return;
    if (e.target?.closest?.("button,input,select,textarea,a,label,[role='button'],[data-no-drag='true']")) return;
    e.preventDefault();
    const sx = e.clientX - rect.x, sy = e.clientY - rect.y;
    const onMove = (ev) => setRect((r) => ({
      ...r,
      x: Math.max(0, Math.min(window.innerWidth - 100, ev.clientX - sx)),
      y: Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - sy)),
    }));
    const onUp = () => {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    document.body.style.cursor = "grabbing";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const startResize = (e, edge) => {
    e.preventDefault();
    e.stopPropagation();
    const sx = e.clientX, sy = e.clientY;
    const start = { ...rect };
    const onMove = (ev) => {
      const dx = ev.clientX - sx, dy = ev.clientY - sy;
      let nw = start.w, nh = start.h, nx = start.x, ny = start.y;
      if (edge.includes("r")) nw = Math.max(minWidth, start.w + dx);
      if (edge.includes("b")) nh = Math.max(minHeight, start.h + dy);
      if (edge.includes("l")) { nw = Math.max(minWidth, start.w - dx); nx = start.x + start.w - nw; }
      if (edge.includes("t")) { nh = Math.max(minHeight, start.h - dy); ny = start.y + start.h - nh; }
      setRect({ w: nw, h: nh, x: nx, y: ny });
    };
    const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const edgeStyle = (cursor, pos) => ({ position: "absolute", ...pos, zIndex: 2, cursor });

  return (
    <Modal bare onClose={onClose} closeOnOverlay={closeOnOverlay} closeOnEscape={closeOnEscape} zIndex={zIndex} clickThrough={clickThrough}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label={ariaLabelledBy ? undefined : ariaLabel}
        aria-labelledby={ariaLabelledBy}
        onClick={(e) => e.stopPropagation()} style={{
        WebkitAppRegion: "no-drag",
        pointerEvents: "auto",
        position: "absolute", left: rect.x, top: rect.y, width: rect.w, height: rect.h,
        background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`,
        borderRadius: 14, display: "flex", flexDirection: "column",
        boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset",
        overflow: "hidden",
        backdropFilter: "blur(40px) saturate(1.6)",
        WebkitBackdropFilter: "blur(40px) saturate(1.6)",
        animation: "tle-modal-in var(--m-modal) var(--ease-out)",
      }}>
        {/* 8 resize handles — 4 edges + 4 corners */}
        <div onMouseDown={(e) => startResize(e, "t")}  style={edgeStyle("ns-resize",   { top: 0, left: 8, right: 8, height: 5 })} />
        <div onMouseDown={(e) => startResize(e, "b")}  style={edgeStyle("ns-resize",   { bottom: 0, left: 8, right: 8, height: 5 })} />
        <div onMouseDown={(e) => startResize(e, "l")}  style={edgeStyle("ew-resize",   { left: 0, top: 8, bottom: 8, width: 5 })} />
        <div onMouseDown={(e) => startResize(e, "r")}  style={edgeStyle("ew-resize",   { right: 0, top: 8, bottom: 8, width: 5 })} />
        <div onMouseDown={(e) => startResize(e, "tl")} style={edgeStyle("nwse-resize", { top: 0, left: 0, width: 10, height: 10 })} />
        <div onMouseDown={(e) => startResize(e, "tr")} style={edgeStyle("nesw-resize", { top: 0, right: 0, width: 10, height: 10 })} />
        <div onMouseDown={(e) => startResize(e, "bl")} style={edgeStyle("nesw-resize", { bottom: 0, left: 0, width: 10, height: 10 })} />
        <div onMouseDown={(e) => startResize(e, "br")} style={edgeStyle("nwse-resize", { bottom: 0, right: 0, width: 10, height: 10 })} />

        {typeof children === "function" ? children({ startDrag, width: rect.w, height: rect.h }) : children}
      </div>
    </Modal>
  );
}
