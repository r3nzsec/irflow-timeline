import { useState, useMemo, useRef } from "react";
import useUIStore from "../store/useUIStore.js";
import useTabStore from "../store/useTabStore.js";
import { PRESETS } from "../constants/presets.js";
import { formatNumber, formatBytes } from "../utils/format.js";

// Helper to build the theme-dependent modal styles object
export function makeModalStyles(th) {
  return {
    mh: { margin: "0 0 14px", fontSize: 16, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" },
    fg: { marginBottom: 10 },
    lb: { display: "block", fontSize: 10, color: th.textDim, marginBottom: 3, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" },
    sl: { width: "100%", padding: "6px 8px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit" },
    ip: { width: "100%", padding: "6px 8px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit", boxSizing: "border-box" },
    bp: { padding: "6px 16px", background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 6, fontSize: 12, fontWeight: 500, cursor: "pointer", fontFamily: "-apple-system,sans-serif" },
    bs: { padding: "6px 16px", background: th.btnBg, color: th.text, border: `1px solid ${th.btnBorder}`, borderRadius: 6, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system,sans-serif" },
    bsm: { padding: "3px 8px", background: th.btnBg, color: th.text, border: `1px solid ${th.btnBorder}`, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif" },
  };
}

// Shared modal overlay wrapper
export function Overlay({ th, children }) {
  return (
    <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitBackdropFilter: "blur(4px)", WebkitAppRegion: "drag", animation: "tle-overlay-in var(--m-fast) var(--ease-out-soft)" }}>
      <div style={{ background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 12, padding: 24, width: 480, maxWidth: "92vw", maxHeight: "80vh", overflow: "auto", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", WebkitAppRegion: "no-drag", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
        {children}
      </div>
    </div>
  );
}

export function ColorModal({ th, ct, up, ms }) {
  const setModal = useUIStore((s) => s.setModal);
  const [col, setCol] = useState(ct?.headers[0] || "");
  const [cond, setCond] = useState("contains");
  const [val, setVal] = useState("");
  const [bg, setBg] = useState("#7f1d1d");
  const [fg, setFg] = useState("#fca5a5");
  return (
    <Overlay th={th}>
      <h3 style={ms.mh}>Conditional Formatting</h3>
      <div style={ms.fg}><label style={ms.lb}>Column</label>
        <select value={col} onChange={(e) => setCol(e.target.value)} style={ms.sl}>
          {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}</select></div>
      <div style={ms.fg}><label style={ms.lb}>Condition</label>
        <select value={cond} onChange={(e) => setCond(e.target.value)} style={ms.sl}>
          <option value="contains">Contains</option><option value="equals">Equals</option>
          <option value="startswith">Starts With</option><option value="regex">Regex</option></select></div>
      <div style={ms.fg}><label style={ms.lb}>Value</label>
        <input value={val} onChange={(e) => setVal(e.target.value)} style={ms.ip} placeholder="e.g. powershell.exe" /></div>
      <div style={{ display: "flex", gap: 16 }}>
        <div style={ms.fg}><label style={ms.lb}>Background</label>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <input type="color" value={bg} onChange={(e) => setBg(e.target.value)} style={{ width: 32, height: 24, border: "none", cursor: "pointer", borderRadius: 4 }} />
            <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "monospace" }}>{bg}</span></div></div>
        <div style={ms.fg}><label style={ms.lb}>Text Color</label>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <input type="color" value={fg} onChange={(e) => setFg(e.target.value)} style={{ width: 32, height: 24, border: "none", cursor: "pointer", borderRadius: 4 }} />
            <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "monospace" }}>{fg}</span></div></div>
      </div>
      <div style={{ marginTop: 8 }}><label style={ms.lb}>DFIR Presets</label>
        <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 4 }}>
          {PRESETS.map((p, i) => <button key={i} onClick={() => { setCol(ct.headers.includes(p.column) ? p.column : ct.headers[0]); setCond(p.condition); setVal(p.value); setBg(p.bgColor); setFg(p.fgColor); }}
            style={{ padding: "3px 8px", background: p.bgColor, color: p.fgColor, border: "1px solid rgba(255,255,255,0.1)", borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "inherit" }}>{p.label}</button>)}
        </div></div>
      {ct.colorRules.length > 0 && <div style={{ marginTop: 12 }}><label style={ms.lb}>Active ({ct.colorRules.length})</label>
        <div style={{ maxHeight: 100, overflow: "auto", marginTop: 4 }}>
          {ct.colorRules.map((r, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 0", borderBottom: `1px solid ${th.border}` }}>
              <div style={{ width: 12, height: 12, borderRadius: 3, background: r.bgColor, flexShrink: 0 }} />
              <span style={{ color: th.textDim, fontSize: 11, flex: 1 }}>{r.column} {r.condition} "{r.value}"</span>
              <button onClick={() => up("colorRules", ct.colorRules.filter((_, j) => j !== i))} style={{ background: "none", border: "none", color: th.danger, cursor: "pointer", fontSize: 12 }}>&#x2715;</button>
            </div>))}
        </div></div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
        <button onClick={() => up("colorRules", [])} style={ms.bs}>Clear All</button>
        <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
        <button disabled={!val} onClick={() => { up("colorRules", [...ct.colorRules, { column: col, condition: cond, value: val, bgColor: bg, fgColor: fg }]); setModal(null); }} style={ms.bp}>Add Rule</button>
      </div>
    </Overlay>
  );
}

export function ColModal({ th, ct, up, ms, colMgrSearch, setColMgrSearch, colMgrDragOver, setColMgrDragOver }) {
  const setModal = useUIStore((s) => s.setModal);
  const colMgrDragSrcRef = useRef(null);

  // Build ordered column list: respect columnOrder, append any new headers not yet in it
  const orderedCols = useMemo(() => {
    const order = ct.columnOrder?.length > 0 ? ct.columnOrder : ct.headers;
    const inHeaders = new Set(ct.headers);
    const inOrder = new Set(order);
    return [
      ...order.filter((h) => inHeaders.has(h)),
      ...ct.headers.filter((h) => !inOrder.has(h)),
    ];
  }, [ct.columnOrder, ct.headers]);

  const handleDragStart = (e, idx) => {
    colMgrDragSrcRef.current = idx;
    e.dataTransfer.effectAllowed = "move";
    // Minimal drag image so the handle feel is snappy
    e.dataTransfer.setDragImage(e.currentTarget, 12, 12);
  };

  const handleDragOver = (e, idx) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    if (colMgrDragOver !== idx) setColMgrDragOver(idx);
  };

  const handleDrop = (e, idx) => {
    e.preventDefault();
    const src = colMgrDragSrcRef.current;
    if (src === null || src === idx) { colMgrDragSrcRef.current = null; setColMgrDragOver(null); return; }
    const newOrder = [...orderedCols];
    const [removed] = newOrder.splice(src, 1);
    newOrder.splice(idx, 0, removed);
    up("columnOrder", newOrder);
    colMgrDragSrcRef.current = null;
    setColMgrDragOver(null);
  };

  const handleDragEnd = () => {
    colMgrDragSrcRef.current = null;
    setColMgrDragOver(null);
  };

  return (
    <Overlay th={th}>
      <h3 style={ms.mh}>Column Manager</h3>
      <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
        <button onClick={() => up("hiddenColumns", new Set())} style={ms.bsm}>Show All</button>
        <button onClick={() => up("hiddenColumns", new Set(ct.headers))} style={ms.bsm}>Hide All</button>
        <button onClick={() => up("columnOrder", [...ct.headers])} style={ms.bsm}>Reset Order</button>
      </div>
      <input
        type="text"
        placeholder="Search columns…"
        value={colMgrSearch}
        onChange={(e) => setColMgrSearch(e.target.value)}
        style={{ ...ms.ip, marginBottom: 8 }}
        autoFocus
      />
      <div style={{ fontSize: 10, color: th.textMuted, marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>
        Drag ⠿ to reorder · checkbox to show/hide
      </div>
      <div style={{ maxHeight: "55vh", overflow: "auto" }}>
        {orderedCols.map((h, origIdx) => [h, origIdx]).filter(([h]) => !colMgrSearch || h.toLowerCase().includes(colMgrSearch.toLowerCase())).map(([h, origIdx]) => {
          const idx = origIdx;
          const isDragOver = colMgrDragOver === idx;
          return (
            <div
              key={h}
              draggable
              onDragStart={(e) => handleDragStart(e, idx)}
              onDragOver={(e) => handleDragOver(e, idx)}
              onDrop={(e) => handleDrop(e, idx)}
              onDragEnd={handleDragEnd}
              style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "5px 4px",
                borderBottom: `1px solid ${th.bgAlt}`,
                borderTop: isDragOver ? `2px solid ${th.accent}` : "2px solid transparent",
                background: isDragOver ? `${th.accent}0d` : "transparent",
                color: th.text, fontSize: 12,
                transition: "border-top var(--m-fast), background var(--m-fast)",
                userSelect: "none",
              }}>
              <span
                title="Drag to reorder"
                style={{ cursor: "grab", color: th.textMuted, fontSize: 15, lineHeight: 1, padding: "0 3px", flexShrink: 0 }}>
                ⠿
              </span>
              <input
                type="checkbox"
                checked={!ct.hiddenColumns.has(h)}
                onChange={() => { const s = new Set(ct.hiddenColumns); s.has(h) ? s.delete(h) : s.add(h); up("hiddenColumns", s); }}
                style={{ accentColor: th.borderAccent, cursor: "pointer", flexShrink: 0 }}
              />
              <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{h}</span>
              {ct.tsColumns.has(h) && <span title="Timestamp column" style={{ fontSize: 10, color: th.accent, flexShrink: 0 }}>&#x23F1;</span>}
              {ct.numericColumns?.has(h) && <span title="Numeric column" style={{ fontSize: 10, color: th.success, flexShrink: 0 }}>#</span>}
              {(ct.pinnedColumns || []).includes(h) && <span title="Pinned" style={{ fontSize: 10, color: th.warning, flexShrink: 0 }}>&#x1F4CC;</span>}
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
        <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
      </div>
    </Overlay>
  );
}

export function ShortModal({ th, ms }) {
  const setModal = useUIStore((s) => s.setModal);
  return (
    <Overlay th={th}>
      <h3 style={ms.mh}>Shortcuts & Search Syntax</h3>
      {[["⌘ O", "Open file"], ["⌘ E", "Export filtered view"], ["⌘⇧R", "Generate report"], ["⌘ S", "Save session"], ["⌘⇧O", "Open session"], ["⌘ W", "Close tab"], ["⌘⇧Q", "Close all tabs"], ["⌘ F", "Focus search"], ["⌘⇧F", "Find in all tabs"], ["F3 / ⌘→", "Next search match"], ["⇧F3 / ⌘←", "Previous search match"], ["↑ / ↓", "Navigate rows"], ["⌘ B", "Toggle bookmarked only"], ["⌘⇧C", "Column Manager"], ["⌘⇧L", "Conditional Formatting"], ["⌘ R", "Reset column widths"], ["⌘ + / ⌘ -", "Font size increase / decrease"], ["⌘ C", "Copy selected rows"], ["Shift+Click", "Select range"], ["⌘+Click", "Context menu (Copy / Tags)"], ["⌃+Click", "Context menu (alt)"], ["⇧F10", "Context menu (keyboard)"], ["FL / HL", "Toggle filter/highlight search mode"], ["⏱ icon", "Date range filter (timestamp cols)"], ["Dbl-click", "Cell detail popup"], ["Dbl-click border", "Auto-fit column"], ["Drag header", "Group by column"], ["Esc", "Close panel/modal"]].map(([k, d]) => (
        <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderBottom: `1px solid ${th.bgAlt}` }}>
          <kbd style={{ background: th.btnBg, color: th.accent, padding: "2px 7px", borderRadius: 4, fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace", border: `1px solid ${th.btnBorder}` }}>{k}</kbd>
          <span style={{ color: th.textDim, fontSize: 12 }}>{d}</span>
        </div>
      ))}
      <h4 style={{ color: th.text, fontSize: 12, marginTop: 12, marginBottom: 6 }}>Mixed Search Syntax</h4>
      {[["word1 word2", "OR"], ["+word", "AND (must include)"], ["-word", "EXCLUDE"], ['"exact phrase"', "Phrase"], ["Column:value", "Column filter"]].map(([s, d]) => (
        <div key={s} style={{ fontSize: 12, color: th.textDim, padding: "2px 0" }}>
          <code style={{ background: th.btnBg, padding: "1px 5px", borderRadius: 3, color: th.accent }}>{s}</code> — {d}
        </div>
      ))}
      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
        <button onClick={() => setModal(null)} style={ms.bp}>Close</button>
      </div>
    </Overlay>
  );
}

export function SheetModal({ th, ms, tle }) {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const data = modal;
  return (
    <Overlay th={th}>
      <h3 style={ms.mh}>Select Sheet — {data.fileName}</h3>
      <p style={{ color: th.textDim, fontSize: 12, marginBottom: 12 }}>This workbook has multiple sheets:</p>
      {(Array.isArray(data.sheets) ? data.sheets : []).map((s) => (
        <button key={s.id} onClick={() => { tle.selectSheet({ filePath: data.filePath, tabId: data.tabId, fileName: `${data.fileName} [${s.name}]`, sheetName: s.id }); setModal(null); }}
          style={{ display: "block", width: "100%", textAlign: "left", padding: "10px 14px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 13, cursor: "pointer", marginBottom: 6, fontFamily: "inherit" }}>
          {s.name} <span style={{ color: th.textMuted, fontSize: 11 }}>({s.rowCount} rows)</span>
        </button>
      ))}
      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 12 }}>
        <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
      </div>
    </Overlay>
  );
}

export function ImportProgress({ th, info }) {
  const importQueue = useTabStore((s) => s.importQueue);
  const queueLen = importQueue.length;
  const phase = info?.phase || (info?.status === "indexing" ? "finalizing" : "parsing");
  const phaseLabel = phase === "finalizing"
    ? "Finalizing SQLite timeline..."
    : phase === "parsing"
      ? "Reading and importing events..."
      : "Preparing import...";
  const percent = Math.max(0, Math.min(100, Number.isFinite(info?.percent) ? info.percent : 0));
  const byteTotal = info?.totalBytes || info?.fileSize || 0;
  const hasByteProgress = byteTotal > 0 && Number.isFinite(info?.bytesRead);
  return (
  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", padding: 40 }}>
    {/* Logo + tagline */}
    <svg width="48" height="54" viewBox="0 0 64 72" fill="none" style={{ marginBottom: 12, opacity: 0.85 }}>
      <path d="M32 4L6 16v20c0 16.5 11.2 31.2 26 36 14.8-4.8 26-19.5 26-36V16L32 4z" fill={`${th.accent}18`} stroke={th.accent} strokeWidth="1.8" strokeLinejoin="round" />
      <polyline points="14,40 22,40 25,28 29,48 33,22 37,44 40,34 42,40 50,40" fill="none" stroke={th.accent} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="32" cy="20" r="6" fill="none" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
      <line x1="32" y1="15.5" x2="32" y2="17" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
      <line x1="32" y1="23" x2="32" y2="24.5" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
      <line x1="27.5" y1="20" x2="29" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
      <line x1="35" y1="20" x2="36.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
      <line x1="32" y1="20" x2="32" y2="17.5" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
      <line x1="32" y1="20" x2="34.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
    </svg>
    <div style={{ fontSize: 18, fontWeight: 700, color: th.text, fontFamily: "-apple-system, 'SF Pro Display', sans-serif", marginBottom: 2 }}>IRFlow <span style={{ color: th.accent }}>Timeline</span></div>
    <p style={{ color: th.textMuted, fontSize: 12, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 28, fontFamily: "-apple-system, sans-serif" }}>DFIR Timeline Analysis</p>
    {/* Progress */}
    <div style={{ width: 400, maxWidth: "100%" }}>
      <h3 style={{ color: th.text, fontSize: 16, marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>
        {info?.status === "indexing" ? "Finalizing..." : "Importing..."}
      </h3>
      <p style={{ color: th.textDim, fontSize: 13, marginBottom: 8 }}>{info?.fileName}</p>
      <p style={{ color: th.textMuted, fontSize: 11, marginBottom: 16, fontFamily: "-apple-system, sans-serif" }}>{phaseLabel}</p>
      <div style={{ height: 6, background: th.border, borderRadius: 3, overflow: "hidden", marginBottom: 12 }}>
        <div style={{ height: "100%", width: "100%", background: info?.status === "indexing" ? th.warning : th.borderAccent, borderRadius: 3, transformOrigin: "left", transform: `scaleX(${percent / 100})`, transition: "transform var(--m-slow)" }} />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", color: th.textDim, fontSize: 12 }}>
        <span>{formatNumber(info?.rowsImported || 0)} rows imported</span>
        <span>{percent}%</span>
      </div>
      {hasByteProgress && (
        <div style={{ display: "flex", justifyContent: "space-between", color: th.textMuted, fontSize: 10, marginTop: 6, fontFamily: "SF Mono, Menlo, monospace" }}>
          <span>{formatBytes(info.bytesRead || 0)} read</span>
          <span>{formatBytes(byteTotal)}</span>
        </div>
      )}
      {info?.fileSize > 3 * 1024 * 1024 * 1024 && (
        <div style={{ marginTop: 16, padding: "10px 14px", background: (th.warning) + "15", border: `1px solid ${(th.warning)}44`, borderRadius: 8, color: th.warning, fontSize: 11, lineHeight: 1.5, fontFamily: "-apple-system, sans-serif" }}>
          <strong>Large file detected ({(info.fileSize / (1024 * 1024 * 1024)).toFixed(1)} GB)</strong> — This may take several minutes. Do not close this window or import additional files until ingestion is complete.
        </div>
      )}
      {queueLen > 0 && (
        <div style={{ marginTop: 20, padding: "12px 14px", background: `${th.accent}08`, border: `1px solid ${th.border}44`, borderRadius: 8 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>
            Queued ({queueLen} file{queueLen > 1 ? "s" : ""} waiting)
          </div>
          {importQueue.map((q, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>
              <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "SF Mono, monospace", minWidth: 16 }}>{i + 1}.</span>
              <span style={{ color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{q.fileName}</span>
              <span style={{ color: th.textDim, fontSize: 10, fontFamily: "SF Mono, monospace", flexShrink: 0 }}>{q.fileSize > 1048576 ? `${(q.fileSize / 1048576).toFixed(1)} MB` : q.fileSize > 1024 ? `${(q.fileSize / 1024).toFixed(0)} KB` : `${q.fileSize} B`}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  </div>
  );
}
