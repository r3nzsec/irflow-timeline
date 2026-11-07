import { useCallback } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { formatNumber } from "../../utils/format.js";
import { Modal, Button } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";

export default function LogSourceCoverageModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const ct = useCurrentTab();
  const { th } = useTheme();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const activeTab = useTabStore((s) => s.activeTab);
  const setTabs = useTabStore((s) => s.setTabs);

  const up = useCallback((key, value) => {
    setTabs((prev) => prev.map((t) => (t.id === activeTab ? { ...t, [key]: value } : t)));
  }, [activeTab, setTabs]);

  const activeFilters = useCallback((tab) => {
    const dis = tab.disabledFilters || new Set();
    if (dis.size === 0) return { columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters };
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: Object.fromEntries(Object.entries(tab.checkboxFilters).filter(([k]) => !dis.has(k))),
    };
  }, []);

  const ms = useModalChrome();

  if (!modal || modal.type !== "logSourceCoverage" || !ct) return null;

  const { phase, sourceCol, tsCol, data } = modal;
  const tsCols = [...(ct.tsColumns || [])];
  const sourcePatterns = /^(Provider|Channel|source|data_type|parser|log_source|EventLog|SourceName|Source|_Source|DataType|ArtifactName|sourcetype|SourceLong|SourceDescription)$/i;
  const knownSourceCols = ct.headers.filter((h) => sourcePatterns.test(h));
  const otherCols = ct.headers.filter((h) => !sourcePatterns.test(h) && !ct.tsColumns?.has(h));

  const handleAnalyze = async () => {
    setModal((p) => ({ ...p, phase: "loading", loading: true, error: null }));
    try {
      const af = activeFilters(ct);
      const result = await tle.getLogSourceCoverage(ct.id, sourceCol, tsCol, {
        searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
        searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
      });
      if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
      setModal((p) => p?.type === "logSourceCoverage" ? ({ ...p, phase: "results", loading: false, data: result, sortBy: "count" }) : p);
    } catch (e) {
      setModal((p) => p?.type === "logSourceCoverage" ? ({ ...p, phase: "config", loading: false, error: e.message }) : p);
    }
  };

  const filterBySource = (sourceValue) => {
    const existing = { ...(ct.checkboxFilters || {}) };
    existing[sourceCol] = [sourceValue];
    up("checkboxFilters", existing);
    setModal(null);
  };

  const parseTs = (ts) => {
    if (!ts) return NaN;
    const s = String(ts).trim();
    let d = new Date(s.replace(" ", "T"));
    if (!isNaN(d.getTime())) return d.getTime();
    d = new Date(s);
    if (!isNaN(d.getTime())) return d.getTime();
    const n = Number(s);
    if (!isNaN(n) && n > 946684800) return n > 1e12 ? n : n * 1000;
    return NaN;
  };
  const fmtDur = (msVal) => {
    if (!msVal || isNaN(msVal) || !isFinite(msVal) || msVal <= 0) return "\u2014";
    const mins = Math.round(msVal / 60000);
    if (mins < 1) return "<1m";
    if (mins < 60) return `${mins}m`;
    if (mins < 1440) return `${Math.floor(mins / 60)}h ${mins % 60}m`;
    return `${Math.floor(mins / 1440)}d ${Math.floor((mins % 1440) / 60)}h`;
  };

  const rowStyle = (i) => ({
    display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 11,
    background: i % 2 === 0 ? "transparent" : `${th.border}15`, cursor: "pointer",
    borderBottom: `1px solid ${th.border}22`, fontFamily: "'SF Mono',Menlo,monospace",
  });

  const footer = (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", width: "100%" }}>
      {phase === "config" && (<>
        <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
        <Button onClick={handleAnalyze}>Analyze</Button>
      </>)}
      {phase === "loading" && <span style={{ color: th.textMuted, fontSize: 11 }}>Scanning...</span>}
      {phase === "results" && (<>
        <Button variant="secondary" onClick={() => setModal((p) => ({ ...p, phase: "config", data: null }))}>Back</Button>
        <Button onClick={() => setModal(null)}>Done</Button>
      </>)}
    </div>
  );

  return (
    <Modal
      title="Log Source Coverage Map"
      subtitle="Visualize evidence coverage across log sources"
      width={700}
      maxHeight="88vh"
      onClose={() => setModal(null)}
      bodyPadding="16px 20px"
      footer={footer}
    >
      <div>
          {phase === "config" && (<>
            <div style={ms.fg}>
              <label style={ms.lb}>Source Column</label>
              <select value={sourceCol} onChange={(e) => setModal((p) => ({ ...p, sourceCol: e.target.value }))} style={ms.sl}>
                {knownSourceCols.length > 0 && (
                  <optgroup label="Detected Source Columns">
                    {knownSourceCols.map((c) => <option key={c} value={c}>{c}</option>)}
                  </optgroup>
                )}
                <optgroup label={knownSourceCols.length > 0 ? "Other Columns" : "All Columns"}>
                  {otherCols.map((c) => <option key={c} value={c}>{c}</option>)}
                </optgroup>
              </select>
            </div>
            <div style={ms.fg}>
              <label style={ms.lb}>Timestamp Column</label>
              <select value={tsCol} onChange={(e) => setModal((p) => ({ ...p, tsCol: e.target.value }))} style={ms.sl}>
                {tsCols.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            {modal.error && <div style={{ color: th.danger, fontSize: 11, padding: "8px 10px", background: `${th.danger}15`, borderRadius: 6, marginBottom: 10 }}>Error: {modal.error}</div>}
          </>)}

          {phase === "loading" && (
            <div style={{ textAlign: "center", padding: 40 }}>
              <div style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>Analyzing log source coverage...</div>
            </div>
          )}

          {phase === "results" && data && (() => {
            const sortBy = modal.sortBy || "count";
            const sorted = [...data.sources].sort((a, b) => {
              if (sortBy === "name") return (a.source || "").localeCompare(b.source || "");
              if (sortBy === "earliest") return (a.earliest || "").localeCompare(b.earliest || "");
              if (sortBy === "duration") {
                const durA = parseTs(a.latest) - parseTs(a.earliest);
                const durB = parseTs(b.latest) - parseTs(b.earliest);
                return durB - durA;
              }
              return b.cnt - a.cnt;
            });

            const gStart = parseTs(data.globalEarliest);
            const gEnd = parseTs(data.globalLatest);
            const gSpan = gEnd - gStart || 1;
            const maxCnt = Math.max(...data.sources.map((s) => s.cnt), 1);
            const BAR_H = 16;

            const heatColor = (ratio) => {
              const t = Math.max(0, Math.min(1, ratio));
              const r = Math.round(30 + t * 202);
              const g = Math.round(40 + t * 53);
              const b = Math.round(56 - t * 14);
              return `rgb(${r},${g},${b})`;
            };

            return (<>
              {/* Summary cards */}
              <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                {[
                  { val: data.totalSources, label: "log sources", color: th.accent },
                  { val: formatNumber(data.totalEvents), label: "total events", color: th.textDim },
                  { val: fmtDur(gEnd - gStart), label: "time span", color: th.textDim },
                ].map((c, i) => (
                  <div key={i} style={{ flex: 1, textAlign: "center", padding: "12px 8px", background: th.panelBg, borderRadius: 8, border: `1px solid ${th.border}` }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif" }}>{c.val}</div>
                    <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                  </div>
                ))}
              </div>

              {/* Gantt chart */}
              <div style={{ marginBottom: 14 }}>
                <div style={ms.lb}>Coverage Timeline</div>
                <div style={{ border: `1px solid ${th.border}`, borderRadius: 6, overflow: "hidden" }}>
                  <div style={{ display: "flex", padding: "4px 10px", borderBottom: `1px solid ${th.border}`, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                    <span style={{ width: 160, flexShrink: 0 }}>Source</span>
                    <span style={{ flex: 1, display: "flex", justifyContent: "space-between" }}>
                      <span>{data.globalEarliest?.slice(0, 16)}</span>
                      <span>{data.globalLatest?.slice(0, 16)}</span>
                    </span>
                    <span style={{ width: 60, flexShrink: 0 }}></span>
                  </div>
                  <div style={{ maxHeight: 300, overflow: "auto" }}>
                    {sorted.map((s, i) => {
                      const sStart = parseTs(s.earliest);
                      const sEnd = parseTs(s.latest);
                      const leftPct = ((sStart - gStart) / gSpan) * 100;
                      const widthPct = Math.max(0.5, ((sEnd - sStart) / gSpan) * 100);
                      const ratio = s.cnt / maxCnt;
                      return (
                        <div key={s.source} style={rowStyle(i)} onClick={() => filterBySource(s.source)}
                          onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                          onMouseLeave={(e) => { e.currentTarget.style.background = i % 2 === 0 ? "transparent" : `${th.border}15`; }}>
                          <span style={{ width: 160, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, fontSize: 10 }} title={s.source}>{s.source}</span>
                          <div style={{ flex: 1, height: BAR_H, position: "relative", background: th.border + "22", borderRadius: 3 }}>
                            <div style={{
                              position: "absolute", left: `${leftPct}%`, width: `${widthPct}%`,
                              height: "100%", background: heatColor(ratio), borderRadius: 3, minWidth: 2,
                            }} title={`${s.source}: ${formatNumber(s.cnt)} events\n${s.earliest} \u2014 ${s.latest}`} />
                          </div>
                          <span style={{ width: 60, flexShrink: 0, textAlign: "right", color: th.textMuted, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>{formatNumber(s.cnt)}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Sort controls */}
              <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
                <span style={{ color: th.textMuted, fontSize: 10, alignSelf: "center", fontFamily: "-apple-system, sans-serif" }}>Sort:</span>
                {["count", "name", "earliest", "duration"].map((s) => (
                  <button key={s} onClick={() => setModal((p) => ({ ...p, sortBy: s }))}
                    style={{ padding: "3px 10px", background: sortBy === s ? th.fillAccent : th.btnBg, color: sortBy === s ? th.onAccent : th.text, border: `1px solid ${sortBy === s ? th.accent : th.btnBorder}`, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </button>
                ))}
              </div>

              {/* Detail list */}
              <div style={{ marginBottom: 14 }}>
                <div style={ms.lb}>Source Details ({data.totalSources})</div>
                <div style={{ maxHeight: 200, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                  {sorted.map((s, i) => {
                    const dur = parseTs(s.latest) - parseTs(s.earliest);
                    return (
                      <div key={s.source} style={rowStyle(i)} onClick={() => filterBySource(s.source)}
                        onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = i % 2 === 0 ? "transparent" : `${th.border}15`; }}>
                        <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text }} title={s.source}>{s.source}</span>
                        <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{formatNumber(s.cnt)} events</span>
                        <span style={{ color: th.textDim, fontSize: 10, whiteSpace: "nowrap" }}>{s.earliest?.slice(0, 16)}</span>
                        <span style={{ color: th.textMuted, fontSize: 10 }}>{"\u2014"}</span>
                        <span style={{ color: th.textDim, fontSize: 10, whiteSpace: "nowrap" }}>{s.latest?.slice(0, 16)}</span>
                        <span style={{ color: th.accent, fontSize: 10, fontWeight: 600, whiteSpace: "nowrap" }}>{fmtDur(dur)}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </>);
          })()}
      </div>
    </Modal>
  );
}
