import { useCallback } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { formatNumber } from "../../utils/format.js";
import { Modal, Button } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";

export default function BurstAnalysisModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const refreshCallback = useUIStore((s) => s.refreshCallback);
  const ct = useCurrentTab();
  const { th } = useTheme();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const activeTab = useTabStore((s) => s.activeTab);
  const setTabs = useTabStore((s) => s.setTabs);

  const up = useCallback((key, value) => {
    setTabs((prev) => prev.map((t) => (t.id === activeTab ? { ...t, [key]: value } : t)));
  }, [activeTab, setTabs]);

  const fetchData = useCallback((tab) => {
    if (refreshCallback) refreshCallback(tab);
  }, [refreshCallback]);

  const activeFilters = useCallback((tab) => {
    const dis = tab.disabledFilters || new Set();
    if (dis.size === 0) return { columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters };
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: Object.fromEntries(Object.entries(tab.checkboxFilters).filter(([k]) => !dis.has(k))),
    };
  }, []);

  const ms = useModalChrome();

  if (!modal || modal.type !== "burstAnalysis" || !ct) return null;

  const { phase, colName, windowMinutes, thresholdMultiplier, data } = modal;
  const tsCols = [...(ct.tsColumns || [])];

  const handleAnalyze = async () => {
    setModal((p) => ({ ...p, phase: "loading", loading: true, error: null }));
    try {
      const af = activeFilters(ct);
      const result = await tle.getBurstAnalysis(ct.id, colName, windowMinutes, thresholdMultiplier, {
        searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
        searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
      });
      if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
      setModal((p) => p?.type === "burstAnalysis" ? ({ ...p, phase: "results", loading: false, data: result }) : p);
    } catch (e) {
      setModal((p) => p?.type === "burstAnalysis" ? ({ ...p, phase: "config", loading: false, error: e.message }) : p);
    }
  };

  const handleTagBursts = async () => {
    if (!data?.bursts?.length) return;
    setModal((p) => ({ ...p, tagging: true }));
    try {
      const ranges = data.bursts.map((b, i) => ({ from: b.from, to: b.to, tag: `Burst ${i + 1}` }));
      const result = await tle.bulkTagByTimeRange(ct.id, colName, ranges);
      const burstColors = [th.sev.critical, th.sev.high, th.sev.med, "#e3b341", th.sev.critical, "#ff7b72", "#ffa657", th.sev.custom];
      const newTagColors = { ...ct.tagColors };
      for (let i = 0; i < data.bursts.length; i++) {
        const tag = `Burst ${i + 1}`;
        if (!newTagColors[tag]) newTagColors[tag] = burstColors[i % burstColors.length];
      }
      up("tagColors", newTagColors);
      await fetchData(ct);
      setModal((p) => p?.type === "burstAnalysis" ? ({ ...p, tagging: false, tagged: true, taggedCount: result.taggedCount }) : p);
    } catch {
      setModal((p) => p?.type === "burstAnalysis" ? ({ ...p, tagging: false }) : p);
    }
  };

  const zoomTo = (from, to) => {
    const fromTs = from.length === 16 ? from + ":00" : from;
    const toTs = to.length === 16 ? to + ":59" : to;
    up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [colName]: { from: fromTs, to: toTs } });
    setModal(null);
  };

  const fmtDur = (mins) => {
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
        <Button variant="secondary" onClick={() => setModal((p) => ({ ...p, phase: "config", data: null, tagged: false, taggedCount: 0 }))}>Back</Button>
        <div style={{ display: "flex", gap: 6 }}>
          {!modal.tagged && data.bursts.length > 0 && (
            <Button onClick={handleTagBursts} loading={modal.tagging} style={{ background: th.danger }}>
              {modal.tagging ? "Tagging..." : `Tag ${data.bursts.length} Burst${data.bursts.length !== 1 ? "s" : ""}`}
            </Button>
          )}
          <Button onClick={() => setModal(null)}>Done</Button>
        </div>
      </>)}
    </div>
  );

  return (
    <Modal
      title="Event Burst Detection"
      subtitle="Find windows with abnormally high event density"
      width={650}
      maxHeight="88vh"
      onClose={() => setModal(null)}
      bodyPadding="16px 20px"
      footer={footer}
    >
      <div>
          {/* Config phase */}
          {phase === "config" && (<>
            <div style={ms.fg}>
              <label style={ms.lb}>Timestamp Column</label>
              <select value={colName} onChange={(e) => setModal((p) => ({ ...p, colName: e.target.value }))} style={ms.sl}>
                {tsCols.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div style={ms.fg}>
              <label style={ms.lb}>Window Size</label>
              <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                {[{v: 1, l: "1m"}, {v: 5, l: "5m"}, {v: 15, l: "15m"}, {v: 30, l: "30m"}, {v: 60, l: "1h"}].map(({v, l}) => (
                  <button key={v} onClick={() => setModal((p) => ({ ...p, windowMinutes: v }))}
                    style={{ padding: "5px 12px", background: windowMinutes === v ? th.fillAccent : th.btnBg, color: windowMinutes === v ? th.onAccent : th.text, border: `1px solid ${windowMinutes === v ? th.accent : th.btnBorder}`, borderRadius: 6, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                    {l}
                  </button>
                ))}
                <input type="number" min="1" value={windowMinutes} onChange={(e) => setModal((p) => ({ ...p, windowMinutes: Math.max(1, Number(e.target.value) || 5) }))}
                  style={{ ...ms.ip, width: 60 }} />
                <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>minutes</span>
              </div>
            </div>
            <div style={ms.fg}>
              <label style={ms.lb}>Threshold Multiplier</label>
              <p style={{ color: th.textMuted, fontSize: 10, margin: "0 0 6px", fontFamily: "-apple-system, sans-serif" }}>Flag windows with N times the median baseline event rate</p>
              <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                {[3, 5, 10, 20].map((v) => (
                  <button key={v} onClick={() => setModal((p) => ({ ...p, thresholdMultiplier: v }))}
                    style={{ padding: "5px 12px", background: thresholdMultiplier === v ? th.fillAccent : th.btnBg, color: thresholdMultiplier === v ? th.onAccent : th.text, border: `1px solid ${thresholdMultiplier === v ? th.accent : th.btnBorder}`, borderRadius: 6, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                    {v}{"\u00D7"}
                  </button>
                ))}
                <input type="number" min="1" step="0.5" value={thresholdMultiplier} onChange={(e) => setModal((p) => ({ ...p, thresholdMultiplier: Math.max(1, Number(e.target.value) || 5) }))}
                  style={{ ...ms.ip, width: 60 }} />
                <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>{"\u00D7"} baseline</span>
              </div>
            </div>
            {modal.error && <div style={{ color: th.danger, fontSize: 11, padding: "8px 10px", background: `${th.danger}15`, borderRadius: 6, marginBottom: 10 }}>Error: {modal.error}</div>}
          </>)}

          {/* Loading phase */}
          {phase === "loading" && (
            <div style={{ textAlign: "center", padding: 40 }}>
              <div style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>Analyzing event density ({windowMinutes}m windows, {thresholdMultiplier}{"\u00D7"} threshold)...</div>
            </div>
          )}

          {/* Results phase */}
          {phase === "results" && data && (<>
            {/* Summary cards */}
            <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
              {[
                { val: data.bursts.length, label: "bursts detected", color: data.bursts.length > 0 ? th.danger : th.textDim },
                { val: data.baseline, label: `baseline /${windowMinutes}m`, color: th.textDim },
                { val: data.peakRate, label: `peak /${windowMinutes}m`, color: th.accent },
                { val: formatNumber(data.totalEvents), label: "total events", color: th.textDim },
              ].map((c, i) => (
                <div key={i} style={{ flex: 1, textAlign: "center", padding: "12px 8px", background: th.panelBg, borderRadius: 8, border: `1px solid ${th.border}` }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif" }}>{c.val}</div>
                  <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                </div>
              ))}
            </div>

            {/* Sparkline chart */}
            {data.sparkline && data.sparkline.length > 0 && (() => {
              const SPARK_H = 80;
              const maxSpk = Math.max(...data.sparkline.map((s) => s.cnt), 1);
              return (
                <div style={{ marginBottom: 14 }}>
                  <div style={ms.lb}>Event Rate Over Time</div>
                  <div style={{ border: `1px solid ${th.border}`, borderRadius: 6, overflow: "hidden", padding: "8px 4px" }}>
                    <svg width="100%" height={SPARK_H} viewBox={`0 0 ${data.sparkline.length} ${SPARK_H}`} preserveAspectRatio="none" style={{ display: "block" }}>
                      <line x1="0" y1={SPARK_H - (data.threshold / maxSpk) * SPARK_H} x2={data.sparkline.length} y2={SPARK_H - (data.threshold / maxSpk) * SPARK_H}
                        stroke={th.danger} strokeWidth="0.3" strokeDasharray="2,2" opacity="0.6" />
                      {data.sparkline.map((s, i) => {
                        const h = Math.max(0.5, (s.cnt / maxSpk) * (SPARK_H - 4));
                        return <rect key={i} x={i} y={SPARK_H - h} width={0.8} height={h}
                          fill={s.isBurst ? (th.danger) : th.accent + "66"} />;
                      })}
                    </svg>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: th.textMuted, marginTop: 4, padding: "0 2px", fontFamily: "-apple-system, sans-serif" }}>
                      <span>{data.sparkline[0]?.ts?.slice(0, 16)}</span>
                      <span style={{ color: th.danger, fontSize: 8 }}>--- threshold ({data.threshold}/{windowMinutes}m)</span>
                      <span>{data.sparkline[data.sparkline.length - 1]?.ts?.slice(0, 16)}</span>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* Bursts list */}
            {data.bursts.length > 0 ? (
              <div style={{ marginBottom: 14 }}>
                <div style={ms.lb}>Bursts ({data.bursts.length})</div>
                <div style={{ maxHeight: 240, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                  {data.bursts.map((b, i) => (
                    <div key={i} style={rowStyle(i)} onClick={() => zoomTo(b.from, b.to)}
                      onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = i % 2 === 0 ? "transparent" : `${th.border}15`; }}>
                      <span style={{ padding: "1px 8px", borderRadius: 3, fontSize: 10, fontWeight: 600, color: "#fff", background: th.danger, fontFamily: "-apple-system, sans-serif" }}>Burst {i + 1}</span>
                      <span style={{ color: th.textDim, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{b.from} {"\u2014"} {b.to}</span>
                      <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{formatNumber(b.eventCount)} events</span>
                      <span style={{ color: th.danger, fontSize: 10, fontWeight: 700, whiteSpace: "nowrap" }}>{b.burstFactor}{"\u00D7"}</span>
                      <span style={{ color: th.accent, fontSize: 10, fontWeight: 600, whiteSpace: "nowrap" }}>{fmtDur(b.durationMinutes)}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div style={{ padding: "20px 0", textAlign: "center", color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>
                No bursts detected above {thresholdMultiplier}{"\u00D7"} baseline. Try lowering the threshold or adjusting the window size.
              </div>
            )}

            {/* Tagged confirmation */}
            {modal.tagged && (
              <div style={{ padding: "8px 12px", background: `${th.success}15`, border: `1px solid ${th.success}33`, borderRadius: 6, color: th.success, fontSize: 11, fontFamily: "-apple-system, sans-serif", marginBottom: 10 }}>
                Tagged {modal.taggedCount?.toLocaleString()} rows across {data.bursts.length} burst periods
              </div>
            )}
          </>)}
      </div>
    </Modal>
  );
}
