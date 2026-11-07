import { Fragment } from "react";
import { formatNumber } from "../../../utils/format.js";
import { useSigmaModalContext } from "./SigmaModalContext.js";

const wrapTextStyle = {
  display: "block",
  maxWidth: "100%",
  minWidth: 0,
  overflow: "visible",
  whiteSpace: "normal",
  overflowWrap: "anywhere",
  wordBreak: "break-word",
};

export default function SigmaTargetStep() {
  const {
    modal,
    setModal,
    ct,
    th,
    ms,
    handleSelectEvtxDir,
    handleSelectKapeOutput,
    handleSelectKapeOutputFolder,
    handleRunMetrics,
  } = useSigmaModalContext();

  return (
    <>
              {/* Scan mode toggle: Raw EVTX first, imported table second */}
              <div style={{ ...ms.fg }}>
                <label style={ms.lb}>Scan Target</label>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 6, marginBottom: 8 }}>
                  {[
                    { id: "evtx-dir", label: "EVTX Folder", meta: "Hayabusa scan of raw .evtx files", color: th.accent },
                    { id: "kape-output", label: "EvtxECmd Output Files", meta: "Sigma scan of validated CSV/XLS/XLSX event-log output", color: th.accent },
                    { id: "tab", label: "Current Timeline Tab", meta: ct?.dataReady ? `Sigma scan of imported CSV/XLSX/KAPE rows - ${formatNumber(ct.totalRows || 0)} rows` : "Open a CSV/XLSX/KAPE tab first", color: th.accent, disabled: !ct?.dataReady },
                  ].map((v) => {
                    const active = (modal.scanMode || "evtx-dir") === v.id;
                    return (
                      <button key={v.id} onClick={() => !v.disabled && setModal((p) => ({ ...p, scanMode: v.id, largeJsSigmaScanConfirmed: false, scanPreflight: null }))} disabled={v.disabled}
                        style={{ padding: "9px 11px", minHeight: 58, borderRadius: 8, textAlign: "left", cursor: v.disabled ? "not-allowed" : "pointer", background: active ? `${v.color}18` : th.panelBg, border: `1px solid ${active ? v.color + "66" : th.border + "44"}`, opacity: v.disabled ? 0.45 : 1, fontFamily: "-apple-system,sans-serif" }}>
                        <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                          <span style={{ width: 10, height: 10, borderRadius: 999, background: active ? v.color : "transparent", border: `1px solid ${active ? v.color : th.textMuted}`, flexShrink: 0 }} />
                          <span style={{ color: active ? th.text : th.textDim, fontSize: 12, lineHeight: 1.25, fontWeight: 700, minWidth: 0, ...wrapTextStyle }}>{v.label}</span>
                        </div>
                        <div style={{ marginLeft: 18, marginTop: 3, color: active ? v.color : th.textMuted, fontSize: 9, lineHeight: 1.3, fontFamily: "'SF Mono',Menlo,monospace", ...wrapTextStyle }}>{v.meta}</div>
                      </button>
                    );
                  })}
                </div>
              </div>


              {/* EvtxECmd direct output picker */}
              {(modal.scanMode || "evtx-dir") === "kape-output" && (() => {
                const info = modal.kapeOutput;
                const color = th.accent;
                return (
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 8, marginBottom: 6 }}>
                      <button onClick={handleSelectKapeOutput} style={{ ...ms.bp, flex: "none", background: th.fillAccent, color: th.onAccent }}>
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ marginRight: 5, verticalAlign: "middle" }}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        {info ? "Change Files" : "Select EvtxECmd Output Files"}
                      </button>
                      <button onClick={handleSelectKapeOutputFolder} style={{ ...ms.bsm, flex: "none" }}>
                        Find in Folder
                      </button>
                      {info?.paths?.length > 0 && (
                        <span style={{ flex: "1 1 260px", minWidth: 0, fontSize: 10, color: th.textDim, lineHeight: 1.3, fontFamily: "'SF Mono',Menlo,monospace", ...wrapTextStyle }}>
                          {info.paths.length === 1 ? info.paths[0] : `${formatNumber(info.paths.length)} selected paths`}
                        </span>
                      )}
                    </div>
                    {info ? (
                      <div style={{ padding: "8px 12px", background: `${color}08`, border: `1px solid ${color}18`, borderRadius: 8, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: info.files?.length > 0 ? 6 : 0 }}>
                          <span style={{ color: th.text, fontWeight: 600 }}>
                            <span style={{ color }}>{formatNumber(info.fileCount || 0)}</span> EvtxECmd file{(info.fileCount || 0) === 1 ? "" : "s"}
                          </span>
                          <span style={{ color: th.textMuted }}>{(Number(info.totalBytes || 0) / (1024 * 1024)).toFixed(1)} MB total</span>
                          {info.overflow > 0 && <span style={{ color: th.textMuted }}>+{formatNumber(info.overflow)} more</span>}
                          {info.ignoredCount > 0 && <span style={{ color: th.sev.med }}>{formatNumber(info.ignoredCount)} ignored</span>}
                        </div>
                        {info.files?.length > 0 && (
                          <div style={{ maxHeight: 94, overflow: "auto", display: "flex", flexWrap: "wrap", gap: 3, marginTop: 4 }}>
                            {info.files.map((f, i) => (
                              <span key={`${f.path || f.name}-${i}`} title={f.path || f.name} style={{ display: "inline-flex", alignItems: "baseline", gap: 3, padding: "1px 6px", borderRadius: 3, background: `${color}12`, color: th.textDim, fontSize: 9, lineHeight: 1.25, fontFamily: "'SF Mono',Menlo,monospace", maxWidth: "100%", whiteSpace: "normal", overflowWrap: "anywhere" }}>
                                <span style={{ minWidth: 0, overflowWrap: "anywhere" }}>{f.name}</span>
                                <span style={{ color: th.textMuted, fontSize: 8, flexShrink: 0 }}>{(Number(f.size || 0) / 1024).toFixed(0)}K</span>
                              </span>
                            ))}
                          </div>
                        )}
                        {info.ignoredCount > 0 && (
                          <div style={{ marginTop: 6, color: th.sev.med, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace" }}>
                            Ignored unrelated KAPE files and invalid outputs. Only validated EvtxECmd event-log files will be scanned.
                          </div>
                        )}
                      </div>
                    ) : (
                      <div style={{ padding: "12px", textAlign: "center", color: th.textMuted, fontSize: 11, border: `1px dashed ${th.border}`, borderRadius: 8 }}>
                        Select one or more EvtxECmd CSV/XLS/XLSX output files, or use Find in Folder to discover valid outputs inside a KAPE collection.
                      </div>
                    )}
                  </div>
                );
              })()}


              {/* Current Tab: data format indicator */}
              {(modal.scanMode || "evtx-dir") === "tab" && ct && (() => {
                const h = ct.headers || [];
                const isEvtxECmd = h.some(c => /^RemoteHost$/i.test(c)) && h.some(c => /^PayloadData1$/i.test(c));
                const isHayabusa = h.some(c => /^RuleTitle$/i.test(c)) && h.some(c => /^Details$/i.test(c));
                const isRawEvtx = !isEvtxECmd && !isHayabusa && h.some(c => /^datetime$/i.test(c)) && h.some(c => /^Provider$/i.test(c));
                const fmt = isEvtxECmd ? "EvtxECmd (KAPE)" : isHayabusa ? "Hayabusa" : isRawEvtx ? "Raw EVTX" : "CSV/Standard";
                const fmtColor = th.textDim;
                const fmtNote = isEvtxECmd
                  ? "Fields extracted from PayloadData columns via KV parsing"
                  : isRawEvtx ? "Fields matched directly from EventData columns"
                  : isHayabusa ? "Fields extracted from Details/ExtraFieldInfo compact format"
                  : "Best-effort column matching";
                return (
                  <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: "5px 8px", padding: "6px 12px", background: `${fmtColor}08`, border: `1px solid ${fmtColor}18`, borderRadius: 8, marginBottom: 10, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={fmtColor} strokeWidth="2" strokeLinecap="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    <span style={{ color: th.text, fontWeight: 600 }}>Format: <span style={{ color: fmtColor }}>{fmt}</span></span>
                    <span style={{ color: th.textMuted }}>{"\u00B7"}</span>
                    <span style={{ color: th.textMuted, flex: "1 1 260px", minWidth: 0, ...wrapTextStyle }}>{fmtNote}</span>
                    <span style={{ color: th.textMuted, marginLeft: "auto", flexShrink: 0 }}>{formatNumber(ct.totalRows || 0)} rows</span>
                  </div>
                );
              })()}

              {/* EVTX Directory: Hayabusa status + folder picker + file list */}
              {(modal.scanMode || "evtx-dir") === "evtx-dir" && (() => {
                const dirInfo = modal.evtxDir;
                const evtxColor = th.accent;
                const hb = modal.hayabusaStatus;
                const hbInstalled = hb?.installed;
                const hbRuleCount = hb?.ruleState?.hayabusaRuleCount || modal.hayabusaUpdateRuleDiff?.currentRuleCount || 0;
                return (
                  <div style={{ marginBottom: 10 }}>
                    {/* Hayabusa engine status */}
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", background: hbInstalled ? th.sev.clean + "08" : `${evtxColor}08`, border: `1px solid ${hbInstalled ? th.sev.clean + "18" : evtxColor + "18"}`, borderRadius: 8, marginBottom: 8, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
                      {hbInstalled ? (
                        <Fragment>
                          <span style={{ color: th.text, flex: 1 }}>
                            <strong style={{ color: th.sev.clean }}>Hayabusa {hb.version || ""}</strong>
                            <span style={{ color: th.textMuted, marginLeft: 6 }}>
                              EVTX scanning engine{hbRuleCount ? ` - ${formatNumber(hbRuleCount)} rules` : ""}
                            </span>
                          </span>
                          <button onClick={() => setModal((p) => ({ ...p, detectionSettingsView: true, scanHistoryView: false }))} style={{ ...ms.bsm, fontSize: 9 }}>
                            Detection Settings
                          </button>
                        </Fragment>
                      ) : (
                        <Fragment>
                          <span style={{ color: th.text, flex: 1 }}>
                            <span style={{ color: th.textMuted }}>Hayabusa is not installed. Install it from Detection Settings or it will be downloaded on first scan.</span>
                          </span>
                          <button onClick={() => setModal((p) => ({ ...p, detectionSettingsView: true, scanHistoryView: false }))} style={{ ...ms.bsm, fontSize: 9, background: `${evtxColor}15`, color: evtxColor, border: `1px solid ${evtxColor}33` }}>
                            Detection Settings
                          </button>
                        </Fragment>
                      )}
                    </div>

                    {/* Directory picker */}
                    <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 8, marginBottom: 6 }}>
                      <button onClick={handleSelectEvtxDir} style={{ ...ms.bp, flex: "none" }}>
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ marginRight: 5, verticalAlign: "middle" }}><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                        {dirInfo ? "Change Directory" : "Select EVTX Directory"}
                      </button>
                      {dirInfo && (
                        <span style={{ flex: "1 1 260px", minWidth: 0, fontSize: 10, color: th.textDim, lineHeight: 1.3, fontFamily: "'SF Mono',Menlo,monospace", ...wrapTextStyle }}>{dirInfo.dirPath}</span>
                      )}
                    </div>
                    {dirInfo && (
                      <div style={{ padding: "8px 12px", background: `${evtxColor}08`, border: `1px solid ${evtxColor}18`, borderRadius: 8, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: dirInfo.files?.length > 0 ? 6 : 0 }}>
                          <span style={{ color: th.text, fontWeight: 600 }}>
                            <span style={{ color: evtxColor }}>{dirInfo.fileCount}</span> EVTX file{dirInfo.fileCount !== 1 ? "s" : ""}
                          </span>
                          <span style={{ color: th.textMuted }}>{(dirInfo.totalBytes / (1024 * 1024)).toFixed(1)} MB total</span>
                        </div>
                        {dirInfo.files?.length > 0 && (
                          <div style={{ maxHeight: 80, overflow: "auto", display: "flex", flexWrap: "wrap", gap: 3, marginTop: 4 }}>
                            {dirInfo.files.map((f, i) => (
                              <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "1px 6px", borderRadius: 3, background: `${evtxColor}12`, color: th.textDim, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace" }}>
                                {f.name}
                                <span style={{ color: th.textMuted, fontSize: 8 }}>{(f.size / 1024).toFixed(0)}K</span>
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                    {/* Triage — collapsible metrics section (self-collapses via showTriage) */}
                    {dirInfo && hbInstalled && (
                      <div style={{ marginTop: 8 }}>
                        <button onClick={() => setModal((p) => ({ ...p, showTriage: !p.showTriage }))} style={{ display: "flex", alignItems: "center", gap: 6, background: "none", border: "none", cursor: "pointer", padding: "4px 0", width: "100%" }}>
                          <span style={{ fontSize: 9, color: th.textMuted, transition: "transform var(--m-base)", transform: modal.showTriage ? "rotate(90deg)" : "rotate(0deg)" }}>{"\u25B6"}</span>
                          <span style={{ fontSize: 10, color: th.textDim, fontWeight: 600, fontFamily: "-apple-system,sans-serif", textTransform: "uppercase", letterSpacing: "0.06em" }}>Triage Tools</span>
                          <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system,sans-serif" }}>Log metrics, computers, event IDs, logons, pivot IOCs</span>
                        </button>
                        {modal.showTriage && <div style={{ marginTop: 4 }}>
                        <div style={{ display: "flex", gap: 4, marginBottom: 6 }}>
                          {[
                            { id: "log", label: "Log Metrics" },
                            { id: "computer", label: "Computers" },
                            { id: "eid", label: "Event IDs" },
                            { id: "logon", label: "Logons" },
                            { id: "pivot", label: "Pivot IOCs" },
                            { id: "base64", label: "Base64 Decode" },
                          ].map((m) => {
                            const active = modal.metricsTab === m.id;
                            const loading = modal.metricsLoading === m.id;
                            const cached = !!modal.metricsData?.[m.id];
                            return (
                              <button key={m.id} onClick={() => handleRunMetrics(m.id)} disabled={loading}
                                style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: loading ? "wait" : "pointer", fontWeight: active ? 600 : 400, fontFamily: "-apple-system,sans-serif",
                                  background: active ? `${th.accent}18` : "transparent", color: active ? th.accent : cached ? th.text : th.textMuted,
                                  border: `1px solid ${active ? th.accent + "44" : cached ? th.border + "44" : th.border + "22"}`,
                                }}>
                                {loading ? "..." : cached && !active ? "\u2713 " : ""}{m.label}
                              </button>
                            );
                          })}
                        </div>

                        {/* Metrics table */}
                        {modal.metricsTab && (() => {
                          const data = modal.metricsData?.[modal.metricsTab];
                          if (modal.metricsLoading) return <div style={{ padding: "10px 0", textAlign: "center", fontSize: 10, color: th.textMuted }}>Running hayabusa {modal.metricsTab}...</div>;
                          if (!data) return null;

                          // Generic table renderer
                          const renderTable = (rows, opts = {}) => {
                            if (!rows || rows.length === 0) return <div style={{ padding: "8px 0", fontSize: 10, color: th.textMuted, textAlign: "center" }}>No data</div>;
                            const cols = Object.keys(rows[0]);
                            return (
                              <div style={{ maxHeight: opts.maxHeight || 160, overflow: "auto", borderRadius: 6, border: `1px solid ${th.border}44` }}>
                                <table style={{ borderCollapse: "collapse", fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", width: "100%", tableLayout: "auto" }}>
                                  <thead>
                                    <tr>{cols.map((c) => <th key={c} style={{ position: "sticky", top: 0, background: th.headerBg || th.panelBg, borderBottom: `2px solid ${th.border}`, padding: "4px 6px", textAlign: "left", fontSize: 8, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", whiteSpace: "nowrap" }}>{c}</th>)}</tr>
                                  </thead>
                                  <tbody>
                                    {rows.slice(0, opts.limit || 200).map((row, ri) => (
                                      <tr key={ri} style={{ borderBottom: `1px solid ${th.border}11`, background: ri % 2 === 0 ? "transparent" : `${th.panelBg}44` }}>
                                        {cols.map((c) => <td key={c} style={{ padding: "3px 6px", color: th.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 300 }}>{row[c]}</td>)}
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                                {rows.length > (opts.limit || 200) && <div style={{ padding: "4px 8px", fontSize: 8, color: th.textMuted, textAlign: "center" }}>Showing {opts.limit || 200} of {rows.length}</div>}
                              </div>
                            );
                          };

                          if (modal.metricsTab === "logon") {
                            return (
                              <div>
                                {data.successful?.length > 0 && (<div style={{ marginBottom: 6 }}><div style={{ fontSize: 9, color: th.textDim, fontWeight: 600, marginBottom: 3 }}>Successful Logons ({data.successful.length})</div>{renderTable(data.successful)}</div>)}
                                {data.failed?.length > 0 && (<div><div style={{ fontSize: 9, color: th.sev.critical, fontWeight: 600, marginBottom: 3 }}>Failed Logons ({data.failed.length})</div>{renderTable(data.failed)}</div>)}
                                {!data.successful?.length && !data.failed?.length && <div style={{ padding: "8px 0", fontSize: 10, color: th.textMuted, textAlign: "center" }}>No logon events found</div>}
                              </div>
                            );
                          }

                          if (modal.metricsTab === "eid") return renderTable(data.rows, { maxHeight: 200, limit: 500 });
                          if (modal.metricsTab === "log") return renderTable(data.rows, { maxHeight: 180 });
                          if (modal.metricsTab === "computer") return renderTable(data.rows);

                          if (modal.metricsTab === "pivot") {
                            const cats = data.categories || {};
                            const catNames = Object.keys(cats);
                            if (catNames.length === 0) return <div style={{ padding: "8px 0", fontSize: 10, color: th.textMuted, textAlign: "center" }}>No pivot keywords found (requires high+ detections)</div>;
                            return (
                              <div style={{ maxHeight: 200, overflow: "auto" }}>
                                {catNames.map((cat) => (
                                  <div key={cat} style={{ marginBottom: 6 }}>
                                    <div style={{ fontSize: 9, fontWeight: 600, color: th.accent, marginBottom: 2 }}>{cat} ({cats[cat].length})</div>
                                    <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                                      {cats[cat].slice(0, 50).map((v, i) => (
                                        <span key={i} style={{ padding: "1px 6px", borderRadius: 3, fontSize: 9, background: `${th.accent}10`, color: th.text, border: `1px solid ${th.border}33`, fontFamily: "'SF Mono',Menlo,monospace", maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "inline-block" }}>{v}</span>
                                      ))}
                                      {cats[cat].length > 50 && <span style={{ fontSize: 8, color: th.textMuted }}>+{cats[cat].length - 50} more</span>}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            );
                          }

                          if (modal.metricsTab === "base64") return renderTable(data.rows, { maxHeight: 200, limit: 100 });
                          return null;
                        })()}
                        </div>}
                      </div>
                    )}

                    {!dirInfo && (
                      <div style={{ padding: "12px", textAlign: "center", color: th.textMuted, fontSize: 11, border: `1px dashed ${th.border}`, borderRadius: 8 }}>
                        Select a directory containing .evtx files to scan with Hayabusa + Sigma rules
                      </div>
                    )}
                  </div>
                );
              })()}


    </>
  );
}
