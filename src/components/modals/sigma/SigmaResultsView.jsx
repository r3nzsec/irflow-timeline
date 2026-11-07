import { Fragment } from "react";
import { formatBytes, formatNumber } from "../../../utils/format.js";
import { sevColorsFor, SEV_ORDER } from "./constants.js";
import { useSigmaModalContext } from "./SigmaModalContext.js";
import SigmaTriageDashboard from "./SigmaTriageDashboard.jsx";

const formatDuration = (ms) => {
  const total = Math.max(0, Math.round(Number(ms || 0) / 1000));
  if (!total) return "0s";
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
};

const isNonBlockingScanNotice = (message) => {
  const text = String(message || "").toLowerCase();
  return (
    text.includes("selected rules were skipped") ||
    text.includes("disabled/noisy rule") ||
    text.includes("skipped by detection settings") ||
    text.includes("unsupported js sigma compatibility") ||
    text.includes("hit row limit")
  );
};

export default function SigmaResultsView() {
  const {
    phase,
    results,
    modal,
    th,
    sigmaResultsRef,
    setModal,
    tle,
    expandedRule,
    sevBadge,
    mitreBadge,
    ms,
    ct,
    handleShowInTimeline,
    handleTagMatches,
    handleBookmarkMatches,
    handleOpenExactMatchesAsTab,
  } = useSigmaModalContext();
  const SEV_COLORS = sevColorsFor(th);

  const handleTimelineColumnResize = (key, startWidth, event) => {
    event.preventDefault();
    event.stopPropagation();
    const startX = event.clientX;
    const minWidth = 48;
    const maxWidth = 720;
    const onMove = (moveEvent) => {
      const nextWidth = Math.max(minWidth, Math.min(maxWidth, Math.round(startWidth + (moveEvent.clientX - startX))));
      setModal((p) => p ? {
        ...p,
        sigmaTimelineColumnWidths: {
          ...(p.sigmaTimelineColumnWidths || {}),
          [key]: nextWidth,
        },
      } : p);
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const rawResultErrors = Array.isArray(results?.errors) ? results.errors : [];
  const explicitWarnings = Array.isArray(results?.warnings) ? results.warnings : [];
  const legacyNoticeErrors = rawResultErrors.filter(isNonBlockingScanNotice);
  const resultErrors = rawResultErrors.filter((message) => !isNonBlockingScanNotice(message));
  const resultWarnings = [...new Set([...explicitWarnings, ...legacyNoticeErrors].map((message) => String(message || "").trim()).filter(Boolean))];

  return (
    <>
          {/* ── RESULTS PHASE ─────────────────────────────────────── */}
          {phase === "results" && results && (
            <Fragment>
              {/* Loading overlay when opening as tab — shows real progress driven by sigma-progress events */}
              {(modal.openingTab || modal.sourceAction === "open") && (() => {
                const ip = modal.importProgress || {};
                const total = ip.importTotal || results?.eventRowCount || 0;
                const inserted = ip.importInserted || 0;
                const pct = ip.importPct != null ? ip.importPct : (total > 0 ? Math.round((inserted / total) * 100) : 0);
                const isDone = ip.phase === "importing-tab-done";
                const exact = modal.sourceAction === "open";
                return (
                  <div style={{ padding: "24px 0", textAlign: "center" }}>
                    <div style={{ fontSize: 13, color: th.text, fontWeight: 600, marginBottom: 4, fontFamily: "-apple-system, sans-serif" }}>
                      {isDone ? "Tab created" : exact ? "Importing exact source rows into new tab" : "Importing scan results into new tab"}
                    </div>
                    <div style={{ fontSize: 11, color: th.textDim, marginBottom: 10, fontFamily: "-apple-system, sans-serif" }}>
                      {formatNumber(inserted)} / {formatNumber(total)} events
                      <span style={{ marginLeft: 10, color: th.accent, fontFamily: "'SF Mono',Menlo,monospace", fontWeight: 600 }}>{pct}%</span>
                    </div>
                    <div style={{ maxWidth: 360, margin: "0 auto", height: 8, background: th.border + "44", borderRadius: 4, overflow: "hidden" }}>
                      <div style={{
                        height: "100%",
                        width: `${pct}%`,
                        background: `linear-gradient(90deg, ${th.accent}, ${th.accent}cc)`,
                        borderRadius: 4,
                        transition: "width var(--m-base) ease-out",
                        boxShadow: `0 0 8px ${th.accent}44`,
                      }} />
                    </div>
                    <div style={{ fontSize: 10, color: th.textMuted, marginTop: 8, fontFamily: "-apple-system, sans-serif" }}>
                      {ip.text || (isDone ? "Indexes building in background — modal will close shortly" : "Inserting rows into SQLite tab...")}
                    </div>
                  </div>
                );
              })()}

              {/* Scan messages */}
              {!modal.openingTab && modal.sourceAction !== "open" && resultErrors.length > 0 && (
                <div style={{ padding: "8px 12px", background: th.sev.critical + "15", border: `1px solid ${th.sev.critical}33`, borderRadius: 6, marginBottom: 10, fontSize: 11, color: th.sev.critical, fontFamily: "-apple-system, sans-serif" }}>
                  <div style={{ fontWeight: 700, marginBottom: 3 }}>Scan errors</div>
                  {resultErrors.map((e, i) => <div key={i}>{e}</div>)}
                </div>
              )}
              {!modal.openingTab && modal.sourceAction !== "open" && resultWarnings.length > 0 && (
                <div style={{ padding: "8px 12px", background: th.sev.med + "15", border: `1px solid ${th.sev.med}44`, borderRadius: 6, marginBottom: 10, fontSize: 11, color: th.sev.med, fontFamily: "-apple-system, sans-serif" }}>
                  <div style={{ fontWeight: 700, marginBottom: 3 }}>Scan notices</div>
                  {resultWarnings.map((w, i) => <div key={i}>{w}</div>)}
                </div>
              )}

              {/* Row-cap warning — shown when the scan matched more events than we materialized */}
              {!modal.openingTab && modal.sourceAction !== "open" && results.stats?.eventRowsCapped && (
                <div style={{ padding: "8px 12px", background: th.sev.med + "15", border: `1px solid ${th.sev.med}44`, borderRadius: 6, marginBottom: 10, fontSize: 11, color: th.sev.med, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "flex-start", gap: 8 }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.sev.med} strokeWidth="2" strokeLinecap="round" style={{ flexShrink: 0, marginTop: 1 }}><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  <div>
                    <div style={{ fontWeight: 600, marginBottom: 2 }}>
                      Showing first {formatNumber(results.stats.eventRowCap || 0)} of {formatNumber(results.stats.totalMatches || 0)} matched events
                    </div>
                    <div style={{ fontSize: 10, color: th.textDim }}>
                      Rule summary, severity counts, and first/last-seen timestamps are accurate for scanned candidates. Narrow the rule-set or severity filter for a fuller JS compatibility pass, or use raw EVTX + Hayabusa when available.
                    </div>
                  </div>
                </div>
              )}

              {/* Summary bar */}
              {!modal.openingTab && modal.sourceAction !== "open" && (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
                <span style={{ fontSize: 12, color: th.text, fontWeight: 600 }}>
                  {formatNumber(results.stats?.matchedRules || 0)} rules matched. {formatNumber(results.stats?.totalMatches || 0)} events flagged.
                </span>
                {results.stats?.format === "Hayabusa" ? (
                  <span style={{ fontSize: 10, color: th.textMuted }}>
                    ({formatNumber(results.stats?.totalRules || 0)} rules evaluated, {formatNumber(results.stats?.evtxFiles || 0)} EVTX files, {formatBytes(results.stats?.evtxTotalBytes || 0)} scanned, {formatNumber(results.stats?.evtxTotalRows || results.eventRowCount || 0)} detection rows, {formatDuration(results.stats?.runtimeMs || 0)})
                  </span>
                ) : (
                  <span style={{ fontSize: 10, color: th.textMuted }}>
                    ({formatNumber(results.stats?.totalRules || 0)} rules evaluated, {formatNumber(results.stats?.rowsScanned || 0)} rows scanned{results.stats?.runtimeMs ? `, ${formatDuration(results.stats.runtimeMs)}` : ""})
                  </span>
                )}
                {results.stats?.format && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${th.accent}15`, color: th.accent }}>{results.stats.format}</span>}
                {results.stats?.evtxFiles > 0 && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: th.textMuted + "15", color: th.textMuted }}>{results.stats.evtxFiles} EVTX files ({formatBytes(results.stats.evtxTotalBytes || 0)})</span>}
              </div>
              )}

              {/* Severity breakdown pills */}
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 10 }}>
                {SEV_ORDER.map((l) => {
                  const count = results.stats?.bySeverity?.[l] || 0;
                  if (!count) return null;
                  return <span key={l} style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", borderRadius: 10, fontSize: 10, fontWeight: 600, background: `${SEV_COLORS[l]}18`, color: SEV_COLORS[l], border: `1px solid ${SEV_COLORS[l]}33` }}>{l.toUpperCase()} <strong>{count}</strong></span>;
                })}
              </div>

              {/* View toggle: Dashboard / Findings / Timeline */}
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10 }}>
                <div style={{ display: "inline-flex", background: th.panelBg, borderRadius: 6, padding: 2, border: `1px solid ${th.border}44`, gap: 1 }}>
                  {[{ id: "dashboard", label: "Dashboard" }, { id: "rules", label: "Findings" }, { id: "timeline", label: "Timeline" }, ...(results.hasHtmlReport ? [{ id: "report", label: "Report" }] : [])].map((v) => (
                    <button key={v.id} onClick={() => setModal((p) => ({ ...p, sigmaView: v.id }))} style={{ padding: "3px 12px", background: (modal.sigmaView || "dashboard") === v.id ? th.fillAccent : "transparent", color: (modal.sigmaView || "dashboard") === v.id ? th.onAccent : th.textDim, border: "none", borderRadius: 4, fontSize: 10, cursor: "pointer", fontWeight: (modal.sigmaView || "dashboard") === v.id ? 600 : 400, transition: "all var(--m-base)" }}>{v.label}{v.id === "timeline" ? ` (${formatNumber(results.eventRowCount || 0)})` : v.id === "rules" ? ` (${formatNumber((results.matches || []).length)})` : ""}</button>
                  ))}
                </div>
                {(results.eventRowCount || 0) > 0 && (
                  <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginLeft: 4 }}>
                    Preview shows {formatNumber((sigmaResultsRef.current?.eventRows || []).length)} of {formatNumber(results.eventRowCount || 0)} rows. Export and Open as Tab use all persisted results.
                  </span>
                )}
              </div>

              {(modal.sigmaView || "dashboard") === "dashboard" && <SigmaTriageDashboard />}

              {/* Timeline view — Hayabusa-style per-event table */}
              {(modal.sigmaView || "dashboard") === "timeline" && (() => {
                const evtRows = sigmaResultsRef.current?.eventRows || [];
                if (evtRows.length === 0) return <div style={{ padding: 20, textAlign: "center", color: th.textDim, fontSize: 12 }}>No event rows to display.</div>;

                // Build columns dynamically from actual data — ordered by priority
                const PRIORITY_COLS = ["Timestamp", "Computer", "Channel", "EventID", "Level", "RuleID", "RuleTitle", "User", "MITRE",
                  "Image", "CommandLine", "ParentImage", "TargetFilename", "TargetObject", "ServiceName",
                  "ScriptBlockText", "Hashes", "LogonType", "IpAddress", "WorkstationName",
                  "DestinationIp", "DestinationPort", "SourcePort", "ShareName",
                  "MapDescription", "RemoteHost", "Description", "Category", "Author"];
                const COL_WIDTHS = {
                  Timestamp: 145, Computer: 120, Channel: 100, EventID: 50, Level: 60, RuleID: 160, RuleTitle: 200,
                  User: 110, MITRE: 80, Image: 200, CommandLine: 300, ParentImage: 180,
                  TargetFilename: 200, TargetObject: 200, ServiceName: 120, ScriptBlockText: 250,
                  Hashes: 180, LogonType: 50, IpAddress: 110, WorkstationName: 120,
                  DestinationIp: 110, DestinationPort: 60, SourcePort: 60, ShareName: 100,
                  MapDescription: 200, RemoteHost: 120, Description: 200, Category: 90, Author: 120,
                };
                // Discover which columns actually have data (sample first 100 rows)
                const colsWithData = new Set();
                const sample = evtRows.slice(0, 100);
                for (const row of sample) {
                  for (const key of Object.keys(row)) {
                    if (key.startsWith("_")) continue;
                    if (row[key] && String(row[key]).trim()) colsWithData.add(key);
                  }
                }
                // Build ordered column list: priority columns first (if they have data), then any extras
                const columnWidths = modal.sigmaTimelineColumnWidths || {};
                const COLS = [];
                for (const key of PRIORITY_COLS) {
                  if (colsWithData.has(key)) COLS.push({ key, w: columnWidths[key] || COL_WIDTHS[key] || 120 });
                }
                // Add any columns not in priority list
                for (const key of colsWithData) {
                  if (key.startsWith("_") || key === "RuleStatus") continue;
                  if (!COLS.find(c => c.key === key)) COLS.push({ key, w: columnWidths[key] || COL_WIDTHS[key] || 120 });
                }
                const totalW = COLS.reduce((s, c) => s + c.w, 0);
                return (
                  <div style={{ borderRadius: 6, border: `1px solid ${th.border}`, overflow: "hidden", background: th.modalBg }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, padding: "6px 8px", background: th.panelBg, borderBottom: `1px solid ${th.border}66`, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                      <span>Drag header edges to resize columns.</span>
                      {Object.keys(columnWidths).length > 0 && (
                        <button
                          onClick={() => setModal((p) => p ? { ...p, sigmaTimelineColumnWidths: {} } : p)}
                          style={{ ...ms.bsm, padding: "1px 7px", fontSize: 9 }}
                        >
                          Reset Columns
                        </button>
                      )}
                    </div>
                    <div style={{ maxHeight: 340, overflow: "auto" }}>
                      <table style={{ borderCollapse: "separate", borderSpacing: 0, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace", tableLayout: "fixed", width: totalW, minWidth: "100%" }}>
                        <thead>
                          <tr>
                            {COLS.map((c) => (
                              <th key={c.key} style={{ position: "sticky", top: 0, zIndex: 2, background: th.headerBg || th.panelBg, borderBottom: `2px solid ${th.border}`, padding: "6px 8px", textAlign: "left", fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", width: c.w, minWidth: c.w, maxWidth: c.w, whiteSpace: "nowrap", boxSizing: "border-box" }}>
                                <span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis" }}>{c.key}</span>
                                <span
                                  onMouseDown={(event) => handleTimelineColumnResize(c.key, c.w, event)}
                                  title={`Resize ${c.key}`}
                                  style={{
                                    position: "absolute",
                                    top: 0,
                                    right: -3,
                                    width: 7,
                                    height: "100%",
                                    cursor: "col-resize",
                                    zIndex: 3,
                                    borderRight: `1px solid ${th.border}55`,
                                  }}
                                />
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {evtRows.slice(0, 2000).map((row, ri) => {
                            const levColor = SEV_COLORS[row.Level] || th.textMuted;
                            return (
                              <tr key={ri} style={{ borderBottom: `1px solid ${th.border}22`, background: ri % 2 === 0 ? "transparent" : `${th.panelBg}44` }}
                                onMouseEnter={(e) => { e.currentTarget.style.background = `${levColor}08`; }}
                                onMouseLeave={(e) => { e.currentTarget.style.background = ri % 2 === 0 ? "transparent" : `${th.panelBg}44`; }}>
                                {COLS.map((c) => {
                                  const val = row[c.key] || "";
                                  if (c.key === "Level") {
                                    return <td key={c.key} style={{ padding: "4px 8px", verticalAlign: "top", borderBottom: `1px solid ${th.border}22` }}><span style={{ padding: "1px 6px", borderRadius: 3, fontSize: 8, fontWeight: 700, textTransform: "uppercase", background: `${levColor}22`, color: levColor }}>{val}</span></td>;
                                  }
                                  if (c.key === "Timestamp") {
                                    return <td key={c.key} style={{ padding: "4px 8px", color: th.textDim, verticalAlign: "top", whiteSpace: "nowrap", borderBottom: `1px solid ${th.border}22` }}>{(val || "").slice(0, 19)}</td>;
                                  }
                                  if (c.key === "MITRE") {
                                    return <td key={c.key} style={{ padding: "4px 8px", verticalAlign: "top", borderBottom: `1px solid ${th.border}22` }}>{val && <span style={{ padding: "1px 4px", borderRadius: 3, fontSize: 8, background: th.textMuted + "18", color: th.textDim, fontWeight: 600 }}>{val}</span>}</td>;
                                  }
                                  if (c.key === "RuleTitle") {
                                    return <td key={c.key} style={{ padding: "4px 8px", color: levColor, fontWeight: 500, verticalAlign: "top", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: c.w, borderBottom: `1px solid ${th.border}22` }}>{val}</td>;
                                  }
                                  if (c.key === "Details") {
                                    return <td key={c.key} style={{ padding: "4px 8px", color: th.textDim, verticalAlign: "top", wordBreak: "break-all", fontSize: 9, lineHeight: 1.4, borderBottom: `1px solid ${th.border}22` }}>{val}</td>;
                                  }
                                  return <td key={c.key} style={{ padding: "4px 8px", color: th.text, verticalAlign: "top", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", borderBottom: `1px solid ${th.border}22` }}>{val}</td>;
                                })}
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                      {(results.eventRowCount || 0) > evtRows.length && (
                        <div style={{ position: "sticky", left: 0, padding: "8px 12px", fontSize: 10, color: th.textMuted, textAlign: "center", background: th.panelBg, borderTop: `1px solid ${th.border}66` }}>
                          Showing {formatNumber(evtRows.length)} preview rows of {formatNumber(results.eventRowCount || 0)} total results. Export and Open as Tab include all persisted results.
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Report view — Hayabusa HTML report in iframe */}
              {(modal.sigmaView || "dashboard") === "report" && results.hasHtmlReport && (() => {
                const loadReport = async () => {
                  if (modal.htmlReportContent) return;
                  try {
                    const html = await tle.sigmaGetHtmlReport(modal.jobId);
                    if (html) setModal((p) => ({ ...p, htmlReportContent: html }));
                  } catch {}
                };
                if (!modal.htmlReportContent) { loadReport(); return <div style={{ padding: 20, textAlign: "center", color: th.textMuted, fontSize: 11 }}>Loading report...</div>; }
                return (
                  <div style={{ borderRadius: 6, border: `1px solid ${th.border}`, overflow: "hidden", maxHeight: 400 }}>
                    <iframe
                      srcDoc={modal.htmlReportContent}
                      style={{ width: "100%", height: 400, border: "none", background: "#fff" }}
                      sandbox="allow-same-origin"
                      title="Hayabusa Report"
                    />
                  </div>
                );
              })()}

              {/* Findings view — rule summaries */}
              {(modal.sigmaView || "dashboard") === "rules" && (
              <div style={{ maxHeight: 360, overflow: "auto", borderRadius: 6, border: `1px solid ${th.border}` }}>
                {(results.matches || []).length === 0 && (
                  <div style={{ padding: 20, textAlign: "center", color: th.textDim, fontSize: 12 }}>No findings matched.</div>
                )}
                {(results.matches || []).map((match, i) => {
                  const isExpanded = expandedRule === i;
                  return (
                    <div key={i} style={{ borderBottom: `1px solid ${th.border}`, background: isExpanded ? `${th.accent}08` : "transparent" }}>
                      {/* Collapsed row */}
                      <div onClick={() => setModal((p) => ({ ...p, expandedRule: isExpanded ? null : i }))} style={{ padding: "8px 12px", cursor: "pointer", display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ flexShrink: 0 }}>{sevBadge(match.level)}</span>
                        <span style={{ flex: 1, fontSize: 12, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{match.title}</span>
                        <span style={{ display: "flex", gap: 2, flexShrink: 0 }}>{(match.mitre || []).slice(0, 3).map(mitreBadge)}</span>
                        <span style={{ fontSize: 10, color: th.textDim, flexShrink: 0, minWidth: 50, textAlign: "right" }}>{formatNumber(match.matchCount)} hits</span>
                        {match.hosts?.length > 0 && <span style={{ fontSize: 10, color: th.textDim, flexShrink: 0 }}>{match.hosts.length} host{match.hosts.length > 1 ? "s" : ""}</span>}
                        <span style={{ fontSize: 9, color: th.textDim, flexShrink: 0, fontFamily: "monospace" }}>{match.firstSeen ? match.firstSeen.slice(0, 16) : ""}</span>
                      </div>

                      {/* Expanded detail */}
                      {isExpanded && (
                        <div style={{ padding: "6px 12px 12px", borderTop: `1px solid ${th.border}44` }}>
                          {match.description && <div style={{ fontSize: 11, color: th.textDim, marginBottom: 6 }}>{match.description}</div>}
                          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 10, color: th.textDim, marginBottom: 8 }}>
                            {match.author && <span><strong style={{ color: th.text }}>Author:</strong> {match.author}</span>}
                            {match.firstSeen && <span><strong style={{ color: th.text }}>First:</strong> {match.firstSeen}</span>}
                            {match.lastSeen && <span><strong style={{ color: th.text }}>Last:</strong> {match.lastSeen}</span>}
                          </div>
                          {match.mitre?.length > 0 && <div style={{ marginBottom: 6 }}>{match.mitre.map(mitreBadge)}</div>}
                          {match.tags?.length > 0 && <div style={{ fontSize: 10, color: th.textDim, marginBottom: 6 }}><strong style={{ color: th.text }}>Tags:</strong> {match.tags.join(", ")}</div>}
                          {match.falsepositives?.length > 0 && (
                            <div style={{ fontSize: 10, color: th.textDim, marginBottom: 6, padding: "4px 8px", background: `${th.border}44`, borderRadius: 4 }}>
                              <strong style={{ color: th.text }}>False positives:</strong> {match.falsepositives.join("; ")}
                            </div>
                          )}
                          {match.sampleRows?.length > 0 && (
                            <div style={{ marginBottom: 8 }}>
                              <label style={{ ...ms.lb, marginBottom: 4 }}>Sample Matched Rows</label>
                              <div style={{ maxHeight: 80, overflow: "auto", fontSize: 10, fontFamily: "monospace", color: th.textDim, background: th.panelBg, padding: 6, borderRadius: 4, border: `1px solid ${th.border}` }}>
                                {match.sampleRows.map((row, ri) => (
                                  <div key={ri} style={{ padding: "2px 0", borderBottom: ri < match.sampleRows.length - 1 ? `1px solid ${th.border}33` : "none", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                                    {typeof row === "string" ? row : JSON.stringify(row)}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                            {ct?.dataReady && sigmaResultsRef.current?.sourceRowMode !== "result" && !sigmaResultsRef.current?.isDirScan && !sigmaResultsRef.current?.isKapeOutput && !sigmaResultsRef.current?.isHistory && (
                              <Fragment>
                                  <span style={{ fontSize: 9, color: th.textMuted, marginRight: 2 }}>Matched Source Rows:</span>
	                                <button onClick={() => handleShowInTimeline(match)} disabled={!!modal.sourceAction} style={{ ...ms.bsm, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontWeight: 600, opacity: modal.sourceAction ? 0.55 : 1 }}>
                                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2.5" strokeLinecap="round" style={{ marginRight: 3, verticalAlign: "middle", display: "inline" }}>
                                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                                  </svg>
	                                  {modal.sourceAction === "show" ? "Loading..." : "Show Exact Hits"}
	                                </button>
	                                <button onClick={() => handleTagMatches(match)} disabled={!!modal.sourceAction} style={{ ...ms.bsm, opacity: modal.sourceAction ? 0.55 : 1 }}>{modal.sourceAction === "tag" ? "Tagging..." : "Tag Exact Hits"}</button>
	                                <button onClick={() => handleBookmarkMatches(match)} disabled={!!modal.sourceAction} style={{ ...ms.bsm, opacity: modal.sourceAction ? 0.55 : 1 }}>{modal.sourceAction === "bookmark" ? "Bookmarking..." : "Bookmark Exact Hits"}</button>
	                                <button onClick={() => handleOpenExactMatchesAsTab(match)} disabled={!!modal.sourceAction} style={{ ...ms.bsm, opacity: modal.sourceAction ? 0.55 : 1 }}>{modal.sourceAction === "open" ? "Opening..." : "Open Exact Hits as Tab"}</button>
	                              </Fragment>
                            )}
                            {(sigmaResultsRef.current?.sourceRowMode === "result" || sigmaResultsRef.current?.isDirScan || sigmaResultsRef.current?.isKapeOutput || sigmaResultsRef.current?.isHistory) && (
                              <Fragment>
                                <span style={{ fontSize: 9, color: th.textMuted, marginRight: 2 }}>
                                  Persisted result rows:
                                </span>
                                <button onClick={() => handleOpenExactMatchesAsTab(match)} disabled={!!modal.sourceAction} style={{ ...ms.bsm, opacity: modal.sourceAction ? 0.55 : 1 }}>{modal.sourceAction === "open" ? "Opening..." : "Open Exact Hits as Tab"}</button>
                                <button onClick={() => handleTagMatches(match)} disabled={!!modal.sourceAction} title="Open exact hits as a result tab and tag every imported row automatically." style={{ ...ms.bsm, opacity: modal.sourceAction ? 0.55 : 1 }}>{modal.sourceAction === "tag" ? "Opening + Tagging..." : "Open + Tag"}</button>
                                <button onClick={() => handleBookmarkMatches(match)} disabled={!!modal.sourceAction} title="Open exact hits as a result tab and bookmark every imported row automatically." style={{ ...ms.bsm, opacity: modal.sourceAction ? 0.55 : 1 }}>{modal.sourceAction === "bookmark" ? "Opening + Bookmarking..." : "Open + Bookmark"}</button>
                              </Fragment>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
              )}
            </Fragment>
          )}

    </>
  );
}
