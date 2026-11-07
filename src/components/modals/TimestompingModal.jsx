import { useCallback } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { DraggableResizableModal, ErrorState } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";

export default function TimestompingModal() {
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

  const ms = useModalChrome();

  if (!modal || modal.type !== "timestomping" || !ct) return null;

  const { data, loading } = modal;

  const sevColors = { critical: th.sev.critical, high: th.sev.high, medium: th.sev.med, low: th.sev.low };
  const sevLabels = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

  const fmtDelta = (h) => {
    if (!h || h <= 0) return "< 1h";
    if (h < 24) return `${h.toFixed(1)}h`;
    if (h < 8760) return `${(h / 24).toFixed(1)}d`;
    return `${(h / 8760).toFixed(1)}y`;
  };

  const rowStyle = (i) => ({
    display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", fontSize: 11,
    background: i % 2 === 0 ? "transparent" : `${th.border}15`,
    borderBottom: `1px solid ${th.border}22`, fontFamily: "'SF Mono',Menlo,monospace",
  });

  const cbStyle = (checked) => ({
    width: 14, height: 14, borderRadius: 4, flexShrink: 0, cursor: "pointer",
    background: checked ? (th.fillAccent) : "transparent",
    border: `1.5px solid ${checked ? th.accent : th.border}`,
    display: "flex", alignItems: "center", justifyContent: "center", transition: "all var(--m-base)",
  });

  const toggleSet = (key, idx) => setModal((p) => {
    if (!p) return p;
    const s = new Set(p[key]); s.has(idx) ? s.delete(idx) : s.add(idx); return { ...p, [key]: s };
  });

  const toggleAll = (key, count) => setModal((p) => {
    if (!p) return p;
    const cur = p[key] || new Set();
    return { ...p, [key]: cur.size === count ? new Set() : new Set(Array.from({ length: count }, (_, i) => i)) };
  });

  const copyReport = () => {
    if (!data) return;
    const d = data;
    const v = d.verdict;
    const lines = [
      "=== Timestomp Indicator Report ===",
      ...(v && v.severity && v.severity !== "info" ? [
        `Verdict: ${v.severity.toUpperCase()} (confidence: ${v.confidence}, score ${v.severityScore}/100)`,
        v.headline, "", v.narrative, "",
        ...((v.mitre || []).length ? ["MITRE candidates:", ...v.mitre.map((m) => `  - ${m.technique} ${m.name} [${m.confidence}] — ${m.evidence}`), ""] : []),
        ...((v.coverage || []).length ? ["Coverage:", ...v.coverage.map((c) => `  [${c.status}] ${c.label}: ${c.detail}`), ""] : []),
      ] : []),
      `Potential Indicators: ${(d.totalTimestomped || 0).toLocaleString()} kept from ${(d.rawSiFnCount || 0).toLocaleString()} raw SI<FN hits (${(d.suppressedCount || 0).toLocaleString()} suppressed)`,
      `High Confidence: ${d.highConfidenceCount || 0}`,
      `Likely: ${d.likelyCount || 0}`,
      `Context / Low Confidence: ${d.contextCount || 0}`,
      `Critical Severity: ${d.criticalCount || 0}`,
      `High Severity: ${d.highCount || 0}`,
      `Medium Severity: ${d.mediumCount || 0}`,
      `Low Severity: ${d.lowCount || 0}`,
      `Forward-dated: ${d.forwardCount || 0}  Future-dated: ${d.futureCount || 0}  Bulk-stomp clusters: ${d.clusterCount || 0}`,
      (d.correlation && (d.correlation.evtxAvailable || d.correlation.usnAvailable))
        ? `Cross-artifact: Sysmon EID 2 ${d.correlation.evtxAvailable ? (d.correlation.candidatesEid2Corroborated || 0) + " confirmed / " + ((d.confirmedStompsNoMftMatch || []).length) + " not-in-$MFT" : "(not loaded)"} · USN ${d.correlation.usnAvailable ? (d.correlation.candidatesUsnContradicted || 0) + " contradicted" : "(not loaded)"}`
        : "Cross-artifact: no companion loaded (single-source $MFT)",
      d.truncated ? `(scan capped at ${(d.files?.length || 0).toLocaleString()} of ${(d.rawSiFnCount || 0).toLocaleString()} candidates)` : null,
      "",
    ].filter((x) => x !== null);
    if ((d.confirmedStompsNoMftMatch || []).length > 0) {
      lines.push("Confirmed Timestomps With No $MFT Mismatch (Sysmon EID 2):");
      d.confirmedStompsNoMftMatch.slice(0, 30).forEach((s) => lines.push(`  ${s.targetFilename || "(unknown)"}${s.preStompCreated ? `  was ${String(s.preStompCreated).slice(0, 19)}` : ""}${s.image ? `  via ${s.image}` : ""}`));
      lines.push("");
    }
    if (d.criticalCount > 0) {
      lines.push("Critical Files:");
      d.files.filter((f) => f.severity === "critical").forEach((f) => lines.push(`  ${f.fileName} \u2014 ${f.parentPath} \u2014 ${f.confidence} \u2014 Delta: ${fmtDelta(f.maxDeltaHours)} \u2014 ${(f.indicators || []).join(", ")}`));
      lines.push("");
    }
    if ((d.clusters || []).length > 0) {
      lines.push("Bulk-Timestomp Clusters:");
      d.clusters.slice(0, 10).forEach((c) => lines.push(`  ${(c.siCreated || "").slice(0, 19)} \u2014 ${c.count} files \u2014 ${c.dominantExt || "(mixed)"}${c.anyExec ? " [exec]" : ""}${c.zeroedSubseconds ? " [zeroed]" : ""}`));
      lines.push("");
    }
    lines.push("Top Directories:");
    (d.topDirectories || []).slice(0, 10).forEach((dir) => lines.push(`  ${dir.path || "(root)"} (${dir.count} files)`));
    lines.push("", "Extension Breakdown:");
    (d.extensionBreakdown || []).slice(0, 10).forEach((e) => lines.push(`  ${e.extension || "(none)"}: ${e.count}`));
    if ((d.notes || []).length > 0) { lines.push("", "Coverage & Limitations:"); d.notes.forEach((n) => lines.push(`  - ${n}`)); }
    navigator.clipboard?.writeText(lines.join("\n"));
  };

  const copySelected = () => {
    const selFiles = modal.tsSelFiles || new Set();
    const selDirs = modal.tsSelDirs || new Set();
    const lines = [];
    if (selFiles.size > 0 && data?.files) {
      lines.push("=== Potential Timestomp Indicators ===");
      lines.push("Severity\tConfidence\tFileName\tExtension\tParentPath\tSI Created\tFN Created\tDelta\tIndicators");
      // Selection indices are positions in the SORTED table projection — iterate the same projection
      // (NOT the unsorted data.files) so the exported rows match what the analyst selected (E3).
      sortTsArr(data.files).forEach((f, i) => { if (selFiles.has(i)) lines.push(`${f.severity}\t${f.confidence}\t${f.fileName}\t${f.extension}\t${f.parentPath}\t${(f.siCreated || "").slice(0, 19)}\t${(f.fnCreated || "").slice(0, 19)}\t${fmtDelta(f.maxDeltaHours)}\t${(f.indicators || []).join(", ")}`); });
      lines.push("");
    }
    if (selDirs.size > 0 && data?.topDirectories) {
      lines.push("=== Top Directories ===");
      data.topDirectories.forEach((d, i) => { if (selDirs.has(i)) lines.push(`${d.path || "(root)"}\t${d.count}`); });
    }
    if (lines.length > 0) navigator.clipboard?.writeText(lines.join("\n"));
  };

  // Tag exactly the scored rows by physical rowId (NOT the non-unique EntryNumber, which over-tags
  // deleted/ADS/directory siblings — E1), report the result, refresh grid tags, and never close on
  // failure (E2 — the regression the ADS fix corrected).
  const tagIndicators = async () => {
    if (!data?.files?.length) return;
    const rowIds = data.files.map((f) => f.rowId).filter((r) => r != null);
    if (rowIds.length === 0) { setModal((p) => (p ? { ...p, tsTagMsg: "Nothing to tag (no row ids)" } : p)); return; }
    const result = await tle.bulkTagFiltered(ct.id, "Timestomp Indicator", { rowIdFilter: rowIds });
    if (isIpcError(result) || result?.error) {
      setModal((p) => (p ? { ...p, tsTagMsg: `Tag failed: ${isIpcError(result) ? ipcErrorMessage(result) : result.error}` } : p));
      return;
    }
    try {
      const td = await tle.getAllTagData(ct.id);
      const nrt = {};
      for (const { rowid, tag } of td) { if (!nrt[rowid]) nrt[rowid] = []; nrt[rowid].push(tag); }
      up("rowTags", nrt);
      up("tagColors", { ...(ct.tagColors || {}), "Timestomp Indicator": th.warning });
    } catch { /* tag refresh is best-effort */ }
    const n = result?.tagged || 0;
    setModal((p) => (p ? { ...p, tsTagMsg: `Tagged ${n.toLocaleString()} indicator${n === 1 ? "" : "s"}` } : p));
    setTimeout(() => setModal((p) => (p ? { ...p, tsTagMsg: null } : p)), 4000);
  };

  const totalSelected = ((modal.tsSelFiles || new Set()).size + (modal.tsSelDirs || new Set()).size);

  // Resizable column helpers
  const defTsW = [10, 180, 50, 220, 90, 140, 140, 55, 64];
  const tsW = modal.tsColW || defTsW;
  const startColResize = (stateKey, defaults, colIdx, e) => {
    e.preventDefault(); e.stopPropagation();
    const startX = e.clientX, startW = (modal[stateKey] || defaults)[colIdx];
    const onMove = (ev) => setModal((p) => { if (!p) return p; const w = [...(p[stateKey] || defaults)]; w[colIdx] = Math.max(30, startW + (ev.clientX - startX)); return { ...p, [stateKey]: w }; });
    const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
  };
  const resH = { position: "absolute", right: -2, top: 0, bottom: 0, width: 5, cursor: "col-resize", zIndex: 3 };

  // Sort helpers
  const handleTsSort = (colKey) => setModal((p) => {
    if (!p) return p;
    const cur = p.tsSort;
    const newDir = cur?.col === colKey && cur.dir === "asc" ? "desc" : "asc";
    return { ...p, tsSort: { col: colKey, dir: newDir } };
  });
  const sortTsArr = (arr) => {
    const s = modal.tsSort;
    if (!s || !arr) return arr;
    return [...arr].sort((a, b) => {
      const va = (a[s.col] || "").toString().toLowerCase();
      const vb = (b[s.col] || "").toString().toLowerCase();
      return s.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
    });
  };
  const tsSort = modal.tsSort;
  const tsSortArrow = (colKey) => {
    const active = tsSort?.col === colKey; const dir = active ? tsSort.dir : null;
    return (
      <svg width="8" height="10" viewBox="0 0 8 10" style={{ marginLeft: 3, flexShrink: 0, opacity: active ? 1 : 0.25, transition: "opacity var(--m-base)" }}>
        <path d="M4 1L7 4H1Z" fill={dir === "asc" ? (th.accent) : th.textMuted} opacity={dir === "asc" ? 1 : 0.4} />
        <path d="M4 9L1 6H7Z" fill={dir === "desc" ? (th.accent) : th.textMuted} opacity={dir === "desc" ? 1 : 0.4} />
      </svg>
    );
  };
  const tsHdrCol = (w, label, colKey, colIdx) => (
    <div style={{ width: w, flexShrink: 0, position: "relative", cursor: "pointer", display: "flex", alignItems: "center", userSelect: "none" }} onClick={() => handleTsSort(colKey)}>
      {label}{tsSortArrow(colKey)}
      <div onMouseDown={(e) => { e.stopPropagation(); startColResize("tsColW", defTsW, colIdx, e); }} style={resH} />
    </div>
  );

  return (
    <DraggableResizableModal defaultWidth={940} minWidth={420} minHeight={280} onClose={() => setModal(null)}>
      {({ startDrag }) => (<>
        {/* Header */}
        <div onMouseDown={startDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.warning}33, ${th.warning}11)`, border: `1px solid ${th.warning}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.warning} strokeWidth="1.8" strokeLinecap="round"><circle cx="12" cy="12" r="10" fill={(th.warning) + "18"}/><polyline points="12 6 12 12 16 14"/><circle cx="19" cy="5" r="2" fill={th.danger} stroke="none"/></svg>
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>Timestomp Indicator Review</h3>
              <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>Score likely timestomp indicators from SI &lt; FN plus NTFS confidence heuristics</p>
            </div>
          </div>
          <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, fontSize: 18, cursor: "pointer", padding: "4px 8px", lineHeight: 1 }}>{"\u2715"}</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
          {loading && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
              <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${th.warning}33, ${th.warning}11)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <div style={{ width: 20, height: 20, border: `2px solid ${th.warning}`, borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
              </div>
              <span style={{ color: th.textDim, fontSize: 13, fontFamily: "-apple-system, sans-serif" }}>Scoring timestomp indicators...</span>
            </div>
          )}

          {!loading && modal.error && (
            <ErrorState message={modal.error} />
          )}

          {!loading && !modal.error && data && isIpcError(data) && (
            <div style={{ textAlign: "center", padding: 40, color: th.danger, fontSize: 13 }}>{ipcErrorMessage(data)}</div>
          )}

          {!loading && !modal.error && data && !isIpcError(data) && data.totalTimestomped === 0 && (data.confirmedStompsNoMftMatch || []).length === 0 && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 12 }}>
              <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${th.success}33, ${th.success}11)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={th.success} strokeWidth="2" strokeLinecap="round"><path d="M20 6L9 17l-5-5"/></svg>
              </div>
              <span style={{ color: th.textDim, fontSize: 13, fontFamily: "-apple-system, sans-serif" }}>No $MFT timestomp indicators detected</span>
              <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif", maxWidth: 460, textAlign: "center", lineHeight: 1.5 }}>SI&lt;FN catches incomplete stomps only; a full-copy $SI==$FN zeroed stomp, or one that also rewrites $FN, is not detectable from $MFT alone. Open a Sysmon EVTX (EID 2) and USN ($J) companion tab to corroborate.</span>
            </div>
          )}

          {!loading && data && !isIpcError(data) && (data.totalTimestomped > 0 || (data.confirmedStompsNoMftMatch || []).length > 0) && (() => {
            const d = data;
            const files = d.files || [];
            const selFiles = modal.tsSelFiles || new Set();
            const selDirs = modal.tsSelDirs || new Set();

            return (<>
              {/* T4: incident verdict — severity = impact, confidence is gated on forgery-resistant
                  Sysmon EID 2 / USN corroboration so a single-source $SI/$FN finding is never overclaimed. */}
              {d.verdict && d.verdict.severity && d.verdict.severity !== "info" && (() => {
                const v = d.verdict;
                const sevColor = (v.severity === "critical" || v.severity === "high") ? th.danger : v.severity === "medium" ? th.warning : v.severity === "low" ? th.accent : th.textMuted;
                const confColor = v.confidence === "corroborated" ? (th.success || "#3fb950") : v.confidence === "weak" ? th.warning : th.textMuted;
                const covColor = (s) => s === "ok" ? (th.success || "#3fb950") : s === "partial" ? th.warning : th.textMuted;
                return (
                  <div style={{ marginBottom: 16, padding: "12px 14px", borderRadius: 10, background: `${sevColor}10`, border: `1px solid ${sevColor}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                      <span style={{ padding: "2px 9px", borderRadius: 999, fontSize: 10, fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.06em", color: sevColor, background: `${sevColor}1e`, border: `1px solid ${sevColor}55` }}>{v.severity}</span>
                      <span title="How far the conclusion can be trusted — 'corroborated' requires forgery-resistant Sysmon EID 2 (FileCreateTime) or a USN FileCreate contradiction backing the $SI/$FN finding." style={{ padding: "2px 9px", borderRadius: 999, fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: confColor, background: `${confColor}18`, border: `1px solid ${confColor}44`, cursor: "help" }}>confidence: {v.confidence}</span>
                      <span title="$STANDARD_INFORMATION ($SI / 0x10) is attacker-settable; $FILE_NAME ($FN / 0x30) is OS-maintained but a full-copy $SI==$FN stomp leaves no $MFT mismatch. Corroborate with Sysmon EID 2 + USN." style={{ padding: "2px 9px", borderRadius: 999, fontSize: 9, fontWeight: 600, letterSpacing: "0.03em", color: th.textMuted, background: `${th.border}22`, border: `1px solid ${th.border}33`, cursor: "help" }}>$SI-derived</span>
                      {v.severityScore > 0 && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>score {v.severityScore}/100</span>}
                    </div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4, marginBottom: 6 }}>{v.headline}</div>
                    <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>{v.narrative}</div>
                    {(v.factors?.length ?? 0) > 0 && (
                      <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {v.factors.map((f, i) => (
                          <span key={i} title={f.detail} style={{ padding: "3px 8px", borderRadius: 8, fontSize: 9, fontWeight: 600, fontFamily: "-apple-system, sans-serif", color: f.severity === "high" ? th.danger : f.severity === "medium" ? th.warning : th.textDim, background: `${th.border}22`, border: `1px solid ${th.border}33`, cursor: "help" }}>{f.label}</span>
                        ))}
                      </div>
                    )}
                    {(v.mitre?.length ?? 0) > 0 && (
                      <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
                        <span style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>MITRE</span>
                        {v.mitre.map((m, i) => (
                          <span key={i} title={`${m.name} — ${m.evidence} (${m.confidence})`} style={{ padding: "3px 8px", borderRadius: 8, fontSize: 9, fontWeight: 700, fontFamily: "'SF Mono',Menlo,monospace", color: th.accent, background: `${th.accent}14`, border: `1px solid ${th.accent}33`, cursor: "help" }}>{m.technique}{m.confidence === "corroborated" ? " ✓" : ""}</span>
                        ))}
                      </div>
                    )}
                    {(v.coverage?.length ?? 0) > 0 && (
                      <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${th.border}22`, display: "flex", flexWrap: "wrap", gap: 8 }}>
                        <span style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", width: "100%" }}>Coverage</span>
                        {v.coverage.map((c, i) => (
                          <span key={i} title={c.detail} style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 9, color: th.textDim, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>
                            <span style={{ width: 7, height: 7, borderRadius: 999, background: covColor(c.status), flexShrink: 0 }} />{c.label}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Summary cards */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
                {[
                  { label: "Potential Indicators", value: d.totalTimestomped.toLocaleString(), sub: `${d.rawSiFnCount.toLocaleString()} raw SI<FN \u00B7 ${d.suppressedCount.toLocaleString()} suppressed`, color: th.warning },
                  { label: "High Confidence", value: d.highConfidenceCount.toLocaleString(), sub: "Stacked indicators + suspicious context", color: th.danger },
                  { label: "Likely", value: d.likelyCount.toLocaleString(), sub: "Strong timestamp mismatch patterns", color: th.warning },
                  { label: "Context", value: d.contextCount.toLocaleString(), sub: "Weak / lower-confidence indicators", color: th.textDim },
                ].map((c, i) => (
                  <div key={i} style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                    <div style={{ fontSize: 10, color: c.color, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.02em" }}>{c.value}</div>
                    <div style={{ fontSize: 10, color: th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif" }}>{c.sub}</div>
                  </div>
                ))}
              </div>

              {/* Truncation warning — the scan was capped; mass-timestomp is exactly when this bites (D5) */}
              {d.truncated && (
                <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "9px 14px", marginBottom: 12, borderRadius: 10, background: `${th.warning}14`, border: `1px solid ${th.warning}44` }}>
                  <span style={{ fontSize: 13 }}>⚠</span>
                  <span style={{ fontSize: 11, color: th.warning, fontFamily: "-apple-system, sans-serif" }}>Scan capped at {(d.files?.length || 0).toLocaleString()} of {(d.rawSiFnCount || 0).toLocaleString()} candidates — the newest / forward-dated records may be omitted. Narrow the tab or re-run after indexing.</span>
                </div>
              )}

              {/* Coverage chips: forward / future / cluster lanes (Tier-2 capabilities the cards don't show) (D5) */}
              {((d.forwardCount || 0) + (d.futureCount || 0) + (d.clusterCount || 0)) > 0 && (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 16 }}>
                  {(d.clusterCount || 0) > 0 && <span title="Groups of files sharing one exact $SI Created with an aligned stomp signal — a bulk-timestomp tool hallmark." style={{ fontSize: 10, padding: "3px 9px", borderRadius: 999, background: `${th.danger}1e`, border: `1px solid ${th.danger}44`, color: th.danger, fontWeight: 600, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>{d.clusterCount} bulk-stomp cluster{d.clusterCount === 1 ? "" : "s"}</span>}
                  {(d.forwardCount || 0) > 0 && <span title="$SI is LATER than $FN on some field (forward/post-dating)." style={{ fontSize: 10, padding: "3px 9px", borderRadius: 999, background: `${th.warning}1e`, border: `1px solid ${th.warning}44`, color: th.warning, fontWeight: 600, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>{d.forwardCount} forward-dated</span>}
                  {(d.futureCount || 0) > 0 && <span title="$SI is dated in the future (beyond a 1-day clock-skew tolerance)." style={{ fontSize: 10, padding: "3px 9px", borderRadius: 999, background: `${th.warning}1e`, border: `1px solid ${th.warning}44`, color: th.warning, fontWeight: 600, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>{d.futureCount} future-dated</span>}
                </div>
              )}

              {/* Cross-artifact corroboration status (Tier 2 — forgery-resistant witnesses) */}
              {(() => {
                const c = d.correlation || {};
                const haveComp = c.evtxAvailable || c.usnAvailable;
                return (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 16, alignItems: "center" }}>
                    {c.evtxAvailable
                      ? <span title="Sysmon EID 2 (FileCreateTime) is the literal timestomp event; a match confirms the stomp and recovers the pre-stomp creation time + the tool." style={{ fontSize: 10, padding: "3px 9px", borderRadius: 999, background: `${th.success}1e`, border: `1px solid ${th.success}44`, color: th.success, fontWeight: 600, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>✓ Sysmon EID 2: {(c.candidatesEid2Corroborated || 0)} confirmed{(d.confirmedStompsNoMftMatch || []).length ? ` · ${d.confirmedStompsNoMftMatch.length} not in $MFT` : ""}</span>
                      : <span title="No Sysmon EVTX companion loaded — the literal timestomp event (EID 2) and the pre-stomp time/tool are unavailable." style={{ fontSize: 10, padding: "3px 9px", borderRadius: 999, background: `${th.border}22`, border: `1px solid ${th.border}44`, color: th.textMuted, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>Sysmon EID 2: not loaded</span>}
                    {c.usnAvailable
                      ? <span title="A USN ($J) FileCreate that postdates the backdated $SI Created is a forgery-resistant contradiction (beats the path-class floor)." style={{ fontSize: 10, padding: "3px 9px", borderRadius: 999, background: `${th.success}1e`, border: `1px solid ${th.success}44`, color: th.success, fontWeight: 600, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>✓ USN ($J): {(c.candidatesUsnContradicted || 0)} contradicted</span>
                      : <span title="No USN ($J) companion loaded — the forgery-resistant create-time contradiction check did not run." style={{ fontSize: 10, padding: "3px 9px", borderRadius: 999, background: `${th.border}22`, border: `1px solid ${th.border}44`, color: th.textMuted, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>USN ($J): not loaded</span>}
                    {!haveComp && <span style={{ fontSize: 9, color: th.warning, fontFamily: "-apple-system, sans-serif" }}>⚠ single-source $MFT — open a Sysmon EVTX / USN tab to corroborate</span>}
                    {(c.evtxCapped || c.usnCapped) && <span title="The companion scan hit its row cap; corroboration covers a subset — counts are a floor, not a ceiling." style={{ fontSize: 9, color: th.warning, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>⚠ companion scan capped — corroboration is a floor</span>}
                  </div>
                );
              })()}

              {/* Severity distribution bar */}
              <div style={{ padding: "10px 14px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, marginBottom: 16 }}>
                <div style={{ fontSize: 10, color: th.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>Severity Distribution</div>
                <div style={{ display: "flex", height: 18, borderRadius: 6, overflow: "hidden", border: `1px solid ${th.border}33` }}>
                  {[
                    { count: d.criticalCount, color: sevColors.critical, label: "Critical" },
                    { count: d.highCount, color: sevColors.high, label: "High" },
                    { count: d.mediumCount, color: sevColors.medium, label: "Medium" },
                    { count: d.lowCount, color: sevColors.low, label: "Low" },
                  ].filter((s) => s.count > 0).map((s, i) => (
                    <div key={i} title={`${s.label}: ${s.count}`} style={{ flex: s.count, background: `linear-gradient(180deg, ${s.color}cc, ${s.color}88)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 600, color: "#fff", textShadow: "0 1px 2px rgba(0,0,0,0.4)", fontFamily: "-apple-system, sans-serif" }}>
                      {s.count > 0 && d.totalTimestomped > 0 && (s.count / d.totalTimestomped * 100) >= 8 ? `${s.label} ${s.count}` : ""}
                    </div>
                  ))}
                </div>
              </div>

              {/* Bulk-timestomp clusters (computed by the engine; the most report-worthy signal) (D3) */}
              {(d.clusters || []).length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.danger}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Bulk-Timestomp Clusters ({d.clusters.length})</span>
                    <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>files sharing one exact $SI Created + an aligned stomp signal</span>
                  </div>
                  <div style={{ maxHeight: 180, overflow: "auto" }}>
                    {d.clusters.map((c, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "7px 12px", borderBottom: `1px solid ${th.border}18`, fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace" }}>
                        <span style={{ fontSize: 9, padding: "1px 7px", borderRadius: 8, background: `${th.danger}22`, color: th.danger, fontWeight: 700, flexShrink: 0 }}>{c.count}</span>
                        <span style={{ color: th.danger, flexShrink: 0 }} title={c.siCreated}>{(c.siCreated || "").slice(0, 19)}</span>
                        <span style={{ color: th.textDim, flexShrink: 0 }}>{c.dominantExt || "(mixed)"}</span>
                        <div style={{ display: "flex", gap: 4, flexShrink: 0 }}>
                          {c.anyExec && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.danger}22`, color: th.danger, fontWeight: 600 }}>exec</span>}
                          {c.zeroedSubseconds && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.warning}22`, color: th.warning, fontWeight: 600 }}>zeroed</span>}
                        </div>
                        <span style={{ color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }} title={(c.directories || []).join("\n")}>{(c.directories || [])[0] || ""}{(c.directories || []).length > 1 ? `  +${c.directories.length - 1} dir` : ""}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Sysmon EID 2 stomps with no $MFT mismatch — confirmed timestomps the $MFT alone can't see
                  (full-copy $SI==$FN / double-stomp). Forgery-resistant; the headline Tier-2 capability. */}
              {(d.confirmedStompsNoMftMatch || []).length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.danger}55`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                  <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: th.danger, fontFamily: "-apple-system, sans-serif" }}>⚑ Confirmed Timestomps With No $MFT Mismatch ({d.confirmedStompsNoMftMatch.length})</span>
                    <div style={{ marginTop: 3, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>Sysmon EID 2 (FileCreateTime) fired but $SI &lt; $FN did not — a full-copy ($SI==$FN) or $FN-rewriting stomp the $MFT cannot reveal. Forgery-resistant.</div>
                  </div>
                  <div style={{ maxHeight: 180, overflow: "auto" }}>
                    {d.confirmedStompsNoMftMatch.map((s, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 12px", borderBottom: `1px solid ${th.border}18`, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>
                        <span style={{ color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }} title={s.targetFilename}>{s.targetFilename || "(unknown)"}</span>
                        <span style={{ color: th.textDim, flexShrink: 0 }} title="pre-stomp creation time">{s.preStompCreated ? `was ${String(s.preStompCreated).slice(0, 19)}` : ""}</span>
                        <span style={{ color: th.warning, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 200 }} title={`tool: ${s.image || "?"}`}>{s.image || ""}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Detailed files table */}
              <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div onClick={() => toggleAll("tsSelFiles", files.length)} style={cbStyle(selFiles.size === files.length && files.length > 0)}>
                      {selFiles.size === files.length && files.length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Potential Timestomp Indicators ({files.length.toLocaleString()}{d.totalTimestomped > files.length ? ` of ${d.totalTimestomped.toLocaleString()}` : ""})</span>
                  </div>
                </div>
                <div style={{ maxHeight: 320, overflow: "auto" }}>
                  {/* Header row */}
                  <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1, minWidth: "fit-content" }}>
                    <div style={{ width: 14, flexShrink: 0 }} />
                    {tsHdrCol(tsW[0], "Sev", "severity", 0)}
                    {tsHdrCol(tsW[1], "FileName", "fileName", 1)}
                    {tsHdrCol(tsW[2], "Ext", "extension", 2)}
                    {tsHdrCol(tsW[3], "ParentPath", "parentPath", 3)}
                    {tsHdrCol(tsW[4], "Stomped", "stompedFields", 4)}
                    {tsHdrCol(tsW[5], "SI Created (suspect)", "siCreated", 5)}
                    {tsHdrCol(tsW[6], "FN Created (OS-set)", "fnCreated", 6)}
                    {tsHdrCol(tsW[7], "Delta", "maxDeltaHours", 7)}
                    {tsHdrCol(tsW[8], "Conf", "confidence", 8)}
                  </div>
                  {sortTsArr(files).map((f, i) => (
                    <div key={i} onClick={() => toggleSet("tsSelFiles", i)} title={(f.indicators || []).join(" • ")} style={{ ...rowStyle(i), cursor: "pointer", background: f.severity === "critical" ? `${sevColors.critical}11` : i % 2 === 0 ? "transparent" : `${th.border}15`, minWidth: "fit-content" }}>
                      <div style={cbStyle(selFiles.has(i))}>
                        {selFiles.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                      </div>
                      <div style={{ width: tsW[0], height: 10, borderRadius: "50%", background: sevColors[f.severity] || sevColors.low, flexShrink: 0 }} title={sevLabels[f.severity]} />
                      <div style={{ width: tsW[1], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: f.severity === "critical" ? (th.danger) : th.text }} title={f.fileName}>{f.fileName}</div>
                      <div style={{ width: tsW[2], flexShrink: 0, color: th.textDim }} title={f.extension}>{f.extension}</div>
                      <div style={{ width: tsW[3], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }} title={f.parentPath}>{f.parentPath}</div>
                      <div style={{ width: tsW[4], flexShrink: 0, display: "flex", gap: 3, flexWrap: "wrap" }}>
                        {(f.stompedFields || []).map((sf) => (
                          <span key={"s" + sf} title={`SI ${sf} precedes FN ${sf} (backdated)`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${sevColors[f.severity]}22`, color: sevColors[f.severity], fontWeight: 600, whiteSpace: "nowrap" }}>{sf.slice(0, 3)}</span>
                        ))}
                        {(f.forwardFields || []).map((ff) => (
                          <span key={"f" + ff} title={`SI ${ff} is LATER than FN ${ff} (forward-dated)`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.accent}22`, color: th.accent, fontWeight: 600, whiteSpace: "nowrap" }}>↑{ff.slice(0, 3)}</span>
                        ))}
                        {f.futureDated && <span title="$SI dated in the future (beyond 1-day skew)" style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.danger}22`, color: th.danger, fontWeight: 700, whiteSpace: "nowrap" }}>FUT</span>}
                        {f.eid2Corroborated && <span title={`CONFIRMED by Sysmon EID 2 (FileCreateTime)${f.stompTool ? ` via ${f.stompTool}` : ""}${f.preStompCreated ? `\nPre-stomp created: ${f.preStompCreated}` : ""}`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.success}22`, color: th.success, fontWeight: 700, whiteSpace: "nowrap" }}>✓EID2</span>}
                        {f.usnContradicted && <span title={`USN FileCreate (${f.usnCreateTime || "?"}) postdates the backdated $SI Created — forgery-resistant contradiction`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.success}22`, color: th.success, fontWeight: 700, whiteSpace: "nowrap" }}>✓USN</span>}
                      </div>
                      <div style={{ width: tsW[5], flexShrink: 0, color: th.warning, fontSize: 10 }} title={f.siCreated}>{(f.siCreated || "").slice(0, 19)}</div>
                      <div style={{ width: tsW[6], flexShrink: 0, color: th.textDim, fontSize: 10 }} title={f.fnCreated}>{(f.fnCreated || "").slice(0, 19)}</div>
                      <div style={{ width: tsW[7], flexShrink: 0, fontWeight: 600, color: f.maxDeltaHours > 8760 ? sevColors.high : f.maxDeltaHours > 720 ? sevColors.medium : th.textDim }}>{fmtDelta(f.maxDeltaHours)}</div>
                      <div style={{ width: tsW[8], flexShrink: 0, fontSize: 9, fontWeight: 600, textTransform: "capitalize", color: f.confidence === "high" ? th.danger : f.confidence === "medium" ? th.warning : th.textMuted }} title={`Confidence: ${f.confidence}`}>{f.confidence || "low"}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Directories + Extension Breakdown side by side */}
              <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                {/* Top Directories */}
                <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <div onClick={() => toggleAll("tsSelDirs", (d.topDirectories || []).length)} style={cbStyle(selDirs.size === (d.topDirectories || []).length && (d.topDirectories || []).length > 0)}>
                        {selDirs.size === (d.topDirectories || []).length && (d.topDirectories || []).length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                      </div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Top Directories</span>
                    </div>
                  </div>
                  <div style={{ maxHeight: 200, overflow: "auto", padding: "4px 0" }}>
                    {(d.topDirectories || []).map((dir, i) => {
                      const maxC = (d.topDirectories || [])[0]?.count || 1;
                      return (
                        <div key={i} onClick={() => toggleSet("tsSelDirs", i)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 12px", cursor: "pointer", fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace" }}>
                          <div style={cbStyle(selDirs.has(i))}>
                            {selDirs.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                          </div>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 2 }}>
                              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, flex: 1, minWidth: 0 }} title={dir.path}>{dir.path || "(root)"}</span>
                              <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 8, background: `${th.warning}22`, color: th.warning, fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{dir.count}</span>
                            </div>
                            <div style={{ height: 4, borderRadius: 2, background: `${th.border}33`, overflow: "hidden" }}>
                              <div style={{ width: `${(dir.count / maxC) * 100}%`, height: "100%", borderRadius: 2, background: `linear-gradient(90deg, ${th.warning}88, ${th.warning}44)` }} />
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Extension Breakdown */}
                <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                  <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Extension Breakdown</span>
                  </div>
                  <div style={{ maxHeight: 200, overflow: "auto", padding: "4px 0" }}>
                    {(d.extensionBreakdown || []).map((eb, i) => {
                      const maxC = (d.extensionBreakdown || [])[0]?.count || 1;
                      const isExec = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".com",".sys",".drv"].includes((eb.extension || "").toLowerCase());
                      return (
                        <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 12px", fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace" }}>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 2 }}>
                              <span style={{ color: isExec ? (th.danger) : th.text, fontWeight: isExec ? 600 : 400 }}>{eb.extension || "(none)"}</span>
                              <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 8, background: isExec ? `${th.danger}22` : `${th.accent}22`, color: isExec ? (th.danger) : th.accent, fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{eb.count}</span>
                            </div>
                            <div style={{ height: 4, borderRadius: 2, background: `${th.border}33`, overflow: "hidden" }}>
                              <div style={{ width: `${(eb.count / maxC) * 100}%`, height: "100%", borderRadius: 2, background: isExec ? `linear-gradient(90deg, ${th.danger}88, ${th.danger}44)` : `linear-gradient(90deg, ${th.accent}88, ${th.accent}44)` }} />
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Coverage / limitations — the honesty caveat ($SI is forgeable; full-copy & $FN-side stomps are invisible here) (D5) */}
              {(d.notes || []).length > 0 && (
                <div style={{ padding: "10px 14px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10, marginBottom: 4 }}>
                  <div style={{ fontSize: 10, color: th.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Coverage &amp; Limitations</div>
                  <ul style={{ margin: 0, paddingLeft: 16, display: "flex", flexDirection: "column", gap: 3 }}>
                    {d.notes.map((n, i) => (
                      <li key={i} style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45 }}>{n}</li>
                    ))}
                  </ul>
                </div>
              )}
            </>);
          })()}
        </div>

        {/* Footer */}
        {!loading && data && !isIpcError(data) && (
          <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", gap: 10, alignItems: "center", justifyContent: "flex-end", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
            {modal.tsTagMsg && <span style={{ marginRight: "auto", fontSize: 11, color: /failed/i.test(modal.tsTagMsg) ? th.danger : th.success, fontFamily: "-apple-system, sans-serif" }}>{modal.tsTagMsg}</span>}
            {totalSelected > 0 && <button onClick={copySelected} style={{ ...ms.bs, position: "relative" }}>Copy Selected <span style={{ marginLeft: 4, fontSize: 9, padding: "1px 5px", borderRadius: 8, background: `${th.accent}33`, color: th.accent }}>{totalSelected}</span></button>}
            {data && (data.totalTimestomped > 0 || (data.confirmedStompsNoMftMatch || []).length > 0) && <button onClick={copyReport} style={ms.bs}>Copy Summary</button>}
            {data && data.totalTimestomped > 0 && <button onClick={tagIndicators} style={{ ...ms.bp, background: th.fillWarning, color: th.onAccent }}>Tag Indicators</button>}
            <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
          </div>
        )}
      </>)}
    </DraggableResizableModal>
  );
}
