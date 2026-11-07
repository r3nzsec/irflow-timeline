import { useCallback, Fragment } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { DraggableResizableModal, ErrorState } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";

export default function AdsModal() {
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

  if (!modal || modal.type !== "ads" || !ct) return null;

  const { data, loading } = modal;
  // Raw $MFT exposes only HasAds + Zone.Identifier; per-stream ADS rows (IsAds) require MFTECmd CSV.
  const isRawMft = ct?.sourceFormat === "raw-mft";

  // Tag the actual downloaded set (Zone.Identifier present), report the count, and refresh grid tags.
  // (Previously passed an unrecognized `{ filters: [...] }` shape that silently tagged EVERY row.)
  const tagDownloaded = async () => {
    const result = await tle.bulkTagFiltered(ct.id, "Downloaded", { advancedFilters: [{ column: "ZoneIdContents", operator: "is_not_empty" }] });
    if (result?.error) {
      setModal((p) => (p ? { ...p, adTagMsg: `Tag failed: ${result.error}` } : p));
      return;
    }
    try {
      const td = await tle.getAllTagData(ct.id);
      const nrt = {};
      for (const { rowid, tag } of td) { if (!nrt[rowid]) nrt[rowid] = []; nrt[rowid].push(tag); }
      up("rowTags", nrt);
      up("tagColors", { ...(ct.tagColors || {}), Downloaded: th.danger });
    } catch { /* tag refresh is best-effort */ }
    const n = result?.tagged || 0;
    setModal((p) => (p ? { ...p, adTagMsg: `Tagged ${n.toLocaleString()} downloaded file${n === 1 ? "" : "s"} as "Downloaded"` } : p));
    setTimeout(() => setModal((p) => (p ? { ...p, adTagMsg: null } : p)), 4000);
  };

  const zoneColors = { Internet: th.danger, Intranet: "#6cb6ff", Trusted: th.success, Local: th.textDim, Restricted: th.warning };

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
      "=== ADS Analyzer Report ===",
      ...(v && v.severity && v.severity !== "info" ? [
        `Verdict: ${v.severity.toUpperCase()} (confidence: ${v.confidence}, score ${v.severityScore}/100)`,
        v.headline, "", v.narrative, "",
        ...((v.mitre || []).length ? ["MITRE candidates:", ...v.mitre.map((m) => `  - ${m.technique} ${m.name} [${m.confidence}] — ${m.evidence}`), ""] : []),
        ...((v.coverage || []).length ? ["Coverage:", ...v.coverage.map((c) => `  [${c.status}] ${c.label}: ${c.detail}`), ""] : []),
      ] : []),
      `Files with ADS: ${(d.totalWithAds || 0).toLocaleString()}`,
      `ADS Entries: ${(d.totalAdsEntries || 0).toLocaleString()}`,
      `Downloaded Files (Zone.Identifier): ${(d.totalWithZoneId || 0).toLocaleString()}`, "",
      ...(d.summary?.narrative ? [`Summary: ${d.summary.narrative}`, ""] : []),
      "Zone Breakdown:",
      `  Internet: ${d.zoneBreakdown?.internet || 0}`,
      `  Intranet: ${d.zoneBreakdown?.intranet || 0}`,
      `  Trusted: ${d.zoneBreakdown?.trusted || 0}`,
      `  Local: ${d.zoneBreakdown?.local || 0}`,
      `  Restricted: ${d.zoneBreakdown?.restricted || 0}`,
      `  Unknown: ${d.zoneBreakdown?.unknown || 0}`,
      ...((d.zoneNoUrlCount || 0) > 0 ? [`  (${d.zoneNoUrlCount} have no recorded source URL)`] : []),
      "",
    ];
    // T6: forgery-resistant corroboration + $SI-reliability coverage.
    {
      const corr = d.correlation || {}; const sr = d.siReliability || {};
      if (corr.usnAvailable || corr.evtxAvailable) {
        lines.push("Cross-Artifact Corroboration (forgery-resistant):");
        if (corr.usnAvailable) lines.push(`  USN ($J): ${(corr.usnNamedStreamTotal || 0).toLocaleString()} named-stream/StreamChange write(s)${corr.carriersUsnCorroborated ? `, ${corr.carriersUsnCorroborated} carrier(s) corroborated` : ""}`);
        if (corr.evtxAvailable) lines.push(`  EVTX: ${(corr.evtxStreamCreateTotal || 0).toLocaleString()} Sysmon EID 15 (FileCreateStreamHash)${corr.carriersEvtxCorroborated ? `, ${corr.carriersEvtxCorroborated} corroborated` : ""}`);
        if (corr.motwCorroborated) lines.push(`  ${corr.motwCorroborated} MOTW-strip(s) corroborated by USN`);
        lines.push("");
      } else {
        lines.push("Cross-Artifact Corroboration: none — single-source $MFT (load a USN $J or EVTX companion tab to corroborate).", "");
      }
      if ((sr.suspectStreamCarriers || 0) > 0) lines.push(`$SI reliability: ${sr.suspectStreamCarriers.toLocaleString()} of ${(sr.totalStreamCarriers || 0).toLocaleString()} stream carrier(s) have timestomped-looking $SI ($SI<$FN or sub-second-zeroed) — corroborate timing with USN/EVTX.`, "");
    }
    if ((d.streamCarriers || []).length > 0) {
      lines.push(`Files with a Non-Zone Named Stream (${(d.totalStreamCarriers || d.streamCarriers.length).toLocaleString()}${(d.totalAdsExecStreams || 0) > 0 ? `, ${d.totalAdsExecStreams} executable/script` : ""}):`);
      d.streamCarriers.slice(0, 20).forEach((f) => {
        const streams = (f.streams || []).map((s) => `${s.execContent ? "⚑" : ""}:${s.name}${s.size != null ? `(${s.size})` : ""}${s.execLike ? " [exec]" : s.large ? " [large]" : s.benign ? " [benign]" : ""}`).join(" ");
        const corrMark = [f.usnCorroboration ? `[USN ${f.usnCorroboration.namedStreamOps}]` : "", f.evtxCorroboration ? `[EID15 ${f.evtxCorroboration.streamCreates}]` : "", f.siSuspect ? "[$SI-suspect]" : ""].filter(Boolean).join(" ");
        lines.push(`  ${f.fileName}${streams ? "  " + streams : ""} — ${f.parentPath} — ${(f.created || "").slice(0, 19)}${corrMark ? "  " + corrMark : ""}`);
      });
      lines.push("");
    }
    if ((d.internalHosts || []).length > 0) {
      lines.push("Internal / Private Source Hosts:");
      d.internalHosts.slice(0, 10).forEach((h) => lines.push(`  ${h.host} (${h.count}) [${h.transferSource || "unknown"}]`));
      lines.push("");
    }
    if ((d.archiveLineage || []).length > 0) {
      lines.push("Archive Lineage:");
      d.archiveLineage.slice(0, 10).forEach((a) => lines.push(`  ${a.archiveName} -> ${a.childCount} child files (${a.motwLossCount} MOTW-loss)`));
      lines.push("");
    }
    if ((d.motwSuspicious || []).length > 0) {
      lines.push("Likely MOTW Loss:");
      d.motwSuspicious.slice(0, 15).forEach((m) => lines.push(`  ${m.archiveName} -> ${m.childName} (${m.reason})${m.usnStripCorroborated ? `  [USN-corroborated strip ${m.usnStripOps}]` : ""}`));
      lines.push("");
    }
    if ((d.downloadedExecutables || []).length > 0) {
      lines.push("Downloaded Executables:");
      d.downloadedExecutables.forEach((f) => lines.push(`  ${f.fileName} \u2014 ${f.parentPath} \u2014 ${f.zoneName} \u2014 ${f.referrerUrl || "(no referrer)"}`));
      lines.push("");
    }
    if ((d.referrerUrls || []).length > 0) {
      lines.push("Top Referrer URLs:");
      d.referrerUrls.slice(0, 15).forEach((u) => lines.push(`  ${u.url} (${u.count})`));
      lines.push("");
    }
    if ((d.hostUrls || []).length > 0) {
      lines.push("Top Download Hosts (by host):");
      d.hostUrls.slice(0, 15).forEach((u) => lines.push(`  ${u.url} (${u.count})`));
    }
    navigator.clipboard?.writeText(lines.join("\n"));
  };

  const copySelected = () => {
    const selExec = modal.adSelExec || new Set();
    const selZone = modal.adSelZone || new Set();
    const selAds = modal.adSelAds || new Set();
    const lines = [];
    if (selExec.size > 0 && data?.downloadedExecutables) {
      lines.push("=== Downloaded Executables ===");
      lines.push("FileName\tExtension\tParentPath\tCreated\tZone\tReferrerUrl");
      data.downloadedExecutables.forEach((f, i) => { if (selExec.has(i)) lines.push(`${f.fileName}\t${f.extension}\t${f.parentPath}\t${(f.created || "").slice(0, 19)}\t${f.zoneName}\t${f.referrerUrl || ""}`); });
      lines.push("");
    }
    if (selZone.size > 0 && data?.zoneIdFiles) {
      lines.push("=== Zone.Identifier Files ===");
      lines.push("FileName\tExtension\tParentPath\tCreated\tZone\tReferrerUrl");
      data.zoneIdFiles.forEach((f, i) => { if (selZone.has(i)) lines.push(`${f.fileName}\t${f.extension}\t${f.parentPath}\t${(f.created || "").slice(0, 19)}\t${f.zoneName}\t${f.referrerUrl || ""}`); });
      lines.push("");
    }
    if (selAds.size > 0 && data?.adsEntries) {
      lines.push("=== ADS Entries ===");
      lines.push("FileName\tParentPath\tCreated\tFileSize");
      data.adsEntries.forEach((f, i) => { if (selAds.has(i)) lines.push(`${f.fileName}\t${f.parentPath}\t${(f.created || "").slice(0, 19)}\t${f.fileSize || ""}`); });
    }
    if (lines.length > 0) navigator.clipboard?.writeText(lines.join("\n"));
  };

  const totalSelected = ((modal.adSelExec || new Set()).size + (modal.adSelZone || new Set()).size + (modal.adSelAds || new Set()).size);

  // Resizable column helpers
  const defExecW = [180, 50, 200, 140, 60, 220];
  const defZoneW = [180, 50, 200, 140, 60, 180];
  const defAdsW = [250, 280, 140, 80];
  const execW = modal.adExecColW || defExecW;
  const zoneW = modal.adZoneColW || defZoneW;
  const adsW = modal.adAdsColW || defAdsW;
  const startColResize = (stateKey, defaults, colIdx, e) => {
    e.preventDefault(); e.stopPropagation();
    const startX = e.clientX, startW = (modal[stateKey] || defaults)[colIdx];
    const onMove = (ev) => setModal((p) => { if (!p) return p; const w = [...(p[stateKey] || defaults)]; w[colIdx] = Math.max(30, startW + (ev.clientX - startX)); return { ...p, [stateKey]: w }; });
    const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
  };
  const resH = { position: "absolute", right: -2, top: 0, bottom: 0, width: 5, cursor: "col-resize", zIndex: 3 };

  // Sort helpers
  const handleAdSort = (stateKey, colKey) => setModal((p) => {
    if (!p) return p;
    const cur = p[stateKey];
    const newDir = cur?.col === colKey && cur.dir === "asc" ? "desc" : "asc";
    return { ...p, [stateKey]: { col: colKey, dir: newDir } };
  });
  const sortAdArr = (arr, sortState) => {
    if (!sortState || !arr) return arr;
    return [...arr].sort((a, b) => {
      const va = (a[sortState.col] || "").toString().toLowerCase();
      const vb = (b[sortState.col] || "").toString().toLowerCase();
      return sortState.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
    });
  };
  const sortArrowAd = (stateKey, colKey) => {
    const s = modal[stateKey]; const active = s?.col === colKey; const dir = active ? s.dir : null;
    return (
      <svg width="10" height="14" viewBox="0 0 10 14" style={{ marginLeft: 4, flexShrink: 0, opacity: active ? 1 : 0.7, transition: "opacity var(--m-base)" }}>
        <path d="M5 1L9 5.5H1Z" fill={dir === "asc" ? (th.accent) : "#b0a8a0"} opacity={dir === "asc" ? 1 : 0.8} />
        <path d="M5 13L1 8.5H9Z" fill={dir === "desc" ? (th.accent) : "#b0a8a0"} opacity={dir === "desc" ? 1 : 0.8} />
      </svg>
    );
  };
  const adHdrCol = (w, label, stateKey, colKey, resizeKey, defWArr, colIdx) => (
    <div style={{ width: w, flexShrink: 0, position: "relative", cursor: "pointer", display: "flex", alignItems: "center", userSelect: "none" }} onClick={() => handleAdSort(stateKey, colKey)}>
      {label}{sortArrowAd(stateKey, colKey)}
      <div onMouseDown={(e) => { e.stopPropagation(); startColResize(resizeKey, defWArr, colIdx, e); }} style={resH} />
    </div>
  );

  const pill = (text, color = th.accent, bg = `${th.accent}22`) => (
    <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 999, background: bg, color, fontWeight: 700, letterSpacing: "0.01em", fontFamily: "-apple-system, sans-serif" }}>{text}</span>
  );

  return (
    <DraggableResizableModal defaultWidth={960} minWidth={420} minHeight={280} onClose={() => setModal(null)}>
      {({ startDrag }) => (<>
        {/* Header */}
        <div onMouseDown={startDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, border: `1px solid ${th.accent}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round"><rect x="4" y="4" width="16" height="16" rx="2" fill={th.accent + "18"}/><path d="M8 8h8"/><path d="M8 12h8" opacity="0.6"/><path d="M8 16h5" opacity="0.3"/></svg>
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>ADS Analyzer</h3>
              <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>Alternate Data Streams, Zone.Identifier, and download forensics</p>
            </div>
          </div>
          <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, fontSize: 18, cursor: "pointer", padding: "4px 8px", lineHeight: 1 }}>{"\u2715"}</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
          {loading && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
              <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <div style={{ width: 20, height: 20, border: `2px solid ${th.accent}`, borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
              </div>
              <span style={{ color: th.textDim, fontSize: 13, fontFamily: "-apple-system, sans-serif" }}>Analyzing Alternate Data Streams...</span>
            </div>
          )}

          {!loading && modal.error && (
            <ErrorState message={modal.error} />
          )}

          {!loading && !modal.error && data && isIpcError(data) && (
            <div style={{ textAlign: "center", padding: 40, color: th.danger, fontSize: 13 }}>{ipcErrorMessage(data)}</div>
          )}

          {!loading && !modal.error && data && !isIpcError(data) && data.totalWithAds === 0 && data.totalAdsEntries === 0 && data.totalWithZoneId === 0 && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 12 }}>
              <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${th.textDim}33, ${th.textDim}11)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6M9 12h4"/></svg>
              </div>
              <span style={{ color: th.textDim, fontSize: 13, fontFamily: "-apple-system, sans-serif" }}>No Alternate Data Streams found</span>
            </div>
          )}

          {!loading && data && !isIpcError(data) && (data.totalWithAds > 0 || data.totalAdsEntries > 0 || data.totalWithZoneId > 0) && (() => {
            const d = data;
            const selExec = modal.adSelExec || new Set();
            const selZone = modal.adSelZone || new Set();
            const selAds = modal.adSelAds || new Set();

            const zb = d.zoneBreakdown || {};
            const totalZoned = (zb.internet || 0) + (zb.intranet || 0) + (zb.trusted || 0) + (zb.local || 0) + (zb.restricted || 0) + (zb.unknown || 0);
            // zoneBreakdown is now exact (full population); the detail-derived panels (prioritized,
            // hosts, clusters, lineage) are a most-recent sample when the population exceeds the cap.
            const zoneSampled = (d.totalWithZoneId || 0) > (d.zoneIdFiles?.length || 0);
            const zoneSampleNote = zoneSampled ? `most recent ${(d.zoneIdFiles?.length || 0).toLocaleString()} of ${(d.totalWithZoneId || 0).toLocaleString()}` : "";

            return (<>
              {/* Raw $MFT capability note: non-Zone stream NAMES/sizes are recovered (T5); full content
                  for non-resident streams still requires MFTECmd CSV / extraction. */}
              {isRawMft && (
                <div style={{ display: "flex", gap: 8, alignItems: "flex-start", padding: "9px 12px", marginBottom: 14, borderRadius: 8, background: `${th.warning}12`, border: `1px solid ${th.warning}33` }}>
                  <span style={{ fontSize: 13, lineHeight: 1.3, color: th.warning, flexShrink: 0 }}>{"ⓘ"}</span>
                  <span style={{ fontSize: 11, lineHeight: 1.45, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>
                    Raw <strong style={{ color: th.text }}>$MFT</strong>: non-Zone alternate-stream <strong style={{ color: th.text }}>names &amp; sizes are recovered</strong> (the <span style={{ fontFamily: "'SF Mono',Menlo,monospace" }}>file.txt:evil.exe</span> case, T1564.004), and resident <strong style={{ color: th.text }}>PE/MZ</strong> content is flagged — see "Files Carrying a Non-Zone Named Stream" below.{(d.totalAdsExecStreams || 0) > 0 ? <> <strong style={{ color: th.danger }}>{d.totalAdsExecStreams.toLocaleString()} look executable/script.</strong></> : null} Full content for <em>non-resident</em> streams (&gt;~700 B) still requires MFTECmd CSV / extraction; corroborate timing with USN StreamChange.
                  </span>
                </div>
              )}

              {/* Summary cards */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 16 }}>
                <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: th.accent, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Files with ADS</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{(d.totalWithAds || 0).toLocaleString()}</div>
                </div>
                {isRawMft ? (
                  <div title="Files carrying a named alternate data stream that is not (only) Zone.Identifier — candidate hidden streams (T1564.004). Stream names + sizes are recovered from $MFT; resident PE/MZ content is flagged." style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${(d.totalStreamCarriers || 0) > 0 ? th.warning : th.border}33`, borderRadius: 10, cursor: "help" }}>
                    <div style={{ fontSize: 10, color: (d.totalStreamCarriers || 0) > 0 ? th.warning : th.accent, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Non-Zone Streams</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{(d.totalStreamCarriers || 0).toLocaleString()}</div>
                    <div style={{ fontSize: 10, color: (d.totalAdsExecStreams || 0) > 0 ? th.danger : th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif" }}>{(d.totalAdsExecStreams || 0) > 0 ? `${d.totalAdsExecStreams.toLocaleString()} executable/script` : `named stream ≠ Zone.Identifier`}</div>
                  </div>
                ) : (
                  <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                    <div style={{ fontSize: 10, color: th.accent, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>ADS Entries</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{(d.totalAdsEntries || 0).toLocaleString()}</div>
                  </div>
                )}
                <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${(d.totalWithZoneId || 0) > 0 ? (th.danger) : th.border}33`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: (d.totalWithZoneId || 0) > 0 ? (th.danger) : th.accent, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Downloaded Files</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{(d.totalWithZoneId || 0).toLocaleString()}</div>
                  <div style={{ fontSize: 10, color: th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif" }}>Zone.Identifier present</div>
                </div>
              </div>

              {/* T7: incident verdict — severity reflects impact; confidence is gated on forgery-resistant
                  USN/EVTX corroboration so a single-source-$MFT (or $SI-timestomped) finding is never
                  presented as authoritative. */}
              {d.verdict && d.verdict.severity && d.verdict.severity !== "info" && (() => {
                const v = d.verdict;
                const sevColor = (v.severity === "critical" || v.severity === "high") ? th.danger : v.severity === "medium" ? th.warning : v.severity === "low" ? th.accent : th.textMuted;
                const confColor = v.confidence === "corroborated" ? (th.success || "#3fb950") : v.confidence === "weak" ? th.warning : th.textMuted;
                const covColor = (s) => s === "ok" ? (th.success || "#3fb950") : s === "partial" ? th.warning : th.textMuted;
                return (
                  <div style={{ marginBottom: 16, padding: "12px 14px", borderRadius: 10, background: `${sevColor}10`, border: `1px solid ${sevColor}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                      <span style={{ padding: "2px 9px", borderRadius: 999, fontSize: 10, fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.06em", color: sevColor, background: `${sevColor}1e`, border: `1px solid ${sevColor}55` }}>{v.severity}</span>
                      <span title="How far the conclusion can be trusted — 'corroborated' requires forgery-resistant USN ($J) named-stream writes or Sysmon EID 15 backing the flagged stream(s)." style={{ padding: "2px 9px", borderRadius: 999, fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: confColor, background: `${confColor}18`, border: `1px solid ${confColor}44`, cursor: "help" }}>confidence: {v.confidence}</span>
                      <span title="A stream's EXISTENCE is structural ($MFT); its TIMING rests on $SI (user-settable). Stream content for non-resident streams is not in $MFT — extract with MFTECmd to hash." style={{ padding: "2px 9px", borderRadius: 999, fontSize: 9, fontWeight: 600, letterSpacing: "0.03em", color: th.textMuted, background: `${th.border}22`, border: `1px solid ${th.border}33`, cursor: "help" }}>$MFT-derived</span>
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

              {d.summary?.narrative && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.accent}33`, borderRadius: 10, padding: "14px 16px", marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 6 }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Download Forensics Summary</span>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                      {d.summary.execCount > 0 && pill(`${d.summary.execCount} exec/script`, th.danger, `${th.danger}22`)}
                      {d.summary.archiveCount > 0 && pill(`${d.summary.archiveCount} archive`, th.warning, `${th.warning}22`)}
                      {d.summary.motwLossCount > 0 && pill(`${d.summary.motwLossCount} MOTW loss`, th.danger, `${th.danger}22`)}
                      {d.summary.internalHostCount > 0 && pill(`${d.summary.internalHostCount} internal host`, "#6cb6ff", "#6cb6ff22")}
                    </div>
                  </div>
                  <div style={{ fontSize: 12, color: th.text, lineHeight: 1.5, fontFamily: "-apple-system, sans-serif" }}>{d.summary.narrative}</div>
                </div>
              )}

              {(d.prioritizedDownloads || []).length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.warning}33`, borderRadius: 10, padding: "12px 14px", marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Prioritized Downloads</span>
                    <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>ranked by extension, location, source, and MOTW context{zoneSampleNote ? ` • ${zoneSampleNote}` : ""}</span>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {d.prioritizedDownloads.slice(0, 8).map((f, i) => (
                      <div key={i} style={{ padding: "8px 10px", borderRadius: 8, border: `1px solid ${th.border}22`, background: `${th.modalBg}55` }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div style={{ fontSize: 12, fontWeight: 700, color: f.riskScore >= 4 ? (th.danger) : th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'SF Mono',Menlo,monospace" }} title={f.fileName}>{f.fileName}</div>
                            <div style={{ marginTop: 3, fontSize: 10, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'SF Mono',Menlo,monospace" }} title={f.parentPath}>{f.parentPath}</div>
                          </div>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                            {pill(`risk ${f.riskScore}`, f.riskScore >= 4 ? (th.danger) : (th.warning), f.riskScore >= 4 ? `${th.danger}22` : `${th.warning}22`)}
                            {f.zoneName && pill(f.zoneName, zoneColors[f.zoneName] || th.textDim, `${zoneColors[f.zoneName] || th.textDim}22`)}
                            {f.transferSource && pill(f.transferSource, f.internalHost ? "#6cb6ff" : th.accent, f.internalHost ? "#6cb6ff22" : `${th.accent}22`)}
                          </div>
                        </div>
                        {(f.riskReasons || []).length > 0 && (
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
                            {f.riskReasons.slice(0, 4).map((r, idx) => <Fragment key={idx}>{pill(r, th.text, `${th.border}33`)}</Fragment>)}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Zone Breakdown */}
              {totalZoned > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Zone Distribution <span style={{ fontSize: 9, fontWeight: 500, color: th.textMuted }}>(all {(d.totalWithZoneId || 0).toLocaleString()} downloads)</span></span>
                    {(d.zoneNoUrlCount || 0) > 0 && <span title="Zone.Identifier present but no HostUrl/ReferrerUrl recorded (URL-less MOTW, or a Zone blob dropped at the parser size cap)." style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>{d.zoneNoUrlCount.toLocaleString()} with no source URL</span>}
                  </div>
                  <div style={{ display: "flex", height: 22, borderRadius: 6, overflow: "hidden", border: `1px solid ${th.border}33`, marginBottom: 10 }}>
                    {[
                      { label: "Internet", count: zb.internet || 0, color: zoneColors.Internet },
                      { label: "Intranet", count: zb.intranet || 0, color: zoneColors.Intranet },
                      { label: "Trusted", count: zb.trusted || 0, color: zoneColors.Trusted },
                      { label: "Local", count: zb.local || 0, color: zoneColors.Local },
                      { label: "Restricted", count: zb.restricted || 0, color: zoneColors.Restricted },
                      { label: "Unknown", count: zb.unknown || 0, color: th.textMuted },
                    ].filter((z) => z.count > 0).map((z, i) => (
                      <div key={i} title={`${z.label}: ${z.count}`} style={{ flex: z.count, background: `linear-gradient(180deg, ${z.color}cc, ${z.color}88)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 600, color: "#fff", textShadow: "0 1px 2px rgba(0,0,0,0.4)", fontFamily: "-apple-system, sans-serif" }}>
                        {(z.count / totalZoned * 100) >= 10 ? `${z.label} ${z.count}` : ""}
                      </div>
                    ))}
                  </div>
                  <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                    {[
                      { label: "Internet", count: zb.internet || 0, color: zoneColors.Internet },
                      { label: "Intranet", count: zb.intranet || 0, color: zoneColors.Intranet },
                      { label: "Trusted", count: zb.trusted || 0, color: zoneColors.Trusted },
                      { label: "Local", count: zb.local || 0, color: zoneColors.Local },
                      { label: "Restricted", count: zb.restricted || 0, color: zoneColors.Restricted },
                      { label: "Unknown", count: zb.unknown || 0, color: th.textMuted },
                    ].map((z, i) => (
                      <span key={i} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>
                        <div style={{ width: 8, height: 8, borderRadius: 2, background: z.color }} />
                        {z.label}: {z.count.toLocaleString()} ({totalZoned > 0 ? ((z.count / totalZoned) * 100).toFixed(1) : 0}%)
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Downloaded Executables */}
              {(d.downloadedExecutables || []).length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.danger}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <div onClick={() => toggleAll("adSelExec", d.downloadedExecutables.length)} style={cbStyle(selExec.size === d.downloadedExecutables.length && d.downloadedExecutables.length > 0)}>
                        {selExec.size === d.downloadedExecutables.length && d.downloadedExecutables.length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                      </div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: th.danger, fontFamily: "-apple-system, sans-serif" }}>Downloaded Executables ({d.downloadedExecutables.length})</span>
                    </div>
                  </div>
                  <div style={{ maxHeight: 220, overflow: "auto" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1, minWidth: "fit-content" }}>
                      <div style={{ width: 14, flexShrink: 0 }} />
                      {adHdrCol(execW[0], "FileName", "adSortExec", "fileName", "adExecColW", defExecW, 0)}
                      {adHdrCol(execW[1], "Ext", "adSortExec", "extension", "adExecColW", defExecW, 1)}
                      {adHdrCol(execW[2], "ParentPath", "adSortExec", "parentPath", "adExecColW", defExecW, 2)}
                      {adHdrCol(execW[3], "Created", "adSortExec", "created", "adExecColW", defExecW, 3)}
                      {adHdrCol(execW[4], "Zone", "adSortExec", "zoneName", "adExecColW", defExecW, 4)}
                      {adHdrCol(execW[5], "ReferrerUrl", "adSortExec", "referrerUrl", "adExecColW", defExecW, 5)}
                    </div>
                    {sortAdArr(d.downloadedExecutables, modal.adSortExec).map((f, i) => (
                      <div key={i} onClick={() => toggleSet("adSelExec", i)} style={{ ...rowStyle(i), cursor: "pointer", background: f.zone === 3 ? `${(th.danger)}0c` : i % 2 === 0 ? "transparent" : `${th.border}15`, minWidth: "fit-content" }}>
                        <div style={cbStyle(selExec.has(i))}>
                          {selExec.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                        </div>
                        <div style={{ width: execW[0], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.danger, fontWeight: 600 }} title={f.fileName}>{f.fileName}</div>
                        <div style={{ width: execW[1], flexShrink: 0, color: th.textDim }}>{f.extension}</div>
                        <div style={{ width: execW[2], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }} title={f.parentPath}>{f.parentPath}</div>
                        <div style={{ width: execW[3], flexShrink: 0, fontSize: 10, color: th.text }}>{(f.created || "").slice(0, 19)}</div>
                        <div style={{ width: execW[4], flexShrink: 0 }}>
                          <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 4, background: `${zoneColors[f.zoneName] || th.textDim}22`, color: zoneColors[f.zoneName] || th.textDim, fontWeight: 600 }}>{f.zoneName || "?"}</span>
                        </div>
                        <div style={{ width: execW[5], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim, fontSize: 10 }} title={f.referrerUrl}>{f.referrerUrl || ""}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Top Download Dirs + Referrer/Host URLs side by side */}
              <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                {(d.topDownloadDirs || []).length > 0 && (
                  <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                    <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                      <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Top Download Directories</span>
                    </div>
                    <div style={{ maxHeight: 200, overflow: "auto", padding: "4px 0" }}>
                      {d.topDownloadDirs.map((dir, i) => {
                        const maxC = d.topDownloadDirs[0]?.count || 1;
                        return (
                          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 12px", fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace" }}>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 2 }}>
                                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, flex: 1, minWidth: 0 }} title={dir.path}>{dir.path || "(root)"}</span>
                                <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 8, background: `${th.accent}22`, color: th.accent, fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{dir.count}</span>
                              </div>
                              <div style={{ height: 4, borderRadius: 2, background: `${th.border}33`, overflow: "hidden" }}>
                                <div style={{ width: `${(dir.count / maxC) * 100}%`, height: "100%", borderRadius: 2, background: `linear-gradient(90deg, ${th.accent}88, ${th.accent}44)` }} />
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
                {((d.referrerUrls || []).length > 0 || (d.hostUrls || []).length > 0) && (
                  <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                    <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                      <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>URLs from Zone.Identifier{zoneSampleNote ? <span style={{ fontSize: 9, fontWeight: 500, color: th.textMuted }}> ({zoneSampleNote})</span> : null}</span>
                    </div>
                    <div style={{ maxHeight: 200, overflow: "auto", padding: "8px 12px" }}>
                      {(d.referrerUrls || []).length > 0 && (<>
                        <div style={{ fontSize: 9, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4, fontFamily: "-apple-system, sans-serif" }}>Referrer URLs</div>
                        {d.referrerUrls.slice(0, 10).map((u, i) => (
                          <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "2px 0", fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>
                            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, flex: 1, minWidth: 0 }} title={u.url}>{u.url}</span>
                            <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 8, background: `${th.accent}22`, color: th.accent, fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{u.count}</span>
                          </div>
                        ))}
                      </>)}
                      {(d.hostUrls || []).length > 0 && (<>
                        <div title="Folded onto the delivery host (the IOC): all downloads from the same HostUrl host are counted together." style={{ fontSize: 9, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginTop: 10, marginBottom: 4, fontFamily: "-apple-system, sans-serif", cursor: "help" }}>Download Hosts</div>
                        {d.hostUrls.slice(0, 10).map((u, i) => (
                          <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "2px 0", fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>
                            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, flex: 1, minWidth: 0 }} title={u.url}>{u.url}</span>
                            <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 8, background: `${th.accent}22`, color: th.accent, fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{u.count}</span>
                          </div>
                        ))}
                      </>)}
                    </div>
                  </div>
                )}
              </div>

              {((d.internalHosts || []).length > 0 || (d.sourceClusters || []).length > 0) && (
                <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                  {(d.internalHosts || []).length > 0 && (
                    <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid #6cb6ff33`, borderRadius: 10, overflow: "hidden" }}>
                      <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: "#6cb6ff", fontFamily: "-apple-system, sans-serif" }}>Internal / Private Source Hosts</span>
                      </div>
                      <div style={{ maxHeight: 190, overflow: "auto", padding: "8px 12px" }}>
                        {d.internalHosts.slice(0, 10).map((h, i) => (
                          <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, padding: "4px 0", fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>
                            <span style={{ color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={h.host}>{h.host}</span>
                            <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                              {pill(h.transferSource || "network", "#6cb6ff", "#6cb6ff22")}
                              {pill(String(h.count), th.text, `${th.border}33`)}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {(d.sourceClusters || []).length > 0 && (
                    <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                      <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Source Clusters{zoneSampleNote ? <span style={{ fontSize: 9, fontWeight: 500, color: th.textMuted }}> ({zoneSampleNote})</span> : null}</span>
                      </div>
                      <div style={{ maxHeight: 190, overflow: "auto", padding: "8px 12px" }}>
                        {d.sourceClusters.slice(0, 8).map((c, i) => (
                          <div key={i} style={{ padding: "6px 0", borderBottom: i === d.sourceClusters.slice(0, 8).length - 1 ? "none" : `1px solid ${th.border}15` }}>
                            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                              <span style={{ color: th.text, fontSize: 10, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'SF Mono',Menlo,monospace" }} title={c.host}>{c.host}</span>
                              <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                                {pill(c.transferSource || "network", c.internal ? "#6cb6ff" : th.accent, c.internal ? "#6cb6ff22" : `${th.accent}22`)}
                                {pill(`${c.count}`, th.text, `${th.border}33`)}
                              </div>
                            </div>
                            {(c.sampleFiles || []).length > 0 && <div style={{ marginTop: 4, fontSize: 9, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'SF Mono',Menlo,monospace" }} title={c.sampleFiles.join(", ")}>{c.sampleFiles.join(", ")}</div>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {((d.archiveLineage || []).length > 0 || (d.motwSuspicious || []).length > 0) && (
                <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                  {(d.archiveLineage || []).length > 0 && (
                    <div style={{ flex: 1.2, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.warning}33`, borderRadius: 10, overflow: "hidden" }}>
                      <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Archive / Extraction Lineage</span>
                      </div>
                      <div style={{ maxHeight: 240, overflow: "auto", padding: "8px 12px" }}>
                        {d.archiveLineage.slice(0, 8).map((a, i) => (
                          <div key={i} style={{ padding: "8px 0", borderBottom: i === d.archiveLineage.slice(0, 8).length - 1 ? "none" : `1px solid ${th.border}15` }}>
                            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                              <span style={{ color: th.text, fontSize: 10, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'SF Mono',Menlo,monospace" }} title={a.archiveName}>{a.archiveName}</span>
                              <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                                {pill(`${a.childCount} child`, th.text, `${th.border}33`)}
                                {a.motwLossCount > 0 && pill(`${a.motwLossCount} MOTW loss`, th.danger, `${th.danger}22`)}
                              </div>
                            </div>
                            <div style={{ marginTop: 4, fontSize: 9, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'SF Mono',Menlo,monospace" }} title={a.archivePath}>{a.archivePath}</div>
                            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
                              {a.children.slice(0, 5).map((c, idx) => <Fragment key={idx}>{pill(c.fileName, c.hasZoneId ? th.textDim : (th.warning), c.hasZoneId ? `${th.border}22` : `${th.warning}22`)}</Fragment>)}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {(d.motwSuspicious || []).length > 0 && (
                    <div style={{ flex: 0.8, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.danger}33`, borderRadius: 10, overflow: "hidden" }}>
                      <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: th.danger, fontFamily: "-apple-system, sans-serif" }}>Possible MOTW Loss / Tamper</span>
                      </div>
                      <div style={{ maxHeight: 240, overflow: "auto", padding: "8px 12px" }}>
                        {d.motwSuspicious.slice(0, 10).map((m, i) => (
                          <div key={i} style={{ padding: "7px 0", borderBottom: i === d.motwSuspicious.slice(0, 10).length - 1 ? "none" : `1px solid ${th.border}15` }}>
                            <div style={{ color: th.text, fontSize: 10, fontWeight: 700, fontFamily: "'SF Mono',Menlo,monospace" }}>{m.childName}</div>
                            <div style={{ marginTop: 3, color: th.textMuted, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace" }}>{m.archiveName}</div>
                            <div style={{ marginTop: 4, fontSize: 9, color: th.warning, fontFamily: "-apple-system, sans-serif" }}>{m.reason}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {(d.adsAnomalies || []).length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.warning}33`, borderRadius: 10, padding: "12px 14px", marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Non-Zone ADS Anomalies</span>
                    {pill(`${d.adsAnomalies.length}`, th.warning, `${th.warning}22`)}
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {d.adsAnomalies.slice(0, 8).map((a, i) => <Fragment key={i}>{pill(a.streamName || a.fileName, a.execLike ? (th.danger) : (th.warning), a.execLike ? `${th.danger}22` : `${th.warning}22`)}</Fragment>)}
                  </div>
                </div>
              )}

              {/* Non-Zone stream carriers — candidate hidden ADS (the knowable surface on raw $MFT) */}
              {(d.streamCarriers || []).length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.warning}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                  <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Files Carrying a Non-Zone Named Stream ({d.streamCarriers.length.toLocaleString()}{d.totalStreamCarriers > d.streamCarriers.length ? ` of ${d.totalStreamCarriers.toLocaleString()}` : ""})</span>
                    <div style={{ marginTop: 3, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>HasAds set with no Zone.Identifier — a candidate hidden stream (e.g. <span style={{ fontFamily: "'SF Mono',Menlo,monospace" }}>invoice.pdf:payload.exe</span>).{isRawMft ? " Stream name(s) + size are recovered from $MFT (resident PE/MZ flagged ⚑); full content for non-resident streams needs MFTECmd CSV / extraction." : ""}</div>
                    {/* T6: forgery-resistant corroboration coverage. $SI (the timing axis here) is user-settable. */}
                    {(() => {
                      const c = d.correlation || {}; const sr = d.siReliability || {};
                      const haveCompanion = c.usnAvailable || c.evtxAvailable;
                      const bits = [];
                      if (c.usnAvailable) bits.push(`USN ($J): ${(c.usnNamedStreamTotal || 0).toLocaleString()} named-stream write(s)${c.carriersUsnCorroborated ? ` · ${c.carriersUsnCorroborated} carrier(s) corroborated` : ""}`);
                      if (c.evtxAvailable) bits.push(`EVTX: ${(c.evtxStreamCreateTotal || 0).toLocaleString()} Sysmon EID 15${c.carriersEvtxCorroborated ? ` · ${c.carriersEvtxCorroborated} corroborated` : ""}`);
                      if (c.motwCorroborated) bits.push(`${c.motwCorroborated} MOTW-strip corroborated`);
                      // Honest coverage: how many displayed carriers were actually corroboration-checked,
                      // and whether the EID 15 scan hit its cap.
                      if (haveCompanion && c.carriersChecked > 0 && c.carriersChecked < (d.totalStreamCarriers || (d.streamCarriers || []).length)) bits.push(`checked the ${c.carriersChecked.toLocaleString()} shown of ${(d.totalStreamCarriers || 0).toLocaleString()} carriers`);
                      if (c.evtxCapped) bits.push(`EID 15 scan capped at ${(c.evtxScanned || 0).toLocaleString()}`);
                      const siBit = (sr.suspectStreamCarriers || 0) > 0 ? `${sr.suspectStreamCarriers.toLocaleString()} of ${(sr.totalStreamCarriers || 0).toLocaleString()} carrier(s) have timestomped-looking $SI` : "";
                      return (
                        <div style={{ marginTop: 5, fontSize: 9, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45, color: haveCompanion ? th.success : th.textDim, display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6 }}>
                          {haveCompanion
                            ? <span title="Forgery-resistant cross-artifact corroboration: USN journal NamedData*/StreamChange reasons and Sysmon EID 15 (FileCreateStreamHash) are stamped at the real operation, unlike $SI.">✓ {bits.join("  •  ")}</span>
                            : <span style={{ color: th.warning }} title="The non-Zone-ADS surface and its timing here come from $MFT alone, and the ordering rests on $SI (user-settable). Open a USN ($J) or EVTX (Sysmon) companion tab to corroborate.">⚠ Single-source $MFT — load a USN ($J) or EVTX companion tab to corroborate stream activity</span>}
                          {siBit ? <span style={{ color: th.warning }} title="These carriers' $SI ($SI<$FN or sub-second-zeroed) looks timestomped — treat their stream timing as unreliable.">⚠ {siBit}</span> : null}
                        </div>
                      );
                    })()}
                  </div>
                  <div style={{ maxHeight: 220, overflow: "auto" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1, minWidth: "fit-content" }}>
                      <div style={{ width: 200, flexShrink: 0 }}>FileName</div>
                      <div style={{ width: 230, flexShrink: 0 }}>Stream(s)</div>
                      <div style={{ width: 220, flexShrink: 0 }}>ParentPath</div>
                      <div style={{ width: 130, flexShrink: 0 }}>Created</div>
                      <div style={{ width: 70, flexShrink: 0 }}>Size</div>
                      <div style={{ width: 150, flexShrink: 0 }}>Corroboration</div>
                    </div>
                    {d.streamCarriers.map((f, i) => (
                      <div key={i} style={{ ...rowStyle(i), minWidth: "fit-content" }}>
                        <div style={{ width: 200, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, fontWeight: 600 }} title={f.fileName}>{f.fileName}</div>
                        <div style={{ width: 230, flexShrink: 0, overflow: "hidden", display: "flex", gap: 4, flexWrap: "nowrap" }}>
                          {(f.streams || []).length > 0 ? (f.streams.map((s, si) => {
                            const sc = s.execLike ? th.danger : s.large ? th.warning : s.benign ? th.textMuted : th.textDim;
                            const title = `:${s.name}${s.size != null ? ` (${s.size.toLocaleString()} bytes)` : ""}${s.execContent ? " — resident PE/MZ content" : ""}${s.large ? " — large hidden stream (inspect)" : ""}${s.benign ? " — known-benign OS/app stream" : ""}`;
                            return (
                            <span key={si} title={title} style={{ flexShrink: 0, fontSize: 9, padding: "1px 6px", borderRadius: 4, fontFamily: "'SF Mono',Menlo,monospace", color: sc, background: `${sc}1e`, border: `1px solid ${sc}33`, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 200 }}>{s.execContent ? "⚑ " : s.large ? "⬆ " : ""}{s.name}</span>
                            );
                          })
                          ) : <span style={{ fontSize: 9, color: th.textMuted }}>(name unavailable — MFTECmd CSV)</span>}
                        </div>
                        <div style={{ width: 220, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }} title={f.parentPath}>{f.parentPath}</div>
                        <div style={{ width: 130, flexShrink: 0, fontSize: 10, color: f.siSuspect ? th.warning : th.text, display: "flex", alignItems: "center", gap: 3 }} title={f.siSuspect ? "$SI ($SI<$FN or sub-second-zeroed) looks timestomped — this Created time is unreliable; rely on USN/EVTX corroboration." : undefined}>{f.siSuspect ? "⚠ " : ""}{(f.created || "").slice(0, 19)}</div>
                        <div style={{ width: 70, flexShrink: 0, color: th.textDim }}>{f.fileSize || ""}</div>
                        <div style={{ width: 150, flexShrink: 0, display: "flex", gap: 4, flexWrap: "wrap", alignItems: "center" }}>
                          {f.usnCorroboration ? <span title={`USN journal: ${f.usnCorroboration.namedStreamOps} named-stream/StreamChange op(s)${f.usnCorroboration.lastTs ? ` — last ${String(f.usnCorroboration.lastTs).slice(0, 19)}` : ""} (forgery-resistant). ${f.usnCorroboration.strong ? "Matched on MFT entry + name (strong)." : "Matched on file name only — USN carries no path, so a same-named file elsewhere is possible (weaker)."}`} style={{ fontSize: 9, padding: "1px 5px", borderRadius: 4, color: th.success, background: `${th.success}1e`, border: `1px solid ${th.success}44`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap" }}>✓ USN {f.usnCorroboration.namedStreamOps}{f.usnCorroboration.strong ? "" : "~"}</span> : null}
                          {f.evtxCorroboration ? <span title={`Sysmon EID 15 (FileCreateStreamHash): ${f.evtxCorroboration.streamCreates} event(s)${(f.evtxCorroboration.samples || [])[0] ? `\n${f.evtxCorroboration.samples[0].text}` : ""}`} style={{ fontSize: 9, padding: "1px 5px", borderRadius: 4, color: th.success, background: `${th.success}1e`, border: `1px solid ${th.success}44`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap" }}>✓ EID15 {f.evtxCorroboration.streamCreates}</span> : null}
                          {!f.usnCorroboration && !f.evtxCorroboration ? (() => {
                            const haveComp = d.correlation && (d.correlation.usnAvailable || d.correlation.evtxAvailable);
                            const title = !haveComp ? "No USN/EVTX companion loaded — single-source $MFT." : (f.corrChecked ? "Checked: no matching USN named-stream / Sysmon EID 15 event for this file (uncorroborated — $MFT only)." : "Not checked — beyond the corroboration sample.");
                            return <span style={{ fontSize: 9, color: th.textMuted }} title={title}>{haveComp && !f.corrChecked ? "·" : "—"}</span>;
                          })() : null}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Zone.Identifier Files */}
              {(d.zoneIdFiles || []).length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <div onClick={() => toggleAll("adSelZone", d.zoneIdFiles.length)} style={cbStyle(selZone.size === d.zoneIdFiles.length && d.zoneIdFiles.length > 0)}>
                        {selZone.size === d.zoneIdFiles.length && d.zoneIdFiles.length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                      </div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>All Zone.Identifier Files ({d.zoneIdFiles.length.toLocaleString()}{d.totalWithZoneId > d.zoneIdFiles.length ? ` of ${d.totalWithZoneId.toLocaleString()}` : ""})</span>
                    </div>
                  </div>
                  <div style={{ maxHeight: 200, overflow: "auto" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1, minWidth: "fit-content" }}>
                      <div style={{ width: 14, flexShrink: 0 }} />
                      {adHdrCol(zoneW[0], "FileName", "adSortZone", "fileName", "adZoneColW", defZoneW, 0)}
                      {adHdrCol(zoneW[1], "Ext", "adSortZone", "extension", "adZoneColW", defZoneW, 1)}
                      {adHdrCol(zoneW[2], "ParentPath", "adSortZone", "parentPath", "adZoneColW", defZoneW, 2)}
                      {adHdrCol(zoneW[3], "Created", "adSortZone", "created", "adZoneColW", defZoneW, 3)}
                      {adHdrCol(zoneW[4], "Zone", "adSortZone", "zoneName", "adZoneColW", defZoneW, 4)}
                      {adHdrCol(zoneW[5], "ReferrerUrl", "adSortZone", "referrerUrl", "adZoneColW", defZoneW, 5)}
                    </div>
                    {sortAdArr(d.zoneIdFiles, modal.adSortZone).map((f, i) => (
                      <div key={i} onClick={() => toggleSet("adSelZone", i)} style={{ ...rowStyle(i), cursor: "pointer", minWidth: "fit-content" }}>
                        <div style={cbStyle(selZone.has(i))}>
                          {selZone.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                        </div>
                        <div style={{ width: zoneW[0], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text }} title={f.fileName}>{f.fileName}</div>
                        <div style={{ width: zoneW[1], flexShrink: 0, color: th.textDim }}>{f.extension}</div>
                        <div style={{ width: zoneW[2], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }} title={f.parentPath}>{f.parentPath}</div>
                        <div style={{ width: zoneW[3], flexShrink: 0, fontSize: 10, color: th.text }}>{(f.created || "").slice(0, 19)}</div>
                        <div style={{ width: zoneW[4], flexShrink: 0 }}>
                          <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 4, background: `${zoneColors[f.zoneName] || th.textDim}22`, color: zoneColors[f.zoneName] || th.textDim, fontWeight: 600 }}>{f.zoneName || "?"}</span>
                        </div>
                        <div style={{ width: zoneW[5], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim, fontSize: 10 }} title={f.referrerUrl}>{f.referrerUrl || ""}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ADS Entries */}
              {(d.adsEntries || []).length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <div onClick={() => toggleAll("adSelAds", d.adsEntries.length)} style={cbStyle(selAds.size === d.adsEntries.length && d.adsEntries.length > 0)}>
                        {selAds.size === d.adsEntries.length && d.adsEntries.length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                      </div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>ADS Entries ({d.adsEntries.length.toLocaleString()}{d.totalAdsEntries > d.adsEntries.length ? ` of ${d.totalAdsEntries.toLocaleString()}` : ""})</span>
                    </div>
                  </div>
                  <div style={{ maxHeight: 200, overflow: "auto" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1, minWidth: "fit-content" }}>
                      <div style={{ width: 14, flexShrink: 0 }} />
                      {adHdrCol(adsW[0], "FileName", "adSortAds", "fileName", "adAdsColW", defAdsW, 0)}
                      {adHdrCol(adsW[1], "ParentPath", "adSortAds", "parentPath", "adAdsColW", defAdsW, 1)}
                      {adHdrCol(adsW[2], "Created", "adSortAds", "created", "adAdsColW", defAdsW, 2)}
                      {adHdrCol(adsW[3], "FileSize", "adSortAds", "fileSize", "adAdsColW", defAdsW, 3)}
                    </div>
                    {sortAdArr(d.adsEntries, modal.adSortAds).map((f, i) => (
                      <div key={i} onClick={() => toggleSet("adSelAds", i)} style={{ ...rowStyle(i), cursor: "pointer", minWidth: "fit-content" }}>
                        <div style={cbStyle(selAds.has(i))}>
                          {selAds.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                        </div>
                        <div style={{ width: adsW[0], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text }} title={f.fileName}>{f.fileName}</div>
                        <div style={{ width: adsW[1], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }} title={f.parentPath}>{f.parentPath}</div>
                        <div style={{ width: adsW[2], flexShrink: 0, fontSize: 10, color: th.text }}>{(f.created || "").slice(0, 19)}</div>
                        <div style={{ width: adsW[3], flexShrink: 0, color: th.textDim }}>{f.fileSize || ""}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>);
          })()}
        </div>

        {/* Footer */}
        {!loading && data && !isIpcError(data) && (
          <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", gap: 10, justifyContent: "space-between", alignItems: "center", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
            <div style={{ minHeight: 16, fontSize: 10, color: /fail/i.test(modal.adTagMsg || "") ? th.danger : (th.success || th.accent), fontFamily: "-apple-system, sans-serif" }}>{modal.adTagMsg || ""}</div>
            <div style={{ display: "flex", gap: 10 }}>
              {totalSelected > 0 && <button onClick={copySelected} style={{ ...ms.bs, position: "relative" }}>Copy Selected <span style={{ marginLeft: 4, fontSize: 9, padding: "1px 5px", borderRadius: 8, background: `${th.accent}33`, color: th.accent }}>{totalSelected}</span></button>}
              <button onClick={copyReport} style={ms.bs}>Copy Summary</button>
              {(data.totalWithZoneId || 0) > 0 && <button onClick={tagDownloaded} style={{ ...ms.bp, background: th.fillDanger, color: th.onAccent }}>Tag Downloaded</button>}
              <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
            </div>
          </div>
        )}
      </>)}
    </DraggableResizableModal>
  );
}
