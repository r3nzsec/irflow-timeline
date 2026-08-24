import { Fragment, useCallback } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { DraggableResizableModal } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";
import { updateModal } from "../../modals/modalRegistry.js";
import { formatNumber } from "../../utils/format.js";

export default function RansomwareModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th, themeName } = useTheme();
  const ct = useCurrentTab();
  const tabs = useTabStore((s) => s.tabs);
  const tle = typeof window !== "undefined" ? window.tle : null;

  const up = useCallback((key, value) => {
    useTabStore.getState().updateActiveTab({ [key]: value });
  }, []);

  // Modal styles (duplicated from App — keeps component self-contained)
  const ms = useModalChrome();

  if (modal?.type !== "ransomware" || !ct) return null;

  const { phase, encryptedExt, ransomNotePattern, data, loading, scanData } = modal;
  const usnTabs = tabs.filter((t) => t.id !== ct.id && t.dataReady && t.sourceFormat === "raw-usnjrnl");
  const autoUsnTab = usnTabs[0] || null;

  const handleScan = async () => {
    setModal((p) => ({ ...p, phase: "scanning", rwProgress: null }));
    try {
      const result = await tle.scanRansomwareExtensions(ct.id);
      if (isIpcError(result)) {
        setModal(updateModal("ransomware", { phase: "input", error: ipcErrorMessage(result) }));
      } else {
        setModal(updateModal("ransomware", { phase: "input", scanData: result }));
      }
    } catch (e) {
      setModal(updateModal("ransomware", { phase: "input", error: e.message }));
    }
  };

  const handleAnalyze = async () => {
    const ext = (encryptedExt || "").trim();
    if (!ext) return;
    setModal((p) => ({ ...p, phase: "loading", loading: true, rwProgress: null }));
    try {
      const resolvedUsnTabId = modal.usnTabId === "__none__" ? null : (modal.usnTabId || autoUsnTab?.id || null);
      const result = await tle.analyzeRansomware(ct.id, ext, (ransomNotePattern || "").trim(), modal.noteMatchMode || "exact", resolvedUsnTabId);
      if (isIpcError(result)) {
        setModal(updateModal("ransomware", { phase: "input", loading: false, error: ipcErrorMessage(result) }));
      } else {
        setModal(updateModal("ransomware", { phase: "results", loading: false, data: result, rwSelDirs: new Set(), rwSelNotes: new Set(), rwSelSusp: new Set(), rwSelFirst: new Set(), rwSelPairs: new Set(), rwSelAF: new Set(), rwSelUsn: new Set(), rwSortDirs: null, rwSortNotes: null, rwSortSusp: null, rwSortFirst: null, rwSortPairs: null, rwExpandedRow: null, rwShowPivots: false, rwPivotMsg: null }));
      }
    } catch (e) {
      setModal(updateModal("ransomware", { phase: "input", loading: false, error: e.message }));
    }
  };

  const fmtBytes = (b) => {
    if (!b || b <= 0) return "0 B";
    const u = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
    return `${(b / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${u[i]}`;
  };
  const fmtDur = (m) => {
    if (!m || m <= 0) return "0 min";
    if (m < 60) return `${m} min`;
    const h = Math.floor(m / 60);
    return h < 24 ? `${h}h ${m % 60}m` : `${Math.floor(m / 1440)}d ${Math.floor((m % 1440) / 60)}h`;
  };

  const copyReport = () => {
    if (!data) return;
    const d = data;
    const lines = [
      "=== Ransomware MFT Analysis ===",
      `Encrypted Extension: ${encryptedExt}`,
      ransomNotePattern ? `Ransom Note: ${ransomNotePattern}${modal.noteMatchMode && modal.noteMatchMode !== "exact" ? ` (${modal.noteMatchMode})` : ""}` : null, "",
      `Encrypted Files: ${(d.encryptedCount || 0).toLocaleString()}`,
      `Total Size: ${fmtBytes(d.totalEncryptedSizeBytes)}`,
      `Duration: ${fmtDur(d.durationMinutes)}`,
      `Rate: ${(d.filesPerMinute || 0).toFixed(1)} files/minute`, "",
      d.firstEncrypted ? `First Encrypted: ${d.firstEncrypted.fileName}\n  Path: ${d.firstEncrypted.parentPath}\n  Time: ${d.firstEncrypted.timestamp}` : null,
      d.lastEncrypted ? `Last Encrypted: ${d.lastEncrypted.fileName}\n  Path: ${d.lastEncrypted.parentPath}\n  Time: ${d.lastEncrypted.timestamp}` : null, "",
    ];
    if (d.timingEvidence) {
      const te = d.timingEvidence;
      lines.push("Timing Evidence:");
      if (te.timelineBasis) lines.push(`  Timeline Basis: ${te.timelineBasis.label} (${te.timelineBasis.column})`);
      if (te.suspiciousWindowBasis?.timestamp) lines.push(`  Payload Anchor: ${te.suspiciousWindowBasis.label} (${te.suspiciousWindowBasis.column}) @ ${te.suspiciousWindowBasis.timestamp}`);
      if (te.start?.preferred?.timestamp) lines.push(`  Start Preference: ${te.start.preferred.label} @ ${te.start.preferred.timestamp}${te.start.skewMinutes ? ` (skew ${te.start.skewMinutes} min)` : ""}`);
      if (te.end?.preferred?.timestamp) lines.push(`  End Preference: ${te.end.preferred.label} @ ${te.end.preferred.timestamp}${te.end.skewMinutes ? ` (skew ${te.end.skewMinutes} min)` : ""}`);
      lines.push("");
    }
    // Original pair detection
    if (d.originalPairs && (d.originalPairs.confirmedPairs > 0 || d.originalPairs.likelyPairs > 0)) {
      const op = d.originalPairs;
      const tilde = op.sampled ? "~" : "";
      const note = op.sampled
        ? `  (estimated from ${op.sampleSize || 0}-row sample of ${op.samplePopulation || 0} encrypted files; rounded to nearest 100)`
        : "";
      lines.push("Original-to-Encrypted Pairs:", `  Confirmed: ${tilde}${op.confirmedPairs}`, `  Likely: ${tilde}${op.likelyPairs}`, `  ${op.sampled ? "Sample " : ""}Pair Rate: ${Math.round(op.pairRate * 100)}%`);
      if (note) lines.push(note);
      lines.push("");
    }
    // Forensic indicators with observed/inferred
    if (d.forensicIndicators?.length > 0) {
      lines.push("Forensic Indicators:");
      d.forensicIndicators.forEach(fi => lines.push(`  [${fi.basis}] ${fi.text}`));
      lines.push("");
    }
    lines.push(
      `Ransom Notes: ${d.ransomNoteCount} dropped`,
      `Deleted Encrypted Files: ${d.deletedEncrypted}`,
      `Timestomped Files: ${d.timestompedCount}`,
      `Payload Candidates: ${(d.suspiciousFiles || []).length}`, "",
    );
    // Top scored payloads
    if (d.suspiciousFiles?.length > 0) {
      lines.push("Top Payload Candidates:");
      d.suspiciousFiles.slice(0, 5).forEach(sf => {
        const sigs = (sf.signals || []).map(s => s.text).join(", ");
        lines.push(`  [${Math.round((sf.score || 0) * 100)}] ${sf.fileName} — ${sf.parentPath} (${sf.confidence || "unknown"}${sigs ? ": " + sigs : ""})`);
      });
      lines.push("");
    }
    // File type impact
    lines.push("File Type Impact:");
    (d.fileTypeBreakdown || []).slice(0, 10).forEach((t) => lines.push(`  ${t.ext}: ${t.count.toLocaleString()} (${((t.count / d.encryptedCount) * 100).toFixed(1)}%)`));
    lines.push("");
    // Business impact
    if (d.businessImpact?.length > 0) {
      lines.push("Business Impact:");
      d.businessImpact.filter(c => c.category !== "Other").forEach(c => lines.push(`  ${c.category}: ${c.count.toLocaleString()} (${Math.round(c.percentage * 100)}%)`));
      lines.push("");
    }
    // Backup recovery
    if (d.backupRecoveryTotal > 0) {
      lines.push(`Backup/Recovery Artifacts: ${d.backupRecoveryTotal} files affected`);
      (d.backupRecoveryImpact || []).forEach(r => lines.push(`  ${r.subtype} (${r.ext}): ${r.count}`));
      lines.push("");
    }
    // Anti-forensics
    if (d.antiForensics) {
      const af = d.antiForensics;
      const afTotal = (af.deletedEncrypted?.length || 0) + (af.timestomped?.length || 0) + (af.cleanup?.length || 0) + (af.drops?.length || 0);
      if (afTotal > 0) {
        lines.push("Anti-Forensics:");
        if (af.deletedEncrypted?.length) lines.push(`  Deleted Encrypted: ${af.deletedEncrypted.length}`);
        if (af.timestomped?.length) lines.push(`  Timestomped in Window: ${af.timestomped.length}`);
        if (af.cleanup?.length) lines.push(`  Cleanup Artifacts: ${af.cleanup.length}`);
        if (af.drops?.length) lines.push(`  Suspicious Drops: ${af.drops.length}`);
        lines.push("");
      }
    }
    // USN enrichment
    if (d.usnEnrichment) {
      const usn = d.usnEnrichment;
      lines.push("USN Journal Correlation:");
      if (usn.preciseStartTime) lines.push(`  Precise Start: ${usn.preciseStartTime}`);
      lines.push(`  Rename Events: ${usn.renameCount}`, `  Data Overwrites: ${usn.overwriteTotal}`, `  Deletions: ${usn.deleteTotal}`, "");
    }
    // Directories
    lines.push("Affected Subtrees:");
    (d.topDirectories || []).slice(0, 10).forEach((dir) => {
      const enc = dir.encryptedCount || dir.count || 0;
      const total = dir.totalCount || enc;
      const ratio = total > 0 ? Math.round((enc / total) * 100) : 0;
      lines.push(`  ${dir.path} (${enc.toLocaleString()} / ${total.toLocaleString()} — ${ratio}%)`);
    });
    navigator.clipboard?.writeText(lines.filter((l) => l !== null).join("\n"));
  };

  const exportPdf = async () => {
    if (!data) return;
    const d = data;
    const esc = (s) => String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const tblRow = (cells, isHeader) => {
      const tag = isHeader ? "th" : "td";
      return `<tr>${cells.map(c => `<${tag}>${esc(c)}</${tag}>`).join("")}</tr>`;
    };
    const section = (title, content) => `<div class="section"><h2>${esc(title)}</h2>${content}</div>`;
    const statBox = (val, label, color) => `<div class="stat" style="border-top:3px solid ${color}"><div class="stat-val" style="color:${color}">${esc(val)}</div><div class="stat-label">${esc(label)}</div></div>`;

    let body = `<div class="header"><h1>Ransomware MFT Analysis Report</h1><div class="meta">Extension: <code>${esc(encryptedExt)}</code>${ransomNotePattern ? ` &nbsp;|&nbsp; Note: <code>${esc(ransomNotePattern)}</code>` : ""}${modal.noteMatchMode && modal.noteMatchMode !== "exact" ? ` (${esc(modal.noteMatchMode)})` : ""} &nbsp;|&nbsp; Generated: ${new Date().toISOString().replace("T", " ").slice(0, 19)}</div></div>`;

    // Stats
    body += `<div class="stats">${statBox((d.encryptedCount || 0).toLocaleString(), "Encrypted Files", th.sev.critical)}${statBox(fmtBytes(d.totalEncryptedSizeBytes), "Total Size", th.sev.info)}${statBox(fmtDur(d.durationMinutes), "Duration", th.sev.med)}${statBox((d.filesPerMinute || 0).toFixed(1), "Files/min", th.sev.info)}</div>`;

    // Incident verdict
    if (d.incidentSummary) {
      const s = d.incidentSummary;
      const sevColor = s.severity === "Critical" ? th.sev.critical : s.severity === "High" ? th.sev.high : s.severity === "Medium" ? th.sev.med : th.sev.low;
      body += section("Incident Verdict", `<p style="line-height:1.55"><span class="badge" style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}66">${esc(s.severity)}</span> &nbsp; ${esc(s.narrative)}</p>`);
    }

    // Recovery prospects
    if (d.recoveryProspects) {
      const r = d.recoveryProspects;
      const avenues = (r.avenues || []).map(a => tblRow([a.name, a.viability, a.detail])).join("");
      body += section("Recovery Prospects", `<p><strong>Outlook: ${esc(r.outlook)}</strong> &nbsp;(method: ${esc(r.method)}) &mdash; ${esc(r.outlookReason)}</p><p>Carvable (deleted originals): <strong>${(r.carvableCount || 0).toLocaleString()}</strong> &nbsp;|&nbsp; MFT-resident est.: <strong>${(r.residentRecoverableCount || 0).toLocaleString()}</strong> &nbsp;|&nbsp; Overwritten on-host: <strong>${(r.overwrittenCount || 0).toLocaleString()}</strong></p><table>${tblRow(["Avenue", "Viability", "Detail"], true)}${avenues}</table><p style="font-size:11px;color:#888;font-style:italic">${esc(r.caveat)}</p>`);
    }

    // Threat attribution + MITRE ATT&CK
    if (d.familyAttribution?.top || d.mitreTechniques?.length) {
      const fa = d.familyAttribution;
      const famLine = fa?.top
        ? `<p>Family: <strong>${esc(fa.top.name)}</strong>${fa.top.aka ? ` (${esc(fa.top.aka)})` : ""} &nbsp; <span class="badge">${esc(fa.top.confidence)}</span> &nbsp; matched on ${esc(fa.top.matchedOn.join(" + "))}${fa.top.evidence?.length ? ` (${esc(fa.top.evidence.join(", "))})` : ""}${fa.candidates?.length > 1 ? ` &nbsp;|&nbsp; other: ${esc(fa.candidates.slice(1).map((c) => c.name).join(", "))}` : ""}</p>`
        : `<p>${esc(fa?.note || "No known-family signature matched.")}</p>`;
      const mitre = (d.mitreTechniques || []).length
        ? `<table>${tblRow(["Technique", "Name", "Basis"], true)}${d.mitreTechniques.map((t) => tblRow([t.id, t.name, t.basis])).join("")}</table>`
        : "";
      body += section("Threat Attribution & MITRE ATT&CK", famLine + mitre);
    }

    // Blast radius
    if (d.blastRadius) {
      const br = d.blastRadius;
      body += section("Blast Radius", `<p><strong>${Math.round((br.encryptedPct || 0) * 100)}%</strong> of files encrypted (${(br.encryptedCount || 0).toLocaleString()} / ${(br.totalFiles || 0).toLocaleString()}) &nbsp;—&nbsp; Severity: <span class="badge ${br.severity || "medium"}">${(br.severity || "unknown").toUpperCase()}</span></p>`);
    }

    // Timeline
    if (d.firstEncrypted && d.lastEncrypted) {
      body += section("Encryption Timeline", `<table>${tblRow(["", "File", "Path", "Timestamp"], true)}${tblRow(["First", d.firstEncrypted.fileName, d.firstEncrypted.parentPath, d.firstEncrypted.timestamp])}${tblRow(["Last", d.lastEncrypted.fileName, d.lastEncrypted.parentPath, d.lastEncrypted.timestamp])}</table>`);
    }

    // Top directories
    if (d.topDirectories?.length > 0) {
      const dirRows = d.topDirectories.slice(0, 15).map(dir => {
        const enc = dir.encryptedCount || dir.count || 0;
        const total = dir.totalCount || enc;
        return tblRow([dir.path, enc.toLocaleString(), total.toLocaleString(), total > 0 ? Math.round((enc / total) * 100) + "%" : "\u2014"]);
      }).join("");
      body += section(`Affected Directories (${d.topDirectories.length})`, `<table>${tblRow(["Path", "Encrypted", "Total", "Ratio"], true)}${dirRows}</table>`);
    }

    // Scope (by area / user)
    if (d.scoping) {
      const sc = d.scoping;
      const scRows = (items) => items.map((it) => tblRow([it.name, it.count.toLocaleString(), Math.round(it.pct * 100) + "%"])).join("");
      const areaTbl = `<table>${tblRow(["Top-level area", "Encrypted", "Share"], true)}${scRows(sc.byArea)}</table>`;
      const userTbl = sc.byUser.length ? `<table>${tblRow(["User profile", "Encrypted", "Share"], true)}${scRows(sc.byUser)}</table>` : "<p>No user-profile paths encrypted.</p>";
      body += section("Scope", `${areaTbl}${userTbl}${sc.note ? `<p style="font-style:italic;color:#888">${esc(sc.note)}</p>` : ""}`);
    }

    // Ransom notes
    if (d.ransomNoteCount > 0 && d.ransomNotes?.length > 0) {
      const noteRows = d.ransomNotes.slice(0, 20).map(n => tblRow([n.fileName, n.parentPath, n.created || "\u2014"])).join("");
      body += section(`Ransom Notes (${d.ransomNoteCount})`, `<table>${tblRow(["File", "Path", "Created"], true)}${noteRows}</table>`);
    }

    // Suspicious payloads
    if (d.suspiciousFiles?.length > 0) {
      const sfRows = d.suspiciousFiles.slice(0, 20).map(sf => {
        const sigs = (sf.signals || []).map(s => s.text).join(", ");
        return tblRow([Math.round((sf.score || 0) * 100) + "", sf.confidence || "\u2014", sf.fileName, sf.parentPath, sf.created || "\u2014", sigs]);
      }).join("");
      body += section(`Suspicious Payload Candidates (${d.suspiciousFiles.length})`, `<table>${tblRow(["Score", "Confidence", "File", "Path", "Created", "Signals"], true)}${sfRows}</table>`);
    }

    // Original-encrypted pairs
    if (d.originalPairs && (d.originalPairs.confirmedPairs > 0 || d.originalPairs.likelyPairs > 0)) {
      const op = d.originalPairs;
      const tilde = op.sampled ? "~" : "";
      const rateLabel = op.sampled ? "Sample Pair Rate" : "Pair Rate";
      const sampleNote = op.sampled
        ? `<p style="font-size:11px;color:#888;font-style:italic;margin-top:4px">Estimated by extrapolation from a ${op.sampleSize || 0}-row sample of ${op.samplePopulation || 0} encrypted files; counts rounded to nearest 100.</p>`
        : "";
      body += section("Original-Encrypted Pairs", `<p>Confirmed: <strong>${tilde}${op.confirmedPairs}</strong> &nbsp;|&nbsp; Likely: <strong>${tilde}${op.likelyPairs}</strong> &nbsp;|&nbsp; ${rateLabel}: <strong>${Math.round(op.pairRate * 100)}%</strong></p>${sampleNote}`);
    }

    // Forensic indicators
    if (d.forensicIndicators?.length > 0) {
      const fiRows = d.forensicIndicators.map(fi => `<div class="pill ${fi.basis}">${esc(fi.text)}<span class="basis">${fi.basis}</span></div>`).join("");
      body += section("Forensic Indicators", `<div class="pills">${fiRows}</div>`);
    }

    // File type breakdown
    if (d.fileTypeBreakdown?.length > 0) {
      const ftRows = d.fileTypeBreakdown.slice(0, 15).map(t => tblRow([t.ext, t.count.toLocaleString(), ((t.count / d.encryptedCount) * 100).toFixed(1) + "%"])).join("");
      body += section("File Type Impact", `<table>${tblRow(["Extension", "Count", "%"], true)}${ftRows}</table>`);
    }

    // Business impact
    if (d.businessImpact?.length > 0) {
      const biRows = d.businessImpact.filter(c => c.category !== "Other").map(c => tblRow([c.category, c.count.toLocaleString(), Math.round(c.percentage * 100) + "%"])).join("");
      body += section("Business Impact", `<table>${tblRow(["Category", "Files", "%"], true)}${biRows}</table>`);
    }

    // Anti-forensics
    if (d.antiForensics) {
      const af = d.antiForensics;
      const afTotal = (af.deletedEncrypted?.length || 0) + (af.timestomped?.length || 0) + (af.cleanup?.length || 0) + (af.drops?.length || 0);
      if (afTotal > 0) {
        let afContent = `<div class="stats">${statBox(String(af.deletedEncrypted?.length || 0), "Deleted Encrypted", th.sev.critical)}${statBox(String(af.timestomped?.length || 0), "Timestomped", th.sev.med)}${statBox(String(af.cleanup?.length || 0), "Cleanup Artifacts", th.accent)}${statBox(String(af.drops?.length || 0), "Suspicious Drops", th.sev.critical)}</div>`;
        body += section("Anti-Forensics & Cleanup", afContent);
      }
    }

    // USN enrichment
    if (d.usnEnrichment) {
      const usn = d.usnEnrichment;
      let usnContent = `<div class="stats">${statBox(String(usn.renameCount), "Rename Events", th.sev.info)}${statBox(String(usn.overwriteTotal), "Data Overwrites", th.sev.med)}${statBox(String(usn.deleteTotal), "Deletions", th.sev.critical)}</div>`;
      if (usn.preciseStartTime) usnContent += `<p>Precise encryption start: <code>${esc(usn.preciseStartTime)}</code></p>`;
      body += section("USN Journal Correlation", usnContent);
    }

    // Defense evasion (EVTX cross-artifact)
    if (d.evtxEnrichment?.total > 0) {
      const ev = d.evtxEnrichment;
      const catSummary = Object.entries(ev.byCategory || {}).sort((a, b) => b[1] - a[1]).map(([c, n]) => `${esc(c)} (${n})`).join(", ");
      const rows = (ev.hits || []).map((h) => tblRow([(h.timestamp || "").slice(0, 19), (h.technique || "review") + (h.eventId ? ` · ${h.eventId}` : ""), h.category, h.text || ""])).join("");
      body += section("Defense Evasion (EVTX)", `<p>${ev.total} correlated event(s) in the encryption window — corroborates T1490 (VSS / backup destruction). ${catSummary}</p><table>${tblRow(["Time", "Technique", "Category", "Detail"], true)}${rows}</table>`);
    }

    // Process execution (EVTX cross-artifact)
    if (d.processCorrelation?.available && d.processCorrelation.total > 0) {
      const pc = d.processCorrelation;
      let pcBody = `<p>${pc.total} process-creation event(s) in the encryption window${pc.confirmedPayloads > 0 ? ` — ${pc.confirmedPayloads} payload candidate(s) execution-confirmed (a dropped binary that also launched).` : " — no payload candidate matched a launched process."}</p>`;
      if (pc.confirmed?.length) {
        const cRows = pc.confirmed.map((cf) => tblRow([cf.fileName, (cf.time || "").slice(0, 19), cf.parentImage || "—", cf.user || "—"])).join("");
        pcBody += `<p><strong>Execution-confirmed payloads</strong></p><table>${tblRow(["Executed Payload", "Time", "Parent", "User"], true)}${cRows}</table>`;
      }
      if (pc.processes?.length) {
        const pRows = pc.processes.slice(0, 25).map((p) => tblRow([(p.timestamp || "").slice(0, 19), [p.matchedPayload ? "PAYLOAD" : "", p.evasion ? "EVASION" : "", p.risky ? "RISKY" : ""].filter(Boolean).join(" "), p.image || p.cmdLine || "", p.parentImage || "—", p.user || "—"])).join("");
        pcBody += `<table>${tblRow(["Time", "Flags", "Process", "Parent", "User"], true)}${pRows}</table>`;
      }
      body += section("Process Execution (EVTX)", pcBody);
    }

    // In-place / overwrite encryption (suspicion surface)
    if (d.inPlaceEncryption?.available) {
      const ip = d.inPlaceEncryption;
      let ipBody = `<p><strong>Confidence: ${esc(ip.confidence.toUpperCase())}</strong>${ip.isSuspicionOnly ? " (SUSPICION — corroboration needed)" : ""}. ${ip.candidateFileCount.toLocaleString()} business-data files rewritten in place (same filename; SI 0x10 Modified later than FN 0x30) over ${ip.durationMinutes} min`;
      if (ip.windowStart || ip.windowEnd) ipBody += `, ${esc(ip.windowStart || "")} → ${esc(ip.windowEnd || "")} UTC`;
      ipBody += `. Peak ${ip.peakFilesPerMinute.toLocaleString()}/min across ${ip.directoryCount} director${ip.directoryCount === 1 ? "y" : "ies"}.</p>`;
      if (ip.reason) ipBody += `<p><em>${esc(ip.reason)}</em></p>`;
      if (ip.extensionBreakdown?.length) {
        const eRows = ip.extensionBreakdown.map((e) => tblRow([e.extension, e.category, String(e.count)])).join("");
        ipBody += `<table>${tblRow(["Extension", "Category", "Count"], true)}${eRows}</table>`;
      }
      const sRows = (ip.signals || []).map((s) => tblRow([s.id, s.fired ? "YES" : "no", s.text])).join("");
      ipBody += `<table>${tblRow(["Signal", "Fired", "Detail"], true)}${sRows}</table>`;
      ipBody += `<p style="font-size:11px;font-style:italic">${esc(ip.disclaimer)}</p>`;
      body += section("In-Place / Overwrite Encryption (Suspected)", ipBody);
    }

    // Theme-aware CSS — adapts to current dark/light mode
    const isDark = themeName === "dark";
    const c = {
      bg: isDark ? "#0d1117" : "#ffffff",
      bgAlt: isDark ? "#161b22" : "#f7f5f3",
      text: isDark ? "#e6edf3" : "#1c1917",
      textDim: isDark ? "#c9d1d9" : "#44403c",
      textMuted: isDark ? th.sev.low : "#78716c",
      border: isDark ? "#30363d" : "#e0dbd6",
      borderSub: isDark ? "#21262d" : "#e7e5e4",
      accent: th.accent,
      danger: th.danger,
      warning: th.warning,
      code: isDark ? th.sev.info : "#0969da",
      stripeBg: isDark ? "#0d111722" : "#faf8f611",
    };
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Ransomware Analysis \u2014 ${esc(encryptedExt)}</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:${c.bg};color:${c.text};font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,sans-serif;font-size:12px;padding:32px 40px;line-height:1.5}
.header{margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid ${c.border}}
h1{font-size:20px;font-weight:700;color:${c.text};margin-bottom:6px}
.meta{font-size:11px;color:${c.textMuted}}
code{background:${c.bgAlt};padding:2px 6px;border-radius:4px;font-family:"SF Mono",Menlo,monospace;font-size:11px;color:${c.code}}
.stats{display:flex;gap:10px;margin:12px 0 16px}
.stat{flex:1;background:${c.bgAlt};border:1px solid ${c.border};border-radius:8px;padding:14px 10px;text-align:center}
.stat-val{font-size:20px;font-weight:700;line-height:1.2}
.stat-label{font-size:9px;text-transform:uppercase;letter-spacing:0.05em;color:${c.textMuted};margin-top:4px}
.section{margin-bottom:20px}
h2{font-size:13px;font-weight:600;color:${c.text};margin-bottom:8px;padding:6px 10px;background:${c.bgAlt};border-radius:6px}
table{width:100%;border-collapse:collapse;font-size:11px;font-family:"SF Mono",Menlo,monospace}
th{text-align:left;padding:6px 10px;background:${c.bgAlt};color:${c.textMuted};font-weight:600;border-bottom:1px solid ${c.border};font-size:10px;text-transform:uppercase;letter-spacing:0.05em}
td{padding:5px 10px;border-bottom:1px solid ${c.borderSub};color:${c.textDim};word-break:break-all}
tr:nth-child(even) td{background:${c.stripeBg}}
.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;color:#fff}
.badge.critical{background:${c.danger}}.badge.high{background:${c.accent}}.badge.medium{background:${c.warning}}.badge.low{background:${c.textMuted}}
.pills{display:flex;flex-wrap:wrap;gap:6px}
.pill{padding:4px 10px;border-radius:6px;font-size:10px;background:${c.bgAlt};border:1px solid ${c.border};display:flex;align-items:center;gap:6px}
.pill.observed{border-color:${c.code}55}.pill.inferred{border-style:dashed;border-color:${c.warning}55}
.basis{font-size:8px;text-transform:uppercase;padding:1px 4px;border-radius:3px;background:${c.border};color:${c.textMuted}}
p{margin:8px 0;color:${c.textDim};font-size:12px}
strong{color:${c.text}}
.footer{margin-top:24px;padding-top:12px;border-top:1px solid ${c.border};color:${c.textMuted};font-size:10px;text-align:center}
@page{margin:12mm}
</style></head><body>${body}<div class="footer">IRFlow Timeline \u2014 Ransomware MFT Analysis Report</div></body></html>`;

    setModal((p) => ({ ...p, rwPivotMsg: "Generating PDF..." }));
    try {
      const result = await tle.exportRansomwarePdf(html, `ransomware_${encryptedExt.replace(/[^a-zA-Z0-9]/g, "")}_report.pdf`);
      setModal((p) => p ? { ...p, rwPivotMsg: result ? `PDF saved to ${result.filePath.split("/").pop()}` : null } : p);
    } catch (e) {
      setModal((p) => p ? { ...p, rwPivotMsg: `Export failed: ${e.message}` } : p);
    }
    setTimeout(() => setModal((p) => p ? { ...p, rwPivotMsg: null } : p), 4000);
  };

  const rowStyle = (i) => ({
    display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", fontSize: 11,
    background: i % 2 === 0 ? "transparent" : `${th.border}15`,
    borderBottom: `1px solid ${th.border}22`, fontFamily: "'SF Mono',Menlo,monospace",
  });

  const cbStyle = (checked) => ({
    width: 14, height: 14, borderRadius: 4, flexShrink: 0, cursor: "pointer",
    background: checked ? (th.accent) : "transparent",
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

  const copySelected = () => {
    const lines = [];
    const selFirst = modal.rwSelFirst || new Set();
    const selPairs = modal.rwSelPairs || new Set();
    const selDirs = modal.rwSelDirs || new Set();
    const selNotes = modal.rwSelNotes || new Set();
    const selSusp = modal.rwSelSusp || new Set();
    const selAF = modal.rwSelAF || new Set();
    const selUsn = modal.rwSelUsn || new Set();
    if (selFirst.size > 0 && data?.firstEncryptedFiles) {
      lines.push("=== First Encrypted Files ===");
      lines.push("Entry#\tFileName\tParentPath\tTimestamp\tSize");
      data.firstEncryptedFiles.forEach((f, i) => { if (selFirst.has(i)) lines.push(`#${f.entryNumber}\t${f.fileName}\t${f.parentPath}\t${(f.timestamp || "").slice(0, 19)}\t${f.fileSize || ""}`); });
      lines.push("");
    }
    if (selPairs.size > 0 && data?.originalPairs?.samplePairs) {
      lines.push("=== Original-to-Encrypted Pairs ===");
      lines.push("Original\tEncrypted\tPath\tStatus");
      data.originalPairs.samplePairs.slice(0, 30).forEach((p, i) => { if (selPairs.has(i)) lines.push(`${p.originalFile}\t${p.encryptedFile}\t${p.parentPath}\t${p.originalDeleted ? "DELETED" : "ABSENT"}`); });
      lines.push("");
    }
    if (selDirs.size > 0 && data?.topDirectories) {
      lines.push("=== Affected Subtrees ===");
      data.topDirectories.slice(0, 15).forEach((d, i) => {
        if (!selDirs.has(i)) return;
        const enc = d.encryptedCount || d.count || 0;
        const total = d.totalCount || enc;
        lines.push(`${d.path || "(root)"}\t${enc}/${total}\t${total > 0 ? Math.round((enc/total)*100) : 0}%`);
      });
      lines.push("");
    }
    if (selNotes.size > 0 && data?.ransomNotes) {
      lines.push("=== Ransom Note Locations ===");
      data.ransomNotes.slice(0, 50).forEach((n, i) => { if (selNotes.has(i)) lines.push(`#${n.entryNumber}\t${n.fileName}\t${n.parentPath}\t${(n.created || "").slice(0, 19)}`); });
      lines.push("");
    }
    if (selSusp.size > 0 && data?.suspiciousFiles) {
      lines.push("=== Payload Candidates ===");
      lines.push("Score\tConfidence\tExt\tFileName\tParentPath\tCreated\tSignals");
      data.suspiciousFiles.forEach((s, i) => { if (selSusp.has(i)) lines.push(`${Math.round((s.score || 0) * 100)}\t${s.confidence || ""}\t${s.extension}\t${s.fileName}\t${s.parentPath}\t${(s.created || "").slice(0, 19)}\t${(s.signals || []).map(sig => sig.text).join(", ")}${s.zoneId ? "\t[WEB]" : ""}${s.executionConfirmed ? `\t[EXEC parent=${s.execContext?.parentImage || "?"} user=${s.execContext?.user || "?"}]` : ""}`); });
      lines.push("");
    }
    if (data?.processCorrelation?.available && data.processCorrelation.processes?.length > 0) {
      const pc = data.processCorrelation;
      lines.push("=== Process Execution (EVTX) ===");
      lines.push(`${pc.total} process-creation event(s) in window · ${pc.confirmedPayloads} payload(s) execution-confirmed`);
      lines.push("Time\tFlags\tProcess\tParent\tUser");
      pc.processes.forEach((p) => lines.push(`${(p.timestamp || "").slice(0, 19)}\t${[p.matchedPayload ? "PAYLOAD" : "", p.evasion ? "EVASION" : "", p.risky ? "RISKY" : ""].filter(Boolean).join(" ")}\t${p.image || p.cmdLine || ""}\t${p.parentImage || ""}\t${p.user || ""}`));
      lines.push("");
    }
    if (selAF.size > 0 && data?.antiForensics) {
      lines.push("=== Anti-Forensics ===");
      let gi = 0;
      const cats = [
        { label: "Deleted Encrypted", items: data.antiForensics.deletedEncrypted || [] },
        { label: "Timestomped", items: data.antiForensics.timestomped || [] },
        { label: "Cleanup", items: data.antiForensics.cleanup || [] },
        { label: "Drops", items: data.antiForensics.drops || [] },
      ];
      for (const cat of cats) {
        for (const item of cat.items) {
          if (selAF.has(gi)) lines.push(`[${cat.label}]\t#${item.entryNumber}\t${item.fileName}\t${item.parentPath}\t${(item.created || item.lastModified || "").slice(0, 19)}`);
          gi++;
        }
      }
      lines.push("");
    }
    if (selUsn.size > 0 && data?.usnEnrichment?.renameSamples) {
      lines.push("=== USN Rename Events ===");
      data.usnEnrichment.renameSamples.forEach((r, i) => { if (selUsn.has(i)) lines.push(`${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath || ""}`); });
      lines.push("");
    }
    if (lines.length > 0) navigator.clipboard?.writeText(lines.join("\n"));
  };

  const totalSelected = ((modal.rwSelDirs || new Set()).size + (modal.rwSelNotes || new Set()).size + (modal.rwSelSusp || new Set()).size + (modal.rwSelFirst || new Set()).size + (modal.rwSelPairs || new Set()).size + (modal.rwSelAF || new Set()).size + (modal.rwSelUsn || new Set()).size);

  // Sort + column resize for ransomware tables
  const handleRwSort = (stateKey, colKey) => setModal((p) => {
    if (!p) return p;
    const cur = p[stateKey];
    const newDir = cur?.col === colKey && cur.dir === "asc" ? "desc" : "asc";
    return { ...p, [stateKey]: { col: colKey, dir: newDir } };
  });
  const sortRwArr = (arr, sortState) => {
    if (!sortState || !arr) return arr;
    return [...arr].sort((a, b) => {
      const va = (a[sortState.col] || "").toString().toLowerCase();
      const vb = (b[sortState.col] || "").toString().toLowerCase();
      return sortState.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
    });
  };
  const rwSortArrow = (stateKey, colKey) => {
    const s = modal[stateKey]; const active = s?.col === colKey; const dir = active ? s.dir : null;
    return (
      <svg width="8" height="10" viewBox="0 0 8 10" style={{ marginLeft: 3, flexShrink: 0, opacity: active ? 1 : 0.25, transition: "opacity var(--m-base)" }}>
        <path d="M4 1L7 4H1Z" fill={dir === "asc" ? (th.accent) : th.textMuted} opacity={dir === "asc" ? 1 : 0.4} />
        <path d="M4 9L1 6H7Z" fill={dir === "desc" ? (th.accent) : th.textMuted} opacity={dir === "desc" ? 1 : 0.4} />
      </svg>
    );
  };
  // Column resize for ransomware
  const defNotesW = [60, 120, 240, 140];
  const defSuspW = [50, 120, 240, 140];
  const notesW = modal.rwNotesColW || defNotesW;
  const suspW = modal.rwSuspColW || defSuspW;
  const startRwColResize = (stateKey, defaults, colIdx, e) => {
    e.preventDefault(); e.stopPropagation();
    const startX = e.clientX, startW = (modal[stateKey] || defaults)[colIdx];
    const onMove = (ev) => setModal((p) => { if (!p) return p; const w = [...(p[stateKey] || defaults)]; w[colIdx] = Math.max(30, startW + (ev.clientX - startX)); return { ...p, [stateKey]: w }; });
    const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
  };
  const rwResH = { position: "absolute", right: -2, top: 0, bottom: 0, width: 5, cursor: "col-resize", zIndex: 3 };
  const rwHdrCol = (w, label, stateKey, colKey, resizeKey, defW, colIdx) => (
    <div style={{ width: w, flexShrink: 0, position: "relative", cursor: "pointer", display: "flex", alignItems: "center", userSelect: "none" }} onClick={() => handleRwSort(stateKey, colKey)}>
      {label}{rwSortArrow(stateKey, colKey)}
      <div onMouseDown={(e) => { e.stopPropagation(); startRwColResize(resizeKey, defW, colIdx, e); }} style={rwResH} />
    </div>
  );

  return (
    <DraggableResizableModal
      key={`${phase}-${scanData ? "scan" : "noscan"}`}
      defaultWidth={phase === "results" ? 860 : (scanData ? 640 : 520)}
      defaultHeight={phase === "results" ? Math.round(window.innerHeight * 0.88) : (scanData ? 520 : 380)}
      minWidth={420}
      minHeight={280}
      onClose={() => setModal(null)}
    >
      {({ startDrag: startRwDrag }) => (<>
        {/* Header — draggable, glass gradient */}
        <div onMouseDown={startRwDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.danger}33, ${th.danger}11)`, border: `1px solid ${th.danger}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.danger} strokeWidth="1.8" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.danger) + "18"}/><rect x="10" y="9" width="4" height="5" rx="1"/><circle cx="12" cy="7.5" r="2.5" fill="none"/></svg>
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>Ransomware MFT Analysis</h3>
              <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>Identify encrypted files, ransom notes, and suspicious activity</p>
            </div>
          </div>
          <button onClick={() => setModal(null)} style={{ background: `${th.border}22`, border: `1px solid ${th.border}33`, color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "4px 8px", borderRadius: 6, lineHeight: 1 }}>{"\u2715"}</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
          {/* Input phase */}
          {phase === "input" && (<>
            {/* MFT format warning */}
            {ct?.sourceFormat && ct.sourceFormat !== "raw-mft" && (
              <div style={{ marginBottom: 10, padding: "8px 12px", background: `${th.warning}0a`, border: `1px solid ${th.warning}22`, borderRadius: 8, fontSize: 10, color: th.warning, fontFamily: "-apple-system, sans-serif" }}>
                This tab was not imported as raw MFT data. Results may be unreliable — timestamps and columns may not match MFT semantics.
              </div>
            )}
            {/* Auto-detect scan */}
            {!scanData && (
              <div style={{ marginBottom: 14, padding: "14px 16px", background: `linear-gradient(135deg, ${th.accent}08, ${th.panelBg}cc)`, border: `1px solid ${th.accent}22`, borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Auto-detect ransomware indicators</div>
                  <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 2 }}>Scan MFT for suspicious extensions and ransom note patterns</div>
                </div>
                <button onClick={handleScan} style={{ ...ms.bp, borderRadius: 8, fontSize: 11, padding: "6px 16px" }}>Scan MFT</button>
              </div>
            )}

            {/* Scan results — extension candidates (multi-select) */}
            {scanData?.candidates?.length > 0 && (() => {
              const selExts = new Set(encryptedExt.split(/[,;|]+/).map(s => s.trim()).filter(Boolean).map(s => s.startsWith(".") ? s : "." + s));
              const toggleExt = (ext) => setModal((p) => {
                const cur = new Set((p.encryptedExt || "").split(/[,;|]+/).map(s => s.trim()).filter(Boolean).map(s => s.startsWith(".") ? s : "." + s));
                if (cur.has(ext)) cur.delete(ext); else cur.add(ext);
                return { ...p, encryptedExt: [...cur].join(", ") };
              });
              return (
              <div style={{ marginBottom: 14 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Detected Encrypted Extensions</span>
                  {selExts.size > 1 && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{selExts.size} selected</span>}
                </div>
                <div style={{ maxHeight: 180, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                  {scanData.candidates.map((c, i) => {
                    const sel = selExts.has(c.extension);
                    const scoreColor = c.score >= 0.7 ? (th.danger) : c.score >= 0.4 ? (th.warning) : th.accent;
                    return (
                      <div key={i} onClick={() => toggleExt(c.extension)}
                        style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 12px", fontSize: 11, borderBottom: `1px solid ${th.border}15`, cursor: "pointer", background: sel ? `${th.accent}12` : (i % 2 === 0 ? "transparent" : `${th.border}08`), transition: "all var(--m-base)" }}>
                        <div style={{ width: 14, height: 14, borderRadius: 4, flexShrink: 0, background: sel ? th.accent : "transparent", border: `1.5px solid ${sel ? th.accent : th.border}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                          {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                        </div>
                        <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 9, fontWeight: 700, background: `${scoreColor}22`, color: scoreColor, fontFamily: "'SF Mono',Menlo,monospace", minWidth: 28, textAlign: "center" }}>{Math.round(c.score * 100)}</span>
                        <span style={{ fontFamily: "'SF Mono',Menlo,monospace", fontWeight: 600, color: th.text, minWidth: 80 }}>{c.extension}</span>
                        {c.family && <span title={`Matches the ${c.family} ransomware family signature`} style={{ padding: "1px 6px", borderRadius: 4, fontSize: 8.5, fontWeight: 700, background: th.danger + "1f", color: th.danger, border: `1px solid ${th.danger}44`, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.03em", flexShrink: 0 }}>{c.family}</span>}
                        <span style={{ color: th.textDim, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>{c.fileCount.toLocaleString()} files</span>
                        {c.peakMinuteCount > 0 && <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace" }}>peak {c.peakMinuteCount.toLocaleString()}/min</span>}
                        {c.samplePaths?.[0] && <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0, textAlign: "right" }}>{c.samplePaths[0]}</span>}
                      </div>
                    );
                  })}
                </div>
              </div>
              );
            })()}

            {/* Scan results — ransom note candidates */}
            {scanData?.noteCandidates?.length > 0 && (
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: th.warning, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif", marginBottom: 6 }}>Detected Ransom Note Patterns</div>
                <div style={{ maxHeight: 130, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                  {scanData.noteCandidates.map((n, i) => {
                    const sel = ransomNotePattern === n.fileName;
                    return (
                      <div key={i} onClick={() => setModal((p) => ({ ...p, ransomNotePattern: n.fileName }))}
                        style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", fontSize: 11, borderBottom: `1px solid ${th.border}15`, cursor: "pointer", background: sel ? `${(th.warning)}12` : (i % 2 === 0 ? "transparent" : `${th.border}08`) }}>
                        <span style={{ fontFamily: "'SF Mono',Menlo,monospace", fontWeight: 600, color: th.text, minWidth: 120 }}>{n.fileName}</span>
                        <span style={{ color: th.textDim, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>{n.dirCount} dirs</span>
                        {n.timeSpanMinutes != null && <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace" }}>{n.timeSpanMinutes < 60 ? `${n.timeSpanMinutes} min` : n.timeSpanMinutes < 1440 ? `${Math.round(n.timeSpanMinutes / 60)}h` : `${Math.round(n.timeSpanMinutes / 1440)}d`} span</span>}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* No candidates found message */}
            {scanData && scanData.candidates?.length === 0 && (
              <div style={{ marginBottom: 14, padding: "10px 14px", background: `${(th.success)}08`, border: `1px solid ${(th.success)}22`, borderRadius: 8, fontSize: 11, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>No suspicious extensions detected — enter extension manually below.</div>
            )}

            {/* Manual input — always shown, acts as override */}
            <div style={{ marginBottom: 10, padding: scanData ? "10px 0 0" : 0, borderTop: scanData ? `1px solid ${th.border}22` : "none" }}>
              {scanData && <div style={{ fontSize: 9, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif", marginBottom: 6 }}>Manual Override</div>}
              <div style={ms.fg}>
                <label style={ms.lb}>Encrypted File Extension</label>
                <input value={encryptedExt} onChange={(e) => setModal((p) => ({ ...p, encryptedExt: e.target.value }))}
                  onKeyDown={(e) => { if (e.key === "Enter" && encryptedExt.trim()) handleAnalyze(); }}
                  placeholder=".locked  or  .locked, .encrypted" style={ms.ip} autoFocus={!scanData} />
                {!scanData && (
                  <div style={{ display: "flex", gap: 4, marginTop: 6, flexWrap: "wrap" }}>
                    {[".locked", ".encrypted", ".enc", ".crypt", ".WNCRY", ".cerber", ".locky", ".ryuk"].map((ext) => (
                      <button key={ext} onClick={() => setModal((p) => ({ ...p, encryptedExt: ext }))}
                        style={{ padding: "3px 8px", background: encryptedExt === ext ? th.accent : th.btnBg, color: encryptedExt === ext ? "#fff" : th.textDim, border: `1px solid ${encryptedExt === ext ? th.accent : th.btnBorder}`, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "'SF Mono',Menlo,monospace" }}>
                        {ext}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div style={ms.fg}>
                <label style={ms.lb}>Ransom Note Filename (optional)</label>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <input value={ransomNotePattern} onChange={(e) => setModal((p) => ({ ...p, ransomNotePattern: e.target.value }))}
                    onKeyDown={(e) => { if (e.key === "Enter" && encryptedExt.trim()) handleAnalyze(); }}
                    placeholder={modal.noteMatchMode === "multi" ? "README.txt, DECRYPT.html" : modal.noteMatchMode === "regex" ? "README.*\\.txt" : "README.txt"} style={{ ...ms.ip, flex: 1 }} />
                  <select value={modal.noteMatchMode || "exact"} onChange={(e) => setModal((p) => ({ ...p, noteMatchMode: e.target.value }))} style={{ ...ms.sl, width: 110, fontSize: 10, padding: "4px 6px" }}>
                    <option value="exact">Exact</option>
                    <option value="contains">Contains</option>
                    <option value="regex">Regex</option>
                    <option value="multi">Multiple</option>
                  </select>
                </div>
              </div>
              {(() => { return usnTabs.length > 0 ? (
                <div style={ms.fg}>
                  <label style={ms.lb}>USN Journal Tab (optional enrichment)</label>
                  <select value={modal.usnTabId || "__none__"} onChange={(e) => setModal((p) => ({ ...p, usnTabId: e.target.value || "__none__" }))} style={ms.sl}>
                    <option value="__none__">None</option>
                    {usnTabs.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                </div>
              ) : (
                <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", fontStyle: "italic", marginTop: 2 }}>Load a USN Journal ($J) for more precise encryption timing</div>
              ); })()}
            </div>
            {modal.error && <div style={{ color: th.danger, fontSize: 11, padding: "8px 10px", background: `${th.danger}15`, borderRadius: 6, marginBottom: 10 }}>Error: {modal.error}</div>}
          </>)}

          {/* Scanning phase */}
          {phase === "scanning" && (
            <div style={{ textAlign: "center", padding: "60px 40px", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1 }}>
              <div style={{ width: 56, height: 56, borderRadius: 14, background: `linear-gradient(135deg, ${th.accent}22, ${th.accent}08)`, border: `1px solid ${th.accent}22`, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" style={{ animation: "tle-pulse 2s ease-in-out infinite" }}>
                  <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
              </div>
              <div style={{ color: th.text, fontSize: 13, fontWeight: 600, fontFamily: "-apple-system, sans-serif", marginBottom: 4 }}>Scanning MFT</div>
              <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif", marginBottom: 16 }}>{modal.rwProgress?.detail || "Detecting ransomware indicators..."}</div>
              <div style={{ width: 280, maxWidth: "100%" }}>
                <div style={{ height: 6, background: th.border, borderRadius: 3, overflow: "hidden", marginBottom: 8 }}>
                  <div style={{ height: "100%", width: "100%", background: th.accent, borderRadius: 3, transformOrigin: "left", transform: `scaleX(${Math.min((modal.rwProgress?.pct || 0) / 100, 1)})`, transition: "transform var(--m-slow) ease" }} />
                </div>
                <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace" }}>{modal.rwProgress?.pct || 0}%</div>
              </div>
            </div>
          )}

          {/* Loading phase */}
          {phase === "loading" && (
            <div style={{ textAlign: "center", padding: "60px 40px", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1 }}>
              <div style={{ width: 56, height: 56, borderRadius: 14, background: `linear-gradient(135deg, ${th.danger}22, ${th.danger}08)`, border: `1px solid ${th.danger}22`, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke={th.danger} strokeWidth="1.5" style={{ animation: "tle-pulse 2s ease-in-out infinite" }}>
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.danger) + "18"} />
                </svg>
              </div>
              <div style={{ color: th.text, fontSize: 13, fontWeight: 600, fontFamily: "-apple-system, sans-serif", marginBottom: 4 }}>Analyzing MFT</div>
              <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif", marginBottom: 16 }}>{modal.rwProgress?.detail || "Scanning for ransomware activity..."}</div>
              <div style={{ width: 280, maxWidth: "100%" }}>
                <div style={{ height: 6, background: th.border, borderRadius: 3, overflow: "hidden", marginBottom: 8 }}>
                  <div style={{ height: "100%", width: "100%", background: th.danger, borderRadius: 3, transformOrigin: "left", transform: `scaleX(${Math.min((modal.rwProgress?.pct || 0) / 100, 1)})`, transition: "transform var(--m-slow) ease" }} />
                </div>
                <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace" }}>{modal.rwProgress?.pct || 0}%</div>
              </div>
            </div>
          )}

          {/* Results phase */}
          {phase === "results" && data && (<>
            {data.encryptedCount === 0 ? (
              <div style={{ textAlign: "center", padding: "60px 20px", display: "flex", flexDirection: "column", alignItems: "center" }}>
                <div style={{ width: 56, height: 56, borderRadius: 14, background: `linear-gradient(135deg, ${th.success}22, ${th.success}08)`, border: `1px solid ${th.success}22`, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke={th.success} strokeWidth="2.5" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>
                </div>
                <div style={{ color: th.text, fontSize: 14, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>No encrypted files found</div>
                <p style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif", marginTop: 4 }}>No files with extension <span style={{ fontFamily: "'SF Mono',Menlo,monospace", color: th.accent }}>{encryptedExt}</span> were detected in this MFT.</p>
              </div>
            ) : (<>
              {/* Section 0a: Incident Verdict — auto-computed severity + narrative */}
              {data.incidentSummary && (() => {
                const s = data.incidentSummary;
                const sevColor = s.severity === "Critical" ? th.danger : s.severity === "High" ? th.warning : s.severity === "Medium" ? th.accent : th.textMuted;
                return (
                  <div style={{ marginBottom: 14, padding: "14px 16px", background: `linear-gradient(135deg, ${sevColor}1c, ${th.panelBg}ee)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 12, border: `1px solid ${sevColor}44` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                      <span style={{ padding: "3px 11px", background: sevColor, color: "#fff", borderRadius: 6, fontSize: 11, fontWeight: 800, fontFamily: "-apple-system, sans-serif", letterSpacing: "0.04em", textTransform: "uppercase" }}>{s.severity}</span>
                      <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700 }}>Incident Verdict</span>
                    </div>
                    <div style={{ fontSize: 13, color: th.text, fontFamily: "-apple-system, sans-serif", lineHeight: 1.55 }}>{s.narrative}</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
                      {(s.factors || []).map((f, i) => (
                        <span key={i} style={{ display: "inline-flex", alignItems: "baseline", gap: 5, padding: "3px 9px", background: `${th.modalBg}aa`, border: `1px solid ${th.border}44`, borderRadius: 6, fontFamily: "-apple-system, sans-serif" }}>
                          <span style={{ color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", fontSize: 8.5, fontWeight: 700 }}>{f.label}</span>
                          <span style={{ color: th.text, fontWeight: 600, fontSize: 10.5 }}>{f.value}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })()}

              {/* Section 0a-2: Threat Attribution — family + MITRE ATT&CK */}
              {(data.familyAttribution || (data.mitreTechniques && data.mitreTechniques.length > 0)) && (() => {
                const fa = data.familyAttribution;
                const top = fa?.top;
                const confColor = top?.confidence === "confirmed" ? th.danger : top?.confidence === "high" ? th.warning : th.textMuted;
                const openMitre = (url) => { if (window.tle?.openExternal) window.tle.openExternal(url); else window.open(url, "_blank"); };
                return (
                  <div style={{ marginBottom: 14, padding: "12px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 12, border: `1px solid ${th.border}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: data.mitreTechniques?.length ? 9 : 0, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Threat Attribution</span>
                      {top ? (<>
                        <span style={{ fontSize: 14, fontWeight: 800, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{top.name}</span>
                        {top.aka && <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>({top.aka})</span>}
                        <span style={{ padding: "1px 8px", background: confColor + "22", color: confColor, border: `1px solid ${confColor}44`, borderRadius: 5, fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>{top.confidence}</span>
                        <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", fontStyle: "italic" }}>matched on {top.matchedOn.join(" + ")}{top.evidence?.length ? ` (${top.evidence.join(", ")})` : ""}</span>
                        {fa.candidates?.length > 1 && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>· other: {fa.candidates.slice(1).map((c) => c.name).join(", ")}</span>}
                      </>) : (
                        <span style={{ fontSize: 11, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{fa?.note || "No known-family signature matched — attribute manually."}</span>
                      )}
                    </div>
                    {data.mitreTechniques?.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {data.mitreTechniques.map((t) => (
                          <span key={t.id + t.name} onClick={() => openMitre(t.url)} title={`${t.name} — ${t.basis}\nOpen on attack.mitre.org`}
                            style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: "3px 9px", background: `${th.accent}14`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 6, fontSize: 10, fontFamily: "-apple-system, sans-serif", cursor: "pointer", fontWeight: 600, transition: "background var(--m-base) var(--ease-out)" }}
                            onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}24`; }}
                            onMouseLeave={(e) => { e.currentTarget.style.background = `${th.accent}14`; }}>
                            <span style={{ fontFamily: "'SF Mono',Menlo,monospace", fontWeight: 700 }}>{t.id}</span>
                            <span style={{ color: th.textDim, fontWeight: 500 }}>{t.name}</span>
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Section 0b: Recovery Prospects */}
              {data.recoveryProspects && (() => {
                const r = data.recoveryProspects;
                const oc = (r.outlook || "").startsWith("Low") ? th.danger : r.outlook === "Moderate" ? th.warning : r.outlook === "Indeterminate" ? th.textMuted : th.success;
                const viaColor = (v) => v === "Viable" ? th.success : v === "Verify" ? th.warning : v === "On-host compromised" ? th.danger : v === "Limited" ? th.warning : th.textMuted;
                return (
                  <div style={{ marginBottom: 16, padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 12, border: `1px solid ${th.border}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Recovery Prospects</span>
                      <span style={{ padding: "2px 9px", background: oc + "22", color: oc, border: `1px solid ${oc}44`, borderRadius: 6, fontSize: 10, fontWeight: 800, fontFamily: "-apple-system, sans-serif", letterSpacing: "0.04em" }}>{r.outlook}</span>
                      <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", fontStyle: "italic" }}>method: {r.method}</span>
                    </div>
                    <div style={{ fontSize: 11.5, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5, marginBottom: 10 }}>{r.outlookReason}</div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6, marginBottom: 10 }}>
                      {[
                        { v: r.carvableCount, l: "carvable (deleted orig.)", c: th.success },
                        { v: r.residentRecoverableCount, l: "MFT-resident est.", c: th.accent },
                        { v: r.overwrittenCount, l: "overwritten on-host", c: th.danger },
                      ].map((x, i) => (
                        <div key={i} style={{ textAlign: "center", padding: "8px 6px", background: `${th.modalBg}88`, borderRadius: 8, border: `1px solid ${x.c}22` }}>
                          <div style={{ fontSize: 16, fontWeight: 700, color: x.c, fontFamily: "-apple-system, sans-serif", lineHeight: 1 }}>{(x.v || 0).toLocaleString()}</div>
                          <div style={{ fontSize: 8, color: th.textMuted, marginTop: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>{x.l}</div>
                        </div>
                      ))}
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                      {(r.avenues || []).map((a, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8, fontSize: 10.5, fontFamily: "-apple-system, sans-serif" }}>
                          <span style={{ flexShrink: 0, marginTop: 1, padding: "1px 7px", borderRadius: 5, fontSize: 8.5, fontWeight: 700, background: viaColor(a.viability) + "1f", color: viaColor(a.viability), border: `1px solid ${viaColor(a.viability)}44`, minWidth: 96, textAlign: "center" }}>{a.viability}</span>
                          <span style={{ color: th.textDim, lineHeight: 1.45 }}><strong style={{ color: th.text }}>{a.name}.</strong> {a.detail}</span>
                        </div>
                      ))}
                    </div>
                    <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", fontStyle: "italic", marginTop: 8 }}>{r.caveat}</div>
                  </div>
                );
              })()}

              {/* Section 0c: Consolidated Incident Timeline — payloads / notes / encryption / USN on one axis */}
              {data.incidentTimeline && (() => {
                const tl = data.incidentTimeline;
                const W = 1000, H = 150;
                const span = Math.max(60000, tl.endMs - tl.startMs);
                const X = (ms) => ((ms - tl.startMs) / span) * W;
                const Xc = (ms) => Math.max(0, Math.min(W, X(ms))); // clamped for marker lines (onset may precede the first data bucket)
                const maxOf = (arr) => arr.reduce((m, p) => Math.max(m, p.count), 0) || 1;
                const encMax = tl.peakCount || 1;
                const usnMax = Math.max(maxOf(tl.deletes), maxOf(tl.overwrites));
                const ENC_TOP = 6, ENC_H = 56, ENC_BASE = ENC_TOP + ENC_H;
                const EV_Y = 80, USN_TOP = 94, USN_H = 28, USN_BASE = USN_TOP + USN_H, AXIS_Y = 124;
                const colEnc = th.danger, colNote = th.warning, colPay = "#a855f7", colOv = th.accent;
                const pad = (n) => String(n).padStart(2, "0");
                const clock = (ms) => { const d = new Date(ms); return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`; };
                const full = (ms) => { const d = new Date(ms); return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`; };
                return (
                  <div style={{ marginBottom: 16, padding: "12px 16px 10px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 12, border: `1px solid ${th.border}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Incident Timeline</span>
                      {[["Encryption", colEnc], ["Ransom notes", colNote], ["Payload drops", colPay], ["USN deletes", th.danger], ["USN overwrites", colOv]].map(([l, c]) => (
                        <span key={l} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 9, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}><span style={{ width: 8, height: 8, borderRadius: 2, background: c }} />{l}</span>
                      ))}
                    </div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <div style={{ width: 60, flexShrink: 0, position: "relative", height: H, fontSize: 8.5, color: th.textMuted, fontFamily: "-apple-system, sans-serif", textAlign: "right" }}>
                        <div style={{ position: "absolute", top: ENC_TOP + ENC_H / 2 - 8, right: 0, lineHeight: 1.15 }}>Encryption<br /><span style={{ color: th.textDim }}>{(tl.peakCount || 0).toLocaleString()}/min</span></div>
                        <div style={{ position: "absolute", top: EV_Y - 6, right: 0 }}>Events</div>
                        <div style={{ position: "absolute", top: USN_TOP + USN_H / 2 - 6, right: 0 }}>USN</div>
                      </div>
                      <div style={{ flex: 1, position: "relative", minWidth: 0 }}>
                        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ width: "100%", height: H, display: "block", overflow: "visible" }}>
                          <line x1="0" y1={ENC_BASE} x2={W} y2={ENC_BASE} stroke={th.border} strokeWidth="1" opacity="0.4" />
                          <line x1="0" y1={EV_Y} x2={W} y2={EV_Y} stroke={th.border} strokeWidth="0.5" opacity="0.25" />
                          <line x1="0" y1={USN_BASE} x2={W} y2={USN_BASE} stroke={th.border} strokeWidth="1" opacity="0.4" />
                          {tl.onsetMs != null && <line x1={Xc(tl.onsetMs)} y1="0" x2={Xc(tl.onsetMs)} y2={AXIS_Y} stroke={th.danger} strokeWidth="1.2" strokeDasharray="3 3" opacity="0.85" />}
                          {tl.peakMs != null && <line x1={Xc(tl.peakMs)} y1="0" x2={Xc(tl.peakMs)} y2={AXIS_Y} stroke={th.warning} strokeWidth="1" strokeDasharray="2 3" opacity="0.7" />}
                          {tl.encryption.map((b, i) => { const h = (b.count / encMax) * ENC_H; return <rect key={"e" + i} x={X(b.ms) - 1} y={ENC_BASE - h} width="2" height={h} fill={colEnc} opacity="0.85" />; })}
                          {tl.overwrites.map((b, i) => { const h = (b.count / usnMax) * USN_H; return <rect key={"o" + i} x={X(b.ms) - 1.6} y={USN_BASE - h} width="1.6" height={h} fill={colOv} opacity="0.8" />; })}
                          {tl.deletes.map((b, i) => { const h = (b.count / usnMax) * USN_H; return <rect key={"d" + i} x={X(b.ms) + 0.2} y={USN_BASE - h} width="1.6" height={h} fill={th.danger} opacity="0.7" />; })}
                          {tl.payloads.map((b, i) => <rect key={"p" + i} x={X(b.ms) - 0.8} y={EV_Y - 9} width="1.6" height="8" fill={colPay} />)}
                          {tl.notes.map((b, i) => <rect key={"n" + i} x={X(b.ms) - 0.8} y={EV_Y + 1} width="1.6" height="8" fill={colNote} />)}
                        </svg>
                        <div style={{ position: "relative", height: 12, marginTop: 2 }}>
                          {[0, 0.25, 0.5, 0.75, 1].map((f) => (
                            <span key={f} style={{ position: "absolute", left: `${f * 100}%`, transform: f === 0 ? "none" : f === 1 ? "translateX(-100%)" : "translateX(-50%)", fontSize: 8.5, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", whiteSpace: "nowrap" }}>{clock(tl.startMs + f * span)}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                    <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 4 }}>
                      <span style={{ color: th.danger, fontWeight: 600 }}>Onset</span> {tl.onsetMs != null ? full(tl.onsetMs) : "—"}
                      {tl.peakMs != null && <> · <span style={{ color: th.warning, fontWeight: 600 }}>Peak</span> {clock(tl.peakMs)} ({(tl.peakCount || 0).toLocaleString()}/min)</>}
                      {tl.endEncMs != null && <> · <span style={{ fontWeight: 600 }}>End</span> {clock(tl.endEncMs)}</>}
                      {" "}UTC
                    </div>
                  </div>
                );
              })()}

              {/* Section 1: Summary Stats */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6, marginBottom: 16 }}>
                {[
                  { val: (data.encryptedCount || 0).toLocaleString(), label: "encrypted files", color: th.danger },
                  { val: fmtBytes(data.totalEncryptedSizeBytes), label: "total size", color: th.accent },
                  { val: fmtDur(data.durationMinutes), label: "duration", color: th.warning },
                  { val: (data.filesPerMinute || 0).toFixed(1), label: "files/min", color: th.accent },
                ].map((c, i) => (
                  <div key={i} style={{ textAlign: "center", padding: "12px 8px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 10, border: `1px solid ${th.border}33` }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.5px", lineHeight: 1 }}>{c.val}</div>
                    <div style={{ fontSize: 9, color: c.color + "bb", marginTop: 4, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{c.label}</div>
                  </div>
                ))}
              </div>

              {/* Section 2: First/Last Encrypted */}
              {data.firstEncrypted && data.lastEncrypted && (
                <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                  {[
                    { label: "First Encrypted", data: data.firstEncrypted, color: th.danger },
                    { label: "Last Encrypted", data: data.lastEncrypted, color: th.warning },
                  ].map((card) => (
                    <div key={card.label} style={{ flex: 1, minWidth: 0, padding: "12px 14px", background: `linear-gradient(135deg, ${card.color}08, ${th.panelBg}ee)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)", borderRadius: 10, border: `1px solid ${card.color}22`, overflow: "hidden" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                        <span style={{ padding: "2px 8px", background: `linear-gradient(135deg, ${card.color}33, ${card.color}15)`, color: card.color, borderRadius: 6, fontSize: 9, fontWeight: 700, fontFamily: "-apple-system, sans-serif", letterSpacing: "0.05em", textTransform: "uppercase" }}>{card.label}</span>
                      </div>
                      <div style={{ fontSize: 13, color: th.text, fontWeight: 600, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.2px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{card.data.fileName}</div>
                      <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", marginTop: 3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{card.data.parentPath}</div>
                      <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", marginTop: 2 }}>{card.data.timestamp}</div>
                    </div>
                  ))}
                </div>
              )}

              {data.timingEvidence && (() => {
                const te = data.timingEvidence;
                const renderTimingCard = (title, snap, color) => (
                  <div style={{ minWidth: 0, padding: "10px 12px", background: `linear-gradient(135deg, ${color}08, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${color}22` }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                      <span style={{ fontSize: 9, fontWeight: 700, color, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>{title}</span>
                      {snap?.skewMinutes > 0 && <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>skew {snap.skewMinutes}m</span>}
                    </div>
                    <div style={{ display: "grid", gap: 4 }}>
                      {(snap?.sources || []).map((src) => (
                        <div key={`${title}-${src.column}-${src.label}`} style={{ display: "grid", gridTemplateColumns: "96px 1fr", gap: 8, fontSize: 10, alignItems: "baseline" }}>
                          <span style={{ color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{src.label}</span>
                          <span style={{ color: th.text, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{src.timestamp}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
                return (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1.05fr 1fr 1fr", gap: 8 }}>
                      <div style={{ minWidth: 0, padding: "10px 12px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, borderRadius: 10, border: `1px solid ${th.border}33` }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif", marginBottom: 8 }}>Timestamp Evidence</div>
                        {te.timelineBasis && (
                          <div style={{ marginBottom: 8 }}>
                            <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Timeline</div>
                            <div style={{ fontSize: 11, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{te.timelineBasis.label} ({te.timelineBasis.column})</div>
                          </div>
                        )}
                        {te.suspiciousWindowBasis?.timestamp && (
                          <div style={{ marginBottom: 8 }}>
                            <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Payload Anchor</div>
                            <div style={{ fontSize: 11, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{te.suspiciousWindowBasis.label} ({te.suspiciousWindowBasis.column})</div>
                            <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", marginTop: 2 }}>{te.suspiciousWindowBasis.timestamp}</div>
                          </div>
                        )}
                        {te.filterWindow?.from && te.filterWindow?.to && (
                          <div>
                            <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Grid Filter Window</div>
                            <div style={{ fontSize: 10, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{te.filterWindow.column}</div>
                            <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", marginTop: 2 }}>{te.filterWindow.from} {"->"} {te.filterWindow.to}</div>
                          </div>
                        )}
                      </div>
                      {renderTimingCard("Encryption Start", te.start, th.danger)}
                      {renderTimingCard("Encryption End", te.end, th.warning)}
                    </div>
                  </div>
                );
              })()}

              {/* Section 2b: First Encrypted Files (Encryption Spread) */}
              {data.firstEncryptedFiles?.length > 0 && (() => {
                const shown = data.firstEncryptedFiles;
                const selF = modal.rwSelFirst || new Set();
                const allF = selF.size === shown.length;
                const defFirstW = [60, 140, 240, 140, 70];
                const firstW = modal.rwFirstColW || defFirstW;
                const fmtSz = (b) => { const n = parseInt(b) || 0; if (n < 1024) return `${n} B`; if (n < 1048576) return `${(n/1024).toFixed(1)} KB`; return `${(n/1048576).toFixed(1)} MB`; };
                return (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <div onClick={() => toggleAll("rwSelFirst", shown.length)} style={cbStyle(allF)}>
                        {allF && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                      </div>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Encryption Spread — First {shown.length} Files</span>
                    </div>
                  </div>
                  <div style={{ maxHeight: 220, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                      <div style={{ width: 14, flexShrink: 0 }} />
                      {rwHdrCol(firstW[0], "Entry#", "rwSortFirst", "entryNumber", "rwFirstColW", defFirstW, 0)}
                      {rwHdrCol(firstW[1], "FileName", "rwSortFirst", "fileName", "rwFirstColW", defFirstW, 1)}
                      <div style={{ flex: 1, display: "flex", alignItems: "center", cursor: "pointer", userSelect: "none" }} onClick={() => handleRwSort("rwSortFirst", "parentPath")}>ParentPath{rwSortArrow("rwSortFirst", "parentPath")}</div>
                      {rwHdrCol(firstW[3], "Timestamp", "rwSortFirst", "timestamp", "rwFirstColW", defFirstW, 3)}
                      {rwHdrCol(firstW[4], "Size", "rwSortFirst", "fileSize", "rwFirstColW", defFirstW, 4)}
                    </div>
                    {sortRwArr(shown, modal.rwSortFirst).map((f, i) => {
                      const sel = selF.has(i);
                      const isExp = modal.rwExpandedRow?.section === "first" && modal.rwExpandedRow?.idx === i;
                      return (<Fragment key={i}>
                      <div onClick={() => toggleSet("rwSelFirst", i)} style={{ ...rowStyle(i), background: sel ? `${th.accent}0a` : (i % 2 === 0 ? "transparent" : `${th.border}0a`), borderBottom: `1px solid ${th.border}15`, cursor: "pointer" }}>
                        <div style={cbStyle(sel)}>
                          {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                        </div>
                        <span onClick={(e) => { e.stopPropagation(); setModal((p) => ({ ...p, rwExpandedRow: isExp ? null : { section: "first", idx: i } })); }} style={{ width: firstW[0], flexShrink: 0, color: th.accent, fontWeight: 600, fontSize: 10, cursor: "pointer", textDecoration: "underline", textDecorationStyle: "dotted" }}>#{f.entryNumber}</span>
                        <span style={{ width: firstW[1], flexShrink: 0, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.fileName}</span>
                        <span style={{ flex: 1, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.parentPath}</span>
                        <span style={{ width: firstW[3], flexShrink: 0, color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{(f.timestamp || "").slice(0, 19)}</span>
                        <span style={{ width: firstW[4], flexShrink: 0, color: th.textMuted, fontSize: 10, textAlign: "right" }}>{f.fileSize != null ? fmtSz(f.fileSize) : ""}</span>
                      </div>
                      {isExp && (
                        <div style={{ padding: "6px 10px 6px 42px", background: `${th.panelBg}dd`, borderBottom: `1px solid ${th.border}22`, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", color: th.textDim }}>
                          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2px 16px" }}>
                            <span>Created (SI): {f.created0x10 || "\u2014"}</span><span>Modified (SI): {f.timestamp || "\u2014"}</span>
                            <span>Record Change: {f.recordChange0x10 || "\u2014"}</span><span>Created (FN): {f.created0x30 || "\u2014"}</span>
                            <span>Modified (FN): {f.lastMod0x30 || "\u2014"}</span>
                          </div>
                        </div>
                      )}
                      </Fragment>);
                    })}
                  </div>
                </div>
                );
              })()}

              {/* Section 2c: Original-to-Encrypted Pair Detection */}
              {data.originalPairs && (data.originalPairs.confirmedPairs > 0 || data.originalPairs.likelyPairs > 0) && (() => {
                const op = data.originalPairs;
                const rateColor = op.pairRate >= 0.8 ? (th.danger) : op.pairRate >= 0.5 ? (th.warning) : th.accent;
                const shownPairs = op.samplePairs || [];
                const selP = modal.rwSelPairs || new Set();
                const allP = selP.size === shownPairs.length;
                return (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Original-to-Encrypted Pair Detection</span>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6, marginBottom: 8 }}>
                    <div style={{ textAlign: "center", padding: "8px 6px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, borderRadius: 8, border: `1px solid ${th.border}33` }}>
                      <div style={{ fontSize: 18, fontWeight: 700, color: th.danger, fontFamily: "-apple-system, sans-serif", lineHeight: 1 }}>{op.sampled ? "~" : ""}{formatNumber(op.confirmedPairs)}</div>
                      <div style={{ fontSize: 8, color: th.textMuted, marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{op.sampled ? "estimated " : ""}confirmed pairs</div>
                    </div>
                    <div style={{ textAlign: "center", padding: "8px 6px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, borderRadius: 8, border: `1px solid ${th.border}33` }}>
                      <div style={{ fontSize: 18, fontWeight: 700, color: th.warning, fontFamily: "-apple-system, sans-serif", lineHeight: 1 }}>{op.sampled ? "~" : ""}{formatNumber(op.likelyPairs)}</div>
                      <div style={{ fontSize: 8, color: th.textMuted, marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{op.sampled ? "estimated " : ""}likely pairs</div>
                    </div>
                    <div style={{ textAlign: "center", padding: "8px 6px", background: `linear-gradient(160deg, ${rateColor}08, ${th.panelBg}cc)`, borderRadius: 8, border: `1px solid ${rateColor}33` }}>
                      <div style={{ fontSize: 18, fontWeight: 700, color: rateColor, fontFamily: "-apple-system, sans-serif", lineHeight: 1 }}>{Math.round(op.pairRate * 100)}%</div>
                      <div style={{ fontSize: 8, color: rateColor + "bb", marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{op.sampled ? "sample " : ""}pair rate</div>
                    </div>
                  </div>
                  {op.sampled && (
                    <div style={{ fontSize: 9, color: th.textMuted, fontStyle: "italic", marginBottom: 8, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>
                      Estimated by extrapolation from a {formatNumber(op.sampleSize || 0)}-row sample of {formatNumber(op.samplePopulation || 0)} encrypted files
                      {(op.confirmedSampleCount != null) && ` (${op.confirmedSampleCount} confirmed + ${op.likelySampleCount} likely in sample)`}.
                      Counts are rounded to nearest 100; ±confidence depends on sample uniformity.
                    </div>
                  )}
                  {shownPairs.length > 0 && (
                  <div style={{ maxHeight: 160, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                      <div style={{ width: 14, flexShrink: 0 }} />
                      <div style={{ width: 130, flexShrink: 0 }}>Original</div>
                      <div style={{ width: 150, flexShrink: 0 }}>Encrypted</div>
                      <div style={{ flex: 1 }}>Path</div>
                      <div style={{ width: 55, flexShrink: 0 }}>Status</div>
                    </div>
                    {shownPairs.slice(0, 30).map((p, i) => {
                      const sel = selP.has(i);
                      return (
                      <div key={i} onClick={() => toggleSet("rwSelPairs", i)} style={{ ...rowStyle(i), background: sel ? `${th.accent}0a` : (i % 2 === 0 ? "transparent" : `${th.border}0a`), borderBottom: `1px solid ${th.border}15`, cursor: "pointer" }}>
                        <div style={cbStyle(sel)}>
                          {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                        </div>
                        <span style={{ width: 130, flexShrink: 0, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 10 }}>{p.originalFile}</span>
                        <span style={{ width: 150, flexShrink: 0, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 10 }}>{p.encryptedFile}</span>
                        <span style={{ flex: 1, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 10 }}>{p.parentPath}</span>
                        <span style={{ width: 55, flexShrink: 0 }}>
                          <span style={{ padding: "1px 5px", borderRadius: 4, fontSize: 8, fontWeight: 700, color: "#fff", background: p.originalDeleted ? (th.danger) : (th.warning) }}>{p.originalDeleted ? "DELETED" : "ABSENT"}</span>
                        </span>
                      </div>
                      );
                    })}
                  </div>
                  )}
                </div>
                );
              })()}

              {/* Section 3: Forensic Indicators — with observed/inferred labels */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6, marginBottom: 8 }}>
                {[
                  { val: data.ransomNoteCount, label: "ransom notes", color: data.ransomNoteCount > 0 ? (th.warning) : th.textDim, active: data.ransomNoteCount > 0 },
                  { val: data.deletedEncrypted, label: "deleted encrypted", color: data.deletedEncrypted > 0 ? (th.danger) : th.textDim, active: data.deletedEncrypted > 0 },
                  { val: data.timestompedCount, label: "timestomped", color: data.timestompedCount > 0 ? (th.danger) : th.textDim, active: data.timestompedCount > 0 },
                  { val: (data.suspiciousFiles || []).length, label: "suspicious exes", color: (data.suspiciousFiles || []).length > 0 ? (th.danger) : th.textDim, active: (data.suspiciousFiles || []).length > 0 },
                ].map((c, i) => (
                  <div key={i} style={{ textAlign: "center", padding: "10px 6px", background: c.active ? `linear-gradient(160deg, ${c.color}12, ${th.panelBg}cc)` : `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 10, border: `1px solid ${c.active ? c.color + "33" : th.border + "33"}` }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.5px", lineHeight: 1 }}>{c.val}</div>
                    <div style={{ fontSize: 9, color: c.active ? c.color + "bb" : th.textMuted, marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{c.label}</div>
                  </div>
                ))}
              </div>
              {/* Forensic indicator pills — observed vs inferred */}
              {data.forensicIndicators?.length > 0 && (
                <div style={{ marginBottom: 16, padding: "8px 12px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Evidence</span>
                    <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                      <span style={{ color: th.accent }}>{"\u25CF"}</span> Observed
                      <span style={{ margin: "0 4px" }}>|</span>
                      <span style={{ color: th.textMuted }}>{"\u25CB"}</span> Inferred
                    </span>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {data.forensicIndicators.map((fi, i) => {
                      const pc = { execution: th.danger, correlation: th.accent, context: th.textMuted };
                      const color = pc[fi.type] || th.textMuted;
                      const isInferred = fi.basis === "inferred";
                      return (
                        <span key={i} title={isInferred ? "Inferred from pattern analysis" : "Directly observed in data"} style={{ fontSize: 9, padding: "2px 7px", borderRadius: 4, background: `${color}${isInferred ? "0c" : "18"}`, color, fontWeight: 500, fontFamily: "-apple-system, sans-serif", border: `1px ${isInferred ? "dashed" : "solid"} ${color}33`, opacity: isInferred ? 0.85 : 1 }}>
                          {fi.text}
                        </span>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Section 4: File Type Impact Breakdown */}
              {data.fileTypeBreakdown && data.fileTypeBreakdown.length > 0 && (() => {
                const types = data.fileTypeBreakdown;
                const maxCount = types[0]?.count || 1;
                const dc = th.danger;
                // Color palette for file types
                const typeColors = { ".docx": "#2b7cd3", ".doc": "#2b7cd3", ".xlsx": "#1d7044", ".xls": "#1d7044", ".pptx": "#c43e1c", ".ppt": "#c43e1c", ".pdf": "#e44d26", ".jpg": "#e8a838", ".jpeg": "#e8a838", ".png": "#a855f7", ".gif": "#f472b6", ".zip": th.sev.med, ".rar": th.sev.med, ".7z": th.sev.med, ".sql": "#3b82f6", ".db": "#3b82f6", ".csv": "#10b981", ".txt": "#6b7280", ".xml": "#f97316", ".json": "#f97316", ".html": "#e44d26", ".py": "#3776ab", ".js": "#f7df1e", ".cpp": "#659ad2", ".java": "#ed8b00", ".psd": "#31a8ff", ".ai": "#ff9a00", ".dwg": "#e51937", ".bak": "#8b5cf6", ".vmdk": "#607078", ".vhdx": "#607078" };
                const getColor = (ext) => typeColors[ext] || th.accent;
                return (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>File Type Impact</span>
                      <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{types.length} types</span>
                    </div>
                    <div style={{ display: "flex", gap: 8, overflow: "hidden" }}>
                      {/* Horizontal bar chart */}
                      <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "8px 0", maxHeight: 200, overflow: "auto" }}>
                        {types.map((t, i) => {
                          const pct = Math.max(2, (t.count / maxCount) * 100);
                          const c = getColor(t.ext);
                          return (
                            <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 12px", fontSize: 11 }}>
                              <span style={{ width: 70, flexShrink: 0, fontFamily: "'SF Mono',Menlo,monospace", fontSize: 10, color: c, fontWeight: 600, textAlign: "right", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.ext}</span>
                              <div style={{ flex: 1, minWidth: 0, height: 14, borderRadius: 4, background: `${th.border}15`, overflow: "hidden", position: "relative" }}>
                                <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${pct}%`, borderRadius: 4, background: `linear-gradient(90deg, ${c}88, ${c}44)`, transition: "width var(--m-slow)" }} />
                              </div>
                              <span style={{ width: 40, flexShrink: 0, textAlign: "right", fontSize: 10, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{t.count.toLocaleString()}</span>
                            </div>
                          );
                        })}
                      </div>
                      {/* Top types summary */}
                      <div style={{ width: 150, flexShrink: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "10px 12px", display: "flex", flexDirection: "column", justifyContent: "center", gap: 4, overflow: "hidden" }}>
                        <div style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif", marginBottom: 2 }}>Top Types</div>
                        {types.slice(0, 6).map((t, i) => {
                          const c = getColor(t.ext);
                          const pct = ((t.count / data.encryptedCount) * 100).toFixed(1);
                          return (
                            <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                              <div style={{ width: 8, height: 8, borderRadius: 2, background: c, flexShrink: 0 }} />
                              <span style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.ext}</span>
                              <span style={{ fontSize: 10, color: th.text, fontWeight: 600, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{pct}%</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Section 4b: Business Impact Assessment */}
              {data.businessImpact?.length > 0 && (() => {
                const cats = data.businessImpact.filter(c => c.category !== "Other");
                if (cats.length === 0) return null;
                const maxCat = cats[0]?.count || 1;
                const catColors = { "Documents": "#2b7cd3", "Spreadsheets": "#1d7044", "Presentations": "#c43e1c", "Email & Messaging": "#e8a838", "Databases": "#8b5cf6", "Archives": th.sev.med, "Source Code": "#10b981", "Images & Design": "#a855f7", "Audio & Video": "#f472b6", "Virtual Machines": "#607078", "Backups & Recovery": "#ef4444", "CAD & Engineering": "#e51937" };
                return (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Business Impact Assessment</span>
                      <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{cats.length} categories</span>
                    </div>
                    <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10, padding: "8px 0", maxHeight: 200, overflow: "auto" }}>
                      {cats.map((c, i) => {
                        const pct = Math.max(2, (c.count / maxCat) * 100);
                        const color = catColors[c.category] || th.accent;
                        return (
                          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 12px", fontSize: 11 }}>
                            <div style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
                            <span style={{ width: 110, flexShrink: 0, fontFamily: "-apple-system, sans-serif", fontSize: 10, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.category}</span>
                            <div style={{ flex: 1, minWidth: 0, height: 14, borderRadius: 4, background: `${th.border}15`, overflow: "hidden", position: "relative" }}>
                              <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${pct}%`, borderRadius: 4, background: `linear-gradient(90deg, ${color}88, ${color}44)`, transition: "width var(--m-slow)" }} />
                            </div>
                            <span style={{ width: 50, flexShrink: 0, textAlign: "right", fontSize: 10, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{c.count.toLocaleString()}</span>
                            <span style={{ width: 36, flexShrink: 0, textAlign: "right", fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{Math.round(c.percentage * 100)}%</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })()}

              {/* Section 4c: Backup & Recovery Artifacts */}
              {data.backupRecoveryTotal > 0 && (() => {
                const items = data.backupRecoveryImpact || [];
                const dc = th.danger;
                return (
                  <div style={{ marginBottom: 16, padding: "12px 14px", background: `linear-gradient(135deg, ${dc}08, ${th.panelBg}ee)`, border: `1px solid ${dc}22`, borderRadius: 10 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={dc} strokeWidth="2" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        <span style={{ fontSize: 10, fontWeight: 700, color: dc, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Backup & Recovery Artifacts Affected</span>
                      </div>
                      <span style={{ fontSize: 10, color: dc, fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace" }}>{data.backupRecoveryTotal.toLocaleString()} files</span>
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {items.map((item, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", background: `${dc}12`, borderRadius: 6, border: `1px solid ${dc}22` }}>
                          <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{item.subtype}</span>
                          <span style={{ fontSize: 10, fontWeight: 600, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{item.ext}</span>
                          <span style={{ fontSize: 9, color: dc, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{item.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                    <div style={{ marginTop: 6, fontSize: 10, color: dc + "cc", fontFamily: "-apple-system, sans-serif" }}>Recovery capability may be impacted — verify backup integrity</div>
                  </div>
                );
              })()}

              {/* Section 5: Encryption Timeline */}
              {data.timeline && data.timeline.length > 0 && (() => {
                const CHART_H = 110;
                let buckets = data.timeline;
                if (buckets.length > 300) {
                  const factor = Math.ceil(buckets.length / 300);
                  const merged = [];
                  for (let i = 0; i < buckets.length; i += factor) {
                    const slice = buckets.slice(i, i + factor);
                    merged.push({ bucket: slice[0].bucket, count: slice.reduce((s, b) => s + b.count, 0) });
                  }
                  buckets = merged;
                }
                const maxCnt = Math.max(...buckets.map((b) => b.count), 1);
                const peakBucket = buckets.reduce((a, b) => b.count > a.count ? b : a, buckets[0]);
                const dc = th.danger;
                return (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Encryption Timeline</span>
                      {peakBucket && <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>peak: <span style={{ color: dc, fontWeight: 600 }}>{peakBucket.count.toLocaleString()}</span> files at {peakBucket.bucket}</span>}
                    </div>
                    <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden", padding: "12px 8px 6px" }}>
                      <svg width="100%" height={CHART_H} viewBox={`0 0 ${buckets.length} ${CHART_H}`} preserveAspectRatio="none" style={{ display: "block" }}>
                        <defs>
                          <linearGradient id="rwBarGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={dc} stopOpacity="0.95" />
                            <stop offset="100%" stopColor={dc} stopOpacity="0.4" />
                          </linearGradient>
                        </defs>
                        {buckets.map((b, i) => {
                          const h = Math.max(0.5, (b.count / maxCnt) * (CHART_H - 6));
                          return <rect key={i} x={i} y={CHART_H - h} width={0.85} height={h} fill="url(#rwBarGrad)" rx={0.2} />;
                        })}
                      </svg>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: th.textMuted, marginTop: 6, padding: "0 2px", fontFamily: "'SF Mono',Menlo,monospace" }}>
                        <span>{buckets[0]?.bucket}</span>
                        <span>{buckets[buckets.length - 1]?.bucket}</span>
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Section 4d: Blast Radius treemap — spatial concentration of encryption */}
              {data.blastTreemap?.rects?.length > 0 && (() => {
                const tm = data.blastTreemap;
                const W = tm.width, H = tm.height;
                const ratioColor = (r) => r == null ? th.textMuted : r >= 0.8 ? th.danger : r >= 0.5 ? th.warning : r >= 0.2 ? th.accent : th.success;
                const shortPath = (p) => { const segs = String(p || "").replace(/^\.\\?/, "").split(/[\\/]+/).filter(Boolean); return segs.slice(-2).join("\\") || (p || "(root)"); };
                return (
                  <div style={{ marginBottom: 16, padding: "12px 16px 10px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 12, border: `1px solid ${th.border}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Blast Radius</span>
                      <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>area = files encrypted · color = % of directory encrypted</span>
                      {[["≥80%", th.danger], ["≥50%", th.warning], ["≥20%", th.accent], ["<20%", th.success]].map(([l, c]) => (
                        <span key={l} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 9, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}><span style={{ width: 8, height: 8, borderRadius: 2, background: c }} />{l}</span>
                      ))}
                    </div>
                    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ width: "100%", aspectRatio: `${W} / ${H}`, height: "auto", display: "block", borderRadius: 6, overflow: "hidden" }}>
                      {tm.rects.map((r, i) => {
                        const c = ratioColor(r.ratio);
                        const showLabel = r.w > 130 && r.h > 42;
                        return (
                          <g key={i}>
                            <rect x={r.x + 1} y={r.y + 1} width={Math.max(0, r.w - 2)} height={Math.max(0, r.h - 2)} fill={c} fillOpacity="0.88" rx="2">
                              <title>{`${r.path}\n${(r.encryptedCount || 0).toLocaleString()} / ${(r.totalCount || 0).toLocaleString()} files (${r.ratio != null ? Math.round(r.ratio * 100) : "?"}% encrypted)`}</title>
                            </rect>
                            {showLabel && <text x={r.x + 9} y={r.y + 19} fill="#ffffff" fontSize="13" fontFamily="-apple-system, sans-serif" fontWeight="600" style={{ pointerEvents: "none" }}>{shortPath(r.path)}</text>}
                            {showLabel && <text x={r.x + 9} y={r.y + 35} fill="#ffffffcc" fontSize="11" fontFamily="'SF Mono',Menlo,monospace" style={{ pointerEvents: "none" }}>{(r.encryptedCount || 0).toLocaleString()}{r.ratio != null ? ` · ${Math.round(r.ratio * 100)}%` : ""}</text>}
                          </g>
                        );
                      })}
                    </svg>
                    <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 6 }}>Top {tm.shown} of {tm.totalDirs} affected subtrees · hover any tile for the full path & counts.</div>
                  </div>
                );
              })()}

              {/* Section 4e: Scope — by administrative boundary (top-level area + user profile) */}
              {data.scoping && (() => {
                const sc = data.scoping;
                const renderCol = (items, maxC, color, label, emptyMsg) => (
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 700, fontFamily: "-apple-system, sans-serif", marginBottom: 6 }}>{label}</div>
                    {items.length === 0 ? <div style={{ fontSize: 10, color: th.textMuted, fontStyle: "italic", fontFamily: "-apple-system, sans-serif" }}>{emptyMsg}</div> : items.map((it, i) => {
                      const w = maxC > 0 ? (it.count / maxC) * 100 : 0;
                      return (
                        <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                          <span title={it.name} style={{ width: 92, flexShrink: 0, fontSize: 10, color: th.text, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{it.name}</span>
                          <div style={{ flex: 1, height: 12, background: `${th.border}22`, borderRadius: 3, position: "relative", minWidth: 0 }}>
                            <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${w}%`, background: color, borderRadius: 3, opacity: 0.75 }} />
                          </div>
                          <span style={{ width: 70, flexShrink: 0, fontSize: 9, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", textAlign: "right" }}>{it.count.toLocaleString()} ({Math.round(it.pct * 100)}%)</span>
                        </div>
                      );
                    })}
                  </div>
                );
                return (
                  <div style={{ marginBottom: 16, padding: "12px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 12, border: `1px solid ${th.border}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Scope</span>
                      <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{sc.areaCount} area{sc.areaCount !== 1 ? "s" : ""} · {sc.userCount} user profile{sc.userCount !== 1 ? "s" : ""}{sc.coverage < 0.999 ? ` · covers top ${Math.round(sc.coverage * 100)}% of encrypted files` : ""}</span>
                    </div>
                    <div style={{ display: "flex", gap: 18 }}>
                      {renderCol(sc.byArea, sc.byArea[0]?.count || 1, th.warning, "By area (top-level)", "—")}
                      {renderCol(sc.byUser, sc.byUser[0]?.count || 1, th.accent, "By user profile", "No user-profile paths encrypted")}
                    </div>
                    {sc.note && <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", marginTop: 10, fontStyle: "italic" }}>{sc.note}</div>}
                  </div>
                );
              })()}

              {/* Section 5: Top Affected Subtrees */}
              {data.topDirectories && data.topDirectories.length > 0 && (() => {
                const shown = data.topDirectories.slice(0, 15);
                const selD = modal.rwSelDirs || new Set();
                const allD = selD.size === shown.length;
                const maxEnc = shown[0]?.encryptedCount || shown[0]?.count || 1;
                return (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <div onClick={() => toggleAll("rwSelDirs", shown.length)} style={cbStyle(allD)}>
                        {allD && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                      </div>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Affected Subtrees</span>
                    </div>
                    <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{data.topDirectories.length} subtrees</span>
                  </div>
                  <div style={{ maxHeight: 220, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                    {shown.map((dir, i) => {
                      const enc = dir.encryptedCount || dir.count || 0;
                      const total = dir.totalCount || enc;
                      const ratio = dir.ratio ?? (total > 0 ? enc / total : 0);
                      const pctBar = Math.max(1, (enc / maxEnc) * 100);
                      const ratioPct = Math.round(ratio * 100);
                      const ratioColor = ratioPct >= 90 ? (th.danger) : ratioPct >= 50 ? (th.warning) : th.accent;
                      const sel = selD.has(i);
                      return (
                        <div key={i} onClick={() => toggleSet("rwSelDirs", i)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", fontSize: 11, borderBottom: `1px solid ${th.border}15`, position: "relative", cursor: "pointer", background: sel ? `${th.accent}0a` : "transparent" }}>
                          <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${pctBar}%`, background: `linear-gradient(90deg, ${ratioColor}12, ${ratioColor}04)`, borderRadius: i === 0 ? "10px 0 0 0" : 0 }} />
                          <div style={{ ...cbStyle(sel), position: "relative" }}>
                            {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                          </div>
                          <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'SF Mono',Menlo,monospace", color: th.textDim, position: "relative", fontSize: 10 }}>{dir.path || "(root)"}</span>
                          {dir.childDirCount > 1 && <span style={{ position: "relative", fontSize: 8, color: th.textMuted, padding: "1px 4px", background: `${th.border}22`, borderRadius: 3, fontFamily: "-apple-system, sans-serif" }}>{dir.childDirCount} dirs</span>}
                          <span style={{ fontWeight: 600, color: th.text, fontSize: 10, whiteSpace: "nowrap", position: "relative", fontFamily: "'SF Mono',Menlo,monospace", padding: "1px 6px", background: `${th.border}22`, borderRadius: 4 }}>{enc.toLocaleString()} / {total.toLocaleString()}</span>
                          <span style={{ position: "relative", fontSize: 9, fontWeight: 700, color: ratioColor, fontFamily: "'SF Mono',Menlo,monospace", minWidth: 32, textAlign: "right" }}>{ratioPct}%</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
                );
              })()}

              {/* Section 6: Ransom Notes */}
              {data.ransomNotes && data.ransomNotes.length > 0 && (() => {
                const shownN = data.ransomNotes.slice(0, 50);
                const selN = modal.rwSelNotes || new Set();
                const allN = selN.size === shownN.length;
                return (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <div onClick={() => toggleAll("rwSelNotes", shownN.length)} style={cbStyle(allN)}>
                        {allN && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                      </div>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Ransom Note Locations</span>
                    </div>
                    <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{data.ransomNoteCount} found</span>
                  </div>
                  <div style={{ maxHeight: 180, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                    {/* Column header */}
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                      <div style={{ width: 14, flexShrink: 0 }} />
                      {rwHdrCol(notesW[0], "Entry#", "rwSortNotes", "entryNumber", "rwNotesColW", defNotesW, 0)}
                      {rwHdrCol(notesW[1], "FileName", "rwSortNotes", "fileName", "rwNotesColW", defNotesW, 1)}
                      <div style={{ flex: 1, display: "flex", alignItems: "center", cursor: "pointer", userSelect: "none" }} onClick={() => handleRwSort("rwSortNotes", "parentPath")}>ParentPath{rwSortArrow("rwSortNotes", "parentPath")}</div>
                      {rwHdrCol(notesW[3], "Created", "rwSortNotes", "created", "rwNotesColW", defNotesW, 3)}
                    </div>
                    {sortRwArr(shownN, modal.rwSortNotes).map((note, i) => {
                      const sel = selN.has(i);
                      return (
                      <div key={i} onClick={() => toggleSet("rwSelNotes", i)} style={{ ...rowStyle(i), background: sel ? `${th.accent}0a` : (i % 2 === 0 ? "transparent" : `${th.border}0a`), borderBottom: `1px solid ${th.border}15`, cursor: "pointer" }}>
                        <div style={cbStyle(sel)}>
                          {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                        </div>
                        <span style={{ width: notesW[0], flexShrink: 0, color: th.warning, fontWeight: 600, fontSize: 10 }}>#{note.entryNumber}</span>
                        <span style={{ width: notesW[1], flexShrink: 0, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{note.fileName}</span>
                        <span style={{ flex: 1, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{note.parentPath}</span>
                        <span style={{ width: notesW[3], flexShrink: 0, color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{(note.created || "").slice(0, 19)}</span>
                      </div>
                      );
                    })}
                    {data.ransomNoteCount > 50 && <div style={{ padding: "6px 10px", fontSize: 10, color: th.textMuted, textAlign: "center", fontFamily: "-apple-system, sans-serif" }}>...and {(data.ransomNoteCount - 50).toLocaleString()} more</div>}
                  </div>
                </div>
                );
              })()}

              {/* Section 7: Scored Payload Candidates */}
              {data.suspiciousFiles && data.suspiciousFiles.length > 0 && (() => {
                const selS = modal.rwSelSusp || new Set();
                const allS = selS.size === data.suspiciousFiles.length;
                const topConf = data.suspiciousFiles[0]?.confidence;
                const confColor = topConf === "confirmed" ? (th.danger) : topConf === "likely" ? (th.warning) : th.textMuted;
                const expanded = modal.rwExpandedRow;
                return (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <div onClick={() => toggleAll("rwSelSusp", data.suspiciousFiles.length)} style={cbStyle(allS)}>
                        {allS && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                      </div>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Payload Candidates</span>
                      {topConf && <span style={{ fontSize: 8, padding: "1px 6px", borderRadius: 3, background: `${confColor}22`, color: confColor, fontFamily: "'SF Mono',Menlo,monospace", fontWeight: 600, border: `1px solid ${confColor}44`, textTransform: "uppercase", letterSpacing: "0.05em" }}>{topConf}</span>}
                    </div>
                    <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{"\u00B1"}30 min window</span>
                  </div>
                  <div style={{ maxHeight: 280, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                      <div style={{ width: 14, flexShrink: 0 }} />
                      <div style={{ width: 32, flexShrink: 0 }}>Score</div>
                      {rwHdrCol(suspW[0], "Ext", "rwSortSusp", "extension", "rwSuspColW", defSuspW, 0)}
                      {rwHdrCol(suspW[1], "FileName", "rwSortSusp", "fileName", "rwSuspColW", defSuspW, 1)}
                      <div style={{ flex: 1, display: "flex", alignItems: "center", cursor: "pointer", userSelect: "none" }} onClick={() => handleRwSort("rwSortSusp", "parentPath")}>ParentPath{rwSortArrow("rwSortSusp", "parentPath")}</div>
                      {rwHdrCol(suspW[3], "Created", "rwSortSusp", "created", "rwSuspColW", defSuspW, 3)}
                      <div style={{ width: 50 }} />
                    </div>
                    {sortRwArr(data.suspiciousFiles, modal.rwSortSusp).map((sf, i) => {
                      const sel = selS.has(i);
                      const sc = sf.score || 0;
                      const scoreColor = sc >= 0.6 ? (th.danger) : sc >= 0.35 ? (th.warning) : sc >= 0.15 ? th.accent : th.textMuted;
                      const isExpanded = expanded?.section === "susp" && expanded?.idx === i;
                      return (<Fragment key={i}>
                      <div onClick={() => toggleSet("rwSelSusp", i)} style={{ ...rowStyle(i), background: sel ? `${th.accent}0a` : (sc >= 0.35 ? `linear-gradient(90deg, ${scoreColor}08, transparent)` : (i % 2 === 0 ? "transparent" : `${th.border}0a`)), borderBottom: `1px solid ${th.border}15`, cursor: "pointer", flexWrap: "wrap" }}>
                        <div style={cbStyle(sel)}>
                          {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                        </div>
                        <span style={{ padding: "1px 5px", borderRadius: 4, fontSize: 9, fontWeight: 700, background: `${scoreColor}22`, color: scoreColor, fontFamily: "'SF Mono',Menlo,monospace", minWidth: 28, textAlign: "center", width: 32, flexShrink: 0 }}>{Math.round(sc * 100)}</span>
                        <span onClick={(e) => { e.stopPropagation(); setModal((p) => ({ ...p, rwExpandedRow: isExpanded ? null : { section: "susp", idx: i } })); }} style={{ width: suspW[0], flexShrink: 0, color: th.danger, fontWeight: 600, fontSize: 10, cursor: "pointer", textDecoration: "underline", textDecorationStyle: "dotted" }}>{sf.extension}</span>
                        <span style={{ width: suspW[1], flexShrink: 0, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{sf.fileName}</span>
                        <span style={{ flex: 1, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{sf.parentPath}</span>
                        <span style={{ width: suspW[3], flexShrink: 0, color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{(sf.created || "").slice(0, 19)}</span>
                        <div style={{ display: "flex", gap: 3, width: 78, flexShrink: 0, justifyContent: "flex-end" }}>
                          {sf.executionConfirmed && <span title={`Process-creation observed in EVTX${sf.execContext?.time ? ` @ ${(sf.execContext.time || "").slice(0, 19)}` : ""}`} style={{ padding: "1px 4px", borderRadius: 3, fontSize: 7, fontWeight: 800, color: "#fff", background: th.accent }}>▶RAN</span>}
                          {sf.zoneId && <span style={{ padding: "1px 4px", borderRadius: 3, fontSize: 7, fontWeight: 700, color: "#fff", background: th.danger }}>WEB</span>}
                          {sf.inUse === "False" && <span style={{ padding: "1px 4px", borderRadius: 3, fontSize: 7, fontWeight: 700, color: "#fff", background: th.warning }}>DEL</span>}
                          {sf.siFN === "True" && <span style={{ padding: "1px 4px", borderRadius: 3, fontSize: 7, fontWeight: 700, color: "#fff", background: "#a855f7" }}>TS</span>}
                        </div>
                        {/* Evidence signal pills */}
                        {sf.signals?.length > 0 && (
                          <div style={{ width: "100%", paddingLeft: 28, display: "flex", flexWrap: "wrap", gap: 3, marginTop: 2 }}>
                            {sf.signals.map((sig, si) => {
                              const pc = { execution: th.danger, correlation: th.accent, context: th.textMuted };
                              const c = pc[sig.type] || th.textMuted;
                              return <span key={si} title={sig.basis === "inferred" ? "Inferred" : "Observed"} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${c}${sig.basis === "inferred" ? "0c" : "15"}`, color: c, fontFamily: "-apple-system, sans-serif", border: `1px ${sig.basis === "inferred" ? "dashed" : "solid"} ${c}22`, opacity: sig.basis === "inferred" ? 0.8 : 1 }}>{sig.text}</span>;
                            })}
                          </div>
                        )}
                      </div>
                      {/* Expandable timestamp detail */}
                      {isExpanded && (
                        <div style={{ padding: "6px 10px 6px 42px", background: `${th.panelBg}dd`, borderBottom: `1px solid ${th.border}22`, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", color: th.textDim }}>
                          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2px 16px" }}>
                            <span>Created (SI): {sf.created || "\u2014"}</span><span>Modified (SI): {sf.lastModified || "\u2014"}</span>
                            <span>Record Change: {sf.recordChange0x10 || "\u2014"}</span><span>Created (FN): {sf.created0x30 || "\u2014"}</span>
                            <span>Modified (FN): {sf.lastMod0x30 || "\u2014"}</span>
                          </div>
                          {sf.executionConfirmed && sf.execContext && (
                            <div style={{ marginTop: 4, paddingTop: 4, borderTop: `1px solid ${th.border}22`, color: th.accent }}>
                              <span style={{ fontWeight: 700 }}>\u25b6 Execution confirmed (EVTX)</span>
                              {sf.execContext.time ? <span style={{ color: th.textDim }}>  @ {(sf.execContext.time || "").slice(0, 19)}{sf.execContext.eventId ? ` \u00b7 EID ${sf.execContext.eventId}` : ""}</span> : null}
                              <div style={{ color: th.textDim, marginTop: 1 }}>parent: <span style={{ color: th.text }}>{sf.execContext.parentImage || "\u2014"}</span>   user: <span style={{ color: th.text }}>{sf.execContext.user || "\u2014"}</span></div>
                            </div>
                          )}
                        </div>
                      )}
                      </Fragment>);
                    })}
                  </div>
                  {/* Click any row entry# to expand timestamps */}
                  <div style={{ fontSize: 8, color: th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif", fontStyle: "italic" }}>Click extension to expand timestamps</div>
                </div>
                );
              })()}

              {/* Section 8: Anti-Forensics & Cleanup */}
              {data.antiForensics && (data.antiForensics.deletedEncrypted?.length > 0 || data.antiForensics.timestomped?.length > 0 || data.antiForensics.cleanup?.length > 0 || data.antiForensics.drops?.length > 0) && (() => {
                const af = data.antiForensics;
                const dc = th.danger;
                const wc = th.warning;
                const cats = [
                  { key: "deletedEncrypted", label: "Deleted Encrypted", items: af.deletedEncrypted || [], color: dc },
                  { key: "timestomped", label: "Timestomped in Window", items: af.timestomped || [], color: "#a855f7" },
                  { key: "cleanup", label: "Cleanup Artifacts", items: af.cleanup || [], color: wc },
                  { key: "drops", label: "Suspicious Drops", items: af.drops || [], color: th.accent },
                ].filter(c => c.items.length > 0);
                const selAF = modal.rwSelAF || new Set();
                let afIdx = 0;
                return (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={dc} strokeWidth="2" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    <span style={{ fontSize: 10, fontWeight: 700, color: dc, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Anti-Forensics & Cleanup</span>
                  </div>
                  {/* Summary bar */}
                  <div style={{ display: "grid", gridTemplateColumns: `repeat(${cats.length}, 1fr)`, gap: 6, marginBottom: 8 }}>
                    {cats.map((c) => (
                      <div key={c.key} style={{ textAlign: "center", padding: "6px", background: `${c.color}08`, borderRadius: 8, border: `1px solid ${c.color}22` }}>
                        <div style={{ fontSize: 16, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif", lineHeight: 1 }}>{c.items.length}</div>
                        <div style={{ fontSize: 8, color: c.color + "bb", marginTop: 2, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                      </div>
                    ))}
                  </div>
                  {/* Collapsible details */}
                  <div style={{ maxHeight: 200, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                    {cats.map((cat) => {
                      const startIdx = afIdx;
                      return cat.items.map((item, ii) => {
                        const gi = afIdx++;
                        const sel = selAF.has(gi);
                        return (
                          <div key={`${cat.key}-${ii}`} onClick={() => toggleSet("rwSelAF", gi)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 10px", fontSize: 10, borderBottom: `1px solid ${th.border}12`, cursor: "pointer", background: sel ? `${th.accent}0a` : (gi % 2 === 0 ? "transparent" : `${th.border}08`) }}>
                            <div style={cbStyle(sel)}>{sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}</div>
                            <span style={{ fontSize: 7, padding: "1px 4px", borderRadius: 3, background: `${cat.color}22`, color: cat.color, fontWeight: 600, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", flexShrink: 0 }}>{cat.label.split(" ")[0]}</span>
                            <span style={{ color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", fontSize: 9, flexShrink: 0 }}>#{item.entryNumber}</span>
                            <span style={{ color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0, fontFamily: "'SF Mono',Menlo,monospace" }}>{item.fileName}</span>
                            <span style={{ flex: 1, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0, fontFamily: "'SF Mono',Menlo,monospace" }}>{item.parentPath}</span>
                            <span style={{ color: th.textMuted, fontSize: 9, whiteSpace: "nowrap", flexShrink: 0, fontFamily: "'SF Mono',Menlo,monospace" }}>{(item.created || item.lastModified || "").slice(0, 19)}</span>
                          </div>
                        );
                      });
                    })}
                  </div>
                </div>
                );
              })()}

              {/* Section 9: USN Journal Correlation */}
              {data.usnEnrichment && (() => {
                const usn = data.usnEnrichment;
                const ac = th.accent;
                return (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: ac, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>USN Journal Correlation</span>
                  </div>
                  {/* Precise start callout */}
                  {usn.preciseStartTime && data.firstEncrypted?.timestamp && usn.preciseStartTime !== data.firstEncrypted.timestamp && (
                    <div style={{ marginBottom: 8, padding: "8px 12px", background: `${ac}08`, border: `1px solid ${ac}22`, borderRadius: 8 }}>
                      <div style={{ fontSize: 10, color: ac, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>USN places encryption start at <span style={{ fontFamily: "'SF Mono',Menlo,monospace" }}>{usn.preciseStartTime}</span></div>
                      <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 2 }}>MFT LastModified shows <span style={{ fontFamily: "'SF Mono',Menlo,monospace" }}>{data.firstEncrypted.timestamp}</span></div>
                    </div>
                  )}
                  {/* Summary stats */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6, marginBottom: 8 }}>
                    {[
                      { val: usn.renameCount, label: "rename events", color: ac },
                      { val: usn.overwriteTotal, label: "data overwrites", color: th.warning },
                      { val: usn.deleteTotal, label: "deletions", color: th.danger },
                    ].map((c, i) => (
                      <div key={i} style={{ textAlign: "center", padding: "8px 6px", background: `${c.color}08`, borderRadius: 8, border: `1px solid ${c.color}22` }}>
                        <div style={{ fontSize: 18, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif", lineHeight: 1 }}>{c.val.toLocaleString()}</div>
                        <div style={{ fontSize: 8, color: c.color + "bb", marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                      </div>
                    ))}
                  </div>
                  {/* Overwrite burst mini-timeline */}
                  {usn.overwriteBuckets?.length > 0 && (() => {
                    const bkts = usn.overwriteBuckets;
                    const maxC = Math.max(...bkts.map(b => b.count), 1);
                    return (
                      <div style={{ marginBottom: 8, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10, padding: "8px 8px 4px" }}>
                        <div style={{ fontSize: 9, fontWeight: 600, color: th.textMuted, marginBottom: 4, fontFamily: "-apple-system, sans-serif" }}>Data Overwrite Burst Pattern</div>
                        <svg width="100%" height="50" viewBox={`0 0 ${bkts.length} 50`} preserveAspectRatio="none" style={{ display: "block" }}>
                          {bkts.map((b, i) => { const h = Math.max(0.5, (b.count / maxC) * 44); return <rect key={i} x={i} y={50 - h} width={0.85} height={h} fill={(th.warning) + "88"} rx={0.2} />; })}
                        </svg>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8, color: th.textMuted, marginTop: 2, fontFamily: "'SF Mono',Menlo,monospace" }}>
                          <span>{bkts[0]?.bucket}</span><span>{bkts[bkts.length - 1]?.bucket}</span>
                        </div>
                      </div>
                    );
                  })()}
                  {/* Sample rename events */}
                  {usn.renameSamples?.length > 0 && (
                    <div style={{ maxHeight: 140, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "-apple-system, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                        <div style={{ width: 14, flexShrink: 0 }} />
                        <div style={{ width: 130, flexShrink: 0 }}>Timestamp</div>
                        <div style={{ flex: 1 }}>FileName</div>
                        <div style={{ width: 200, flexShrink: 0 }}>Path</div>
                      </div>
                      {usn.renameSamples.map((r, i) => {
                        const sel = (modal.rwSelUsn || new Set()).has(i);
                        return (
                          <div key={i} onClick={() => toggleSet("rwSelUsn", i)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 10px", fontSize: 10, borderBottom: `1px solid ${th.border}12`, cursor: "pointer", background: sel ? `${th.accent}0a` : (i % 2 === 0 ? "transparent" : `${th.border}08`), fontFamily: "'SF Mono',Menlo,monospace" }}>
                            <div style={cbStyle(sel)}>{sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}</div>
                            <span style={{ width: 130, flexShrink: 0, color: th.textMuted, fontSize: 9 }}>{(r.timestamp || "").slice(0, 19)}</span>
                            <span style={{ flex: 1, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.name}</span>
                            <span style={{ width: 200, flexShrink: 0, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.parentPath || ""}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
                );
              })()}

              {/* Section 10: Defense Evasion (EVTX cross-artifact) — completes T1490 */}
              {data.evtxEnrichment && data.evtxEnrichment.total > 0 && (() => {
                const ev = data.evtxEnrichment;
                const techColor = (tech) => tech === "T1490" ? th.danger : tech === "T1070.001" ? th.warning : tech === "T1569.002" ? th.accent : th.textMuted;
                return (
                  <div style={{ marginTop: 14, padding: "12px 14px", background: `linear-gradient(135deg, ${th.danger}0e, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${th.danger}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.danger, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Defense Evasion (EVTX)</span>
                      <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{ev.total.toLocaleString()} correlated event{ev.total !== 1 ? "s" : ""} in window · corroborates T1490 (VSS / backup destruction)</span>
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 8 }}>
                      {Object.entries(ev.byCategory || {}).sort((a, b) => b[1] - a[1]).map(([cat, n], i) => (
                        <span key={i} style={{ padding: "2px 8px", borderRadius: 5, fontSize: 9, fontWeight: 600, background: `${th.danger}14`, color: th.danger, border: `1px solid ${th.danger}33`, fontFamily: "-apple-system, sans-serif" }}>{cat} ×{n}</span>
                      ))}
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 180, overflowY: "auto" }}>
                      {ev.hits.map((h, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "baseline", gap: 8, fontSize: 9.5, fontFamily: "'SF Mono',Menlo,monospace", padding: "2px 0", borderBottom: `1px solid ${th.border}12` }}>
                          <span style={{ width: 122, flexShrink: 0, color: th.textMuted }}>{(h.timestamp || "").slice(0, 19)}</span>
                          <span style={{ width: 76, flexShrink: 0, color: techColor(h.technique), fontWeight: 600 }}>{h.technique || "review"}{h.eventId ? ` ·${h.eventId}` : ""}</span>
                          <span title={h.text} style={{ flex: 1, minWidth: 0, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}><span style={{ color: th.text }}>{h.category}</span>{h.text ? ` — ${h.text}` : ""}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}

              {/* Section 11: Process Execution (EVTX cross-artifact) — who/what ran the encryption */}
              {data.processCorrelation && data.processCorrelation.available && data.processCorrelation.total > 0 && (() => {
                const pc = data.processCorrelation;
                const trunc = (s, n) => { const v = String(s || ""); return v.length > n ? v.slice(0, n) + "…" : v; };
                return (
                  <div style={{ marginTop: 14, padding: "12px 14px", background: `linear-gradient(135deg, ${th.accent}0e, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${th.accent}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>Process Execution (EVTX)</span>
                      <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                        {pc.total.toLocaleString()} process-creation event{pc.total !== 1 ? "s" : ""} (Sysmon 1 / Security 4688)
                        {pc.confirmedPayloads > 0 ? ` · ${pc.confirmedPayloads} payload${pc.confirmedPayloads !== 1 ? "s" : ""} execution-confirmed` : " · no payload candidate matched a launched process"}
                      </span>
                    </div>
                    {(pc.windowStart || pc.windowEnd) && (
                      <div style={{ fontSize: 8.5, color: th.textDim, fontFamily: "-apple-system, sans-serif", marginBottom: 8 }}>
                        Window {(pc.windowStart || "").slice(0, 16)} → {(pc.windowEnd || "").slice(0, 16)} (onset −60m … end +10m)
                        {pc.channelScoped ? " · scoped to Sysmon/Security channels" : " · EID-only (no Channel column to scope — verify source)"}
                      </div>
                    )}
                    {/* Execution-confirmed payloads — the smoking guns: a dropped binary that ALSO ran */}
                    {pc.confirmed && pc.confirmed.length > 0 && (
                      <div style={{ marginBottom: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                        {pc.confirmed.map((c, i) => (
                          <div key={i} style={{ padding: "5px 8px", background: `${th.danger}12`, border: `1px solid ${th.danger}33`, borderRadius: 6, fontFamily: "'SF Mono',Menlo,monospace", fontSize: 9.5 }}>
                            <div style={{ display: "flex", alignItems: "baseline", gap: 6, flexWrap: "wrap" }}>
                              <span style={{ color: th.danger, fontWeight: 700 }}>▶ {c.fileName}</span>
                              <span style={{ color: th.textMuted }}>executed</span>
                              {c.time && <span style={{ color: th.textDim }}>@ {(c.time || "").slice(0, 19)}</span>}
                              {c.eventId && <span style={{ color: th.textMuted }}>· EID {c.eventId}</span>}
                            </div>
                            <div style={{ display: "flex", gap: 14, marginTop: 2, color: th.textDim, flexWrap: "wrap" }}>
                              {c.parentImage && <span>parent: <span style={{ color: th.text }}>{trunc(c.parentImage, 64)}</span></span>}
                              {c.user && <span>user: <span style={{ color: th.text }}>{trunc(c.user, 40)}</span></span>}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    {/* Observed process-creation events in the window, prioritised by relevance */}
                    {pc.processes && pc.processes.length > 0 ? (
                      <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 200, overflowY: "auto" }}>
                        {pc.processes.map((p, i) => (
                          <div key={i} title={`${p.image || ""}\n${p.cmdLine || ""}\nparent: ${p.parentImage || "?"}\nuser: ${p.user || "?"}`} style={{ display: "flex", alignItems: "baseline", gap: 8, fontSize: 9.5, fontFamily: "'SF Mono',Menlo,monospace", padding: "2px 0", borderBottom: `1px solid ${th.border}12` }}>
                            <span style={{ width: 122, flexShrink: 0, color: th.textMuted }}>{(p.timestamp || "").slice(0, 19)}</span>
                            <span style={{ width: 12, flexShrink: 0, textAlign: "center" }}>{p.matchedPayload ? <span style={{ color: th.danger }} title="matches a payload candidate">▶</span> : p.evasion ? <span style={{ color: th.warning }} title="defense-evasion command">!</span> : p.risky ? <span style={{ color: th.accent }} title="risky path">•</span> : ""}</span>
                            <span style={{ flex: 1, minWidth: 0, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              <span style={{ color: th.text }}>{trunc(p.image || p.cmdLine || "(unparsed)", 66)}</span>
                              {p.parentImage ? <span style={{ color: th.textMuted }}> ← {trunc(p.parentImage, 36)}</span> : ""}
                              {p.user ? <span style={{ color: th.textMuted }}> · {trunc(p.user, 24)}</span> : ""}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: 9.5, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                        {pc.total.toLocaleString()} process-creation event{pc.total !== 1 ? "s" : ""} present, but no image / command line could be parsed from this EVTX format.
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Section 12: In-Place / Overwrite Encryption — SUSPICION surface (no rename) */}
              {data.inPlaceEncryption && data.inPlaceEncryption.available && (() => {
                const ip = data.inPlaceEncryption;
                const cc = ip.confidence === "high" ? th.danger : ip.confidence === "medium" ? th.warning : th.textMuted;
                const trunc = (s, n) => { const v = String(s || ""); return v.length > n ? "…" + v.slice(-n) : v; };
                return (
                  <div style={{ marginTop: 14, padding: "12px 14px", background: `linear-gradient(135deg, ${cc}12, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${cc}44` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: cc, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system, sans-serif" }}>In-Place Encryption</span>
                      <span style={{ padding: "1px 6px", borderRadius: 4, fontSize: 8.5, fontWeight: 800, color: "#fff", background: cc, textTransform: "uppercase" }}>{ip.confidence}</span>
                      {ip.isSuspicionOnly && <span style={{ padding: "1px 6px", borderRadius: 4, fontSize: 8.5, fontWeight: 700, color: th.textMuted, background: `${th.textMuted}1c`, border: `1px solid ${th.textMuted}33`, textTransform: "uppercase" }}>Suspicion</span>}
                    </div>
                    <div style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", marginBottom: 6 }}>
                      <strong style={{ color: cc }}>{ip.candidateFileCount.toLocaleString()}</strong> business-data files rewritten in place (same name; SI 0x10 Modified later than FN 0x30) over <strong>{ip.durationMinutes}m</strong>
                      {ip.peakFilesPerMinute ? <span style={{ color: th.textMuted }}> · peak {ip.peakFilesPerMinute.toLocaleString()}/min · {ip.directoryCount} dir{ip.directoryCount === 1 ? "" : "s"}</span> : null}
                      {(ip.windowStart || ip.windowEnd) && <div style={{ fontSize: 9, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", marginTop: 1 }}>{(ip.windowStart || "")} → {(ip.windowEnd || "")} UTC</div>}
                    </div>
                    {ip.reason && <div style={{ fontSize: 9.5, color: ip.confidence === "low" ? th.textMuted : cc, fontStyle: "italic", marginBottom: 6 }}>{ip.reason}</div>}
                    {/* Extension category chips */}
                    {ip.extensionBreakdown?.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 6 }}>
                        {ip.extensionBreakdown.slice(0, 10).map((e, i) => (
                          <span key={i} title={e.category} style={{ padding: "2px 7px", borderRadius: 5, fontSize: 9, fontWeight: 600, background: `${cc}12`, color: cc, border: `1px solid ${cc}26`, fontFamily: "'SF Mono',Menlo,monospace" }}>{e.extension} ×{e.count.toLocaleString()}</span>
                        ))}
                      </div>
                    )}
                    {/* Signal ladder */}
                    <div style={{ display: "flex", flexDirection: "column", gap: 1, marginBottom: 6 }}>
                      {(ip.signals || []).map((s, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "baseline", gap: 6, fontSize: 9, fontFamily: "-apple-system, sans-serif" }}>
                          <span style={{ width: 12, flexShrink: 0, color: s.fired ? th.success : th.textDim, fontWeight: 700 }}>{s.fired ? "✓" : "·"}</span>
                          <span style={{ width: 22, flexShrink: 0, color: th.textMuted, fontWeight: 600 }}>{s.id}</span>
                          <span style={{ flex: 1, color: s.fired ? th.textDim : th.textMuted }}>{s.text}</span>
                        </div>
                      ))}
                    </div>
                    {/* Sample files */}
                    {ip.samples?.length > 0 && (
                      <details style={{ marginBottom: 6 }}>
                        <summary style={{ fontSize: 9, color: th.textMuted, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Sample rewritten files ({ip.samples.length})</summary>
                        <div style={{ marginTop: 3, display: "flex", flexDirection: "column", gap: 1, maxHeight: 150, overflowY: "auto" }}>
                          {ip.samples.map((s, i) => (
                            <div key={i} title={`${s.parentPath}\\${s.fileName}\nSI Modified: ${s.lastMod0x10}\nFN Modified: ${s.lastMod0x30}\nCreated: ${s.created0x10}`} style={{ display: "flex", alignItems: "baseline", gap: 8, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", padding: "1px 0", borderBottom: `1px solid ${th.border}10` }}>
                              <span style={{ width: 118, flexShrink: 0, color: th.textMuted }}>{(s.lastMod0x10 || "").slice(0, 19)}</span>
                              <span style={{ flex: 1, minWidth: 0, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}><span style={{ color: th.text }}>{s.fileName}</span> <span style={{ color: th.textMuted }}>{trunc(s.parentPath, 40)}</span></span>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                    <div style={{ fontSize: 8.5, color: th.textMuted, fontStyle: "italic", fontFamily: "-apple-system, sans-serif", paddingTop: 5, borderTop: `1px solid ${th.border}1a` }}>{ip.disclaimer}</div>
                  </div>
                );
              })()}
            </>)}
          </>)}
        </div>

        {/* Footer — glass */}
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
          {phase === "input" && (<>
            <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
            <button onClick={handleAnalyze} disabled={!encryptedExt.trim() || loading} style={{ ...ms.bp, opacity: !encryptedExt.trim() ? 0.5 : 1 }}>Analyze</button>
          </>)}
          {phase === "scanning" && <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>Scanning...</span>}
          {phase === "loading" && <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>Analyzing...</span>}
          {phase === "results" && (<>
            <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
              <button onClick={() => setModal((p) => ({ ...p, phase: "input", data: null }))} style={ms.bs}>Back</button>
              {/* Pivot actions menu */}
              {data && data.encryptedCount > 0 && (
                <div style={{ position: "relative" }}>
                  <button onClick={() => setModal((p) => ({ ...p, rwShowPivots: !p.rwShowPivots }))} style={{ ...ms.bs, display: "flex", alignItems: "center", gap: 4, fontSize: 10 }}>
                    Pivots <svg width="8" height="5" viewBox="0 0 8 5" style={{ marginLeft: 2 }}><path d="M0 0L4 5L8 0" fill={th.textMuted} /></svg>
                  </button>
                  {modal.rwShowPivots && (
                    <div style={{ position: "absolute", bottom: "100%", left: 0, marginBottom: 4, minWidth: 240, background: th.modalBg, border: `1px solid ${th.border}66`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.4)", zIndex: 10, padding: "4px 0", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
                      {/* Tag encrypted files (multi-extension aware) */}
                      <button onClick={async () => {
                        try {
                          const exts = (data.extensions || [encryptedExt]);
                          const extFilters = exts.map((e, ei) => ({ column: "Extension", operator: "equals", value: e, logic: ei === 0 ? "AND" : "OR" }));
                          await tle.bulkTagFiltered(ct.id, "Encrypted", { advancedFilters: extFilters });
                          const td = await tle.getAllTagData(ct.id); const nrt = {}; for (const { rowid, tag } of td) { if (!nrt[rowid]) nrt[rowid] = []; nrt[rowid].push(tag); } up("rowTags", nrt);
                          const nc = { ...(ct.tagColors || {}), Encrypted: th.sev.critical }; up("tagColors", nc);
                          setModal((p) => ({ ...p, rwPivotMsg: `Tagged ${data.encryptedCount.toLocaleString()} files as "Encrypted"`, rwShowPivots: false }));
                          setTimeout(() => setModal((p) => p ? { ...p, rwPivotMsg: null } : p), 3000);
                        } catch {}
                      }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                        Tag Encrypted Files ({data.encryptedCount.toLocaleString()})
                      </button>
                      {/* Filter grid to encryption window */}
                      {(data.timingEvidence?.filterWindow?.from || data.firstEncrypted?.timestamp) && (data.timingEvidence?.filterWindow?.to || data.lastEncrypted?.timestamp) && (
                        <button onClick={() => {
                          const filterCol = (data.timingEvidence?.filterWindow?.column && ct.headers?.includes(data.timingEvidence.filterWindow.column))
                            ? data.timingEvidence.filterWindow.column
                            : (ct.headers?.find((h) => h === "LastModified0x10") || "LastModified0x10");
                          const from = data.timingEvidence?.filterWindow?.from || data.firstEncrypted.timestamp;
                          const to = data.timingEvidence?.filterWindow?.to || data.lastEncrypted.timestamp;
                          up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [filterCol]: { from, to } });
                          setModal(null);
                        }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                          Filter Grid to Encryption Window
                        </button>
                      )}
                      {/* Open top directory */}
                      {data.topDirectories?.[0] && (
                        <button onClick={() => {
                          const topDir = (data.topDirectories[0].path || "").replace(/^\.\\/, "");
                          up("searchTerm", "");
                          up("advancedFilters", [
                            { column: "ParentPath", operator: "equals", value: topDir, logic: "AND" },
                            { column: "ParentPath", operator: "starts_with", value: `${topDir}\\`, logic: "OR" },
                          ]);
                          setModal(null);
                        }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                          Open Top Directory in Grid
                        </button>
                      )}
                      {/* Tag ransom notes */}
                      {data.ransomNoteCount > 0 && ransomNotePattern && (
                        <button onClick={async () => {
                          try {
                            const tagMap = {};
                            (data.ransomNotes || []).forEach((note) => {
                              if (note.rowId != null) tagMap[note.rowId] = ["Ransom Note"];
                            });
                            await tle.bulkAddTags(ct.id, tagMap);
                            const td = await tle.getAllTagData(ct.id); const nrt = {}; for (const { rowid, tag } of td) { if (!nrt[rowid]) nrt[rowid] = []; nrt[rowid].push(tag); } up("rowTags", nrt);
                            const nc = { ...(ct.tagColors || {}), "Ransom Note": th.sev.med }; up("tagColors", nc);
                            setModal((p) => ({ ...p, rwPivotMsg: `Tagged ${Object.keys(tagMap).length} files as "Ransom Note"`, rwShowPivots: false }));
                            setTimeout(() => setModal((p) => p ? { ...p, rwPivotMsg: null } : p), 3000);
                          } catch {}
                        }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                          Tag Ransom Note Files ({data.ransomNoteCount})
                        </button>
                      )}
                      {/* Tag payload candidates */}
                      {data.suspiciousFiles?.filter(s => s.score >= 0.35).length > 0 && (
                        <button onClick={async () => {
                          try {
                            const cands = data.suspiciousFiles.filter(s => s.score >= 0.35);
                            const tagMap = {};
                            cands.forEach((cand) => {
                              if (cand.rowId != null) tagMap[cand.rowId] = ["Payload"];
                            });
                            await tle.bulkAddTags(ct.id, tagMap);
                            const td = await tle.getAllTagData(ct.id); const nrt = {}; for (const { rowid, tag } of td) { if (!nrt[rowid]) nrt[rowid] = []; nrt[rowid].push(tag); } up("rowTags", nrt);
                            const nc = { ...(ct.tagColors || {}), Payload: th.sev.critical }; up("tagColors", nc);
                            setModal((p) => ({ ...p, rwPivotMsg: `Tagged ${Object.keys(tagMap).length} files as "Payload"`, rwShowPivots: false }));
                            setTimeout(() => setModal((p) => p ? { ...p, rwPivotMsg: null } : p), 3000);
                          } catch {}
                        }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                          Tag Payload Candidates ({data.suspiciousFiles.filter(s => s.score >= 0.35).length})
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
            {/* Pivot feedback toast */}
            {modal.rwPivotMsg && (
              <span style={{ fontSize: 10, color: th.accent, fontWeight: 500, fontFamily: "-apple-system, sans-serif", animation: "tle-overlay-in var(--m-base) var(--ease-out-soft)" }}>{modal.rwPivotMsg}</span>
            )}
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              {totalSelected > 0 && <button onClick={copySelected} style={{ ...ms.bs, display: "flex", alignItems: "center", gap: 4 }}>Copy Selected <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 8, background: th.accent, color: "#fff", fontWeight: 700, lineHeight: "14px" }}>{totalSelected}</span></button>}
              {data && data.encryptedCount > 0 && <button onClick={copyReport} style={ms.bs}>Copy Summary</button>}
              {data && data.encryptedCount > 0 && <button onClick={exportPdf} style={{ ...ms.bs, display: "flex", alignItems: "center", gap: 4 }}><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><polyline points="9 15 12 18 15 15"/></svg>Export PDF</button>}
              <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
            </div>
          </>)}
        </div>
      </>)}
    </DraggableResizableModal>
  );
}
