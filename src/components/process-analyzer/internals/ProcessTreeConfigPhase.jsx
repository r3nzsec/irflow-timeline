import { PI_ALL_RULES, PI_TECHNIQUE_GROUPS } from "../../../utils/process-inspector.js";
import { customRuleErrors, validateCustomRule } from "../../../utils/process-inspector-pipeline.js";

/**
 * Process Inspector config phase — column mapping, intents, rules, custom rules, build.
 * Receives a flat props bag from ProcessTreeModal (shared state/handlers).
 */
export default function ProcessTreeConfigPhase(p) {
  const {
    modal, setModal, th, ms, ct, cols, hasCols,
    handleBuild, refreshPtPreview,
    piAnalystProfile, setPiAnalystProfile,
    PI_SEV_COLORS, SUS_COLORS,
    piCoverageInfo, piGroupState, togglePiGroup, applyPiIntent, resetPiRules,
    ptSkipWarnings, ptSanityWarnings, PI_INTENTS,
    pw = 1200,
  } = p;

        const piDisabledSet = modal.ptDisabledRules || new Set();
        const eventIdValue = modal.eventIdValue;
        const selStyle = {
          background: th.bgInput,
          color: th.text,
          border: `1px solid ${th.border}`,
          borderRadius: 6,
          padding: "4px 8px",
          fontSize: 12,
          fontFamily: "monospace",
        };
        const PI_TELEMETRY = [
          { id: "sysmon", label: "Sysmon Process Create", eid: "1", desc: "Full parent/child with GUIDs + command line" },
          { id: "security", label: "Security Process Create", eid: "4688", desc: "PID-based linking, limited parent info" },
        ];
        // Active when value is not explicitly false (default on).
        const toggleTelemetry = (key) => {
          setModal((p) => {
            const cur = p.ptTelemetry || {};
            const nextActive = !(cur[key] !== false);
            const newTel = { ...cur, [key]: nextActive };
            const eids = [];
            if (newTel.sysmon !== false) eids.push("1");
            if (newTel.security !== false) eids.push("4688");
            return { ...p, ptTelemetry: newTel, eventIdValue: eids.join(",") || null };
          });
          setTimeout(() => refreshPtPreview(), 0);
        };
        const prev = modal.ptPreview;
        const prevLoading = modal.ptPreviewLoading;
        const evCounts = prev?.eventCounts || {};
        const fullEvCounts = prev?.fullScopeEventCounts || {};
        const colQuality = prev?.columnQuality || {};
        const linkQuality = prev?.linkingQuality || {};
        const linkMode = prev?.linkingMode || "unknown";
        const providerMix = prev?.providerMix || {};
        const isEvtxECmd = prev?.isEvtxECmd || false;
        const trackedEvents = prev?.trackedEvents || 0;
        const candidateRows = prev?.candidateRows || 0;
        const fullScopeCandidateRows = prev?.fullScopeCandidateRows || 0;
        const previewMode = prev?.previewMode || "empty";
        const autoGenericFallback = prev?.autoGenericFallback === true;
        const usingGenericRows = autoGenericFallback && previewMode === "candidate-rows";
        const buildableRows = usingGenericRows ? candidateRows : trackedEvents;
        const providerFallback = prev?.providerFallback || false;
        const eidNormalized = prev?.eidNormalized || false;
        const skipW = ptSkipWarnings(evCounts, candidateRows, fullScopeCandidateRows, autoGenericFallback);
        const sanityW = ptSanityWarnings(colQuality, linkQuality);
        const allWarnings = [...skipW, ...sanityW];
        if (providerFallback)
          allWarnings.push({ level: "warn", text: "Provider column may be mis-mapped \u2014 preview using event-ID-only fallback" });
        if (eidNormalized)
          allWarnings.push({ level: "warn", text: "Event ID column contains non-standard values \u2014 using normalized matching" });
        if (buildableRows > (modal.maxRows || 200000))
          allWarnings.push({ level: "warn", text: `${buildableRows.toLocaleString()} rows exceed limit of ${(modal.maxRows || 200000).toLocaleString()} \u2014 tree will be truncated` });
        const topValues = prev?.topValues || {};
        const dataShape = prev?.dataShape || {};
        const linkDot = { guid: th.success, "pid-only": th.sev.high, insufficient: th.danger }[linkMode] || th.textMuted;
        const sampleRows = prev?.sampleRows || [];
        const sampleHeaders = dataShape.sampleHeaders || [];
        // Readiness score + detection capability breakdown
        const _readiness = (() => {
          if (!prev || prevLoading) return { score: "unknown", label: "Scanning\u2026", color: th.textMuted, blockers: [], caps: [] };
          const blockers = [];
          if (buildableRows === 0) blockers.push(usingGenericRows ? "No generic process rows found" : "No process-creation events (EID 1/4688) found");
          if (!usingGenericRows && !cols.eventId) blockers.push("Event ID column not mapped");
          if (linkMode === "insufficient") blockers.push("No GUID or PID linkage available");
          if ((linkQuality.cmdLineCoverage || 0) < 10) blockers.push("Command line coverage < 10%");
          if ((linkQuality.parentImageCoverage || 0) < 10) blockers.push("Parent image coverage < 10%");
          if (!usingGenericRows && eidNormalized) blockers.push("Event ID values needed normalization");
          if (!usingGenericRows && providerFallback) blockers.push("Provider column may be mis-mapped");
          // Detection capability breakdown
          const guidOk = (linkQuality.guidCoverage || 0) >= 50;
          const pidOk = (linkQuality.pidCoverage || 0) >= 50;
          const cmdOk = (linkQuality.cmdLineCoverage || 0) >= 30;
          const piOk = (linkQuality.parentImageCoverage || 0) >= 30;
          const noEvents = buildableRows === 0;
          const caps = [
            { name: "Tree reconstruction", status: noEvents ? "unavailable" : guidOk ? "good" : pidOk ? "weak" : "unavailable",
              note: noEvents ? "no rows" : guidOk ? "GUID-linked" : pidOk ? "PID-only fallback" : "no linkage" },
            { name: "Chain detections", status: noEvents ? "unavailable" : (guidOk || pidOk) && piOk ? "good" : (guidOk || pidOk) ? "weak" : "unavailable",
              note: noEvents ? "no rows" : !guidOk && !pidOk ? "needs parent linkage" : !piOk ? "parent image sparse" : "parent context available" },
            { name: "Standalone detections", status: noEvents ? "unavailable" : cmdOk ? "good" : "weak",
              note: noEvents ? "no rows" : cmdOk ? `command line ${linkQuality.cmdLineCoverage || 0}%` : `command line only ${linkQuality.cmdLineCoverage || 0}%` },
            { name: "Sequence detection", status: noEvents ? "unavailable" : cmdOk && (guidOk || pidOk) ? "good" : cmdOk ? "weak" : "unavailable",
              note: noEvents ? "no rows" : !cmdOk ? "needs command line" : !(guidOk || pidOk) ? "no tree for root affinity" : "tree + command line available" },
          ];
          const crit = blockers.length > 0 && (buildableRows === 0 || linkMode === "insufficient");
          if (crit) return { score: "insufficient", label: "Insufficient for tree building", color: th.danger, blockers, caps };
          if (usingGenericRows && blockers.length > 0) return { score: "usable", label: "Usable with generic process rows", color: th.sev.high, blockers, caps };
          if (usingGenericRows) return { score: "ready", label: "Ready with generic process rows", color: th.success, blockers: [], caps };
          if (blockers.length > 0) return { score: "usable", label: "Usable with reduced confidence", color: th.sev.high, blockers, caps };
          return { score: "ready", label: "Ready", color: th.success, blockers: [], caps };
        })();
        // Mapping status language
        const _coreCols = ["pid", "ppid", "image", "cmdLine", "ts", "eventId"].filter(k => cols[k]).length;
        const _enrichCols = ["guid", "parentGuid", "parentImage", "user", "elevation", "integrity", "provider"].filter(k => cols[k]).length;
        const _mapLabel = _coreCols >= 6 ? "Core mapped" : _coreCols >= 4 ? "Core incomplete" : "Core missing";
        const _enrichLabel = _enrichCols >= 5 ? "enrichment good" : _enrichCols >= 2 ? "enrichment sparse" : "enrichment minimal";
        const warnIcon = { error: "\u26D4", warn: "\u26A0", info: "\u2139" };
        const warnColor = { error: th.danger, warn: th.sev.high, info: th.accent };
        const mappedCount = ["pid", "ppid", "guid", "parentGuid", "image", "parentImage", "cmdLine", "user", "ts", "eventId", "elevation", "integrity", "provider"].filter(k => cols[k]).length;
        // PI_ALL_RULES, PI_SEV_COLORS, PI_TECHNIQUE_GROUPS are now imported from
        // process-inspector.js — the canonical source of truth for rule metadata.
        // (local PI_RULES + PI_SEV_COLORS deleted — now imported from process-inspector.js)
        const piActiveCount = PI_ALL_RULES.length - [...piDisabledSet].filter(k => k.startsWith("pi-")).length;
        const piCustomCount = (modal.ptCustomRules || []).length;
        const piCustomRuleErrors = (modal.ptCustomRules || [])
          .map((rule, idx) => {
            const pattern = String(rule.pattern || "").trim();
            const key = pattern || rule.name || `custom-${idx}`;
            const message = customRuleErrors.get(key) || customRuleErrors.get(pattern) || validateCustomRule(rule);
            return message ? { idx, rule, message } : null;
          })
          .filter(Boolean);
        const togglePiRule = (key) => setModal((p) => { const s = new Set(p.ptDisabledRules || []); s.has(key) ? s.delete(key) : s.add(key); return { ...p, ptDisabledRules: s }; });
        const togglePiExpand = (key) => setModal((p) => ({ ...p, ptExpandedRule: p.ptExpandedRule === key ? null : key }));
        const addPiCustomRule = () => {
          const nr = modal.ptNewRule || {};
          const name = String(nr.name || "").trim();
          const pattern = String(nr.pattern || "").trim();
          const error = validateCustomRule(nr);
          if (error) {
            setModal((p) => ({ ...p, ptNewRuleError: error }));
            return;
          }
          setModal((p) => ({
            ...p,
            ptCustomRules: [...(p.ptCustomRules || []), {
              ...nr,
              name,
              pattern,
              parentProcess: String(nr.parentProcess || "").trim(),
              processName: String(nr.processName || "").trim(),
              imageContains: String(nr.imageContains || "").trim(),
              cmdContains: String(nr.cmdContains || "").trim(),
            }],
            ptAddingRule: false,
            ptNewRule: {},
            ptNewRuleError: "",
          }));
        };
        const deletePiCustomRule = (idx) => setModal((p) => { const arr = [...(p.ptCustomRules || [])]; arr.splice(idx, 1); return { ...p, ptCustomRules: arr }; });
        const ptCoverageTone = (pct, threshold) => pct >= threshold ? (th.success) : pct > 0 ? th.sev.high : (th.danger);
        const piCov = piCoverageInfo(cols);
        const piCovColor = { high: th.sev.clean, medium: th.sev.med, low: th.sev.critical }[piCov.level];
        const piTechniqueGridColumns = pw < 980 ? "1fr" : "1fr 1fr";

        return (
        <div style={{ padding: 20, overflowY: "auto", flex: 1, minHeight: 0 }}>
          {modal.error && <div style={{ padding: "10px 14px", marginBottom: 14, background: `${(th.danger)}15`, border: `1px solid ${(th.danger)}33`, borderRadius: 8, color: th.danger, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>{modal.error}</div>}
          <div style={{ marginBottom: 12 }}>
            <div style={{ padding: "10px 14px", background: `${piCovColor}08`, border: `1px solid ${piCovColor}22`, borderRadius: 10, marginBottom: 12, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={piCovColor} strokeWidth="2" strokeLinecap="round">
                  {piCov.level === "high" ? <><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></> : piCov.level === "medium" ? <><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></> : <><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></>}
                </svg>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>
                    {piCov.level === "high" ? "Tree-ready mapping detected" : piCov.level === "medium" ? "Core tree mapping detected" : "Missing required tree columns"}
                  </div>
                  <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1 }}>
                    {piCov.reqOk}/{piCov.required.length} required · {piCov.recOk}/{piCov.recommended.length} recommended{piCov.guidLink ? " · GUID linkage" : piCov.pidLink ? " · PID linkage" : ""}
                  </div>
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                {!modal.ptShowMapping && <div style={{ display: "flex", gap: 3, marginRight: 4 }}>
                  {[...piCov.required, ...piCov.recommended].map((item) => (
                    <span key={item.key} title={`${item.label}: ${item.mapped ? "mapped" : "unmapped"}`} style={{ width: 6, height: 6, borderRadius: 3, background: item.mapped ? th.sev.clean : th.sev.critical + "66" }} />
                  ))}
                </div>}
                <button onClick={() => setModal((p) => ({ ...p, ptShowMapping: !p.ptShowMapping }))} style={{ ...ms.bsm, fontSize: 10, padding: "2px 8px" }}>
                  {modal.ptShowMapping ? "Hide" : "Edit"}
                </button>
              </div>
            </div>

            {modal.ptShowMapping && (
              <div style={{ padding: "10px 14px", background: `${th.panelBg}55`, border: `1px solid ${th.border}22`, borderRadius: 10, marginBottom: 12 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6 }}>
                  {[
                    ["pid", "Process ID", true], ["ppid", "Parent PID", true], ["guid", "Process GUID", true],
                    ["parentGuid", "Parent GUID", true], ["image", "Image / Exe", true], ["cmdLine", "Command Line", false],
                    ["ts", "Timestamp", false], ["eventId", "Event ID", false], ["parentImage", "Parent Image", false],
                    ["user", "User", false], ["provider", "Provider", false], ["integrity", "Integrity", false], ["elevation", "Elevation", false],
                  ].map(([key, label, req]) => (
                    <div key={key}>
                      <label style={{ fontSize: 9, color: cols[key] ? th.textDim : req ? th.sev.critical : th.textMuted, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.04em", display: "flex", alignItems: "center", gap: 3, marginBottom: 2 }}>
                        {cols[key] ? <span style={{ color: th.sev.clean }}>{"\u2713"}</span> : req ? <span style={{ color: th.sev.critical }}>{"\u2717"}</span> : <span style={{ color: th.textMuted }}>{"\u25CB"}</span>}
                        {label}
                      </label>
                      <select value={cols[key] || ""} onChange={(e) => { const v = e.target.value || null; setModal((p) => { const nc = { ...p.columns, [key]: v }; setTimeout(() => refreshPtPreview(nc), 0); return { ...p, columns: nc }; }); }} style={{ ...ms.sl, fontSize: 10, padding: "3px 6px" }}>
                        <option value="">-- auto --</option>
                        {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}
                      </select>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
              <div style={{ display: "flex", gap: 4 }}>
                {PI_INTENTS.map((intent) => {
                  const active = (modal.ptIntent || "balanced") === intent.id;
                  return (
                    <button key={intent.id} onClick={() => applyPiIntent(intent)} title={intent.desc}
                      style={{ padding: "4px 10px", fontSize: 10, fontWeight: active ? 600 : 400, fontFamily: "-apple-system, sans-serif", background: active ? `${th.accent}18` : "transparent", color: active ? th.accent : th.textDim, border: `1px solid ${active ? th.accent + "44" : th.border + "22"}`, borderRadius: 6, cursor: "pointer", transition: "all var(--m-base)" }}>
                      {intent.label}
                    </button>
                  );
                })}
              </div>
              <button onClick={resetPiRules} title="Reset all rules to defaults"
                style={{ padding: "3px 8px", fontSize: 9, fontFamily: "-apple-system, sans-serif", background: "transparent", color: th.textMuted, border: `1px solid ${th.border}22`, borderRadius: 4, cursor: "pointer", display: "flex", alignItems: "center", gap: 3, transition: "all var(--m-base)" }}
                onMouseEnter={(e) => { e.currentTarget.style.color = th.accent; e.currentTarget.style.borderColor = th.accent + "44"; }}
                onMouseLeave={(e) => { e.currentTarget.style.color = th.textMuted; e.currentTarget.style.borderColor = th.border + "22"; }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
                Reset
              </button>
            </div>

            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>Detection Techniques</div>
              <div style={{ display: "grid", gridTemplateColumns: piTechniqueGridColumns, gap: 8, alignItems: "start" }}>
                {PI_TECHNIQUE_GROUPS.map((group) => {
                  const state = piGroupState(group.ruleIds, piDisabledSet);
                  const activeRuleCount = group.ruleIds.filter((id) => !piDisabledSet.has(id)).length;
                  const isOn = state !== "off";
                  return (
                    <div key={group.id} style={{ padding: "10px 14px", background: isOn ? `${th.accent}08` : `${th.panelBg}33`, border: `1px solid ${isOn ? th.accent + "22" : th.border + "22"}`, borderRadius: 10, cursor: "pointer", transition: "all var(--m-base)", opacity: isOn ? 1 : 0.6, minHeight: state === "partial" ? 100 : 72 }}
                      onClick={() => togglePiGroup(group)}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                        <div style={{ minWidth: 0, paddingRight: 10 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{group.label}</div>
                          <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1, lineHeight: 1.4 }}>{group.desc}</div>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                          <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{activeRuleCount}/{group.ruleIds.length}</span>
                          <div style={{ width: 32, height: 18, borderRadius: 10, background: isOn ? th.accent : th.textMuted + "33", transition: "background var(--m-base)", position: "relative" }}>
                            <div style={{ width: 14, height: 14, borderRadius: 8, background: "#fff", position: "absolute", top: 2, left: isOn ? 16 : 2, transition: "left var(--m-base)", boxShadow: "0 1px 3px rgba(0,0,0,0.2)" }} />
                          </div>
                        </div>
                      </div>
                      {state === "partial" && (
                        <div style={{ marginTop: 6, paddingTop: 6, borderTop: `1px solid ${th.border}15`, display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {group.ruleIds.map((ruleId) => {
                            const r = PI_ALL_RULES.find((x) => x.id === ruleId);
                            if (!r) return null;
                            const off = piDisabledSet.has(ruleId);
                            return (
                              <span key={ruleId} onClick={(e) => { e.stopPropagation(); togglePiRule(ruleId); }}
                                style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: off ? `${th.textMuted}11` : `${PI_SEV_COLORS[r.sev]}15`, color: off ? th.textMuted : PI_SEV_COLORS[r.sev], border: `1px solid ${off ? th.border + "22" : PI_SEV_COLORS[r.sev] + "33"}`, fontFamily: "-apple-system, sans-serif", cursor: "pointer", textDecoration: off ? "line-through" : "none", opacity: off ? 0.5 : 1, transition: "all var(--m-base)" }}>
                                {r.name}
                              </span>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                {PI_TELEMETRY.map((src) => {
                  const active = modal.ptTelemetry?.[src.id] !== false;
                  const srcCount = evCounts[src.eid] || 0;
                  return (
                    <label key={src.id} style={{ fontSize: 11, color: th.textDim, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontFamily: "-apple-system, sans-serif" }}>
                      <input type="checkbox" checked={active} onChange={() => toggleTelemetry(src.id)} style={{ accentColor: th.accent }} />
                      {src.label}
                      <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "SF Mono, monospace" }}>{srcCount.toLocaleString()}</span>
                    </label>
                  );
                })}
              </div>
              <span style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{piActiveCount}/{PI_ALL_RULES.length} rules{piCustomCount > 0 ? ` + ${piCustomCount} custom` : ""}</span>
            </div>

            <div style={{ padding: "10px 14px", background: `${th.panelBg}44`, border: `1px solid ${th.border}22`, borderRadius: 10 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Event Availability</div>
                {prev && <span style={{ fontSize: 9, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{trackedEvents > 0 ? `${trackedEvents.toLocaleString()} tracked events` : candidateRows > 0 ? `${candidateRows.toLocaleString()} candidate rows` : "0 rows"}</span>}
              </div>
              {prevLoading ? (
                <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: "6px 0" }}>Scanning dataset...</div>
              ) : !prev ? (
                <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: "6px 0" }}>Preview unavailable</div>
              ) : (
                <>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: allWarnings.length > 0 ? 8 : 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${_readiness.color}12`, border: `1px solid ${_readiness.color}22` }}>
                      <span style={{ width: 5, height: 5, borderRadius: 3, background: _readiness.color }} />
                      <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{_readiness.label}</span>
                    </div>
                    {PI_TELEMETRY.map((src) => {
                      const total = evCounts[src.eid] || 0;
                      const present = total > 0;
                      return (
                        <div key={src.id} style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: present ? th.sev.clean + "10" : `${th.textMuted}08`, border: `1px solid ${present ? th.sev.clean + "22" : th.border + "15"}` }}>
                          <span style={{ width: 5, height: 5, borderRadius: 3, background: present ? th.sev.clean : th.textMuted + "44" }} />
                          <span style={{ fontSize: 9, color: present ? th.text : th.textMuted, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{src.label}</span>
                          {present && <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{total >= 1000 ? (total / 1000).toFixed(1) + "k" : total}</span>}
                        </div>
                      );
                    })}
                    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${linkDot}10`, border: `1px solid ${linkDot}22` }}>
                      <span style={{ width: 5, height: 5, borderRadius: 3, background: linkDot }} />
                      <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Linking</span>
                      <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{linkMode === "guid" ? "GUID" : linkMode === "pid-only" ? "PID" : "None"}</span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${ptCoverageTone(linkQuality.cmdLineCoverage || 0, 30)}10`, border: `1px solid ${ptCoverageTone(linkQuality.cmdLineCoverage || 0, 30)}22` }}>
                      <span style={{ width: 5, height: 5, borderRadius: 3, background: ptCoverageTone(linkQuality.cmdLineCoverage || 0, 30) }} />
                      <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Command Line</span>
                      <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{linkQuality.cmdLineCoverage || 0}%</span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${ptCoverageTone(linkQuality.parentImageCoverage || 0, 30)}10`, border: `1px solid ${ptCoverageTone(linkQuality.parentImageCoverage || 0, 30)}22` }}>
                      <span style={{ width: 5, height: 5, borderRadius: 3, background: ptCoverageTone(linkQuality.parentImageCoverage || 0, 30) }} />
                      <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Parent Image</span>
                      <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{linkQuality.parentImageCoverage || 0}%</span>
                    </div>
                    {candidateRows > 0 && trackedEvents === 0 && (
                      <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${th.accent}10`, border: `1px solid ${th.accent}22` }}>
                        <span style={{ width: 5, height: 5, borderRadius: 3, background: th.accent }} />
                        <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Generic Rows</span>
                        <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{candidateRows >= 1000 ? (candidateRows / 1000).toFixed(1) + "k" : candidateRows}</span>
                      </div>
                    )}
                    {usingGenericRows && (
                      <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${th.accent}10`, border: `1px solid ${th.accent}22` }}>
                        <span style={{ width: 5, height: 5, borderRadius: 3, background: th.accent }} />
                        <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Fallback Build Mode</span>
                      </div>
                    )}
                  </div>

                  {allWarnings.length > 0 && (
                    <div style={{ borderTop: `1px solid ${th.border}15`, paddingTop: 6 }}>
                      {allWarnings.slice(0, 4).map((warning, idx) => (
                        <div key={`${warning.level}-${idx}`} style={{ display: "flex", alignItems: "flex-start", gap: 6, padding: "2px 0" }}>
                          <span style={{ fontSize: 10, flexShrink: 0, marginTop: 1, color: warning.level === "error" ? th.sev.critical : warning.level === "warn" ? th.sev.med : th.textMuted }}>
                            {warning.level === "error" ? "\u2717" : warning.level === "warn" ? "\u26A0" : "\u25CB"}
                          </span>
                          <span style={{ fontSize: 10, color: warning.level === "error" ? th.sev.critical : warning.level === "warn" ? th.sev.med : th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>{warning.text}</span>
                        </div>
                      ))}
                      {allWarnings.length > 4 && (
                        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", paddingTop: 2 }}>
                          {allWarnings.length - 4} more notes in current scope.
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          {/* 6h. Collapsible Advanced Section */}
          <button onClick={() => setModal(p => ({ ...p, ptShowAdvanced: !p.ptShowAdvanced }))}
            style={{ width: "100%", padding: "10px 14px", background: `${th.accent}08`, border: `1px solid ${th.border}33`, borderRadius: modal.ptShowAdvanced ? "10px 10px 0 0" : 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "space-between", transition: "all var(--m-base)", marginBottom: modal.ptShowAdvanced ? 0 : 0, opacity: buildableRows === 0 ? 0.5 : 1 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
              Advanced
            </span>
            <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
	              <span>{piActiveCount}/{PI_ALL_RULES.length} rules{piCustomCount > 0 ? `, ${piCustomCount} custom` : ""}{piCustomRuleErrors.length > 0 ? `, ${piCustomRuleErrors.length} rule error${piCustomRuleErrors.length === 1 ? "" : "s"}` : ""}</span>
              <span style={{ transform: modal.ptShowAdvanced ? "rotate(180deg)" : "rotate(0deg)", transition: "transform var(--m-base)", fontSize: 12 }}>{"\u25BE"}</span>
            </span>
          </button>
          {modal.ptShowAdvanced && (
            <div style={{ padding: "12px 14px", borderLeft: `1px solid ${th.border}33`, borderRight: `1px solid ${th.border}33`, borderBottom: `1px solid ${th.border}33`, borderRadius: "0 0 10px 10px", background: `${th.panelBg}55` }}>
              {/* Custom EventID override + Max processes */}
              <div style={{ display: "grid", gridTemplateColumns: "110px 1fr 110px 1fr", gap: "6px 10px", alignItems: "center", fontSize: 12, fontFamily: "-apple-system, sans-serif", marginBottom: 12 }}>
                <label style={{ color: th.textDim, textAlign: "right", fontSize: 11 }}>EventID override:</label>
                <input value={eventIdValue || ""} onChange={(e) => setModal(p => ({ ...p, eventIdValue: e.target.value }))} placeholder="1,4688 (blank = all)" style={{ ...selStyle, width: "100%" }} />
                <label style={{ color: th.textDim, textAlign: "right", fontSize: 11 }}>Max processes:</label>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <input type="number" value={modal.maxRowsInput ?? modal.maxRows ?? 200000} onChange={(e) => setModal(p => ({ ...p, maxRowsInput: e.target.value }))} onBlur={(e) => { const v = parseInt(e.target.value); setModal(p => ({ ...p, maxRows: isNaN(v) || v < 100 ? 200000 : v, maxRowsInput: undefined })); }} style={{ ...selStyle, width: 100 }} min="100" step="50000" />
                  <span style={{ fontSize: 10, color: th.textMuted }}>default: 200,000</span>
                </div>
              </div>

              {/* Individual rule toggles */}
              <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                Detection Rules ({piActiveCount}/{PI_ALL_RULES.length})
              </div>
              {[...PI_ALL_RULES].sort((a, b) => { const so = { critical: 0, high: 1, medium: 2, low: 3 }; return (so[a.sev] ?? 9) - (so[b.sev] ?? 9); }).map((r) => {
                const off = piDisabledSet.has(r.id);
                const expanded = modal.ptExpandedRule === r.id;
                const groupMeta = PI_TECHNIQUE_GROUPS.find((g) => g.id === r.group);
                const groupLabel = groupMeta?.label || r.group || "";
                return (
                  <div key={r.id}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", cursor: "pointer", opacity: off ? 0.45 : 1, transition: "opacity var(--m-base)" }}>
                      <input type="checkbox" checked={!off} onChange={() => togglePiRule(r.id)} style={{ accentColor: th.accent, margin: 0, flexShrink: 0 }} />
                      <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: PI_SEV_COLORS[r.sev] + "22", color: PI_SEV_COLORS[r.sev], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 52, textAlign: "center", textTransform: "uppercase" }}>{r.sev}</span>
                      <span onClick={() => togglePiExpand(r.id)} style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1, cursor: "pointer" }}>{groupLabel} {"\u2014"} {r.name}</span>
                      <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{r.technique}</span>
                      <span onClick={() => togglePiExpand(r.id)} style={{ fontSize: 9, color: expanded ? th.accent : th.textMuted, cursor: "pointer", padding: "0 2px", transform: expanded ? "rotate(180deg)" : "rotate(0deg)", transition: "transform var(--m-base)", flexShrink: 0 }}>{"\u25BE"}</span>
                    </div>
                    {expanded && r.logic && (
                      <div style={{ margin: "2px 0 6px 28px", padding: "8px 12px", background: `${th.accent}06`, border: `1px solid ${th.accent}18`, borderRadius: 6 }}>
                        <div style={{ display: "grid", gridTemplateColumns: "90px 1fr", gap: "3px 10px", fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace" }}>
                          {r.logic.map((l, li) => (
                            <div key={li} style={{ display: "contents" }}>
                              <span style={{ color: th.textMuted, textTransform: "uppercase", fontSize: 9, fontWeight: 600, letterSpacing: "0.04em", paddingTop: 1 }}>{l.label}</span>
                              <span style={{ color: th.text, lineHeight: 1.5, wordBreak: "break-word" }}>{l.value}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Custom rules */}
	              {(modal.ptCustomRules || []).length > 0 && (
	                <div style={{ marginTop: 10 }}>
	                  <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Custom Rules</div>
	                  {(modal.ptCustomRules || []).map((cr, i) => {
	                    const pattern = String(cr.pattern || "").trim();
	                    const key = pattern || cr.name || `custom-${i}`;
	                    const ruleError = customRuleErrors.get(key) || customRuleErrors.get(pattern) || validateCustomRule(cr);
	                    const fieldBits = [cr.parentProcess && `parent=${cr.parentProcess}`, cr.processName && `proc=${cr.processName}`, cr.imageContains && `path~${cr.imageContains}`, cr.cmdContains && `cmd~${cr.cmdContains}`, pattern && `rx`].filter(Boolean).join(" · ");
	                    return (
	                      <div key={`custom-${i}`} style={{ padding: "3px 0" }}>
	                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
	                          <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: PI_SEV_COLORS[cr.severity || "medium"] + "22", color: PI_SEV_COLORS[cr.severity || "medium"], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 52, textAlign: "center", textTransform: "uppercase" }}>{cr.severity || "med"}</span>
	                          <span style={{ fontSize: 11, color: ruleError ? th.danger : th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{cr.category || "Custom"} {"\u2014"} {cr.name || "Custom Rule"}</span>
	                          {ruleError && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.danger}18`, color: th.danger, fontFamily: "SF Mono, monospace", fontWeight: 600 }}>not active</span>}
	                          {cr.behavior && <span style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontFamily: "SF Mono, monospace", fontWeight: 600 }}>{cr.behavior}</span>}
	                          <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{cr.technique || ""}</span>
	                          <button onClick={() => deletePiCustomRule(i)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "0 4px", lineHeight: 1 }} onMouseEnter={(e) => e.currentTarget.style.color = th.danger} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>{"\u00D7"}</button>
	                        </div>
	                        {fieldBits && !ruleError && (
	                          <div style={{ marginLeft: 60, marginTop: 2, fontSize: 9, color: th.textMuted, fontFamily: "SF Mono, monospace" }}>{fieldBits}</div>
	                        )}
	                        {ruleError && (
	                          <div style={{ marginLeft: 60, marginTop: 2, fontSize: 9, color: th.danger, fontFamily: "-apple-system, sans-serif", lineHeight: 1.35 }}>
	                            {ruleError}. This rule is skipped until fixed.
	                          </div>
	                        )}
	                      </div>
	                    );
	                  })}
	                </div>
	              )}

              {/* Add custom rule */}
              {!modal.ptAddingRule ? (
	                <button onClick={() => setModal(p => ({ ...p, ptAddingRule: true, ptNewRule: {}, ptNewRuleError: "" }))}
	                  style={{ ...ms.bsm, marginTop: 8, display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ fontSize: 13, lineHeight: 1 }}>+</span> Add Custom Rule
                </button>
              ) : (
                <div style={{ marginTop: 8, padding: "10px 12px", background: `${th.accent}08`, border: `1px solid ${th.accent}22`, borderRadius: 8 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
	                    <input value={(modal.ptNewRule || {}).category || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, category: e.target.value }, ptNewRuleError: "" }))} placeholder="Category (e.g. Execution)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
	                    <input value={(modal.ptNewRule || {}).name || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, name: e.target.value }, ptNewRuleError: "" }))} placeholder="Rule Name" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px", borderColor: modal.ptNewRuleError === "Rule name is required." ? th.danger : undefined }} />
	                    <input value={(modal.ptNewRule || {}).technique || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, technique: e.target.value } }))} placeholder="MITRE Technique (e.g. T1059)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                    <select value={(modal.ptNewRule || {}).severity || "medium"} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, severity: e.target.value } }))}
                      style={{ ...ms.sl, fontSize: 11, padding: "4px 8px" }}>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                    <input value={(modal.ptNewRule || {}).parentProcess || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, parentProcess: e.target.value }, ptNewRuleError: "" }))} placeholder="Parent process (e.g. winword.exe)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                    <input value={(modal.ptNewRule || {}).processName || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, processName: e.target.value }, ptNewRuleError: "" }))} placeholder="Child process (e.g. powershell.exe)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                    <input value={(modal.ptNewRule || {}).imageContains || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, imageContains: e.target.value }, ptNewRuleError: "" }))} placeholder="Image path contains" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                    <input value={(modal.ptNewRule || {}).cmdContains || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, cmdContains: e.target.value }, ptNewRuleError: "" }))} placeholder="Command line contains" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
	                    <input value={(modal.ptNewRule || {}).pattern || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, pattern: e.target.value }, ptNewRuleError: "" }))} placeholder="Optional regex (process/cmdline/path)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px", gridColumn: "1 / -1", borderColor: modal.ptNewRuleError && /regex|pattern|compile|quantifier/i.test(modal.ptNewRuleError || "") ? th.danger : undefined }} />
                    <select value={(modal.ptNewRule || {}).behavior || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, behavior: e.target.value || null } }))}
                      style={{ ...ms.sl, fontSize: 11, padding: "4px 8px", borderColor: !(modal.ptNewRule || {}).behavior ? th.sev.med : undefined }}>
                      <option value="">Behavior (recommended)</option>
                      <option value="script-exec">Script Execution</option>
                      <option value="shell-exec">Shell Execution</option>
                      <option value="lolbin-exec">LOLBin Execution</option>
                      <option value="service-exec">Service Execution</option>
                      <option value="cred">Credential Access</option>
                      <option value="evasion">Defense Evasion</option>
                      <option value="persist">Persistence</option>
                      <option value="lateral">Lateral Movement</option>
                      <option value="download">Download/Stage</option>
                      <option value="recon">Reconnaissance</option>
                      <option value="exfil">Exfiltration</option>
                      <option value="rmm">Remote Management</option>
                      <option value="network">Network</option>
                      <option value="dns">DNS</option>
                      <option value="file-drop">File Drop</option>
                      <option value="image-load">Image Load</option>
                      <option value="inject">Injection</option>
                    </select>
	                  </div>
	                  {modal.ptNewRuleError && (
	                    <div style={{ fontSize: 10, color: th.danger, fontFamily: "-apple-system, sans-serif", marginTop: 6, padding: "6px 8px", border: `1px solid ${th.danger}33`, borderRadius: 6, background: `${th.danger}10` }}>
	                      {modal.ptNewRuleError}
	                    </div>
	                  )}
                  <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 4 }}>
                    Match any combination of parent, process, path, cmdline, and/or regex. Behavior tag feeds Story sequence detection.
                  </div>
	                  {!(modal.ptNewRule || {}).behavior && (modal.ptNewRule || {}).name && (
                    <div style={{ fontSize: 9, color: th.sev.med, fontFamily: "-apple-system, sans-serif", marginTop: 4 }}>
                      Without a behavior tag this rule won{"'"}t participate in sequence detection.
                    </div>
	                  )}
	                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 8 }}>
	                    <button onClick={() => setModal(p => ({ ...p, ptAddingRule: false, ptNewRule: {}, ptNewRuleError: "" }))} style={ms.bsm}>Cancel</button>
                    <button onClick={addPiCustomRule} style={{ ...ms.bsm, background: th.primaryBtn || th.fillAccent, color: th.onPrimary, border: "none" }}>Add Rule</button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 6i. Action Buttons */}
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
            <button onClick={() => setModal(null)} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif" }}>Cancel</button>
            <button onClick={handleBuild} disabled={!hasCols} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: hasCols ? "pointer" : "not-allowed", background: hasCols ? (th.fillAccent) : th.border, color: hasCols ? th.onAccent : th.textMuted, border: "none", fontFamily: "-apple-system, sans-serif" }}>Build Tree</button>
          </div>
        </div>
  );
}
