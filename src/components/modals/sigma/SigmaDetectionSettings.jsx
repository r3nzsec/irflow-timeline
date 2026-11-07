import { Fragment } from "react";
import { formatNumber } from "../../../utils/format.js";
import { useSigmaModalContext } from "./SigmaModalContext.js";

const RULE_SETS = [
  { id: "all", label: "All Rules", desc: "Every detection rule" },
  { id: "core", label: "Core", desc: "Stable+test, high+critical; lowest FP" },
  { id: "core+", label: "Core+", desc: "Stable+test, medium+; needs tuning" },
  { id: "core++", label: "Core++", desc: "All statuses, medium+; broader hunt" },
  { id: "et", label: "Emerging Threats", desc: "Current threat campaigns" },
  { id: "th", label: "Threat Hunting", desc: "Unknown malware; highest FP" },
];

const OUTPUT_MODES = [
  { id: "csv", label: "CSV" },
  { id: "json", label: "JSON" },
  { id: "jsonl", label: "JSONL" },
];

export default function SigmaDetectionSettings() {
  const {
    modal,
    setModal,
    th,
    ms,
    tle,
    status,
    progress,
    downloading,
    availableRepos,
    selectedRepos,
    renderRuleDiffSummary,
    handleDownload,
    handleOpenCustomDir,
    handleImportCustom,
    handleDownloadHayabusa,
    handleUpdateHayabusaRules,
    handleUpdateHayabusa,
    handleSaveDetectionSettings,
    handleAddRuleSuppression,
    handleUpdateRuleSuppression,
    handleRemoveRuleSuppression,
    handleSaveRuleSuppressions,
    checkbox,
  } = useSigmaModalContext();

  const repos = availableRepos || [];
  const repoSelection = selectedRepos || [];
  const hb = modal.hayabusaStatus;
  const hbInstalled = !!hb?.installed;
  const hbDownloading = !!modal.hayabusaDownloading;
  const hbRuleCount = hb?.ruleState?.hayabusaRuleCount || modal.hayabusaUpdateRuleDiff?.currentRuleCount || 0;
  const updateLines = modal.hayabusaUpdateLog || [];
  const updateResult = modal.hayabusaUpdateResult || null;
  const updateActive = hbDownloading || modal.hayabusaUpdating;
  const compatibilityReport = status?.compatibilityReport || modal.ruleInfo?.meta?.compatibilityReport || null;

  const section = (title, meta, children) => (
    <div style={{ ...ms.fg, padding: 12, border: `1px solid ${th.border}44`, borderRadius: 8, background: `${th.panelBg}55` }}>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 10, marginBottom: 9 }}>
        <label style={{ ...ms.lb, margin: 0 }}>{title}</label>
        {meta && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system,sans-serif" }}>{meta}</span>}
      </div>
      {children}
    </div>
  );

  const smallStat = (label, value, color = th.text) => (
    <div style={{ minWidth: 130, padding: "7px 9px", borderRadius: 8, border: `1px solid ${th.border}33`, background: `${th.bgInput || th.bg}66` }}>
      <div style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 11, color, fontWeight: 700, fontFamily: "-apple-system,sans-serif", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div>
    </div>
  );

  const renderUpdatePanel = () => {
    if (!updateActive && updateLines.length === 0 && !updateResult) return null;
    const mode = modal.hayabusaUpdateMode || updateResult?.type || "binary";
    const title = mode === "rules"
      ? "Hayabusa Rule Update"
      : mode === "install"
        ? "Hayabusa Install"
        : "Hayabusa Binary Update";
    const statusText = updateActive ? (progress?.text || "Running...") : "Complete";
    return (
      <div style={{ marginTop: 10, border: `1px solid ${th.border}66`, borderRadius: 8, background: `${th.bgInput || th.bg}66`, overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 10px", borderBottom: `1px solid ${th.border}44` }}>
          <span style={{ fontSize: 11, color: th.text, fontWeight: 700 }}>{title}</span>
          <span style={{ fontSize: 10, color: updateActive ? th.accent : th.sev.clean, marginLeft: "auto" }}>{statusText}</span>
        </div>
        {updateResult && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", padding: "7px 10px 2px" }}>
            {updateResult.type === "binary" && (
              <Fragment>
                <span style={{ fontSize: 10, color: th.textDim }}>Previous: <strong style={{ color: th.text }}>{updateResult.oldVersion || "not installed"}</strong></span>
                <span style={{ fontSize: 10, color: th.textDim }}>Current: <strong style={{ color: th.sev.clean }}>{updateResult.newVersion || updateResult.version || "unknown"}</strong></span>
                <span style={{ fontSize: 10, color: th.textDim }}>{updateResult.upgraded ? "Version changed" : "Already on latest detected version"}</span>
              </Fragment>
            )}
            {updateResult.type === "rules" && (
              <Fragment>
                <span style={{ fontSize: 10, color: th.textDim }}>Engine: <strong style={{ color: th.text }}>{updateResult.version || hb?.version || "unknown"}</strong></span>
                <span style={{ fontSize: 10, color: th.textDim }}>Captured output lines: <strong style={{ color: th.text }}>{formatNumber(updateResult.lineCount || updateLines.length)}</strong></span>
              </Fragment>
            )}
            {updateResult.type === "install" && (
              <Fragment>
                <span style={{ fontSize: 10, color: th.textDim }}>Installed: <strong style={{ color: th.sev.clean }}>{updateResult.version || "unknown"}</strong></span>
                <span style={{ fontSize: 10, color: th.textDim }}>Source: <strong style={{ color: th.text }}>{updateResult.source || "downloaded"}</strong></span>
              </Fragment>
            )}
          </div>
        )}
        {mode === "rules" && renderRuleDiffSummary(updateResult?.ruleDiff || modal.hayabusaUpdateRuleDiff, !!updateResult?.ruleDiff)}
        {updateLines.length > 0 && (
          <div style={{ margin: "6px 10px 10px", maxHeight: 140, overflow: "auto", background: th.bgInput || th.bg, border: `1px solid ${th.border}44`, borderRadius: 6, padding: "6px 8px", fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", lineHeight: 1.45, whiteSpace: "pre-wrap" }}>
            {updateLines.join("\n")}
          </div>
        )}
      </div>
    );
  };

  const renderCompatibilityReport = () => {
    if (!compatibilityReport) return null;
    const unsupported = compatibilityReport.unsupportedRules || 0;
    const skipped = compatibilityReport.skipped || 0;
    const color = unsupported || skipped ? th.sev.med : th.sev.clean;
    const topMap = (map) => Object.entries(map || {})
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 5);
    const renderMap = (label, map) => {
      const rows = topMap(map);
      if (rows.length === 0) return null;
      return (
        <div style={{ minWidth: 160, flex: 1 }}>
          <div style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", fontWeight: 700, marginBottom: 3 }}>{label}</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
            {rows.map(([key, count]) => (
              <span key={`${label}-${key}`} title={key} style={{ maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", padding: "1px 5px", borderRadius: 4, border: `1px solid ${color}33`, background: `${color}10`, color: th.textDim, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace" }}>
                {key}: {formatNumber(count)}
              </span>
            ))}
          </div>
        </div>
      );
    };
    return (
      <div style={{ marginTop: 8, padding: "8px 10px", borderRadius: 8, border: `1px solid ${color}44`, background: `${color}0d` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
          <strong style={{ color, fontSize: 11 }}>JS compatibility report</strong>
          <span style={{ color: th.textDim, fontSize: 10 }}>{formatNumber(compatibilityReport.compatible || 0)} compatible</span>
          <span style={{ color: th.textDim, fontSize: 10 }}>{formatNumber(compatibilityReport.parsed || 0)} parsed</span>
          <span style={{ color: unsupported ? color : th.textMuted, fontSize: 10 }}>{formatNumber(unsupported)} unsupported</span>
          <span style={{ color: skipped ? color : th.textMuted, fontSize: 10 }}>{formatNumber(skipped)} skipped YAML docs</span>
          {status?.ruleSnapshotHash && <span title={status.ruleSnapshotHash} style={{ color: th.textMuted, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", marginLeft: "auto" }}>snapshot {status.ruleSnapshotHash.slice(0, 12)}</span>}
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {renderMap("Unsupported modifiers", compatibilityReport.byModifier)}
          {renderMap("Unsupported conditions", compatibilityReport.byCondition)}
          {renderMap("Unsupported logsources", compatibilityReport.byLogsource)}
        </div>
      </div>
    );
  };

  const renderRepoSelector = () => (
    <Fragment>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 7 }}>
        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system,sans-serif" }}>
          Used only for Current Timeline Tab compatibility scans.
        </div>
        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system,sans-serif" }}>
          {status?.cachedRuleCount
            ? <span>{formatNumber(status.cachedRuleCount)} cached {status.lastUpdate ? <span style={{ color: th.textMuted }}>({new Date(status.lastUpdate).toLocaleDateString()})</span> : null}</span>
            : <span style={{ color: th.textMuted }}>No cached rules</span>}
        </div>
      </div>

      {repos.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 6 }}>
            <button onClick={() => setModal((p) => ({ ...p, selectedRepos: repos.map(r => r.id) }))} style={{ ...ms.bsm, fontSize: 9, padding: "1px 6px" }}>Select All</button>
            <button onClick={() => setModal((p) => ({ ...p, selectedRepos: repos.filter(r => r.default).map(r => r.id) }))} style={{ ...ms.bsm, fontSize: 9, padding: "1px 6px" }}>Defaults</button>
            <button onClick={() => setModal((p) => ({ ...p, selectedRepos: [] }))} style={{ ...ms.bsm, fontSize: 9, padding: "1px 6px" }}>Clear</button>
            <span style={{ fontSize: 9, color: th.textMuted, marginLeft: "auto", fontFamily: "-apple-system,sans-serif" }}>{repoSelection.length}/{repos.length} selected</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 170, overflow: "auto", border: `1px solid ${th.border}22`, borderRadius: 6, padding: 4 }}>
            {repos.map((repo) => {
              const sel = repoSelection.includes(repo.id);
              return (
                <button key={repo.id} onClick={() => {
                  setModal((p) => {
                    const cur = [...(p.selectedRepos || [])];
                    const idx = cur.indexOf(repo.id);
                    if (idx >= 0) cur.splice(idx, 1); else cur.push(repo.id);
                    return { ...p, selectedRepos: cur };
                  });
                }}
                  style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 8px", background: sel ? `${th.accent}08` : "transparent", border: "none", borderRadius: 6, cursor: "pointer", textAlign: "left" }}>
                  <span style={{ color: sel ? th.accent : th.textMuted, fontSize: 12, width: 16, textAlign: "center", flexShrink: 0 }}>{sel ? "\u2713" : "\u25CB"}</span>
                  <div style={{ flex: 1, overflow: "hidden" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 11, color: sel ? th.text : th.textDim, fontWeight: 500, fontFamily: "-apple-system,sans-serif" }}>{repo.name}</span>
                      {repo.default && <span style={{ fontSize: 8, padding: "0 4px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontWeight: 600 }}>recommended</span>}
                    </div>
                    <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system,sans-serif", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{repo.desc}</div>
                  </div>
                  <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", flexShrink: 0 }}>{repo.repo}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      <button onClick={handleDownload} disabled={downloading || repoSelection.length === 0}
        style={{ ...ms.bp, width: "100%", opacity: downloading || repoSelection.length === 0 ? 0.5 : 1, cursor: downloading || repoSelection.length === 0 ? "not-allowed" : "pointer" }}>
        {downloading ? "Downloading..." : `Download Compatibility Rules from ${repoSelection.length} Repo${repoSelection.length !== 1 ? "s" : ""}`}
      </button>

      {renderCompatibilityReport()}

      {downloading && progress && (
        <div style={{ marginTop: 6 }}>
          <div style={{ height: 4, background: th.border, borderRadius: 2, overflow: "hidden" }}>
            <div style={{ height: "100%", background: th.accent, borderRadius: 2, transition: "width var(--m-slow)", width: "100%", animation: "tle-pulse 1.5s ease-in-out infinite" }} />
          </div>
          {progress.detail && <div style={{ fontSize: 10, color: th.textDim, marginTop: 3 }}>{progress.detail}</div>}
        </div>
      )}

      <div style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 12, color: th.text, marginTop: 8 }}>
        <label style={{ ...ms.lb, margin: 0, flexShrink: 0 }}>Compatibility Custom Rules</label>
        <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim, fontSize: 10 }}>
          {status?.customDir || "~/sigma-custom"} {status?.customRuleCount != null && <span>({formatNumber(status.customRuleCount)} rules)</span>}
        </span>
        <button onClick={handleOpenCustomDir} style={ms.bsm}>Open Folder</button>
        <button onClick={handleImportCustom} style={ms.bsm}>Import YAML</button>
      </div>
    </Fragment>
  );

  const renderSuppressionManager = () => {
    const suppressions = modal.ruleSuppressions || [];
    const draft = modal.ruleSuppressionDraft || { ruleId: "", title: "", scopeType: "global", scope: "all cases", reason: "" };
    const enabledCount = suppressions.filter((entry) => entry.enabled !== false).length;
    const globalCount = suppressions.filter((entry) => (entry.scopeType || "global") === "global").length;
    const caseCount = suppressions.filter((entry) => entry.scopeType === "case").length;
    const setDraft = (patch) => setModal((p) => ({
      ...p,
      ruleSuppressionDraft: {
        ...(p.ruleSuppressionDraft || { ruleId: "", title: "", scopeType: "global", scope: "all cases", reason: "" }),
        ...patch,
      },
    }));
    return (
      <Fragment>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 9 }}>
          {smallStat("Enabled", formatNumber(enabledCount), enabledCount ? th.sev.clean : th.textMuted)}
          {smallStat("Global", formatNumber(globalCount), th.textDim)}
          {smallStat("Case-specific", formatNumber(caseCount), th.textDim)}
          {smallStat("Hayabusa Sync", modal.ruleSuppressionSync?.path ? "noisy_rules.txt" : "pending", modal.ruleSuppressionSync?.synced ? th.sev.clean : th.sev.med)}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "minmax(150px, 1fr) minmax(180px, 1.2fr) 120px minmax(130px, 0.8fr) minmax(180px, 1.2fr) auto", gap: 6, alignItems: "center", marginBottom: 8 }}>
          <input type="text" placeholder="Rule ID" value={draft.ruleId || ""} onChange={(e) => setDraft({ ruleId: e.target.value })} style={ms.ip} />
          <input type="text" placeholder="Rule title" value={draft.title || ""} onChange={(e) => setDraft({ title: e.target.value })} style={ms.ip} />
          <select value={draft.scopeType || "global"} onChange={(e) => {
            const scopeType = e.target.value;
            setDraft({ scopeType, scope: scopeType === "global" ? "all cases" : "" });
          }} style={ms.sl}>
            <option value="global">Global</option>
            <option value="case">Case-specific</option>
          </select>
          <input type="text" placeholder={draft.scopeType === "case" ? "Case / dataset" : "all cases"} value={draft.scope || ""} onChange={(e) => setDraft({ scope: e.target.value })} style={ms.ip} />
          <input type="text" placeholder="Reason" value={draft.reason || ""} onChange={(e) => setDraft({ reason: e.target.value })} style={ms.ip} />
          <button onClick={handleAddRuleSuppression} style={ms.bsm}>Add</button>
        </div>

        <div style={{ border: `1px solid ${th.border}33`, borderRadius: 8, overflow: "hidden", background: `${th.bgInput || th.bg}44` }}>
          <div style={{ display: "grid", gridTemplateColumns: "58px minmax(130px, 0.8fr) minmax(170px, 1.2fr) 95px minmax(120px, 0.8fr) minmax(160px, 1.2fr) 110px", gap: 6, padding: "6px 8px", background: th.panelBg, borderBottom: `1px solid ${th.border}44`, fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", fontWeight: 800 }}>
            <span>State</span><span>Rule ID</span><span>Title</span><span>Scope</span><span>Applies To</span><span>Reason</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 220, overflow: "auto" }}>
            {suppressions.length === 0 && (
              <div style={{ padding: 14, textAlign: "center", color: th.textMuted, fontSize: 11 }}>No disabled/noisy rules configured.</div>
            )}
            {suppressions.map((entry) => {
              const enabled = entry.enabled !== false;
              const isDefault = entry.source === "irflow-default";
              return (
                <div key={entry.id} style={{ display: "grid", gridTemplateColumns: "58px minmax(130px, 0.8fr) minmax(170px, 1.2fr) 95px minmax(120px, 0.8fr) minmax(160px, 1.2fr) 110px", gap: 6, alignItems: "center", padding: "6px 8px", borderBottom: `1px solid ${th.border}22`, opacity: enabled ? 1 : 0.62 }}>
                  <button onClick={() => handleUpdateRuleSuppression(entry.id, { enabled: !enabled })} style={{ ...ms.bsm, padding: "2px 7px", color: enabled ? th.sev.clean : th.textMuted, border: `1px solid ${enabled ? th.sev.clean + "44" : th.border}` }}>
                    {enabled ? "On" : "Off"}
                  </button>
                  <input type="text" value={entry.ruleId || ""} onChange={(e) => handleUpdateRuleSuppression(entry.id, { ruleId: e.target.value })} style={{ ...ms.ip, fontFamily: "'SF Mono',Menlo,monospace" }} />
                  <input type="text" value={entry.title || ""} onChange={(e) => handleUpdateRuleSuppression(entry.id, { title: e.target.value })} style={ms.ip} />
                  <select value={entry.scopeType || "global"} onChange={(e) => handleUpdateRuleSuppression(entry.id, { scopeType: e.target.value, scope: e.target.value === "global" ? "all cases" : entry.scope || "" })} style={ms.sl}>
                    <option value="global">Global</option>
                    <option value="case">Case</option>
                  </select>
                  <input type="text" value={entry.scope || ""} onChange={(e) => handleUpdateRuleSuppression(entry.id, { scope: e.target.value })} style={ms.ip} />
                  <input type="text" value={entry.reason || ""} onChange={(e) => handleUpdateRuleSuppression(entry.id, { reason: e.target.value })} style={ms.ip} />
                  <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                    {isDefault && <span title="IRFlow default noisy tuning" style={{ fontSize: 8, color: th.sev.med, fontWeight: 800 }}>default</span>}
                    <button onClick={() => handleRemoveRuleSuppression(entry.id)} disabled={isDefault} title={isDefault ? "Default entries can be turned off but not removed." : "Remove suppression"} style={{ ...ms.bsm, opacity: isDefault ? 0.4 : 1, color: isDefault ? th.textMuted : th.sev.critical, border: `1px solid ${isDefault ? th.border : th.sev.critical + "44"}` }}>Remove</button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 8 }}>
          <button onClick={handleSaveRuleSuppressions} disabled={modal.ruleSuppressionsSaving} style={{ ...ms.bp, padding: "5px 12px", opacity: modal.ruleSuppressionsSaving ? 0.55 : 1 }}>
            {modal.ruleSuppressionsSaving ? "Saving..." : "Save Disabled / Noisy Rules"}
          </button>
          <span style={{ fontSize: 10, color: th.textMuted }}>
            Global enabled rule IDs are written to Hayabusa noisy_rules.txt. JS Sigma scans skip enabled entries by rule ID.
          </span>
        </div>
      </Fragment>
    );
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ padding: 10, border: `1px solid ${th.border}44`, borderRadius: 8, background: `${th.accent}08` }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
          <div>
            <div style={{ fontSize: 13, color: th.text, fontWeight: 800, fontFamily: "-apple-system,sans-serif" }}>Detection Settings</div>
            <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2 }}>Rule sources, Hayabusa maintenance, GeoIP, and advanced scan defaults live here. Changes auto-save as global defaults.</div>
            {modal.detectionSettingsNotice && (
              <div style={{ fontSize: 10, color: th.sev.clean, marginTop: 5 }}>{modal.detectionSettingsNotice}</div>
            )}
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <button onClick={handleSaveDetectionSettings} disabled={modal.detectionSettingsSaving} style={{ ...ms.bsm, opacity: modal.detectionSettingsSaving ? 0.55 : 1 }}>
              {modal.detectionSettingsSaving ? "Saving..." : "Save Defaults"}
            </button>
            <button onClick={() => setModal((p) => ({ ...p, detectionSettingsView: false, scanHistoryView: false }))} style={ms.bsm}>Back to Scan</button>
          </div>
        </div>
      </div>

      {section("Hayabusa Engine", hbInstalled ? "Primary engine for EVTX folder scans" : "Install required for raw EVTX scans", (
        <Fragment>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 9 }}>
            {smallStat("Engine", hbInstalled ? `Hayabusa ${hb.version || ""}` : "Not installed", hbInstalled ? th.sev.clean : th.sev.high)}
            {smallStat("Rule Count", hbRuleCount ? formatNumber(hbRuleCount) : "Unknown", hbRuleCount ? th.text : th.textMuted)}
            {smallStat("Rule Update", modal.hayabusaUpdateRuleDiff?.lastUpdate ? new Date(modal.hayabusaUpdateRuleDiff.lastUpdate).toLocaleString() : "Not recorded", th.textDim)}
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {hbInstalled ? (
              <Fragment>
                <button onClick={handleUpdateHayabusaRules} disabled={modal.hayabusaUpdating || hbDownloading} style={ms.bsm}>
                  {modal.hayabusaUpdating ? "Updating Rules..." : "Update Rules"}
                </button>
                <button onClick={handleUpdateHayabusa} disabled={hbDownloading || modal.hayabusaUpdating} style={ms.bsm}>
                  {hbDownloading ? "Updating Hayabusa..." : "Update Hayabusa"}
                </button>
              </Fragment>
            ) : (
              <button onClick={handleDownloadHayabusa} disabled={hbDownloading} style={{ ...ms.bsm, background: th.accent + "15", color: th.accent, border: `1px solid ${th.accent}33` }}>
                {hbDownloading ? "Downloading..." : "Install Hayabusa"}
              </button>
            )}
            <button onClick={() => tle?.sigmaOpenRulesConfigDir?.()} style={ms.bsm}>Open Rules Config Folder</button>
          </div>
          {renderUpdatePanel()}
        </Fragment>
      ))}

      {section("Disabled / Noisy Rules", "Suppress known-noisy rules globally or document case-specific decisions", renderSuppressionManager())}

      {section("Compatibility Rule Sources", `${formatNumber(status?.cachedRuleCount || 0)} cached rules`, renderRepoSelector())}

      {section("Hayabusa Scan Defaults", "Used for EVTX folder scans", (
        <Fragment>
          <div style={{ marginBottom: 10 }}>
            <label style={ms.lb}>Rule Set</label>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {RULE_SETS.map((rs) => {
                const active = (modal.ruleSet || "all") === rs.id;
                return (
                  <button key={rs.id} onClick={() => setModal((p) => ({ ...p, ruleSet: rs.id, scanPreflight: null }))} title={rs.desc}
                    style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", fontWeight: active ? 600 : 400, fontFamily: "-apple-system,sans-serif",
                      background: active ? `${th.accent}18` : "transparent", color: active ? th.accent : th.textDim,
                      border: `1px solid ${active ? th.accent + "44" : th.border + "33"}` }}>
                    {rs.label}
                  </button>
                );
              })}
            </div>
          </div>

          <div style={{ marginBottom: 10 }}>
            <label style={ms.lb}>Time Range</label>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input type="text" placeholder="Start: 2025-12-01 00:00:00" value={modal.timelineStart || ""} onChange={(e) => setModal((p) => ({ ...p, timelineStart: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: 1 }} />
              <span style={{ color: th.textMuted, fontSize: 10 }}>to</span>
              <input type="text" placeholder="End: 2025-12-31 23:59:59" value={modal.timelineEnd || ""} onChange={(e) => setModal((p) => ({ ...p, timelineEnd: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: 1 }} />
            </div>
          </div>

          <div style={{ marginBottom: 10 }}>
            <label style={ms.lb}>Output Profile</label>
            <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
              <select value={modal.profile || "verbose"} onChange={(e) => setModal((p) => ({ ...p, profile: e.target.value, scanPreflight: null }))} style={{ ...ms.sl, width: "auto", flex: "0 1 220px" }}>
                <option value="minimal">Minimal</option>
                <option value="standard">Standard</option>
                <option value="verbose">Verbose (default)</option>
                <option value="all-field-info">All Fields</option>
                <option value="all-field-info-verbose">All Fields Verbose</option>
                <option value="super-verbose">Super Verbose</option>
                <option value="timesketch-minimal">Timesketch Minimal</option>
                <option value="timesketch-verbose">Timesketch Verbose</option>
              </select>
              <div style={{ display: "inline-flex", background: th.panelBg, borderRadius: 4, padding: 1, border: `1px solid ${th.border}33`, gap: 1 }}>
                {OUTPUT_MODES.map((m) => (
                  <button key={m.id} onClick={() => setModal((p) => ({ ...p, outputMode: m.id, scanPreflight: null }))} style={{ padding: "2px 10px", borderRadius: 3, fontSize: 9, border: "none", cursor: "pointer", fontFamily: "-apple-system,sans-serif", background: (modal.outputMode || "csv") === m.id ? th.fillAccent : "transparent", color: (modal.outputMode || "csv") === m.id ? th.onAccent : th.textMuted, fontWeight: (modal.outputMode || "csv") === m.id ? 600 : 400 }}>{m.label}</button>
                ))}
              </div>
            </div>
          </div>

          <div style={{ marginBottom: 10 }}>
            <label style={ms.lb}>Scan Options</label>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              {checkbox("Recover deleted records", modal.recoverRecords || false, () => setModal((p) => ({ ...p, recoverRecords: !p.recoverRecords, scanPreflight: null })))}
              {checkbox("UTC timestamps", modal.utc || false, () => setModal((p) => ({ ...p, utc: !p.utc, scanPreflight: null })))}
              {checkbox("Proven rules only", modal.provenRules || false, () => setModal((p) => ({ ...p, provenRules: !p.provenRules, scanPreflight: null })))}
              {checkbox("Include noisy rules", modal.enableNoisy || false, () => setModal((p) => ({ ...p, enableNoisy: !p.enableNoisy, scanPreflight: null })))}
              {checkbox("Include deprecated rules", modal.enableDeprecated || false, () => setModal((p) => ({ ...p, enableDeprecated: !p.enableDeprecated, scanPreflight: null })))}
              {checkbox("Include unsupported rules", modal.enableUnsupported || false, () => setModal((p) => ({ ...p, enableUnsupported: !p.enableUnsupported, scanPreflight: null })))}
              {checkbox("EID filter (faster scan)", modal.eidFilter || false, () => setModal((p) => ({ ...p, eidFilter: !p.eidFilter, scanPreflight: null })))}
              {checkbox("Enable ALL rules (-A)", modal.enableAllRules || false, () => setModal((p) => ({ ...p, enableAllRules: !p.enableAllRules, scanPreflight: null })))}
              {checkbox("Scan ALL EVTX files (-a)", modal.scanAllEvtxFiles || false, () => setModal((p) => ({ ...p, scanAllEvtxFiles: !p.scanAllEvtxFiles, scanPreflight: null })))}
              {checkbox("GeoIP enrichment", modal.geoIpEnabled || false, () => setModal((p) => ({ ...p, geoIpEnabled: !p.geoIpEnabled, scanPreflight: null })))}
            </div>
            {modal.geoIpEnabled && (
              <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 6 }}>
                <input type="text" placeholder="GeoIP database directory (MaxMind GeoLite2)" value={modal.geoIpDir || ""} onChange={(e) => setModal((p) => ({ ...p, geoIpDir: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: 1 }} />
                <button onClick={async () => {
                  const res = await tle?.sigmaSelectGeoIpDir?.();
                  if (res?.path) setModal((p) => ({ ...p, geoIpDir: res.path, scanPreflight: null }));
                }} style={ms.bsm}>Browse</button>
                <button onClick={async () => {
                  setModal((p) => ({ ...p, geoIpDownloading: true }));
                  try {
                    const res = await tle?.sigmaGeoIpDownload?.();
                    if (res?.path) setModal((p) => ({ ...p, geoIpDir: res.path, geoIpDownloading: false, scanPreflight: null }));
                    else setModal((p) => ({ ...p, geoIpDownloading: false }));
                  } catch (e) {
                    setModal((p) => ({ ...p, geoIpDownloading: false, error: e?.message || "GeoIP download failed" }));
                  }
                }} disabled={modal.geoIpDownloading} style={{ ...ms.bsm, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33` }}>
                  {modal.geoIpDownloading ? "Downloading..." : "Auto-Download"}
                </button>
              </div>
            )}
          </div>

          <div style={{ marginBottom: 10 }}>
            <label style={ms.lb}>Advanced Filters</label>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              <input type="text" placeholder="Include MITRE tags: attack.lateral_movement, attack.execution" value={modal.includeTags || ""} onChange={(e) => setModal((p) => ({ ...p, includeTags: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: "1 1 45%", minWidth: 180 }} />
              <input type="text" placeholder="Exclude MITRE tags" value={modal.excludeTags || ""} onChange={(e) => setModal((p) => ({ ...p, excludeTags: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: "1 1 45%", minWidth: 180 }} />
              <input type="text" placeholder="Include computers: DC01, WKS01" value={modal.includeComputers || ""} onChange={(e) => setModal((p) => ({ ...p, includeComputers: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: "1 1 45%", minWidth: 180 }} />
              <input type="text" placeholder="Exclude computers" value={modal.excludeComputers || ""} onChange={(e) => setModal((p) => ({ ...p, excludeComputers: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: "1 1 45%", minWidth: 180 }} />
              <input type="text" placeholder="Include Event IDs: 4624, 4625, 1" value={modal.includeEids || ""} onChange={(e) => setModal((p) => ({ ...p, includeEids: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: "1 1 45%", minWidth: 180 }} />
              <input type="text" placeholder="Exclude Event IDs: 10, 5156" value={modal.excludeEids || ""} onChange={(e) => setModal((p) => ({ ...p, excludeEids: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: "1 1 45%", minWidth: 180 }} />
            </div>
          </div>

          <div>
            <label style={ms.lb}>Rules and Tuning</label>
            <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 6 }}>
              <input type="text" placeholder="Custom Hayabusa rules directory; leave empty for default rules" value={modal.rulesPath || ""} onChange={(e) => setModal((p) => ({ ...p, rulesPath: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: 1 }} />
              <button onClick={async () => {
                const res = await tle?.sigmaSelectRulesPath?.();
                if (res?.path) setModal((p) => ({ ...p, rulesPath: res.path, scanPreflight: null }));
              }} style={ms.bsm}>Browse Rules</button>
              {modal.rulesPath && <button onClick={() => setModal((p) => ({ ...p, rulesPath: "", scanPreflight: null }))} style={{ ...ms.bsm, color: th.textMuted }}>Clear</button>}
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <input type="text" placeholder="Rules config YAML; leave empty for default config" value={modal.rulesConfig || ""} onChange={(e) => setModal((p) => ({ ...p, rulesConfig: e.target.value, scanPreflight: null }))} style={{ ...ms.ip, flex: 1 }} />
              <button onClick={async () => {
                const res = await tle?.sigmaSelectRulesConfig?.();
                if (res?.path) setModal((p) => ({ ...p, rulesConfig: res.path, scanPreflight: null }));
              }} style={ms.bsm}>Browse Config</button>
              {modal.rulesConfig && <button onClick={() => setModal((p) => ({ ...p, rulesConfig: "", scanPreflight: null }))} style={{ ...ms.bsm, color: th.textMuted }}>Clear</button>}
            </div>
          </div>
        </Fragment>
      ))}
    </div>
  );
}
