import { Fragment } from "react";
import { formatNumber } from "../../../utils/format.js";
import { useSigmaModalContext } from "./SigmaModalContext.js";
// Single source of truth — keep the displayed cap in lock-step with the value actually
// passed to the scan (previously duplicated here and drifted easily).
import { JS_SIGMA_LARGE_TAB_ROWS, JS_SIGMA_MAX_ROWS_PER_QUERY } from "./sigmaModalHelpers.js";

const wrapTextStyle = {
  display: "block",
  maxWidth: "100%",
  minWidth: 0,
  overflow: "visible",
  whiteSpace: "normal",
  overflowWrap: "anywhere",
  wordBreak: "break-word",
};

export default function SigmaValidateStep() {
  const {
    modal,
    setModal,
    ct,
    th,
    ms,
    tle,
    status,
    renderScanReadinessPanel,
    renderPreflightPanel,
    checkbox,
  } = useSigmaModalContext();

  const openSettings = () => setModal((p) => ({ ...p, detectionSettingsView: true, scanHistoryView: false }));
  const scanMode = modal.scanMode || "evtx-dir";
  const disabledRuleCount = (modal.ruleSuppressions || []).filter((entry) => entry?.enabled !== false && entry?.ruleId).length;
  const largeCurrentTab = scanMode === "tab" && (ct?.totalRows || 0) >= JS_SIGMA_LARGE_TAB_ROWS;
  const largeKapeOutput = scanMode === "kape-output" && Number(modal.kapeOutput?.totalBytes || 0) >= 1024 * 1024 * 1024;

  const renderJsSigmaPerformanceNotice = () => {
    if (!largeCurrentTab && !largeKapeOutput) return null;
    const label = largeCurrentTab
      ? `${formatNumber(ct.totalRows || 0)} imported rows`
      : `${((Number(modal.kapeOutput?.totalBytes || 0)) / (1024 * 1024 * 1024)).toFixed(1)} GB of EvtxECmd output`;
    return (
      <div style={{ ...ms.fg, padding: 10, borderRadius: 8, border: `1px solid ${th.sev.med}44`, background: th.sev.med + "10", color: th.sev.med, fontSize: 10, lineHeight: 1.4, fontFamily: "-apple-system,sans-serif" }}>
        <strong>Large JS Sigma compatibility scan:</strong> {label}. Raw EVTX + Hayabusa is the preferred full-speed path when raw .evtx files are available.
        This compatibility scan caps each logsource group at {formatNumber(JS_SIGMA_MAX_ROWS_PER_QUERY)} candidate rows to avoid runaway memory/CPU use.
      </div>
    );
  };

  const renderSummaryShell = (title, subtitle, color, children) => (
    <div style={{ ...ms.fg, padding: 12, border: `1px solid ${color}33`, borderRadius: 8, background: `${color}08` }}>
      <div style={{ display: "flex", alignItems: "flex-start", flexWrap: "wrap", gap: "8px 10px" }}>
        <span style={{ width: 10, height: 10, borderRadius: 999, background: color, flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, color: th.text, fontWeight: 800, fontFamily: "-apple-system,sans-serif", ...wrapTextStyle }}>{title}</div>
          <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2, lineHeight: 1.35, ...wrapTextStyle }}>{subtitle}</div>
        </div>
        <button onClick={openSettings} style={{ ...ms.bsm, flexShrink: 0 }}>Detection Settings</button>
      </div>
      {children && <div style={{ marginTop: 9 }}>{children}</div>}
    </div>
  );

  const renderPill = (label, value, color = th.textDim) => (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, maxWidth: "100%", padding: "2px 7px", borderRadius: 999, border: `1px solid ${color}33`, background: `${color}0F`, color, fontSize: 9, lineHeight: 1.25, fontFamily: "'SF Mono',Menlo,monospace", whiteSpace: "normal", overflowWrap: "anywhere" }}>
      {label}{value ? `: ${value}` : ""}
    </span>
  );

  const renderCompatibilitySummary = () => {
    const cached = status?.cachedRuleCount || 0;
    const custom = status?.customRuleCount || 0;
    const lastUpdate = status?.lastUpdate ? new Date(status.lastUpdate).toLocaleString() : "never";
    const compat = status?.compatibilityReport || null;
    const color = cached || custom ? th.sev.clean : th.sev.high;
    return renderSummaryShell(
      "Current Timeline Tab Rules",
      cached || custom
        ? "JS Sigma compatibility scan against imported CSV/XLSX/KAPE rows"
        : "Download or import compatibility rules before scanning the current tab",
      color,
      <Fragment>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {renderPill("cached", formatNumber(cached), color)}
          {renderPill("custom", formatNumber(custom), custom ? th.textDim : th.textMuted)}
          {renderPill("last update", lastUpdate, th.textMuted)}
          {compat && renderPill("compatible", formatNumber(compat.compatible || 0), th.sev.clean)}
          {compat && renderPill("unsupported", formatNumber(compat.unsupportedRules || 0), compat.unsupportedRules ? th.sev.med : th.textMuted)}
          {disabledRuleCount > 0 && renderPill("disabled/noisy", formatNumber(disabledRuleCount), th.sev.med)}
          {status?.ruleSnapshotHash && renderPill("snapshot", status.ruleSnapshotHash.slice(0, 12), th.textMuted)}
        </div>
        {!cached && !custom && (
          <div style={{ marginTop: 7, fontSize: 10, color: th.sev.high }}>
            No compatibility rules are ready. Open Detection Settings to download repositories or import YAML rules.
          </div>
        )}
      </Fragment>
    );
  };

  const renderKapeOutputSummary = () => {
    const cached = status?.cachedRuleCount || 0;
    const custom = status?.customRuleCount || 0;
    const compat = status?.compatibilityReport || null;
    const info = modal.kapeOutput || {};
    const color = cached || custom ? th.sev.clean : th.sev.high;
    return renderSummaryShell(
      "EvtxECmd Output File Rules",
      info.fileCount
        ? `JS Sigma compatibility scan against ${formatNumber(info.fileCount)} validated EvtxECmd file${info.fileCount === 1 ? "" : "s"}`
        : "Select EvtxECmd CSV/XLS/XLSX output files before scanning",
      color,
      <Fragment>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {renderPill("cached", formatNumber(cached), cached ? th.sev.clean : th.textMuted)}
          {renderPill("custom", formatNumber(custom), custom ? th.textDim : th.textMuted)}
          {renderPill("files", formatNumber(info.fileCount || 0), color)}
          {renderPill("bytes", `${((Number(info.totalBytes || 0)) / (1024 * 1024)).toFixed(1)} MB`, th.textMuted)}
          {Number(info.ignoredCount || 0) > 0 && renderPill("ignored", formatNumber(info.ignoredCount || 0), th.sev.med)}
          {compat && renderPill("compatible", formatNumber(compat.compatible || 0), th.sev.clean)}
          {compat && renderPill("unsupported", formatNumber(compat.unsupportedRules || 0), compat.unsupportedRules ? th.sev.med : th.textMuted)}
          {disabledRuleCount > 0 && renderPill("disabled/noisy", formatNumber(disabledRuleCount), th.sev.med)}
          {status?.ruleSnapshotHash && renderPill("snapshot", status.ruleSnapshotHash.slice(0, 12), th.textMuted)}
        </div>
        {!cached && !custom && (
          <div style={{ marginTop: 7, fontSize: 10, color: th.sev.high }}>
            No compatibility rules are ready. Open Detection Settings to download repositories or import YAML rules.
          </div>
        )}
      </Fragment>
    );
  };

  const renderEvtxSettingsSummary = () => {
    const hb = modal.hayabusaStatus;
    const hbInstalled = !!hb?.installed;
    const hbRuleCount = hb?.ruleState?.hayabusaRuleCount || modal.hayabusaUpdateRuleDiff?.currentRuleCount || 0;
    const options = [];
    if (modal.recoverRecords) options.push("recover");
    if (modal.utc) options.push("utc");
    if (modal.provenRules) options.push("proven");
    if (modal.enableNoisy) options.push("noisy");
    if (modal.enableDeprecated) options.push("deprecated");
    if (modal.enableUnsupported) options.push("unsupported");
    if (modal.eidFilter) options.push("eid-filter");
    if (modal.enableAllRules) options.push("all-rules");
    if (modal.scanAllEvtxFiles) options.push("all-evtx");
    if (modal.geoIpEnabled) options.push("geoip");
    if (modal.rulesPath) options.push("custom-rules");
    if (modal.rulesConfig) options.push("rules-config");
    if (modal.timelineStart || modal.timelineEnd) options.push("time-range");

    return renderSummaryShell(
      "EVTX Folder Engine",
      hbInstalled
        ? `Hayabusa ${hb.version || ""}${hbRuleCount ? ` with ${formatNumber(hbRuleCount)} rules` : ""}`
        : "Hayabusa will be installed from Detection Settings or on first scan",
      hbInstalled ? th.sev.clean : th.sev.high,
      <Fragment>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {renderPill("rule set", modal.ruleSet || "all", th.textDim)}
          {renderPill("profile", `${modal.profile || "verbose"} / ${modal.outputMode || "csv"}`, th.textDim)}
          {renderPill("options", options.length ? options.join(", ") : "default", th.textDim)}
          {disabledRuleCount > 0 && renderPill("disabled/noisy", formatNumber(disabledRuleCount), th.sev.med)}
        </div>
        {(modal.timelineStart || modal.timelineEnd) && (
          <div style={{ marginTop: 6, fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>
            {modal.timelineStart || "beginning"} to {modal.timelineEnd || "end"}
          </div>
        )}
      </Fragment>
    );
  };

  const renderSearchTable = () => {
    const rows = modal.searchResults?.rows || [];
    if (!rows.length) return null;
    const cols = Object.keys(rows[0]).filter(k => !k.startsWith("_")).slice(0, 8);
    return (
      <div style={{ maxHeight: 160, overflow: "auto", borderRadius: 6, border: `1px solid ${th.border}44` }}>
        <table style={{ borderCollapse: "collapse", fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", width: "100%", tableLayout: "auto" }}>
          <thead>
            <tr>
              {cols.map((c) => (
                <th key={c} style={{ position: "sticky", top: 0, background: th.headerBg || th.panelBg, borderBottom: `2px solid ${th.border}`, padding: "4px 6px", textAlign: "left", fontSize: 8, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", whiteSpace: "nowrap" }}>{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 100).map((row, ri) => (
              <tr key={ri} style={{ borderBottom: `1px solid ${th.border}11`, background: ri % 2 === 0 ? "transparent" : `${th.panelBg}44` }}>
                {cols.map((c) => (
                  <td key={c} style={{ padding: "3px 6px", color: th.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 250 }}>{String(row[c] || "").substring(0, 200)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length > 100 && <div style={{ padding: "4px 8px", fontSize: 8, color: th.textMuted, textAlign: "center" }}>Showing 100 of {rows.length}</div>}
      </div>
    );
  };

  const renderEvtxSearch = () => {
    if (scanMode !== "evtx-dir" || !modal.evtxDir?.dirPath) return null;
    return (
      <div style={{ ...ms.fg }}>
        <button onClick={() => setModal((p) => ({ ...p, showSearch: !p.showSearch }))} style={{ display: "flex", alignItems: "center", gap: 6, background: "none", border: "none", cursor: "pointer", padding: "2px 0", width: "100%" }}>
          <span style={{ fontSize: 9, color: th.textMuted, transition: "transform var(--m-base)", transform: modal.showSearch ? "rotate(90deg)" : "rotate(0deg)" }}>{"\u25B6"}</span>
          <span style={{ fontSize: 10, color: th.textDim, fontWeight: 600, fontFamily: "-apple-system,sans-serif", textTransform: "uppercase", letterSpacing: "0.06em" }}>EVTX Search Utility</span>
          <span style={{ fontSize: 9, color: th.textMuted, marginLeft: "auto" }}>Keyword hunt before or after the detection scan</span>
        </button>
        {modal.showSearch && (
          <div style={{ marginTop: 6 }}>
            <div style={{ display: "flex", gap: 6, alignItems: "flex-end", marginBottom: 6 }}>
              <div style={{ flex: 1 }}>
                <label style={{ ...ms.lb, marginBottom: 3 }}>{modal.searchMode === "regex" ? "Regex pattern" : "Keywords (comma-separated)"}</label>
                <input type="text" placeholder={modal.searchMode === "regex" ? "Regex: mimikatz|kali|192\\.168\\.1\\." : "mimikatz, kali, 192.168.1.50"} value={modal.searchKeywords || ""} onChange={(e) => setModal((p) => ({ ...p, searchKeywords: e.target.value }))} style={ms.ip} />
              </div>
              <div>
                <label style={{ ...ms.lb, marginBottom: 3 }}>Field filter</label>
                <input type="text" placeholder="e.g. CommandLine" value={modal.searchFieldFilter || ""} onChange={(e) => setModal((p) => ({ ...p, searchFieldFilter: e.target.value }))} style={{ ...ms.ip, width: 130 }} />
              </div>
              <button onClick={async () => {
                const kw = (modal.searchKeywords || "").trim();
                if (!kw || !modal.evtxDir?.dirPath) return;
                setModal((p) => ({ ...p, searchLoading: true, searchResults: null, error: null }));
                try {
                  const searchOpts = {
                    ignoreCase: true,
                    timelineStart: modal.timelineStart || undefined,
                    timelineEnd: modal.timelineEnd || undefined,
                    fieldFilter: (modal.searchFieldFilter || "").trim() || undefined,
                  };
                  if (modal.searchMode === "regex") {
                    searchOpts.regex = kw;
                  } else {
                    searchOpts.keywords = kw.split(",").map(s => s.trim()).filter(Boolean);
                    if (modal.searchAndLogic) searchOpts.andLogic = true;
                  }
                  const res = await tle.sigmaSearch(modal.evtxDir.dirPath, searchOpts);
                  setModal((p) => ({ ...p, searchLoading: false, searchResults: res }));
                } catch (e) {
                  setModal((p) => ({ ...p, searchLoading: false, error: e?.message || "Search failed" }));
                }
              }} disabled={modal.searchLoading || !(modal.searchKeywords || "").trim()} style={{ ...ms.bp, flexShrink: 0, padding: "6px 16px", opacity: (modal.searchKeywords || "").trim() && !modal.searchLoading ? 1 : 0.4 }}>
                {modal.searchLoading ? "Searching..." : "Search"}
              </button>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
              <div style={{ display: "inline-flex", background: th.panelBg, borderRadius: 4, padding: 1, border: `1px solid ${th.border}33`, gap: 1 }}>
                {[{ id: "keywords", label: "Keywords" }, { id: "regex", label: "Regex" }].map((m) => (
                  <button key={m.id} onClick={() => setModal((p) => ({ ...p, searchMode: m.id }))} style={{ padding: "2px 8px", borderRadius: 3, fontSize: 9, border: "none", cursor: "pointer", fontFamily: "-apple-system,sans-serif", background: (modal.searchMode || "keywords") === m.id ? th.fillAccent : "transparent", color: (modal.searchMode || "keywords") === m.id ? th.onAccent : th.textMuted, fontWeight: (modal.searchMode || "keywords") === m.id ? 600 : 400 }}>{m.label}</button>
                ))}
              </div>
              {(modal.searchMode || "keywords") === "keywords" && checkbox("AND logic (all keywords must match)", modal.searchAndLogic || false, () => setModal((p) => ({ ...p, searchAndLogic: !p.searchAndLogic })))}
            </div>
            {modal.searchResults && (
              <div style={{ marginTop: 6 }}>
                <div style={{ fontSize: 10, color: modal.searchResults.totalFindings > 0 ? th.sev.high : th.textMuted, fontWeight: 600, marginBottom: 4 }}>
                  {formatNumber(modal.searchResults.totalFindings || 0)} finding{modal.searchResults.totalFindings === 1 ? "" : "s"} across raw EVTX events
                </div>
                {renderSearchTable()}
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  const setupOpen = !!modal.showSetupDetails;

  return (
    <Fragment>
      {/* Always-visible readiness: the headline strip + any preflight result + large-scan warning. */}
      {renderScanReadinessPanel()}
      {renderPreflightPanel(modal.scanPreflight)}
      {renderJsSigmaPerformanceNotice()}

      {/* Setup details — engine/rules summary + EVTX keyword search, collapsed by default. */}
      <div style={{ ...ms.fg }}>
        <button
          onClick={() => setModal((p) => p?.type === "sigma" ? { ...p, showSetupDetails: !p.showSetupDetails } : p)}
          style={{ display: "flex", alignItems: "center", gap: 8, background: "none", border: "none", cursor: "pointer", padding: "4px 0", width: "100%", minWidth: 0 }}
        >
          <span style={{ fontSize: 9, color: th.textMuted, transition: "transform var(--m-base)", transform: setupOpen ? "rotate(90deg)" : "rotate(0deg)", flexShrink: 0 }}>{"▶"}</span>
          <span style={{ fontSize: 10, color: th.textDim, fontWeight: 700, fontFamily: "-apple-system,sans-serif", textTransform: "uppercase", letterSpacing: "0.06em", flexShrink: 0 }}>Setup details</span>
          <span style={{ marginLeft: "auto", fontSize: 9, color: th.textMuted, fontFamily: "-apple-system,sans-serif", flexShrink: 0 }}>{setupOpen ? "Hide" : "Engine, rules & EVTX search"}</span>
        </button>
        {setupOpen && (
          <div style={{ marginTop: 6 }}>
            {scanMode === "evtx-dir" ? renderEvtxSettingsSummary() : scanMode === "kape-output" ? renderKapeOutputSummary() : renderCompatibilitySummary()}
            {renderEvtxSearch()}
          </div>
        )}
      </div>
    </Fragment>
  );
}
