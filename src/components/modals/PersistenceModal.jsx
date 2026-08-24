import { useCallback, useState, useEffect } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import { toast } from "../../store/useToastStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { DraggableResizableModal } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";
import { buildPillsByRowid } from "../../utils/evidence-pills.js";
import { updateModal } from "../../modals/modalRegistry.js";
import {
  PA_EVTX_RULES, PA_REG_RULES, PA_EVTX_PRESETS, PA_REG_PRESETS, PA_INTENTS, paRuleLabel,
} from "../../constants/persistenceRuleCatalog.mjs";

// Animated count-up for the results stat cards — eases 0 → value on mount/value change.
function CountUp({ value, duration = 550 }) {
  const target = Number(value) || 0;
  const [n, setN] = useState(0);
  useEffect(() => {
    if (target <= 0) { setN(0); return; }
    let raf, start;
    const tick = (t) => {
      if (start == null) start = t;
      const p = Math.min(1, (t - start) / duration);
      setN(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);
  return <>{n.toLocaleString()}</>;
}

// ── Inline helpers (originally defined in App.jsx scope) ────────────
const _downloadFile = (content, filename, mime) => {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
};

const _toCSV = (rows) => {
  if (!rows.length) return "";
  const keys = Object.keys(rows[0]);
  const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  return [keys.join(","), ...rows.map((r) => keys.map((k) => esc(r[k])).join(","))].join("\n");
};

export default function PersistenceModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const ct = useCurrentTab();
  const { th } = useTheme();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const tabs = useTabStore((s) => s.tabs);
  const activeTab = useTabStore((s) => s.activeTab);
  const setTabs = useTabStore((s) => s.setTabs);
  const updateActiveTab = useTabStore((s) => s.updateActiveTab);

  // Replicate the `up` helper from App.jsx
  const up = useCallback((key, value) => {
    setTabs((prev) => prev.map((t) => (t.id === activeTab ? { ...t, [key]: value } : t)));
  }, [activeTab, setTabs]);

  // Replicate activeFilters from App.jsx
  const activeFilters = useCallback((tab) => {
    const dis = tab.disabledFilters || new Set();
    if (dis.size === 0) return { columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters };
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: Object.fromEntries(Object.entries(tab.checkboxFilters).filter(([k]) => !dis.has(k))),
    };
  }, []);

  // Shared modal styles (replicate the `ms` object from App.jsx)
  const ms = useModalChrome();

  // Other imported tabs available to merge into a multi-source scan. A KAPE package is not
  // one file: the 7045 lives in System.evtx, the 4688 that corroborates it in Security.evtx.
  const otherTabs = tabs.filter((t) => t.dataReady && t.id !== ct?.id);

  // ── Guard: only render when persistence modal is active ────────────
  if (modal?.type !== "persistence" || !ct) return null;

  // ── All original IIFE logic below, kept exactly as-is ─────────────
  const { phase, data, mode: pMode } = modal;
  const viewTab = modal.viewTab || "grouped";
  const searchText = modal.searchText || "";
  const severityFilter = modal.severityFilter || "all";
  const categoryFilter = modal.categoryFilter || "all";

  const SEVERITY_COLORS = { critical: th.sev.critical, high: th.sev.high, medium: th.sev.med, low: th.sev.low };
  // Evidence-pill colors: pure brand palette — accent for the strongest signal (execution
  // corroboration), neutral grays for the rest. No blue/green "mixing" (Unit 42 theme).
  const PA_PILL_COLORS = { execution: th.accent, context: th.textMuted, correlation: th.textMuted, target: th.textMuted };

  // ── Typography scale for the findings table + detail panel ─────────────────
  // ONE three-step size ramp (9 pill / 10 label / 11 value), TWO weights, THREE
  // text colors. Everything in the table and the detail panel derives from here
  // so rows can't drift into mixed sizes/weights/families again.
  //
  //   size    9 → pills & badges       10 → column headers, field labels
  //          11 → every value (cells, detail values)
  //   weight 600 → headers, labels, pill text, the risk number   400 → all values
  //   color  th.text    → the value that carries the finding (detection, artifact)
  //          th.textDim → supporting values (category, path, time, host, user)
  //          th.textMuted → headers and labels
  //
  // Severity/risk color is confined to the severity pill and the risk number.
  // Value TEXT is never severity-colored — the row already shows severity other ways,
  // and coloring the artifact was the main source of the
  // "some red, some white, some bold" inconsistency.
  const PA_SANS = "-apple-system, BlinkMacSystemFont, sans-serif";
  const PA_MONO = "SF Mono, Menlo, monospace";
  const PA_SZ = { pill: 9, label: 10, value: 11 };
  const PA_W = { strong: 600, normal: 400 };
  // Machine data reads as monospace; prose (category, detection name) reads as sans.
  const PA_MONO_COLS = new Set(["artifact", "command", "timestamp", "computer", "user", "source"]);
  // The two columns that carry the finding get full-contrast text; the rest support it.
  const PA_STRONG_COLS = new Set(["name", "artifact"]);
  const paPill = (color, bg) => ({
    fontSize: PA_SZ.pill, fontWeight: PA_W.strong, fontFamily: PA_SANS,
    padding: "1px 5px", borderRadius: 3, whiteSpace: "nowrap", flexShrink: 0,
    color, background: bg !== undefined ? bg : color + "1f",
  });
  const paLabel = { fontSize: PA_SZ.label, fontWeight: PA_W.strong, fontFamily: PA_SANS, color: th.textMuted, flexShrink: 0 };
  const paValue = { fontSize: PA_SZ.value, fontWeight: PA_W.normal, fontFamily: PA_MONO, color: th.text };
  const paMeta = { fontSize: PA_SZ.label, fontWeight: PA_W.normal, fontFamily: PA_SANS, color: th.textDim };
  // Section caption — matches the existing "REGISTRY COVERAGE" captions in this modal.
  const paCaption = { fontSize: PA_SZ.label, fontWeight: PA_W.strong, fontFamily: PA_SANS, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" };
  const paRiskColor = (n) => (n >= 8 ? th.sev.critical : n >= 6 ? th.sev.high : th.textMuted);
  const PA_CAT_MITRE = { "Services": "T1543.003", "Scheduled Tasks": "T1053.005", "WMI Persistence": "T1546.003", "Run Keys": "T1547.001", "Registry Autorun": "T1547.001", "Registry Modification": "T1547.001", "Winlogon": "T1547.004", "AppInit DLLs": "T1546.010", "IFEO": "T1546.012", "COM Hijacking": "T1546.015", "Shell Extensions": "T1546.015", "Boot Execute": "T1547.002", "BHO": "T1176", "LSA": "T1556.002", "Print Monitors": "T1547.010", "Active Setup": "T1547.014", "Startup Folder": "T1547.009", "DLL Hijacking": "T1574.001", "Driver Loading": "T1543.003", "Process Tampering": "T1055", "Account Persistence": "T1136", "Domain Persistence": "T1484", "Network Providers": "T1556", "Scheduled Tasks (Reg)": "T1053.005", "Registry Rename": "T1112", "Silent Process Exit": "T1546.012", "Logon Script": "T1037.001", "AppCert DLLs": "T1546.009", "Credential Providers": "T1556", "Command Processor": "T1547.001", "Explorer Autoruns": "T1547.001", "Netsh Helper DLLs": "T1546.007", "Screensaver": "T1546.002", "Office Add-ins": "T1137.006", "Time Providers": "T1547.003", "Terminal Server": "T1547", "File Association": "T1546.001", "Group Policy Scripts": "T1037.001", "Security Support Provider": "T1547.005", "Environment Hijack": "T1574.012", "Defender Tampering": "T1562.001" };
  const PA_MITRE_MAP = {
    "T1543.003": { name: "Create or Modify System Process: Windows Service", url: "https://attack.mitre.org/techniques/T1543/003/" },
    "T1053.005": { name: "Scheduled Task/Job: Scheduled Task", url: "https://attack.mitre.org/techniques/T1053/005/" },
    "T1546.003": { name: "Event Triggered Execution: WMI Event Subscription", url: "https://attack.mitre.org/techniques/T1546/003/" },
    "T1547.001": { name: "Boot or Logon Autostart Execution: Registry Run Keys", url: "https://attack.mitre.org/techniques/T1547/001/" },
    "T1547.004": { name: "Boot or Logon Autostart Execution: Winlogon Helper DLL", url: "https://attack.mitre.org/techniques/T1547/004/" },
    "T1546.015": { name: "Event Triggered Execution: COM Object Hijacking", url: "https://attack.mitre.org/techniques/T1546/015/" },
    "T1547.014": { name: "Boot or Logon Autostart Execution: Active Setup", url: "https://attack.mitre.org/techniques/T1547/014/" },
    "T1547.009": { name: "Boot or Logon Autostart Execution: Shortcut Modification", url: "https://attack.mitre.org/techniques/T1547/009/" },
    "T1556.002": { name: "Modify Authentication Process: Password Filter DLL", url: "https://attack.mitre.org/techniques/T1556/002/" },
    "T1574.001": { name: "Hijack Execution Flow: DLL Search Order Hijacking", url: "https://attack.mitre.org/techniques/T1574/001/" },
    "T1136": { name: "Create Account", url: "https://attack.mitre.org/techniques/T1136/" },
    "T1546.012": { name: "Event Triggered Execution: Image File Execution Options Injection", url: "https://attack.mitre.org/techniques/T1546/012/" },
    "T1176": { name: "Browser Extensions", url: "https://attack.mitre.org/techniques/T1176/" },
    "T1547.010": { name: "Boot or Logon Autostart Execution: Port Monitors", url: "https://attack.mitre.org/techniques/T1547/010/" },
    "T1055": { name: "Process Injection", url: "https://attack.mitre.org/techniques/T1055/" },
    "T1556": { name: "Modify Authentication Process", url: "https://attack.mitre.org/techniques/T1556/" },
    "T1112": { name: "Modify Registry", url: "https://attack.mitre.org/techniques/T1112/" },
    "T1484": { name: "Domain Policy Modification", url: "https://attack.mitre.org/techniques/T1484/" },
    "T1546.010": { name: "Event Triggered Execution: AppInit DLLs", url: "https://attack.mitre.org/techniques/T1546/010/" },
    "T1547.002": { name: "Boot or Logon Autostart Execution: Authentication Package", url: "https://attack.mitre.org/techniques/T1547/002/" },
    "T1037.001": { name: "Boot or Logon Initialization Scripts: Logon Script (Windows)", url: "https://attack.mitre.org/techniques/T1037/001/" },
    "T1546.009": { name: "Event Triggered Execution: AppCert DLLs", url: "https://attack.mitre.org/techniques/T1546/009/" },
    "T1546.007": { name: "Event Triggered Execution: Netsh Helper DLL", url: "https://attack.mitre.org/techniques/T1546/007/" },
    "T1546.002": { name: "Event Triggered Execution: Screensaver", url: "https://attack.mitre.org/techniques/T1546/002/" },
    "T1137.006": { name: "Office Application Startup: Add-ins", url: "https://attack.mitre.org/techniques/T1137/006/" },
    "T1547.003": { name: "Boot or Logon Autostart Execution: Time Providers", url: "https://attack.mitre.org/techniques/T1547/003/" },
    "T1547": { name: "Boot or Logon Autostart Execution", url: "https://attack.mitre.org/techniques/T1547/" },
    "T1546.001": { name: "Event Triggered Execution: Change Default File Association", url: "https://attack.mitre.org/techniques/T1546/001/" },
    "T1547.005": { name: "Boot or Logon Autostart Execution: Security Support Provider", url: "https://attack.mitre.org/techniques/T1547/005/" },
    "T1574.012": { name: "Hijack Execution Flow: COR_PROFILER", url: "https://attack.mitre.org/techniques/T1574/012/" },
    "T1562.001": { name: "Impair Defenses: Disable or Modify Tools", url: "https://attack.mitre.org/techniques/T1562/001/" },
  };
  const PaMitreBadge = ({ category }) => { const id = PA_CAT_MITRE[category]; const m = id ? PA_MITRE_MAP[id] : null; if (!m) return null; return <span onClick={(e) => { e.stopPropagation(); window.open(m.url, "_blank"); }} title={m.name} style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "1px 6px", background: th.textMuted + "18", color: th.textDim, border: `1px solid ${th.textMuted}33`, borderRadius: 4, fontSize: 9, fontFamily: "monospace", cursor: "pointer", fontWeight: 600, letterSpacing: "0.02em", transition: "all var(--m-base)" }} onMouseEnter={(e) => { e.currentTarget.style.background = th.textMuted + "30"; e.currentTarget.style.color = th.accent; }} onMouseLeave={(e) => { e.currentTarget.style.background = th.textMuted + "18"; e.currentTarget.style.color = th.textDim; }}>{id}</span>; };
  const checkedItems = modal.checkedItems || new Set();
  const isChecked = (item) => checkedItems.has(item.rowid + "|" + item.name + "|" + item.timestamp);
  const toggleCheck = (item, e) => {
    e.stopPropagation();
    const key = item.rowid + "|" + item.name + "|" + item.timestamp;
    setModal((p) => {
      const s = new Set(p.checkedItems || []);
      s.has(key) ? s.delete(key) : s.add(key);
      return { ...p, checkedItems: s };
    });
  };
  const persistItemKey = (item) => item.rowid + "|" + item.name + "|" + item.timestamp;
  const itemForKey = (key) => {
    const items = data?.items || [];
    return items.find((i) => persistItemKey(i) === key);
  };
  const selectedPersistKey = modal.selectedPersistKey || null;
  const isSelPersist = (item) => selectedPersistKey === persistItemKey(item);
  const toggleSelPersist = (item) => {
    const k = persistItemKey(item);
    setModal((p) => ({ ...p, selectedPersistKey: p.selectedPersistKey === k ? null : k }));
  };
  const formatItemText = (i) => `[${i.severity.toUpperCase()}] ${i.name}\t${i.detailsSummary}\t${i.timestamp || "N/A"}\t${i.computer || "N/A"}\t${i.user || "N/A"}\t${i.source}\t${i.riskScore}/10`;

  // Rule catalog — MIRRORED from the analyzer via src/constants/persistenceRuleCatalog.mjs.
  // Rules are addressed positionally (`evtx-<i>` / `reg-<i>`), so this list must stay
  // index-for-index with electron/analyzers/persistence/rules.js; it used to be maintained
  // by hand here and had drifted three rules out of alignment (unchecking "Registry Value
  // Modified (4657)" disabled the 7040 service rule) while 13 rules had no entry at all and
  // were therefore invisible and impossible to disable. tests/persistence-rule-catalog.test.js
  // now fails the build on any drift.
  const EVTX_SUMMARIES = PA_EVTX_RULES;
  const REG_SUMMARIES = PA_REG_RULES;
  // Default display order for the EVTX rule catalog: severity-first (Critical → High →
  // Medium → Low). Each entry keeps its ORIGINAL index `i` because the enable/disable
  // toggle, presets, and intents key off positional `evtx-${i}` IDs — reordering only the
  // display must never remap a checkbox. Array sort is stable, so same-severity rules keep
  // their original (category) order.
  const _evtxSevRank = { critical: 0, high: 1, medium: 2, low: 3 };
  const EVTX_SUMMARIES_SORTED = EVTX_SUMMARIES
    .map((r, i) => ({ r, i }))
    .sort((a, b) => (_evtxSevRank[a.r.sev] ?? 9) - (_evtxSevRank[b.r.sev] ?? 9));
  const toggleRule = (key) => setModal((p) => { const s = new Set(p.disabledRules || []); s.has(key) ? s.delete(key) : s.add(key); return { ...p, disabledRules: s }; });
  const deleteCustomRule = (idx) => setModal((p) => ({ ...p, customRules: (p.customRules || []).filter((_, i) => i !== idx) }));
  const addCustomRule = () => {
    const nr = modal.newRule || {};
    if (!nr.name && !nr.eventIds && !nr.keyPathPattern) return;
    // Validate regex fields before adding
    for (const field of ["keyPathPattern", "payloadFilter", "valueNameFilter"]) {
      if (nr[field]) { try { new RegExp(nr[field]); } catch (e) { toast.error(`Invalid regex in ${field}`, { detail: e.message }); return; } }
    }
    setModal((p) => ({ ...p, customRules: [...(p.customRules || []), { ...nr, type: p.addingRule }], addingRule: false, newRule: {} }));
  };
  const disabledSet = modal.disabledRules || new Set();
  const evtxActive = EVTX_SUMMARIES.length - [...disabledSet].filter((k) => k.startsWith("evtx-")).length;
  const regActive = REG_SUMMARIES.length - [...disabledSet].filter((k) => k.startsWith("reg-")).length;
  const customCount = (modal.customRules || []).length;

  // --- Technique Preset Cards ---
  // Which rules each card selects lives in the shared catalog next to the rule list, so
  // a rule change and its preset wiring are reviewed together and index drift is caught
  // by tests/persistence-rule-catalog.test.js. Only the artwork stays here.
  const PA_PRESET_ICONS = {
    svc: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9"/></svg>,
    task: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
    wmi: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/></svg>,
    regsys: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>,
    adv: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    remote: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><rect x="2" y="3" width="20" height="7" rx="1"/><rect x="2" y="14" width="20" height="7" rx="1"/><line x1="6" y1="6.5" x2="6.01" y2="6.5"/><line x1="6" y1="17.5" x2="6.01" y2="17.5"/></svg>,
    defender: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="12" x2="15" y2="12"/></svg>,
    core: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>,
    stealth: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
    shell: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>,
    supp: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>,
    hijack: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>,
  };
  const withIcon = (presets) => presets.map((p) => ({ ...p, icon: PA_PRESET_ICONS[p.id] }));
  const paPresetState = (presetRules, prefix, disSet) => {
    const offCount = presetRules.filter(i => disSet.has(`${prefix}-${i}`)).length;
    return offCount === 0 ? "on" : offCount === presetRules.length ? "off" : "partial";
  };
  const togglePaPreset = (preset, prefix) => setModal((p) => {
    const s = new Set(p.disabledRules || []);
    const state = paPresetState(preset.rules, prefix, s);
    if (state === "on") { preset.rules.forEach(i => s.add(`${prefix}-${i}`)); }
    else { preset.rules.forEach(i => s.delete(`${prefix}-${i}`)); }
    return { ...p, disabledRules: s };
  });

  // --- Intent Selector (rule ids live in the shared catalog) ---
  const applyPaIntent = (intent) => setModal((p) => ({ ...p, disabledRules: new Set(intent.disabled), paIntent: intent.id }));
  const resetPaRules = () => setModal((p) => ({ ...p, disabledRules: new Set(), paIntent: "balanced" }));

  // --- Event/Coverage Groups ---
  const PA_EVTX_GROUPS = [
    { label: "Svc Install", eids: ["7045","4697","7040"], detector: "Service persistence" },
    { label: "Sched Tasks", eids: ["4698","4699","106","140","129","200","141","118","119","4702"], detector: "Task creation/deletion/triggers" },
    { label: "WMI", eids: ["5861","19","20","21"], detector: "WMI event subscriptions" },
    { label: "Reg Sysmon", eids: ["13","12","14"], detector: "Registry autorun (Sysmon)" },
    { label: "Startup", eids: ["11"], detector: "Startup folder drops" },
    { label: "Driver", eids: ["6"], detector: "Driver loading" },
    { label: "DLL Load", eids: ["7"], detector: "DLL hijacking" },
    { label: "Tamper", eids: ["25"], detector: "Process tampering" },
    { label: "Acct Changes", eids: ["4720","4728","4732","4756","4724","4738"], detector: "Account creation/modification/group adds" },
    { label: "AD Objects", eids: ["5136","5137","5141"], detector: "Domain persistence (AD object changes)" },
    { label: "Reg 4657", eids: ["4657"], detector: "Registry autorun (Security 4657 fallback)" },
    { label: "PS 4104", eids: ["4104"], detector: "PowerShell script block persistence" },
    { label: "Defender", eids: ["5001", "5007", "5010", "5012", "5101"], detector: "Defender tampering (exclusions, protection disabled)" },
    { label: "Remote Exec", eids: ["5857", "5858", "5860", "145", "161", "169"], detector: "WinRM / WMI operations attributed to another machine" },
    { label: "Inbound Logon", eids: ["4624"], detector: "Network/RDP logons — used to attribute persistence to the pivot that planted it" },
  ];
  // Registry coverage chips. Each label must exist as a group label in the analyzer's
  // previewPersistenceAnalysis regGroups, or the chip can only ever render 0.
  const PA_REG_GROUPS = [
    { label: "Run Keys" }, { label: "Services" }, { label: "Winlogon" }, { label: "IFEO" },
    { label: "COM Objects" }, { label: "Scheduled Tasks" }, { label: "Boot Execute" },
    { label: "LSA" }, { label: "Shell Extensions" }, { label: "AppInit DLLs" },
    { label: "Print Monitors" }, { label: "Active Setup" }, { label: "BHO" }, { label: "Network Providers" },
    { label: "Logon Script" }, { label: "AppCert DLLs" }, { label: "Silent Process Exit" }, { label: "Credential Providers" },
    { label: "Command Processor" }, { label: "Explorer Autoruns" }, { label: "Netsh Helper DLLs" },
    { label: "Screensaver" }, { label: "Office Add-ins" }, { label: "Time Providers" }, { label: "Terminal Server" },
    { label: "File Association" }, { label: "Group Policy Scripts" }, { label: "Security Support Provider" },
    { label: "COM TreatAs" }, { label: "Defender Tampering" },
  ];

  // --- Skip/Reduced-Confidence Warnings ---
  const paSkipWarnings = (evCounts, mode) => {
    const warnings = [];
    const has = (eids) => eids.some(e => (evCounts[e] || 0) > 0);
    if (mode === "evtx" || mode === "auto") {
      if (!has(["7045","4697"]) && !has(["7040"])) warnings.push({ level: "warn", text: "No service install events (7045/4697/7040) — service persistence unavailable" });
      if (!has(["4698","4702"]) && !has(["106","129","140","200"])) warnings.push({ level: "warn", text: "No scheduled task events — task persistence coverage limited" });
      if (!has(["5861"]) && !has(["19","20","21"])) warnings.push({ level: "warn", text: "No WMI events (5861/Sysmon 19-21) — WMI persistence unavailable" });
      if (!has(["13","12","14"]) && !has(["4657"])) warnings.push({ level: "info", text: "No Sysmon registry (12/13/14) or Security 4657 — registry autorun detection unavailable" });
      else if (!has(["13","12","14"]) && has(["4657"])) warnings.push({ level: "info", text: "No Sysmon registry (12/13/14) — using Security 4657 fallback (lower fidelity)" });
      if (!has(["11"])) warnings.push({ level: "info", text: "No Sysmon 11 — startup folder monitoring unavailable" });
      if (!has(["6"])) warnings.push({ level: "info", text: "No Sysmon 6 — driver load detection unavailable" });
      if (!has(["4104"])) warnings.push({ level: "info", text: "No PowerShell 4104 (ScriptBlock) events — PowerShell persistence detection unavailable" });
      if (!has(["5136","5137","5141"])) warnings.push({ level: "info", text: "No AD object events (5136/5137/5141) — domain persistence detection unavailable" });
      if (!has(["4738"])) warnings.push({ level: "info", text: "No 4738 events — user account modification detection unavailable" });
      if (!has(["5001", "5007", "5010", "5012", "5101"])) warnings.push({ level: "info", text: "No Defender events (5001/5007/5010/5012/5101) — AV tampering detection unavailable" });
    }
    if (mode === "registry" || mode === "auto") {
      if (evCounts && Object.values(evCounts).every(v => v === 0)) warnings.push({ level: "error", text: "No persistence-related registry keys found in dataset" });
    }
    return warnings;
  };

  // --- Column quality warnings ---
  const paSanityWarnings = (colQuality, mode) => {
    const warnings = [];
    if (!colQuality) return warnings;
    if (mode === "evtx") {
      if (colQuality.payload && !colQuality.payload.mapped && colQuality.execInfo && !colQuality.execInfo.mapped) warnings.push({ level: "warn", text: "Missing PayloadData/ExecutableInfo — command/path scoring reduced" });
      if (colQuality.channel && !colQuality.channel.mapped) warnings.push({ level: "info", text: "No Channel column — channel-based rule filtering unavailable" });
    } else if (mode === "registry") {
      if (colQuality.keyPath && !colQuality.keyPath.mapped) warnings.push({ level: "error", text: "KeyPath column not mapped — registry mode cannot function" });
      if (colQuality.valueName && !colQuality.valueName.mapped) warnings.push({ level: "error", text: "ValueName column not mapped — registry mode cannot function" });
      if (colQuality.hivePath && !colQuality.hivePath.mapped) warnings.push({ level: "info", text: "No HivePath column — hive context unavailable" });
    }
    for (const [key, q] of Object.entries(colQuality)) {
      if (q.mapped && q.nullRate > 50) warnings.push({ level: "info", text: `${key} column has ${q.nullRate}% null/empty values` });
    }
    return warnings;
  };

  // --- Detector Blurbs ---
  const PA_DETECTOR_BLURBS = {
    "Service Installed": "Flags non-standard ImagePaths, RMM tools, PsExec services, browser-service mimicry",
    "Task Created": "GUID task names, LOLBin executables, user-writable paths, suspicious actions",
    "WMI Event Subscription": "High-confidence — WMI event consumers and subscriptions are strong persistence indicators",
    "Registry Value Set": "Sysmon 13 — common autorun keys (Run, Services, Winlogon, IFEO, COM)",
    "File Created in Startup": "Sysmon 11 — files dropped in user or common startup folders",
    "Suspicious Driver Loaded": "Sysmon 6 — unsigned or suspicious driver loading events",
    "Unsigned DLL Loaded": "Sysmon 7 — unsigned DLL loading, can be noisy in enterprise environments",
    "Process Tampering Detected": "Sysmon 25 — process hollowing, herpaderping, or image modification",
  };

  // --- Preview refresh ---
  let _paPreviewTimer = null;
  const refreshPaPreview = (colOverrides) => {
    if (!tle.previewPersistenceAnalysis || !ct) {
      setModal(updateModal("persistence", { paPreviewLoading: false }));
      return;
    }
    clearTimeout(_paPreviewTimer);
    _paPreviewTimer = setTimeout(() => {
      setModal((p) => {
        if (!p || p.type !== "persistence") return p;
        const c = colOverrides || p.columns || {};
        const af = activeFilters(ct);
        const seq = (p._paPreviewSeq || 0) + 1;
        tle.previewPersistenceAnalysis(ct.id, {
          mode: p.mode, columns: c,
          searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
          columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
          bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        }).then((prev) => {
          setModal(updateModal("persistence", (q) => (q._paPreviewSeq || 0) === seq ? { paPreview: prev, paPreviewLoading: false } : null));
        }).catch(() => {
          setModal(updateModal("persistence", (q) => (q._paPreviewSeq || 0) === seq ? { paPreviewLoading: false } : null));
        });
        return { ...p, paPreviewLoading: true, _paPreviewSeq: seq };
      });
    }, 600);
  };
  if (modal._paNeedsPreview) {
    setModal((p) => ({ ...p, _paNeedsPreview: false }));
    refreshPaPreview();
  }

  // Multi-source preview: what each selected tab contributes (shape + which correlation
  // events only it can supply). Refreshed whenever the tab selection changes.
  if (modal._paNeedsMultiPreview) {
    setModal((p) => ({ ...p, _paNeedsMultiPreview: false }));
    if (tle?.previewMultiSourcePersistence && ct) {
      const ids = [ct.id, ...(modal.paSelectedTabIds || [])];
      const tabLabels = {};
      for (const t of tabs) tabLabels[t.id] = t.name;
      tle.previewMultiSourcePersistence(ids, { _tabLabels: tabLabels })
        .then((prev) => setModal(updateModal("persistence", () => (isIpcError(prev) ? null : { paMultiPreview: prev }))))
        .catch(() => { /* preview is advisory — a failure must not block the scan */ });
    }
  }

  // Shared completion path for both the job-backed and the direct-invoke route.
  const applyPersistenceResult = async (payload, pInt) => {
    clearInterval(pInt);
    tle?.removeAllListeners?.("persistence-analysis-complete");
    if (payload?.cancelled) {
      setModal(updateModal("persistence", { phase: "config", loading: false, progress: 0, _paJobId: null }));
      return;
    }
    const result = payload?.result ?? payload;
    const errMsg = payload?.error || (isIpcError(result) ? ipcErrorMessage(result) : null);
    if (errMsg) {
      setModal(updateModal("persistence", (p) => !p._cancelled ? { phase: "config", loading: false, error: errMsg, progress: 0, _paJobId: null } : null));
      return;
    }
    setModal(updateModal("persistence", (p) => !p._cancelled ? { progress: 100, phaseIdx: 3 } : null));
    await new Promise((r) => setTimeout(r, 250));
    setModal(updateModal("persistence", (p) => !p._cancelled ? { phase: "results", data: result, loading: false, _paJobId: null } : null));
    // Distribute incident-level evidence pills to per-row map so the main
    // grid can render an Evidence column. Replaces any prior persistence
    // pill state on this tab — re-running re-derives from fresh results.
    //
    // Skipped for a merged run: every tab's rowids start at 1, so a pill keyed on rowid
    // alone would decorate whichever unrelated row happens to share that number in the
    // current tab. Clear instead of mis-attributing.
    const pillsMap = result?.multiSource ? {} : buildPillsByRowid(result?.incidents || []);
    useTabStore.getState().updateTab(ct.id, { evidencePillsByRowid: pillsMap });
  };

  const handleAnalyze = async () => {
    const t0 = Date.now();
    const pInt = setInterval(() => {
      setModal((p) => {
        if (!p || p.type !== "persistence" || p.phase !== "loading") { clearInterval(pInt); return p; }
        const el = (Date.now() - t0) / 1000;
        const prog = Math.min(92, 90 * (1 - Math.exp(-el / 6)));
        const pi = prog < 15 ? 0 : prog < 50 ? 1 : prog < 80 ? 2 : 3;
        return { ...p, progress: prog, phaseIdx: pi };
      });
    }, 150);
    setModal((p) => ({ ...p, phase: "loading", loading: true, error: null, progress: 0, phaseIdx: 0, _cancelled: false, _paJobId: null }));
    try {
      const af = activeFilters(ct);
      const options = {
        mode: pMode === "auto" ? "auto" : pMode,
        columns: modal.columns || {},
        searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        disabledRules: [...(modal.disabledRules || [])],
        customRules: modal.customRules || [],
      };

      // A collection scan reads a FOLDER, not this tab, so nothing tab-scoped applies.
      const collectionDir = modal.paCollection?.dir && !modal.paCollection?.scan?.error ? modal.paCollection.dir : null;

      // Multi-source merges several tabs into one analysis so a finding in one file can be
      // corroborated by events in another. Row-level column overrides and this tab's grid
      // filters are single-tab concepts, so they are not forwarded.
      const multiTabIds = (!collectionDir && modal.paMultiSource && (modal.paSelectedTabIds || []).length > 0)
        ? [ct.id, ...modal.paSelectedTabIds]
        : null;
      if (collectionDir) {
        delete options.columns;
        for (const k of ["searchTerm", "searchMode", "searchCondition", "columnFilters",
          "checkboxFilters", "bookmarkedOnly", "dateRangeFilters", "advancedFilters"]) {
          delete options[k];
        }
      }
      if (multiTabIds) {
        const tabLabels = {};
        for (const t of tabs) tabLabels[t.id] = t.name;
        options._tabLabels = tabLabels;
        // Column overrides and this tab's grid scope (search, column/date filters,
        // bookmarks) describe ONE tab. Applied across a merge they would quietly shrink
        // every other tab's contribution by a predicate that means nothing there — and the
        // corroborating 4688 you filtered out is exactly what the merge exists to find.
        delete options.columns;
        for (const k of ["searchTerm", "searchMode", "searchCondition", "columnFilters",
          "checkboxFilters", "bookmarkedOnly", "dateRangeFilters", "advancedFilters"]) {
          delete options[k];
        }
      }

      // Prefer the job-backed route: it hands back a jobId so Cancel can actually
      // terminate the analyzer worker instead of only hiding the modal.
      if (tle?.startPersistenceAnalysis && tle?.onPersistenceAnalysisComplete) {
        tle.removeAllListeners?.("persistence-analysis-complete");
        tle.onPersistenceAnalysisComplete((payload = {}) => {
          const currentModal = useUIStore.getState?.().modal;
          if (currentModal?.type !== "persistence") return;
          if (currentModal._paJobId && payload.jobId && currentModal._paJobId !== payload.jobId) return;
          applyPersistenceResult(payload, pInt);
        });
        const started = collectionDir && tle.analyzeKapeCollection
          ? await tle.analyzeKapeCollection(collectionDir, options)
          : multiTabIds && tle.startMultiSourcePersistence
            ? await tle.startMultiSourcePersistence(multiTabIds, options)
            : await tle.startPersistenceAnalysis(ct.id, options);
        if (isIpcError(started)) throw new Error(ipcErrorMessage(started));
        // No worker available in this build — the handler ran it inline and returned it.
        if (started?.result || started?.error) {
          await applyPersistenceResult(started, pInt);
          return;
        }
        if (!started?.jobId) throw new Error("Persistence analysis job did not start");
        setModal((p) => p?.type === "persistence" ? { ...p, _paJobId: started.jobId } : p);
      } else {
        const result = collectionDir && tle.analyzeKapeCollection
          ? (await tle.analyzeKapeCollection(collectionDir, options))?.result
          : multiTabIds && tle.getMultiSourcePersistence
            ? await tle.getMultiSourcePersistence(multiTabIds, options)
            : await tle.getPersistenceAnalysis(ct.id, options);
        await applyPersistenceResult({ result }, pInt);
      }
    } catch (e) {
      clearInterval(pInt);
      tle?.removeAllListeners?.("persistence-analysis-complete");
      setModal(updateModal("persistence", { phase: "config", loading: false, error: e.message, progress: 0, _paJobId: null }));
    }
  };

  // Auto-run when Process Inspector (or another feature) hands off with _paAutoRun.
  if (modal._paAutoRun && modal.phase === "config" && !modal.loading) {
    setModal((p) => ({ ...p, _paAutoRun: false }));
    setTimeout(() => handleAnalyze(), 80);
  }

  // Stop the analyzer worker, don't just navigate away from it.
  const handleCancelAnalyze = async () => {
    const currentModal = useUIStore.getState?.().modal;
    const jobId = (currentModal?.type === "persistence" ? currentModal._paJobId : null) || modal._paJobId;
    tle?.removeAllListeners?.("persistence-analysis-complete");
    setModal((p) => p?.type === "persistence"
      ? { ...p, phase: "config", loading: false, progress: 0, phaseIdx: 0, _cancelled: true, _paJobId: null }
      : p);
    if (jobId && tle?.cancelJob) {
      try { await tle.cancelJob(jobId); } catch { /* worker already finished or gone */ }
    }
  };

  // Filtered items for results
  const filteredItems = data?.items?.filter((item) => {
    if (severityFilter !== "all" && item.severity !== severityFilter) return false;
    if (categoryFilter !== "all" && item.category !== categoryFilter) return false;
    if (searchText) {
      const s = searchText.toLowerCase();
      const blob = `${item.name} ${item.detailsSummary} ${item.computer} ${item.user} ${item.source} ${item.category}`.toLowerCase();
      if (!blob.includes(s)) return false;
    }
    return true;
  }) || [];

  // Group items by category (kept for timeline/table views)
  const grouped = {};
  for (const item of filteredItems) {
    if (!grouped[item.category]) grouped[item.category] = [];
    grouped[item.category].push(item);
  }
  const categories = Object.keys(grouped).sort();
  const allCategories = data?.stats?.byCategory ? Object.keys(data.stats.byCategory).sort() : [];
  const collapsedCats = modal.collapsedCats || new Set();

  // --- Incident-based grouping for Grouped view ---
  const allIncidents = data?.incidents || [];
  const paFindingsView = modal.paFindingsView || "alerts";
  const paSortBy = modal.paSortBy || "triage";
  const paGroupBy = modal.paGroupBy || "incident";
  const expandedIncident = modal.expandedIncident;

  const filteredIncidents = allIncidents.filter((inc) => {
    if (severityFilter !== "all" && inc.severity !== severityFilter) return false;
    if (categoryFilter !== "all" && inc.category !== categoryFilter) return false;
    if (searchText) { const s = searchText.toLowerCase(); if (!`${inc.title} ${inc.artifact} ${inc.command} ${inc.computer} ${inc.user} ${inc.category} ${inc.source}`.toLowerCase().includes(s)) return false; }
    return true;
  });
  const _sevOrd = { critical: 0, high: 1, medium: 2, low: 3 };
  const sortedIncidents = [...filteredIncidents].sort((a, b) => {
    if (paSortBy === "triage") return (b.triageScore || 0) - (a.triageScore || 0);
    if (paSortBy === "severity") return (_sevOrd[a.severity] ?? 4) - (_sevOrd[b.severity] ?? 4);
    if (paSortBy === "recency") return ((b.lastSeen) || "").localeCompare((a.lastSeen) || "");
    if (paSortBy === "events") return (b.occurrenceCount || 0) - (a.occurrenceCount || 0);
    return 0;
  });
  let paGroupedEntries = null;
  if (paGroupBy !== "incident") {
    const gm = new Map();
    for (const inc of sortedIncidents) {
      let key = "(none)";
      if (paGroupBy === "host") key = inc.computer || "(no host)";
      else if (paGroupBy === "technique") key = inc.category || "(none)";
      else if (paGroupBy === "artifact") key = (inc.artifact || "").split("\\").pop() || "(none)";
      if (!gm.has(key)) gm.set(key, []);
      gm.get(key).push(inc);
    }
    paGroupedEntries = [...gm.entries()].sort((a, b) => Math.max(...b[1].map(i => i.triageScore || 0)) - Math.max(...a[1].map(i => i.triageScore || 0)));
  }

  // The results toolbar must act on what is actually on screen. The default landing view
  // (Alerts + Grouped) lists INCIDENTS; every other view lists items. Exporting/selecting
  // filteredItems regardless meant "Select All (N)" showed an item count next to a list of
  // incidents, and "↓ CSV" wrote a different set of rows than the analyst was looking at.
  const paShowingIncidents = paFindingsView === "alerts" && viewTab === "grouped";
  const paVisibleRows = paShowingIncidents ? sortedIncidents : filteredItems;
  // Checkbox state is per-item (rowid|name|timestamp), so selecting a visible incident
  // means selecting the items it clustered.
  const paSelectableItems = paShowingIncidents
    ? sortedIncidents.flatMap((inc) => inc.items || [])
    : filteredItems;
  // Row -> flat export record. Incidents and items expose different field names for the
  // same concepts (title/name, firstSeen/timestamp, triageScore/riskScore), so both shapes
  // map onto one CSV schema.
  const paExportRow = (row) => ({
    Severity: row.severity || "", Category: row.category || "", Name: row.name || row.title || "",
    Computer: row.computer || "", User: row.user || "", Timestamp: row.timestamp || row.firstSeen || "",
    Artifact: row.artifact || "", Command: row.command || "", Source: row.source || "",
    RiskScore: row.triageScore ?? row.riskScore ?? "", Occurrences: row.occurrenceCount ?? "",
    Description: row.detailsSummary || row.description || "",
    SuspiciousReasons: Array.isArray(row.suspiciousReasons) ? row.suspiciousReasons.join("; ") : "",
  });

  // --- Pivot handlers ---
  const _paBtnS = { padding: "2px 8px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, fontSize: 9, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 };
  const _paBtnActive = (a) => a ? { ..._paBtnS, background: th.accent, color: "#fff" } : _paBtnS;
  // Artifact search term: use the shortest unique identifier so it actually matches payload text
  const _artSearchTerm = (inc) => {
    if (!inc.artifact) return "";
    // For paths, use the leaf name (e.g. "PSEXESVC" not full registry path)
    const leaf = inc.artifact.split("\\").pop();
    return leaf || inc.artifact;
  };
  const _paFilterArtifact = (inc, e) => {
    if (e) e.stopPropagation();
    const cols = data.columns || {};
    const cf = { ...(ct.columnFilters || {}) };
    // EventID narrows to the right event type
    if (inc.mode === "evtx") { const eid = (inc.source || "").match(/EventID (\d+)/)?.[1]; if (eid && cols.eventId) cf[cols.eventId] = eid; }
    else { if (inc.artifact && cols.keyPath) cf[cols.keyPath] = _artSearchTerm(inc); }
    up("columnFilters", cf);
    // Use searchTerm for artifact text — works across all payload columns
    if (inc.mode === "evtx" && inc.artifact) up("searchTerm", _artSearchTerm(inc));
    setModal(null);
  };
  const _paFilterHost = (inc, e) => {
    if (e) e.stopPropagation();
    const cols = data.columns || {};
    const cf = { ...(ct.columnFilters || {}) };
    if (inc.computer && cols.computer) cf[cols.computer] = inc.computer;
    up("columnFilters", cf); setModal(null);
  };
  const _paFilterRelated = (inc, e) => {
    if (e) e.stopPropagation();
    const cols = data.columns || {};
    const cf = { ...(ct.columnFilters || {}) };
    if (inc.mode === "evtx") {
      const eid = (inc.source || "").match(/EventID (\d+)/)?.[1];
      if (eid && cols.eventId) cf[cols.eventId] = eid;
      if (inc.computer && cols.computer) cf[cols.computer] = inc.computer;
    } else {
      if (inc.artifact && cols.keyPath) cf[cols.keyPath] = _artSearchTerm(inc);
    }
    up("columnFilters", cf);
    // Also set searchTerm for artifact to further narrow EVTX results
    if (inc.mode === "evtx" && inc.artifact) up("searchTerm", _artSearchTerm(inc));
    setModal(null);
  };
  const _paOpenInTimeline = (inc, e) => {
    if (e) e.stopPropagation();
    const cols = data.columns || {};
    if (cols.ts && inc.firstSeen) {
      const rF = inc.firstSeen, rT = inc.lastSeen || rF;
      const sep = rF.includes("T") ? "T" : " ";
      const pad = (s, d) => { const dt = new Date(s.replace("T", " ").replace("Z", "")); if (isNaN(dt)) return s; const nd = new Date(dt.getTime() + d); const p = (n) => String(n).padStart(2, "0"); return `${nd.getFullYear()}-${p(nd.getMonth()+1)}-${p(nd.getDate())}${sep}${p(nd.getHours())}:${p(nd.getMinutes())}:${p(nd.getSeconds())}`; };
      up("dateRangeFilters", { [cols.ts]: { from: pad(rF, -300000), to: pad(rT, 300000) } });
    }
    const cf = { ...(ct.columnFilters || {}) };
    if (inc.mode === "evtx") {
      const eid = (inc.source || "").match(/EventID (\d+)/)?.[1];
      if (eid && cols.eventId) cf[cols.eventId] = eid;
      if (inc.computer && cols.computer) cf[cols.computer] = inc.computer;
    } else {
      if (inc.artifact && cols.keyPath) cf[cols.keyPath] = _artSearchTerm(inc);
    }
    up("columnFilters", cf);
    if (inc.mode === "evtx" && inc.artifact) up("searchTerm", _artSearchTerm(inc));
    setModal(null);
  };
  const _paCopyIOC = (inc, e) => {
    if (e) e.stopPropagation();
    const lines = [`[${inc.severity.toUpperCase()}] ${inc.category} (Score: ${inc.triageScore}/10)`, `Artifact: ${inc.artifact || "(none)"}`, `Command: ${inc.command || "(none)"}`, `Host: ${inc.computer || "(none)"}`, `User: ${inc.user || "(none)"}`, `Time: ${(inc.firstSeen || "").slice(0, 19)} - ${(inc.lastSeen || "").slice(0, 19)}`, `Occurrences: ${inc.occurrenceCount}`, `Source: ${inc.source}`];
    if (inc.suspiciousReasons.length > 0) lines.push(`Reasons: ${inc.suspiciousReasons.join(", ")}`);
    if (inc.evidencePills.length > 0) lines.push(`Evidence: ${inc.evidencePills.map(p => p.text).join(", ")}`);
    const mitreId = PA_CAT_MITRE[inc.category]; if (mitreId) lines.splice(1, 0, `MITRE: ${mitreId} (${(PA_MITRE_MAP[mitreId] || {}).name || ""})`);
    navigator.clipboard?.writeText?.(lines.join("\n"));
  };

  return (
    <DraggableResizableModal
      defaultWidth={Math.round(window.innerWidth * 0.92)}
      defaultHeight={Math.round(window.innerHeight * 0.88)}
      minWidth={600}
      minHeight={400}
      zIndex={200}
      onClose={() => setModal(null)}
    >
      {({ startDrag: startPaDrag }) => (<>
        {/* Header — draggable */}
        <div onMouseDown={startPaDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)", flexShrink: 0, cursor: "grab" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill={(th.danger)+"22"} stroke={th.danger} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: th.text, letterSpacing: "-0.3px", fontFamily: "-apple-system, sans-serif" }}>Persistence Analyzer</div>
              <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1 }}>
                {phase === "results" && data ? (modal.paFindingsView === "alerts" && viewTab === "grouped"
                  ? `${data.stats.incidentCount || 0} incidents (${data.stats.total} items) | ${data.stats.byIncidentSeverity?.critical || 0} critical | ${data.detectedMode?.toUpperCase()} mode`
                  : `${data.stats.total} mechanisms found | ${data.stats.bySeverity?.critical || 0} critical | ${data.detectedMode?.toUpperCase()} mode`) : "Automated persistence mechanism detection"}
              </div>
            </div>
          </div>
          <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", padding: 4, borderRadius: 6, fontSize: 18, lineHeight: 1 }} onMouseEnter={(e) => e.currentTarget.style.color = th.text} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>&times;</button>
        </div>

        {/* Body — scrollable */}
        <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>

          {/* Config phase */}
          {phase === "config" && (
            <div>
              {modal.error && <div style={{ padding: "10px 14px", marginBottom: 14, background: `${(th.danger)}15`, border: `1px solid ${(th.danger)}33`, borderRadius: 8, color: th.danger, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>{modal.error}</div>}

              {/* Auto-detect summary card */}
              {(() => {
                const prev = modal.paPreview;
                const dm = prev?.detectedMode || (pMode !== "auto" ? pMode : null);
                const modeLabel = dm === "evtx" ? "EVTX Logs" : dm === "registry" ? "Registry Export" : "Unknown";
                const modeHint = dm === "evtx" ? "EvtxECmd / Hayabusa / Chainsaw" : dm === "registry" ? "RECmd / Registry Explorer" : "";
                return (
                  <div style={{ padding: "12px 14px", background: `${th.panelBg}44`, border: `1px solid ${th.border}22`, borderRadius: 10, marginBottom: 14 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Data Source</span>
                        {dm && <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, background: `${th.accent}15`, color: th.accent, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{modeLabel}</span>}
                        {dm && <span style={{ fontSize: 9, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{modeHint}</span>}
                      </div>
                      <div style={{ display: "flex", gap: 4 }}>
                        {["auto", "evtx", "registry"].map((m) => (
                          <button key={m} onClick={() => { setModal((p) => ({ ...p, mode: m, _paNeedsPreview: true })); }}
                            style={{ padding: "3px 10px", borderRadius: 6, border: `1px solid ${pMode === m ? th.accent : th.border}44`, background: pMode === m ? `${th.accent}15` : "transparent", color: pMode === m ? th.accent : th.textMuted, fontSize: 10, fontWeight: 600, cursor: "pointer", fontFamily: "-apple-system, sans-serif", transition: "all var(--m-base)" }}>
                            {m === "auto" ? "Auto" : m.toUpperCase()}
                          </button>
                        ))}
                      </div>
                    </div>
                    {prev?.trackedEvents != null && <span style={{ fontSize: 9, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{(prev.trackedEvents || 0).toLocaleString()} tracked events</span>}
                  </div>
                );
              })()}

              {/* Collapsible column mapping — available in all modes including auto */}
              {(() => {
                const dm = modal.paPreview?.detectedMode || (pMode !== "auto" ? pMode : null);
                const mappingMode = pMode !== "auto" ? pMode : dm;
                if (!mappingMode) return null;
                return (
                <div style={{ marginBottom: 14 }}>
                  <button onClick={() => setModal((p) => ({ ...p, paShowMapping: !p.paShowMapping }))}
                    style={{ width: "100%", padding: "8px 14px", background: `${th.panelBg}44`, border: `1px solid ${th.border}22`, borderRadius: 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "space-between", transition: "all var(--m-base)" }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Column Mapping ({mappingMode === "evtx" ? "EVTX" : "Registry"})</span>
                    <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                        {(() => {
                          const cq = modal.paPreview?.columnQuality;
                          if (!cq) return "auto-detected";
                          const mapped = Object.values(cq).filter(v => v.mapped).length;
                          const total = Object.keys(cq).length;
                          return `${mapped}/${total} mapped`;
                        })()}
                      </span>
                      <span style={{ transform: modal.paShowMapping ? "rotate(180deg)" : "rotate(0deg)", transition: "transform var(--m-base)", fontSize: 12, color: th.textMuted }}>&#9662;</span>
                    </span>
                  </button>
                  {modal.paShowMapping && (
                    <div style={{ marginTop: 6, padding: "10px 12px", background: `${th.panelBg}88`, border: `1px solid ${th.border}22`, borderRadius: 10 }}>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px 12px" }}>
                        {(mappingMode === "evtx"
                          ? [["eventId","Event ID"],["channel","Channel"],["ts","Timestamp"],["computer","Computer"],["user","User"]]
                          : [["keyPath","Key Path"],["valueName","Value Name"],["valueData","Value Data"],["hivePath","Hive Path"],["ts","Timestamp"]]
                        ).map(([key, label]) => {
                          const cq = modal.paPreview?.columnQuality?.[key];
                          return (
                            <div key={key}>
                              <div style={{ fontSize: 10, color: th.textMuted, marginBottom: 3, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 4 }}>
                                {label}
                                {cq && cq.mapped && <span style={{ fontSize: 8, color: cq.nullRate > 50 ? (th.danger) : th.sev.clean }}>{cq.nullRate > 0 ? `${cq.nullRate}% null` : "OK"}</span>}
                              </div>
                              <select value={modal.columns?.[key] || ""} onChange={(e) => { const v = e.target.value || undefined; setModal((p) => ({ ...p, columns: { ...p.columns, [key]: v } })); refreshPaPreview({ ...modal.columns, [key]: v }); }}
                                style={{ ...ms.sl, width: "100%", fontSize: 11, padding: "5px 8px" }}>
                                <option value="">-- auto --</option>
                                {(ct?.headers || []).map((h) => <option key={h} value={h}>{h}</option>)}
                              </select>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
                );
              })()}

              {/* Analyze a whole KAPE collection folder */}
              {tle?.selectKapeCollection && (
                <div style={{ padding: "10px 14px", background: modal.paCollection ? `${th.accent}08` : `${th.panelBg}55`, border: `1px solid ${modal.paCollection ? th.accent + "33" : th.border + "22"}`, borderRadius: 10, marginBottom: 12, transition: "all var(--m-base)" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={modal.paCollection ? th.accent : th.textDim} strokeWidth="2" strokeLinecap="round">
                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                      </svg>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Analyze KAPE Collection</div>
                        <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1 }}>
                          Point at a triage folder to read the scheduled-task definitions on disk — every registered task, including ones that never fired, with Hidden/RunLevel/COM-handler/triggers read rather than inferred.
                        </div>
                      </div>
                    </div>
                    <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                      {modal.paCollection && (
                        <button onClick={() => setModal((p) => ({ ...p, paCollection: null }))}
                          style={{ fontSize: 9, padding: "3px 8px", borderRadius: 5, background: "transparent", color: th.textMuted, border: `1px solid ${th.border}44`, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Clear</button>
                      )}
                      <button onClick={async () => {
                        try {
                          const res = await tle.selectKapeCollection();
                          if (isIpcError(res)) { toast.error("Could not open that folder", { detail: ipcErrorMessage(res) }); return; }
                          if (res?.canceled) return;
                          setModal(updateModal("persistence", () => ({ paCollection: { dir: res.dir, scan: res.scan } })));
                        } catch (e) { toast.error("Could not open that folder", { detail: e.message }); }
                      }} style={{ fontSize: 10, padding: "5px 12px", borderRadius: 6, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>
                        {modal.paCollection ? "Change folder…" : "Choose folder…"}
                      </button>
                    </div>
                  </div>
                  {modal.paCollection?.scan && (
                    <div style={{ borderTop: `1px solid ${th.border}22`, marginTop: 8, paddingTop: 8 }}>
                      <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: 5 }}>
                        {modal.paCollection.dir}
                      </div>
                      {modal.paCollection.scan.error ? (
                        <div style={{ fontSize: 10, color: th.danger, fontFamily: "-apple-system, sans-serif" }}>{modal.paCollection.scan.error}</div>
                      ) : (() => {
                        const a = modal.paCollection.scan.artifacts || {};
                        const chip = (label, n, readable) => (
                          <span key={label} title={readable ? "Read by this scan" : "Found, but needs importing as a tab"}
                            style={{ fontSize: 9, padding: "2px 7px", borderRadius: 5, fontFamily: "'SF Mono',Menlo,monospace",
                              background: n > 0 && readable ? `${th.accent}15` : `${th.border}22`,
                              color: n > 0 && readable ? th.accent : th.textMuted,
                              border: `1px solid ${n > 0 && readable ? th.accent + "33" : th.border + "22"}` }}>
                            {label} {n.toLocaleString()}{n > 0 && !readable ? " ·not read" : ""}
                          </span>
                        );
                        return (
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", alignItems: "center" }}>
                            <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                              {modal.paCollection.scan.host ? `${modal.paCollection.scan.host} · ` : ""}{modal.paCollection.scan.layout || "unrecognized"} layout
                            </span>
                            {chip("tasks", (a.taskXml || []).length, true)}
                            {chip("registry CSV", (a.moduleCsv || []).filter((c) => c.kind === "recmd-batch" || c.projects).length, true)}
                            {chip("evtx", (a.evtx || []).length, false)}
                            {chip("hives", (a.hives || []).length, false)}
                          </div>
                        );
                      })()}
                    </div>
                  )}
                </div>
              )}

              {/* Multi-source correlation */}
              {otherTabs.length > 0 && (
                <div style={{ padding: "10px 14px", background: modal.paMultiSource ? `${th.accent}08` : `${th.panelBg}55`, border: `1px solid ${modal.paMultiSource ? th.accent + "33" : th.border + "22"}`, borderRadius: 10, marginBottom: 12, transition: "all var(--m-base)" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: modal.paMultiSource ? 8 : 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={modal.paMultiSource ? th.accent : th.textDim} strokeWidth="2" strokeLinecap="round">
                        <circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="18" r="3"/>
                        <line x1="9" y1="6" x2="15" y2="6"/><line x1="6" y1="9" x2="6" y2="15"/><line x1="18" y1="9" x2="18" y2="15"/><line x1="9" y1="18" x2="15" y2="18"/>
                      </svg>
                      <div>
                        <div style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Multi-source Correlation</div>
                        <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1 }}>
                          A persistence artifact and its corroboration live in different files. Merge Security (4688), Sysmon (1/13), PowerShell (4104) and hive exports so a service install can be confirmed, not just observed.
                        </div>
                      </div>
                    </div>
                    <button onClick={() => setModal((p) => ({ ...p, paMultiSource: !p.paMultiSource, paSelectedTabIds: p.paSelectedTabIds || [], _paNeedsMultiPreview: !p.paMultiSource }))}
                      style={{ width: 36, height: 20, borderRadius: 10, border: "none", background: modal.paMultiSource ? th.accent : th.btnBg, cursor: "pointer", position: "relative", transition: "background var(--m-base)", flexShrink: 0 }}>
                      <div style={{ width: 16, height: 16, borderRadius: 8, background: "#fff", position: "absolute", top: 2, left: modal.paMultiSource ? 18 : 2, transition: "left var(--m-base)", boxShadow: "0 1px 3px rgba(0,0,0,0.3)" }} />
                    </button>
                  </div>
                  {modal.paMultiSource && (
                    <div style={{ borderTop: `1px solid ${th.border}22`, paddingTop: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                        <span style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>
                          Select tabs to merge ({(modal.paSelectedTabIds || []).length + 1} of {otherTabs.length + 1})
                        </span>
                        <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                          <button onClick={() => setModal((p) => ({ ...p, paSelectedTabIds: otherTabs.map((t) => t.id), _paNeedsMultiPreview: true }))}
                            style={{ fontSize: 9, padding: "2px 7px", borderRadius: 4, background: `${th.accent}12`, color: th.accent, border: `1px solid ${th.accent}25`, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Select all</button>
                          <button onClick={() => setModal((p) => ({ ...p, paSelectedTabIds: [], _paNeedsMultiPreview: true }))}
                            style={{ fontSize: 9, padding: "2px 7px", borderRadius: 4, background: "transparent", color: th.textMuted, border: `1px solid ${th.border}44`, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Clear</button>
                        </div>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 3, maxHeight: 140, overflow: "auto" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", background: `${th.accent}12`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                          <span style={{ color: th.accent, fontSize: 12, width: 14, textAlign: "center" }}>{"✓"}</span>
                          <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{ct.name}</span>
                          <span style={{ fontSize: 8, color: th.accent, fontFamily: "-apple-system, sans-serif", padding: "1px 5px", background: `${th.accent}15`, borderRadius: 4 }}>current</span>
                        </div>
                        {otherTabs.map((t) => {
                          const sel = (modal.paSelectedTabIds || []).includes(t.id);
                          // What the preview says this tab brings: its shape, plus which
                          // correlation events only it can supply.
                          const info = (modal.paMultiPreview?.tabs || []).find((x) => x.tabId === t.id);
                          return (
                            <button key={t.id} onClick={() => setModal((p) => {
                              const ids = [...(p.paSelectedTabIds || [])];
                              const idx = ids.indexOf(t.id);
                              if (idx >= 0) ids.splice(idx, 1); else ids.push(t.id);
                              return { ...p, paSelectedTabIds: ids, _paNeedsMultiPreview: true };
                            })}
                              style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", background: sel ? `${th.accent}08` : "transparent", borderRadius: 6, border: `1px solid ${sel ? th.accent + "22" : th.border + "11"}`, cursor: "pointer", textAlign: "left", transition: "all var(--m-base)" }}>
                              <span style={{ color: sel ? th.accent : th.textMuted, fontSize: 12, width: 14, textAlign: "center" }}>{sel ? "✓" : "○"}</span>
                              <span style={{ fontSize: 11, color: sel ? th.text : th.textDim, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.name}</span>
                              {info?.error && <span title={info.error} style={{ fontSize: 8, color: th.warning, fontFamily: "-apple-system, sans-serif", padding: "1px 5px", background: `${th.warning}15`, borderRadius: 4 }}>unusable</span>}
                              {info?.mode && <span style={{ fontSize: 8, color: th.textDim, fontFamily: "-apple-system, sans-serif", padding: "1px 5px", background: `${th.border}22`, borderRadius: 4 }}>{info.format || info.mode}</span>}
                              {(info?.correlationEids || []).length > 0 && (
                                <span title={`Supplies correlation events ${info.correlationEids.join(", ")}`} style={{ fontSize: 8, color: th.accent, fontFamily: "'SF Mono',Menlo,monospace", padding: "1px 5px", background: `${th.accent}15`, borderRadius: 4 }}>
                                  +{info.correlationEids.join(",")}
                                </span>
                              )}
                              <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{(t.totalRows || 0).toLocaleString()} rows</span>
                            </button>
                          );
                        })}
                      </div>
                      {(modal.paSelectedTabIds || []).length === 0 ? (
                        <div style={{ fontSize: 10, color: th.warning, marginTop: 6, fontFamily: "-apple-system, sans-serif" }}>Select at least one additional tab — with one tab this is the normal single-tab scan.</div>
                      ) : (
                        <div style={{ fontSize: 9, color: th.textMuted, marginTop: 6, fontFamily: "-apple-system, sans-serif" }}>
                          A merged scan ignores this tab's grid filters and column overrides — they describe one tab, and filtering out the corroborating events is what the merge exists to avoid.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Intent selector + Reset */}
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 14 }}>
                {PA_INTENTS.map((intent) => (
                  <button key={intent.id} onClick={() => applyPaIntent(intent)}
                    style={{ flex: 1, padding: "8px 10px", borderRadius: 8, border: `1px solid ${modal.paIntent === intent.id ? th.accent : th.border}44`, background: modal.paIntent === intent.id ? `${th.accent}12` : "transparent", cursor: "pointer", transition: "all var(--m-base)", textAlign: "center" }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: modal.paIntent === intent.id ? th.accent : th.text, fontFamily: "-apple-system, sans-serif" }}>{intent.label}{intent.id === "balanced" && <span title="Recommended default" style={{ color: th.accent, marginLeft: 3, fontSize: 9 }}>★</span>}</div>
                    <div style={{ fontSize: 9, color: th.textMuted, marginTop: 1, fontFamily: "-apple-system, sans-serif" }}>{intent.desc}</div>
                  </button>
                ))}
                <button onClick={resetPaRules} title="Reset to recommended"
                  style={{ padding: "8px 10px", borderRadius: 8, border: `1px solid ${th.border}44`, background: "transparent", cursor: "pointer", color: th.textMuted, fontSize: 10, fontWeight: 600, fontFamily: "-apple-system, sans-serif", transition: "all var(--m-base)", flexShrink: 0 }}
                  onMouseEnter={(e) => e.currentTarget.style.color = th.accent} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>
                  Reset
                </button>
              </div>

              {/* Technique Preset Cards */}
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>Detection Techniques</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {withIcon((pMode === "registry") ? PA_REG_PRESETS : PA_EVTX_PRESETS).map((preset) => {
                    const prefix = pMode === "registry" ? "reg" : "evtx";
                    const state = paPresetState(preset.rules, prefix, disabledSet);
                    const activeCount = preset.rules.filter(i => !disabledSet.has(`${prefix}-${i}`)).length;
                    const isOn = state !== "off";
                    return (
                      <div key={preset.id} style={{ padding: "10px 14px", background: isOn ? `${th.accent}08` : `${th.panelBg}33`, border: `1px solid ${isOn ? th.accent + "22" : th.border + "22"}`, borderRadius: 10, cursor: "pointer", transition: "all var(--m-base)", opacity: isOn ? 1 : 0.6 }}
                        onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = `0 4px 14px ${th.accent}1f`; }}
                        onMouseLeave={(e) => { e.currentTarget.style.transform = "none"; e.currentTarget.style.boxShadow = "none"; }}
                        onClick={() => togglePaPreset(preset, prefix)}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span style={{ color: isOn ? th.accent : th.textMuted, transition: "color var(--m-base)" }}>{preset.icon}</span>
                            <span style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{preset.name}</span>
                            <span style={{ fontSize: 9, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{activeCount}/{preset.rules.length}</span>
                          </div>
                          <div style={{ width: 28, height: 16, borderRadius: 8, background: isOn ? th.accent : th.border, position: "relative", transition: "background var(--m-base)" }}>
                            <div style={{ width: 12, height: 12, borderRadius: 6, background: "#fff", position: "absolute", top: 2, left: isOn ? 14 : 2, transition: "left 0.22s cubic-bezier(0.34, 1.56, 0.64, 1)" }} />
                          </div>
                        </div>
                        <div style={{ fontSize: 10, color: th.textMuted, marginTop: 4, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>{preset.desc}</div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Event/Coverage Availability Strip */}
              <div style={{ padding: "10px 14px", background: `${th.panelBg}44`, border: `1px solid ${th.border}22`, borderRadius: 10, marginBottom: 12 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>
                    {pMode === "registry" ? "Registry Coverage" : "Event Availability"}
                  </div>
                  {modal.paPreview && <span style={{ fontSize: 9, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{(modal.paPreview.trackedEvents || 0).toLocaleString()} tracked events</span>}
                </div>
                {modal.paPreviewLoading ? (
                  <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: "6px 0" }}>Scanning dataset...</div>
                ) : (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {(pMode === "registry" ? PA_REG_GROUPS : PA_EVTX_GROUPS).map((g, gi) => {
                      const prev = modal.paPreview;
                      let count = 0;
                      if (prev?.eventCounts) {
                        if (g.eids) { for (const e of g.eids) count += (prev.eventCounts[e] || 0); }
                        else { count = prev.eventCounts[g.label] || 0; }
                      }
                      const hasData = count > 0;
                      const clickable = Array.isArray(g.eids) && g.eids.length > 0;
                      const hi = modal.paHilite;
                      const active = clickable && Array.isArray(hi) && hi.length === g.eids.length && g.eids.every((e) => hi.includes(e));
                      return (
                        <div key={gi} title={clickable ? `Click to highlight rules using ${g.detector || g.label}` : (g.detector || g.label)}
                          onClick={clickable ? () => setModal((p) => ({ ...p, paHilite: active ? null : g.eids, showRules: true })) : undefined}
                          style={{ padding: "3px 8px", borderRadius: 6, fontSize: 9, fontWeight: 600, fontFamily: "-apple-system, sans-serif", cursor: clickable ? "pointer" : "default",
                          background: active ? th.accent : hasData ? `${th.accent}15` : `${th.border}22`, color: active ? "#fff" : hasData ? th.accent : th.textMuted, border: `1px solid ${active ? th.accent : hasData ? th.accent + "33" : th.border + "22"}`, transition: "all var(--m-base)" }}>
                          {g.label} {hasData && <span style={{ fontFamily: "SF Mono, monospace", fontSize: 8 }}>({count.toLocaleString()})</span>}
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* Live coverage summary — reacts to rule toggles */}
                {!modal.paPreviewLoading && modal.paPreview && (() => {
                  const prev = modal.paPreview.eventCounts || {};
                  let enabled, total, scope = null;
                  if (pMode === "registry") {
                    enabled = regActive; total = REG_SUMMARIES.length;
                  } else {
                    enabled = evtxActive; total = EVTX_SUMMARIES.length;
                    const eids = new Set();
                    EVTX_SUMMARIES.forEach((r, i) => { if (!disabledSet.has(`evtx-${i}`)) r.hint.split(",").forEach((e) => eids.add(e.trim())); });
                    scope = [...eids].reduce((s, e) => s + (prev[e] || 0), 0);
                  }
                  return (
                    <div style={{ marginTop: 8, paddingTop: 8, borderTop: `1px solid ${th.border}22`, display: "flex", alignItems: "center", gap: 8, fontSize: 10, fontFamily: "-apple-system, sans-serif", flexWrap: "wrap" }}>
                      <span style={{ color: th.text, fontWeight: 600 }}>{enabled}<span style={{ color: th.textMuted, fontWeight: 400 }}>/{total}</span> {pMode === "registry" ? "registry" : "EVTX"} {enabled === 1 ? "rule" : "rules"} enabled</span>
                      {scope != null && <><span style={{ color: th.textDim }}>·</span><span style={{ color: th.textMuted }}>≈ <span style={{ color: th.accent, fontFamily: "SF Mono, monospace", fontWeight: 600 }}>{scope.toLocaleString()}</span> events in scope</span></>}
                    </div>
                  );
                })()}

                {/* Skip + sanity warnings */}
                {modal.paPreview && !modal.paPreviewLoading && (() => {
                  const dm = modal.paPreview.detectedMode || pMode;
                  // A preview-level error means the dataset cannot be analyzed at all (e.g. a
                  // RECmd execution-evidence plugin CSV). Say so here rather than letting the
                  // analyst run a scan that can only come back empty.
                  const previewErr = modal.paPreview.error
                    ? [{ level: "error", text: modal.paPreview.error }]
                    : [];
                  const plugin = modal.paPreview.registryPlugin;
                  const pluginW = plugin?.projects
                    ? [{ level: "info", text: `Detected ${plugin.label} — a full-state inventory. Routine system entries are filtered; only rows with a hunting signal are listed.` }]
                    : [];
                  const skipW = modal.paPreview.error ? [] : paSkipWarnings(modal.paPreview.eventCounts || {}, dm);
                  const sanityW = paSanityWarnings(modal.paPreview.columnQuality, dm);
                  const allW = [...previewErr, ...pluginW, ...skipW, ...sanityW];
                  if (allW.length === 0) return null;
                  const wColors = { error: th.danger, warn: th.sev.med, info: th.textMuted };
                  return (
                    <div style={{ marginTop: 8 }}>
                      {allW.map((w, wi) => (
                        <div key={wi} style={{ fontSize: 10, color: wColors[w.level] || th.textMuted, fontFamily: "-apple-system, sans-serif", padding: "2px 0", lineHeight: 1.4 }}>
                          {w.level === "error" ? "\u2718" : w.level === "warn" ? "\u26A0" : "\u2139"} {w.text}
                        </div>
                      ))}
                    </div>
                  );
                })()}
              </div>

              {/* Advanced: individual rules + custom rules */}
              <div>
                <button onClick={() => setModal((p) => ({ ...p, showRules: !p.showRules }))}
                  style={{ width: "100%", padding: "10px 14px", background: `${th.accent}08`, border: `1px solid ${th.border}33`, borderRadius: 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "space-between", transition: "all var(--m-base)" }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                    Advanced
                  </span>
                  <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                    <span>{evtxActive}/{EVTX_SUMMARIES.length} EVTX, {regActive}/{REG_SUMMARIES.length} Reg{customCount > 0 ? `, ${customCount} custom` : ""}</span>
                    <span style={{ transform: modal.showRules ? "rotate(180deg)" : "rotate(0deg)", transition: "transform var(--m-base)", fontSize: 12 }}>&#9662;</span>
                  </span>
                </button>

                {modal.showRules && (
                  <div style={{ marginTop: 8, padding: "10px 12px", background: `${th.panelBg}88`, border: `1px solid ${th.border}22`, borderRadius: 10, maxHeight: 320, overflowY: "auto" }}>
                    {(pMode === "evtx" || pMode === "auto") && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                          EVTX Rules ({evtxActive}/{EVTX_SUMMARIES.length})
                        </div>
                        {(() => {
                          const prev = modal.paPreview?.eventCounts || {};
                          const countFor = (r) => r.hint.split(",").map((s) => s.trim()).reduce((s, e) => s + (prev[e] || 0), 0);
                          const maxCount = Math.max(1, ...EVTX_SUMMARIES_SORTED.map(({ r }) => countFor(r)));
                          const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
                          const rows = [];
                          let prevSev = null;
                          for (const { r, i } of EVTX_SUMMARIES_SORTED) {
                            const key = `evtx-${i}`;
                            const off = disabledSet.has(key);
                            const evCount = countFor(r);
                            const blurb = PA_DETECTOR_BLURBS[paRuleLabel(r)] || PA_DETECTOR_BLURBS[r.name];
                            const sevColor = SEVERITY_COLORS[r.sev] || th.textMuted;
                            const isHi = Array.isArray(modal.paHilite) && r.hint.split(",").map((s) => s.trim()).some((e) => modal.paHilite.includes(e));
                            if (r.sev !== prevSev) {
                              prevSev = r.sev;
                              const sevTotal = EVTX_SUMMARIES_SORTED.filter(({ r: rr }) => rr.sev === r.sev).length;
                              rows.push(
                                <div key={`hdr-${r.sev}`} style={{ display: "flex", alignItems: "center", gap: 6, margin: "9px 0 3px", paddingLeft: 1 }}>
                                  <span style={{ width: 6, height: 6, borderRadius: 3, background: sevColor, flexShrink: 0 }} />
                                  <span style={{ fontSize: 9, fontWeight: 700, color: sevColor, textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "-apple-system, sans-serif" }}>{SEV_LABEL[r.sev] || r.sev}</span>
                                  <span style={{ flex: 1, height: 1, background: `${sevColor}22` }} />
                                  <span style={{ fontSize: 9, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{sevTotal}</span>
                                </div>
                              );
                            }
                            rows.push(
                              <div key={key} style={{ padding: "2px 4px 2px 8px", background: isHi ? th.accent + "14" : "transparent", borderRadius: isHi ? 4 : 0, opacity: off ? 0.4 : (evCount > 0 ? 1 : 0.6), transition: "opacity var(--m-base), background var(--m-base)" }}>
                                <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                                  <input type="checkbox" checked={!off} onChange={() => toggleRule(key)} style={{ accentColor: th.accent, margin: 0, flexShrink: 0 }} />
                                  <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: sevColor + "22", color: sevColor, fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{r.sev}</span>
                                  <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{r.cat} — {paRuleLabel(r)}</span>
                                  <span title={`${evCount.toLocaleString()} events`} style={{ width: 36, height: 4, borderRadius: 2, background: th.border + "33", overflow: "hidden", flexShrink: 0 }}>
                                    <span style={{ display: "block", height: "100%", width: `${evCount > 0 ? Math.max(6, Math.round((evCount / maxCount) * 100)) : 0}%`, background: sevColor, borderRadius: 2, transition: "width var(--m-base)" }} />
                                  </span>
                                  <span style={{ fontSize: 9, color: evCount > 0 ? th.accent : th.textDim, fontFamily: "SF Mono, monospace", minWidth: 44, textAlign: "right" }}>{evCount > 0 ? evCount.toLocaleString() : "0"}</span>
                                  <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace", minWidth: 30, textAlign: "right" }}>EID {r.hint}</span>
                                </label>
                                {blurb && <div style={{ fontSize: 9, color: th.textDim, fontFamily: "-apple-system, sans-serif", marginLeft: 22, marginTop: 1 }}>{blurb}</div>}
                              </div>
                            );
                          }
                          return rows;
                        })()}
                      </div>
                    )}

                    {(pMode === "registry" || pMode === "auto") && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                          Registry Rules ({regActive}/{REG_SUMMARIES.length})
                        </div>
                        {REG_SUMMARIES.map((r, i) => {
                          const key = `reg-${i}`;
                          const off = disabledSet.has(key);
                          return (
                            <label key={key} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", cursor: "pointer", opacity: off ? 0.45 : 1, transition: "opacity var(--m-base)" }}>
                              <input type="checkbox" checked={!off} onChange={() => toggleRule(key)} style={{ accentColor: th.accent, margin: 0, flexShrink: 0 }} />
                              <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: SEVERITY_COLORS[r.sev] + "22", color: SEVERITY_COLORS[r.sev], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{r.sev}</span>
                              <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{r.cat} — {paRuleLabel(r)}</span>
                              <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{r.hint}</span>
                            </label>
                          );
                        })}
                      </div>
                    )}

                    {(modal.customRules || []).length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Custom Rules</div>
                        {(modal.customRules || []).map((cr, i) => (
                          <div key={`custom-${i}`} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0" }}>
                            <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: SEVERITY_COLORS[cr.severity || "medium"] + "22", color: SEVERITY_COLORS[cr.severity || "medium"], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{cr.severity || "med"}</span>
                            <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: `${th.accent}22`, color: th.accent, fontWeight: 600, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase" }}>{cr.type}</span>
                            <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{cr.category || "Custom"} — {cr.name || "Custom Rule"}</span>
                            <button onClick={() => deleteCustomRule(i)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "0 4px", lineHeight: 1 }} onMouseEnter={(e) => e.currentTarget.style.color = th.danger} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>&times;</button>
                          </div>
                        ))}
                      </div>
                    )}

                    {!modal.addingRule ? (
                      <button onClick={() => setModal((p) => ({ ...p, addingRule: pMode === "registry" ? "registry" : "evtx", newRule: {} }))}
                        style={{ ...ms.bsm, marginTop: 4, display: "flex", alignItems: "center", gap: 4 }}>
                        <span style={{ fontSize: 13, lineHeight: 1 }}>+</span> Add Custom Rule
                      </button>
                    ) : (
                      <div style={{ marginTop: 8, padding: "10px 12px", background: `${th.accent}08`, border: `1px solid ${th.accent}22`, borderRadius: 8 }}>
                        <div style={{ display: "flex", gap: 6, marginBottom: 8 }}>
                          {["evtx", "registry"].map((t) => (
                            <button key={t} onClick={() => setModal((p) => ({ ...p, addingRule: t, newRule: { ...(p.newRule || {}), type: t } }))}
                              style={{ padding: "3px 10px", borderRadius: 4, border: `1px solid ${modal.addingRule === t ? th.accent : th.border}44`, background: modal.addingRule === t ? `${th.accent}15` : "transparent", color: modal.addingRule === t ? th.accent : th.textMuted, fontSize: 10, fontWeight: 600, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                              {t.toUpperCase()}
                            </button>
                          ))}
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                          <input value={(modal.newRule || {}).category || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, category: e.target.value } }))} placeholder="Category" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                          <input value={(modal.newRule || {}).name || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, name: e.target.value } }))} placeholder="Rule Name" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                          {modal.addingRule === "evtx" ? (
                            <>
                              <input value={(modal.newRule || {}).eventIds || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, eventIds: e.target.value } }))} placeholder="Event IDs (e.g. 7045,4697)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                              <input value={(modal.newRule || {}).channels || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, channels: e.target.value } }))} placeholder="Channels (e.g. system,security)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                            </>
                          ) : (
                            <>
                              <input value={(modal.newRule || {}).keyPathPattern || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, keyPathPattern: e.target.value } }))} placeholder="Key Path Pattern (regex)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                              <input value={(modal.newRule || {}).valueNameFilter || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, valueNameFilter: e.target.value } }))} placeholder="Value Name Filter (regex, optional)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                            </>
                          )}
                          <select value={(modal.newRule || {}).severity || "medium"} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, severity: e.target.value } }))}
                            style={{ ...ms.sl, fontSize: 11, padding: "4px 8px" }}>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                          </select>
                          {modal.addingRule === "evtx" && (
                            <input value={(modal.newRule || {}).payloadFilter || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, payloadFilter: e.target.value } }))} placeholder="Payload regex filter (optional)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                          )}
                        </div>
                        <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 8 }}>
                          <button onClick={() => setModal((p) => ({ ...p, addingRule: false, newRule: {} }))} style={ms.bsm}>Cancel</button>
                          <button onClick={addCustomRule} style={{ ...ms.bsm, background: th.primaryBtn, color: "#fff", border: "none" }}>Add Rule</button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Loading phase */}
          {phase === "loading" && (() => {
            const prog = modal.progress || 0;
            const pi = modal.phaseIdx || 0;
            const plabels = ["Querying database...", "Scanning for persistence mechanisms...", "Scoring risk levels...", "Complete"];
            return (
              <div style={{ padding: "50px 40px 40px", textAlign: "center" }}>
                <style>{`@keyframes paPulse{0%,100%{opacity:.35}50%{opacity:1}}`}</style>
                <div style={{ marginBottom: 22 }}>
                  <svg width="36" height="36" viewBox="0 0 24 24" fill={(th.danger)+"22"} stroke={th.danger} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ animation: "paPulse 1.5s ease-in-out infinite" }}>
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/>
                  </svg>
                </div>
                <div style={{ color: th.text, fontSize: 13, fontWeight: 500, marginBottom: 6, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.2px" }}>{plabels[pi]}</div>
                <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif", marginBottom: 24 }}>This may take a moment for large datasets</div>
                <div style={{ position: "relative", height: 4, background: th.border + "22", borderRadius: 2, overflow: "hidden", maxWidth: 360, margin: "0 auto 12px" }}>
                  <div style={{ position: "absolute", left: 0, top: 0, height: "100%", width: `${prog}%`, background: `linear-gradient(90deg, ${th.accent}, ${th.danger})`, borderRadius: 2, transition: "width var(--m-slow) ease-out", boxShadow: `0 0 12px ${th.accent}44` }} />
                </div>
                <div style={{ color: th.textDim, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>{Math.round(prog)}%</div>
              </div>
            );
          })()}

          {/* Results phase */}
          {phase === "results" && data && (
            <div>
              {/* Collection scan provenance — what was read off disk, and what was found
                  but left unread. Coverage is stated, never implied. */}
              {data.collectionScan && data.collection && (
                <div style={{ padding: "7px 10px", background: `${th.accent}0d`, border: `1px solid ${th.accent}26`, borderRadius: 8, marginBottom: 10, fontFamily: "-apple-system, sans-serif" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.06em" }}>Collection</span>
                    <span style={{ fontSize: 10, color: th.textDim }}>
                      {data.collection.host || "unknown host"}
                      {data.collection.hostSource && data.collection.hostSource !== "user" && <span style={{ color: th.textMuted }}> ({data.collection.hostSource.replace(/-/g, " ")})</span>}
                      {" · "}{(data.stats?.taskDefinitionsRead || 0).toLocaleString()} task definitions read
                      {data.stats?.registryRowsRead > 0 && <> · {data.stats.registryRowsRead.toLocaleString()} registry rows</>}
                    </span>
                  </div>
                  <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", marginTop: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {data.collection.root}
                  </div>
                </div>
              )}

              {/* Merge provenance — which tabs contributed, and how many findings only
                  exist because more than one of them was in scope. */}
              {data.multiSource && (data.tabSummaries || []).length > 0 && (
                <div style={{ padding: "7px 10px", background: `${th.accent}0d`, border: `1px solid ${th.accent}26`, borderRadius: 8, marginBottom: 10, fontFamily: "-apple-system, sans-serif" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.06em" }}>Merged</span>
                    <span style={{ fontSize: 10, color: th.textDim }}>
                      {(data.stats?.totalMergedRows || 0).toLocaleString()} rows from {data.stats?.tabCount || 0} tabs
                      {data.stats?.crossSourceIncidents > 0 && <> · <b style={{ color: th.accent }}>{data.stats.crossSourceIncidents}</b> alert{data.stats.crossSourceIncidents === 1 ? "" : "s"} corroborated across sources</>}
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 5 }}>
                    {data.tabSummaries.map((t) => (
                      <span key={t.tabId} title={t.error || t.format || ""}
                        style={{ fontSize: 9, padding: "2px 7px", borderRadius: 5, fontFamily: "'SF Mono',Menlo,monospace",
                          background: t.skipped ? `${th.border}22` : `${th.accent}12`,
                          color: t.skipped ? th.textMuted : th.textDim,
                          border: `1px solid ${t.skipped ? th.border + "22" : th.accent + "22"}`,
                          textDecoration: t.skipped ? "line-through" : "none" }}>
                        {t.label} {!t.skipped && <span style={{ color: th.textMuted }}>({t.rowCount.toLocaleString()})</span>}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {/* Pivot attribution — persistence that can be tied to the remote session
                  that planted it. The headline answer for a triage package: this host was
                  reached AND kept. */}
              {data.stats?.remoteOriginItems > 0 && (() => {
                const attributed = (data.incidents || []).filter((i) => i.remoteOrigin);
                const sources = [...new Set(attributed.map((i) => i.remoteOrigin.sourceHost || i.remoteOrigin.sourceIp).filter(Boolean))];
                return (
                  <div style={{ padding: "7px 10px", background: `${th.sev.high}12`, border: `1px solid ${th.sev.high}33`, borderRadius: 8, marginBottom: 10, fontFamily: "-apple-system, sans-serif" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: th.sev.high, textTransform: "uppercase", letterSpacing: "0.06em" }}>Remotely planted</span>
                      <span style={{ fontSize: 10, color: th.textDim }}>
                        <b style={{ color: th.text }}>{attributed.length || data.stats.remoteOriginItems}</b> finding{(attributed.length || data.stats.remoteOriginItems) === 1 ? "" : "s"} tied to an inbound session
                        {sources.length > 0 && <> from <b style={{ color: th.text }}>{sources.slice(0, 4).join(", ")}</b>{sources.length > 4 ? ` +${sources.length - 4}` : ""}</>}
                      </span>
                    </div>
                    <div style={{ fontSize: 9, color: th.textMuted, marginTop: 3 }}>
                      Each carries the source host, IP and logon session id — the join key into the lateral-movement graph.
                    </div>
                  </div>
                );
              })()}
              {(data.warnings || []).length > 0 && <div style={{ padding: "6px 10px", background: (th.warning) + "12", border: `1px solid ${(th.warning)}30`, borderRadius: 6, color: th.warning, fontSize: 10, marginBottom: 10, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>
                <span style={{ fontWeight: 600 }}>Data quality:</span> {data.warnings.map((w, i) => <span key={i}>{i > 0 && " | "}{w}</span>)}
              </div>}
              {/* Stats cards — uniform glass */}
              <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
                {(modal.paFindingsView === "alerts" && viewTab === "grouped" ? [
                  { val: data.stats.incidentCount || 0, label: "incidents" },
                  { val: data.stats.byIncidentSeverity?.critical || 0, label: "critical" },
                  { val: data.stats.byIncidentSeverity?.high || 0, label: "high" },
                  { val: data.stats.suspiciousIncidents || 0, label: "suspicious", danger: true },
                  { val: data.stats.categoriesFound || 0, label: "categories" },
                ] : [
                  { val: data.stats.total, label: "total found" },
                  { val: data.stats.bySeverity?.critical || 0, label: "critical" },
                  { val: data.stats.bySeverity?.high || 0, label: "high" },
                  { val: data.stats.suspicious || 0, label: "suspicious", danger: true },
                  { val: data.stats.categoriesFound || 0, label: "categories" },
                ]).map((c, i) => (
                  <div key={i}
                    onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.borderColor = th.accent + "44"; }}
                    onMouseLeave={(e) => { e.currentTarget.style.transform = "none"; e.currentTarget.style.borderColor = th.border + "33"; }}
                    style={{ flex: 1, textAlign: "center", padding: "10px 6px 8px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 10, border: `1px solid ${th.border}33`, transition: "transform var(--m-base), border-color var(--m-base)" }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color: c.danger && c.val > 0 ? (th.danger) : th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.5px", lineHeight: 1 }}><CountUp value={c.val} /></div>
                    <div style={{ fontSize: 9, color: c.danger && c.val > 0 ? (th.danger) + "bb" : th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 500 }}>{c.label}</div>
                  </div>
                ))}
              </div>

              {/* Severity distribution bar + top categories (clickable to filter) */}
              {(() => {
                const useInc = modal.paFindingsView === "alerts" && viewTab === "grouped";
                const sevCounts = (useInc ? data.stats.byIncidentSeverity : data.stats.bySeverity) || {};
                const order = ["critical", "high", "medium", "low"];
                const totalSev = order.reduce((s, k) => s + (sevCounts[k] || 0), 0);
                const cats = Object.entries(data.stats.byCategory || {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
                if (totalSev === 0 && cats.length === 0) return null;
                return (
                  <div style={{ marginBottom: 14 }}>
                    {totalSev > 0 && (
                      <>
                        <div style={{ display: "flex", height: 8, borderRadius: 4, overflow: "hidden", background: th.border + "22" }}>
                          {order.map((k) => {
                            const v = sevCounts[k] || 0;
                            if (v === 0) return null;
                            return <div key={k} title={`${v} ${k}`} style={{ width: `${(v / totalSev) * 100}%`, background: SEVERITY_COLORS[k], transition: "width var(--m-base)" }} />;
                          })}
                        </div>
                        <div style={{ display: "flex", gap: 12, marginTop: 5, flexWrap: "wrap" }}>
                          {order.filter((k) => (sevCounts[k] || 0) > 0).map((k) => (
                            <span key={k} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", textTransform: "capitalize" }}>
                              <span style={{ width: 7, height: 7, borderRadius: 2, background: SEVERITY_COLORS[k] }} />
                              {k} <span style={{ color: th.text, fontWeight: 600, fontFamily: "SF Mono, monospace" }}>{sevCounts[k]}</span>
                            </span>
                          ))}
                        </div>
                      </>
                    )}
                    {cats.length > 0 && (
                      <div style={{ display: "flex", gap: 5, marginTop: 9, flexWrap: "wrap", alignItems: "center" }}>
                        <span style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Top</span>
                        {cats.map(([cat, cnt]) => {
                          const sel = categoryFilter === cat;
                          return (
                            <button key={cat} onClick={() => setModal((p) => ({ ...p, categoryFilter: sel ? "all" : cat }))}
                              style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: "2px 8px", borderRadius: 6, border: `1px solid ${sel ? th.accent : th.border + "33"}`, background: sel ? th.accent + "18" : `${th.panelBg}66`, color: sel ? th.accent : th.text, fontSize: 10, fontWeight: 500, cursor: "pointer", fontFamily: "-apple-system, sans-serif", transition: "all var(--m-base)" }}>
                              {cat} <span style={{ fontSize: 9, color: sel ? th.accent : th.textMuted, fontFamily: "SF Mono, monospace" }}>{cnt}</span>
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Filter bar */}
              <div style={{ display: "flex", gap: 8, marginBottom: 12, alignItems: "center" }}>
                <input type="text" placeholder="Search results..." value={searchText} onChange={(e) => setModal((p) => ({ ...p, searchText: e.target.value }))}
                  style={{ ...ms.si, flex: 1, fontSize: 11, padding: "5px 10px" }} />
                <select value={severityFilter} onChange={(e) => setModal((p) => ({ ...p, severityFilter: e.target.value }))}
                  style={{ ...ms.sl, fontSize: 11, padding: "5px 8px", minWidth: 90 }}>
                  <option value="all">All Severity</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <select value={categoryFilter} onChange={(e) => setModal((p) => ({ ...p, categoryFilter: e.target.value }))}
                  style={{ ...ms.sl, fontSize: 11, padding: "5px 8px", minWidth: 120 }}>
                  <option value="all">All Categories</option>
                  {allCategories.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>

              {/* View tabs */}
              <div style={{ display: "flex", gap: 8, marginBottom: 14, alignItems: "center" }}>
                <div style={{ display: "flex", gap: 0, background: th.border + "22", borderRadius: 8, padding: 2, width: "fit-content" }}>
                  {["grouped", "timeline", "table"].map((tab) => (
                    <button key={tab} onClick={() => setModal((p) => ({ ...p, viewTab: tab }))}
                      style={{ padding: "5px 16px", fontSize: 11, fontWeight: viewTab === tab ? 600 : 400, fontFamily: "-apple-system, sans-serif", background: viewTab === tab ? th.accent + "20" : "transparent", color: viewTab === tab ? th.accent : th.textMuted, border: "none", borderRadius: 6, cursor: "pointer", textTransform: "capitalize", transition: "all var(--m-base)" }}>{tab}</button>
                  ))}
                </div>
                <div style={{ display: "flex", gap: 4, marginLeft: "auto", alignItems: "center" }}>
                  <button title={paShowingIncidents ? `Select the ${paSelectableItems.length.toLocaleString()} events behind these alerts` : "Select every listed item"}
                    onClick={() => {
                    setModal((p) => {
                      const s = new Set(p.checkedItems || []);
                      paSelectableItems.forEach((i) => s.add(persistItemKey(i)));
                      return { ...p, checkedItems: s };
                    });
                  }} style={{ padding: "3px 8px", fontSize: 10, background: "transparent", color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Select All ({paVisibleRows.length})</button>
                  {checkedItems.size > 0 && <button onClick={() => setModal((p) => ({ ...p, checkedItems: new Set() }))} style={{ padding: "3px 8px", fontSize: 10, background: "transparent", color: th.textMuted, border: `1px solid ${th.border}`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Clear ({checkedItems.size})</button>}
                <div style={{ width: 1, height: 14, background: th.border + "55", margin: "0 2px" }} />
                <button onClick={() => {
                  _downloadFile(
                    _toCSV(paVisibleRows.map(paExportRow)),
                    paShowingIncidents ? "persistence-alerts.csv" : "persistence-items.csv",
                    "text/csv",
                  );
                }} style={{ padding: "3px 8px", fontSize: 10, background: "transparent", color: th.textMuted, border: `1px solid ${th.border}`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}
                  title={`Export the ${paVisibleRows.length.toLocaleString()} ${paShowingIncidents ? "alerts" : "items"} currently listed as CSV`}>↓ CSV</button>
                <button onClick={() => {
                  const payload = { exportedAt: new Date().toISOString(), stats: data.stats, incidents: data.incidents || [], items: data.items || [] };
                  _downloadFile(JSON.stringify(payload, null, 2), "persistence-findings.json", "application/json");
                }} style={{ padding: "3px 8px", fontSize: 10, background: "transparent", color: th.textMuted, border: `1px solid ${th.border}`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }} title="Export all findings as JSON">↓ JSON</button>
                </div>
              </div>

              {paVisibleRows.length === 0 && (
                <div style={{ textAlign: "center", padding: "40px 20px", color: th.textMuted, fontSize: 13, fontFamily: "-apple-system, sans-serif" }}>
                  No persistence mechanisms found{searchText || severityFilter !== "all" || categoryFilter !== "all" ? " matching filters" : ""}
                </div>
              )}

              {/* Grouped view — incident-clustered */}
              {viewTab === "grouped" && (() => {
                const _renderIncCard = (inc) => {
                  const isExp = expandedIncident === inc.id;
                  const pills = inc.evidencePills || [];
                  return (
                    <div key={inc.id} style={{ borderRadius: 6, border: `1px solid ${SEVERITY_COLORS[inc.severity]}${isExp ? "44" : "22"}`, background: `${SEVERITY_COLORS[inc.severity]}${isExp ? "0a" : "04"}`, cursor: "pointer", transition: "border-color var(--m-base)", marginBottom: 3 }}
                      onClick={() => setModal((p) => ({ ...p, expandedIncident: isExp ? null : inc.id }))}
                      onMouseEnter={(e) => { if (!isExp) e.currentTarget.style.borderColor = SEVERITY_COLORS[inc.severity] + "44"; }}
                      onMouseLeave={(e) => { if (!isExp) e.currentTarget.style.borderColor = SEVERITY_COLORS[inc.severity] + "22"; }}>
                      {/* Collapsed row */}
                      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 10px", minHeight: 28 }}>
                        <span style={{ padding: "1px 6px", background: SEVERITY_COLORS[inc.severity] + "22", color: SEVERITY_COLORS[inc.severity], borderRadius: 3, fontSize: 8, fontWeight: 700, textTransform: "uppercase", fontFamily: "-apple-system, sans-serif", letterSpacing: "0.03em", flexShrink: 0 }}>{inc.severity}</span>
                        <span style={{ fontFamily: "monospace", fontSize: 9, color: th.accent, background: `${th.accent}15`, padding: "1px 4px", borderRadius: 3, fontWeight: 600, flexShrink: 0, minWidth: 20, textAlign: "center" }}>{inc.triageScore}</span>
                        <PaMitreBadge category={inc.category} />
                        <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inc.title}</span>
                        {inc.computer && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{inc.computer}</span>}
                        {inc.occurrenceCount > 1 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontWeight: 500, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{inc.occurrenceCount}x</span>}
                        {pills.slice(0, 3).map((p, i) => (
                          <span key={i} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: (PA_PILL_COLORS[p.type] || th.sev.low) + "18", color: PA_PILL_COLORS[p.type] || th.sev.low, fontWeight: 500, fontFamily: "-apple-system, sans-serif", flexShrink: 0, whiteSpace: "nowrap" }}>{p.text}</span>
                        ))}
                        {inc.rmmTool && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.high + "22", color: th.sev.high, fontWeight: 700, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", flexShrink: 0 }}>RMM</span>}
                      </div>
                      {/* Expanded detail */}
                      {isExp && (
                        <div style={{ padding: "8px 10px 10px", borderTop: `1px solid ${SEVERITY_COLORS[inc.severity]}22` }} onClick={(e) => e.stopPropagation()}>
                          {/* Artifact + Command */}
                          {(inc.artifact || inc.command) && (
                            <div style={{ marginBottom: 6, display: "flex", flexDirection: "column", gap: 2 }}>
                              {inc.artifact && <div style={{ fontSize: 10, fontFamily: "SF Mono, Menlo, monospace" }}><span style={{ color: th.accent, fontWeight: 600 }}>artifact: </span><span style={{ color: inc.isSuspicious ? (th.danger) : th.text, fontWeight: inc.isSuspicious ? 600 : 400 }}>{inc.artifact}</span></div>}
                              {inc.command && <div style={{ fontSize: 10, fontFamily: "SF Mono, Menlo, monospace" }}><span style={{ color: th.accent, fontWeight: 600 }}>command: </span><span style={{ color: th.textMuted }}>{inc.command}</span></div>}
                            </div>
                          )}
                          {/* Time range + host + user */}
                          <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "monospace", marginBottom: 6 }}>
                            {inc.computer}{inc.user ? ` (${inc.user})` : ""}
                            <span style={{ marginLeft: 12 }}>{(inc.firstSeen || "").slice(0, 19)}{inc.lastSeen && inc.lastSeen !== inc.firstSeen ? ` \u2014 ${inc.lastSeen.slice(0, 19)}` : ""}</span>
                            <span style={{ marginLeft: 12 }}>{inc.occurrenceCount} occurrence{inc.occurrenceCount !== 1 ? "s" : ""}</span>
                          </div>
                          {/* Suspicious reasons */}
                          {inc.suspiciousReasons.length > 0 && (
                            <div style={{ marginBottom: 6, display: "flex", gap: 4, flexWrap: "wrap" }}>
                              {inc.suspiciousReasons.map((r, i) => (
                                <span key={i} style={{ fontSize: 9, padding: "2px 7px", borderRadius: 4, background: `${th.danger}15`, color: th.danger, fontWeight: 500, fontFamily: "-apple-system, sans-serif" }}>{r}</span>
                              ))}
                            </div>
                          )}
                          {/* All evidence pills */}
                          {pills.length > 0 && (
                            <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 8 }}>
                              {pills.map((p, i) => (
                                <span key={i} style={{ fontSize: 9, padding: "2px 7px", borderRadius: 4, background: (PA_PILL_COLORS[p.type] || th.sev.low) + "18", color: PA_PILL_COLORS[p.type] || th.sev.low, fontWeight: 500, fontFamily: "-apple-system, sans-serif" }}>{p.text}</span>
                              ))}
                            </div>
                          )}
                          {/* All occurrences when multiple */}
                          {inc.occurrenceCount > 1 && (
                            <div style={{ marginBottom: 8 }}>
                              <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.04em" }}>All Occurrences</div>
                              <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 120, overflowY: "auto" }}>
                                {inc.items.slice(0, 50).map((it, i) => (
                                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 9, fontFamily: "SF Mono, Menlo, monospace", color: th.textDim, padding: "2px 4px", borderRadius: 3, background: i % 2 === 0 ? "transparent" : `${th.border}11` }}>
                                    <span style={{ color: th.textMuted, minWidth: 130 }}>{(it.timestamp || "").slice(0, 19)}</span>
                                    <span style={{ color: SEVERITY_COLORS[it.severity], fontWeight: 600, textTransform: "uppercase", fontSize: 8, minWidth: 45 }}>{it.severity}</span>
                                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{it.detailsSummary}</span>
                                    <span style={{ color: th.accent, flexShrink: 0 }}>{it.riskScore}/10</span>
                                  </div>
                                ))}
                                {inc.items.length > 50 && <div style={{ fontSize: 9, color: th.textMuted, fontStyle: "italic", padding: "2px 4px" }}>...and {inc.items.length - 50} more</div>}
                              </div>
                            </div>
                          )}
                          {/* Raw fields */}
                          {inc.details && Object.keys(inc.details).length > 0 && (
                            <div style={{ marginBottom: 8 }}>
                              <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.04em" }}>Raw Fields</div>
                              <div style={{ display: "flex", flexWrap: "wrap", gap: "2px 12px" }}>
                                {Object.entries(inc.details).filter(([k]) => !k.startsWith("_")).map(([k, v]) => v ? (
                                  <div key={k} style={{ fontSize: 9, fontFamily: "SF Mono, Menlo, monospace" }}>
                                    <span style={{ color: th.accent + "aa", fontWeight: 500 }}>{k}: </span>
                                    <span style={{ color: th.textDim }}>{String(v).substring(0, 200)}</span>
                                  </div>
                                ) : null)}
                              </div>
                            </div>
                          )}
                          {/* Pivot buttons */}
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                            <button onClick={(e) => _paFilterArtifact(inc, e)} style={_paBtnS}>Filter Artifact</button>
                            {inc.computer && <button onClick={(e) => _paFilterHost(inc, e)} style={_paBtnS}>Filter Host</button>}
                            <button onClick={(e) => _paFilterRelated(inc, e)} style={_paBtnS}>Filter Related</button>
                            <button onClick={(e) => _paOpenInTimeline(inc, e)} style={_paBtnS}>Open in Timeline</button>
                            <button onClick={(e) => _paCopyIOC(inc, e)} style={_paBtnS}>Copy IOC</button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                };
                return (
                  <div>
                    {/* Toolbar row */}
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
                      <button onClick={() => setModal((p) => ({ ...p, paFindingsView: "alerts" }))} style={_paBtnActive(paFindingsView === "alerts")}>Alerts ({sortedIncidents.length})</button>
                      <button onClick={() => setModal((p) => ({ ...p, paFindingsView: "items" }))} style={_paBtnActive(paFindingsView === "items")}>Items ({filteredItems.length})</button>
                      <span style={{ width: 1, height: 16, background: th.border, margin: "0 4px" }} />
                      <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Sort:</span>
                      <select value={paSortBy} onChange={(e) => setModal((p) => ({ ...p, paSortBy: e.target.value }))} style={{ fontSize: 9, padding: "2px 4px", background: th.bg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 3, fontFamily: "-apple-system, sans-serif" }}>
                        <option value="triage">Priority</option>
                        <option value="severity">Severity</option>
                        <option value="recency">Recency</option>
                        <option value="events">Events</option>
                      </select>
                      {paFindingsView === "alerts" && <>
                        <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Group:</span>
                        <select value={paGroupBy} onChange={(e) => setModal((p) => ({ ...p, paGroupBy: e.target.value }))} style={{ fontSize: 9, padding: "2px 4px", background: th.bg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 3, fontFamily: "-apple-system, sans-serif" }}>
                          <option value="incident">By Incident</option>
                          <option value="host">By Host</option>
                          <option value="technique">By Technique</option>
                          <option value="artifact">By Artifact</option>
                        </select>
                      </>}
                      <span style={{ width: 1, height: 16, background: th.border, margin: "0 4px" }} />
                      {Object.entries((paFindingsView === "alerts" ? data.stats.byIncidentSeverity : data.stats.bySeverity) || {}).filter(([, v]) => v > 0).map(([sev, cnt]) => (
                        <span key={sev} style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 7px", background: SEVERITY_COLORS[sev] + "15", color: SEVERITY_COLORS[sev], borderRadius: 4, fontSize: 9, fontWeight: 600, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase" }}>
                          {cnt} {sev}
                        </span>
                      ))}
                    </div>

                    {/* Alerts view — incident cards */}
                    {paFindingsView === "alerts" && (
                      <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                        {paGroupedEntries ? paGroupedEntries.map(([gKey, gIncs]) => (
                          <div key={gKey}>
                            <div style={{ fontSize: 10, fontWeight: 600, color: th.textDim, padding: "6px 0 4px", fontFamily: "-apple-system, sans-serif", borderBottom: `1px solid ${th.border}`, marginBottom: 4 }}>
                              {gKey} <span style={{ fontWeight: 400, color: th.textMuted }}>({gIncs.length} incidents) | Top score: {Math.max(...gIncs.map(i => i.triageScore || 0))}</span>
                            </div>
                            {gIncs.map(inc => _renderIncCard(inc))}
                          </div>
                        )) : sortedIncidents.map(inc => _renderIncCard(inc))}
                        {sortedIncidents.length === 0 && <div style={{ fontSize: 11, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: 20, textAlign: "center" }}>No persistence incidents found matching filters.</div>}
                      </div>
                    )}

                    {/* Items view — flat fallback */}
                    {paFindingsView === "items" && (
                      <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                        {filteredItems.slice(0, modal._itemsLimit || 500).map((item, idx) => (
                          <div key={idx} style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 10px", borderRadius: 4, border: `1px solid ${SEVERITY_COLORS[item.severity]}22`, background: `${SEVERITY_COLORS[item.severity]}04`, cursor: "pointer" }}
                            onClick={() => _paOpenInTimeline({ ...item, firstSeen: item.timestamp, lastSeen: item.timestamp, mode: item.mode, source: item.source, artifact: item.artifact, computer: item.computer })}>
                            <span style={{ padding: "1px 5px", background: SEVERITY_COLORS[item.severity] + "22", color: SEVERITY_COLORS[item.severity], borderRadius: 3, fontSize: 8, fontWeight: 700, textTransform: "uppercase", flexShrink: 0 }}>{item.severity}</span>
                            <span style={{ fontFamily: "monospace", fontSize: 9, color: th.accent, background: `${th.accent}15`, padding: "1px 4px", borderRadius: 3, fontWeight: 600, flexShrink: 0 }}>{item.riskScore}</span>
                            <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 500, fontSize: 10, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{item.name}</span>
                            <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "monospace", flexShrink: 0 }}>{(item.timestamp || "").slice(0, 19)}</span>
                            {item.computer && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, flexShrink: 0, fontFamily: "-apple-system, sans-serif" }}>{item.computer}</span>}
                            {(item.evidencePills || []).slice(0, 2).map((p, i) => (
                              <span key={i} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: (PA_PILL_COLORS[p.type] || th.sev.low) + "18", color: PA_PILL_COLORS[p.type] || th.sev.low, fontWeight: 500, flexShrink: 0, whiteSpace: "nowrap", fontFamily: "-apple-system, sans-serif" }}>{p.text}</span>
                            ))}
                          </div>
                        ))}
                        {filteredItems.length > (modal._itemsLimit || 500) && <div style={{ fontSize: 10, color: th.textMuted, padding: 6, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 8 }}>
                          <span style={{ fontStyle: "italic" }}>Showing {modal._itemsLimit || 500} of {filteredItems.length}</span>
                          <button onClick={() => setModal(p => ({ ...p, _itemsLimit: (p._itemsLimit || 500) + 500 }))} style={{ padding: "2px 10px", fontSize: 9, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 3, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Load more</button>
                        </div>}
                        {filteredItems.length === 0 && <div style={{ fontSize: 11, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: 20, textAlign: "center" }}>No items found matching filters.</div>}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Timeline view */}
              {viewTab === "timeline" && (() => {
                const tlCols = [
                  { key: "timestamp", label: "Timestamp", dw: 155 },
                  { key: "severity", label: "Sev", dw: 55 },
                  { key: "riskScore", label: "Risk", dw: 45 },
                  { key: "name", label: "Detection", dw: 160 },
                  { key: "artifact", label: "Artifact", dw: 220 },
                  { key: "evidence", label: "Evidence", dw: 180 },
                  { key: "command", label: "Command/Path", dw: 400 },
                ];
                const tlWidths = modal.tlColWidths || {};
                const gtlw = (k) => tlWidths[k] || tlCols.find((c) => c.key === k)?.dw || 120;
                const onTlResize = (colKey, e) => {
                  e.preventDefault(); e.stopPropagation();
                  const startX = e.clientX, startW = gtlw(colKey);
                  document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                  const onMove = (ev) => setModal((p) => ({ ...p, tlColWidths: { ...(p.tlColWidths || {}), [colKey]: Math.max(50, startW + ev.clientX - startX) } }));
                  const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                  window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                };
                // --- Analyst modes ---
                const TL_MODES = {
                  triage:     { label: "Triage",     sort: "riskScore", dir: "desc", filter: "suspicious", desc: "Suspicious only, risk-sorted" },
                  hunt:       { label: "Hunt",       sort: "riskScore", dir: "desc", filter: "medium+",    desc: "Medium+ severity, risk-sorted" },
                  chronology: { label: "Chronology", sort: "timestamp", dir: "asc",  filter: "all",        desc: "All items, time-sorted" },
                };
                const tlMode = modal.tlMode || "triage";
                const activeMode = TL_MODES[tlMode];
                const tlSortCol = activeMode ? activeMode.sort : (modal.tlSortCol || "riskScore");
                const tlSortDir = activeMode ? activeMode.dir : (modal.tlSortDir || "desc");
                const toggleTlSort = (col) => setModal((p) => ({ ...p, tlMode: "custom", tlSortCol: col, tlSortDir: p.tlSortCol === col && p.tlSortDir === "asc" ? "desc" : "asc" }));
                const tlCatFilter = modal.tlCatFilter; // Set of category names or null
                // Column filters (shared tableColFilters state)
                const colFilters = modal.tableColFilters || {};
                // Mode + category filtering pipeline
                const modeFilter = activeMode?.filter || "all";
                const suspOnly = modeFilter === "suspicious" || (tlMode === "custom" && modal._tlSuspOnly);
                // Pre-category filter (for faceted category pill counts)
                const tlPreCat = filteredItems.filter((item) => {
                  if (suspOnly && !item.isSuspicious) return false;
                  if (modeFilter === "medium+" && item.severity === "low") return false;
                  for (const [col, allowed] of Object.entries(colFilters)) {
                    if (!allowed || allowed.length === 0) continue;
                    if (!allowed.includes(String(item[col] ?? ""))) return false;
                  }
                  return true;
                });
                // Final filter with category applied
                const tlFiltered = tlCatFilter && tlCatFilter.size > 0
                  ? tlPreCat.filter(item => tlCatFilter.has(item.category))
                  : tlPreCat;
                const sorted = [...tlFiltered].sort((a, b) => {
                  const _sc = tlSortCol === "riskScore" ? "triageScore" : tlSortCol;
                  const av = a[_sc] ?? "", bv = b[_sc] ?? "";
                  const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                  return tlSortDir === "desc" ? -cmp : cmp;
                });
                // --- Streak collapsing: group consecutive low-risk same-artifact items ---
                const displayRows = [];
                let streakBuf = [];
                const flushStreak = () => {
                  if (streakBuf.length >= 3) {
                    displayRows.push({ _streak: true, items: streakBuf, rep: streakBuf[0], count: streakBuf.length });
                  } else {
                    for (const it of streakBuf) displayRows.push(it);
                  }
                  streakBuf = [];
                };
                const streakKey = (it) => `${it.artifact}|${it.computer}|${it.category}`;
                const _tlLimit = modal._tlLimit || 600;
                for (const item of sorted.slice(0, _tlLimit)) {
                  const isLowRisk = !item.isSuspicious && (item.riskScore || 0) <= 3;
                  if (isLowRisk && streakBuf.length > 0 && streakKey(item) === streakKey(streakBuf[0])) {
                    streakBuf.push(item);
                  } else {
                    if (streakBuf.length > 0) flushStreak();
                    if (isLowRisk) streakBuf = [item];
                    else displayRows.push(item);
                  }
                }
                if (streakBuf.length > 0) flushStreak();
                // --- Banner summary (from visible tlFiltered) ---
                const suspCount = tlFiltered.filter(i => i.isSuspicious).length;
                const suspHosts = new Set(tlFiltered.filter(i => i.isSuspicious).map(i => i.computer).filter(Boolean)).size;
                const bannerCatCounts = {};
                for (const i of tlFiltered) bannerCatCounts[i.category] = (bannerCatCounts[i.category] || 0) + 1;
                const topCats = Object.entries(bannerCatCounts).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([c]) => c);
                const pillCounts = {};
                for (const i of tlFiltered) for (const p of (i.evidencePills || [])) { if (p.type === "execution" || p.type === "correlation") pillCounts[p.text] = (pillCounts[p.text] || 0) + 1; }
                const topPills = Object.entries(pillCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);
                // --- Category pill counts (faceted: pre-category filter so toggled-off categories still show counts) ---
                const catCounts = {};
                for (const i of tlPreCat) catCounts[i.category] = (catCounts[i.category] || 0) + 1;
                // --- Category pills ---
                const allCatKeys = Object.keys(data?.stats?.byCategory || {}).sort();
                const openTlFilter = (colKey, e) => {
                  e.stopPropagation();
                  const rect = e.currentTarget.getBoundingClientRect();
                  const counts = {};
                  for (const item of filteredItems) { const v = String(item[colKey] ?? ""); counts[v] = (counts[v] || 0) + 1; }
                  const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
                  const current = colFilters[colKey];
                  const selected = new Set(current && current.length > 0 ? current : allVals);
                  setModal((p) => ({ ...p, colFilterOpen: colKey, colFilterPos: { x: rect.left, y: rect.bottom + 2 }, colFilterVals: allVals, colFilterCounts: counts, colFilterSel: selected, colFilterSearch: "", colFilterX: null, colFilterY: null }));
                };
                const filterOpen = modal.colFilterOpen;
                const filterPos = modal.colFilterPos || {};
                const filterVals = modal.colFilterVals || [];
                const filterCounts = modal.colFilterCounts || {};
                const filterSel = modal.colFilterSel || new Set();
                const filterSearch = modal.colFilterSearch || "";
                const displayVals = filterSearch ? filterVals.filter((v) => v.toLowerCase().includes(filterSearch.toLowerCase())) : filterVals;
                const tlTotalW = 20 + 26 + tlCols.reduce((s, c) => s + gtlw(c.key), 0) + tlCols.length * 8;
                const activeFilterCount = Object.values(colFilters).filter((v) => v && v.length > 0).length;
                return (
                <div style={{ position: "relative", paddingLeft: 20 }}>
                  <div style={{ position: "absolute", left: 6, top: 0, bottom: 0, width: 2, background: th.border + "33" }} />
                  {/* Mode toolbar */}
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6, flexWrap: "wrap" }}>
                    {Object.entries(TL_MODES).map(([k, m]) => (
                      <button key={k} onClick={() => setModal((p) => ({ ...p, tlMode: k }))} title={m.desc}
                        style={{ padding: "3px 10px", fontSize: 10, fontWeight: tlMode === k ? 700 : 500, background: tlMode === k ? th.accent : `${th.accent}15`, color: tlMode === k ? "#fff" : th.accent, border: `1px solid ${tlMode === k ? th.accent : th.accent + "33"}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>{m.label}</button>
                    ))}
                    {tlMode === "custom" && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", fontStyle: "italic" }}>Custom sort/filter</span>}
                    <span style={{ width: 1, height: 16, background: th.border, margin: "0 2px" }} />
                    <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", cursor: "pointer" }}>
                      <input type="checkbox" checked={suspOnly} onChange={(e) => {
                        if (e.target.checked) setModal((p) => ({ ...p, tlMode: "custom", _tlSuspOnly: true }));
                        else setModal((p) => ({ ...p, _tlSuspOnly: false, tlMode: p.tlMode === "custom" ? "chronology" : p.tlMode }));
                      }} style={{ width: 12, height: 12, accentColor: th.accent }} />
                      Suspicious Only
                    </label>
                    {/* Banner summary */}
                    {suspCount > 0 && <span style={{ marginLeft: "auto", fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                      <span style={{ color: th.danger, fontWeight: 600 }}>{suspCount} suspicious</span> across {suspHosts} host{suspHosts !== 1 ? "s" : ""}
                      {topCats.length > 0 && <> | Top: {topCats.join(", ")}</>}
                      {topPills.length > 0 && <> | {topPills.map(([t, c]) => `${c} ${t}`).join(", ")}</>}
                    </span>}
                  </div>
                  {/* Category quick-filter pills */}
                  {allCatKeys.length > 1 && (
                    <div style={{ display: "flex", gap: 4, marginBottom: 6, flexWrap: "wrap" }}>
                      {allCatKeys.map((cat) => {
                        const active = !tlCatFilter || tlCatFilter.has(cat);
                        return (
                          <button key={cat} onClick={() => setModal((p) => {
                            const cur = p.tlCatFilter ? new Set(p.tlCatFilter) : new Set(allCatKeys);
                            if (cur.has(cat)) cur.delete(cat); else cur.add(cat);
                            return { ...p, tlCatFilter: cur.size === allCatKeys.length ? null : cur };
                          })} style={{ padding: "2px 7px", fontSize: 9, background: active ? `${th.accent}18` : "transparent", color: active ? th.accent : th.textMuted + "66", border: `1px solid ${active ? th.accent + "33" : th.border + "22"}`, borderRadius: 3, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: active ? 600 : 400 }}>
                            {cat} ({catCounts[cat] || 0})
                          </button>
                        );
                      })}
                      {tlCatFilter && <button onClick={() => setModal((p) => ({ ...p, tlCatFilter: null }))} style={{ padding: "2px 7px", fontSize: 9, background: "transparent", color: th.textMuted, border: `1px solid ${th.border}22`, borderRadius: 3, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Reset</button>}
                    </div>
                  )}
                  {/* Active filter indicator */}
                  {activeFilterCount > 0 && (
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", marginBottom: 6, background: `${th.accent}11`, borderRadius: 6, fontSize: 10, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
                      <span style={{ fontWeight: 600 }}>Filter active ({activeFilterCount} column{activeFilterCount > 1 ? "s" : ""})</span>
                      <span style={{ fontSize: 10, color: th.textMuted }}>— {tlFiltered.length} of {filteredItems.length} items</span>
                      <button onClick={() => setModal((p) => ({ ...p, tableColFilters: {} }))} style={{ marginLeft: "auto", padding: "1px 8px", fontSize: 9, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}>Clear All</button>
                    </div>
                  )}
                  {/* Header */}
                  <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", borderBottom: `1px solid ${th.border}`, marginBottom: 2, position: "sticky", top: 0, zIndex: 2, background: th.modalBg, minWidth: tlTotalW }}>
                    <input type="checkbox" checked={sorted.length > 0 && sorted.slice(0, modal._tlRowLimit || 500).every((i) => isChecked(i))} onChange={() => {
                      const lim = modal._tlRowLimit || 500;
                      const visible = sorted.slice(0, lim);
                      const allChecked = visible.every((i) => isChecked(i));
                      setModal((p) => {
                        const s = new Set(p.checkedItems || []);
                        if (allChecked) { visible.forEach((i) => s.delete(persistItemKey(i))); }
                        else { visible.forEach((i) => s.add(persistItemKey(i))); }
                        return { ...p, checkedItems: s };
                      });
                    }} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent, flexShrink: 0 }} title={sorted.length > 0 && sorted.slice(0, modal._tlRowLimit || 500).every((i) => isChecked(i)) ? "Deselect all" : "Select all visible"} />
                    {tlCols.map((col) => (
                      <div key={col.key} style={{ width: gtlw(col.key), minWidth: 40, flexShrink: 0, display: "flex", alignItems: "center", position: "relative", userSelect: "none", gap: 3 }}>
                        <span onClick={() => col.key !== "evidence" && toggleTlSort(col.key)} style={{ fontSize: 10, fontWeight: 600, color: tlSortCol === col.key ? th.accent : th.textMuted, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: 0.5, cursor: col.key !== "evidence" ? "pointer" : "default", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {col.label}{tlSortCol === col.key ? (tlSortDir === "asc" ? " \u25B2" : " \u25BC") : ""}
                        </span>
                        {col.key !== "evidence" && col.key !== "riskScore" && <span style={{ cursor: "pointer", fontSize: 9, color: colFilters[col.key] ? th.accent : th.textMuted, flexShrink: 0, marginLeft: "auto", paddingRight: 8, opacity: colFilters[col.key] ? 1 : 0.5 }}
                          onClick={(e) => { e.stopPropagation(); openTlFilter(col.key, e); }}>{colFilters[col.key] ? "\u25BC" : "\u25BE"}</span>}
                        <div onMouseDown={(e) => onTlResize(col.key, e)} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 6, cursor: "col-resize" }}>
                          <div style={{ position: "absolute", right: 2, top: 2, bottom: 2, width: 1, background: th.border }} />
                        </div>
                      </div>
                    ))}
                  </div>
                  {/* Rows */}
                  {displayRows.slice(0, modal._tlRowLimit || 500).map((row, idx) => {
                    if (row._streak) {
                      const { rep, count, items: sItems } = row;
                      const expanded = modal._expandedStreak === idx;
                      return (
                        <div key={`s${idx}`}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", cursor: "pointer", background: `${th.border}08`, minWidth: tlTotalW, borderRadius: 3, marginBottom: 1 }}
                            onClick={() => setModal((p) => ({ ...p, _expandedStreak: p._expandedStreak === idx ? null : idx }))}>
                            <div style={{ position: "absolute", left: -17, width: 8, height: 8, borderRadius: 4, background: th.textMuted + "44", border: `2px solid ${th.modalBg}`, zIndex: 1 }} />
                            <span style={{ width: 13, flexShrink: 0, fontSize: 9, textAlign: "center", color: th.textMuted }}>{expanded ? "\u25BC" : "\u25B6"}</span>
                            <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                              <span style={{ fontWeight: 500 }}>{rep.artifact || rep.name}</span>
                              {rep.computer && <span> on {rep.computer}</span>}
                              <span style={{ padding: "1px 5px", marginLeft: 6, borderRadius: 3, background: `${th.border}22`, fontSize: 9, fontWeight: 600 }}>\u00D7 {count}</span>
                              <span style={{ marginLeft: 6, color: th.textMuted + "88", fontSize: 9 }}>low risk</span>
                            </span>
                          </div>
                          {expanded && sItems.map((item, si) => (
                            <div key={si} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0 3px 20px", cursor: "pointer", position: "relative", background: isSelPersist(item) ? `${th.accent}14` : "transparent", minWidth: tlTotalW, opacity: 0.7 }}
                              onClick={() => toggleSelPersist(item)}>
                              <input type="checkbox" checked={isChecked(item)} onChange={(e) => toggleCheck(item, e)} onClick={(e) => e.stopPropagation()} style={{ width: 12, height: 12, cursor: "pointer", accentColor: th.accent, flexShrink: 0 }} />
                              <span style={{ width: gtlw("timestamp"), fontSize: 9, color: th.textMuted, fontFamily: "monospace", flexShrink: 0 }}>{(item.timestamp || "").slice(0, 19)}</span>
                              <span style={{ flex: 1, fontSize: 9, color: th.textDim, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.detailsSummary || item.command || ""}</span>
                            </div>
                          ))}
                        </div>
                      );
                    }
                    const item = row;
                    const isLowRisk = !item.isSuspicious && (item.riskScore || 0) <= 3;
                    return (
                    <div key={idx} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", cursor: "pointer", position: "relative", background: isSelPersist(item) ? `${th.accent}14` : isChecked(item) ? `${th.accent}0a` : "transparent", minWidth: tlTotalW }}
                      onClick={() => toggleSelPersist(item)}
                      onMouseEnter={(e) => { if (!isSelPersist(item) && !isChecked(item)) e.currentTarget.style.background = `${th.accent}08`; }}
                      onMouseLeave={(e) => { if (!isSelPersist(item)) e.currentTarget.style.background = isChecked(item) ? `${th.accent}0a` : "transparent"; }}>
                      <div style={{ position: "absolute", left: -17, width: 8, height: 8, borderRadius: 4, background: item.isSuspicious ? (th.danger) : (SEVERITY_COLORS[item.severity] || th.textMuted), border: `2px solid ${th.modalBg}`, zIndex: 1 }} />
                      <input type="checkbox" checked={isChecked(item)} onChange={(e) => toggleCheck(item, e)} onClick={(e) => e.stopPropagation()} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent, flexShrink: 0 }} />
                      <span style={{ width: gtlw("timestamp"), minWidth: 40, fontSize: 10, color: isLowRisk ? th.textDim : th.textMuted, fontFamily: "SF Mono, Menlo, monospace", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.timestamp ? String(item.timestamp).substring(0, 19) : "\u2014"}</span>
                      <span style={{ width: gtlw("severity"), minWidth: 40, fontSize: 9, flexShrink: 0 }}>
                        <span style={{ padding: "1px 5px", borderRadius: 3, background: (SEVERITY_COLORS[item.severity] || th.textMuted) + "20", color: SEVERITY_COLORS[item.severity] || th.textMuted, fontWeight: 700, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase" }}>{item.severity.substring(0, 4)}</span>
                      </span>
                      <span style={{ width: gtlw("riskScore"), minWidth: 40, fontSize: 10, fontFamily: "monospace", fontWeight: 600, textAlign: "right", paddingRight: 6, color: (item.riskScore || 0) >= 8 ? th.sev.critical : (item.riskScore || 0) >= 6 ? th.sev.high : th.textMuted, flexShrink: 0 }}>{item.riskScore || 0}{item.confidence === "confirmed" ? <span style={{ fontSize: 6, color: th.sev.clean, marginLeft: 2 }}>●</span> : item.confidence === "likely" ? <span style={{ fontSize: 6, color: th.sev.high, marginLeft: 2 }}>●</span> : null}</span>
                      <span style={{ width: gtlw("name"), minWidth: 40, fontSize: 11, fontWeight: 500, color: isLowRisk ? th.textDim : th.text, fontFamily: "-apple-system, sans-serif", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {item.name}{item.isSuspicious && <span style={{ fontSize: 7, padding: "1px 4px", marginLeft: 4, borderRadius: 2, background: `${th.danger}22`, color: th.danger, fontWeight: 700, textTransform: "uppercase" }}>!</span>}{item.rmmTool && <span title="Remote Management tool" style={{ fontSize: 7, padding: "1px 4px", marginLeft: 4, borderRadius: 2, background: th.sev.high + "22", color: th.sev.high, fontWeight: 700, textTransform: "uppercase" }}>RMM</span>}
                      </span>
                      <span title={item.artifact || ""} style={{ width: gtlw("artifact"), minWidth: 40, fontSize: 10, color: item.isSuspicious ? (th.danger) : isLowRisk ? th.textDim : th.textMuted, fontWeight: item.isSuspicious ? 500 : 400, fontFamily: "SF Mono, Menlo, monospace", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.artifact || ""}</span>
                      <span style={{ width: gtlw("evidence"), minWidth: 40, flexShrink: 0, display: "flex", gap: 3, alignItems: "center", overflow: "hidden" }}>
                        {(item.evidencePills || []).filter(p => p.type !== "target").slice(0, 3).map((p, i) => (
                          <span key={i} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: (PA_PILL_COLORS[p.type] || th.sev.low) + "18", color: PA_PILL_COLORS[p.type] || th.sev.low, fontWeight: 500, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>{p.text}</span>
                        ))}
                        {(!item.evidencePills || item.evidencePills.filter(p => p.type !== "target").length === 0) && <span style={{ fontSize: 9, color: th.textMuted + "44" }}>\u2014</span>}
                      </span>
                      <span title={item.command || item.detailsSummary || ""} style={{ width: gtlw("command"), minWidth: 40, fontSize: 10, color: isLowRisk ? th.textDim + "88" : th.textDim, fontFamily: "SF Mono, Menlo, monospace", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.command || item.detailsSummary || ""}</span>
                    </div>
                    );
                  })}
                  {sorted.length > (modal._tlRowLimit || 500) && <div style={{ padding: "8px 0 4px 10px", fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontStyle: "italic" }}>Showing {modal._tlRowLimit || 500} of {sorted.length}</span>
                    <button onClick={() => setModal(p => ({ ...p, _tlRowLimit: (p._tlRowLimit || 500) + 500 }))} style={{ padding: "2px 10px", fontSize: 9, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 3, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Load more</button>
                  </div>}
                  {displayRows.length === 0 && <div style={{ padding: "20px 10px", fontSize: 11, color: th.textMuted, textAlign: "center", fontFamily: "-apple-system, sans-serif" }}>No items match current filters{tlMode === "triage" ? " — try Hunt or Chronology mode" : ""}</div>}
                  {/* Column filter dropdown popup */}
                  {filterOpen && (
                    <>
                      <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))} />
                      <div style={{ position: "fixed", left: modal.colFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340), top: modal.colFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440), width: modal.colFilterW || 320, height: modal.colFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                        <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                          onMouseDown={(e) => {
                            e.preventDefault();
                            const startX = e.clientX, startY = e.clientY;
                            const startLeft = modal.colFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340);
                            const startTop = modal.colFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440);
                            document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                            const onMove = (ev) => setModal((p) => ({ ...p, colFilterX: startLeft + ev.clientX - startX, colFilterY: startTop + ev.clientY - startY }));
                            const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                            window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                          }}>
                          <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER — {(tlCols.find((c) => c.key === filterOpen)?.label || filterOpen).toUpperCase()}</span>
                          <span style={{ cursor: "pointer", color: th.textMuted, fontSize: 14, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))}>×</span>
                        </div>
                        <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                          <input type="text" placeholder="Search values..." value={filterSearch} onChange={(e) => setModal((p) => ({ ...p, colFilterSearch: e.target.value }))}
                            style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: 11, background: th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                            autoFocus />
                        </div>
                        <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                          <button onClick={() => setModal((p) => ({ ...p, colFilterSel: new Set(filterVals) }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                          <button onClick={() => setModal((p) => ({ ...p, colFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                          <span style={{ marginLeft: "auto", fontSize: 10, color: th.textMuted }}>{filterVals.length} values</span>
                        </div>
                        <div style={{ flex: 1, overflow: "auto", padding: "0 6px", minHeight: 0 }}>
                          {displayVals.slice(0, 1000).map((v) => (
                            <div key={v} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", borderRadius: 3, cursor: "pointer" }}
                              onClick={() => setModal((p) => { const s = new Set(p.colFilterSel || []); s.has(v) ? s.delete(v) : s.add(v); return { ...p, colFilterSel: s }; })}
                              onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}0a`}
                              onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                              <input type="checkbox" checked={filterSel.has(v)} readOnly style={{ width: 13, height: 13, accentColor: th.accent, cursor: "pointer", flexShrink: 0 }} />
                              <span style={{ fontSize: 11, color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "SF Mono, Menlo, monospace" }}>{v || "(empty)"}</span>
                              <span style={{ fontSize: 10, color: th.textMuted, flexShrink: 0 }}>{filterCounts[v]}</span>
                            </div>
                          ))}
                        </div>
                        <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                          <button onClick={() => setModal((p) => { const cf = { ...(p.tableColFilters || {}) }; delete cf[filterOpen]; return { ...p, tableColFilters: cf, colFilterOpen: null }; })}
                            style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Reset</button>
                          <button onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))}
                            style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Cancel</button>
                          <button onClick={() => setModal((p) => ({ ...p, tableColFilters: { ...(p.tableColFilters || {}), [filterOpen]: [...(p.colFilterSel || [])] }, colFilterOpen: null }))}
                            style={{ padding: "4px 12px", fontSize: 10, background: th.accent, border: "none", borderRadius: 4, color: "#fff", cursor: "pointer", fontWeight: 600 }}>Apply</button>
                        </div>
                        <div onMouseDown={(e) => {
                          e.preventDefault(); e.stopPropagation();
                          const startX = e.clientX, startY = e.clientY, startW = modal.colFilterW || 320, startH = modal.colFilterH || 420;
                          document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                          const onMove = (ev) => setModal((p) => ({ ...p, colFilterW: Math.max(240, startW + ev.clientX - startX), colFilterH: Math.max(250, startH + ev.clientY - startY) }));
                          const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                        }} style={{ position: "absolute", right: 0, bottom: 0, width: 16, height: 16, cursor: "nwse-resize", zIndex: 2 }}>
                          <svg width="8" height="8" viewBox="0 0 10 10" style={{ position: "absolute", right: 3, bottom: 3, opacity: 0.3 }}><path d="M9 1L1 9M9 5L5 9M9 9L9 9" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round"/></svg>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              ); })()}

              {/* Table view */}
              {viewTab === "table" && (() => {
                // --- Analyst modes ---
                const TBL_MODES = {
                  triage: { label: "Triage",  sort: "riskScore", dir: "desc", filter: "suspicious", collapse: true,  desc: "Suspicious only, deduped, risk-sorted" },
                  review: { label: "Review",  sort: "riskScore", dir: "desc", filter: "medium+",    collapse: true,  desc: "Medium+ severity, deduped, risk-sorted" },
                  raw:    { label: "Raw",     sort: "riskScore", dir: "desc", filter: "all",         collapse: false, desc: "All items, flat rows" },
                };
                const tblMode = modal.tblMode || "triage";
                const activeMode = TBL_MODES[tblMode];
                const sortCol = activeMode ? activeMode.sort : (modal.sortCol || "riskScore");
                const sortDir = activeMode ? activeMode.dir : (modal.sortDir || "desc");
                const useCollapse = activeMode ? activeMode.collapse : !!modal._tblCollapse;
                const colFilters = modal.tableColFilters || {};
                const modeFilter = activeMode?.filter || "all";
                // --- Mode + column filtering on flat items ---
                const modeFiltered = filteredItems.filter((item) => {
                  if (modeFilter === "suspicious" && !item.isSuspicious) return false;
                  if (modeFilter === "medium+" && item.severity === "low") return false;
                  return true;
                });
                const hideExpected = !!modal._tblHideExpected;
                const _isItemExpected = (item) => item.whitelisted || (item.riskScore || 0) <= 0;
                const _isIncExpected = (inc) => (inc.triageScore || 0) <= 0 || (inc.items || []).every(i => i.whitelisted);
                let _expectedHiddenRaw = 0;
                const tableFiltered = modeFiltered.filter((item) => {
                  for (const [col, allowed] of Object.entries(colFilters)) {
                    if (!allowed || allowed.length === 0) continue;
                    if (!allowed.includes(String(item[col] ?? ""))) return false;
                  }
                  if (hideExpected && _isItemExpected(item)) { _expectedHiddenRaw++; return false; }
                  return true;
                });
                const sorted = [...tableFiltered].sort((a, b) => {
                  const av = a[sortCol] ?? "", bv = b[sortCol] ?? "";
                  const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                  return sortDir === "desc" ? -cmp : cmp;
                });
                // --- Incident filtering for collapse mode ---
                const _incVal = (inc, col) => {
                  if (col === "riskScore") return String(inc.triageScore || 0);
                  if (col === "name") { const r = inc.items?.reduce((b, i) => (i.riskScore || 0) > (b.riskScore || 0) ? i : b, inc.items?.[0]); return r?.name || inc.category || ""; }
                  if (col === "command") { const r = inc.items?.reduce((b, i) => (i.riskScore || 0) > (b.riskScore || 0) ? i : b, inc.items?.[0]); return r?.command || inc.command || ""; }
                  if (col === "timestamp") return (inc.firstSeen || "").substring(0, 16);
                  return String(inc[col] ?? "");
                };
                let _expectedHiddenInc = 0;
                const filteredIncidentsTable = useCollapse ? (data?.incidents || []).filter((inc) => {
                  if (modeFilter === "suspicious" && !inc.isSuspicious) return false;
                  if (modeFilter === "medium+" && inc.severity === "low") return false;
                  if (severityFilter !== "all" && inc.severity !== severityFilter) return false;
                  if (categoryFilter !== "all" && inc.category !== categoryFilter) return false;
                  if (searchText) {
                    const s = searchText.toLowerCase();
                    const repName = inc.items?.reduce((b, i) => (i.riskScore || 0) > (b.riskScore || 0) ? i : b, inc.items?.[0])?.name || "";
                    if (!`${inc.title} ${repName} ${inc.artifact} ${inc.command} ${inc.computer} ${inc.user} ${inc.category} ${inc.source}`.toLowerCase().includes(s)) return false;
                  }
                  for (const [col, allowed] of Object.entries(colFilters)) {
                    if (!allowed || allowed.length === 0) continue;
                    if (!allowed.includes(_incVal(inc, col))) return false;
                  }
                  if (hideExpected && _isIncExpected(inc)) { _expectedHiddenInc++; return false; }
                  return true;
                }) : [];
                const expectedHiddenCount = useCollapse ? _expectedHiddenInc : _expectedHiddenRaw;
                const sortedIncidentsTable = [...filteredIncidentsTable].sort((a, b) => {
                  let av, bv;
                  if (sortCol === "riskScore") { av = a.triageScore || 0; bv = b.triageScore || 0; }
                  else if (sortCol === "timestamp") { av = a.firstSeen || ""; bv = b.firstSeen || ""; }
                  else { av = a[sortCol] ?? ""; bv = b[sortCol] ?? ""; }
                  const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv));
                  return sortDir === "desc" ? -cmp : cmp;
                });
                const displayData = useCollapse ? sortedIncidentsTable : sorted;
                const toggleSort = (col) => setModal((p) => ({ ...p, tblMode: "custom", _tblCollapse: useCollapse, sortCol: col, sortDir: p.sortCol === col && p.sortDir === "asc" ? "desc" : "asc" }));
                const cw = modal.colWidths || {};
                const colDefs = [
                  { key: "riskScore", label: "Risk", dw: 50 },
                  { key: "severity", label: "Severity", dw: 70 },
                  { key: "category", label: "Category", dw: 110 },
                  { key: "name", label: "Detection", dw: 140 },
                  { key: "artifact", label: "Artifact", dw: 170 },
                  { key: "command", label: "Command/Path", dw: 180 },
                  { key: "timestamp", label: "Timestamp", dw: 145 },
                  { key: "computer", label: "Computer", dw: 90 },
                  { key: "user", label: "User", dw: 90 },
                  { key: "source", label: "Source", dw: 80 },
                ];
                const gw = (k) => cw[k] || colDefs.find((c) => c.key === k)?.dw || 100;
                const savedOrder = modal.colOrder || colDefs.map((c) => c.key);
                const colOrder = [...savedOrder.filter((k) => colDefs.some((c) => c.key === k)), ...colDefs.filter((c) => !savedOrder.includes(c.key)).map((c) => c.key)];
                const orderedCols = colOrder.map((k) => colDefs.find((c) => c.key === k)).filter(Boolean);
                const onColDragStart = (e, key) => { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", key); setModal((p) => ({ ...p, dragCol: key })); };
                const onColDrop = (e, targetKey) => {
                  e.preventDefault();
                  const fromKey = e.dataTransfer.getData("text/plain");
                  if (fromKey && fromKey !== targetKey) {
                    setModal((p) => {
                      const order = [...(p.colOrder || colDefs.map((c) => c.key))];
                      const fi = order.indexOf(fromKey), ti = order.indexOf(targetKey);
                      if (fi >= 0 && ti >= 0) { order.splice(fi, 1); order.splice(ti, 0, fromKey); }
                      return { ...p, colOrder: order, dragCol: null };
                    });
                  }
                };
                const onColResize = (colKey, e) => {
                  e.preventDefault(); e.stopPropagation();
                  const startX = e.clientX, startW = gw(colKey);
                  document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                  const onMove = (ev) => setModal((p) => ({ ...p, colWidths: { ...(p.colWidths || {}), [colKey]: Math.max(40, startW + ev.clientX - startX) } }));
                  const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                  window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                };
                const openColFilter = (colKey, e) => {
                  e.stopPropagation();
                  const rect = e.currentTarget.getBoundingClientRect();
                  const counts = {};
                  if (useCollapse) {
                    for (const inc of (data?.incidents || [])) {
                      if (modeFilter === "suspicious" && !inc.isSuspicious) continue;
                      if (modeFilter === "medium+" && inc.severity === "low") continue;
                      if (severityFilter !== "all" && inc.severity !== severityFilter) continue;
                      if (categoryFilter !== "all" && inc.category !== categoryFilter) continue;
                      if (hideExpected && _isIncExpected(inc)) continue;
                      if (searchText) { const s = searchText.toLowerCase(); const rn = inc.items?.reduce((b, i) => (i.riskScore || 0) > (b.riskScore || 0) ? i : b, inc.items?.[0])?.name || ""; if (!`${inc.title} ${rn} ${inc.artifact} ${inc.command} ${inc.computer} ${inc.user} ${inc.category} ${inc.source}`.toLowerCase().includes(s)) continue; }
                      let skip = false;
                      for (const [col, allowed] of Object.entries(colFilters)) {
                        if (col === colKey) continue;
                        if (!allowed || allowed.length === 0) continue;
                        if (!allowed.includes(_incVal(inc, col))) { skip = true; break; }
                      }
                      if (skip) continue;
                      const v = _incVal(inc, colKey);
                      counts[v] = (counts[v] || 0) + 1;
                    }
                  } else {
                    for (const item of modeFiltered) {
                      if (hideExpected && _isItemExpected(item)) continue;
                      let skip = false;
                      for (const [col, allowed] of Object.entries(colFilters)) {
                        if (col === colKey) continue;
                        if (!allowed || allowed.length === 0) continue;
                        if (!allowed.includes(String(item[col] ?? ""))) { skip = true; break; }
                      }
                      if (skip) continue;
                      const v = String(item[colKey] ?? "");
                      counts[v] = (counts[v] || 0) + 1;
                    }
                  }
                  const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
                  const current = colFilters[colKey];
                  const selected = new Set(current && current.length > 0 ? current : allVals);
                  setModal((p) => ({ ...p, colFilterOpen: colKey, colFilterPos: { x: rect.left, y: rect.bottom + 2 }, colFilterVals: allVals, colFilterCounts: counts, colFilterSel: selected, colFilterSearch: "" }));
                };
                const renderCell = (item, col) => {
                  if (col.key === "riskScore") return <span style={{ fontWeight: PA_W.strong, fontFamily: PA_MONO, color: paRiskColor(item.riskScore || 0), display: "flex", alignItems: "center", gap: 3 }}>{item.riskScore}{item.isSuspicious && <span title={item.suspiciousReasons?.join(", ")} style={{ fontSize: PA_SZ.pill, color: th.sev.critical }}>!</span>}{item.confidence === "confirmed" ? <span title="Execution corroborated" style={{ fontSize: 7, color: th.sev.clean }}>●</span> : item.confidence === "likely" ? <span title="Likely corroborated" style={{ fontSize: 7, color: th.sev.high }}>●</span> : null}</span>;
                  if (col.key === "severity") return <span style={{ ...paPill(SEVERITY_COLORS[item.severity] || th.textMuted), textTransform: "uppercase" }}>{item.severity}</span>;
                  if (col.key === "name") return <span style={{ display: "flex", alignItems: "center", gap: 4 }}><span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.name}</span>{item.rmmTool && <span title="Remote Management tool" style={{ ...paPill(th.sev.high), textTransform: "uppercase" }}>RMM</span>}</span>;
                  if (col.key === "timestamp") return item.timestamp ? String(item.timestamp).substring(0, 19) : "";
                  return item[col.key] || "";
                };
                // Incident cell renderer for collapsed rows
                const _confOrd = { confirmed: 2, likely: 1, present: 0 };
                const renderIncCell = (inc, col) => {
                  const rep = inc.items?.reduce((best, it) => (it.riskScore || 0) > (best.riskScore || 0) ? it : best, inc.items[0]);
                  const maxConf = inc.items?.reduce((best, it) => (_confOrd[it.confidence] || 0) > (_confOrd[best] || 0) ? it.confidence : best, "") || "";
                  if (col.key === "riskScore") return <span style={{ fontWeight: PA_W.strong, fontFamily: PA_MONO, color: paRiskColor(inc.triageScore || 0), display: "flex", alignItems: "center", gap: 3 }}>{inc.triageScore || 0}{inc.isSuspicious && <span title={inc.suspiciousReasons?.join(", ")} style={{ fontSize: PA_SZ.pill, color: th.sev.critical }}>!</span>}{maxConf === "confirmed" ? <span title="Execution corroborated" style={{ fontSize: 7, color: th.sev.clean }}>●</span> : maxConf === "likely" ? <span title="Likely corroborated" style={{ fontSize: 7, color: th.sev.high }}>●</span> : null}</span>;
                  if (col.key === "severity") return <span style={{ ...paPill(SEVERITY_COLORS[inc.severity] || th.textMuted), textTransform: "uppercase" }}>{inc.severity}</span>;
                  if (col.key === "name") {
                    const pillPrio = ["execution", "correlation", "context"];
                    const topPills = (inc.evidencePills || []).filter(p => p.type !== "target").sort((a, b) => pillPrio.indexOf(a.type) - pillPrio.indexOf(b.type)).slice(0, 2);
                    return <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <span style={{ fontSize: PA_SZ.pill, color: th.textMuted, flexShrink: 0 }}>{modal._expandedCluster === inc.id ? "\u25BC" : "\u25B6"}</span>
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{rep?.name || inc.category}</span>
                      {inc.occurrenceCount > 1 && <span title={`${inc.occurrenceCount} occurrences in this cluster`} style={paPill(th.accent)}>{inc.occurrenceCount}x</span>}
                      {inc.rmmTool && <span title="Remote Management tool" style={{ ...paPill(th.sev.high), textTransform: "uppercase" }}>RMM</span>}
                      {topPills.map((p, i) => <span key={i} style={paPill(PA_PILL_COLORS[p.type] || th.sev.low)}>{p.text}</span>)}
                    </span>;
                  }
                  if (col.key === "timestamp") {
                    const fs = (inc.firstSeen || "").substring(0, 16); const ls = (inc.lastSeen || "").substring(0, 16);
                    return fs === ls ? fs : `${fs} \u2014 ${ls}`;
                  }
                  if (col.key === "artifact") return inc.artifact || "";
                  if (col.key === "command") return rep?.command || inc.command || "";
                  return inc[col.key] || "";
                };
                const filterOpen = modal.colFilterOpen;
                const filterPos = modal.colFilterPos || {};
                const filterVals = modal.colFilterVals || [];
                const filterCounts = modal.colFilterCounts || {};
                const filterSel = modal.colFilterSel || new Set();
                const filterSearch = modal.colFilterSearch || "";
                const displayVals = filterSearch ? filterVals.filter((v) => v.toLowerCase().includes(filterSearch.toLowerCase())) : filterVals;
                return (
                  <div style={{ border: `1px solid ${th.border}22`, borderRadius: 8, overflow: "hidden", position: "relative" }}>
                    {/* Mode toolbar */}
                    <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 10px", borderBottom: `1px solid ${th.border}22` }}>
                      {Object.entries(TBL_MODES).map(([k, m]) => (
                        <button key={k} onClick={() => setModal((p) => ({ ...p, tblMode: k, _expandedCluster: null }))} title={m.desc}
                          style={{ padding: "3px 10px", fontSize: PA_SZ.label, fontWeight: PA_W.strong, background: tblMode === k ? th.accent : `${th.accent}15`, color: tblMode === k ? "#fff" : th.accent, border: `1px solid ${tblMode === k ? th.accent : th.accent + "33"}`, borderRadius: 4, cursor: "pointer", fontFamily: PA_SANS }}>{m.label}</button>
                      ))}
                      {tblMode === "custom" && <span style={paMeta}>Custom</span>}
                      <button onClick={() => setModal(p => ({ ...p, _tblHideExpected: !p._tblHideExpected }))} title="Hide expected/whitelisted items"
                        style={{ padding: "3px 10px", fontSize: PA_SZ.label, fontWeight: PA_W.strong, background: hideExpected ? `${th.accent}15` : "transparent", color: hideExpected ? th.accent : th.textMuted, border: `1px solid ${hideExpected ? th.accent + "33" : th.border + "33"}`, borderRadius: 4, cursor: "pointer", fontFamily: PA_SANS }}>
                        {hideExpected ? "Expected Hidden" : "Hide Expected"}
                      </button>
                      {expectedHiddenCount > 0 && <span style={paMeta}>{expectedHiddenCount} hidden</span>}
                      <span style={{ ...paMeta, marginLeft: "auto" }}>
                        {useCollapse ? `${sortedIncidentsTable.length} clusters` : `${tableFiltered.length} items`}
                        {useCollapse && sortedIncidentsTable.filter(i => i.isSuspicious).length > 0 && <span style={{ color: th.sev.critical, fontWeight: PA_W.strong }}> · {sortedIncidentsTable.filter(i => i.isSuspicious).length} suspicious</span>}
                      </span>
                    </div>
                    <div style={{ overflow: "auto", maxHeight: 440 }}>
                      <div style={{ minWidth: "fit-content" }}>
                        {/* Column headers */}
                        <div style={{ display: "flex", background: th.panelBg, borderBottom: `1px solid ${th.border}33`, position: "sticky", top: 0, zIndex: 5 }}>
                          <div style={{ width: 30, flexShrink: 0, padding: "6px 8px", display: "flex", alignItems: "center" }}>
                            {!useCollapse && <input type="checkbox" checked={sorted.length > 0 && sorted.slice(0, modal._tblLimit || 500).every((i) => isChecked(i))} onChange={(e) => {
                              e.stopPropagation();
                              setModal((p) => {
                                const lim = p._tblLimit || 500;
                                const s = new Set(p.checkedItems || []);
                                const allChecked = sorted.slice(0, lim).every((i) => s.has(i.rowid + "|" + i.name + "|" + i.timestamp));
                                sorted.slice(0, lim).forEach((i) => { const k = i.rowid + "|" + i.name + "|" + i.timestamp; allChecked ? s.delete(k) : s.add(k); });
                                return { ...p, checkedItems: s };
                              });
                            }} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />}
                          </div>
                          {orderedCols.map((c) => (
                            <div key={c.key} draggable onDragStart={(e) => onColDragStart(e, c.key)} onDragOver={(e) => e.preventDefault()} onDrop={(e) => onColDrop(e, c.key)} onDragEnd={() => setModal((p) => ({ ...p, dragCol: null }))}
                              style={{ width: gw(c.key), flexShrink: 0, padding: "6px 8px", fontSize: PA_SZ.label, fontWeight: PA_W.strong, letterSpacing: "0.03em", color: sortCol === c.key ? th.accent : th.textMuted, cursor: "grab", fontFamily: PA_SANS, userSelect: "none", position: "relative", opacity: modal.dragCol === c.key ? 0.4 : 1, transition: "opacity var(--m-base)", display: "flex", alignItems: "center", gap: 2 }}>
                              <span onClick={() => toggleSort(c.key)} style={{ cursor: "pointer", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {c.label}{sortCol === c.key ? (sortDir === "asc" ? " \u25B2" : " \u25BC") : ""}
                              </span>
                              <span style={{ cursor: "pointer", fontSize: 9, color: colFilters[c.key] ? th.accent : th.textMuted, flexShrink: 0, marginLeft: "auto", opacity: colFilters[c.key] ? 1 : 0.5 }}
                                onClick={(e) => { e.stopPropagation(); openColFilter(c.key, e); }}>{colFilters[c.key] ? "\u25BC" : "\u25BE"}</span>
                              <div onMouseDown={(e) => onColResize(c.key, e)} style={{ position: "absolute", right: -3, top: 0, bottom: 0, width: 6, cursor: "col-resize", zIndex: 2 }}
                                onClick={(e) => e.stopPropagation()}>
                                <div style={{ position: "absolute", right: 2, top: 4, bottom: 4, width: 2, borderRadius: 2, background: th.border + "55", transition: "background var(--m-base)" }}
                                  onMouseEnter={(e) => e.currentTarget.style.background = th.accent}
                                  onMouseLeave={(e) => e.currentTarget.style.background = th.border + "55"} />
                              </div>
                            </div>
                          ))}
                        </div>
                        {/* Collapsed incident rows */}
                        {useCollapse && sortedIncidentsTable.slice(0, modal._tblLimit || 500).map((inc) => {
                          const isExp = modal._expandedCluster === inc.id;
                          const repItem = inc.items?.[0];
                          return (
                            <div key={inc.id}>
                              <div style={{ display: "flex", borderBottom: `1px solid ${th.border}11`, transition: "background var(--m-fast)", background: inc.isSuspicious ? `${th.sev.critical}0d` : "transparent", cursor: "pointer" }}
                                onClick={() => setModal((p) => ({ ...p, _expandedCluster: p._expandedCluster === inc.id ? null : inc.id, selectedPersistKey: repItem ? persistItemKey(repItem) : p.selectedPersistKey }))}
                                onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}06`}
                                onMouseLeave={(e) => e.currentTarget.style.background = inc.isSuspicious ? `${th.sev.critical}0d` : "transparent"}>
                                <div style={{ width: 30, flexShrink: 0, padding: "5px 8px" }} />
                                {orderedCols.map((col) => (
                                  <div key={col.key} style={{ width: gw(col.key), flexShrink: 0, padding: "5px 8px", fontSize: PA_SZ.value, fontWeight: PA_W.normal, color: PA_STRONG_COLS.has(col.key) ? th.text : th.textDim, fontFamily: PA_MONO_COLS.has(col.key) ? PA_MONO : PA_SANS, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                    {renderIncCell(inc, col)}
                                  </div>
                                ))}
                              </div>
                              {isExp && inc.items.slice(0, 50).map((item, si) => {
                                const isSelSub = isSelPersist(item);
                                return (
                                  <div key={si} style={{ display: "flex", borderBottom: `1px solid ${th.border}08`, background: isSelSub ? `${th.accent}14` : `${th.border}06`, cursor: "pointer", paddingLeft: 12 }}
                                    onClick={() => toggleSelPersist(item)}
                                    onMouseEnter={(e) => { if (!isSelSub) e.currentTarget.style.background = `${th.accent}08`; }}
                                    onMouseLeave={(e) => { if (!isSelSub) e.currentTarget.style.background = `${th.border}06`; }}>
                                    <div style={{ width: 30, flexShrink: 0, padding: "5px 8px", display: "flex", alignItems: "center" }}>
                                      <input type="checkbox" checked={isChecked(item)} onChange={(e) => toggleCheck(item, e)} onClick={(e) => e.stopPropagation()} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                    </div>
                                    {orderedCols.map((col) => (
                                      <div key={col.key} style={{ width: gw(col.key), flexShrink: 0, padding: "5px 8px", fontSize: PA_SZ.value, fontWeight: PA_W.normal, color: th.textDim, fontFamily: PA_MONO_COLS.has(col.key) ? PA_MONO : PA_SANS, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                        {renderCell(item, col)}
                                      </div>
                                    ))}
                                  </div>
                                );
                              })}
                              {isExp && inc.items.length > 50 && <div style={{ ...paMeta, padding: "4px 42px" }}>…and {inc.items.length - 50} more</div>}
                            </div>
                          );
                        })}
                        {/* Flat item rows (raw mode) */}
                        {!useCollapse && sorted.slice(0, modal._tblLimit || 500).map((item, idx) => {
                          const isSelItem = isSelPersist(item);
                          return (
                          <div key={idx} style={{ display: "flex", borderBottom: `1px solid ${th.border}11`, transition: "background var(--m-fast)", background: isSelItem ? `${th.accent}14` : isChecked(item) ? `${th.accent}0a` : item.isSuspicious ? `${th.sev.critical}0d` : "transparent", cursor: "pointer" }}
                            onClick={() => toggleSelPersist(item)}
                            onMouseEnter={(e) => { if (!isSelItem && !isChecked(item)) e.currentTarget.style.background = `${th.accent}06`; }}
                            onMouseLeave={(e) => { if (!isSelItem) e.currentTarget.style.background = isChecked(item) ? `${th.accent}0a` : item.isSuspicious ? `${th.sev.critical}0d` : "transparent"; }}>
                            <div style={{ width: 30, flexShrink: 0, padding: "5px 8px", display: "flex", alignItems: "center" }}>
                              <input type="checkbox" checked={isChecked(item)} onChange={(e) => toggleCheck(item, e)} onClick={(e) => e.stopPropagation()} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                            </div>
                            {orderedCols.map((col) => (
                              <div key={col.key} title={col.key === "artifact" && item.isSuspicious ? item.suspiciousReasons?.join(", ") : undefined} style={{ width: gw(col.key), flexShrink: 0, padding: "5px 8px", fontSize: PA_SZ.value, fontWeight: PA_W.normal, color: PA_STRONG_COLS.has(col.key) ? th.text : th.textDim, fontFamily: PA_MONO_COLS.has(col.key) ? PA_MONO : PA_SANS, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {renderCell(item, col)}
                              </div>
                            ))}
                          </div>
                        ); })}
                      </div>
                    </div>
                    {displayData.length > (modal._tblLimit || 500) && <div style={{ padding: "6px 10px", borderTop: `1px solid ${th.border}11`, display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={paMeta}>Showing {modal._tblLimit || 500} of {displayData.length} {useCollapse ? "clusters" : "items"}</span>
                      <button onClick={() => setModal(p => ({ ...p, _tblLimit: (p._tblLimit || 500) + 500 }))} style={{ padding: "3px 10px", fontSize: PA_SZ.label, fontWeight: PA_W.strong, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, cursor: "pointer", fontFamily: PA_SANS }}>Load more</button>
                    </div>}
                    {displayData.length === 0 && <div style={{ padding: "20px 10px", fontSize: PA_SZ.value, fontWeight: PA_W.normal, color: th.textMuted, textAlign: "center", fontFamily: PA_SANS }}>No items match current filters{tblMode === "triage" ? " \u2014 try Review or Raw mode" : ""}</div>}
                    {/* Column filter dropdown popup */}
                    {filterOpen && (
                      <>
                        <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))} />
                        <div style={{ position: "fixed", left: modal.colFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340), top: modal.colFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440), width: modal.colFilterW || 320, height: modal.colFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                          {/* Draggable header */}
                          <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                            onMouseDown={(e) => {
                              e.preventDefault();
                              const startX = e.clientX, startY = e.clientY;
                              const startLeft = modal.colFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340);
                              const startTop = modal.colFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440);
                              document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                              const onMove = (ev) => setModal((p) => ({ ...p, colFilterX: startLeft + ev.clientX - startX, colFilterY: startTop + ev.clientY - startY }));
                              const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                              window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                            }}>
                            <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER — {(colDefs.find((c) => c.key === filterOpen)?.label || filterOpen).toUpperCase()}</span>
                            <span style={{ cursor: "pointer", color: th.textMuted, fontSize: 14, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))}>×</span>
                          </div>
                          <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                            <input type="text" placeholder="Search values..." value={filterSearch} onChange={(e) => setModal((p) => ({ ...p, colFilterSearch: e.target.value }))}
                              style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: 11, background: th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                              autoFocus />
                          </div>
                          <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                            <button onClick={() => setModal((p) => ({ ...p, colFilterSel: new Set(filterVals) }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                            <button onClick={() => setModal((p) => ({ ...p, colFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                            <span style={{ marginLeft: "auto", fontSize: 10, color: th.textMuted }}>{filterVals.length} values</span>
                          </div>
                          <div style={{ flex: 1, overflow: "auto", padding: "0 6px", minHeight: 0 }}>
                            {displayVals.slice(0, 1000).map((v) => (
                              <div key={v} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", borderRadius: 3, cursor: "pointer" }}
                                onClick={() => setModal((p) => { const s = new Set(p.colFilterSel || []); s.has(v) ? s.delete(v) : s.add(v); return { ...p, colFilterSel: s }; })}
                                onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}0a`}
                                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                                <input type="checkbox" checked={filterSel.has(v)} readOnly style={{ width: 13, height: 13, accentColor: th.accent, cursor: "pointer", flexShrink: 0 }} />
                                <span style={{ fontSize: 11, color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "SF Mono, Menlo, monospace" }}>{v || "(empty)"}</span>
                                <span style={{ fontSize: 10, color: th.textMuted, flexShrink: 0 }}>{filterCounts[v]}</span>
                              </div>
                            ))}
                          </div>
                          <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                            <button onClick={() => setModal((p) => { const cf = { ...(p.tableColFilters || {}) }; delete cf[filterOpen]; return { ...p, tableColFilters: cf, colFilterOpen: null }; })}
                              style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Reset</button>
                            <button onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))}
                              style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Cancel</button>
                            <button onClick={() => setModal((p) => ({ ...p, tableColFilters: { ...(p.tableColFilters || {}), [filterOpen]: [...(p.colFilterSel || [])] }, colFilterOpen: null }))}
                              style={{ padding: "4px 12px", fontSize: 10, background: th.accent, border: "none", borderRadius: 4, color: "#fff", cursor: "pointer", fontWeight: 600 }}>Apply</button>
                          </div>
                          {/* Resize handle */}
                          <div onMouseDown={(e) => {
                            e.preventDefault(); e.stopPropagation();
                            const startX = e.clientX, startY = e.clientY, startW = modal.colFilterW || 320, startH = modal.colFilterH || 420;
                            document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                            const onMove = (ev) => setModal((p) => ({ ...p, colFilterW: Math.max(240, startW + ev.clientX - startX), colFilterH: Math.max(250, startH + ev.clientY - startY) }));
                            const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                            window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                          }} style={{ position: "absolute", right: 0, bottom: 0, width: 16, height: 16, cursor: "nwse-resize", zIndex: 2 }}>
                            <svg width="8" height="8" viewBox="0 0 10 10" style={{ position: "absolute", right: 3, bottom: 3, opacity: 0.3 }}><path d="M9 1L1 9M9 5L5 9M9 9L9 9" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round"/></svg>
                          </div>
                        </div>
                      </>
                    )}
                  </div>
                );
              })()}
            </div>
          )}
        </div>

        {/* Event Detail Panel — shared across all views */}
        {phase === "results" && selectedPersistKey && (() => {
          const selItem = itemForKey(selectedPersistKey);
          if (!selItem) return null;
          const sevCol = SEVERITY_COLORS[selItem.severity] || th.textMuted;
          return (
            <div style={{ borderTop: `2px solid ${sevCol}44`, background: `linear-gradient(135deg, ${sevCol}06, ${th.panelBg}ee)`, padding: "14px 16px", display: "flex", flexDirection: "column", gap: 10, flexShrink: 0, maxHeight: 280, overflow: "auto" }}>
              {/* Header row */}
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span style={{ ...paPill(sevCol), textTransform: "uppercase" }}>{selItem.severity}</span>
                {selItem.isSuspicious && <span style={{ ...paPill(th.sev.critical), textTransform: "uppercase" }}>SUSPICIOUS</span>}
                {selItem.rmmTool && <span title="Remote Management tool" style={{ ...paPill(th.sev.high), textTransform: "uppercase" }}>RMM</span>}
                {(selItem.tags || []).filter(t => t !== "RMM Tool").map((t, i) => <span key={i} style={{ ...paPill(th.accent), textTransform: "uppercase" }}>{t}</span>)}
                <PaMitreBadge category={selItem.category} />
                <span style={{ fontSize: 13, fontWeight: PA_W.strong, color: th.text, fontFamily: PA_SANS }}>{selItem.name}</span>
                <span style={{ ...paLabel, marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>Risk Score: <span style={{ fontSize: PA_SZ.value, fontFamily: PA_MONO, fontWeight: PA_W.strong, color: paRiskColor(selItem.riskScore || 0) }}>{selItem.riskScore}/10</span>
                  {selItem.confidence && <span style={{ ...paPill(selItem.confidence === "confirmed" ? th.sev.clean : selItem.confidence === "likely" ? th.sev.high : th.textMuted), textTransform: "capitalize" }}>{selItem.confidence}</span>}
                </span>
                <button onClick={() => setModal((p) => ({ ...p, selectedPersistKey: null }))} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "0 4px", lineHeight: 1 }} title="Close">&times;</button>
              </div>
              {/* Info grid */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: "6px 16px" }}>
                {[
                  { label: "Category", value: selItem.category },
                  { label: "Source", value: selItem.source },
                  { label: "Timestamp", value: selItem.timestamp ? String(selItem.timestamp).substring(0, 23) : "" },
                  { label: "Computer", value: selItem.computer },
                  { label: "User", value: selItem.user },
                  { label: "Confidence", value: selItem.confidence ? selItem.confidence.charAt(0).toUpperCase() + selItem.confidence.slice(1) : "" },
                ].filter(f => f.value).map((f, i) => (
                  <div key={i} style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
                    <span style={paLabel}>{f.label}:</span>
                    <span style={{ ...paValue, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.value}</span>
                  </div>
                ))}
              </div>
              {/* Host context strip */}
              {(() => {
                const ctxArt = selItem.artifact, ctxHost = selItem.computer, ctxUser = selItem.user;
                const allIt = data?.items || [];
                const sameAH = ctxArt && ctxHost ? allIt.filter(i => i.artifact === ctxArt && i.computer === ctxHost) : [];
                const sahFirst = sameAH.length > 1 ? sameAH.reduce((a, b) => (a.timestamp || "") < (b.timestamp || "") ? a : b).timestamp : null;
                const sahLast = sameAH.length > 1 ? sameAH.reduce((a, b) => (a.timestamp || "") > (b.timestamp || "") ? a : b).timestamp : null;
                const otherCats = ctxArt ? [...new Set(allIt.filter(i => i.artifact === ctxArt && i.category !== selItem.category).map(i => i.category))] : [];
                const userOther = ctxUser && ctxHost ? [...new Set(allIt.filter(i => i.user === ctxUser && i.computer === ctxHost && i.artifact && i.artifact !== ctxArt).map(i => i.artifact))] : [];
                if (sameAH.length <= 1 && otherCats.length === 0 && userOther.length === 0) return null;
                return (
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", padding: "6px 0", borderTop: `1px solid ${th.border}15`, borderBottom: `1px solid ${th.border}15` }}>
                    {sameAH.length > 1 && <span style={paMeta}>
                      <span style={{ fontWeight: PA_W.strong, color: th.text }}>{sameAH.length}</span> occurrences on {ctxHost}
                      {sahFirst && sahLast && sahFirst !== sahLast && <span style={{ marginLeft: 4, fontFamily: PA_MONO, fontSize: PA_SZ.label }}>({String(sahFirst).substring(0, 10)} \u2014 {String(sahLast).substring(0, 10)})</span>}
                    </span>}
                    {otherCats.length > 0 && <span style={paMeta}>
                      Also in: {otherCats.map((c, i) => <span key={i} style={{ ...paPill(th.accent), marginLeft: 2 }}>{c}</span>)}
                    </span>}
                    {userOther.length > 0 && <span style={paMeta}>
                      {ctxUser} \u2192 <span style={{ fontWeight: 600, color: th.text }}>{userOther.length}</span> other artifact{userOther.length !== 1 ? "s" : ""}
                      {userOther.length <= 3 && <span style={{ fontFamily: PA_MONO, fontSize: PA_SZ.label, marginLeft: 4, color: th.textDim }}>({userOther.map(a => (a || "").split("\\").pop()).join(", ")})</span>}
                    </span>}
                  </div>
                );
              })()}
              {/* Artifact + Command */}
              {selItem.artifact && (
                <div style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
                  <span style={paLabel}>Artifact:</span>
                  <span style={{ ...paValue, wordBreak: "break-all" }}>{selItem.artifact}</span>
                </div>
              )}
              {selItem.command && (
                <div style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
                  <span style={paLabel}>Command:</span>
                  <span style={{ ...paValue, wordBreak: "break-all", maxHeight: 60, overflow: "auto" }}>{selItem.command}</span>
                </div>
              )}
              {/* Remote origin — who planted this. The single most actionable fact a
                  persistence finding can carry, so it gets its own block rather than
                  being buried in the extracted-fields dump. */}
              {selItem.remoteOrigin && (
                <div style={{ background: `${th.accent}0e`, border: `1px solid ${th.accent}2e`, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ ...paCaption, marginBottom: 5, color: th.accent }}>Remote origin</div>
                  <div style={{ display: "flex", gap: 6, alignItems: "baseline", flexWrap: "wrap" }}>
                    <span style={{ ...paValue, fontWeight: 600 }}>
                      {selItem.remoteOrigin.sourceHost || selItem.remoteOrigin.sourceIp || "unknown source"}
                    </span>
                    <span style={{ ...paLabel, color: th.textMuted }}>→</span>
                    <span style={paValue}>{selItem.computer || "this host"}</span>
                    <span style={{ ...paLabel, color: th.textMuted }}>via {selItem.remoteOrigin.via}</span>
                  </div>
                  <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 4 }}>
                    {selItem.remoteOrigin.sourceIp && <span style={paLabel}>IP: <span style={paValue}>{selItem.remoteOrigin.sourceIp}</span></span>}
                    {selItem.remoteOrigin.user && <span style={paLabel}>User: <span style={paValue}>{selItem.remoteOrigin.user}</span></span>}
                    {selItem.remoteOrigin.logonId && <span style={paLabel}>Logon ID: <span style={paValue}>{selItem.remoteOrigin.logonId}</span></span>}
                    <span style={paLabel}>{Math.round((selItem.remoteOrigin.gapMs || 0) / 60000)} min before</span>
                  </div>
                  {(selItem.remoteOrigin.sourceHost || selItem.remoteOrigin.sourceIp) && (
                    <button onClick={() => setModal((p) => ({
                      ...p, searchTerm: selItem.remoteOrigin.sourceHost || selItem.remoteOrigin.sourceIp,
                      tableColFilters: {}, viewTab: "timeline", tlMode: "chronology", tlCatFilter: null,
                    }))} style={{ marginTop: 6, fontSize: PA_SZ.label, fontWeight: PA_W.strong, padding: "3px 10px", borderRadius: 6, background: `${th.accent}18`, color: th.accent, border: `1px solid ${th.accent}33`, cursor: "pointer", fontFamily: PA_SANS }}>
                      Trace this source
                    </button>
                  )}
                </div>
              )}
              {/* All extracted details */}
              {selItem.details && Object.keys(selItem.details).length > 0 && (
                <div style={{ background: `${th.modalBg}cc`, borderRadius: 6, padding: "8px 10px", border: `1px solid ${th.border}22` }}>
                  <div style={{ ...paCaption, marginBottom: 6 }}>Extracted Fields</div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(250px, 1fr))", gap: "3px 16px" }}>
                    {Object.entries(selItem.details).filter(([k]) => !k.startsWith("_")).map(([k, v]) => (
                      <div key={k} style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
                        <span style={paLabel}>{k}:</span>
                        <span style={{ ...paValue, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={v}>{v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {/* Suspicious reasons */}
              {selItem.isSuspicious && selItem.suspiciousReasons?.length > 0 && (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {selItem.suspiciousReasons.map((r, i) => (
                    <span key={i} style={paPill(th.sev.critical)}>{r}</span>
                  ))}
                </div>
              )}
              {/* Evidence pills */}
              {selItem.evidencePills?.length > 0 && (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  <span style={{ ...paLabel, marginRight: 2, alignSelf: "center" }}>Evidence:</span>
                  {selItem.evidencePills.filter(p => p.type !== "target").map((p, i) => (
                    <span key={i} style={paPill(PA_PILL_COLORS[p.type] || th.sev.low)}>{p.text}</span>
                  ))}
                </div>
              )}
              {/* Action buttons */}
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                {selItem.artifact && <button onClick={() => {
                  const leaf = (selItem.artifact || "").split(/[/\\]/).pop().replace(/\{[0-9a-f-]+\}$/i, "").trim();
                  setModal((p) => ({ ...p, searchTerm: leaf || selItem.artifact, tableColFilters: {}, viewTab: "timeline", tlMode: "chronology", tlCatFilter: null }));
                }} style={{ fontSize: PA_SZ.label, fontWeight: PA_W.strong, padding: "3px 10px", borderRadius: 6, background: `${th.accent}11`, color: th.accent, border: `1px solid ${th.accent}22`, cursor: "pointer", fontFamily: PA_SANS }}>Same Artifact</button>}
                {selItem.computer && <button onClick={() => {
                  setModal((p) => ({ ...p, tableColFilters: { computer: [selItem.computer] }, searchTerm: "", viewTab: "timeline", tlMode: "chronology", tlCatFilter: null }));
                }} style={{ fontSize: PA_SZ.label, fontWeight: PA_W.strong, padding: "3px 10px", borderRadius: 6, background: `${th.accent}11`, color: th.accent, border: `1px solid ${th.accent}22`, cursor: "pointer", fontFamily: PA_SANS }}>Same Host</button>}
                {selItem.user && <button onClick={() => {
                  setModal((p) => ({ ...p, tableColFilters: { user: [selItem.user] }, searchTerm: "", viewTab: "timeline", tlMode: "chronology", tlCatFilter: null }));
                }} style={{ fontSize: PA_SZ.label, fontWeight: PA_W.strong, padding: "3px 10px", borderRadius: 6, background: `${th.accent}11`, color: th.accent, border: `1px solid ${th.accent}22`, cursor: "pointer", fontFamily: PA_SANS }}>Same User</button>}
                <button onClick={() => {
                  const lines = [`[${selItem.severity.toUpperCase()}] ${selItem.name}`, `Category: ${selItem.category}`, `Source: ${selItem.source}`, `Timestamp: ${selItem.timestamp}`, `Computer: ${selItem.computer}`, `User: ${selItem.user}`];
                  if (selItem.artifact) lines.push(`Artifact: ${selItem.artifact}`);
                  if (selItem.command) lines.push(`Command: ${selItem.command}`);
                  if (selItem.details) { for (const [k, v] of Object.entries(selItem.details)) lines.push(`  ${k}: ${v}`); }
                  if (selItem.suspiciousReasons?.length) lines.push(`Suspicious: ${selItem.suspiciousReasons.join("; ")}`);
                  if (selItem.evidencePills?.length) lines.push(`Evidence: ${selItem.evidencePills.map(p => p.text).join(", ")}`);
                  lines.push(`Risk Score: ${selItem.riskScore}/10`);
                  if (selItem.confidence) lines.push(`Confidence: ${selItem.confidence}`);
                  const mitre = PA_CAT_MITRE[selItem.category];
                  if (mitre) lines.push(`MITRE ATT&CK: ${mitre}`);
                  navigator.clipboard?.writeText?.(lines.join("\n"));
                }} style={{ fontSize: PA_SZ.label, fontWeight: PA_W.strong, padding: "3px 10px", borderRadius: 6, background: th.accent + "18", color: th.accent, border: `1px solid ${th.accent}33`, cursor: "pointer", fontFamily: PA_SANS }}>Copy Details</button>
              </div>
            </div>
          );
        })()}

        {/* Footer */}
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
          {phase === "config" && (
            <div style={{ display: "flex", justifyContent: "space-between", width: "100%" }}>
              <button onClick={() => setModal(null)} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
              <button onClick={handleAnalyze} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Analyze</button>
            </div>
          )}
          {phase === "loading" && (
            <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
              <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>{Math.round(modal.progress || 0)}% complete</span>
              <button onClick={handleCancelAnalyze} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
            </div>
          )}
          {phase === "results" && (
            <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
              <button onClick={() => setModal((p) => ({ ...p, phase: "config", data: null }))} style={{ ...ms.bs, borderRadius: 8 }}>Back</button>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                {checkedItems.size > 0 && (
                  <>
                    <span style={{ fontSize: 11, color: th.accent, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{checkedItems.size} selected</span>
                    <button onClick={() => {
                      const hdr = "Severity\tDetection\tDetails\tTimestamp\tComputer\tUser\tSource\tRisk\n";
                      const body = [...checkedItems].map((key) => itemForKey(key)).filter(Boolean).map((i) => formatItemText(i)).join("\n");
                      navigator.clipboard?.writeText?.(hdr + body);
                    }} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Copy Selected ({checkedItems.size})</button>
                    <button onClick={() => setModal((p) => ({ ...p, checkedItems: new Set() }))} style={{ ...ms.bs, borderRadius: 8 }}>Clear</button>
                  </>
                )}
                <button title={`Copy the ${paVisibleRows.length.toLocaleString()} ${paShowingIncidents ? "alerts" : "items"} currently listed`} onClick={() => {
                  const hdr = "Risk\tSeverity\tCategory\tDetection\tArtifact\tCommand/Path\tDetails\tTimestamp\tComputer\tUser\tSource\tSuspicious\n";
                  const body = paVisibleRows.map((r) => {
                    const c = paExportRow(r);
                    return `${c.RiskScore}\t${c.Severity}\t${c.Category}\t${c.Name}\t${c.Artifact}\t${c.Command}\t${c.Description}\t${c.Timestamp}\t${c.Computer}\t${c.User}\t${c.Source}\t${c.SuspiciousReasons}`;
                  }).join("\n");
                  navigator.clipboard?.writeText?.(hdr + body);
                }} style={{ ...ms.bs, borderRadius: 8 }}>Copy All</button>
                <button onClick={() => setModal(null)} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Done</button>
              </div>
            </div>
          )}
        </div>
      </>)}
    </DraggableResizableModal>
  );
}
