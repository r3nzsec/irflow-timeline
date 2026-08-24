import { useState, useEffect, useRef } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import { toast } from "../../store/useToastStore.js";
import { confirm } from "../../store/useConfirmStore.js";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result.js";
import { cleanupAiSecretLifecycle } from "../../utils/ai-secret-lifecycle.js";
import DraggableResizableModal from "../primitives/DraggableResizableModal.jsx";

/**
 * AI Secret & Leak Scan — runs the main-process credential/key/PII detector over an AI history
 * tab and presents findings (redacted by default, reveal per-row).
 *
 * UI: enterprise "liquid glass" surfaces + a Unit 42 / threat-report severity palette (th.sev),
 * progressive disclosure (severity-driven hero → one toolbar → incident list → expand for evidence/
 * tags/actions). Findings can be grouped by incident, tool, session or tag; provider badges aid
 * scanning; and an exposure brief exports to PDF/HTML (redacted — cleartext never leaves memory).
 */

const CAT_LABELS = {
  "secret-cloud": "Cloud", "secret-scm": "Source control", "secret-ai": "AI provider",
  "secret-payment": "Payment", "secret-messaging": "Messaging", "secret-generic": "Generic credential",
  "private-key": "Private key", "high-entropy": "High entropy", "pii": "PII",
};
const MAX_VISIBLE = 1000;
const MAX_VISIBLE_INCIDENTS = 500;
const DEFAULT_MODAL_HEIGHT = 720;
const TAG_PRESETS = ["Needs Rotation", "Confirmed Leak", "False Positive", "Revoked", "Sensitive Data"];
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_ORDER = ["critical", "high", "medium", "low"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", none: "Clean" };
const GROUP_MODES = [{ id: "incident", label: "Incident" }, { id: "tool", label: "Tool" }, { id: "session", label: "Session" }, { id: "tag", label: "Tag" }];

// Brand-tinted monogram badges (recognizable colors + initials — not trademarked logos) for fast
// visual scanning of finding provenance. Keyed by detection-rule id; falls back to a category glyph.
const PROVIDER_BRAND = {
  "aws-access-key": ["AWS", "#FF9900"], "aws-secret-key": ["AWS", "#FF9900"],
  "gcp-api-key": ["GCP", "#4285F4"], "gcp-oauth-secret": ["GCP", "#4285F4"],
  "azure-storage-conn": ["AZ", "#0078D4"], "do-pat": ["DO", "#0080FF"],
  "github-pat": ["GH", "#8b949e"], "github-fine-grained": ["GH", "#8b949e"],
  "gitlab-pat": ["GL", "#FC6D26"], "npm-token": ["npm", "#CB3837"], "pypi-token": ["PyPI", "#3775A9"],
  "openai-key": ["AI", "#10A37F"], "anthropic-key": ["An", "#CC785C"], "huggingface-token": ["HF", "#FFB000"],
  "stripe-live-key": ["S", "#635BFF"], "stripe-test-key": ["S", "#635BFF"],
  "sendgrid-key": ["SG", "#1A82E2"], "twilio-key": ["Tw", "#F22F46"],
  "slack-token": ["Sl", "#36C5F0"], "slack-webhook": ["Sl", "#36C5F0"], "telegram-bot-token": ["Tg", "#26A5E4"],
  "jwt": ["JWT", "#a371f7"],
};
const TOOL_BRAND = {
  "Claude Code": ["Cl", "#D97757"], "ChatGPT": ["GPT", "#10A37F"], "OpenAI Codex": ["Cx", "#2F6FED"],
  "Grok Build": ["Gr", "#8B5CF6"],
  "Gemini CLI": ["Gem", "#4285F4"], "Cursor": ["Cu", "#7d8590"], "GitHub Copilot": ["Co", "#8b949e"],
  "Windsurf": ["Ws", "#58a6ff"], "Continue": ["Ct", "#3fb950"],
};
function providerMeta(ruleId, category, th, sev) {
  const b = PROVIDER_BRAND[ruleId];
  if (b) return { abbr: b[0], color: b[1] };
  switch (category) {
    case "private-key": return { abbr: "KEY", color: sev.high };
    case "pii": return { abbr: "PII", color: sev.info };
    case "high-entropy": return { abbr: "H", color: sev.med };
    case "secret-generic": return { abbr: "•••", color: th.textDim };
    default: return { abbr: "?", color: th.textMuted };
  }
}
function toolMeta(tool, th) {
  const b = TOOL_BRAND[tool];
  if (b) return { abbr: b[0], color: b[1] };
  return { abbr: String(tool || "?").replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "?", color: th.textDim };
}

const clean = (v) => String(v || "").trim();
const uniq = (values) => [...new Set(values.map(clean).filter(Boolean))].sort((a, b) => a.localeCompare(b));
const tagList = (value) => Array.isArray(value) ? uniq(value) : [];
const normalizeTag = (tag) => clean(tag).replace(/\s+/g, " ").slice(0, 48);
const normalizeDisplayText = (v) => String(v ?? "")
  .replace(/\r\n/g, "\n")
  .replace(/\\\\r\\\\n/g, "\n")
  .replace(/\\\\n/g, "\n")
  .replace(/\\\\r/g, "\n")
  .replace(/\\r\\n/g, "\n")
  .replace(/\\n/g, "\n")
  .replace(/\\r/g, "\n")
  .replace(/\\t/g, "\t");
const isMultilineSecret = (text, category, title) =>
  String(category || "") === "private-key"
  || /PRIVATE KEY/i.test(String(title || ""))
  || /-----BEGIN [A-Z ]*PRIVATE KEY-----|-----END [A-Z ]*PRIVATE KEY-----|\n/.test(String(text || ""));
const setToText = (set, fallback = "—") => {
  const vals = [...set].filter(Boolean);
  return vals.length ? vals.join(", ") : fallback;
};
const safeName = (name) => clean(name).replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 80) || "ai-secret-scan";
const csvCell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
const htmlEsc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const plural = (n, one, many = `${one}s`) => `${Number(n || 0).toLocaleString()} ${Number(n || 0) === 1 ? one : many}`;
const withoutCleartext = (f) => {
  const { match, value, ...rest } = f || {};
  return rest;
};
const basename = (p) => (p ? String(p).split(/[\\/]/).pop() : "");

function makeAiSecretSalt(tabId) {
  const prefix = `ai-secret-scan:${tabId || "tab"}`;
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return `${prefix}:${crypto.randomUUID()}`;
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return `${prefix}:${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  }
  return `${prefix}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 12)}`;
}

function betterSeverity(a, b) {
  return (SEVERITY_RANK[a] || 0) >= (SEVERITY_RANK[b] || 0) ? a : b;
}
function minTs(a, b) { if (!a) return b || ""; if (!b) return a || ""; return a <= b ? a : b; }
function maxTs(a, b) { if (!a) return b || ""; if (!b) return a || ""; return a >= b ? a : b; }

function buildIncidentGroups(findings, tags = {}) {
  const map = new Map();
  for (const f of findings || []) {
    const key = f.fingerprint || `${f.ruleId}:${f.recordId}:${f.redacted}`;
    let g = map.get(key);
    if (!g) {
      g = {
        id: key, fingerprint: f.fingerprint || "", redacted: f.redacted || "",
        title: f.title || f.ruleId || "Finding", severity: f.severity || "info", findings: [],
        categories: new Set(), confidences: new Set(), tools: new Set(), roles: new Set(),
        sessions: new Set(), workspaces: new Set(), sourceFiles: new Set(), directions: new Set(),
        ruleIds: new Set(), firstSeen: f.timestamp || "", lastSeen: f.timestamp || "",
      };
      map.set(key, g);
    }
    g.findings.push(f);
    g.severity = betterSeverity(g.severity, f.severity || "info");
    if ((SEVERITY_RANK[f.severity] || 0) >= (SEVERITY_RANK[g.representative?.severity] || -1)) g.representative = f;
    if (f.category) g.categories.add(f.category);
    if (f.confidence) g.confidences.add(f.confidence);
    if (f.tool) g.tools.add(f.tool);
    if (f.role) g.roles.add(f.role);
    if (f.sessionId) g.sessions.add(f.sessionId);
    if (f.workspace) g.workspaces.add(f.workspace);
    if (f.sourceFile) g.sourceFiles.add(f.sourceFile);
    if (f.leakDirection) g.directions.add(f.leakDirection);
    if (f.ruleId) g.ruleIds.add(f.ruleId);
    g.firstSeen = minTs(g.firstSeen, f.timestamp || "");
    g.lastSeen = maxTs(g.lastSeen, f.timestamp || "");
  }
  return [...map.values()].map((g) => ({
    ...g, tags: tagList(tags[g.id]),
  })).sort((a, b) =>
    (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
    || b.findings.length - a.findings.length
    || String(a.firstSeen).localeCompare(String(b.firstSeen)));
}

// Re-bucket incident groups by an alternate lens (tool / session). An incident spanning multiple
// tools appears under each — this is a lens, not a partition.
function bucketGroups(groups, dimension) {
  const buckets = new Map();
  for (const g of groups) {
    const keys = dimension === "tool"
      ? [...g.tools]
      : dimension === "tag"
        ? tagList(g.tags)
        : [...g.sessions];
    const list = keys.length ? keys : [dimension === "tag" ? "(untagged)" : "(unknown)"];
    for (const k of list) {
      let b = buckets.get(k);
      if (!b) { b = { key: k, groups: [], severity: "info", bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, findingCount: 0 }; buckets.set(k, b); }
      b.groups.push(g);
      b.severity = betterSeverity(b.severity, g.severity);
      if (b.bySeverity[g.severity] != null) b.bySeverity[g.severity] += 1;
      b.findingCount += g.findings.length;
    }
  }
  return [...buckets.values()].sort((a, b) =>
    (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
    || b.groups.length - a.groups.length
    || String(a.key).localeCompare(String(b.key)));
}

// Lock-in-shield glyph, tinted by the run's highest severity (clean = green when nothing found).
function ShieldGlyph({ color, size = 26 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2.5l7 3v5c0 4.6-3 8-7 9.5-4-1.5-7-4.9-7-9.5v-5z" fill={`${color}1f`} />
      <rect x="9" y="10.5" width="6" height="5" rx="1.1" />
      <path d="M10.3 10.5V9.2a1.7 1.7 0 0 1 3.4 0v1.3" />
    </svg>
  );
}

function ProviderBadge({ abbr, color, size = 22 }) {
  const fs = abbr.length >= 4 ? 7.5 : abbr.length === 3 ? 8.5 : 10;
  return (
    <span style={{ display: "inline-grid", placeItems: "center", width: size, height: size, flexShrink: 0, borderRadius: 6, background: `${color}1f`, border: `1px solid ${color}55`, color, fontFamily: "'SF Mono',Menlo,monospace", fontWeight: 700, fontSize: fs, letterSpacing: "-0.02em" }}>{abbr}</span>
  );
}

function AiSecretsShell({ th, close, children, width = 520, height = DEFAULT_MODAL_HEIGHT, minWidth = 460, minHeight = 260 }) {
  return (
    <DraggableResizableModal defaultWidth={width} defaultHeight={height} minWidth={minWidth} minHeight={minHeight} onClose={close} closeOnOverlay={false} closeOnEscape={false} ariaLabel="AI Secret and Leak Scan">
      {({ startDrag, width: shellWidth, height: shellHeight }) => (
        <div style={{ height: "100%", display: "flex", flexDirection: "column", minHeight: 0 }}>
          {typeof children === "function" ? children({ width: shellWidth, height: shellHeight, startDrag }) : children}
        </div>
      )}
    </DraggableResizableModal>
  );
}

function resultsModalSize() {
  const vw = typeof window !== "undefined" ? window.innerWidth : 1280;
  const vh = typeof window !== "undefined" ? window.innerHeight : 820;
  const width = Math.max(720, vw - 48);
  const height = Math.max(560, vh - 48);
  return { width, height, minWidth: Math.min(720, width), minHeight: Math.min(520, height) };
}

export default function AiSecretsModal({ th }) {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const setActiveTab = useTabStore((s) => s.setActiveTab);
  const updateTab = useTabStore((s) => s.updateTab);
  const tabs = useTabStore((s) => s.tabs);
  const tle = typeof window !== "undefined" ? window.tle : null;
  const [progress, setProgress] = useState(null);
  const autoStartedRef = useRef(false);
  const lifecycleRef = useRef({});

  useEffect(() => {
    if (!tle?.onAnalysisProgress) return undefined;
    const unsub = tle.onAnalysisProgress((p) => { if (p && p.phase === "ai-secrets") setProgress(p); });
    return typeof unsub === "function" ? unsub : undefined;
  }, [tle]);

  useEffect(() => {
    if (!tle?.onAiSecretScanComplete) return undefined;
    return tle.onAiSecretScanComplete((payload) => {
      setModal((prev) => {
        if (!prev || prev.type !== "aiSecrets" || prev.jobId !== payload?.jobId) {
          if (payload?.result?.scanId) tle.releaseAiSecretScan?.(payload.result.scanId);
          return prev;
        }
        if (payload?.error) {
          return { ...prev, phase: "input", jobId: null, error: payload.cancelled ? "Scan cancelled." : payload.error };
        }
        return {
          ...prev,
          phase: "results", jobId: null, data: payload?.result || null, error: null, reveal: null,
          secretTags: useTabStore.getState().tabs.find((t) => t.id === prev.tabId)?.aiSecretTags || {},
          tagDraft: "", tagMenuGroup: null, expandedGroup: null,
          fSev: "all", fCat: "all", fConf: "all", fTool: "all", fRole: "all", fSession: "all",
          fWorkspace: "all", fSource: "all", fTag: "all", q: "", showFilters: false, collapsedBuckets: {},
        };
      });
    });
  }, [tle, setModal]);

  useEffect(() => () => {
    cleanupAiSecretLifecycle(tle, lifecycleRef.current);
  }, [tle]);

  const isOpen = modal?.type === "aiSecrets";

  useEffect(() => {
    if (!isOpen) { autoStartedRef.current = false; return; }
    if (modal.phase === "input" && modal.autoStart && !autoStartedRef.current && (tle?.startAiSecretScan || tle?.analyzeAiHistory) && modal.tabId) {
      autoStartedRef.current = true;
      runScan(modal.scanMode || "quick");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, modal?.phase, modal?.autoStart, modal?.tabId]);

  if (!isOpen) return null;

  const {
    phase = "input", tabName, scanMode = "quick", data, error, reveal = null, jobId = null, loadingMore = false,
    fSev = "all", fCat = "all", fConf = "all", fTool = "all", fRole = "all",
    fSession = "all", fWorkspace = "all", fSource = "all", fTag = "all",
    q = "", expandedGroup = null, secretTags = {}, tagDraft = "", tagMenuGroup = null, showFilters = false,
    groupBy = "incident", collapsedBuckets = {},
  } = modal;
  const tab = tabs.find((t) => t.id === modal.tabId);
  const tabSecretTags = tab?.aiSecretTags || {};
  const hasModalSecretTags = Object.prototype.hasOwnProperty.call(modal, "secretTags");
  const effectiveTags = hasModalSecretTags ? (secretTags || {}) : tabSecretTags;
  const patch = (updater) => setModal((prev) => {
    if (!prev || prev.type !== "aiSecrets") return prev;
    const p = typeof updater === "function" ? updater(prev) : updater;
    return p ? { ...prev, ...p } : prev;
  });
  lifecycleRef.current = { jobId: phase === "loading" ? jobId : null, scanId: data?.scanId || null };
  const close = () => {
    cleanupAiSecretLifecycle(tle, { jobId: phase === "loading" ? jobId : null, scanId: data?.scanId });
    lifecycleRef.current = {};
    setModal(null);
  };

  // ── Unit 42 / threat-report severity palette + liquid-glass style helpers ──
  const sev = th.sev || { critical: th.danger, high: th.warning, med: th.accent, low: th.textMuted, clean: th.success, info: "#58a6ff" };
  const sevColor = (s) => (s === "critical" ? sev.critical : s === "high" ? sev.high : s === "medium" ? sev.med : s === "low" ? sev.low : s === "info" ? sev.info : sev.clean);
  const glass = (extra = {}) => ({ background: th.glassBg, border: `1px solid ${th.glassBorder}`, borderRadius: 14, boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)", ...extra });
  const pill = (c, sm) => ({ display: "inline-flex", alignItems: "center", gap: 5, padding: sm ? "2px 8px" : "3px 10px", borderRadius: 999, fontSize: sm ? 9.5 : 10.5, fontWeight: 700, letterSpacing: "0.03em", color: c, background: `${c}1f`, border: `1px solid ${c}44`, textTransform: "uppercase", whiteSpace: "nowrap" });
  const softBtn = (active) => ({ display: "inline-flex", alignItems: "center", gap: 5, padding: "5px 11px", borderRadius: 9, fontSize: 11, fontWeight: 500, cursor: "pointer", color: active ? "#fff" : th.textDim, background: active ? th.accent : th.glassBg, border: `1px solid ${active ? th.accent : th.glassBorder}`, whiteSpace: "nowrap" });
  const tinyBtn = { display: "inline-flex", alignItems: "center", gap: 4, padding: "3px 9px", borderRadius: 7, fontSize: 10.5, fontWeight: 500, cursor: "pointer", color: th.textDim, background: th.glassBg, border: `1px solid ${th.glassBorder}`, whiteSpace: "nowrap" };
  const primaryBtn = { padding: "9px 20px", borderRadius: 11, fontSize: 12.5, fontWeight: 600, cursor: "pointer", color: "#fff", background: `linear-gradient(180deg, ${th.accentHover || th.accent}, ${th.accent})`, border: `1px solid ${th.accent}`, boxShadow: `0 4px 16px ${th.accent}40, inset 0 1px 0 rgba(255,255,255,0.22)` };
  const ghostBtn = { padding: "9px 16px", borderRadius: 11, fontSize: 12, fontWeight: 500, cursor: "pointer", color: th.textDim, background: "transparent", border: `1px solid ${th.glassBorder}` };
  const segWrap = { display: "inline-flex", padding: 3, gap: 2, ...glass({ borderRadius: 10 }) };
  const segItem = (active) => ({ padding: "5px 11px", borderRadius: 8, fontSize: 11, fontWeight: 600, cursor: "pointer", border: "1px solid transparent", color: active ? "#fff" : th.textMuted, background: active ? th.accent : "transparent", whiteSpace: "nowrap" });
  const provMeta = (ruleId, category) => providerMeta(ruleId, category, th, sev);
  // Confidence chip — only surfaced when it changes triage: trust ("verified") or caution
  // ("heuristic"/"entropy"). The common distinctive-token case ("pattern") gets no chip.
  const CONF_META = {
    verified: { label: "Verified", color: sev.clean, title: "Structurally validated (checksum / entropy) — high confidence" },
    heuristic: { label: "Heuristic", color: sev.high, title: "Keyword-anchored guess — review for false positives" },
    entropy: { label: "Entropy", color: sev.info, title: "High-entropy string — possible unknown secret" },
    "entropy+context": { label: "Entropy", color: sev.info, title: "High-entropy string near a secret keyword" },
  };
  const confChip = (conf) => {
    const m = CONF_META[conf];
    if (!m) return null;
    return <span title={m.title} style={{ ...pill(m.color, true), textTransform: "none", fontWeight: 600 }}>{m.label}</span>;
  };
  const directionBadge = (dir) => {
    const out = dir === "user→service";
    const color = out ? sev.high : th.textMuted;
    return <span key={dir} title={out ? "Subject pasted a secret into a third-party AI service" : "The model returned a secret in its reply"} style={{ ...pill(color, true), textTransform: "none", fontWeight: 600 }}>{out ? "↗" : "↘"} {dir}</span>;
  };

  // ── handlers ──
  const runScan = async (mode = scanMode) => {
    if (!(tle?.startAiSecretScan || tle?.analyzeAiHistory) || !modal.tabId) { toast.error("No AI history tab to scan"); return; }
    if (data?.scanId) await tle.releaseAiSecretScan?.(data.scanId);
    patch({ phase: "loading", scanMode: mode, error: null, autoStart: false, data: null, reveal: null, jobId: null });
    setProgress(null);
    try {
      const salt = tab?.aiSecretSalt || makeAiSecretSalt(modal.tabId);
      if (!tab?.aiSecretSalt) updateTab(modal.tabId, { aiSecretSalt: salt });
      const r = tle.startAiSecretScan
        ? await tle.startAiSecretScan(modal.tabId, { mode, salt })
        : { result: await tle.analyzeAiHistory(modal.tabId, { mode, salt }) };
      if (isIpcError(r)) { patch({ phase: "input", error: ipcErrorMessage(r) }); return; }
      if (r?.error) { patch({ phase: "input", error: r.error }); return; }
      if (r?.jobId) {
        patch({ jobId: r.jobId });
        return;
      }
      const result = r?.result;
      patch({
        phase: "results", data: result, jobId: null, error: null, reveal: null, secretTags: tabSecretTags, tagDraft: "", tagMenuGroup: null, expandedGroup: null,
        fSev: "all", fCat: "all", fConf: "all", fTool: "all", fRole: "all", fSession: "all",
        fWorkspace: "all", fSource: "all", fTag: "all", q: "", showFilters: false, collapsedBuckets: {},
      });
    } catch (e) {
      patch({ phase: "input", error: String(e?.message || e || "Scan failed") });
    }
  };

  const showInGrid = (f) => {
    if (!modal.tabId || !f.recordId) return;
    setActiveTab(modal.tabId);
    updateTab(modal.tabId, { columnFilters: { RecordId: String(f.recordId) }, searchTerm: "", searchHighlight: false });
    close();
    toast.success("Filtered to finding", { detail: `${f.title} · RecordId ${f.recordId}` });
  };
  const copyText = async (text, label = "Copied") => {
    try { await navigator.clipboard?.writeText?.(String(text || "")); toast.success(label); }
    catch (e) { toast.error("Copy failed", { detail: String(e?.message || e) }); }
  };
  const confirmReveal = async (finding) => {
    if (!finding?.findingId || !data?.scanId || !tle?.revealAiSecret) return;
    if (reveal?.findingId === finding.findingId) {
      patch({ reveal: null });
      return;
    }
    const approved = await confirm({
      title: "Reveal cleartext secret?",
      message: "This reads and displays one sensitive value from source evidence. Continue only if screen exposure is acceptable.",
      confirmLabel: "Reveal",
      destructive: true,
    });
    if (!approved) return;
    const result = await tle.revealAiSecret(data.scanId, finding.findingId);
    if (isIpcError(result) || result?.error) {
      toast.error("Reveal failed", { detail: isIpcError(result) ? ipcErrorMessage(result) : result.error });
      return;
    }
    patch({ reveal: { findingId: result.findingId, value: result.value } });
  };

  const loadMoreFindings = async () => {
    if (!data?.scanId || !data?.page?.hasMore || loadingMore || !tle?.getAiSecretResultsPage) return;
    patch({ loadingMore: true });
    try {
      const offset = Number(data.page.offset || 0) + Number(data.page.returned || data.findings?.length || 0);
      const next = await tle.getAiSecretResultsPage(data.scanId, offset, 1000);
      if (isIpcError(next) || next?.error) throw new Error(isIpcError(next) ? ipcErrorMessage(next) : next.error);
      patch((prev) => ({
        loadingMore: false,
        data: { ...prev.data, findings: [...(prev.data?.findings || []), ...(next.findings || [])], page: next },
      }));
    } catch (err) {
      patch({ loadingMore: false });
      toast.error("Could not load more findings", { detail: String(err?.message || err) });
    }
  };
  const openSource = async (f) => {
    if (!f?.sourceFile || !tle?.openAiSource) { toast.error("No source file recorded for this evidence row"); return; }
    const r = await tle.openAiSource(f.sourceFile, f.lineNumber || "");
    if (isIpcError(r)) toast.error("Open source failed", { detail: ipcErrorMessage(r) });
  };
  const sourceRowIds = (findings) => [...new Set((findings || []).map((f) => Number(f.rowId || f.recordId)).filter((n) => Number.isInteger(n) && n > 0))];
  const bookmarkRows = async (findings) => {
    const ids = sourceRowIds(findings);
    if (!ids.length || !modal.tabId || !tle?.setBookmarks) { toast.error("No source rows available to bookmark"); return; }
    await tle.setBookmarks(modal.tabId, ids, true);
    toast.success("Bookmarked source rows", { detail: `${ids.length.toLocaleString()} row${ids.length === 1 ? "" : "s"}` });
  };
  const tagRows = async (findings, tag = "AI Secret Leak", notify = true) => {
    const ids = sourceRowIds(findings);
    if (!ids.length || !modal.tabId || !tle?.bulkAddTags) {
      if (notify) toast.error("No source rows available to tag");
      return false;
    }
    const tagMap = {};
    for (const id of ids) tagMap[id] = [tag];
    await tle.bulkAddTags(modal.tabId, tagMap);
    const rowTags = { ...(tab?.rowTags || {}) };
    for (const id of ids) rowTags[id] = uniq([...(rowTags[id] || []), tag]);
    updateTab(modal.tabId, { rowTags, tagColors: { ...(tab?.tagColors || {}), [tag]: tab?.tagColors?.[tag] || th.accent } });
    if (notify) toast.success("Tagged source rows", { detail: `${ids.length.toLocaleString()} row${ids.length === 1 ? "" : "s"} · ${tag}` });
    return true;
  };
  const untagRows = async (findings, tag, notify = true) => {
    const ids = sourceRowIds(findings);
    if (!ids.length || !modal.tabId || !tle?.removeTag) {
      if (notify) toast.error("No source rows available to untag");
      return false;
    }
    // One transaction, not one IPC round trip per finding row.
    if (tle.setTagOnRows) await tle.setTagOnRows(modal.tabId, ids, tag, false);
    else for (const id of ids) await tle.removeTag(modal.tabId, id, tag);
    const rowTags = { ...(tab?.rowTags || {}) };
    for (const id of ids) {
      const next = (rowTags[id] || []).filter((t) => t !== tag);
      if (next.length) rowTags[id] = next;
      else delete rowTags[id];
    }
    updateTab(modal.tabId, { rowTags });
    if (notify) toast.success("Removed source-row tag", { detail: `${ids.length.toLocaleString()} row${ids.length === 1 ? "" : "s"} · ${tag}` });
    return true;
  };
  const setGroupTags = (g, tags) => {
    const nextTags = tagList(tags.map(normalizeTag));
    const next = { ...(effectiveTags || {}) };
    if (nextTags.length) next[g.id] = nextTags;
    else delete next[g.id];
    patch({ secretTags: next });
    if (modal.tabId) updateTab(modal.tabId, { aiSecretTags: next });
    return nextTags;
  };
  const addGroupTag = async (g, tag) => {
    const finalTag = normalizeTag(tag);
    if (!finalTag) return;
    const nextTags = setGroupTags(g, [...(g.tags || []), finalTag]);
    const appliedRows = await tagRows(g.findings, finalTag, false);
    patch({ tagDraft: "", tagMenuGroup: null });
    toast.success("Tagged incident", { detail: appliedRows ? `${finalTag} · ${sourceRowIds(g.findings).length.toLocaleString()} source row${sourceRowIds(g.findings).length === 1 ? "" : "s"}` : `${finalTag} · ${nextTags.length} tag${nextTags.length === 1 ? "" : "s"}` });
  };
  const removeGroupTag = async (g, tag) => {
    setGroupTags(g, (g.tags || []).filter((t) => t !== tag));
    if (fTag === tag && groups.filter((item) => item.id !== g.id && (item.tags || []).includes(tag)).length === 0) patch({ fTag: "all" });
    await untagRows(g.findings, tag, false);
    toast.success("Removed incident tag", { detail: `${tag} · source rows synced` });
  };

  // ── INPUT (chooser — shown on "New scan"; first open auto-runs past it) ──
  if (phase === "input") {
    const card = (active, title, desc, onClick) => (
      <button type="button" onClick={onClick} style={glass({ flex: 1, padding: "14px 14px", textAlign: "left", cursor: "pointer", borderColor: active ? th.accent : th.glassBorder, background: active ? `${th.accent}14` : th.glassBg })}>
        <div style={{ fontWeight: 700, fontSize: 13, color: active ? th.accent : th.text }}>{title}</div>
        <div style={{ fontSize: 11, color: th.textMuted, marginTop: 4, lineHeight: 1.4 }}>{desc}</div>
      </button>
    );
    return (
      <AiSecretsShell th={th} close={close} height={400} minHeight={360} width={560} minWidth={460}>
        {({ startDrag }) => (
          <div style={{ padding: 26, display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
            <div onMouseDown={startDrag} style={{ display: "flex", alignItems: "center", gap: 12, cursor: "grab", userSelect: "none" }}>
              <span style={glass({ width: 44, height: 44, borderRadius: 12, display: "grid", placeItems: "center", flexShrink: 0, background: `${th.accent}14`, borderColor: `${th.accent}44` })}><ShieldGlyph color={th.accent} /></span>
              <div>
                <div style={{ fontSize: 16, fontWeight: 700, color: th.text }}>AI Secret Hunt</div>
                <div style={{ fontSize: 11.5, color: th.textMuted, marginTop: 2 }}>Hunt for leaked secrets, API keys, private keys &amp; PII in <strong style={{ color: th.textDim }}>{tabName || "this AI history tab"}</strong></div>
              </div>
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
              {card(scanMode === "quick", "Quick", "Validated API keys, tokens, private keys & hardcoded credentials. Precision-first.", () => patch({ scanMode: "quick" }))}
              {card(scanMode === "deep", "Deep", "Adds PII (email, SSN, cards) & high-entropy unknown secrets. More to review.", () => patch({ scanMode: "deep" }))}
            </div>
            <div style={{ fontSize: 11.5, color: th.textDim, marginTop: 18, ...glass({ padding: "9px 11px", borderRadius: 9 }) }}>
              🔒 Results and exports are always redacted. Reveal reads one verified value from source evidence at a time.
            </div>
            {error && <div style={{ fontSize: 11.5, color: sev.critical, marginTop: 14, ...glass({ padding: "8px 10px", borderColor: `${sev.critical}55`, background: `${sev.critical}14` }) }}>{error}</div>}
            <div style={{ marginTop: "auto", paddingTop: 18, display: "flex", justifyContent: "flex-end", gap: 10 }}>
              <button type="button" onClick={close} style={ghostBtn}>Cancel</button>
              <button type="button" onClick={() => runScan(scanMode)} style={primaryBtn}>Run {scanMode} scan</button>
            </div>
          </div>
        )}
      </AiSecretsShell>
    );
  }

  // ── LOADING ──
  if (phase === "loading") {
    const pct = progress?.total ? Math.min(100, Math.round((progress.processed / progress.total) * 100)) : null;
    return (
      <AiSecretsShell th={th} close={close} height={280} minHeight={240} width={520} minWidth={440}>
        {({ startDrag }) => (
          <div style={{ padding: 28, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", textAlign: "center" }} onMouseDown={startDrag}>
            <span style={{ animation: "tle-pulse 1.4s ease-in-out infinite" }}><ShieldGlyph color={th.accent} size={42} /></span>
            <div style={{ fontSize: 14, fontWeight: 600, color: th.text, marginTop: 14 }}>Scanning for leaked secrets…</div>
            <div style={{ fontSize: 11.5, color: th.textMuted, marginTop: 6 }}>
              {progress?.total ? `${progress.processed.toLocaleString()} / ${progress.total.toLocaleString()} messages${pct != null ? ` · ${pct}%` : ""}` : `Analyzing ${tabName || "messages"}…`}
            </div>
            <div style={{ width: "80%", height: 5, background: th.glassBg, border: `1px solid ${th.glassBorder}`, borderRadius: 3, overflow: "hidden", marginTop: 16 }}>
              <div style={{ width: pct != null ? `${pct}%` : "42%", height: "100%", background: `linear-gradient(90deg, ${th.accent}, ${th.accentHover || th.accent})`, borderRadius: 3, transition: "width .25s", animation: pct == null ? "tle-pulse 1.2s ease-in-out infinite" : "none" }} />
            </div>
            <button type="button" onMouseDown={(e) => e.stopPropagation()} onClick={close} style={{ ...ghostBtn, marginTop: 18 }}>Cancel scan</button>
          </div>
        )}
      </AiSecretsShell>
    );
  }

  // ── RESULTS ──
  const summary = data?.summary || { total: 0, bySeverity: {}, byCategory: {}, byConfidence: {}, mitre: [], flaggedRows: 0, uniqueSecrets: 0, severity: "info" };
  const all = data?.findings || [];
  const summaryOnlyRows = Number(data?.rowsSummaryOnly || 0);
  const coverageComplete = data?.coverage?.complete !== false;
  const fullTextLimited = !!data && (!coverageComplete || data.fullTextAvailable === false || summaryOnlyRows > 0);
  const fullTextWarning = data?.fullTextAvailable === false
    ? "This tab stores only a 500-char preview per message — secrets beyond the preview may be missed. Re-import the collection to scan full content."
    : `${summaryOnlyRows.toLocaleString()} message${summaryOnlyRows === 1 ? "" : "s"} only had the 500-char preview; secrets beyond those may be missed.`;
  const totalStored = Number(data?.page?.totalStored ?? data?.storedFindings ?? all.length);
  const pageHasMore = !!data?.page?.hasMore;
  const resultCapReached = !!data?.resultsTruncated;
  const groups = buildIncidentGroups(all, effectiveTags);
  const ql = q.trim().toLowerCase();
  const groupTextOf = (g) => [
    g.title, g.redacted, g.fingerprint, ...(g.tags || []), setToText(g.ruleIds), setToText(g.tools), setToText(g.roles),
    setToText(g.sessions), setToText(g.workspaces), setToText(g.sourceFiles),
    ...g.findings.map((f) => `${f.snippet} ${f.recordId} ${f.messageId}`),
  ].join(" ").toLowerCase();
  const filteredGroups = groups.filter((g) =>
    (fSev === "all" || g.severity === fSev)
    && (fCat === "all" || g.categories.has(fCat))
    && (fConf === "all" || g.confidences.has(fConf))
    && (fTool === "all" || g.tools.has(fTool))
    && (fRole === "all" || g.roles.has(fRole))
    && (fSession === "all" || g.sessions.has(fSession))
    && (fWorkspace === "all" || g.workspaces.has(fWorkspace))
    && (fSource === "all" || g.sourceFiles.has(fSource))
    && (fTag === "all" || (g.tags || []).includes(fTag))
    && (!ql || groupTextOf(g).includes(ql)));
  const visibleGroups = filteredGroups.slice(0, MAX_VISIBLE_INCIDENTS);
  const affectedSessions = new Set(all.map((f) => f.sessionId).filter(Boolean)).size;
  const affectedTools = new Set(all.map((f) => f.tool).filter(Boolean)).size;
  const highest = summary.severity && summary.severity !== "info" ? summary.severity : "none";
  const heroColor = sevColor(highest === "none" ? "clean" : highest);

  const filterOptions = {
    category: Object.keys(summary.byCategory || {}).sort(),
    confidence: uniq(all.map((f) => f.confidence)),
    tool: uniq(all.map((f) => f.tool)),
    role: uniq(all.map((f) => f.role)),
    session: uniq(all.map((f) => f.sessionId)),
    workspace: uniq(all.map((f) => f.workspace)),
    source: uniq(all.map((f) => f.sourceFile)),
    tag: uniq(groups.flatMap((g) => g.tags || [])),
  };
  const advKeys = ["fCat", "fConf", "fTool", "fRole", "fSession", "fWorkspace", "fSource", "fTag"];
  const advActive = [fCat, fConf, fTool, fRole, fSession, fWorkspace, fSource, fTag].filter((v) => v && v !== "all").length;
  const tagCounts = Object.fromEntries(filterOptions.tag.map((tag) => [tag, groups.filter((g) => (g.tags || []).includes(tag)).length]));
  const tagFindingCounts = Object.fromEntries(filterOptions.tag.map((tag) => [tag, groups.reduce((n, g) => n + ((g.tags || []).includes(tag) ? g.findings.length : 0), 0)]));
  const taggedIncidentCount = groups.filter((g) => (g.tags || []).length > 0).length;

  const crit = summary.bySeverity.critical || 0;
  const high = summary.bySeverity.high || 0;
  const headline = crit ? `${crit} critical secret${crit === 1 ? "" : "s"} exposed`
    : high ? `${high} high-severity secret${high === 1 ? "" : "s"} found`
      : summary.total ? `${summary.total} potential secret${summary.total === 1 ? "" : "s"} found`
        : coverageComplete ? "No leaked secrets detected" : "No secrets detected in covered evidence";
  const sevTotal = SEV_ORDER.reduce((n, s) => n + (summary.bySeverity[s] || 0), 0) || 1;

  const exportRowsForGroups = (groupsToExport) => groupsToExport.flatMap((g) => g.findings.map((f) => ({ incidentId: g.id, tags: (g.tags || []).join("; "), ...withoutCleartext(f) })));
  const exportCsv = async ({ tagOnly = false } = {}) => {
    const groupsToExport = tagOnly && fTag !== "all"
      ? groups.filter((g) => (g.tags || []).includes(fTag))
      : filteredGroups;
    const exportRows = exportRowsForGroups(groupsToExport);
    const headers = ["IncidentId", "Tags", "Severity", "Confidence", "Category", "RuleId", "Title", "Redacted", "Fingerprint", "RecordId", "Timestamp", "Tool", "Role", "SessionId", "Workspace", "SourceFile", "LineNumber", "LeakDirection", "Snippet"];
    const lines = exportRows.map((r) => [r.incidentId, r.tags, r.severity, r.confidence, r.category, r.ruleId, r.title, r.redacted, r.fingerprint, r.recordId, r.timestamp, r.tool, r.role, r.sessionId, r.workspace, r.sourceFile, r.lineNumber, r.leakDirection, r.snippet].map(csvCell).join(","));
    const suffix = tagOnly && fTag !== "all" ? `tag-${safeName(fTag)}` : "filtered";
    const res = await tle?.saveAiSecretExport?.([headers.join(","), ...lines].join("\n"), `${safeName(tabName)}-ai-secret-scan-${suffix}-redacted.csv`, [{ name: "CSV", extensions: ["csv"] }]);
    if (res?.filePath) toast.success(tagOnly && fTag !== "all" ? `Exported ${fTag} CSV` : "Exported redacted CSV", { detail: res.filePath });
  };
  const exportJson = async () => {
    const payload = {
      tabName, scanMode, exportedAt: new Date().toISOString(),
      coverage: data?.coverage || { fullTextAvailable: data?.fullTextAvailable, rowsWithFullText: data?.rowsWithFullText || 0, rowsSummaryOnly: data?.rowsSummaryOnly || 0 },
      exportScope: { loadedFindings: all.length, storedFindings: totalStored, totalFindings: summary.total, resultCapReached },
      summary,
      incidents: filteredGroups.map((g) => ({
        incidentId: g.id, fingerprint: g.fingerprint, redacted: g.redacted, severity: g.severity, title: g.title,
        tags: g.tags || [], timestamp: g.firstSeen, count: g.findings.length,
        categories: [...g.categories], tools: [...g.tools], roles: [...g.roles], sessions: [...g.sessions],
        workspaces: [...g.workspaces], sourceFiles: [...g.sourceFiles], leakDirections: [...g.directions],
        evidence: g.findings.map(withoutCleartext),
      })),
    };
    const res = await tle?.saveAiSecretExport?.(JSON.stringify(payload, null, 2), `${safeName(tabName)}-ai-secret-scan-redacted.json`, [{ name: "JSON", extensions: ["json"] }]);
    if (res?.filePath) toast.success("Exported redacted JSON", { detail: res.filePath });
  };

  // ── Exposure brief (redacted) — threat-report styling, exported as real PDF or self-contained HTML.
  const buildReportHtml = () => {
    const RS = { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#6b7280", info: "#2563eb", clean: "#16a34a" };
    const rc = (s) => RS[s] || RS.low;
    const now = new Date().toISOString().replace("T", " ").slice(0, 19);
    const sb = summary.bySeverity || {};
    const verdictColor = highest === "none" ? RS.clean : rc(highest);
    const stat = (val, label, color) => `<div class="stat" style="border-top:3px solid ${color}"><div class="sv" style="color:${color}">${htmlEsc(val)}</div><div class="sl">${htmlEsc(label)}</div></div>`;
    const sevBar = SEV_ORDER.filter((s) => sb[s]).map((s) => `<div style="width:${((sb[s] || 0) / sevTotal) * 100}%;background:${rc(s)}"></div>`).join("");
    const toolBuckets = bucketGroups(filteredGroups, "tool");
    const toolRows = toolBuckets.map((b) => `<tr><td>${htmlEsc(b.key)}</td><td>${b.groups.length}</td><td style="color:${RS.critical}">${b.bySeverity.critical || 0}</td><td style="color:${RS.high}">${b.bySeverity.high || 0}</td><td style="color:${RS.medium}">${b.bySeverity.medium || 0}</td><td>${b.bySeverity.low || 0}</td></tr>`).join("");
    const mitreRows = (summary.mitre || []).map((m) => `<tr><td><code>${htmlEsc(m.id)}</code></td><td>${htmlEsc(m.name)}</td><td>${htmlEsc(m.count)}</td></tr>`).join("");
    const incRows = filteredGroups.map((g) => `<tr>
      <td><span class="badge" style="background:${rc(g.severity)}">${htmlEsc(SEV_LABEL[g.severity])}</span></td>
      <td>${htmlEsc(g.title)}<div class="cat">${htmlEsc([...g.categories].map((x) => CAT_LABELS[x] || x).join(", "))}</div></td>
      <td><code>${htmlEsc(g.redacted)}</code></td>
      <td>${htmlEsc([...g.confidences].join(", ") || "—")}</td>
      <td>${htmlEsc(setToText(g.directions, "—"))}</td>
      <td>${htmlEsc(setToText(g.tools, "—"))}</td>
      <td>${htmlEsc(g.firstSeen || "—")}</td>
      <td>${g.findings.length}</td>
      <td>${htmlEsc((g.tags || []).join(", ") || "—")}</td>
    </tr>`).join("");
    const coverageNote = fullTextLimited ? `<p class="warn">⚠ ${htmlEsc(fullTextWarning)}</p>` : "";
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>AI Secret Hunt — Exposure Brief — ${htmlEsc(tabName)}</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;color:#1c1917;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,sans-serif;font-size:12px;line-height:1.5}
.band{background:#0b0d10;color:#fff;padding:26px 40px;display:flex;align-items:center;gap:16px;border-bottom:4px solid #E85D2A}
.band .mark{width:46px;height:46px;border-radius:12px;background:rgba(232,93,42,0.18);border:1px solid rgba(232,93,42,0.5);display:grid;place-items:center;flex-shrink:0}
.band h1{font-size:21px;font-weight:700;letter-spacing:-0.01em}
.band .sub{font-size:11.5px;color:#9a9590;margin-top:3px}
.wrap{padding:26px 40px}
.verdict{font-size:18px;font-weight:700;margin-bottom:4px}
.stats{display:flex;gap:10px;margin:14px 0 18px}
.stat{flex:1;background:#f7f5f3;border:1px solid #e5e0db;border-radius:8px;padding:13px 10px;text-align:center}
.sv{font-size:21px;font-weight:700;line-height:1.1}
.sl{font-size:9px;text-transform:uppercase;letter-spacing:0.05em;color:#6b6560;margin-top:4px}
.sevbar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:#eee;margin-bottom:20px}
h2{font-size:13px;font-weight:700;margin:22px 0 8px;padding:6px 10px;background:#f7f5f3;border-radius:5px}
table{width:100%;border-collapse:collapse;font-size:11px}
th{text-align:left;padding:6px 9px;background:#f3f0ec;color:#6b6560;font-weight:700;border-bottom:1px solid #e5e0db;font-size:9.5px;text-transform:uppercase;letter-spacing:0.04em}
td{padding:6px 9px;border-bottom:1px solid #eee;vertical-align:top;word-break:break-word}
tr:nth-child(even) td{background:#fbfaf9}
code{font-family:"SF Mono",Menlo,monospace;font-size:10.5px;background:#f4f1ee;padding:1px 5px;border-radius:4px;color:#9a3412}
.cat{font-size:9px;color:#a09a94;margin-top:2px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9.5px;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:0.03em}
.warn{margin:8px 0;color:#b45309;font-size:11px}
.footer{margin-top:26px;padding:14px 40px;border-top:1px solid #e5e0db;color:#a09a94;font-size:10px;text-align:center}
@page{margin:14mm}
</style></head><body>
<div class="band">
  <div class="mark"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="1.6"><path d="M12 2.5l7 3v5c0 4.6-3 8-7 9.5-4-1.5-7-4.9-7-9.5v-5z" fill="rgba(232,93,42,0.18)"/><rect x="9" y="10.5" width="6" height="5" rx="1.1"/><path d="M10.3 10.5V9.2a1.7 1.7 0 0 1 3.4 0v1.3"/></svg></div>
  <div><h1>AI Secret Hunt — Exposure Brief</h1><div class="sub">${htmlEsc(tabName || "AI history")} &nbsp;·&nbsp; ${htmlEsc(scanMode)} scan &nbsp;·&nbsp; generated ${now} UTC</div></div>
</div>
<div class="wrap">
  <div class="verdict" style="color:${verdictColor}">${htmlEsc(headline)}</div>
  ${coverageNote}
  <div class="stats">
    ${stat(summary.total.toLocaleString(), "Findings", "#1c1917")}
    ${stat(summary.uniqueSecrets.toLocaleString(), "Unique secrets", "#1c1917")}
    ${stat(affectedSessions.toLocaleString(), "Sessions", "#1c1917")}
    ${stat(affectedTools.toLocaleString(), "Tools", "#1c1917")}
    ${stat((sb.critical || 0).toLocaleString(), "Critical", RS.critical)}
    ${stat((sb.high || 0).toLocaleString(), "High", RS.high)}
  </div>
  ${summary.total > 0 ? `<div class="sevbar">${sevBar}</div>` : ""}
  <h2>Exposure by tool</h2>
  <table><tr><th>Tool</th><th>Incidents</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>${toolRows || `<tr><td colspan="6">No findings.</td></tr>`}</table>
  ${mitreRows ? `<h2>MITRE ATT&CK</h2><table><tr><th>Technique</th><th>Name</th><th>Findings</th></tr>${mitreRows}</table>` : ""}
  <h2>Findings (redacted)</h2>
  <table><tr><th>Severity</th><th>Type</th><th>Secret</th><th>Confidence</th><th>Direction</th><th>Tool</th><th>Timestamp</th><th>Count</th><th>Tags</th></tr>${incRows || `<tr><td colspan="9">No findings match the current filters.</td></tr>`}</table>
</div>
<div class="footer">Generated by IRFlow Timeline · AI Secret Hunt · Secrets are redacted — cleartext is never written to this report.</div>
</body></html>`;
  };

  const exportReport = async (format) => {
    const html = buildReportHtml();
    if (format === "pdf") {
      if (!tle?.exportAiSecretsPdf) { toast.error("PDF export unavailable in this session"); return; }
      toast.info("Generating exposure brief…");
      const res = await tle.exportAiSecretsPdf(html, `${safeName(tabName)}-ai-secret-hunt-exposure-brief.pdf`);
      if (isIpcError(res)) { toast.error("PDF export failed", { detail: ipcErrorMessage(res) }); return; }
      if (res?.filePath) toast.success("Exposure brief (PDF) saved", { detail: res.filePath });
    } else {
      const res = await tle?.saveAiSecretExport?.(html, `${safeName(tabName)}-ai-secret-hunt-exposure-brief.html`, [{ name: "HTML", extensions: ["html"] }]);
      if (res?.filePath) toast.success("Exposure brief (HTML) saved", { detail: res.filePath });
    }
  };

  const glassSelect = (label, value, keyName, options, labeler = (v) => v) => (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 9.5, color: th.textMuted }}>
      <span style={{ textTransform: "uppercase", letterSpacing: "0.05em" }}>{label}</span>
      <select value={value} onChange={(e) => patch({ [keyName]: e.target.value })} style={{ background: th.bgInput, border: `1px solid ${th.glassBorder}`, color: th.text, fontSize: 11, padding: "6px 8px", borderRadius: 8, outline: "none" }}>
        <option value="all">All</option>
        {options.map((v) => <option key={v} value={v}>{labeler(v)}</option>)}
      </select>
    </label>
  );
  const resultsShell = resultsModalSize();

  const renderEvidence = (g) => {
    const rows = g.findings.slice(0, MAX_VISIBLE);
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 7, minWidth: 0, maxWidth: "100%" }}>
        {rows.map((f, i) => {
          const rowKey = f.findingId || `${g.id}:${f.recordId}:${i}`;
          const rowReveal = reveal?.findingId === f.findingId;
          const secretText = normalizeDisplayText(rowReveal ? reveal.value : f.redacted);
          const snippetText = normalizeDisplayText(f.snippet);
          const multiline = isMultilineSecret(secretText, f.category, f.title) || isMultilineSecret(snippetText, f.category, f.title);
          return (
            <div key={rowKey} style={glass({ padding: "9px 10px", borderRadius: 10, display: "flex", flexDirection: "column", gap: 6, minWidth: 0, maxWidth: "100%", boxSizing: "border-box", overflow: "hidden" })}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", fontSize: 9.5, color: th.textMuted }}>
                <span>{f.timestamp || "—"}</span>
                {f.tool && <span style={pill(th.textDim, true)}>{f.tool}</span>}
                {f.role && <span>· {f.role}</span>}
                {f.leakDirection && <span style={{ color: sev.high }}>· {f.leakDirection}</span>}
                {f.evidenceField && <span>· {f.evidenceField}</span>}
                <span style={{ marginLeft: "auto" }}>RecordId {f.recordId || "—"}</span>
              </div>
              <div style={{ fontFamily: "'SF Mono',Menlo,monospace", fontSize: 11, color: rowReveal ? sev.critical : th.text, whiteSpace: multiline ? "pre-wrap" : "normal", wordBreak: "break-word", overflowWrap: "anywhere", lineHeight: 1.45, maxWidth: "100%", minWidth: 0 }}>
                {secretText}
              </div>
              {f.snippet && <div style={{ fontSize: 10.5, color: th.textMuted, lineHeight: 1.45, whiteSpace: multiline ? "pre-wrap" : "normal", overflowWrap: "anywhere", wordBreak: "break-word", maxWidth: "100%", minWidth: 0 }}>{snippetText}</div>}
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", minWidth: 0, maxWidth: "100%" }}>
                {f.findingId && <button type="button" onClick={() => confirmReveal(f)} style={{ ...tinyBtn, color: rowReveal ? sev.critical : th.textDim, borderColor: rowReveal ? `${sev.critical}66` : th.glassBorder }}>{rowReveal ? "Hide" : "Reveal"}</button>}
                <button type="button" onClick={() => showInGrid(f)} disabled={!f.recordId} style={{ ...tinyBtn, opacity: f.recordId ? 1 : 0.4 }}>Show in grid</button>
                {f.sourceFile && <button type="button" onClick={() => openSource(f)} title={`${f.sourceFile}${f.lineNumber ? `:${f.lineNumber}` : ""}`} style={{ ...tinyBtn, maxWidth: "100%", whiteSpace: "normal", overflowWrap: "anywhere", wordBreak: "break-word", textAlign: "left" }}>Source · {f.sourceFile}{f.lineNumber ? `:${f.lineNumber}` : ""}</button>}
              </div>
            </div>
          );
        })}
        {g.findings.length > MAX_VISIBLE && <div style={{ fontSize: 10, color: th.textMuted }}>Showing first {MAX_VISIBLE.toLocaleString()} of {g.findings.length.toLocaleString()} occurrences.</div>}
      </div>
    );
  };

  const renderIncidentCard = (g) => {
    const isOpen = expandedGroup === g.id;
    const revealed = reveal?.findingId === g.representative?.findingId;
    const displayValue = revealed ? reveal.value : g.redacted;
    const displayText = normalizeDisplayText(displayValue);
    const c = sevColor(g.severity);
    const primaryCategory = [...g.categories][0] || "";
    const multiline = isMultilineSecret(displayText, primaryCategory, g.title);
    const pm = provMeta(g.representative?.ruleId, primaryCategory);
    const tagMenuOpen = tagMenuGroup === g.id;
    const presetTags = TAG_PRESETS.filter((tag) => !(g.tags || []).includes(tag));
    return (
      <div key={g.id} style={glass({ overflow: tagMenuOpen ? "visible" : "hidden", position: "relative", zIndex: tagMenuOpen ? 8 : "auto", borderColor: isOpen ? `${c}66` : th.glassBorder })}>
        <button type="button" onClick={() => patch({ expandedGroup: isOpen ? null : g.id })}
          style={{ width: "100%", display: "flex", alignItems: "center", gap: 11, padding: "11px 14px 11px 12px", background: "none", border: "none", cursor: "pointer", textAlign: "left" }}>
          <span style={{ ...pill(c, true), flexShrink: 0, width: 58, justifyContent: "center" }}>{SEV_LABEL[g.severity]}</span>
          <ProviderBadge {...pm} />
          <span style={{ minWidth: 0, flex: 1 }}>
            <span style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span style={{ fontSize: 12.5, fontWeight: 650, color: th.text }}>{g.title}</span>
              <span style={{ fontSize: 9.5, color: th.textMuted, padding: "1px 7px", borderRadius: 999, border: `1px solid ${th.glassBorder}`, background: th.glassBg, whiteSpace: "nowrap" }}>{[...g.categories].map((x) => CAT_LABELS[x] || x).join(", ")}</span>
              {confChip(g.representative?.confidence)}
              {g.findings.length > 1 && <span style={pill(th.textDim, true)}>×{g.findings.length}</span>}
              {(g.tags || []).slice(0, 3).map((tag) => <span key={tag} style={{ ...pill(th.accent, true), textTransform: "none" }}>{tag}</span>)}
            </span>
            <span style={{ display: "block", fontFamily: "'SF Mono',Menlo,monospace", fontSize: 11, color: th.textDim, marginTop: 3, wordBreak: "break-all" }}>{g.redacted}</span>
          </span>
          <span style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 3, flexShrink: 0, fontSize: 10, color: th.textMuted }}>
            <span>{[...g.tools].slice(0, 2).join(", ") || "—"}</span>
            {g.directions.size > 0 && <span style={{ display: "flex", gap: 4, flexWrap: "wrap", justifyContent: "flex-end" }}>{[...g.directions].map((d) => directionBadge(d))}</span>}
          </span>
          <span style={{ color: th.textMuted, fontSize: 12, flexShrink: 0, transform: isOpen ? "rotate(90deg)" : "none", transition: "transform .15s" }}>▸</span>
        </button>
        {isOpen && (
          <div style={{ padding: "4px 14px 14px", borderTop: `1px solid ${th.glassBorder}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", margin: "12px 0", minWidth: 0, maxWidth: "100%", position: "relative", zIndex: tagMenuOpen ? 6 : 1 }}>
              <div style={glass({ flex: "1 1 100%", minWidth: 0, maxWidth: "100%", padding: "8px 11px", borderRadius: 9, fontFamily: "'SF Mono',Menlo,monospace", fontSize: 11.5, color: revealed ? sev.critical : th.text, whiteSpace: multiline ? "pre-wrap" : "normal", wordBreak: "break-word", overflowWrap: "anywhere", lineHeight: 1.45, boxSizing: "border-box", overflow: "hidden" })}>
                {displayText}
              </div>
              {g.representative?.findingId && <button type="button" onClick={() => confirmReveal(g.representative)} style={{ ...tinyBtn, color: revealed ? sev.critical : th.textDim, borderColor: revealed ? `${sev.critical}66` : th.glassBorder }}>{revealed ? "Hide" : "Reveal"}</button>}
              <button type="button" onClick={() => g.representative && showInGrid(g.representative)} style={tinyBtn}>Show in grid</button>
              <button type="button" onClick={() => bookmarkRows(g.findings)} style={tinyBtn}>Bookmark</button>
              {(g.tags || []).map((tag) => (
                <span key={tag} style={{ display: "inline-flex", alignItems: "center", gap: 5, ...pill(th.accent, true), textTransform: "none", maxWidth: 180, overflow: "hidden" }}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{tag}</span>
                  <button type="button" onClick={() => removeGroupTag(g, tag)} title={`Remove ${tag}`} style={{ border: "none", background: "transparent", color: th.accent, cursor: "pointer", padding: 0, fontSize: 11, lineHeight: 1, flexShrink: 0 }}>×</button>
                </span>
              ))}
              <div style={{ position: "relative", display: "inline-flex" }}>
                <button type="button" onClick={() => patch({ tagMenuGroup: tagMenuOpen ? null : g.id, tagDraft: "" })}
                  title={(g.tags || []).length ? "Add another tag" : "Add a tag"}
                  style={{ ...tinyBtn, borderStyle: (g.tags || []).length || tagMenuOpen ? "solid" : "dashed", color: tagMenuOpen ? th.accent : th.textMuted, borderColor: tagMenuOpen ? `${th.accent}88` : th.glassBorder, background: tagMenuOpen ? `${th.accent}14` : "transparent" }}>
                  + Tag <span style={{ fontSize: 9, opacity: 0.7 }}>{tagMenuOpen ? "▴" : "▾"}</span>
                </button>
                {tagMenuOpen && (
                  <div style={glass({ position: "absolute", left: 0, top: "calc(100% + 6px)", width: 260, maxWidth: "min(260px, calc(100vw - 48px))", padding: 10, borderRadius: 10, background: th.bgElevated || th.bg || th.glassBg, boxShadow: th.shadowLg || "0 14px 35px rgba(0,0,0,0.18)", zIndex: 20 })}>
                    <div style={{ fontSize: 9.5, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 7 }}>Add Tag</div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <input value={tagDraft} onChange={(e) => patch({ tagDraft: e.target.value })} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addGroupTag(g, tagDraft); } }}
                        placeholder="Custom tag" autoFocus style={{ flex: 1, minWidth: 0, background: th.bgInput, color: th.text, border: `1px solid ${th.glassBorder}`, borderRadius: 8, padding: "6px 8px", fontSize: 11, outline: "none" }} />
                      <button type="button" onClick={() => addGroupTag(g, tagDraft)} disabled={!normalizeTag(tagDraft)} style={{ ...tinyBtn, opacity: normalizeTag(tagDraft) ? 1 : 0.45 }}>Add</button>
                    </div>
                    {presetTags.length > 0 && (
                      <div style={{ marginTop: 9, display: "flex", flexDirection: "column", gap: 4 }}>
                        {presetTags.map((tag) => (
                          <button key={tag} type="button" onClick={() => addGroupTag(g, tag)} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, width: "100%", padding: "6px 8px", borderRadius: 8, cursor: "pointer", color: th.textDim, background: "transparent", border: "1px solid transparent", textAlign: "left", fontSize: 11 }}>
                            <span>{tag}</span>
                            <span style={{ color: th.textMuted, fontSize: 10 }}>+</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
            <div style={{ fontSize: 9.5, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>
              Evidence · {g.findings.length} occurrence{g.findings.length === 1 ? "" : "s"}{g.findings.length > 1 && g.firstSeen ? (g.firstSeen === g.lastSeen ? ` · ${g.firstSeen}` : ` · ${g.firstSeen} → ${g.lastSeen}`) : ""}
            </div>
            {renderEvidence(g)}
          </div>
        )}
      </div>
    );
  };

  const renderBuckets = () => {
    const buckets = bucketGroups(filteredGroups, groupBy);
    let shown = 0;
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {buckets.map((b) => {
          const ckey = `${groupBy}:${b.key}`;
          const isCollapsed = !!collapsedBuckets[ckey];
          const bc = sevColor(b.severity);
          const tm = groupBy === "tool" ? toolMeta(b.key, th) : null;
          const bucketLabel = groupBy === "session" ? `Session ${b.key}` : groupBy === "tag" && b.key !== "(untagged)" ? `Tag ${b.key}` : b.key;
          const cards = [];
          if (!isCollapsed) {
            for (const g of b.groups) {
              if (shown >= MAX_VISIBLE_INCIDENTS) break;
              cards.push(renderIncidentCard(g));
              shown++;
            }
          }
          return (
            <div key={ckey} style={glass({ overflow: "hidden", borderColor: isCollapsed ? th.glassBorder : `${bc}55` })}>
              <button type="button" onClick={() => patch({ collapsedBuckets: { ...collapsedBuckets, [ckey]: !isCollapsed } })}
                style={{ width: "100%", display: "flex", alignItems: "center", gap: 11, padding: "10px 14px", background: `${bc}0f`, border: "none", cursor: "pointer", textAlign: "left" }}>
                {tm ? <ProviderBadge {...tm} size={24} /> : <span style={{ ...pill(bc, true), width: 54, justifyContent: "center" }}>{SEV_LABEL[b.severity]}</span>}
                <span style={{ minWidth: 0, flex: 1 }}>
                  <span style={{ fontSize: 13, fontWeight: 700, color: th.text, wordBreak: "break-all" }}>{bucketLabel}</span>
                  <span style={{ display: "block", fontSize: 10, color: th.textMuted, marginTop: 2 }}>
                    {b.groups.length} secret{b.groups.length === 1 ? "" : "s"} · {b.findingCount} finding{b.findingCount === 1 ? "" : "s"}
                    {b.bySeverity.critical ? ` · ${b.bySeverity.critical} critical` : ""}{b.bySeverity.high ? ` · ${b.bySeverity.high} high` : ""}
                  </span>
                </span>
                <span style={{ display: "flex", height: 5, width: 90, borderRadius: 3, overflow: "hidden", background: th.glassBg, flexShrink: 0 }}>
                  {SEV_ORDER.map((s) => (b.bySeverity[s] ? <span key={s} style={{ width: `${(b.bySeverity[s] / (b.groups.length || 1)) * 100}%`, background: sevColor(s) }} /> : null))}
                </span>
                <span style={{ color: th.textMuted, fontSize: 12, flexShrink: 0, transform: isCollapsed ? "none" : "rotate(90deg)", transition: "transform .15s" }}>▸</span>
              </button>
              {!isCollapsed && <div style={{ padding: "8px 12px 12px", display: "flex", flexDirection: "column", gap: 8 }}>{cards}</div>}
            </div>
          );
        })}
        {shown >= MAX_VISIBLE_INCIDENTS && <div style={{ fontSize: 10.5, color: th.textMuted, padding: "4px 2px" }}>Showing first {MAX_VISIBLE_INCIDENTS.toLocaleString()} incidents — narrow the filters to see the rest.</div>}
      </div>
    );
  };

  return (
    <AiSecretsShell key="results" th={th} close={close} {...resultsShell}>
      {({ startDrag }) => (
        <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
          {/* ── HERO ── */}
          <div onMouseDown={startDrag} style={{ flexShrink: 0, cursor: "grab", userSelect: "none", padding: "18px 20px 14px", borderBottom: `1px solid ${th.glassBorder}`, background: `linear-gradient(135deg, ${heroColor}1a, transparent 70%)` }}>
            <div style={{ display: "flex", alignItems: "flex-start", gap: 14 }}>
              <span style={glass({ width: 46, height: 46, borderRadius: 13, display: "grid", placeItems: "center", flexShrink: 0, background: `${heroColor}1f`, borderColor: `${heroColor}55` })}><ShieldGlyph color={heroColor} size={26} /></span>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 17, fontWeight: 700, color: th.text }}>{headline}</span>
                  {highest !== "none" && <span style={pill(heroColor)}>{SEV_LABEL[highest]}</span>}
                </div>
                <div style={{ fontSize: 11.5, color: th.textMuted, marginTop: 3 }}>
                  {tabName} · {scanMode} scan · {summary.total === summary.uniqueSecrets ? plural(summary.total, "secret") : `${plural(summary.total, "finding")} · ${summary.uniqueSecrets.toLocaleString()} unique`} · {plural(affectedSessions, "session")} · {plural(affectedTools, "tool")}
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }} onMouseDown={(e) => e.stopPropagation()}>
                <div style={segWrap}>
                  {["quick", "deep"].map((m) => (
                    <button key={m} type="button" onClick={() => m !== scanMode && runScan(m)} style={{ ...segItem(m === scanMode), textTransform: "capitalize" }}>{m}</button>
                  ))}
                </div>
                <button type="button" onClick={close} title="Close" style={{ ...tinyBtn, padding: "6px 9px" }}>✕</button>
              </div>
            </div>
            {summary.total > 0 && (
              <div style={{ display: "flex", height: 6, borderRadius: 4, overflow: "hidden", marginTop: 14, background: th.glassBg, border: `1px solid ${th.glassBorder}` }}>
                {SEV_ORDER.map((s) => {
                  const n = summary.bySeverity[s] || 0;
                  if (!n) return null;
                  return <div key={s} title={`${SEV_LABEL[s]}: ${n}`} style={{ width: `${(n / sevTotal) * 100}%`, background: sevColor(s) }} />;
                })}
              </div>
            )}
            {fullTextLimited && (
              <div style={{ marginTop: 12, fontSize: 10.5, color: sev.high, ...glass({ padding: "7px 10px", borderRadius: 9, background: `${sev.high}12`, borderColor: `${sev.high}40` }) }}>⚠ {fullTextWarning}</div>
            )}
          </div>

          {/* ── TOOLBAR ── */}
          {all.length > 0 && (
            <div style={{ flexShrink: 0, padding: "10px 20px", display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", borderBottom: `1px solid ${th.glassBorder}` }}>
              <button type="button" onClick={() => patch({ fSev: "all" })} style={softBtn(fSev === "all")}>All <span style={{ opacity: 0.7 }}>{groups.length}</span></button>
              {SEV_ORDER.filter((s) => summary.bySeverity[s]).map((s) => (
                <button key={s} type="button" onClick={() => patch({ fSev: fSev === s ? "all" : s })} style={{ ...softBtn(fSev === s), color: fSev === s ? "#fff" : sevColor(s), borderColor: fSev === s ? sevColor(s) : `${sevColor(s)}55`, background: fSev === s ? sevColor(s) : `${sevColor(s)}14` }}>
                  {SEV_LABEL[s]} <span style={{ opacity: 0.85 }}>{summary.bySeverity[s]}</span>
                </button>
              ))}
              {filterOptions.tag.length > 0 && (
                <>
                  <span style={{ fontSize: 9.5, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", marginLeft: 4 }}>Tags</span>
                  <button type="button" onClick={() => patch({ fTag: "all" })} style={{ ...softBtn(fTag === "all" && groupBy === "tag"), color: fTag === "all" ? th.textDim : th.textMuted }}>
                    All tags <span style={{ opacity: 0.8 }}>{taggedIncidentCount}</span>
                  </button>
                  {filterOptions.tag.slice(0, 6).map((tag) => (
                    <button key={tag} type="button" onClick={() => patch({ fTag: fTag === tag ? "all" : tag, groupBy: fTag === tag ? groupBy : "tag" })} style={{ ...softBtn(fTag === tag), color: fTag === tag ? "#fff" : th.accent, borderColor: fTag === tag ? th.accent : `${th.accent}55`, background: fTag === tag ? th.accent : `${th.accent}14` }}>
                      {tag} <span style={{ opacity: 0.8 }}>{tagCounts[tag]}/{tagFindingCounts[tag]}</span>
                    </button>
                  ))}
                </>
              )}
              <div style={{ ...segWrap, marginLeft: 4 }}>
                {GROUP_MODES.map((m) => <button key={m.id} type="button" onClick={() => patch({ groupBy: m.id })} style={segItem(groupBy === m.id)}>{m.label}</button>)}
              </div>
              <input value={q} onChange={(e) => patch({ q: e.target.value })} placeholder="Search secrets, tags, sources, sessions…"
                style={{ marginLeft: "auto", flex: "1 1 160px", maxWidth: 260, background: th.bgInput, border: `1px solid ${th.glassBorder}`, color: th.text, fontSize: 11.5, padding: "6px 11px", borderRadius: 9, outline: "none" }} />
              <button type="button" onClick={() => patch({ showFilters: !showFilters })} style={softBtn(showFilters || advActive > 0)}>Filters{advActive ? ` · ${advActive}` : ""}</button>
              <button type="button" onClick={() => exportReport("pdf")} style={{ ...tinyBtn, color: th.accent, borderColor: `${th.accent}66` }}>Report PDF</button>
              <button type="button" onClick={() => exportReport("html")} style={tinyBtn}>HTML</button>
              <button type="button" onClick={() => exportCsv()} style={tinyBtn}>CSV</button>
              {fTag !== "all" && <button type="button" onClick={() => exportCsv({ tagOnly: true })} style={{ ...tinyBtn, color: th.accent, borderColor: `${th.accent}66` }}>CSV · {fTag}</button>}
              <button type="button" onClick={exportJson} style={tinyBtn}>JSON</button>
            </div>
          )}

          {/* advanced filters */}
          {showFilters && all.length > 0 && (
            <div style={{ flexShrink: 0, padding: "12px 20px", borderBottom: `1px solid ${th.glassBorder}`, background: th.glassBg }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 10 }}>
                {glassSelect("Type", fCat, "fCat", filterOptions.category, (v) => CAT_LABELS[v] || v)}
                {glassSelect("Confidence", fConf, "fConf", filterOptions.confidence)}
                {glassSelect("Tag", fTag, "fTag", filterOptions.tag, (tag) => `${tag} (${plural(tagCounts[tag], "incident")} / ${plural(tagFindingCounts[tag], "finding")})`)}
                {glassSelect("Tool", fTool, "fTool", filterOptions.tool)}
                {glassSelect("Role", fRole, "fRole", filterOptions.role)}
                {glassSelect("Session", fSession, "fSession", filterOptions.session)}
                {glassSelect("Workspace", fWorkspace, "fWorkspace", filterOptions.workspace)}
                {glassSelect("Source", fSource, "fSource", filterOptions.source, (v) => basename(v) || v)}
              </div>
              {advActive > 0 && <button type="button" onClick={() => patch(Object.fromEntries(advKeys.map((k) => [k, "all"])))} style={{ ...tinyBtn, marginTop: 10 }}>Clear advanced filters</button>}
            </div>
          )}

          {/* ── BODY ── */}
          <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "14px 20px" }}>
            {all.length === 0 ? (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", textAlign: "center", gap: 10 }}>
                <ShieldGlyph color={sev.clean} size={48} />
                <div style={{ fontSize: 15, fontWeight: 600, color: th.text }}>{coverageComplete ? "No leaked secrets detected" : "No secrets detected in covered evidence"}</div>
                <div style={{ fontSize: 12, color: th.textMuted, maxWidth: 380 }}>
                  {!coverageComplete
                    ? "This is not an unqualified clean verdict because some messages only contained a preview. Re-import full content before relying on absence of findings."
                    : scanMode === "quick" ? "Quick scan covers validated keys, tokens and private keys. Run a Deep scan to also check PII and high-entropy strings." : "Deep scan found no credentials, PII or high-entropy secrets in this collection."}
                </div>
                {scanMode === "quick" && <button type="button" onClick={() => runScan("deep")} style={{ ...primaryBtn, marginTop: 6 }}>Run Deep scan</button>}
              </div>
            ) : filteredGroups.length === 0 ? (
              <div style={{ padding: 24, color: th.textMuted, fontSize: 12, textAlign: "center" }}>No incidents match the current filters.</div>
            ) : groupBy === "incident" ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {visibleGroups.map((g) => renderIncidentCard(g))}
                {filteredGroups.length > MAX_VISIBLE_INCIDENTS && (
                  <div style={{ fontSize: 10.5, color: th.textMuted, padding: "4px 2px" }}>Showing first {MAX_VISIBLE_INCIDENTS.toLocaleString()} of {filteredGroups.length.toLocaleString()} incidents — narrow the filters to see the rest.</div>
                )}
              </div>
            ) : renderBuckets()}
            {pageHasMore && (
              <div style={{ display: "flex", justifyContent: "center", padding: "14px 0 4px" }}>
                <button type="button" disabled={loadingMore} onClick={loadMoreFindings} style={{ ...ghostBtn, opacity: loadingMore ? 0.6 : 1 }}>
                  {loadingMore ? "Loading…" : `Load next page · ${all.length.toLocaleString()} of ${totalStored.toLocaleString()} stored`}
                </button>
              </div>
            )}
            {resultCapReached && (
              <div style={{ marginTop: 10, fontSize: 10.5, color: sev.high, ...glass({ padding: "7px 10px", borderRadius: 9, background: `${sev.high}12`, borderColor: `${sev.high}40` }) }}>
                The safety cap retained {totalStored.toLocaleString()} of {summary.total.toLocaleString()} findings. Occurrence and severity totals remain complete; narrow the evidence scope for occurrence-level review.
              </div>
            )}
          </div>

          {/* ── FOOTER ── */}
          <div style={{ flexShrink: 0, padding: "12px 20px", borderTop: `1px solid ${th.glassBorder}`, display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 10.5, color: th.textMuted }}>
              🔒 Findings and exports are permanently redacted · {all.length.toLocaleString()}/{totalStored.toLocaleString()} stored findings loaded · {filteredGroups.length.toLocaleString()}/{groups.length.toLocaleString()} loaded incidents
            </span>
            <div style={{ display: "flex", gap: 10 }}>
              <button type="button" onClick={async () => { if (data?.scanId) await tle?.releaseAiSecretScan?.(data.scanId); patch({ phase: "input", data: null, reveal: null, autoStart: false }); }} style={ghostBtn}>↻ New scan</button>
              <button type="button" onClick={close} style={primaryBtn}>Done</button>
            </div>
          </div>
        </div>
      )}
    </AiSecretsShell>
  );
}
