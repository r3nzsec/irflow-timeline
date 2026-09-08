import { TIMELINE_PALETTE, TIMELINE_PALETTE_LIGHT } from "../constants/timeline-palette.js";
import { detectKapeProfile, isChainsawDataset } from "./dataset-detect.js";

const TOOL_CLAUDE_CODE = "Claude Code";
const TOOL_CHATGPT = "ChatGPT";
const TOOL_GEMINI_CLI = "Gemini CLI";
const TOOL_CODEX = "OpenAI Codex";
const TOOL_GROK_BUILD = "Grok Build";
const TOOL_GROK_BOT = "Grok Bot";
const TOOL_CURSOR = "Cursor";
const TOOL_COPILOT = "GitHub Copilot";

export function isAiHistorySourceFormat(sourceFormat) {
  if (typeof sourceFormat !== "string") return false;
  return sourceFormat.startsWith("ai-history-") || sourceFormat === "ai-history-merged";
}

/** Keep IPC/query payloads small while still showing that FullText exists in the grid. */
export function aiHistoryQueryIpcOptions() {
  return {
    truncateColumns: {
      Summary: 240,
      FullText: 240,
      ToolInput: 2048,
      ToolDescription: 1000,
      Description: 480,
      Transcript: 480,
    },
  };
}

/** True when export options should be treated as filtered (vs full tab). */
export function tabHasActiveExportFilters(tab, activeFiltersFn) {
  if (!tab) return false;
  const af = typeof activeFiltersFn === "function" ? activeFiltersFn(tab) : { columnFilters: {}, checkboxFilters: {} };
  const colActive = Object.values(af.columnFilters || {}).some((v) => String(v || "").trim());
  const cbActive = Object.values(af.checkboxFilters || {}).some((s) => checkboxFilterActive(s));
  return !!(
    (tab.searchTerm && String(tab.searchTerm).trim() && !tab.searchHighlight)
    || tab.showBookmarkedOnly
    || tab.rowIdFilter
    || tab.tagFilter
    || Object.keys(tab.dateRangeFilters || {}).length
    || (tab.advancedFilters || []).length
    || colActive
    || cbActive
  );
}

/** Optional Role / RecordType / Tool colors (not applied by default — kept for manual rules). */
export function buildAiHistoryColorRules(isDark) {
  const p = isDark ? TIMELINE_PALETTE : TIMELINE_PALETTE_LIGHT;
  const pick = (i) => ({ bgColor: p[i % p.length].bg, fgColor: p[i % p.length].fg });
  const roleRules = [
    { column: "Role", condition: "equals", value: "user", ...pick(0) },
    { column: "Role", condition: "equals", value: "assistant", ...pick(1) },
    { column: "Role", condition: "equals", value: "conversation", ...pick(2) },
    { column: "Role", condition: "equals", value: "system", ...pick(3) },
    { column: "Role", condition: "equals", value: "tool", ...pick(4) },
    { column: "RecordType", condition: "contains", value: "tool", ...pick(5) },
    { column: "RecordType", condition: "contains", value: "function", ...pick(6) },
    { column: "RecordType", condition: "contains", value: "thinking", ...pick(7) },
    { column: "RecordType", condition: "contains", value: "reasoning", ...pick(8) },
    { column: "RecordType", condition: "equals", value: "conversation", ...pick(2) },
  ];
  const toolRules = [
    { column: "Tool", condition: "equals", value: TOOL_CLAUDE_CODE, ...pick(9) },
    { column: "Tool", condition: "equals", value: TOOL_CHATGPT, ...pick(10) },
    { column: "Tool", condition: "equals", value: TOOL_GEMINI_CLI, ...pick(11) },
    { column: "Tool", condition: "equals", value: TOOL_CODEX, ...pick(12) },
    { column: "Tool", condition: "equals", value: TOOL_GROK_BUILD, ...pick(13) },
    { column: "Tool", condition: "equals", value: TOOL_CURSOR, ...pick(14) },
    { column: "Tool", condition: "equals", value: TOOL_COPILOT, ...pick(15) },
    { column: "Tool", condition: "equals", value: TOOL_GROK_BOT, ...pick(16) },
  ];
  return [...roleRules, ...toolRules];
}

/** Normalize checkbox filter values (renderer may use Set; SQLite layer needs arrays). */
export function normalizeCheckboxFilterValues(values) {
  if (!values) return [];
  if (Array.isArray(values)) return values;
  if (values instanceof Set) return [...values];
  return [];
}

export function checkboxFilterActive(values) {
  return normalizeCheckboxFilterValues(values).length > 0;
}

/** Build checkbox filters for Role (optional; not applied on tab open by default). */
export function buildAiHistoryDefaultCheckboxFilters(headers, roleValues = ["user"]) {
  if (!headers?.includes("Role")) return {};
  return { Role: [...roleValues] };
}

/** Column filter patch to show one conversation thread (SessionId uses SQL LIKE). */
export function buildSessionIdColumnFilter(sessionId) {
  const id = String(sessionId || "").trim();
  if (!id) return {};
  return { SessionId: id };
}

function decodeFileUri(uri) {
  const raw = String(uri || "").trim();
  if (!raw.startsWith("file://")) return raw;
  try {
    let p = decodeURIComponent(raw.replace(/^file:\/\//, ""));
    if (/^\/[A-Za-z]:/.test(p)) p = p.slice(1);
    return p;
  } catch {
    return raw;
  }
}

function normPathForCorrelation(p) {
  if (!p) return "";
  return String(p).trim().replace(/\\/g, "/").toLowerCase();
}

function pathBasename(p) {
  const s = normPathForCorrelation(p);
  const i = s.lastIndexOf("/");
  return i >= 0 ? s.slice(i + 1) : s;
}

/** Resolve Workspace (+ optional SourceFile hint) to a path for cross-artifact correlation. */
export function resolveAiWorkspacePath(workspace, sourceFile = "") {
  const ws = String(workspace || "").trim();
  if (!ws) return "";

  const decoded = decodeFileUri(ws);
  if (decoded && (decoded.includes("/") || decoded.includes("\\"))) return decoded;

  if (ws.startsWith("~/.cursor/projects/")) {
    return ws;
  }

  if (ws.includes("/") || ws.includes("\\")) return ws;

  const sf = String(sourceFile || "").replace(/\\/g, "/");
  const m = sf.match(/\/projects\/([^/]+)\//i);
  if (m) return `~/.cursor/projects/${m[1]}`;

  return ws;
}

/**
 * Open tabs that can be filtered to this workspace path (Prefetch, EVTX/Sigma, Amcache).
 */
export function buildWorkspaceCorrelationTargets(tabs, pathStr) {
  const base = pathBasename(pathStr);
  const norm = normPathForCorrelation(pathStr);
  if (!base && !norm) return [];

  const targets = [];
  const seen = new Set();

  const push = (tab, kind, column, value, hint) => {
    const key = `${tab.id}:${column}:${value}`;
    if (seen.has(key) || !tab?.dataReady) return;
    seen.add(key);
    targets.push({ tabId: tab.id, tabName: tab.name || "Tab", kind, column, value, hint });
  };

  for (const tab of tabs || []) {
    const headers = tab.headers || [];
    const profile = detectKapeProfile(headers);

    if (headers.includes("ExecutableName")) {
      push(tab, "Prefetch", "ExecutableName", base, `ExecutableName contains ${base}`);
    }
    if (isChainsawDataset(headers)) {
      const col = headers.find((h) => /^image$/i.test(h))
        || headers.find((h) => /commandline|cmdline/i.test(h))
        || headers.find((h) => /^details$/i.test(h));
      if (col) push(tab, "EVTX / Sigma", col, base, `${col} contains ${base}`);
    }
    if (headers.includes("FullPath") && profile?.name?.includes("Amcache")) {
      push(tab, "Amcache", "FullPath", base, `FullPath contains ${base}`);
    }
  }

  return targets;
}

/** Prefer FullText in row detail when the grid Summary is truncated. */
export function aiHistoryDetailCellValue(row, columnName) {
  if (!row) return "";
  if (columnName === "Summary" || columnName === "FullText") {
    const full = String(row.FullText || "").trim();
    if (full) return full;
  }
  return row[columnName] ?? "";
}

const AI_DETAIL_PINNED_FIELDS = [
  "RecordType",
  "Role",
  "Tool",
  "AlsoInTools",
  "InvokedTool",
  "ToolName",
  "ToolCommand",
  "ToolDescription",
  "Model",
  "IsSidechain",
  "InputTokens",
  "OutputTokens",
];

const AI_DETAIL_FIELD_LABELS = {
  AlsoInTools: "Also in tools",
  InvokedTool: "Invoked tool",
  ToolName: "Invoked tool",
  ToolCommand: "Exact command",
  ToolDescription: "Tool description",
};

function fieldHasValue(row, field) {
  const v = row?.[field];
  if (v == null) return false;
  const s = String(v).trim();
  if (!s) return false;
  if (field === "IsSidechain" && s === "false") return false;
  return true;
}

/**
 * Key fields for the row detail summary strip (shown even when columns are hidden).
 * @returns {{ field: string, label: string, value: string }[]}
 */
export function aiHistoryDetailPinnedFields(row) {
  if (!row) return [];
  const out = [];
  for (const field of AI_DETAIL_PINNED_FIELDS) {
    if (field === "InputTokens" || field === "OutputTokens") continue;
    if (!fieldHasValue(row, field)) continue;
    out.push({ field, label: AI_DETAIL_FIELD_LABELS[field] || field, value: String(row[field]).trim() });
  }
  const inn = String(row.InputTokens || "").trim();
  const outTok = String(row.OutputTokens || "").trim();
  if (inn || outTok) {
    out.push({
      field: "Tokens",
      label: "Tokens (in / out)",
      value: [inn && `in ${inn}`, outTok && `out ${outTok}`].filter(Boolean).join(" · "),
    });
  }
  return out;
}

/** Column order for AI history row detail (pinned first, then remaining headers). */
export function aiHistoryDetailHeaderOrder(headers) {
  const list = Array.isArray(headers) ? headers : [];
  const pinned = AI_DETAIL_PINNED_FIELDS.filter((h) => list.includes(h));
  const rest = list.filter((h) => !AI_DETAIL_PINNED_FIELDS.includes(h));
  return [...pinned, ...rest];
}
