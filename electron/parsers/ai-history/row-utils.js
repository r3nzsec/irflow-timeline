/**
 * ai-history/row-utils.js — shared timeline row builders for AI history parsers.
 */

const crypto = require("crypto");
const { SUMMARY_MAX_LEN } = require("./schema");

// Bound a single message body held in heap. FullText is the only uncapped field (Summary is
// truncated to 500); without this a single adversarial JSONL line / SQLite value carrying a
// multi-hundred-MB string would be materialized in full per row. 1MB is far above any real
// prompt/response; truncation is marked so it is auditable rather than silent.
const MAX_FULLTEXT_CHARS = 1024 * 1024;
// Tool inputs may contain file bodies or other large arguments. Keep enough source evidence for
// normal invocations while bounding a malicious/pathological single value. The marker makes the
// exceptional truncation visible; ordinary shell commands remain byte-for-byte unchanged.
const MAX_TOOL_EVIDENCE_CHARS = 1024 * 1024;

function capEvidenceText(text, maxChars) {
  const value = String(text ?? "");
  if (value.length <= maxChars) return value;
  const dropped = value.length - maxChars;
  return `${value.slice(0, maxChars)}\n…[truncated ${dropped} chars over ${maxChars}-char cap]`;
}

function capFullText(text) {
  return capEvidenceText(text, MAX_FULLTEXT_CHARS);
}

function formatTimestampUtc(ms) {
  if (ms == null || !Number.isFinite(ms)) return "";
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} `
    + `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function parseIsoTimestamp(s) {
  if (s == null) return null;
  if (typeof s === "number" && Number.isFinite(s)) {
    return s > 1e12 ? s : (s > 1e9 ? s * 1000 : null);
  }
  const raw = String(s).trim();
  if (!raw) return null;
  const iso = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(raw) ? raw : `${raw.replace(" ", "T")}Z`;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

function truncateSummary(text) {
  const s = String(text || "").replace(/\r?\n/g, " ").trim();
  if (s.length <= SUMMARY_MAX_LEN) return s;
  return `${s.slice(0, SUMMARY_MAX_LEN - 1)}…`;
}

function detectActivity(role, content, recordType) {
  const rt = String(recordType || "").toLowerCase();
  if (rt && rt !== "user" && rt !== "assistant" && rt !== "history") {
    return rt.split("-").map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
  }
  const lower = String(content || "").toLowerCase();
  if (role === "conversation") return "Conversation";
  if (role === "assistant") return "AI Response";
  if (role !== "user") return "System Message";
  if (/\b(fix|bug|error)\b/.test(lower)) return "Bug Fix Request";
  if (/\b(create|build|implement|add)\b/.test(lower)) return "Feature Request";
  if (/\b(explain|what|how|why)\b/.test(lower)) return "Question";
  if (/\b(refactor|clean|optimize)\b/.test(lower)) return "Refactor Request";
  if (/\btest\b/.test(lower)) return "Test Request";
  return "User Query";
}

function buildDescription(entry) {
  const activity = detectActivity(entry.role, entry.summary, entry.recordType);
  const preview = truncateSummary(entry.summary).slice(0, 150);
  const sessionShort = entry.sessionId && entry.sessionId.length > 8
    ? entry.sessionId.slice(0, 8)
    : (entry.sessionId || "—");
  const tokenInfo = (entry.inputTokens > 0 || entry.outputTokens > 0)
    ? ` | Tokens: ${entry.inputTokens}/${entry.outputTokens}`
    : "";
  const modelInfo = entry.model ? ` | Model: ${entry.model}` : "";
  const workspaceInfo = entry.workspace ? ` | Workspace: ${entry.workspace}` : "";
  const toolInfo = entry.toolName && entry.toolName !== entry.tool ? ` | InvokedTool: ${entry.toolName}` : "";
  const branchInfo = entry.gitBranch ? ` | Branch: ${entry.gitBranch}` : "";
  const typeInfo = entry.recordType && !["user", "assistant", "history"].includes(entry.recordType)
    ? ` | Type: ${entry.recordType}`
    : "";
  return `[${entry.timestamp}] ${activity} in ${entry.tool} - "${preview}" (Session: ${sessionShort})${typeInfo}${modelInfo}${workspaceInfo}${toolInfo}${branchInfo}${tokenInfo}`;
}

function makeRow(fields, defaultTool) {
  const fullText = capFullText(String(fields.fullText ?? fields.summary ?? "")
    .replace(/\r\n/g, "\n")
    .trim());
  // Callers may provide an analyst-friendly event summary plus a much larger evidence body.
  // Preserve that explicit summary; use FullText as the fallback only when no summary exists.
  const summarySource = fields.summary != null && String(fields.summary).trim()
    ? fields.summary
    : fullText;
  const summary = truncateSummary(summarySource);
  const tool = fields.tool || defaultTool || "";
  const row = {
    Timestamp: fields.timestamp || "",
    TimestampBasis: fields.timestampBasis || "",
    Role: fields.role || "",
    RecordType: fields.recordType || "",
    Summary: summary,
    FullText: fullText,
    InvokedTool: fields.toolName || "",
    ToolCommand: capEvidenceText(fields.toolCommand, MAX_TOOL_EVIDENCE_CHARS),
    ToolInput: capEvidenceText(fields.toolInput, MAX_TOOL_EVIDENCE_CHARS),
    ToolDescription: capEvidenceText(fields.toolDescription, MAX_TOOL_EVIDENCE_CHARS),
    SessionId: fields.sessionId || "",
    MessageId: fields.messageId || "",
    ParentId: fields.parentId || "",
    Workspace: fields.workspace || "",
    IsSidechain: fields.isSidechain === true ? "true" : (fields.isSidechain === false ? "false" : ""),
    GitBranch: fields.gitBranch || "",
    Tool: tool,
    Model: fields.model || "",
    InputTokens: fields.inputTokens != null ? String(fields.inputTokens) : "",
    OutputTokens: fields.outputTokens != null ? String(fields.outputTokens) : "",
    SourceFile: fields.sourceFile || "",
    LineNumber: fields.lineNumber != null && fields.lineNumber !== "" ? String(fields.lineNumber) : "",
    SourceOffset: fields.sourceOffset != null && fields.sourceOffset !== "" ? String(fields.sourceOffset) : "",
    User: fields.user || "",
    Host: fields.host || "",
    AlsoInTools: fields.alsoInTools || "",
    RecordId: "",
    Description: "",
  };
  row.Description = buildDescription({
    timestamp: row.Timestamp,
    role: row.Role,
    summary: fullText || row.Summary,
    sessionId: row.SessionId,
    tool: row.Tool,
    model: row.Model,
    workspace: row.Workspace,
    recordType: row.RecordType,
    toolName: row.InvokedTool,
    gitBranch: row.GitBranch,
    inputTokens: Number(row.InputTokens) || 0,
    outputTokens: Number(row.OutputTokens) || 0,
  });
  return row;
}

function summaryDedupeSlice(row) {
  return String(row.Summary || "").toLowerCase().replace(/\s+/g, " ").trim().slice(0, 120);
}

function normalizedEvidenceBody(row) {
  return String(row.FullText || row.Summary || "").replace(/\r\n/g, "\n").trim();
}

function evidenceBodyHash(row) {
  return crypto.createHash("sha256").update(normalizedEvidenceBody(row), "utf8").digest("hex");
}

function crossToolPromptKey(row) {
  const body = normalizedEvidenceBody(row);
  if (!body || body.length < 20) return "";
  const role = String(row.Role || "").toLowerCase();
  if (role !== "user" && role !== "assistant") return "";
  return `${role}\x1f${evidenceBodyHash(row)}`;
}

function pickRicherAiHistoryRow(a, b) {
  const lenA = String(a.FullText || a.Summary || "").length;
  const lenB = String(b.FullText || b.Summary || "").length;
  if (a.Timestamp && !b.Timestamp) return a;
  if (b.Timestamp && !a.Timestamp) return b;
  if (lenA !== lenB) return lenA > lenB ? a : b;
  if (a.Tool && b.Tool && a.Tool !== b.Tool) return a;
  return a;
}

/**
 * Preserve every source occurrence. When byte-equivalent prompt bodies appear across tools, annotate
 * each occurrence with the complete tool set. Source paths and physical locators remain intact, so
 * correlation never destroys evidence provenance.
 */
function dedupeCrossToolPrompts(rows) {
  const bucketsByKey = new Map();
  for (const r of rows) {
    const key = crossToolPromptKey(r);
    if (!key) continue;
    const tool = String(r.Tool || "").trim();
    const bucket = bucketsByKey.get(key) || { rows: [], tools: new Set() };
    bucket.rows.push(r);
    if (tool) bucket.tools.add(tool);
    for (const existing of String(r.AlsoInTools || "").split(",").map((v) => v.trim()).filter(Boolean)) {
      bucket.tools.add(existing);
    }
    bucketsByKey.set(key, bucket);
  }
  for (const bucket of bucketsByKey.values()) {
    if (bucket.tools.size < 2) continue;
    const alsoInTools = [...bucket.tools].sort().join(", ");
    for (const row of bucket.rows) row.AlsoInTools = alsoInTools;
  }
  return rows;
}

function aiHistoryDedupeKey(row) {
  return [
    row.Tool || "",
    row.User || "",
    row.Host || "",
    row.SourceFile || "",
    row.SourceOffset || "",
    row.LineNumber || "",
    row.SessionId || "",
    row.MessageId || "",
    row.ParentId || "",
    row.Timestamp || "",
    row.Role || "",
    row.RecordType || "",
    evidenceBodyHash(row),
  ].join("\x1e");
}

/** Match history.jsonl prompts to session rows when timestamps differ. */
function aiHistoryLooseKey(row) {
  return [
    row.SessionId || "",
    row.Role || "",
    evidenceBodyHash(row),
  ].join("\x1e");
}

function isHistoryRow(row) {
  const src = row.SourceFile || "";
  return src.endsWith("history.jsonl") || row.RecordType === "history";
}

function isSessionRow(row) {
  if (isHistoryRow(row)) return false;
  const src = row.SourceFile || "";
  return !!(row.MessageId || /\.jsonl$/i.test(src));
}

/**
 * Remove only duplicate representations of the same physical source occurrence.
 */
function dedupeAiHistoryRows(rows, options = {}) {
  const seen = new Set();
  const out = [];
  for (const r of rows) {
    const key = aiHistoryDedupeKey(r);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  if (options.crossTool) return dedupeCrossToolPrompts(out);
  return out;
}

function assignLineNumber(row, lineNumber, sourceLocation = null) {
  if (row && lineNumber != null && lineNumber !== "") row.LineNumber = String(lineNumber);
  if (row && sourceLocation?.byteOffset != null) row.SourceOffset = String(sourceLocation.byteOffset);
  return row;
}

function sortAndNumberRows(rows) {
  rows.sort((a, b) => (a.Timestamp < b.Timestamp ? -1 : a.Timestamp > b.Timestamp ? 1 : 0));
  for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
  return rows;
}

/**
 * Per-tool sort + dedupe. Pass `skipFinalize: true` when rows feed `extractMergedAiHistoryRoots`
 * so merge performs a single dedupe/sort pass (P2).
 */
function finalizeAiHistoryRows(rows, options = {}) {
  if (options.skipFinalize) return rows;
  return sortAndNumberRows(dedupeAiHistoryRows(rows, options));
}

module.exports = {
  formatTimestampUtc,
  parseIsoTimestamp,
  truncateSummary,
  detectActivity,
  buildDescription,
  makeRow,
  normalizedEvidenceBody,
  evidenceBodyHash,
  aiHistoryDedupeKey,
  aiHistoryLooseKey,
  crossToolPromptKey,
  dedupeCrossToolPrompts,
  dedupeAiHistoryRows,
  isHistoryRow,
  isSessionRow,
  assignLineNumber,
  sortAndNumberRows,
  finalizeAiHistoryRows,
};
