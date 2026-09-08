/**
 * parsers/ai-history/claude-code.js — Claude Code JSONL history + session extraction.
 *
 * Artifacts:
 *   ~/.claude/history.jsonl  — { display, timestamp (ms), sessionId, project }
 *   ~/.claude/projects/.../<session>.jsonl — user/assistant messages with tool blocks
 */

const fs = require("fs");
const path = require("path");
const { readJsonlBounded } = require("./jsonl-reader");

const { dbg } = require("../../logger");
const { TOOL_CLAUDE_CODE } = require("./schema");
const { buildToolEvidence } = require("./tool-evidence");
const {
  isClaudeJsonStateFile,
  extractClaudeJsonFile,
  countClaudeJsonExtractFiles,
} = require("./claude-code-state");
const {
  isClaudeCliConfigRoot,
  listClaudeContextFiles,
  extractClaudeContext,
} = require("./claude-code-context");
const { shouldSkipSubagentPath, filterSidechainRows, tickFileProgress } = require("./extract-plan");
const { processFilesConcurrently } = require("./file-batch");
const {
  formatTimestampUtc,
  parseIsoTimestamp,
  makeRow,
  finalizeAiHistoryRows,
  assignLineNumber,
  truncateSummary,
} = require("./row-utils");

function claudeRow(fields) {
  const timestampBasis = fields.timestampBasis || (fields.timestamp ? "source artifact timestamp" : "unavailable");
  return makeRow({ ...fields, timestampBasis, tool: fields.tool || TOOL_CLAUDE_CODE }, TOOL_CLAUDE_CODE);
}

function parseRecordTimestamp(obj) {
  const raw = obj.timestamp ?? obj._audit_timestamp ?? obj.createdAt ?? obj.updatedAt ?? obj.lastActivityAt;
  if (raw == null) return null;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    // Heuristic shared with the other parsers: >1e12 is already epoch-ms,
    // a smaller value is epoch-seconds and must be scaled to ms.
    return raw > 1e12 ? raw : raw * 1000;
  }
  return parseIsoTimestamp(raw);
}

function serializeContentValue(value) {
  if (value == null) return "";
  if (typeof value === "string") return value.trim();
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (typeof item === "string") return item.trim();
      if (!item || typeof item !== "object") return "";
      if (["text", "input_text", "output_text"].includes(item.type) && item.text != null) {
        return String(item.text).trim();
      }
      if (item.type === "image") {
        const media = item.source?.media_type || item.media_type || "";
        return media ? `[Image: ${media}]` : "[Image]";
      }
      try { return JSON.stringify(item); } catch { return String(item); }
    }).filter(Boolean).join("\n");
  }
  try { return JSON.stringify(value); } catch { return String(value); }
}

function attachmentSummary(attachment) {
  if (!attachment || typeof attachment !== "object") return "[Attachment]";
  const kind = attachment.type ? String(attachment.type) : "attachment";
  const names = [
    attachment.fileName,
    attachment.filename,
    attachment.name,
    ...(Array.isArray(attachment.addedNames) ? attachment.addedNames : []),
    ...(Array.isArray(attachment.removedNames) ? attachment.removedNames : []),
  ].filter((v) => v != null && String(v).trim()).map(String);
  return names.length
    ? `[Attachment: ${kind}] ${[...new Set(names)].join(", ")}`
    : `[Attachment: ${kind}]`;
}

/** Extract text, tool calls, and thinking/result flags from message.content. */
function extractContentParts(content) {
  const result = {
    textParts: [],
    toolNames: [],
    toolCalls: [],
    hasThinking: false,
    hasToolResult: false,
  };
  if (content == null) return result;
  if (typeof content === "string") {
    const s = content.trim();
    if (s) result.textParts.push(s);
    return result;
  }
  if (!Array.isArray(content)) return result;

  for (const item of content) {
    if (!item || typeof item !== "object") continue;
    const type = item.type || "";
    if (type === "text" && item.text) {
      const t = String(item.text).trim();
      if (t) result.textParts.push(t);
    } else if ((type === "tool_use" || type === "function_call") && (item.name || item.function?.name)) {
      const name = String(item.name || item.function.name);
      const input = item.input ?? item.arguments ?? item.function?.arguments;
      result.toolNames.push(name);
      result.toolCalls.push({ name, input });
      result.textParts.push(`[Tool: ${name}]`);
    } else if (type === "tool_result") {
      result.hasToolResult = true;
      const output = serializeContentValue(item.content ?? item.output ?? item.result);
      result.textParts.push(output ? `[Tool Result]\n${output}` : "[Tool Result]");
    } else if (type === "thinking") {
      result.hasThinking = true;
    } else if (type === "image" || type === "input_image") {
      const media = item.source?.media_type || item.media_type || "";
      result.textParts.push(media ? `[Image: ${media}]` : "[Image]");
    } else if (type === "document") {
      const title = item.title || item.name || item.source?.name || "";
      result.textParts.push(title ? `[Document: ${title}]` : "[Document]");
    } else if (type === "fallback") {
      const fallback = serializeContentValue(item.content ?? item.text);
      if (fallback) result.textParts.push(fallback);
    }
  }
  return result;
}

function extractContentText(content) {
  const parts = extractContentParts(content);
  let text = parts.textParts.join(" ");
  if (parts.hasThinking && !/\[Reasoning present\]/.test(text)) {
    text = text ? `${text} [Reasoning present]` : "[Reasoning present]";
  }
  return text.trim();
}

function extractToolEvidence(content) {
  return buildToolEvidence(extractContentParts(content).toolCalls);
}

/** Pull prompt text from a history.jsonl record (schema varies by Claude Code version). */
function historyLineText(obj) {
  if (obj.display != null) {
    const s = String(obj.display).trim();
    if (s) return s;
  }
  if (obj.message != null) {
    const s = typeof obj.message === "string" ? obj.message.trim() : "";
    if (s) return s;
  }
  if (obj.text != null && String(obj.text).trim()) return String(obj.text).trim();
  if (obj.prompt != null && String(obj.prompt).trim()) return String(obj.prompt).trim();

  const pc = obj.pastedContents;
  if (pc && typeof pc === "object" && !Array.isArray(pc)) {
    const parts = [];
    for (const v of Object.values(pc)) {
      if (typeof v === "string" && v.trim()) parts.push(v.trim());
      else if (v && typeof v === "object") {
        const t = v.text ?? v.content ?? v.display;
        if (t != null && String(t).trim()) parts.push(String(t).trim());
      }
    }
    if (parts.length) return parts.join(" ");
  }
  return "";
}

function buildGenericSummary(obj, recordType) {
  switch (recordType) {
    case "file-history-snapshot":
      return "[File history snapshot]";
    case "file-history-delta":
      return obj.trackingPath
        ? `[File history delta] ${obj.trackingPath}`
        : "[File history delta]";
    case "system":
      return obj.subtype ? `[System: ${obj.subtype}]` : "[System event]";
    case "attachment":
      return obj.title || obj.aiTitle || attachmentSummary(obj.attachment);
    case "ai-title":
      return obj.aiTitle || obj.title || "[AI title]";
    case "last-prompt":
      return obj.lastPrompt || obj.prompt || "[Last prompt]";
    case "mode":
      return obj.mode ? `[Mode: ${obj.mode}]` : "[Mode]";
    case "permission-mode":
      return obj.permissionMode ? `[Permission mode: ${obj.permissionMode}]` : "[Permission mode]";
    case "agent-name":
      return obj.agentName ? `[Agent: ${obj.agentName}]` : "[Agent name]";
    case "bridge-session":
      return obj.bridgeSessionId ? `[Bridge session: ${obj.bridgeSessionId}]` : "[Bridge session]";
    case "started":
      return obj.agentId ? `[Agent started: ${obj.agentId}]` : "[Agent started]";
    case "result": {
      const result = serializeContentValue(obj.result);
      return result ? `[Result] ${result}` : "[Result]";
    }
    case "queue-operation":
      return obj.operation ? `[Queue: ${obj.operation}]` : "[Queue operation]";
    case "progress":
      return obj.message?.content ? extractContentText(obj.message.content) : "[Progress]";
    default:
      break;
  }
  const message = obj.message && typeof obj.message === "object" ? obj.message : null;
  if (message?.content) {
    const t = extractContentText(message.content);
    if (t) return t;
  }
  if (typeof obj.content === "string" && obj.content.trim()) {
    return truncateSummary(obj.content);
  }
  return `[${recordType}]`;
}

function genericFullText(obj, recordType, summary) {
  if (recordType === "attachment") return serializeContentValue(obj.attachment) || summary;
  if (recordType === "result") return serializeContentValue(obj.result) || summary;
  if (recordType === "last-prompt") return serializeContentValue(obj.lastPrompt ?? obj.prompt) || summary;
  if (recordType === "file-history-delta") {
    return serializeContentValue({
      trackingPath: obj.trackingPath,
      backup: obj.backup,
      messageId: obj.messageId,
      snapshotMessageId: obj.snapshotMessageId,
    }) || summary;
  }
  const message = obj.message && typeof obj.message === "object" ? obj.message : null;
  return message?.content ? extractContentText(message.content) : summary;
}

function inferRole(obj, recordType) {
  const message = obj.message && typeof obj.message === "object" ? obj.message : null;
  if (message?.role) return String(message.role);
  if (recordType === "user" || recordType === "assistant") return recordType;
  if (recordType === "history") return "user";
  return "system";
}

/** Parse one history.jsonl line. */
function parseHistoryLine(obj, sourceFile, attribution = {}) {
  const summary = historyLineText(obj);
  if (!summary) return null;

  const tsMs = typeof obj.timestamp === "number" ? obj.timestamp : parseInt(obj.timestamp, 10);
  if (!Number.isFinite(tsMs) || tsMs <= 0) return null;

  return claudeRow({
    timestamp: formatTimestampUtc(tsMs),
    role: "user",
    recordType: "history",
    summary,
    sessionId: obj.sessionId != null ? String(obj.sessionId) : "",
    messageId: "",
    parentId: "",
    workspace: obj.project != null ? String(obj.project) : "",
    isSidechain: false,
    gitBranch: "",
    toolName: "",
    model: "",
    inputTokens: 0,
    outputTokens: 0,
    sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

/** Parse one session / project JSONL line (all record types). */
function parseSessionLine(obj, sourceFile, attribution = {}, parseOptions = {}) {
  const recordType = obj.type != null ? String(obj.type) : "unknown";
  const outputRecordType = `${parseOptions.recordTypePrefix || ""}${recordType}`;
  const tsMs = parseRecordTimestamp(obj);
  const timestamp = tsMs == null ? "" : formatTimestampUtc(tsMs);

  const message = obj.message && typeof obj.message === "object" ? obj.message : null;
  const isSidechain = obj.isSidechain === true || obj.parent_tool_use_id != null;
  const gitBranch = obj.gitBranch != null ? String(obj.gitBranch) : "";

  if (recordType === "user" || recordType === "assistant") {
    const role = message?.role != null ? String(message.role) : recordType;
    const contentText = extractContentText(message?.content);
    if (!contentText) return null;
    const toolEvidence = extractToolEvidence(message?.content);

    const usage = message?.usage && typeof message.usage === "object" ? message.usage : {};
    const inputTokens = Number(usage.input_tokens) || 0;
    const outputTokens = Number(usage.output_tokens) || 0;

    return claudeRow({
      timestamp,
      role,
      recordType: outputRecordType,
      summary: contentText,
      fullText: contentText,
      ...toolEvidence,
      sessionId: obj.sessionId != null ? String(obj.sessionId) : (obj.session_id != null ? String(obj.session_id) : ""),
      messageId: obj.uuid != null ? String(obj.uuid) : "",
      parentId: obj.parentUuid != null ? String(obj.parentUuid) : (obj.parent_tool_use_id != null ? String(obj.parent_tool_use_id) : ""),
      workspace: obj.cwd != null ? String(obj.cwd) : "",
      isSidechain,
      gitBranch,
      model: message?.model != null ? String(message.model) : "",
      inputTokens,
      outputTokens,
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  }

  const summary = buildGenericSummary(obj, recordType);
  if (!summary) return null;
  const toolEvidence = message?.content ? extractToolEvidence(message.content) : {};

  return claudeRow({
    timestamp,
    role: inferRole(obj, recordType),
    recordType: outputRecordType,
    summary,
    fullText: genericFullText(obj, recordType, summary),
    ...toolEvidence,
    sessionId: obj.sessionId != null ? String(obj.sessionId) : (obj.session_id != null ? String(obj.session_id) : ""),
    messageId: obj.uuid != null ? String(obj.uuid) : "",
    parentId: obj.parentUuid != null ? String(obj.parentUuid) : (obj.parent_tool_use_id != null ? String(obj.parent_tool_use_id) : ""),
    workspace: obj.cwd != null ? String(obj.cwd) : "",
    isSidechain,
    gitBranch,
    model: message?.model != null ? String(message.model) : "",
    inputTokens: 0,
    outputTokens: 0,
    sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

async function readJsonlFile(filePath, onLine, parseStats = null) {
  // Bounded reader: caps per-line size so a single huge/newline-free session line cannot OOM
  // the worker, and contains a per-line handler throw instead of unwinding the whole file.
  await readJsonlBounded(filePath, onLine, { parseStats });
}

/** Extract all rows from history.jsonl. */
async function extractHistoryFile(historyPath, attribution = {}, parseStats = null) {
  const rows = [];
  await readJsonlFile(historyPath, (obj, lineNumber, sourceLocation) => {
    const row = assignLineNumber(parseHistoryLine(obj, historyPath, attribution), lineNumber, sourceLocation);
    if (row) rows.push(row);
  }, parseStats);
  return rows;
}

/** Extract all rows from a session *.jsonl file. */
async function extractSessionFile(sessionPath, attribution = {}, parseStats = null) {
  const rows = [];
  await readJsonlFile(sessionPath, (obj, lineNumber, sourceLocation) => {
    const row = assignLineNumber(parseSessionLine(obj, sessionPath, attribution), lineNumber, sourceLocation);
    if (row) rows.push(row);
  }, parseStats);
  return rows;
}

function listSessionJsonlFiles(projectsDir, options = {}) {
  const out = [];
  if (!fs.existsSync(projectsDir)) return out;

  const stack = [projectsDir];
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (shouldSkipSubagentPath(full, options)) continue;
        if (!e.isSymbolicLink()) stack.push(full);
      } else if (e.isFile() && path.extname(e.name).toLowerCase() === ".jsonl") {
        if (!shouldSkipSubagentPath(full, options)) out.push(full);
      }
    }
  }
  return out;
}

function countClaudeExtractFiles(claudeDir, options = {}) {
  if (isClaudeJsonStateFile(claudeDir)) return countClaudeJsonExtractFiles(claudeDir);
  const {
    isClaudeDesktopSessionsRoot,
    countClaudeDesktopExtractFiles,
  } = require("./claude-desktop");
  if (isClaudeDesktopSessionsRoot(claudeDir) && path.basename(claudeDir) !== ".claude") {
    return countClaudeDesktopExtractFiles(claudeDir, options);
  }
  let n = 0;
  if (isClaudeCliConfigRoot(claudeDir)) {
    if (fs.existsSync(path.join(claudeDir, "history.jsonl"))) n += 1;
    n += listSessionJsonlFiles(path.join(claudeDir, "projects"), options).length;
    const context = listClaudeContextFiles(claudeDir, options);
    n += context.files.length;
    if (fs.existsSync(path.join(claudeDir, "settings.json"))) n += 1;
    if (fs.existsSync(path.join(claudeDir, ".mcp.json"))) n += 1;
  } else {
    n += listSessionJsonlFiles(claudeDir, options).length;
  }
  return n;
}

/**
 * Extract from a .claude directory (history + all project session files).
 * @param {string} claudeDir
 * @param {{ user?: string, host?: string }} attribution
 */
async function extractClaudeDir(claudeDir, attribution = {}, options = {}) {
  if (isClaudeJsonStateFile(claudeDir)) {
    return extractClaudeJsonFile(claudeDir, attribution, options);
  }
  const { isClaudeDesktopSessionsRoot, extractClaudeDesktopDir } = require("./claude-desktop");
  if (isClaudeDesktopSessionsRoot(claudeDir) && path.basename(claudeDir) !== ".claude") {
    const { rows, stats } = await extractClaudeDesktopDir(claudeDir, attribution, options);
    const filtered = filterSidechainRows(rows, options);
    filtered._claudeDesktopStats = stats;
    return filtered;
  }

  const rows = [];
  const parseStats = options.parseStats || { errors: 0 };
  const isCliHome = isClaudeCliConfigRoot(claudeDir);
  const sessionPaths = isCliHome
    ? listSessionJsonlFiles(path.join(claudeDir, "projects"), options)
    : listSessionJsonlFiles(claudeDir, options);
  const historyPath = isCliHome ? path.join(claudeDir, "history.jsonl") : null;
  const fileCount = (historyPath && fs.existsSync(historyPath) ? 1 : 0) + sessionPaths.length;
  let fileIndex = 0;
  const { onFileProgress, onExtractedRows } = options;

  const emitBatch = (batch) => {
    if (!batch?.length) return;
    const filtered = filterSidechainRows(batch, options);
    if (onExtractedRows && filtered.length) {
      onExtractedRows(filtered);
      return;
    }
    rows.push(...filtered);
  };

  if (historyPath && fs.existsSync(historyPath)) {
    fileIndex += 1;
    tickFileProgress(onFileProgress, fileIndex, fileCount, historyPath);
    try {
      emitBatch(await extractHistoryFile(historyPath, attribution, parseStats));
    } catch (e) {
      dbg("AIHIST", "history.jsonl failed", { path: historyPath, err: e.message });
    }
  }

  // Read session files in bounded-concurrency batches (order-independent: sink dedupes, DB/finalize
  // sorts). Per-file error isolation + progress preserved; yields between batches.
  await processFilesConcurrently(sessionPaths, {
    process: (sessionPath) => extractSessionFile(sessionPath, attribution, parseStats),
    onProgress: (sessionPath) => { fileIndex += 1; tickFileProgress(onFileProgress, fileIndex, fileCount, sessionPath); },
    onRows: (batch) => emitBatch(batch),
    onError: (e, sessionPath) => dbg("AIHIST", "session jsonl failed", { path: sessionPath, err: e.message }),
    checkAbort: options.checkAbort,
  });

  let contextStats = null;
  if (isCliHome && options.includeClaudeContext !== false) {
    options.checkAbort?.();
    try {
      const context = extractClaudeContext(claudeDir, attribution, options);
      contextStats = context.stats;
      emitBatch(context.rows);
    } catch (e) {
      dbg("AIHIST", "claude context artifacts failed", { path: claudeDir, err: e.message });
    }
  }

  if (onExtractedRows) {
    const out = [];
    if (contextStats) out._claudeContextStats = contextStats;
    if (parseStats.errors) out._parseErrors = parseStats.errors;
    return out;
  }

  const result = finalizeAiHistoryRows(filterSidechainRows(rows, options), options);
  if (contextStats) result._claudeContextStats = contextStats;
  if (parseStats.errors) result._parseErrors = parseStats.errors;
  return result;
}

function isClaudeDir(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  if (path.basename(dirPath) !== ".claude") return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  const history = path.join(dirPath, "history.jsonl");
  const projects = path.join(dirPath, "projects");
  return fs.existsSync(history) || fs.existsSync(projects);
}

/**
 * Extract Claude Code rows from a file or directory path.
 * @param {string} target — .claude dir, history.jsonl, or session .jsonl
 * @param {{ user?: string, host?: string }} attribution
 */
async function extractClaudeCodePath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  let stat;
  try { stat = fs.statSync(target); } catch (e) {
    throw new Error(`Cannot read path: ${e.message}`);
  }

  if (stat.isDirectory()) {
    const { isClaudeCodeArtifactRoot } = require("./artifact-paths");
    const root = isClaudeCodeArtifactRoot(target) ? target : resolveClaudeDir(target);
    if (root) return extractClaudeDir(root, attribution, options);
    throw new Error("Not a Claude Code directory (~/.claude or Claude Desktop claude-code-sessions).");
  }

  if (isClaudeJsonStateFile(target)) {
    const rows = extractClaudeJsonFile(target, attribution, options);
    if (options.onExtractedRows) return rows;
    for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
    return rows;
  }

  const ext = path.extname(target).toLowerCase();
  if (ext !== ".jsonl") {
    throw new Error("Expected a .jsonl file, ~/.claude.json, or a .claude directory.");
  }

  if (path.basename(target) === "history.jsonl") {
    const rows = await extractHistoryFile(target, attribution, options.parseStats);
    for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
    return rows;
  }

  const rows = await extractSessionFile(target, attribution, options.parseStats);
  for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
  return rows;
}

/** Resolve a path to the enclosing .claude directory, if any. */
function resolveClaudeDir(target) {
  if (!target) return null;
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  const { isClaudeCodeArtifactRoot } = require("./artifact-paths");
  for (let i = 0; i < 20; i++) {
    if (isClaudeCodeArtifactRoot(p)) return p;
    const base = path.basename(p);
    if (/^\.(?:copilot|cursor|continue|gemini|grok|codex)$/i.test(base)) break;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  if (isClaudeCodeArtifactRoot(target)) return target;
  return null;
}

module.exports = {
  extractContentText,
  extractContentParts,
  extractToolEvidence,
  historyLineText,
  parseHistoryLine,
  parseSessionLine,
  extractHistoryFile,
  extractSessionFile,
  extractClaudeDir,
  extractClaudeCodePath,
  isClaudeDir,
  resolveClaudeDir,
  // Re-export discovery helper (CLI + Desktop paths)
  isClaudeCodeArtifactRoot: require("./artifact-paths").isClaudeCodeArtifactRoot,
  listSessionJsonlFiles,
  countClaudeExtractFiles,
  isClaudeJsonStateFile,
  extractClaudeJsonFile,
  isClaudeCliConfigRoot,
  listClaudeContextFiles,
  extractClaudeContext,
};
