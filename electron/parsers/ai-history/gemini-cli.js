/**
 * parsers/ai-history/gemini-cli.js — Google Gemini CLI session extraction.
 *
 * Artifacts:
 * - ~/.gemini/tmp/<hash>/chats/session-*.jsonl — current append-only session records
 * - ~/.gemini/tmp/<hash>/chats/session-*.json — legacy { messages: [...] } sessions
 * - ~/.gemini/tmp/<hash>/logs.json — legacy CLI log array [{ type, message, timestamp, sessionId, messageId }]
 * - ~/.gemini/tmp/<hash>/shell_history — project-scoped shell command history
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { tickFileProgress } = require("./extract-plan");
const { TOOL_GEMINI_CLI } = require("./schema");
const { formatTimestampUtc, parseIsoTimestamp, makeRow, finalizeAiHistoryRows } = require("./row-utils");
const { parseChatgptTimestamp } = require("./chatgpt");
const { readJsonlBounded } = require("./jsonl-reader");
const { buildToolEvidence, serializeEvidenceValue } = require("./tool-evidence");
const { safeServerConfig } = require("./claude-code-context");
const { contextInventoryRow, walkContextFiles, safeStat: safeContextStat } = require("./context-inventory");

const GEMINI_DIR_NAME = ".gemini";
const LOGS_FILE_NAME = "logs.json";
const SHELL_HISTORY_FILE_NAME = "shell_history";
const SESSION_FILE_RE = /^session-.+\.(?:json|jsonl)$/i;
const CHECKPOINT_FILE_RE = /^checkpoint-.+\.json$/i;
const MAX_LEGACY_SESSION_BYTES = 32 * 1024 * 1024;
const MAX_SHELL_HISTORY_BYTES = 4 * 1024 * 1024;
const MAX_STATE_JSON_BYTES = 4 * 1024 * 1024;
const PROJECT_ROOT_FILE = ".project_root";
const SETTINGS_FILE = "settings.json";
const PROJECTS_FILE = "projects.json";
const TRUSTED_FOLDERS_FILE = "trustedFolders.json";
const GOOGLE_ACCOUNTS_FILE = "google_accounts.json";
const GEMINI_MD_FILE = "GEMINI.md";
const GEMINI_STATE_BACKUP_RE = /^(?:settings|projects)\.json(?:\.orig|\.bak|\.[0-9a-f-]+\.tmp)$/i;
const OAUTH_INVENTORY_FILES = new Set([
  "oauth_creds.json",
  "mcp-oauth-tokens.json",
  "a2a-oauth-tokens.json",
]);
const IDENTITY_FILES = new Set([
  "google_account_id",
  "installation_id",
  "user_id",
]);

const ROLE_BY_TYPE = {
  user: "user",
  gemini: "assistant",
  assistant: "assistant",
  model: "assistant",
  system: "system",
  error: "system",
  info: "system",
  tool: "tool",
  function: "tool",
};

function parseMessageTimestamp(value, fallbackMs) {
  if (value == null || value === "") {
    return fallbackMs != null ? fallbackMs : null;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 1e12 ? value : value * 1000;
  }
  return parseChatgptTimestamp(value) ?? parseIsoTimestamp(String(value));
}

function parseTokenCounts(tokens) {
  if (!tokens || typeof tokens !== "object") return { input: 0, output: 0 };
  const input = tokens.input ?? tokens.inputTokens ?? tokens.prompt ?? tokens.promptTokenCount ?? 0;
  const output = tokens.output ?? tokens.outputTokens ?? tokens.completion ?? tokens.candidatesTokenCount ?? 0;
  return {
    input: Number(input) || 0,
    output: Number(output) || 0,
  };
}

function normalizeThoughts(thoughts) {
  if (!thoughts) return "";
  const values = Array.isArray(thoughts) ? thoughts : [thoughts];
  return values.map((thought) => {
    if (typeof thought === "string") return thought;
    if (!thought || typeof thought !== "object") return "";
    const subject = thought.subject != null ? String(thought.subject).trim() : "";
    const description = thought.description != null ? String(thought.description).trim() : "";
    const text = thought.text ?? thought.summary?.text ?? thought.summary ?? "";
    return [subject, description, typeof text === "string" ? text.trim() : ""]
      .filter(Boolean)
      .join(": ");
  }).filter(Boolean).join("\n");
}

function contentText(content) {
  let text = "";
  if (typeof content === "string") text = content.trim();
  else if (Array.isArray(content)) {
    text = content.map((p) => {
      if (typeof p === "string") return p;
      if (p && typeof p === "object") return p.text || p.content || "";
      return "";
    }).filter(Boolean).join(" ");
  } else if (content && typeof content === "object") {
    text = String(content.text || content.content || "").trim();
  }
  return text;
}

function normalizeContent(content, thoughts) {
  let text = contentText(content);
  const thoughtText = normalizeThoughts(thoughts);
  if (!text && thoughtText) text = "[Reasoning only]";
  else if (thoughtText) text = `${text} [Reasoning present]`.trim();
  return text;
}

function geminiRow(fields) {
  const timestampBasis = fields.timestampBasis || (fields.timestamp ? "source artifact timestamp" : "unavailable");
  return makeRow({ ...fields, timestampBasis, tool: fields.tool || TOOL_GEMINI_CLI }, TOOL_GEMINI_CLI);
}

function isNestedSubagentSession(sessionPath) {
  const norm = String(sessionPath || "").replace(/\\/g, "/");
  const afterChats = norm.split(/\/chats\//i)[1];
  return !!afterChats && afterChats.split("/").filter(Boolean).length > 1;
}

function parentSessionIdFromPath(sessionPath) {
  if (!isNestedSubagentSession(sessionPath)) return "";
  return path.basename(path.dirname(sessionPath));
}

function geminiWorkspace(data) {
  const directories = Array.isArray(data?.directories)
    ? data.directories.filter((p) => typeof p === "string" && p.trim())
    : [];
  if (directories.length) return directories.join(", ");
  return data?.projectHash != null ? String(data.projectHash) : "";
}

function rowsFromGeminiConversation(data, sessionPath, attribution = {}) {
  if (!data || typeof data !== "object") return [];
  const messages = Array.isArray(data.messages) ? data.messages : [];
  if (!messages.length) return [];

  const sessionId = data.sessionId != null ? String(data.sessionId) : "";
  const workspace = geminiWorkspace(data);
  const sessionFallback = parseMessageTimestamp(data.startTime)
    ?? parseMessageTimestamp(data.lastUpdated);
  const isSidechain = data.kind === "subagent" || isNestedSubagentSession(sessionPath);
  const parentSessionId = parentSessionIdFromPath(sessionPath);
  const rows = [];
  let idx = 0;

  for (let msgIdx = 0; msgIdx < messages.length; msgIdx++) {
    const msg = messages[msgIdx];
    if (!msg || typeof msg !== "object") continue;
    const lineNumber = msg.__irflowLineNumber ?? (msgIdx + 1);
    const msgType = msg.type != null ? String(msg.type).toLowerCase() : "";
    const role = ROLE_BY_TYPE[msgType] || (msgType ? "system" : "");
    const messageId = msg.id != null
      ? String(msg.id)
      : `${sessionId || path.basename(sessionPath)}-${idx + 1}`;
    const tsMs = parseMessageTimestamp(msg.timestamp, sessionFallback);
    const thoughtText = normalizeThoughts(msg.thoughts);

    let summary = normalizeContent(msg.content, msg.thoughts);
    if (!summary && msg.message != null) summary = String(msg.message).trim();
    if (!summary && msg.error) summary = String(msg.error).trim();
    if (!summary && msgType === "error") summary = "[Error event]";
    if (!summary && role && !Array.isArray(msg.toolCalls)) summary = `[${msgType || role} event]`;

    if (summary) {
      const tokens = parseTokenCounts(msg.tokens);
      const bodyText = contentText(msg.content);
      const fullText = thoughtText
        ? `${bodyText ? `${bodyText}\n\n` : ""}Reasoning:\n${thoughtText}`
        : (bodyText || summary);
      idx += 1;
      rows.push(geminiRow({
        timestamp: formatTimestampUtc(tsMs),
        role: role || "system",
        recordType: msgType || role || "event",
        summary,
        fullText,
        toolName: "",
        sessionId,
        messageId,
        parentId: parentSessionId,
        workspace,
        isSidechain,
        gitBranch: "",
        model: msg.model != null ? String(msg.model) : "",
        inputTokens: tokens.input,
        outputTokens: tokens.output,
        sourceFile: sessionPath,
        lineNumber,
        sourceOffset: msg.__irflowSourceOffset,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }

    const toolCalls = Array.isArray(msg.toolCalls) ? msg.toolCalls : [];
    for (let toolIdx = 0; toolIdx < toolCalls.length; toolIdx++) {
      const call = toolCalls[toolIdx];
      if (!call || typeof call !== "object" || !call.name) continue;
      const callId = call.id != null ? String(call.id) : `${messageId}-tool-${toolIdx + 1}`;
      const callTs = parseMessageTimestamp(call.timestamp, tsMs);
      const status = call.status != null ? String(call.status) : "";
      const evidence = buildToolEvidence([{ name: call.name, input: call.args }]);
      rows.push(geminiRow({
        timestamp: formatTimestampUtc(callTs),
        role: "tool",
        recordType: "tool_call",
        summary: `${call.name}${status ? ` (${status})` : ""}`,
        fullText: serializeEvidenceValue(call.args),
        ...evidence,
        sessionId,
        messageId: callId,
        parentId: messageId,
        workspace,
        isSidechain,
        model: msg.model != null ? String(msg.model) : "",
        sourceFile: sessionPath,
        lineNumber,
        sourceOffset: msg.__irflowSourceOffset,
        user: attribution.user || "",
        host: attribution.host || "",
      }));

      if (call.result != null || call.resultDisplay != null) {
        const result = call.result ?? call.resultDisplay;
        rows.push(geminiRow({
          timestamp: formatTimestampUtc(callTs),
          role: "tool",
          recordType: "tool_result",
          summary: `${call.name} result${status ? ` (${status})` : ""}`,
          fullText: serializeEvidenceValue(result),
          ...evidence,
          sessionId,
          messageId: `${callId}-result`,
          parentId: callId,
          workspace,
          isSidechain,
          model: msg.model != null ? String(msg.model) : "",
          sourceFile: sessionPath,
          lineNumber,
          sourceOffset: msg.__irflowSourceOffset,
          user: attribution.user || "",
          host: attribution.host || "",
        }));
      }
    }
  }

  return rows;
}

/**
 * Parse one Gemini CLI session JSON file into timeline rows.
 */
function extractGeminiSessionFile(sessionPath, attribution = {}) {
  let data;
  try {
    if (fs.statSync(sessionPath).size > MAX_LEGACY_SESSION_BYTES) {
      dbg("AIHIST", "skip large gemini legacy session", { sessionPath });
      return [];
    }
    data = JSON.parse(fs.readFileSync(sessionPath, "utf8"));
  } catch (e) {
    dbg("AIHIST", "gemini session parse failed", { sessionPath, err: e.message });
    return [];
  }

  // JSON.parse("null") (and primitives/arrays) survive the try/catch above; guard before deref.
  if (!data || typeof data !== "object") return [];
  return rowsFromGeminiConversation(data, sessionPath, attribution);
}

function setGeminiMessageLineNumber(msg, lineNumber, sourceLocation = null) {
  if (!msg || typeof msg !== "object") return null;
  return { ...msg, __irflowLineNumber: lineNumber, __irflowSourceOffset: sourceLocation?.byteOffset };
}

async function extractGeminiSessionJsonlFile(sessionPath, attribution = {}, options = {}) {
  const metadata = {};
  const messages = new Map();
  const historyEvents = [];
  const historyOperations = [];
  const parseStats = options.parseStats || { errors: 0 };

  const addMessage = (msg, lineNumber, sourceLocation, sourceEventKind, pointer = "") => {
    if (!msg || typeof msg !== "object" || msg.id == null) return;
    const nativeId = String(msg.id);
    const previous = messages.get(nativeId);
    if (previous) {
      previous.historyStatus = "superseded";
      previous.replacedAtLine = lineNumber;
    }
    const sourceOffset = sourceLocation?.byteOffset != null
      ? `${sourceLocation.byteOffset}${pointer}`
      : pointer.replace(/^#/, "");
    const event = {
      message: { ...msg, __irflowLineNumber: lineNumber, __irflowSourceOffset: sourceOffset },
      nativeId,
      lineNumber,
      sourceOffset,
      sourceEventKind,
      revision: historyEvents.filter((item) => item.nativeId === nativeId).length + 1,
      historyStatus: "current",
      replacedAtLine: null,
      rewindAtLine: null,
    };
    historyEvents.push(event);
    messages.set(nativeId, event);
  };

  await readJsonlBounded(sessionPath, (record, lineNumber, sourceLocation) => {
    if (!record || typeof record !== "object" || Array.isArray(record)) return;

    if (typeof record.$rewindTo === "string") {
      let found = false;
      const affectedIds = [];
      for (const id of [...messages.keys()]) {
        if (id === record.$rewindTo) found = true;
        if (found) {
          const event = messages.get(id);
          if (event) {
            event.historyStatus = "rewound";
            event.rewindAtLine = lineNumber;
          }
          affectedIds.push(id);
          messages.delete(id);
        }
      }
      if (!found) {
        for (const [id, event] of messages) {
          event.historyStatus = "rewound_target_missing";
          event.rewindAtLine = lineNumber;
          affectedIds.push(id);
        }
        messages.clear();
      }
      historyOperations.push({
        kind: "rewind",
        lineNumber,
        sourceOffset: sourceLocation?.byteOffset,
        targetId: record.$rewindTo,
        targetFound: found,
        affectedIds,
        timestamp: record.timestamp ?? record.ts ?? null,
      });
      return;
    }

    if (record.$set && typeof record.$set === "object" && !Array.isArray(record.$set)) {
      if (Array.isArray(record.$set.messages)) {
        const replacedIds = [...messages.keys()];
        for (const event of messages.values()) {
          event.historyStatus = "replaced_by_snapshot";
          event.replacedAtLine = lineNumber;
        }
        messages.clear();
        for (let index = 0; index < record.$set.messages.length; index++) {
          addMessage(record.$set.messages[index], lineNumber, sourceLocation, "set_messages", `#/$set/messages/${index}`);
        }
        historyOperations.push({
          kind: "set_messages",
          lineNumber,
          sourceOffset: sourceLocation?.byteOffset,
          replacedIds,
          snapshotIds: [...messages.keys()],
          timestamp: record.timestamp ?? record.$set.timestamp ?? record.$set.lastUpdated ?? null,
        });
      }
      Object.assign(metadata, record.$set);
      return;
    }

    if (record.id != null && record.type != null && record.content != null) {
      addMessage(record, lineNumber, sourceLocation, "message");
      return;
    }

    if (record.sessionId != null || record.projectHash != null) {
      Object.assign(metadata, record);
      if (Array.isArray(record.messages)) {
        for (let index = 0; index < record.messages.length; index++) {
          addMessage(record.messages[index], lineNumber, sourceLocation, "session_snapshot", `#/messages/${index}`);
        }
      }
    }
  }, { parseStats });

  const currentRows = rowsFromGeminiConversation(
    { ...metadata, messages: [...messages.values()].map((event) => event.message) },
    sessionPath,
    attribution,
  );

  const historyRows = [];
  for (const event of historyEvents) {
    const normalized = rowsFromGeminiConversation(
      { ...metadata, messages: [event.message] },
      sessionPath,
      attribution,
    );
    for (let index = 0; index < normalized.length; index++) {
      const row = normalized[index];
      const nativeRecordType = row.RecordType;
      const nativeMessageId = row.MessageId;
      row.RecordType = `history_${nativeRecordType || "message"}`;
      row.Summary = `[Gemini history: ${event.historyStatus}] ${row.Summary}`;
      row.FullText = JSON.stringify({
        historyStatus: event.historyStatus,
        currentState: event.historyStatus === "current",
        sourceEventKind: event.sourceEventKind,
        nativeMessageId: event.nativeId,
        nativeRecordId: nativeMessageId,
        revision: event.revision,
        replacedAtLine: event.replacedAtLine,
        rewindAtLine: event.rewindAtLine,
        normalizedEvidence: row.FullText,
      }, null, 2);
      row.MessageId = `${event.nativeId}@line:${event.lineNumber}:rev:${event.revision}:${index + 1}`;
      row.ParentId = event.nativeId;
      row.SourceOffset = event.sourceOffset == null ? "" : String(event.sourceOffset);
      row.ToolDescription = "Immutable Gemini JSONL event-history projection. The currentState flag distinguishes active context from superseded, rewound, or snapshot-replaced source evidence.";
      historyRows.push(row);
    }
  }

  const operationRows = historyOperations.map((operation) => {
    const tsMs = parseMessageTimestamp(operation.timestamp);
    const affected = operation.affectedIds || operation.replacedIds || [];
    return geminiRow({
      timestamp: formatTimestampUtc(tsMs),
      timestampBasis: tsMs == null ? "unavailable" : "source history-operation timestamp",
      role: "system",
      recordType: operation.kind === "rewind" ? "history_rewind" : "history_set_messages",
      summary: operation.kind === "rewind"
        ? `Gemini history rewind to ${operation.targetId} — ${affected.length} message id(s) removed from current state`
        : `Gemini history snapshot replacement — ${affected.length} prior message id(s), ${operation.snapshotIds.length} replacement id(s)`,
      fullText: JSON.stringify(operation, null, 2),
      sessionId: metadata.sessionId != null ? String(metadata.sessionId) : "",
      messageId: `history-operation-line-${operation.lineNumber}`,
      parentId: operation.targetId || "",
      workspace: geminiWorkspace(metadata),
      sourceFile: sessionPath,
      lineNumber: operation.lineNumber,
      sourceOffset: operation.sourceOffset,
      user: attribution.user || "",
      host: attribution.host || "",
      toolDescription: "Source history operation preserved independently of the reconstructed current conversation. It changes current context but does not erase the earlier source events from forensic output.",
    });
  });

  const rows = [...currentRows, ...historyRows, ...operationRows];
  rows._geminiHistoryStats = {
    currentMessageRows: currentRows.length,
    historyRows: historyRows.length,
    historySourceMessages: historyEvents.length,
    operations: operationRows.length,
    rewoundMessages: historyEvents.filter((event) => event.historyStatus.startsWith("rewound")).length,
    supersededMessages: historyEvents.filter((event) => event.historyStatus === "superseded").length,
    snapshotReplacedMessages: historyEvents.filter((event) => event.historyStatus === "replaced_by_snapshot").length,
  };
  return rows;
}

function extractGeminiShellHistoryFile(historyPath, attribution = {}) {
  let raw;
  try {
    if (fs.statSync(historyPath).size > MAX_SHELL_HISTORY_BYTES) {
      dbg("AIHIST", "skip large gemini shell history", { historyPath });
      return [];
    }
    raw = fs.readFileSync(historyPath, "utf8");
  } catch {
    return [];
  }

  const workspace = path.basename(path.dirname(historyPath));
  const commands = [];
  let current = "";
  let startLine = 0;
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const line = lines[i];
    if (!line.trim()) continue;
    const trailingSlashes = current.match(/(\\+)$/);
    if (current && trailingSlashes && trailingSlashes[1].length % 2 === 1) {
      current = `${current.slice(0, -1)} ${line}`;
      continue;
    }
    if (current) commands.push({ command: current, lineNumber: startLine });
    current = line;
    startLine = lineNumber;
  }
  if (current) commands.push({ command: current, lineNumber: startLine });

  return commands.map(({ command, lineNumber }, index) => {
    const evidence = buildToolEvidence([{
      name: "run_shell_command",
      input: { command },
    }]);
    return geminiRow({
      timestamp: "",
      role: "user",
      recordType: "shell_history",
      summary: command,
      fullText: command,
      ...evidence,
      sessionId: "",
      messageId: `shell-history-${index + 1}`,
      workspace,
      isSidechain: false,
      sourceFile: historyPath,
      lineNumber,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

/**
 * Parse legacy tmp/<hash>/logs.json (array of { type, message, timestamp, sessionId, messageId }).
 */
function extractGeminiLogsFile(logsPath, attribution = {}) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(logsPath, "utf8"));
  } catch (e) {
    dbg("AIHIST", "gemini logs parse failed", { logsPath, err: e.message });
    return [];
  }

  const entries = Array.isArray(data)
    ? data
    : (Array.isArray(data?.messages) ? data.messages : (Array.isArray(data?.logs) ? data.logs : []));
  if (!entries.length) return [];

  const workspace = path.basename(path.dirname(logsPath));
  const rows = [];

  for (let msgIdx = 0; msgIdx < entries.length; msgIdx++) {
    const msg = entries[msgIdx];
    if (!msg || typeof msg !== "object") continue;

    const msgType = msg.type != null ? String(msg.type).toLowerCase() : "";
    const role = ROLE_BY_TYPE[msgType] || (msgType ? "system" : "user");

    let summary = normalizeContent(msg.content ?? msg.message, msg.thoughts);
    if (!summary && msg.error) summary = String(msg.error).trim();
    if (!summary && msgType === "error") summary = "[Error event]";
    if (!summary && role) summary = `[${msgType || role} event]`;
    if (!summary) continue;

    const tsMs = parseMessageTimestamp(msg.timestamp);
    if (tsMs == null) continue;

    const sessionId = msg.sessionId != null ? String(msg.sessionId) : "";
    const msgKey = msg.messageId != null ? String(msg.messageId) : String(msgIdx + 1);
    const tokens = parseTokenCounts(msg.tokens);

    rows.push(geminiRow({
      timestamp: formatTimestampUtc(tsMs),
      role: role || "user",
      recordType: msgType || role || "event",
      summary,
      toolName: "",
      sessionId,
      messageId: sessionId ? `${sessionId}-${msgKey}` : `${path.basename(logsPath)}-${msgKey}`,
      parentId: "",
      workspace,
      isSidechain: false,
      gitBranch: "",
      model: msg.model != null ? String(msg.model) : "",
      inputTokens: tokens.input,
      outputTokens: tokens.output,
      sourceFile: logsPath,
      lineNumber: msgIdx + 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  return rows;
}

function isGeminiLogsFile(filePath) {
  if (!filePath || path.basename(filePath) !== LOGS_FILE_NAME) return false;
  const norm = filePath.replace(/\\/g, "/").toLowerCase();
  return norm.includes("/tmp/");
}

function isGeminiSessionFile(filePath) {
  const base = path.basename(filePath);
  const norm = filePath.replace(/\\/g, "/").toLowerCase();
  if (SESSION_FILE_RE.test(base)) return norm.includes("/chats/");
  if (base.toLowerCase().endsWith(".jsonl") && norm.includes("/chats/")) return true;
  if (CHECKPOINT_FILE_RE.test(base)) return norm.includes("/tmp/");
  return false;
}

function isGeminiShellHistoryFile(filePath) {
  if (!filePath || path.basename(filePath) !== SHELL_HISTORY_FILE_NAME) return false;
  const norm = filePath.replace(/\\/g, "/").toLowerCase();
  return norm.includes("/tmp/");
}

function safeStat(p) {
  try { return fs.statSync(p); } catch { return null; }
}

function readJsonIfObject(filePath, maxBytes = MAX_STATE_JSON_BYTES) {
  const st = safeStat(filePath);
  if (!st || !st.isFile() || st.size > maxBytes) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    if (!parsed || typeof parsed !== "object") return null;
    return parsed;
  } catch {
    return null;
  }
}

function isGeminiStateFile(filePath) {
  if (!filePath) return false;
  const base = path.basename(filePath);
  const parent = path.basename(path.dirname(filePath));
  const grand = path.basename(path.dirname(path.dirname(filePath)));
  const parentPath = path.dirname(filePath);
  const likelyRoot = parent === GEMINI_DIR_NAME || ["tmp", "history", PROJECTS_FILE, SETTINGS_FILE, "installation_id"]
    .some((name) => fs.existsSync(path.join(parentPath, name)));
  if (base === SETTINGS_FILE && likelyRoot) return true;
  if (base === PROJECTS_FILE && likelyRoot) return true;
  if (base === TRUSTED_FOLDERS_FILE && likelyRoot) return true;
  if (base === GOOGLE_ACCOUNTS_FILE && likelyRoot) return true;
  if (base === GEMINI_MD_FILE && likelyRoot) return true;
  if (GEMINI_STATE_BACKUP_RE.test(base) && likelyRoot) return true;
  if (OAUTH_INVENTORY_FILES.has(base) && likelyRoot) return true;
  if (IDENTITY_FILES.has(base) && likelyRoot) return true;
  if (/\.(?:toml|json)$/i.test(base) && parent === "policies") return true;
  if (base === PROJECT_ROOT_FILE && (grand === "history" || grand === "tmp")) {
    return true;
  }
  return false;
}

function isGeminiDataFile(filePath) {
  return isGeminiSessionFile(filePath)
    || isGeminiLogsFile(filePath)
    || isGeminiShellHistoryFile(filePath)
    || isGeminiStateFile(filePath);
}

function walkGeminiTmp(geminiRoot, onFile, limits = { maxDirs: 96, maxDepth: 6 }) {
  const tmpDir = path.join(geminiRoot, "tmp");
  if (!fs.existsSync(tmpDir)) return;
  let dirsVisited = 0;
  const stack = [{ d: tmpDir, depth: 0 }];
  while (stack.length && dirsVisited < limits.maxDirs) {
    const { d, depth } = stack.pop();
    dirsVisited += 1;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isFile()) onFile(full);
      if (e.isDirectory() && depth < limits.maxDepth && !e.isSymbolicLink()) {
        stack.push({ d: full, depth: depth + 1 });
      }
    }
  }
}

/** Fast existence check for discovery (bounded walk — avoids hanging on huge ~/.gemini/tmp). */
function hasGeminiSessionsQuick(geminiRoot, limits = { maxDirs: 96, maxDepth: 6 }) {
  if (fs.existsSync(path.join(geminiRoot, SETTINGS_FILE))
    || fs.existsSync(path.join(geminiRoot, PROJECTS_FILE))
    || fs.existsSync(path.join(geminiRoot, TRUSTED_FOLDERS_FILE))) {
    return true;
  }
  const tmpDir = path.join(geminiRoot, "tmp");
  if (!fs.existsSync(tmpDir)) return false;
  let found = false;
  walkGeminiTmp(geminiRoot, (full) => {
    if (!found && isGeminiDataFile(full)) found = true;
  }, limits);
  return found;
}

/** List current JSONL and legacy JSON session files under geminiRoot/tmp/.../chats/. */
function listSessionJsonFiles(geminiRoot) {
  const out = [];
  walkGeminiTmp(geminiRoot, (full) => {
    if (isGeminiSessionFile(full)) out.push(full);
  }, { maxDirs: 10_000, maxDepth: 12 });
  return out;
}

function listShellHistoryFiles(geminiRoot) {
  const out = [];
  walkGeminiTmp(geminiRoot, (full) => {
    if (isGeminiShellHistoryFile(full)) out.push(full);
  }, { maxDirs: 10_000, maxDepth: 12 });
  return out;
}

/** List tmp/<hash>/logs.json files (legacy Gemini CLI conversation log). */
function listLogsJsonFiles(geminiRoot) {
  const out = [];
  walkGeminiTmp(geminiRoot, (full) => {
    if (isGeminiLogsFile(full)) out.push(full);
  }, { maxDirs: 10_000, maxDepth: 12 });
  return out;
}

/** All parseable Gemini CLI JSON artifacts under a .gemini root. */
function listGeminiDataFiles(geminiRoot) {
  return [
    ...listSessionJsonFiles(geminiRoot),
    ...listLogsJsonFiles(geminiRoot),
    ...listShellHistoryFiles(geminiRoot),
  ];
}

function listProjectRootFiles(geminiRoot) {
  const out = [];
  for (const sub of ["history", "tmp"]) {
    const dir = path.join(geminiRoot, sub);
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink()) continue;
      const marker = path.join(dir, e.name, PROJECT_ROOT_FILE);
      if (fs.existsSync(marker)) out.push(marker);
    }
  }
  return out;
}

/** Root-level 0.58+ control-plane files (settings, project registry, identity). */
function listGeminiStateFiles(geminiRoot) {
  if (!geminiRoot) return [];
  const out = [];
  for (const name of [
    SETTINGS_FILE, PROJECTS_FILE, TRUSTED_FOLDERS_FILE, GOOGLE_ACCOUNTS_FILE, GEMINI_MD_FILE,
    ...OAUTH_INVENTORY_FILES, ...IDENTITY_FILES,
  ]) {
    const full = path.join(geminiRoot, name);
    if (fs.existsSync(full) && safeStat(full)?.isFile()) out.push(full);
  }
  let rootEntries = [];
  try { rootEntries = fs.readdirSync(geminiRoot, { withFileTypes: true }); } catch { /* absent */ }
  for (const entry of rootEntries) {
    if (entry.isFile() && GEMINI_STATE_BACKUP_RE.test(entry.name)) out.push(path.join(geminiRoot, entry.name));
  }
  out.push(...listProjectRootFiles(geminiRoot));
  const skillsDir = path.join(geminiRoot, "skills");
  if (fs.existsSync(skillsDir)) out.push(skillsDir);
  const policyDir = path.join(geminiRoot, "policies");
  if (fs.existsSync(policyDir)) {
    const listed = walkContextFiles(policyDir, {
      maxDepth: 4,
      maxFiles: 500,
      accept: (filePath) => /\.(?:toml|json)$/i.test(filePath),
    });
    out.push(...listed.files);
  }
  return out;
}

function extractGeminiSettings(filePath, attribution) {
  const obj = readJsonIfObject(filePath);
  if (!obj) return [];
  const st = safeStat(filePath);
  const timestamp = formatTimestampUtc(st ? st.mtimeMs : null);
  const rows = [];
  const authType = obj.security?.auth?.selectedType || obj.security?.auth?.type || "";
  const retention = obj.general?.sessionRetention || null;
  const autoMemory = obj.experimental?.autoMemory;
  const tools = obj.tools && typeof obj.tools === "object" ? obj.tools : {};
  const policy = obj.policy && typeof obj.policy === "object" ? obj.policy : {};
  const security = obj.security && typeof obj.security === "object" ? obj.security : {};
  rows.push(geminiRow({
    timestamp,
    role: "metadata",
    recordType: "cli_settings",
    summary: "Gemini CLI settings"
      + `${authType ? ` — auth ${authType}` : ""}`
      + `${retention?.enabled ? `, sessionRetention ${retention.maxAge || ""}/${retention.maxCount || ""}` : ""}`
      + `${autoMemory === true ? ", Auto Memory on" : ""}`,
    fullText: JSON.stringify({
      authType,
      sessionRetention: retention,
      autoMemory: autoMemory === true,
      theme: obj.ui?.theme || "",
      toolPolicy: {
        allowed: Array.isArray(tools.allowed) ? tools.allowed.map(String) : [],
        excluded: Array.isArray(tools.exclude) ? tools.exclude.map(String) : [],
        sandbox: tools.sandbox ?? security.sandbox ?? null,
        approvalMode: policy.approvalMode ?? security.approvalMode ?? null,
      },
      configuredMcpServers: obj.mcpServers && typeof obj.mcpServers === "object"
        ? Object.keys(obj.mcpServers).sort() : [],
      timeSource: "settings.json mtime",
    }, null, 2),
    toolDescription: "User-level Gemini CLI settings. Dated from the file mtime.",
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  }));

  const hooks = obj.hooks && typeof obj.hooks === "object" ? obj.hooks : {};
  for (const [eventName, entries] of Object.entries(hooks)) {
    const list = Array.isArray(entries) ? entries : [entries];
    for (const entry of list) {
      if (!entry || typeof entry !== "object") continue;
      const matcher = entry.matcher != null ? String(entry.matcher) : "";
      const hookList = Array.isArray(entry.hooks) ? entry.hooks : [];
      for (const hook of hookList) {
        if (!hook || typeof hook !== "object") continue;
        const command = hook.command != null ? String(hook.command) : "";
        const type = hook.type != null ? String(hook.type) : "";
        rows.push(geminiRow({
          timestamp,
          role: "metadata",
          recordType: "hook",
          summary: `Gemini CLI hook — ${eventName}${matcher ? ` (${matcher})` : ""}: ${command || type || "(empty)"}`,
          fullText: JSON.stringify({
            event: eventName, matcher, type, command, timeSource: "settings.json mtime",
          }, null, 2),
          toolName: eventName,
          toolCommand: command,
          toolDescription: "A command Gemini CLI runs on a lifecycle event. Execution-persistence "
            + "surface, equivalent to Claude/Codex hooks.",
          sourceFile: filePath,
          user: attribution.user || "",
          host: attribution.host || "",
        }));
      }
    }
  }
  const mcpServers = obj.mcpServers && typeof obj.mcpServers === "object" ? obj.mcpServers : {};
  for (const [name, config] of Object.entries(mcpServers).sort(([a], [b]) => a.localeCompare(b))) {
    const safe = safeServerConfig(name, config);
    rows.push(geminiRow({
      timestamp,
      timestampBasis: "settings.json mtime",
      role: "metadata",
      recordType: "mcp_server_config",
      summary: `Gemini CLI MCP server — ${name}`
        + `${safe.command ? ` (${safe.command})` : safe.url ? ` (${safe.url})` : ""}`
        + `${safe.disabled ? " [disabled]" : ""}`,
      fullText: JSON.stringify(safe, null, 2),
      toolName: name,
      toolCommand: safe.command,
      toolInput: safe.args.join(" "),
      toolDescription: "Gemini CLI MCP configuration. Environment, header, credential, and URL query values are excluded; only their names are retained.",
      sourceFile: filePath,
      messageId: `mcp:${name}`,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function extractGeminiProjects(filePath, attribution) {
  const obj = readJsonIfObject(filePath);
  if (!obj) return [];
  const st = safeStat(filePath);
  const timestamp = formatTimestampUtc(st ? st.mtimeMs : null);
  const map = obj.projects && typeof obj.projects === "object" ? obj.projects : obj;
  if (!map || typeof map !== "object" || Array.isArray(map)) return [];
  const rows = [];
  for (const [workspace, shortId] of Object.entries(map)) {
    if (!workspace || workspace === "projects") continue;
    const id = shortId != null ? String(shortId) : "";
    rows.push(geminiRow({
      timestamp,
      role: "metadata",
      recordType: "project_registry",
      summary: `Gemini CLI project — ${workspace} (${id})`,
      fullText: JSON.stringify({ workspace, shortId: id, timeSource: "projects.json mtime" }, null, 2),
      workspace,
      sessionId: id,
      toolDescription: "0.58+ project registry mapping a workspace path to the short id used under "
        + "~/.gemini/tmp/<id> and ~/.gemini/history/<id>.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function extractGeminiTrustedFolders(filePath, attribution) {
  const obj = readJsonIfObject(filePath);
  if (!obj) return [];
  const st = safeStat(filePath);
  const timestamp = formatTimestampUtc(st ? st.mtimeMs : null);
  const rows = [];
  const emit = (folder, decision) => {
    if (!folder) return;
    rows.push(geminiRow({
      timestamp,
      role: "metadata",
      recordType: "trusted_folder",
      summary: `Gemini CLI trusted folder — ${folder}${decision ? ` (${decision})` : ""}`,
      fullText: JSON.stringify({ folder, decision: decision || "", timeSource: "trustedFolders.json mtime" }, null, 2),
      workspace: folder,
      toolDescription: "A folder the user trusted so Gemini CLI may act in it without a further prompt.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  };
  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (typeof item === "string") emit(item, "");
      else if (item && typeof item === "object") emit(item.path || item.folder || "", item.decision || item.trust || "");
    }
    return rows;
  }
  const map = obj.folders && typeof obj.folders === "object" ? obj.folders : obj;
  for (const [folder, val] of Object.entries(map)) {
    if (folder === "folders") continue;
    if (typeof val === "string" || typeof val === "boolean") emit(folder, String(val));
    else if (val && typeof val === "object") emit(folder, String(val.decision || val.trust || val.level || ""));
    else emit(folder, "");
  }
  return rows;
}

function extractGeminiAccounts(filePath, attribution) {
  const obj = readJsonIfObject(filePath);
  if (!obj) return [];
  const st = safeStat(filePath);
  const timestamp = formatTimestampUtc(st ? st.mtimeMs : null);
  const active = obj.active != null ? String(obj.active) : "";
  const old = Array.isArray(obj.old) ? obj.old.map((v) => String(v)) : [];
  return [geminiRow({
    timestamp,
    role: "metadata",
    recordType: "account_identity",
    summary: `Gemini CLI account — ${active || "(none active)"}`
      + `${old.length ? `, ${old.length} previous` : ""}`,
    fullText: JSON.stringify({ active, old, timeSource: "google_accounts.json mtime" }, null, 2),
    toolDescription: "Google account email recorded by Gemini CLI. OAuth tokens live in "
      + "oauth_creds.json and are inventoried without being read.",
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  })];
}

function extractGeminiIdentityFile(filePath, attribution) {
  const st = safeStat(filePath);
  if (!st || !st.isFile() || st.size > 256) return [];
  let value = "";
  try { value = fs.readFileSync(filePath, "utf8").trim(); } catch { return []; }
  const name = path.basename(filePath);
  return [geminiRow({
    timestamp: formatTimestampUtc(st.mtimeMs),
    role: "metadata",
    recordType: "cli_identity",
    summary: `Gemini CLI ${name} — ${value}`,
    fullText: JSON.stringify({ name, value, timeSource: `${name} mtime` }, null, 2),
    toolDescription: "A stable Gemini CLI identifier (installation, user, or Google account id).",
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  })];
}

function extractGeminiOauthInventory(filePath, attribution) {
  const st = safeStat(filePath);
  if (!st) return [];
  return [geminiRow({
    timestamp: formatTimestampUtc(st.mtimeMs),
    role: "metadata",
    recordType: "credential_inventory",
    summary: `Gemini CLI credential store present — ${path.basename(filePath)} (${st.size} bytes)`,
    fullText: JSON.stringify({
      file: path.basename(filePath),
      sizeBytes: st.size,
      timeSource: "file mtime",
      contentsRead: false,
    }, null, 2),
    toolDescription: "OAuth/token store inventoried by name and size. Contents are never read.",
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  })];
}

function extractGeminiProjectRootMarker(filePath, attribution) {
  const st = safeStat(filePath);
  if (!st) return [];
  let workspace = "";
  try { workspace = fs.readFileSync(filePath, "utf8").trim(); } catch { return []; }
  if (!workspace) return [];
  const shortId = path.basename(path.dirname(filePath));
  const kind = path.basename(path.dirname(path.dirname(filePath)));
  return [geminiRow({
    timestamp: formatTimestampUtc(st.mtimeMs),
    role: "metadata",
    recordType: "project_root",
    summary: `Gemini CLI ${kind} slug ${shortId} → ${workspace}`,
    fullText: JSON.stringify({ shortId, workspace, tree: kind, timeSource: ".project_root mtime" }, null, 2),
    workspace,
    sessionId: shortId,
    toolDescription: "0.58+ slug directory marker mapping ~/.gemini/tmp/<id> or history/<id> back "
      + "to the workspace path. Replaces the older hash-named tmp folders.",
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  })];
}

function extractGeminiSkillsInventory(skillsDir, attribution) {
  const st = safeStat(skillsDir);
  if (!st || !st.isDirectory()) return [];
  let names = [];
  try {
    names = fs.readdirSync(skillsDir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !e.isSymbolicLink())
      .map((e) => e.name);
  } catch { return []; }
  if (!names.length) return [];
  const rows = [geminiRow({
    timestamp: formatTimestampUtc(st.mtimeMs),
    role: "metadata",
    recordType: "skill_inventory",
    summary: `Gemini CLI skills — ${names.join(", ")}`,
    fullText: JSON.stringify({ skills: names, timeSource: "skills directory mtime" }, null, 2),
    toolDescription: "Skill directories under ~/.gemini/skills. Names only; SKILL.md bodies are not ingested.",
    sourceFile: skillsDir,
    user: attribution.user || "",
    host: attribution.host || "",
  })];
  const listed = walkContextFiles(skillsDir, {
    maxDepth: 5,
    maxFiles: 1000,
    accept: (filePath) => path.basename(filePath) === "SKILL.md" || /\.(?:json|ya?ml)$/i.test(filePath),
  });
  for (const filePath of listed.files) {
    const row = contextInventoryRow({
      tool: TOOL_GEMINI_CLI,
      rootPath: skillsDir,
      filePath,
      family: "skill-context",
      recordType: "skill_file_inventory",
      summaryLabel: "Gemini CLI skill context",
      attribution,
      toolDescription: "Skill definition or manifest inventoried with SHA-256. The body is not copied into the timeline row.",
    });
    if (row) rows.push(row);
  }
  return rows;
}

function extractGeminiMd(filePath, attribution) {
  const st = safeStat(filePath);
  if (!st || !st.isFile()) return [];
  const row = contextInventoryRow({
    tool: TOOL_GEMINI_CLI,
    rootPath: path.dirname(filePath),
    filePath,
    family: "instruction-memory",
    recordType: "memory_file",
    summaryLabel: "Gemini CLI GEMINI.md",
    attribution,
    toolDescription: "Global instruction or memory file loaded into Gemini CLI sessions. The row retains a SHA-256 and source metadata; acquire SourceFile for the body.",
  });
  return row ? [row] : [];
}

function extractGeminiBackupOrPolicyInventory(filePath, attribution) {
  const st = safeContextStat(filePath);
  if (!st?.isFile()) return [];
  const backup = GEMINI_STATE_BACKUP_RE.test(path.basename(filePath));
  const row = contextInventoryRow({
    tool: TOOL_GEMINI_CLI,
    rootPath: path.dirname(filePath),
    filePath,
    family: backup ? "state-backup" : "policy-config",
    recordType: backup ? "state_backup_inventory" : "policy_inventory",
    summaryLabel: backup ? "Gemini CLI replaced or backup state" : "Gemini CLI policy configuration",
    attribution,
    toolDescription: backup
      ? "Replacement/backup artifact retained independently of current state. SHA-256 allows exact raw linkage without treating it as current configuration."
      : "Policy file inventoried as configuration. Presence and mtime do not prove a policy decision or tool execution.",
    extra: backup ? { currentState: false, linkedCurrentSource: path.join(path.dirname(filePath), path.basename(filePath).split(".json")[0] + ".json") } : {},
  });
  return row ? [row] : [];
}

function extractGeminiStateFile(filePath, attribution) {
  const base = path.basename(filePath);
  if (base === SETTINGS_FILE) return extractGeminiSettings(filePath, attribution);
  if (base === PROJECTS_FILE) return extractGeminiProjects(filePath, attribution);
  if (base === TRUSTED_FOLDERS_FILE) return extractGeminiTrustedFolders(filePath, attribution);
  if (base === GOOGLE_ACCOUNTS_FILE) return extractGeminiAccounts(filePath, attribution);
  if (base === GEMINI_MD_FILE) return extractGeminiMd(filePath, attribution);
  if (OAUTH_INVENTORY_FILES.has(base)) return extractGeminiOauthInventory(filePath, attribution);
  if (IDENTITY_FILES.has(base)) return extractGeminiIdentityFile(filePath, attribution);
  if (base === PROJECT_ROOT_FILE) return extractGeminiProjectRootMarker(filePath, attribution);
  if (GEMINI_STATE_BACKUP_RE.test(base) || /[\\/]policies[\\/].*\.(?:toml|json)$/i.test(filePath)) {
    return extractGeminiBackupOrPolicyInventory(filePath, attribution);
  }
  const st = safeStat(filePath);
  if (st && st.isDirectory() && path.basename(filePath) === "skills") {
    return extractGeminiSkillsInventory(filePath, attribution);
  }
  return [];
}

function mergeGeminiHistoryStats(a, b) {
  const out = { ...(a || {}) };
  for (const [key, value] of Object.entries(b || {})) {
    if (typeof value === "number") out[key] = Number(out[key] || 0) + value;
  }
  return out;
}

function isGeminiCliRoot(dirPath, { quick = false } = {}) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  const configuredHome = process.env.GEMINI_CLI_HOME ? path.resolve(process.env.GEMINI_CLI_HOME) : "";
  const explicitRoot = path.basename(dirPath) === GEMINI_DIR_NAME
    || (configuredHome && path.resolve(dirPath) === configuredHome)
    || [SETTINGS_FILE, PROJECTS_FILE, TRUSTED_FOLDERS_FILE, GOOGLE_ACCOUNTS_FILE, GEMINI_MD_FILE, "installation_id"]
      .some((name) => fs.existsSync(path.join(dirPath, name)));
  if (!explicitRoot) return false;
  if (quick) return hasGeminiSessionsQuick(dirPath);
  return listGeminiDataFiles(dirPath).length > 0 || listGeminiStateFiles(dirPath).length > 0;
}

async function extractGeminiDataFile(filePath, attribution, options = {}) {
  if (isGeminiStateFile(filePath) || (safeStat(filePath)?.isDirectory() && path.basename(filePath) === "skills")) {
    return extractGeminiStateFile(filePath, attribution);
  }
  if (isGeminiLogsFile(filePath)) return extractGeminiLogsFile(filePath, attribution);
  if (isGeminiShellHistoryFile(filePath)) return extractGeminiShellHistoryFile(filePath, attribution);
  if (path.extname(filePath).toLowerCase() === ".jsonl") {
    return extractGeminiSessionJsonlFile(filePath, attribution, options);
  }
  return extractGeminiSessionFile(filePath, attribution);
}

async function extractGeminiCliDir(geminiRoot, attribution = {}, options = {}) {
  const rows = [];
  const parseStats = options.parseStats || { errors: 0 };
  const dataPaths = [...listGeminiStateFiles(geminiRoot), ...listGeminiDataFiles(geminiRoot)];
  const fileCount = dataPaths.length;
  const { onFileProgress, onExtractedRows, checkAbort } = options;
  let historyStats = null;

  for (let i = 0; i < dataPaths.length; i++) {
    const dataPath = dataPaths[i];
    if (typeof checkAbort === "function") checkAbort();
    tickFileProgress(onFileProgress, i + 1, fileCount, dataPath);
    try {
      const fileRows = await extractGeminiDataFile(
        dataPath,
        attribution,
        { ...options, parseStats },
      );
      if (fileRows._geminiHistoryStats) {
        historyStats = mergeGeminiHistoryStats(historyStats, fileRows._geminiHistoryStats);
      }
      if (onExtractedRows && fileRows.length) onExtractedRows(fileRows);
      else rows.push(...fileRows);
    } catch (e) {
      dbg("AIHIST", "gemini extract failed", { dataPath, err: e.message });
    }
    if ((i + 1) % 16 === 0) await new Promise((r) => setImmediate(r));
  }
  if (onExtractedRows) {
    const out = [];
    if (historyStats) out._geminiHistoryStats = historyStats;
    if (parseStats.errors) out._parseErrors = parseStats.errors;
    return out;
  }
  const finalized = finalizeAiHistoryRows(rows, options);
  if (historyStats) finalized._geminiHistoryStats = historyStats;
  if (parseStats.errors) finalized._parseErrors = parseStats.errors;
  return finalized;
}

function resolveGeminiCliRoot(target) {
  if (!target) return null;
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }

  for (let i = 0; i < 12; i++) {
    if (isGeminiCliRoot(p)) return p;
    const base = path.basename(p);
    if (/^\.(?:copilot|cursor|continue|claude|grok|codex)$/i.test(base)) break;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  if (isGeminiCliRoot(target)) return target;
  return null;
}

async function extractGeminiCliPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  const stat = fs.statSync(target);
  if (stat.isFile()) {
    if (!isGeminiDataFile(target) && path.basename(target) !== "skills") {
      throw new Error("Expected a Gemini CLI session JSON/JSONL, logs.json, shell_history, or .gemini state file.");
    }
    return finalizeAiHistoryRows(await extractGeminiDataFile(target, attribution, options), options);
  }

  const root = resolveGeminiCliRoot(target);
  if (!root || !isGeminiCliRoot(root)) {
    throw new Error("Not a Gemini CLI .gemini directory (expected chats/*.jsonl, legacy JSON/logs, shell_history, or 0.58+ state files).");
  }
  return extractGeminiCliDir(root, attribution, options);
}

/** Count parseable data files (for triage manifest sizing). */
function countGeminiSessions(geminiRoot) {
  return listGeminiDataFiles(geminiRoot).length;
}

module.exports = {
  GEMINI_DIR_NAME,
  extractGeminiSessionFile,
  extractGeminiSessionJsonlFile,
  extractGeminiShellHistoryFile,
  extractGeminiLogsFile,
  extractGeminiCliDir,
  extractGeminiCliPath,
  isGeminiCliRoot,
  isGeminiSessionFile,
  isGeminiShellHistoryFile,
  isGeminiLogsFile,
  isGeminiDataFile,
  resolveGeminiCliRoot,
  hasGeminiSessionsQuick,
  listSessionJsonFiles,
  listShellHistoryFiles,
  listLogsJsonFiles,
  listGeminiDataFiles,
  listGeminiStateFiles,
  countGeminiSessions,
  isGeminiStateFile,
  extractGeminiStateFile,
  mergeGeminiHistoryStats,
};
