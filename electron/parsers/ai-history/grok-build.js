/**
 * parsers/ai-history/grok-build.js — official xAI Grok Build terminal-agent artifacts.
 *
 * Verified layout (Grok Build 0.2.x):
 *   $GROK_HOME or ~/.grok/
 *     sessions/<url-encoded-cwd>/prompt_history.jsonl
 *     sessions/<url-encoded-cwd>/<session-id>/summary.json
 *     sessions/<url-encoded-cwd>/<session-id>/updates.jsonl
 *     sessions/<url-encoded-cwd>/<session-id>/chat_history.jsonl
 *     sessions/<url-encoded-cwd>/<session-id>/hunk_records.jsonl
 *     sessions/<url-encoded-cwd>/<session-id>/terminal/call-*.log
 *
 * updates.jsonl is preferred because it supplies event timestamps and exact rawInput/rawOutput.
 * chat_history.jsonl is a normalized, timestamp-less fallback for older/incomplete sessions.
 * Credential/config files (auth.json, mcp_credentials.json, config.toml) are intentionally ignored.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const { dbg } = require("../../logger");
const { readJsonlBounded } = require("./jsonl-reader");
const { filterSidechainRows, tickFileProgress } = require("./extract-plan");
const { TOOL_GROK_BUILD } = require("./schema");
const { buildToolEvidence, serializeEvidenceValue } = require("./tool-evidence");
const { collectGrokRuntimeArtifacts } = require("./grok-runtime");
const {
  formatTimestampUtc,
  parseIsoTimestamp,
  makeRow,
  assignLineNumber,
  finalizeAiHistoryRows,
  truncateSummary,
} = require("./row-utils");

const GROK_DIR_NAME = ".grok";
const GROK_SESSION_FILES = new Set([
  "summary.json",
  "updates.jsonl",
  "chat_history.jsonl",
  "hunk_records.jsonl",
]);
const MAX_SUMMARY_BYTES = 4 * 1024 * 1024;

function grokRow(fields) {
  return makeRow({ ...fields, tool: fields.tool || TOOL_GROK_BUILD }, TOOL_GROK_BUILD);
}

function safeIsDirectory(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}

function safeIsFile(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

function defaultGrokHome() {
  if (process.env.GROK_HOME) return path.resolve(process.env.GROK_HOME);
  return path.join(os.homedir(), GROK_DIR_NAME);
}

function workspaceFromContainerDir(workspaceDir) {
  const cwdFile = path.join(workspaceDir, ".cwd");
  try {
    if (safeIsFile(cwdFile) && fs.statSync(cwdFile).size <= 64 * 1024) {
      const cwd = fs.readFileSync(cwdFile, "utf8").trim();
      if (cwd) return cwd;
    }
  } catch { /* fall through to encoded directory name */ }
  try {
    return decodeURIComponent(path.basename(workspaceDir));
  } catch {
    return path.basename(workspaceDir);
  }
}

function hasGrokSessionEvidence(sessionsDir, { quick = false } = {}) {
  if (!safeIsDirectory(sessionsDir)) return false;
  const stack = [{ dir: sessionsDir, depth: 0 }];
  let checked = 0;
  while (stack.length) {
    const { dir, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      checked += 1;
      if (entry.isFile() && (
        entry.name === "prompt_history.jsonl"
        || entry.name === "summary.json"
        || entry.name === "updates.jsonl"
        || entry.name === "chat_history.jsonl"
      )) return true;
      if (entry.isDirectory() && !entry.isSymbolicLink() && depth < 4) {
        stack.push({ dir: path.join(dir, entry.name), depth: depth + 1 });
      }
      if (quick && checked >= 100) return false;
    }
  }
  return false;
}

function isGrokBuildRoot(rootPath, options = {}) {
  if (!rootPath || !safeIsDirectory(rootPath)) return false;
  const sessionsDir = path.join(rootPath, "sessions");
  if (!safeIsDirectory(sessionsDir)) return false;
  return hasGrokSessionEvidence(sessionsDir, options);
}

function resolveGrokHome(target) {
  if (!target) {
    const candidate = defaultGrokHome();
    return isGrokBuildRoot(candidate) ? candidate : null;
  }
  let current = path.resolve(target);
  try {
    if (fs.statSync(current).isFile()) current = path.dirname(current);
  } catch { return null; }
  for (let i = 0; i < 24; i++) {
    if (isGrokBuildRoot(current, { quick: true })) return current;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

function isGrokBuildArtifactFile(filePath) {
  if (!filePath || !safeIsFile(filePath)) return false;
  const base = path.basename(filePath);
  if (base !== "prompt_history.jsonl" && !GROK_SESSION_FILES.has(base)) return false;
  return !!resolveGrokHome(filePath);
}

function isGrokSidechainPath(filePath) {
  const normalized = String(filePath || "").replace(/\\/g, "/");
  return normalized.includes("/subagents/");
}

function listGrokPromptHistoryFiles(grokRoot) {
  const sessionsDir = path.join(grokRoot, "sessions");
  if (!safeIsDirectory(sessionsDir)) return [];
  const out = [];
  let workspaces;
  try { workspaces = fs.readdirSync(sessionsDir, { withFileTypes: true }); } catch { return out; }
  for (const workspace of workspaces) {
    if (!workspace.isDirectory() || workspace.isSymbolicLink()) continue;
    const candidate = path.join(sessionsDir, workspace.name, "prompt_history.jsonl");
    if (safeIsFile(candidate)) out.push(candidate);
  }
  return out.sort();
}

function listGrokSessionDirs(grokRoot, options = {}) {
  const sessionsDir = path.join(grokRoot, "sessions");
  if (!safeIsDirectory(sessionsDir)) return [];
  const includeSubagents = options.includeSubagents === true || options.skipSubagents === false;
  const out = [];
  const stack = [{ dir: sessionsDir, depth: 0 }];
  while (stack.length) {
    const { dir, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    const names = new Set(entries.filter((entry) => entry.isFile()).map((entry) => entry.name));
    if (names.has("summary.json") && (names.has("updates.jsonl") || names.has("chat_history.jsonl"))) {
      out.push(dir);
    }
    if (depth >= 7) continue;
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      if (entry.name === "terminal" || entry.name === "web_fetch" || entry.name === "images") continue;
      if (entry.name === "subagents" && !includeSubagents) continue;
      stack.push({ dir: path.join(dir, entry.name), depth: depth + 1 });
    }
  }
  return out.sort();
}

function listGrokDataFiles(grokRoot, options = {}) {
  const out = [...listGrokPromptHistoryFiles(grokRoot)];
  for (const sessionDir of listGrokSessionDirs(grokRoot, options)) {
    const summaryPath = path.join(sessionDir, "summary.json");
    const updatesPath = path.join(sessionDir, "updates.jsonl");
    const chatPath = path.join(sessionDir, "chat_history.jsonl");
    const hunkPath = path.join(sessionDir, "hunk_records.jsonl");
    if (safeIsFile(summaryPath)) out.push(summaryPath);
    if (safeIsFile(updatesPath)) out.push(updatesPath);
    else if (safeIsFile(chatPath)) out.push(chatPath);
    if (safeIsFile(hunkPath)) out.push(hunkPath);
  }
  return out;
}

function countGrokDataFiles(grokRoot, options = {}) {
  return listGrokDataFiles(grokRoot, options).length;
}

function safeReadSummary(summaryPath) {
  try {
    const stat = fs.statSync(summaryPath);
    if (!stat.isFile() || stat.size > MAX_SUMMARY_BYTES) return {};
    const value = JSON.parse(fs.readFileSync(summaryPath, "utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch {
    return {};
  }
}

function sessionContext(sessionDir) {
  const summaryPath = path.join(sessionDir, "summary.json");
  const summary = safeReadSummary(summaryPath);
  const info = summary.info && typeof summary.info === "object" ? summary.info : {};
  const workspaceDir = path.dirname(sessionDir);
  return {
    summary,
    summaryPath,
    sessionId: String(info.id || path.basename(sessionDir) || ""),
    workspace: String(info.cwd || workspaceFromContainerDir(workspaceDir) || ""),
    model: String(summary.current_model_id || ""),
    gitBranch: String(summary.head_branch || ""),
    isSidechain: isGrokSidechainPath(sessionDir),
  };
}

function formattedTimestamp(value) {
  const ms = parseIsoTimestamp(value);
  return ms == null ? "" : formatTimestampUtc(ms);
}

function safeJson(value) {
  try { return JSON.stringify(value); } catch { return String(value ?? ""); }
}

function contentText(content) {
  if (content == null) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content.map((item) => contentText(item)).filter(Boolean).join("\n");
  }
  if (typeof content !== "object") return String(content);
  if (typeof content.text === "string") return content.text;
  if (content.type === "image" || content.mimeType?.startsWith?.("image/")) {
    return `[Image attachment${content.mimeType ? `: ${content.mimeType}` : ""}]`;
  }
  if (content.content != null) return contentText(content.content);
  if (content.output_text != null) return contentText(content.output_text);
  if (content.data != null) {
    if (typeof content.data === "string" && content.data.length > 4096) {
      return `[Embedded ${content.mimeType || "binary"} data omitted: ${content.data.length} chars]`;
    }
    return contentText(content.data);
  }
  return safeJson(content);
}

function summaryRow(ctx, attribution = {}) {
  const { summary } = ctx;
  const title = String(summary.generated_title || summary.session_summary || "").trim();
  const details = [
    title ? `Title: ${title}` : "",
    ctx.workspace ? `Workspace: ${ctx.workspace}` : "",
    ctx.model ? `Model: ${ctx.model}` : "",
    summary.agent_name ? `Agent: ${summary.agent_name}` : "",
    summary.sandbox_profile ? `Sandbox: ${summary.sandbox_profile}` : "",
    summary.reasoning_effort ? `Reasoning effort: ${summary.reasoning_effort}` : "",
  ].filter(Boolean);
  return grokRow({
    timestamp: formattedTimestamp(summary.created_at),
    role: "system",
    recordType: "session_meta",
    summary: details.join("\n") || "[Grok Build session]",
    sessionId: ctx.sessionId,
    messageId: ctx.sessionId,
    workspace: ctx.workspace,
    isSidechain: ctx.isSidechain,
    gitBranch: ctx.gitBranch,
    model: ctx.model,
    sourceFile: ctx.summaryPath,
    lineNumber: 1,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function parseGrokPromptHistoryLine(obj, sourceFile, attribution = {}) {
  const prompt = obj?.prompt != null ? String(obj.prompt).trim() : "";
  if (!prompt) return null;
  const isBash = obj.is_bash === true;
  return grokRow({
    timestamp: formattedTimestamp(obj.timestamp),
    role: "user",
    recordType: isBash ? "shell_command" : "history",
    summary: prompt,
    toolName: isBash ? "shell" : "",
    toolCommand: isBash ? prompt : "",
    toolInput: isBash ? prompt : "",
    toolDescription: isBash ? "Direct shell command entered through Grok Build" : "",
    sessionId: obj.session_id != null ? String(obj.session_id) : "",
    sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

async function extractGrokPromptHistoryFile(historyPath, attribution = {}, parseStats = null) {
  const rows = [];
  await readJsonlBounded(historyPath, (obj, lineNumber) => {
    const row = assignLineNumber(parseGrokPromptHistoryLine(obj, historyPath, attribution), lineNumber);
    if (row) rows.push(row);
  }, { parseStats });
  return rows;
}

function toolNameFromUpdate(update) {
  const meta = update?._meta?.["x.ai/tool"];
  if (meta && typeof meta === "object" && meta.name) return String(meta.name);
  return "";
}

function toolCallSummary(name, evidence, update) {
  const label = name || "tool";
  const detail = evidence.toolCommand || evidence.toolDescription
    || (update.title != null ? String(update.title) : "")
    || evidence.toolInput;
  return detail ? `[Tool: ${label}] ${truncateSummary(detail).slice(0, 260)}` : `[Tool: ${label}]`;
}

function terminalOutputText(rawOutput) {
  if (!rawOutput || typeof rawOutput !== "object" || Array.isArray(rawOutput)) {
    return serializeEvidenceValue(rawOutput);
  }
  const output = rawOutput.output ?? rawOutput.output_for_prompt ?? "";
  const lines = [];
  if (rawOutput.command != null) lines.push(`Command: ${serializeEvidenceValue(rawOutput.command)}`);
  if (rawOutput.current_dir != null) lines.push(`Working directory: ${rawOutput.current_dir}`);
  if (rawOutput.exit_code != null) lines.push(`Exit code: ${rawOutput.exit_code}`);
  if (rawOutput.signal != null) lines.push(`Signal: ${rawOutput.signal}`);
  if (rawOutput.timed_out != null) lines.push(`Timed out: ${rawOutput.timed_out}`);
  if (rawOutput.truncated != null) lines.push(`Truncated: ${rawOutput.truncated}`);
  if (rawOutput.output_file != null) lines.push(`Output file: ${rawOutput.output_file}`);
  if (output !== "") lines.push(`Output:\n${serializeEvidenceValue(output)}`);
  return lines.length ? lines.join("\n") : safeJson(rawOutput);
}

function toolResultText(name, update) {
  if (name === "run_terminal_command") return terminalOutputText(update.rawOutput);
  if (update.rawOutput != null) return safeJson(update.rawOutput);
  if (update.content != null) return contentText(update.content);
  return "";
}

function grokUpdateRow(obj, sourceFile, ctx, state, attribution = {}) {
  const update = obj?.params?.update;
  if (!update || typeof update !== "object") return null;
  const eventType = String(update.sessionUpdate || "");
  const timestamp = formattedTimestamp(obj.timestamp);
  const sessionId = String(obj.params?.sessionId || ctx.sessionId || "");
  const base = {
    timestamp,
    sessionId,
    workspace: ctx.workspace,
    isSidechain: ctx.isSidechain,
    gitBranch: ctx.gitBranch,
    model: ctx.model,
    sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  };

  if (eventType === "user_message_chunk" || eventType === "agent_message_chunk"
    || eventType === "agent_thought_chunk") {
    const text = contentText(update.content).trim();
    if (!text) return null;
    const role = eventType === "user_message_chunk" ? "user" : "assistant";
    const recordType = eventType === "agent_thought_chunk" ? "reasoning" : (
      eventType === "user_message_chunk" ? "user" : "assistant"
    );
    const promptIndex = update._meta?.promptIndex;
    return grokRow({
      ...base,
      role,
      recordType,
      summary: text,
      messageId: promptIndex != null ? `prompt-${promptIndex}` : "",
    });
  }

  if (eventType === "tool_call") {
    const name = toolNameFromUpdate(update) || "tool";
    const callId = String(update.toolCallId || "");
    const evidence = buildToolEvidence([{ name, input: update.rawInput }]);
    if (callId) state.toolCalls.set(callId, { name, input: update.rawInput, evidence });
    return grokRow({
      ...base,
      role: "assistant",
      recordType: "tool_call",
      summary: toolCallSummary(name, evidence, update),
      ...evidence,
      messageId: callId,
    });
  }

  if (eventType === "tool_call_update"
    && (update.status === "completed" || update.status === "failed")) {
    const callId = String(update.toolCallId || "");
    const call = state.toolCalls.get(callId) || {};
    const name = call.name || toolNameFromUpdate(update) || "tool";
    const evidence = call.evidence || buildToolEvidence([{ name, input: update.rawInput }]);
    const output = toolResultText(name, update);
    const status = String(update.status);
    const outputPreview = output ? ` ${truncateSummary(output).slice(0, 220)}` : "";
    return grokRow({
      ...base,
      role: "tool",
      recordType: status === "failed" ? "tool_result_failed" : "tool_result",
      summary: `[Tool result: ${name}] ${status}${outputPreview}`,
      fullText: output || `[Tool result: ${name}] ${status}`,
      ...evidence,
      messageId: callId ? `${callId}:result` : "",
      parentId: callId,
    });
  }

  if (eventType === "tool_call_update") {
    const callId = String(update.toolCallId || "");
    const prior = state.toolCalls.get(callId) || {};
    const name = prior.name || toolNameFromUpdate(update);
    const input = prior.input ?? update.rawInput;
    if (callId && name) {
      state.toolCalls.set(callId, {
        name,
        input,
        evidence: buildToolEvidence([{ name, input }]),
      });
    }
    return null;
  }

  if (eventType === "turn_completed") {
    const usage = update.usage && typeof update.usage === "object" ? update.usage : {};
    const inputTokens = Number(usage.inputTokens) || 0;
    const outputTokens = Number(usage.outputTokens) || 0;
    const stop = update.stop_reason != null ? String(update.stop_reason) : "completed";
    return grokRow({
      ...base,
      role: "system",
      recordType: "turn_completed",
      summary: `Turn ${stop}; tokens ${inputTokens} in / ${outputTokens} out`,
      messageId: update.prompt_id != null ? String(update.prompt_id) : "",
      inputTokens,
      outputTokens,
    });
  }

  if (eventType === "session_recap") {
    const recap = update.summary != null ? String(update.summary).trim() : "";
    if (!recap) return null;
    return grokRow({
      ...base,
      role: "system",
      recordType: "session_recap",
      summary: recap,
    });
  }

  if (eventType === "auto_compact_started" || eventType === "auto_compact_completed"
    || eventType === "compaction_checkpoint") {
    return grokRow({
      ...base,
      role: "system",
      recordType: eventType,
      summary: safeJson(update),
      messageId: update.checkpoint_id != null ? String(update.checkpoint_id) : "",
    });
  }

  return null;
}

async function extractGrokUpdatesFile(updatesPath, ctx, attribution = {}, parseStats = null) {
  const rows = [];
  const state = { toolCalls: new Map() };
  await readJsonlBounded(updatesPath, (obj, lineNumber) => {
    const row = assignLineNumber(
      grokUpdateRow(obj, updatesPath, ctx, state, attribution),
      lineNumber,
    );
    if (row) rows.push(row);
  }, { parseStats });
  return rows;
}

function chatItemText(item) {
  if (!item || typeof item !== "object") return "";
  if (item.type === "reasoning") return contentText(item.summary);
  return contentText(item.content);
}

async function extractGrokChatHistoryFile(chatPath, ctx, attribution = {}, parseStats = null) {
  const rows = [];
  await readJsonlBounded(chatPath, (item, lineNumber) => {
    const type = String(item?.type || "");
    const base = {
      timestamp: "",
      sessionId: ctx.sessionId,
      workspace: ctx.workspace,
      isSidechain: ctx.isSidechain,
      gitBranch: ctx.gitBranch,
      model: item.model_id != null ? String(item.model_id) : ctx.model,
      sourceFile: chatPath,
      lineNumber,
      user: attribution.user || "",
      host: attribution.host || "",
    };
    const text = chatItemText(item).trim();
    if (text) {
      const role = type === "tool_result" ? "tool" : (
        type === "reasoning" ? "assistant" : (type || "system")
      );
      rows.push(grokRow({
        ...base,
        role,
        recordType: type || "message",
        summary: text,
        messageId: item.id != null ? String(item.id) : (
          item.tool_call_id != null ? `${item.tool_call_id}:result` : ""
        ),
        parentId: item.tool_call_id != null ? String(item.tool_call_id) : "",
      }));
    }
    if (type === "assistant" && Array.isArray(item.tool_calls)) {
      for (const call of item.tool_calls) {
        if (!call || typeof call !== "object") continue;
        const name = String(call.name || "tool");
        const evidence = buildToolEvidence([{ name, input: call.arguments }]);
        rows.push(grokRow({
          ...base,
          role: "assistant",
          recordType: "tool_call",
          summary: toolCallSummary(name, evidence, call),
          ...evidence,
          messageId: call.id != null ? String(call.id) : "",
        }));
      }
    }
  }, { parseStats });
  return rows;
}

function parseGrokHunkLine(obj, sourceFile, ctx, attribution = {}) {
  if (!obj || typeof obj !== "object" || !obj.filePath) return null;
  const eventType = String(obj.eventType || "updated");
  const added = Number(obj.linesAdded) || 0;
  const removed = Number(obj.linesRemoved) || 0;
  const filePath = String(obj.filePath);
  const range = obj.hunkStart != null || obj.hunkEnd != null
    ? ` lines ${obj.hunkStart ?? "?"}-${obj.hunkEnd ?? "?"}`
    : "";
  const reason = obj.removalReason ? `; ${obj.removalReason}` : "";
  return grokRow({
    timestamp: formattedTimestamp(obj.timestamp),
    role: obj.authorType != null ? String(obj.authorType) : "assistant",
    recordType: `file_hunk_${eventType}`,
    summary: `${eventType}: ${filePath}${range}; +${added}/-${removed}${reason}`,
    sessionId: String(obj.sessionId || ctx.sessionId || ""),
    messageId: obj.hunkId != null ? String(obj.hunkId) : "",
    parentId: obj.promptIndex != null ? `prompt-${obj.promptIndex}` : "",
    workspace: ctx.workspace,
    isSidechain: ctx.isSidechain,
    gitBranch: ctx.gitBranch,
    model: ctx.model,
    sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

async function extractGrokHunkFile(hunkPath, ctx, attribution = {}, parseStats = null) {
  const rows = [];
  await readJsonlBounded(hunkPath, (obj, lineNumber) => {
    const row = assignLineNumber(parseGrokHunkLine(obj, hunkPath, ctx, attribution), lineNumber);
    if (row) rows.push(row);
  }, { parseStats });
  return rows;
}

async function extractGrokSessionDir(sessionDir, attribution = {}, options = {}, progress = null) {
  const ctx = sessionContext(sessionDir);
  const parseStats = options.parseStats || { errors: 0 };
  const rows = [summaryRow(ctx, attribution)];
  const updatesPath = path.join(sessionDir, "updates.jsonl");
  const chatPath = path.join(sessionDir, "chat_history.jsonl");
  const hunkPath = path.join(sessionDir, "hunk_records.jsonl");

  if (safeIsFile(updatesPath)) {
    progress?.(updatesPath);
    rows.push(...await extractGrokUpdatesFile(updatesPath, ctx, attribution, parseStats));
  } else if (safeIsFile(chatPath)) {
    progress?.(chatPath);
    rows.push(...await extractGrokChatHistoryFile(chatPath, ctx, attribution, parseStats));
  }
  if (safeIsFile(hunkPath)) {
    progress?.(hunkPath);
    rows.push(...await extractGrokHunkFile(hunkPath, ctx, attribution, parseStats));
  }
  return rows;
}

async function extractGrokBuildDir(grokRoot, attribution = {}, options = {}) {
  const rows = [];
  const parseStats = { errors: 0 };
  const promptFiles = listGrokPromptHistoryFiles(grokRoot);
  const sessionDirs = listGrokSessionDirs(grokRoot, options);
  const fileCount = countGrokDataFiles(grokRoot, options);
  const { onFileProgress, onExtractedRows } = options;
  let fileIndex = 0;

  const emitBatch = (batch) => {
    if (!batch?.length) return;
    const filtered = filterSidechainRows(batch, options);
    if (onExtractedRows && filtered.length) onExtractedRows(filtered);
    else rows.push(...filtered);
  };
  const progress = (filePath) => {
    fileIndex += 1;
    tickFileProgress(onFileProgress, fileIndex, fileCount, filePath);
  };

  for (const historyPath of promptFiles) {
    options.checkAbort?.();
    progress(historyPath);
    try {
      emitBatch(await extractGrokPromptHistoryFile(historyPath, attribution, parseStats));
    } catch (error) {
      dbg("AIHIST", "grok prompt history failed", { path: historyPath, err: error.message });
    }
  }

  for (const sessionDir of sessionDirs) {
    options.checkAbort?.();
    const summaryPath = path.join(sessionDir, "summary.json");
    progress(summaryPath);
    try {
      emitBatch(await extractGrokSessionDir(
        sessionDir,
        attribution,
        { ...options, parseStats },
        progress,
      ));
    } catch (error) {
      dbg("AIHIST", "grok session failed", { path: sessionDir, err: error.message });
    }
    await new Promise((resolve) => setImmediate(resolve));
  }

  // Runtime stores outside the session tree — the search index, the app log, and open sessions.
  // They survive deletion of the session directories, so they run last and independently.
  if (options.includeGrokRuntime !== false) {
    options.checkAbort?.();
    try {
      emitBatch(await collectGrokRuntimeArtifacts(grokRoot, attribution, options));
    } catch (error) {
      dbg("AIHIST", "grok runtime artifacts failed", { path: grokRoot, err: error.message });
    }
  }

  if (onExtractedRows) {
    const out = [];
    if (parseStats.errors) out._parseErrors = parseStats.errors;
    return out;
  }
  const finalized = finalizeAiHistoryRows(filterSidechainRows(rows, options), options);
  if (parseStats.errors) finalized._parseErrors = parseStats.errors;
  return finalized;
}

async function extractSingleGrokFile(filePath, attribution = {}) {
  const base = path.basename(filePath);
  if (base === "prompt_history.jsonl") {
    return extractGrokPromptHistoryFile(filePath, attribution);
  }
  const sessionDir = path.dirname(filePath);
  const ctx = sessionContext(sessionDir);
  if (base === "summary.json") return [summaryRow(ctx, attribution)];
  if (base === "updates.jsonl") return extractGrokUpdatesFile(filePath, ctx, attribution);
  if (base === "chat_history.jsonl") return extractGrokChatHistoryFile(filePath, ctx, attribution);
  if (base === "hunk_records.jsonl") return extractGrokHunkFile(filePath, ctx, attribution);
  throw new Error("Unrecognized Grok Build artifact file.");
}

async function extractGrokBuildPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) throw new Error(`Path does not exist: ${target}`);
  if (safeIsDirectory(target)) {
    const root = resolveGrokHome(target);
    if (!root) throw new Error("Not a Grok Build data directory (expected $GROK_HOME or ~/.grok).");
    return extractGrokBuildDir(root, attribution, options);
  }
  if (!isGrokBuildArtifactFile(target)) {
    throw new Error("Expected a Grok Build summary, prompt history, chat history, updates, or hunk JSONL file.");
  }
  const rows = await extractSingleGrokFile(target, attribution);
  return finalizeAiHistoryRows(rows, options);
}

module.exports = {
  GROK_DIR_NAME,
  GROK_SESSION_FILES,
  defaultGrokHome,
  isGrokBuildRoot,
  resolveGrokHome,
  isGrokBuildArtifactFile,
  listGrokPromptHistoryFiles,
  listGrokSessionDirs,
  listGrokDataFiles,
  countGrokDataFiles,
  parseGrokPromptHistoryLine,
  grokUpdateRow,
  parseGrokHunkLine,
  extractGrokPromptHistoryFile,
  extractGrokUpdatesFile,
  extractGrokChatHistoryFile,
  extractGrokHunkFile,
  extractGrokSessionDir,
  extractGrokBuildDir,
  extractGrokBuildPath,
};
