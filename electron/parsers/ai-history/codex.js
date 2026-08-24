/**
 * parsers/ai-history/codex.js — OpenAI Codex CLI / Desktop local artifacts (~/.codex).
 *
 * Artifacts:
 *   ~/.codex/history.jsonl — { session_id, ts, text }
 *   ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl — session transcripts
 *   ~/.codex/archived_sessions/.../rollout-*.jsonl — archived threads
 *   ~/.codex/session_index.jsonl — thread id / title index (optional metadata)
 *
 * Desktop app state lives under ~/.codex (not Application Support/Codex, which is UI cache).
 */

const fs = require("fs");
const path = require("path");
const { readJsonlBounded } = require("./jsonl-reader");
const os = require("os");

const { dbg } = require("../../logger");
const { shouldSkipSubagentPath, filterSidechainRows, tickFileProgress } = require("./extract-plan");
const { processFilesConcurrently } = require("./file-batch");
const { TOOL_CODEX } = require("./schema");
const { buildToolEvidence } = require("./tool-evidence");
const {
  formatTimestampUtc,
  parseIsoTimestamp,
  makeRow,
  assignLineNumber,
  finalizeAiHistoryRows,
  truncateSummary,
} = require("./row-utils");

const CODEX_DIR_NAME = ".codex";
const ROLLOUT_FILE_RE = /^rollout-.+\.jsonl$/i;

function codexRow(fields) {
  return makeRow({ ...fields, tool: fields.tool || TOOL_CODEX }, TOOL_CODEX);
}

/** Forked / child Codex threads (parent session id or explicit subagent flag). */
function isCodexForkedSession(payload) {
  if (!payload || typeof payload !== "object") return false;
  if (payload.is_subagent === true || payload.subagent === true || payload.is_fork === true) return true;
  const parent = payload.parent_session_id ?? payload.parentSessionId
    ?? payload.parent_thread_id ?? payload.parentThreadId
    ?? payload.forked_from ?? payload.forked_from_id ?? payload.forkedFromId
    ?? payload.forked_from_session_id ?? payload.parent_id;
  if (parent != null && String(parent).trim() !== "") return true;
  return /subagent|sub-agent|child|fork/i.test(
    `${payload.thread_source || ""} ${payload.source || ""} ${payload.agent_role || ""}`,
  );
}

function codexParentId(payload) {
  const parent = payload?.parent_session_id ?? payload?.parentSessionId
    ?? payload?.parent_thread_id ?? payload?.parentThreadId
    ?? payload?.forked_from ?? payload?.forked_from_id ?? payload?.forkedFromId
    ?? payload?.forked_from_session_id ?? payload?.parent_id;
  return parent == null ? "" : String(parent);
}

function resolveCodexHome(target) {
  // An explicitly selected artifact path is authoritative. Falling back to the examiner's
  // CODEX_HOME while resolving a forensic target can silently import unrelated live-host data.
  if (!target) {
    if (process.env.CODEX_HOME) {
      const envHome = path.resolve(process.env.CODEX_HOME);
      if (fs.existsSync(envHome) && isCodexDir(envHome)) return envHome;
    }
    return null;
  }
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }

  for (let i = 0; i < 16; i++) {
    if (path.basename(p) === CODEX_DIR_NAME && isCodexDir(p)) return p;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  if (isCodexDir(target)) return path.resolve(target);
  return null;
}

function peekHistoryJsonl(histPath) {
  try {
    const fd = fs.openSync(histPath, "r");
    const buf = Buffer.alloc(4096);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    const line = buf.slice(0, n).toString("utf8").split("\n").find((l) => l.trim());
    if (!line) return null;
    const o = JSON.parse(line);
    if (o && o.session_id != null && o.ts != null && o.text != null) return o;
  } catch { /* ignore */ }
  return null;
}

function isCodexDir(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  if (path.basename(dirPath) !== CODEX_DIR_NAME) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }

  if (fs.existsSync(path.join(dirPath, "sessions"))) return true;
  if (fs.existsSync(path.join(dirPath, "archived_sessions"))) return true;

  const hist = path.join(dirPath, "history.jsonl");
  if (fs.existsSync(hist) && peekHistoryJsonl(hist)) return true;

  return listRolloutFiles(dirPath).length > 0;
}

function isCodexRolloutFile(filePath) {
  if (!filePath || path.extname(filePath).toLowerCase() !== ".jsonl") return false;
  if (!ROLLOUT_FILE_RE.test(path.basename(filePath))) return false;
  return filePath.includes(`${path.sep}${CODEX_DIR_NAME}${path.sep}`);
}

function listRolloutFiles(codexRoot, options = {}) {
  const out = [];
  for (const sub of ["sessions", "archived_sessions"]) {
    const base = path.join(codexRoot, sub);
    if (!fs.existsSync(base)) continue;
    const stack = [base];
    while (stack.length) {
      const d = stack.pop();
      let entries;
      try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
      for (const e of entries) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) {
          if (shouldSkipSubagentPath(full, options)) continue;
          if (!e.isSymbolicLink()) stack.push(full);
        } else if (e.isFile() && ROLLOUT_FILE_RE.test(e.name)) {
          if (!shouldSkipSubagentPath(full, options)) out.push(full);
        }
      }
    }
  }
  return out;
}

function countRolloutFiles(codexRoot) {
  return listRolloutFiles(codexRoot).length;
}

/** Strip IDE wrapper / environment blocks from Codex user prompts. */
function stripCodexUserText(text) {
  const s = String(text || "").trim();
  if (!s) return "";
  const req = s.match(/##\s*My request for Codex:\s*([\s\S]*)/i);
  if (req) return req[1].trim();
  if (/<environment_context>/i.test(s)) return "";
  return s;
}

function extractPayloadContent(content) {
  if (content == null) return "";
  if (typeof content === "string") return content.trim();
  if (!Array.isArray(content)) {
    if (typeof content === "object" && content.text != null) return String(content.text).trim();
    return "";
  }

  const parts = [];
  let hasReasoning = false;
  for (const item of content) {
    if (!item || typeof item !== "object") continue;
    const type = item.type || "";
    if (type === "input_text" || type === "output_text" || type === "text") {
      const t = item.text != null ? String(item.text) : "";
      const cleaned = stripCodexUserText(t);
      if (cleaned) parts.push(cleaned);
    } else if (type === "tool_use" || type === "function_call") {
      const name = item.name || item.function?.name || "tool";
      parts.push(`[Tool: ${name}]`);
    } else if (type === "tool_result" || type === "function_call_output") {
      const output = serializeCodexValue(item.output ?? item.content ?? item.result);
      parts.push(output ? `[Tool Result]\n${output}` : "[Tool Result]");
    } else if (type === "thinking" || type === "reasoning") {
      hasReasoning = true;
    } else if (type === "input_image" || type === "output_image" || type === "image") {
      const url = item.image_url || item.url || "";
      const kind = typeof url === "string" && url.startsWith("data:") ? "embedded" : "referenced";
      parts.push(`[Image ${kind}]`);
    } else if (type === "document" || type === "input_file") {
      const name = item.filename || item.name || "";
      parts.push(name ? `[Document: ${name}]` : "[Document]");
    }
  }
  let text = parts.join(" ").trim();
  if (hasReasoning && !/\[Reasoning present\]/.test(text)) {
    text = text ? `${text} [Reasoning present]` : "[Reasoning present]";
  }
  return text;
}

function serializeCodexValue(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function payloadTextWithoutOpaqueFields(payload) {
  if (!payload || typeof payload !== "object") return serializeCodexValue(payload);
  const {
    encrypted_content: _encryptedContent,
    internal_chat_message_metadata_passthrough: _internalMetadata,
    ...safe
  } = payload;
  return serializeCodexValue(safe);
}

function reasoningSummary(payload) {
  const summary = payload?.summary;
  if (typeof summary === "string") return summary.trim();
  if (!Array.isArray(summary)) return "";
  return summary.map((item) => {
    if (typeof item === "string") return item.trim();
    if (item && typeof item === "object") return String(item.text ?? item.summary ?? "").trim();
    return "";
  }).filter(Boolean).join("\n");
}

function tokenUsage(payload) {
  const info = payload?.info && typeof payload.info === "object" ? payload.info : {};
  const usage = info.total_token_usage || info.last_token_usage || info;
  return {
    input: Number(usage.input_tokens ?? usage.prompt_tokens) || 0,
    output: Number(usage.output_tokens ?? usage.completion_tokens) || 0,
  };
}

function baseRolloutFields(ctx, sourceFile, attribution) {
  return {
    sessionId: ctx.sessionId,
    parentId: ctx.parentId || "",
    workspace: ctx.workspace,
    isSidechain: !!ctx.isSidechainSession,
    gitBranch: ctx.gitBranch || "",
    model: ctx.model,
    sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  };
}

function loadThreadIndex(codexRoot) {
  const map = new Map();
  const idxPath = path.join(codexRoot, "session_index.jsonl");
  if (!fs.existsSync(idxPath)) return map;
  try {
    for (const line of fs.readFileSync(idxPath, "utf8").split("\n")) {
      if (!line.trim()) continue;
      let o;
      try { o = JSON.parse(line); } catch { continue; }
      if (o?.id) {
        map.set(String(o.id), {
          threadName: o.thread_name != null ? String(o.thread_name) : "",
          updatedAt: o.updated_at != null ? String(o.updated_at) : "",
        });
      }
    }
  } catch (e) {
    dbg("AIHIST", "codex session_index read failed", { err: e.message });
  }
  return map;
}

/** Parse ~/.codex/history.jsonl line. */
function parseCodexHistoryLine(obj, sourceFile, attribution = {}) {
  const summary = obj.text != null ? String(obj.text).trim() : "";
  if (!summary) return null;

  const tsRaw = obj.ts;
  const tsMs = typeof tsRaw === "number" ? (tsRaw > 1e12 ? tsRaw : tsRaw * 1000) : parseInt(tsRaw, 10);
  if (!Number.isFinite(tsMs) || tsMs <= 0) return null;

  return codexRow({
    timestamp: formatTimestampUtc(tsMs),
    role: "user",
    recordType: "history",
    summary,
    sessionId: obj.session_id != null ? String(obj.session_id) : "",
    messageId: "",
    parentId: "",
    workspace: "",
    toolName: "",
    isSidechain: false,
    gitBranch: "",
    model: "",
    inputTokens: 0,
    outputTokens: 0,
    sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function parseRolloutEnvelope(obj, sourceFile, ctx, attribution) {
  const recordType = obj.type != null ? String(obj.type) : "unknown";
  const tsMs = parseIsoTimestamp(obj.timestamp);
  const timestamp = tsMs == null ? "" : formatTimestampUtc(tsMs);
  const payload = obj.payload && typeof obj.payload === "object" ? obj.payload : {};

  if (recordType === "session_meta") {
    ctx.sessionId = payload.id != null
      ? String(payload.id)
      : (payload.session_id != null ? String(payload.session_id) : ctx.sessionId);
    ctx.parentId = codexParentId(payload) || ctx.parentId || "";
    ctx.isSidechainSession = isCodexForkedSession(payload);
    ctx.workspace = payload.cwd != null ? String(payload.cwd) : ctx.workspace;
    ctx.model = payload.model != null
      ? String(payload.model)
      : (payload.model_provider != null ? String(payload.model_provider) : ctx.model);
    ctx.gitBranch = payload.git?.branch != null
      ? String(payload.git.branch)
      : (payload.git_branch != null ? String(payload.git_branch) : ctx.gitBranch);
    const thread = ctx.threadIndex?.get(ctx.sessionId);
    const title = thread?.threadName ? ` — ${thread.threadName}` : "";
    return codexRow({
      timestamp,
      role: "system",
      recordType: "session_meta",
      summary: `[Session start]${title}`.trim(),
      fullText: serializeCodexValue({
        threadId: ctx.sessionId,
        parentThreadId: ctx.parentId,
        originator: payload.originator,
        source: payload.source,
        threadSource: payload.thread_source,
        cliVersion: payload.cli_version,
        modelProvider: payload.model_provider,
        historyMode: payload.history_mode,
        git: payload.git,
      }),
      ...baseRolloutFields(ctx, sourceFile, attribution),
      messageId: payload.id != null ? String(payload.id) : "",
      toolName: "",
    });
  }

  if (recordType === "response_item") {
    const payloadType = payload.type != null ? String(payload.type) : "";

    if (payloadType === "message" || payloadType === "agent_message") {
      const role = payload.role != null
        ? String(payload.role)
        : (payloadType === "agent_message" ? "assistant" : "unknown");
      const summary = extractPayloadContent(payload.content ?? payload.message);
      if (!summary) return null;
      return codexRow({
        timestamp,
        role,
        recordType: payloadType,
        summary,
        fullText: summary,
        toolName: "",
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.id != null ? String(payload.id) : "",
      });
    }

    if (payloadType === "function_call" || payloadType === "custom_tool_call") {
      const name = payload.name != null ? String(payload.name) : "tool";
      const input = payload.arguments ?? payload.input;
      if (!ctx.toolNamesByCallId) ctx.toolNamesByCallId = new Map();
      if (payload.call_id != null) ctx.toolNamesByCallId.set(String(payload.call_id), name);
      const toolEvidence = buildToolEvidence([{ name, input }]);
      const argPreview = truncateSummary(serializeCodexValue(input)).slice(0, 120);
      const summary = argPreview ? `[Tool: ${name}] ${argPreview}` : `[Tool: ${name}]`;
      return codexRow({
        timestamp,
        role: "assistant",
        recordType: payloadType,
        summary,
        fullText: serializeCodexValue(input) || summary,
        ...toolEvidence,
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.call_id != null ? String(payload.call_id) : "",
      });
    }

    if (payloadType === "function_call_output" || payloadType === "custom_tool_call_output") {
      const outText = serializeCodexValue(payload.output ?? payload.result);
      const summary = outText ? `[Tool output] ${truncateSummary(outText).slice(0, 200)}` : "[Tool output]";
      const callId = payload.call_id != null ? String(payload.call_id) : "";
      const toolName = ctx.toolNamesByCallId?.get(callId) || "";
      return codexRow({
        timestamp,
        role: "tool",
        recordType: payloadType,
        summary,
        fullText: outText || summary,
        toolName,
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: callId,
      });
    }

    if (payloadType === "reasoning") {
      const reasoning = reasoningSummary(payload);
      const encrypted = payload.encrypted_content ? " (encrypted body present)" : "";
      return codexRow({
        timestamp,
        role: "assistant",
        recordType: "reasoning",
        summary: reasoning ? `[Reasoning] ${reasoning}` : `[Reasoning present]${encrypted}`,
        fullText: reasoning || `[Reasoning present]${encrypted}`,
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.id != null ? String(payload.id) : "",
      });
    }

    if (payloadType === "tool_search_call") {
      const input = payload.arguments ?? {};
      const toolEvidence = buildToolEvidence([{ name: "tool_search", input }]);
      const query = input?.query != null ? String(input.query) : "";
      return codexRow({
        timestamp,
        role: "assistant",
        recordType: "tool_search_call",
        summary: query ? `[Tool search] ${query}` : "[Tool search]",
        fullText: serializeCodexValue(input),
        ...toolEvidence,
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.call_id != null ? String(payload.call_id) : "",
      });
    }

    if (payloadType === "tool_search_output") {
      const output = serializeCodexValue(payload.tools ?? payload.output);
      const count = Array.isArray(payload.tools) ? payload.tools.length : 0;
      return codexRow({
        timestamp,
        role: "tool",
        recordType: "tool_search_output",
        summary: count ? `[Tool search output] ${count} result(s)` : "[Tool search output]",
        fullText: output || "[Tool search output]",
        toolName: "tool_search",
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.call_id != null ? String(payload.call_id) : "",
      });
    }

    if (payloadType === "web_search_call") {
      const input = payload.action ?? {};
      const query = input.query
        ?? (Array.isArray(input.queries) ? input.queries.join("; ") : "");
      return codexRow({
        timestamp,
        role: "assistant",
        recordType: payloadType,
        summary: query ? `[Web search] ${query}` : "[Web search]",
        fullText: serializeCodexValue(input),
        ...buildToolEvidence([{ name: "web_search", input }]),
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.id != null ? String(payload.id) : "",
      });
    }

    return codexRow({
      timestamp,
      role: "system",
      recordType: payloadType || "response_item",
      summary: `[${payloadType || "response_item"}]`,
      fullText: payloadTextWithoutOpaqueFields(payload),
      ...baseRolloutFields(ctx, sourceFile, attribution),
      messageId: "",
      toolName: "",
    });
  }

  if (recordType === "event_msg") {
    const evt = payload.type != null ? String(payload.type) : "event_msg";

    if (evt === "user_message") {
      const summary = stripCodexUserText(payload.message || payload.text || "");
      if (!summary) return null;
      return codexRow({
        timestamp,
        role: "user",
        recordType: "user_message",
        summary,
        fullText: summary,
        ...baseRolloutFields(ctx, sourceFile, attribution),
        toolName: "",
      });
    }

    if (evt === "agent_reasoning" || evt === "agent_message") {
      const text = payload.text != null
        ? String(payload.text).trim()
        : (payload.message != null ? String(payload.message).trim() : "");
      const label = evt === "agent_reasoning" ? "Reasoning" : "Agent message";
      return codexRow({
        timestamp,
        role: "assistant",
        recordType: evt,
        summary: text ? `[${label}] ${text}` : `[${label}]`,
        fullText: text || `[${label}]`,
        ...baseRolloutFields(ctx, sourceFile, attribution),
        toolName: "",
      });
    }

    if (evt === "token_count") {
      const { input, output } = tokenUsage(payload);
      if (!input && !output) return null;
      return codexRow({
        timestamp,
        role: "system",
        recordType: "token_count",
        summary: `Tokens: ${input} in / ${output} out`,
        ...baseRolloutFields(ctx, sourceFile, attribution),
        toolName: "",
        inputTokens: input,
        outputTokens: output,
      });
    }

    if (evt === "patch_apply_end") {
      const output = serializeCodexValue({
        status: payload.status,
        success: payload.success,
        changes: payload.changes,
        stdout: payload.stdout,
        stderr: payload.stderr,
      });
      const changed = payload.changes && typeof payload.changes === "object"
        ? Object.keys(payload.changes).length
        : 0;
      return codexRow({
        timestamp,
        role: "tool",
        recordType: evt,
        summary: `[Patch ${payload.success === false ? "failed" : "applied"}] ${changed} file(s)`,
        fullText: output,
        toolName: "apply_patch",
        toolInput: serializeCodexValue(payload.changes),
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.call_id != null ? String(payload.call_id) : "",
      });
    }

    if (evt === "web_search_end") {
      const input = { query: payload.query, action: payload.action };
      return codexRow({
        timestamp,
        role: "tool",
        recordType: evt,
        summary: payload.query ? `[Web search] ${payload.query}` : "[Web search]",
        fullText: serializeCodexValue(payload.results ?? payload.action ?? input),
        ...buildToolEvidence([{ name: "web_search", input }]),
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.call_id != null ? String(payload.call_id) : "",
      });
    }

    if (evt === "mcp_tool_call_end") {
      const invocation = payload.invocation && typeof payload.invocation === "object"
        ? payload.invocation
        : {};
      const server = invocation.server ? String(invocation.server) : "mcp";
      const tool = invocation.tool ? String(invocation.tool) : "tool";
      const name = `${server}.${tool}`;
      return codexRow({
        timestamp,
        role: "tool",
        recordType: evt,
        summary: `[MCP tool: ${name}]`,
        fullText: serializeCodexValue(payload.result),
        ...buildToolEvidence([{ name, input: invocation.arguments }]),
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.call_id != null ? String(payload.call_id) : "",
      });
    }

    if (evt === "sub_agent_activity") {
      const agentThreadId = payload.agent_thread_id != null ? String(payload.agent_thread_id) : "";
      return codexRow({
        timestamp,
        role: "system",
        recordType: evt,
        summary: `[Subagent ${payload.kind || "activity"}] ${payload.agent_path || agentThreadId}`,
        fullText: payloadTextWithoutOpaqueFields(payload),
        sessionId: agentThreadId || ctx.sessionId,
        parentId: ctx.sessionId,
        workspace: ctx.workspace,
        isSidechain: true,
        gitBranch: ctx.gitBranch || "",
        model: ctx.model,
        sourceFile,
        user: attribution.user || "",
        host: attribution.host || "",
        messageId: payload.event_id != null ? String(payload.event_id) : "",
      });
    }

    if (evt === "thread_settings_applied") {
      const settings = payload.thread_settings && typeof payload.thread_settings === "object"
        ? payload.thread_settings
        : {};
      if (settings.cwd != null) ctx.workspace = String(settings.cwd);
      if (settings.model != null) ctx.model = String(settings.model);
      return codexRow({
        timestamp,
        role: "system",
        recordType: evt,
        summary: `[Thread settings] model=${settings.model || "unknown"} approval=${settings.approval_policy || "unknown"}`,
        fullText: serializeCodexValue(settings),
        ...baseRolloutFields(ctx, sourceFile, attribution),
      });
    }

    if (evt === "task_started" || evt === "task_complete" || evt === "turn_aborted") {
      const duration = Number(payload.duration_ms);
      const status = evt === "turn_aborted" ? (payload.reason || "aborted") : evt.replace("_", " ");
      return codexRow({
        timestamp,
        role: "system",
        recordType: evt,
        summary: `[${status}]${Number.isFinite(duration) ? ` ${duration} ms` : ""}`,
        fullText: payloadTextWithoutOpaqueFields(payload),
        ...baseRolloutFields(ctx, sourceFile, attribution),
        messageId: payload.turn_id != null ? String(payload.turn_id) : "",
      });
    }

    if (evt === "context_compacted") {
      return codexRow({
        timestamp,
        role: "system",
        recordType: evt,
        summary: "[Context compacted]",
        fullText: payloadTextWithoutOpaqueFields(payload),
        ...baseRolloutFields(ctx, sourceFile, attribution),
      });
    }

    return codexRow({
      timestamp,
      role: "system",
      recordType: evt,
      summary: `[${evt}]`,
      fullText: payloadTextWithoutOpaqueFields(payload),
      ...baseRolloutFields(ctx, sourceFile, attribution),
      toolName: "",
    });
  }

  if (recordType === "turn_context") {
    if (payload.cwd != null) ctx.workspace = String(payload.cwd);
    if (payload.model != null) ctx.model = String(payload.model);
    const approval = payload.approval_policy || "";
    const effort = payload.effort || payload.reasoning_effort || "";
    return codexRow({
      timestamp,
      role: "system",
      recordType: "turn_context",
      summary: `[Turn context] model=${ctx.model || "unknown"}${effort ? ` effort=${effort}` : ""}${approval ? ` approval=${approval}` : ""}`,
      fullText: serializeCodexValue({
        turnId: payload.turn_id,
        cwd: payload.cwd,
        workspaceRoots: payload.workspace_roots,
        currentDate: payload.current_date,
        timezone: payload.timezone,
        approvalPolicy: payload.approval_policy,
        sandboxPolicy: payload.sandbox_policy,
        permissionProfile: payload.permission_profile,
        model: payload.model,
        collaborationMode: payload.collaboration_mode,
        multiAgentVersion: payload.multi_agent_version,
        multiAgentMode: payload.multi_agent_mode,
        effort,
      }),
      ...baseRolloutFields(ctx, sourceFile, attribution),
      messageId: payload.turn_id != null ? String(payload.turn_id) : "",
      toolName: "",
    });
  }

  if (recordType === "compacted") {
    const replacementCount = Array.isArray(payload.replacement_history)
      ? payload.replacement_history.length
      : 0;
    return codexRow({
      timestamp,
      role: "system",
      recordType,
      summary: `[Compacted context] ${replacementCount} replacement item(s)`,
      fullText: serializeCodexValue({
        message: payload.message,
        replacementCount,
        windowNumber: payload.window_number,
        firstWindowId: payload.first_window_id,
        previousWindowId: payload.previous_window_id,
        windowId: payload.window_id,
      }),
      ...baseRolloutFields(ctx, sourceFile, attribution),
    });
  }

  if (recordType === "world_state") {
    const stateKeys = payload.state && typeof payload.state === "object"
      ? Object.keys(payload.state)
      : [];
    return codexRow({
      timestamp,
      role: "system",
      recordType,
      summary: `[World state: ${payload.full ? "full" : "incremental"}] ${stateKeys.join(", ")}`,
      fullText: serializeCodexValue({ full: !!payload.full, stateKeys }),
      ...baseRolloutFields(ctx, sourceFile, attribution),
    });
  }

  if (recordType === "inter_agent_communication_metadata") {
    return codexRow({
      timestamp,
      role: "system",
      recordType,
      summary: `[Inter-agent communication metadata] trigger_turn=${!!payload.trigger_turn}`,
      fullText: payloadTextWithoutOpaqueFields(payload),
      ...baseRolloutFields(ctx, sourceFile, attribution),
    });
  }

  return codexRow({
    timestamp,
    role: "system",
    recordType,
    summary: `[${recordType}]`,
    fullText: payloadTextWithoutOpaqueFields(payload),
    ...baseRolloutFields(ctx, sourceFile, attribution),
    toolName: "",
  });
}

async function readJsonlFile(filePath, onLine, parseStats = null) {
  // Bounded reader: caps per-line size (one huge/newline-free rollout line can't OOM the worker)
  // and contains a per-line handler throw — a literal `null` line skips itself instead of
  // unwinding the loop and discarding every row already parsed from this file.
  await readJsonlBounded(filePath, onLine, { parseStats });
}

async function extractCodexHistoryFile(historyPath, attribution = {}, parseStats = null) {
  const rows = [];
  await readJsonlFile(historyPath, (obj, lineNumber) => {
    const row = assignLineNumber(parseCodexHistoryLine(obj, historyPath, attribution), lineNumber);
    if (row) rows.push(row);
  }, parseStats);
  return rows;
}

async function extractCodexRolloutFile(rolloutPath, threadIndex, attribution = {}, parseStats = null) {
  const ctx = {
    sessionId: "",
    parentId: "",
    workspace: "",
    model: "",
    gitBranch: "",
    threadIndex,
    isSidechainSession: false,
    toolNamesByCallId: new Map(),
  };
  const rows = [];
  await readJsonlFile(rolloutPath, (obj, lineNumber) => {
    const row = assignLineNumber(parseRolloutEnvelope(obj, rolloutPath, ctx, attribution), lineNumber);
    if (row) rows.push(row);
  }, parseStats);
  return rows;
}

/**
 * Extract all Codex rows from a ~/.codex directory.
 */
async function extractCodexDir(codexRoot, attribution = {}, options = {}) {
  const rows = [];
  const parseStats = { errors: 0 };
  const threadIndex = loadThreadIndex(codexRoot);
  const rolloutPaths = listRolloutFiles(codexRoot, options);
  const historyPath = path.join(codexRoot, "history.jsonl");
  const hasHistory = fs.existsSync(historyPath) && peekHistoryJsonl(historyPath);
  const fileCount = (hasHistory ? 1 : 0) + rolloutPaths.length;
  let fileIndex = 0;
  let emittedRowCount = 0;
  const { onFileProgress, onExtractedRows } = options;

  const emitBatch = (batch) => {
    if (!batch?.length) return;
    const filtered = filterSidechainRows(batch, options);
    emittedRowCount += filtered.length;
    if (onExtractedRows && filtered.length) {
      onExtractedRows(filtered);
      return;
    }
    rows.push(...filtered);
  };

  if (hasHistory) {
    fileIndex += 1;
    tickFileProgress(onFileProgress, fileIndex, fileCount, historyPath);
    try {
      emitBatch(await extractCodexHistoryFile(historyPath, attribution, parseStats));
    } catch (e) {
      dbg("AIHIST", "codex history.jsonl failed", { path: historyPath, err: e.message });
    }
  }

  // Read rollout files in bounded-concurrency batches (threadIndex is a read-only map; sink dedupes +
  // DB/finalize sorts, so order is irrelevant). Per-file error isolation + progress preserved.
  await processFilesConcurrently(rolloutPaths, {
    process: (rolloutPath) => extractCodexRolloutFile(rolloutPath, threadIndex, attribution, parseStats),
    onProgress: (rolloutPath) => { fileIndex += 1; tickFileProgress(onFileProgress, fileIndex, fileCount, rolloutPath); },
    onRows: (batch) => emitBatch(batch),
    onError: (e, rolloutPath) => dbg("AIHIST", "codex rollout failed", { path: rolloutPath, err: e.message }),
    checkAbort: options.checkAbort,
  });

  const { supplementCodexFromStateSqlite } = require("./codex-state-sqlite");
  const { rows: sqliteRows, stats: sqliteStats } = supplementCodexFromStateSqlite(codexRoot, attribution, options);
  if (sqliteRows.length) emitBatch(sqliteRows);

  // Auxiliary stores (sqlite/codex-dev.db, logs*.sqlite) and flat-file evidence
  // (memories/rollout_summaries, hooks.json). Both resolve strictly inside codexRoot, so a triage
  // folder stays scope-confined. Failures are contained per-store and must not fail the import.
  const { supplementCodexFromAuxSqlite } = require("./codex-aux-sqlite");
  let auxSqliteStats = null;
  try {
    const { rows: auxRows, stats } = supplementCodexFromAuxSqlite(codexRoot, attribution, options);
    if (auxRows.length) emitBatch(auxRows);
    auxSqliteStats = stats;
  } catch (e) {
    dbg("AIHIST", "codex aux sqlite supplement failed", { err: e.message });
  }

  const { supplementCodexFromLocalEvidence } = require("./codex-local-evidence");
  let localEvidenceStats = null;
  try {
    const { rows: localRows, stats } = supplementCodexFromLocalEvidence(codexRoot, attribution, options);
    if (localRows.length) emitBatch(localRows);
    localEvidenceStats = stats;
  } catch (e) {
    dbg("AIHIST", "codex local evidence supplement failed", { err: e.message });
  }

  let vscodeAgentStats = null;
  // VS Code is a separate evidence root. Only consult directories explicitly supplied by the
  // caller; never probe the examiner workstation's global VS Code locations from a Codex import.
  const codexVsCodeUserDirs = Array.isArray(options.codexVsCodeUserDirs)
    ? options.codexVsCodeUserDirs.filter((p) => typeof p === "string" && p.trim())
    : [];
  const needsVsCodeAgentSupplement = emittedRowCount < 8 && codexVsCodeUserDirs.length > 0;
  if (needsVsCodeAgentSupplement) {
    try {
      const { supplementCodexFromVsCodeAgentSessions } = require("./vscode-chat-db");
      const { dedupeAiHistoryRows } = require("./row-utils");
      const { rows: vsRows, stats: vsStats } = await supplementCodexFromVsCodeAgentSessions(
        attribution,
        { ...options, userDataDirs: codexVsCodeUserDirs },
      );
      if (vsRows.length) {
        if (onExtractedRows) {
          emitBatch(vsRows);
        } else {
          const merged = dedupeAiHistoryRows([...rows, ...vsRows]);
          rows.length = 0;
          rows.push(...merged);
        }
        vscodeAgentStats = vsStats;
      }
    } catch (e) {
      dbg("AIHIST", "codex vscode agent supplement failed", { err: e.message });
    }
  }

  if (onExtractedRows) {
    const out = [];
    if (sqliteStats) out._codexStateSqliteStats = sqliteStats;
    if (auxSqliteStats) out._codexAuxSqliteStats = auxSqliteStats;
    if (localEvidenceStats) out._codexLocalEvidenceStats = localEvidenceStats;
    if (vscodeAgentStats) out._codexVsCodeAgentStats = vscodeAgentStats;
    if (parseStats.errors) out._parseErrors = parseStats.errors;
    return out;
  }

  const finalized = finalizeAiHistoryRows(filterSidechainRows(rows, options), options);
  if (sqliteStats) finalized._codexStateSqliteStats = sqliteStats;
  if (auxSqliteStats) finalized._codexAuxSqliteStats = auxSqliteStats;
  if (localEvidenceStats) finalized._codexLocalEvidenceStats = localEvidenceStats;
  if (vscodeAgentStats) finalized._codexVsCodeAgentStats = vscodeAgentStats;
  if (parseStats.errors) finalized._parseErrors = parseStats.errors;
  return finalized;
}

async function extractCodexPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  let stat;
  try { stat = fs.statSync(target); } catch (e) {
    throw new Error(`Cannot read path: ${e.message}`);
  }

  if (stat.isDirectory()) {
    const root = resolveCodexHome(target);
    if (!root) throw new Error("Not an OpenAI Codex .codex directory.");
    return extractCodexDir(root, attribution, options);
  }

  const ext = path.extname(target).toLowerCase();
  if (ext !== ".jsonl") {
    throw new Error("Expected a .jsonl file or a .codex directory.");
  }

  const codexRoot = resolveCodexHome(target);
  const threadIndex = codexRoot ? loadThreadIndex(codexRoot) : new Map();

  if (path.basename(target) === "history.jsonl" && peekHistoryJsonl(target)) {
    const rows = await extractCodexHistoryFile(target, attribution);
    for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
    return rows;
  }

  if (isCodexRolloutFile(target)) {
    const rows = await extractCodexRolloutFile(target, threadIndex, attribution);
    for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
    return rows;
  }

  throw new Error("Unrecognized Codex JSONL file (expected history.jsonl or rollout-*.jsonl under .codex).");
}

function defaultCodexHome() {
  const env = process.env.CODEX_HOME;
  if (env && fs.existsSync(env)) return env;
  return path.join(os.homedir(), CODEX_DIR_NAME);
}

module.exports = {
  CODEX_DIR_NAME,
  ROLLOUT_FILE_RE,
  resolveCodexHome,
  isCodexDir,
  isCodexRolloutFile,
  listRolloutFiles,
  countRolloutFiles,
  stripCodexUserText,
  extractPayloadContent,
  parseCodexHistoryLine,
  parseRolloutEnvelope,
  isCodexForkedSession,
  extractCodexDir,
  extractCodexPath,
  defaultCodexHome,
};
