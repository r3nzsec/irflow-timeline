/** Grok Build configuration, trust, identity, prompt, terminal, worktree, and task artifacts. */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { TOOL_GROK_BUILD } = require("./schema");
const { formatTimestampUtc, parseIsoTimestamp, makeRow } = require("./row-utils");
const { openVscdbReadOnly, listTables, safeCloseDb } = require("./vscdb-kv");
const { copySqliteFamilyToTemp } = require("./codex-state-sqlite");
const { safeStat, walkContextFiles, inventoryContextFiles, contextInventoryRow } = require("./context-inventory");

const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_TERMINAL_BYTES = 1024 * 1024;
const SECRET_KEY_RE = /(auth|token|secret|password|credential|cookie|api[_-]?key|private[_-]?key)/i;

function row(fields) {
  return makeRow({ ...fields, tool: TOOL_GROK_BUILD }, TOOL_GROK_BUILD);
}

function fileTime(filePath) {
  return formatTimestampUtc(safeStat(filePath)?.mtimeMs);
}

function readTextCapped(filePath, maxBytes = MAX_CONFIG_BYTES) {
  const st = safeStat(filePath);
  if (!st?.isFile() || st.size > maxBytes) return null;
  try { return fs.readFileSync(filePath, "utf8"); } catch { return null; }
}

function scalar(value) {
  const v = String(value || "").trim();
  if (/^(true|false)$/i.test(v)) return v.toLowerCase() === "true";
  if (/^-?\d+(?:\.\d+)?$/.test(v)) return Number(v);
  if (v.startsWith("[") && v.endsWith("]")) {
    try { return JSON.parse(v.replace(/'/g, '"')); } catch { return v; }
  }
  return v.replace(/^['"]|['"]$/g, "");
}

function safeTomlValue(key, rawValue) {
  const keyText = String(key || "");
  const raw = String(rawValue || "").trim();
  if (SECRET_KEY_RE.test(keyText)) return "[REDACTED]";
  if (/^(?:env|environment|headers?|http_headers)$/i.test(keyText)) {
    const names = [...raw.matchAll(/([A-Za-z_][A-Za-z0-9_.-]*)\s*=/g)].map((match) => match[1]);
    return { valueNames: [...new Set(names)].sort(), sensitiveValuesCopied: false };
  }
  if (/(?:url|endpoint)$/i.test(keyText)) {
    const value = scalar(raw);
    try {
      const parsed = new URL(String(value));
      const queryParameterNames = [...parsed.searchParams.keys()];
      parsed.search = "";
      parsed.hash = "";
      return { url: parsed.toString(), queryParameterNames, sensitiveQueryValuesCopied: false };
    } catch { return value; }
  }
  const value = scalar(raw);
  if (Array.isArray(value)) {
    return value.map((item, index, all) => (
      index > 0 && SECRET_KEY_RE.test(String(all[index - 1])) ? "[REDACTED]" : item
    ));
  }
  if (typeof value === "string" && SECRET_KEY_RE.test(value) && /=/.test(value)) {
    return value.replace(/((?:auth|token|secret|password|credential|cookie|api[_-]?key)[A-Za-z0-9_.-]*\s*=\s*)[^,}\s]+/ig, "$1[REDACTED]");
  }
  return value;
}

function parseTomlSafe(text) {
  const sections = { global: {} };
  let section = "global";
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line) continue;
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1].trim();
      if (!sections[section]) sections[section] = {};
      continue;
    }
    const match = /^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    sections[section][match[1]] = safeTomlValue(match[1], match[2]);
  }
  return sections;
}

function extractConfigRows(rootPath, attribution = {}) {
  const rows = [];
  const configPath = path.join(rootPath, "config.toml");
  const configText = readTextCapped(configPath);
  if (configText != null) {
    const sections = parseTomlSafe(configText);
    rows.push(row({
      timestamp: fileTime(configPath),
      timestampBasis: "config.toml mtime",
      role: "metadata",
      recordType: "cli_settings",
      summary: `Grok Build configuration — ${Object.keys(sections).length} section(s)`,
      fullText: JSON.stringify({ sections, sensitiveValuesCopied: false }, null, 2),
      toolDescription: "Grok Build configuration and policy. Secret-like values are redacted. This proves configuration, not use or execution.",
      sourceFile: configPath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  const trustedPath = path.join(rootPath, "trusted_folders.toml");
  const trustedText = readTextCapped(trustedPath);
  if (trustedText != null) {
    const sections = parseTomlSafe(trustedText);
    for (const [folder, details] of Object.entries(sections)) {
      if (folder === "global" && !Object.keys(details).length) continue;
      const folderKey = folder.replace(/^['"]|['"]$/g, "");
      const ts = parseIsoTimestamp(details.decided_at);
      rows.push(row({
        timestamp: formatTimestampUtc(ts) || fileTime(trustedPath),
        timestampBasis: ts != null ? "trusted_folders decided_at" : "trusted_folders.toml mtime",
        role: "metadata",
        recordType: "trusted_folder_config",
        summary: `Grok Build trust decision — ${folderKey}: ${String(details.trusted ?? "unknown")}`,
        fullText: JSON.stringify({ folder: folderKey, ...details }, null, 2),
        workspace: folderKey === "global" ? "" : folderKey,
        messageId: folderKey,
        toolDescription: "Recorded trust configuration. It does not prove a command ran in the folder.",
        sourceFile: trustedPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }
  }
  return rows;
}

function extractIdentityRows(rootPath, attribution = {}) {
  const rows = [];
  for (const name of ["version.json", "agent_id"]) {
    const filePath = path.join(rootPath, name);
    const text = readTextCapped(filePath, 64 * 1024);
    if (text == null) continue;
    let value = text.trim();
    if (name.endsWith(".json")) {
      try { value = JSON.parse(value); } catch { /* retain text */ }
    }
    rows.push(row({
      timestamp: fileTime(filePath),
      timestampBasis: "source file mtime",
      role: "metadata",
      recordType: name === "agent_id" ? "local_agent_identity" : "application_version",
      summary: name === "agent_id" ? `Grok Build local agent identity — ${String(value)}` : "Grok Build version metadata",
      fullText: typeof value === "string" ? value : JSON.stringify(value, null, 2),
      messageId: name === "agent_id" ? String(value) : "version",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function listPromptAndTerminalFiles(rootPath, options = {}) {
  const sessions = path.join(rootPath, "sessions");
  return walkContextFiles(sessions, {
    maxDepth: 8,
    maxFiles: options.maxGrokIndependentFiles || 20000,
    accept: (filePath) => path.basename(filePath) === "prompt_context.json"
      || (path.basename(path.dirname(filePath)) === "terminal" && path.extname(filePath).toLowerCase() === ".log"),
  });
}

function sessionFromGrokPath(filePath) {
  const parts = filePath.split(path.sep);
  const terminalIndex = parts.lastIndexOf("terminal");
  const baseIndex = terminalIndex >= 0 ? terminalIndex - 1 : parts.length - 2;
  return baseIndex >= 0 ? parts[baseIndex] : "";
}

function hashedPromptValue(value) {
  const body = typeof value === "string" ? value : JSON.stringify(value);
  return {
    present: !!body,
    length: body?.length || 0,
    sha256: body ? crypto.createHash("sha256").update(body).digest("hex") : null,
    contentCopied: false,
  };
}

function sanitizePromptContext(value, parentKey = "", depth = 0) {
  if (depth > 16) return { omitted: true, reason: "depth_limit" };
  if (value == null || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (/(?:prompt_body|system_prompt(?!_label)|content|body|instruction_text|memory_text|persona_summaries)/i.test(parentKey)) {
      return hashedPromptValue(value);
    }
    return value;
  }
  if (Array.isArray(value)) return value.slice(0, 1000).map((item) => sanitizePromptContext(item, parentKey, depth + 1));
  if (typeof value !== "object") return String(value);
  const out = {};
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_KEY_RE.test(key)) {
      out[key] = "[REDACTED]";
      continue;
    }
    if (/(?:prompt_body|system_prompt(?!_label)|content|body|instruction_text|memory_text)/i.test(key)) {
      out[key] = hashedPromptValue(child);
      continue;
    }
    out[key] = sanitizePromptContext(child, key, depth + 1);
  }
  return out;
}

function extractPromptAndTerminalRows(rootPath, attribution = {}, options = {}) {
  const listed = listPromptAndTerminalFiles(rootPath, options);
  const rows = [];
  let terminalRows = 0;
  let promptRows = 0;
  let oversized = 0;
  for (const filePath of listed.files) {
    options.checkAbort?.();
    const base = path.basename(filePath);
    const sessionId = sessionFromGrokPath(filePath);
    if (base === "prompt_context.json") {
      const text = readTextCapped(filePath);
      if (text == null) {
        oversized += 1;
        const inventory = contextInventoryRow({
          tool: TOOL_GROK_BUILD,
          rootPath,
          filePath,
          family: "oversized-prompt-context",
          recordType: "prompt_context_inventory",
          summaryLabel: "Grok Build prompt context over decode limit",
          attribution,
          sessionId,
          extra: { decodeLimitBytes: MAX_CONFIG_BYTES, omissionReason: "source exceeds prompt-context decode limit" },
        });
        if (inventory) rows.push(inventory);
        continue;
      }
      let obj;
      try { obj = JSON.parse(text); } catch { continue; }
      const safe = sanitizePromptContext(obj || {});
      safe.sensitiveValuesCopied = false;
      rows.push(row({
        timestamp: fileTime(filePath),
        timestampBasis: "prompt_context.json mtime",
        role: "metadata",
        recordType: "prompt_context",
        summary: `Grok Build prompt context — ${safe.prompt_mode || "unknown mode"}${safe.cwd ? ` in ${safe.cwd}` : ""}`,
        fullText: JSON.stringify(safe, null, 2),
        sessionId,
        workspace: safe.cwd || "",
        sourceFile: filePath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
      promptRows += 1;
      continue;
    }
    const text = readTextCapped(filePath, MAX_TERMINAL_BYTES);
    if (text == null) {
      oversized += 1;
      const inventory = contextInventoryRow({
        tool: TOOL_GROK_BUILD,
        rootPath,
        filePath,
        family: "oversized-terminal-output",
        recordType: "terminal_output_inventory",
        summaryLabel: "Grok Build terminal output over decode limit",
        attribution,
        sessionId,
        extra: { decodeLimitBytes: MAX_TERMINAL_BYTES, omissionReason: "source exceeds terminal-output decode limit" },
        toolDescription: "Independent terminal output exceeds the bounded timeline body limit. SourceFile retains the acquisition path and FullText records size/hash/omission reason.",
      });
      if (inventory) rows.push(inventory);
      continue;
    }
    const callMatch = /(?:monitor-)?call-([0-9a-f-]{36})-(\d+)\.log$/i.exec(base);
    const callId = callMatch?.[1] || base;
    rows.push(row({
      timestamp: fileTime(filePath),
      timestampBasis: "terminal log file mtime",
      role: "tool",
      recordType: "terminal_output_log",
      summary: `Grok Build terminal output — ${base}${text.trim() ? `: ${text.trim().split(/\r?\n/, 1)[0]}` : " [empty]"}`,
      fullText: text,
      toolName: "terminal",
      toolDescription: "Independent terminal output retained by Grok Build. Call UUID provides a join key; file mtime is not command execution start time.",
      sessionId,
      messageId: callId,
      parentId: callMatch?.[2] || "",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
    terminalRows += 1;
  }
  return { rows, stats: { terminalRows, promptRows, oversized, ...listed.stats } };
}

function safeDbRecord(value) {
  const out = {};
  for (const [key, val] of Object.entries(value || {})) {
    if (SECRET_KEY_RE.test(key)) out[key] = "[REDACTED]";
    else if (Buffer.isBuffer(val)) out[key] = `[BLOB ${val.length} bytes]`;
    else out[key] = val;
  }
  return out;
}

function extractWorktreeRows(rootPath, attribution = {}) {
  const dbPath = path.join(rootPath, "worktrees.db");
  if (!safeStat(dbPath)?.isFile()) return { rows: [], stats: { databases: 0, records: 0, failed: 0 } };
  let snapshot;
  let db;
  try {
    snapshot = copySqliteFamilyToTemp(dbPath);
    db = openVscdbReadOnly(snapshot.dbPath);
    if (!listTables(db).includes("worktrees")) return { rows: [], stats: { databases: 1, records: 0, unsupported: 1 } };
    const records = db.prepare("SELECT * FROM worktrees ORDER BY rowid ASC").all();
    const rows = records.map((record, index) => {
      const safe = safeDbRecord(record);
      const ts = parseIsoTimestamp(safe.last_accessed_at ?? safe.created_at);
      return row({
        timestamp: formatTimestampUtc(ts),
        timestampBasis: ts != null ? "worktrees database record timestamp" : "unavailable",
        role: "metadata",
        recordType: "worktree_state",
        summary: `Grok Build worktree — ${safe.path || safe.id || index}${safe.status ? ` [${safe.status}]` : ""}`,
        fullText: JSON.stringify(safe, null, 2),
        sessionId: safe.session_id || "",
        messageId: safe.id || String(index + 1),
        workspace: safe.path || safe.source_repo || "",
        gitBranch: safe.git_ref || "",
        sourceFile: dbPath,
        lineNumber: index + 1,
        user: attribution.user || "",
        host: attribution.host || "",
      });
    });
    return { rows, stats: { databases: 1, records: rows.length, companions: snapshot.sidecars.length, failed: 0 } };
  } catch {
    return { rows: [], stats: { databases: 0, records: 0, failed: 1 } };
  } finally {
    safeCloseDb(db);
    snapshot?.cleanup();
  }
}

function classifyTaskFile(rootPath, filePath) {
  const rel = path.relative(rootPath, filePath).replace(/\\/g, "/");
  if (rel.startsWith("long-running-background-tasks/") && /\.(?:sh|py|log)$/i.test(rel)) return {
    family: rel.endsWith(".log") ? "background-task-output" : "background-task-definition",
    recordType: rel.endsWith(".log") ? "background_task_log_inventory" : "background_task_definition",
    summaryLabel: rel.endsWith(".log") ? "Grok Build background task output" : "Grok Build background task command",
    toolDescription: rel.endsWith(".log")
      ? "Persistent background task output inventoried by path, size, mtime, and hash."
      : "Persistent background task definition. Presence proves configuration, not execution.",
  };
  if (/^(?:upload_queue|uploads|automations)(?:\/|$)/i.test(rel) || rel === "campaigns_state.json") return {
    family: rel.includes("upload") ? "upload-queue" : "automation-state",
    recordType: "local_state_inventory",
    summaryLabel: "Grok Build upload or automation state",
  };
  return null;
}

function listGrokBuildContextFiles(rootPath, options = {}) {
  const direct = ["config.toml", "trusted_folders.toml", "version.json", "agent_id", "worktrees.db"]
    .map((name) => path.join(rootPath, name)).filter((p) => safeStat(p)?.isFile());
  const independent = listPromptAndTerminalFiles(rootPath, options);
  const tasks = walkContextFiles(rootPath, {
    maxDepth: 6,
    maxFiles: options.maxGrokTaskFiles || 5000,
    checkAbort: options.checkAbort,
    accept: (p) => !!classifyTaskFile(rootPath, p),
    skipDir: (p) => /(?:^|[\\/])(?:sessions|bundled|marketplace-cache|downloads|docs|memtrace)(?:[\\/]|$)/i.test(p),
  });
  const primary = [...new Set([...direct, ...independent.files, ...tasks.files])].sort();
  const companions = [];
  for (const p of direct.filter((p) => path.basename(p) === "worktrees.db")) {
    for (const suffix of ["-wal", "-shm", "-journal"]) if (safeStat(`${p}${suffix}`)?.isFile()) companions.push(`${p}${suffix}`);
  }
  return { files: [...primary, ...companions], stats: { independent: independent.stats, tasks: tasks.stats, companionFiles: companions.length } };
}

function extractGrokBuildContext(rootPath, attribution = {}, options = {}) {
  const rows = [...extractConfigRows(rootPath, attribution), ...extractIdentityRows(rootPath, attribution)];
  const independent = extractPromptAndTerminalRows(rootPath, attribution, options);
  rows.push(...independent.rows);
  const worktrees = extractWorktreeRows(rootPath, attribution);
  rows.push(...worktrees.rows);
  const taskListing = walkContextFiles(rootPath, {
    maxDepth: 6,
    maxFiles: options.maxGrokTaskFiles || 5000,
    checkAbort: options.checkAbort,
    accept: (p) => !!classifyTaskFile(rootPath, p),
    skipDir: (p) => /(?:^|[\\/])(?:sessions|bundled|marketplace-cache|downloads|docs|memtrace)(?:[\\/]|$)/i.test(p),
  });
  const inventory = inventoryContextFiles({
    tool: TOOL_GROK_BUILD,
    rootPath,
    files: taskListing.files,
    attribution,
    checkAbort: options.checkAbort,
    classify: (p) => classifyTaskFile(rootPath, p),
  });
  rows.push(...inventory.rows);
  return { rows, stats: { typedRows: rows.length - inventory.rows.length, independent: independent.stats, worktrees: worktrees.stats, taskInventory: inventory.stats, taskOmitted: taskListing.stats.omitted } };
}

module.exports = {
  parseTomlSafe,
  safeTomlValue,
  extractConfigRows,
  extractIdentityRows,
  listPromptAndTerminalFiles,
  extractPromptAndTerminalRows,
  sanitizePromptContext,
  extractWorktreeRows,
  classifyTaskFile,
  listGrokBuildContextFiles,
  extractGrokBuildContext,
};
