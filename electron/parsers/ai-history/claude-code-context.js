/** Claude Code policy, MCP, instruction, task, plan, backup, and file-history artifacts. */

const fs = require("fs");
const path = require("path");

const { TOOL_CLAUDE_CODE } = require("./schema");
const { formatTimestampUtc, makeRow } = require("./row-utils");
const {
  safeStat,
  walkContextFiles,
  inventoryContextFiles,
  contextInventoryRow,
} = require("./context-inventory");

const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const SECRET_KEY_RE = /(authorization|api[_-]?key|token|secret|password|credential|cookie)/i;

function readJsonObject(filePath) {
  const st = safeStat(filePath);
  if (!st || !st.isFile() || st.size > MAX_CONFIG_BYTES) return null;
  try {
    const value = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch { return null; }
}

function claudeContextRow(fields) {
  return makeRow({ ...fields, tool: TOOL_CLAUDE_CODE }, TOOL_CLAUDE_CODE);
}

function redactArgument(value, index, args) {
  const text = String(value ?? "");
  if (index > 0 && SECRET_KEY_RE.test(String(args[index - 1] ?? ""))) return "[REDACTED]";
  return text.replace(/((?:token|secret|password|authorization|api[_-]?key)=)[^\s]+/ig, "$1[REDACTED]");
}

function safeServerConfig(name, config) {
  const cfg = config && typeof config === "object" && !Array.isArray(config) ? config : {};
  const args = Array.isArray(cfg.args) ? cfg.args.map(redactArgument) : [];
  const urlText = cfg.url != null ? String(cfg.url) : "";
  let url = urlText;
  let queryParameterNames = [];
  try {
    const parsed = new URL(urlText);
    queryParameterNames = [...parsed.searchParams.keys()];
    parsed.search = "";
    parsed.hash = "";
    url = parsed.toString();
  } catch { /* retain non-URL value */ }
  return {
    name,
    type: cfg.type != null ? String(cfg.type) : "",
    command: cfg.command != null ? String(cfg.command) : "",
    args,
    url,
    queryParameterNames,
    envVariableNames: cfg.env && typeof cfg.env === "object" ? Object.keys(cfg.env).sort() : [],
    headerNames: cfg.headers && typeof cfg.headers === "object" ? Object.keys(cfg.headers).sort() : [],
    disabled: cfg.disabled === true,
    sensitiveValuesCopied: false,
  };
}

function extractMcpRows(filePath, servers, attribution = {}) {
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) return [];
  const st = safeStat(filePath);
  const timestamp = formatTimestampUtc(st?.mtimeMs);
  const rows = [];
  for (const [name, config] of Object.entries(servers).sort(([a], [b]) => a.localeCompare(b))) {
    const safe = safeServerConfig(name, config);
    rows.push(claudeContextRow({
      timestamp,
      timestampBasis: "configuration file mtime",
      role: "metadata",
      recordType: "mcp_server_config",
      summary: `Claude Code MCP server — ${name}`
        + `${safe.command ? ` (${safe.command})` : safe.url ? ` (${safe.url})` : ""}`
        + `${safe.disabled ? " [disabled]" : ""}`,
      fullText: JSON.stringify(safe, null, 2),
      toolName: name,
      toolCommand: safe.command,
      toolInput: safe.args.join(" "),
      toolDescription: "MCP server configuration. Environment, header, credential, and URL query values are excluded; only their names are retained.",
      messageId: `mcp:${name}`,
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function extractClaudeSettings(filePath, attribution = {}) {
  const obj = readJsonObject(filePath);
  if (!obj) return [];
  const st = safeStat(filePath);
  const timestamp = formatTimestampUtc(st?.mtimeMs);
  const permissions = obj.permissions && typeof obj.permissions === "object" ? obj.permissions : {};
  const safeSettings = {
    model: obj.model ?? null,
    effortLevel: obj.effortLevel ?? null,
    theme: obj.theme ?? null,
    permissionMode: obj.permissionMode ?? permissions.defaultMode ?? null,
    permissionAllow: Array.isArray(permissions.allow) ? permissions.allow.map(String) : [],
    permissionAsk: Array.isArray(permissions.ask) ? permissions.ask.map(String) : [],
    permissionDeny: Array.isArray(permissions.deny) ? permissions.deny.map(String) : [],
    additionalDirectories: Array.isArray(permissions.additionalDirectories)
      ? permissions.additionalDirectories.map(String) : [],
    statusLineCommand: obj.statusLine?.command != null ? String(obj.statusLine.command) : "",
    environmentVariableNames: obj.env && typeof obj.env === "object" ? Object.keys(obj.env).sort() : [],
    sensitiveValuesCopied: false,
  };
  const rows = [claudeContextRow({
    timestamp,
    timestampBasis: "settings.json mtime",
    role: "metadata",
    recordType: "cli_settings",
    summary: "Claude Code settings"
      + `${safeSettings.model ? ` — model ${safeSettings.model}` : ""}`
      + `${safeSettings.permissionMode ? `, permission mode ${safeSettings.permissionMode}` : ""}`
      + `, ${safeSettings.permissionAllow.length} allow / ${safeSettings.permissionDeny.length} deny rule(s)`,
    fullText: JSON.stringify(safeSettings, null, 2),
    toolDescription: "Claude Code policy and UI configuration. Environment and credential values are excluded.",
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  })];

  const hooks = obj.hooks && typeof obj.hooks === "object" ? obj.hooks : {};
  for (const [event, groups] of Object.entries(hooks)) {
    for (const group of (Array.isArray(groups) ? groups : [groups])) {
      if (!group || typeof group !== "object") continue;
      const matcher = group.matcher != null ? String(group.matcher) : "";
      const hookList = Array.isArray(group.hooks) ? group.hooks : [group];
      for (let i = 0; i < hookList.length; i++) {
        const hook = hookList[i];
        if (!hook || typeof hook !== "object") continue;
        const command = hook.command != null ? String(hook.command) : "";
        if (!command && !hook.type) continue;
        rows.push(claudeContextRow({
          timestamp,
          timestampBasis: "settings.json mtime",
          role: "metadata",
          recordType: "hook_config",
          summary: `Claude Code hook — ${event}${matcher ? ` [${matcher}]` : ""}: ${command || hook.type}`,
          fullText: JSON.stringify({
            event,
            matcher,
            type: hook.type ?? null,
            command,
            timeout: hook.timeout ?? null,
            environmentVariableNames: hook.env && typeof hook.env === "object" ? Object.keys(hook.env).sort() : [],
            sensitiveValuesCopied: false,
          }, null, 2),
          toolName: event,
          toolCommand: command,
          toolInput: matcher,
          toolDescription: "Configured lifecycle command. This row proves configuration at file mtime; it does not prove the hook executed.",
          messageId: `hook:${event}:${i}`,
          sourceFile: filePath,
          user: attribution.user || "",
          host: attribution.host || "",
        }));
      }
    }
  }
  rows.push(...extractMcpRows(filePath, obj.mcpServers, attribution));
  return rows;
}

function classifyClaudeContextFile(rootPath, filePath) {
  const rel = path.relative(rootPath, filePath).replace(/\\/g, "/");
  const base = path.basename(filePath);
  if (rel === "settings.json" || rel === ".mcp.json") return null;
  if (rel === ".credentials.json") return {
    family: "credential-store",
    recordType: "credential_inventory",
    summaryLabel: "Claude Code credential store",
    credentialExcluded: true,
    toolDescription: "Credential store inventoried by path, size, and mtime. Contents are never opened or hashed.",
  };
  if (rel.startsWith("file-history/")) {
    const match = /^file-history\/([^/]+)\/([^@/]+)@v(\d+)$/.exec(rel);
    return {
      family: "file-history",
      recordType: "file_history_backup",
      summaryLabel: "Claude Code physical file-history copy",
      sessionId: match?.[1] || path.basename(path.dirname(filePath)),
      messageId: match ? `${match[2]}@v${match[3]}` : rel,
      parentId: match?.[2] || "",
      extra: { backupVersion: match ? Number(match[3]) : null, contentId: match?.[2] || null },
      toolDescription: "Physical file-history bytes retained by Claude Code. The timeline stores metadata and a content hash; acquire SourceFile for the original bytes.",
    };
  }
  if (rel.startsWith("backups/") && /^\.claude\.json\.backup(?:\.\d+)?$/.test(base)) {
    const epoch = Number(base.match(/\.(\d{10,})$/)?.[1]);
    return {
      family: "state-backup",
      recordType: "claude_state_backup_inventory",
      summaryLabel: "Claude Code state backup",
      extra: {
        backupFilenameEpochMs: Number.isFinite(epoch) ? epoch : null,
        linkedCurrentSource: path.join(path.dirname(rootPath), ".claude.json"),
      },
      toolDescription: "Raw ~/.claude.json backup layout. The hash links this physical backup without copying the state body into the row.",
    };
  }
  if (rel.startsWith("plans/")) return { family: "plan", recordType: "plan_inventory", summaryLabel: "Claude Code plan" };
  if (rel.startsWith("tasks/") || rel.startsWith("todos/")) {
    return { family: rel.startsWith("tasks/") ? "task" : "todo", recordType: "task_inventory", summaryLabel: "Claude Code task state" };
  }
  if (base === "CLAUDE.md" || base === "MEMORY.md" || /(?:^|\/)memory\//i.test(rel)) {
    return { family: "instruction-memory", recordType: "instruction_inventory", summaryLabel: "Claude Code instruction or memory" };
  }
  if (base === "SKILL.md" || rel.startsWith("skills/")) {
    return { family: "skill", recordType: "skill_inventory", summaryLabel: "Claude Code skill context" };
  }
  if (rel.startsWith("plugins/") && (
    /(?:^|\/)(?:installed_plugins|known_marketplaces)\.json$/.test(rel)
    || /(?:^|\/)plugin\.json$/.test(rel)
    || /\/commands\/[^/]+\.md$/.test(rel)
  )) {
    return { family: "plugin", recordType: "plugin_inventory", summaryLabel: "Claude Code plugin context" };
  }
  return null;
}

function listClaudeContextFiles(rootPath, options = {}) {
  if (!rootPath || !safeStat(rootPath)?.isDirectory()) return { files: [], stats: { eligible: 0, selected: 0, omitted: 0 } };
  return walkContextFiles(rootPath, {
    maxDepth: 14,
    maxFiles: options.maxClaudeContextFiles || 10000,
    checkAbort: options.checkAbort,
    accept: (filePath) => !!classifyClaudeContextFile(rootPath, filePath),
    skipDir: (dir) => /(?:^|[\\/])(?:cache|debug|telemetry|test-results|chrome)(?:[\\/]|$)/i.test(dir),
  });
}

function isClaudeCliConfigRoot(rootPath) {
  const st = safeStat(rootPath);
  if (!st || !st.isDirectory()) return false;
  if (path.basename(rootPath) === ".claude") return true;
  const configuredRoot = process.env.CLAUDE_CONFIG_DIR ? path.resolve(process.env.CLAUDE_CONFIG_DIR) : "";
  if (configuredRoot && path.resolve(rootPath) === configuredRoot) return true;
  // Relocated CLAUDE_CONFIG_DIR roots keep at least one Claude-specific direct marker. A generic
  // `projects/` directory alone is shared by Cursor, ChatGPT, Continue, and ordinary repositories.
  if (fs.existsSync(path.join(rootPath, "file-history"))) return true;
  const backupDir = path.join(rootPath, "backups");
  try {
    if (fs.readdirSync(backupDir).some((name) => /^\.claude\.json\.backup(?:\.\d+)?$/.test(name))) return true;
  } catch { /* absent */ }
  const settings = readJsonObject(path.join(rootPath, "settings.json"));
  if (settings && ["permissions", "effortLevel", "statusLine", "enabledPlugins", "includeCoAuthoredBy"]
    .some((key) => Object.prototype.hasOwnProperty.call(settings, key))) return true;
  const hasProjectState = fs.existsSync(path.join(rootPath, "projects")) || fs.existsSync(path.join(rootPath, "history.jsonl"));
  return hasProjectState && (
    fs.existsSync(path.join(rootPath, ".mcp.json"))
    || fs.existsSync(path.join(rootPath, ".credentials.json"))
  );
}

function extractClaudeContext(rootPath, attribution = {}, options = {}) {
  const rows = [];
  const settingsPath = path.join(rootPath, "settings.json");
  const mcpPath = path.join(rootPath, ".mcp.json");
  if (safeStat(settingsPath)?.isFile()) rows.push(...extractClaudeSettings(settingsPath, attribution));
  const mcp = readJsonObject(mcpPath);
  if (mcp) rows.push(...extractMcpRows(mcpPath, mcp.mcpServers || mcp, attribution));

  const listed = listClaudeContextFiles(rootPath, options);
  const inventory = inventoryContextFiles({
    tool: TOOL_CLAUDE_CODE,
    rootPath,
    files: listed.files,
    attribution,
    checkAbort: options.checkAbort,
    classify: (filePath) => classifyClaudeContextFile(rootPath, filePath),
  });
  rows.push(...inventory.rows);
  return {
    rows,
    stats: {
      typedRows: rows.length - inventory.rows.length,
      ...inventory.stats,
      eligible: listed.stats.eligible,
      selected: listed.stats.selected,
      omitted: listed.stats.omitted,
    },
  };
}

module.exports = {
  MAX_CONFIG_BYTES,
  safeServerConfig,
  extractMcpRows,
  extractClaudeSettings,
  classifyClaudeContextFile,
  listClaudeContextFiles,
  isClaudeCliConfigRoot,
  extractClaudeContext,
  contextInventoryRow,
};
