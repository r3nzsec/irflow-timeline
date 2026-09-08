/** Cursor hooks, MCP, plans, agent instructions, skills, plugins, and raw index inventory. */

const fs = require("fs");
const path = require("path");

const { TOOL_CURSOR } = require("./schema");
const { formatTimestampUtc, makeRow } = require("./row-utils");
const { safeServerConfig } = require("./claude-code-context");
const {
  safeStat,
  walkContextFiles,
  inventoryContextFiles,
} = require("./context-inventory");

const MAX_CURSOR_CONFIG_BYTES = 4 * 1024 * 1024;

function readJsonObject(filePath) {
  const st = safeStat(filePath);
  if (!st?.isFile() || st.size > MAX_CURSOR_CONFIG_BYTES) return null;
  try {
    const value = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch { return null; }
}

function row(fields) {
  return makeRow({ ...fields, tool: TOOL_CURSOR }, TOOL_CURSOR);
}

function configTime(filePath) {
  return formatTimestampUtc(safeStat(filePath)?.mtimeMs);
}

function extractCursorMcpRows(filePath, attribution = {}) {
  const obj = readJsonObject(filePath);
  const servers = obj?.mcpServers || obj;
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) return [];
  return Object.entries(servers).sort(([a], [b]) => a.localeCompare(b)).map(([name, config]) => {
    const safe = safeServerConfig(name, config);
    return row({
      timestamp: configTime(filePath),
      timestampBasis: "configuration file mtime",
      role: "metadata",
      recordType: "mcp_server_config",
      summary: `Cursor MCP server — ${name}${safe.disabled ? " [disabled]" : ""}`,
      fullText: JSON.stringify(safe, null, 2),
      toolName: name,
      toolCommand: safe.command,
      toolInput: safe.args.join(" "),
      toolDescription: "Configured MCP server. Secret, environment, header, and URL query values are excluded. Configuration does not prove execution.",
      messageId: `mcp:${name}`,
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

function extractCursorHookRows(filePath, attribution = {}) {
  const obj = readJsonObject(filePath);
  if (!obj) return [];
  const hooks = obj.hooks && typeof obj.hooks === "object" ? obj.hooks : obj;
  const rows = [];
  for (const [event, raw] of Object.entries(hooks)) {
    const groups = Array.isArray(raw) ? raw : [raw];
    groups.forEach((group, groupIndex) => {
      if (!group || typeof group !== "object") return;
      const commands = Array.isArray(group.hooks) ? group.hooks : [group];
      commands.forEach((hook, hookIndex) => {
        if (!hook || typeof hook !== "object") return;
        const command = String(hook.command ?? hook.script ?? "");
        const type = String(hook.type ?? "command");
        if (!command && !type) return;
        rows.push(row({
          timestamp: configTime(filePath),
          timestampBasis: "hooks.json mtime",
          role: "metadata",
          recordType: "hook_config",
          summary: `Cursor hook — ${event}: ${command || type}`,
          fullText: JSON.stringify({
            event,
            matcher: group.matcher ?? null,
            type,
            command,
            timeout: hook.timeout ?? null,
            environmentVariableNames: hook.env && typeof hook.env === "object" ? Object.keys(hook.env).sort() : [],
            sensitiveValuesCopied: false,
          }, null, 2),
          toolName: event,
          toolCommand: command,
          toolDescription: "Configured Cursor lifecycle hook. This proves configuration at file mtime and does not prove execution.",
          messageId: `hook:${event}:${groupIndex}:${hookIndex}`,
          sourceFile: filePath,
          user: attribution.user || "",
          host: attribution.host || "",
        }));
      });
    });
  }
  return rows;
}

function classifyCursorContextFile(rootPath, filePath) {
  const rel = path.relative(rootPath, filePath).replace(/\\/g, "/");
  const base = path.basename(filePath);
  if (base === "hooks.json" || base === "mcp.json" || base === ".mcp.json") return null;
  if (/^ai-tracking\/.*\.(?:db|sqlite)$/i.test(rel)) return {
    family: "raw-search-index",
    recordType: "raw_index_inventory",
    summaryLabel: "Cursor raw AI tracking index",
    toolDescription: "Raw Cursor search/tracking index provenance. The database is inventoried and retained as SourceFile; its contents are not promoted as chat evidence without a qualified schema.",
  };
  if (/(?:^|\/)plans?\//i.test(rel)) return { family: "plan", recordType: "plan_inventory", summaryLabel: "Cursor plan" };
  if (base === "AGENTS.md" || base === ".cursorrules" || /(?:^|\/)rules\/.*\.mdc?$/i.test(rel)) {
    return { family: "agent-instruction", recordType: "instruction_inventory", summaryLabel: "Cursor agent instruction" };
  }
  if (base === "SKILL.md" || /(?:^|\/)skills?\//i.test(rel)) return {
    family: "skill",
    recordType: "skill_inventory",
    summaryLabel: "Cursor skill context",
  };
  if (/(?:^|\/)plugins?\//i.test(rel) && /(?:plugin\.json|package\.json|\.md)$/i.test(base)) return {
    family: "plugin",
    recordType: "plugin_inventory",
    summaryLabel: "Cursor plugin context",
  };
  return null;
}

function listCursorContextFiles(rootPath, options = {}) {
  if (!safeStat(rootPath)?.isDirectory()) return { files: [], stats: { eligible: 0, selected: 0, omitted: 0 } };
  return walkContextFiles(rootPath, {
    maxDepth: 14,
    maxFiles: options.maxCursorContextFiles || 10000,
    checkAbort: options.checkAbort,
    accept: (filePath) => !!classifyCursorContextFile(rootPath, filePath),
    skipDir: (dir) => /(?:^|[\\/])(?:cache|cacheddata|logs?|crashpad|gpu-cache)(?:[\\/]|$)/i.test(dir),
  });
}

function directConfigFiles(rootPath) {
  const candidates = [
    path.join(rootPath, "hooks.json"),
    path.join(rootPath, "mcp.json"),
    path.join(rootPath, ".mcp.json"),
    path.join(rootPath, ".cursor", "hooks.json"),
    path.join(rootPath, ".cursor", "mcp.json"),
  ];
  return [...new Set(candidates)].filter((p) => safeStat(p)?.isFile());
}

function extractCursorContext(rootPath, attribution = {}, options = {}) {
  const rows = [];
  const configs = directConfigFiles(rootPath);
  for (const filePath of configs) {
    const base = path.basename(filePath);
    if (base === "hooks.json") rows.push(...extractCursorHookRows(filePath, attribution));
    else rows.push(...extractCursorMcpRows(filePath, attribution));
  }
  const listed = listCursorContextFiles(rootPath, options);
  const inventory = inventoryContextFiles({
    tool: TOOL_CURSOR,
    rootPath,
    files: listed.files,
    attribution,
    checkAbort: options.checkAbort,
    classify: (filePath) => classifyCursorContextFile(rootPath, filePath),
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
  readJsonObject,
  extractCursorMcpRows,
  extractCursorHookRows,
  classifyCursorContextFile,
  listCursorContextFiles,
  directConfigFiles,
  extractCursorContext,
};
