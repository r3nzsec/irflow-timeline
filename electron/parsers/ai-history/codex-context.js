/** Codex core configuration, project trust, MCP, plugin, skill, and instruction context. */

const fs = require("fs");
const path = require("path");

const { TOOL_CODEX } = require("./schema");
const { formatTimestampUtc, makeRow } = require("./row-utils");
const { parseTomlSafe } = require("./grok-build-context");
const { safeStat, walkContextFiles, inventoryContextFiles } = require("./context-inventory");

const MAX_CODEX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_CODEX_INSTRUCTION_BYTES = 1024 * 1024;

function row(fields) {
  return makeRow({ ...fields, tool: TOOL_CODEX }, TOOL_CODEX);
}

function fileTime(filePath) {
  return formatTimestampUtc(safeStat(filePath)?.mtimeMs);
}

function readCapped(filePath, maxBytes) {
  const st = safeStat(filePath);
  if (!st?.isFile() || st.size > maxBytes) return null;
  try { return fs.readFileSync(filePath, "utf8"); } catch { return null; }
}

function sectionKind(name) {
  const normalized = String(name || "").toLowerCase();
  if (normalized.startsWith("projects.")) return "project_trust_config";
  if (normalized.startsWith("mcp_servers.")) return "mcp_server_config";
  if (normalized.startsWith("plugins.")) return "plugin_config";
  return "cli_settings";
}

function extractCodexConfigRows(codexRoot, attribution = {}) {
  const filePath = path.join(codexRoot, "config.toml");
  const text = readCapped(filePath, MAX_CODEX_CONFIG_BYTES);
  if (text == null) return [];
  const sections = parseTomlSafe(text);
  const rows = [];
  for (const [section, values] of Object.entries(sections)) {
    if (section === "global" && !Object.keys(values).length) continue;
    const recordType = sectionKind(section);
    const label = recordType === "project_trust_config" ? "project trust"
      : recordType === "mcp_server_config" ? "MCP server"
        : recordType === "plugin_config" ? "plugin" : "settings";
    const identity = section === "global" ? "global" : section.split(".").slice(1).join(".").replace(/^['"]|['"]$/g, "");
    rows.push(row({
      timestamp: fileTime(filePath),
      timestampBasis: "config.toml mtime",
      role: "metadata",
      recordType,
      summary: `Codex ${label} — ${identity}`,
      fullText: JSON.stringify({ section, values, sensitiveValuesCopied: false }, null, 2),
      toolName: recordType === "mcp_server_config" ? identity : "",
      toolCommand: recordType === "mcp_server_config" ? String(values.command || "") : "",
      toolDescription: "Codex configuration with secret-like values redacted. Environment/header names can remain, but values are not retained. Configuration does not prove execution.",
      messageId: `config:${section}`,
      workspace: recordType === "project_trust_config" ? identity : "",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function classifyCodexContextFile(codexRoot, filePath) {
  const rel = path.relative(codexRoot, filePath).replace(/\\/g, "/");
  const base = path.basename(filePath);
  if (rel === "config.toml") return null;
  if (base === "auth.json" || /(?:^|\/)(?:credentials?|tokens?|secrets?)(?:\/|\.|$)/i.test(rel)) return {
    family: "credential-store",
    recordType: "credential_inventory",
    summaryLabel: "Codex credential store",
    credentialExcluded: true,
    toolDescription: "Credential store inventoried by path, size, and mtime. Contents are never read or hashed.",
  };
  if (base === "AGENTS.md" || base === "instructions.md") return {
    family: "instruction",
    recordType: "instruction_inventory",
    summaryLabel: "Codex instruction context",
  };
  if (base === "SKILL.md" || rel.startsWith("skills/")) return {
    family: "skill",
    recordType: "skill_inventory",
    summaryLabel: "Codex skill context",
  };
  if (rel.startsWith("plugins/") && /(?:plugin\.json|package\.json|\.md)$/i.test(base)) return {
    family: "plugin",
    recordType: "plugin_inventory",
    summaryLabel: "Codex plugin context",
  };
  return null;
}

function listCodexContextFiles(codexRoot, options = {}) {
  if (!safeStat(codexRoot)?.isDirectory()) return { files: [], stats: { eligible: 0, selected: 0, omitted: 0 } };
  return walkContextFiles(codexRoot, {
    maxDepth: 12,
    maxFiles: options.maxCodexContextFiles || 10000,
    checkAbort: options.checkAbort,
    accept: (p) => !!classifyCodexContextFile(codexRoot, p),
    skipDir: (p) => /(?:^|[\\/])(?:sessions|archived_sessions|shell_snapshots|memories|logs?|cache|tmp)(?:[\\/]|$)/i.test(p),
  });
}

function extractInstructionRows(codexRoot, attribution = {}, files = null, checkAbort = () => {}) {
  const rows = [];
  const instructionFiles = (files || listCodexContextFiles(codexRoot).files)
    .filter((p) => /(?:AGENTS|instructions)\.md$/i.test(path.basename(p)));
  for (const filePath of instructionFiles) {
    checkAbort();
    const text = readCapped(filePath, MAX_CODEX_INSTRUCTION_BYTES);
    if (text == null) continue;
    rows.push(row({
      timestamp: fileTime(filePath),
      timestampBasis: "instruction file mtime",
      role: "metadata",
      recordType: "instruction_context",
      summary: `Codex instruction context — ${path.relative(codexRoot, filePath)}`,
      fullText: text,
      messageId: path.relative(codexRoot, filePath),
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function extractCodexContext(codexRoot, attribution = {}, options = {}) {
  const configRows = extractCodexConfigRows(codexRoot, attribution);
  const listed = listCodexContextFiles(codexRoot, options);
  const instructionRows = extractInstructionRows(codexRoot, attribution, listed.files, options.checkAbort);
  const inventory = inventoryContextFiles({
    tool: TOOL_CODEX,
    rootPath: codexRoot,
    files: listed.files.filter((p) => !/(?:AGENTS|instructions)\.md$/i.test(path.basename(p))),
    attribution,
    checkAbort: options.checkAbort,
    classify: (p) => classifyCodexContextFile(codexRoot, p),
  });
  return {
    rows: [...configRows, ...instructionRows, ...inventory.rows],
    stats: {
      configRows: configRows.length,
      instructionRows: instructionRows.length,
      ...inventory.stats,
      eligible: listed.stats.eligible,
      selected: listed.stats.selected,
      omitted: listed.stats.omitted,
    },
  };
}

module.exports = {
  sectionKind,
  extractCodexConfigRows,
  classifyCodexContextFile,
  listCodexContextFiles,
  extractInstructionRows,
  extractCodexContext,
};
