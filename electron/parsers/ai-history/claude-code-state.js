/**
 * claude-code-state.js — ~/.claude.json workspace inventory and its timestamped backups.
 *
 * The file sits NEXT TO ~/.claude, not inside it. Per project it records lastSessionId,
 * lastStartTime, lastCost, trust-dialog acceptance, allowedTools, and MCP servers — the best
 * workspace inventory Claude Code writes, and the one the session JSONL extract previously
 * skipped. Global fields cover first-run time, startup count, Remote Control use, and the
 * signed-in account (identifiers only).
 *
 * OAuth / API tokens are never copied into a row. MCP environment VALUES are never emitted;
 * names are listed so an examiner can see which secrets the process expected.
 *
 * Backups (~/.claude.json.backup, ~/.claude.json.backup.<epoch_ms>) are inventoried from the
 * SAME directory as the file being read (no walk-up). A project that exists only in a backup
 * is emitted as project_removed — evidence a workspace was forgotten after the backup was taken.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { TOOL_CLAUDE_CODE } = require("./schema");
const { formatTimestampUtc, parseIsoTimestamp, makeRow } = require("./row-utils");

const CLAUDE_JSON_NAME = ".claude.json";
const MAX_CLAUDE_JSON_BYTES = 8 * 1024 * 1024;
const MAX_PROJECTS = 4000;
const CURRENT_KIND = "current";
const BACKUP_KIND = "backup";

function claudeRow(fields) {
  return makeRow({ ...fields, tool: fields.tool || TOOL_CLAUDE_CODE }, TOOL_CLAUDE_CODE);
}

function safeStat(p) {
  try { return fs.statSync(p); } catch { return null; }
}

/** Classify a basename: current file, timestamped/plain backup, or not a Claude JSON state file. */
function claudeJsonFileKind(filePath) {
  const base = path.basename(filePath || "");
  if (!base || /\.tmp\./i.test(base)) return null;
  if (base === CLAUDE_JSON_NAME) return CURRENT_KIND;
  if (base === `${CLAUDE_JSON_NAME}.backup`) return BACKUP_KIND;
  if (/^\.claude\.json\.backup\.\d{10,}$/.test(base)) return BACKUP_KIND;
  return null;
}

function backupEpochMs(filePath) {
  const m = /^\.claude\.json\.backup\.(\d{10,})$/.exec(path.basename(filePath || ""));
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n)) return null;
  return n > 1e12 ? n : (n > 1e9 ? n * 1000 : null);
}

function isClaudeJsonStateFile(filePath) {
  if (!filePath || !claudeJsonFileKind(filePath)) return false;
  const st = safeStat(filePath);
  if (!st || !st.isFile() || st.size < 2 || st.size > MAX_CLAUDE_JSON_BYTES) return false;
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(64);
    const n = fs.readSync(fd, buf, 0, 64, 0);
    const start = buf.slice(0, n).toString("utf8").trimStart();
    return start.startsWith("{");
  } catch {
    return false;
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* ignore */ } }
  }
}

function readClaudeJson(filePath) {
  const st = safeStat(filePath);
  if (!st || !st.isFile() || st.size > MAX_CLAUDE_JSON_BYTES) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed;
  } catch (e) {
    dbg("AIHIST", "claude.json parse failed", { path: filePath, err: e.message });
    return null;
  }
}

function looksLikeClaudeJson(obj) {
  if (!obj || typeof obj !== "object") return false;
  return obj.projects != null
    || obj.firstStartTime != null
    || obj.numStartups != null
    || obj.mcpServers != null
    || obj.oauthAccount != null;
}

function timestampFrom(value, fallbackMs) {
  if (value == null || value === "") {
    return fallbackMs != null ? fallbackMs : null;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 1e12 ? value : (value > 1e9 ? value * 1000 : null);
  }
  return parseIsoTimestamp(value);
}

function mcpServerRows(servers, filePath, timestamp, attribution, workspace) {
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) return [];
  const rows = [];
  for (const [name, def] of Object.entries(servers)) {
    if (!def || typeof def !== "object") continue;
    const command = def.command != null ? String(def.command) : "";
    const args = Array.isArray(def.args) ? def.args.map((a) => String(a)) : [];
    const url = def.url != null ? String(def.url) : "";
    const envKeys = def.env && typeof def.env === "object" ? Object.keys(def.env) : [];
    const commandLine = [command, ...args].filter(Boolean).join(" ");
    rows.push(claudeRow({
      timestamp,
      role: "metadata",
      recordType: "mcp_server_config",
      summary: `MCP server configured — ${name}: ${commandLine || url || "(no command)"}`
        + `${def.disabled === true ? " [disabled]" : ""}`,
      fullText: JSON.stringify({
        name,
        command,
        args,
        url,
        type: def.type || def.transport || "",
        disabled: def.disabled === true,
        envKeys,
        envValuesRedacted: envKeys.length > 0,
        workspace: workspace || "",
      }, null, 2),
      toolName: name,
      toolCommand: commandLine,
      toolInput: JSON.stringify({ command, args, url }),
      workspace: workspace || "",
      toolDescription: "A process Claude Code launches (or an endpoint it connects to) as an MCP "
        + "server. Environment variable names are listed; their values are never read into the row.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function accountIdentity(oauth) {
  if (!oauth || typeof oauth !== "object") return null;
  const pick = (k) => (oauth[k] != null && oauth[k] !== "" ? oauth[k] : undefined);
  const out = {};
  for (const k of [
    "emailAddress", "accountUuid", "organizationUuid", "organizationName",
    "organizationType", "organizationRole", "workspaceRole", "billingType",
    "seatTier", "displayName", "accountCreatedAt", "subscriptionCreatedAt",
    "profileFetchedAt",
  ]) {
    if (pick(k) !== undefined) out[k] = pick(k);
  }
  return Object.keys(out).length ? out : null;
}

function projectEntries(projects) {
  if (!projects || typeof projects !== "object" || Array.isArray(projects)) return [];
  return Object.entries(projects).slice(0, MAX_PROJECTS);
}

function collectFromObject(obj, filePath, attribution, { kind, siblingCurrentProjects } = {}) {
  const rows = [];
  const st = safeStat(filePath);
  const fileMtime = st ? st.mtimeMs : null;
  const backupMs = backupEpochMs(filePath);
  const fileTs = formatTimestampUtc(backupMs || fileMtime);
  const fileTimeSource = backupMs != null
    ? "backup filename epoch"
    : "file mtime";

  const currentSet = siblingCurrentProjects instanceof Set ? siblingCurrentProjects : null;
  const backupAgainstCurrent = kind === BACKUP_KIND && currentSet != null;

  const identity = accountIdentity(obj.oauthAccount);
  const firstStartMs = timestampFrom(obj.firstStartTime, null);
  const identityTs = formatTimestampUtc(
    timestampFrom(identity?.profileFetchedAt, null)
      ?? firstStartMs
      ?? fileMtime,
  );
  const identityTimeSource = identity?.profileFetchedAt
    ? "oauthAccount.profileFetchedAt"
    : (firstStartMs != null ? "firstStartTime" : fileTimeSource);

  const identityBody = {
    kind,
    firstStartTime: obj.firstStartTime || "",
    numStartups: obj.numStartups ?? null,
    installMethod: obj.installMethod || "",
    lastReleaseNotesSeen: obj.lastReleaseNotesSeen || "",
    lastOnboardingVersion: obj.lastOnboardingVersion || "",
    hasUsedRemoteControl: obj.hasUsedRemoteControl === true,
    userID: obj.userID != null ? String(obj.userID) : "",
    machineID: obj.machineID != null ? String(obj.machineID) : "",
    projectCount: projectEntries(obj.projects).length,
    timeSource: identityTimeSource,
    account: identity,
  };
  const email = identity?.emailAddress ? ` (${identity.emailAddress})` : "";
  if (!backupAgainstCurrent) rows.push(claudeRow({
    timestamp: identityTs,
    role: "metadata",
    recordType: "cli_identity",
    summary: `Claude Code CLI identity${email} — ${obj.numStartups ?? 0} startup(s)`
      + `${obj.hasUsedRemoteControl === true ? ", Remote Control used" : ""}`
      + `${kind === BACKUP_KIND ? " [backup]" : ""}`,
    fullText: JSON.stringify(identityBody, null, 2),
    toolDescription: "Signed-in account identifiers, install method, and first-start time from "
      + `${path.basename(filePath)}. Token-shaped keys in oauthAccount are dropped.`,
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  }));

  if (!backupAgainstCurrent && obj.hasUsedRemoteControl === true) {
    rows.push(claudeRow({
      timestamp: identityTs,
      role: "metadata",
      recordType: "remote_control_used",
      summary: "Claude Code has used Remote Control on this machine",
      fullText: JSON.stringify({
        hasUsedRemoteControl: true,
        timeSource: identityTimeSource,
      }, null, 2),
      toolDescription: "Boolean flag in ~/.claude.json. It proves Remote Control was used at least "
        + "once; it is not a per-session audit log.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  if (!backupAgainstCurrent && obj.skillUsage && typeof obj.skillUsage === "object" && !Array.isArray(obj.skillUsage)) {
    const skills = Object.entries(obj.skillUsage).map(([name, count]) => ({ name, count }));
    rows.push(claudeRow({
      timestamp: fileTs,
      role: "metadata",
      recordType: "skill_usage",
      summary: `Claude Code skill usage — ${skills.length} skill(s)`,
      fullText: JSON.stringify({ skills, timeSource: fileTimeSource }, null, 2),
      toolDescription: "Lifetime skill invocation counts recorded in ~/.claude.json.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  if (!backupAgainstCurrent && obj.toolUsage && typeof obj.toolUsage === "object" && !Array.isArray(obj.toolUsage)) {
    const tools = Object.entries(obj.toolUsage).map(([name, count]) => ({ name, count }));
    rows.push(claudeRow({
      timestamp: fileTs,
      role: "metadata",
      recordType: "tool_usage",
      summary: `Claude Code tool usage — ${tools.map((t) => t.name).join(", ")}`,
      fullText: JSON.stringify({ tools, timeSource: fileTimeSource }, null, 2),
      toolDescription: "Lifetime tool invocation counts recorded in ~/.claude.json.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  if (!backupAgainstCurrent && obj.githubRepoPaths && typeof obj.githubRepoPaths === "object" && !Array.isArray(obj.githubRepoPaths)) {
    const repos = Object.entries(obj.githubRepoPaths).map(([repo, localPath]) => ({
      repo,
      path: typeof localPath === "string" ? localPath : "",
    }));
    if (repos.length) {
      rows.push(claudeRow({
        timestamp: fileTs,
        role: "metadata",
        recordType: "github_repo_paths",
        summary: `Claude Code GitHub repo mappings — ${repos.map((r) => r.repo).join(", ")}`,
        fullText: JSON.stringify({ repos, timeSource: fileTimeSource }, null, 2),
        workspace: repos[0].path || "",
        toolDescription: "Repos Claude Code associated with a local path.",
        sourceFile: filePath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }
  }

  if (!backupAgainstCurrent) {
    rows.push(...mcpServerRows(obj.mcpServers, filePath, fileTs, attribution, ""));
  }

  let projectCount = 0;
  for (const [workspace, meta] of projectEntries(obj.projects)) {
    if (!workspace || !meta || typeof meta !== "object") continue;
    projectCount += 1;
    const startMs = timestampFrom(meta.lastStartTime, fileMtime);
    const timestamp = formatTimestampUtc(startMs);
    const timeSource = meta.lastStartTime != null ? "projects[].lastStartTime" : fileTimeSource;
    const allowedTools = Array.isArray(meta.allowedTools)
      ? meta.allowedTools.map((t) => String(t)).filter(Boolean)
      : [];
    const enabledMcp = Array.isArray(meta.enabledMcpjsonServers)
      ? meta.enabledMcpjsonServers.map(String)
      : [];
    const disabledMcp = Array.isArray(meta.disabledMcpjsonServers)
      ? meta.disabledMcpjsonServers.map(String)
      : [];
    const trusted = meta.hasTrustDialogAccepted === true;
    const removed = currentSet != null && !currentSet.has(workspace);
    if (currentSet && !removed) continue;
    const recordType = removed ? "project_removed" : "project_state";
    const cost = meta.lastCost != null ? meta.lastCost : null;
    const sessionId = meta.lastSessionId != null ? String(meta.lastSessionId) : "";
    const summaryBits = [
      removed ? "Claude Code project removed since backup" : "Claude Code project",
      workspace,
      sessionId ? `last session ${sessionId}` : null,
      `trust ${trusted ? "accepted" : "not accepted"}`,
      cost != null && Number(cost) > 0 ? `last cost ${cost}` : null,
    ].filter(Boolean);
    rows.push(claudeRow({
      timestamp,
      role: "metadata",
      recordType,
      summary: summaryBits.join(" — "),
      fullText: JSON.stringify({
        workspace,
        lastSessionId: sessionId,
        lastStartTime: meta.lastStartTime ?? null,
        lastCost: cost,
        lastDuration: meta.lastDuration ?? null,
        lastLinesAdded: meta.lastLinesAdded ?? null,
        lastLinesRemoved: meta.lastLinesRemoved ?? null,
        lastVersionBase: meta.lastVersionBase || "",
        lastGracefulShutdown: meta.lastGracefulShutdown ?? null,
        hasTrustDialogAccepted: trusted,
        hasClaudeMdExternalIncludesApproved: meta.hasClaudeMdExternalIncludesApproved === true,
        allowedTools,
        enabledMcpjsonServers: enabledMcp,
        disabledMcpjsonServers: disabledMcp,
        timeSource,
        kind,
      }, null, 2),
      sessionId,
      workspace,
      toolDescription: removed
        ? "This workspace was present in a ~/.claude.json backup and is absent from the current file."
        : "Per-project inventory from ~/.claude.json: last session, cost, trust, and allowed tools. "
          + "Dated from lastStartTime when present.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
    rows.push(...mcpServerRows(meta.mcpServers, filePath, timestamp, attribution, workspace));
  }

  if (kind === BACKUP_KIND && currentSet) {
    rows.push(claudeRow({
      timestamp: fileTs,
      role: "metadata",
      recordType: "claude_json_backup",
      summary: `Claude Code ~/.claude.json backup — ${projectCount} project(s)`,
      fullText: JSON.stringify({
        backupFile: path.basename(filePath),
        sizeBytes: st ? st.size : null,
        projectCount,
        timeSource: fileTimeSource,
      }, null, 2),
      toolDescription: "A timestamped copy of ~/.claude.json. Projects that later disappeared are "
        + "emitted separately as project_removed.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  return rows;
}

/** State files in the same directory as `filePath` (no parent walk). */
function listSiblingClaudeJsonFiles(filePath) {
  const dir = path.dirname(filePath);
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
  const out = [];
  for (const e of entries) {
    if (!e.isFile()) continue;
    const full = path.join(dir, e.name);
    if (isClaudeJsonStateFile(full)) out.push(full);
  }
  return out;
}

function countClaudeJsonExtractFiles(filePath) {
  if (!isClaudeJsonStateFile(filePath)) return 0;
  if (claudeJsonFileKind(filePath) !== CURRENT_KIND) return 1;
  return listSiblingClaudeJsonFiles(filePath).length || 1;
}

/**
 * Extract timeline rows from a ~/.claude.json (or backup) file.
 * When the target is the current file, sibling backups in the same folder are inventoried too.
 */
function extractClaudeJsonFile(filePath, attribution = {}, options = {}) {
  if (!isClaudeJsonStateFile(filePath)) return [];
  const obj = readClaudeJson(filePath);
  if (!obj || !looksLikeClaudeJson(obj)) return [];

  const kind = claudeJsonFileKind(filePath);
  const rows = collectFromObject(obj, filePath, attribution, { kind });

  if (kind === CURRENT_KIND) {
    const currentProjects = new Set(projectEntries(obj.projects).map(([p]) => p));
    for (const sibling of listSiblingClaudeJsonFiles(filePath)) {
      if (path.resolve(sibling) === path.resolve(filePath)) continue;
      if (claudeJsonFileKind(sibling) !== BACKUP_KIND) continue;
      const backup = readClaudeJson(sibling);
      if (!backup || !looksLikeClaudeJson(backup)) continue;
      rows.push(...collectFromObject(backup, sibling, attribution, {
        kind: BACKUP_KIND,
        siblingCurrentProjects: currentProjects,
      }));
    }
  }

  if (options.onExtractedRows && rows.length) {
    options.onExtractedRows(rows);
    return [];
  }
  return rows;
}

module.exports = {
  CLAUDE_JSON_NAME,
  MAX_CLAUDE_JSON_BYTES,
  claudeJsonFileKind,
  isClaudeJsonStateFile,
  listSiblingClaudeJsonFiles,
  countClaudeJsonExtractFiles,
  extractClaudeJsonFile,
  readClaudeJson,
};
