/**
 * claude-desktop-state.js — Claude Desktop state artifacts that outlive the conversations.
 *
 * `claude-desktop.js` reconstructs sessions from `local_<uuid>.json` metadata and the transcripts
 * they point at. The stores below sit beside those files and answer questions the transcripts
 * cannot, precisely because they persist after a conversation is removed:
 *
 *   deleted_<session-uuid>           under claude-code-sessions: a 13-byte file whose entire
 *                                    content is the epoch-ms DELETION TIME, named for the session
 *                                    it replaced. Dated proof a conversation existed and was removed.
 *   pending-uploads/<uuid>-<epoch_ms>_<name>         files staged for upload — what the user
 *                                    attached or pasted into a conversation, retained on disk
 *                                    independently of it.
 *   plan-usage-history.json          dense usage samples (~5 min apart) with an org id: an
 *                                    "application in use" timeline that survives session deletion.
 *   scheduled-tasks.json             scheduled/automated agent runs, at any depth below the root.
 *   git-worktrees.json               working directories with last-seen timestamps.
 *   bridge-state.json                Remote Control bridge: which local session is linked to which
 *                                    claude.ai remote session, whether the bridge is enabled and
 *                                    whether the user consented. No timestamp of its own.
 *   claude_desktop_config.json       `preferences.localAgentModeTrustedFolders` (folders Cowork may
 *                                    act in without asking), `remoteSessionFolderGrants` (folders a
 *                                    REMOTE session was granted), `remoteFolderConsentMemory`,
 *                                    `coworkUserFilesPath`, the security-relevant Cowork toggles,
 *                                    and `mcpServers` (also read from config.json) — the commands
 *                                    the desktop app launches as MCP servers.
 *
 * Measured on Claude Desktop (claude-code 2.1.229): 2 tombstones against 5 live sessions, 84
 * staged attachments totalling 58.7 MB spanning six months, and 5,189 usage samples across a month.
 *
 * Attachment CONTENT is never read. These rows are an inventory — path, size, recorded time — for
 * the same reason tracked files are inventory-only elsewhere: the bytes are evidence to preserve,
 * not text to sweep into a timeline.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { TOOL_CLAUDE_CODE } = require("./schema");
const { formatTimestampUtc, makeRow } = require("./row-utils");

const DELETED_SESSION_RE = /^deleted_([0-9a-f-]{8,})$/i;
const PENDING_UPLOADS_DIR = "pending-uploads";
/** `<uuid>-<13-digit epoch ms>_<original name>` */
const PENDING_UPLOAD_RE = /^(.+?)-(\d{13})_(.+)$/;
const PLAN_USAGE_FILE = "plan-usage-history.json";
const SCHEDULED_TASKS_FILE = "scheduled-tasks.json";
const WORKTREES_FILE = "git-worktrees.json";
const BRIDGE_STATE_FILE = "bridge-state.json";
const DESKTOP_CONFIG_FILE = "claude_desktop_config.json";
const APP_CONFIG_FILE = "config.json";
const MAX_SCAN_DEPTH = 8;
/** Cowork preference keys that change what the agent is allowed to do. Others are UI state. */
const COWORK_SECURITY_PREF_KEYS = [
  "coworkBrowserToolsEnabled",
  "coworkPreferredBrowser",
  "coworkWebSearchEnabled",
  "coworkScheduledTasksEnabled",
  "ccdScheduledTasksEnabled",
  "bypassPermissionsGateByAccount",
  "coworkModelAutoFallbackByAccount",
  "coworkHipaaRestricted",
  "orgWorkAcrossAppsDisabled",
  "remoteToolsDeviceName",
  "keepAwakeEnabled",
  "sidebarMode",
];

/**
 * Gap that splits one run of usage samples from the next. Samples land roughly every five minutes
 * while the app is open, so anything beyond half an hour is a separate period of use rather than a
 * pause within one.
 */
const USAGE_SESSION_GAP_MS = 30 * 60 * 1000;

function desktopRow(fields) {
  return makeRow({ ...fields, tool: TOOL_CLAUDE_CODE }, TOOL_CLAUDE_CODE);
}

function safeStat(p) {
  try { return fs.statSync(p); } catch { return null; }
}

/** Bounded walk that collects files matching `match`, staying inside `rootDir`. */
function walkFiles(rootDir, match, maxDepth = MAX_SCAN_DEPTH) {
  const out = [];
  const queue = [{ dir: rootDir, depth: 0 }];
  while (queue.length) {
    const { dir, depth } = queue.shift();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (depth < maxDepth) queue.push({ dir: full, depth: depth + 1 });
      } else if (match(e.name, full)) {
        out.push(full);
      }
    }
  }
  return out;
}

/* --------------------------------------------------- deleted-session tombstones */

/**
 * Dated evidence that a conversation was deleted.
 *
 * The file is named for the session it replaced and contains nothing but an epoch-ms stamp, so both
 * halves of the finding — which session, and when it went — come from the artifact itself and need
 * no inference. The row is timestamped at the DELETION, because that is the event it records; the
 * conversation's own activity time is not recoverable from this file.
 */
function collectDeletedSessions(rootDir, attribution = {}) {
  const files = walkFiles(rootDir, (name) => DELETED_SESSION_RE.test(name));
  const rows = [];
  for (const filePath of files) {
    const sessionId = path.basename(filePath).match(DELETED_SESSION_RE)?.[1] || "";
    let raw = "";
    try { raw = fs.readFileSync(filePath, "utf8").trim(); } catch { continue; }

    const stamp = Number(raw);
    const deletedMs = Number.isFinite(stamp) && stamp > 1e12 ? stamp : null;
    const st = safeStat(filePath);
    // Fall back to mtime only when the content is not a usable stamp, and say which was used.
    const timestampMs = deletedMs ?? (st ? st.mtimeMs : null);

    rows.push(desktopRow({
      timestamp: formatTimestampUtc(timestampMs),
      role: "metadata",
      recordType: "session_deleted",
      summary: `Conversation deleted — session ${sessionId}`,
      fullText: JSON.stringify({
        sessionId,
        deletedAt: formatTimestampUtc(timestampMs),
        rawValue: raw,
        timeSource: deletedMs != null ? "file content (epoch ms)" : "file mtime (content unusable)",
        tombstonePath: filePath,
      }, null, 2),
      sessionId,
      toolDescription: "DELETION EVIDENCE: a tombstone left where a conversation was removed. The "
        + "filename carries the deleted session id and the file content is the deletion time. "
        + "It proves the conversation existed and when it was deleted — it does not recover its "
        + "content, and this row's timestamp is the deletion, not the conversation's activity.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/* ------------------------------------------------------------- pending uploads */

/**
 * Files staged for upload to the model — inventory only, never content.
 *
 * These are what the user attached or pasted into a conversation. They persist independently of the
 * conversation, so they can evidence that a document or screenshot was sent to the assistant long
 * after the chat itself is gone. On a data-loss question this is the material half of the answer.
 */
function collectPendingUploads(rootDir, attribution = {}) {
  const dir = path.join(rootDir, PENDING_UPLOADS_DIR);
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }

  const rows = [];
  for (const e of entries) {
    if (!e.isFile() || e.name.startsWith(".")) continue;
    const filePath = path.join(dir, e.name);
    const st = safeStat(filePath);
    const m = e.name.match(PENDING_UPLOAD_RE);
    const stagedMs = m ? Number(m[2]) : null;
    const originalName = m ? m[3] : e.name;
    const attachmentId = m ? m[1] : "";

    rows.push(desktopRow({
      timestamp: formatTimestampUtc(
        Number.isFinite(stagedMs) ? stagedMs : (st ? st.mtimeMs : null),
      ),
      role: "attachment",
      recordType: "pending_upload",
      summary: `Attachment staged for upload — ${originalName}`
        + `${st ? ` (${st.size.toLocaleString()} bytes)` : ""}`,
      fullText: JSON.stringify({
        originalName,
        attachmentId,
        stagedAt: formatTimestampUtc(stagedMs),
        sizeBytes: st ? st.size : null,
        path: filePath,
      }, null, 2),
      messageId: attachmentId,
      toolDescription: "INVENTORY ONLY — file content is not read. A file staged for upload to the "
        + "assistant, retained independently of the conversation it belonged to. Preserve the "
        + "bytes separately; the timestamp is the staging time parsed from the filename.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/* ------------------------------------------------------------ plan usage history */

/**
 * Periods during which the application was in use, derived from the usage sample stream.
 *
 * One row per sample would be thousands of near-identical entries; the evidence is not any single
 * sample but the CONTIGUOUS RUN they form. Runs are split on a gap wider than the sampling interval
 * (see USAGE_SESSION_GAP_MS) and labelled as derived, because a run is an inference from sample
 * spacing rather than a recorded session boundary.
 */
function collectPlanUsageWindows(rootDir, attribution = {}) {
  const filePath = path.join(rootDir, PLAN_USAGE_FILE);
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { return []; }

  const samples = Array.isArray(parsed?.samples) ? parsed.samples : [];
  const stamped = samples
    .map((s) => ({ t: Number(s?.t), org: String(s?.org || "") }))
    .filter((s) => Number.isFinite(s.t) && s.t > 1e12)
    .sort((a, b) => a.t - b.t);
  if (!stamped.length) return [];

  const runs = [];
  let cur = { start: stamped[0].t, end: stamped[0].t, count: 1, org: stamped[0].org };
  for (let i = 1; i < stamped.length; i++) {
    const s = stamped[i];
    if (s.t - cur.end > USAGE_SESSION_GAP_MS) {
      runs.push(cur);
      cur = { start: s.t, end: s.t, count: 1, org: s.org };
    } else {
      cur.end = s.t;
      cur.count += 1;
      if (!cur.org) cur.org = s.org;
    }
  }
  runs.push(cur);

  return runs.map((run) => {
    const minutes = Math.round((run.end - run.start) / 60000);
    return desktopRow({
      timestamp: formatTimestampUtc(run.start),
      role: "metadata",
      recordType: "app_usage_window",
      summary: `Claude Desktop in use for ~${minutes} min (${run.count} usage samples)`,
      fullText: JSON.stringify({
        startedAt: formatTimestampUtc(run.start),
        endedAt: formatTimestampUtc(run.end),
        approxMinutes: minutes,
        sampleCount: run.count,
        org: run.org,
        gapThresholdMinutes: USAGE_SESSION_GAP_MS / 60000,
      }, null, 2),
      sessionId: run.org,
      toolDescription: "DERIVED from usage-sample spacing, not a recorded session boundary. It "
        + "evidences that the application was open and in use across this span, and survives "
        + "deletion of the conversations that happened during it.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

/* ------------------------------------------- scheduled tasks and worktree access */

function collectScheduledTasks(rootDir, attribution = {}) {
  const files = walkFiles(rootDir, (name) => name === SCHEDULED_TASKS_FILE);
  const rows = [];
  for (const filePath of files) {
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { continue; }
    const tasks = Array.isArray(parsed?.scheduledTasks) ? parsed.scheduledTasks : [];
    if (!tasks.length) continue; // an empty schedule is not evidence

    const st = safeStat(filePath);
    for (const task of tasks) {
      rows.push(desktopRow({
        timestamp: formatTimestampUtc(
          Number(task?.nextRunAt) || Number(task?.createdAt) || (st ? st.mtimeMs : null),
        ),
        role: "metadata",
        recordType: "scheduled_task",
        summary: `Scheduled agent task — ${String(task?.name || task?.id || "(unnamed)")}`,
        fullText: JSON.stringify(task, null, 2),
        sessionId: String(task?.sessionId || task?.id || ""),
        toolDescription: "An agent run configured to fire without further user interaction. "
          + "Treat as an automation/persistence surface.",
        sourceFile: filePath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }
  }
  return rows;
}

function collectWorktreeAccess(rootDir, attribution = {}) {
  const filePath = path.join(rootDir, WORKTREES_FILE);
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { return []; }

  const cwds = parsed?.untrackedDirGc?.cwds;
  if (!cwds || typeof cwds !== "object") return [];

  const rows = [];
  for (const [dir, seen] of Object.entries(cwds)) {
    const ms = Number(seen);
    rows.push(desktopRow({
      timestamp: formatTimestampUtc(Number.isFinite(ms) && ms > 1e12 ? ms : null),
      role: "metadata",
      recordType: "workspace_seen",
      summary: `Workspace last seen — ${dir}`,
      fullText: JSON.stringify({ workspace: dir, lastSeenAt: formatTimestampUtc(ms) }, null, 2),
      workspace: dir,
      toolDescription: "Working directory the desktop app last observed, with its timestamp. "
        + "Places a workspace on the timeline even when no transcript for it survives.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/* -------------------------------------------------- remote control bridge state */

function readJsonFile(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { return null; }
}

/**
 * Remote Control bridge entries.
 *
 * Each key is `<id>:<id>` (account and organization scope) and maps a LOCAL desktop session to the
 * REMOTE claude.ai session that can drive it. The file carries no timestamp, so the row is dated
 * from its mtime and says so; what it proves is the pairing and the consent flag, not when the
 * bridge was used.
 */
function collectRemoteBridgeState(rootDir, attribution = {}) {
  const filePath = path.join(rootDir, BRIDGE_STATE_FILE);
  const parsed = readJsonFile(filePath);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return [];
  const st = safeStat(filePath);
  const timestamp = formatTimestampUtc(st ? st.mtimeMs : null);

  const rows = [];
  for (const [scopeKey, entry] of Object.entries(parsed)) {
    if (!entry || typeof entry !== "object") continue;
    const enabled = entry.enabled === true;
    const consented = entry.userConsented === true;
    const localSessionId = String(entry.localSessionId || "");
    const remoteSessionId = String(entry.remoteSessionId || "");
    const processed = Array.isArray(entry.processedMessageUuids) ? entry.processedMessageUuids.length : 0;
    const pending = Array.isArray(entry.pendingProcessedAcks) ? entry.pendingProcessedAcks.length : 0;
    rows.push(desktopRow({
      timestamp,
      role: "metadata",
      recordType: "remote_control_bridge",
      summary: `Remote Control bridge ${enabled ? "ENABLED" : "disabled"}`
        + `${consented ? ", user consented" : ", no user consent recorded"}`
        + ` — local session ${localSessionId || "?"} ↔ remote session ${remoteSessionId || "?"}`
        + `${processed ? `; ${processed} remote message(s) processed` : ""}`,
      fullText: JSON.stringify({
        scopeKey,
        scopeIds: scopeKey.split(":"),
        enabled,
        userConsented: consented,
        environmentId: entry.environmentId || "",
        localSessionId,
        remoteSessionId,
        processedMessageCount: processed,
        pendingAckCount: pending,
        timeSource: "bridge-state.json mtime (the file records no timestamp)",
      }, null, 2),
      sessionId: localSessionId,
      messageId: remoteSessionId,
      toolDescription: "Links a local Claude Desktop session to a claude.ai Remote Control session so "
        + "a phone or web client can drive this machine. Configuration state: Timestamp is the "
        + "file's modification time, not a use of the bridge.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/* ---------------------------------------------- desktop config: trust + MCP */

function asStringList(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((v) => (typeof v === "string" ? v : (v && typeof v === "object" ? String(v.path || v.folder || "") : "")))
    .map((v) => v.trim())
    .filter(Boolean);
}

/** MCP server definitions → rows. Environment VALUES are never emitted — they routinely hold API keys. */
function mcpServerRows(servers, filePath, timestamp, attribution) {
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) return [];
  const rows = [];
  for (const [name, def] of Object.entries(servers)) {
    if (!def || typeof def !== "object") continue;
    const command = def.command != null ? String(def.command) : "";
    const args = Array.isArray(def.args) ? def.args.map((a) => String(a)) : [];
    const url = def.url != null ? String(def.url) : "";
    const envKeys = def.env && typeof def.env === "object" ? Object.keys(def.env) : [];
    const commandLine = [command, ...args].filter(Boolean).join(" ");
    rows.push(desktopRow({
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
      }, null, 2),
      toolName: name,
      toolCommand: commandLine,
      toolInput: JSON.stringify({ command, args, url }),
      toolDescription: "A process the desktop app launches (or an endpoint it connects to) as an MCP "
        + "server, whose tools become callable by Claude. Execution-persistence and supply-chain "
        + "surface. Environment variable names are listed; their values are never read into the row.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/**
 * Trust and permission state from claude_desktop_config.json, plus MCP servers from both config
 * files. All of it is configuration: rows are dated from the file mtime and never claim otherwise.
 */
function collectDesktopConfigState(rootDir, attribution = {}) {
  const rows = [];

  const cfgPath = path.join(rootDir, DESKTOP_CONFIG_FILE);
  const cfg = readJsonFile(cfgPath);
  if (cfg && typeof cfg === "object") {
    const st = safeStat(cfgPath);
    const timestamp = formatTimestampUtc(st ? st.mtimeMs : null);
    const prefs = cfg.preferences && typeof cfg.preferences === "object" ? cfg.preferences : {};

    for (const folder of asStringList(prefs.localAgentModeTrustedFolders)) {
      rows.push(desktopRow({
        timestamp,
        role: "metadata",
        recordType: "trusted_folder",
        summary: `Trusted folder (Cowork local agent mode) — ${folder}`,
        fullText: JSON.stringify({ folder, source: "preferences.localAgentModeTrustedFolders" }, null, 2),
        workspace: folder,
        toolDescription: "The user accepted the trust dialog for this folder: Cowork sessions may read "
          + "and write inside it without a further per-folder prompt. Dated from the config file's "
          + "mtime — the acceptance itself is not timestamped.",
        sourceFile: cfgPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }

    const grants = prefs.remoteSessionFolderGrants;
    if (grants && typeof grants === "object" && !Array.isArray(grants)) {
      for (const [sessionId, list] of Object.entries(grants)) {
        for (const folder of asStringList(list)) {
          rows.push(desktopRow({
            timestamp,
            role: "metadata",
            recordType: "remote_folder_grant",
            summary: `Remote session ${sessionId} granted folder — ${folder}`,
            fullText: JSON.stringify({ sessionId, folder, source: "preferences.remoteSessionFolderGrants" }, null, 2),
            sessionId,
            workspace: folder,
            toolDescription: "A folder on this machine that a REMOTE (claude.ai-driven) session was "
              + "granted access to. Pairs with remote_control_bridge rows.",
            sourceFile: cfgPath,
            user: attribution.user || "",
            host: attribution.host || "",
          }));
        }
      }
    }

    for (const folder of asStringList(prefs.remoteFolderConsentMemory)) {
      rows.push(desktopRow({
        timestamp,
        role: "metadata",
        recordType: "remote_folder_consent",
        summary: `Remote folder consent remembered — ${folder}`,
        fullText: JSON.stringify({ folder, source: "preferences.remoteFolderConsentMemory" }, null, 2),
        workspace: folder,
        toolDescription: "The user chose to remember consent for remote sessions to use this folder, "
          + "so later remote sessions were not asked again.",
        sourceFile: cfgPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }

    if (typeof cfg.coworkUserFilesPath === "string" && cfg.coworkUserFilesPath.trim()) {
      rows.push(desktopRow({
        timestamp,
        role: "metadata",
        recordType: "cowork_user_files_path",
        summary: `Cowork user files folder — ${cfg.coworkUserFilesPath}`,
        fullText: JSON.stringify({ path: cfg.coworkUserFilesPath }, null, 2),
        workspace: cfg.coworkUserFilesPath,
        toolDescription: "Where Cowork writes artifacts and scheduled-task output for the user to "
          + "browse. Collect it: files Claude created live there, outside the app-data tree.",
        sourceFile: cfgPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }

    const present = COWORK_SECURITY_PREF_KEYS.filter((k) => prefs[k] !== undefined);
    if (present.length) {
      const picked = Object.fromEntries(present.map((k) => [k, prefs[k]]));
      const onOff = (v) => (v === true ? "on" : v === false ? "off" : String(v ?? "unset"));
      const bypassAccounts = picked.bypassPermissionsGateByAccount && typeof picked.bypassPermissionsGateByAccount === "object"
        ? Object.entries(picked.bypassPermissionsGateByAccount).filter(([, v]) => v === true).map(([k]) => k)
        : [];
      rows.push(desktopRow({
        timestamp,
        role: "metadata",
        recordType: "cowork_preferences",
        summary: "Cowork preferences — "
          + `browser tools ${onOff(picked.coworkBrowserToolsEnabled)}`
          + `${picked.coworkPreferredBrowser ? ` (${picked.coworkPreferredBrowser})` : ""}, `
          + `web search ${onOff(picked.coworkWebSearchEnabled)}, `
          + `scheduled tasks ${onOff(picked.coworkScheduledTasksEnabled)}, `
          + `bypass-permissions gate on for ${bypassAccounts.length} account(s)`,
        fullText: JSON.stringify({ ...picked, bypassPermissionsAccounts: bypassAccounts }, null, 2),
        toolDescription: "Security-relevant Cowork toggles as of the config file's mtime. "
          + "bypassPermissionsGateByAccount=true means the account could run sessions with the "
          + "permission gate off.",
        sourceFile: cfgPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }

    rows.push(...mcpServerRows(cfg.mcpServers, cfgPath, timestamp, attribution));
  }

  const appCfgPath = path.join(rootDir, APP_CONFIG_FILE);
  const appCfg = readJsonFile(appCfgPath);
  if (appCfg && typeof appCfg === "object" && appCfg.mcpServers) {
    const st = safeStat(appCfgPath);
    rows.push(...mcpServerRows(appCfg.mcpServers, appCfgPath, formatTimestampUtc(st ? st.mtimeMs : null), attribution));
  }

  return rows;
}

/* ------------------------------------------------------------------ orchestration */

function countClaudeDesktopStateFiles(rootDir) {
  let n = 0;
  for (const f of [PLAN_USAGE_FILE, WORKTREES_FILE, BRIDGE_STATE_FILE, DESKTOP_CONFIG_FILE]) {
    if (fs.existsSync(path.join(rootDir, f))) n += 1;
  }
  if (fs.existsSync(path.join(rootDir, PENDING_UPLOADS_DIR))) n += 1;
  n += walkFiles(rootDir, (name) => DELETED_SESSION_RE.test(name) || name === SCHEDULED_TASKS_FILE).length;
  return n;
}

/**
 * Every state artifact under a Claude Desktop root. Each collector is guarded independently so a
 * malformed store cannot cost the others.
 */
function collectClaudeDesktopState(rootDir, attribution = {}, options = {}) {
  if (!rootDir || !fs.existsSync(rootDir)) return [];
  const rows = [];
  const run = (label, fn) => {
    try { rows.push(...fn()); } catch (e) {
      dbg("AIHIST", `claude desktop ${label} failed`, { path: rootDir, err: e.message });
    }
  };

  run("deleted sessions", () => collectDeletedSessions(rootDir, attribution));
  if (options.includePendingUploads !== false) {
    run("pending uploads", () => collectPendingUploads(rootDir, attribution));
  }
  run("plan usage", () => collectPlanUsageWindows(rootDir, attribution));
  run("scheduled tasks", () => collectScheduledTasks(rootDir, attribution));
  run("worktrees", () => collectWorktreeAccess(rootDir, attribution));
  run("remote bridge", () => collectRemoteBridgeState(rootDir, attribution));
  run("desktop config", () => collectDesktopConfigState(rootDir, attribution));

  return rows;
}

module.exports = {
  DELETED_SESSION_RE,
  PENDING_UPLOADS_DIR,
  PENDING_UPLOAD_RE,
  PLAN_USAGE_FILE,
  SCHEDULED_TASKS_FILE,
  WORKTREES_FILE,
  BRIDGE_STATE_FILE,
  DESKTOP_CONFIG_FILE,
  APP_CONFIG_FILE,
  COWORK_SECURITY_PREF_KEYS,
  USAGE_SESSION_GAP_MS,
  collectDeletedSessions,
  collectPendingUploads,
  collectPlanUsageWindows,
  collectScheduledTasks,
  collectWorktreeAccess,
  collectRemoteBridgeState,
  collectDesktopConfigState,
  countClaudeDesktopStateFiles,
  collectClaudeDesktopState,
};
