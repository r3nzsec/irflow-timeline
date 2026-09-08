/**
 * parsers/ai-history/grok-bot.js — xAI Grok Bot (desktop app + local exec daemon) artifacts.
 *
 * Grok Bot (beta, August 2026) is an always-on agent product: each agent runs on a cloud "box"
 * and can reach back into this machine through a LOCAL EXEC DAEMON the desktop app installs. That
 * makes it a different evidence class from Grok Build. Grok Bot records local-tool requests,
 * recorded decisions and independently linked results, alongside what the user said to an agent.
 *
 * Verified layout (Grok Bot 1.x, macOS):
 *
 *   ~/.grokbot/                                   — daemon state (GROKBOT_HOME)
 *     .grokbot-data-root-v1                       — root marker
 *     settings.json                               — localToolPermission, egress tunnel, WebAuthn
 *                                                   proxy, MCP "box" servers, account scope
 *     local-exec-daemon.json                      — pid, startedAt, inflightCount, generation
 *     local-exec-supervisor.json                  — supervisor pid + heartbeat
 *     local-exec-daemon.log[.N]                   — current/rotated `[tag] message` lines, NO timestamps;
 *                                                   daemon starts and shell-exec lifecycle
 *     attachment-staging/                         — files staged for upload (inventory only)
 *     local-exec-daemon-credential.json           — SENSITIVE, never read
 *     local-exec-daemon-connection.json           — SENSITIVE, never read
 *
 *   ~/Library/Application Support/Grok Bot/       — Electron app data
 *     sand-client-persistence/<base32>.blob       — JSON slices; the filename is the base32 of a
 *         dotted slice name, e.g. `sand.client.slice.account.<acct>.transcript.replicas.<agentId>`
 *         (client-side copy of an agent transcript: user messages, agent sends, attachments,
 *         automation events), `...roster.last-roster` (the user's agents with names, creation and
 *         last-activity times), `...composer-drafts` (unsent prompt text), `...send-journal`.
 *     sand-session-marker.json                    — app version, pid, start and last-alive times
 *     sand-update-apply-marker.json               — version transitions
 *     sentry/scope_v3.json, sentry/session.json   — crash-reporter scope: signed-in account id +
 *         email, app version, OS/hardware, timezone, boot/app-start times, last open agent
 *     Local State                                 — Chromium profile creation stamp
 *     link-preview-cache/link-cache/<sha>.json    — cached unfurl metadata with
 *         title/site and fetch time (survives the replica window)
 *     sand-secrets.json, gateway-descriptor.json, box-secrets-push-state.v1.json — SENSITIVE,
 *         inventoried by name and size only
 *
 * Transcript replicas are the client's cache of a cloud-hosted conversation. Retention is hard-coded
 * in the renderer bundle (verified in Grok Bot 0.43.0, `transcript.replicas` persistence): the last
 * 200 entries or 768 KB serialized per agent, whichever is hit first; at most 24 agent replicas per
 * account (least recently persisted is evicted); and any replica not refreshed for 7 days is deleted
 * the next time the app restores. None of this is configurable, so a replica is a recent window and
 * each row says so. Message text is emitted verbatim.
 *
 * Attachments: the transcript records the file's name, size, dimensions and cloud-box path. A
 * hash-shaped box filename is retained as `referenceSha256`; it becomes verified evidence only
 * after hashing recovered local bytes. The parser looks for a local original (same name, size and
 * SHA-256) inside the selected Grok Bot data folders and inventories any remaining staged files.
 * Desktop/Documents/Downloads are not searched unless the caller opts in.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { dbg } = require("../../logger");
const { TOOL_GROK_BOT } = require("./schema");
const { filterSidechainRows, tickFileProgress } = require("./extract-plan");
const {
  formatTimestampUtc,
  makeRow,
  assignLineNumber,
  finalizeAiHistoryRows,
  truncateSummary,
} = require("./row-utils");

const GROKBOT_DIR_NAME = ".grokbot";
const GROKBOT_APP_DIR_NAME = "Grok Bot";
const GROKBOT_ROOT_MARKER = ".grokbot-data-root-v1";
const PERSISTENCE_DIR = "sand-client-persistence";
const DAEMON_LOG_FILE = "local-exec-daemon.log";
const DAEMON_STATE_FILE = "local-exec-daemon.json";
const SUPERVISOR_STATE_FILE = "local-exec-supervisor.json";
const SETTINGS_FILE = "settings.json";
const ATTACHMENT_STAGING_DIR = "attachment-staging";
const SESSION_MARKER_FILE = "sand-session-marker.json";
const UPDATE_MARKER_FILE = "sand-update-apply-marker.json";
const SENTRY_DIR = "sentry";
const SENTRY_SCOPE_FILE = "scope_v3.json";
const SENTRY_SESSION_FILE = "session.json";
const LOCAL_STATE_FILE = "Local State";
const LINK_CACHE_PARENT = "link-preview-cache";
const LINK_CACHE_DIR_NAME = "link-cache";

/** Credential and key material. Existence, size and mtime are evidence; contents are never read. */
const SENSITIVE_FILES = new Set([
  "local-exec-daemon-credential.json",
  "local-exec-daemon-connection.json",
  "sand-secrets.json",
  "box-secrets-push-state.v1.json",
  "gateway-descriptor.json",
]);

const SLICE_PREFIX = "sand.client.slice.";
const MAX_JSON_BYTES = 32 * 1024 * 1024;
const MAX_LOG_BYTES = 8 * 1024 * 1024;
const MAX_LOG_ROWS = 5000;
const MAX_ENTRIES_PER_REPLICA = 20000;
/** Grok Bot's own replica retention (renderer constants, verified 0.43.0). */
const REPLICA_ENTRY_CAP = 200;
const REPLICA_BYTE_CAP = 768 * 1024;
const REPLICA_MAX_AGENTS = 24;
const REPLICA_MAX_AGE_DAYS = 7;
const REPLICA_RETENTION_NOTE = `Grok Bot keeps only the last ${REPLICA_ENTRY_CAP} entries or a ${REPLICA_BYTE_CAP / 1024} KB-equivalent JSON.stringify character budget per agent, `
  + `at most ${REPLICA_MAX_AGENTS} agent replicas per account, and deletes any replica not refreshed for `
  + `${REPLICA_MAX_AGE_DAYS} days when the app next starts. The authoritative history is on xAI's servers.`;
const MAX_LINK_PREVIEWS = 2000;
/** The agent's box uses hash-shaped attachment names; treat the value as a reference until verified. */
const SHA256_NAME_RE = /^([0-9a-f]{64})\.[a-z0-9]{1,8}$/i;
/** Where a local original of an uploaded file is looked for, relative to the owning profile's home. */
const ATTACHMENT_SEARCH_DIRS = ["Downloads", "Desktop", "Documents", "Pictures"];
const ATTACHMENT_SEARCH_DEPTH = 3;
const ATTACHMENT_SEARCH_MAX_DIRS = 1500;
const MAX_ATTACHMENT_HASH_BYTES = 256 * 1024 * 1024;
const ATTACHMENT_SEARCH_MAX_HASHES = 256;

function isDaemonLogName(name) {
  return /^local-exec-daemon\.log(?:\.\d+)?$/i.test(String(name || ""));
}

function listDaemonLogFiles(rootDir) {
  if (!safeIsDirectory(rootDir)) return [];
  try {
    return fs.readdirSync(rootDir, { withFileTypes: true })
      .filter((e) => e.isFile() && isDaemonLogName(e.name))
      .map((e) => path.join(rootDir, e.name))
      .sort((a, b) => a.localeCompare(b));
  } catch {
    return [];
  }
}

function botRow(fields) {
  const timestampBasis = fields.timestampBasis || (fields.timestamp ? "source artifact timestamp" : "unavailable");
  return makeRow({ ...fields, timestampBasis, tool: TOOL_GROK_BOT }, TOOL_GROK_BOT);
}

function safeStat(p) {
  try { return fs.statSync(p); } catch { return null; }
}
function safeIsDirectory(p) { return !!safeStat(p)?.isDirectory(); }
function safeIsFile(p) { return !!safeStat(p)?.isFile(); }

function readJsonBounded(filePath) {
  const st = safeStat(filePath);
  if (!st?.isFile() || st.size > MAX_JSON_BYTES) return null;
  try { return JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { return null; }
}

function safeJson(value) {
  try { return JSON.stringify(value, null, 2); } catch { return String(value ?? ""); }
}

/** Epoch ms → formatted; anything that is not a plausible ms stamp yields "" (never fabricated). */
function msToTimestamp(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 1e12) return "";
  return formatTimestampUtc(n);
}

/** Epoch seconds (Sentry, Chromium Local State) → formatted, or "". */
function secToTimestamp(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 1e9 || n >= 1e12) return "";
  return formatTimestampUtc(Math.round(n * 1000));
}

/** ISO-8601 → formatted, or "". */
function isoToTimestamp(value) {
  if (value == null || value === "") return "";
  const n = Date.parse(String(value));
  return Number.isFinite(n) ? formatTimestampUtc(n) : "";
}

/** `/home/box/.../attachments/<sha256>.png` or a file:// URL of it → the hex hash, else "". */
function contentHashFromBoxPath(value) {
  const raw = String(value || "").replace(/^file:\/\//i, "");
  const m = SHA256_NAME_RE.exec(path.basename(raw));
  return m ? m[1].toLowerCase() : "";
}

function sha256OfFile(filePath, checkAbort = null) {
  let cancellationError = null;
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size > MAX_ATTACHMENT_HASH_BYTES) return "";
    const hash = crypto.createHash("sha256");
    const fd = fs.openSync(filePath, "r");
    try {
      const buf = Buffer.allocUnsafe(1 << 20);
      let n;
      while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
        try { checkAbort?.(); } catch (e) { cancellationError = e; throw e; }
        hash.update(buf.subarray(0, n));
      }
    } finally { fs.closeSync(fd); }
    return hash.digest("hex");
  } catch (e) {
    if (e === cancellationError) throw e;
    return "";
  }
}

/**
 * Finder for the local original of an uploaded attachment. Indexes file names under the owning
 * profile's user folders once (bounded depth and directory count, no symlink following, never
 * leaves `home`), then only hashes candidates whose name AND size match. A hit means the file on
 * disk is byte-for-byte what was sent to the cloud agent.
 */
function createLocalAttachmentFinder(roots, opts = {}) {
  const start = [];
  const addDir = (d) => { if (d && safeIsDirectory(d) && !start.includes(d)) start.push(d); };
  if (Array.isArray(roots)) roots.forEach(addDir);
  else addDir(roots);
  // Opt-in only: walking Desktop/Documents/Downloads hashes the user's files and
  // widens the read beyond the selected Grok Bot data directory.
  if (opts.includeUserFolders && opts.home) {
    for (const d of ATTACHMENT_SEARCH_DIRS) addDir(path.join(opts.home, d));
  }
  if (!start.length) return null;
  let index = null;
  const hashCache = new Map();
  const finderStats = {
    searchEnabled: true,
    includeUserFolders: !!opts.includeUserFolders,
    roots: [...start],
    directoriesVisited: 0,
    directoryLimitReached: false,
    filesIndexed: 0,
    hashCandidates: 0,
    hashCandidatesOmitted: 0,
    matches: 0,
  };
  const build = () => {
    index = new Map();
    const queue = start.map((dir) => ({ dir, depth: 0 }));
    let head = 0;
    let visited = 0;
    while (head < queue.length && visited < ATTACHMENT_SEARCH_MAX_DIRS) {
      opts.checkAbort?.();
      const { dir, depth } = queue[head++];
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
      visited += 1;
      finderStats.directoriesVisited = visited;
      for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (depth < ATTACHMENT_SEARCH_DEPTH && !e.name.startsWith(".")) queue.push({ dir: full, depth: depth + 1 });
        } else if (e.isFile() && !SENSITIVE_FILES.has(e.name)) {
          const list = index.get(e.name) || [];
          list.push(full);
          index.set(e.name, list);
          finderStats.filesIndexed += 1;
        }
      }
    }
    finderStats.directoryLimitReached = head < queue.length;
  };
  const find = (fileName, byteSize, sha256) => {
    if (!fileName || !sha256 || !Number.isFinite(byteSize) || byteSize <= 0) return [];
    if (!index) build();
    const out = [];
    for (const full of index.get(fileName) || []) {
      opts.checkAbort?.();
      const st = safeStat(full);
      if (!st?.isFile() || st.size !== byteSize) continue;
      let h = hashCache.get(full);
      if (h == null) {
        if (finderStats.hashCandidates >= ATTACHMENT_SEARCH_MAX_HASHES) {
          finderStats.hashCandidatesOmitted += 1;
          continue;
        }
        finderStats.hashCandidates += 1;
        h = sha256OfFile(full, opts.checkAbort);
        hashCache.set(full, h);
      }
      if (h === sha256) {
        out.push(full);
        finderStats.matches += 1;
      }
    }
    return out;
  };
  find.getStats = () => ({ ...finderStats, roots: [...finderStats.roots] });
  return find;
}

/* ------------------------------------------------------------- slice name codec */

const B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

/** RFC 4648 base32 (lower-case, unpadded) → utf8, or null when the name is not base32. */
function decodeSliceBlobName(fileName) {
  const stem = String(fileName || "").replace(/\.blob$/i, "").toLowerCase();
  if (!stem || /[^a-z2-7]/.test(stem)) return null;
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of stem) {
    value = ((value << 5) | B32_ALPHABET.indexOf(ch)) >>> 0;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  const text = Buffer.from(out).toString("utf8");
  return /^[\x20-\x7e]+$/.test(text) ? text : null;
}

/** Inverse of decodeSliceBlobName — used to build fixtures and to name blobs deterministically. */
function encodeSliceBlobName(sliceName) {
  const bytes = Buffer.from(String(sliceName), "utf8");
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = ((value << 8) | b) >>> 0;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return `${out}.blob`;
}

/**
 * `sand.client.slice.account.<acct>.transcript.replicas.<agentId>` →
 *   { kind: "transcript", account: "<acct>", agentId: "<agentId>" }
 */
function classifySliceName(sliceName) {
  if (!sliceName || !sliceName.startsWith(SLICE_PREFIX)) return null;
  const rest = sliceName.slice(SLICE_PREFIX.length);
  const acct = /^account\.(.+?)\.(transcript\.replicas\.(.+)|roster\.last-roster|roster\.agent-avatars|composer-drafts|send-journal|selection\.last-agent|sidebar\.last-sections|ui-agent-refs)$/.exec(rest);
  if (acct) {
    let account = acct[1];
    try { account = decodeURIComponent(account); } catch { /* keep raw */ }
    const tail = acct[2];
    if (tail.startsWith("transcript.replicas.")) return { kind: "transcript", account, agentId: acct[3] };
    if (tail === "roster.last-roster") return { kind: "roster", account };
    if (tail === "composer-drafts") return { kind: "drafts", account };
    if (tail === "send-journal") return { kind: "send-journal", account };
    return { kind: "ui", account, slice: tail };
  }
  return { kind: "ui", account: "", slice: rest };
}

/* ------------------------------------------------------------------- roots */

function defaultGrokBotHome() {
  if (process.env.GROKBOT_HOME) return path.resolve(process.env.GROKBOT_HOME);
  return path.join(os.homedir(), GROKBOT_DIR_NAME);
}

function defaultGrokBotAppDir() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", GROKBOT_APP_DIR_NAME);
  }
  if (process.platform === "win32") {
    const roaming = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return path.join(roaming, GROKBOT_APP_DIR_NAME);
  }
  return path.join(home, ".config", GROKBOT_APP_DIR_NAME);
}

function isGrokBotDaemonRoot(dirPath) {
  if (!dirPath || !safeIsDirectory(dirPath)) return false;
  if (safeIsFile(path.join(dirPath, GROKBOT_ROOT_MARKER))) return true;
  if (safeIsFile(path.join(dirPath, DAEMON_LOG_FILE))) return true;
  if (safeIsFile(path.join(dirPath, DAEMON_STATE_FILE))) return true;
  if (safeIsFile(path.join(dirPath, SUPERVISOR_STATE_FILE))) return true;
  // A bare settings.json is only evidence when it carries Grok Bot's own keys — many apps have one.
  const settings = readJsonBounded(path.join(dirPath, SETTINGS_FILE));
  return !!(settings && typeof settings === "object"
    && ("localToolPermission" in settings || "accountScopes" in settings || "mcpBoxServers" in settings));
}

function isGrokBotAppRoot(dirPath) {
  if (!dirPath || !safeIsDirectory(dirPath)) return false;
  return safeIsDirectory(path.join(dirPath, PERSISTENCE_DIR))
    || safeIsFile(path.join(dirPath, SESSION_MARKER_FILE));
}

function isGrokBotRoot(dirPath) {
  return isGrokBotDaemonRoot(dirPath) || isGrokBotAppRoot(dirPath);
}

const NOT_A_GROK_BOT_DIR = "Not a Grok Bot data directory. Choose ~/.grokbot (local exec daemon) "
  + "or the 'Grok Bot' application-support folder (the one that contains sand-client-persistence).";

/**
 * Well-known child locations only — no recursive walk of a home directory.
 * Used when the picker lands on ~, Application Support, or AppData instead of the real root.
 */
function listGrokBotExtractRoots(dirPath) {
  if (!dirPath || !safeIsDirectory(dirPath)) return [];
  const resolved = path.resolve(dirPath);
  if (isGrokBotRoot(resolved)) return [resolved];
  const seen = new Set();
  const out = [];
  const add = (p) => {
    if (!p) return;
    const full = path.resolve(p);
    if (seen.has(full) || !isGrokBotRoot(full)) return;
    seen.add(full);
    out.push(full);
  };
  add(path.join(resolved, GROKBOT_DIR_NAME));
  add(path.join(resolved, GROKBOT_APP_DIR_NAME));
  add(path.join(resolved, "Library", "Application Support", GROKBOT_APP_DIR_NAME));
  add(path.join(resolved, "AppData", "Roaming", GROKBOT_APP_DIR_NAME));
  add(path.join(resolved, ".config", GROKBOT_APP_DIR_NAME));
  return out;
}

/** User profile that owns a Grok Bot leaf root (`~/.grokbot` or `…/Grok Bot`). */
function userHomeForGrokBotRoot(rootDir) {
  if (!rootDir) return null;
  const resolved = path.resolve(rootDir);
  const base = path.basename(resolved);
  if (base === GROKBOT_DIR_NAME && isGrokBotDaemonRoot(resolved)) return path.dirname(resolved);
  if (base !== GROKBOT_APP_DIR_NAME || !isGrokBotAppRoot(resolved)) return null;
  const parent = path.dirname(resolved);
  const grand = path.dirname(parent);
  const great = path.dirname(grand);
  if (path.basename(parent) === "Application Support" && path.basename(grand) === "Library") return great;
  if (path.basename(parent) === "Roaming" && path.basename(grand) === "AppData") return great;
  if (path.basename(parent) === ".config") return grand;
  return null;
}

/**
 * Walk up from a file/folder, look down into known children, and pair the daemon + app
 * roots that belong to the same user profile so a pick of ~/.grokbot still gets prompts.
 */
function grokBotExtractTargets(target) {
  const seen = new Set();
  const out = [];
  const addAll = (list) => {
    for (const p of list || []) {
      if (!p || seen.has(p)) continue;
      seen.add(p);
      out.push(p);
    }
  };
  const resolved = resolveGrokBotRoot(target);
  if (resolved) addAll([resolved]);
  else addAll(listGrokBotExtractRoots(target));
  for (const root of [...out]) {
    const home = userHomeForGrokBotRoot(root);
    if (home) addAll(listGrokBotExtractRoots(home));
  }
  return out;
}

function resolveGrokBotRoot(target) {
  if (!target) return null;
  let current = path.resolve(target);
  const st = safeStat(current);
  if (!st) return null;
  if (st.isFile()) current = path.dirname(current);
  for (let i = 0; i < 24; i++) {
    if (isGrokBotRoot(current)) return current;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

function isGrokBotArtifactFile(filePath) {
  if (!filePath || !safeIsFile(filePath)) return false;
  const base = path.basename(filePath);
  const parent = path.basename(path.dirname(filePath));
  const known = isDaemonLogName(base) || base === DAEMON_STATE_FILE || base === SUPERVISOR_STATE_FILE
    || base === SETTINGS_FILE || base === SESSION_MARKER_FILE || base === UPDATE_MARKER_FILE
    || base === LOCAL_STATE_FILE
    || (parent === SENTRY_DIR && (base === SENTRY_SCOPE_FILE || base === SENTRY_SESSION_FILE))
    || (parent === LINK_CACHE_DIR_NAME && /\.json$/i.test(base))
    || (/\.blob$/i.test(base) && parent === PERSISTENCE_DIR);
  if (!known) return false;
  return !!resolveGrokBotRoot(filePath);
}

/* ---------------------------------------------------------------- file lists */

function listGrokBotDataFiles(rootDir) {
  const out = [];
  const push = (p) => { if (safeIsFile(p)) out.push(p); };
  if (isGrokBotDaemonRoot(rootDir)) {
    for (const f of [SETTINGS_FILE, DAEMON_STATE_FILE, SUPERVISOR_STATE_FILE]) {
      push(path.join(rootDir, f));
    }
    out.push(...listDaemonLogFiles(rootDir));
    const staging = path.join(rootDir, ATTACHMENT_STAGING_DIR);
    if (safeIsDirectory(staging)) {
      try {
        for (const e of fs.readdirSync(staging, { withFileTypes: true })) {
          if (e.isFile()) out.push(path.join(staging, e.name));
        }
      } catch { /* ignore */ }
    }
  }
  if (isGrokBotAppRoot(rootDir)) {
    for (const f of [SESSION_MARKER_FILE, UPDATE_MARKER_FILE, LOCAL_STATE_FILE]) push(path.join(rootDir, f));
    push(path.join(rootDir, SENTRY_DIR, SENTRY_SCOPE_FILE));
    push(path.join(rootDir, SENTRY_DIR, SENTRY_SESSION_FILE));
    const persist = path.join(rootDir, PERSISTENCE_DIR);
    if (safeIsDirectory(persist)) {
      try {
        for (const e of fs.readdirSync(persist, { withFileTypes: true })) {
          if (!e.isFile() || !/\.blob$/i.test(e.name)) continue;
          out.push(path.join(persist, e.name));
        }
      } catch { /* ignore */ }
    }
    const linkDir = path.join(rootDir, LINK_CACHE_PARENT, LINK_CACHE_DIR_NAME);
    if (safeIsDirectory(linkDir)) {
      try {
        for (const e of fs.readdirSync(linkDir, { withFileTypes: true })) {
          if (e.isFile() && /\.json$/i.test(e.name)) out.push(path.join(linkDir, e.name));
        }
      } catch { /* ignore */ }
    }
  }
  return out.sort();
}

function countGrokBotExtractFiles(rootDir) {
  return listGrokBotDataFiles(rootDir).length;
}

/* ------------------------------------------------------------- daemon root rows */

function daemonStateRows(rootDir, attribution) {
  const rows = [];
  const statePath = path.join(rootDir, DAEMON_STATE_FILE);
  const state = readJsonBounded(statePath);
  if (state && typeof state === "object") {
    const pid = state.pid != null ? String(state.pid) : "";
    rows.push(botRow({
      timestamp: msToTimestamp(state.startedAt) || formatTimestampUtc(safeStat(statePath)?.mtimeMs ?? null),
      timestampBasis: msToTimestamp(state.startedAt) ? "daemon state startedAt" : "source file mtime",
      role: "system",
      recordType: "local_exec_daemon",
      summary: `Grok Bot local exec daemon started — pid ${pid || "?"}, generation ${state.generation ?? "?"}, `
        + `${state.inflightCount ?? 0} in-flight request(s)`,
      fullText: safeJson({
        pid: state.pid,
        startedAt: msToTimestamp(state.startedAt) || null,
        generation: state.generation,
        inflightCount: state.inflightCount,
        filesKeyId: state.filesKeyId,
        timeSource: msToTimestamp(state.startedAt) ? "startedAt" : "file mtime",
      }),
      messageId: pid,
      toolDescription: "The daemon that executes commands on this machine on behalf of cloud-hosted "
        + "Grok Bot agents. While it ran, an agent (or anyone controlling the account) could run "
        + "local tools here subject to settings.json localToolPermission.",
      sourceFile: statePath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  const supPath = path.join(rootDir, SUPERVISOR_STATE_FILE);
  const sup = readJsonBounded(supPath);
  if (sup && typeof sup === "object") {
    rows.push(botRow({
      timestamp: msToTimestamp(sup.at) || formatTimestampUtc(safeStat(supPath)?.mtimeMs ?? null),
      timestampBasis: msToTimestamp(sup.at) ? "supervisor state at" : "source file mtime",
      role: "system",
      recordType: "local_exec_supervisor",
      summary: `Grok Bot local exec supervisor heartbeat — pid ${sup.pid ?? "?"}`,
      fullText: safeJson({ pid: sup.pid, at: msToTimestamp(sup.at) || null }),
      messageId: sup.pid != null ? String(sup.pid) : "",
      toolDescription: "Supervisor process that keeps the local exec daemon alive; `at` is its last "
        + "heartbeat, which bounds how recently the daemon was being supervised.",
      sourceFile: supPath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function hostOnly(url) {
  try { return new URL(String(url)).host; } catch { return ""; }
}

function settingsRows(rootDir, attribution) {
  const settingsPath = path.join(rootDir, SETTINGS_FILE);
  const settings = readJsonBounded(settingsPath);
  if (!settings || typeof settings !== "object") return [];
  const st = safeStat(settingsPath);
  const onOff = (v) => (v === true ? "on" : v === false ? "off" : "unset");

  const boxServers = Array.isArray(settings.mcpBoxServers) ? settings.mcpBoxServers : [];
  const boxServerSummary = boxServers.map((srv) => {
    if (!srv || typeof srv !== "object") return String(srv ?? "");
    return {
      id: srv.id ?? srv.serverId ?? "",
      name: srv.name ?? "",
      host: hostOnly(srv.url ?? srv.endpoint ?? ""),
      enabled: srv.enabled,
    };
  });
  const customInstructions = settings.mcpCustomInstructionsByServerId
    && typeof settings.mcpCustomInstructionsByServerId === "object"
    ? settings.mcpCustomInstructionsByServerId : {};
  const disabledTools = settings.mcpDisabledToolsByServerId
    && typeof settings.mcpDisabledToolsByServerId === "object"
    ? settings.mcpDisabledToolsByServerId : {};

  const picked = {
    version: settings.version,
    localToolPermission: settings.localToolPermission ?? null,
    egressTunnelEnabled: settings.egressTunnelEnabled,
    webauthnProxyEnabled: settings.webauthnProxyEnabled,
    messagesEnabled: settings.messagesEnabled,
    conciergeConsent: settings.conciergeConsent,
    activeAccountScope: settings.activeAccountScope,
    hasSeenOnboarding: settings.hasSeenOnboarding,
    autoUpdateWhenIdleOptIn: settings.autoUpdateWhenIdleOptIn,
    mcpBoxServers: boxServerSummary,
    mcpCustomInstructionsByServerId: customInstructions,
    mcpDisabledToolsByServerId: disabledTools,
    timeSource: "settings.json mtime",
  };

  return [botRow({
    timestamp: formatTimestampUtc(st?.mtimeMs ?? null),
    timestampBasis: "settings.json file mtime",
    role: "metadata",
    recordType: "grokbot_settings",
    summary: `Grok Bot settings — local tool permission "${settings.localToolPermission ?? "unset"}", `
      + `egress tunnel ${onOff(settings.egressTunnelEnabled)}, WebAuthn proxy ${onOff(settings.webauthnProxyEnabled)}, `
      + `messages ${onOff(settings.messagesEnabled)}, ${boxServers.length} MCP box server(s)`
      + `${Object.keys(customInstructions).length ? `, custom MCP instructions for ${Object.keys(customInstructions).length} server(s)` : ""}`,
    fullText: safeJson(picked),
    toolDescription: "localToolPermission governs whether cloud agents may run tools on this machine "
      + "through the local exec daemon (and whether the user is asked each time). egressTunnelEnabled "
      + "routes the agent's outbound traffic through this host. Configuration state dated from the "
      + "file mtime; MCP server URLs are reduced to their host.",
    sourceFile: settingsPath,
    lineNumber: 1,
    user: attribution.user || "",
    host: attribution.host || "",
  })];
}

/**
 * local-exec-daemon.log — `[tag] message` lines with NO timestamps.
 *
 * Daemon starts and shell-exec lifecycle lines become rows in file order (LineNumber is the only
 * ordering evidence). Everything else is aggregated into one summary row so hundreds of identical
 * connection-retry lines do not bury the timeline.
 */
function daemonLogRows(rootDir, attribution, stats = null, checkAbort = null, selectedLogPath = null) {
  const logPath = selectedLogPath || path.join(rootDir, DAEMON_LOG_FILE);
  const logName = path.basename(logPath);
  const st = safeStat(logPath);
  if (!st?.isFile()) return [];

  let text;
  let bytesRead = 0;
  try {
    const fd = fs.openSync(logPath, "r");
    try {
      const len = Math.min(st.size, MAX_LOG_BYTES);
      bytesRead = len;
      const buf = Buffer.allocUnsafe(len);
      fs.readSync(fd, buf, 0, len, 0);
      text = buf.toString("utf8");
    } finally { fs.closeSync(fd); }
  } catch { return []; }
  const truncated = st.size > MAX_LOG_BYTES;

  const rows = [];
  const tagCounts = {};
  const errorValues = new Map();
  let lineCount = 0;
  let detailCandidates = 0;
  let detailOmitted = 0;
  let firstLine = "";
  let lastLine = "";
  const noTimestamps = "Daemon log lines carry no timestamp: order by LineNumber; the file mtime "
    + "bounds the last line.";

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    checkAbort?.();
    const line = lines[i].trim();
    if (!line) continue;
    lineCount += 1;
    if (!firstLine) firstLine = line;
    lastLine = line;

    if (line.startsWith("{")) {
      try {
        const obj = JSON.parse(line);
        const err = obj && typeof obj === "object" ? String(obj.error ?? obj.code ?? "").slice(0, 120) : "";
        if (err) errorValues.set(err, (errorValues.get(err) || 0) + 1);
        tagCounts["<json>"] = (tagCounts["<json>"] || 0) + 1;
      } catch {
        tagCounts["<unparsed>"] = (tagCounts["<unparsed>"] || 0) + 1;
      }
      continue;
    }

    const m = /^\[([A-Za-z0-9_.-]+)\]\s*(.*)$/.exec(line);
    const tag = m ? m[1] : "<untagged>";
    const message = m ? m[2] : line;
    tagCounts[tag] = (tagCounts[tag] || 0) + 1;

    const started = /\bstarted\b.*?\(pid\s+(\d+)\)/i.exec(message);
    if (started) {
      detailCandidates += 1;
      if (rows.length >= MAX_LOG_ROWS) { detailOmitted += 1; continue; }
      rows.push(assignLineNumber(botRow({
        timestamp: "",
        timestampBasis: "unavailable; daemon log line has no timestamp",
        // No timestamp and no session in this log: without a per-line key, identical repeated
        // lines (same pid restarting, the same shell-exec warning 40×) collapse under dedupe.
        sessionId: `${logName}#L${i + 1}`,
        role: "system",
        recordType: "daemon_started",
        summary: `Local exec daemon started — pid ${started[1]}: ${truncateSummary(message)}`,
        fullText: line,
        messageId: started[1],
        toolDescription: `A daemon (re)start. ${noTimestamps}`,
        sourceFile: logPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }), i + 1));
      continue;
    }
    if (tag === "shell-exec") {
      detailCandidates += 1;
      if (rows.length >= MAX_LOG_ROWS) { detailOmitted += 1; continue; }
      rows.push(assignLineNumber(botRow({
        timestamp: "",
        timestampBasis: "unavailable; daemon log line has no timestamp",
        sessionId: `${logName}#L${i + 1}`,
        role: "tool",
        recordType: "daemon_shell_exec",
        summary: `[shell-exec] ${truncateSummary(message)}`,
        fullText: safeJson({ rawLine: line, command: null, requestId: null, result: "unknown", correlationStatus: "unlinked" }),
        toolName: "shell-exec",
        toolDescription: "Shell-exec lifecycle text recorded by the local exec daemon. The command, "
          + "request ID, process result and exit status are not logged here, so execution and success "
          + "remain unknown and this row is not time-correlated to a transcript request. "
          + noTimestamps,
        sourceFile: logPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }), i + 1));
    }
  }

  if (lineCount) {
    const errors = [...errorValues.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12)
      .map(([error, count]) => ({ error, count }));
    const tagText = Object.entries(tagCounts).sort((a, b) => b[1] - a[1])
      .map(([t, c]) => `${t}×${c}`).join(", ");
    rows.push(botRow({
      timestamp: formatTimestampUtc(st.mtimeMs),
      timestampBasis: "daemon log file mtime; bounds the readable prefix's last line",
      role: "system",
      recordType: "daemon_log_summary",
      summary: `Local exec daemon log — ${lineCount} line(s)${truncated ? " (read capped)" : ""}: ${tagText}`,
      fullText: safeJson({
        lineCount,
        readCapped: truncated,
        fileBytes: st.size,
        bytesRead,
        bytesOmittedByReadLimit: Math.max(0, st.size - bytesRead),
        detailRowLimit: MAX_LOG_ROWS,
        detailCandidates,
        detailRowsEmitted: rows.length,
        detailRowsOmittedByLimit: detailOmitted,
        tagCounts,
        errorCodes: errors,
        firstLine: firstLine.slice(0, 300),
        lastLine: lastLine.slice(0, 300),
        timeSource: "file mtime",
      }),
      toolDescription: `Aggregate of the ${truncated ? "readable prefix" : "whole file"}; detail-row and byte omissions are reported separately. ${noTimestamps}`,
      sourceFile: logPath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  if (stats) {
    stats.daemonLogFiles += 1;
    stats.daemonLogBytes += st.size;
    stats.daemonLogBytesRead += bytesRead;
    stats.daemonLogBytesOmitted += Math.max(0, st.size - bytesRead);
    stats.daemonLogLinesRead += lineCount;
    stats.daemonLogDetailCandidates += detailCandidates;
    stats.daemonLogDetailRows += rows.filter((r) => r.RecordType !== "daemon_log_summary").length;
    stats.daemonLogDetailRowsOmitted += detailOmitted;
    if (truncated) stats.daemonLogsReadCapped += 1;
  }
  return rows;
}

function inventoryRow(filePath, recordType, summaryPrefix, description, attribution, extra = {}) {
  const st = safeStat(filePath);
  if (!st?.isFile()) return null;
  return botRow({
    timestamp: formatTimestampUtc(st.mtimeMs),
    timestampBasis: "source file mtime",
    role: extra.role || "system",
    recordType,
    summary: `${summaryPrefix} — ${path.basename(filePath)} (${st.size} bytes)`,
    fullText: safeJson({
      fileName: path.basename(filePath),
      sizeBytes: st.size,
      modifiedUtc: formatTimestampUtc(st.mtimeMs),
      contentParsed: false,
      ...extra.detail,
    }),
    toolDescription: description,
    sourceFile: filePath,
    lineNumber: 1,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function sensitiveInventoryRows(rootDir, attribution) {
  const rows = [];
  for (const name of SENSITIVE_FILES) {
    const row = inventoryRow(
      path.join(rootDir, name),
      "credential_store_inventory",
      "Grok Bot credential/key store present (not read)",
      "INVENTORY ONLY. Holds daemon credentials, gateway keys or encrypted secrets; its presence "
        + "and modification time are the evidence. Preserve the file; never ingest its contents.",
      attribution,
    );
    if (row) rows.push(row);
  }
  return rows;
}

function attachmentStagingRows(rootDir, attribution) {
  const staging = path.join(rootDir, ATTACHMENT_STAGING_DIR);
  if (!safeIsDirectory(staging)) return [];
  const rows = [];
  let entries;
  try { entries = fs.readdirSync(staging, { withFileTypes: true }); } catch { return rows; }
  for (const e of entries) {
    if (!e.isFile()) continue;
    const row = inventoryRow(
      path.join(staging, e.name),
      "attachment_staged",
      "Attachment staged for upload to a Grok Bot agent",
      "INVENTORY ONLY — a file the user attached, held locally until uploaded. Content is never read.",
      attribution,
      { role: "attachment" },
    );
    if (row) rows.push(row);
  }
  return rows;
}

/* ---------------------------------------------------------------- app root rows */

function appMarkerRows(rootDir, attribution) {
  const rows = [];
  const sessionPath = path.join(rootDir, SESSION_MARKER_FILE);
  const session = readJsonBounded(sessionPath);
  if (session && typeof session === "object") {
    const alive = msToTimestamp(session.aliveAtMs);
    rows.push(botRow({
      timestamp: msToTimestamp(session.startedAtMs) || formatTimestampUtc(safeStat(sessionPath)?.mtimeMs ?? null),
      timestampBasis: msToTimestamp(session.startedAtMs) ? "session marker startedAtMs" : "source file mtime",
      role: "system",
      recordType: "app_session",
      summary: `Grok Bot ${session.appVersion ?? "?"} started — pid ${session.pid ?? "?"}`
        + `${alive ? `, last alive ${alive}` : ""}${session.crashSeen ? ", crash seen" : ""}`,
      fullText: safeJson({
        appVersion: session.appVersion,
        pid: session.pid,
        startedAt: msToTimestamp(session.startedAtMs) || null,
        aliveAt: alive || null,
        crashSeen: session.crashSeen,
      }),
      messageId: session.pid != null ? String(session.pid) : "",
      toolDescription: "Desktop app process marker: when the app started and the last heartbeat it "
        + "wrote. Brackets the period the app (and its local exec daemon) was running.",
      sourceFile: sessionPath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  const updatePath = path.join(rootDir, UPDATE_MARKER_FILE);
  const update = readJsonBounded(updatePath);
  if (update && typeof update === "object") {
    rows.push(botRow({
      timestamp: msToTimestamp(update.stagedAtMs) || formatTimestampUtc(safeStat(updatePath)?.mtimeMs ?? null),
      timestampBasis: msToTimestamp(update.stagedAtMs) ? "update marker stagedAtMs" : "source file mtime",
      role: "system",
      recordType: "app_update",
      summary: `Grok Bot update ${update.fromVersion ?? "?"} → ${update.targetVersion ?? "?"}`
        + ` (${update.phase ?? "?"}, ${update.mechanism ?? "?"}, attempt ${update.attempt ?? "?"})`,
      fullText: safeJson({
        fromVersion: update.fromVersion,
        targetVersion: update.targetVersion,
        phase: update.phase,
        mechanism: update.mechanism,
        attempt: update.attempt,
        stagedAt: msToTimestamp(update.stagedAtMs) || null,
      }),
      toolDescription: "Version transition staged by the updater — dates which build was in use.",
      sourceFile: updatePath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function textOf(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(textOf).filter(Boolean).join("\n");
  if (typeof value === "object") {
    if (typeof value.text === "string") return value.text;
    if (typeof value.content === "string") return value.content;
    if (value.content != null) return textOf(value.content);
    return safeJson(value);
  }
  return String(value);
}

const NEGATIVE_PERMISSION_STATES = new Set(["denied", "deny", "rejected", "expired", "cancelled", "canceled", "skipped"]);
const POSITIVE_PERMISSION_STATES = new Set(["allow", "allowed", "approve", "approved", "yes"]);

/** Keep the native fields while deriving a conservative evidentiary state. */
function normalizePermissionEvidence(ask, respondedValue, skipped) {
  const nativeAskStatus = ask?.status == null ? "" : String(ask.status).trim().toLowerCase();
  const nativeResponse = respondedValue == null ? "" : String(respondedValue).trim().toLowerCase();
  let permissionState = "unknown";
  let authorizationRecorded = null;
  let decisionBasis = "no decision or policy state recorded";

  if (skipped === true) {
    permissionState = "skipped";
    authorizationRecorded = false;
    decisionBasis = "widgetSkipped";
  } else if (NEGATIVE_PERMISSION_STATES.has(nativeResponse)) {
    permissionState = nativeResponse === "deny" || nativeResponse === "rejected" ? "denied" : nativeResponse;
    authorizationRecorded = false;
    decisionBasis = "respondedValue";
  } else if (POSITIVE_PERMISSION_STATES.has(nativeResponse)) {
    permissionState = "allowed";
    authorizationRecorded = true;
    decisionBasis = "respondedValue";
  } else if (NEGATIVE_PERMISSION_STATES.has(nativeAskStatus)) {
    permissionState = nativeAskStatus === "deny" || nativeAskStatus === "rejected" ? "denied" : nativeAskStatus;
    authorizationRecorded = false;
    decisionBasis = "ask.status";
  } else if (nativeAskStatus === "always") {
    permissionState = "persistent_policy";
    authorizationRecorded = true;
    decisionBasis = "ask.status=always";
  } else if (POSITIVE_PERMISSION_STATES.has(nativeAskStatus)) {
    permissionState = "allowed";
    authorizationRecorded = true;
    decisionBasis = "ask.status";
  } else if (nativeAskStatus === "pending") {
    permissionState = "pending";
    authorizationRecorded = false;
    decisionBasis = "ask.status";
  }

  return {
    permissionState,
    authorizationRecorded,
    decisionBasis,
    nativeAskStatus: nativeAskStatus || null,
    nativeResponse: nativeResponse || null,
    executionObserved: false,
    executionOutcome: "unknown",
    resultCorrelation: "unavailable: transcript request has no explicitly linked daemon result",
  };
}

function entryRelationshipDetail(entry) {
  return {
    replyTo: entry.replyTo ?? null,
    requestId: entry.requestId ?? null,
    clientNonce: entry.clientNonce ?? null,
    batchId: entry.batchId ?? null,
    channel: entry.channel ?? null,
    channelSender: entry.channelSender ?? null,
    author: entry.author ?? null,
    fromAgent: entry.fromAgent ?? null,
    toAgent: entry.toAgent ?? null,
    fromUser: entry.fromUser ?? null,
  };
}

/** roster.last-roster → agent rows + an agentId → { name, path } map used by the transcripts. */
function rosterRows(parsed, filePath, info, attribution) {
  const rows = [];
  const agents = new Map();
  const list = Array.isArray(parsed?.value?.rows) ? parsed.value.rows : [];
  for (const agent of list) {
    if (!agent || typeof agent !== "object") continue;
    const id = String(agent.id || "");
    if (!id) continue;
    const name = agent.name != null ? String(agent.name) : "";
    const workspace = typeof agent.path === "string" ? agent.path : "";
    agents.set(id, { name, workspace });
    const lastEntry = agent.lastEntry && typeof agent.lastEntry === "object" ? agent.lastEntry : null;
    rows.push(botRow({
      timestamp: msToTimestamp(agent.lastActivityAt) || msToTimestamp(agent.updatedAt) || msToTimestamp(agent.createdAt),
      timestampBasis: msToTimestamp(agent.lastActivityAt) ? "roster agent.lastActivityAt"
        : msToTimestamp(agent.updatedAt) ? "roster agent.updatedAt"
          : msToTimestamp(agent.createdAt) ? "roster agent.createdAt" : "unavailable",
      role: "metadata",
      recordType: "agent_roster",
      summary: `Agent "${name || id}"${agent.title ? ` — ${agent.title}` : ""}`
        + `${agent.description ? `: ${truncateSummary(String(agent.description)).slice(0, 160)}` : ""}`
        + `; origin ${agent.origin ?? "?"}${agent.isGroup ? ", group" : ""}`
        + `${msToTimestamp(agent.createdAt) ? `; created ${msToTimestamp(agent.createdAt)}` : ""}`,
      fullText: safeJson({
        agentId: id,
        name,
        title: agent.title,
        description: agent.description,
        origin: agent.origin,
        isGroup: agent.isGroup === true,
        memberCount: Array.isArray(agent.memberIds) ? agent.memberIds.length : 0,
        path: workspace,
        createdAt: msToTimestamp(agent.createdAt) || null,
        updatedAt: msToTimestamp(agent.updatedAt) || null,
        lastActivityAt: msToTimestamp(agent.lastActivityAt) || null,
        lastViewedAt: msToTimestamp(agent.lastViewedAt) || null,
        lastEntry: lastEntry ? { kind: lastEntry.kind, text: textOf(lastEntry.text).slice(0, 500) } : null,
        unreadCount: agent.unreadCount,
        isHiddenFromSidebar: agent.isHiddenFromSidebar,
        notificationsEnabled: agent.notificationsEnabled,
        accountScope: info.account,
      }),
      sessionId: id,
      workspace,
      toolDescription: "A Grok Bot agent on the user's roster: a persistent cloud-hosted agent with its "
        + "own box. Timestamp is its last activity (else last update, else creation). `path` is the "
        + "agent's working directory on its box, not a folder on this machine.",
      sourceFile: filePath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return { rows, agents };
}

function transcriptEntryRow(entry, ctx) {
  if (!entry || typeof entry !== "object") return null;
  const kind = String(entry.kind || "");
  const base = {
    timestamp: msToTimestamp(entry.timestampMs),
    timestampBasis: msToTimestamp(entry.timestampMs) ? "entry.timestampMs" : "unavailable",
    sessionId: ctx.agentId,
    messageId: entry.id != null ? String(entry.id) : "",
    parentId: entry.requestId != null ? String(entry.requestId)
      : entry.replyTo != null ? String(entry.replyTo) : "",
    workspace: ctx.workspace,
    sourceFile: ctx.filePath,
    user: ctx.attribution.user || "",
    host: ctx.attribution.host || "",
  };

  if (kind === "message") {
    const text = textOf(entry.content) || textOf(entry.richText);
    if (!text.trim()) return null;
    const role = entry.role != null ? String(entry.role) : "user";
    return botRow({
      ...base,
      role,
      recordType: role === "user" ? "user" : "message",
      summary: text,
      fullText: Object.values(entryRelationshipDetail(entry)).some((v) => v != null)
        ? `${text}\n\n${safeJson({ relationships: entryRelationshipDetail(entry), richText: entry.richText ?? null, reactions: entry.reactions ?? null })}`
        : text,
    });
  }

  if (kind === "tool-call") {
    const tool = entry.tool && typeof entry.tool === "object" ? entry.tool : {};
    const name = String(entry.toolName ?? entry.name ?? tool.name ?? "tool-call");
    const status = entry.status == null ? "unknown" : String(entry.status);
    const command = entry.command == null ? "" : String(entry.command);
    const input = entry.input ?? entry.arguments ?? entry.args ?? tool.input ?? tool.arguments ?? null;
    const inputText = typeof input === "string" ? input : input == null ? "" : safeJson(input);
    return botRow({
      ...base,
      role: "tool",
      recordType: "tool_call",
      summary: `[Tool call ${status}] ${name}${command ? ` — ${command}` : inputText ? ` — ${truncateSummary(inputText)}` : ""}`,
      fullText: safeJson({ nativeEntry: entry, normalized: { toolName: name, status, command: command || null, input: input ?? null } }),
      toolName: name,
      toolCommand: command,
      toolInput: command ? "" : inputText,
      toolDescription: "Cloud-agent transcript tool-call state. The native status is retained; this row alone does not establish execution on the local endpoint or a successful result.",
    });
  }

  if (kind === "notice") {
    const noticeText = textOf(entry.notice ?? entry.content ?? entry.message ?? entry.text) || truncateSummary(safeJson(entry));
    return botRow({
      ...base,
      role: "system",
      recordType: "notice",
      summary: `[Notice] ${noticeText}`,
      fullText: safeJson(entry),
      toolDescription: "Notice recorded in the retained Grok Bot transcript, with reply and channel relationships preserved when present.",
    });
  }

  if (kind === "send-message") {
    const msg = entry.message && typeof entry.message === "object" ? entry.message : {};
    const type = String(msg.type || "text");
    const text = textOf(msg.content ?? msg);
    const responded = entry.respondedValue != null ? String(entry.respondedValue) : "";
    const skipped = entry.widgetSkipped === true;
    const detail = {
      messageType: type,
      boxInstruction: entry.boxInstruction ?? null,
      boxRequestId: entry.boxRequestId ?? null,
      boxResolution: entry.boxResolution ?? null,
      respondedValue: entry.respondedValue ?? null,
      widgetSkipped: entry.widgetSkipped ?? null,
      batchId: entry.batchId ?? null,
    };
    const hasBox = entry.boxInstruction != null || entry.boxResolution != null;

    if (type === "local-tool-permission") {
      // Newer builds carry a structured `ask`: { action: "run-command" | "read-file" | …, target,
      // machineId, machineLabel, status }. `target` is the exact command line or file path.
      const ask = msg.ask && typeof msg.ask === "object" ? msg.ask : null;
      const action = ask?.action != null ? String(ask.action) : "";
      const target = ask?.target != null ? String(ask.target) : "";
      const machine = ask?.machineLabel != null ? String(ask.machineLabel)
        : ask?.machineId != null ? String(ask.machineId) : "";
      const status = ask?.status != null ? String(ask.status) : "";
      const nativeRequestId = ask?.requestId != null ? String(ask.requestId)
        : entry.requestId != null ? String(entry.requestId) : "";
      const permission = normalizePermissionEvidence(ask, entry.respondedValue, skipped);
      ctx.onPermission?.(permission);
      const askText = ask
        ? `${action || "local tool"}${machine ? ` on ${machine}` : ""}${status ? ` (${status})` : ""}: ${target}`
        : (text || "agent requested to run a tool on this machine");
      return botRow({
        ...base,
        parentId: nativeRequestId,
        role: "system",
        recordType: "local_tool_permission_request",
        summary: `[Local tool request] ${truncateSummary(askText)} — permission state ${permission.permissionState}; execution not established`,
        fullText: safeJson({
          request: {
            requestId: nativeRequestId || null,
            action: action || null,
            target: target || null,
            machineId: ask?.machineId ?? null,
            machineLabel: ask?.machineLabel ?? null,
          },
          decision: permission,
          native: { ...detail, ask: ask || null },
        }),
        toolName: action || "local-exec",
        toolCommand: action === "run-command" ? target : "",
        toolInput: action && action !== "run-command" ? target : "",
        toolDescription: "A cloud agent requested a local tool action. ToolCommand or ToolInput keeps "
          + "the recorded target. permissionState distinguishes pending, allowed, persistent policy, "
          + "denied, expired, cancelled and unknown states. A request or approval record does not prove "
          + "that this machine received, executed or successfully completed the action; an explicit "
          + "same-scope result ID is required for that conclusion.",
      });
    }
    if (type === "widget") {
      const widget = msg.widget && typeof msg.widget === "object" ? msg.widget : null;
      const options = Array.isArray(widget?.options) ? widget.options : [];
      const labels = options.map((o) => (o && typeof o === "object" ? textOf(o.label ?? o.value) : textOf(o))).filter(Boolean);
      const widgetText = widget
        ? `${textOf(widget.prompt)}${labels.length ? ` [${labels.join(" | ")}]` : ""}`
        : text;
      return botRow({
        ...base,
        role: "assistant",
        recordType: "agent_widget",
        summary: `[Widget] ${truncateSummary(widgetText)}${responded ? ` → responded: ${responded}` : skipped ? " → skipped" : ""}`,
        fullText: `${widgetText}${widget?.helpText ? `\n${textOf(widget.helpText)}` : ""}\n\n${safeJson({ ...detail, widget: widget || null })}`,
        toolDescription: "Interactive prompt (choice/confirmation) the agent showed the user; "
          + "respondedValue is what the user picked.",
      });
    }
    if (["auto-review-approval", "cookie-origin-approval", "virtual-card-approval"].includes(type)) {
      const approval = msg.approval && typeof msg.approval === "object" ? msg.approval : {};
      const approvalRequestId = approval.requestId != null ? String(approval.requestId) : "";
      const approvalStatus = approval.status != null ? String(approval.status) : "unknown";
      const command = approval.command != null ? String(approval.command) : "";
      const origins = Array.isArray(approval.origins) ? approval.origins.map(String) : [];
      return botRow({
        ...base,
        parentId: approvalRequestId || base.parentId,
        role: "system",
        recordType: type.replace(/-/g, "_"),
        summary: `[${type}] ${approvalStatus}${command ? ` — ${truncateSummary(command)}` : origins.length ? ` — ${origins.join(", ")}` : text ? ` — ${truncateSummary(text)}` : ""}`,
        fullText: safeJson({ approval, interaction: detail, executionObserved: false, executionOutcome: "unknown" }),
        toolName: type,
        toolCommand: command,
        toolInput: origins.length ? origins.join("\n") : "",
        toolDescription: "Structured approval card from the transcript. Its native status and request "
          + "ID are preserved. Pending, stale, expired or denied cards are not authorization, and no "
          + "approval card alone proves that an action executed or succeeded.",
      });
    }
    if (type === "attachment") {
      const url = msg.url != null ? String(msg.url) : "";
      const fileName = msg.file_name != null ? String(msg.file_name) : "";
      const sha = contentHashFromBoxPath(url);
      const label = fileName || text || "(no description)";
      return botRow({
        ...base,
        role: "assistant",
        recordType: "agent_attachment",
        summary: `[Agent attachment] ${truncateSummary(label)}${sha ? ` — reference sha256 ${sha.slice(0, 12)}…` : ""}`,
        fullText: `${label}\n\n${safeJson({ fileName: fileName || null, url: url || null, referenceSha256: sha || null, referenceHashSource: sha ? "hash-shaped cloud box filename" : null, computedSha256: null, ...detail })}`,
        toolDescription: "A file the agent sent back. It lives on the agent's cloud box; only the "
          + "transcript reference is recorded here. A hash-shaped box filename is labelled "
          + "referenceSha256 until independently verified against recovered bytes.",
      });
    }
    // Agent screenshots of what it was looking at on its box (browser automation). The alt text
    // is the agent's own description of the image and the URL carries the content hash.
    const images = Array.isArray(msg.images) ? msg.images.filter((im) => im && typeof im === "object") : [];
    const imageLines = images.map((im) => {
      const sha = contentHashFromBoxPath(im.url);
      const ref = sha ? `reference sha256 ${sha}` : (im.url != null ? String(im.url) : "");
      return `[Agent image] ${textOf(im.alt) || "(no alt text)"}${ref ? ` — ${ref}` : ""}`;
    });
    if (!text.trim() && !hasBox && !imageLines.length) return null;
    const body = [text, ...imageLines].filter((part) => part && part.trim()).join("\n");
    const resolution = entry.boxResolution != null ? String(entry.boxResolution) : "";
    return botRow({
      ...base,
      role: "assistant",
      recordType: hasBox ? "agent_box_instruction" : "assistant",
      summary: `${hasBox ? "[Box instruction] " : ""}${text.trim() ? text : (imageLines[0] || "")}`
        + `${hasBox && resolution ? ` → ${resolution}` : ""}`,
      fullText: hasBox ? `${body}\n\n${safeJson(detail)}` : body,
      toolDescription: hasBox
        ? "The agent handed its cloud-box browser to the user for an action it could not do itself "
          + "(typically a sign-in); boxResolution says whether the user completed it (handed_back) or "
          + "dismissed it. Credentials entered there went to the box, not through this machine."
        : imageLines.length
          ? "The agent attached screenshot(s) of what it was looking at on its cloud box; alt text is "
            + "the agent's own description and the hash names the image on the box."
          : "",
    });
  }

  if (kind === "user-attachment") {
    const boxPath = entry.file_path != null ? String(entry.file_path) : "";
    const name = entry.file_name != null ? String(entry.file_name) : path.basename(boxPath);
    const dims = entry.width != null && entry.height != null ? `, ${entry.width}x${entry.height}` : "";
    const sha = contentHashFromBoxPath(boxPath);
    const byteSize = Number(entry.byteSize);
    const localCopies = ctx.findLocalCopies ? ctx.findLocalCopies(name, byteSize, sha) : [];
    // Some attachment entries carry no stamp of their own; the message sent in the same batch does.
    const batchTs = entry.batchId != null ? ctx.batchTimestamps?.get(String(entry.batchId)) || "" : "";
    const timestamp = base.timestamp || batchTs;
    const recovered = localCopies.length > 0;
    return botRow({
      ...base,
      timestamp,
      timestampBasis: base.timestamp ? "entry.timestampMs"
        : batchTs ? "timestampMs of a message in the same batch" : "unavailable",
      role: "attachment",
      recordType: "user_attachment",
      summary: `Attachment sent to agent — ${name || "(unnamed)"}`
        + `${entry.byteSize != null ? ` (${entry.byteSize} bytes${dims})` : ""}`
        + `${recovered ? ` — original verified on disk: ${localCopies[0]}` : sha && ctx.findLocalCopies ? " — no local copy found" : ""}`,
      fullText: safeJson({
        fileName: name,
        boxPath: boxPath || null,
        referenceSha256: sha || null,
        referenceHashSource: sha ? "hash-shaped cloud box filename" : null,
        computedLocalSha256: recovered ? sha : null,
        hashMatchStatus: recovered ? "reference equals computed hash of recovered local bytes"
          : sha ? "reference not independently verified" : "no hash reference available",
        byteSize: Number.isFinite(byteSize) ? byteSize : entry.byteSize ?? null,
        width: entry.width ?? null,
        height: entry.height ?? null,
        batchId: entry.batchId ?? null,
        localCopies,
        localCopyVerification: recovered ? "name + size + SHA-256 match" : ctx.findLocalCopies ? "searched, none matched" : "not searched",
        timeSource: base.timestamp ? "entry timestampMs" : batchTs ? "message sent in the same batch" : "",
      }),
      toolDescription: "A file the user uploaded to the agent. boxPath is on the agent's CLOUD box, not "
        + "this machine. A hash-shaped box filename is a referenceSha256 until recovered bytes are "
        + "independently hashed. localCopies are "
        + "files in the owning profile's Downloads/Desktop/Documents/Pictures whose name, size and "
        + "SHA-256 all match — recoverable originals. Pasted screenshots (image.png) rarely have one.",
      ...(recovered ? { toolInput: localCopies.join("\n") } : {}),
    });
  }

  if (kind === "event") {
    const ev = entry.event && typeof entry.event === "object" ? entry.event : {};
    const type = String(ev.type || "event");
    const action = ev.action != null ? String(ev.action) : "";
    const recordType = `event_${type.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}`;
    let summary;
    if (type === "automation-changed") {
      summary = `Automation ${action || "changed"} — "${ev.automationName ?? "?"}" (${ev.automationId ?? "?"})`;
    } else if (type === "name-changed") {
      summary = `Agent renamed${ev.name ? ` — "${ev.name}"` : ""}${ev.previousName ? ` (was "${ev.previousName}")` : ""}`;
    } else {
      summary = `${type}${action ? ` ${action}` : ""}`;
    }
    return botRow({
      ...base,
      role: "system",
      recordType,
      summary,
      fullText: safeJson(ev),
      toolDescription: type === "automation-changed"
        ? "Scheduled automation on a cloud agent was created/updated/enabled/deleted — a persistence "
          + "surface that keeps running after the desktop app is closed."
        : "",
    });
  }

  if (kind === "feedback") {
    return botRow({
      ...base,
      role: "metadata",
      recordType: "feedback",
      summary: `Feedback ${entry.state ?? "?"} on request ${entry.requestId ?? "?"}`,
      fullText: safeJson({ state: entry.state, requestId: entry.requestId }),
    });
  }

  return botRow({
    ...base,
    role: "system",
    recordType: kind ? `entry_${kind.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}` : "entry",
    summary: truncateSummary(safeJson(entry)),
    fullText: safeJson(entry),
  });
}

function transcriptRows(parsed, filePath, info, agents, attribution, stats, helpers = {}) {
  const value = parsed?.value && typeof parsed.value === "object" ? parsed.value : {};
  const entries = Array.isArray(value.entries) ? value.entries : [];
  const agent = agents.get(info.agentId) || { name: "", workspace: "" };
  const batchTimestamps = new Map();
  for (const entry of entries) {
    if (!entry || typeof entry !== "object" || entry.batchId == null) continue;
    const ts = msToTimestamp(entry.timestampMs);
    if (ts && !batchTimestamps.has(String(entry.batchId))) batchTimestamps.set(String(entry.batchId), ts);
  }
  const ctx = {
    agentId: info.agentId,
    workspace: agent.workspace,
    filePath,
    attribution,
    batchTimestamps,
    findLocalCopies: helpers.findLocalCopies || null,
    onPermission: (permission) => {
      const state = permission.permissionState || "unknown";
      stats.permissionStates[state] = (stats.permissionStates[state] || 0) + 1;
      if (permission.authorizationRecorded === true) stats.localToolAuthorizationsRecorded += 1;
      else if (permission.authorizationRecorded === false) stats.localToolNonAuthorizations += 1;
      else stats.localToolAuthorizationUnknown += 1;
    },
  };
  const rows = [];
  let emitted = 0;
  const selectedEntries = entries.slice(0, MAX_ENTRIES_PER_REPLICA);
  stats.transcriptSourceEntries += entries.length;
  stats.transcriptEntriesOmittedByParserLimit += entries.length - selectedEntries.length;
  selectedEntries.forEach((entry, idx) => {
    helpers.checkAbort?.();
    const row = transcriptEntryRow(entry, ctx);
    if (!row) { stats.transcriptEntriesWithoutRows += 1; return; }
    assignLineNumber(row, idx + 1);
    row.SourceOffset = `/value/entries/${idx}`;
    if (row.RecordType === "local_tool_permission_request") stats.localToolPermissionRequests += 1;
    if (row.RecordType === "user_attachment") {
      stats.attachments += 1;
      if (row.ToolInput) stats.attachmentsRecovered += 1;
    }
    rows.push(row);
    emitted += 1;
  });
  stats.transcriptEntries += emitted;

  const persisted = msToTimestamp(value.persistedAt);
  const fileSize = safeStat(filePath)?.size ?? 0;
  let retainedEntryJsonChars = 0;
  let entrySerializationFailures = 0;
  for (const entry of entries) {
    try { retainedEntryJsonChars += JSON.stringify(entry).length; } catch { entrySerializationFailures += 1; }
  }
  const atEntryCap = entries.length >= REPLICA_ENTRY_CAP;
  const nearByteCap = retainedEntryJsonChars >= REPLICA_BYTE_CAP * 0.9;
  const atByteCap = retainedEntryJsonChars >= REPLICA_BYTE_CAP;
  const retentionBoundaryObserved = atEntryCap || nearByteCap;
  if (retentionBoundaryObserved) {
    stats.replicasAtCap += 1;
    stats.replicasAtRetentionBoundary += 1;
  }
  if (atEntryCap) stats.replicasAtEntryLimit += 1;
  if (nearByteCap) stats.replicasNearByteLimit += 1;
  const timestamped = entries.map((e) => Number(e?.timestampMs)).filter((n) => Number.isFinite(n) && n >= 1e12);
  const oldestRetained = timestamped.length ? msToTimestamp(Math.min(...timestamped)) : "";
  const persistedMs = Number(value.persistedAt);
  const expiredUnderCurrentContract = Number.isFinite(persistedMs)
    && (Date.now() - persistedMs) > REPLICA_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
  if (expiredUnderCurrentContract) stats.replicasPastRestoreTtl += 1;
  rows.push(botRow({
    timestamp: persisted || formatTimestampUtc(safeStat(filePath)?.mtimeMs ?? null),
    timestampBasis: persisted ? "replica.persistedAt" : "source file mtime",
    role: "metadata",
    recordType: "transcript_replica",
    summary: `Transcript replica for agent "${agent.name || info.agentId}" — ${entries.length} entr${entries.length === 1 ? "y" : "ies"}`
      + `${persisted ? `, persisted ${persisted}` : ""}`
      + `${atEntryCap ? ` — AT THE ${REPLICA_ENTRY_CAP}-ENTRY RETENTION LIMIT; earlier history availability unknown` : nearByteCap ? ` — near the ${REPLICA_BYTE_CAP / 1024} KB serialized-entry limit; earlier history availability unknown` : ""}`
      + `${expiredUnderCurrentContract ? ` — persistedAt exceeds the ${REPLICA_MAX_AGE_DAYS}-day restore TTL` : ""}`
      + `${oldestRetained ? `; oldest retained ${oldestRetained}` : ""}`,
    fullText: safeJson({
      agentId: info.agentId,
      agentName: agent.name,
      accountScope: info.account,
      entryCount: entries.length,
      emittedRows: emitted,
      persistedAt: persisted || null,
      oldestRetainedEntry: oldestRetained || null,
      fileBytes: fileSize,
      retainedEntryJsonChars,
      entrySerializationFailures,
      atEntryCap,
      atByteCap,
      nearByteCap,
      retentionBoundaryObserved,
      historicalDeletionProven: false,
      earlierHistoryAvailability: retentionBoundaryObserved ? "unknown; retention boundary observed" : "unknown; this is a bounded client replica",
      expiredUnderCurrentContract,
      parserEntryLimit: MAX_ENTRIES_PER_REPLICA,
      parserEntriesOmitted: entries.length - selectedEntries.length,
      retention: {
        maxEntries: REPLICA_ENTRY_CAP,
        maxSerializedEntryChars: REPLICA_BYTE_CAP,
        serializedSizeMeasurement: "sum of JSON.stringify(entry).length",
        maxAgentsPerAccount: REPLICA_MAX_AGENTS,
        maxAgeDays: REPLICA_MAX_AGE_DAYS,
        verifiedIn: "Grok Bot 0.43.0 renderer bundle",
      },
      epochHint: value.epochHint ?? null,
      acceptedSequenceHint: value.acceptedSequenceHint ?? null,
      schemaVersion: parsed?.schemaVersion ?? null,
    }),
    sessionId: info.agentId,
    workspace: agent.workspace,
    toolDescription: "Client-side replica of a cloud-hosted agent transcript: what this desktop had "
      + `synced at persistedAt. ${REPLICA_RETENTION_NOTE} A retention boundary means earlier local `
      + "history may be unavailable; it does not prove that a specific earlier entry existed or was "
      + "deleted. oldestRetainedEntry is the start of the observed surviving window. Acquire this folder "
      + "before launching the app, and re-acquire on a schedule to extend coverage.",
    sourceFile: filePath,
    lineNumber: 1,
    user: attribution.user || "",
    host: attribution.host || "",
  }));
  return rows;
}

function draftRows(parsed, filePath, info, agents, attribution) {
  const drafts = parsed?.value?.agents;
  if (!drafts || typeof drafts !== "object") return [];
  const st = safeStat(filePath);
  const rows = [];
  for (const [agentId, draft] of Object.entries(drafts)) {
    const text = textOf(draft?.text ?? draft?.content ?? draft?.richText ?? draft);
    if (!text.trim()) continue;
    const agent = agents.get(agentId) || { name: "", workspace: "" };
    rows.push(botRow({
      timestamp: msToTimestamp(draft?.updatedAt) || msToTimestamp(draft?.timestampMs)
        || formatTimestampUtc(st?.mtimeMs ?? null),
      timestampBasis: msToTimestamp(draft?.updatedAt) ? "draft.updatedAt"
        : msToTimestamp(draft?.timestampMs) ? "draft.timestampMs" : "source file mtime",
      role: "user",
      recordType: "composer_draft",
      summary: `[Unsent draft to "${agent.name || agentId}"] ${text}`,
      fullText: text,
      sessionId: agentId,
      workspace: agent.workspace,
      toolDescription: "Prompt text typed but not sent. Dated from the draft's own stamp when present, "
        + "else the slice file mtime.",
      sourceFile: filePath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function sendJournalRows(parsed, filePath, info, attribution, stats = null) {
  const records = parsed?.value?.records;
  const schemaVersion = parsed?.schemaVersion;
  const schemaQualified = schemaVersion === 1 || schemaVersion === 2;
  if (stats) {
    stats.sendJournalFiles += 1;
    const schemaKey = String(schemaVersion ?? "unknown");
    stats.sendJournalSchemaVersions[schemaKey] = (stats.sendJournalSchemaVersions[schemaKey] || 0) + 1;
    if (!schemaQualified) stats.sendJournalUnknownSchema += 1;
  }
  if (!Array.isArray(records)) {
    return [];
  }
  if (!records.length) {
    if (stats) stats.emptySendJournals += 1;
    return [];
  }
  const st = safeStat(filePath);
  const selected = records.slice(0, MAX_ENTRIES_PER_REPLICA);
  if (stats) {
    stats.sendJournalRecords += records.length;
    stats.sendJournalRecordsOmittedByParserLimit += records.length - selected.length;
  }
  return selected.map((rec, idx) => {
    const input = rec?.input && typeof rec.input === "object" ? rec.input : null;
    const isNativeJournal = !!(rec && typeof rec === "object" && rec.nonce && input);
    const phase = rec?.phase != null ? String(rec.phase) : rec?.status != null ? String(rec.status) : "unknown";
    const prompt = input ? textOf(input.prompt) : textOf(rec?.message ?? rec?.text ?? rec?.prompt);
    const messageId = rec?.nonce != null ? String(rec.nonce) : rec?.id != null ? String(rec.id) : "";
    const agentId = rec?.agentId != null ? String(rec.agentId)
      : input?.agentId != null ? String(input.agentId) : info?.agentId || "";
    const parentId = input?.replyToId != null ? String(input.replyToId)
      : rec?.authoredThreadRootId != null ? String(rec.authoredThreadRootId) : "";
    const createdAt = msToTimestamp(rec?.createdAtMs);
    const legacyTimestamp = msToTimestamp(rec?.timestampMs) || msToTimestamp(rec?.ts);
    const timestamp = createdAt || legacyTimestamp || formatTimestampUtc(st?.mtimeMs ?? null);
    const validationIssues = [];
    if (schemaVersion === 2) {
      if (!rec?.nonce || typeof rec.nonce !== "string") validationIssues.push("nonce");
      if (!rec?.agentId || typeof rec.agentId !== "string") validationIssues.push("agentId");
      if (rec?.accountSlot !== info?.account) validationIssues.push("accountSlot");
      if (!Number.isFinite(rec?.createdAtMs)) validationIssues.push("createdAtMs");
      if (!["prepared", "queued", "dispatching", "accepted-awaiting-echo"].includes(rec?.phase)) validationIssues.push("phase");
      if (!input || typeof input.prompt !== "string" || input.agentId !== rec.agentId) validationIssues.push("input");
      if (!Array.isArray(input?.attachmentPaths) || !Array.isArray(input?.attachmentNames)
        || input.attachmentPaths.length !== input.attachmentNames.length) validationIssues.push("input attachments");
      if (!Array.isArray(rec?.attachments)) validationIssues.push("attachments");
      else if (rec.phase !== "queued" && rec.attachments.some((a) => typeof a?.committedPath !== "string")) {
        validationIssues.push("committedPath");
      }
    }
    const normalized = {
      schemaVersion: schemaVersion ?? null,
      schemaQualified,
      recordQualified: schemaVersion === 2 ? validationIssues.length === 0 : null,
      validationIssues,
      nonce: rec?.nonce ?? null,
      priorNonces: Array.isArray(rec?.priorNonces) ? rec.priorNonces : null,
      accountSlot: rec?.accountSlot ?? info?.account ?? null,
      agentId: agentId || null,
      digest: rec?.digest ?? null,
      phase,
      prompt: prompt || null,
      richText: input?.richText ?? null,
      replyToId: input?.replyToId ?? null,
      isFork: input?.isFork ?? null,
      sessionId: input?.sessionId ?? null,
      automationWriteProvenance: input?.automationWriteProvenance ?? null,
      attachmentPaths: Array.isArray(input?.attachmentPaths) ? input.attachmentPaths : null,
      attachmentNames: Array.isArray(input?.attachmentNames) ? input.attachmentNames : null,
      attachments: Array.isArray(rec?.attachments) ? rec.attachments.map((a) => ({
        stagedPath: a?.stagedPath ?? null,
        committedPath: a?.committedPath ?? null,
        name: a?.name ?? null,
      })) : null,
      draftRecovery: rec?.draftRecovery ?? null,
      authoredThreadRootId: rec?.authoredThreadRootId ?? null,
      consumedDraftId: rec?.consumedDraftId ?? null,
      createdAtMs: rec?.createdAtMs ?? null,
      createdAt: createdAt || null,
      queuedAtMs: rec?.queuedAtMs ?? null,
      queuedAt: msToTimestamp(rec?.queuedAtMs) || null,
      firstFlushAtMs: rec?.firstFlushAtMs ?? null,
      firstFlushAt: msToTimestamp(rec?.firstFlushAtMs) || null,
      ackTimeoutStartedAtMs: rec?.ackTimeoutStartedAtMs ?? null,
      ackTimeoutStartedAt: msToTimestamp(rec?.ackTimeoutStartedAtMs) || null,
      failedAtMs: rec?.failedAtMs ?? null,
      failedAt: msToTimestamp(rec?.failedAtMs) || null,
    };
    if (stats) {
      stats.sendJournalByPhase[phase] = (stats.sendJournalByPhase[phase] || 0) + 1;
      if (!isNativeJournal) stats.sendJournalLegacyOrUnknownRecords += 1;
      if (schemaVersion === 2 && validationIssues.length) stats.sendJournalMalformedRecords += 1;
    }
    const failure = normalized.failedAt ? `; failed ${normalized.failedAt}` : "";
    const row = assignLineNumber(botRow({
      timestamp,
      timestampBasis: createdAt ? "send-journal.createdAtMs"
        : legacyTimestamp ? "legacy send-journal timestamp" : "source file mtime",
      role: "metadata",
      recordType: "send_journal",
      summary: `Send journal ${phase} — ${truncateSummary(prompt || "(prompt unavailable)")}${failure}`,
      fullText: safeJson({ normalized, nativeRecord: rec }),
      sessionId: agentId,
      messageId,
      parentId,
      toolName: "send-journal",
      toolInput: Array.isArray(input?.attachmentPaths) ? input.attachmentPaths.join("\n") : "",
      toolDescription: `${schemaQualified ? "Qualified" : "Unqualified schema; raw-preserved"} client-persisted outbound send state. Native nonce, phase, prompt, reply/fork/session `
        + "links, attachment staging mappings and lifecycle timestamps are preserved. queued, dispatching "
        + "or accepted-awaiting-echo do not independently prove server delivery or transcript echo.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }), idx + 1);
    row.SourceOffset = `/value/records/${idx}`;
    return row;
  });
}

/** All rows from the persistence directory. The roster is read first so transcripts can be named. */
function persistenceRows(rootDir, attribution, stats, progress, options = {}) {
  const dir = path.join(rootDir, PERSISTENCE_DIR);
  if (!safeIsDirectory(dir)) return [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }

  const blobs = [];
  const inventory = [];
  for (const e of entries) {
    if (!e.isFile() || !/\.blob$/i.test(e.name)) continue;
    stats.persistenceBlobsSeen += 1;
    const filePath = path.join(dir, e.name);
    const sliceName = decodeSliceBlobName(e.name);
    const info = classifySliceName(sliceName);
    if (!info) {
      stats.persistenceBlobsUnknown += 1;
      const row = inventoryRow(filePath, "persistence_blob_inventory", "Unknown Grok Bot persistence blob", "INVENTORY ONLY. The filename could not be decoded/classified; content was not read.", attribution, { detail: { classification: "unknown" } });
      if (row) inventory.push(row);
      continue;
    }
    if (info.kind === "ui") {
      stats.persistenceBlobsExcludedUi += 1;
      const row = inventoryRow(filePath, "persistence_blob_inventory", "Excluded Grok Bot UI/state slice", "INVENTORY ONLY. The slice name was decoded, but the low-value UI/state body is outside the transcript parser scope.", attribution, { detail: { classification: "excluded-ui", sliceName } });
      if (row) inventory.push(row);
      continue;
    }
    stats.persistenceBlobsEligible += 1;
    blobs.push({ filePath, sliceName, info });
  }
  const order = { roster: 0, transcript: 1, drafts: 2, "send-journal": 3 };
  blobs.sort((a, b) => (order[a.info.kind] - order[b.info.kind]) || a.filePath.localeCompare(b.filePath));

  const rows = [...inventory];
  stats.inventoryOnly += inventory.length;
  const agents = new Map();
  const helpers = {
    findLocalCopies: createLocalAttachmentFinder([rootDir], {
      includeUserFolders: !!options.findLocalAttachments,
      home: userHomeForGrokBotRoot(rootDir),
      checkAbort: options.checkAbort,
    }),
    checkAbort: options.checkAbort,
  };
  for (const blob of blobs) {
    progress?.(blob.filePath);
    const parsed = readJsonBounded(blob.filePath);
    if (!parsed || typeof parsed !== "object") {
      stats.unreadableBlobs += 1;
      const row = inventoryRow(blob.filePath, "persistence_blob_unreadable", "Unreadable Grok Bot persistence slice", `INVENTORY ONLY. The qualified ${blob.info.kind} slice was malformed, unreadable, or exceeded the ${MAX_JSON_BYTES}-byte JSON limit; content was not decoded.`, attribution, { detail: { sliceName: blob.sliceName, kind: blob.info.kind } });
      if (row) { rows.push(row); stats.inventoryOnly += 1; }
      continue;
    }
    try {
      if (blob.info.kind === "roster") {
        const r = rosterRows(parsed, blob.filePath, blob.info, attribution);
        for (const [id, a] of r.agents) agents.set(id, a);
        stats.agents += r.agents.size;
        rows.push(...r.rows);
      } else if (blob.info.kind === "transcript") {
        stats.transcripts += 1;
        rows.push(...transcriptRows(parsed, blob.filePath, blob.info, agents, attribution, stats, helpers));
      } else if (blob.info.kind === "drafts") {
        const d = draftRows(parsed, blob.filePath, blob.info, agents, attribution);
        stats.drafts += d.length;
        rows.push(...d);
      } else if (blob.info.kind === "send-journal") {
        rows.push(...sendJournalRows(parsed, blob.filePath, blob.info, attribution, stats));
      }
    } catch (e) {
      stats.persistenceBlobFailures += 1;
      const row = inventoryRow(blob.filePath, "persistence_blob_parse_failure", "Grok Bot persistence slice parse failure", "INVENTORY ONLY. JSON was readable but the qualified decoder failed; preserve the original for a newer decoder.", attribution, { detail: { sliceName: blob.sliceName, kind: blob.info.kind, error: String(e.message || e).slice(0, 300) } });
      if (row) { rows.push(row); stats.inventoryOnly += 1; }
      dbg("AIHIST", "grok bot slice failed", { path: blob.filePath, err: e.message });
    }
  }
  if (helpers.findLocalCopies?.getStats) stats.attachmentRecovery = helpers.findLocalCopies.getStats();
  return rows;
}

/* ------------------------------------------------------- app identity + link cache */

/**
 * sentry/scope_v3.json + sentry/session.json + Chromium "Local State" — written by the app's crash
 * reporter and profile, not by the chat. They carry the signed-in account (id + email), version,
 * host OS/hardware, timezone, boot/app-start times and the agent that was open: attribution
 * evidence that survives even when every transcript replica has been pruned.
 */
function appIdentityRows(rootDir, attribution) {
  const rows = [];
  const scopePath = path.join(rootDir, SENTRY_DIR, SENTRY_SCOPE_FILE);
  const scope = readJsonBounded(scopePath);
  if (scope && typeof scope === "object") {
    const inner = scope.scope && typeof scope.scope === "object" ? scope.scope : {};
    const user = inner.user && typeof inner.user === "object" ? inner.user : {};
    const tags = inner.tags && typeof inner.tags === "object" ? inner.tags : {};
    const ctxs = scope.event?.contexts && typeof scope.event.contexts === "object" ? scope.event.contexts : {};
    const app = ctxs.app && typeof ctxs.app === "object" ? ctxs.app : {};
    const osCtx = ctxs.os && typeof ctxs.os === "object" ? ctxs.os : {};
    const device = ctxs.device && typeof ctxs.device === "object" ? ctxs.device : {};
    const culture = ctxs.culture && typeof ctxs.culture === "object" ? ctxs.culture : {};
    const appStart = isoToTimestamp(app.app_start_time);
    const conversationId = tags["sand.conversation_id"] != null ? String(tags["sand.conversation_id"]) : "";
    const version = app.app_version ?? scope.event?.release ?? "?";
    rows.push(botRow({
      timestamp: appStart || formatTimestampUtc(safeStat(scopePath)?.mtimeMs ?? null),
      timestampBasis: appStart ? "Sentry app.app_start_time" : "source file mtime",
      role: "metadata",
      recordType: "app_identity",
      summary: `Grok Bot ${version} signed in as ${user.email || user.id || "?"}`
        + `${osCtx.name ? ` on ${osCtx.name}${osCtx.version ? ` ${osCtx.version}` : ""}` : ""}`
        + `${culture.timezone ? `, timezone ${culture.timezone}` : ""}`
        + `${conversationId ? `; last open agent ${conversationId}` : ""}`,
      fullText: safeJson({
        accountId: user.id ?? null,
        email: user.email ?? null,
        lastConversationId: conversationId || null,
        appVersion: app.app_version ?? null,
        release: scope.event?.release ?? null,
        appArch: app.app_arch ?? tags.app_flavor ?? null,
        appStartTime: appStart || null,
        deviceBootTime: isoToTimestamp(device.boot_time) || null,
        os: { name: osCtx.name ?? null, version: osCtx.version ?? null, build: osCtx.build ?? null, kernel: osCtx.kernel_version ?? null },
        device: { arch: device.arch ?? null, cpu: device.cpu_description ?? null, processors: device.processor_count ?? null,
          memoryBytes: device.memory_size ?? null, screen: device.screen_resolution ?? null },
        timezone: culture.timezone ?? null,
        locale: culture.locale ?? null,
        electron: ctxs.runtime?.version ?? null,
        chrome: ctxs.chrome?.version ?? null,
        node: ctxs.node?.version ?? null,
        timeSource: appStart ? "app_start_time" : "file mtime",
      }),
      sessionId: conversationId,
      toolDescription: "Crash-reporter scope written by the app: the signed-in account (id + email), "
        + "app version, host OS/hardware, timezone, the last boot and app-start times, and the agent "
        + "that was open. Attribution evidence that outlives the transcript replicas; nothing here is a credential.",
      sourceFile: scopePath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  const sessPath = path.join(rootDir, SENTRY_DIR, SENTRY_SESSION_FILE);
  const sess = readJsonBounded(sessPath);
  if (sess && typeof sess === "object") {
    const started = secToTimestamp(sess.started);
    const last = secToTimestamp(sess.timestamp);
    rows.push(botRow({
      timestamp: started || formatTimestampUtc(safeStat(sessPath)?.mtimeMs ?? null),
      timestampBasis: started ? "Sentry session started" : "source file mtime",
      role: "system",
      recordType: "app_crash_reporter_session",
      summary: `Grok Bot crash-reporter session ${sess.status ?? "?"} — ${sess.release ?? "?"}`
        + `${last ? `, last update ${last}` : ""}${Number(sess.errors) > 0 ? `, ${sess.errors} error(s)` : ""}`,
      fullText: safeJson({
        sessionId: sess.sid ?? null,
        accountId: sess.did ?? null,
        release: sess.release ?? null,
        status: sess.status ?? null,
        started: started || null,
        lastUpdate: last || null,
        durationSeconds: sess.duration ?? null,
        errors: sess.errors ?? null,
      }),
      messageId: sess.sid != null ? String(sess.sid) : "",
      toolDescription: "Sentry session record: `started` and `timestamp` bracket an app run "
        + "independently of sand-session-marker.json; `did` is the signed-in account id.",
      sourceFile: sessPath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  const localStatePath = path.join(rootDir, LOCAL_STATE_FILE);
  const localState = readJsonBounded(localStatePath);
  const installed = secToTimestamp(localState?.uninstall_metrics?.installation_date2);
  if (installed) {
    rows.push(botRow({
      timestamp: installed,
      timestampBasis: "Chromium profile uninstall_metrics.installation_date2",
      role: "system",
      recordType: "app_profile_created",
      summary: `Grok Bot Chromium profile creation stamp ${installed}`,
      fullText: safeJson({ profileCreatedAt: installed, source: "Local State -> uninstall_metrics.installation_date2", applicationInstallTimeProven: false }),
      toolDescription: "Chromium profile creation evidence. It does not conclusively establish the first "
        + "application installation time and may move with a copied or restored profile.",
      sourceFile: localStatePath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/**
 * link-preview-cache/link-cache/<sha>.json — cached unfurl metadata. One row per valid cache record;
 * image/favicon data URLs are never copied.
 */
function linkPreviewRows(rootDir, attribution, stats) {
  const dir = path.join(rootDir, LINK_CACHE_PARENT, LINK_CACHE_DIR_NAME);
  if (!safeIsDirectory(dir)) return [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
  const rows = [];
  const eligible = entries.filter((e) => e.isFile() && /\.json$/i.test(e.name))
    .sort((a, b) => a.name.localeCompare(b.name));
  if (stats) {
    stats.linkPreviewFiles += eligible.length;
    stats.linkPreviewsOmittedByParserLimit += Math.max(0, eligible.length - MAX_LINK_PREVIEWS);
  }
  for (const e of eligible.slice(0, MAX_LINK_PREVIEWS)) {
    const full = path.join(dir, e.name);
    const d = readJsonBounded(full);
    if (!d || typeof d !== "object" || typeof d.url !== "string" || !d.url) {
      if (stats) stats.linkPreviewUnreadableOrInvalid += 1;
      continue;
    }
    const fetched = msToTimestamp(d.fetchedAt);
    const title = textOf(d.title);
    rows.push(botRow({
      timestamp: fetched || formatTimestampUtc(safeStat(full)?.mtimeMs ?? null),
      timestampBasis: fetched ? "link preview fetchedAt" : "link preview cache file mtime",
      role: "system",
      recordType: "link_preview",
      summary: `Link preview ${fetched ? "fetched" : "cached (fetch time unavailable)"} — ${title ? `${title} (${d.url})` : d.url}`,
      fullText: safeJson({
        url: d.url,
        canonicalUrl: d.canonicalUrl ?? null,
        title: title || null,
        description: textOf(d.description) || null,
        siteName: textOf(d.siteName) || null,
        hostname: d.hostname ?? hostOnly(d.url) ?? null,
        fetchedAt: fetched || null,
        cacheVersion: d.cacheVersion ?? null,
        hasImage: !!d.imageDataUrl,
        hasFavicon: !!d.faviconDataUrl,
        timeSource: fetched ? "fetchedAt" : "file mtime",
      }),
      toolDescription: "Cached unfurl metadata for a URL associated with Grok Bot. fetchedAt records "
        + "the preview fetch time when present; the cache alone does not prove a user click, a rendered "
        + "view, or successful access to the destination page.",
      sourceFile: full,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  if (stats) stats.linkPreviews += rows.length;
  return rows;
}

/* ------------------------------------------------------------------ orchestration */

function emptyStats() {
  return {
    roots: [],
    perRoot: [],
    daemonRoot: false,
    appRoot: false,
    agents: 0,
    transcripts: 0,
    transcriptSourceEntries: 0,
    transcriptEntries: 0,
    transcriptEntriesWithoutRows: 0,
    transcriptEntriesOmittedByParserLimit: 0,
    localToolPermissionRequests: 0,
    localToolAuthorizationsRecorded: 0,
    localToolNonAuthorizations: 0,
    localToolAuthorizationUnknown: 0,
    permissionStates: {},
    drafts: 0,
    daemonLogRows: 0,
    daemonLogFiles: 0,
    daemonLogBytes: 0,
    daemonLogBytesRead: 0,
    daemonLogBytesOmitted: 0,
    daemonLogLinesRead: 0,
    daemonLogDetailCandidates: 0,
    daemonLogDetailRows: 0,
    daemonLogDetailRowsOmitted: 0,
    daemonLogsReadCapped: 0,
    inventoryOnly: 0,
    unreadableBlobs: 0,
    replicasAtCap: 0,
    replicasAtRetentionBoundary: 0,
    replicasAtEntryLimit: 0,
    replicasNearByteLimit: 0,
    replicasPastRestoreTtl: 0,
    attachments: 0,
    attachmentsRecovered: 0,
    attachmentRecovery: null,
    linkPreviews: 0,
    linkPreviewFiles: 0,
    linkPreviewsOmittedByParserLimit: 0,
    linkPreviewUnreadableOrInvalid: 0,
    persistenceBlobsSeen: 0,
    persistenceBlobsEligible: 0,
    persistenceBlobsExcludedUi: 0,
    persistenceBlobsUnknown: 0,
    persistenceBlobFailures: 0,
    sendJournalFiles: 0,
    emptySendJournals: 0,
    sendJournalRecords: 0,
    sendJournalRecordsOmittedByParserLimit: 0,
    sendJournalLegacyOrUnknownRecords: 0,
    sendJournalMalformedRecords: 0,
    sendJournalUnknownSchema: 0,
    sendJournalByPhase: {},
    sendJournalSchemaVersions: {},
  };
}

function mergeGrokBotStats(a, b) {
  const left = a || emptyStats();
  const right = b || emptyStats();
  const out = emptyStats();
  out.daemonRoot = !!(left.daemonRoot || right.daemonRoot);
  out.appRoot = !!(left.appRoot || right.appRoot);
  const numberFields = Object.keys(out).filter((key) => typeof out[key] === "number");
  for (const key of numberFields) out[key] = Number(left[key] || 0) + Number(right[key] || 0);
  for (const key of ["permissionStates", "sendJournalByPhase", "sendJournalSchemaVersions"]) {
    for (const source of [left[key] || {}, right[key] || {}]) {
      for (const [name, count] of Object.entries(source)) out[key][name] = (out[key][name] || 0) + Number(count || 0);
    }
  }
  out.roots = [...new Set([...(left.roots || []), ...(right.roots || [])])].sort();
  const perRoot = [...(left.perRoot || []), ...(right.perRoot || [])];
  out.perRoot = [...new Map(perRoot.map((item) => [`${item.host || ""}\0${item.user || ""}\0${item.path}`, item])).values()]
    .sort((x, y) => `${x.host || ""}\0${x.user || ""}\0${x.path}`.localeCompare(`${y.host || ""}\0${y.user || ""}\0${y.path}`));
  const recovery = [left.attachmentRecovery, right.attachmentRecovery].filter(Boolean);
  if (recovery.length) {
    out.attachmentRecovery = {
      searchEnabled: recovery.some((r) => r.searchEnabled),
      includeUserFolders: recovery.some((r) => r.includeUserFolders),
      roots: [...new Set(recovery.flatMap((r) => r.roots || []))].sort(),
      directoriesVisited: recovery.reduce((n, r) => n + Number(r.directoriesVisited || 0), 0),
      directoryLimitReached: recovery.some((r) => r.directoryLimitReached),
      filesIndexed: recovery.reduce((n, r) => n + Number(r.filesIndexed || 0), 0),
      hashCandidates: recovery.reduce((n, r) => n + Number(r.hashCandidates || 0), 0),
      hashCandidatesOmitted: recovery.reduce((n, r) => n + Number(r.hashCandidatesOmitted || 0), 0),
      matches: recovery.reduce((n, r) => n + Number(r.matches || 0), 0),
    };
  }
  return out;
}

function attachPerRootStats(stats, rootDir, attribution = {}) {
  const resolved = path.resolve(rootDir);
  stats.roots = [resolved];
  stats.perRoot = [{
    path: resolved,
    user: attribution.user || "",
    host: attribution.host || "",
    type: stats.daemonRoot ? "daemon" : stats.appRoot ? "application" : "unknown",
    agents: stats.agents,
    transcripts: stats.transcripts,
    transcriptSourceEntries: stats.transcriptSourceEntries,
    transcriptEntries: stats.transcriptEntries,
    localToolPermissionRequests: stats.localToolPermissionRequests,
    daemonLogLinesRead: stats.daemonLogLinesRead,
    daemonLogDetailRowsOmitted: stats.daemonLogDetailRowsOmitted,
    persistenceBlobsSeen: stats.persistenceBlobsSeen,
    persistenceBlobsEligible: stats.persistenceBlobsEligible,
    unreadableBlobs: stats.unreadableBlobs,
    sendJournalRecords: stats.sendJournalRecords,
    linkPreviewFiles: stats.linkPreviewFiles,
  }];
}

async function extractGrokBotOneRoot(rootDir, attribution = {}, options = {}) {
  const rows = [];
  const stats = emptyStats();
  const { onFileProgress, onExtractedRows } = options;
  const files = listGrokBotDataFiles(rootDir);
  let fileIndex = 0;
  const progress = (filePath) => {
    fileIndex += 1;
    tickFileProgress(onFileProgress, fileIndex, files.length, filePath);
  };
  const emitBatch = (batch) => {
    if (!batch?.length) return;
    const filtered = filterSidechainRows(batch, options);
    if (onExtractedRows && filtered.length) onExtractedRows(filtered);
    else rows.push(...filtered);
  };
  const run = (label, fn) => {
    options.checkAbort?.();
    try { emitBatch(fn()); } catch (e) {
      dbg("AIHIST", `grok bot ${label} failed`, { path: rootDir, err: e.message });
    }
  };

  if (isGrokBotDaemonRoot(rootDir)) {
    stats.daemonRoot = true;
    run("settings", () => { progress(path.join(rootDir, SETTINGS_FILE)); return settingsRows(rootDir, attribution); });
    run("daemon state", () => { progress(path.join(rootDir, DAEMON_STATE_FILE)); return daemonStateRows(rootDir, attribution); });
    for (const logPath of listDaemonLogFiles(rootDir)) {
      run("daemon log", () => {
        progress(logPath);
        const out = daemonLogRows(rootDir, attribution, stats, options.checkAbort, logPath);
        stats.daemonLogRows += out.length;
        return out;
      });
    }
    run("attachments", () => {
      const out = attachmentStagingRows(rootDir, attribution);
      stats.inventoryOnly += out.length;
      return out;
    });
    run("sensitive inventory", () => {
      const out = sensitiveInventoryRows(rootDir, attribution);
      stats.inventoryOnly += out.length;
      return out;
    });
  }

  if (isGrokBotAppRoot(rootDir)) {
    stats.appRoot = true;
    run("app markers", () => appMarkerRows(rootDir, attribution));
    run("app identity", () => {
      progress(path.join(rootDir, SENTRY_DIR, SENTRY_SCOPE_FILE));
      return appIdentityRows(rootDir, attribution);
    });
    run("persistence", () => persistenceRows(rootDir, attribution, stats, progress, options));
    run("link previews", () => linkPreviewRows(rootDir, attribution, stats));
    run("sensitive inventory", () => {
      const out = sensitiveInventoryRows(rootDir, attribution);
      stats.inventoryOnly += out.length;
      return out;
    });
  }

  attachPerRootStats(stats, rootDir, attribution);

  if (onExtractedRows) {
    const out = [];
    out._grokBotStats = stats;
    return out;
  }
  const finalized = finalizeAiHistoryRows(rows, options);
  finalized._grokBotStats = stats;
  return finalized;
}

async function extractGrokBotRoots(rootDirs, attribution = {}, options = {}) {
  const rows = [];
  let stats = emptyStats();
  for (const nestedRoot of rootDirs) {
    const part = await extractGrokBotOneRoot(nestedRoot, attribution, options);
    stats = mergeGrokBotStats(stats, part._grokBotStats);
    if (!options.onExtractedRows && part.length) rows.push(...part);
  }
  if (options.onExtractedRows) {
    const out = [];
    out._grokBotStats = stats;
    return out;
  }
  const finalized = options.skipFinalize ? rows : finalizeAiHistoryRows(rows, options);
  finalized._grokBotStats = stats;
  return finalized;
}

async function extractGrokBotDir(rootDir, attribution = {}, options = {}) {
  // A leaf root (~/.grokbot or …/Grok Bot) is extracted as-is so Collect AI Artifacts,
  // which already lists both, does not pair and duplicate. Companion pairing lives in
  // grokBotExtractTargets / extractGrokBotPath (single-tool decode).
  if (isGrokBotRoot(rootDir)) return extractGrokBotOneRoot(rootDir, attribution, options);
  const nested = listGrokBotExtractRoots(rootDir);
  if (!nested.length) {
    if (options.onExtractedRows) {
      const out = [];
      out._grokBotStats = emptyStats();
      return out;
    }
    const empty = options.skipFinalize ? [] : finalizeAiHistoryRows([], options);
    empty._grokBotStats = emptyStats();
    return empty;
  }
  if (nested.length === 1) return extractGrokBotOneRoot(nested[0], attribution, options);
  return extractGrokBotRoots(nested, attribution, options);
}

async function extractSingleGrokBotFile(filePath, rootDir, attribution = {}, options = {}) {
  const base = path.basename(filePath);
  const parent = path.basename(path.dirname(filePath));
  const stats = emptyStats();
  stats.daemonRoot = isGrokBotDaemonRoot(rootDir);
  stats.appRoot = isGrokBotAppRoot(rootDir);
  const withStats = (out) => {
    attachPerRootStats(stats, rootDir, attribution);
    out._grokBotStats = stats;
    return out;
  };
  if (base === SETTINGS_FILE) return withStats(settingsRows(rootDir, attribution));
  if (base === DAEMON_STATE_FILE || base === SUPERVISOR_STATE_FILE) return withStats(daemonStateRows(rootDir, attribution));
  if (isDaemonLogName(base)) {
    const out = daemonLogRows(rootDir, attribution, stats, options.checkAbort, filePath);
    stats.daemonLogRows = out.length;
    return withStats(out);
  }
  if (base === SESSION_MARKER_FILE || base === UPDATE_MARKER_FILE) return withStats(appMarkerRows(rootDir, attribution));
  if (base === LOCAL_STATE_FILE || (parent === SENTRY_DIR && (base === SENTRY_SCOPE_FILE || base === SENTRY_SESSION_FILE))) {
    return withStats(appIdentityRows(rootDir, attribution));
  }
  if (parent === LINK_CACHE_DIR_NAME && /\.json$/i.test(base)) {
    return withStats(linkPreviewRows(rootDir, attribution, stats).filter((r) => r.SourceFile === path.resolve(filePath)));
  }
  if (/\.blob$/i.test(base)) {
    const info = classifySliceName(decodeSliceBlobName(base));
    stats.persistenceBlobsSeen = 1;
    if (!info || info.kind === "ui") {
      if (info?.kind === "ui") stats.persistenceBlobsExcludedUi = 1;
      else stats.persistenceBlobsUnknown = 1;
      stats.inventoryOnly = 1;
      const row = inventoryRow(filePath, "persistence_blob_inventory",
        info?.kind === "ui" ? "Excluded Grok Bot UI/state slice" : "Unknown Grok Bot persistence blob",
        "INVENTORY ONLY. The blob is outside the qualified transcript slice decoder; content was not read.",
        attribution, { detail: { classification: info?.kind === "ui" ? "excluded-ui" : "unknown", sliceName: decodeSliceBlobName(base) } });
      return withStats(row ? [row] : []);
    }
    stats.persistenceBlobsEligible = 1;
    // Read the roster (if present) so a single transcript can carry its agent name.
    const agents = new Map();
    const rosterBlob = path.join(path.dirname(filePath), encodeSliceBlobName(
      `${SLICE_PREFIX}account.${encodeURIComponent(info.account)}.roster.last-roster`,
    ));
    if (info.kind !== "roster" && safeIsFile(rosterBlob)) {
      const parsed = readJsonBounded(rosterBlob);
      if (parsed) for (const [id, a] of rosterRows(parsed, rosterBlob, info, attribution).agents) agents.set(id, a);
    }
    const parsed = readJsonBounded(filePath);
    if (!parsed) {
      stats.unreadableBlobs = 1;
      stats.inventoryOnly = 1;
      const row = inventoryRow(filePath, "persistence_blob_unreadable", "Unreadable Grok Bot persistence slice", `INVENTORY ONLY. The qualified ${info.kind} slice was malformed, unreadable, or exceeded the ${MAX_JSON_BYTES}-byte JSON limit; content was not decoded.`, attribution, { detail: { kind: info.kind } });
      return withStats(row ? [row] : []);
    }
    if (info.kind === "roster") {
      const roster = rosterRows(parsed, filePath, info, attribution);
      stats.agents = roster.agents.size;
      return withStats(roster.rows);
    }
    if (info.kind === "transcript") {
      stats.transcripts = 1;
      const helpers = {
        findLocalCopies: createLocalAttachmentFinder([rootDir], { checkAbort: options.checkAbort }),
        checkAbort: options.checkAbort,
      };
      return withStats(transcriptRows(parsed, filePath, info, agents, attribution, stats, helpers));
    }
    if (info.kind === "drafts") {
      const out = draftRows(parsed, filePath, info, agents, attribution);
      stats.drafts = out.length;
      return withStats(out);
    }
    return withStats(sendJournalRows(parsed, filePath, info, attribution, stats));
  }
  throw new Error("Unrecognized Grok Bot artifact file.");
}

async function extractGrokBotPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) throw new Error(`Path does not exist: ${target}`);
  const targets = grokBotExtractTargets(target);
  if (!targets.length) throw new Error(NOT_A_GROK_BOT_DIR);
  if (safeIsDirectory(target)) {
    return extractGrokBotRoots(targets, attribution, options);
  }
  if (!isGrokBotArtifactFile(target)) {
    throw new Error("Expected a Grok Bot settings/daemon/marker JSON, local-exec-daemon.log, sentry scope/session JSON, Local State, a link-cache JSON, or a sand-client-persistence .blob file.");
  }
  const rows = await extractSingleGrokBotFile(target, targets[0], attribution, options);
  const stats = rows._grokBotStats;
  const finalized = finalizeAiHistoryRows(rows, options);
  finalized._grokBotStats = stats;
  return finalized;
}

function buildGrokBotImportNotice(stats) {
  if (!stats) return "";
  const parts = [];
  if (stats.localToolPermissionRequests > 0) {
    const states = Object.entries(stats.permissionStates || {}).map(([state, count]) => `${state}=${count}`).join(", ");
    parts.push(`${stats.localToolPermissionRequests} LOCAL TOOL request(s) (${states || "decision state unknown"}); request/approval is not execution proof`);
  }
  if (stats.daemonRoot) {
    parts.push(`local exec daemon state parsed (${stats.daemonLogRows} log row(s), ${stats.daemonLogLinesRead || 0} line(s) read`
      + `${stats.daemonLogDetailRowsOmitted ? `, ${stats.daemonLogDetailRowsOmitted} detail row(s) omitted by the ${MAX_LOG_ROWS}-row limit` : ""}`
      + `${stats.daemonLogBytesOmitted ? `, ${stats.daemonLogBytesOmitted} byte(s) outside the read limit` : ""}; credential files inventoried, never read)`);
  }
  if (stats.appRoot) {
    parts.push(`${stats.agents} agent(s) on roster, ${stats.transcripts} transcript replica(s) with ${stats.transcriptSourceEntries} retained source entr(ies) and ${stats.transcriptEntries} emitted row(s)`
      + `${stats.replicasAtRetentionBoundary > 0 ? ` — ${stats.replicasAtRetentionBoundary} replica(s) at/near Grok Bot's ${REPLICA_ENTRY_CAP}-entry/${REPLICA_BYTE_CAP / 1024} KB retention boundary; earlier history availability is unknown` : ` — replicas are bounded to the last ${REPLICA_ENTRY_CAP} entries per agent`}`);
  }
  if (stats.transcriptEntriesOmittedByParserLimit > 0) parts.push(`${stats.transcriptEntriesOmittedByParserLimit} transcript entr(ies) omitted by the parser limit`);
  if (stats.sendJournalFiles > 0) parts.push(`${stats.sendJournalRecords} send-journal record(s) across ${stats.sendJournalFiles} file(s), ${stats.emptySendJournals} empty`);
  if (stats.sendJournalUnknownSchema > 0) parts.push(`${stats.sendJournalUnknownSchema} send-journal file(s) have an unqualified schema and were raw-preserved`);
  if (stats.sendJournalMalformedRecords > 0) parts.push(`${stats.sendJournalMalformedRecords} v2 send-journal record(s) failed schema checks but were raw-preserved`);
  if (stats.attachments > 0) {
    const recoveryScope = stats.attachmentRecovery?.includeUserFolders
      ? "inside the selected roots and opted-in user folders"
      : "inside the selected Grok Bot roots (personal folders were not searched)";
    parts.push(`${stats.attachments} uploaded attachment reference(s), ${stats.attachmentsRecovered} with a SHA-256-verified original ${recoveryScope}`);
  }
  if (stats.linkPreviews > 0) parts.push(`${stats.linkPreviews} link preview(s)`);
  if (stats.linkPreviewsOmittedByParserLimit > 0) parts.push(`${stats.linkPreviewsOmittedByParserLimit} link-preview file(s) omitted by the parser limit`);
  if (stats.attachmentRecovery?.hashCandidatesOmitted > 0) parts.push(`${stats.attachmentRecovery.hashCandidatesOmitted} attachment hash candidate(s) omitted by the hashing limit`);
  if (stats.drafts > 0) parts.push(`${stats.drafts} unsent draft(s)`);
  if (stats.unreadableBlobs > 0) parts.push(`${stats.unreadableBlobs} slice blob(s) unreadable`);
  if (stats.persistenceBlobsUnknown > 0) parts.push(`${stats.persistenceBlobsUnknown} persistence blob(s) have unknown names and were retained as inventory rows`);
  return parts.length ? `Grok Bot: ${parts.join("; ")}.` : "";
}

module.exports = {
  GROKBOT_DIR_NAME,
  GROKBOT_APP_DIR_NAME,
  GROKBOT_ROOT_MARKER,
  PERSISTENCE_DIR,
  DAEMON_LOG_FILE,
  DAEMON_STATE_FILE,
  SUPERVISOR_STATE_FILE,
  SETTINGS_FILE,
  SESSION_MARKER_FILE,
  UPDATE_MARKER_FILE,
  SENTRY_DIR,
  SENTRY_SCOPE_FILE,
  SENTRY_SESSION_FILE,
  LOCAL_STATE_FILE,
  SENSITIVE_FILES,
  SLICE_PREFIX,
  REPLICA_ENTRY_CAP,
  REPLICA_BYTE_CAP,
  REPLICA_MAX_AGENTS,
  REPLICA_MAX_AGE_DAYS,
  contentHashFromBoxPath,
  createLocalAttachmentFinder,
  decodeSliceBlobName,
  encodeSliceBlobName,
  classifySliceName,
  defaultGrokBotHome,
  defaultGrokBotAppDir,
  isGrokBotDaemonRoot,
  isGrokBotAppRoot,
  isGrokBotRoot,
  resolveGrokBotRoot,
  listGrokBotExtractRoots,
  grokBotExtractTargets,
  NOT_A_GROK_BOT_DIR,
  isGrokBotArtifactFile,
  listGrokBotDataFiles,
  countGrokBotExtractFiles,
  transcriptEntryRow,
  emptyStats,
  mergeGrokBotStats,
  extractGrokBotDir,
  extractGrokBotRoots,
  extractGrokBotPath,
  buildGrokBotImportNotice,
};
