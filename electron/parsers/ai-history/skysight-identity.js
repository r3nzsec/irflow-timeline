/**
 * ai-history/skysight-identity.js — attribution artifacts for ChatGPT Computer History.
 *
 * The event stream answers "what happened on this machine". It does not answer "whose account was
 * this" or "does this corroborate the Codex artifacts", and those are the next two questions any
 * investigator asks. This module collects the identifiers that answer them.
 *
 * There are at least FOUR unrelated pseudonyms on a single host, and conflating them produces wrong
 * attribution:
 *
 *   distinct_id        Analytics.db, UPPERCASE UUID   the recorder install (native Swift service)
 *   Statsig stableID   per-app plist, UPPERCASE UUID  feature-flag device id — a different UUID,
 *                                                     and each OpenAI app has its own
 *   installation_id    ~/.codex, lowercase UUID       the Codex install (Electron/Node)
 *   account id         plist FILENAME + auth.json     the actual ChatGPT account
 *
 * Only the last one is an account. The cheapest attribution on the box is a directory listing:
 * `com.openai.chat.RemoteFeatureFlags.<account-uuid>.plist` carries the account UUID in its NAME,
 * so it needs no parsing, survives token expiry, and two such files mean two accounts used the host.
 *
 * CREDENTIALS: `auth.json` holds live bearer/refresh tokens. Identity claims are read out of the
 * id_token payload; the tokens themselves are never returned, never stored and never exported.
 */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const { dbg } = require("../../logger");

/** Attribution strength, reported on every identifier so it cannot be overstated in a report. */
const STRENGTH_DIRECT = "direct";
const STRENGTH_VENDOR = "vendor-side";
const STRENGTH_DEVICE = "device-pseudonym";
const STRENGTH_TIMELINE = "presence-timeline";

const ACCOUNT_PLIST_RE = /^com\.openai\.chat\.RemoteFeatureFlags\.([0-9a-fA-F-]{36})\.plist$/;
const UUID_ANY_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PLUTIL_TIMEOUT_MS = 10000;
const PLUTIL_MAX_BUFFER = 8 * 1024 * 1024;
/** A memories/global-state file holds tens of threads, not tens of thousands. */
const MAX_THREAD_ROWS = 2000;

/* ------------------------------------------------------------------ uuid v7 */

/**
 * Decode the millisecond timestamp embedded in a UUIDv7.
 *
 * Codex conversation ids are v7, so every thread id is self-dating — no other artifact needed to
 * place a conversation on the timeline. Returns null for any other UUID version.
 */
function decodeUuidV7(uuid) {
  const s = String(uuid || "").trim();
  if (!UUID_ANY_RE.test(s)) return null;
  const hex = s.replace(/-/g, "");
  if (hex[12] !== "7") return null;               // version nibble
  const variant = parseInt(hex[16], 16);
  if (Number.isNaN(variant) || variant < 8 || variant > 11) return null; // RFC 4122 variant
  const ms = parseInt(hex.slice(0, 12), 16);
  if (!Number.isFinite(ms) || ms <= 0) return null;
  return ms;
}

/* ------------------------------------------------------------------- roots */

/**
 * Walk up from the evidence target to the home-shaped directory that holds the sibling artifacts.
 *
 * A bare `Library` check is NOT enough to recognise a home: the CUAService group container has its
 * own `Library/Preferences` tree, so that test stops one level inside the container and finds none
 * of the sibling artifacts. A home is recognised by `.codex` or `Library/Group Containers`, neither
 * of which nests inside an app container.
 *
 * Bounded to 16 levels, so a triage folder resolves to the acquired user's home rather than
 * escaping into the examiner's own filesystem.
 */
function findIdentityRoot(target) {
  if (!target) return null;
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }

  const looksLikeHome = (dir) => fs.existsSync(path.join(dir, ".codex"))
    || fs.existsSync(path.join(dir, "Library", "Group Containers"));

  let fallback = null;
  for (let i = 0; i < 16; i++) {
    if (looksLikeHome(p)) return p;
    // Weaker signal: a Preferences directory that actually holds OpenAI app preferences.
    if (!fallback) {
      const prefs = path.join(p, "Library", "Preferences");
      try {
        if (fs.readdirSync(prefs).some((n) => n.startsWith("com.openai."))) fallback = p;
      } catch { /* not this level */ }
    }
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return fallback;
}

/* ------------------------------------------------------------------ plists */

/**
 * Read ONE key out of a (possibly binary) plist via the macOS-bundled plutil.
 *
 * Deliberately key-at-a-time rather than `-convert json`: these plists contain `<data>` blobs, which
 * have no JSON representation, so a whole-file conversion fails outright ("Invalid object in plist
 * for JSON format") and takes the readable keys down with it. `-extract … raw` returns strings
 * verbatim and data as base64.
 *
 * Key names here contain dots, which plutil treats as keypath separators, so each dot is escaped.
 */
function readPlistKey(filePath, key) {
  if (!filePath || !key || !fs.existsSync(filePath)) return null;
  const keypath = String(key).replace(/\./g, "\\.");
  try {
    return execFileSync("plutil", ["-extract", keypath, "raw", "-o", "-", filePath], {
      timeout: PLUTIL_TIMEOUT_MS, maxBuffer: PLUTIL_MAX_BUFFER, encoding: "utf8",
      windowsHide: true, stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null; // key absent is the common case, not an error worth logging per app
  }
}

/**
 * Account UUIDs taken from preference FILENAMES.
 * More than one result means more than one ChatGPT account was used on this host.
 */
function listAccountPlists(prefsDir) {
  if (!prefsDir || !fs.existsSync(prefsDir)) return [];
  let entries;
  try { entries = fs.readdirSync(prefsDir, { withFileTypes: true }); } catch { return []; }
  const out = [];
  for (const e of entries) {
    if (!e.isFile()) continue;
    const m = e.name.match(ACCOUNT_PLIST_RE);
    if (!m) continue;
    const filePath = path.join(prefsDir, e.name);
    let mtimeMs = null;
    try { mtimeMs = fs.statSync(filePath).mtimeMs; } catch { /* keep the id */ }
    out.push({ accountId: m[1].toLowerCase(), filePath, mtimeMs });
  }
  return out.sort((a, b) => (a.mtimeMs || 0) - (b.mtimeMs || 0));
}

/** Statsig device pseudonym + the cached evaluation contexts that double as a presence timeline. */
function readStatsigStore(plistPath) {
  if (!plistPath || !fs.existsSync(plistPath)) return null;
  const stableId = readPlistKey(plistPath, "com.Statsig.InternalStore.stableIDKey") || "";

  const contexts = [];
  const raw = readPlistKey(plistPath, "com.Statsig.InternalStore.localStorageKeyV2");
  if (raw) {
    let text = raw;
    try {
      const buf = Buffer.from(raw, "base64");
      if (buf.length && (buf[0] === 0x7b || buf[0] === 0x5b)) text = buf.toString("utf8");
    } catch { /* treat as plain text */ }
    try {
      const j = JSON.parse(text);
      for (const [key, v] of Object.entries(j || {})) {
        if (!v || typeof v !== "object") continue;
        const ms = Number(v.time || v.evaluation_time) || null;
        contexts.push({ key: String(key).split(":")[0], userHash: v.user_hash ?? null, evaluatedMs: ms });
      }
    } catch { /* cache shape changed — stable id is still useful */ }
  }
  if (!stableId && !contexts.length) return null;
  return { stableId, contexts, filePath: plistPath };
}

/**
 * ChatGPT Desktop StatsigService.plist — account id, user id and email without touching auth.json.
 *
 * This file is not a token store. It survives token expiry and is the cheapest local binding of
 * email → account UUID besides the RemoteFeatureFlags filename. Missing from the 1.0.10/1.0.11
 * attribution table because those releases only walked CUAService / auth.json / Analytics.db.
 */
function readChatgptStatsigServicePlist(plistPath) {
  if (!plistPath || !fs.existsSync(plistPath)) return null;
  const accountId = readPlistKey(plistPath, "accountID") || "";
  const userId = readPlistKey(plistPath, "userID") || "";
  const email = readPlistKey(plistPath, "userEmail") || "";
  const paidRaw = readPlistKey(plistPath, "hasAnyPaidPlanAccount");
  const totalAccounts = readPlistKey(plistPath, "totalAccounts");
  if (!accountId && !userId && !email) return null;
  const paid = paidRaw === "true" || paidRaw === true || paidRaw === "1";
  return {
    filePath: plistPath,
    accountId: String(accountId),
    userId: String(userId),
    email: String(email),
    paid,
    totalAccounts: totalAccounts != null && totalAccounts !== "" ? String(totalAccounts) : "",
  };
}

/* -------------------------------------------------------------- analytics.db */

/**
 * Read the three Analytics.db tables.
 *
 * Expect it EMPTY on anything but a fast live acquisition: events are uploaded then deleted, and
 * the freed pages are zeroed rather than merely unlinked (measured: 99% of a 593KB file was zero
 * bytes with 137 pages on the freelist and nothing carvable). The value here is `distinct_id`, and
 * above all `distinct_id_alias` — the anonymous-device → identified-account bridge.
 */
function readAnalyticsDb(dbPath) {
  if (!dbPath || !fs.existsSync(dbPath)) return null;
  let Database;
  try { Database = require("better-sqlite3"); } catch (e) {
    dbg("AIHIST", "analytics db driver unavailable", { err: e.message });
    return { filePath: dbPath, unreadable: true, distinctIds: [], aliases: [], eventCount: null };
  }

  let db;
  try {
    db = new Database(dbPath, { readonly: true, fileMustExist: true });
    const has = (t) => !!db.prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
    ).get(t);

    const distinctIds = has("distinct_id")
      ? db.prepare("SELECT distinct_id FROM distinct_id").all().map((r) => r.distinct_id) : [];
    const aliases = has("distinct_id_alias")
      ? db.prepare("SELECT distinct_id, alias FROM distinct_id_alias").all() : [];
    const eventCount = has("analytics_event")
      ? db.prepare("SELECT COUNT(*) AS n FROM analytics_event").get().n : null;
    const freelist = db.pragma("freelist_count", { simple: true });
    const pageCount = db.pragma("page_count", { simple: true });

    return { filePath: dbPath, unreadable: false, distinctIds, aliases, eventCount, freelist, pageCount };
  } catch (e) {
    dbg("AIHIST", "analytics db read failed", { path: dbPath, err: e.message });
    return { filePath: dbPath, unreadable: true, distinctIds: [], aliases: [], eventCount: null };
  } finally {
    try { db?.close(); } catch { /* ignore */ }
  }
}

/* ------------------------------------------------------------------- codex */

/** Identity claims from the id_token. Tokens themselves are never returned. */
function readAuthIdentity(authPath) {
  if (!authPath || !fs.existsSync(authPath)) return null;
  let j;
  try { j = JSON.parse(fs.readFileSync(authPath, "utf8")); } catch { return null; }

  const out = {
    filePath: authPath,
    authMode: typeof j.auth_mode === "string" ? j.auth_mode : "",
    accountId: typeof j?.tokens?.account_id === "string" ? j.tokens.account_id : "",
    lastRefresh: typeof j.last_refresh === "string" ? j.last_refresh : "",
    hasApiKey: j.OPENAI_API_KEY != null && j.OPENAI_API_KEY !== "",
    email: "", name: "", subject: "", userId: "", plan: "", orgs: "", authProvider: "", authTimeMs: null,
  };

  const idToken = typeof j?.tokens?.id_token === "string" ? j.tokens.id_token : "";
  const part = idToken.split(".")[1];
  if (!part) return out;
  let claims;
  try { claims = JSON.parse(Buffer.from(part, "base64url").toString("utf8")); } catch { return out; }

  const auth = claims["https://api.openai.com/auth"] || {};
  out.email = typeof claims.email === "string" ? claims.email : "";
  out.name = typeof claims.name === "string" ? claims.name : "";
  out.subject = typeof claims.sub === "string" ? claims.sub : "";
  out.authProvider = typeof claims.auth_provider === "string" ? claims.auth_provider : "";
  out.userId = typeof auth.chatgpt_user_id === "string" ? auth.chatgpt_user_id : (auth.user_id || "");
  out.plan = typeof auth.chatgpt_plan_type === "string" ? auth.chatgpt_plan_type : "";
  if (!out.accountId && typeof auth.chatgpt_account_id === "string") out.accountId = auth.chatgpt_account_id;
  if (Array.isArray(auth.organizations)) {
    out.orgs = auth.organizations
      .map((o) => `${o?.id || "?"}${o?.role ? ` (${o.role})` : ""}`).join(", ");
  }
  if (Number.isFinite(claims.auth_time)) out.authTimeMs = claims.auth_time * 1000;
  return out;
}

/** Install/environment ids and the UUIDv7 thread ledger from Codex global state. */
function readCodexIdentity(codexRoot) {
  if (!codexRoot || !fs.existsSync(codexRoot)) return null;
  const out = {
    root: codexRoot, installationId: "", environmentId: "",
    installationIdPath: "", statePath: "", threads: [],
  };

  const instPath = path.join(codexRoot, "installation_id");
  if (fs.existsSync(instPath)) {
    try {
      const v = fs.readFileSync(instPath, "utf8").trim();
      if (UUID_ANY_RE.test(v)) { out.installationId = v; out.installationIdPath = instPath; }
    } catch { /* ignore */ }
  }

  const statePath = path.join(codexRoot, ".codex-global-state.json");
  if (!fs.existsSync(statePath)) return out;
  out.statePath = statePath;

  let text;
  try { text = fs.readFileSync(statePath, "utf8"); } catch { return out; }

  const env = text.match(/"electron-local-remote-control-environment-id"\s*:\s*"([^"]{1,120})"/);
  if (env) out.environmentId = env[1];

  // Threads the UI has marked deleted — their conversation is gone, but Computer History may still
  // hold what the user typed into them.
  const deleted = new Set();
  for (const m of text.matchAll(/codex-writing-block-deleted-thread-v1:([0-9a-f-]{36})/gi)) {
    deleted.add(m[1].toLowerCase());
  }

  const seen = new Set();
  for (const m of text.matchAll(/\b[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi)) {
    const id = m[0].toLowerCase();
    if (seen.has(id)) continue;
    seen.add(id);
    const createdMs = decodeUuidV7(id);
    if (createdMs == null) continue;
    out.threads.push({ id, createdMs, deleted: deleted.has(id) });
    if (out.threads.length >= MAX_THREAD_ROWS) break;
  }
  out.threads.sort((a, b) => a.createdMs - b.createdMs);
  return out;
}

module.exports = {
  decodeUuidV7,
  findIdentityRoot,
  readPlistKey,
  listAccountPlists,
  readStatsigStore,
  readAnalyticsDb,
  readAuthIdentity,
  readCodexIdentity,
  readChatgptStatsigServicePlist,
  STRENGTH_DIRECT,
  STRENGTH_VENDOR,
  STRENGTH_DEVICE,
  STRENGTH_TIMELINE,
  ACCOUNT_PLIST_RE,
  MAX_THREAD_ROWS,
};
