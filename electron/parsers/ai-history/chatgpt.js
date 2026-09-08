/**
 * parsers/ai-history/chatgpt.js — ChatGPT Desktop local store extraction.
 *
 * Handles Electron LevelDB conversation metadata (.ldb/.log) and SQLite message DBs when
 * present. Full message bodies depend on the app version; metadata (title, timestamps) is
 * always attempted from LevelDB.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const { dbg } = require("../../logger");
const { TOOL_CHATGPT } = require("./schema");
const { tickFileProgress } = require("./extract-plan");
const { formatTimestampUtc, parseIsoTimestamp, makeRow, finalizeAiHistoryRows } = require("./row-utils");

const MAX_LEVELDB_BYTES = 64 * 1024 * 1024;
// Bounded recovery limits so a crafted/large LevelDB byte stream cannot pin the worker (DoS).
// The raw scan is best-effort carving over untrusted bytes; these caps keep it strictly linear.
const MAX_LEVELDB_OBJECT_BYTES = 4 * 1024 * 1024; // cap on one recovered JSON array/object
const LEVELDB_BACKSCAN_WINDOW = 8 * 1024;         // how far back to look for an enclosing '{'
const MAX_LEVELDB_MATCHES = 50_000;               // cap key occurrences scanned per file
const MAX_CHROMIUM_HISTORY_ROWS = 20_000;

// Chromium profile directories that are cache/component noise, not ChatGPT conversation evidence.
const CHROMIUM_SKIP_DIR_NAMES = new Set([
  "Cache", "Code Cache", "GPUCache", "GrShaderCache", "ShaderCache",
  "DawnGraphiteCache", "DawnWebGPUCache", "DawnCache",
  "Service Worker", "Crashpad", "Crowd Deny",
  "FileTypePolicies", "FirstPartySetsPreloaded", "MEIPreload",
  "OnDeviceHeadSuggestModel", "OptimizationHints", "OriginTrials",
  "SSLErrorAssistant", "Safe Browsing", "Subresource Filter",
  "TLSDeprecationConfig", "TpcdMetadata", "TrustTokenKeyCommitments",
  "WidevineCdm", "ZxcvbnData", "hyphen-data",
  "component_crx_cache", "extensions_crx_cache",
  "CertificateRevocation", "PKIMetadata", "SafetyTips",
  "WasmTtsEngine", "blob_storage",
  "AutofillAiModelCache", "AutofillStrikeDatabase",
  "BudgetDatabase", "ClientCertificates",
  "Feature Engagement Tracker", "GCM Store",
  "PersistentOriginTrials", "Segmentation Platform",
  "shared_proto_db", "optimization_guide_hint_cache_store",
  "chrome_cart_db", "commerce_subscription_db",
  "discount_infos_db", "discounts_db", "parcel_tracking_db",
  "Site Characteristics Database", "Sync Data",
  "Extension Rules", "Extension Scripts", "Extension State",
]);

// Credential / autofill / cookie stores — never run the generic message-table extractor on these.
const CHATGPT_SKIP_SQLITE_NAMES = new Set([
  "login data",
  "login data for account",
  "cookies",
  "web data",
  "account web data",
  "favicons",
  "trust tokens",
  "shortcuts",
  "top sites",
  "network action predictor",
  "reporting and nel",
  "affiliation database",
  "servercertificate",
  "sharedstorage",
  "first_party_sets.db",
  "heavy_ad_intervention_opt_out.db",
  "declarative_performance_observer.db",
  "preferredapps",
]);

/** Chrome/WebKit internal time: microseconds since 1601-01-01 UTC → epoch ms. */
function chromeTimeToMs(chromeTime) {
  const n = Number(chromeTime);
  if (!Number.isFinite(n) || n <= 0) return null;
  const ms = Math.round(n / 1000) - 11644473600000;
  return ms > 0 ? ms : null;
}

function isCodexDesktopAppDir(dirPath) {
  if (!dirPath || path.basename(dirPath) !== "Codex") return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  const markers = [
    "codex-browser-app",
    "artifact-sessions",
    path.join("Default", "History"),
    path.join("Local Storage", "leveldb"),
    "Local State",
  ];
  return markers.some((rel) => {
    try { return fs.existsSync(path.join(dirPath, rel)); } catch { return false; }
  });
}

// Char codes for the hot scan loops — charCodeAt avoids allocating a one-char string per index.
const CC_QUOTE = 34;   // "
const CC_BACKSLASH = 92; // \
const CC_OBRACE = 123; // {
const CC_OBRACKET = 91; // [

function isSqliteFile(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, 16, 0);
    return buf.slice(0, 6).toString("latin1") === "SQLite";
  } catch {
    return false;
  } finally {
    // Always release the descriptor — readSync can throw after openSync succeeds (EIO on
    // damaged media), and a leaked fd per failing file eventually exhausts the fd table (EMFILE).
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* ignore */ } }
  }
}

function isLeveldbWhitespace(ch) {
  return ch === " " || ch === "\t" || ch === "\n" || ch === "\r";
}

function isInLeveldbDir(filePath) {
  const lower = filePath.toLowerCase();
  return lower.includes("leveldb")
    || lower.includes("local storage")
    || lower.includes("localstorage")
    || lower.includes("indexeddb");
}

function parseChatgptTimestamp(s) {
  if (s == null || s === "") return null;
  if (typeof s === "number" && Number.isFinite(s)) {
    if (s > 1e12) return s;
    if (s > 1e9) return s * 1000;
    return null;
  }
  const str = String(s).trim();
  if (!str) return null;
  const iso = parseIsoTimestamp(str);
  if (iso != null) return iso;
  if (/^\d{10}(\.\d+)?$/.test(str)) return Math.round(parseFloat(str) * 1000);
  if (/^\d{13}$/.test(str)) return parseInt(str, 10);
  return null;
}

// Scan `text` in place from `start` for a balanced open/close pair, bounded by maxLen.
// Returns the single matched substring (one slice) or null. Scanning in place — rather than
// slicing the tail per call as before — is what makes the LevelDB carve O(n) instead of O(n^2).
function extractBalanced(text, start, open, close, maxLen = MAX_LEVELDB_OBJECT_BYTES) {
  const limit = Math.min(text.length, start + maxLen);
  const openCode = open.charCodeAt(0);
  const closeCode = close.charCodeAt(0);
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = start; i < limit; i++) {
    const cc = text.charCodeAt(i);
    if (escape) { escape = false; continue; }
    if (cc === CC_BACKSLASH && inString) { escape = true; continue; }
    if (cc === CC_QUOTE) { inString = !inString; continue; }
    if (inString) continue;
    if (cc === openCode) depth++;
    else if (cc === closeCode) {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

function parseConversationItem(item, sourceFile, attribution) {
  const id = item.id != null ? String(item.id) : "";
  const title = item.title != null ? String(item.title) : "";
  const createTime = item.create_time != null ? String(item.create_time) : "";
  const updateTime = item.update_time != null ? String(item.update_time) : "";
  if (!id || (!title && !createTime)) return null;
  if (!id.includes("-") || id.length < 10) return null;

  const tsMs = parseChatgptTimestamp(createTime) ?? parseChatgptTimestamp(updateTime);
  if (tsMs == null) return null;

  const isArchived = !!item.is_archived;
  const gizmoId = item.gizmo_id != null ? String(item.gizmo_id) : "";
  let summary = title || `Conversation ${id}`;
  if (isArchived) summary = `${summary} [archived]`;
  const model = gizmoId ? `Custom GPT (${gizmoId})` : "";

  return makeRow({
    timestamp: formatTimestampUtc(tsMs),
    role: "conversation",
    recordType: "conversation",
    summary,
    sessionId: id,
    messageId: id,
    parentId: "",
    workspace: "",
    toolName: "",
    isSidechain: false,
    gitBranch: "",
    tool: TOOL_CHATGPT,
    model,
    sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  }, TOOL_CHATGPT);
}

function extractFromLeveldbBytes(data, sourceFile, attribution, out) {
  const text = data.toString("latin1");
  const len = text.length;
  let capped = false;

  // Primary path: "items": [ ... ]. Scan for the colon/bracket in place within a small window
  // after the key (JSON puts them adjacent) instead of slicing the entire tail per match.
  let searchFrom = 0;
  let matches = 0;
  while (searchFrom < len) {
    const rel = text.indexOf('"items"', searchFrom);
    if (rel < 0) break;
    if (++matches > MAX_LEVELDB_MATCHES) { capped = true; break; }
    const keyEnd = rel + 7;
    searchFrom = keyEnd; // advance past this key unconditionally — never rescan it
    let p = keyEnd;
    while (p < len && p < keyEnd + 16 && isLeveldbWhitespace(text[p])) p++;
    if (text[p] !== ":") continue;
    p++;
    while (p < len && p < keyEnd + 48 && isLeveldbWhitespace(text[p])) p++;
    if (text[p] !== "[") continue;
    const arrJson = extractBalanced(text, p, "[", "]");
    if (!arrJson) continue;
    try {
      const items = JSON.parse(arrJson);
      if (Array.isArray(items)) {
        for (const item of items) {
          if (!item || typeof item !== "object") continue;
          const row = parseConversationItem(item, sourceFile, attribution);
          if (row) out.push(row);
        }
      }
    } catch { /* skip malformed blob */ }
  }

  // Fallback path: standalone {...} objects carrying "create_time". Walk backward to the
  // enclosing '{' only within a bounded window (the metadata key sits near the object start),
  // so a buffer packed with the key but no brace cannot trigger an O(n) walk-to-zero per match.
  searchFrom = 0;
  matches = 0;
  while (searchFrom < len) {
    const rel = text.indexOf('"create_time"', searchFrom);
    if (rel < 0) break;
    if (++matches > MAX_LEVELDB_MATCHES) { capped = true; break; }
    searchFrom = rel + 13;
    const floor = Math.max(0, rel - LEVELDB_BACKSCAN_WINDOW);
    let start = rel;
    while (start > floor && text.charCodeAt(start) !== CC_OBRACE) start--;
    if (text.charCodeAt(start) !== CC_OBRACE) continue; // no enclosing object in window — bail
    const objJson = extractBalanced(text, start, "{", "}");
    if (!objJson) continue;
    try {
      const obj = JSON.parse(objJson);
      if (obj && typeof obj === "object") {
        const row = parseConversationItem(obj, sourceFile, attribution);
        if (row) out.push(row);
      }
    } catch { /* skip */ }
  }

  if (capped) {
    dbg("AIHIST", "leveldb match cap reached", { sourceFile, max: MAX_LEVELDB_MATCHES });
  }
}

function extractLeveldbFile(filePath, attribution) {
  const stat = fs.statSync(filePath);
  if (stat.size > MAX_LEVELDB_BYTES) {
    dbg("AIHIST", "skip large leveldb file", { path: filePath, size: stat.size });
    return [];
  }
  const data = fs.readFileSync(filePath);
  const rows = [];
  extractFromLeveldbBytes(data, filePath, attribution, rows);
  return rows;
}

function copySqliteToTemp(dbPath) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-chatgpt-"));
  try {
    const base = path.basename(dbPath);
    const dest = path.join(tmpDir, base);
    fs.copyFileSync(dbPath, dest);
    for (const suffix of ["-wal", "-shm", "-journal"]) {
      const aux = path.join(path.dirname(dbPath), `${base}${suffix}`);
      if (fs.existsSync(aux)) {
        try { fs.copyFileSync(aux, path.join(tmpDir, `${base}${suffix}`)); } catch { /* ignore */ }
      }
    }
    return dest;
  } catch (e) {
    // The primary copy can throw (source vanished mid-scan, EACCES, EIO). Reclaim the just-created
    // temp dir before rethrowing so a large triage scan does not accumulate orphaned dirs.
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
    throw e;
  }
}

function extractSqliteDatabase(dbPath, attribution) {
  let Database;
  try { Database = require("better-sqlite3"); } catch (e) {
    throw new Error("SQLite support unavailable (better-sqlite3 not loaded).");
  }

  const tmpDb = copySqliteToTemp(dbPath);
  const rows = [];
  let db;
  try {
    db = new Database(tmpDb, { readonly: true, fileMustExist: true });
    const tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table'",
    ).all().map((r) => r.name);

    const tableNames = tables.filter((t) => {
      const tl = t.toLowerCase();
      if (/meta|schema|migration|version|sqlite_/.test(tl)) return false;
      return /message|chat|conv|thread|turn|interaction|mapping|completion|prompt/.test(tl);
    });

    for (const table of tableNames) {
      const cols = db.prepare(`PRAGMA table_info("${table.replace(/"/g, '""')}")`).all()
        .map((c) => c.name);
      const colLower = cols.map((c) => c.toLowerCase());

      const contentCol = cols.find((_, i) => /content|text|body|message_text|prompt|completion|parts/.test(colLower[i]));
      if (!contentCol) continue;

      const roleCol = cols.find((_, i) => /role|author|sender|speaker/.test(colLower[i]));
      const timeCol = cols.find((_, i) => /time|date|created|updated|timestamp/.test(colLower[i]));
      const modelCol = cols.find((_, i) => colLower[i].includes("model"));
      const sessionCol = cols.find((_, i) => /conversation|session|chat_id|thread/.test(colLower[i]));

      const selectCols = ["rowid", contentCol];
      if (roleCol) selectCols.push(roleCol);
      if (timeCol) selectCols.push(timeCol);
      if (modelCol) selectCols.push(modelCol);
      if (sessionCol) selectCols.push(sessionCol);

      const sql = `SELECT ${selectCols.map((c) => `"${c.replace(/"/g, '""')}"`).join(", ")} FROM "${table.replace(/"/g, '""')}"`;
      let stmt;
      try { stmt = db.prepare(sql); } catch { continue; }

      for (const rec of stmt.iterate()) {
        const content = rec[contentCol] != null ? String(rec[contentCol]) : "";
        if (!content.trim()) continue;
        const role = roleCol && rec[roleCol] != null ? String(rec[roleCol]) : "unknown";
        const tsMs = timeCol ? parseChatgptTimestamp(rec[timeCol]) : null;
        if (tsMs == null) continue;
        rows.push(makeRow({
          timestamp: formatTimestampUtc(tsMs),
          role: role || "unknown",
          recordType: "message",
          summary: content,
          sessionId: sessionCol && rec[sessionCol] != null ? String(rec[sessionCol]) : "",
          messageId: String(rec.rowid),
          parentId: "",
          workspace: "",
          toolName: "",
          isSidechain: false,
          gitBranch: "",
          tool: TOOL_CHATGPT,
          model: modelCol && rec[modelCol] != null ? String(rec[modelCol]) : "",
          sourceFile: dbPath,
          user: attribution.user || "",
          host: attribution.host || "",
        }, TOOL_CHATGPT));
      }
    }
  } finally {
    if (db) try { db.close(); } catch { /* ignore */ }
    try { fs.rmSync(path.dirname(tmpDb), { recursive: true, force: true }); } catch { /* ignore */ }
  }

  return rows;
}

function conversationBundleInfo(filePath) {
  if (!filePath) return null;
  const normalized = path.normalize(filePath);
  const parts = normalized.split(path.sep);
  let bundleDirIndex = -1;
  let version = 0;
  for (let i = 0; i < parts.length; i++) {
    const match = /^conversations-v([23])(?:-|$)/i.exec(parts[i]);
    if (!match) continue;
    bundleDirIndex = i;
    version = Number(match[1]);
    break;
  }
  if (bundleDirIndex < 0) return null;

  const base = path.basename(normalized);
  if (version === 3 && path.extname(base).toLowerCase() !== ".data") return null;
  const storeDir = parts[bundleDirIndex];
  const projectId = [...parts.slice(0, bundleDirIndex)]
    .reverse()
    .find((part) => /^project-/i.test(part)) || "";
  let sizeBytes = 0;
  let mtimeMs = null;
  try {
    const st = fs.statSync(normalized);
    if (!st.isFile()) return null;
    sizeBytes = st.size;
    mtimeMs = st.mtimeMs;
  } catch {
    return null;
  }

  return {
    path: normalized,
    version,
    storeId: storeDir.replace(/^conversations-v[23]-?/i, ""),
    projectId,
    bundleId: path.basename(base, path.extname(base)),
    sizeBytes,
    mtimeMs,
  };
}

function detectConversationBundles(appDir, maxDepth = 10) {
  const hits = [];
  if (!appDir || !fs.existsSync(appDir)) return hits;
  const stack = [{ d: appDir, depth: 0 }];
  while (stack.length) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory() && depth < maxDepth && !e.isSymbolicLink()) {
        if (!CHROMIUM_SKIP_DIR_NAMES.has(e.name)) stack.push({ d: full, depth: depth + 1 });
      } else if (e.isFile()) {
        const info = conversationBundleInfo(full);
        if (info) hits.push(info);
      }
    }
  }
  return hits;
}

function detectEncryptedConversationBundles(appDir, maxDepth = 10) {
  return detectConversationBundles(appDir, maxDepth)
    .filter((bundle) => bundle.version === 2)
    .map((bundle) => bundle.path);
}

function normalizeConversationBundles(bundles) {
  return (Array.isArray(bundles) ? bundles : []).map((bundle) => {
    if (bundle && typeof bundle === "object" && bundle.path) return bundle;
    if (typeof bundle === "string") {
      return conversationBundleInfo(bundle) || {
        path: bundle,
        version: /^conversations-v3/i.test(path.basename(path.dirname(bundle))) ? 3 : 2,
        storeId: "",
        projectId: "",
        bundleId: path.basename(bundle, path.extname(bundle)),
        sizeBytes: 0,
        mtimeMs: null,
      };
    }
    return null;
  }).filter(Boolean);
}

function buildChatgptExtractionStats(rows, appDir = null, precomputedBundles = null) {
  let conversationCount = 0;
  let messageCount = 0;
  for (const r of rows) {
    if (r.RecordType === "conversation") conversationCount += 1;
    else if (r.RecordType === "message") messageCount += 1;
  }
  const leveldbMetadataOnly = conversationCount > 0 && messageCount === 0;
  const conversationBundles = normalizeConversationBundles(
    precomputedBundles || (appDir ? detectConversationBundles(appDir) : []),
  );
  const v2BundleCount = conversationBundles.filter((bundle) => bundle.version === 2).length;
  const v3BundleCount = conversationBundles.filter((bundle) => bundle.version === 3).length;
  return {
    conversationCount,
    messageCount,
    leveldbMetadataOnly,
    // Retain the established field for warning/UI compatibility; v3 is opaque rather than
    // asserting a specific encryption mechanism.
    encryptedBundleCount: conversationBundles.length,
    conversationBundleCount: conversationBundles.length,
    v2BundleCount,
    v3BundleCount,
    encryptedBundleSample: conversationBundles.slice(0, 3).map((bundle) => bundle.path),
  };
}

function formatChatgptImportNotice(stats) {
  if (!stats) return "";
  const {
    conversationCount,
    messageCount,
    leveldbMetadataOnly,
    encryptedBundleCount,
    v2BundleCount = encryptedBundleCount || 0,
    v3BundleCount = 0,
  } = stats;
  const bundleParts = [];
  if (v2BundleCount > 0) bundleParts.push(`${v2BundleCount} encrypted conversations-v2 bundle(s)`);
  if (v3BundleCount > 0) bundleParts.push(`${v3BundleCount} opaque conversations-v3 bundle(s)`);
  const bundleText = bundleParts.join(" and ");
  if (encryptedBundleCount > 0 && messageCount === 0) {
    return `ChatGPT: found ${bundleText || `${encryptedBundleCount} conversation bundle(s)`} — metadata was inventoried, but message bodies were not decrypted or decoded.`;
  }
  if (encryptedBundleCount > 0 && messageCount > 0) {
    return `ChatGPT: ${messageCount} message(s) from SQLite; ${bundleText || `${encryptedBundleCount} conversation bundle(s)`} also inventoried, but their bodies were not decrypted or decoded.`;
  }
  if (leveldbMetadataOnly) {
    return `ChatGPT: ${conversationCount} conversation(s) from LevelDB metadata; no message bodies found in SQLite — open the app or check for a messages database.`;
  }
  if (messageCount > 0) {
    return `ChatGPT: ${messageCount} message(s)${conversationCount ? `, ${conversationCount} conversation header(s)` : ""}.`;
  }
  return `ChatGPT: ${conversationCount || messageCount} row(s) imported.`;
}

function dedupeRows(rows) {
  const seen = new Set();
  return rows.filter((r) => {
    const key = `${r.SessionId}:${r.Timestamp}:${r.Role}:${r.Summary.slice(0, 80)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function walkChatgptFiles(appDir, onFile) {
  const stack = [appDir];
  let depth = 0;
  while (stack.length && depth < 12) {
    const levelSize = stack.length;
    for (let i = 0; i < levelSize; i++) {
      const d = stack.shift();
      let entries;
      try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
      for (const e of entries) {
        const full = path.join(d, e.name);
        if (e.isSymbolicLink()) continue;
        if (e.isDirectory()) {
          if (CHROMIUM_SKIP_DIR_NAMES.has(e.name)) continue;
          stack.push(full);
        } else if (e.isFile()) onFile(full);
      }
    }
    depth++;
  }
}

function isChatgptDataFile(filePath) {
  const norm = String(filePath || "").replace(/\\/g, "/").toLowerCase();
  // TipKit is application-help state, not ChatGPT conversation evidence. Generic SQLite probing
  // previously treated this unrelated database as the only "data" in current v3 installations.
  if (norm.includes("/.tipkit/")) return false;
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath);
  if (CHATGPT_SKIP_SQLITE_NAMES.has(base.toLowerCase())) return false;
  if ((ext === ".ldb" || ext === ".log") && isInLeveldbDir(filePath)) return true;
  if (ext === ".db" || ext === ".sqlite" || ext === ".sqlite3") return true;
  if (!ext && !base.endsWith("-wal") && !base.endsWith("-shm") && !base.endsWith("-journal")
    && isSqliteFile(filePath)) return true;
  return false;
}

function conversationBundleRow(bundle, attribution = {}) {
  const isV3 = bundle.version === 3;
  const label = isV3 ? "Opaque ChatGPT conversations-v3 bundle" : "Encrypted ChatGPT conversations-v2 bundle";
  return makeRow({
    timestamp: formatTimestampUtc(bundle.mtimeMs),
    role: "system",
    recordType: isV3 ? "opaque_bundle" : "encrypted_bundle",
    summary: `${label}: ${path.basename(bundle.path)} (${bundle.sizeBytes} bytes)`,
    fullText: JSON.stringify({
      version: bundle.version,
      bundleId: bundle.bundleId,
      storeId: bundle.storeId,
      projectId: bundle.projectId,
      sizeBytes: bundle.sizeBytes,
      decoded: false,
    }),
    sessionId: bundle.bundleId || "",
    messageId: bundle.bundleId || "",
    parentId: "",
    workspace: bundle.projectId || "",
    toolName: "",
    sourceFile: bundle.path,
    user: attribution.user || "",
    host: attribution.host || "",
  }, TOOL_CHATGPT);
}

function listChatgptDataFiles(appDir) {
  const files = [];
  walkChatgptFiles(appDir, (filePath) => {
    if (isChatgptDataFile(filePath)) files.push(filePath);
  });
  return files;
}

function profileLabel(filePath) {
  const norm = String(filePath || "").replace(/\\/g, "/");
  if (/\/codex-browser-app(\/|$)/i.test(norm)) return "codex-browser-app";
  if (/\/Default(\/|$)/i.test(norm)) return "Default";
  return "profile";
}

function extractChromiumHistory(dbPath, attribution) {
  let Database;
  try { Database = require("better-sqlite3"); } catch {
    throw new Error("SQLite support unavailable (better-sqlite3 not loaded).");
  }
  const tmpDb = copySqliteToTemp(dbPath);
  const rows = [];
  let db;
  try {
    db = new Database(tmpDb, { readonly: true, fileMustExist: true });
    const tables = new Set(
      db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name),
    );
    if (!tables.has("urls") || !tables.has("visits")) return [];

    const profile = profileLabel(dbPath);
    let visitCount = 0;
    const visitSql = `
      SELECT u.url AS url, u.title AS title, u.visit_count AS visit_count,
             v.visit_time AS visit_time, v.visit_duration AS visit_duration,
             v.transition AS transition
      FROM visits v JOIN urls u ON v.url = u.id
      ORDER BY v.visit_time DESC
      LIMIT ${MAX_CHROMIUM_HISTORY_ROWS}
    `;
    let visitStmt;
    try { visitStmt = db.prepare(visitSql); } catch { visitStmt = null; }
    if (visitStmt) {
      for (const rec of visitStmt.iterate()) {
        const tsMs = chromeTimeToMs(rec.visit_time);
        if (tsMs == null) continue;
        visitCount += 1;
        const url = rec.url != null ? String(rec.url) : "";
        const title = rec.title != null ? String(rec.title) : "";
        rows.push(makeRow({
          timestamp: formatTimestampUtc(tsMs),
          role: "metadata",
          recordType: "browser_visit",
          summary: `ChatGPT app visited ${title || url}`.trim(),
          fullText: JSON.stringify({
            url,
            title,
            visitCount: rec.visit_count ?? null,
            visitDurationUs: rec.visit_duration ?? null,
            transition: rec.transition ?? null,
            profile,
            timeSource: "Chromium visits.visit_time",
          }, null, 2),
          sessionId: "",
          workspace: url,
          toolDescription: "A URL visited inside the ChatGPT/Codex desktop Chromium profile. "
            + "Dated from Chromium's internal visit_time (microseconds since 1601-01-01).",
          sourceFile: dbPath,
          user: attribution.user || "",
          host: attribution.host || "",
        }, TOOL_CHATGPT));
      }
    }

    if (tables.has("downloads")) {
      let dlStmt;
      try {
        dlStmt = db.prepare(`
          SELECT current_path, target_path, start_time, end_time, received_bytes, total_bytes, state
          FROM downloads LIMIT 2000
        `);
      } catch { dlStmt = null; }
      if (dlStmt) {
        for (const rec of dlStmt.iterate()) {
          const tsMs = chromeTimeToMs(rec.start_time) ?? chromeTimeToMs(rec.end_time);
          const target = rec.target_path || rec.current_path || "";
          rows.push(makeRow({
            timestamp: formatTimestampUtc(tsMs),
            role: "metadata",
            recordType: "browser_download",
            summary: `ChatGPT app download — ${target || "(path unknown)"}`,
            fullText: JSON.stringify({
              currentPath: rec.current_path || "",
              targetPath: rec.target_path || "",
              receivedBytes: rec.received_bytes ?? null,
              totalBytes: rec.total_bytes ?? null,
              state: rec.state ?? null,
              profile,
              timeSource: "Chromium downloads.start_time",
            }, null, 2),
            workspace: String(target),
            toolDescription: "A file downloaded by the ChatGPT/Codex desktop Chromium profile.",
            sourceFile: dbPath,
            user: attribution.user || "",
            host: attribution.host || "",
          }, TOOL_CHATGPT));
        }
      }
    }

    if (!rows.length && visitCount === 0) {
      const st = fs.statSync(dbPath);
      rows.push(makeRow({
        timestamp: formatTimestampUtc(st.mtimeMs),
        role: "metadata",
        recordType: "browser_history_empty",
        summary: `ChatGPT app Chromium history is empty (${profile})`,
        fullText: JSON.stringify({
          profile,
          sizeBytes: st.size,
          timeSource: "History file mtime",
        }, null, 2),
        toolDescription: "The History database exists but contains no visits. The merged ChatGPT/Codex "
          + "app has not recorded in-app browsing on this profile yet.",
        sourceFile: dbPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }, TOOL_CHATGPT));
    }
  } finally {
    if (db) try { db.close(); } catch { /* ignore */ }
    try { fs.rmSync(path.dirname(tmpDb), { recursive: true, force: true }); } catch { /* ignore */ }
  }
  return rows;
}

function isChromiumHistoryFile(filePath) {
  const base = path.basename(filePath || "");
  if (base !== "History") return false;
  return isSqliteFile(filePath);
}

function collectArtifactSessionInventory(appDir, attribution = {}) {
  const root = path.join(appDir, "artifact-sessions");
  if (!fs.existsSync(root)) return [];
  const rows = [];
  const stack = [root];
  let files = 0;
  let bytes = 0;
  let newest = 0;
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory() && !e.isSymbolicLink()) { stack.push(full); continue; }
      if (!e.isFile()) continue;
      files += 1;
      try {
        const st = fs.statSync(full);
        bytes += st.size;
        if (st.mtimeMs > newest) newest = st.mtimeMs;
      } catch { /* ignore */ }
    }
  }
  if (!files && !fs.existsSync(root)) return [];
  const st = fs.statSync(root);
  rows.push(makeRow({
    timestamp: formatTimestampUtc(newest || st.mtimeMs),
    role: "metadata",
    recordType: "artifact_sessions",
    summary: files
      ? `ChatGPT artifact-sessions — ${files} file(s), ${bytes} bytes`
      : "ChatGPT artifact-sessions directory present (empty)",
    fullText: JSON.stringify({
      path: root,
      fileCount: files,
      totalBytes: bytes,
      timeSource: newest ? "newest artifact-sessions mtime" : "directory mtime",
    }, null, 2),
    toolDescription: "On-disk staging folder the merged ChatGPT/Codex app uses for generated "
      + "artifacts. Contents are inventoried, not parsed.",
    sourceFile: root,
    user: attribution.user || "",
    host: attribution.host || "",
  }, TOOL_CHATGPT));
  return rows;
}

function collectCodexDesktopProfileRow(appDir, attribution = {}) {
  if (!isCodexDesktopAppDir(appDir)) return [];
  const markers = {
    hasCodexBrowserApp: fs.existsSync(path.join(appDir, "codex-browser-app")),
    hasArtifactSessions: fs.existsSync(path.join(appDir, "artifact-sessions")),
    hasDefaultHistory: fs.existsSync(path.join(appDir, "Default", "History")),
    hasLocalStorage: fs.existsSync(path.join(appDir, "Local Storage", "leveldb")),
    hasLocalState: fs.existsSync(path.join(appDir, "Local State")),
  };
  const stampSources = [
    path.join(appDir, "Local State"),
    path.join(appDir, "Preferences"),
    appDir,
  ];
  let mtimeMs = null;
  let timeSource = "directory mtime";
  for (const p of stampSources) {
    try {
      const st = fs.statSync(p);
      mtimeMs = st.mtimeMs;
      timeSource = `${path.basename(p)} mtime`;
      break;
    } catch { /* try next */ }
  }
  return [makeRow({
    timestamp: formatTimestampUtc(mtimeMs),
    role: "metadata",
    recordType: "chatgpt_desktop_profile",
    summary: "ChatGPT/Codex merged desktop Chromium profile",
    fullText: JSON.stringify({ ...markers, timeSource }, null, 2),
    toolDescription: "On 2026-07-09 OpenAI folded ChatGPT desktop into the Codex app (bundle id "
      + "com.openai.codex). This Chromium profile under Application Support/Codex is that app's "
      + "local store; conversation bodies live in ~/.codex. Presence of the profile is evidence "
      + "the merged app ran on this machine.",
    sourceFile: appDir,
    user: attribution.user || "",
    host: attribution.host || "",
  }, TOOL_CHATGPT)];
}

/* ------------------------------------------------------------------ *
 * Crash-reporter scope (merged Codex desktop profile), app pairings, credential-store inventory
 * ------------------------------------------------------------------ */

const APP_PAIRING_DIR = "app_pairing_extensions";
const MAX_BREADCRUMBS = 500;
const MAX_APP_PAIRINGS = 500;
const CHROMIUM_CREDENTIAL_STORES = ["Login Data", "Login Data For Account", "Cookies", "Web Data"];
const WRITE_CAPABILITIES = new Set(["setContent", "replace", "insert", "write", "applyEdit", "replaceSelection"]);

function secToTimestamp(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 1e9 || n >= 1e12) return "";
  return formatTimestampUtc(Math.round(n * 1000));
}

function readJsonBoundedFile(filePath, maxBytes = 4 * 1024 * 1024) {
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size > maxBytes) return null;
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch { return null; }
}

/** Drop query string and fragment — telemetry URLs can carry ids and tokens; the endpoint is the evidence. */
function stripUrlQuery(raw) {
  const value = raw == null ? "" : String(raw).trim();
  if (!value) return "";
  try {
    const u = new URL(value);
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch {
    return value.split(/[?#]/)[0];
  }
}

/** Strip the query string / fragment from every URL embedded in free text (console lines carry client keys). */
function redactUrlsInText(text) {
  return String(text ?? "").replace(/(https?:\/\/[^\s"'<>?#]+)[?#][^\s"'<>]*/gi, "$1");
}

/**
 * sentry/scope_v3.json + sentry/session.json under the merged ChatGPT/Codex desktop profile.
 * The scope carries the signed-in user id, account id and auth method, plus up to 200 timestamped
 * breadcrumbs: backend HTTP calls, UI clicks / inputs, console messages. That is a network and UI
 * trail with second precision that no other store in the profile provides.
 */
function collectCodexDesktopSentryRows(appDir, attribution = {}) {
  const rows = [];
  const scopePath = path.join(appDir, "sentry", "scope_v3.json");
  const scope = readJsonBoundedFile(scopePath);
  if (scope && typeof scope === "object") {
    const inner = scope.scope && typeof scope.scope === "object" ? scope.scope : {};
    const user = inner.user && typeof inner.user === "object" ? inner.user : {};
    const tags = inner.tags && typeof inner.tags === "object" ? inner.tags : {};
    const ctxs = scope.event?.contexts && typeof scope.event.contexts === "object" ? scope.event.contexts : {};
    const app = ctxs.app && typeof ctxs.app === "object" ? ctxs.app : {};
    const osCtx = ctxs.os && typeof ctxs.os === "object" ? ctxs.os : {};
    let mtimeMs = null;
    try { mtimeMs = fs.statSync(scopePath).mtimeMs; } catch { /* ignore */ }
    const appStart = app.app_start_time ? formatTimestampUtc(Date.parse(app.app_start_time)) : "";
    rows.push(makeRow({
      timestamp: appStart || formatTimestampUtc(mtimeMs),
      role: "metadata",
      recordType: "app_identity",
      summary: `ChatGPT/Codex desktop signed in as ${user.email || user.id || "?"}`
        + `${user.account_id ? ` (account ${user.account_id})` : ""}${user.authMethod ? `, auth ${user.authMethod}` : ""}`
        + `${scope.event?.release ? `, ${scope.event.release}` : ""}${osCtx.name ? ` on ${osCtx.name} ${osCtx.version ?? ""}`.trimEnd() : ""}`,
      fullText: JSON.stringify({
        userId: user.id ?? null,
        email: user.email ?? null,
        accountId: user.account_id ?? null,
        authMethod: user.authMethod ?? null,
        sentrySessionId: tags.sessionId ?? null,
        buildFlavor: tags.buildFlavor ?? null,
        bundle: tags.bundle ?? null,
        release: scope.event?.release ?? null,
        appVersion: app.app_version ?? null,
        appStartTime: appStart || null,
        os: osCtx.name ? { name: osCtx.name, version: osCtx.version ?? null, build: osCtx.build ?? null } : null,
        breadcrumbCount: Array.isArray(inner.breadcrumbs) ? inner.breadcrumbs.length : 0,
        timeSource: appStart ? "app_start_time" : "file mtime",
      }, null, 2),
      toolDescription: "Crash-reporter scope written by the merged ChatGPT/Codex desktop app: the signed-in "
        + "user and account, auth method, build, and the breadcrumb trail below. Attribution evidence; "
        + "no token is stored here.",
      sourceFile: scopePath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }, TOOL_CHATGPT));

    const crumbs = Array.isArray(inner.breadcrumbs) ? inner.breadcrumbs.filter((b) => b && typeof b === "object") : [];
    crumbs.slice(-MAX_BREADCRUMBS).forEach((b, idx) => {
      const data = b.data && typeof b.data === "object" ? b.data : {};
      const category = String(b.category ?? b.type ?? "breadcrumb");
      let summary;
      if (b.type === "http" || category === "fetch" || data.url) {
        summary = `${String(data.method ?? "GET").toUpperCase()} ${stripUrlQuery(data.url)}${data.status_code != null ? ` → ${data.status_code}` : ""}`;
      } else if (category === "console") {
        const args = Array.isArray(data.arguments) ? data.arguments.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ") : String(b.message ?? "");
        summary = `Console: ${redactUrlsInText(args).replace(/\s+/g, " ").trim()}`;
      } else if (/^ui\./.test(category)) {
        summary = `UI ${category.slice(3)}: ${String(b.message ?? data.target ?? "")}`;
      } else {
        summary = `${category}: ${String(b.message ?? "")}`;
      }
      rows.push(makeRow({
        timestamp: secToTimestamp(b.timestamp),
        role: "system",
        recordType: "app_breadcrumb",
        summary: summary.trim(),
        fullText: JSON.stringify({
          type: b.type ?? null,
          category,
          level: b.level ?? null,
          message: b.message != null ? redactUrlsInText(b.message) : null,
          url: data.url ? stripUrlQuery(data.url) : null,
          method: data.method ?? null,
          statusCode: data.status_code ?? null,
          queryStripped: !!(data.url && /[?#]/.test(String(data.url))),
        }),
        toolName: b.type === "http" || data.url ? "http" : category,
        toolDescription: "Sentry breadcrumb recorded by the desktop app: backend calls (query strings stripped), "
          + "UI clicks and inputs, console messages. Second-precision trail of what the app did around the last run.",
        sourceFile: scopePath,
        lineNumber: idx + 1,
        user: attribution.user || "",
        host: attribution.host || "",
      }, TOOL_CHATGPT));
    });
  }

  const sessPath = path.join(appDir, "sentry", "session.json");
  const sess = readJsonBoundedFile(sessPath);
  if (sess && typeof sess === "object") {
    const started = secToTimestamp(sess.started);
    const last = secToTimestamp(sess.timestamp);
    let mtimeMs = null;
    try { mtimeMs = fs.statSync(sessPath).mtimeMs; } catch { /* ignore */ }
    rows.push(makeRow({
      timestamp: started || formatTimestampUtc(mtimeMs),
      role: "system",
      recordType: "app_crash_reporter_session",
      summary: `ChatGPT/Codex desktop crash-reporter session ${sess.status ?? "?"} — ${sess.release ?? "?"}`
        + `${last ? `, last update ${last}` : ""}${Number(sess.errors) > 0 ? `, ${sess.errors} error(s)` : ""}`,
      fullText: JSON.stringify({
        sessionId: sess.sid ?? null,
        userId: sess.did ?? null,
        release: sess.release ?? null,
        status: sess.status ?? null,
        started: started || null,
        lastUpdate: last || null,
        durationSeconds: sess.duration ?? null,
        errors: sess.errors ?? null,
      }),
      messageId: sess.sid != null ? String(sess.sid) : "",
      toolDescription: "Sentry session record: `started` and `timestamp` bracket an app run; `did` is the signed-in user id.",
      sourceFile: sessPath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }, TOOL_CHATGPT));
  }
  return rows;
}

/**
 * com.openai.chat/app_pairing_extensions/<App>-<uuid> — ChatGPT "Work with Apps" pairings. Each
 * record names the paired application, its bundle id and the workspace, and lists capabilities;
 * `setContent` / `replace` mean ChatGPT could write into that editor, not just read it.
 */
function collectAppPairingRows(appDir, attribution = {}) {
  const dir = path.join(appDir, APP_PAIRING_DIR);
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
  const rows = [];
  for (const e of entries.filter((d) => d.isFile()).sort((a, b) => a.name.localeCompare(b.name)).slice(0, MAX_APP_PAIRINGS)) {
    const filePath = path.join(dir, e.name);
    const rec = readJsonBoundedFile(filePath, 1024 * 1024);
    if (!rec || typeof rec !== "object") continue;
    let mtimeMs = null;
    try { mtimeMs = fs.statSync(filePath).mtimeMs; } catch { /* ignore */ }
    const caps = rec.capabilities && typeof rec.capabilities === "object" ? Object.keys(rec.capabilities).filter((k) => rec.capabilities[k]) : [];
    const writeCaps = caps.filter((c) => WRITE_CAPABILITIES.has(c));
    const appName = String(rec.appName ?? e.name.split("-")[0] ?? "app");
    const workspace = rec.workspaceName != null ? String(rec.workspaceName) : "";
    rows.push(makeRow({
      timestamp: formatTimestampUtc(mtimeMs),
      role: "metadata",
      recordType: "app_pairing",
      summary: `ChatGPT paired with ${appName}${workspace ? ` — workspace "${workspace}"` : ""}`
        + ` (${caps.length} capabilit${caps.length === 1 ? "y" : "ies"}${writeCaps.length ? `, WRITE access: ${writeCaps.join("/")}` : ", read-only"})`,
      fullText: JSON.stringify({
        id: rec.id ?? e.name,
        appName,
        bundleID: rec.bundleID ?? null,
        extensionName: rec.extensionName ?? null,
        extensionVersion: rec.extensionVersion ?? null,
        marketplaceID: rec.marketplaceID ?? null,
        workspaceName: workspace || null,
        capabilities: caps,
        writeCapable: writeCaps.length > 0,
        timeSource: "file mtime",
      }, null, 2),
      workspace,
      toolInput: caps.join(", "),
      toolDescription: "ChatGPT Work-with-Apps pairing: the desktop app was granted access to this application "
        + "and workspace. Capabilities such as setContent or replace mean ChatGPT could modify the editor "
        + "content, not only read it. Dated from the file mtime.",
      sourceFile: filePath,
      lineNumber: 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }, TOOL_CHATGPT));
  }
  return rows;
}

/** Chromium credential stores in the profile and the agent's in-app browser profile — inventoried by name, never read. */
function collectChromiumCredentialStoreInventory(appDir, attribution = {}) {
  const rows = [];
  for (const profile of ["", "Default", "codex-browser-app"]) {
    for (const name of CHROMIUM_CREDENTIAL_STORES) {
      const filePath = profile ? path.join(appDir, profile, name) : path.join(appDir, name);
      let st;
      try { st = fs.statSync(filePath); } catch { continue; }
      if (!st.isFile()) continue;
      const label = profile || "profile root";
      rows.push(makeRow({
        timestamp: formatTimestampUtc(st.mtimeMs),
        role: "system",
        recordType: "credential_store_inventory",
        summary: `Chromium credential store present (not read) — ${label}/${name} (${st.size} bytes)`,
        fullText: JSON.stringify({ profile: label, fileName: name, sizeBytes: st.size, modifiedUtc: formatTimestampUtc(st.mtimeMs), contentParsed: false }, null, 2),
        toolDescription: profile === "codex-browser-app"
          ? "INVENTORY ONLY. This is the agent's in-app browser profile: a populated Login Data or Cookies "
            + "store here means the AGENT held web sessions or saved credentials. Preserve; never ingest."
          : "INVENTORY ONLY. Browser credential/cookie store of the desktop app. Preserve; never ingest.",
        sourceFile: filePath,
        lineNumber: 1,
        user: attribution.user || "",
        host: attribution.host || "",
      }, TOOL_CHATGPT));
    }
  }
  return rows;
}

function extractChatgptDataFile(filePath, attribution) {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath);
  if ((ext === ".ldb" || ext === ".log") && isInLeveldbDir(filePath)) {
    return extractLeveldbFile(filePath, attribution);
  }
  if (isChromiumHistoryFile(filePath)) {
    return extractChromiumHistory(filePath, attribution);
  }
  if (ext === ".db" || ext === ".sqlite" || ext === ".sqlite3") {
    return extractSqliteDatabase(filePath, attribution);
  }
  if (!ext && !base.endsWith("-wal") && !base.endsWith("-shm") && !base.endsWith("-journal")
    && isSqliteFile(filePath)) {
    return extractSqliteDatabase(filePath, attribution);
  }
  return [];
}

/**
 * Extract timeline rows from a ChatGPT Desktop application data directory.
 */
async function extractChatgptDir(appDir, attribution = {}, options = {}) {
  const rows = [];
  // Single tree walk collects parseable stores and opaque/encrypted conversation bundles.
  const dataFiles = [];
  const conversationBundles = [];
  walkChatgptFiles(appDir, (filePath) => {
    if (isChatgptDataFile(filePath)) dataFiles.push(filePath);
    const bundle = conversationBundleInfo(filePath);
    if (bundle) conversationBundles.push(bundle);
  });
  const fileCount = dataFiles.length;
  const { onFileProgress, onExtractedRows } = options;
  let streamConversationCount = 0;
  let streamMessageCount = 0;

  for (let i = 0; i < dataFiles.length; i++) {
    const filePath = dataFiles[i];
    tickFileProgress(onFileProgress, i + 1, fileCount, filePath);
    try {
      const fileRows = extractChatgptDataFile(filePath, attribution);
      if (onExtractedRows && fileRows.length) {
        for (const r of fileRows) {
          if (r.RecordType === "conversation") streamConversationCount += 1;
          else if (r.RecordType === "message") streamMessageCount += 1;
        }
        onExtractedRows(fileRows);
      } else {
        rows.push(...fileRows);
      }
    } catch (e) {
      dbg("AIHIST", "chatgpt file extract failed", { filePath, err: e.message });
    }
    if ((i + 1) % 12 === 0) await new Promise((r) => setImmediate(r));
  }

  const bundleRows = conversationBundles.map((bundle) => conversationBundleRow(bundle, attribution));
  const extraRows = [
    ...bundleRows,
    ...collectCodexDesktopProfileRow(appDir, attribution),
    ...collectArtifactSessionInventory(appDir, attribution),
    ...(isCodexDesktopAppDir(appDir) ? collectCodexDesktopSentryRows(appDir, attribution) : []),
    ...collectAppPairingRows(appDir, attribution),
    ...collectChromiumCredentialStoreInventory(appDir, attribution),
  ];
  if (extraRows.length) {
    if (onExtractedRows) onExtractedRows(extraRows);
    else rows.push(...extraRows);
  }

  if (onExtractedRows) {
    const out = [];
    out._chatgptStats = {
      conversationCount: streamConversationCount,
      messageCount: streamMessageCount,
      leveldbMetadataOnly: streamConversationCount > 0 && streamMessageCount === 0,
      encryptedBundleCount: conversationBundles.length,
      conversationBundleCount: conversationBundles.length,
      v2BundleCount: conversationBundles.filter((bundle) => bundle.version === 2).length,
      v3BundleCount: conversationBundles.filter((bundle) => bundle.version === 3).length,
      encryptedBundleSample: conversationBundles.slice(0, 3).map((bundle) => bundle.path),
    };
    return out;
  }

  const sorted = finalizeAiHistoryRows(dedupeRows(rows), options);
  sorted._chatgptStats = buildChatgptExtractionStats(sorted, appDir, conversationBundles);
  return sorted;
}

/** Shallow probe for profile discovery (no deep tree walk). */
function isChatgptAppDirQuick(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  if (isCodexDesktopAppDir(dirPath)) return true;
  const hints = [
    path.join(dirPath, "Local Storage", "leveldb"),
    path.join(dirPath, "IndexedDB"),
    path.join(dirPath, "databases"),
    path.join(dirPath, "conversations.db"),
  ];
  for (const h of hints) {
    if (fs.existsSync(h)) return true;
  }
  let entries;
  try { entries = fs.readdirSync(dirPath, { withFileTypes: true }); } catch { return false; }
  for (const entry of entries) {
    if (/^conversations-v[23](?:-|$)/i.test(entry.name)) return true;
    if (!entry.isDirectory() || !/^project-/i.test(entry.name)) continue;
    let projectEntries;
    try {
      projectEntries = fs.readdirSync(path.join(dirPath, entry.name), { withFileTypes: true });
    } catch {
      continue;
    }
    if (projectEntries.some((child) => child.isDirectory() && /^conversations-v[23](?:-|$)/i.test(child.name))) {
      return true;
    }
  }
  return false;
}

function isChatgptAppDir(dirPath, { quick = false } = {}) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  if (isCodexDesktopAppDir(dirPath)) return true;
  if (quick) return isChatgptAppDirQuick(dirPath);
  if (detectConversationBundles(dirPath).length > 0) return true;

  const name = path.basename(dirPath);
  const lower = dirPath.toLowerCase();
  const nameMatch = name === "com.openai.chat"
    || name === "Atlas"
    || name === "ChatGPT"
    || name === "chat.openai.com"
    || name.startsWith("OpenAI.ChatGPT")
    || /^openai\.chatgpt/i.test(name);

  const pathMatch = /packages[\\/]openai\.chatgpt/i.test(lower)
    || lower.includes("com.openai.chat")
    || (lower.includes("localcache") && lower.includes("openai"));

  if (!nameMatch && !pathMatch && !lower.includes("chatgpt") && !lower.includes("openai")) return false;

  let found = false;
  walkChatgptFiles(dirPath, (filePath) => {
    if (found) return;
    const ext = path.extname(filePath).toLowerCase();
    if (ext === ".ldb" || ext === ".log" || ext === ".db" || ext === ".sqlite" || ext === ".sqlite3") {
      found = true;
      return;
    }
    if (!ext && isSqliteFile(filePath)) found = true;
  });
  return found;
}

function resolveChatgptDir(target) {
  if (!target) return null;
  if (isChatgptAppDir(target)) return target;
  const base = path.basename(target);
  if (base === "ChatGPT" || base === "com.openai.chat" || base === "Atlas" || base === "Codex") {
    const parent = path.dirname(target);
    if (isChatgptAppDir(parent)) return parent;
  }
  return isChatgptAppDir(target) ? target : null;
}

async function extractChatgptPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  const stat = fs.statSync(target);
  if (stat.isDirectory()) {
    const appDir = resolveChatgptDir(target) || target;
    if (!isChatgptAppDir(appDir)) {
      throw new Error("Not a ChatGPT Desktop data directory (no LevelDB/SQLite stores found).");
    }
    return extractChatgptDir(appDir, attribution, options);
  }

  if (stat.isFile()) {
    const ext = path.extname(target).toLowerCase();
    const rows = [];
    const bundle = conversationBundleInfo(target);
    if (bundle) {
      rows.push(conversationBundleRow(bundle, attribution));
    } else if ((ext === ".ldb" || ext === ".log") && isInLeveldbDir(target)) {
      rows.push(...extractLeveldbFile(target, attribution));
    } else if (isChromiumHistoryFile(target)) {
      rows.push(...extractChromiumHistory(target, attribution));
    } else if (ext === ".db" || ext === ".sqlite" || ext === ".sqlite3" || isSqliteFile(target)) {
      rows.push(...extractSqliteDatabase(target, attribution));
    } else {
      throw new Error("Expected a ChatGPT conversation bundle, LevelDB (.ldb), or SQLite database file.");
    }
    return finalizeAiHistoryRows(dedupeRows(rows), options);
  }

  throw new Error("Expected a ChatGPT data directory or database file.");
}

module.exports = {
  collectCodexDesktopSentryRows,
  collectAppPairingRows,
  collectChromiumCredentialStoreInventory,
  stripUrlQuery,
  redactUrlsInText,
  extractChatgptDir,
  extractChatgptPath,
  isChatgptAppDir,
  isChatgptAppDirQuick,
  isCodexDesktopAppDir,
  chromeTimeToMs,
  resolveChatgptDir,
  parseChatgptTimestamp,
  parseConversationItem,
  extractFromLeveldbBytes,
  extractLeveldbFile,
  extractSqliteDatabase,
  isSqliteFile,
  isInLeveldbDir,
  buildChatgptExtractionStats,
  formatChatgptImportNotice,
  conversationBundleInfo,
  detectConversationBundles,
  detectEncryptedConversationBundles,
  isChatgptDataFile,
  listChatgptDataFiles,
};
