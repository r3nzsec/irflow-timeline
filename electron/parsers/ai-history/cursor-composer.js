/**
 * cursor-composer.js — Cursor composer chat extraction from state.vscdb / store.db.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { TOOL_CURSOR } = require("./schema");
const { tickFileProgress } = require("./extract-plan");
const {
  formatTimestampUtc,
  parseIsoTimestamp,
  makeRow,
  assignLineNumber,
} = require("./row-utils");
const {
  openVscdbReadOnly,
  listComposerDataRows,
  loadBubblesForComposer,
  loadBubbleMapForComposer,
  parseKvValue,
  findVscdbFilesUnder,
  readWorkspaceJsonMap,
  safeCloseDb,
  kvTableNames,
} = require("./vscdb-kv");
const { formatWorkspaceDisplay } = require("./workspace-utils");
const { copySqliteFamilyToTemp } = require("./codex-state-sqlite");
const { pageDiscoveryInventory } = require("./discovery-inventory");

const CURSOR_DIR_NAME = ".cursor";
const CONVERSATION_SEARCH_DB = "conversation-search.db";
const COMPOSER_YIELD_EVERY = 8;

// Cursor IDE User-data layouts, relative to a user home (macOS / Linux / Windows).
const CURSOR_USER_DATA_SUFFIXES = [
  ["Library", "Application Support", "Cursor", "User"],
  [".config", "Cursor", "User"],
  ["AppData", "Roaming", "Cursor", "User"],
];

/** The user home that owns a .cursor (or Cursor User) root, derived from the path itself. */
function deriveUserHomeFromCursorRoot(cursorRoot) {
  const norm = path.resolve(cursorRoot);
  if (path.basename(norm) === CURSOR_DIR_NAME) return path.dirname(norm);
  const lower = norm.replace(/\\/g, "/").toLowerCase();
  for (const suffix of [
    "/library/application support/cursor/user",
    "/.config/cursor/user",
    "/appdata/roaming/cursor/user",
  ]) {
    const idx = lower.lastIndexOf(suffix);
    if (idx > 0) return norm.slice(0, idx);
  }
  return path.dirname(norm);
}

/**
 * Cursor IDE User dirs for the home that OWNS this cursorRoot — NOT os.homedir(). During forensic
 * triage cursorRoot lives under the seized collection, so deriving the User dir from it keeps
 * composer reads inside the evidence tree instead of scanning the live analyst's own Cursor data
 * (which would both contaminate the timeline and read outside the authorized scan scope).
 */
function cursorUserDataDirsForRoot(cursorRoot) {
  const home = deriveUserHomeFromCursorRoot(cursorRoot);
  const out = [];
  for (const parts of CURSOR_USER_DATA_SUFFIXES) {
    const p = path.join(home, ...parts);
    try { if (fs.statSync(p).isDirectory()) out.push(p); } catch { /* not in this collection */ }
  }
  return out;
}

function isCursorUserDataDir(dirPath) {
  if (!dirPath || path.basename(dirPath) !== "User") return false;
  try { if (!fs.statSync(dirPath).isDirectory()) return false; } catch { return false; }
  const globalStorage = path.join(dirPath, "globalStorage");
  const workspaceStorage = path.join(dirPath, "workspaceStorage");
  // conversation-search.db is Cursor-specific and survives relocation into an evidence
  // folder. Generic state.vscdb/workspaceStorage markers also exist in VS Code products,
  // so require a Cursor-branded parent path before accepting those weaker markers.
  if (fs.existsSync(path.join(globalStorage, CONVERSATION_SEARCH_DB))) return true;
  const cursorBrandedPath = path.resolve(dirPath)
    .split(/[\\/]+/)
    .some((part) => part.toLowerCase() === "cursor");
  return cursorBrandedPath && (
    fs.existsSync(path.join(globalStorage, "state.vscdb"))
    || fs.existsSync(workspaceStorage)
  );
}

function cursorComposerRow(fields) {
  return makeRow({ ...fields, tool: TOOL_CURSOR }, TOOL_CURSOR);
}

function bubbleRole(type) {
  const n = Number(type);
  if (n === 1) return "user";
  if (n === 2) return "assistant";
  return null;
}

function bubbleText(bubble) {
  if (!bubble || typeof bubble !== "object") return "";
  if (bubble.text != null && String(bubble.text).trim()) return String(bubble.text).trim();
  if (bubble.rawText != null && String(bubble.rawText).trim()) return String(bubble.rawText).trim();
  if (Array.isArray(bubble.richText)) {
    return bubble.richText.map((p) => (p && p.text) || "").filter(Boolean).join(" ").trim();
  }
  return "";
}

function parseMaybeJson(value) {
  if (value == null || value === "") return null;
  if (typeof value === "object") return value;
  const text = String(value);
  try { return JSON.parse(text); } catch { return text; }
}

function cursorBubbleToolEvidence(bubble) {
  if (!bubble || typeof bubble !== "object") return null;
  const former = bubble.toolFormerData && typeof bubble.toolFormerData === "object"
    ? bubble.toolFormerData : null;
  const toolResults = Array.isArray(bubble.toolResults) ? bubble.toolResults : [];
  const interpreterResults = Array.isArray(bubble.interpreterResults) ? bubble.interpreterResults : [];
  if (!former && !toolResults.length && !interpreterResults.length) return null;

  const args = parseMaybeJson(former?.params ?? former?.rawArgs);
  const result = parseMaybeJson(former?.result);
  const command = args && typeof args === "object" && !Array.isArray(args)
    ? String(args.command ?? args.cmd ?? args.script ?? "") : "";
  const name = String(former?.name ?? former?.toolName ?? "cursor_tool");
  const status = String(former?.status ?? former?.additionalData?.status ?? "unknown");
  return {
    name,
    status,
    command,
    args,
    result,
    toolCallId: String(former?.toolCallId ?? ""),
    modelCallId: String(former?.modelCallId ?? ""),
    toolIndex: former?.toolIndex ?? null,
    numericTool: former?.tool ?? null,
    additionalData: former?.additionalData ?? null,
    toolCallBinaryPresent: !!former?.toolCallBinary,
    toolResults,
    interpreterResults,
  };
}

function parseBubbleRow(bubble, composerId, sourceFile, attribution, workspace, headerIndex) {
  const toolEvidence = cursorBubbleToolEvidence(bubble);
  const role = toolEvidence ? "tool" : bubbleRole(bubble.type);
  if (!role) return null;
  const summary = bubbleText(bubble);
  if (!summary && !toolEvidence) return null;

  let tsMs = null;
  if (bubble.createdAt != null) {
    const n = Number(bubble.createdAt);
    if (Number.isFinite(n)) tsMs = n > 1e12 ? n : n * 1000;
    else tsMs = parseIsoTimestamp(bubble.createdAt);
  }
  if (tsMs == null && bubble.timestamp != null) {
    const n = Number(bubble.timestamp);
    if (Number.isFinite(n)) tsMs = n > 1e12 ? n : n * 1000;
  }

  const usage = bubble.tokenCount || bubble.usage || {};
  const inputTokens = usage.inputTokens ?? usage.input_tokens ?? "";
  const outputTokens = usage.outputTokens ?? usage.output_tokens ?? "";

  const evidenceBody = toolEvidence ? {
    text: summary || null,
    tool: toolEvidence,
    requestId: bubble.requestId ?? null,
    serverBubbleId: bubble.serverBubbleId ?? null,
    attachedFiles: bubble.attachedFileCodeChunksMetadataOnly ?? [],
    images: bubble.images ?? [],
    relevantFiles: bubble.relevantFiles ?? [],
    webReferences: bubble.webReferences ?? [],
  } : null;
  return cursorComposerRow({
    timestamp: tsMs != null ? formatTimestampUtc(tsMs) : "",
    timestampBasis: bubble.createdAt != null
      ? "composer bubble createdAt"
      : (bubble.timestamp != null ? "composer bubble timestamp" : "unavailable"),
    role,
    recordType: toolEvidence ? "composer_tool_evidence" : role,
    summary: toolEvidence
      ? `[Cursor tool: ${toolEvidence.name}] ${toolEvidence.status}` + (summary ? ` — ${summary}` : "")
      : summary,
    fullText: toolEvidence ? JSON.stringify(evidenceBody, null, 2) : summary,
    toolName: toolEvidence?.name || "",
    toolCommand: toolEvidence?.command || "",
    toolInput: toolEvidence?.args == null
      ? ""
      : (typeof toolEvidence.args === "string" ? toolEvidence.args : JSON.stringify(toolEvidence.args)),
    toolDescription: toolEvidence
      ? `Structured Cursor composer tool evidence; native status=${toolEvidence.status}. Tool result fields are preserved in FullText.`
      : "",
    sessionId: composerId,
    messageId: bubble.bubbleId != null ? String(bubble.bubbleId) : (toolEvidence?.toolCallId || ""),
    parentId: toolEvidence?.modelCallId || toolEvidence?.toolCallId || "",
    workspace,
    sourceFile,
    lineNumber: headerIndex != null ? String(headerIndex) : "",
    inputTokens: inputTokens !== "" ? String(inputTokens) : "",
    outputTokens: outputTokens !== "" ? String(outputTokens) : "",
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function extractComposerSessionRows(compData, composerId, db, dbPath, attribution, workspaceLabel) {
  const rows = [];
  let headers = [];
  if (compData && Array.isArray(compData.fullConversationHeadersOnly)) {
    headers = compData.fullConversationHeadersOnly;
  }

  if (headers.length) {
    // Bulk-load this composer's bubbles in ONE scoped query, then look up per header by key —
    // replaces the prior per-header `SELECT … WHERE key = ?` (N+1: 100+ round-trips for a long session).
    const bubbleMap = loadBubbleMapForComposer(db, composerId);
    let idx = 0;
    for (const h of headers) {
      idx += 1;
      const bubbleId = h.bubbleId || h.id;
      if (!bubbleId) continue;
      const bubble = bubbleMap.get(`bubbleId:${composerId}:${bubbleId}`) || null;
      const row = parseBubbleRow(
        bubble || { type: h.type, text: "" },
        composerId,
        dbPath,
        attribution,
        workspaceLabel,
        idx,
      );
      if (row) rows.push(assignLineNumber(row, idx));
    }
    return rows;
  }

  const bubbles = loadBubblesForComposer(db, composerId);
  let idx = 0;
  for (const bubble of bubbles) {
    idx += 1;
    const row = parseBubbleRow(bubble, composerId, dbPath, attribution, workspaceLabel, idx);
    if (row) rows.push(assignLineNumber(row, idx));
  }
  return rows;
}

async function extractBubblesFromDb(db, dbPath, attribution, workspaceLabel, options = {}) {
  const rows = [];
  let messageRows = 0;
  const composerRows = listComposerDataRows(db);
  const { checkAbort, onComposerProgress, onExtractedRows } = options;
  let composersDone = 0;

  for (const { key, value } of composerRows) {
    composersDone += 1;
    if (typeof checkAbort === "function") checkAbort();
    if (typeof onComposerProgress === "function") {
      onComposerProgress(composersDone, composerRows.length, dbPath);
    }

    const composerId = key.slice("composerData:".length);
    if (!composerId) continue;
    const compData = parseKvValue(value);
    const chunk = extractComposerSessionRows(
      compData,
      composerId,
      db,
      dbPath,
      attribution,
      workspaceLabel,
    );
    if (chunk.length) {
      messageRows += chunk.length;
      if (onExtractedRows) onExtractedRows(chunk);
      else rows.push(...chunk);
    }

    if (composersDone % COMPOSER_YIELD_EVERY === 0) {
      await new Promise((r) => setImmediate(r));
    }
  }

  rows._extractedCount = messageRows;
  return rows;
}

function workspaceLabelForDb(dbPath, cursorHome) {
  const norm = dbPath.replace(/\\/g, "/");
  const wsMatch = norm.match(/workspaceStorage\/([^/]+)\//i);
  if (wsMatch && cursorHome) {
    const map = readWorkspaceJsonMap(cursorHome);
    const folder = map.get(wsMatch[1]);
    if (folder) return formatWorkspaceDisplay(folder, folder);
  }
  if (norm.includes("/chats/")) {
    const slug = norm.split("/chats/")[1]?.split("/")[0];
    if (slug) return `Cursor chat workspace ${slug}`;
  }
  if (norm.includes("globalStorage")) return "Cursor (global composer)";
  return "Cursor composer";
}

function extractConversationSearchRows(db, dbPath, attribution, options = {}) {
  const rows = [];
  const tables = new Set(db.prepare(
    "SELECT name FROM sqlite_master WHERE type IN ('table','view')",
  ).all().map((row) => row.name));
  if (!tables.has("conversations") || !tables.has("conversation_fts")) return rows;

  const maxRows = Math.max(1, Math.min(Number(options.maxConversationSearchRows) || 5000, 20000));
  const records = db.prepare(`
    SELECT
      c.fts_rowid,
      c.source,
      c.scope,
      c.id,
      c.title,
      c.updated_at,
      c.is_archived,
      f.body
    FROM conversations c
    JOIN conversation_fts f ON f.rowid = c.fts_rowid
    ORDER BY c.updated_at ASC, c.fts_rowid ASC
    LIMIT ?
  `).all(maxRows);

  for (const record of records) {
    const rawTs = Number(record.updated_at);
    const timestampMs = Number.isFinite(rawTs)
      ? (rawTs > 1e12 ? rawTs : rawTs > 1e9 ? rawTs * 1000 : null)
      : null;
    const title = String(record.title || "").trim();
    const body = String(record.body || "").trim();
    const scope = String(record.scope || "").trim();
    const source = String(record.source || "local").trim();
    const archived = Number(record.is_archived) === 1;
    const identifier = record.id != null && String(record.id).trim()
      ? String(record.id)
      : String(record.fts_rowid ?? "");
    const summary = title
      ? `${title}${archived ? " [archived]" : ""}`
      : `Cursor indexed conversation ${identifier || "(unknown)"}${archived ? " [archived]" : ""}`;
    const fullText = body || JSON.stringify({
      conversationId: identifier,
      title,
      source,
      scope,
      archived,
      bodyPresent: false,
    }, null, 2);
    rows.push(cursorComposerRow({
      timestamp: formatTimestampUtc(timestampMs),
      timestampBasis: timestampMs != null ? "conversation index updated_at" : "unavailable",
      role: "conversation",
      recordType: "conversation_search",
      summary,
      fullText,
      sessionId: identifier,
      messageId: record.fts_rowid != null ? String(record.fts_rowid) : "",
      workspace: scope
        ? `Cursor conversation search — ${source}/${scope}`
        : `Cursor conversation search — ${source}`,
      sourceFile: dbPath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

function listCursorComposerDbsWithStats(cursorRoot, extraUserDirs = [], options = {}) {
  // Stay inside the supplied root: never fall back to the live ~/.cursor (defaultCursorHome).
  const agentHome = cursorRoot;

  const dbs = new Set();
  const userDirs = [...extraUserDirs, ...cursorUserDataDirsForRoot(cursorRoot)];
  for (const userDir of userDirs) {
    const globalVscdb = path.join(userDir, "globalStorage", "state.vscdb");
    if (fs.existsSync(globalVscdb)) dbs.add(globalVscdb);
    const conversationSearch = path.join(userDir, "globalStorage", CONVERSATION_SEARCH_DB);
    if (fs.existsSync(conversationSearch)) dbs.add(conversationSearch);
    for (const p of findVscdbFilesUnder(userDir, { maxDepth: 8, maxFiles: 100000 })) {
      dbs.add(p);
    }
  }

  const chatsDir = path.join(agentHome, "chats");
  if (fs.existsSync(chatsDir)) {
    for (const p of findVscdbFilesUnder(chatsDir, { maxDepth: 12, maxFiles: 100000 })) {
      dbs.add(p);
    }
  }

  const eligiblePaths = [...dbs].sort();
  const maxDatabases = Math.max(1, Math.min(Number(options.maxCursorDatabases) || 2048, 100000));
  const page = pageDiscoveryInventory(eligiblePaths, {
    limit: maxDatabases,
    cursor: options.cursorDatabaseCursor,
  });
  const paths = page.paths;
  let companions = 0;
  for (const dbPath of eligiblePaths) {
    for (const suffix of ["-wal", "-shm"]) if (fs.existsSync(`${dbPath}${suffix}`)) companions += 1;
  }
  return {
    paths,
    eligiblePaths,
    stats: {
      eligibleDatabases: eligiblePaths.length,
      selectedDatabases: paths.length,
      omittedDatabases: Math.max(0, eligiblePaths.length - paths.length),
      remainingDatabasePaths: page.remainingPaths,
      nextCursor: page.nextCursor,
      inventoryFingerprintSha256: page.fingerprintSha256,
      companionFiles: companions,
      maxDatabases,
    },
  };
}

function listCursorComposerDbs(cursorRoot, extraUserDirs = [], options = {}) {
  return listCursorComposerDbsWithStats(cursorRoot, extraUserDirs, options).paths;
}

/**
 * @param {string} cursorRoot — ~/.cursor or Cursor User folder
 */
async function extractCursorComposerStores(cursorRoot, attribution = {}, options = {}) {
  const rows = [];
  const stats = {
    databases: 0,
    messageRows: 0,
    searchDatabases: 0,
    searchRows: 0,
    failed: 0,
    unsupported: 0,
    empty: 0,
    acquisitions: [],
  };
  // Derive everything from the supplied (possibly forensic) root — do not touch the live host.
  const discovered = listCursorComposerDbsWithStats(cursorRoot, options.userDataDirs || [], options);
  const dbPaths = discovered.paths;
  Object.assign(stats, discovered.stats);
  let fileIndex = 0;
  const { onFileProgress, checkAbort, onExtractedRows } = options;

  for (const dbPath of dbPaths) {
    fileIndex += 1;
    tickFileProgress(onFileProgress, fileIndex, dbPaths.length, dbPath);
    if (typeof checkAbort === "function") checkAbort();

    let snapshot;
    let db;
    try {
      snapshot = copySqliteFamilyToTemp(dbPath, { checkAbort });
      stats.acquisitions.push({
        source: dbPath,
        method: snapshot.snapshotMethod,
        acquiredAtMs: snapshot.acquiredAtMs,
        integrityCheck: snapshot.integrityCheck,
        originalIdentity: snapshot.originalIdentity,
        snapshotIdentity: snapshot.snapshotIdentity,
      });
      db = openVscdbReadOnly(snapshot.dbPath);
      stats.databases += 1;
      if (path.basename(dbPath) === CONVERSATION_SEARCH_DB) {
        const chunk = extractConversationSearchRows(db, dbPath, attribution, options);
        stats.searchDatabases += 1;
        stats.searchRows += chunk.length;
        stats.messageRows += chunk.length;
        if (chunk.length) {
          if (onExtractedRows) onExtractedRows(chunk);
          else rows.push(...chunk);
        }
        continue;
      }
      if (!kvTableNames(db).length) {
        stats.unsupported += 1;
        continue;
      }
      const ws = workspaceLabelForDb(dbPath, cursorUserDataDirsForRoot(cursorRoot)[0] || cursorRoot);
      const chunk = await extractBubblesFromDb(db, dbPath, attribution, ws, {
        checkAbort,
        onExtractedRows,
        onComposerProgress: (composerIndex, composerTotal) => {
          if (typeof onFileProgress !== "function") return;
          const base = path.basename(dbPath);
          const detail = composerTotal > 0
            ? `${base} — composers ${composerIndex}/${composerTotal}`
            : base;
          onFileProgress(fileIndex, dbPaths.length, detail);
        },
      });
      const extracted = chunk._extractedCount ?? chunk.length;
      stats.messageRows += extracted;
      if (!extracted) stats.empty += 1;
      if (!onExtractedRows) rows.push(...chunk);
    } catch (e) {
      if (e?.canceled || e?.cancelled) throw e;
      stats.failed += 1;
      dbg("AIHIST", "cursor composer db failed", { dbPath, err: e.message });
    } finally {
      safeCloseDb(db);
      if (snapshot) snapshot.cleanup();
    }
    if (fileIndex % 2 === 0) await new Promise((r) => setImmediate(r));
  }

  if (onExtractedRows) {
    const out = [];
    out._cursorComposerStats = stats;
    return { rows: out, stats };
  }

  return { rows, stats };
}

function buildCursorComposerImportNotice(stats) {
  if (!stats || !stats.eligibleDatabases) return "";
  const inventory = `${stats.selectedDatabases}/${stats.eligibleDatabases} eligible SQLite store(s) selected`
    + `${stats.omittedDatabases ? `; ${stats.omittedDatabases} omitted by the explicit database cap` : "; no database omitted"}`
    + `${stats.failed ? `; ${stats.failed} failed` : ""}`
    + `${stats.unsupported ? `; ${stats.unsupported} unsupported schema` : ""}`;
  if (stats.messageRows > 0) {
    const search = stats.searchRows > 0
      ? `; ${stats.searchRows} conversation-search row(s) from ${stats.searchDatabases} index`
      : "";
    return `Cursor local DBs: ${stats.messageRows} row(s) from ${stats.databases} opened SQLite store(s)${search}; ${inventory}.`;
  }
  return `Cursor local DBs: ${inventory}; opened ${stats.databases} store(s) but found no composer or conversation-search rows.`;
}

module.exports = {
  CONVERSATION_SEARCH_DB,
  extractCursorComposerStores,
  extractBubblesFromDb,
  extractConversationSearchRows,
  listCursorComposerDbs,
  listCursorComposerDbsWithStats,
  cursorBubbleToolEvidence,
  deriveUserHomeFromCursorRoot,
  cursorUserDataDirsForRoot,
  isCursorUserDataDir,
  buildCursorComposerImportNotice,
};
