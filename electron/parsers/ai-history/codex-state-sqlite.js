/**
 * codex-state-sqlite.js — supplemental Codex thread metadata from state*.sqlite.
 *
 * Codex versions the active store (for example state_5.sqlite). Live stores commonly use WAL,
 * so extraction snapshots the primary database with its -wal/-shm/-journal companions before
 * opening it. SourceFile always points to the acquired artifact, not the temporary copy.
 *
 * Tables read explicitly: `threads`, `thread_spawn_edges`, `thread_dynamic_tools`, and (state_5+)
 * `remote_control_enrollments` — the record that this host's Codex app-server was paired for
 * Remote Control, i.e. that a ChatGPT client elsewhere could drive Codex on this machine through
 * the listed relay. Its columns carry no thread or session name, so the generic table sweep below
 * would never surface it; it needs its own reader.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { dbg } = require("../../logger");
const { openVscdbReadOnly, listTables, safeCloseDb } = require("./vscdb-kv");
const { TOOL_CODEX } = require("./schema");
const { formatTimestampUtc, parseIsoTimestamp, makeRow, sortAndNumberRows } = require("./row-utils");

/** Parse epoch-seconds, epoch-ms, or ISO strings to epoch ms. */
function parseFlexibleTimestamp(raw) {
  if (raw == null || raw === "") return null;
  const s = String(raw).trim();
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    if (!Number.isFinite(n)) return null;
    return n > 1e12 ? n : (n > 1e9 ? n * 1000 : null);
  }
  return parseIsoTimestamp(s);
}

function codexMetaRow(fields) {
  return makeRow({ ...fields, tool: TOOL_CODEX, role: fields.role || "system", recordType: fields.recordType || "thread_index" }, TOOL_CODEX);
}

function pickString(obj, keys) {
  if (!obj || typeof obj !== "object") return "";
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string" && v.trim()) return v.trim();
    if (typeof v === "number" && Number.isFinite(v)) return String(v);
  }
  return "";
}

function pickValue(obj, keys) {
  if (!obj || typeof obj !== "object") return null;
  for (const k of keys) {
    if (obj[k] != null && obj[k] !== "") return obj[k];
  }
  return null;
}

function serializeSafe(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function listCodexStateSqliteFiles(codexRoot) {
  let entries;
  try { entries = fs.readdirSync(codexRoot, { withFileTypes: true }); } catch { return []; }
  const files = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const match = /^state(?:_(\d+))?\.sqlite$/i.exec(entry.name);
    if (!match) continue;
    const filePath = path.join(codexRoot, entry.name);
    let mtimeMs = 0;
    try { mtimeMs = fs.statSync(filePath).mtimeMs; } catch { /* ignore */ }
    files.push({
      path: filePath,
      version: match[1] == null ? 0 : Number(match[1]),
      mtimeMs,
    });
  }
  files.sort((a, b) => (b.version - a.version) || (b.mtimeMs - a.mtimeMs) || a.path.localeCompare(b.path));
  return files.map((entry) => entry.path);
}

function hashFileSha256(filePath, checkAbort = () => {}) {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(filePath, "r");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let offset = 0;
  try {
    while (true) {
      checkAbort();
      const read = fs.readSync(fd, buffer, 0, buffer.length, offset);
      if (!read) break;
      hash.update(buffer.subarray(0, read));
      offset += read;
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}

function sqliteSourceIdentity(filePath, options = {}) {
  const checkAbort = typeof options.checkAbort === "function" ? options.checkAbort : () => {};
  const before = fs.statSync(filePath);
  const sha256 = options.hash === false ? null : hashFileSha256(filePath, checkAbort);
  const after = fs.statSync(filePath);
  return {
    path: filePath,
    sizeBytes: before.size,
    modifiedAtMs: Math.trunc(before.mtimeMs),
    sha256,
    hashStatus: sha256 ? "computed" : "not_requested",
    stableDuringHash: before.size === after.size && Math.trunc(before.mtimeMs) === Math.trunc(after.mtimeMs),
    observedAfter: {
      sizeBytes: after.size,
      modifiedAtMs: Math.trunc(after.mtimeMs),
    },
  };
}

function hasSqliteHeader(filePath) {
  const fd = fs.openSync(filePath, "r");
  const header = Buffer.alloc(16);
  try {
    return fs.readSync(fd, header, 0, header.length, 0) === header.length
      && header.equals(Buffer.from("SQLite format 3\0", "binary"));
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Acquire a consistent SQLite snapshot. VACUUM INTO reads one SQLite transaction and includes
 * committed WAL pages. Non-SQLite/corrupt inputs retain the prior family-copy fallback so the
 * parser can report an unsupported source without mutating evidence.
 */
function copySqliteFamilyToTemp(dbPath, options = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-state-"));
  const base = path.basename(dbPath);
  const dest = path.join(tmpDir, base);
  const sidecars = [];
  const checkAbort = typeof options.checkAbort === "function" ? options.checkAbort : () => {};
  const family = [dbPath];
  for (const suffix of ["-wal", "-shm", "-journal"]) {
    const source = `${dbPath}${suffix}`;
    if (fs.existsSync(source)) {
      family.push(source);
      sidecars.push(source);
    }
  }
  const acquiredAtMs = Date.now();
  try {
    const originalIdentity = family.map((source) => sqliteSourceIdentity(source, {
      hash: options.hashOriginals !== false,
      checkAbort,
    }));
    let snapshotMethod = "sqlite_vacuum_into";
    let integrityCheck = "ok";
    let sourceDb = null;
    try {
      checkAbort();
      if (!hasSqliteHeader(dbPath)) throw new Error("not a SQLite database header");
      sourceDb = openVscdbReadOnly(dbPath);
      sourceDb.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`);
    } catch {
      snapshotMethod = "family_copy_fallback";
      integrityCheck = "not_checked";
      try { sourceDb?.close(); } catch { /* ignore */ }
      sourceDb = null;
      fs.copyFileSync(dbPath, dest);
      for (const source of sidecars) {
        checkAbort();
        fs.copyFileSync(source, `${dest}${source.slice(dbPath.length)}`);
      }
    } finally {
      try { sourceDb?.close(); } catch { /* ignore */ }
    }
    if (snapshotMethod === "sqlite_vacuum_into") {
      const verifyDb = openVscdbReadOnly(dest);
      try {
        integrityCheck = String(verifyDb.prepare("PRAGMA quick_check").pluck().get() || "unknown");
      } finally {
        verifyDb.close();
      }
      if (integrityCheck !== "ok") throw new Error(`SQLite snapshot integrity check failed: ${integrityCheck}`);
    }
    const snapshotIdentity = sqliteSourceIdentity(dest, { hash: true, checkAbort });
    return {
      dbPath: dest,
      sidecars,
      acquiredAtMs,
      snapshotMethod,
      integrityCheck,
      originalIdentity,
      snapshotIdentity,
      cleanup: () => {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
      },
    };
  } catch (e) {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
    throw e;
  }
}

function parseMaybeJson(val) {
  if (val == null) return null;
  if (Buffer.isBuffer(val)) val = val.toString("utf8");
  if (typeof val !== "string") return val;
  const t = val.trim();
  if (!t) return null;
  try { return JSON.parse(t); } catch { return t; }
}

function rowFromThreadRecord(rec, sourceFile, attribution) {
  const title = pickString(rec, ["title", "name", "subject", "summary", "displayName", "thread_title"]);
  const sessionId = pickString(rec, ["session_id", "sessionId", "thread_id", "threadId", "id", "uuid"]);
  const tsRaw = pickValue(rec, [
    "updated_at_ms",
    "updatedAtMs",
    "updated_at",
    "updatedAt",
    "created_at_ms",
    "createdAtMs",
    "created_at",
    "createdAt",
    "ts",
    "timestamp",
    "last_message_at",
  ]);
  const tsMs = parseFlexibleTimestamp(tsRaw);
  const ts = tsMs != null ? formatTimestampUtc(tsMs) : "";
  const workspace = pickString(rec, ["cwd", "workspace", "project_path", "projectPath"]);
  const model = pickString(rec, ["model", "model_provider", "modelProvider"]);
  const gitBranch = pickString(rec, ["git_branch", "gitBranch"]);
  const threadSource = pickString(rec, ["thread_source", "threadSource", "source"]);
  const agentRole = pickString(rec, ["agent_role", "agentRole"]);
  const isSidechain = /subagent|sub-agent|child|fork/i.test(`${threadSource} ${agentRole}`);
  const preview = pickString(rec, ["preview", "first_user_message", "firstUserMessage"]);
  const summary = title
    ? `Codex thread index: ${title}`
    : sessionId
      ? `Codex thread index: ${sessionId}`
      : `Codex thread index entry (${path.basename(sourceFile)})`;
  const metadata = {
    title,
    source: threadSource,
    modelProvider: pickString(rec, ["model_provider", "modelProvider"]),
    agentNickname: pickString(rec, ["agent_nickname", "agentNickname"]),
    agentRole,
    approvalMode: pickString(rec, ["approval_mode", "approvalMode"]),
    sandboxPolicy: pickString(rec, ["sandbox_policy", "sandboxPolicy"]),
    rolloutPath: pickString(rec, ["rollout_path", "rolloutPath"]),
    archived: rec.archived == null ? undefined : !!rec.archived,
    archivedAt: (() => { const ms = parseFlexibleTimestamp(pickValue(rec, ["archived_at"])); return ms == null ? undefined : formatTimestampUtc(ms); })(),
    tokensUsed: pickValue(rec, ["tokens_used", "tokensUsed"]),
    preview,
    name: pickString(rec, ["name"]) || undefined,
    isPinned: rec.is_pinned == null ? undefined : !!rec.is_pinned,
    gitOriginUrl: pickString(rec, ["git_origin_url"]) || undefined,
    gitSha: pickString(rec, ["git_sha"]) || undefined,
    cliVersion: pickString(rec, ["cli_version"]) || undefined,
    reasoningEffort: pickString(rec, ["reasoning_effort"]) || undefined,
    historyMode: pickString(rec, ["history_mode"]) || undefined,
    memoryMode: pickString(rec, ["memory_mode"]) || undefined,
    projectId: pickString(rec, ["project_id"]) || undefined,
    sectionId: pickString(rec, ["thread_section_id"]) || undefined,
    createdAt: (() => { const ms = parseFlexibleTimestamp(pickValue(rec, ["created_at_ms", "created_at"])); return ms == null ? undefined : formatTimestampUtc(ms); })(),
  };
  return codexMetaRow({
    timestamp: ts,
    role: "system",
    recordType: "thread_index",
    summary,
    fullText: serializeSafe(metadata),
    sessionId,
    messageId: "",
    parentId: "",
    workspace,
    toolName: "",
    isSidechain,
    gitBranch,
    model,
    sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function extractRowsFromTable(db, tableName, sourceFile, attribution, maxRows) {
  const rows = [];
  let columns;
  try {
    columns = db.prepare(`PRAGMA table_info(${tableName})`).all().map((c) => c.name);
  } catch {
    return rows;
  }
  const colLower = columns.map((c) => c.toLowerCase());
  const hasThreadHint = colLower.some((c) => /thread|session|title|conversation/.test(c));
  if (!hasThreadHint) return rows;

  let records;
  try {
    records = db.prepare(`SELECT * FROM "${tableName.replace(/"/g, "")}" LIMIT ${maxRows}`).all();
  } catch {
    return rows;
  }

  for (const rec of records) {
    const row = rowFromThreadRecord(rec, sourceFile, attribution);
    if (row.SessionId || (row.Summary && !row.Summary.endsWith("(state.sqlite)"))) {
      rows.push(row);
    }
  }
  return rows;
}

function extractCurrentThreadRows(db, sourceFile, attribution, maxRows) {
  let records;
  try {
    records = db.prepare(`SELECT * FROM threads ORDER BY COALESCE(updated_at_ms, updated_at, created_at_ms, created_at) DESC LIMIT ?`)
      .all(maxRows);
  } catch {
    try { records = db.prepare("SELECT * FROM threads LIMIT ?").all(maxRows); } catch { return []; }
  }
  return records.map((rec) => rowFromThreadRecord(rec, sourceFile, attribution));
}

function extractSpawnEdgeRows(db, sourceFile, attribution, maxRows) {
  let records;
  try {
    records = db.prepare(`
      SELECT e.parent_thread_id, e.child_thread_id, e.status,
             t.created_at, t.created_at_ms, t.cwd, t.model, t.git_branch
      FROM thread_spawn_edges e
      LEFT JOIN threads t ON t.id = e.child_thread_id
      LIMIT ?
    `).all(maxRows);
  } catch {
    try { records = db.prepare("SELECT * FROM thread_spawn_edges LIMIT ?").all(maxRows); } catch { return []; }
  }
  return records.map((rec) => {
    const tsMs = parseFlexibleTimestamp(rec.created_at_ms ?? rec.created_at);
    const status = rec.status != null ? String(rec.status) : "";
    return codexMetaRow({
      timestamp: tsMs == null ? "" : formatTimestampUtc(tsMs),
      role: "system",
      recordType: "thread_spawn",
      summary: `Codex subagent thread spawned${status ? ` (${status})` : ""}`,
      fullText: serializeSafe({
        parentThreadId: rec.parent_thread_id,
        childThreadId: rec.child_thread_id,
        status,
      }),
      sessionId: rec.child_thread_id != null ? String(rec.child_thread_id) : "",
      parentId: rec.parent_thread_id != null ? String(rec.parent_thread_id) : "",
      workspace: rec.cwd != null ? String(rec.cwd) : "",
      isSidechain: true,
      gitBranch: rec.git_branch != null ? String(rec.git_branch) : "",
      model: rec.model != null ? String(rec.model) : "",
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

function extractDynamicToolRows(db, sourceFile, attribution, maxRows) {
  let records;
  try {
    records = db.prepare(`
      SELECT d.*, t.updated_at, t.updated_at_ms, t.cwd, t.model, t.git_branch,
             t.thread_source, t.agent_role
      FROM thread_dynamic_tools d
      LEFT JOIN threads t ON t.id = d.thread_id
      ORDER BY d.thread_id, d.position
      LIMIT ?
    `).all(maxRows);
  } catch {
    try { records = db.prepare("SELECT * FROM thread_dynamic_tools LIMIT ?").all(maxRows); } catch { return []; }
  }
  return records.map((rec) => {
    const tsMs = parseFlexibleTimestamp(rec.updated_at_ms ?? rec.updated_at);
    const name = rec.name != null ? String(rec.name) : "dynamic tool";
    const isSidechain = /subagent|sub-agent|child|fork/i.test(
      `${rec.thread_source || ""} ${rec.agent_role || ""}`,
    );
    return codexMetaRow({
      timestamp: tsMs == null ? "" : formatTimestampUtc(tsMs),
      role: "system",
      recordType: "thread_dynamic_tool",
      summary: `Codex dynamic tool registered: ${name}`,
      fullText: serializeSafe({
        name,
        namespace: rec.namespace,
        description: rec.description,
        inputSchema: parseMaybeJson(rec.input_schema),
        deferLoading: !!rec.defer_loading,
      }),
      toolName: name,
      toolInput: rec.input_schema != null ? String(rec.input_schema) : "",
      toolDescription: rec.description != null ? String(rec.description) : "",
      sessionId: rec.thread_id != null ? String(rec.thread_id) : "",
      workspace: rec.cwd != null ? String(rec.cwd) : "",
      isSidechain,
      gitBranch: rec.git_branch != null ? String(rec.git_branch) : "",
      model: rec.model != null ? String(rec.model) : "",
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

/** Drop a URL's query string and fragment — relay URLs can carry tokens; the endpoint is the evidence. */
function stripUrlSecrets(raw) {
  const value = raw == null ? "" : String(raw).trim();
  if (!value) return { url: "", queryStripped: false };
  try {
    const u = new URL(value);
    const stripped = !!(u.search || u.hash);
    u.search = "";
    u.hash = "";
    return { url: u.toString(), queryStripped: stripped };
  } catch {
    const cut = value.split(/[?#]/)[0];
    return { url: cut, queryStripped: cut !== value };
  }
}

/**
 * Remote Control enrollments — one row per (relay, account, client) pairing.
 *
 * Configuration state rather than an activity record: the timestamp is `updated_at` (epoch
 * seconds), the last time the enrollment changed, not a session time. `remote_control_enabled`
 * is the flag an analyst actually needs; a disabled enrollment still evidences that pairing was
 * set up at some point.
 */
function extractRemoteControlRows(db, sourceFile, attribution, maxRows) {
  let records;
  try {
    records = db.prepare("SELECT * FROM remote_control_enrollments ORDER BY updated_at DESC LIMIT ?").all(maxRows);
  } catch {
    try { records = db.prepare("SELECT * FROM remote_control_enrollments LIMIT ?").all(maxRows); } catch { return []; }
  }
  return records.map((rec) => {
    const tsMs = parseFlexibleTimestamp(rec.updated_at);
    const enabled = rec.remote_control_enabled == null ? null : Number(rec.remote_control_enabled) !== 0;
    const serverName = rec.server_name != null ? String(rec.server_name) : "";
    const clientName = rec.app_server_client_name != null ? String(rec.app_server_client_name) : "";
    const environmentId = rec.environment_id != null ? String(rec.environment_id) : "";
    const relay = stripUrlSecrets(rec.websocket_url);
    const state = enabled === null ? "enrolled" : (enabled ? "ENABLED" : "disabled");
    return codexMetaRow({
      timestamp: tsMs == null ? "" : formatTimestampUtc(tsMs),
      role: "system",
      recordType: "remote_control_enrollment",
      summary: `Codex Remote Control ${state} — server "${serverName || "?"}"`
        + `${clientName ? ` via ${clientName}` : ""}${environmentId ? `, environment ${environmentId}` : ""}`
        + `${relay.url ? ` (relay ${relay.url})` : ""}`,
      fullText: serializeSafe({
        remoteControlEnabled: enabled,
        serverName,
        serverId: rec.server_id != null ? String(rec.server_id) : "",
        environmentId,
        appServerClientName: clientName,
        accountId: rec.account_id != null ? String(rec.account_id) : "",
        relayUrl: relay.url,
        relayQueryStripped: relay.queryStripped,
        updatedAt: tsMs == null ? null : formatTimestampUtc(tsMs),
      }),
      sessionId: environmentId,
      messageId: rec.server_id != null ? String(rec.server_id) : "",
      toolName: "",
      toolDescription: "Pairing of this host's Codex app-server for Remote Control: a signed-in ChatGPT "
        + "client (phone, web, or another desktop) could start and drive Codex threads on this "
        + "machine through the relay while the enrollment was enabled. Configuration state — the "
        + "timestamp is when the enrollment last changed, not when it was used. Relay query strings "
        + "are stripped before storage.",
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

/**
 * `projects` + `project_roots` — the desktop app's project catalogue: a name, the local root paths
 * it maps to, and creation/update times. Threads reference `project_id`, so this is how a thread id
 * resolves to a folder on disk when its cwd column is empty.
 */
function extractProjectRows(db, sourceFile, attribution, maxRows) {
  let records;
  try {
    records = db.prepare(`
      SELECT p.id, p.name, p.metadata, p.created_at_ms, p.updated_at_ms, p.position,
             GROUP_CONCAT(r.path, char(10)) AS paths
      FROM projects p LEFT JOIN project_roots r ON r.project_id = p.id
      GROUP BY p.id ORDER BY p.updated_at_ms DESC LIMIT ?
    `).all(maxRows);
  } catch {
    try { records = db.prepare("SELECT * FROM projects LIMIT ?").all(maxRows); } catch { return []; }
  }
  return records.map((rec) => {
    const tsMs = parseFlexibleTimestamp(rec.updated_at_ms ?? rec.created_at_ms);
    const createdMs = parseFlexibleTimestamp(rec.created_at_ms);
    const paths = rec.paths != null ? String(rec.paths).split("\n").filter(Boolean) : [];
    const name = rec.name != null ? String(rec.name) : "";
    return codexMetaRow({
      timestamp: tsMs == null ? "" : formatTimestampUtc(tsMs),
      role: "system",
      recordType: "project",
      summary: `Codex project "${name || rec.id}"${paths.length ? ` — ${paths.join(", ")}` : ""}`,
      fullText: serializeSafe({
        projectId: rec.id ?? null,
        name,
        rootPaths: paths,
        metadata: parseMaybeJson(rec.metadata) ?? rec.metadata ?? null,
        position: rec.position ?? null,
        createdAt: createdMs == null ? null : formatTimestampUtc(createdMs),
        updatedAt: tsMs == null ? null : formatTimestampUtc(tsMs),
      }),
      sessionId: "",
      messageId: rec.id != null ? String(rec.id) : "",
      workspace: paths[0] || "",
      toolDescription: "Project catalogue entry from state*.sqlite: the folder(s) a project maps to on this "
        + "machine. Threads carry project_id; join it here to place a thread in a directory.",
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

function extractDatabaseRows(db, sourceFile, attribution, maxRows) {
  const rows = [];
  const tables = new Set(listTables(db));
  if (tables.has("threads")) {
    rows.push(...extractCurrentThreadRows(db, sourceFile, attribution, Math.max(0, maxRows - rows.length)));
  }
  if (tables.has("thread_spawn_edges") && rows.length < maxRows) {
    rows.push(...extractSpawnEdgeRows(db, sourceFile, attribution, maxRows - rows.length));
  }
  if (tables.has("thread_dynamic_tools") && rows.length < maxRows) {
    rows.push(...extractDynamicToolRows(db, sourceFile, attribution, maxRows - rows.length));
  }
  if (tables.has("remote_control_enrollments") && rows.length < maxRows) {
    rows.push(...extractRemoteControlRows(db, sourceFile, attribution, maxRows - rows.length));
  }
  if (tables.has("projects") && rows.length < maxRows) {
    rows.push(...extractProjectRows(db, sourceFile, attribution, maxRows - rows.length));
  }

  for (const table of tables) {
    if (rows.length >= maxRows) break;
    if (["threads", "thread_spawn_edges", "thread_dynamic_tools", "remote_control_enrollments",
      "projects", "project_roots", "project_idempotency_keys"].includes(table)) continue;
    try {
      rows.push(...extractRowsFromTable(db, table, sourceFile, attribution, maxRows - rows.length));
    } catch (e) {
      dbg("AIHIST", "codex state sqlite table skipped", { table, err: e.message });
    }
  }

  // ItemTable / KV style used by some older builds.
  if (rows.length < maxRows) {
    try {
      const itemRows = db.prepare(
        "SELECT key, value FROM ItemTable WHERE key LIKE '%thread%' OR key LIKE '%session%' OR key LIKE '%codex%' LIMIT 200",
      ).all();
      for (const { key, value } of itemRows) {
        if (rows.length >= maxRows) break;
        const parsed = parseMaybeJson(value);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          const row = rowFromThreadRecord({ ...parsed, title: parsed.title || key }, sourceFile, attribution);
          if (row.Summary) rows.push(row);
        }
      }
    } catch { /* no ItemTable */ }
  }
  return rows;
}

/**
 * @returns {{ rows: object[], stats: { databases: number, indexRows: number }|null }}
 */
function supplementCodexFromStateSqlite(codexRoot, attribution = {}, options = {}) {
  const candidates = listCodexStateSqliteFiles(codexRoot);
  if (!candidates.length) {
    return { rows: [], stats: null };
  }

  const maxRows = options.maxIndexRows ?? 500;
  const rows = [];
  const dbPath = candidates[0];
  let snapshot;
  let db;
  try {
    snapshot = copySqliteFamilyToTemp(dbPath, { checkAbort: options.checkAbort });
    db = openVscdbReadOnly(snapshot.dbPath);
    rows.push(...extractDatabaseRows(db, dbPath, attribution, maxRows));
  } catch (e) {
    dbg("AIHIST", "codex state sqlite snapshot/open failed", { dbPath, err: e.message });
    return { rows: [], stats: null };
  } finally {
    safeCloseDb(db);
    if (snapshot) snapshot.cleanup();
  }

  // Single-pass Set dedupe (keep first occurrence in sorted order) — the prior findIndex-in-filter was
  // O(n^2) over the index rows (~250k comparisons at 500 rows).
  const seen = new Set();
  const unique = sortAndNumberRows(rows).filter((r) => {
    const k = `${r.RecordType}:${r.SessionId}:${r.ParentId}:${r.InvokedTool}:${r.Summary.slice(0, 120)}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const remoteControlRows = unique.filter((r) => r.RecordType === "remote_control_enrollment");
  const remoteControlEnabled = remoteControlRows.filter((r) => /"remoteControlEnabled":true/.test(r.FullText)).length;

  return {
    rows: unique,
    stats: unique.length
      ? {
        databases: 1,
        indexRows: unique.length,
        remoteControlEnrollments: remoteControlRows.length,
        remoteControlEnabled,
        projectRows: unique.filter((r) => r.RecordType === "project").length,
        source: dbPath,
        candidates,
        sidecarsAcquired: snapshot?.sidecars?.map((p) => path.basename(p)) || [],
        acquisition: snapshot ? {
          method: snapshot.snapshotMethod,
          acquiredAtMs: snapshot.acquiredAtMs,
          integrityCheck: snapshot.integrityCheck,
          originalIdentity: snapshot.originalIdentity,
          snapshotIdentity: snapshot.snapshotIdentity,
        } : null,
      }
      : null,
  };
}

function buildCodexStateSqliteNotice(stats) {
  if (!stats?.indexRows) return "";
  const source = stats.source ? path.basename(stats.source) : "state*.sqlite";
  const sidecars = stats.sidecarsAcquired?.length
    ? `; acquired ${stats.sidecarsAcquired.join(", ")}`
    : "";
  // Lead with remote control: a paired relay is the finding an analyst must not skim past.
  const remote = stats.remoteControlEnrollments
    ? `Codex REMOTE CONTROL: ${stats.remoteControlEnrollments} enrollment(s), ${stats.remoteControlEnabled || 0} enabled. `
    : "";
  return `${remote}OpenAI Codex: +${stats.indexRows} state/enrichment row(s) from ${source}${sidecars}.`;
}

module.exports = {
  listCodexStateSqliteFiles,
  copySqliteFamilyToTemp,
  hashFileSha256,
  sqliteSourceIdentity,
  hasSqliteHeader,
  parseFlexibleTimestamp,
  rowFromThreadRecord,
  stripUrlSecrets,
  extractRemoteControlRows,
  extractProjectRows,
  supplementCodexFromStateSqlite,
  buildCodexStateSqliteNotice,
};
