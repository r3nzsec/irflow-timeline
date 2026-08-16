/**
 * claude-desktop.js — Claude Desktop/Cowork metadata, transcripts, and audit trails.
 *
 * Current Cowork sessions keep isolated .claude/projects trees and audit.jsonl files below
 * local-agent-mode-sessions. Older Desktop builds link local_<uuid>.json to ~/.claude/projects/.
 */

const fs = require("fs");
const path = require("path");
const { readJsonlBounded } = require("./jsonl-reader");

const { dbg } = require("../../logger");
const { TOOL_CLAUDE_CODE } = require("./schema");
const { filterSidechainRows, tickFileProgress } = require("./extract-plan");
const { processFilesConcurrently } = require("./file-batch");
const {
  isClaudeDesktopSessionsRoot,
  CLAUDE_DIR_NAME,
} = require("./artifact-paths");
const {
  parseSessionLine,
  extractSessionFile,
  listSessionJsonlFiles,
} = require("./claude-code");
const {
  formatTimestampUtc,
  makeRow,
  finalizeAiHistoryRows,
  assignLineNumber,
} = require("./row-utils");
const { collectClaudeDesktopState } = require("./claude-desktop-state");

const LOCAL_META_RE = /^local_.*\.json$/i;
const AUDIT_JSONL_RE = /^audit(?:\d+)?\.jsonl$/i;
const COWORK_SCAN_SKIP_DIRS = new Set([
  "outputs",
  "uploads",
  "tool-results",
  "file-history",
  "shell-snapshots",
  "tasks",
  "node_modules",
]);

function isNullJsonFile(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    if (!buf.length) return true;
    const nonZero = buf.find((b) => b !== 0);
    return nonZero === undefined;
  } catch {
    return true;
  }
}

function parseDesktopMetadataFile(filePath) {
  if (isNullJsonFile(filePath)) return null;
  let raw;
  try { raw = fs.readFileSync(filePath, "utf8"); } catch { return null; }
  const trimmed = raw.replace(/\0/g, "").trim();
  if (!trimmed) return null;
  let obj;
  try { obj = JSON.parse(trimmed); } catch {
    dbg("AIHIST", "claude desktop metadata parse failed", { filePath });
    return null;
  }
  if (!obj || typeof obj !== "object") return null;
  return obj;
}

function normalizeCliSessionId(meta) {
  let id = meta.cliSessionId != null ? String(meta.cliSessionId).trim() : "";
  if (!id && meta.sessionId != null) {
    const sid = String(meta.sessionId).trim();
    if (sid.startsWith("local_")) id = sid.slice("local_".length);
    else if (!sid.startsWith("local")) id = sid;
  }
  return id.replace(/\.jsonl$/i, "");
}

function listDesktopMetadataFiles(rootDir, maxDepth = 12) {
  const out = [];
  const stack = [{ d: rootDir, depth: 0 }];
  while (stack.length) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory() && depth < maxDepth && !e.isSymbolicLink()) {
        stack.push({ d: full, depth: depth + 1 });
      } else if (e.isFile() && LOCAL_META_RE.test(e.name)) {
        out.push(full);
      }
    }
  }
  return out;
}

function listCoworkArtifactFiles(rootDir, options = {}) {
  const maxDepth = options.maxDepth ?? 20;
  const transcriptFiles = [];
  const auditFiles = [];
  const auditKeyFiles = [];
  const stack = [{ d: rootDir, depth: 0 }];
  while (stack.length) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!e.isSymbolicLink() && depth < maxDepth && !COWORK_SCAN_SKIP_DIRS.has(e.name)) {
          stack.push({ d: full, depth: depth + 1 });
        }
        continue;
      }
      if (!e.isFile()) continue;
      if (AUDIT_JSONL_RE.test(e.name)) {
        auditFiles.push(full);
        continue;
      }
      if (e.name === ".audit-key") {
        auditKeyFiles.push(full);
        continue;
      }
      if (path.extname(e.name).toLowerCase() !== ".jsonl") continue;
      const marker = `${path.sep}.claude${path.sep}projects${path.sep}`;
      if (full.includes(marker)) transcriptFiles.push(full);
    }
  }
  transcriptFiles.sort();
  auditFiles.sort();
  auditKeyFiles.sort();
  return { transcriptFiles, auditFiles, auditKeyFiles };
}

function countClaudeDesktopExtractFiles(rootDir, options = {}) {
  const artifacts = listCoworkArtifactFiles(rootDir, options);
  return listDesktopMetadataFiles(rootDir).length
    + artifacts.transcriptFiles.length
    + artifacts.auditFiles.length;
}

function coworkSessionDirForPath(filePath, desktopRoot) {
  let p = path.dirname(filePath);
  const root = path.resolve(desktopRoot);
  for (let i = 0; i < 24; i++) {
    if (path.basename(p).startsWith("local_")) return p;
    if (p === root) break;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return null;
}

async function extractClaudeAuditFile(auditPath, attribution = {}, parseStats = null) {
  const rows = [];
  await readJsonlBounded(auditPath, (obj, lineNumber) => {
    const normalized = {
      ...obj,
      timestamp: obj.timestamp ?? obj._audit_timestamp,
      sessionId: obj.sessionId ?? obj.session_id,
      parentUuid: obj.parentUuid ?? obj.parent_tool_use_id,
    };
    const row = assignLineNumber(
      parseSessionLine(normalized, auditPath, attribution, { recordTypePrefix: "audit-" }),
      lineNumber,
    );
    if (row) rows.push(row);
  }, { parseStats });
  return rows;
}

/** Resolve ~/.claude next to a Desktop sessions tree (same user profile). */
function resolveClaudeProjectsDir(desktopRoot, extraSearchRoots = []) {
  const candidates = [];
  const push = (p) => { if (p && !candidates.includes(p)) candidates.push(p); };

  for (const root of extraSearchRoots) {
    push(path.join(root, CLAUDE_DIR_NAME, "projects"));
    push(path.join(root, ".claude", "projects"));
  }

  let p = path.resolve(desktopRoot);
  for (let i = 0; i < 24; i++) {
    push(path.join(p, CLAUDE_DIR_NAME, "projects"));
    const base = path.basename(p);
    if (base === CLAUDE_DIR_NAME) {
      push(path.join(p, "projects"));
      break;
    }
    if (/^Users$/i.test(base) || base === "home") {
      try {
        const users = fs.readdirSync(p, { withFileTypes: true });
        for (const u of users) {
          if (!u.isDirectory()) continue;
          push(path.join(p, u.name, CLAUDE_DIR_NAME, "projects"));
          push(path.join(p, u.name, ".claude", "projects"));
        }
      } catch { /* ignore */ }
    }
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }

  const homedir = require("os").homedir();
  push(path.join(homedir, CLAUDE_DIR_NAME, "projects"));

  for (const projectsDir of candidates) {
    if (projectsDir && fs.existsSync(projectsDir)) return projectsDir;
  }
  return null;
}

function buildJsonlIndex(projectsDir) {
  const index = new Map();
  if (!projectsDir) return index;
  for (const jsonlPath of listSessionJsonlFiles(projectsDir, { includeSubagents: true })) {
    const id = path.basename(jsonlPath, ".jsonl");
    if (id && !index.has(id)) index.set(id, jsonlPath);
  }
  return index;
}

function metadataSummaryRow(meta, metaPath, attribution) {
  const title = meta.title != null ? String(meta.title).trim() : "";
  const model = meta.model != null ? String(meta.model) : "";
  const cwd = meta.cwd || meta.originCwd || "";
  const tsMs = Number(meta.lastActivityAt) || Number(meta.createdAt) || null;
  const sessionId = meta.sessionId != null ? String(meta.sessionId) : "";
  const cliId = normalizeCliSessionId(meta);
  let summary = title || "[Claude Desktop session]";
  if (!meta.cliSessionId && cliId) summary += " (no cliSessionId — transcript link uncertain)";

  return makeRow({
    timestamp: tsMs != null && Number.isFinite(tsMs) ? formatTimestampUtc(tsMs) : "",
    role: "session",
    recordType: "desktop-metadata",
    summary,
    sessionId: cliId || sessionId,
    messageId: sessionId,
    workspace: cwd ? String(cwd) : "",
    model,
    sourceFile: metaPath,
    user: attribution.user || "",
    host: attribution.host || "",
    tool: TOOL_CLAUDE_CODE,
  }, TOOL_CLAUDE_CODE);
}

/**
 * @returns {{ rows: object[], stats: object }}
 */
async function extractClaudeDesktopDir(desktopRoot, attribution = {}, options = {}) {
  const metaFiles = listDesktopMetadataFiles(desktopRoot);
  const coworkArtifacts = listCoworkArtifactFiles(desktopRoot, options);
  const projectsDir = resolveClaudeProjectsDir(desktopRoot, options.claudeProjectsSearchRoots || []);
  const jsonlIndex = buildJsonlIndex(projectsDir);
  const rows = [];
  const parseStats = { errors: 0 };
  const stats = {
    metadataFiles: metaFiles.length,
    linkedTranscripts: 0,
    metadataOnly: 0,
    danglingCli: 0,
    corruptMetadata: 0,
    transcriptRows: 0,
    nestedTranscripts: coworkArtifacts.transcriptFiles.length,
    auditFiles: coworkArtifacts.auditFiles.length,
    auditKeys: coworkArtifacts.auditKeyFiles.length,
    auditRows: 0,
    orphanTranscripts: 0,
  };

  let fileIndex = 0;
  const transcriptPaths = new Set(coworkArtifacts.transcriptFiles);
  const transcriptMeta = new Map();
  const metaBySessionDir = new Map();
  const localTranscriptsBySessionDir = new Map();
  const { onFileProgress, onExtractedRows } = options;

  for (const transcriptPath of coworkArtifacts.transcriptFiles) {
    const sessionDir = coworkSessionDirForPath(transcriptPath, desktopRoot);
    if (!sessionDir) continue;
    const existing = localTranscriptsBySessionDir.get(sessionDir);
    if (existing) existing.push(transcriptPath);
    else localTranscriptsBySessionDir.set(sessionDir, [transcriptPath]);
  }

  const emitBatch = (batch) => {
    if (!batch?.length) return;
    const filtered = filterSidechainRows(batch, options);
    if (onExtractedRows && filtered.length) {
      onExtractedRows(filtered);
      return;
    }
    rows.push(...filtered);
  };

  for (const metaPath of metaFiles) {
    fileIndex += 1;
    tickFileProgress(
      onFileProgress,
      fileIndex,
      metaFiles.length + transcriptPaths.size + coworkArtifacts.auditFiles.length,
      metaPath,
    );

    const meta = parseDesktopMetadataFile(metaPath);
    if (!meta) {
      stats.corruptMetadata += 1;
      continue;
    }

    const cliId = normalizeCliSessionId(meta);
    const expectedSessionDir = path.join(
      path.dirname(metaPath),
      path.basename(metaPath, path.extname(metaPath)),
    );
    const localPaths = localTranscriptsBySessionDir.get(expectedSessionDir) || [];
    if (localPaths.length) {
      metaBySessionDir.set(expectedSessionDir, meta);
      for (const transcriptPath of localPaths) transcriptMeta.set(transcriptPath, meta);
      stats.linkedTranscripts += 1;
    } else {
      const hostJsonlPath = cliId ? jsonlIndex.get(cliId) : null;
      if (hostJsonlPath) {
        transcriptPaths.add(hostJsonlPath);
        transcriptMeta.set(hostJsonlPath, meta);
        stats.linkedTranscripts += 1;
      } else {
        emitBatch([metadataSummaryRow(meta, metaPath, attribution)]);
        if (cliId) stats.danglingCli += 1;
        else stats.metadataOnly += 1;
      }
    }

    if (fileIndex % 6 === 0) await new Promise((r) => setImmediate(r));
    if (typeof options.checkAbort === "function") options.checkAbort();
  }

  for (const transcriptPath of coworkArtifacts.transcriptFiles) {
    const sessionDir = coworkSessionDirForPath(transcriptPath, desktopRoot);
    if (sessionDir && !metaBySessionDir.has(sessionDir)) stats.orphanTranscripts += 1;
  }

  const allTranscriptPaths = [...transcriptPaths].sort();
  const fileCount = metaFiles.length + allTranscriptPaths.length + coworkArtifacts.auditFiles.length;
  await processFilesConcurrently(allTranscriptPaths, {
    process: async (transcriptPath) => {
      const meta = transcriptMeta.get(transcriptPath) || {};
      const sessionRows = await extractSessionFile(transcriptPath, {
        ...attribution,
        desktopTitle: meta.title,
        desktopModel: meta.model,
      }, parseStats);
      for (const row of sessionRows) {
        if (!row.Workspace && (meta.cwd || meta.originCwd)) row.Workspace = String(meta.cwd || meta.originCwd);
        if (!row.Model && meta.model) row.Model = String(meta.model);
      }
      return sessionRows;
    },
    onProgress: (transcriptPath) => {
      fileIndex += 1;
      tickFileProgress(onFileProgress, fileIndex, fileCount, transcriptPath);
    },
    onRows: (batch) => {
      stats.transcriptRows += batch.length;
      emitBatch(batch);
    },
    onError: (e, transcriptPath) => dbg(
      "AIHIST",
      "claude desktop transcript failed",
      { transcriptPath, err: e.message },
    ),
    checkAbort: options.checkAbort,
  });

  await processFilesConcurrently(coworkArtifacts.auditFiles, {
    process: (auditPath) => extractClaudeAuditFile(auditPath, attribution, parseStats),
    onProgress: (auditPath) => {
      fileIndex += 1;
      tickFileProgress(onFileProgress, fileIndex, fileCount, auditPath);
    },
    onRows: (batch) => {
      stats.auditRows += batch.length;
      emitBatch(batch);
    },
    onError: (e, auditPath) => dbg(
      "AIHIST",
      "claude desktop audit failed",
      { auditPath, err: e.message },
    ),
    checkAbort: options.checkAbort,
  });

  if (!rows.length && !onExtractedRows && metaFiles.length === 0) {
    const orphanJsonl = projectsDir
      ? listSessionJsonlFiles(projectsDir, options).length
      : 0;
    stats.orphanJsonlHint = orphanJsonl;
  }
  if (parseStats.errors) stats.parseErrors = parseStats.errors;

  // State artifacts that outlive the conversations: deletion tombstones, staged attachments, the
  // usage timeline, scheduled runs, and workspace sightings. Collected last so a failure here can
  // never cost the transcripts.
  if (options.includeDesktopState !== false) {
    const stateRows = collectClaudeDesktopState(desktopRoot, attribution, options);
    if (stateRows.length) {
      stats.deletedSessions = stateRows.filter((r) => r.RecordType === "session_deleted").length;
      stats.pendingUploads = stateRows.filter((r) => r.RecordType === "pending_upload").length;
      stats.usageWindows = stateRows.filter((r) => r.RecordType === "app_usage_window").length;
      stats.scheduledTasks = stateRows.filter((r) => r.RecordType === "scheduled_task").length;
      emitBatch(stateRows);
    }
  }

  return {
    rows: onExtractedRows ? [] : finalizeAiHistoryRows(rows, options),
    stats,
    projectsDir,
  };
}

function buildClaudeDesktopImportNotice(stats) {
  if (!stats) return "";
  const parts = [];
  if (stats.linkedTranscripts > 0) {
    parts.push(`Claude Desktop: ${stats.linkedTranscripts} session(s) linked to CLI transcripts (${stats.transcriptRows} row(s))`);
  }
  if (stats.nestedTranscripts > 0) {
    parts.push(`${stats.nestedTranscripts} isolated Cowork transcript file(s) parsed`);
  }
  if (stats.auditFiles > 0) {
    const keyNote = stats.auditKeys > 0 ? `; ${stats.auditKeys} audit key file(s) present` : "";
    parts.push(`${stats.auditFiles} Cowork audit file(s) parsed (${stats.auditRows} row(s)${keyNote})`);
  }
  if (stats.danglingCli > 0) {
    parts.push(`${stats.danglingCli} metadata file(s) reference missing ~/.claude/projects JSONL — collect the user's .claude folder`);
  }
  if (stats.metadataOnly > 0) {
    parts.push(`${stats.metadataOnly} metadata file(s) without cliSessionId (titles only)`);
  }
  // Lead with deletion: it is the finding an analyst must not miss in a notice they may skim.
  if (stats.deletedSessions > 0) {
    parts.unshift(`${stats.deletedSessions} DELETED conversation(s) evidenced by tombstone, with deletion time`);
  }
  if (stats.pendingUploads > 0) {
    parts.push(`${stats.pendingUploads} staged upload(s) inventoried (content not read — preserve separately)`);
  }
  if (stats.usageWindows > 0) {
    parts.push(`${stats.usageWindows} app-usage window(s) derived from usage samples`);
  }
  if (stats.scheduledTasks > 0) {
    parts.push(`${stats.scheduledTasks} scheduled agent task(s)`);
  }
  if (stats.metadataFiles > 0 && stats.linkedTranscripts === 0 && stats.danglingCli === 0 && stats.metadataOnly === stats.metadataFiles) {
    return "Claude Desktop: session metadata found but no CLI transcripts — also import ~/.claude/projects for message bodies.";
  }
  if (stats.metadataFiles === 0 && stats.orphanJsonlHint > 0) {
    return `Claude Desktop folder has no local_*.json index; ${stats.orphanJsonlHint} JSONL file(s) exist under .claude/projects on this host.`;
  }
  return parts.join("; ");
}

module.exports = {
  listDesktopMetadataFiles,
  listCoworkArtifactFiles,
  countClaudeDesktopExtractFiles,
  parseDesktopMetadataFile,
  normalizeCliSessionId,
  resolveClaudeProjectsDir,
  extractClaudeAuditFile,
  extractClaudeDesktopDir,
  buildClaudeDesktopImportNotice,
  isClaudeDesktopSessionsRoot,
};
