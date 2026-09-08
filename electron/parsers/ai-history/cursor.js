/**
 * parsers/ai-history/cursor.js — Cursor IDE agent transcript extraction.
 *
 * Artifacts:
 *   ~/.cursor/projects/<project-slug>/agent-transcripts/<session-id>/<session-id>.jsonl
 *   Each line: { role, message: { content: [{ type: "text"|"tool_use", ... }] } }
 */

const fs = require("fs");
const path = require("path");
const { readJsonlBounded, readLinesBounded } = require("./jsonl-reader");

const { dbg } = require("../../logger");
const { TOOL_CURSOR } = require("./schema");
const { shouldSkipSubagentPath, filterSidechainRows, tickFileProgress } = require("./extract-plan");
const { processFilesConcurrently } = require("./file-batch");
const { extractContentText, extractToolEvidence } = require("./claude-code");
const {
  formatWorkspaceDisplay,
  workspaceFromCursorTranscriptPath,
} = require("./workspace-utils");
const { defaultCursorHome } = require("./artifact-paths");
const {
  formatTimestampUtc,
  parseIsoTimestamp,
  makeRow,
  finalizeAiHistoryRows,
  assignLineNumber,
} = require("./row-utils");
const {
  isCursorUserDataDir,
  listCursorComposerDbs,
} = require("./cursor-composer");

const CURSOR_DIR_NAME = ".cursor";
const AGENT_TRANSCRIPTS = "agent-transcripts";
const CURSOR_EVENT_TIMESTAMP_BASIS = "source event timestamp";
const CURSOR_SYNTHETIC_TIMESTAMP_BASIS = "file metadata synthetic spread";

function cursorRow(fields) {
  return makeRow({ ...fields, tool: fields.tool || TOOL_CURSOR }, TOOL_CURSOR);
}

function resolveCursorHome(target, options = {}) {
  if (options.cursorHome) return options.cursorHome;
  const root = resolveCursorRoot(target);
  return root || defaultCursorHome();
}

function workspaceFromTranscriptPath(filePath, cursorHome) {
  const raw = workspaceFromCursorTranscriptPath(filePath, cursorHome);
  return formatWorkspaceDisplay(raw, raw);
}

function sessionIdFromTranscriptPath(filePath) {
  const base = path.basename(filePath, path.extname(filePath));
  if (/^[0-9a-f-]{36}$/i.test(base)) return base;
  const parent = path.basename(path.dirname(filePath));
  if (/^[0-9a-f-]{36}$/i.test(parent)) return parent;
  return base;
}

function isSidechainPath(filePath) {
  return shouldSkipSubagentPath(filePath, { includeSubagents: false });
}

/** Sub-agent turn: either a subagents/ path or a per-line isSidechain flag in the transcript. */
function isSidechainTranscriptLine(obj, filePath) {
  if (obj && (obj.isSidechain === true || obj.message?.isSidechain === true)) return true;
  return isSidechainPath(filePath);
}

function fileTimestampSpread(filePath, messageCount) {
  let endMs = null;
  let startMs = null;
  try {
    const st = fs.statSync(filePath);
    endMs = st.mtimeMs;
    const birth = st.birthtimeMs;
    if (birth > 0 && birth <= endMs) {
      startMs = birth;
    } else {
      startMs = endMs - Math.min(Math.max(messageCount, 1) * 2000, 3600000);
    }
  } catch { /* ignore */ }
  if (startMs != null && endMs != null && startMs > endMs) {
    const t = startMs;
    startMs = endMs;
    endMs = t;
  }
  return { startMs, endMs };
}

function timestampForMessageIndex(index, total, startMs, endMs) {
  if (endMs == null) return null;
  if (total <= 1 || startMs == null) return endMs;
  const span = Math.max(endMs - startMs, 1000);
  const ratio = (index - 1) / Math.max(total - 1, 1);
  return Math.round(startMs + ratio * span);
}

function transcriptTimestampMs(obj, fallbackMs) {
  return transcriptTimestampDetails(obj, fallbackMs).timestampMs;
}

function transcriptTimestampDetails(obj, fallbackMs) {
  if (!obj || typeof obj !== "object") {
    return { timestampMs: fallbackMs, timestampBasis: CURSOR_SYNTHETIC_TIMESTAMP_BASIS };
  }
  const candidates = [
    obj.timestamp,
    obj.createdAt,
    obj.message?.timestamp,
    obj.message?.createdAt,
  ];
  for (const c of candidates) {
    if (c == null) continue;
    if (typeof c === "number" && Number.isFinite(c)) {
      return { timestampMs: c > 1e12 ? c : c * 1000, timestampBasis: CURSOR_EVENT_TIMESTAMP_BASIS };
    }
    const parsed = parseIsoTimestamp(c);
    if (parsed != null) return { timestampMs: parsed, timestampBasis: CURSOR_EVENT_TIMESTAMP_BASIS };
  }
  return { timestampMs: fallbackMs, timestampBasis: CURSOR_SYNTHETIC_TIMESTAMP_BASIS };
}

function parseTranscriptLine(obj, filePath, attribution, lineNumber, fallbackTsMs, workspace, sourceLocation = null) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  const role = obj.role != null ? String(obj.role).toLowerCase() : "";
  if (role !== "user" && role !== "assistant") return null;

  const message = obj.message && typeof obj.message === "object" ? obj.message : {};
  const summary = extractContentText(message.content);
  if (!summary) return null;
  const toolEvidence = extractToolEvidence(message.content);

  const { timestampMs: tsMs, timestampBasis } = transcriptTimestampDetails(obj, fallbackTsMs);

  return cursorRow({
    timestamp: formatTimestampUtc(tsMs),
    timestampBasis,
    role,
    recordType: role,
    summary,
    ...toolEvidence,
    sessionId: sessionIdFromTranscriptPath(filePath),
    messageId: obj.id != null ? String(obj.id) : "",
    workspace,
    isSidechain: isSidechainTranscriptLine(obj, filePath),
    sourceFile: filePath,
    lineNumber,
    sourceOffset: sourceLocation?.byteOffset,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function cursorTextRoleHeader(line) {
  const value = String(line || "");
  const bracket = value.match(/^\s*\[(user|human|assistant|ai)\]\s*:?[ \t]*(.*)$/i);
  const labelled = value.match(/^\s*(user|human|assistant|ai)\s*:[ \t]*(.*)$/i);
  const heading = value.match(/^\s*#{1,6}\s+(user|human|assistant|ai)\s*:?[ \t]*(.*)$/i);
  const match = bracket || labelled || heading;
  if (!match) return null;
  const rawRole = match[1].toLowerCase();
  return { role: rawRole === "user" || rawRole === "human" ? "user" : "assistant", text: match[2] || "" };
}

async function readCursorTextTranscript(filePath, attribution, workspace, options = {}) {
  const messages = [];
  let current = null;
  let sawContent = false;
  const flush = () => {
    if (!current) return;
    const text = current.parts.join("\n").trim();
    if (text) messages.push({ ...current, text });
    current = null;
  };
  await readLinesBounded(filePath, (line, lineNumber, sourceLocation) => {
    if (line.trim()) sawContent = true;
    const header = cursorTextRoleHeader(line);
    if (header) {
      flush();
      current = {
        role: header.role,
        parts: header.text ? [header.text] : [],
        lineNumber,
        sourceLocation,
      };
      return;
    }
    if (current) current.parts.push(line);
  }, { parseStats: options.parseStats, maxLineBytes: options.maxLineBytes });
  flush();

  if (sawContent && messages.length === 0 && options.parseStats) {
    options.parseStats.unsupportedFormats = (options.parseStats.unsupportedFormats || 0) + 1;
  }
  const { startMs, endMs } = fileTimestampSpread(filePath, messages.length);
  return messages.map((message, index) => cursorRow({
    timestamp: formatTimestampUtc(timestampForMessageIndex(index + 1, messages.length, startMs, endMs)),
    timestampBasis: CURSOR_SYNTHETIC_TIMESTAMP_BASIS,
    role: message.role,
    recordType: "legacy_text_transcript",
    summary: message.text,
    fullText: message.text,
    sessionId: sessionIdFromTranscriptPath(filePath),
    messageId: `text-line-${message.lineNumber}`,
    workspace,
    isSidechain: isSidechainPath(filePath),
    sourceFile: filePath,
    lineNumber: message.lineNumber,
    sourceOffset: message.sourceLocation.byteOffset,
    user: attribution.user || "",
    host: attribution.host || "",
  }));
}

async function readTranscriptFile(filePath, attribution = {}, options = {}) {
  const cursorHome = resolveCursorHome(filePath, options);
  const workspace = workspaceFromTranscriptPath(filePath, cursorHome);

  if (path.extname(filePath).toLowerCase() === ".txt") {
    const textRows = await readCursorTextTranscript(filePath, attribution, workspace, options);
    if (textRows.length) textRows._cursorSyntheticTimestamps = true;
    return textRows;
  }

  const pending = [];
  await readJsonlBounded(filePath, (obj, lineNumber, sourceLocation) => {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return;
    const role = obj.role != null ? String(obj.role).toLowerCase() : "";
    if (role !== "user" && role !== "assistant") return;
    const message = obj.message && typeof obj.message === "object" ? obj.message : {};
    if (!extractContentText(message.content)) return;
    pending.push({ obj, lineNumber, sourceLocation });
  }, { parseStats: options.parseStats, maxLineBytes: options.maxLineBytes });

  const messageCount = options._messageCount != null ? options._messageCount : pending.length;
  const { startMs, endMs } = fileTimestampSpread(filePath, messageCount);

  const rows = [];
  let msgIndex = 0;
  let syntheticCount = 0;
  for (const { obj, lineNumber: ln, sourceLocation } of pending) {
    msgIndex += 1;
    const spreadMs = timestampForMessageIndex(msgIndex, messageCount, startMs, endMs);
    const before = transcriptTimestampMs(obj, null);
    const row = parseTranscriptLine(obj, filePath, attribution, ln, spreadMs, workspace, sourceLocation);
    if (!row) continue;
    if (before == null) syntheticCount += 1;
    rows.push(assignLineNumber(row, ln, sourceLocation));
  }

  if (syntheticCount > 0 && syntheticCount < rows.length) {
    rows._cursorPartialSyntheticTimestamps = true;
  } else if (syntheticCount === rows.length && rows.length > 0) {
    rows._cursorSyntheticTimestamps = true;
  }
  return rows;
}

function applyCursorTimestampMetadata(rows, parseStats = null, composerStats = null) {
  const timed = rows.filter((r) => String(r.Timestamp || "").trim()).length;
  const synthetic = rows.filter((r) => r.TimestampBasis === CURSOR_SYNTHETIC_TIMESTAMP_BASIS).length;
  if (synthetic > 0 && synthetic === timed) rows._cursorSyntheticTimestamps = true;
  else if (synthetic > 0) rows._cursorPartialSyntheticTimestamps = true;
  if (composerStats) rows._cursorComposerStats = composerStats;
  if (parseStats?.errors) rows._parseErrors = parseStats.errors;
  if (parseStats?.unsupportedFormats) rows._unsupportedFormats = parseStats.unsupportedFormats;
  return rows;
}

function listTranscriptJsonlFiles(rootDir, options = {}) {
  const out = [];
  if (!rootDir || !fs.existsSync(rootDir)) return out;

  const stack = [rootDir];
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (shouldSkipSubagentPath(full, options)) continue;
        if (!e.isSymbolicLink()) stack.push(full);
      } else if (e.isFile()) {
        const ext = path.extname(e.name).toLowerCase();
        if ((ext === ".jsonl" || ext === ".txt")
          && full.includes(`${path.sep}${AGENT_TRANSCRIPTS}${path.sep}`)
          && !shouldSkipSubagentPath(full, options)) {
          out.push(full);
        }
      }
    }
  }
  return out;
}

function isCursorTranscriptFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (!filePath || (ext !== ".jsonl" && ext !== ".txt")) return false;
  const norm = filePath.replace(/\\/g, "/");
  return norm.includes(`/${AGENT_TRANSCRIPTS}/`);
}

function isCursorHome(dirPath) {
  if (!dirPath || path.basename(dirPath) !== CURSOR_DIR_NAME) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  return fs.existsSync(path.join(dirPath, "projects"));
}

function isCursorDataRoot(dirPath) {
  return isCursorHome(dirPath) || isCursorUserDataDir(dirPath);
}

function resolveCursorRoot(target) {
  if (!target) return null;
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  for (let i = 0; i < 16; i++) {
    if (path.basename(p) === CURSOR_DIR_NAME && isCursorHome(p)) return p;
    if (isCursorUserDataDir(p)) return p;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  if (isCursorDataRoot(target)) return target;
  return null;
}

function countCursorExtractFiles(cursorRoot, options = {}) {
  const projects = path.join(cursorRoot, "projects");
  return listTranscriptJsonlFiles(projects, options).length
    + listCursorComposerDbs(cursorRoot, options.userDataDirs || [], options).length
    + require("./cursor-context").directConfigFiles(cursorRoot).length
    + require("./cursor-context").listCursorContextFiles(cursorRoot, options).files.length;
}

async function extractCursorDir(cursorRoot, attribution = {}, options = {}) {
  const parseStats = options.parseStats || { errors: 0 };
  const extractOpts = { ...options, cursorHome: cursorRoot, parseStats };
  const projects = path.join(cursorRoot, "projects");
  const files = listTranscriptJsonlFiles(projects, options);
  const rows = [];
  let fileIndex = 0;
  const { onFileProgress, checkAbort, onExtractedRows } = options;
  let streamTimed = 0;
  let streamSynthetic = 0;
  let streamTotal = 0;
  const flushExtracted = onExtractedRows
    ? (batch) => {
      if (!batch?.length) return;
      for (const r of batch) {
        streamTotal += 1;
        if (String(r.Timestamp || "").trim()) streamTimed += 1;
        if (r.TimestampBasis === CURSOR_SYNTHETIC_TIMESTAMP_BASIS) streamSynthetic += 1;
      }
      onExtractedRows(batch);
    }
    : null;

  // Read transcripts in bounded-concurrency batches (order-independent: streamed rows dedupe at the
  // sink, in-memory rows are finalize-sorted). Per-file error isolation + progress + abort preserved.
  await processFilesConcurrently(files, {
    process: async (filePath) => filterSidechainRows(await readTranscriptFile(filePath, attribution, extractOpts), options),
    onProgress: (filePath) => { fileIndex += 1; tickFileProgress(onFileProgress, fileIndex, files.length, filePath); },
    onRows: (fileRows) => { if (flushExtracted && fileRows.length) flushExtracted(fileRows); else rows.push(...fileRows); },
    onError: (e, filePath) => dbg("AIHIST", "cursor transcript failed", { path: filePath, err: e.message }),
    checkAbort,
  });

  const { extractCursorComposerStores } = require("./cursor-composer");
  const { rows: composerRows, stats: composerStats } = await extractCursorComposerStores(
    cursorRoot,
    attribution,
    { ...options, onExtractedRows: flushExtracted },
  );
  if (!flushExtracted && composerRows.length) {
    rows.push(...composerRows);
  }

  let cursorContextStats = null;
  try {
    const { rows: contextRows, stats } = require("./cursor-context")
      .extractCursorContext(cursorRoot, attribution, options);
    cursorContextStats = stats;
    if (flushExtracted && contextRows.length) flushExtracted(contextRows);
    else rows.push(...contextRows);
  } catch (e) {
    dbg("AIHIST", "cursor context extraction failed", { path: cursorRoot, err: e.message });
  }

  if (onExtractedRows) {
    const out = [];
    if (streamSynthetic > 0 && streamSynthetic === streamTimed) out._cursorSyntheticTimestamps = true;
    else if (streamSynthetic > 0) out._cursorPartialSyntheticTimestamps = true;
    out._cursorComposerStats = composerStats;
    if (cursorContextStats) out._cursorContextStats = cursorContextStats;
    if (parseStats.errors) out._parseErrors = parseStats.errors;
    return out;
  }

  const sorted = finalizeAiHistoryRows(filterSidechainRows(rows, options), options);
  const result = applyCursorTimestampMetadata(sorted, parseStats, composerStats);
  if (cursorContextStats) result._cursorContextStats = cursorContextStats;
  return result;
}

async function extractCursorPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  let stat;
  try { stat = fs.statSync(target); } catch (e) {
    throw new Error(`Cannot read path: ${e.message}`);
  }

  if (stat.isDirectory()) {
    const base = path.basename(target);
    if (isCursorDataRoot(target)) {
      return extractCursorDir(target, attribution, options);
    }
    if (base === AGENT_TRANSCRIPTS || target.includes(`${path.sep}${AGENT_TRANSCRIPTS}${path.sep}`)) {
      const cursorHome = resolveCursorRoot(target) || path.dirname(path.dirname(path.dirname(target)));
      const files = listTranscriptJsonlFiles(target, options);
      const rows = [];
      let fileIndex = 0;
      for (const filePath of files) {
        fileIndex += 1;
        tickFileProgress(options.onFileProgress, fileIndex, files.length, filePath);
        rows.push(...await readTranscriptFile(filePath, attribution, { ...options, cursorHome }));
      }
      const sorted = finalizeAiHistoryRows(filterSidechainRows(rows, options), options);
      return applyCursorTimestampMetadata(sorted);
    }
    if (base === "projects") {
      return extractCursorDir(path.dirname(target), attribution, options);
    }
    const root = resolveCursorRoot(target);
    if (root) return extractCursorDir(root, attribution, options);
    throw new Error("Not a Cursor .cursor agent root or Cursor User data directory.");
  }

  if (path.basename(target) === "conversation-search.db") {
    const root = resolveCursorRoot(target);
    if (root) return extractCursorDir(root, attribution, options);
  }
  if (!isCursorTranscriptFile(target)) {
    throw new Error("Expected a Cursor transcript, conversation-search.db, .cursor root, or Cursor User directory.");
  }

  const cursorHome = resolveCursorRoot(target);
  const parsedRows = await readTranscriptFile(target, attribution, { ...options, cursorHome });
  const rows = applyCursorTimestampMetadata(filterSidechainRows(parsedRows, options));
  for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
  return rows;
}

module.exports = {
  CURSOR_DIR_NAME,
  AGENT_TRANSCRIPTS,
  isCursorHome,
  isCursorUserDataDir,
  isCursorDataRoot,
  isCursorTranscriptFile,
  resolveCursorRoot,
  listTranscriptJsonlFiles,
  countCursorExtractFiles,
  extractCursorDir,
  extractCursorPath,
  readTranscriptFile,
  workspaceFromTranscriptPath,
  sessionIdFromTranscriptPath,
  fileTimestampSpread,
  timestampForMessageIndex,
};
