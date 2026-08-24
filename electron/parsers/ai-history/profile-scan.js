/**
 * ai-history/profile-scan.js — discover local AI artifact roots on the analyst machine.
 */

const fs = require("fs");
const os = require("os");

const { dbg } = require("../../logger");
const { AI_HISTORY_TOOLS, AI_HISTORY_COLUMNS, AI_HISTORY_DB_OMIT_FULLTEXT } = require("./schema");
const { extractClaudeDir } = require("./claude-code");
const { extractCodexDir } = require("./codex");
const { extractGrokBuildDir } = require("./grok-build");
const { extractChatgptDir } = require("./chatgpt");
const { extractGeminiCliDir } = require("./gemini-cli");
const { extractCursorDir } = require("./cursor");
const { extractCopilotPath, getCopilotExtractionStats } = require("./copilot");
const { sortAndNumberRows, dedupeAiHistoryRows } = require("./row-utils");
const {
  MAX_AI_HISTORY_ROWS,
  prepareChunkRowsForDb,
  writeAiHistoryRowsToDb,
  filterAlreadySeenStreamedRows,
  makeSourceAccumulator,
} = require("./db-sink");
const {
  buildAiHistoryImportNotice,
  buildCopilotExtractionStats,
} = require("./import-meta");
const artifactPaths = require("./artifact-paths");
const {
  getLocalAiHistoryCandidates,
  expandChatgptMsStorePackages,
  isClaudeCodeArtifactRoot,
  isGrokBuildRoot,
  isChatgptAppDir,
  isGeminiCliRoot,
  isCursorHome,
  isCursorUserDataDir,
  isCopilotWorkspaceStorageRoot,
  isCopilotCliRoot,
} = artifactPaths;
const { defaultCodexHome, isCodexDir } = require("./codex");
const { isContinueRoot } = require("./continue");
const { isWindsurfUserDir } = require("./windsurf");
const { scanAiArtifacts, extractUsername } = require("../ai-artifacts");
const { buildEmptyAiScanReport } = require("./scan-report");
const { AiHistoryExtractAbortedError } = require("./extract-abort");
const path = require("path");


const FOLDER_SCAN_TOOL_MAP = [
  ["claudeCode", "claude-code"],
  ["codex", "codex"],
  ["grokBuild", "grok-build"],
  ["chatgpt", "chatgpt"],
  ["geminiCli", "gemini-cli"],
  ["cursor", "cursor"],
  ["copilot", "copilot"],
  ["windsurf", "windsurf"],
  ["continue", "continue"],
];

function realPathKey(p) {
  try {
    return fs.realpathSync.native ? fs.realpathSync.native(p) : fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

function validateAiHistoryRoot(tool, rootPath, { quick = false } = {}) {
  if (!rootPath || !fs.existsSync(rootPath)) return false;
  const q = { quick };
  switch (tool) {
    case "claude-code": return isClaudeCodeArtifactRoot(rootPath);
    case "codex": return isCodexDir(rootPath);
    case "grok-build": return isGrokBuildRoot(rootPath, q);
    case "chatgpt": return isChatgptAppDir(rootPath, q);
    case "gemini-cli": return isGeminiCliRoot(rootPath, q);
    case "cursor": return isCursorHome(rootPath) || isCursorUserDataDir(rootPath);
    case "copilot": return isCopilotWorkspaceStorageRoot(rootPath, q) || isCopilotCliRoot(rootPath, q);
    case "windsurf": return isWindsurfUserDir(rootPath);
    case "continue": return isContinueRoot(rootPath);
    default: return false;
  }
}

function pushRoot(roots, seen, tool, rootPath, extra = {}) {
  const key = `${tool}:${realPathKey(rootPath)}`;
  if (seen.has(key)) return;
  seen.add(key);
  const baseLabel = AI_HISTORY_TOOLS[tool]?.label || tool;
  const userTag = extra.endpointUser ? ` — ${extra.endpointUser}` : "";
  roots.push({
    tool,
    path: rootPath,
    label: `${baseLabel}${userTag}`,
    endpointUser: extra.endpointUser || "",
    endpointHost: extra.endpointHost || "",
    ...extra,
  });
}

/**
 * Discover AI artifact roots inside a KAPE / triage / mounted image folder (Windows, Linux, macOS layouts).
 * @param {string} scanRoot
 * @param {{ onProgress?: Function }} [options]
 */
async function discoverAiHistoryInFolder(scanRoot, options = {}) {
  const { onProgress } = options;
  const report = (patch) => {
    if (typeof onProgress === "function") onProgress(patch);
  };

  if (!scanRoot || !fs.existsSync(scanRoot)) {
    return { roots: [], candidateCount: 0, scanRoot, scanMode: "folder" };
  }

  const resolvedRoot = path.resolve(scanRoot);
  report({
    phase: "discovering",
    percent: 2,
    statusDetail: "Walking collection tree…",
    logLine: `Forensic scan: ${resolvedRoot} (Windows Users\\…, Linux /home/…, macOS Users/… layouts)`,
  });

  const found = scanAiArtifacts(resolvedRoot, {
    maxDepth: 20,
    maxPerKind: 64,
    onProgress: report,
  });

  const seen = new Set();
  const roots = [];
  let hits = 0;

  for (const [kind, tool] of FOLDER_SCAN_TOOL_MAP) {
    const entries = found[kind] || [];
    for (const hit of entries) {
      hits += 1;
      const endpointUser = hit.username || extractUsername(hit.path) || "";
      pushRoot(roots, seen, tool, hit.path, {
        endpointUser,
        endpointHost: path.basename(resolvedRoot),
        sessionCount: hit.sessionCount,
      });
      report({
        logLine: `  ✓ ${AI_HISTORY_TOOLS[tool]?.label || tool}${endpointUser ? ` (${endpointUser})` : ""}: ${hit.path}`,
      });
    }
  }

  report({
    phase: "discovering",
    percent: 100,
    statusDetail: roots.length
      ? `Found ${roots.length} source(s) in collection`
      : "No AI artifacts in this folder",
    logLine: roots.length
      ? `Collection scan complete — ${roots.length} source(s), ${found.scanned.toLocaleString()} dirs indexed.`
      : `No readable AI history under ${resolvedRoot} (${found.scanned.toLocaleString()} dirs checked).`,
    candidateCount: found.scanned,
    candidatesChecked: found.scanned,
  });

  const scanReport = roots.length
    ? null
    : buildEmptyAiScanReport({
      scanRoot: resolvedRoot,
      scanMode: "folder",
      scanned: found.scanned,
      hitsFound: hits,
      browserAgentHints: found.browserAgentHints || [],
    });

  const browserAgentHints = scanReport?.browserAgentHints || [];

  return {
    roots,
    candidateCount: found.scanned,
    scanRoot: resolvedRoot,
    scanMode: "folder",
    hitsFound: hits,
    scanReport,
    browserAgentHints,
  };
}

/**
 * @param {{ scanRoot?: string, scanMode?: 'local'|'folder', onProgress?: Function, quickValidate?: boolean }} [options]
 */
async function discoverAiHistoryRoots(options = {}) {
  const { scanRoot, scanMode } = options;
  if (scanMode === "folder" && scanRoot) {
    return discoverAiHistoryInFolder(scanRoot, options);
  }
  const local = await discoverLocalAiHistoryRoots(options);
  return { ...local, scanMode: "local", scanRoot: null };
}

/**
 * Find every AI history root on this machine that exists and looks valid.
 * @param {{ onProgress?: Function, quickValidate?: boolean }} [options]
 * @returns {Promise<{ roots: Array<{tool, path, label}>, candidateCount: number }>}
 */
async function discoverLocalAiHistoryRoots(options = {}) {
  const { onProgress, quickValidate = false } = options;
  const report = (patch) => {
    if (typeof onProgress === "function") onProgress(patch);
  };
  const candidates = getLocalAiHistoryCandidates();
  const seen = new Set();
  const roots = [];
  const total = candidates.length;
  let checked = 0;

  report({
    phase: "discovering",
    percent: 1,
    statusDetail: `Checking ${total} standard location(s)…`,
    logLine: `Probing ${total} candidate path(s) on this machine…`,
    candidateCount: total,
    candidatesChecked: 0,
  });

  for (const { tool, path: candidatePath } of candidates) {
    checked += 1;
    const label = AI_HISTORY_TOOLS[tool]?.label || tool;
    const pct = Math.min(95, Math.round((checked / Math.max(total, 1)) * 94));
    report({
      phase: "discovering",
      percent: pct,
      statusDetail: `Checking ${label}…`,
      logLine: `Checking ${label}: ${candidatePath}`,
      candidateCount: total,
      candidatesChecked: checked,
    });

    if (tool === "chatgpt" && path.basename(candidatePath) === "Packages" && process.platform === "win32") {
      for (const pkgRoot of expandChatgptMsStorePackages(candidatePath)) {
        if (!validateAiHistoryRoot(tool, pkgRoot, { quick: quickValidate })) continue;
        pushRoot(roots, seen, tool, pkgRoot);
        report({ logLine: `  ✓ MS Store ChatGPT: ${pkgRoot}` });
      }
      if (checked % 2 === 0) await new Promise((r) => setImmediate(r));
      continue;
    }

    if (validateAiHistoryRoot(tool, candidatePath, { quick: quickValidate })) {
      pushRoot(roots, seen, tool, candidatePath);
      report({ logLine: `  ✓ ${label} validated` });
    }

    if (checked % 2 === 0) await new Promise((r) => setImmediate(r));
  }

  report({
    phase: "discovering",
    percent: 100,
    statusDetail: roots.length
      ? `Found ${roots.length} source(s)`
      : "No validated sources found",
    logLine: roots.length
      ? `Discovery complete — ${roots.length} source(s) ready.`
      : "Discovery complete — no readable AI history at standard paths.",
    candidateCount: total,
    candidatesChecked: checked,
  });

  const scanReport = roots.length
    ? null
    : buildEmptyAiScanReport({ scanMode: "local", scanned: total, hitsFound: roots.length });

  return { roots, candidateCount: total, scanReport };
}

async function extractRoot(tool, rootPath, attribution, options) {
  switch (tool) {
    case "claude-code": return extractClaudeDir(rootPath, attribution, options);
    case "codex": return extractCodexDir(rootPath, attribution, options);
    case "grok-build": return extractGrokBuildDir(rootPath, attribution, options);
    case "chatgpt": return extractChatgptDir(rootPath, attribution, options);
    case "gemini-cli": return extractGeminiCliDir(rootPath, attribution, options);
    case "cursor": return extractCursorDir(rootPath, attribution, options);
    case "copilot": return extractCopilotPath(rootPath, attribution, options);
    case "windsurf": return require("./windsurf").extractWindsurfPath(rootPath, attribution, options);
    case "continue": return require("./continue").extractContinuePath(rootPath, attribution, options);
    default: return [];
  }
}

/**
 * Extract and merge every discovered (or supplied) root into one timeline row set.
 */
async function extractMergedAiHistoryRoots(roots, attribution = {}, options = {}) {
  const { onProgress, includeSubagents } = options;
  // G1: honor a caller-supplied abort token (worker cancel) so cancellation works during the
  // parse phase too; only fall back to the process-global flag when no token is provided.
  const checkAbort = typeof options.checkAbort === "function"
    ? options.checkAbort
    : () => {};
  const maxRows = Number.isFinite(options.maxRows) && options.maxRows > 0
    ? options.maxRows
    : MAX_AI_HISTORY_ROWS;
  const report = (patch) => {
    if (typeof onProgress === "function") onProgress(patch);
  };
  // Throttle per-file progress to ~6/sec (always send a source's last file) — see the matching note
  // in extractMergedAiHistoryRootsToDb; a 500-file source otherwise fires 500 progress callbacks.
  const FILE_PROGRESS_THROTTLE_MS = 160;
  let lastFileReportAt = 0;
  const reportFileProgress = (patch, isLast) => {
    const now = Date.now();
    if (!isLast && now - lastFileReportAt < FILE_PROGRESS_THROTTLE_MS) return;
    lastFileReportAt = now;
    report(patch);
  };
  const merged = [];
  const failures = [];
  let copilotStats = null;
  let claudeDesktopStats = null;
  let chatgptStats = null;
  let cursorComposerStats = null;
  let windsurfStats = null;
  let codexStateSqliteStats = null;
  let codexAuxSqliteStats = null;
  let codexLocalEvidenceStats = null;
  let windsurfCascadeStats = null;
  let parseErrorTotal = 0;
  let capped = false;
  const sourceCount = roots.length;

  report({
    phase: "extracting",
    percent: 4,
    statusDetail: `Parsing ${sourceCount} AI source${sourceCount === 1 ? "" : "s"}…`,
    logLine: includeSubagents
      ? `Scope: main + subagent session folders (${sourceCount} source${sourceCount === 1 ? "" : "s"})`
      : `Scope: main sessions only (${sourceCount} source${sourceCount === 1 ? "" : "s"})`,
    sourceCount,
    rowsSoFar: 0,
  });

  const defaultUser = attribution.user || "";
  const defaultHost = attribution.host || "";

  for (let i = 0; i < roots.length; i++) {
    checkAbort();
    const { tool, path: rootPath, label, endpointUser, endpointHost } = roots[i];
    const rootAttribution = {
      user: endpointUser || defaultUser,
      host: endpointHost || defaultHost,
    };
    const rootOptions = {
      includeSubagents: !!includeSubagents,
      skipSubagents: !includeSubagents,
      skipFinalize: true,
      checkAbort,
      onFileProgress: (fileIndex, fileCount, filePath) => {
        const fileFrac = fileCount > 0 ? fileIndex / fileCount : 0;
        const fileLabel = filePath && (String(filePath).includes(path.sep) || String(filePath).includes("/"))
          ? path.basename(filePath)
          : String(filePath || "…");
        reportFileProgress({
          phase: "extracting",
          percent: Math.min(90, Math.round(4 + ((i + fileFrac) / sourceCount) * 86)),
          sourceIndex: i + 1,
          sourceCount,
          tool,
          label,
          rootPath,
          fileIndex,
          fileCount,
          filePath,
          statusDetail: `${label}: ${fileLabel} (${fileIndex}/${fileCount})`,
          logLine: `${label} — ${fileLabel} [${fileIndex}/${fileCount}]`,
          rowsSoFar: merged.length,
        }, fileIndex >= fileCount);
      },
    };

    report({
      phase: "extracting",
      percent: Math.round(4 + (i / sourceCount) * 86),
      sourceIndex: i + 1,
      sourceCount,
      tool,
      label,
      rootPath,
      statusDetail: `Starting ${label}…`,
      logLine: `▶ ${label}\n   ${rootPath}`,
      rowsSoFar: merged.length,
    });

    try {
      const chunk = await extractRoot(tool, rootPath, rootAttribution, rootOptions);
      if (chunk._copilotStats) copilotStats = chunk._copilotStats;
      if (chunk._claudeDesktopStats) claudeDesktopStats = chunk._claudeDesktopStats;
      if (chunk._chatgptStats) chatgptStats = chunk._chatgptStats;
      if (chunk._cursorComposerStats) cursorComposerStats = chunk._cursorComposerStats;
      if (chunk._windsurfStats) windsurfStats = chunk._windsurfStats;
      if (chunk._codexStateSqliteStats) codexStateSqliteStats = chunk._codexStateSqliteStats;
      if (chunk._codexAuxSqliteStats) codexAuxSqliteStats = chunk._codexAuxSqliteStats;
      if (chunk._codexLocalEvidenceStats) codexLocalEvidenceStats = chunk._codexLocalEvidenceStats;
      if (chunk._windsurfCascadeStats) windsurfCascadeStats = chunk._windsurfCascadeStats;
      if (chunk._parseErrors) parseErrorTotal += chunk._parseErrors;
      // Push element-by-element, not `merged.push(...chunk)`: spreading an array past ~125k
      // elements throws RangeError (Maximum call stack size). Stop at the cap during accumulation
      // so a single pathological source can't blow past maxRows before the between-source check.
      for (const r of chunk) {
        if (merged.length >= maxRows) { capped = true; break; }
        merged.push(r);
      }
      dbg("AIHIST", "profile-scan extracted", { tool, rootPath, rows: chunk.length });
      report({
        phase: "extracting",
        percent: Math.round(4 + ((i + 1) / sourceCount) * 86),
        sourceIndex: i + 1,
        sourceCount,
        tool,
        label,
        rootPath,
        messagesInSource: chunk.length,
        rowsSoFar: merged.length,
        statusDetail: `${label}: ${chunk.length.toLocaleString()} message row(s)`,
        logLine: `✓ ${label}: ${chunk.length.toLocaleString()} row(s) extracted`,
      });
      // G2: stop ingesting once the safety cap is hit; remaining sources are reported, not read.
      if (merged.length >= maxRows) {
        capped = true;
        failures.push({
          tool,
          label,
          path: rootPath,
          error: `Row cap of ${maxRows.toLocaleString()} reached — remaining source(s) were skipped.`,
        });
        break;
      }
    } catch (e) {
      failures.push({ tool, label, path: rootPath, error: e.message });
      dbg("AIHIST", "profile-scan extract failed", { tool, rootPath, err: e.message });
      report({
        phase: "extracting",
        sourceIndex: i + 1,
        sourceCount,
        tool,
        label,
        rootPath,
        statusDetail: `${label} failed: ${e.message}`,
        logLine: `✗ ${label}: ${e.message}`,
        rowsSoFar: merged.length,
      });
    }
    if (i % 2 === 1) await new Promise((r) => setImmediate(r));
  }

  report({
    phase: "merging",
    percent: 92,
    statusDetail: "Deduplicating and sorting messages…",
    logLine: "Merging: dedupe overlapping prompts + chronological sort…",
    rowsSoFar: merged.length,
  });

  let rows = sortAndNumberRows(dedupeAiHistoryRows(merged, { crossTool: true }));
  if (rows.length > maxRows) {
    capped = true;
    rows = rows.slice(0, maxRows);
    for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
  }

  report({
    phase: "merging",
    percent: 96,
    statusDetail: `${rows.length.toLocaleString()} unique messages ready`,
    logLine: `Merge complete — ${rows.length.toLocaleString()} timeline row(s)`,
    rowsSoFar: rows.length,
  });
  const importMeta = {
    cursor: {
      syntheticTimestamps: roots.some((r) => r.tool === "cursor"),
      composer: cursorComposerStats,
    },
  };
  if (claudeDesktopStats) importMeta.claudeDesktop = claudeDesktopStats;
  if (chatgptStats) importMeta.chatgpt = chatgptStats;
  if (copilotStats || roots.some((r) => r.tool === "copilot")) {
    importMeta.copilot = buildCopilotExtractionStats(rows, copilotStats || getCopilotExtractionStats(rows));
  }
  if (windsurfStats) importMeta.windsurf = windsurfStats;
  if (codexStateSqliteStats) importMeta.codexStateSqlite = codexStateSqliteStats;
  if (codexAuxSqliteStats) importMeta.codexAuxSqlite = codexAuxSqliteStats;
  if (codexLocalEvidenceStats) importMeta.codexLocalEvidence = codexLocalEvidenceStats;
  if (windsurfCascadeStats) importMeta.windsurfCascade = windsurfCascadeStats;
  if (parseErrorTotal) importMeta.parseErrors = parseErrorTotal;
  if (capped) importMeta.capped = { maxRows, rowCount: rows.length };
  if (parseErrorTotal) rows._parseErrors = parseErrorTotal;
  if (capped) rows._capped = importMeta.capped;

  return {
    rows,
    importMeta,
    importNotice: buildAiHistoryImportNotice(importMeta) || null,
    failures,
    parseErrors: parseErrorTotal,
    capped,
  };
}

function collectChunkSidecarStats(chunk, acc) {
  if (chunk._copilotStats) acc.copilotStats = chunk._copilotStats;
  if (chunk._claudeDesktopStats) acc.claudeDesktopStats = chunk._claudeDesktopStats;
  if (chunk._chatgptStats) acc.chatgptStats = chunk._chatgptStats;
  if (chunk._cursorComposerStats) acc.cursorComposerStats = chunk._cursorComposerStats;
  if (chunk._windsurfStats) acc.windsurfStats = chunk._windsurfStats;
  if (chunk._codexStateSqliteStats) acc.codexStateSqliteStats = chunk._codexStateSqliteStats;
  if (chunk._codexAuxSqliteStats) acc.codexAuxSqliteStats = chunk._codexAuxSqliteStats;
  if (chunk._codexLocalEvidenceStats) acc.codexLocalEvidenceStats = chunk._codexLocalEvidenceStats;
  if (chunk._windsurfCascadeStats) acc.windsurfCascadeStats = chunk._windsurfCascadeStats;
  if (chunk._parseErrors) acc.parseErrorTotal += chunk._parseErrors;
}

/**
 * Extract discovered roots straight into a tab SQLite DB (worker path).
 * Never materializes the full merged row array — each source is deduped/sorted and flushed
 * before the next root is parsed.
 */
async function extractMergedAiHistoryRootsToDb(db, tabId, roots, attribution = {}, options = {}) {
  const { onProgress, includeSubagents } = options;
  const checkAbort = typeof options.checkAbort === "function" ? options.checkAbort : () => {};
  const maxRows = Number.isFinite(options.maxRows) && options.maxRows > 0
    ? options.maxRows
    : MAX_AI_HISTORY_ROWS;
  const headers = options.headers || AI_HISTORY_COLUMNS;
  const report = (patch) => {
    if (typeof onProgress === "function") onProgress(patch);
  };
  // Per-FILE progress fires once per source file (500+ ChatGPT LevelDB files, 200+ Cursor transcripts):
  // every one becomes a worker postMessage + a renderer re-render + a log line + a scroll. Throttle the
  // per-file reports to ~6/sec, but ALWAYS send the last file of a source so completion stays visible.
  // (Milestone reports — "Starting X", source-done — go through `report` directly, unthrottled.)
  const FILE_PROGRESS_THROTTLE_MS = 160;
  let lastFileReportAt = 0;
  const reportFileProgress = (patch, isLast) => {
    const now = Date.now();
    if (!isLast && now - lastFileReportAt < FILE_PROGRESS_THROTTLE_MS) return;
    lastFileReportAt = now;
    report(patch);
  };
  const failures = [];
  const stats = {
    copilotStats: null,
    claudeDesktopStats: null,
    chatgptStats: null,
    cursorComposerStats: null,
    windsurfStats: null,
    codexStateSqliteStats: null,
    codexAuxSqliteStats: null,
    codexLocalEvidenceStats: null,
    windsurfCascadeStats: null,
    parseErrorTotal: 0,
  };
  let capped = false;
  let totalWritten = 0;
  let nextRecordId = 1;
  let streamedDuplicatesDropped = 0;
  const streamedSeenKeys = new Set();
  const sourceCount = roots.length;

  db.createTab(tabId, [...headers]);

  report({
    phase: "extracting",
    percent: 4,
    statusDetail: `Parsing ${sourceCount} AI source${sourceCount === 1 ? "" : "s"}…`,
    logLine: includeSubagents
      ? `Scope: main + subagent session folders (${sourceCount} source${sourceCount === 1 ? "" : "s"})`
      : `Scope: main sessions only (${sourceCount} source${sourceCount === 1 ? "" : "s"})`,
    sourceCount,
    rowsSoFar: 0,
  });

  const defaultUser = attribution.user || "";
  const defaultHost = attribution.host || "";

  for (let i = 0; i < roots.length; i++) {
    checkAbort();
    if (totalWritten >= maxRows) break;

    const { tool, path: rootPath, label, endpointUser, endpointHost } = roots[i];
    const rootAttribution = {
      user: endpointUser || defaultUser,
      host: endpointHost || defaultHost,
    };
    const rootOptions = {
      includeSubagents: !!includeSubagents,
      skipSubagents: !includeSubagents,
      skipFinalize: true,
      checkAbort,
      onFileProgress: (fileIndex, fileCount, filePath) => {
        const fileFrac = fileCount > 0 ? fileIndex / fileCount : 0;
        const fileLabel = filePath && (String(filePath).includes(path.sep) || String(filePath).includes("/"))
          ? path.basename(filePath)
          : String(filePath || "…");
        reportFileProgress({
          phase: "extracting",
          percent: Math.min(90, Math.round(4 + ((i + fileFrac) / sourceCount) * 86)),
          sourceIndex: i + 1,
          sourceCount,
          tool,
          label,
          rootPath,
          fileIndex,
          fileCount,
          filePath,
          statusDetail: `${label}: ${fileLabel} (${fileIndex}/${fileCount})`,
          logLine: `${label} — ${fileLabel} [${fileIndex}/${fileCount}]`,
          rowsSoFar: totalWritten,
        }, fileIndex >= fileCount);
      },
    };

    report({
      phase: "extracting",
      percent: Math.round(4 + (i / sourceCount) * 86),
      sourceIndex: i + 1,
      sourceCount,
      tool,
      label,
      rootPath,
      statusDetail: `Starting ${label}…`,
      logLine: `▶ ${label}\n   ${rootPath}`,
      rowsSoFar: totalWritten,
    });

    try {
      const rowsBeforeSource = totalWritten;
      // Accumulate the whole source (bounded to the remaining row budget) then flush once, so the
      // history.jsonl↔session dedupe in dedupeAiHistoryRows — which needs both row kinds together —
      // actually fires. The previous per-flush-batch dedupe left duplicate rows in the merged tab.
      const acc = makeSourceAccumulator(maxRows);
      const collectExtractedRows = (rawBatch) => {
        checkAbort();
        acc.add(rawBatch, totalWritten);
      };
      const chunk = await extractRoot(tool, rootPath, rootAttribution, {
        ...rootOptions,
        onExtractedRows: collectExtractedRows,
      });
      collectChunkSidecarStats(chunk, stats);
      if (chunk.length) acc.add(chunk, totalWritten);
      // Retain FullText for AI tabs so the AI Secret Scan can see content past the 500-char Summary
      // preview (the merged/triage path previously slimmed it, leaving secret detection blind).
      let prepared = prepareChunkRowsForDb(acc.rows, nextRecordId, maxRows, totalWritten, { keepFullText: true });
      const filtered = filterAlreadySeenStreamedRows(prepared, streamedSeenKeys);
      prepared = filtered.rows;
      streamedDuplicatesDropped += filtered.dropped;
      for (let j = 0; j < prepared.length; j++) prepared[j].RecordId = String(nextRecordId + j);
      if (prepared.length) {
        writeAiHistoryRowsToDb(db, tabId, headers, prepared, checkAbort);
        totalWritten += prepared.length;
        nextRecordId += prepared.length;
      }
      if (acc.truncated) capped = true;
      const sourceRows = totalWritten - rowsBeforeSource;
      dbg("AIHIST", "profile-scan streamed to db", { tool, rootPath, rows: sourceRows, totalWritten });
      report({
        phase: "extracting",
        percent: Math.round(4 + ((i + 1) / sourceCount) * 86),
        sourceIndex: i + 1,
        sourceCount,
        tool,
        label,
        rootPath,
        messagesInSource: sourceRows,
        rowsSoFar: totalWritten,
        statusDetail: `${label}: ${sourceRows.toLocaleString()} message row(s)`,
        logLine: `✓ ${label}: ${sourceRows.toLocaleString()} row(s) written`,
      });
      if (totalWritten >= maxRows) {
        capped = true;
        failures.push({
          tool,
          label,
          path: rootPath,
          error: `Row cap of ${maxRows.toLocaleString()} reached — remaining source(s) were skipped.`,
        });
        break;
      }
    } catch (e) {
      failures.push({ tool, label, path: rootPath, error: e.message });
      dbg("AIHIST", "profile-scan extract failed", { tool, rootPath, err: e.message });
      report({
        phase: "extracting",
        sourceIndex: i + 1,
        sourceCount,
        tool,
        label,
        rootPath,
        statusDetail: `${label} failed: ${e.message}`,
        logLine: `✗ ${label}: ${e.message}`,
        rowsSoFar: totalWritten,
      });
    }
    if (i % 2 === 1) await new Promise((r) => setImmediate(r));
  }

  report({
    phase: "merging",
    percent: 96,
    statusDetail: `${totalWritten.toLocaleString()} messages written`,
    logLine: `Stream complete — ${totalWritten.toLocaleString()} timeline row(s) in database`,
    rowsSoFar: totalWritten,
  });

  const meta = db.databases.get(tabId);
  if (meta && totalWritten > 50_000) meta.isLargeFile = true;

  const importMeta = {
    cursor: {
      syntheticTimestamps: roots.some((r) => r.tool === "cursor"),
      composer: stats.cursorComposerStats,
    },
  };
  if (stats.claudeDesktopStats) importMeta.claudeDesktop = stats.claudeDesktopStats;
  if (stats.chatgptStats) importMeta.chatgpt = stats.chatgptStats;
  if (stats.copilotStats || roots.some((r) => r.tool === "copilot")) {
    importMeta.copilot = buildCopilotExtractionStats([], stats.copilotStats || {});
  }
  if (stats.windsurfStats) importMeta.windsurf = stats.windsurfStats;
  if (stats.codexStateSqliteStats) importMeta.codexStateSqlite = stats.codexStateSqliteStats;
  if (stats.codexAuxSqliteStats) importMeta.codexAuxSqlite = stats.codexAuxSqliteStats;
  if (stats.codexLocalEvidenceStats) importMeta.codexLocalEvidence = stats.codexLocalEvidenceStats;
  if (stats.windsurfCascadeStats) importMeta.windsurfCascade = stats.windsurfCascadeStats;
  if (stats.parseErrorTotal) importMeta.parseErrors = stats.parseErrorTotal;
  if (capped) importMeta.capped = { maxRows, rowCount: totalWritten };
  if (sourceCount > 1) {
    importMeta.streamedMerge = {
      crossToolDedupe: false,
      exactDuplicatesDropped: streamedDuplicatesDropped,
      note: "Streamed import performs per-source dedupe plus exact duplicate suppression across sources. "
        + "Cross-tool prompt merge is still skipped to preserve source provenance.",
    };
  }

  return {
    rowCount: totalWritten,
    importMeta,
    importNotice: buildAiHistoryImportNotice(importMeta) || null,
    failures,
    parseErrors: stats.parseErrorTotal,
    capped,
  };
}

module.exports = {
  AiHistoryExtractAbortedError,
  getLocalAiHistoryCandidates,
  validateAiHistoryRoot,
  discoverLocalAiHistoryRoots,
  discoverAiHistoryInFolder,
  discoverAiHistoryRoots,
  extractMergedAiHistoryRoots,
  extractMergedAiHistoryRootsToDb,
  ARTIFACT_PATH_REFERENCES: artifactPaths.ARTIFACT_PATH_REFERENCES,
  FORENSIC_AI_PATH_HINTS: artifactPaths.FORENSIC_AI_PATH_HINTS,
  defaultCodexHome,
  buildEmptyAiScanReport,
};
