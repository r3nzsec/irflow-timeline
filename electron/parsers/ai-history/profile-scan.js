/**
 * ai-history/profile-scan.js — discover local AI artifact roots on the analyst machine.
 */

const fs = require("fs");
const os = require("os");

const { dbg } = require("../../logger");
const { AI_HISTORY_TOOLS, AI_HISTORY_COLUMNS, AI_HISTORY_DB_OMIT_FULLTEXT } = require("./schema");
const { extractClaudeDir, isClaudeJsonStateFile } = require("./claude-code");
const { extractCodexDir } = require("./codex");
const { extractGrokBuildDir } = require("./grok-build");
const { extractGrokBotDir, mergeGrokBotStats } = require("./grok-bot");
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
  isGrokBotRoot,
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
const { extractWithSourceCoverage, inventoryAiHistorySources, SourceCoverageTracker } = require("./source-coverage");
const { mergePerformanceMetrics } = require("./performance-metrics");
const { inventoryFingerprint } = require("./discovery-inventory");
const path = require("path");


const FOLDER_SCAN_TOOL_MAP = [
  ["claudeCode", "claude-code"],
  ["codex", "codex"],
  ["grokBuild", "grok-build"],
  ["grokBot", "grok-bot"],
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
    case "claude-code": return isClaudeCodeArtifactRoot(rootPath) || isClaudeJsonStateFile(rootPath);
    case "codex": return isCodexDir(rootPath);
    case "grok-build": return isGrokBuildRoot(rootPath, q);
    case "grok-bot": return isGrokBotRoot(rootPath);
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
  const extractors = {
    "claude-code": extractClaudeDir,
    codex: extractCodexDir,
    "grok-build": extractGrokBuildDir,
    "grok-bot": extractGrokBotDir,
    chatgpt: extractChatgptDir,
    "gemini-cli": extractGeminiCliDir,
    cursor: extractCursorDir,
    copilot: extractCopilotPath,
    windsurf: require("./windsurf").extractWindsurfPath,
    continue: require("./continue").extractContinuePath,
  };
  const extractor = extractors[tool];
  if (!extractor) return [];
  return extractWithSourceCoverage(tool, rootPath, attribution, options, extractor);
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
  let codexThreadHistoryStats = null;
  let codexLocalEvidenceStats = null;
  let claudeContextStats = null;
  let cursorContextStats = null;
  let codexContextStats = null;
  let grokContextStats = null;
  let geminiHistoryStats = null;
  let windsurfCascadeStats = null;
  let grokBotStats = null;
  let sourceCoverage = [];
  let cursorSyntheticTimestamps = false;
  let cursorPartialSyntheticTimestamps = false;
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
      if (chunk._codexThreadHistoryStats) codexThreadHistoryStats = chunk._codexThreadHistoryStats;
      if (chunk._codexLocalEvidenceStats) codexLocalEvidenceStats = chunk._codexLocalEvidenceStats;
      if (chunk._claudeContextStats) claudeContextStats = chunk._claudeContextStats;
      if (chunk._cursorContextStats) cursorContextStats = chunk._cursorContextStats;
      if (chunk._codexContextStats) codexContextStats = chunk._codexContextStats;
      if (chunk._grokContextStats) grokContextStats = chunk._grokContextStats;
      if (chunk._geminiHistoryStats) geminiHistoryStats = chunk._geminiHistoryStats;
      if (chunk._windsurfCascadeStats) windsurfCascadeStats = chunk._windsurfCascadeStats;
      if (chunk._grokBotStats) grokBotStats = mergeGrokBotStats(grokBotStats, chunk._grokBotStats);
      if (chunk._sourceCoverage) sourceCoverage.push(...chunk._sourceCoverage);
      if (chunk._cursorSyntheticTimestamps) cursorSyntheticTimestamps = true;
      if (chunk._cursorPartialSyntheticTimestamps) cursorPartialSyntheticTimestamps = true;
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
      if (e?.canceled || e?.cancelled) throw e;
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
    statusDetail: "Correlating and sorting source occurrences…",
    logLine: "Merging: correlate matching prompts + chronological sort…",
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
    statusDetail: `${rows.length.toLocaleString()} evidence row(s) ready`,
    logLine: `Merge complete — ${rows.length.toLocaleString()} timeline row(s)`,
    rowsSoFar: rows.length,
  });
  const importMeta = {
    cursor: {
      syntheticTimestamps: cursorSyntheticTimestamps || cursorPartialSyntheticTimestamps,
      partialSyntheticTimestamps: cursorPartialSyntheticTimestamps,
      composer: cursorComposerStats,
      context: cursorContextStats,
    },
  };
  if (sourceCoverage.length) importMeta.sourceCoverage = sourceCoverage;
  if (claudeDesktopStats) importMeta.claudeDesktop = claudeDesktopStats;
  if (chatgptStats) importMeta.chatgpt = chatgptStats;
  if (copilotStats || roots.some((r) => r.tool === "copilot")) {
    importMeta.copilot = buildCopilotExtractionStats(rows, copilotStats || getCopilotExtractionStats(rows));
  }
  if (windsurfStats) importMeta.windsurf = windsurfStats;
  if (codexStateSqliteStats) importMeta.codexStateSqlite = codexStateSqliteStats;
  if (codexAuxSqliteStats) importMeta.codexAuxSqlite = codexAuxSqliteStats;
  if (codexThreadHistoryStats) importMeta.codexThreadHistory = codexThreadHistoryStats;
  if (codexLocalEvidenceStats) importMeta.codexLocalEvidence = codexLocalEvidenceStats;
  if (claudeContextStats) importMeta.claudeContext = claudeContextStats;
  if (codexContextStats) importMeta.codexContext = codexContextStats;
  if (grokContextStats) importMeta.grokContext = grokContextStats;
  if (geminiHistoryStats) importMeta.geminiHistory = geminiHistoryStats;
  if (windsurfCascadeStats) importMeta.windsurfCascade = windsurfCascadeStats;
  if (grokBotStats) importMeta.grokBot = grokBotStats;
  if (parseErrorTotal) importMeta.parseErrors = parseErrorTotal;
  if (capped) importMeta.capped = { maxRows, rowCount: rows.length };
  if (parseErrorTotal) rows._parseErrors = parseErrorTotal;
  if (sourceCoverage.length) rows._sourceCoverage = sourceCoverage;
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
  if (chunk._sourceCoverage) acc.sourceCoverage.push(...chunk._sourceCoverage);
  if (chunk._cursorSyntheticTimestamps) acc.cursorSyntheticTimestamps = true;
  if (chunk._cursorPartialSyntheticTimestamps) acc.cursorPartialSyntheticTimestamps = true;
  if (chunk._copilotStats) acc.copilotStats = chunk._copilotStats;
  if (chunk._claudeDesktopStats) acc.claudeDesktopStats = chunk._claudeDesktopStats;
  if (chunk._chatgptStats) acc.chatgptStats = chunk._chatgptStats;
  if (chunk._cursorComposerStats) acc.cursorComposerStats = chunk._cursorComposerStats;
  if (chunk._windsurfStats) acc.windsurfStats = chunk._windsurfStats;
  if (chunk._codexStateSqliteStats) acc.codexStateSqliteStats = chunk._codexStateSqliteStats;
  if (chunk._codexAuxSqliteStats) acc.codexAuxSqliteStats = chunk._codexAuxSqliteStats;
  if (chunk._codexThreadHistoryStats) acc.codexThreadHistoryStats = chunk._codexThreadHistoryStats;
  if (chunk._codexLocalEvidenceStats) acc.codexLocalEvidenceStats = chunk._codexLocalEvidenceStats;
  if (chunk._claudeContextStats) acc.claudeContextStats = chunk._claudeContextStats;
  if (chunk._cursorContextStats) acc.cursorContextStats = chunk._cursorContextStats;
  if (chunk._codexContextStats) acc.codexContextStats = chunk._codexContextStats;
  if (chunk._grokContextStats) acc.grokContextStats = chunk._grokContextStats;
  if (chunk._geminiHistoryStats) acc.geminiHistoryStats = chunk._geminiHistoryStats;
  if (chunk._windsurfCascadeStats) acc.windsurfCascadeStats = chunk._windsurfCascadeStats;
  if (chunk._grokBotStats) acc.grokBotStats = mergeGrokBotStats(acc.grokBotStats, chunk._grokBotStats);
  if (chunk._parseErrors) acc.parseErrorTotal += chunk._parseErrors;
  if (chunk._performance) acc.performance.push(chunk._performance);
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
    codexThreadHistoryStats: null,
    codexLocalEvidenceStats: null,
    claudeContextStats: null,
    cursorContextStats: null,
    codexContextStats: null,
    grokContextStats: null,
    geminiHistoryStats: null,
    windsurfCascadeStats: null,
    grokBotStats: null,
    sourceCoverage: [],
    cursorSyntheticTimestamps: false,
    cursorPartialSyntheticTimestamps: false,
    parseErrorTotal: 0,
    performance: [],
  };
  let capped = false;
  let totalWritten = 0;
  let nextRecordId = 1;
  let streamedDuplicatesDropped = 0;
  const MERGED_FULLTEXT_CHARS = 8 * 1024;
  const fullTextStats = { fullTextTruncated: 0 };
  const streamedSeenKeys = new Set();
  const sourceCount = roots.length;
  // Build each root's eligible-source list once. The same list drives parsing, the completion
  // ledger, and deterministic remaining-source reporting if the global row budget stops early.
  const sourceInventories = roots.map((root) => inventoryAiHistorySources(root.tool, root.path, {
    ...options,
    includeSubagents: !!includeSubagents,
    skipSubagents: !includeSubagents,
  }));
  const attemptedRoots = new Set();

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
      sourceInventory: sourceInventories[i],
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
      attemptedRoots.add(i);
      const rowsBeforeSource = totalWritten;
      // Flush in bounded chunks. Holding an entire Codex/Claude source (multi-GB rollouts) in
      // acc.rows with FullText kept is what OOMs the V8 worker and aborts the whole Electron
      // process. Cross-flush exact-duplicate dedupe uses streamedSeenKeys.
      //
      // Each physical source occurrence remains eligible for output. Cross-flush dedupe removes
      // only a repeated representation with the same source locator and content hash.
      const SOURCE_FLUSH_ROWS = 15_000;
      const acc = makeSourceAccumulator(maxRows);
      const addRows = (batch) => {
        if (!batch || !batch.length) return;
        acc.add(batch, totalWritten);
      };
      const flushAcc = () => {
        if (!acc.rows.length) return;
        let prepared = prepareChunkRowsForDb(acc.rows, nextRecordId, maxRows, totalWritten, {
          keepFullText: true,
          maxFullTextChars: MERGED_FULLTEXT_CHARS,
          stats: fullTextStats,
        });
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
        acc.reset();
      };
      const collectExtractedRows = (rawBatch) => {
        checkAbort();
        addRows(rawBatch);
        if (acc.rows.length >= SOURCE_FLUSH_ROWS) flushAcc();
      };
      const chunk = await extractRoot(tool, rootPath, rootAttribution, {
        ...rootOptions,
        onExtractedRows: collectExtractedRows,
      });
      collectChunkSidecarStats(chunk, stats);
      if (chunk.length) addRows(chunk);
      flushAcc();
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
      if (e?.canceled || e?.cancelled) throw e;
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
      syntheticTimestamps: stats.cursorSyntheticTimestamps || stats.cursorPartialSyntheticTimestamps,
      partialSyntheticTimestamps: stats.cursorPartialSyntheticTimestamps,
      composer: stats.cursorComposerStats,
      context: stats.cursorContextStats,
    },
  };
  const completeCoverage = new Map(stats.sourceCoverage.map((entry) => [entry.sourceFile, entry]));
  for (let i = 0; i < roots.length; i++) {
    const root = roots[i];
    for (const sourceFile of sourceInventories[i]) {
      const source = path.resolve(sourceFile);
      if (completeCoverage.has(source)) continue;
      const tracker = new SourceCoverageTracker(root.tool, [source]);
      tracker.mark(
        source,
        attemptedRoots.has(i) ? "unavailable" : "excluded",
        attemptedRoots.has(i)
          ? "source was eligible but the parser did not complete it"
          : "source remained after extraction stopped at the global row budget",
      );
      completeCoverage.set(source, tracker.report()[0]);
    }
  }
  stats.sourceCoverage = [...completeCoverage.values()].sort((a, b) => a.sourceFile.localeCompare(b.sourceFile));
  const remainingSources = stats.sourceCoverage
    .filter((entry) => entry.status === "excluded")
    .map((entry) => entry.sourceFile);
  const allInventoryPaths = sourceInventories.flat().map((source) => path.resolve(source));
  importMeta.discoveryInventory = {
    version: 1,
    eligibleSources: allInventoryPaths.length,
    inventoryFingerprintSha256: inventoryFingerprint([...new Set(allInventoryPaths)].sort()),
    remainingSources,
    remainingSourceCount: remainingSources.length,
  };
  if (stats.sourceCoverage.length) importMeta.sourceCoverage = stats.sourceCoverage;
  if (stats.claudeDesktopStats) importMeta.claudeDesktop = stats.claudeDesktopStats;
  if (stats.chatgptStats) importMeta.chatgpt = stats.chatgptStats;
  if (stats.copilotStats || roots.some((r) => r.tool === "copilot")) {
    importMeta.copilot = buildCopilotExtractionStats([], stats.copilotStats || {});
  }
  if (stats.windsurfStats) importMeta.windsurf = stats.windsurfStats;
  if (stats.codexStateSqliteStats) importMeta.codexStateSqlite = stats.codexStateSqliteStats;
  if (stats.codexAuxSqliteStats) importMeta.codexAuxSqlite = stats.codexAuxSqliteStats;
  if (stats.codexThreadHistoryStats) importMeta.codexThreadHistory = stats.codexThreadHistoryStats;
  if (stats.codexLocalEvidenceStats) importMeta.codexLocalEvidence = stats.codexLocalEvidenceStats;
  if (stats.claudeContextStats) importMeta.claudeContext = stats.claudeContextStats;
  if (stats.codexContextStats) importMeta.codexContext = stats.codexContextStats;
  if (stats.grokContextStats) importMeta.grokContext = stats.grokContextStats;
  if (stats.geminiHistoryStats) importMeta.geminiHistory = stats.geminiHistoryStats;
  if (stats.windsurfCascadeStats) importMeta.windsurfCascade = stats.windsurfCascadeStats;
  if (stats.grokBotStats) importMeta.grokBot = stats.grokBotStats;
  if (stats.parseErrorTotal) importMeta.parseErrors = stats.parseErrorTotal;
  const performance = mergePerformanceMetrics(stats.performance);
  if (performance) importMeta.performance = performance;
  if (capped) importMeta.capped = { maxRows, rowCount: totalWritten };
  if (fullTextStats.fullTextTruncated > 0) {
    importMeta.fullTextTruncated = { rows: fullTextStats.fullTextTruncated, maxChars: MERGED_FULLTEXT_CHARS };
  }
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
