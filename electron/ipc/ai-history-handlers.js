/**
 * ipc/ai-history-handlers.js — AI assistant history collection / decode handlers.
 *
 * Registers the IPC channels that discover & extract AI conversation history into timeline tabs:
 *   decode-ai-history            — per-tool decode (Claude Code, Codex, ChatGPT, …) from a file/folder
 *   pick-ai-history-scan-folder  — folder picker for a KAPE / triage / mounted collection
 *   discover-ai-history-profile  — discover AI roots on this Mac or a collection folder
 *   extract-ai-history-profile   — discover + extract + merge into one AI Query History tab
 *   cancel-ai-history-extract    — abort an in-flight extraction
 *
 * Kept separate from unrelated forensic handler groups so AI collection remains self-contained.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { dialog } = require("electron");

const { dbg } = require("../logger");
const { openDialogOptions } = require("../utils/open-dialog");
const { defaultDecodeAiHistoryDialogPath } = require("../parsers/ai-history/open-dialog-paths");
const {
  TOOL_COMPUTER_HISTORY,
  COMPUTER_HISTORY_TOOL_ID,
} = require("../parsers/ai-history/computer-history-schema");
const {
  defaultComputerHistoryRoots,
  isComputerHistoryDir,
  isSkysightEventsFile,
  isSkysightSummaryFile,
} = require("../parsers/ai-history/computer-history");
const {
  extractAiHistory,
  extractClaudeDir,
  extractCodexDir,
  extractChatgptDir,
  extractGeminiCliDir,
  extractCursorDir,
  extractCopilotPath,
  resolveClaudeDir,
  resolveCodexHome,
  resolveGrokHome,
  resolveChatgptDir,
  resolveGeminiCliRoot,
  resolveCursorRoot,
  resolveCopilotRoot,
  resolveWindsurfUserDir,
  continueHome,
  defaultCodexHome,
  defaultCopilotWorkspaceStorage,
  AI_HISTORY_TOOLS,
  getCopilotExtractionStats,
} = require("../parsers/ai-history");
const {
  buildAiHistoryImportNotice,
  buildCopilotExtractionStats,
} = require("../parsers/ai-history/import-meta");
const {
  discoverAiHistoryRoots,
  buildEmptyAiScanReport,
  extractMergedAiHistoryRoots,
} = require("../parsers/ai-history/profile-scan");
const { confineRootsToScope } = require("../parsers/ai-history/resolve-root");
const {
  createAiHistoryExtractAbortToken,
  requestAiHistoryExtractAbort,
  AiHistoryExtractAbortedError,
} = require("../parsers/ai-history/extract-abort");
const {
  authorizeAiScanTarget,
  authorizeAiArtifactPick,
  authorizeDiscoveredRoots,
  assertAiReadablePath,
  assertAiScanTarget,
  assertExtractRootsAuthorized,
} = require("../parsers/ai-history/path-auth");
const { deriveUser, deriveHost, annotateCsvUserHost } = require("../parsers/path-attribution");
const { parseCSVLine } = require("../parsers/csv");

const AI_HISTORY_IPC_QUERY_OPTS = {
  omitHeaders: ["FullText"],
  truncateColumns: {
    Summary: 240,
    ToolInput: 2048,
    ToolDescription: 1000,
    Description: 480,
    Transcript: 480,
  },
};

const AI_HISTORY_EMPTY_COL_OMIT = ["FullText", "Description", "Transcript"];

/**
 * Computer History rows carry two potentially huge payloads: ScreenText (a full accessibility-tree
 * screen scrape, observed >100K chars for a single event) and Content (terminal scrollback). Both
 * must be truncated for the grid window or the initial payload dwarfs the rest of the tab; the full
 * values stay in SQLite for row detail, search and export.
 */
const COMPUTER_HISTORY_IPC_QUERY_OPTS = {
  truncateColumns: {
    ScreenText: 2048,
    Content: 2048,
    Description: 480,
    WindowTitle: 300,
    TargetLabel: 300,
  },
};

const COMPUTER_HISTORY_EMPTY_COL_OMIT = ["ScreenText", "Content", "Description"];

function finishAiHistoryWorkerImport(ctx, tabId, result, {
  fileName, sourceFormat, importNotice, sendProgress, queryOpts, emptyColOmit,
}) {
  const { db, _tabMeta, scheduleIndexBuild, safeSend } = ctx;
  const isAiHistory = typeof sourceFormat === "string" && sourceFormat.startsWith("ai-history");
  // Explicit per-family overrides let a non-ai-history schema (Computer History) reuse this
  // finisher without inheriting AI-history column assumptions such as omitting FullText.
  const effectiveQueryOpts = queryOpts || (isAiHistory ? AI_HISTORY_IPC_QUERY_OPTS : null);
  const effectiveEmptyColOmit = emptyColOmit || (isAiHistory ? AI_HISTORY_EMPTY_COL_OMIT : null);
  if (typeof sendProgress === "function") {
    sendProgress({
      phase: "loading",
      percent: 99,
      statusDetail: "Opening timeline database…",
      rowsSoFar: result.rowCount || 0,
    });
  }
  db.adoptTabFromFile(tabId, {
    dbPath: result.dbPath,
    headers: result.headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns || [],
    isLargeFile: result.isLargeFile || false,
  });
  if (_tabMeta) _tabMeta.set(tabId, { filePath: "", sourceFormat });

  const rowCount = result.rowCount || 0;
  if (typeof sendProgress === "function") {
    sendProgress({
      phase: "loading",
      percent: 99,
      statusDetail: "Preparing grid…",
      rowsSoFar: rowCount,
    });
  }
  const aiHistoryLarge = isAiHistory && rowCount >= 50_000;
  const initialLimit = isAiHistory
    ? (rowCount >= 20_000 ? 0 : rowCount >= 10_000 ? 100 : rowCount >= 5_000 ? 200 : 400)
    : (result.isLargeFile ? 2500 : 5000);
  const initialData = initialLimit > 0
    ? db.queryRows(tabId, {
      offset: 0,
      limit: initialLimit,
      sortCol: null,
      sortDir: "asc",
      ...(effectiveQueryOpts || {}),
    })
    : { rows: [], totalFiltered: rowCount };
  const emptyColumns = effectiveEmptyColOmit
    ? db.getEmptyColumns(tabId, { omitHeaders: effectiveEmptyColOmit, forceSample: true })
    : db.getEmptyColumns(tabId);

  safeSend("import-progress", {
    tabId,
    fileName,
    rowsImported: rowCount,
    percent: 100,
    phase: "finalizing",
    statusDetail: "Timeline ready",
  });

  safeSend("import-complete", {
    tabId,
    fileName,
    headers: result.headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns || [],
    initialRows: initialData.rows,
    totalFiltered: initialData.totalFiltered,
    emptyColumns,
    sourceFormat,
    importNotice: importNotice || null,
    isLargeFile: result.isLargeFile || aiHistoryLarge,
    initialRowsDeferred: isAiHistory && initialLimit === 0,
  });
  if (scheduleIndexBuild) scheduleIndexBuild(tabId);

  return {
    tabId,
    openedTab: true,
    name: fileName,
    count: result.rowCount,
    sourceFormat,
    importNotice: importNotice || null,
  };
}


async function runAiHistoryProfileExtractWorker(ctx, roots, opts = {}) {
  const {
    db,
    jobManager,
    nextTabId,
    _newTempDbPath,
    scheduleIndexBuild,
    _tabMeta,
  } = ctx;
  const {
    sendProgress,
    useSubagents,
    user,
    host,
    resolvedScanRoot,
    resolvedScanMode,
  } = opts;
  const safeSend = opts.safeSend || ctx.safeSend;
  if (typeof safeSend !== "function") {
    throw new Error("AI history worker requires safeSend");
  }

  const tabId = nextTabId();
  const dbPath = _newTempDbPath(tabId);
  const collSuffix = resolvedScanRoot ? ` — ${path.basename(resolvedScanRoot)}` : "";
  const baseName = opts.baseName || `AI Query History${collSuffix}`;
  const sourceFormat = opts.sourceFormat || "ai-history-merged";
  const deferImportStart = !!opts.deferImportStart;

  if (!deferImportStart) {
    safeSend("import-start", { tabId, fileName: baseName, filePath: "", fileSize: 0 });
  }
  const { promise } = jobManager.startWorkerJob({
    type: "ai-history-profile",
    worker: "ai-history-profile-worker.js",
    workerData: {
      roots,
      includeSubagents: useSubagents,
      user,
      host,
      dbPath,
      tabId,
    },
    channels: { progress: "ai-history-profile-progress" },
    metadata: { tabId, sourceCount: roots.length },
    resourceClass: "heavy",
  });

  let result;
  try {
    result = await promise;
  } catch (e) {
    if (e?.cancelled || e?.canceled) return { canceled: true };
    safeSend("import-error", { tabId, fileName: baseName, error: e?.message || "AI history profile extract failed" });
    return { error: e?.message || "AI history profile extract failed" };
  }
  if (result?.error) {
    safeSend("import-error", { tabId, fileName: baseName, error: result.error });
    return { error: result.error, failures: result.failures || [] };
  }

  if (deferImportStart) {
    safeSend("import-start", { tabId, fileName: baseName, filePath: "", fileSize: 0 });
  }

  // Tab bar already appends (totalRows); keep the tab title as the tool prefix only.
  const fileName = baseName;
  sendProgress({
    phase: "loading",
    percent: 99,
    statusDetail: "Opening timeline tab…",
    rowsSoFar: result.rowCount,
  });
  finishAiHistoryWorkerImport(
    { db, _tabMeta, scheduleIndexBuild, safeSend },
    tabId,
    result,
    {
      fileName,
      sourceFormat,
      importNotice: result.importNotice || null,
      sendProgress,
    },
  );

  sendProgress({
    phase: "complete",
    percent: 100,
    statusDetail: `Extracted ${result.rowCount.toLocaleString()} messages`,
    logLine: (result.failures || []).length
      ? `Done with ${result.failures.length} source error(s) — timeline tab ready`
      : "Done — timeline tab ready",
    rowsSoFar: result.rowCount,
  });

  const sourcesLabel = roots.map((r) => r.label).join(", ");
  return {
    tabId,
    openedTab: true,
    name: fileName,
    count: result.rowCount,
    sourceFormat,
    importNotice: result.importNotice || null,
    sources: roots.map((r) => ({ tool: r.tool, path: r.path, label: r.label })),
    failures: result.failures || [],
    partial: (result.failures || []).length > 0,
    sourcesLabel,
    scanRoot: resolvedScanRoot || null,
    scanMode: resolvedScanMode || "local",
  };
}


module.exports = function registerAiHistoryHandlers(safeHandle, safeSend, ctx) {
  const {
    _tabMeta,
    _activeWindow,
    db,
    jobManager,
    nextTabId,
    _newTempDbPath,
    scheduleIndexBuild,
  } = ctx;
  safeHandle("decode-ai-history", async (event, { path: inputPath, tool, includeSubagents, ...options } = {}) => {
    const selectedTool = tool || "claude-code";
    const meta = AI_HISTORY_TOOLS[selectedTool];
    if (!meta) {
      return { error: `Unsupported AI tool: ${selectedTool}. Supported: ${Object.keys(AI_HISTORY_TOOLS).join(", ")}.` };
    }

    let target = inputPath;
    if (!target) {
      const win = typeof _activeWindow === "function" ? _activeWindow() : null;
      const dialogByTool = {
        chatgpt: {
          title: "Select ChatGPT Desktop data",
          message: "Choose the ChatGPT app data folder (com.openai.chat, Atlas, or Roaming\\ChatGPT)",
          filters: [{ name: "ChatGPT bundle / SQLite / LevelDB", extensions: ["data", "db", "sqlite", "sqlite3", "ldb"] }],
        },
        "gemini-cli": {
          title: "Select Gemini CLI artifacts",
          message: "Choose a .gemini folder, session JSON/JSONL, or project shell_history",
          filters: [{ name: "Gemini CLI history", extensions: ["json", "jsonl", "*"] }],
        },
        codex: {
          title: "Select OpenAI Codex artifacts",
          message: "Choose a .codex folder (CLI/Desktop sessions, history.jsonl, rollout-*.jsonl)",
          filters: [{ name: "Codex JSONL", extensions: ["jsonl"] }],
        },
        "grok-build": {
          title: "Select Grok Build artifacts",
          message: "Choose a .grok folder or a session summary/updates/chat_history/prompt_history JSONL file",
          filters: [{ name: "Grok Build JSON / JSONL", extensions: ["json", "jsonl"] }],
        },
        "claude-code": {
          title: "Select Claude Code artifacts",
          message: "Choose a .claude folder, history.jsonl, or a session .jsonl file",
          filters: [{ name: "Claude Code JSONL", extensions: ["jsonl"] }],
        },
        cursor: {
          title: "Select Cursor artifacts",
          message: "Choose a .cursor folder, Cursor User folder, agent transcript, or conversation-search.db",
          filters: [{ name: "Cursor artifacts", extensions: ["jsonl", "txt", "db", "vscdb"] }],
        },
        copilot: {
          title: "Select GitHub Copilot artifacts",
          message: "Choose .copilot, workspaceStorage, chatSessions, events.jsonl, or session-store.db",
          filters: [{ name: "Copilot VS Code / CLI artifacts", extensions: ["json", "jsonl", "yaml", "yml", "md", "db", "log"] }],
        },
        windsurf: {
          title: "Select Windsurf chat data",
          message: "Choose Windsurf User folder (workspaceStorage / globalStorage state.vscdb)",
          filters: [{ name: "SQLite", extensions: ["vscdb", "db"] }],
        },
        continue: {
          title: "Select Continue sessions",
          message: "Choose a .continue folder or sessions/*.json",
          filters: [{ name: "Continue session", extensions: ["json"] }],
        },
      };
      const dlg = dialogByTool[selectedTool] || dialogByTool["claude-code"];
      const homedir = os.homedir();
      const hinted = defaultDecodeAiHistoryDialogPath(selectedTool);
      const defaultPath = hinted && fs.existsSync(hinted) ? hinted : hinted;
      const res = await dialog.showOpenDialog(win, openDialogOptions({
        title: dlg.title,
        message: dlg.message,
        properties: ["openFile", "openDirectory"],
        filters: dlg.filters,
        buttonLabel: "Extract",
        defaultPath: defaultPath && fs.existsSync(defaultPath) ? defaultPath : homedir,
      }));
      if (res.canceled || !res.filePaths || !res.filePaths[0]) return { canceled: true };
      target = res.filePaths[0];
      authorizeAiArtifactPick(target, { label: meta.label });
    }

    try {
      assertAiReadablePath(target);
    } catch (e) {
      return { error: e.message || "Path is not authorized for AI extraction." };
    }

    const root = selectedTool === "chatgpt"
      ? (resolveChatgptDir(target) || target)
      : selectedTool === "gemini-cli"
        ? (resolveGeminiCliRoot(target) || target)
        : selectedTool === "codex"
          ? (resolveCodexHome(target) || target)
          : selectedTool === "grok-build"
            ? (resolveGrokHome(target) || target)
            : selectedTool === "cursor"
              ? (resolveCursorRoot(target) || target)
              : selectedTool === "copilot"
                ? (resolveCopilotRoot(target) || target)
                : selectedTool === "windsurf"
                  ? (resolveWindsurfUserDir(target) || target)
                  : selectedTool === "continue"
                    ? (continueHome(target) || target)
                    : (resolveClaudeDir(target) || target);
    const extractTarget = root || target;
    const user = deriveUser(extractTarget);
    const host = "";

    const scopeTools = new Set(["claude-code", "codex", "grok-build", "cursor"]);
    if (options?.promptScope && scopeTools.has(selectedTool) && options?.includeSubagents == null) {
      try {
        const st = fs.statSync(target);
        if (st.isDirectory()) {
          authorizeAiArtifactPick(target, { label: meta.label });
          return {
            needsScopeChoice: true,
            tool: selectedTool,
            target,
            extractTarget,
            label: meta.label,
          };
        }
      } catch { /* ignore */ }
    }

    const useSubagents = options?.includeSubagents != null ? !!options.includeSubagents : false;
    const roots = [{
      tool: selectedTool,
      path: extractTarget,
      label: meta.label,
      endpointUser: user,
      endpointHost: host,
    }];

    if (options?.prepareOnly) {
      return {
        prepared: true,
        tool: selectedTool,
        target,
        extractTarget,
        label: meta.label,
      };
    }

    const workerCtx = jobManager && db && nextTabId && _newTempDbPath
      ? { db, jobManager, nextTabId, _newTempDbPath, scheduleIndexBuild, _tabMeta, safeSend }
      : null;
    const sendProgress = (patch) => safeSend("ai-history-profile-progress", patch);

    try {
      if (workerCtx) {
        const workerResult = await runAiHistoryProfileExtractWorker(
          workerCtx,
          roots,
          {
            safeSend,
            sendProgress,
            useSubagents,
            user,
            host,
            baseName: meta.tabPrefix,
            sourceFormat: `ai-history-${selectedTool}`,
            deferImportStart: true,
          },
        );
        if (workerResult?.canceled) return { canceled: true };
        if (workerResult?.error) {
          const msg = workerResult.error;
          if (/no message|no rows|contained no/i.test(msg)) {
            return { error: `No ${meta.label} messages found at this path.` };
          }
          return { error: msg };
        }
        dbg("EXEC", "decode-ai-history", {
          tool: selectedTool,
          target: extractTarget,
          count: workerResult.count,
          tabId: workerResult.tabId,
        });
        return { ...workerResult, tool: selectedTool };
      }

      const rows = await extractAiHistory(selectedTool, extractTarget, { user, host }, {
        includeSubagents: useSubagents,
      });
      if (!rows.length) {
        return { error: `No ${meta.label} messages found at this path.` };
      }
      const labelUser = user ? ` — ${user}` : "";
      dbg("EXEC", "decode-ai-history (inline)", { tool: selectedTool, target, count: rows.length });
      return {
        rows,
        name: `${meta.tabPrefix} (${rows.length.toLocaleString()})${labelUser}`,
        count: rows.length,
        tool: selectedTool,
        sourceFormat: `ai-history-${selectedTool}`,
        importNotice: buildAiHistoryImportNotice({
          copilot: buildCopilotExtractionStats(rows, getCopilotExtractionStats(rows)),
          claudeDesktop: rows._claudeDesktopStats,
          chatgpt: rows._chatgptStats,
          cursor: { syntheticTimestamps: !!rows._cursorSyntheticTimestamps, composer: rows._cursorComposerStats },
          windsurf: rows._windsurfStats,
          codexStateSqlite: rows._codexStateSqliteStats,
          windsurfCascade: rows._windsurfCascadeStats,
          parseErrors: rows._parseErrors,
        }) || null,
      };
    } catch (e) {
      return { error: `AI history extraction failed: ${e.message}` };
    }
  });

  /**
   * ChatGPT Computer History (Skysight) — OS activity telemetry, not conversation history.
   * Kept off the shared ai-history extract path: it emits COMPUTER_HISTORY_COLUMNS and must not go
   * through the ai-history dedupe/sink, which keys on fields this schema does not have.
   */
  safeHandle("decode-computer-history", async (event, { path: inputPath, ...options } = {}) => {
    const label = TOOL_COMPUTER_HISTORY;

    let target = inputPath;
    if (!target) {
      const win = typeof _activeWindow === "function" ? _activeWindow() : null;
      const { segmentsDir } = defaultComputerHistoryRoots();
      const hinted = fs.existsSync(segmentsDir) ? segmentsDir : os.homedir();
      const res = await dialog.showOpenDialog(win, openDialogOptions({
        title: "Select ChatGPT Computer History artifacts",
        message: "Choose the Skysight segments folder, a segment bucket, an events.jsonl, a .codex "
          + "folder (derived summaries), or a triage folder containing them",
        properties: ["openFile", "openDirectory"],
        filters: [{ name: "Skysight events / summaries", extensions: ["jsonl", "json", "md"] }],
        buttonLabel: "Extract",
        defaultPath: hinted,
      }));
      if (res.canceled || !res.filePaths || !res.filePaths[0]) return { canceled: true };
      target = res.filePaths[0];
      authorizeAiArtifactPick(target, { label });
    }

    try {
      assertAiReadablePath(target);
    } catch (e) {
      return { error: e.message || "Path is not authorized for AI extraction." };
    }

    if (!isComputerHistoryDir(target) && !isSkysightEventsFile(target) && !isSkysightSummaryFile(target)) {
      return {
        error: "No ChatGPT Computer History (Skysight) artifacts found at this path. Expected a "
          + "segments folder, an events.jsonl, or a *-10min-*.md / *-6h-*.md summary.",
      };
    }

    if (options?.prepareOnly) {
      return { prepared: true, tool: COMPUTER_HISTORY_TOOL_ID, target, extractTarget: target, label };
    }

    const user = deriveUser(target);
    const sourceFormat = "computer-history";
    const baseName = "Codex Computer History";

    if (!(jobManager && db && nextTabId && _newTempDbPath)) {
      return { error: "Computer History extraction requires the worker runtime." };
    }

    const tabId = nextTabId();
    const dbPath = _newTempDbPath(tabId);
    const sendProgress = (patch) => safeSend("ai-history-profile-progress", patch);

    const { promise } = jobManager.startWorkerJob({
      type: "computer-history",
      worker: "computer-history-worker.js",
      workerData: {
        target,
        tabId,
        dbPath,
        user,
        host: "",
        includeScreenText: options?.includeScreenText !== false,
        screenTextMaxChars: options?.screenTextMaxChars || 0,
      },
      channels: { progress: "ai-history-profile-progress" },
      metadata: { tabId, target },
      resourceClass: "heavy",
    });

    let result;
    try {
      result = await promise;
    } catch (e) {
      if (e?.cancelled || e?.canceled) return { canceled: true };
      safeSend("import-error", { tabId, fileName: baseName, error: e?.message || "Computer History extract failed" });
      return { error: e?.message || "Computer History extract failed" };
    }
    if (result?.error) {
      safeSend("import-error", { tabId, fileName: baseName, error: result.error });
      return { error: result.error };
    }

    safeSend("import-start", { tabId, fileName: baseName, filePath: "", fileSize: 0 });
    sendProgress({
      phase: "loading", percent: 99, statusDetail: "Opening timeline tab…", rowsSoFar: result.rowCount,
    });

    finishAiHistoryWorkerImport(
      { db, _tabMeta, scheduleIndexBuild, safeSend },
      tabId,
      result,
      {
        fileName: baseName,
        sourceFormat,
        importNotice: result.importNotice || null,
        sendProgress,
        queryOpts: COMPUTER_HISTORY_IPC_QUERY_OPTS,
        emptyColOmit: COMPUTER_HISTORY_EMPTY_COL_OMIT,
      },
    );

    sendProgress({
      phase: "complete",
      percent: 100,
      statusDetail: `Extracted ${(result.rowCount || 0).toLocaleString()} activity events`,
      logLine: "Done — timeline tab ready",
      rowsSoFar: result.rowCount,
    });

    dbg("EXEC", "decode-computer-history", { target, count: result.rowCount, tabId });

    return {
      tabId,
      openedTab: true,
      name: baseName,
      count: result.rowCount,
      tool: COMPUTER_HISTORY_TOOL_ID,
      sourceFormat,
      importNotice: result.importNotice || null,
      computerHistoryStats: result.computerHistoryStats || null,
    };
  });

  async function runAiHistoryProfileDiscover(sendProgress, { scanRoot, scanMode } = {}) {
    const mode = scanMode === "folder" && scanRoot ? "folder" : "local";
    if (mode === "folder") {
      assertAiScanTarget(scanRoot);
    }
    const result = await discoverAiHistoryRoots({
      scanRoot: mode === "folder" ? scanRoot : undefined,
      scanMode: mode,
      quickValidate: mode === "local",
      onProgress: sendProgress,
    });
    const hasScopeChoice = result.roots.some((r) =>
      r.tool === "claude-code" || r.tool === "codex" || r.tool === "grok-build" || r.tool === "cursor",
    );
    authorizeDiscoveredRoots(result.roots, mode === "folder" ? result.scanRoot : null);
    return { ...result, hasScopeChoice, scanReport: result.scanReport || null };
  }

  safeHandle("pick-ai-history-scan-folder", async () => {
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const res = await dialog.showOpenDialog(win, openDialogOptions({
      title: "Select KAPE / triage / mounted disk folder",
      properties: ["openDirectory"],
      buttonLabel: "Select folder",
    }));
    if (res.canceled || !res.filePaths?.length) return { canceled: true };
    const picked = res.filePaths[0];
    authorizeAiScanTarget(picked, { label: "AI profile / triage collection" });
    return { path: picked };
  });

  safeHandle("discover-ai-history-profile", async (event, options = {}) => {
    const sendProgress = (patch) => safeSend("ai-history-profile-progress", patch);
    const { scanRoot, scanMode } = options;
    try {
      return await runAiHistoryProfileDiscover(sendProgress, { scanRoot, scanMode });
    } catch (e) {
      return { error: e.message || "AI artifact scan path is not authorized." };
    }
  });

  safeHandle("extract-ai-history-profile", async (event, options = {}) => {
    const {
      includeSubagents,
      roots: clientRoots,
      discoverOnly = false,
      scanRoot,
      scanMode,
    } = options;
    const sendProgress = (patch) => safeSend("ai-history-profile-progress", patch);

    if (discoverOnly) {
      try {
        return await runAiHistoryProfileDiscover(sendProgress, { scanRoot, scanMode });
      } catch (e) {
        return { error: e.message || "AI artifact scan path is not authorized." };
      }
    }

    let roots = Array.isArray(clientRoots) && clientRoots.length > 0 ? clientRoots : null;
    let resolvedScanRoot = scanRoot;
    let resolvedScanMode = scanMode;
    let lastDiscover = null;
    if (!roots?.length) {
      lastDiscover = await runAiHistoryProfileDiscover(sendProgress, { scanRoot, scanMode });
      roots = lastDiscover.roots;
      resolvedScanRoot = lastDiscover.scanRoot || scanRoot;
      resolvedScanMode = lastDiscover.scanMode || scanMode;
    }

    // G4: when a collection root is set (folder browse or triage handoff), confine
    // extraction to that scope — reject forged/replayed roots outside the tree.
    if (resolvedScanRoot && roots?.length) {
      try {
        assertAiScanTarget(resolvedScanRoot);
      } catch (e) {
        return { error: e.message || "Collection folder is not authorized." };
      }
      const { allowed, rejected } = confineRootsToScope(roots, resolvedScanRoot);
      if (rejected.length) {
        dbg("EXEC", "ai-history: dropped out-of-scope roots", {
          count: rejected.length,
          scanRoot: resolvedScanRoot,
        });
      }
      roots = allowed;
    }

    try {
      assertExtractRootsAuthorized(roots, resolvedScanRoot || null);
    } catch (e) {
      return { error: e.message || "AI artifact paths are not authorized." };
    }

    if (!roots.length) {
      const scanReport = lastDiscover?.scanReport || buildEmptyAiScanReport({
        scanRoot: resolvedScanRoot || scanRoot,
        scanMode: resolvedScanMode || scanMode,
        scanned: lastDiscover?.candidateCount || 0,
        hitsFound: 0,
      });
      return {
        error: scanReport.summary,
        scanReport,
      };
    }

    const hasScopeChoice = roots.some((r) =>
      r.tool === "claude-code" || r.tool === "codex" || r.tool === "grok-build" || r.tool === "cursor",
    );
    if (includeSubagents == null && hasScopeChoice) {
      return {
        needsScopeChoice: true,
        roots,
        scanRoot: resolvedScanRoot,
        scanMode: resolvedScanMode,
        hasScopeChoice: true,
      };
    }

    const useSubagents = !!includeSubagents;

    const user = os.userInfo().username || "";
    const host = os.hostname() || "";

    sendProgress({
      phase: "extracting",
      percent: 3,
      statusDetail: `Preparing ${roots.length} source(s)…`,
      logLine: roots.map((r) => `• ${r.label}: ${r.path}`).join("\n"),
      sourceCount: roots.length,
    });

    try {
      if (jobManager && db && nextTabId && _newTempDbPath) {
        const workerResult = await runAiHistoryProfileExtractWorker(ctx, roots, {
          safeSend,
          sendProgress,
          useSubagents,
          user,
          host,
          resolvedScanRoot,
          resolvedScanMode,
        });
        if (workerResult.error) return workerResult;
        dbg("EXEC", "extract-ai-history-profile (worker)", {
          roots: roots.length,
          rows: workerResult.count,
          failures: workerResult.failures?.length || 0,
        });
        return workerResult;
      }

      const abortToken = createAiHistoryExtractAbortToken();
      let rows;
      let importNotice;
      let failures;
      try {
        ({ rows, importNotice, failures } = await extractMergedAiHistoryRoots(
          roots,
          { user, host },
          {
            includeSubagents: useSubagents,
            skipFinalize: true,
            onProgress: (p) => sendProgress(p),
            checkAbort: () => abortToken.checkAbort(),
          },
        ));
      } finally {
        abortToken.dispose();
      }
      if (!rows.length) {
        const failDetail = failures.length
          ? failures.map((f) => `${f.label}: ${f.error}`).join("; ")
          : "Sources were found but contained no message rows.";
        return { error: failDetail };
      }

      sendProgress({
        phase: "complete",
        percent: 100,
        statusDetail: `Extracted ${rows.length.toLocaleString()} messages`,
        logLine: failures.length
          ? `Done with ${failures.length} source error(s) — opening timeline tab…`
          : "Done — opening merged AI Query History tab…",
        rowsSoFar: rows.length,
      });

      dbg("EXEC", "extract-ai-history-profile (main)", {
        roots: roots.length, rows: rows.length, failures: failures.length,
      });

      const sourcesLabel = roots.map((r) => r.label).join(", ");
      const collSuffix = resolvedScanRoot
        ? ` — ${path.basename(resolvedScanRoot)}`
        : "";
      return {
        rows,
        name: `AI Query History${collSuffix} (${rows.length.toLocaleString()})`,
        count: rows.length,
        sourceFormat: "ai-history-merged",
        importNotice,
        sources: roots.map((r) => ({ tool: r.tool, path: r.path, label: r.label })),
        failures,
        partial: failures.length > 0,
        sourcesLabel,
        scanRoot: resolvedScanRoot || null,
        scanMode: resolvedScanMode || "local",
      };
    } catch (e) {
      if (e instanceof AiHistoryExtractAbortedError || e?.canceled || e?.cancelled) {
        return { canceled: true };
      }
      return { error: `AI history profile scan failed: ${e.message}` };
    }
  });

  safeHandle("cancel-ai-history-extract", async () => {
    requestAiHistoryExtractAbort();
    if (jobManager) {
      // Computer History runs its own worker type but shares this modal's Cancel button.
      jobManager.cancelWhere((job) => job.type === "ai-history-profile" || job.type === "computer-history");
    }
    return { ok: true };
  });

};
