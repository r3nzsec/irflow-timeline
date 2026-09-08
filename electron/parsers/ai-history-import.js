/**
 * parsers/ai-history-import.js — import Claude / ChatGPT / Gemini artifacts as timeline tabs.
 *
 * Structured AI artifacts must not fall through to the CSV parser. Multiple files under the
 * same .claude, .codex, ChatGPT app data, or .gemini tree consolidate into one tab (one unified table).
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../logger");
const { AI_HISTORY_COLUMNS, AI_HISTORY_TOOLS } = require("./ai-history/schema");
const { extractAiHistory } = require("./ai-history");
const {
  MAX_AI_HISTORY_ROWS,
  prepareChunkRowsForDb,
  writeAiHistoryRowsToDb,
  makeSourceAccumulator,
} = require("./ai-history/db-sink");
const { buildChatgptExtractionStats } = require("./ai-history/chatgpt");
const {
  isClaudeDir,
  isClaudeCodeArtifactRoot,
  resolveClaudeDir,
  isClaudeJsonStateFile,
} = require("./ai-history/claude-code");
const {
  isChatgptAppDir,
  resolveChatgptDir,
  isInLeveldbDir,
  isSqliteFile,
  conversationBundleInfo,
  detectConversationBundles,
} = require("./ai-history/chatgpt");
const {
  GEMINI_DIR_NAME,
  isGeminiCliRoot,
  isGeminiSessionFile,
  isGeminiShellHistoryFile,
  resolveGeminiCliRoot,
} = require("./ai-history/gemini-cli");
const {
  CODEX_DIR_NAME,
  isCodexDir,
  isCodexRolloutFile,
  resolveCodexHome,
} = require("./ai-history/codex");
const {
  GROK_DIR_NAME,
  isGrokBuildRoot,
  isGrokBuildArtifactFile,
  resolveGrokHome,
  countGrokDataFiles,
} = require("./ai-history/grok-build");
const {
  isGrokBotRoot,
  isGrokBotArtifactFile,
  resolveGrokBotRoot,
  countGrokBotExtractFiles,
} = require("./ai-history/grok-bot");
const {
  isCursorDataRoot,
  isCursorTranscriptFile,
  resolveCursorRoot,
  countCursorExtractFiles,
} = require("./ai-history/cursor");
const {
  isChatSessionsDir,
  isCopilotWorkspaceStorageDir,
  resolveCopilotRoot,
  countCopilotExtractFiles,
  isCopilotCliArtifactPath,
} = require("./ai-history/copilot");
const { deriveUser } = require("./path-attribution");
const { countClaudeExtractFiles } = require("./ai-history/claude-code");
const { listRolloutFiles } = require("./ai-history/codex");
const { listChatgptDataFiles } = require("./ai-history/chatgpt");
const { listGeminiDataFiles } = require("./ai-history/gemini-cli");
const { getCopilotExtractionStats } = require("./ai-history/copilot");
const {
  buildAiHistoryImportNotice,
  buildAiHistoryImportWarning,
  buildCopilotExtractionStats,
} = require("./ai-history/import-meta");

const EXTRACT_PHASE_WEIGHT = 0.45;

const AI_SCOPE_TOOLS = new Set(["claude-code", "codex", "grok-build", "cursor"]);

function needsScopeForAiImport(tool, targetPath) {
  if (!AI_SCOPE_TOOLS.has(tool) || !targetPath) return false;
  try {
    return fs.statSync(targetPath).isDirectory();
  } catch {
    return false;
  }
}

function pushAiHistoryPlanned(planned, tool, rootPath) {
  const resolved = path.resolve(rootPath);
  const needsScopeChoice = needsScopeForAiImport(tool, resolved);
  planned.push({
    path: resolved,
    opts: { aiHistoryTool: tool },
    needsScopeChoice,
    scopeTool: tool,
    scopeTarget: resolved,
    scopeLabel: AI_HISTORY_TOOLS[tool]?.label || tool,
  });
}

function buildExtractOptions(detect, onProgress, fileCountHint = 0) {
  const includeSubagents = !!detect?.includeSubagents;
  const skipSubagents = !includeSubagents;
  let filesTotal = fileCountHint;

  return {
    includeSubagents,
    skipSubagents,
    onFileProgress: (fileIndex, fileCount, filePath) => {
      filesTotal = fileCount;
      if (!onProgress || !fileCount) return;
      const extractPct = Math.round((fileIndex / fileCount) * EXTRACT_PHASE_WEIGHT * 100);
      onProgress(0, fileIndex, fileCount, {
        phase: "extracting",
        statusDetail: `Reading ${path.basename(filePath)} (${fileIndex}/${fileCount})`,
        percentHint: extractPct,
      });
    },
    getFilesTotal: () => filesTotal,
  };
}

function countAiHistorySourceFiles(tool, target, detect = {}) {
  const includeSubagents = !!detect.includeSubagents;
  const skipSubagents = !includeSubagents;
  const opts = { includeSubagents, skipSubagents };

  try {
    if (tool === "claude-code") {
      if (isClaudeJsonStateFile(target)) return countClaudeExtractFiles(target, opts);
      const root = resolveClaudeDir(target) || target;
      if (root && isClaudeCodeArtifactRoot(root)) return countClaudeExtractFiles(root, opts);
    }
    if (tool === "codex") {
      const root = resolveCodexHome(target) || target;
      if (root && isCodexDir(root)) {
        const history = fs.existsSync(path.join(root, "history.jsonl")) ? 1 : 0;
        return history + listRolloutFiles(root, opts).length;
      }
    }
    if (tool === "grok-build") {
      const root = resolveGrokHome(target) || target;
      if (root && isGrokBuildRoot(root)) return countGrokDataFiles(root, opts);
    }
    if (tool === "grok-bot") {
      const root = resolveGrokBotRoot(target) || target;
      if (root && isGrokBotRoot(root)) return countGrokBotExtractFiles(root);
    }
    if (tool === "chatgpt") {
      const root = resolveChatgptDir(target) || target;
      if (root && isChatgptAppDir(root)) {
        return listChatgptDataFiles(root).length + detectConversationBundles(root).length;
      }
    }
    if (tool === "gemini-cli") {
      const root = resolveGeminiCliRoot(target) || target;
      if (root && isGeminiCliRoot(root)) return listGeminiDataFiles(root).length;
    }
    if (tool === "cursor") {
      const root = resolveCursorRoot(target) || target;
      if (root && isCursorDataRoot(root)) return countCursorExtractFiles(root, opts);
    }
    if (tool === "copilot") {
      const root = resolveCopilotRoot(target) || target;
      if (root) return countCopilotExtractFiles(root, opts);
    }
    if (tool === "continue") {
      const { continueHome, isContinueRoot, listContinueSessionFiles } = require("./ai-history/continue");
      const root = continueHome(target) || target;
      if (root && isContinueRoot(root)) return listContinueSessionFiles(root).length;
    }
    if (tool === "windsurf") {
      const { resolveWindsurfUserDir } = require("./ai-history/windsurf");
      const userDir = resolveWindsurfUserDir(target);
      if (userDir) {
        const { findVscdbFilesUnder } = require("./ai-history/vscdb-kv");
        return Math.max(1, findVscdbFilesUnder(userDir).length);
      }
    }
  } catch { /* ignore */ }
  return 1;
}

function reportAiHistoryProgress(onProgress, rowsImported, workDone, workTotal, statusDetail, phase) {
  if (!onProgress) return;
  const total = Math.max(1, workTotal);
  const done = Math.min(workDone, total);
  const percentHint = Math.round((done / total) * 100);
  onProgress(rowsImported, done, total, {
    phase: phase || "parsing",
    statusDetail: statusDetail || "",
    percentHint,
  });
}

function findClaudeRootForPath(filePath) {
  let p = filePath;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  for (let i = 0; i < 16; i++) {
    if (path.basename(p) === ".claude") return p;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return null;
}

function findChatgptRootForPath(filePath) {
  let p = filePath;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  for (let i = 0; i < 20; i++) {
    const lower = p.replace(/\\/g, "/").toLowerCase();
    const base = path.basename(p).toLowerCase();
    const hasProductHint = lower.includes("chatgpt")
      || lower.includes("com.openai.chat")
      || lower.includes("openai.chatgpt")
      || base === "atlas"
      || base === "codex";
    if (hasProductHint) {
      const resolved = resolveChatgptDir(p);
      if (resolved) return resolved;
    }
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return null;
}

function findCodexRootForPath(filePath) {
  const resolved = resolveCodexHome(filePath);
  if (resolved) return resolved;
  let p = filePath;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  for (let i = 0; i < 16; i++) {
    if (path.basename(p) === CODEX_DIR_NAME && isCodexDir(p)) return p;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return null;
}

function findGrokRootForPath(filePath) {
  const resolved = resolveGrokHome(filePath);
  if (resolved) return resolved;
  let p = filePath;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  for (let i = 0; i < 24; i++) {
    if (path.basename(p) === GROK_DIR_NAME && isGrokBuildRoot(p)) return p;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return null;
}

function findGeminiRootForPath(filePath) {
  const resolved = resolveGeminiCliRoot(filePath);
  if (resolved) return resolved;
  let p = filePath;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  for (let i = 0; i < 16; i++) {
    if (path.basename(p) === GEMINI_DIR_NAME && isGeminiCliRoot(p)) return p;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return null;
}

function findCursorRootForPath(filePath) {
  return resolveCursorRoot(filePath);
}

function findCopilotRootForPath(filePath) {
  return resolveCopilotRoot(filePath);
}

function findWindsurfRootForPath(filePath) {
  const { resolveWindsurfUserDir } = require("./ai-history/windsurf");
  return resolveWindsurfUserDir(filePath);
}

function findContinueRootForPath(filePath) {
  const { continueHome } = require("./ai-history/continue");
  return continueHome(filePath);
}

function isClaudeJsonlPath(filePath) {
  if (path.extname(filePath).toLowerCase() !== ".jsonl") return false;
  if (isCodexArtifactPath(filePath)) return false;
  if (path.basename(filePath) === "history.jsonl") return !!findClaudeRootForPath(filePath);
  if (filePath.includes(`${path.sep}.claude${path.sep}`)) return true;
  return !!findClaudeRootForPath(filePath);
}

function isChatgptArtifactPath(filePath) {
  let st;
  try { st = fs.statSync(filePath); } catch { return false; }
  if (st.isDirectory()) {
    const root = findChatgptRootForPath(filePath);
    return !!root && (isChatgptAppDir(filePath) || filePath === root);
  }

  const ext = path.extname(filePath).toLowerCase();
  if (conversationBundleInfo(filePath)) return true;
  if ((ext === ".ldb" || ext === ".log") && isInLeveldbDir(filePath)) return true;
  const sqliteCandidate = ext === ".db"
    || ext === ".sqlite"
    || ext === ".sqlite3"
    || (!ext && isSqliteFile(filePath));
  if (!sqliteCandidate) return false;

  // Resolve an app root only after the cheap file-type gates. Running the recursive
  // ChatGPT detector for every unrelated JSONL/JSON artifact can walk broad ancestors
  // (for example a shared temporary directory) and stall mixed-source import planning.
  return !!findChatgptRootForPath(filePath);
}

function isCodexArtifactPath(filePath) {
  if (isCodexRolloutFile(filePath)) return true;
  if (filePath.includes(`${path.sep}${CODEX_DIR_NAME}${path.sep}`)) {
    const base = path.basename(filePath);
    if (base === "history.jsonl" || base === "session_index.jsonl") return true;
  }
  let st;
  try { st = fs.statSync(filePath); } catch { return false; }
  if (st.isDirectory()) return isCodexDir(filePath);
  return false;
}

function isGrokArtifactPath(filePath) {
  if (isGrokBuildArtifactFile(filePath)) return true;
  let st;
  try { st = fs.statSync(filePath); } catch { return false; }
  return st.isDirectory() && !!resolveGrokHome(filePath);
}

function isGrokBotArtifactPath(filePath) {
  if (isGrokBotArtifactFile(filePath)) return true;
  let st;
  try { st = fs.statSync(filePath); } catch { return false; }
  return st.isDirectory() && isGrokBotRoot(filePath);
}

function isGeminiArtifactPath(filePath) {
  if (isGeminiSessionFile(filePath) || isGeminiShellHistoryFile(filePath)) return true;
  if (filePath.includes(`${path.sep}${GEMINI_DIR_NAME}${path.sep}`)) {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === ".json" && /^session-.+\.json$/i.test(path.basename(filePath))) return true;
  }
  let st;
  try { st = fs.statSync(filePath); } catch { return false; }
  if (st.isDirectory()) return isGeminiCliRoot(filePath);
  return false;
}

function isCursorArtifactPath(filePath) {
  if (isCursorTranscriptFile(filePath)) return true;
  let st;
  try { st = fs.statSync(filePath); } catch { return false; }
  if (st.isDirectory()) {
    if (isCursorDataRoot(filePath)) return true;
    const norm = filePath.replace(/\\/g, "/");
    if (norm.includes("/agent-transcripts")) return true;
  }
  if (path.basename(filePath) === "conversation-search.db") {
    return !!resolveCursorRoot(filePath);
  }
  return false;
}

function isCopilotArtifactPath(filePath) {
  if (isCopilotCliArtifactPath(filePath)) return true;
  let st;
  try { st = fs.statSync(filePath); } catch { return false; }
  if (st.isDirectory()) {
    return isChatSessionsDir(filePath)
      || isCopilotWorkspaceStorageDir(filePath)
      || path.basename(filePath) === "workspaceStorage";
  }
  const ext = path.extname(filePath).toLowerCase();
  if ((ext === ".json" || ext === ".jsonl") && filePath.includes(`${path.sep}chatSessions${path.sep}`)) {
    return true;
  }
  return false;
}

function isWindsurfArtifactPath(filePath) {
  const { isWindsurfUserDir } = require("./ai-history/windsurf");
  let st;
  try { st = fs.statSync(filePath); } catch { return false; }
  if (st.isDirectory()) return isWindsurfUserDir(filePath);
  return path.basename(filePath) === "state.vscdb"
    && filePath.includes(`${path.sep}Windsurf${path.sep}`);
}

function isContinueArtifactPath(filePath) {
  const { isContinueRoot, continueHome } = require("./ai-history/continue");
  let st;
  try { st = fs.statSync(filePath); } catch { return false; }
  if (st.isDirectory()) return isContinueRoot(filePath);
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".json" && filePath.includes(`${path.sep}.continue${path.sep}sessions${path.sep}`)) {
    return path.basename(filePath) !== "sessions.json";
  }
  const root = continueHome(filePath);
  return !!(root && isContinueRoot(root));
}

/**
 * Should this path be imported via the AI history extractor (not CSV)?
 * @returns {{ tool: string, target: string } | null}
 */
function detectAiHistoryImport(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return null;

  let st;
  try { st = fs.statSync(filePath); } catch { return null; }

  if (st.isDirectory()) {
    const grokRoot = resolveGrokHome(filePath);
    if (grokRoot) return { tool: "grok-build", target: grokRoot };
    if (isGrokBuildRoot(filePath)) return { tool: "grok-build", target: path.resolve(filePath) };
    if (isGrokBotRoot(filePath)) return { tool: "grok-bot", target: path.resolve(filePath) };

    const codexRoot = resolveCodexHome(filePath);
    if (codexRoot) return { tool: "codex", target: codexRoot };
    if (isCodexDir(filePath)) return { tool: "codex", target: path.resolve(filePath) };

    const claude = resolveClaudeDir(filePath);
    if (claude) return { tool: "claude-code", target: claude };
    if (isClaudeCodeArtifactRoot(filePath) || isClaudeDir(filePath)) {
      return { tool: "claude-code", target: path.resolve(resolveClaudeDir(filePath) || filePath) };
    }

    const chatgpt = resolveChatgptDir(filePath);
    if (chatgpt) return { tool: "chatgpt", target: chatgpt };
    if (isChatgptAppDir(filePath)) return { tool: "chatgpt", target: path.resolve(filePath) };

    const gemini = resolveGeminiCliRoot(filePath);
    if (gemini) return { tool: "gemini-cli", target: gemini };
    if (isGeminiCliRoot(filePath)) return { tool: "gemini-cli", target: path.resolve(filePath) };

    const cursorRoot = resolveCursorRoot(filePath);
    if (cursorRoot) return { tool: "cursor", target: cursorRoot };
    if (isCursorDataRoot(filePath)) return { tool: "cursor", target: path.resolve(filePath) };

    const copilotRoot = resolveCopilotRoot(filePath);
    if (copilotRoot) return { tool: "copilot", target: copilotRoot };
    if (isCopilotWorkspaceStorageDir(filePath) || path.basename(filePath) === "workspaceStorage") {
      return { tool: "copilot", target: path.resolve(filePath) };
    }

    const { isWindsurfUserDir, resolveWindsurfUserDir } = require("./ai-history/windsurf");
    const wsDir = resolveWindsurfUserDir(filePath);
    if (wsDir) return { tool: "windsurf", target: wsDir };
    if (isWindsurfUserDir(filePath)) return { tool: "windsurf", target: path.resolve(filePath) };

    const { isContinueRoot, continueHome } = require("./ai-history/continue");
    const contRoot = continueHome(filePath);
    if (contRoot && isContinueRoot(contRoot)) return { tool: "continue", target: contRoot };

    return null;
  }

  if (isCodexArtifactPath(filePath)) {
    const root = findCodexRootForPath(filePath);
    return { tool: "codex", target: root || filePath };
  }
  if (isGrokArtifactPath(filePath)) {
    const root = findGrokRootForPath(filePath);
    return { tool: "grok-build", target: root || filePath };
  }
  if (isGrokBotArtifactFile(filePath)) {
    return { tool: "grok-bot", target: resolveGrokBotRoot(filePath) || filePath };
  }
  if (isClaudeJsonStateFile(filePath)) {
    return { tool: "claude-code", target: filePath };
  }
  if (isClaudeJsonlPath(filePath)) {
    return { tool: "claude-code", target: filePath };
  }
  if (isChatgptArtifactPath(filePath)) {
    const root = findChatgptRootForPath(filePath);
    return { tool: "chatgpt", target: root || filePath };
  }
  if (isGeminiArtifactPath(filePath)) {
    const root = findGeminiRootForPath(filePath);
    return { tool: "gemini-cli", target: root || filePath };
  }
  if (isCursorArtifactPath(filePath)) {
    const root = findCursorRootForPath(filePath);
    return { tool: "cursor", target: root || filePath };
  }
  if (isCopilotArtifactPath(filePath)) {
    const root = findCopilotRootForPath(filePath);
    return { tool: "copilot", target: root || filePath };
  }
  if (isWindsurfArtifactPath(filePath)) {
    const root = findWindsurfRootForPath(filePath);
    return { tool: "windsurf", target: root || filePath };
  }
  if (isContinueArtifactPath(filePath)) {
    const root = findContinueRootForPath(filePath);
    return { tool: "continue", target: root || filePath };
  }

  return null;
}

function mergeFileGroup(files, findRoot, rootsSet, normal, singleBucket) {
  if (files.length >= 2) {
    const root = findRoot(files[0]);
    if (root) rootsSet.add(path.resolve(root));
    else normal.push(...files);
  } else if (files.length === 1) {
    singleBucket.push(files[0]);
  }
}

/**
 * Plan import queue entries: merge AI artifact files / dirs into one import each.
 * @param {string[]} filePaths
 * @returns {Array<{ path: string, opts?: object }>}
 */
function planImportPaths(filePaths) {
  const claudeRoots = new Set();
  const claudeJsonlFiles = [];
  const chatgptRoots = new Set();
  const chatgptFiles = [];
  const codexRoots = new Set();
  const codexFiles = [];
  const grokRoots = new Set();
  const grokFiles = [];
  const grokBotRoots = new Set();
  const grokBotFiles = [];
  const geminiRoots = new Set();
  const geminiFiles = [];
  const cursorRoots = new Set();
  const cursorFiles = [];
  const copilotRoots = new Set();
  const copilotFiles = [];
  const windsurfRoots = new Set();
  const windsurfFiles = [];
  const continueRoots = new Set();
  const continueFiles = [];
  const normal = [];

  for (const fp of filePaths || []) {
    if (!fp || !fs.existsSync(fp)) continue;

    let st;
    try { st = fs.statSync(fp); } catch { normal.push(fp); continue; }

    if (st.isDirectory()) {
      const grokRoot = resolveGrokHome(fp);
      if (grokRoot || isGrokBuildRoot(fp)) {
        grokRoots.add(path.resolve(grokRoot || fp));
        continue;
      }
      if (isGrokBotRoot(fp)) {
        grokBotRoots.add(path.resolve(fp));
        continue;
      }
      const claude = resolveClaudeDir(fp);
      if (claude || isClaudeCodeArtifactRoot(fp) || isClaudeDir(fp)) {
        claudeRoots.add(path.resolve(claude || fp));
        continue;
      }
      const codexRoot = resolveCodexHome(fp);
      if (codexRoot || isCodexDir(fp)) {
        codexRoots.add(path.resolve(codexRoot || fp));
        continue;
      }
      const chatgpt = resolveChatgptDir(fp);
      if (chatgpt || isChatgptAppDir(fp)) {
        chatgptRoots.add(path.resolve(chatgpt || fp));
        continue;
      }
      const gemini = resolveGeminiCliRoot(fp);
      if (gemini || isGeminiCliRoot(fp)) {
        geminiRoots.add(path.resolve(gemini || fp));
        continue;
      }
      const cursorRoot = resolveCursorRoot(fp);
      if (cursorRoot || isCursorDataRoot(fp)) {
        cursorRoots.add(path.resolve(cursorRoot || fp));
        continue;
      }
      const copilotRoot = resolveCopilotRoot(fp);
      if (copilotRoot || isCopilotWorkspaceStorageDir(fp) || path.basename(fp) === "workspaceStorage") {
        copilotRoots.add(path.resolve(copilotRoot || fp));
        continue;
      }
      const { resolveWindsurfUserDir, isWindsurfUserDir } = require("./ai-history/windsurf");
      const wsDir = resolveWindsurfUserDir(fp);
      if (wsDir || isWindsurfUserDir(fp)) {
        windsurfRoots.add(path.resolve(wsDir || fp));
        continue;
      }
      const { continueHome, isContinueRoot } = require("./ai-history/continue");
      const contRoot = continueHome(fp);
      if (contRoot && isContinueRoot(contRoot)) {
        continueRoots.add(path.resolve(contRoot));
        continue;
      }
      normal.push(fp);
      continue;
    }

    if (isClaudeJsonStateFile(fp)) {
      claudeRoots.add(path.resolve(fp));
      continue;
    }
    if (isClaudeJsonlPath(fp)) {
      claudeJsonlFiles.push(path.resolve(fp));
      continue;
    }
    if (isCodexArtifactPath(fp)) {
      codexFiles.push(path.resolve(fp));
      continue;
    }
    if (isGrokArtifactPath(fp)) {
      grokFiles.push(path.resolve(fp));
      continue;
    }
    if (isGrokBotArtifactFile(fp)) {
      grokBotFiles.push(path.resolve(fp));
      continue;
    }
    if (isChatgptArtifactPath(fp)) {
      chatgptFiles.push(path.resolve(fp));
      continue;
    }
    if (isGeminiArtifactPath(fp)) {
      geminiFiles.push(path.resolve(fp));
      continue;
    }
    if (isCursorArtifactPath(fp)) {
      cursorFiles.push(path.resolve(fp));
      continue;
    }
    if (isCopilotArtifactPath(fp)) {
      copilotFiles.push(path.resolve(fp));
      continue;
    }
    if (isWindsurfArtifactPath(fp)) {
      windsurfFiles.push(path.resolve(fp));
      continue;
    }
    if (isContinueArtifactPath(fp)) {
      continueFiles.push(path.resolve(fp));
      continue;
    }

    normal.push(fp);
  }

  mergeFileGroup(claudeJsonlFiles, findClaudeRootForPath, claudeRoots, normal, normal);
  mergeFileGroup(codexFiles, findCodexRootForPath, codexRoots, normal, normal);
  mergeFileGroup(grokFiles, findGrokRootForPath, grokRoots, normal, normal);
  mergeFileGroup(grokBotFiles, resolveGrokBotRoot, grokBotRoots, normal, normal);
  mergeFileGroup(chatgptFiles, findChatgptRootForPath, chatgptRoots, normal, normal);
  mergeFileGroup(geminiFiles, findGeminiRootForPath, geminiRoots, normal, normal);
  mergeFileGroup(cursorFiles, findCursorRootForPath, cursorRoots, normal, normal);
  mergeFileGroup(copilotFiles, findCopilotRootForPath, copilotRoots, normal, normal);
  for (const fp of windsurfFiles) {
    const root = findWindsurfRootForPath(fp);
    if (root) windsurfRoots.add(path.resolve(root));
    else normal.push(fp);
  }
  for (const fp of continueFiles) {
    const root = findContinueRootForPath(fp);
    if (root) continueRoots.add(path.resolve(root));
    else normal.push(fp);
  }

  const planned = [];
  for (const root of claudeRoots) pushAiHistoryPlanned(planned, "claude-code", root);
  for (const root of codexRoots) pushAiHistoryPlanned(planned, "codex", root);
  for (const root of grokRoots) pushAiHistoryPlanned(planned, "grok-build", root);
  for (const root of grokBotRoots) pushAiHistoryPlanned(planned, "grok-bot", root);
  for (const root of chatgptRoots) pushAiHistoryPlanned(planned, "chatgpt", root);
  for (const root of geminiRoots) pushAiHistoryPlanned(planned, "gemini-cli", root);
  for (const root of cursorRoots) pushAiHistoryPlanned(planned, "cursor", root);
  for (const root of copilotRoots) pushAiHistoryPlanned(planned, "copilot", root);
  for (const root of windsurfRoots) pushAiHistoryPlanned(planned, "windsurf", root);
  for (const root of continueRoots) pushAiHistoryPlanned(planned, "continue", root);
  for (const fp of normal) planned.push({ path: fp });
  return planned;
}

/**
 * Import AI history into a tab (same contract as the other parseFile delegates).
 */
async function parseAiHistoryImport(filePath, tabId, db, onProgress, detect) {
  const target = detect?.target || filePath;
  const tool = detect?.tool || "claude-code";
  const user = deriveUser(target);
  const fileCountHint = countAiHistorySourceFiles(tool, target, detect);
  const extractOpts = buildExtractOptions(detect, onProgress, fileCountHint);

  // Stream the extractor's output into a bounded per-source accumulator rather than returning the
  // whole corpus: this caps the single-import path at MAX_AI_HISTORY_ROWS (it was the only ingest
  // path with no row ceiling) and routes rows through the same dedupe/slim/RecordId sink the merged
  // scan uses. keepFullText: true preserves the full message body for single-tool imports.
  const acc = makeSourceAccumulator(MAX_AI_HISTORY_ROWS);
  extractOpts.skipFinalize = true;
  extractOpts.onExtractedRows = (batch) => acc.add(batch, 0);

  const returned = await extractAiHistory(tool, target, { user, host: "" }, extractOpts);
  // Streaming-aware extractors emit via onExtractedRows and return an empty array carrying only
  // sidecar stats; the others ignore the callback and return the full row array — fold it in.
  if (returned && returned.length) acc.add(returned, 0);
  const capped = acc.truncated;

  const prepared = prepareChunkRowsForDb(acc.rows, 1, MAX_AI_HISTORY_ROWS, 0, { keepFullText: true });
  acc.reset();
  if (!prepared.length) throw new Error("No AI history messages found in this path.");

  const filesProcessed = extractOpts.getFilesTotal() || fileCountHint || 1;
  const sidecar = returned || {};
  const meta = {
    tool,
    target,
    filesProcessed,
    subagentsSkipped: !extractOpts.includeSubagents,
  };
  if (tool === "chatgpt") {
    meta.chatgpt = sidecar._chatgptStats || buildChatgptExtractionStats(prepared, target);
  }
  if (sidecar._claudeDesktopStats) meta.claudeDesktop = sidecar._claudeDesktopStats;
  if (sidecar._claudeContextStats) meta.claudeContext = sidecar._claudeContextStats;
  if (sidecar._cursorComposerStats) {
    meta.cursor = { ...(meta.cursor || {}), composer: sidecar._cursorComposerStats, syntheticTimestamps: true };
  }
  if (tool === "copilot") {
    // _copilotStats (session-level diagnostics, leveldbMetadataOnly, etc.) is attached to the
    // extractor's RETURN value, not the re-prepared rows — read it from `sidecar`. `prepared` is
    // the first arg only so the row count reflects what was actually stored.
    meta.copilot = buildCopilotExtractionStats(prepared, getCopilotExtractionStats(sidecar));
  }
  if (tool === "cursor") {
    meta.cursor = {
      ...(meta.cursor || {}),
      syntheticTimestamps: !!(sidecar._cursorSyntheticTimestamps || sidecar._cursorPartialSyntheticTimestamps),
      context: sidecar._cursorContextStats,
    };
  }
  if (sidecar._codexContextStats) meta.codexContext = sidecar._codexContextStats;
  if (sidecar._grokContextStats) meta.grokContext = sidecar._grokContextStats;
  if (sidecar._geminiHistoryStats) meta.geminiHistory = sidecar._geminiHistoryStats;
  if (sidecar._parseErrors) meta.parseErrors = sidecar._parseErrors;
  if (sidecar._sourceCoverage) meta.sourceCoverage = sidecar._sourceCoverage;
  if (sidecar._performance) meta.performance = sidecar._performance;
  if (sidecar._grokBotStats) meta.grokBot = sidecar._grokBotStats;
  if (capped) meta.capped = { maxRows: MAX_AI_HISTORY_ROWS, rowCount: prepared.length };

  const headers = [...AI_HISTORY_COLUMNS];
  db.createTab(tabId, headers);

  const workTotal = filesProcessed + prepared.length;
  reportAiHistoryProgress(onProgress, 0, filesProcessed, workTotal, "Writing rows…", "loading");
  writeAiHistoryRowsToDb(db, tabId, headers, prepared);
  reportAiHistoryProgress(onProgress, prepared.length, workTotal, workTotal, "Finalizing…", "finalizing");

  const result = db.finalizeImport(tabId);
  dbg("AIHIST", "parseAiHistoryImport done", { tool, target, rowCount: result.rowCount });

  const importNotice = buildAiHistoryImportNotice(meta) || null;
  const importWarning = buildAiHistoryImportWarning(meta) || null;

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
    sourceFormat: `ai-history-${tool}`,
    meta,
    importNotice,
    importWarning,
  };
}

module.exports = {
  detectAiHistoryImport,
  needsScopeForAiImport,
  planImportPaths,
  parseAiHistoryImport,
  isClaudeJsonlPath,
  isChatgptArtifactPath,
  isCodexArtifactPath,
  isGrokArtifactPath,
  isGrokBotArtifactPath,
  isGeminiArtifactPath,
  isCursorArtifactPath,
  isCopilotArtifactPath,
  findClaudeRootForPath,
  findCodexRootForPath,
  findGrokRootForPath,
  findChatgptRootForPath,
  findGeminiRootForPath,
  findCursorRootForPath,
  findCopilotRootForPath,
};
