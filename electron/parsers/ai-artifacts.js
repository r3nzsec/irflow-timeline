/**
 * parsers/ai-artifacts.js — detect AI assistant artifact roots in triage / live paths.
 *
 * Directory-based detection (Claude Code `.claude`, ChatGPT Desktop app data) for Scan AI Artifacts.
 */

const fs = require("fs");
const path = require("path");

const {
  isClaudeCodeArtifactRoot,
  COPILOT_PRODUCT_NAMES,
  isCopilotWorkspaceStorageRoot,
} = require("./ai-history/artifact-paths");
const { isChatgptAppDir, isCodexDesktopAppDir } = require("./ai-history/chatgpt");
const { isClaudeJsonStateFile, claudeJsonFileKind } = require("./ai-history/claude-code-state");
const { isGeminiCliRoot, GEMINI_DIR_NAME } = require("./ai-history/gemini-cli");
const { isCodexDir, countRolloutFiles, CODEX_DIR_NAME } = require("./ai-history/codex");
const {
  isGrokBuildRoot,
  countGrokDataFiles,
  GROK_DIR_NAME,
} = require("./ai-history/grok-build");
const {
  isGrokBotDaemonRoot,
  isGrokBotAppRoot,
  countGrokBotExtractFiles,
  GROKBOT_DIR_NAME,
  GROKBOT_APP_DIR_NAME,
} = require("./ai-history/grok-bot");
const {
  isCursorHome,
  isCursorUserDataDir,
  countCursorExtractFiles,
  CURSOR_DIR_NAME,
} = require("./ai-history/cursor");
const { isContinueRoot, listContinueSessionFiles, CONTINUE_DIR } = require("./ai-history/continue");
const { isWindsurfUserDir } = require("./ai-history/windsurf");
const {
  isChatSessionsDir,
  isCopilotWorkspaceStorageDir,
  countCopilotExtractFiles,
  CHAT_SESSIONS_DIR,
  WORKSPACE_STORAGE,
} = require("./ai-history/copilot");
const {
  COPILOT_CLI_DIR_NAME,
  isCopilotCliRoot,
  countCopilotCliExtractFiles,
} = require("./ai-history/copilot-cli");

const CLAUDE_DIR_NAME = ".claude";
const CLAUDE_DESKTOP_SESSION_DIRS = ["claude-code-sessions", "local-agent-mode-sessions"];
const KIND_LABELS = {
  aiClaude: "Claude Code (AI query history)",
  aiCodex: "OpenAI Codex (AI query history)",
  aiGrokBuild: "Grok Build (AI query history)",
  aiGrokBot: "Grok Bot (AI query history)",
  aiChatgpt: "ChatGPT Desktop (AI query history)",
  aiGemini: "Gemini CLI (AI query history)",
  aiCursor: "Cursor (AI query history)",
  aiCopilot: "GitHub Copilot (AI query history)",
  aiWindsurf: "Windsurf (AI query history)",
  aiContinue: "Continue (AI query history)",
};

function dirHasDataFiles(dirPath, maxDepth = 5) {
  const stack = [{ d: dirPath, depth: 0 }];
  while (stack.length) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!e.isSymbolicLink() && depth < maxDepth) stack.push({ d: full, depth: depth + 1 });
        continue;
      }
      if (!e.isFile()) continue;
      const ext = path.extname(e.name).toLowerCase();
      if (ext === ".db" || ext === ".sqlite" || ext === ".sqlite3" || ext === ".ldb" || ext === ".log" || ext === ".json") {
        return true;
      }
      if (!ext) {
        try {
          const fd = fs.openSync(full, "r");
          const buf = Buffer.alloc(6);
          fs.readSync(fd, buf, 0, 6, 0);
          fs.closeSync(fd);
          if (buf.toString("latin1") === "SQLite") return true;
        } catch { /* ignore */ }
      }
      const lowerName = e.name.toLowerCase();
      if (lowerName === "blob_storage" || lowerName === "indexeddb" || lowerName === "databases") {
        return true;
      }
    }
  }
  return false;
}

function classifyChatgptDir(full) {
  if (isCodexDesktopAppDir(full)) return true;
  const dirName = path.basename(full);
  const lower = full.toLowerCase();

  const isChatgptDir = dirName === "com.openai.chat"
    || dirName === "Atlas"
    || dirName === "ChatGPT"
    || dirName === "chat.openai.com"
    || (dirName === "ChatGPT" && (lower.includes("openai") || lower.includes("roaming")));

  const isChatgptPackage = dirName.startsWith("OpenAI.ChatGPT")
    || /^openai\.chatgpt/i.test(dirName);

  const pathLooksChatgpt = /packages[\\/]openai\.chatgpt/i.test(lower)
    || lower.includes("com.openai.chat")
    || (lower.includes("localcache") && lower.includes("openai"));

  if (!isChatgptDir && !isChatgptPackage && !pathLooksChatgpt) return false;
  if (!pathLooksChatgpt && !lower.includes("openai") && !lower.includes("chatgpt")
    && !lower.includes("roaming") && !lower.includes("packages")) return false;

  return dirHasDataFiles(full, 5) || isChatgptAppDir(full);
}

/**
 * Recursively find AI artifact roots under a triage root.
 * @returns {{ claudeCode, codex, chatgpt, geminiCli, cursor, copilot, scanned }}
 */
function resolveCopilotStorageRoot(chatSessionsPath) {
  let p = chatSessionsPath;
  for (let i = 0; i < 6; i++) {
    if (path.basename(p) === WORKSPACE_STORAGE && isCopilotWorkspaceStorageRoot(p, { quick: true })) {
      return p;
    }
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return null;
}

function scanAiArtifacts(dir, opts = {}) {
  const maxDepth = opts.maxDepth ?? 18;
  const maxPerKind = opts.maxPerKind ?? 48;
  const onProgress = typeof opts.onProgress === "function" ? opts.onProgress : null;
  const progressEvery = opts.progressEvery ?? 400;
  const collectBrowserHints = opts.collectBrowserHints !== false;
  const maxBrowserHits = opts.maxBrowserHits ?? 16;
  const browserAgentHints = [];
  const browserSeen = new Set();
  const scanRootResolved = path.resolve(dir);
  const claudeCode = [];
  const codex = [];
  const grokBuild = [];
  const grokBot = [];
  const chatgpt = [];
  const geminiCli = [];
  const cursor = [];
  const copilot = [];
  const windsurf = [];
  const continueCli = [];
  const seenClaude = new Set();
  const seenCodex = new Set();
  const seenGrokBuild = new Set();
  const seenGrokBot = new Set();
  const seenChatgpt = new Set();
  const seenGemini = new Set();
  const seenCursor = new Set();
  const seenCopilot = new Set();
  const seenWindsurf = new Set();
  const seenContinue = new Set();
  let scanned = 0;

  const { collectBrowserHintAtDir } = require("./ai-history/browser-agents");

  const stack = [{ d: scanRootResolved, depth: 0 }];
  while (stack.length) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }

    for (const e of entries) {
      if (e.isFile() && isClaudeJsonStateFile(path.join(d, e.name))) {
        const full = path.join(d, e.name);
        scanned++;
        // A `.claude.json.backup*` next to a live `.claude.json` is already covered by the
        // live file's sibling pass (project_removed / claude_json_backup rows); listing it as
        // its own root would extract every project twice and burn a maxPerKind slot.
        const shadowedBackup = claudeJsonFileKind(full) === "backup"
          && entries.some((sib) => sib.isFile() && sib.name === ".claude.json");
        if (!shadowedBackup && !seenClaude.has(full) && claudeCode.length < maxPerKind) {
          seenClaude.add(full);
          claudeCode.push({ path: full, username: extractUsername(full) });
        }
        continue;
      }
      if (!e.isDirectory()) continue;
      const full = path.join(d, e.name);
      scanned++;

      if (collectBrowserHints && browserAgentHints.length < maxBrowserHits) {
        const rel = full.slice(scanRootResolved.length).replace(/\\/g, "/");
        collectBrowserHintAtDir(full, rel, depth, browserAgentHints, browserSeen, maxBrowserHits);
      }

      if ((e.name === CLAUDE_DIR_NAME && isClaudeCodeArtifactRoot(full))
        || (CLAUDE_DESKTOP_SESSION_DIRS.includes(e.name) && isClaudeCodeArtifactRoot(full))) {
        if (!seenClaude.has(full) && claudeCode.length < maxPerKind) {
          seenClaude.add(full);
          claudeCode.push({ path: full, username: extractUsername(full) });
        }
      }

      if (e.name === CODEX_DIR_NAME && isCodexDir(full)) {
        if (!seenCodex.has(full) && codex.length < maxPerKind) {
          seenCodex.add(full);
          codex.push({
            path: full,
            username: extractUsername(full),
            sessionCount: countRolloutFiles(full),
          });
        }
      }

      if (e.name === GROK_DIR_NAME && isGrokBuildRoot(full, { quick: true })) {
        if (!seenGrokBuild.has(full) && grokBuild.length < maxPerKind) {
          seenGrokBuild.add(full);
          grokBuild.push({
            path: full,
            username: extractUsername(full),
            sessionCount: countGrokDataFiles(full),
          });
        }
      }

      if ((e.name === GROKBOT_DIR_NAME && isGrokBotDaemonRoot(full))
        || (e.name === GROKBOT_APP_DIR_NAME && isGrokBotAppRoot(full))) {
        if (!seenGrokBot.has(full) && grokBot.length < maxPerKind) {
          seenGrokBot.add(full);
          grokBot.push({
            path: full,
            username: extractUsername(full),
            sessionCount: countGrokBotExtractFiles(full),
          });
        }
      }

      if (classifyChatgptDir(full)) {
        if (!seenChatgpt.has(full) && chatgpt.length < maxPerKind) {
          seenChatgpt.add(full);
          chatgpt.push({ path: full, username: extractUsername(full) });
        }
      }

      if (e.name === GEMINI_DIR_NAME && isGeminiCliRoot(full, { quick: true })) {
        if (!seenGemini.has(full) && geminiCli.length < maxPerKind) {
          seenGemini.add(full);
          const { countGeminiSessions } = require("./ai-history/gemini-cli"); // lazy — avoids circular import at load
          geminiCli.push({
            path: full,
            username: extractUsername(full),
            sessionCount: countGeminiSessions(full),
          });
        }
      }

      if (e.name === CURSOR_DIR_NAME && isCursorHome(full)) {
        if (!seenCursor.has(full) && cursor.length < maxPerKind) {
          seenCursor.add(full);
          cursor.push({
            path: full,
            username: extractUsername(full),
            sessionCount: countCursorExtractFiles(full),
          });
        }
      }

      if (e.name === "User" && path.basename(d) === "Cursor" && isCursorUserDataDir(full)) {
        if (!seenCursor.has(full) && cursor.length < maxPerKind) {
          seenCursor.add(full);
          cursor.push({
            path: full,
            username: extractUsername(full),
            sessionCount: countCursorExtractFiles(full),
          });
        }
      }

      if (e.name === COPILOT_CLI_DIR_NAME && isCopilotCliRoot(full, { quick: true })) {
        if (!seenCopilot.has(full) && copilot.length < maxPerKind) {
          seenCopilot.add(full);
          copilot.push({
            path: full,
            username: extractUsername(full),
            sessionCount: countCopilotCliExtractFiles(full),
          });
        }
      }

      if (e.name === CHAT_SESSIONS_DIR && isChatSessionsDir(full)) {
        const storageRoot = resolveCopilotStorageRoot(full);
        if (storageRoot && !seenCopilot.has(storageRoot) && copilot.length < maxPerKind) {
          seenCopilot.add(storageRoot);
          copilot.push({
            path: storageRoot,
            username: extractUsername(full),
            sessionCount: countCopilotExtractFiles(storageRoot),
          });
        }
      }

      if (e.name === WORKSPACE_STORAGE && isCopilotWorkspaceStorageRoot(full, { quick: true })) {
        if (!seenCopilot.has(full) && copilot.length < maxPerKind) {
          seenCopilot.add(full);
          copilot.push({
            path: full,
            username: extractUsername(full),
            sessionCount: countCopilotExtractFiles(full),
          });
        }
      }

      if (e.name === "User" && COPILOT_PRODUCT_NAMES.includes(path.basename(d))) {
        const storageRoot = path.join(full, WORKSPACE_STORAGE);
        if (!seenCopilot.has(storageRoot) && copilot.length < maxPerKind
          && isCopilotWorkspaceStorageRoot(storageRoot, { quick: true })) {
          seenCopilot.add(storageRoot);
          copilot.push({
            path: storageRoot,
            username: extractUsername(full),
            sessionCount: countCopilotExtractFiles(storageRoot),
          });
        }
      }

      if (e.name === "User" && path.basename(d) === "Windsurf") {
        const storageRoot = path.join(full, WORKSPACE_STORAGE);
        if (!seenWindsurf.has(full) && windsurf.length < maxPerKind && isWindsurfUserDir(full)) {
          seenWindsurf.add(full);
          windsurf.push({
            path: full,
            username: extractUsername(full),
            sessionCount: 0,
          });
        }
      }

      if (e.name === CONTINUE_DIR && isContinueRoot(full)) {
        if (!seenContinue.has(full) && continueCli.length < maxPerKind) {
          seenContinue.add(full);
          continueCli.push({
            path: full,
            username: extractUsername(full),
            sessionCount: listContinueSessionFiles(full).length,
          });
        }
      }

      if (!e.isSymbolicLink() && depth < maxDepth) stack.push({ d: full, depth: depth + 1 });
    }

    if (onProgress && scanned > 0 && scanned % progressEvery === 0) {
      onProgress({
        phase: "discovering",
        statusDetail: `Indexed ${scanned.toLocaleString()} folders…`,
        logLine: `…${scanned.toLocaleString()} directories scanned under ${dir}`,
        dirsScanned: scanned,
      });
    }
  }

  return {
    claudeCode,
    codex,
    grokBuild,
    grokBot,
    chatgpt,
    geminiCli,
    cursor,
    copilot,
    windsurf,
    continue: continueCli,
    scanned,
    browserAgentHints,
  };
}

/** Username from `Users/<name>/` or `home/<name>/` in a path. */
function extractUsername(filePath) {
  const parts = String(filePath || "").replace(/\\/g, "/").split("/").filter(Boolean);
  for (let i = 0; i < parts.length - 1; i++) {
    const lower = parts[i].toLowerCase();
    if (lower === "users" || lower === "home") {
      const name = parts[i + 1];
      if (!name || name === "." || name === "..") continue;
      const nl = name.toLowerCase();
      if (nl === "default" || nl === "public") continue;
      return name;
    }
  }
  return "";
}

module.exports = {
  scanAiArtifacts,
  extractUsername,
  classifyChatgptDir,
  KIND_LABELS,
  CLAUDE_DIR_NAME,
};
