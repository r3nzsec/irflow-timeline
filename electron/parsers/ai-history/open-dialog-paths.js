/**
 * open-dialog-paths.js — File → Open filter groups and defaultPath hints for AI artifacts.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  listClaudeCodeCandidatePaths,
  listChatgptCandidatePaths,
  defaultCursorHome,
  defaultCopilotCliHome,
  defaultCopilotWorkspaceStorage,
  listWindsurfUserDataDirs,
  defaultContinueHome,
  defaultWindsurfUserDir,
  getLocalAiHistoryCandidates,
  expandChatgptMsStorePackages,
  localAppDataDir,
  isClaudeCodeArtifactRoot,
  isCopilotWorkspaceStorageRoot,
  isCursorHome,
  isCursorUserDataDir,
  isCopilotCliRoot,
} = require("./artifact-paths");
const { defaultCodexHome, isCodexDir } = require("./codex");
const { defaultGrokHome, isGrokBuildRoot } = require("./grok-build");
const { defaultGrokBotHome, defaultGrokBotAppDir, isGrokBotRoot } = require("./grok-bot");
const { isChatgptAppDirQuick } = require("./chatgpt");
const { hasGeminiSessionsQuick } = require("./gemini-cli");
const { isWindsurfUserDir } = require("./windsurf");
const { isContinueRoot } = require("./continue");

const GEMINI_DIR_NAME = ".gemini";

function firstExistingPath(candidates) {
  for (const p of candidates) {
    if (p && fs.existsSync(p)) return p;
  }
  return null;
}

/** Shallow probe — safe on the UI thread when opening the native file dialog. */
function hasDecodedAiHistoryAtPath(tool, dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  switch (tool) {
    case "claude-code": return isClaudeCodeArtifactRoot(dirPath);
    case "codex": return isCodexDir(dirPath);
    case "grok-build": return isGrokBuildRoot(dirPath, { quick: true });
    case "grok-bot": return isGrokBotRoot(dirPath);
    case "chatgpt": return isChatgptAppDirQuick(dirPath);
    case "gemini-cli": return hasGeminiSessionsQuick(dirPath);
    case "cursor": return isCursorHome(dirPath) || isCursorUserDataDir(dirPath);
    case "copilot": return isCopilotCliRoot(dirPath, { quick: true })
      || isCopilotWorkspaceStorageRoot(dirPath, { quick: true });
    case "windsurf": return isWindsurfUserDir(dirPath);
    case "continue": return isContinueRoot(dirPath);
    default: return false;
  }
}

/** First on-disk root for a tool (Tools → AI Artifacts menu dialog defaultPath). */
function defaultDecodeAiHistoryDialogPath(tool) {
  const home = os.homedir();

  if (tool === "chatgpt") {
    for (const p of listChatgptCandidatePaths()) {
      if (hasDecodedAiHistoryAtPath("chatgpt", p)) return p;
    }
    if (process.platform === "win32") {
      const packages = path.join(localAppDataDir(), "Packages");
      for (const p of expandChatgptMsStorePackages(packages)) {
        if (hasDecodedAiHistoryAtPath("chatgpt", p)) return p;
      }
    }
  } else {
    for (const { tool: t, path: p } of getLocalAiHistoryCandidates()) {
      if (t !== tool) continue;
      if (hasDecodedAiHistoryAtPath(tool, p)) return p;
    }
  }

  const fallbacks = {
    "claude-code": listClaudeCodeCandidatePaths().find((c) => c.kind === "cli")?.path
      || path.join(home, ".claude"),
    codex: defaultCodexHome(),
    "grok-build": defaultGrokHome(),
    "grok-bot": [defaultGrokBotHome(), defaultGrokBotAppDir()].find((p) => p && fs.existsSync(p))
      || defaultGrokBotHome(),
    "gemini-cli": path.join(home, GEMINI_DIR_NAME),
    cursor: defaultCursorHome(),
    copilot: fs.existsSync(defaultCopilotCliHome())
      ? defaultCopilotCliHome()
      : defaultCopilotWorkspaceStorage(),
    windsurf: listWindsurfUserDataDirs()[0] || defaultWindsurfUserDir(),
    continue: defaultContinueHome(),
  };
  const hint = fallbacks[tool];
  return hint && fs.existsSync(hint) ? hint : hint || home;
}

/** Best defaultPath for the system open dialog (first known AI store, else home). */
function defaultAiHistoryOpenPath() {
  const home = os.homedir();
  const candidates = [
    ...listClaudeCodeCandidatePaths().map((c) => c.path),
    defaultCodexHome(),
    defaultGrokHome(),
    defaultGrokBotHome(),
    defaultGrokBotAppDir(),
    defaultCursorHome(),
    ...listChatgptCandidatePaths(),
    path.join(home, GEMINI_DIR_NAME),
    defaultCopilotCliHome(),
    defaultCopilotWorkspaceStorage(),
    listWindsurfUserDataDirs()[0],
    defaultContinueHome(),
    home,
  ];
  return firstExistingPath(candidates) || home;
}

/** macOS open dialog filter groups (files + folders via openDirectory). */
function aiHistoryOpenDialogFilters() {
  return [
    { name: "All Supported Files", extensions: ["*"] },
    { name: "CSV / TSV / Logs", extensions: ["csv", "tsv", "txt", "log"] },
    { name: "Excel", extensions: ["xlsx", "xls", "xlsm"] },
    { name: "EVTX", extensions: ["evtx"] },
    { name: "Plaso / Timeline", extensions: ["plaso", "timeline"] },
    { name: "NTFS ($MFT, $J)", extensions: ["mft", "bin"] },
    { name: "Claude Code (.claude / JSONL)", extensions: ["jsonl"] },
    { name: "OpenAI Codex (.codex / JSONL)", extensions: ["jsonl"] },
    { name: "Grok Build (.grok / JSONL)", extensions: ["json", "jsonl", "log"] },
    { name: "Grok Bot (.grokbot / Grok Bot app / blob)", extensions: ["json", "blob", "log"] },
    { name: "ChatGPT Desktop (bundles / LevelDB / SQLite)", extensions: ["data", "ldb", "log", "db", "sqlite", "sqlite3"] },
    { name: "Gemini CLI (.gemini / session JSONL)", extensions: ["json", "jsonl", "*"] },
    { name: "Cursor (transcripts / local databases)", extensions: ["jsonl", "txt", "db", "vscdb"] },
    { name: "GitHub Copilot (VS Code / CLI artifacts)", extensions: ["json", "jsonl", "yaml", "yml", "md", "db", "log"] },
    { name: "VS Code / Windsurf (state.vscdb)", extensions: ["vscdb", "db"] },
    { name: "Continue (.continue sessions)", extensions: ["json"] },
  ];
}

module.exports = {
  defaultDecodeAiHistoryDialogPath,
  defaultAiHistoryOpenPath,
  aiHistoryOpenDialogFilters,
  hasDecodedAiHistoryAtPath,
};
