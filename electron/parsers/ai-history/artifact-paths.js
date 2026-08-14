/**
 * ai-history/artifact-paths.js — canonical on-disk locations for AI assistant artifacts.
 *
 * Sources (public docs / DFIR writeups, verified 2025–2026):
 * - Claude Code CLI: ~/.claude/ (history.jsonl, projects/.../*.jsonl) — claudecodehq.com, DFIR lab notes
 * - Claude Desktop "Code" tab: ~/Library/Application Support/Claude/claude-code-sessions/ (separate from CLI) — tielec.blog
 * - OpenAI Codex: ~/.codex/ (CODEX_HOME), sessions/YYYY/MM/DD/rollout-*.jsonl — openai/codex recorder.rs
 * - xAI Grok Build: ~/.grok/ (GROK_HOME), sessions/<encoded-cwd>/<session-id> — xai-org/grok-build
 * - ChatGPT Desktop: com.openai.chat, Atlas, MS Store Packages — as-aix, pvieito.com, garr3ttmjo writeup
 * - Gemini CLI: ~/.gemini/tmp/<hash>/chats/*.jsonl + shell_history — google-gemini/gemini-cli
 * - Cursor: ~/.cursor agent transcripts plus Cursor/User conversation-search.db and state.vscdb
 * - GitHub Copilot: VS Code chatSessions plus $COPILOT_HOME/~/.copilot CLI session-state — GitHub Docs
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const { defaultCodexHome, isCodexDir } = require("./codex");
const { defaultComputerHistoryRoots, isComputerHistoryDir } = require("./computer-history");
const { defaultGrokHome, isGrokBuildRoot } = require("./grok-build");
const { isChatgptAppDir } = require("./chatgpt");
const { isCursorUserDataDir } = require("./cursor-composer");
const {
  defaultCopilotCliHome,
  isCopilotCliRoot,
} = require("./copilot-cli");

function dirHasJsonlFiles(rootDir, maxDepth = 12) {
  if (!rootDir || !fs.existsSync(rootDir)) return false;
  const stack = [{ d: rootDir, depth: 0 }];
  while (stack.length) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isFile() && path.extname(e.name).toLowerCase() === ".jsonl") return true;
      if (e.isDirectory() && depth < maxDepth && !e.isSymbolicLink()) {
        stack.push({ d: path.join(d, e.name), depth: depth + 1 });
      }
    }
  }
  return false;
}

function dirHasGeminiSessions(rootDir) {
  try {
    const { listGeminiDataFiles } = require("./gemini-cli");
    return listGeminiDataFiles(rootDir).length > 0;
  } catch { return false; }
}

const CLAUDE_DIR_NAME = ".claude";
const GEMINI_DIR_NAME = ".gemini";
const CURSOR_DIR_NAME = ".cursor";

/** VS Code / forks that store Copilot chatSessions under User/workspaceStorage. */
const COPILOT_PRODUCT_NAMES = [
  "Code",
  "Code - Insiders",
  "VSCodium",
  "VSCodium - Insiders",
];

function appSupportDir() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support");
  }
  if (process.platform === "win32") {
    return process.env.APPDATA || path.join(home, "AppData", "Roaming");
  }
  return path.join(home, ".config");
}

function localAppDataDir() {
  const home = os.homedir();
  if (process.platform === "win32") {
    return process.env.LOCALAPPDATA || path.join(home, "AppData", "Local");
  }
  return path.join(home, ".local", "share");
}

/** Cursor data root (~/.cursor or CURSOR_AGENT_HOME). */
function defaultCursorHome() {
  const env = process.env.CURSOR_AGENT_HOME || process.env.CURSOR_HOME;
  if (env && fs.existsSync(env)) return env;
  return path.join(os.homedir(), CURSOR_DIR_NAME);
}

/** Default Windsurf User dir (may not exist on this machine). */
function defaultWindsurfUserDir() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", "Windsurf", "User");
  }
  if (process.platform === "win32") {
    const roaming = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return path.join(roaming, "Windsurf", "User");
  }
  return path.join(home, ".config", "Windsurf", "User");
}

/** Windsurf IDE User dirs that exist on this machine. */
function listWindsurfUserDataDirs() {
  const candidates = [defaultWindsurfUserDir()];
  return candidates.filter((p) => fs.existsSync(p));
}

/** Continue.dev global dir (~/.continue/sessions). */
function defaultContinueHome() {
  const env = process.env.CONTINUE_GLOBAL_DIR;
  if (env && fs.existsSync(env)) return env;
  return path.join(os.homedir(), ".continue");
}

/** Cursor IDE User dir (globalStorage / workspaceStorage), separate from ~/.cursor agent tree. */
function listCursorUserDataDirs() {
  const home = os.homedir();
  const out = [];
  if (process.platform === "darwin") {
    out.push(path.join(home, "Library", "Application Support", "Cursor", "User"));
  } else if (process.platform === "win32") {
    const roaming = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    out.push(path.join(roaming, "Cursor", "User"));
  } else {
    out.push(path.join(home, ".config", "Cursor", "User"));
  }
  return out.filter((p) => fs.existsSync(p));
}

/** Desktop session metadata dirs (2026+ and pre-migration legacy name). */
const CLAUDE_DESKTOP_SESSION_DIR_NAMES = [
  "claude-code-sessions",
  "local-agent-mode-sessions", // Cowork isolated sessions; older builds also used it as metadata-only
];

function listClaudeDesktopSessionRoots() {
  const support = appSupportDir();
  const claudeBase = path.join(support, "Claude");
  const roots = [];
  for (const name of CLAUDE_DESKTOP_SESSION_DIR_NAMES) {
    roots.push(path.join(claudeBase, name));
  }
  return roots.filter((p) => fs.existsSync(p));
}

/** Candidate paths to probe before validation (may not exist). */
function listClaudeCodeCandidatePaths() {
  const home = os.homedir();
  const out = [{ path: path.join(home, CLAUDE_DIR_NAME), kind: "cli" }];
  for (const p of listClaudeDesktopSessionRoots()) {
    out.push({ path: p, kind: "desktop" });
  }
  return out;
}

function listChatgptCandidatePaths() {
  const home = os.homedir();
  const out = [];

  if (process.platform === "darwin") {
    const support = path.join(home, "Library", "Application Support");
    out.push(
      { path: path.join(support, "com.openai.chat"), kind: "mac-native" },
      { path: path.join(support, "OpenAI", "Atlas"), kind: "mac-atlas" },
    );
  } else if (process.platform === "win32") {
    const roaming = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    const local = localAppDataDir();
    out.push(
      { path: path.join(roaming, "OpenAI", "ChatGPT"), kind: "win-standalone" },
      { path: path.join(local, "OpenAI", "ChatGPT"), kind: "win-local" },
      { path: path.join(local, "Packages"), kind: "win-msstore-scan" },
    );
  } else {
    const cfg = path.join(home, ".config");
    out.push(
      { path: path.join(cfg, "com.openai.chat"), kind: "linux-native" },
      { path: path.join(cfg, "ChatGPT"), kind: "linux-chatgpt" },
      { path: path.join(home, ".config", "OpenAI", "ChatGPT"), kind: "linux-openai" },
    );
  }

  return out.map((e) => e.path);
}

function listCopilotUserDirs() {
  const home = os.homedir();
  const out = [];
  if (process.platform === "darwin") {
    const base = path.join(home, "Library", "Application Support");
    for (const name of COPILOT_PRODUCT_NAMES) {
      out.push(path.join(base, name, "User"));
    }
  } else if (process.platform === "win32") {
    const roaming = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    for (const name of COPILOT_PRODUCT_NAMES) {
      out.push(path.join(roaming, name, "User"));
    }
  } else {
    for (const name of COPILOT_PRODUCT_NAMES) {
      out.push(path.join(home, ".config", name, "User"));
    }
  }
  return out;
}

function listCopilotWorkspaceStorageCandidates() {
  const out = new Set();
  for (const userDir of listCopilotUserDirs()) {
    out.add(path.join(userDir, "workspaceStorage"));
  }
  return [...out];
}

function defaultCopilotWorkspaceStorage() {
  for (const ws of listCopilotWorkspaceStorageCandidates()) {
    if (fs.existsSync(ws)) return ws;
  }
  const first = listCopilotUserDirs()[0];
  return first ? path.join(first, "workspaceStorage") : path.join(os.homedir(), "workspaceStorage");
}

function getLocalAiHistoryCandidates() {
  const home = os.homedir();
  const out = [];

  for (const { path: p } of listClaudeCodeCandidatePaths()) {
    out.push({ tool: "claude-code", path: p });
  }
  out.push({ tool: "codex", path: defaultCodexHome() });
  out.push({ tool: "grok-build", path: defaultGrokHome() });
  out.push({ tool: "gemini-cli", path: path.join(home, GEMINI_DIR_NAME) });
  out.push({ tool: "cursor", path: defaultCursorHome() });
  for (const p of listCursorUserDataDirs()) {
    out.push({ tool: "cursor", path: p });
  }
  out.push({ tool: "continue", path: defaultContinueHome() });
  out.push({ tool: "windsurf", path: defaultWindsurfUserDir() });

  for (const p of listChatgptCandidatePaths()) {
    out.push({ tool: "chatgpt", path: p });
  }

  // ChatGPT Computer History (Skysight) — raw event stream + derived activity summaries.
  {
    const { segmentsDir, resourcesDir } = defaultComputerHistoryRoots();
    out.push({ tool: "computer-history", path: segmentsDir });
    out.push({ tool: "computer-history", path: resourcesDir });
  }

  out.push({ tool: "copilot", path: defaultCopilotCliHome() });
  for (const p of listCopilotWorkspaceStorageCandidates()) {
    out.push({ tool: "copilot", path: p });
  }

  return out;
}

function dirHasClaudeDesktopMetadata(rootDir, maxDepth = 8) {
  if (!rootDir || !fs.existsSync(rootDir)) return false;
  const stack = [{ d: rootDir, depth: 0 }];
  while (stack.length) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isFile() && /^local_.*\.json$/i.test(e.name)) return true;
      if (e.isDirectory() && depth < maxDepth && !e.isSymbolicLink()) {
        stack.push({ d: path.join(d, e.name), depth: depth + 1 });
      }
    }
  }
  return false;
}

function isClaudeDesktopSessionsRoot(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  const base = path.basename(dirPath);
  if (!CLAUDE_DESKTOP_SESSION_DIR_NAMES.includes(base)
    && !CLAUDE_DESKTOP_SESSION_DIR_NAMES.some((n) => String(dirPath).includes(`${path.sep}${n}${path.sep}`))) {
    return false;
  }
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  // Desktop stores local_*.json metadata; full transcripts live under ~/.claude/projects/
  return dirHasClaudeDesktopMetadata(dirPath) || dirHasJsonlFiles(dirPath);
}

function isClaudeDir(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  if (path.basename(dirPath) !== CLAUDE_DIR_NAME) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  const history = path.join(dirPath, "history.jsonl");
  const projects = path.join(dirPath, "projects");
  return fs.existsSync(history) || fs.existsSync(projects);
}

/** CLI ~/.claude or Claude Desktop claude-code-sessions tree. */
function isClaudeCodeArtifactRoot(dirPath) {
  if (isClaudeDir(dirPath)) return true;
  return isClaudeDesktopSessionsRoot(dirPath);
}

function isCursorHome(dirPath) {
  if (!dirPath || path.basename(dirPath) !== CURSOR_DIR_NAME) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  return fs.existsSync(path.join(dirPath, "projects"));
}

function isGeminiCliRoot(dirPath, options = {}) {
  const { isGeminiCliRoot: geminiRootCheck } = require("./gemini-cli");
  return geminiRootCheck(dirPath, options);
}

function isCopilotWorkspaceStorageRoot(dirPath, { quick = false, maxWorkspaces = 80 } = {}) {
  const WORKSPACE_STORAGE = "workspaceStorage";
  const GLOBAL_EMPTY = path.join("globalStorage", "emptyWindowChatSessions");
  if (!dirPath || path.basename(dirPath) !== WORKSPACE_STORAGE) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  const globalDir = path.join(path.dirname(dirPath), GLOBAL_EMPTY);
  if (fs.existsSync(globalDir)) return true;
  let entries;
  try { entries = fs.readdirSync(dirPath, { withFileTypes: true }); } catch { return false; }
  let checked = 0;
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (fs.existsSync(path.join(dirPath, e.name, "chatSessions"))) return true;
    if (quick && ++checked >= maxWorkspaces) break;
  }
  return false;
}

function expandChatgptMsStorePackages(packagesDir) {
  const found = [];
  if (!packagesDir || !fs.existsSync(packagesDir)) return found;
  let entries;
  try { entries = fs.readdirSync(packagesDir, { withFileTypes: true }); } catch { return found; }
  for (const e of entries) {
    if (!e.isDirectory() || !/^openai\.chatgpt/i.test(e.name)) continue;
    found.push(path.join(packagesDir, e.name, "LocalCache", "Roaming", "ChatGPT"));
  }
  return found;
}

/** Relative paths under each OS user profile (for KAPE / triage / mounted disk scans). */
const FORENSIC_AI_PATH_HINTS = {
  windows: [
    "Users\\<user>\\.claude\\",
    "Users\\<user>\\.codex\\",
    "Users\\<user>\\.grok\\",
    "Users\\<user>\\.cursor\\",
    "Users\\<user>\\.copilot\\",
    "Users\\<user>\\.gemini\\",
    "Users\\<user>\\AppData\\Roaming\\Claude\\claude-code-sessions\\",
    "Users\\<user>\\AppData\\Roaming\\Claude\\local-agent-mode-sessions\\",
    "Users\\<user>\\AppData\\Roaming\\OpenAI\\ChatGPT\\",
    "Users\\<user>\\AppData\\Local\\Packages\\OpenAI.ChatGPT-*\\LocalCache\\Roaming\\ChatGPT\\",
    "Users\\<user>\\AppData\\Roaming\\Code\\User\\workspaceStorage\\",
    "Users\\<user>\\AppData\\Roaming\\Code - Insiders\\User\\workspaceStorage\\",
    "Users\\<user>\\AppData\\Roaming\\VSCodium\\User\\workspaceStorage\\",
    "Users\\<user>\\AppData\\Roaming\\Cursor\\User\\globalStorage\\conversation-search.db",
  ],
  linux: [
    "home/<user>/.claude/",
    "home/<user>/.codex/",
    "home/<user>/.grok/",
    "home/<user>/.cursor/",
    "home/<user>/.copilot/",
    "home/<user>/.gemini/",
    "home/<user>/.config/com.openai.chat/",
    "home/<user>/.config/Code/User/workspaceStorage/",
    "home/<user>/.config/VSCodium/User/workspaceStorage/",
    "home/<user>/.config/Cursor/User/globalStorage/conversation-search.db",
  ],
  macos: [
    "Users/<user>/.continue/sessions/",
    "Users/<user>/.claude/",
    "Users/<user>/.codex/",
    "Users/<user>/.grok/",
    "Users/<user>/.cursor/",
    "Users/<user>/.copilot/",
    "Users/<user>/.gemini/",
    "Users/<user>/Library/Application Support/Claude/claude-code-sessions/",
    "Users/<user>/Library/Application Support/Claude/local-agent-mode-sessions/",
    "Users/<user>/Library/Application Support/com.openai.chat/",
    "Users/<user>/Library/Group Containers/2DC432GLL2.com.openai.sky.CUAService/Library/Caches/ComputerUse/Skysight/segments/",
    "Users/<user>/.codex/memories/extensions/skysight/resources/",
    "Users/<user>/Library/Application Support/Code/User/workspaceStorage/",
    "Users/<user>/Library/Application Support/Cursor/User/globalStorage/conversation-search.db",
    "Users/<user>/Library/Application Support/Windsurf/User/workspaceStorage/",
  ],
};

/** Human-readable map for docs / import notices. */
const ARTIFACT_PATH_REFERENCES = {
  "claude-code": {
    label: "Claude Code",
    paths: [
      { platform: "macOS/Linux/WSL", path: "~/.claude/ (history.jsonl + projects/**/*.jsonl)" },
      { platform: "macOS", path: "~/Library/Application Support/Claude/claude-code-sessions/ (Desktop metadata local_*.json)" },
      { platform: "Windows", path: "%APPDATA%\\Claude\\claude-code-sessions\\" },
      { platform: "all", path: ".../Claude/local-agent-mode-sessions/ (Cowork metadata, isolated .claude/projects transcripts, audit*.jsonl)" },
    ],
  },
  codex: {
    label: "OpenAI Codex",
    paths: [
      { platform: "all", path: "$CODEX_HOME or ~/.codex/ (history.jsonl, sessions/**/rollout-*.jsonl, archived_sessions/, state*.sqlite + WAL/SHM)" },
    ],
  },
  "computer-history": {
    label: "ChatGPT Computer History",
    paths: [
      { platform: "macOS", path: "~/Library/Group Containers/2DC432GLL2.com.openai.sky.CUAService/Library/Caches/ComputerUse/Skysight/segments/<YYYY-MM-DDTHH-MM-SSZ>/{events.jsonl,metadata.json}" },
      { platform: "macOS", path: "~/.codex/memories/extensions/skysight/resources/*-(10min|6h)-*.md (derived activity summaries)" },
      { platform: "macOS", path: "~/.codex/config.toml → [plugins.\"computer-history@openai-bundled\"] enabled (feature on/off state)" },
      { platform: "macOS", path: "~/Library/Group Containers/2DC432GLL2.com.openai.sky.CUAService/Library/Application Support/Software/ComputerUseAppApprovals.json (app coverage gaps)" },
    ],
    notes: "Opt-in, off by default. Raw events are retained ~48h under Library/Caches (commonly excluded "
      + "from backup/EDR collection and purgeable under disk pressure); the derived summaries persist until "
      + "deleted and are often the only survivor on a stale image. Capture depth varies by app: browsers, "
      + "Electron apps and terminal emulators yield full text, while hardened native apps (Telegram, Slack) "
      + "yield window metadata only — in those, typed OUTBOUND text is captured but received content is not.",
  },
  "grok-build": {
    label: "Grok Build",
    paths: [
      { platform: "all", path: "$GROK_HOME or ~/.grok/ (sessions/**/prompt_history.jsonl + <session-id>/{summary,updates,chat_history,hunk_records}.json*)" },
    ],
    notes: "auth.json and mcp_credentials.json are sensitive configuration artifacts and are deliberately not parsed into timeline rows.",
  },
  chatgpt: {
    label: "ChatGPT Desktop",
    paths: [
      { platform: "macOS", path: "~/Library/Application Support/com.openai.chat/" },
      { platform: "macOS", path: "~/Library/Application Support/OpenAI/Atlas/" },
      { platform: "Windows", path: "%APPDATA%\\OpenAI\\ChatGPT\\ and MS Store LocalCache\\...\\ChatGPT" },
      { platform: "Linux", path: "~/.config/com.openai.chat/ (and variants)" },
    ],
    notes: "conversations-v2-* and opaque conversations-v3-*/*.data bundles are inventoried even when message bodies cannot be decoded; LevelDB/SQLite content is extracted when present.",
  },
  "gemini-cli": {
    label: "Gemini CLI",
    paths: [
      { platform: "all", path: "~/.gemini/tmp/<project_hash>/chats/session-*.jsonl (current append-only sessions)" },
      { platform: "all", path: "~/.gemini/tmp/<project_hash>/chats/<parent-session>/<subagent>.jsonl" },
      { platform: "all", path: "~/.gemini/tmp/<project_hash>/shell_history" },
      { platform: "all", path: "~/.gemini/tmp/<project_hash>/chats/session-*.json (legacy)" },
      { platform: "all", path: "~/.gemini/tmp/<project_hash>/logs.json (legacy CLI log)" },
      { platform: "all", path: "~/.gemini/tmp/<project_hash>/checkpoint-*.json (/chat save)" },
    ],
  },
  cursor: {
    label: "Cursor",
    paths: [
      { platform: "all", path: "$CURSOR_AGENT_HOME or ~/.cursor/projects/<slug>/agent-transcripts/**/*.jsonl" },
      { platform: "macOS", path: "~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db" },
      { platform: "Windows", path: "%APPDATA%\\Cursor\\User\\globalStorage\\conversation-search.db" },
      { platform: "Linux", path: "~/.config/Cursor/User/globalStorage/conversation-search.db" },
    ],
    notes: "Composer chat DBs under ~/.cursor/chats/ (store.db), global/workspace state.vscdb, and conversation-search.db FTS bodies are parsed when collected.",
  },
  copilot: {
    label: "GitHub Copilot",
    paths: [
      { platform: "all", path: "<VS Code User>/workspaceStorage/<hash>/chatSessions/*.json|.jsonl" },
      { platform: "all", path: "<VS Code User>/globalStorage/emptyWindowChatSessions/" },
      { platform: "all", path: "$COPILOT_HOME or ~/.copilot/session-state/<session-id>/events.jsonl" },
      { platform: "all", path: "~/.copilot/session-state/<session-id>/{workspace.yaml,plan.md,checkpoints/,files/}" },
      { platform: "all", path: "~/.copilot/{command-history-state/,session-store.db,logs/}" },
    ],
    notes: "VS Code products: Code, Code - Insiders, VSCodium (+ Insiders). Copilot CLI authentication/config.json and MCP OAuth/secret stores are deliberately excluded.",
  },
};

module.exports = {
  CLAUDE_DIR_NAME,
  GEMINI_DIR_NAME,
  CURSOR_DIR_NAME,
  COPILOT_PRODUCT_NAMES,
  FORENSIC_AI_PATH_HINTS,
  ARTIFACT_PATH_REFERENCES,
  appSupportDir,
  localAppDataDir,
  defaultCursorHome,
  defaultGrokHome,
  listCursorUserDataDirs,
  listWindsurfUserDataDirs,
  defaultWindsurfUserDir,
  defaultContinueHome,
  defaultCopilotWorkspaceStorage,
  defaultCopilotCliHome,
  listClaudeCodeCandidatePaths,
  listClaudeDesktopSessionRoots,
  listChatgptCandidatePaths,
  listCopilotUserDirs,
  listCopilotWorkspaceStorageCandidates,
  getLocalAiHistoryCandidates,
  expandChatgptMsStorePackages,
  isClaudeDir,
  isClaudeDesktopSessionsRoot,
  isClaudeCodeArtifactRoot,
  isGrokBuildRoot,
  isChatgptAppDir,
  isCursorHome,
  isCursorUserDataDir,
  isGeminiCliRoot,
  isCopilotWorkspaceStorageRoot,
  isCopilotCliRoot,
  defaultComputerHistoryRoots,
  isComputerHistoryDir,
};
