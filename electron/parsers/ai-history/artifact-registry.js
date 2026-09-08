/** Versioned scope and evidence contract for the AI Apps Forensics feature. */

const AI_ARTIFACT_CONTRACT_VERSION = 2;

const source = (id, status, patterns, timestamp, locator, recordFamilies, companionFiles = []) => ({
  id,
  status,
  patterns,
  signatures: patterns,
  schemaVersions: ["fixture-qualified shapes captured 2026-09-08; unknown variants remain partial"],
  timestamp,
  locator,
  recordFamilies,
  companionFiles,
});

const qualification = (applicationVersions, platforms, scope) => ({
  asOf: "2026-09-08",
  applicationVersions,
  platforms,
  scope,
});

const AI_ARTIFACT_REGISTRY = Object.freeze({
  "claude-code": {
    surface: "Claude Code CLI",
    status: "partial",
    platforms: ["macOS", "Linux", "Windows"],
    qualification: qualification(["unversioned CLI fixture schemas"], ["portable synthetic corpus"], "transcript and prompt-history schemas"),
    rootRules: ["~/.claude", "relocated evidence tree selected by examiner"],
    privacy: "message bodies and tool evidence are retained with bounded fields; credentials are inventory only",
    sources: [
      source("prompt-history", "supported", ["history.jsonl"], "record ts", "physical line and byte offset", ["user history"]),
      source("sessions", "supported", ["projects/**/*.jsonl"], "record timestamp", "physical line and byte offset", ["messages", "tool calls", "tool results", "attachments"]),
      source("cli-policy-context", "supported", ["settings.json", ".mcp.json", ".credentials.json", "CLAUDE.md", "MEMORY.md", "skills", "plugins", "plans", "tasks", "todos", "file-history", "backups"], "configuration or source-file mtime", "typed key or inventoried path/hash", ["settings", "permission posture", "hooks", "MCP server definitions", "credential exclusion", "instruction/memory/skill/plugin inventory", "tasks/plans", "physical file history", "state backups"]),
    ],
  },
  "claude-desktop": {
    surface: "Claude Desktop Code and Cowork",
    status: "partial",
    platforms: ["macOS"],
    qualification: qualification(["1.46388.4 observed"], ["macOS"], "Code/Cowork metadata, transcript, audit, and selected state stores"),
    rootRules: ["Claude Application Support sessions root", "paired ~/.claude when present in evidence"],
    privacy: "browser/cache stores remain opaque unless a qualified decoder exists",
    sources: [source("desktop-code-state", "supported", ["sessions", "audit JSONL", "scheduled tasks", "worktrees"], "record or source metadata", "row-specific locator", ["Code/Cowork sessions", "audit", "grants", "uploads"])],
  },
  "claude-consumer-chat": {
    surface: "Claude consumer chat",
    status: "unsupported",
    platforms: ["web", "desktop", "mobile"],
    rootRules: [],
    privacy: "requires a separately qualified native store or vendor export",
    sources: [],
  },
  codex: {
    surface: "OpenAI Codex CLI and desktop thread data",
    status: "partial",
    platforms: ["macOS", "Linux", "Windows"],
    qualification: qualification(["unversioned rollout and SQLite fixture schemas"], ["macOS fixture/runtime"], "CLI rollouts, history, projections, config/instruction/plugin context, media references, and selected local state"),
    rootRules: ["~/.codex", "CODEX_HOME when no forensic target is supplied"],
    privacy: "opaque encrypted reasoning is not decrypted; SQLite is snapshotted with WAL/SHM",
    sources: [
      source("rollouts", "supported", ["sessions/**/rollout-*.jsonl", "archived_sessions/**/rollout-*.jsonl"], "envelope timestamp", "physical line and byte offset", ["messages", "tools", "turn context", "compaction", "collaboration"]),
      source("rollout-media", "supported", ["response_item payload.content media items"], "envelope timestamp", "physical line, byte offset and JSON pointer", ["image", "audio", "video", "file and document references", "bounded embedded-content hashes"]),
      source("thread-history", "supported-fallback", ["thread_history*.sqlite"], "created_at_ms or turn time", "rollout ordinal", ["projected messages", "commands", "file changes", "turns"], ["-wal", "-shm"]),
      source("state-and-local", "partial", ["state*.sqlite", "sqlite/*.db", "logs*.sqlite", "memories", "hooks.json"], "record or source metadata", "table key, rowid, or path", ["thread catalog", "automation", "local evidence"]),
      source("core-context", "supported", ["config.toml", "AGENTS.md", "instructions.md", "skills", "plugins", "auth.json inventory"], "source-file mtime", "typed config section or path/hash", ["project trust", "MCP", "plugins", "instructions", "skill/plugin inventory", "credential exclusion"]),
    ],
  },
  "grok-build": {
    surface: "Grok Build",
    status: "partial",
    platforms: ["macOS", "Linux"],
    qualification: qualification(["1.0.13 distribution observed"], ["macOS fixture/runtime"], "Build prompt, session, and runtime stores"),
    rootRules: ["~/.grok", "selected relocated .grok tree"],
    privacy: "configuration and upload stores require schema qualification before body decoding",
    sources: [
      source("session-streams", "supported", ["summary.json", "updates.jsonl", "chat_history.jsonl", "events.jsonl", "hunk_records.jsonl", "signals.json"], "record timestamp or documented metadata fallback", "physical line and byte offset or JSON source", ["messages", "tools", "permissions", "lifecycle", "MCP", "file hunks", "session metrics"]),
      source("runtime", "partial", ["session search SQLite", "unified log", "active sessions"], "record timestamp", "row or physical line", ["runtime recovery"]),
      source("build-context", "supported", ["config.toml", "trusted_folders.toml", "version.json", "agent_id", "prompt_context.json", "terminal/*.log", "worktrees.db", "long-running-background-tasks", "upload_queue", "campaigns_state.json"], "native record timestamp or source-file mtime", "typed config key, database row, call UUID, or path/hash", ["configuration", "trust decisions", "version and identity", "hashed prompt context", "independent terminal output", "worktrees", "background task and upload/automation inventory"], ["worktrees.db-wal", "worktrees.db-shm"]),
    ],
  },
  "grok-consumer": {
    surface: "Consumer Grok AI on grok.com, X, and mobile",
    status: "unsupported",
    platforms: ["web", "mobile"],
    rootRules: [],
    privacy: "browser hints are leads and do not establish conversation recovery",
    sources: [],
  },
  "grok-bot": {
    surface: "Grok Bot desktop and local daemon",
    status: "partial",
    platforms: ["macOS"],
    qualification: qualification(["0.43.0 installed bundle observed"], ["macOS fixture/runtime"], "desktop persistence replicas and local daemon artifacts"),
    rootRules: ["~/.grokbot", "~/Library/Application Support/Grok Bot", "paired relocated roots"],
    privacy: "credential files are inventoried and never decoded; external attachment search is opt in",
    sources: [
      source("persistence-slices", "supported", ["sand-client-persistence/*.blob"], "entry timestamp, journal createdAtMs or persistence metadata", "slice, account, agent, JSON pointer and native ID", ["roster", "replica messages", "tool calls", "notices", "approval and permission states", "attachments", "automation", "drafts", "send journal v1/v2"]),
      source("daemon", "supported", ["local-exec-daemon.log", "local-exec-daemon.log.N", "daemon state", "supervisor state"], "state timestamp or file mtime; individual log lines are untimed", "physical line or JSON field", ["daemon lifecycle", "unlinked shell-exec lifecycle; command and result unknown"]),
      source("desktop-runtime", "partial", ["Sentry scope/session", "Local State", "link cache", "markers"], "record or file metadata", "path and native key", ["identity", "runtime", "link previews"]),
    ],
  },
  "gemini-cli": {
    surface: "Gemini CLI",
    status: "partial",
    platforms: ["macOS", "Linux", "Windows"],
    qualification: qualification(["0.58.0 package observed"], ["macOS fixture/runtime"], "CLI session current-state replay and selected local state"),
    rootRules: ["~/.gemini", "selected relocated .gemini tree"],
    privacy: "OAuth stores are inventory only; rewound, superseded, and replacement history is retained separately from current state",
    sources: [
      source("sessions", "supported", ["tmp/**/chats/*.jsonl", "tmp/**/chats/*.json", "logs.json", "checkpoints"], "message or operation timestamp", "physical line and byte offset or JSON index", ["current messages", "immutable message revisions", "rewind/replacement operations", "tools", "subagents", "checkpoints"]),
      source("state", "partial", ["settings.json", "settings.json.orig", "settings.json.bak", "projects.json", "policies", "skills", "GEMINI.md", "shell_history", "OAuth inventory"], "record or source metadata", "typed key, path/hash, or line", ["settings", "MCP/tool policy", "workspace", "hashed instructions/skills", "shell history", "backup/replacement state", "credential inventory"]),
    ],
  },
  "gemini-consumer": {
    surface: "Gemini desktop, web, and mobile consumer chat",
    status: "unsupported",
    platforms: ["web", "desktop", "mobile"],
    rootRules: [],
    privacy: "requires a separately qualified source corpus",
    sources: [],
  },
  cursor: {
    surface: "Cursor local agent and composer history",
    status: "partial",
    platforms: ["macOS", "Linux", "Windows"],
    qualification: qualification(["3.19.13 observed"], ["macOS fixture/runtime"], "local agent transcripts and qualified composer stores"),
    rootRules: ["~/.cursor", "Cursor User data directory", "selected relocated tree"],
    privacy: "cloud-only conversation content is outside local-parser scope",
    sources: [
      source("agent-transcripts", "supported", ["projects/**/agent-transcripts/**/*.jsonl", "projects/**/agent-transcripts/**/*.txt"], "event timestamp or labelled file-metadata synthesis", "physical line and byte offset", ["user", "assistant", "tool evidence", "legacy role-labelled text"]),
      source("composer", "supported", ["state.vscdb", "store.db", "conversation-search.db"], "bubble createdAt/timestamp or index updated_at", "database key or row identifier", ["composer text", "structured tool calls/results including tool-only bubbles", "conversation index"], ["-wal", "-shm"]),
      source("cursor-context", "supported", ["hooks.json", "mcp.json", ".mcp.json", "plans", "AGENTS.md", ".cursorrules", "rules", "skills", "plugins", "ai-tracking/*.db"], "source-file mtime", "typed config key or path/hash", ["hooks", "MCP", "plans", "agent instructions", "skills/plugins", "raw search index inventory"]),
    ],
  },
  "cursor-cloud": {
    surface: "Cursor cloud-only history",
    status: "unsupported",
    platforms: ["cloud"],
    rootRules: [],
    privacy: "local absence is not evidence of no conversation",
    sources: [],
  },
});

function getArtifactContract(surfaceId) {
  return AI_ARTIFACT_REGISTRY[surfaceId] || null;
}

module.exports = { AI_ARTIFACT_CONTRACT_VERSION, AI_ARTIFACT_REGISTRY, getArtifactContract };
