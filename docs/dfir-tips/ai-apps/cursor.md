---
description: Cursor forensic artifacts — agent transcripts, composer and workspace SQLite chats, and conversation-search.db.
---

# Cursor

Cursor stores agent transcripts as JSONL under `~/.cursor/projects`, plus VS Code-family SQLite chats and a local full-text search index. IRFlow merges those into one AI Query History tab.

Back to [AI Query History](/dfir-tips/ai-query-history).

## Canonical paths

| Platform | Path |
|----------|------|
| all | `$CURSOR_AGENT_HOME` or `~/.cursor/projects/<slug>/agent-transcripts/` |
| macOS | `~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db` |
| Windows | `%APPDATA%\Cursor\User\globalStorage\conversation-search.db` |
| Linux | `~/.config/Cursor/User/globalStorage/conversation-search.db` |
| all | `globalStorage/state.vscdb`, `workspaceStorage/*/state.vscdb`, `~/.cursor/chats/**/store.db` |

Typical transcript path:

```text
~/.cursor/projects/<project-slug>/agent-transcripts/<session-id>/<session-id>.jsonl
```

Windows: `%USERPROFILE%\.cursor\projects\...`

## What IRFlow extracts

| Artifact | Status | Why it matters |
|----------|--------|----------------|
| `~/.cursor/projects/<slug>/agent-transcripts/**/*.{jsonl,txt}` | Parsed | Instructions, responses, tool-use text, sidechain flags, workspace attribution. |
| `globalStorage/state.vscdb`, `workspaceStorage/*/state.vscdb`, `~/.cursor/chats/**/store.db` | Parsed when SQLite support is available | Composer/global/workspace chats that are not in the transcript files. |
| `Cursor/User/globalStorage/conversation-search.db` plus WAL/SHM | Parsed | Local FTS index: title, indexed body, conversation ID, source/scope, archive state, update time. |
| `hooks.json`, `mcp.json`, `.mcp.json` | Parsed | Hook commands and MCP definitions with secret environment/header/query values excluded. Configuration does not prove execution. |
| `plans/`, `AGENTS.md`, `.cursorrules`, `rules/`, `skills/`, `plugins/` | Hashed inventory | Local plan and agent context with path, size, mtime, and SHA-256. |
| `ai-tracking/*.db` | Hashed inventory | Raw index provenance retained without claiming an unqualified database schema. |

Each JSONL line is a `user` or `assistant` message with structured `message.content` blocks (text, tool calls). IRFlow uses embedded `timestamp` / `createdAt` values when present; file birth/mtime spreading is only a fallback for rows without per-message time. Project slugs under `projects/` decode to filesystem paths when possible.

`conversation-search.db` is also accepted as a standalone artifact or through its parent Cursor `User` folder. Each indexed conversation becomes a searchable row with title in **Summary**, indexed body in **FullText**, conversation ID in **SessionId**, and the recorded update time.

SQLite sources are snapshotted with available WAL/SHM companions so recent composer/search rows are not silently missed.

Composer bubbles with `toolFormerData`, tool results, or interpreter results are emitted even when they contain no user-visible text. The native `createdAt`, tool/call/model IDs, raw arguments, command, status, and result are retained. Discovery enumerates all eligible stores and processes up to an explicit 2,048-database safety limit; omitted stores are reported instead of silently stopping at the former 20/16 limits.

## How to import

1. **File → Open…** and select `~/.cursor`, the Cursor `User` folder, or `conversation-search.db`, or **Tools → Analysis → AI Artifacts → AI Apps → Cursor…**
2. Agent transcripts and available Cursor SQLite stores consolidate into **one** tab.
3. Subagent folders (`subagents/`) and `isSidechain` transcript lines are skipped unless you choose **Include subagents**.

**Collect AI Artifacts** also finds Cursor roots on This Mac or inside a KAPE/triage folder (Windows/macOS/Linux profile layouts).

## Investigation tips

- Prefer per-message `createdAt` / `timestamp` from JSONL and composer DB. File-mtime spread is a last resort.
- Sidechain / subagent lines are easy to over-collect on a large developer workstation — start with main sessions.
- `conversation-search.db` can still hold indexed body text after a transcript file is gone. Compare **SessionId** against recovered JSONL.

## Limitations

- Composer/workspace recovery requires SQLite support (`better-sqlite3` rebuilt for Electron).
- Proprietary or encrypted Cursor stores beyond the paths above are not claimed.

## See also

- [AI Query History overview](/dfir-tips/ai-query-history)
- [Gemini](/dfir-tips/ai-apps/gemini)
- [AI Artifacts](/features/ai-artifacts)
