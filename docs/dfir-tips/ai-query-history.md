---
description: Forensic artifact paths and parsing coverage for ChatGPT Computer History, Grok Build, Claude, Codex, ChatGPT, Copilot, Gemini, Cursor, Windsurf, Continue, and other local AI applications.
---

# AI Query History and AI App Artifacts

IRFlow Timeline includes a native **AI Query History** extractor for investigating local AI assistant usage during incident response. It parses local desktop, CLI, and editor-assistant stores into one timeline so analysts can review prompts, responses, tool calls, workspaces, source files, and possible pasted secrets.

For the feature-level overview, see [AI Artifacts](/features/ai-artifacts). This guide is the deeper artifact inventory and investigation workflow.

::: tip v1.0.11 coverage
v1.0.11 adds the **Grok Build** and **Claude Desktop** stores that live outside the session trees and outlive the conversations in them: the [Grok session search index, app log and open-session record](#runtime-stores-outside-the-session-tree), and [Claude Desktop deletion tombstones, staged uploads and usage windows](#claude-desktop-state-artifacts). It also corrects four Computer History claims that did not survive testing against a live capture.
:::

::: tip v1.0.10 coverage
v1.0.10 adds **[ChatGPT Computer History (Skysight)](#chatgpt-computer-history-skysight)** — a separate artifact class covering OS-level interaction telemetry rather than conversation history, with deletion detection, recovery of cleared summaries, and host attribution.
:::

::: tip v1.0.8 coverage
The v1.0.8 parser expansion adds **Grok Build**, recursive **Claude Desktop/Cowork** transcripts and audit records, versioned **Codex** SQLite recovery with WAL/SHM companions, and exact `ToolCommand`/structured `ToolInput` preservation across modern JSONL formats.
:::

## AI History vs AI Prompts

IRFlow collects user prompts, but the evidence scope is broader than prompts alone. **AI Query History** includes prompts, assistant responses, tool calls or invoked actions, session metadata, timestamps, workspace paths, source files, model data, and endpoint user/host attribution when available.

This makes AI-assisted activity usable as timeline evidence. Analysts can answer questions such as whether a user pasted credentials into an AI tool, asked for help with suspicious commands, generated code for a sensitive workspace, or received output that exposed secrets.

Supported today:

| Tool | Status |
|------|--------|
| **Claude Code** | CLI `~/.claude/` + Claude Desktop/Cowork session stores, deletion tombstones, staged uploads, and usage windows |
| **OpenAI Codex** | `$CODEX_HOME` or `~/.codex/` — `history.jsonl`, `sessions/**/rollout-*.jsonl`, `archived_sessions/` |
| **Grok Build** | `$GROK_HOME` or `~/.grok/` — workspace prompt history, timestamped session updates, normalized chat fallback, file-hunk records, plus the session search index, app log, and open-session record |
| **ChatGPT Desktop** | LevelDB + SQLite under app data dirs (see paths below); `conversations-v2-*` and `conversations-v3-*` bundles are inventoried but not decoded |
| **Gemini CLI** | `~/.gemini/tmp/<hash>/chats/**/*.jsonl`, `~/.gemini/shell_history`, plus legacy `session-*.json`, `logs.json`, and checkpoints |
| **Cursor** | `$CURSOR_AGENT_HOME` or `~/.cursor/projects/.../agent-transcripts/*.jsonl`, composer databases, and Cursor `User/globalStorage/conversation-search.db` |
| **GitHub Copilot** | Copilot CLI `$COPILOT_HOME` or `~/.copilot/`, plus VS Code / VSCodium `workspaceStorage/*/chatSessions/` and `globalStorage/emptyWindowChatSessions/` |
| **Windsurf** | `Windsurf/User/workspaceStorage/*/state.vscdb` (VS Code–family chat keys) |
| **Continue** | `~/.continue/sessions/*.json` |
| **ChatGPT Computer History** | macOS only — Skysight event segments plus derived activity summaries. Not conversation history; see [the dedicated section](#chatgpt-computer-history-skysight). |

### Canonical artifact paths (what IRFlow scans)

IRFlow’s **Collect AI Artifacts**, triage detection, and **File → Open** defaults use the paths below (aligned with [as-aix](https://github.com/acquiredsecurity/as-aix), vendor docs, and DFIR writeups).

| Tool | Platform | Path |
|------|----------|------|
| **Claude Code (CLI)** | all | `~/.claude/history.jsonl`, `~/.claude/projects/**/*.jsonl` |
| **Claude Desktop** | macOS | `~/Library/Application Support/Claude/` — `claude-code-sessions/` (`local_*.json` index linked to `~/.claude/projects/<slug>/<cliSessionId>.jsonl`), plus sibling state stores `pending-uploads/`, `plan-usage-history.json`, `git-worktrees.json` |
| **Claude Desktop** | Windows | `%APPDATA%\Claude\` (same layout as macOS) |
| **Claude Desktop / Cowork** | all | `.../Claude/local-agent-mode-sessions/` (`local_*.json`, isolated `.claude/projects/**/*.jsonl`, `audit*.jsonl`, `.audit-key`) |
| **OpenAI Codex** | all | `$CODEX_HOME` or `~/.codex/` |
| **Grok Build** | all | `$GROK_HOME` or `~/.grok/` — `sessions/`, plus `sessions/session_search.sqlite`, `logs/unified.jsonl`, `active_sessions.json` |
| **ChatGPT** | macOS | `~/Library/Application Support/com.openai.chat/`, `~/Library/Application Support/OpenAI/Atlas/` |
| **ChatGPT** | Windows | `%APPDATA%\OpenAI\ChatGPT\`, MS Store `%LOCALAPPDATA%\Packages\OpenAI.ChatGPT-*\LocalCache\Roaming\ChatGPT\` |
| **ChatGPT** | Linux | `~/.config/com.openai.chat/` (and related variants) |
| **Gemini CLI** | all | `~/.gemini/tmp/<project_hash>/chats/`, including nested subagent sessions; `~/.gemini/shell_history`; legacy checkpoints |
| **Cursor** | all | `~/.cursor/projects/<slug>/agent-transcripts/`; Cursor `User/globalStorage/conversation-search.db` under `%APPDATA%`, `~/Library/Application Support`, or `~/.config` |
| **GitHub Copilot CLI** | all | `$COPILOT_HOME` or `~/.copilot/` — `session-state/`, `command-history-state/`, `session-store.db`, and `logs/` |
| **GitHub Copilot (VS Code)** | all | `%APPDATA%` or `~/Library/Application Support` → `Code`, `Code - Insiders`, `VSCodium` (+ Insiders) → `User/workspaceStorage/<hash>/chatSessions/` |
| **Windsurf** | all | `~/Library/Application Support/Windsurf/User/` (or `~/.config/Windsurf/User/`) — `workspaceStorage/*/state.vscdb` |
| **Continue** | all | `~/.continue/sessions/*.json` |

> **Stores that outlive the conversation:** several artifacts persist after the chat they belong to is deleted, which makes them the highest-value collection targets on a stale host. Claude Desktop `deleted_<session-uuid>` tombstones date the removal of a conversation; `pending-uploads/` retains what was attached to it; `plan-usage-history.json` shows the app was in use. Grok Build `sessions/session_search.sqlite` mirrors transcript text and `logs/unified.jsonl` timestamps tool executions independently of the session tree. Collect these even when the session directories look empty.

> **SQLite and sensitive stores:** IRFlow reads Cursor `conversation-search.db`, `globalStorage/state.vscdb`, workspace `state.vscdb`, and `~/.cursor/chats/**/store.db` using snapshots that preserve available WAL/SHM companions. Copilot CLI `config.json`, MCP OAuth/secret stores, tracked-file contents, and process-log contents are not copied into timeline text; tracked files and logs are inventory-only. **ChatGPT** `conversations-v2-*` and `conversations-v3-*` bundles appear as inventory rows; their message bodies are not decoded. **Codex** versioned `state*.sqlite` stores are snapshotted with their WAL/SHM companions and contribute thread, spawn-edge, and dynamic-tool metadata (full transcripts remain in rollout JSONL). **Grok Build** credentials (`auth.json`, `mcp_credentials.json`) are never added to timeline rows. **Windsurf** Cascade `.pb` files are inventoried but protobuf bodies are not decoded. **Browser-only** AI usage may only appear under Chrome, Edge, Firefox, and Safari profiles — profile scan empty reports list likely browser paths when found.

## Artifact coverage and IR value

IRFlow separates AI evidence into three categories:

| Category | Meaning |
|----------|---------|
| **Parsed history** | Message/session rows are extracted into the AI Query History grid. |
| **Inventory-only** | The artifact is detected and reported, but message bodies are not decoded. |
| **Browser hints** | Browser paths likely to contain web-only AI activity are reported so the profile can be collected separately. |

| App | Artifact | Status | Why it matters in incident response |
|-----|----------|--------|-------------------------------------|
| **Claude Code** | `~/.claude/history.jsonl` | Parsed | Fast prompt history for user intent, suspicious questions, credential pasting, and session pivots. |
| **Claude Code** | `~/.claude/projects/**/*.jsonl` | Parsed | Full prompts, responses, tool-use records, attachments, file-history snapshots, model data, token counts, sidechain flags, and workspace context. |
| **Claude Desktop / Cowork** | `claude-code-sessions/**/local_*.json`; `local-agent-mode-sessions/**/{.claude/projects/**/*.jsonl,audit*.jsonl,.audit-key}` | Parsed metadata, recursive transcripts, and audit rows | Reconstructs isolated Cowork sessions instead of assuming every transcript lives in the host `~/.claude/projects`; audit-key presence is reported so collection tooling can preserve it for later integrity validation. |
| **OpenAI Codex** | `history.jsonl`, `sessions/**/rollout-*.jsonl`, `archived_sessions/**/rollout-*.jsonl` | Parsed | Shows AI-assisted actions, shell command intent, file edits, tool calls, workspace paths, and possible disclosure of sensitive data. |
| **OpenAI Codex** | `session_index.jsonl`, `state*.sqlite` plus WAL/SHM, VS Code-family `agentSessions.model.cache` entries | Metadata supplement | Adds thread titles, workspace/model/git context, parent-child spawn edges, dynamic tools, and embedded Codex provider evidence when full rollout files are sparse or absent. |
| **Grok Build** | `sessions/<encoded-cwd>/prompt_history.jsonl` | Parsed | Provides timestamped user prompts and direct shell entries (`is_bash`), including the exact command in **ToolCommand**. |
| **Grok Build** | `<session-id>/summary.json`, `updates.jsonl`, `chat_history.jsonl`, `hunk_records.jsonl` | Parsed | Reconstructs sessions, responses/reasoning, tool calls and completion output, token usage, model/workspace context, and files changed by the agent. |
| **Grok Build** | `<session-id>/terminal/call-*.log` | Preserved source artifact | Captured terminal output is normally present in `updates.jsonl`; `rawOutput.output_file` records the corresponding terminal-log path for provenance. |
| **Grok Build** | `sessions/session_search.sqlite` | Parsed when SQLite support is available | FTS5 index over session transcripts — `session_id`, `cwd`, `title`, `updated_at`, and the indexed body. It mirrors the transcript and **survives deletion of the session directory**. |
| **Grok Build** | `logs/unified.jsonl` | Parsed (selective) | Tool executions with outcome and duration, plus turn boundaries, written independently of the session tree. Records *that* a tool ran, never the command. |
| **Grok Build** | `active_sessions.json` | Parsed | Sessions open at acquisition: `session_id`, `pid`, `cwd`, `opened_at`. |
| **Grok Build** | `memtrace/*.jsonl` | Deliberately not parsed | Despite the name, a **memory profiler** trace (`rss_bytes`, `alloc`) — no conversation content. Tens of MB of allocation samples; only process-lifetime value. |
| **Claude Desktop** | `claude-code-sessions/**/deleted_<session-uuid>` | Parsed | **Deletion evidence.** A 13-byte tombstone whose content is the epoch-ms deletion time and whose filename is the deleted session id. |
| **Claude Desktop** | `pending-uploads/<uuid>-<epoch_ms>_<name>` | Inventory-only | Files staged for upload — what the user attached or pasted into a conversation, retained independently of it. Content is never read. |
| **Claude Desktop** | `plan-usage-history.json` | Parsed (derived) | Dense usage samples collapsed into contiguous "application in use" windows that survive deletion of the conversations inside them. |
| **Claude Desktop** | `scheduled-tasks.json`, `git-worktrees.json` | Parsed | Agent runs configured to fire without user interaction, and working directories with last-seen timestamps. |
| **Grok Build** | `auth.json`, `mcp_credentials.json`, `config.toml`, `trusted_folders.toml` | Deliberately not parsed | These files can expose authorization/configuration state. Preserve and examine them only when in scope; IRFlow does not copy credential values into timeline fixtures or rows. |
| **ChatGPT Desktop / Atlas** | LevelDB and SQLite stores under app data directories | Parsed when local stores contain data | LevelDB often proves conversation existence and titles; SQLite stores can contain full user/assistant message bodies on supported app versions. |
| **ChatGPT Desktop / Atlas** | `conversations-v2-*`, `conversations-v3-*/*.data`, including `project-*` stores | Inventory-only | IRFlow reports bundle UUID, generation, project/store context, size, and source path. It does not decode message bodies. |
| **Gemini CLI** | `~/.gemini/tmp/<hash>/chats/**/*.jsonl`, `~/.gemini/shell_history`, and legacy `session-*.json`, checkpoints, and logs | Parsed | Replays current append-only sessions, including `$set` checkpoints and `$rewindTo`, exact tool inputs and shell commands, tool results, nested subagents, and exact shell-history entries. |
| **Cursor** | `~/.cursor/projects/<slug>/agent-transcripts/**/*.{jsonl,txt}` | Parsed | High-value Cursor agent evidence: instructions, responses, tool-use text, sidechain flags, and workspace attribution. |
| **Cursor** | `globalStorage/state.vscdb`, `workspaceStorage/*/state.vscdb`, `~/.cursor/chats/**/store.db` | Parsed when SQLite support is available | Recovers composer/global/workspace chats that are not present in agent-transcript files. |
| **Cursor** | `Cursor/User/globalStorage/conversation-search.db` plus WAL/SHM when present | Parsed | Recovers the local full-text conversation index: title, indexed body, conversation ID, source/scope, archive state, and update time. |
| **GitHub Copilot** | VS Code-family `workspaceStorage/*/chatSessions/*.{json,jsonl}` and `globalStorage/emptyWindowChatSessions/*` | Parsed | Reconstructs Copilot Chat tied to workspaces and captures chats created without a folder open. |
| **GitHub Copilot** | VS Code-family `state.vscdb` chat/session keys | Metadata/message supplement | Recovers chat session indexes, prompt arrays, or cached messages when chat session files are sparse. |
| **GitHub Copilot CLI** | `~/.copilot/session-state/<session-id>/events.jsonl`, `workspace.yaml`, `plan.md`, and `checkpoints/` | Parsed | Reconstructs prompts, responses, exact tool inputs and shell commands, results, session/workspace/model context, plans, and checkpoints. |
| **GitHub Copilot CLI** | `~/.copilot/command-history-state/` and `session-store.db` plus WAL/SHM | Parsed / metadata supplement | Preserves exact recorded command history and safe session/checkpoint metadata that can bridge sparse session files. |
| **GitHub Copilot CLI** | `~/.copilot/session-state/*/files/` and `~/.copilot/logs/` | Inventory-only | Records path, size, and modification time without ingesting tracked-file or process-log contents. |
| **GitHub Copilot CLI** | `config.json`, `mcp-oauth-config/`, `mcp-secrets/`, permission/config stores | Deliberately excluded | Avoids importing authentication, OAuth, MCP secret, or permission values into timeline rows. Preserve separately only when authorized and in scope. |
| **Windsurf** | `Windsurf/User/globalStorage/state.vscdb` and `workspaceStorage/*/state.vscdb` | Parsed when SQLite support is available | Captures global and workspace Windsurf chat/session evidence. |
| **Windsurf** | `globalStorage/windsurf.cascade/**/*.pb` | Inventory-only | Flags proprietary Cascade protobuf bundles for preservation. Message bodies are not decoded. |
| **Continue** | `~/.continue/sessions/*.json` | Parsed | Captures Continue.dev local prompts/responses and maps them to the workspace directory. |
| **Browser AI usage** | Chrome, Edge, Firefox, and Safari profile storage paths | Hint-only | Browser-only ChatGPT, Claude, Grok, Copilot, and Gemini usage may require browser profile collection or vendor export. |

`Tool` identifies the AI app family, such as **OpenAI Codex**, **Grok Build**, or **Claude Code**. `InvokedTool` is reserved for an invoked function/tool inside that app, such as a shell command, editor operation, or model tool call. Provider names should not appear in `InvokedTool`; older saved tabs may still show the legacy `ToolName` header.

For Cursor and Claude-style `tool_use` records, Codex `function_call` records, and Copilot CLI tool-execution events, IRFlow also preserves **ToolCommand**, **ToolInput**, and **ToolDescription**. `ToolCommand` is the exact recorded command value. When the source stores an argument vector instead of a command string, the value stays in JSON array form so quoting and argument boundaries are not invented. `ToolInput` keeps the original structured arguments; a message containing multiple tool calls stores a JSON array keyed by tool name.

`Summary` is the grid-friendly preview. `FullText` preserves the richer message body for long prompts, responses, tool output, secret scanning, and export.

## What it extracts

Claude Code stores conversation data as JSONL on disk:

| Artifact | Typical path |
|----------|----------------|
| Prompt history | `~/.claude/history.jsonl` |
| Full sessions | `~/.claude/projects/<project>/<session>.jsonl` |

From a triage image, look under user profiles, for example:

- `C:\Users\<user>\.claude\`
- `/Users/<user>/.claude/` (when collected from macOS endpoints)

Each message becomes a timeline row with **Timestamp**, **Role**, **RecordType**, **Summary**, **FullText**, **InvokedTool**, **ToolCommand**, **ToolInput**, **ToolDescription**, **SessionId**, **Model**, token counts (when present), **IsSidechain**, **GitBranch**, **SourceFile**, and a **Description** column for search and review. Claude session files also surface non-chat events (file snapshots, system/compaction markers, attachments, and similar).

When both `history.jsonl` and session JSONL contain the same prompt, the session copy is kept and the history duplicate is dropped.

### Claude Desktop state artifacts

Alongside the transcripts, Claude Desktop keeps stores that answer questions the transcripts cannot — precisely because they persist after a conversation is removed.

**Deleted conversations leave a dated tombstone.** Under `claude-code-sessions/<account>/<org>/`, a removed session is replaced by a file named `deleted_<session-uuid>` whose entire 13-byte content is the **epoch-ms deletion time**. Both halves of the finding come from the artifact: the filename gives the session id, the content gives when it went. Measured on a live host, two tombstones sat beside five live `local_*.json` sessions. It does **not** recover the conversation, and the row's timestamp is the deletion — not the conversation's own activity.

**Staged attachments outlive the chat.** `pending-uploads/` holds files named `<uuid>-<epoch_ms>_<original name>` — what the user attached or pasted into a conversation. They are retained independently of it, so they can evidence that a document or screenshot was sent to the assistant long after the chat is gone. Measured: 84 files, 58.7 MB, spanning six months. IRFlow inventories path, size and the timestamp parsed from the filename; **file content is never read**. Preserve the bytes separately under the usual evidence controls.

**Usage samples give a presence timeline.** `plan-usage-history.json` records a sample roughly every five minutes while the app is open, each with an org UUID — 5,189 of them across a month on the measured host. One row per sample would be noise, so IRFlow collapses them into contiguous windows, splitting on a gap wider than the sampling interval. Those windows are *derived* from sample spacing, not recorded session boundaries, and the rows say so.

Also collected: `scheduled-tasks.json` (agent runs configured to fire without user interaction — treat as an automation/persistence surface; an empty schedule is not reported) and `git-worktrees.json` (working directories with last-seen timestamps, which can place a workspace on the timeline when no transcript for it survives).

::: tip Point the scan at the app-support folder
`pending-uploads/`, `plan-usage-history.json` and `git-worktrees.json` are **siblings** of `claude-code-sessions`, not children of it. Select `~/Library/Application Support/Claude` (or `%APPDATA%\Claude`) to reach everything; discovery does this automatically. Selecting `claude-code-sessions` alone still works and still finds the tombstones — it simply cannot see its own siblings, because a scan never walks up out of the folder you authorized.
:::

### ChatGPT Desktop

| Platform | Typical path |
|----------|----------------|
| macOS | `~/Library/Application Support/com.openai.chat/` |
| macOS (Atlas) | `~/Library/Application Support/OpenAI/Atlas/` |
| Windows (standalone) | `%AppData%\Roaming\OpenAI\ChatGPT\` |
| Windows (MS Store) | `%LocalAppData%\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\` |

ChatGPT stores vary by version:

- **LevelDB** (`Local Storage/leveldb/*.ldb`) — conversation titles and timestamps (role `conversation`).
- **SQLite** — full user/assistant message bodies when the app version writes them locally.
- **Conversation bundles** — `conversations-v2-*` and `conversations-v3-*/*.data`, including project stores, become metadata inventory rows. IRFlow records their UUID, generation, project/store context, size, and path without claiming to decode their bodies.

### OpenAI Codex (CLI / Desktop)

| Platform | Typical path |
|----------|----------------|
| macOS / Linux | `~/.codex/` (override with `CODEX_HOME`) |
| Windows | `%USERPROFILE%\.codex\` |

| Artifact | Contents |
|----------|----------|
| `history.jsonl` | Prompt log (`session_id`, `ts`, `text`) |
| `sessions/YYYY/MM/DD/rollout-*.jsonl` | Full threads: user/assistant messages, `shell` tool calls, reasoning events |
| `archived_sessions/` | Archived rollout files |
| `session_index.jsonl` | Thread titles (metadata) |

The macOS **Codex** app in `~/Library/Application Support/Codex` is UI cache only; forensic content is under **`~/.codex`**.

### Grok Build (Grok AI terminal agent)

[Grok Build](https://github.com/xai-org/grok-build) is the terminal coding agent distributed as the `grok` CLI. Its default data root is `~/.grok`; `GROK_HOME` can override that location. The upstream [authentication guide](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md) documents `~/.grok/auth.json` and `~/.grok/mcp_credentials.json`, both of which should be treated as credential-bearing evidence.

| Artifact | Forensic value |
|----------|----------------|
| `sessions/<encoded-cwd>/prompt_history.jsonl` | Timestamp, session ID, prompt, and `is_bash`; direct bash entries populate **ToolCommand** exactly. |
| `<session-id>/summary.json` | Session ID/title, created/updated time, cwd, model, Git branch/commit context, agent mode, sandbox profile, and reasoning effort. |
| `<session-id>/updates.jsonl` | Timestamped user/assistant/reasoning chunks, tool calls (`rawInput`), completion output (`rawOutput`), stop reason, and token usage. |
| `<session-id>/chat_history.jsonl` | Normalized conversation fallback when timestamped updates are absent. |
| `<session-id>/hunk_records.jsonl` | File path, added/removed line counts, prompt index, hunk ID, author, and event timestamp. |
| `<session-id>/terminal/call-*.log` | Captured output for terminal commands; the related updates record can reference the log through `output_file`. |
| `<session-id>/events.jsonl`, `signals.json`, `prompt_context.json` | Additional lifecycle, performance, environment, and context evidence; preserve even when not yet projected into timeline rows. |
| `trusted_folders.toml`, `slash-mru.json`, `version.json`, `agent_id` | Trust decisions, recent slash-command state, installed-version metadata, and installation identity. |

For a `run_terminal_command` event, IRFlow places the exact recorded `rawInput.command` in **ToolCommand**, retains all structured input in **ToolInput**, and creates a related `tool_result` row containing working directory, exit code, timeout/truncation flags, captured output, and terminal-log path when present. Failed calls use `tool_result_failed`.

#### Runtime stores outside the session tree

Three Grok stores live outside `sessions/<encoded-cwd>/<session-id>/` and are written independently of it. That independence is the point: deleting a session directory does not delete the index that mirrors its text, the log that timestamped its tool calls, or the record that it was open.

| Artifact | What it gives you |
|----------|-------------------|
| `sessions/session_search.sqlite` | `session_docs` holds `session_id`, `cwd`, `title`, `updated_at` (epoch **seconds**) and the indexed transcript body, with an FTS5 index over it. `last_indexed_offset` shows how much of the source was consumed — well below the body length means a partial view. |
| `logs/unified.jsonl` | `shell.tool.exec_done` records give tool name, success/failure and duration per `sid`; turn boundaries bracket model calls. There is **no command string** here — that only ever lives in the session's `updates.jsonl`. |
| `active_sessions.json` | `session_id` → `pid`, `cwd`, `opened_at` for sessions open when the host was captured. |

::: warning `memtrace/` is not what the name suggests
`~/.grok/memtrace/*.jsonl` looks like agent memory and is not. Every record is `{"kind":"sample","rss_bytes":…,"footprint_bytes":…,"alloc":{…}}` — a **memory profiler** trace, tens of megabytes of allocation samples with no conversation content. IRFlow does not parse it. Its only evidentiary use is proving the process was alive, which `active_sessions.json` and the unified log already cover.
:::

The consumer Grok product is separate. IRFlow does not currently claim a native parser for consumer Grok web/mobile chats. Investigate ordinary browser history, downloads, cache, cookies, local/IndexedDB storage, and vendor exports for `grok.com` or X/Grok use; do not attribute a generic browser profile to Grok without origin-level evidence.

### Gemini CLI

| Platform | Typical path |
|----------|----------------|
| macOS / Linux | `~/.gemini/tmp/<hash>/chats/**/*.jsonl`, `~/.gemini/shell_history` |
| Windows | `C:\Users\<user>\.gemini\tmp\<hash>\chats\**\*.jsonl`, `C:\Users\<user>\.gemini\shell_history` |

Current Gemini CLI sessions are append-only JSONL. IRFlow replays message records, `$set` checkpoints, and `$rewindTo` operations to reconstruct the retained session state. It emits separate tool-call and tool-result rows, preserves the exact `run_shell_command` command in **ToolCommand**, and marks nested chat directories as subagent evidence. `shell_history` is also parsed, including continued multiline commands. Legacy `session-*.json`, checkpoints, and `logs.json` remain supported.

This is the **Gemini CLI** (npm/agentic CLI), not the official Gemini macOS desktop app (which is mostly cloud-synced).

### Cursor

| Platform | Typical path |
|----------|----------------|
| macOS / Linux | `~/.cursor/projects/<project-slug>/agent-transcripts/<session-id>/<session-id>.jsonl` |
| Windows | `%USERPROFILE%\.cursor\projects\...` |
| macOS | `~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db` |
| Windows | `%APPDATA%\Cursor\User\globalStorage\conversation-search.db` |
| Linux | `~/.config/Cursor/User/globalStorage/conversation-search.db` |

Each JSONL line is a `user` or `assistant` message with structured `message.content` blocks (text, tool calls). IRFlow uses embedded `timestamp` / `createdAt` values when present; file birth/mtime spreading is only a fallback for transcript rows without per-message time. Project slugs under `projects/` decode to filesystem paths when possible. Subagent transcripts under `subagents/` are skipped by default (same scope prompt as Claude/Codex).

`conversation-search.db` is also accepted as a standalone artifact or through its parent Cursor `User` folder. Each indexed conversation becomes a searchable timeline row with its title in **Summary**, indexed body in **FullText**, conversation ID in **SessionId**, and the recorded update time.

### GitHub Copilot (CLI and VS Code)

| Platform | Typical path |
|----------|----------------|
| all (CLI) | `$COPILOT_HOME` or `~/.copilot/` |
| macOS | `~/Library/Application Support/Code/User/workspaceStorage/<hash>/chatSessions/` |
| Windows | `%APPDATA%\Code\User\workspaceStorage\<hash>\chatSessions\` |
| Linux | `~/.config/Code/User/workspaceStorage/<hash>/chatSessions/` |

Copilot CLI session events are read from `session-state/<session-id>/events.jsonl`; IRFlow also parses workspace metadata, plans, checkpoints, exact command history, and safe `session-store.db` metadata. Tracked files and process logs are inventoried without reading their contents, and authentication/MCP secret stores are excluded.

VS Code sessions are stored as `.json` or `.jsonl`. JSONL replays `kind: 0` / `kind: 2` / `kind: 1` lines (not only the last snapshot). **Code - Insiders** and **`emptyWindowChatSessions`** (chats with no folder open) are included. `workspace.json` beside each hash folder maps to the opened workspace path for the **Workspace** column.

## ChatGPT Computer History (Skysight)

::: tip New in v1.0.10
Computer History is a **separate artifact class from AI Query History**. Everything above is prompt/response conversation data. Computer History is OS-level user-activity telemetry — focus changes, clicks, keystrokes, selections, drags, and window/URL context — so it opens in its own tab with a dedicated 54-column schema.
:::

Computer History is an opt-in macOS feature of the ChatGPT desktop app, released 13 August 2026 as the replacement for the screenshot-based Chronicle research preview. It is **off by default**, requires Memories, is limited to Pro/Business/Enterprise plans, and is not available in the EEA, Switzerland, or the UK. When enabled it records an interaction-event stream from allowed apps and websites, then periodically distils it into natural-language activity summaries.

It explicitly does **not** capture screenshots, screen recordings, microphone input, system audio, or private-mode browsing. Everything it records reaches disk through the macOS Accessibility API, which is why capture depth varies so much between applications.

Two properties matter for acquisition. Raw events are uploaded to OpenAI for summarisation, so the local stream is not the only copy — a vendor request is a parallel avenue. And the local files are **plain text and unencrypted**: OpenAI's own documentation notes that other programs running as the same macOS user can read them, which makes them readable by any user-context malware and, equally, readable by a live-response script without elevation.

### Canonical artifact paths

| Artifact | Path | Retention |
|----------|------|-----------|
| **Raw event stream** | `~/Library/Group Containers/2DC432GLL2.com.openai.sky.CUAService/Library/Caches/ComputerUse/Skysight/segments/<YYYY-MM-DDTHH-MM-SSZ>/events.jsonl` | **~48 hours**, then purged |
| **Segment metadata** | `…/segments/<bucket>/metadata.json` | with its segment |
| **Activity summaries** | `~/.codex/memories/extensions/skysight/resources/<ts>-<4char>-(10min\|6h)-*.md` | until the user clears them |
| **Summariser instructions** | `~/.codex/memories/extensions/skysight/instructions.md` | persistent |
| **Consolidated memory** | `~/.codex/memories/{memory_summary.md,MEMORY.md,raw_memories.md}`, `~/.codex/memories_*.sqlite` | **indefinite** — see below |
| **Memories git repository** | `~/.codex/memories/.git` | persistent |
| **Feature state** | `~/.codex/config.toml` → `[plugins."computer-history@openai-bundled"] enabled` | persistent |
| **Computer Use agent approvals** | `…/CUAService/Library/Application Support/Software/ComputerUseAppApprovals.json` — see the caveat below; **not** the recording scope | persistent |
| **Analytics store** | `…/CUAService/Library/Application Support/Software/Analytics.db` | uploaded then cleared |
| **Device pseudonyms** | `~/Library/Preferences/com.openai.sky.CUAService.plist`, `com.openai.chat.plist` | persistent |
| **Account binding** | `~/Library/Preferences/com.openai.chat.RemoteFeatureFlags.<account-uuid>.plist` | persistent |
| **Helper app / IPC** | `~/.codex/computer-use/Codex Computer Use.app`, `…/CUAService/IPC/computeruse.sock` | persistent |

Segment directories are fixed **10-minute UTC buckets**. A *closed* `metadata.json` carries `startedAt`, `endedAt`, `eventCount`, `suppressedEventCount`, `id`, and `eventsPath` — the absolute path recorded at capture time, which on a triage copy is the only in-artifact proof of the original home directory, user, and volume.

The **currently open** bucket is different: it carries only `id`, `startedAt`, and `eventsPath`. `endedAt`, `eventCount`, and `suppressedEventCount` are written when the bucket closes. On a live acquisition the newest one or two buckets will therefore look "incomplete" — that is normal, not tampering, and they must be excluded from count reconciliation rather than scored as a shortfall.

### Event kinds observed in the live schema

`session.started` · `session.ended` · `window.changed` · `mouse.click` · `mouse.context_menu` · `mouse.drag` · `selection.changed` · `keyboard.text_input` · `keyboard.submit` · `keyboard.shortcut`

Each event may carry the frontmost app (bundle id and name), window title and URL, the accessibility target (role, subrole, label, description, identifier), the typed or selected payload, drag origin **and** destination, and an `ax` block containing accessibility text.

`mouse.modifiers` records the modifier held during a click or drag, and it changes what the click *meant*. A `command`-click on an `AXLink` opens that link in a **background tab** — a deliberate choice not to navigate away, and the signature of bulk-opening results rather than reading one. `shift`-click extends a range selection; `command`-click on a row multi-selects. It shares the `KeyChord` column with keyboard chords, since both use the same vocabulary (`command`, `shift`, `control`, `function`).

`app.secureInput` is a further per-event flag: `true` means macOS **Secure Input Mode** was engaged at that moment (a password field held focus anywhere on the system). It is a stronger and more common credential signal than the `AXSecureTextField` target subrole — see the credential note below.

### What IRFlow extracts

Rows land in a dedicated schema rather than the AI history columns. The fields that carry the evidence:

| Group | Columns |
|-------|---------|
| **When** | `Timestamp`, `EventId`, `SegmentId`, `SegmentStart`, `SegmentEnd`, `SegmentSuppressed`, `SegmentEventCount`, `SegmentCountDelta` |
| **What** | `EventClass`, `AppClass`, `EventKind`, `Activity` |
| **Where** | `AppName`, `BundleId`, `WindowTitle`, `Url` |
| **Target** | `TargetRole`, `TargetSubrole`, `TargetLabel`, `TargetDescription`, `TargetId` |
| **Payload** | `Content`, `ContentLength`, `TypedDelta`, `KeyChord`, `MouseButton`, `ClickCount`, `SelectionOffset`, `SelectionLength`, `SelectedItems`, `SelectedItemRoles`, `SelectedItemCount` |
| **Movement** | `DestAppName`, `DestBundleId`, `DestWindowTitle`, `DestUrl`, `DestTargetRole`, `DestTargetSubrole`, `DestTargetLabel`, `DestContent` |
| **Capture** | `FidelityTier`, `AxMode`, `AxLength`, `ScreenText` |
| **Narrative** | `SummarySuggestion`, `SummaryCitations` |
| **Provenance** | `Identifier`, `SourceFile`, `RecordedSourcePath`, `LineNumber`, `User`, `Host`, `Description`, `RecordId` |

`EventClass` describes **what the user did** (typing is `Input` wherever it happens). `AppClass` describes **where** it happened (`Terminal`, `Communication`, `Web`, `FileSystem`). They are deliberately separate — filter typed content on `EventClass = Input`.

### Investigation value

| Question | Where to look |
|----------|---------------|
| Did the subject enter credentials? | `TargetSubrole = AXSecureTextField`, surfaced as `Activity: Credential Entry` / `Credential Submit`. This proves a password field was focused — it does **not** recover the password. See the credential note below. |
| Which files were selected before an exfil? | `SelectedItems` / `SelectedItemRoles` — Finder row selections. These events carry no selected text, so without this column they are empty rows. |
| Where did data move? | `mouse.drag` with `DestAppName` / `DestTargetLabel` / `DestContent` — the receiving end of a cross-app drag. |
| What commands were run? | Terminal rows. Emulators expose the whole scrollback buffer as one `AXTextArea`, so these are screen-state snapshots, not a single command. |
| What was searched for? | `TargetSubrole = AXSearchField`. After the 48h purge, typed search terms often still survive in `summary.profile` rows. |
| Were links opened in background tabs? | `KeyChord = command` on a `mouse.click` against `AXLink` — deliberate non-navigation, the bulk-open pattern. |
| Did a double-click open something? | `Activity = Double-Click`; exact multiplicity is in `ClickCount`. |
| Was recording paused or cleared? | `Configuration` and `Integrity` rows — see the caveats below. |
| Who does this host belong to? | `Identity` rows — see the attribution table below. |

### Field notes from live analysis

These are the findings that change how the data should be read. Each was measured against a live capture, not inferred.

**Raw events purge after ~48 hours. Collect early.** On a stale image the derived summaries are frequently the only surviving record — and they are model-generated interpretation, not primary evidence. The summariser also self-redacts, omitting content it judges sensitive, so a summary can understate what the raw events showed.

**Secure Input suppresses the keystrokes — a credential row is not a recovered password.** When a password field takes focus, macOS engages Secure Input Mode, which blocks the event tap the recorder relies on. The result on disk is that the keystrokes are *consumed but never written*: the event-id counter advances across them while no records appear. Measured across a full live capture of 5,370 events, `keyboard.text_input` records with captured text under Secure Input: **zero**. Two illustrations from that capture — a `loginwindow` password prompt produced a single `keyboard.submit` against an `AXSecureTextField` with `text: null` and ids `2593`/`2594` missing; a browser login produced the typed *username* (`keyboard.text_input`, id 12626) followed by a `tab` into the password field, after which ids 12628 and 12630 were consumed with nothing persisted.

Read a credential row as **"a password was entered here, at this time, into this field, in this app"** — an excellent pivot, and enough to time-anchor an authentication event against other logs. It is not the credential. Reporting it as recoverable plaintext is wrong and will not survive review.

The corollary is the useful part: `app.secureInput: true` fires on *any* system-wide password prompt, including ones with no `AXSecureTextField` target — in the same capture it marked a third-party app-lock prompt (`com.cisdem.appencrypt`, window title "Please Enter your Password") that carried no secure-field subrole at all. Filter on both signals, not just the subrole.

One value *does* surface, and it is worth knowing exactly what it is. When a secure field is selected, `selection.selectedText` carries the field's **masked rendering** — a run of U+2022 bullets. Verified byte-level on the capture above: two such rows, one of 14 bullets and one of 5, with no other codepoint present. That is not the password, and a `Content` cell full of bullets must never be quoted as though it were. It does disclose the **length**, which is a legitimate corroborating detail — a 14-character value is consistent with a generated passphrase and not with a 6-digit PIN — so record it as a length observation and nothing more.

**`ScreenText` is not always a screen snapshot.** `AxMode` decides how to read it: `fullTree` is a snapshot of the visible accessibility tree, while `diffFromPrevious` carries **only what changed** since the previous snapshot. Diffs dominate — in one capture 66% of ax-bearing events were diffs (median 1,625 chars) against 34% full trees (median 7,032 chars). The exact split varies by host and workload; what does not vary is that reading a diff as a snapshot understates what was on screen.

**Capture depth is a property of the app, not the event — and it must be measured, not assumed.** `FidelityTier` is resolved once per application from its largest full-tree capture. In genuine Tier 3 apps, **outbound typed text is captured while inbound message content is not**, because keyboard events are hardware-level and app-independent while message bodies only ever appear via the accessibility tree. Such a capture is one side of a conversation and must never be presented as a chat record.

Do not assume which apps those are. "Messaging app" is not the predictor — *UI toolkit* is. Measured on one live capture: **Telegram** exposed a maximum full-tree of **144 characters** (window and menu labels only — genuinely Tier 3), while **Slack**, an Electron app, exposed **53,590 characters** including channel message text, thread markers, and per-message timestamps. Two apps in the same product category, three orders of magnitude apart. Verify the tier against `AxLength` for that bundle in your own capture before writing either the "we have the conversation" or the "we only have one side" sentence into a report.

**`EventId` gaps are not a suppression count.** The counter is monotonic *within a recorder session*, but it also advances for events that are never persisted at all. Measured on one 10-minute bucket: 2,374 ids spanned, 329 events retained, and a declared `suppressedEventCount` of **13**. Only the metadata count is authoritative about suppression; reporting the id gap as withheld events overstates it by two orders of magnitude.

**`EventId` resets to 1 every time the recorder restarts.** This is the trap in the previous check. The counter is *not* capture-global: each `session.started` event carries `id: 1`, and the events themselves contain no session identifier, so the only way to segment runs is the reset itself. One 35-hour capture contained four such runs, the counter reaching 17,169 before dropping back to 1. Any continuity test that simply compares the last id before a hole with the first id after it produces nonsense across a restart — "ids run continuously, 17169 → 1" — and, worse, reports a *clearance* it never earned. Split the capture at each `session.started` first, then test continuity **within** each run only. Across a restart boundary, event-id continuity cannot assess deletion at all; say so rather than clearing it.

**A missing segment bucket is not evidence of deletion.** Within a single recorder run, cross-check event-id continuity across the hole. Observed live: bucket `06-30` absent while ids ran `6347 → 6348` straight through, which proves the host was idle rather than that a bucket was removed. A genuine deletion shows an id **jump** — a positive discontinuity inside one run, never a reset to 1.

**`metadata.eventCount` is a usable integrity anchor.** It matched the file exactly on every closed segment measured. Because the app offers "clear the last 10 minutes / hour / day / all", a clear removes records while leaving the count behind — so a shortfall between declared count and well-formed records present is a deletion lead. Count malformed lines separately: corruption and deletion both lower the record count but are different findings.

**The activity data does not stop at Skysight — and the onward copy outlives everything.** `extensions/skysight/instructions.md` instructs the Codex memory consolidator to mine the summaries, naming the *"Important non-obvious context about the user"* section explicitly, and fold what it finds into the durable memory store one directory up. That produces a third copy of the observed activity with a completely different retention:

| Copy | Retention |
|------|-----------|
| `segments/*/events.jsonl` | ~48 hours |
| `skysight/resources/*.md` | until the user clears Computer History |
| `~/.codex/memories/*.md` + `memories_*.sqlite` | **indefinite** — a different subsystem, not cleared with Computer History |

This inverts the collection priority on a stale host. Measured on a live one: `memory_summary.md` carried a `## User Profile` built partly from observed activity, `MEMORY.md` cited a specific 6-hour summary *by path* as the evidence for a task-group memory, and 13 lines carried an explicit **`[skysight memory]`** provenance tag. IRFlow collects only those tagged lines and blocks citing a Skysight resource — the rest of `MEMORY.md` is ordinary Codex conversation memory, a different artifact family. These files are git-tracked too, so deletions are recoverable by the same route as cleared summaries.

**A summary file is not one statement.** Its body holds structurally different assertions, and IRFlow now emits each as its own row so it can be filtered and searched:

- **`Recording summary`** — what happened inside the window. Bounded by it.
- **`Relevant prior context`** (`summary.priorcontext`) — carried in from *earlier* windows. The row timestamp is when it was written, **not** when the activity happened. Do not date evidence from it.
- **`Important non-obvious context about the user`** (`summary.profile`) — the largest section, averaging ~1,000 characters against ~415 for the recording summary, and the highest-value one: a model-written dossier naming documents, typed search terms, organisation and project names, and each app's role. It survives the 48-hour purge, so it can still name a search term whose primary record is already gone. Corroborate before relying on it — it is inference, not observation.

**`~/.codex/memories/` is a git repository.** Summaries cleared through the UI remain recoverable from the git object store, and the deleting commit is timestamped. On a host where the 48-hour purge has already run *and* the user cleared their history, this can be the only surviving record. Recovery proves the summary existed and when it was removed — it does not upgrade the summary's own evidentiary weight.

**Absence of events for an app is not evidence the app was unused — but do not read the coverage map out of `ComputerUseAppApprovals.json`.** That file belongs to **Computer Use**, the separate feature that lets ChatGPT *drive* the Mac, and it lists the apps the agent is approved to control. It is not the Skysight recording scope, and treating it as one inverts the finding. On one live host it contained a single bundle (`com.microsoft.edgemac`) and carried an mtime of **4 May 2026** — three months before Computer History shipped — while the event stream from the same host recorded **38 distinct bundle identifiers**, Edge among the least active of them.

Computer History does have per-app and per-website include/exclude controls, and collection can be paused from the menu bar. Those settings were **not resolvable from local artifacts** in the captures examined; treat the recording scope as unknown unless you can evidence it from the account side. Scope silence honestly: "no events for app X" means the recorder did not persist events for X, which could be exclusion, a pause, an idle period, or a recorder restart.

### Attribution — four different UUIDs

A single host carries several unrelated pseudonyms. Conflating them produces wrong attribution.

| Identifier | Location | What it identifies |
|------------|----------|--------------------|
| **Account UUID** | `com.openai.chat.RemoteFeatureFlags.<uuid>.plist` **filename** | The ChatGPT account. Cheapest attribution on the box — no parsing, no tokens, survives token expiry. **Two such files mean two accounts used the host.** |
| **Signed-in identity** | `~/.codex/auth.json` → `id_token` claims | Email, name, `chatgpt_user_id`, plan, org and role, Auth0 `sub`, `auth_time`. **Holds live bearer and refresh tokens — treat as credential material.** |
| **`distinct_id`** | `Analytics.db` | The recorder install. Uppercase UUID written by the native Swift service. Appears nowhere else on the host; its value is as the key to cite in a vendor request. |
| **Statsig `stableID`** | `com.openai.sky.CUAService.plist`, `com.openai.chat.plist` | Per-app device pseudonym. Each OpenAI app generates its own, so several of these are one machine, not several. |
| **`installation_id`** | `~/.codex/installation_id` | The Codex (Electron) install — lowercase UUID, a different namespace again. |

Two further pivots worth knowing:

- **The Statsig evaluation cache outlives the purge.** `com.Statsig.InternalStore.localStorageKeyV2` holds cached evaluation contexts with timestamps. One host showed contexts spanning five months against 48 hours of raw events. It proves the process was alive at those times — not that recording was enabled, and not that the user was active.
- **Codex conversation ids are UUIDv7**, so the id itself encodes a creation timestamp and joins conversations to the event timeline with no other artifact. Threads flagged under `codex-writing-block-deleted-thread-v1:` are deleted conversations — and the model chosen and text typed into them are often still present in the event stream. Deleting the conversation does not delete the record of it.

::: warning Analytics.db expectations
The local analytics event table is uploaded and then cleared, and the freed pages are zeroed rather than merely unlinked — one measured file was 99% zero bytes with 137 of 145 pages on the freelist and nothing carvable. Expect it **empty** on anything but a fast live acquisition, and treat that absence as normal rather than as evidence the feature was unused. Its `distinct_id_alias` table is the designed anonymous-device-to-account bridge; if it is ever populated, that is direct local account attribution.
:::

## How to use it in IRFlow

![Tools → Analysis → AI Artifacts with Collect AI Artifacts and the AI Apps submenu](/dfir-tips/Tools-Menu-AI-Artifacts.png)

### Collect AI Artifacts (all tools)

**Tools → Analysis → AI Artifacts → Collect AI Artifacts…** opens a progress modal with two targets:

![Collect AI Artifacts target picker — This Mac or Browse folder for KAPE/triage collections](/dfir-tips/Collect-AI-Artifacts-Target.png)

1. **This Mac** — the logged-in analyst profile (same paths as the table below).
2. **Browse folder…** — KAPE collections, triage packages, mounted disks, or external drives. IRFlow walks the tree and matches **Windows** (`Users\<user>\…`, `AppData\Roaming\…`), **Linux** (`home/<user>/…`, `.config/…`), and **macOS** (`Users/<user>/Library/…`) layouts automatically.

After discovery you choose **main sessions only** vs **include subagents**, then a live activity log shows per-source status, files read, and row counts.

All sources merge into **one** **AI Query History** tab with the KAPE profile (all roles visible; no row colors by default). Endpoint **User** is taken from `Users\<name>` / `home/<name>` when scanning collections.

Use this for a live Mac triage without a KAPE folder, or to sanity-check what is on your own machine before collecting from an endpoint.

**Empty collection folder:** If discovery finds no AI stores, the modal shows an **expected paths checklist** (Windows / Linux / macOS), flags when `Users\` or `home/` exists but AI paths were not collected, and suggests the AI assistant paths to add to the collection before rescanning.

**Stale app session:** If discovery falls back to an older IPC channel, a banner asks you to quit and restart IRFlow so preload loads `discoverAiHistoryProfile`.

### Single artifact

**Claude Code**

1. **File → Open…** and select your `.claude` folder (recommended), or use **Tools → Analysis → AI Artifacts → AI Apps → Claude Code…**
2. Dragging multiple `*.jsonl` files from the same `.claude` tree consolidates into **one** timeline tab (not one tab per file).
3. Opening `history.jsonl` directly uses the AI history parser (proper `Timestamp`, `Role`, `Summary` columns) — not the generic CSV importer.

**ChatGPT Desktop**

1. **File → Open…** and select the app data folder (e.g. `~/Library/Application Support/com.openai.chat`), or **Tools → Analysis → AI Artifacts → AI Apps → ChatGPT Desktop…**
2. Selecting multiple `.ldb` / SQLite files from the same ChatGPT data folder merges into **one** tab.
3. Hidden folders (e.g. under `Library/Application Support`) are visible in the open dialog by default.

**OpenAI Codex**

1. **File → Open…** and select your `~/.codex` folder (recommended), or **Tools → Analysis → AI Artifacts → AI Apps → OpenAI Codex…**
2. Imports `history.jsonl` plus all `rollout-*.jsonl` under `sessions/` and `archived_sessions/` (deduped against session prompts).

**Grok Build**

1. **File → Open…** and select `$GROK_HOME` or `~/.grok` (recommended), or **Tools → Analysis → AI Artifacts → AI Apps → Grok Build…**
2. IRFlow imports workspace prompt histories and session `summary.json`, `updates.jsonl` (or `chat_history.jsonl` fallback), and `hunk_records.jsonl`.
3. Subagent session folders are skipped by default unless you choose **Include subagents**.

**Gemini CLI**

1. **File → Open…** and select your `.gemini` folder (recommended), or **Tools → Analysis → AI Artifacts → AI Apps → Gemini CLI…**
2. Current `chats/**/*.jsonl`, `shell_history`, and legacy JSON artifacts from the same `.gemini` tree consolidate into **one** tab.

**Cursor**

1. **File → Open…** and select your `~/.cursor` folder, Cursor `User` folder, or `conversation-search.db`, or **Tools → Analysis → AI Artifacts → AI Apps → Cursor…**
2. Agent transcripts and available Cursor SQLite stores consolidate into **one** tab. Subagent folders are skipped unless you choose **Include subagents**.

**GitHub Copilot**

1. **File → Open…** and select `$COPILOT_HOME` / `~/.copilot`, `workspaceStorage`, or a specific `chatSessions` folder, or **Tools → Analysis → AI Artifacts → AI Apps → GitHub Copilot…**
2. CLI sessions or all sessions for each VS Code workspace hash are merged into **one** tab per import path.

**Windsurf**

1. **File → Open…** and select the Windsurf `User` folder (e.g. `~/Library/Application Support/Windsurf/User`), or **Tools → Analysis → AI Artifacts → AI Apps → Windsurf…**
2. IRFlow reads `globalStorage/state.vscdb` and per-workspace `workspaceStorage/*/state.vscdb` chat keys; Cascade `.pb` bundles are inventoried but not decoded.

**Continue**

1. **File → Open…** and select `~/.continue` or a `sessions/` folder, or **Tools → Analysis → AI Artifacts → AI Apps → Continue…**
2. Multiple `sessions/*.json` files from the same tree consolidate into **one** tab.

IRFlow opens a new timeline tab with all extracted messages.

## Large trees and performance

- **File → Open** on a `.claude`, `.codex`, or `.grok` folder skips **`subagents/`** session paths by default (main thread only). This keeps triage imports fast on large developer workstations.
- **Tools → Analysis → AI Artifacts → AI Apps → Claude Code / OpenAI Codex / Grok Build / Cursor** asks whether to include subagent content when you pick a directory: Claude `subagents/` folders and inline sidechains, Cursor `isSidechain` transcript lines, Codex forked threads (`parent_session_id` in session metadata), and Grok Build `subagents/` session trees.
- Import progress shows **per-source file** status (e.g. `Reading session-12.jsonl (12/340)`) while JSONL/SQLite is parsed, then row write progress.

### Extraction safeguards

- **Cancel** — profile imports run in a worker thread; cancel uses a per-job abort check so a second import is not stopped by an earlier cancel.
- **Row cap** — merged profile extracts stop ingesting after **3,000,000** rows; the tab notice reports when the cap was hit.
- **Malformed JSONL** — Claude, Codex, Grok Build, and Cursor parsers count lines that fail JSON parse; the import notice reports the total so you know data may be incomplete.
- **Scope confinement** — when you pick a KAPE folder or collection root for AI extract, discovered artifact paths must resolve **inside** that folder; paths outside the scope (including `..` traversal) are dropped. The same confinement applies whenever a **browse folder** path is set on **Collect AI Artifacts**, even if discovery also probed standard local paths.
- **Path authorization** — folders and files chosen in **File → Open**, **Tools → Analysis → AI Artifacts**, and **Collect AI Artifacts** (browse) are registered in a scoped allow-list before read (same model as Sigma/KAPE scan targets). Renderer-supplied paths that were not picked in-app are rejected.

### AI Secret Hunt

On an **AI Query History** tab, run **Tools → Detection → AI Secret Hunt** to scan prompts, responses, and tool output for API keys, tokens, private keys, credentials, and high-confidence secret patterns. Findings are **redacted by default** (cleartext is never written to disk). Group results by tool or session, tag rows for triage, jump to source evidence, and export a redacted PDF/HTML exposure brief or CSV.

![Tools → Detection with AI Secret Hunt enabled on an AI Query History tab](/dfir-tips/Tools-Menu-Detection-AI-Secret-Hunt.png)

![AI Secret Hunt results with grouped findings, severity, and redacted previews](/dfir-tips/AI-Secret-Hunt-Results.png)

## Export for reporting

On an **AI Query History** tab, use **Tools → Export → Export AI History Package…** to write a folder containing:

| File | Purpose |
|------|---------|
| `<tab>_timeline.csv` | Current grid rows (respects filters, sort, visible columns) |
| `manifest.json` | Each **SourceFile** path, row count, size, mtime, SHA-256 (first 250 files hashed) |
| `README.txt` | Short description of the bundle |

Share the folder with counsel or attach it to a case folder; re-hash sources independently using the paths in `manifest.json`.

## Investigation tips

- On an **AI Query History** tab, run **AI Secret Hunt** for credential and key exposure, then use **Row Detail → Filter session** / **Correlate path** (jumps to open Prefetch, EVTX/Sigma, or Amcache tabs with a column filter on the workspace executable/path).
- Filter **InvokedTool** for `Shell` or `Bash`, then review **ToolCommand** for the exact recorded command and **ToolInput** for cwd, timeout, permissions, and other invocation arguments. Tool inputs may themselves contain secrets and should be handled as evidence.
- **FullText** holds the complete message when **Summary** is truncated; Row Detail also prefers FullText for Summary cells. **Export AI History Package** always includes **FullText** in the CSV even if the column is hidden in the grid.
- Merged profile scans **dedupe identical prompts across tools** (same role + message text) so Claude and Cursor duplicates collapse to one row. Provenance is preserved: the kept row's **AlsoInTools** column lists every tool the prompt appeared in (e.g. `Claude Code, Cursor`), so the merge never hides which assistants ran the same prompt.
- **Copilot** replays JSONL `kind:0` / `kind:2` / `kind:1` lines, falls back to sibling `.jsonl` when `.json` is empty, and scans `emptyWindowChatSessions`.
- **Cursor** uses per-message `createdAt` / `timestamp` from JSONL and composer DB when present; file-mtime spread is only a fallback.
- Filter **Role** = `user` to focus on analyst prompts; `assistant` for model replies.
- Use **Description** or full-text search on **Summary** for keywords (credentials, internal hostnames, exploit terms).
- Correlate **Workspace** (project/cwd) with suspicious repositories or production paths.
- **User** / **Host** columns are derived from the collection path when the artifact sits under `Users\<name>\` or a KAPE host folder.
- Filter **RecordType** = `session_deleted` first on any Claude Desktop import: it lists conversations that were removed, with the time of removal, before you draw conclusions from what remains.
- **RecordType** = `pending_upload` shows what was sent to the assistant as an attachment; the timeline row is an inventory entry, so pull the file itself from `pending-uploads/` for the content.
- **RecordType** = `session_search` (Grok) can hold transcript text for sessions whose directories are gone. Compare its `SessionId` against the sessions you actually recovered.
- **RecordType** = `log_tool_exec` (Grok) places tool executions on the timeline with outcome and duration. It never carries the command — correlate `MessageId` (the tool call id) back to the session's `updates.jsonl` for that.

## Extraction safeguards

Large profile scans, **Collect AI Artifacts**, and merged folder extracts share the same merge pipeline:

- **Cancel** — Stop during profile scans and folder-based AI artifact scans; the worker passes an abort token so parsing stops promptly (not only after the merge phase).
- **Row cap** — Merged timelines stop at **3,000,000** message rows by default; the import notice reports truncation and any skipped sources.
- **Parse errors** — Malformed JSONL lines (Claude Code, Codex, Cursor agent transcripts) are skipped and counted; the import notice reports how many lines failed.
- **Folder scope** — When you scan a chosen folder (KAPE output, triage root, mounted disk, or copied profile folder), discovered AI roots must lie under that directory; paths outside the scope are dropped.

## Limitations

- **Summary** is truncated for grid display; use row detail **Open source** (and **LineNumber** for JSONL) to jump to the artifact on disk.
- Claude Code: `history.jsonl` and session files may overlap; both are extracted for completeness.
- ChatGPT: newer builds may keep full chat text cloud-only — local LevelDB may contain titles/timestamps only.
- Consumer Grok: web/mobile chats are not decoded as a native application store; collect browser origin data or a vendor export.
- Grok Build: `events.jsonl`, `signals.json`, `prompt_context.json`, and some auxiliary state remain preservation targets even though the first parser slice does not project every record into the timeline.
- Official **Gemini macOS desktop app** is not parsed (cloud-first); only **Gemini CLI** local sessions are supported.
- **Computer History** is macOS-only, opt-in, off by default, and unavailable in the EEA, Switzerland, and the UK. Absence of the artifact means nothing about user activity.
- **Computer History** raw events are purged after ~48 hours; on a stale image the derived summaries may be all that remains, and they are model-generated interpretation rather than primary evidence.
- **Computer History** summaries can self-redact — the generator omits content it judges sensitive, so a summary may understate the raw events.
- **Computer History** capture depth varies by application, and the tier follows the UI toolkit rather than the app category — Electron and Chromium apps (Slack included) expose full message text, while hardened native UIs (Telegram) yield window metadata and outbound typed text only. Verify `AxLength` per bundle in your own capture before characterising what a messaging app did or did not record.
- **Computer History** credential rows prove a password field was focused; they do not recover the password. macOS Secure Input Mode blocks the recorder's event tap, so the keystrokes consume event ids without being written to disk.
- **Computer History** `EventId` resets to 1 on every recorder restart, so it is a within-run join key only. Across a restart boundary, id continuity cannot assess whether events were deleted.
- **Computer History** activity is consolidated onward into `~/.codex/memories/`, which is **not** purged at 48 hours and **not** cleared with Computer History. Collect it alongside the segments, and expect it to be the surviving copy on a stale host.
- **Computer History** `summary.profile` and `summary.priorcontext` rows are model inference, not observation, and `summary.priorcontext` describes activity from outside its own window — never date evidence from either.
- The ChatGPT **analytics event store** (`Analytics.db`) is uploaded then cleared with freed pages zeroed. Expect it empty outside a fast live acquisition, and note that deleted analytics events are **not** carvable.
- **Computer History** summary recovery from the memories git repository requires `git` on the examination host (Xcode Command Line Tools on macOS).
- **Grok Build** `session_search.sqlite` requires SQLite support; `last_indexed_offset` well below the body length means the index is a partial view of the transcript.
- **Grok Build** `logs/unified.jsonl` records that a tool ran, with outcome and duration, but never the command string. Do not present a `log_tool_exec` row as evidence of what was executed.
- **Grok Build** `memtrace/` is a memory profiler trace, not agent memory, and is deliberately not parsed.
- **Claude Desktop** deletion tombstones prove a conversation existed and when it was removed. They do not recover its content, and their timestamp is the deletion rather than the conversation's activity.
- **Claude Desktop** `pending-uploads/` rows are inventory only — file content is never ingested. Preserve the files separately.
- **Claude Desktop** app-usage windows are derived from usage-sample spacing, not recorded session boundaries.
