---
description: Claude Code and Claude Desktop forensic artifacts — CLI JSONL, Cowork sessions, deletion tombstones, staged uploads, and usage windows.
---

# Claude Desktop

IRFlow treats **Claude Code** (CLI under `~/.claude`) and **Claude Desktop / Cowork** as one family. Transcripts live in JSONL; Desktop also keeps stores **outside** the session tree that survive deleting a conversation.

Back to [AI Query History](/dfir-tips/ai-query-history).

## What IRFlow extracts

Claude Code stores conversation data as JSONL:

| Artifact | Typical path |
|----------|----------------|
| Prompt history | `~/.claude/history.jsonl` |
| Full sessions | `~/.claude/projects/<project>/<session>.jsonl` |

On a triage image look under user profiles, for example `C:\Users\<user>\.claude\` or `/Users/<user>/.claude/`.

Each message becomes a timeline row with **Timestamp**, **Role**, **RecordType**, **Summary**, **FullText**, **InvokedTool**, **ToolCommand**, **ToolInput**, **ToolDescription**, **SessionId**, **Model**, token counts (when present), **IsSidechain**, **GitBranch**, **SourceFile**, and **Description**. Session files also surface file snapshots, system/compaction markers, and attachments.

When both `history.jsonl` and a session JSONL contain the same prompt, the session copy is kept and the history duplicate is dropped.

## Canonical paths

| Tool | Platform | Path |
|------|----------|------|
| **Claude Code (CLI)** | all | `~/.claude/history.jsonl`, `~/.claude/projects/**/*.jsonl`, `~/.claude.json` |
| **Claude Desktop** | macOS | `~/Library/Application Support/Claude/` — `claude-code-sessions/` plus sibling stores below |
| **Claude Desktop** | Windows | `%APPDATA%\Claude\` (same layout) |
| **Claude Desktop / Cowork** | all | `.../Claude/local-agent-mode-sessions/` (`local_*.json`, isolated `.claude/projects/**/*.jsonl`, `audit*.jsonl`, `.audit-key`) |

Discovery prefers `~/Library/Application Support/Claude` over its `claude-code-sessions` child, because three of the highest-value stores are **siblings** of that directory — not children of it.

## Artifact coverage

| Artifact | Status | Why it matters |
|----------|--------|----------------|
| `~/.claude/history.jsonl` | Parsed | Fast prompt history for intent, suspicious questions, credential pasting. |
| `~/.claude/projects/**/*.jsonl` | Parsed | Full prompts, responses, tool-use, attachments, file-history snapshots, model/token data, sidechains, workspace. |
| `settings.json`, `.mcp.json` | Parsed | Model and permission posture, allow/ask/deny rules, lifecycle hooks, status-line command, and MCP definitions. Environment/header/query secret values are excluded; configuration does not prove execution. |
| `CLAUDE.md`, `MEMORY.md`, `skills/`, `plugins/`, `plans/`, `tasks/`, `todos/` | Hashed inventory | Instruction, memory, extension, plan, and task context with path, size, mtime, and bounded SHA-256. |
| `file-history/`, `backups/.claude.json.backup*` | Hashed inventory | Physical file revisions and raw state backups. Backup rows link to the expected current `~/.claude.json` source. |
| `.credentials.json` | Excluded-content inventory | Path, size, and mtime only. The file is never opened or hashed. |
| `~/.claude.json` and `.claude.json.backup*` | Parsed | Per-project last session, lastStartTime, cost, trust-dialog, allowed tools, MCP (env values redacted), Remote Control flag, account identifiers. Sits next to `~/.claude`, not inside it. Workspaces that exist only in a backup become `project_removed`. |
| `claude-code-sessions/**/local_*.json` and Cowork `local-agent-mode-sessions/**` | Parsed metadata, recursive transcripts, audit rows | Isolated Cowork sessions instead of assuming every transcript lives in `~/.claude/projects`. |
| `deleted_<session-uuid>` tombstone | Parsed | Dated proof a conversation existed and was removed. |
| `pending-uploads/` | Inventory-only | Files staged for upload. Content is never read. |
| `plan-usage-history.json` | Parsed (derived) | Contiguous “application in use” windows. |
| `scheduled-tasks.json`, `git-worktrees.json` | Parsed | Unattended agent runs, and workspaces with last-seen times. |
| `bridge-state.json` | Parsed | Remote Control: local session linked to a claude.ai session, consent flag. |
| `claude_desktop_config.json`, `config.json` | Parsed | Trusted folders, remote folder grants, Cowork security prefs, MCP servers (env values redacted). |

## Stores that outlive the conversation {#claude-desktop-state-artifacts}

These answer questions the transcripts cannot, because they persist after a chat is removed.

**Deleted conversations leave a dated tombstone.** Under `claude-code-sessions/<account>/<org>/`, a removed session is replaced by a file named `deleted_<session-uuid>` whose entire 13-byte content is the **epoch-ms deletion time**. The filename is the session id; the content is when it went. It does **not** recover the conversation. The row timestamp is the deletion — not the conversation’s own activity. Filter **RecordType** = `session_deleted` first on any Claude Desktop import.

**Staged attachments outlive the chat.** `pending-uploads/` holds files named `<uuid>-<epoch_ms>_<original name>`. They can evidence that a document or screenshot was sent to the assistant long after the chat is gone. IRFlow inventories path, size, and the timestamp from the filename; **file content is never read**. Preserve the bytes separately. **RecordType** = `pending_upload`.

**Usage samples give a presence timeline.** `plan-usage-history.json` records a sample roughly every five minutes while the app is open. IRFlow collapses them into contiguous windows, splitting on a gap wider than the sampling interval. Those windows are *derived* from sample spacing, not recorded session boundaries.

Also collected: `scheduled-tasks.json` (agent runs configured to fire without user interaction — treat as an automation/persistence surface) and `git-worktrees.json` (working directories with last-seen timestamps).

::: tip Point the scan at the app-support folder
`pending-uploads/`, `plan-usage-history.json`, and `git-worktrees.json` are **siblings** of `claude-code-sessions`. Select `~/Library/Application Support/Claude` (or `%APPDATA%\Claude`) to reach everything. Selecting `claude-code-sessions` alone still finds the tombstones — it cannot see its siblings, because a scan never walks up out of the folder you authorized.
:::

## How to import

**Claude Code**

1. **File → Open…** and select the `.claude` folder, or **Tools → Analysis → AI Artifacts → AI Apps → Claude Code…**
2. Dragging multiple `*.jsonl` files from the same `.claude` tree consolidates into **one** tab.
3. Opening `history.jsonl` or `~/.claude.json` directly uses the AI history parser — not the generic CSV importer. Collect AI Artifacts on This Mac picks up `~/.claude.json` as its own Claude Code root so a scan aimed at `~/.claude` does not have to walk up.
4. A relocated `CLAUDE_CONFIG_DIR` is accepted when supplied as the evidence root. Generic folders named `projects` are not treated as Claude roots.

**Collect everything (CLI + Desktop)**

Use **Collect AI Artifacts** and pick **This Mac** or a triage folder. Discovery already prefers the Claude app-support parent so transcripts are not parsed twice.

**Subagents:** **File → Open** on a `.claude` folder skips `subagents/` by default. The AI Apps picker asks whether to include them (Claude `subagents/` folders and inline sidechains).

## Limitations

- `history.jsonl` and session files may overlap; both are extracted, then identical prompts are collapsed.
- Deletion tombstones prove a conversation existed and when it was removed. They do not recover content.
- `pending-uploads/` rows are inventory only.
- App-usage windows are derived from sample spacing, not recorded session boundaries.

## See also

- [AI Query History overview](/dfir-tips/ai-query-history)
- [ChatGPT / Codex](/dfir-tips/ai-apps/chatgpt-codex)
- [AI Artifacts](/features/ai-artifacts)
