---
description: Gemini CLI forensic artifacts — JSONL chats, shell history, checkpoints, nested subagents, and what IRFlow does not parse.
---

# Gemini

IRFlow parses the **Gemini CLI** (the npm/agentic CLI), not the official Gemini macOS desktop app. Desktop history is mostly cloud-synced and is not decoded.

Back to [AI Query History](/dfir-tips/ai-query-history).

## Canonical paths

| Platform | Path |
|----------|------|
| macOS / Linux | `~/.gemini/tmp/<project_hash-or-slug>/chats/**/*.jsonl`, `~/.gemini/shell_history` |
| Windows | `C:\Users\<user>\.gemini\tmp\<hash-or-slug>\chats\**\*.jsonl`, `C:\Users\<user>\.gemini\shell_history` |

Also parsed when present: legacy `session-*.json`, `logs.json`, checkpoints, and 0.58+ control-plane files (`projects.json`, `settings.json` and backups, `trustedFolders.json`, `google_accounts.json`, policy files, skills, `GEMINI.md`, and `history/<slug>/.project_root`). `GEMINI_CLI_HOME` relocations are supported.

## What IRFlow extracts

| Artifact | Status | Why it matters |
|----------|--------|----------------|
| `~/.gemini/tmp/<hash>/chats/**/*.jsonl` | Parsed | Reconstructed current state plus immutable source-event history. Rewound, superseded, and `$set`-replaced messages remain recoverable with status and physical source locations. |
| `~/.gemini/shell_history` | Parsed | Exact shell-history entries, including continued multiline commands. |
| Legacy `session-*.json`, checkpoints, `logs.json` | Parsed | Older Gemini CLI layouts. |
| `projects.json`, `tmp/<slug>/.project_root`, `history/<slug>/.project_root` | Parsed | 0.58+ workspace registry. Slug directories replace hash-named tmp folders. |
| `settings.json`, backups, `policies/*` | Parsed/inventoried | Auth type, retention, Auto Memory, lifecycle hooks, MCP server definitions, tool policy, and replacement/backup provenance. Secret values are excluded. |
| `GEMINI.md`, `skills/**/{SKILL.md,json,yaml}` | Hashed inventory | Instruction, memory, and skill context with source path, size, mtime, and SHA-256. |
| `trustedFolders.json` | Parsed | Folders the CLI may act in without a further prompt. |
| `google_accounts.json`, `installation_id`, `user_id` | Parsed | Account / install identifiers. |
| `oauth_creds.json` (and MCP/A2A token files) | Inventory-only | Name and size; contents are never read. |

Current sessions are append-only JSONL. IRFlow emits the reconstructed current state and a separate `history_*` lane for every source revision, plus `history_rewind` and `history_set_messages` operation rows. Tool calls/results keep their exact source line and byte offset in both views.

## How to import

1. **File → Open…** and select the `.gemini` folder, or **Tools → Analysis → AI Artifacts → AI Apps → Gemini CLI…**
2. Current `chats/**/*.jsonl`, `shell_history`, and legacy JSON artifacts from the same `.gemini` tree consolidate into **one** tab.

**Collect AI Artifacts** also finds Gemini CLI roots on This Mac or inside a KAPE/triage folder.

## Investigation tips

- **ToolCommand** holds the exact `run_shell_command` string — treat it as evidence, the same as a shell history hit.
- Nested chat directories are subagent evidence. Start with main sessions on a large project tree.
- Filter `RecordType = history_*` to inspect revisions and rewound content; use the ordinary message/tool types for the current reconstructed conversation.

## Limitations

- Official **Gemini macOS desktop** app history is not parsed.
- Browser-only Gemini usage is hint-only; collect the browser profile separately.

## See also

- [AI Query History overview](/dfir-tips/ai-query-history)
- [Cursor](/dfir-tips/ai-apps/cursor)
- [AI Artifacts](/features/ai-artifacts)
