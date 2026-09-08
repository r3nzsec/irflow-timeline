---
description: Grok Build and Grok Bot forensic artifacts — session transcripts, tool commands, cloud-agent local-tool requests and decisions, attachment verification, and stores that can outlive a retained transcript window.
---

# Grok AI

[Grok Build](https://github.com/xai-org/grok-build) is the terminal coding agent distributed as the `grok` CLI. Its default data root is `~/.grok` (`GROK_HOME` can override it). IRFlow parses workspace prompt history, session transcripts, file-hunk records, and three stores that sit **outside** the session tree.

**Grok Bot** is the always-on agent desktop app. Its agents run on xAI cloud "boxes" and reach back into the Mac through a local exec daemon. It is a different evidence class from Grok Build and is covered in [its own section below](#grok-bot).

The consumer Grok product (`grok.com` / X) is separate — there is no native parser for web or mobile chats. Collect browser origin data or a vendor export.

Back to [AI Query History](/dfir-tips/ai-query-history).

## Canonical paths

| Platform | Path |
|----------|------|
| all | `$GROK_HOME` or `~/.grok/` — `sessions/`, plus `sessions/session_search.sqlite`, `logs/unified.jsonl`, `active_sessions.json` |

The upstream [authentication guide](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md) documents `~/.grok/auth.json` and `~/.grok/mcp_credentials.json`. Treat both as credential-bearing evidence. IRFlow **never** copies those values into timeline rows.

## Session artifacts

| Artifact | Forensic value |
|----------|----------------|
| `sessions/<encoded-cwd>/prompt_history.jsonl` | Timestamp, session ID, prompt, and `is_bash`; direct bash entries populate **ToolCommand** exactly. |
| `<session-id>/summary.json` | Session ID/title, created/updated time, cwd, model, Git branch/commit, agent mode, sandbox profile, reasoning effort. |
| `<session-id>/updates.jsonl` | Timestamped user/assistant/reasoning chunks, tool calls (`rawInput`), completion output (`rawOutput`), stop reason, token usage. |
| `<session-id>/chat_history.jsonl` | Normalized conversation fallback when timestamped updates are absent. |
| `<session-id>/hunk_records.jsonl` | File path, added/removed lines, prompt index, hunk ID, author, event timestamp. |
| `<session-id>/terminal/call-*.log` | Parsed independently as terminal output with the native call UUID and session ID, even when the primary update stream is missing. File mtime is retained as a fallback basis, not claimed as command start time. |
| `<session-id>/events.jsonl`, `signals.json`, `prompt_context.json` | Lifecycle, performance, upload counters, and prompt context. Prompt bodies are represented by length and SHA-256 rather than copied into the context row. |
| `config.toml`, `trusted_folders.toml`, `version.json`, `agent_id` | Permission/model settings, trust decisions with `decided_at`, installed version, and local agent identity. Secret-like values are redacted; configuration does not prove execution. |
| `worktrees.db` plus WAL/SHM | Worktree path, source repo, Git ref/commit, creating session, creation/access times, status, and metadata. |
| `long-running-background-tasks/`, upload/automation state | Hashed definition/log inventory and state provenance. A script definition proves configuration; output or linked lifecycle evidence is needed to show execution. |

For a `run_terminal_command` event, IRFlow places the exact recorded `rawInput.command` in **ToolCommand**, retains structured input in **ToolInput**, and creates a related `tool_result` row with cwd, exit code, timeout/truncation flags, captured output, and terminal-log path. Failed calls use `tool_result_failed`.

## Stores that outlive the conversation {#runtime-stores-outside-the-session-tree}

Three stores live outside `sessions/<encoded-cwd>/<session-id>/` and are written independently of it. Deleting a session directory does not delete them.

| Artifact | What it gives you |
|----------|-------------------|
| `sessions/session_search.sqlite` | `session_docs` holds `session_id`, `cwd`, `title`, `updated_at` (epoch **seconds**) and the indexed transcript body, with an FTS5 index over it. It **mirrors the transcript and survives deleting the session directory**. **RecordType** = `session_search`. `last_indexed_offset` well below the body length means a partial view. |
| `logs/unified.jsonl` | `shell.tool.exec_done` records give tool name, success/failure, and duration per `sid`; turn boundaries bracket model calls. There is **no command string** here — that only lives in the session’s `updates.jsonl`. **RecordType** = `log_tool_exec`. Correlate `MessageId` (the tool call id) back to `updates.jsonl`. |
| `active_sessions.json` | `session_id` → `pid`, `cwd`, `opened_at` for sessions open at acquisition. |

::: warning `memtrace/` is not what the name suggests
`~/.grok/memtrace/*.jsonl` looks like agent memory and is not. Every record is a **memory profiler** sample (`rss_bytes`, `alloc`) — tens of megabytes with no conversation content. IRFlow does not parse it. Process-lifetime value is already covered by `active_sessions.json` and the unified log.
:::

## How to import

1. **File → Open…** and select `$GROK_HOME` or `~/.grok`, or **Tools → Analysis → AI Artifacts → AI Apps → Grok Build…**
2. IRFlow imports workspace prompt histories and session `summary.json`, `updates.jsonl` (or `chat_history.jsonl` fallback), `hunk_records.jsonl`, context/terminal evidence, and the out-of-tree stores above.
3. Subagent session folders are skipped by default unless you choose **Include subagents**.

**Collect AI Artifacts** also finds Grok roots on This Mac or inside a KAPE/triage folder.

## Limitations

- Consumer Grok web/mobile chats are not decoded as a native app store. Collect browser history/cache for `grok.com` or X/Grok separately — do not attribute a generic browser profile to Grok without origin-level evidence.
- `auth.json` and `mcp_credentials.json` remain excluded credential stores. `config.toml` and `trusted_folders.toml` are parsed with sensitive values redacted.
- `prompt_context.json` bodies are hashed rather than copied; acquire the original when the exact generated system prompt is required.
- `session_search.sqlite` requires SQLite support.
- `log_tool_exec` records *that* a tool ran, never the command. Do not present them as evidence of what was executed.
- `memtrace/` is a profiler trace and is deliberately not parsed.

## Grok Bot {#grok-bot}

Grok Bot (bundle `com.anysphere.sand`, app name "Grok Bot") splits its state between a daemon home and an Electron profile. **Tools → Analysis → AI Artifacts → AI Apps → Grok Bot…** accepts either folder and pairs the other automatically; **Collect AI Artifacts** lists both.

| Location | What it holds |
|----------|---------------|
| `~/.grokbot/settings.json` | `localToolPermission` (`always` = cloud agents run local tools without a prompt), egress tunnel, WebAuthn proxy, MCP box servers and per-server custom instructions. **RecordType** `grokbot_settings`. |
| `~/.grokbot/local-exec-daemon.json`, `local-exec-supervisor.json` | Daemon pid + `startedAt`; supervisor heartbeat. |
| `~/.grokbot/local-exec-daemon.log`, `.log.N` | Current and rotated `[tag] message` lines with **no timestamps**. Daemon starts and `[shell-exec]` lifecycle become rows ordered by `LineNumber`; everything else is aggregated into one `daemon_log_summary`. The command, request ID, exit status and result are **not** in these logs. Byte-read and detail-row omissions are reported separately. |
| `~/.grokbot/local-exec-daemon-credential.json`, `-connection.json` | Inventoried by name, size and mtime. Never read. |
| `Application Support/Grok Bot/sand-client-persistence/<base32>.blob` | Client replicas of each agent's cloud transcript. The file name is the base32 of a slice name such as `sand.client.slice.account.<account>.transcript.replicas.<agentId>`. |
| `Application Support/Grok Bot/sentry/scope_v3.json`, `session.json` | Signed-in account id **and email**, app version, macOS version, hardware, timezone, last boot and app-start time, the agent that was open. **RecordType** `app_identity`, `app_crash_reporter_session`. |
| `Application Support/Grok Bot/Local State` | Chromium profile creation stamp. This is not conclusive first-install evidence. **RecordType** `app_profile_created`. |
| `Application Support/Grok Bot/link-preview-cache/link-cache/*.json` | Cached unfurl metadata with title, site and `fetchedAt`. A cache record does not prove a user click, rendered view, or successful page access. **RecordType** `link_preview`. |
| `sand-secrets.json`, `gateway-descriptor.json`, `box-secrets-push-state.v1.json` | Inventoried, never read. |

### What a transcript replica gives you

| Entry | Row | Notes |
|-------|-----|-------|
| `message` (role `user`) | `user` | The **verbatim prompt** in `Summary`/`FullText`, with `timestampMs`, agent id in `SessionId`, request id in `ParentId`. |
| `send-message` type `text` | `assistant` | Agent reply. When it carries `images`, each screenshot's alt text (the agent's own description of what it saw on its box) is appended as `[Agent image] … — sha256 …`. |
| `send-message` type `local-tool-permission` | `local_tool_permission_request` | A cloud agent asked to act on the recorded machine. `InvokedTool` = `run-command` / `read-file`; the exact target is in `ToolCommand` or `ToolInput`. `permissionState` distinguishes pending, allowed, persistent policy, denied, expired, cancelled and unknown. A request or recorded approval does not prove receipt, execution or success. |
| `tool-call`, `notice`, structured approval cards | `tool_call`, `notice`, `*_approval` | Native status, request/reply IDs, channel/author relationships and raw payloads survive. Tool-call state remains cloud transcript evidence unless a same-scope local result is explicitly linked. |
| `send-journal` v1/v2 slice | `send_journal` | Nonce, account/agent, prompt, phase, reply/fork/session links, staged/committed attachments, and created/queued/flush/failure times. `queued`, `dispatching`, and `accepted-awaiting-echo` are not independent proof of server delivery. |
| `send-message` type `widget` | `agent_widget` | Prompt, option labels and the user's `respondedValue`. |
| `send-message` with `boxInstruction` | `agent_box_instruction` | The agent handed its box browser to the user (typically a sign-in); `boxResolution` says whether it was completed. Credentials typed there went to the box, not through the Mac. |
| `user-attachment` | `user_attachment` | See below. |
| `send-message` type `attachment` | `agent_attachment` | A file the agent sent back; `referenceSha256` from a hash-shaped box path, not independently verified content bytes. |
| `event` `automation-changed` / `name-changed` | `event_automation_changed`, `event_name_changed` | Scheduled automations are persistence that keeps running with the app closed. |

### The replica window is fixed by the app {#grok-bot-replica-window}

Retention is hard-coded in the renderer bundle (verified in Grok Bot 0.43.0, `dist/renderer/assets/index-*.js`, the `transcript.replicas` persistence slice). There is no setting, feature flag, or environment variable that changes it.

| Rule | Value | Effect |
|------|-------|--------|
| Entries per agent | last **200** | Older entries are dropped from the on-disk replica as new ones arrive |
| Serialized-entry budget per agent | **768 KiB constant**, applied to the sum of `JSON.stringify(entry).length` | A replica full of long replies or attachments can reach the limit earlier than 200; this is a JavaScript character-count budget rather than whole-file bytes |
| Replicas per account | **24** agents | The least recently persisted replica is deleted when a 25th agent is used |
| Replica age | **7 days** since `persistedAt` | Any replica not refreshed for 7 days is deleted the next time the app starts or the account is restored |
| Live fetch from the server | 500 entries for the open agent, 200 for others | In memory only; what lands on disk is still capped as above |

Consequences for acquisition:

- **Acquire the persistence folder before launching the app on the evidence machine.** A launch triggers the 7-day and 24-agent pruning.
- **Re-acquire on a schedule** on a live host you are monitoring. Each snapshot is a different 200-entry window, and IRFlow rows carry the stable entry id in `MessageId`, so snapshots can be merged without duplicates.
- **APFS local snapshots and Time Machine** of `~/Library/Application Support/Grok Bot/` are older windows of the same replicas.
- The `transcript_replica` row records source/emitted/omitted counts, `persistedAt`, serialized-entry characters, `oldestRetainedEntry`, retention-boundary state, and the current 7-day restore-TTL assessment. Exactly 200 entries establishes that the observed replica is at the entry limit; it does not prove that a specific 201st entry existed or was deleted.

Patching `app.asar` to raise the constants breaks the code signature and asar integrity check, and modifies the evidence source; it is not a viable route.

### Recovering attached files {#grok-bot-attachments}

The retained replica records a file name, byte size, image dimensions and a path on the agent's cloud box. Hash-shaped box filenames are useful recovery keys, but IRFlow labels them as references until it hashes recovered bytes independently. Staging files that still exist are inventoried without reading their contents.

IRFlow turns that into recovery:

1. `user_attachment` rows carry `referenceSha256`, `byteSize`, `boxPath`, verification status, and any independently computed local hash in `FullText`.
2. The default search stays inside the selected Grok Bot roots. Searching the owning profile's `Downloads`, `Desktop`, `Documents` and `Pictures` is opt in, bounded by directory depth/count and candidate-hash count, checks cancellation while walking and hashing, and hashes only files whose **name and size** match first.
3. A SHA-256 match is reported as `— original verified on disk: <path>` in `Summary`, the path list in `ToolInput`, `computedLocalSha256`, and `localCopyVerification: "name + size + SHA-256 match"`.

Named documents may recover this way when a matching local copy remains. For unmatched files, the row preserves the cloud reference, size, dimensions and time while clearly marking that the reference hash was not independently verified.

### Limitations

- Daemon log lines have no timestamps; only the file mtime bounds the last line.
- A requested command may be recorded in a transcript `local-tool-permission` entry, but the daemon log does not carry the command or a linking request ID. Without an explicit same-scope result, do not infer that the requested command ran from a nearby `[shell-exec]` line.
- The replica window (200 entries / 768 KB / 24 agents / 7 days) cannot be adjusted; see [above](#grok-bot-replica-window).
- Agent-side conversation content that was never synced to this client is not on disk anywhere.
- The current qualification evidence covers Grok Bot 0.43.0 storage contracts and macOS fixtures/runtime. Windows and Linux remain unqualified.
- **View AI Extraction Coverage** records every Grok Bot source status and the attachment-search scope. The exported manifest carries the same ledger; a partial source is never labelled complete.

## See also

- [AI Query History overview](/dfir-tips/ai-query-history)
- [Claude Desktop](/dfir-tips/ai-apps/claude-desktop)
- [AI Artifacts](/features/ai-artifacts)
