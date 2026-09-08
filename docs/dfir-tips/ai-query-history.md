---
description: AI Query History overview — collect local AI assistant artifacts into a forensic timeline, then open the per-app guides for Claude, ChatGPT/Codex, Grok, Cursor, and Gemini.
---

# AI Query History and AI App Artifacts

IRFlow Timeline turns local AI assistant stores into timeline evidence. **Collect AI Artifacts** (or a single **AI Apps** import) parses desktop, CLI, and editor-assistant history into one **AI Query History** tab so you can review prompts, responses, tool calls, workspaces, source files, and possible pasted secrets.

This page is the high-level workflow. Per-app artifact paths, parser coverage, and caveats live in the guides below.

| Guide | What it covers |
|-------|----------------|
| [Claude Desktop](/dfir-tips/ai-apps/claude-desktop) | Claude Code CLI, Desktop/Cowork sessions, deletion tombstones, staged uploads, usage windows |
| [ChatGPT / Codex](/dfir-tips/ai-apps/chatgpt-codex) | ChatGPT Desktop/Atlas, OpenAI Codex rollouts, and ChatGPT Computer History (Skysight) |
| [Grok AI](/dfir-tips/ai-apps/grok-ai) | Grok Build sessions, search index, app log, and stores that outlive a deleted chat |
| [Cursor](/dfir-tips/ai-apps/cursor) | Agent transcripts, composer/workspace SQLite, and `conversation-search.db` |
| [Gemini](/dfir-tips/ai-apps/gemini) | Gemini CLI chats, shell history, checkpoints, and nested subagents |

For the product overview, see [AI Artifacts](/features/ai-artifacts).

::: tip v1.0.11
Grok Build and Claude Desktop stores that sit **outside** the session tree are now collected — search indexes, deletion tombstones, staged uploads, and usage windows. Computer History claims were re-checked against a live capture. Details are on the [Grok](/dfir-tips/ai-apps/grok-ai), [Claude](/dfir-tips/ai-apps/claude-desktop), and [ChatGPT / Codex](/dfir-tips/ai-apps/chatgpt-codex#chatgpt-computer-history-skysight) pages.
:::

## What AI Query History is

IRFlow collects more than prompts. A typical row can carry the user or assistant message, invoked tools, exact shell commands, session IDs, workspace/cwd, source file, model, and endpoint user/host when the collection path exposes them.

That is what makes the tab usable as evidence: did someone paste credentials, ask for help with suspicious commands, generate code in a sensitive workspace, or receive output that exposed secrets?

`Tool` is the AI app family (Claude Code, OpenAI Codex, Grok Build, Cursor). `InvokedTool` is a tool/action **inside** that app (a shell command, editor operation, or model tool call). `Summary` is the grid preview. `FullText` retains the parser body for a single-app import; merged worker imports bound very large bodies to 8 KiB per row and report every truncation in extraction coverage.

## Supported apps

| App | Status | Guide |
|-----|--------|-------|
| **Claude Code / Desktop** | Parsed — CLI JSONL, Desktop/Cowork transcripts, deletion tombstones, staged uploads | [Claude Desktop](/dfir-tips/ai-apps/claude-desktop) |
| **OpenAI Codex** | Parsed — `history.jsonl`, rollout JSONL, versioned `state*.sqlite` | [ChatGPT / Codex](/dfir-tips/ai-apps/chatgpt-codex) |
| **ChatGPT Desktop / Atlas** | Parsed LevelDB/SQLite when present; v2/v3 bundles inventoried only | [ChatGPT / Codex](/dfir-tips/ai-apps/chatgpt-codex) |
| **ChatGPT Computer History** | Separate 54-column tab — OS interaction telemetry, not chat | [ChatGPT / Codex](/dfir-tips/ai-apps/chatgpt-codex#chatgpt-computer-history-skysight) |
| **Grok Build** | Parsed sessions plus search index, app log, and open-session record | [Grok AI](/dfir-tips/ai-apps/grok-ai) |
| **Cursor** | Parsed transcripts, composer/workspace SQLite, conversation search index | [Cursor](/dfir-tips/ai-apps/cursor) |
| **Gemini CLI** | Parsed JSONL chats, shell history, checkpoints, nested subagents | [Gemini](/dfir-tips/ai-apps/gemini) |
| **GitHub Copilot** | Parsed CLI sessions and VS Code-family `chatSessions/` | below |
| **Windsurf** | Parsed VS Code-family chat stores; Cascade `.pb` inventory-only | below |
| **Continue** | Parsed `~/.continue/sessions/*.json` | below |

Evidence is one of **parsed history** (rows in the grid), **inventory-only** (detected, bodies not decoded), or **browser hints** (collect the browser profile separately).

## Collect AI Artifacts

![Tools → Analysis → AI Artifacts with Collect AI Artifacts, nested OpenAI Codex / ChatGPT Computer History, and Grok Build](/dfir-tips/Tools-Menu-AI-Artifacts.png)

**Tools → Analysis → AI Artifacts → Collect AI Artifacts** merges every discovered store into one tab.

![Collect AI Artifacts target picker — This Mac or Browse folder for KAPE/triage collections](/dfir-tips/Collect-AI-Artifacts-Target.png)

1. **This Mac** — the logged-in analyst profile.
2. **Browse folder…** — KAPE output, triage packages, mounted disks, or any tree with `Users\` / `home/` layouts. IRFlow matches Windows, Linux, and macOS paths **inside** the folder you pick.

After discovery, choose **main sessions only** (faster triage) or **include subagents**. The activity log shows per-source status, files read, and row counts.

After the tab opens, use **Tools → Export → View AI Extraction Coverage** for the durable per-source ledger. It distinguishes parsed, empty, partial, malformed, unsupported, excluded, and unavailable sources, shows row-cap and parse-error state, identifies credential stores inventoried without copying values, and states the Grok Bot attachment-recovery scope.

Use a single **AI Apps** entry when you already know the root (`.claude`, `.codex`, `.grok`, `.cursor`, `.gemini`). **File → Open…** on those folders does the same thing.

**Empty collection:** the modal lists expected paths and flags `Users\` / `home/` trees that have no AI stores. **Stale app session:** if discovery falls back to an older IPC channel, quit and restart so preload loads `discoverAiHistoryProfile`.

## Other supported apps

These stay on the merged timeline and do not have a dedicated guide yet.

| App | Typical path | Notes |
|-----|--------------|-------|
| **GitHub Copilot CLI** | `$COPILOT_HOME` or `~/.copilot/` | Sessions, command history, plans/checkpoints, safe `session-store.db` metadata. Auth/MCP secrets are excluded. |
| **GitHub Copilot (VS Code)** | `Code/User/workspaceStorage/<hash>/chatSessions/` | Also Insiders, VSCodium, and `emptyWindowChatSessions`. |
| **Windsurf** | `Windsurf/User/workspaceStorage/*/state.vscdb` | Cascade `.pb` bundles are inventoried, not decoded. |
| **Continue** | `~/.continue/sessions/*.json` | Local prompts/responses mapped to the workspace directory. |

Import from **Tools → Analysis → AI Artifacts → AI Apps → GitHub Copilot / Windsurf / Continue**.

## AI Secret Hunt

On an **AI Query History** tab, **Tools → Detection → AI Secret Hunt** scans prompts, responses, and tool output for API keys, tokens, private keys, and high-confidence secrets. Findings are **redacted by default** — cleartext is never written to disk.

![Tools → Detection with AI Secret Hunt enabled on an AI Query History tab](/dfir-tips/Tools-Menu-Detection-AI-Secret-Hunt.png)

![AI Secret Hunt results with grouped findings, severity, and redacted previews](/dfir-tips/AI-Secret-Hunt-Results.png)

## Export for reporting {#export-for-reporting}

**Tools → Export → Export AI History Package…** writes:

| File | Purpose |
|------|---------|
| `<tab>_timeline.csv` | Current grid rows (filters, sort, visible columns). **FullText** is always included. |
| `manifest.json` | Source path, row count, size, mtime, SHA-256 (first 250 eligible files hashed), plus the extraction coverage ledger, failures, caps, and remaining-source inventory |
| `README.txt` | Short description of the bundle |

**Export Source Manifest (sources only)** writes the inventory without the timeline CSV.

## Investigation tips

- Filter **InvokedTool** for `Shell` / `Bash`, then read **ToolCommand** (exact command) and **ToolInput** (cwd, timeout, permissions). Treat those columns as evidence.
- Filter **Role** = `user` for prompts; `assistant` for model replies.
- Merged scans retain each source occurrence. Matching text across tools is linked through **AlsoInTools** without deleting either source row.
- **Workspace** correlates to repos and production paths. **User** / **Host** come from `Users\<name>\` or a KAPE host folder when present.
- **Row Detail → Filter session** / **Correlate path** jumps to open Prefetch, EVTX/Sigma, or Amcache tabs.

## Safeguards

- Profile extracts run in a worker, are cancellable, and stop at **3,000,000** rows.
- Malformed JSONL lines are skipped and counted in the import notice.
- Browse-folder scans stay **inside** the folder you authorized.
- Paths come from in-app pickers and the path-authorizer allow-list.

## Limitations

- **Summary** is truncated for the grid. Merged imports also bound exceptionally large **FullText** values to 8 KiB; the import notice, coverage view, and export manifest disclose the affected row count. Use **Open source** for the original bytes.
- Browser-only ChatGPT, Claude, Grok, Copilot, or Gemini usage is hint-only; collect the browser profile separately.
- Consumer Grok web/mobile is not a native store.
- Official Gemini **desktop** app is not parsed — only Gemini CLI.
- ChatGPT `conversations-v2-*` / `v3-*` bundles are inventoried, not decoded.

App-specific caveats (Computer History retention, Claude tombstones, Grok `memtrace/`, Cursor search indexes) are on the per-app pages.

## See also

- [AI Artifacts](/features/ai-artifacts)
- [Supported Formats](/getting-started/supported-formats)
- [KAPE Triage Workflow](/dfir-tips/kape-triage-workflow)
- [Export and Reports](/workflows/export-reports)

## Relocated sections

Older links that pointed at headings on this page now live on the per-app guides:

- <span id="chatgpt-computer-history-skysight"></span>[ChatGPT Computer History (Skysight)](/dfir-tips/ai-apps/chatgpt-codex#chatgpt-computer-history-skysight)
- <span id="claude-desktop-state-artifacts"></span>[Claude Desktop state artifacts](/dfir-tips/ai-apps/claude-desktop#claude-desktop-state-artifacts)
- <span id="runtime-stores-outside-the-session-tree"></span>[Grok runtime stores outside the session tree](/dfir-tips/ai-apps/grok-ai#runtime-stores-outside-the-session-tree)
