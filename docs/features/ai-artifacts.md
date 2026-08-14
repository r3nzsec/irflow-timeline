---
description: AI Artifacts in IRFlow Timeline - extract local AI assistant history, prompts, tool calls, workspaces, source files, and possible secret exposure into forensic timeline evidence.
---

# AI Artifacts

AI Artifacts turns local AI assistant history into timeline evidence. It helps investigators answer practical incident-response questions: did a user paste credentials into an AI tool, ask for help with suspicious commands, generate code in a sensitive workspace, expose API keys in a prompt, or run an AI assistant during the incident window?

The feature creates an **AI Query History** timeline tab from local desktop, CLI, and editor-assistant stores. Each row keeps the evidence context analysts need: timestamp, role, AI app, invoked action, session, workspace, source file, summary, full text, and endpoint attribution when available.

::: tip Expanded in v1.0.8
**Grok Build is now a native evidence source.** IRFlow also adds recursive Claude Desktop/Cowork transcript and audit parsing, version-aware Codex SQLite discovery with WAL/SHM acquisition, and bounded JSONL/tool evidence that preserves exact shell commands without allowing one oversized record to exhaust Electron memory.
:::

## Opening AI Artifacts

- **Menu:** **Tools → Analysis → AI Artifacts → Collect AI Artifacts**
- **Per-app import:** **Tools → Analysis → AI Artifacts → AI Apps → …** (Claude Code, Codex, Grok Build, ChatGPT Desktop, Gemini CLI, Cursor, Copilot, Windsurf, Continue)
- **Home launcher:** **Collect AI Artifacts** tile on the capability launcher
- **Single artifact:** **File → Open…** on a supported AI app folder or file
- **Output:** one **AI Query History** timeline tab

![Tools → Analysis → AI Artifacts with Collect AI Artifacts and the AI Apps submenu](/dfir-tips/Tools-Menu-AI-Artifacts.png)

Use **Collect AI Artifacts** for live Mac triage, KAPE collections, mounted disks, copied profile folders, or external triage packages. Use **AI Apps** or **File → Open…** when you already know the specific AI artifact root, such as `.claude`, `.codex`, `.grok`, `.cursor`, `.gemini`, or a supported app data directory.

![Home capability launcher with Collect AI Artifacts shortcut](/dfir-tips/Home-Capability-Launcher-v107.png)

## What It Captures

| Evidence | Why it matters |
|----------|----------------|
| User prompts | Shows user intent, pasted data, searched commands, and questions asked during the incident window. |
| Assistant responses | Preserves generated commands, code, explanations, and possible operational guidance. |
| Invoked tools or actions | Captures shell/editor/model tool calls when the AI app records them locally. |
| Session metadata | Groups prompts and responses into conversations for timeline review. |
| Workspace paths | Connects AI activity to repositories, production directories, mounted evidence, or sensitive project paths. |
| Source files and line hints | Lets analysts trace a row back to the original local artifact. |
| User and host attribution | Helps map AI activity back to an endpoint profile or KAPE collection path. |
| Possible secrets | Review with **Tools → Detection → AI Secret Hunt** for exposed keys, private keys, tokens, and credentials. |

## Supported AI Apps

IRFlow scans local artifacts from these AI apps:

| App | Local evidence handled |
|-----|------------------------|
| **Claude Code** | CLI history and project JSONL transcripts under `.claude`. |
| **Claude Desktop** | `claude-code-sessions` metadata plus recursive Cowork `local-agent-mode-sessions` transcripts and audit trails. |
| **OpenAI Codex** | `history.jsonl`, current/archived rollout JSONL, session indexes, and versioned `state*.sqlite` thread/subagent/tool metadata. |
| **Grok Build** | Timestamped prompts, responses, exact tool inputs, shell completions, session metadata, and file-hunk records under `.grok`. |
| **ChatGPT Desktop / Atlas** | Local LevelDB and SQLite stores plus v2/v3 conversation-bundle metadata inventory. |
| **Gemini CLI** | Current JSONL chats, nested subagent sessions, exact shell history/tool commands, and legacy session data under `.gemini`. |
| **Cursor** | Agent transcripts, composer/workspace SQLite chat stores, and `conversation-search.db` indexed bodies. |
| **GitHub Copilot** | Copilot CLI sessions, exact command history, plans/checkpoints, safe session-store metadata, and VS Code-family chat sessions. |
| **Windsurf** | VS Code-family workspace/global chat stores and Cascade inventory. |
| **Continue** | Local session JSON files under `.continue`. |

For exact paths, collection notes, and parser caveats, see [AI Query History and AI App Artifacts](/dfir-tips/ai-query-history).

## Collect Modes

### This Mac

Scans the current analyst profile using the same local paths IRFlow knows how to parse. This is useful for validating the workflow, reviewing your own workstation, or quickly checking whether AI history exists before building a collection profile.

### Browse Folder

Scans a selected folder such as a KAPE collection, copied user profile, mounted disk, or triage package. IRFlow walks common Windows, macOS, and Linux profile layouts and only reads AI roots that resolve inside the selected scope.

![Collect AI Artifacts — This Mac or Browse folder for KAPE/triage collections](/dfir-tips/Collect-AI-Artifacts-Target.png)

This scope confinement matters for incident response: a scan pointed at a collection folder should not silently read unrelated local analyst data.

## AI Secret Hunt

On an **AI Query History** tab, run **Tools → Detection → AI Secret Hunt** to review extracted history for possible sensitive data exposure. It is designed for analyst triage, not as a replacement for enterprise secret-scanning controls.

![Tools → Detection with Sigma Scan and AI Secret Hunt on an AI history tab](/dfir-tips/Tools-Menu-Detection-AI-Secret-Hunt.png)

It helps find:

- API keys and service tokens
- PEM private-key blocks
- Cloud access keys
- Credentials and connection strings
- High-confidence provider-specific secret formats

Results are **redacted by default** (cleartext is never written to disk). Analysts can reveal evidence when needed, tag findings, group by tool or session, open source rows, and export a redacted PDF/HTML exposure brief or CSV.

![AI Secret Hunt results with grouped findings, severity, and redacted previews](/dfir-tips/AI-Secret-Hunt-Results.png)

## Key Columns

| Column | Meaning |
|--------|---------|
| **Timestamp** | Best available event time for the prompt, response, tool call, or metadata row. |
| **Tool** | The AI app family, such as Claude Code, OpenAI Codex, Grok Build, Cursor, or ChatGPT. |
| **InvokedTool** | A tool/action called inside the AI app, such as a shell command or editor operation. Older saved tabs may still show the legacy `ToolName` header. |
| **ToolCommand** | Exact command value recorded for a shell/function call. Array-valued commands remain JSON so argument boundaries are preserved. |
| **ToolInput** | Original structured arguments for the tool call. Rows containing multiple calls retain a JSON array with each tool name and input. |
| **ToolDescription** | Description or purpose stored with the tool invocation, when present. |
| **Role** | User, assistant, tool, system, or metadata role. |
| **Summary** | Grid-friendly preview for scanning large timelines. |
| **FullText** | Complete message body for row detail, search, secret scan, and export. |
| **SessionId** | Conversation or transcript identifier. |
| **Workspace** | Project, cwd, repository, or folder context when available. |
| **SourceFile** | Original artifact path used to produce the row. |
| **AlsoInTools** | Other AI apps where the same prompt appeared after dedupe. |

## ChatGPT Computer History

Computer History is a separate, opt-in macOS feature of the ChatGPT desktop app. It is **not**
conversation history: it records an interaction-event stream from the host — app focus changes,
clicks, keystrokes, shortcuts, selections, drags, and the window and URL context macOS exposes
through its accessibility system — and periodically distils it into natural-language activity
summaries. It is off by default and is not available in the EEA, Switzerland, or the UK.

Because these are OS-level activity events rather than prompt/response turns, they open in their own
tab with a dedicated column set rather than the AI Query History columns.

| Artifact | Location | Retention |
|----------|----------|-----------|
| Raw event stream | `~/Library/Group Containers/2DC432GLL2.com.openai.sky.CUAService/Library/Caches/ComputerUse/Skysight/segments/<bucket>/{events.jsonl,metadata.json}` | ~48 hours, then purged |
| Activity summaries | `~/.codex/memories/extensions/skysight/resources/<ts>-<id>-(10min\|6h)-*.md` | Until the user clears them |
| Feature state | `~/.codex/config.toml`, `ComputerUseAppApprovals.json` | Persistent |

What the parser adds beyond the raw events:

- **Credential entry.** Targets carrying the `AXSecureTextField` subrole are labelled as credential
  entry. macOS withholds the field's value, but keystrokes are captured at hardware level, so typed
  characters can still reach the stream.
- **File and menu selection.** Finder row selections and menu commands are captured; these events
  carry no selected text and would otherwise appear as empty rows.
- **Capture fidelity.** Everything flows through the macOS Accessibility API, so depth varies by
  app. `FidelityTier` is resolved once per application. In Tier 3 messaging apps, outbound typed
  text is captured while inbound message content is not — such a capture is one side of a
  conversation and must not be presented as a conversation record.
- **Screen text is qualified.** `ScreenText` is only a screen snapshot when `AxMode` is `fullTree`;
  most events are `diffFromPrevious` and carry only what changed.
- **Deletion detection.** Closed segments are reconciled against their own metadata event count. A
  shortfall is reported as a derived lead consistent with the app's "clear last 10 minutes / hour /
  day" control. Summaries cleared through that control are recovered read-only from the Codex
  memories git history, with the time they were removed.
- **Gap interpretation.** A missing segment bucket is only flagged when the event-id chain is
  actually broken across it; an unbroken chain means the host was idle, not that data was deleted.
- **Attribution.** Identity rows collect the ChatGPT account, signed-in identity, and per-app device
  identifiers, each labelled with how strongly it identifies an account rather than a device. Codex
  conversations are dated from their identifiers and joined to the timeline, with deleted
  conversations flagged — the prompt typed into a deleted conversation is often still recorded in
  the event stream. No token material is stored or exported.
- **Coverage.** Feature-state rows record which apps the recorder was permitted to observe, so an
  absence of events for an app is not misread as inactivity.

## Performance and Safeguards

- Large scans run through the background extraction pipeline so the UI stays responsive.
- Folder scans are cancellable.
- Merged AI timelines cap at 3,000,000 rows and report truncation.
- Malformed JSONL lines are skipped and counted in the import notice.
- Subagent or sidechain content can be included for broader hunts, but main-session-only scans are faster for first-pass triage.
- Tool inputs can contain paths, prompts, or secrets. Treat `ToolCommand` and `ToolInput` as evidence and apply the same access controls used for full message text.
- **Tools → Export → Export AI History Package…** includes the filtered timeline CSV plus a manifest of source files and hashes for the first 250 sources.

## Limitations

- Browser-only AI usage may require browser profile collection; local desktop/CLI history is not the same as cloud account history.
- Consumer Grok web/mobile history is not decoded as a native app store. Browser history/cache may still show `grok.com` or X/Grok usage and should be collected separately.
- Grok Build credential/configuration files such as `auth.json` and `mcp_credentials.json` are deliberately excluded from timeline parsing; preserve them under appropriate evidence controls when authorization material is in scope.
- ChatGPT Desktop `conversations-v2-*` and `conversations-v3-*` bundles are inventoried, not decoded.
- Gemini macOS desktop app history is not parsed; Gemini CLI local sessions are supported.
- Proprietary Windsurf Cascade protobuf bundles are preserved as inventory unless decoders are available.
- Secret detection is intentionally conservative and should be reviewed by an analyst before reporting.
- Computer History raw events are purged after about 48 hours, so on a stale image the derived summaries are often the only surviving record — and they are model-generated interpretation, not primary evidence.
- Computer History activity summaries can be self-redacting; the generator omits content it judges sensitive, so a summary may understate what the raw events showed.
- The local ChatGPT analytics event store is uploaded and cleared, with freed pages zeroed. Expect it empty on anything but a fast live acquisition, and treat its absence as normal rather than as evidence the feature was unused.

## See Also

- [AI Query History and AI App Artifacts](/dfir-tips/ai-query-history)
- [Supported Formats](/getting-started/supported-formats)
- [KAPE Triage Workflow](/dfir-tips/kape-triage-workflow)
- [Export and Reports](/workflows/export-reports)
