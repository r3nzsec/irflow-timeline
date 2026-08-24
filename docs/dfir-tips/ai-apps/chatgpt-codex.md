---
description: ChatGPT Desktop, OpenAI Codex, and ChatGPT Computer History (Skysight) forensic artifacts — conversation stores, rollout JSONL, and macOS interaction telemetry.
---

# ChatGPT / Codex

Three related families share this page:

| Family | What it is | Tab |
|--------|------------|-----|
| **ChatGPT Desktop / Atlas** | Local conversation stores (LevelDB, SQLite, v2/v3 bundles) | AI Query History |
| **OpenAI Codex** | CLI/Desktop rollouts under `~/.codex` | AI Query History |
| **ChatGPT Computer History** | macOS interaction telemetry (Skysight) | Own 54-column tab |

Back to [AI Query History](/dfir-tips/ai-query-history).

## ChatGPT Desktop / Atlas

| Platform | Typical path |
|----------|----------------|
| macOS | `~/Library/Application Support/com.openai.chat/` |
| macOS (Atlas) | `~/Library/Application Support/OpenAI/Atlas/` |
| Windows (standalone) | `%AppData%\Roaming\OpenAI\ChatGPT\` |
| Windows (MS Store) | `%LocalAppData%\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\` |
| Linux | `~/.config/com.openai.chat/` |

ChatGPT stores vary by version:

- **LevelDB** (`Local Storage/leveldb/*.ldb`) — conversation titles and timestamps (role `conversation`).
- **SQLite** — full user/assistant message bodies when the app version writes them locally.
- **Conversation bundles** — `conversations-v2-*` and `conversations-v3-*/*.data`, including project stores, become **inventory-only** rows (UUID, generation, project/store context, size, path). Message bodies are not decoded.

Newer builds may keep full chat text cloud-only — local LevelDB may contain titles and timestamps only.

### How to import

1. **File → Open…** and select the app data folder, or **Tools → Analysis → AI Artifacts → AI Apps → ChatGPT Desktop…**
2. Selecting multiple `.ldb` / SQLite files from the same ChatGPT data folder merges into **one** tab.
3. Hidden folders under `Library/Application Support` are visible in the open dialog by default.

## OpenAI Codex

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
| `state*.sqlite` plus WAL/SHM | Thread, spawn-edge, and dynamic-tool metadata |
| VS Code-family `agentSessions.model.cache` | Embedded Codex provider evidence when rollouts are sparse |

The macOS **Codex** app in `~/Library/Application Support/Codex` is UI cache only. Forensic content is under **`~/.codex`**.

Versioned `state*.sqlite` stores are snapshotted with their WAL/SHM companions. Full transcripts remain in rollout JSONL.

### How to import

1. **File → Open…** and select `~/.codex`, or **Tools → Analysis → AI Artifacts → AI Apps → OpenAI Codex → Codex AI History…**
2. Imports `history.jsonl` plus all `rollout-*.jsonl` under `sessions/` and `archived_sessions/` (deduped against session prompts).
3. Forked threads (`parent_session_id`) are skipped unless you include subagents.

## ChatGPT Computer History (Skysight) {#chatgpt-computer-history-skysight}

::: tip Separate artifact class
Computer History is **not** conversation history. It is OS-level user-activity telemetry — focus, clicks, keystrokes, selections, drags, window and URL context — so it opens in its **own tab** with a dedicated 54-column schema.
:::

Computer History is an opt-in macOS feature of the ChatGPT desktop app (August 2026 replacement for the Chronicle research preview). It is **off by default**, requires Memories, is limited to Pro/Business/Enterprise plans, and is not available in the EEA, Switzerland, or the UK.

It does **not** capture screenshots, screen recordings, microphone, system audio, or private-mode browsing. Everything on disk comes through the macOS Accessibility API, which is why capture depth varies so much between applications.

Two acquisition properties matter. Raw events are uploaded to OpenAI for summarisation, so the local stream is not the only copy. And the local files are **plain text and unencrypted** — any process running as the same macOS user can read them.

### Canonical artifact paths

| Artifact | Path | Retention |
|----------|------|-----------|
| **Raw event stream** | `~/Library/Group Containers/2DC432GLL2.com.openai.sky.CUAService/Library/Caches/ComputerUse/Skysight/segments/<YYYY-MM-DDTHH-MM-SSZ>/events.jsonl` | Advertised **~48 hours** while the recorder is running. A **stopped** recorder can leave segments on disk longer — measured: 90 buckets still present 3 days after the last write |
| **Segment metadata** | `…/segments/<bucket>/metadata.json` | with its segment |
| **Activity summaries** | `~/.codex/memories/extensions/skysight/resources/<ts>-<4char>-(10min\|6h)-*.md` | until the user clears them |
| **Summariser instructions** | `~/.codex/memories/extensions/skysight/instructions.md` | persistent |
| **Consolidated memory** | `~/.codex/memories/{memory_summary.md,MEMORY.md,raw_memories.md}`, `~/.codex/memories_*.sqlite` | **indefinite** — not cleared with Computer History |
| **Memories git repository** | `~/.codex/memories/.git` | persistent |
| **Feature state** | `~/.codex/config.toml` → `[plugins."computer-history@openai-bundled"] enabled` | persistent |
| **Computer Use agent approvals** | `…/CUAService/Library/Application Support/Software/ComputerUseAppApprovals.json` — **not** the recording scope | persistent |
| **Analytics store** | `…/CUAService/Library/Application Support/Software/Analytics.db` | uploaded then cleared |
| **Device pseudonyms** | `~/Library/Preferences/com.openai.sky.CUAService.plist`, `com.openai.chat.plist` | persistent |
| **Account binding** | `~/Library/Preferences/com.openai.chat.RemoteFeatureFlags.<account-uuid>.plist` | persistent |
| **Statsig account cache** | `~/Library/Preferences/com.openai.chat.StatsigService.plist` — email, user id, account UUID, **no tokens** | persistent |
| **Plugin cache** | `~/.codex/plugins/cache/openai-bundled/computer-history/<version>/.codex-plugin/plugin.json` | persistent |
| **Helper app / IPC** | `~/.codex/computer-use/Codex Computer Use.app`, `…/CUAService/IPC/computeruse.sock` | persistent |

Segment directories are fixed **10-minute UTC buckets**. A closed `metadata.json` carries `startedAt`, `endedAt`, `eventCount`, `suppressedEventCount`, `id`, and `eventsPath` — the original home directory recorded at capture time.

The **currently open** bucket carries only `id`, `startedAt`, and `eventsPath`. On a live acquisition the newest one or two buckets look incomplete — that is normal. Exclude them from count reconciliation rather than scoring a shortfall.

### Event kinds

`session.started` · `session.ended` · `window.changed` · `mouse.click` · `mouse.context_menu` · `mouse.drag` · `selection.changed` · `keyboard.text_input` · `keyboard.submit` · `keyboard.shortcut` · **`terminal.value_changed`**

`terminal.value_changed` was missing from the 1.0.10/1.0.11 catalog. It is the visible terminal scrollback (`keyboard.target.value`) emitted when macOS **Secure Input Mode** blocks keystroke capture — typically an SSH/sudo/rsync password prompt. The typed password is **not** in the payload. The command that opened the prompt **is**. Some records start with `[truncated to visible range]`: that is the on-screen AX slice, not the full scrollback. Window titles like `ssh` / `Default (ssh)` mark an SSH session.

Each event may carry the frontmost app, window title and URL, accessibility target, typed or selected payload, drag origin **and** destination, and an `ax` block.

`mouse.modifiers` records the modifier held during a click or drag. A `command`-click on an `AXLink` opens that link in a **background tab**. It shares the `KeyChord` column with keyboard chords.

`app.secureInput` is `true` when macOS **Secure Input Mode** is engaged (a password field holds focus anywhere on the system). It is a stronger credential signal than the `AXSecureTextField` subrole alone.

### What IRFlow extracts

Rows land in a dedicated schema, not the AI Query History columns.

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

`EventClass` is what the user did (typing is `Input` wherever it happens). `AppClass` is where it happened. Filter typed content on `EventClass = Input`.

### Investigation value

| Question | Where to look |
|----------|---------------|
| Did the subject enter credentials? | `TargetSubrole = AXSecureTextField` or `app.secureInput`, surfaced as `Activity: Credential Entry` / `Password Prompt`. Proves a password was entered — **not** what it was. |
| Which files were selected? | `SelectedItems` / `SelectedItemRoles` — Finder row selections. |
| Where did data move? | `mouse.drag` with `DestAppName` / `DestTargetLabel` / `DestContent`. |
| What commands were run? | `EventKind = terminal.value_changed` (`Content` = visible buffer) and Terminal `keyboard.*` rows. Emulators also expose scrollback as `AXTextArea` on other kinds. Filter `Activity` for `SSH Session` / `Terminal Buffer`. |
| What was searched for? | `TargetSubrole = AXSearchField`. After the 48h purge, terms often survive in `summary.profile`. |
| Background-tab opens? | `KeyChord = command` on `mouse.click` against `AXLink`. |
| Double-click? | `Activity = Double-Click`; exact multiplicity is in `ClickCount`. |
| Recording paused or cleared? | `Configuration` and `Integrity` rows. |
| Who owns this host? | `Identity` rows — see attribution below. |

### Field notes from live analysis

These were measured against a live capture, not inferred.

**Raw events are advertised as a ~48 hour rolling window. Collect early anyway.** The purge is performed by the live recorder. A **stopped** recorder can leave the last segments on disk well past 48 hours (measured: 90 buckets from a 36-hour capture still present three days after the last write). On a truly stale image the derived summaries and `~/.codex/memories/` are still the copies that outlive a running purge. Summaries are model-generated interpretation and self-redact.

**A credential row is not a recovered password.** Secure Input Mode blocks the recorder’s event tap. Keystrokes are consumed (event ids advance) but never written. Measured across 5,370 events: zero text-bearing `keyboard.text_input` records under Secure Input. Read the row as *a password was entered here, at this time, into this field, in this app*. `app.secureInput: true` also fires on password prompts with no `AXSecureTextField` subrole. `selection.selectedText` on a secure field is a run of U+2022 bullets — length only, never the value.

**`ScreenText` is not always a snapshot.** `AxMode = fullTree` is a snapshot; `diffFromPrevious` is only what changed. Diffs dominate.

**Capture depth is a property of the UI toolkit, not the app category.** `FidelityTier` is resolved once per application from its largest full-tree capture. Measured: Telegram 144 characters (window labels) vs Slack 53,590 characters (channel bodies). Check `AxLength` for the bundle in *your* capture.

**`EventId` gaps are not a suppression count.** Only `metadata.suppressedEventCount` is authoritative about suppression.

**`EventId` resets to 1 on every recorder restart.** Split the capture at each `session.started`, then test continuity *within* a run. Across a restart boundary, id continuity cannot assess deletion. A missing bucket with an unbroken id chain is idle time, not deletion.

**`metadata.eventCount` is a usable integrity anchor.** A shortfall against well-formed records present is consistent with the app’s “clear last 10 minutes / hour / day” control.

**Activity is consolidated into `~/.codex/memories/`.** That copy is **not** purged at 48 hours and **not** cleared with Computer History. IRFlow collects `[skysight memory]`-tagged lines and blocks citing a Skysight resource as `memory.consolidated` rows.

A summary file is not one statement:

- **`Recording summary`** — what happened inside the window.
- **`Relevant prior context`** (`summary.priorcontext`) — carried in from *earlier* windows. Do not date evidence from it.
- **`Important non-obvious context about the user`** (`summary.profile`) — model-written dossier. Survives the raw purge. Corroborate; it is inference.

**`~/.codex/memories/` is a git repository.** Summaries cleared through the UI remain recoverable from git, timestamped. Recovery requires `git` on the examination host.

**Do not read recording scope from `ComputerUseAppApprovals.json`.** That file belongs to the separate Computer Use *agent* feature. On one live host it listed one bundle against 38 actually recorded, with an mtime predating Computer History. Treat recording scope as unknown unless you can evidence it from the account side.

**Computer Use and Computer History are independent.** `[plugins."computer-history@openai-bundled"] enabled = true` can coexist with `[mcp_servers.computer-use] enabled = false`. Shared CUAService container and helper app do not mean the agent was driving the Mac.

**Observation allow/block lists** are managed through Computer History MCP tools (`computer_history_get_settings`). The vendor skill implies a settings document on disk; a live host search did not find a standalone JSON/plist for it. Continue to treat recording scope as **unknown** from disk, not as “account-only so it cannot exist locally.”

### Attribution — four different UUIDs

| Identifier | Location | What it identifies |
|------------|----------|--------------------|
| **Account UUID** | `com.openai.chat.RemoteFeatureFlags.<uuid>.plist` **filename** | The ChatGPT account. Two such files mean two accounts used the host. |
| **Statsig account cache** | `com.openai.chat.StatsigService.plist` | Email, user id, account UUID, paid-plan flag. **No tokens.** Survives `auth.json` expiry. |
| **Signed-in identity** | `~/.codex/auth.json` → `id_token` claims | Email, name, plan, org. **Holds live bearer and refresh tokens.** |
| **`distinct_id`** | `Analytics.db` | The recorder install. Cite this in a vendor request. |
| **Statsig `stableID`** | `com.openai.sky.CUAService.plist`, `com.openai.chat.plist` | Per-app device pseudonym — several of these are one machine. |
| **`installation_id`** | `~/.codex/installation_id` | The Codex (Electron) install — a different namespace. |

Codex conversation ids are **UUIDv7**, so the id encodes a creation timestamp. Threads flagged `codex-writing-block-deleted-thread-v1:` are deleted conversations — the prompt typed into them is often still in the event stream.

::: warning Analytics.db expectations
The local analytics table is uploaded then cleared, and freed pages are zeroed. Expect it **empty** on anything but a fast live acquisition. Treat absence as normal, not as proof the feature was unused.
:::

### How to import

1. **Tools → Analysis → AI Artifacts → AI Apps → OpenAI Codex → ChatGPT Computer History…**
2. Pick a `segments/` directory, `skysight/resources/`, a `.codex` folder, a CUAService group container, or a triage root that contains either.

This is **not** conversation history. It opens in its own tab.

## See also

- [AI Query History overview](/dfir-tips/ai-query-history)
- [v1.0.10 — Computer History](/blog/v1.0.10-computer-history)
- [v1.0.11 — Computer History verified](/blog/v1.0.11-computer-history-verified)
- [AI Artifacts](/features/ai-artifacts)
