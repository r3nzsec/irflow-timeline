# Changelog

All notable changes to IRFlow Timeline. The macOS release workflow
(`.github/workflows/release-macos.yml`) publishes the section matching the
released version as the GitHub release notes — keep version headers in the form
`## v<MAJOR.MINOR.PATCH>`.

## v1.0.10

IRFlow Timeline 1.0.10 adds ChatGPT Computer History as a first-class forensic artifact and is a
crash-resilience update for long-running investigations.

### ChatGPT Computer History (new artifact family)

- New parser for the opt-in macOS ChatGPT "Computer History" (Skysight) feature: the raw
  interaction-event stream (`events.jsonl` segment buckets, retained ~48h) and the derived
  activity summaries under `~/.codex/memories/extensions/skysight/resources/`, which persist until
  the user clears them.
- Dedicated 54-column schema rather than the conversation-history columns, covering event class,
  app/window/URL context, accessibility target role and subrole, typed content, cross-app drag
  origin and destination, capture fidelity, segment provenance, and attribution.
- `AXSecureTextField` targets are reported as credential entry, with the caveat that macOS withholds
  the field value while the keystrokes are still captured at hardware level.
- Finder and menu item selections (`selection.selectedItems`) are captured; these events carry no
  selected text and previously produced rows with an empty payload.
- Per-keystroke input runs are coalesced into the completed field value, while terminal scrollback
  snapshots are never coalesced — including for terminal emulators absent from the app table,
  which are now recognised structurally.
- Integrity checks: closed segments are reconciled against `metadata.eventCount`, and a shortfall is
  reported as a derived deletion lead consistent with the "clear last 10 minutes / hour / day"
  control. Malformed lines are counted separately from missing records.
- Activity summaries the user cleared are recovered read-only from the `~/.codex/memories` git
  object store, with the deleting commit's timestamp.
- Attribution rows collect the ChatGPT account id (read from per-account preference filenames), the
  signed-in identity claims, the recorder and per-app device pseudonyms, and the Statsig evaluation
  cache, which extends the presence timeline well beyond the 48-hour event retention. Every
  identifier states its own attribution strength, and no token material is ever stored or exported.
- Codex conversation ids are decoded from UUIDv7 to timestamps and joined to the event timeline;
  conversations marked deleted are flagged, since the model chosen and the text typed into them are
  often still present in the event stream.
- Feature-state rows record what the recorder was permitted to observe, so an absence of events for
  an app is not misread as inactivity.

### Computer History accuracy fixes

- `EventClass` now describes what the user did rather than which app they were in. The app family
  moved to a separate `AppClass` column; previously it reclassified the large majority of input
  events away from `Input`, so filtering for typed content missed keystrokes in terminal and
  messaging apps.
- `ScreenText` is qualified by `AxMode`: `diffFromPrevious` rows carry only what changed since the
  previous snapshot and are labelled as such instead of reading as a full screen capture.
- Segment gaps are cross-checked against event-id continuity. A gap with an unbroken id chain is
  reported as an idle host rather than as a possible deletion.
- Event-id gaps are no longer described as suppressed events; only the metadata suppressed count is
  reported as authoritative.
- `FidelityTier` is resolved once per application from its largest full-tree capture instead of
  per row, so an application no longer reports different capture depths on adjacent rows.

### Worker Lifecycle Reliability

- One-shot query, import, index, analyzer, Sigma, and AI-history workers now close their parent ports after delivering a terminal result and are force-retired if they fail to exit promptly.
- Live workers remain visible to concurrency accounting until their actual exit, preventing completed worker threads and V8 isolates from accumulating during long sessions.
- Autosave bookmark snapshots use the main SQLite connection instead of creating a worker per tab every 30 seconds.
- Worker jobs now settle exactly once and fail explicitly when a worker exits without a terminal result, cannot start, or exits abnormally.

### Crash-Safe Session Recovery

- Autosaves are single-flight and serialized so slow snapshots cannot overlap.
- Session files are written through a synced temporary file and atomic rename, with the previous valid autosave retained as a recovery backup.
- Recovery validates session structure and falls back to the backup when the primary snapshot is missing or corrupt.

### Application and Resource Resilience

- Closing the macOS window now hides the live workspace instead of destroying the renderer while workers and SQLite tabs remain active; Dock activation restores that same window.
- Uncaught main-process errors, unhandled rejections, and unexpected renderer exits now trigger synchronous worker/database cleanup, diagnostic flushing, and one controlled relaunch. A 30-second guard suppresses restart loops.
- Electron's local crash reporter is enabled without uploading crash data, and child-process exits are recorded in the debug log.
- A memory-aware global worker budget now spans imports, index/FTS builds, analyzers, Sigma scans, AI-history extraction, and worker-backed queries. Heavy work has a separate ceiling, and live/queued counts are exposed through job diagnostics.

### Hayabusa Process Reliability

- Cancelling an EVTX scan now waits for the Hayabusa process to close, escalates from `SIGTERM` to `SIGKILL` when necessary, and removes temporary output only after the process has stopped writing.
- Scan registration is cleared on every success, cancellation, and error path, including cancel-before-spawn races.
- Captured Hayabusa diagnostics are capped at 256 KiB, and progress-parser failures are contained instead of reaching the Electron main process as uncaught exceptions.

### Supported Runtime

- Upgraded Electron from 33 to 43, `better-sqlite3` from 11 to 13, Electron Builder to 26, Electron Rebuild to 4, and Electron Updater to 6.8.
- Development and release automation now require **Node.js 22.14 or newer**. The `better-sqlite3` 13 prebuilt binding segfaults when a database is opened under Node 22.12 and 22.13, so those two releases are not usable for building or testing even though they satisfy the package's own `>=22` floor. The EVTX message provider is pinned to the same SQLite 13 native addon so every SQLite call uses the Electron 43 ABI.
- The packaged minimum is now explicit at macOS 12 (Monterey), matching Electron 43's supported platform floor.

## v1.0.9

IRFlow Timeline 1.0.9 is a focused reliability patch for large Windows Event Log investigations.

### Large EVTX Imports

- **Issue #22 fixed** — Raw EVTX files are no longer opened through Node's whole-file `readFile()` path, removing the 2 GiB Buffer ceiling that rejected large `Security.evtx` files before the first record was parsed.
- **Bounded native chunk parsing** — Reads the 4 KiB EVTX header once, then processes one native 64 KiB EVTX chunk at a time instead of retaining the complete source file in memory.
- **Approximately 4 GiB EVTX support** — Handles logs up to the EVTX format's 65,535-chunk limit, including the reported 4,109,438,976-byte (~3.83 GiB) file.
- **Accurate large-file progress** — Progress now follows physical EVTX chunk offsets rather than record-local offsets.

### Import Reliability

- Duplicate requests for the same pending source are suppressed while preserving distinct workbook sheets and AI-history scopes.
- Repeated identical import failures collapse into one actionable notification instead of filling the screen with duplicate toasts.
- Regression coverage exercises the exact issue #22 file size and verifies that individual reads remain bounded to 64 KiB.

## v1.0.8

IRFlow Timeline 1.0.8 significantly expands **AI application forensics**, adding deeper artifact collection and parsing across popular AI assistants.

### AI Application Forensics

- **Grok Build support (new)** — collect and analyze Grok AI prompts, responses, reasoning, exact terminal commands, tool results, session context, and file-change records.
- **Claude expanded** — recursively parse Claude Code and Claude Desktop/Cowork sessions, transcripts, audit records, tool activity, and actual shell commands.
- **Codex expanded** — recover versioned SQLite data with WAL/SHM support, dated rollout sessions, commands, tool calls, and bounded outputs.
- Improved parsing for ChatGPT Desktop, GitHub Copilot CLI, Gemini CLI, Cursor, and other supported assistants.
- Better provenance, session relationships, and AI Secret Hunt safeguards.

### Additional Improvements

- New guided workflow for importing KAPE and triage collections.
- Enhanced Process Inspector, Persistence Analyzer, and Lateral Movement Tracker.
- Improved timeline navigation, bulk actions, and evidence review.
- Memory-safe queries and bounded workers for greater stability with large datasets.
- Signed and notarized universal macOS release for Apple Silicon and Intel.

## v1.0.7

Brings **AI assistant query history** into the timeline as a first-class forensic artifact: collect it from a host or triage package, normalize every tool into one tab, and **hunt for secrets that were leaked into AI chats** — passwords, API keys, tokens, and private keys.

### AI Query History (new)

- **Collect AI Artifacts** — choose **This Mac** or **Browse folder** (KAPE / triage / mounted disk); a forensic tree scan finds Windows, Linux, and macOS user-profile layouts, attributes each row to its `Users\<user>` / `home/<user>` profile and host, and merges every source into one **AI Query History** tab with verbose progress. Available from the **Tools** menu and the startup screen.
- **Native, offline extractors — no third-party AI binary:**
  - **Claude Code** — `history.jsonl` + project session JSONL under `.claude/` (Timestamp, Role, Summary, SessionId, Model, token counts, per-user/host attribution). Opening or dropping a `.claude` folder consolidates all JSONL into one tab (fixes JSONL mis-importing as broken CSV columns).
  - **ChatGPT Desktop** — LevelDB conversation metadata + SQLite message tables.
  - **Gemini CLI** — `~/.gemini/tmp/.../chats/session-*.json` (user + model messages, token counts, reasoning flag).
  - **Cursor**, **GitHub Copilot**, **OpenAI Codex**, **Continue**, **Windsurf**, and **Claude Desktop** — chat/session stores decoded into the same unified column schema.
- **Copilot JSONL depth** — replays `kind:0`/`1`/`2`, Code Insiders, and `emptyWindowChatSessions`; flags metadata-only sessions on import.
- **Cursor workspace decode** — project slugs map to filesystem paths where possible; transcript timestamps estimated from file birth/mtime.
- **AI Apps menu** — per-brand-tinted launchers for each supported assistant.

### AI Secret Hunt (new)

- **Automated secret & credential leak detection over collected AI history** — surfaces passwords, API keys, tokens, and private keys that were pasted into AI assistants. Lives under **Detection**, beside Sigma Scan.
- **Two-stage, precision-first detector** — a ReDoS-guarded regex catalog proposes candidates, then a validation layer (format/checksum validators, Shannon entropy, and an allow-list of well-known public test values) confirms them, so the default **Quick** scan favors precision. A **Deep** toggle adds PII (emails, phone numbers, and similar).
- **Redact-by-default** — findings are masked in the UI and **cleartext is never written to disk**; reveal per-row on demand, and each match carries a salted fingerprint for dedup/correlation.
- **Threat-report results view** — a liquid-glass UI on a Unit 42–style palette with progressive disclosure: group findings **by Tool or by Session**, provider badges per finding, and confidence / leak-direction / category chips.
- **Exposure brief** — export a polished **PDF or HTML** report of the findings.

### Under the hood

- New unit coverage across every AI-history extractor (Claude Code, ChatGPT, Gemini, Cursor, Copilot, Codex, Continue, Windsurf, Claude Desktop) and the secret detector, plus the path-attribution and profile-scan helpers.

## v1.0.6

A major release: IRFlow Timeline was rebuilt into ~150 focused modules and gained a full Sigma/Hayabusa detection layer plus RDP bitmap-cache recovery.

### Sigma Detection (new)

- **Dual detection engine** — run Sigma rules over **raw `.evtx` folders** via the bundled **Hayabusa** engine (universal binary, no setup, works offline), or over **imported timelines / EvtxECmd output** via an in-app JS Sigma engine.
- **MITRE ATT&CK-mapped triage dashboard** with severity/status filtering and a reopenable **scan history**.
- Scan **presets**, **custom YAML rules**, and **noisy-rule suppression**.

### RDP Bitmap Cache (new)

- Recover bitmap **tiles and collages** from Windows `bcache*.bmc` / `cache????.bin` artifacts (bundled **bmc-tools**).
- Records source/output hashes, keeps prior extraction history, and exports an **evidence package** for reporting.

### Lateral Movement — Accounts Accuracy

- Privilege/credential counts are now **scoped to lateral-movement activity** instead of host-wide totals, so suspicion scores aren't inflated by background noise.
- **Admin-logon correlation (4624 ↔ 4672)** recovers the ADMIN signal for network logons; machine/service accounts are no longer mislabeled.
- **Per-channel Sources/Targets breakdown** (logon / explicit-cred / RDP) explains why those columns can exceed the logon count.

### Under the Hood

- Full modular refactor of the renderer and main process (~150 focused modules).
- Import, indexing, and Sigma scans now run on **worker threads** for a smoother UI on large (30–50 GB) timelines.

### Build & Security

- **Universal** build (Apple Silicon + Intel), **signed and notarized**.
- Upgraded **xlsx (SheetJS) to 0.20.3**, addressing known vulnerabilities in 0.18.5.

### First-Run Notes

- **Sigma scans work fully offline out of the box.** Both the **EVTX Folder** (Hayabusa) and **Current Timeline Tab / EvtxECmd** (JS engine) scans use rules bundled inside the app — no install or network download is required (important on TLS-intercepting corporate/DFIR networks). When online, you can still refresh the JS Sigma rule set from SigmaHQ via the rule manager.
- **RDP Bitmap Cache** requires **Python 3** installed on your machine.

## v1.0.5

### Bug Fixes

- **Plaso import crash fixed** — all Plaso/log2timeline `.plaso` and `.timeline` files now import correctly (a malformed `LIMIT` clause in the column-discovery query caused a SQLite error on every Plaso file).
- **Intel Mac crash fixed** — `better-sqlite3` is now compiled as a universal fat binary (x86_64 + arm64), so the app no longer crashes on Intel MacBooks when opening a file.

### Context Menu Improvements

- **Filter in / Filter out** — right-click any cell to filter the grid to rows matching that value, or exclude them.
- **Tags submenu** — tags are collapsed into a submenu to keep the context menu compact.
- **Multi-row tagging** — select multiple rows, right-click, and apply a tag to all selected rows at once.
- **Opaque menu background** — grid content no longer bleeds through the context menu.

### Copy Behaviour Fix

- **⌘C respects text selection** — when text is selected in the detail panel, ⌘C copies the selection instead of intercepting it and copying the whole row.
