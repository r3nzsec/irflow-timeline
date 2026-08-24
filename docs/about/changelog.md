---
description: IRFlow Timeline changelog — version history, new features, performance improvements, and bug fixes.
---

# Changelog

## v1.0.12 — August 24, 2026

### Diff Tabs

View → **Diff Tabs** compares any two imported files — not a Computer History special case. Pick a baseline and a compare tab, match on auto-detected identity columns or entire-row content, and get a result timeline of Added / Removed / Changed rows with field-level before/after, clickable status counts, and schema-delta highlighting.

### Tags and bookmarks

A triage layer that was losing work in several places. Every item below is a fix, not a new feature.

- **Bulk Tag / Bookmark leads with an explicit scope** — Selected rows / Filtered view / Entire tab — defaulting to the selection whenever one exists, with the real row count for each option resolved in SQLite. Opened from the Actions menu it previously ignored the selection entirely and, on an unfiltered tab, tagged every row in the file on a single click. Writing to a whole tab now asks first, and the store refuses an unscoped write that has not been confirmed
- **Tags written during the post-import index build are no longer discarded.** Single- and multi-row tag and bookmark writes were dropped for the minutes that build takes, while the grid showed the tag as applied. The guard was unnecessary — the build runs on the same connection and touches only the data tables
- **Multi-row tagging applies one direction uniformly.** The right-clicked row is the anchor: its ● / ○ state decides add-versus-remove and that decision applies to every selected row. Previously each row decided for itself, so one click on a mixed selection tagged some rows and untagged others
- **"Select all" plus tag writes the whole filtered population** in SQL, honouring deselected rows. It used to write exactly one row while the status bar reported the full count
- **Cached query windows no longer repaint pre-tag state.** A filter round-trip could restore the tag snapshot from before an edit, making a successful write look like it had reverted
- **Manage Tags is backed by live row counts** and can rename a tag (merging into the destination on collision), collapse tags that differ only by case or spacing, and delete a tag from the rows that carry it. Deleting previously removed only the colour swatch — every row kept the tag, still filterable and still in the report, and could no longer be untagged from the row menu because the palette no longer listed it. Analyzer-written tags (`IOC:`, `VT:`, Sigma, `Encrypted`) now appear alongside manual ones
- **Tags and bookmarks survive export.** CSV, TSV and XLSX exports carry `Tags` and `Bookmarked` columns when the tab has any
- **`⌘⇧1`–`⌘⇧9` apply palette tag 1–9** to the current selection, under the same scope rules as the context menu
- Multi-row tag writes go through a single transaction instead of one IPC round trip per row

### ChatGPT Computer History — live re-audit (this Mac, 16,173 events)

The 1.0.10 catalog and the 1.0.11 verification both missed a later recorder kind, and overstated how hard 48-hour purge is.

- **`terminal.value_changed` is now parsed.** Nine events on the measured host, all while Secure Input was engaged. Content is the visible iTerm2 scrollback (`keyboard.target.value`): SSH targets, `rsync`/`scp` command lines, first-seen host-key acceptance. The typed password is still withheld. Previously the kind fell through to an empty `Content` field. Activity values: `Terminal Buffer`, `SSH Session`, and the Secure Input variants
- **Visible-range truncation is labelled.** Records prefixed `[truncated to visible range]` are the on-screen AX slice, not full scrollback
- **`com.openai.chat.StatsigService.plist`** is collected as `identity.statsig_account` — email / user id / account UUID with no tokens
- **Computer History plugin vs Computer Use MCP** are recorded separately. They share a container; they are not the same feature
- **48-hour purge caveat.** Advertised rolling window applies while the recorder is running. A stopped recorder left 90 segment buckets on disk three days after the last write

### Signed and notarized disk image

Every release through v1.0.11 shipped a DMG that was **never signed or submitted to Apple**. The application inside was notarized and stapled, so it ran cleanly once installed — but the downloaded disk image itself failed Gatekeeper (`no usable signature`), which is the *"Apple could not verify…"* dialog on first open and the reason the install page advised right-click → Open.

Notarization ran as an `afterSign` step, which fires on the `.app` before any DMG exists; the build then wrapped that stapled app in a disk image and did nothing further to the wrapper. The build now signs, notarizes and staples the DMG itself, and asserts with `spctl` that Gatekeeper accepts it before the build is allowed to succeed.

### Hayabusa v2 / v3 / v4 compatibility

Hayabusa v4 merged `csv-timeline` and `json-timeline` into a single `dfir-timeline` subcommand with an explicit `-t` output type, and rejects the old form before scanning a single event.

- **The scanner detects the installed binary's version and builds the matching command line**, keeping v2 and v3 on the legacy subcommands. Contributed by [@Yuds16](https://github.com/Yuds16) in [#27](https://github.com/r3nzsec/irflow-timeline/pull/27)
- **The output file extension matches the requested type.** `json` and `jsonl` both landed on `.jsonl`, so a JSON run wrote a JSON document into a file named `.jsonl`
- **Version detection requires a real version token.** A loose digit match meant an unparsable version string could route a v4 binary down the legacy path; anything unrecognised now falls back to the modern CLI
- **Hayabusa's abbreviated level names (`crit`, `med`) map to full severities.** Left unmapped they became their own severity buckets, so critical detections dropped out of the severity histogram

Known limitation: the `JSON` output mode still cannot be read by the result parser, which is line-delimited. Use `CSV` or `JSONL`.

### Multi-tab selection controls

- **Lateral Movement Tracker** gains **Select All** and **Clear** for its multi-source tab list
- **Persistence Analyzer** gains **Clear** alongside its existing **Select all**

Both contributed by [@Yuds16](https://github.com/Yuds16) in [#27](https://github.com/r3nzsec/irflow-timeline/pull/27).

## v1.0.11 — August 16, 2026

Computer History correctness release. Every claim in the 1.0.10 analysis was re-tested against a live 9,000-event capture; four were wrong, and three artifacts were not being collected at all.

### Corrected analysis

- **Credential rows no longer claim to recover passwords.** macOS Secure Input Mode blocks the recorder's event tap, so keystrokes consume event ids without ever being written — zero text-bearing input events under secure input across the measured capture. A credential row is now presented as a timing anchor: that a password was entered, in which field and app, at what second
- **Recorder restarts are detected instead of clearing the gap.** `EventId` restarts at 1 with each recorder session, and the previous continuity check subtracted ids across that boundary — yielding a negative shortfall that read as reassurance. On the measured capture it cleared 183 of 186 gap rows with "ids run continuously (17169 → 1)". Restart-spanning gaps are now reported as unassessed
- **Capture fidelity is measured, not assumed.** `resolveFidelityTier` takes the more capable of the known-app table and what the application actually produced, so a stale table entry can be corrected by evidence while a thin sample can never argue capability away. Slack, previously pinned to metadata-only on category reasoning, exposed 53,590 characters of channel content including message bodies
- **`ComputerUseAppApprovals.json` is no longer presented as the recording scope.** It belongs to the separate Computer Use agent feature; on the measured host it listed one bundle against 38 actually recorded, with an mtime predating the feature. Recording scope is account-side and is now reported as unknown

### New evidence collected

- **Consolidated Codex memory.** Skysight summaries are mined by the Codex memory consolidator into `~/.codex/memories/`, which is neither purged at 48 hours nor cleared with Computer History — on a stale host it can be the only surviving copy. Lines carrying the `[skysight memory]` provenance tag, and blocks citing a Skysight resource, are collected as `memory.consolidated` rows
- **Summary bodies are split into their distinct assertions.** `summary.profile` carries the model-inferred user dossier — the largest section, naming documents, typed search terms and application roles, and surviving the raw purge. `summary.priorcontext` carries text describing activity from outside its own window and is labelled so it is never used to date evidence
- **Mouse modifiers.** `mouse.modifiers` was dropped entirely. A command-click on a link opens it in a background tab — deliberate non-navigation, the bulk-open pattern — and now reaches the `KeyChord` column alongside keyboard chords
- **Secure Input as a second credential signal.** `app.secureInput` fires on any system-wide password prompt, including those exposing no secure-field subrole, and surfaces as `Password Prompt`

### Grok Build and Claude Desktop — stores that outlive the conversation

Six stores sitting outside the session trees were unread. All of them survive deletion of the conversation, which is what makes them worth having.

- **Grok `sessions/session_search.sqlite`** — the FTS5 index over session transcripts (`session_id`, `cwd`, `title`, `updated_at`, indexed body). The same artifact class as Cursor's `conversation-search.db`; it mirrors the transcript and survives deleting the session directory
- **Grok `logs/unified.jsonl`** — tool executions with outcome and duration, plus turn boundaries, written independently of the session tree. Records *that* a tool ran, never the command string
- **Grok `active_sessions.json`** — sessions open at acquisition, with pid and working directory
- **Claude Desktop `deleted_<session-uuid>` tombstones** — a 13-byte file whose content is the epoch-ms deletion time and whose filename is the deleted session id. Dated proof a conversation existed and was removed
- **Claude Desktop `pending-uploads/`** — files staged for upload, inventoried by path, size and staging time. File content is never read
- **Claude Desktop `plan-usage-history.json`** — usage samples collapsed into contiguous "application in use" windows, labelled as derived rather than as recorded session boundaries
- **Claude Desktop `scheduled-tasks.json` and `git-worktrees.json`** — agent runs configured to fire without user interaction, and workspaces with last-seen timestamps
- Discovery now prefers `~/Library/Application Support/Claude` over its `claude-code-sessions` child, because three of those stores are siblings of that directory. It replaces the child roots rather than adding to them, so no transcript is parsed twice, and nothing walks up out of a folder you selected
- `~/.grok/memtrace/` is **deliberately not parsed**: despite the name it is a memory profiler trace, not agent memory, and carries no conversation content

### Grid quality

- Click multiplicity is named by meaning — `Click`, `Double-Click`, `Triple-Click`, `Multi-Click` — instead of ten numeric `Click (xN)` values. The exact count remains in the `ClickCount` column, where a numeric dimension belongs
- Open (in-progress) segments are excluded from count reconciliation rather than scored as a shortfall
- Fidelity table corrections: Cursor's real bundle identifier added, a mislabelled entry removed, Slack and Discord tiered from evidence

### Naming

- The artifact family is **ChatGPT Computer History** everywhere — menu, tab title and the `Tool` column previously disagreed

The column schema is unchanged at 54 columns; existing saved tabs and sessions need no migration.

## v1.0.10 — August 14, 2026

### ChatGPT Computer History

- Added ChatGPT "Computer History" (Skysight) as a new macOS artifact family: the raw interaction-event stream retained for about 48 hours, plus the derived activity summaries that persist until cleared
- Dedicated 54-column schema for user-activity telemetry — app, window and URL context, accessibility target role and subrole, typed content, cross-app drag origin and destination, capture fidelity, and segment provenance
- Password-field entry is identified and labelled as a timing anchor — macOS Secure Input Mode withholds the field value *and* suppresses the keystrokes, so a credential row evidences that a password was entered, not what it was
- Finder file selections and menu commands are captured instead of landing as empty rows
- Typed input is collapsed into completed prompts, while terminal scrollback is preserved as a command timeline
- Segments are reconciled against their own metadata so that records removed after the fact — the effect of the "clear last 10 minutes / hour / day" control — are surfaced as a deletion lead
- Activity summaries the user cleared are recovered read-only from the Codex memories git history, with the time they were removed
- Attribution rows collect the ChatGPT account, the signed-in identity, and the per-app device identifiers, each labelled with how strongly it identifies an account; no token material is stored or exported
- Codex conversations are dated from their identifiers and joined to the timeline, with deleted conversations flagged — the prompt typed into a deleted conversation is often still recorded

### Crash and Worker Reliability

- Fixed a one-shot worker lifecycle leak that could accumulate hundreds of worker threads during long sessions
- Moved recurring autosave bookmark snapshots onto the main SQLite connection instead of creating a worker for every loaded tab
- Added exactly-once job settlement for clean exits without results, abnormal exits, startup failures, cancellation races, and duplicate terminal events
- Kept live worker accounting active until the operating-system thread actually exits, with bounded forced retirement for stragglers

### Crash-Safe Session Recovery

- Serialized autosaves and prevented overlapping snapshots
- Replaced direct autosave overwrites with synced temporary files and atomic rename
- Retained the previous valid snapshot as a backup and automatically falls back to it when the primary is missing or corrupt
- Validated session structure before writing or restoring recovery data

### Application and Resource Resilience

- Closing the last macOS window hides and preserves the live workspace; Dock activation restores it without orphaning workers or SQLite tabs
- Fatal main-process errors, unhandled rejections, and unexpected renderer exits now clean up runtime resources and relaunch once, with a 30-second crash-loop guard
- Enabled local-only Electron crash dumps and child-process exit logging
- Added a memory-aware global worker ceiling plus a separate heavy-work ceiling across every worker-backed feature; live and queued usage is available through job diagnostics

### Hayabusa Process Reliability

- EVTX scan cancellation now waits for Hayabusa to close and escalates from `SIGTERM` to `SIGKILL` when required
- Temporary scan output is removed only after the child process stops, and scan registration is cleared on every terminal path
- Hayabusa diagnostic capture is capped at 256 KiB, with progress-parser errors contained safely in the scan promise

### Runtime Modernization

- Upgraded to Electron 43, `better-sqlite3` 13, Electron Builder 26, Electron Rebuild 4, and Electron Updater 6.8
- Aligned local and CI builds on Node.js 22.12+ and deduplicated the EVTX message provider onto the Electron-compatible SQLite 13 addon
- Set the packaged operating-system floor to macOS 12 (Monterey), matching Electron 43 support

## v1.0.9 — July 27, 2026

### Large EVTX Imports

- **Fixed issue #22** — Raw EVTX files no longer use Node's whole-file read path, eliminating the 2 GiB Buffer failure seen on large `Security.evtx` files
- **Bounded 64 KiB parsing** — Reads the EVTX header once and processes one native EVTX chunk at a time, keeping memory use stable as the source grows
- **Approximately 4 GiB support** — Supports the EVTX format's 65,535-chunk ceiling, including the reported 4,109,438,976-byte (~3.83 GiB) log
- **Better progress reporting** — Large-file progress tracks physical chunk offsets

### Import Reliability

- Duplicate requests for the same pending file are suppressed without blocking distinct workbook-sheet or AI-history-scope imports
- Repeated identical failures collapse into one retryable notification instead of stacking across the screen
- Added an exact-size issue #22 regression plus real multi-gigabyte EVTX validation

## v1.0.8 — July 27, 2026

### AI Application Forensics

- **Grok Build support (new)** — Parses `.grok` prompt history and session stores into AI Query History:
  - Timestamped prompts, responses, reasoning, exact terminal-command inputs, completion output, and token usage
  - Session/model/workspace/Git context plus file-hunk records
  - Credential-bearing Grok configuration files are deliberately excluded from timeline text
- **Claude expanded** — Recursively parses Claude Code projects and subagents plus Claude Desktop/Cowork session metadata, isolated transcripts, audit JSONL, tool calls, and actual shell commands
- **Codex expanded** — Adds current/archived dated rollouts and version-aware `state*.sqlite` discovery; snapshots SQLite with WAL/SHM companions to preserve recent thread, spawn-edge, and dynamic-tool metadata
- **Modernized AI evidence model** — Preserves `InvokedTool`, exact `ToolCommand`, structured `ToolInput`, descriptions, and bounded tool results across modern JSONL formats
- **Broader app coverage** — Improves ChatGPT Desktop, GitHub Copilot CLI and VS Code, Gemini CLI, Cursor, Windsurf, and Continue extraction
- **AI Secret Hunt safeguards** — Sensitive-value reveal now uses the managed confirmation workflow

### Collection and Investigation Workflows

- **Open Triage Collection** — Inventory KAPE/triage folders, attribute artifacts to likely hosts, choose import lanes, and optionally hand EVTX to Sigma analysis
- **Process Inspector overhaul** — Verdict-first results, Story/Triage/Hunt/Graph/Raw modes, rule-health coverage, enrichment passes, Filter Grid pivots, and cross-analyzer handoffs
- **Persistence Analyzer** — Multi-source scanning, KAPE collection analysis, incident clustering, registry-shape hardening, and remote-origin scoring
- **Lateral Movement Tracker** — Multi-source detection, normalized endpoints, raw Terminal Services evidence, stronger RDP scoring, graph layout, campaign triage, and stage isolation
- **Timeline workflow** — Command palette, keyboard navigation, selection bar, multi-row bulk actions, and grid/filter polish

### Performance, Stability, and Release Quality

- Streams heavy query results and bounds worker memory/lifecycle to prevent JavaScript heap exhaustion on large evidence sets
- Uses bounded JSONL readers and explicit per-row evidence caps while retaining useful tool output
- Gates macOS packaging on automated tests plus renderer and VitePress documentation builds
- Ships as a signed and notarized universal macOS release for Apple Silicon and Intel

---

## v1.0.7 — June 4, 2026

### New Features

- **AI Artifacts / AI Query History** — New **Tools → Analysis → AI Artifacts → Collect AI Artifacts** workflow for turning local AI assistant activity into timeline evidence
  - Parses prompts, assistant responses, invoked tool/action records, timestamps, sessions, workspace paths, source files, models, and endpoint user/host attribution when available
  - Supports Claude Code, OpenAI Codex, ChatGPT Desktop, Gemini CLI, Cursor, GitHub Copilot, Windsurf, and Continue
  - Scans the current Mac or a selected KAPE / triage / mounted-disk folder across Windows, Linux, and macOS profile layouts
  - Merges discovered sources into one **AI Query History** tab with consistent columns and provenance fields

- **AI Secret Hunt** — New **Tools → Detection → AI Secret Hunt** workflow for finding sensitive data exposed through AI history
  - Detects API keys, private keys, tokens, credentials, and high-confidence secret patterns across prompts, responses, and tool output
  - Groups repeated evidence by fingerprint, redacts cleartext by default (cleartext is never written to disk), and supports analyst tagging for triage
  - Group findings by tool or session, then export a redacted PDF / HTML exposure brief or a redacted CSV of findings

### Data Quality

- **AI history parser hardening** — Improved timestamp normalization, `Summary` versus `FullText` handling, `Tool` versus `InvokedTool` column naming, and source-row attribution across AI app parsers
- **False-positive reduction** — Tightened credit-card and high-entropy secret detection so placeholder identifiers, directory paths, and non-secret strings are less likely to appear as findings
- **Private key evidence handling** — Multi-line PEM-style findings preserve expanded block context instead of collapsing to a one-line preview

### Performance and Stability

- **Large AI History tabs** — Scroll-window handling and streamed import behavior were hardened for 100k+ row AI History tabs
- **Extraction UI polish** — Progress, expanded evidence rows, tag controls, source paths, and reveal/copy controls were cleaned up to reduce renderer jank during long AI artifact scans

---

## v1.0.6 — June 1, 2026

### New Features

- **Sigma Detection (dual engine)** — Rule-based detection built directly into the app, accessible from **Tools → Detection → Sigma Scan**
  - **Hayabusa engine** — the bundled Hayabusa binary scans raw `.evtx` folders at full speed; self-updating rule set with in-app binary/rule maintenance
  - **In-app JS Sigma engine** — compiles Sigma detection YAML to a JS predicate and scans imported data (current tab) or EvtxECmd CSV/XLS/XLSX output when raw `.evtx` is unavailable
  - Three scan targets: EVTX Folder (Hayabusa), EvtxECmd Output Files (JS Sigma), and Current Timeline Tab (JS Sigma) with automatic format detection (EvtxECmd / Hayabusa / raw EVTX / CSV)
  - Detection profile with scan presets (Fast high-confidence, Full hunt, Critical/high only) plus custom saveable presets, severity/status filters, and JS Sigma rule-category selection
  - Hayabusa rule sets: Core, Core+, Core++, Emerging Threats, Threat Hunting, All; output profiles (minimal → super-verbose, Timesketch) and CSV/JSON/JSONL modes
  - Scan options: record recovery, UTC, proven-only, noisy/deprecated/unsupported toggles, EID filter, `-A`/`-a`, GeoIP enrichment (MaxMind GeoLite2 auto-download), and include/exclude filters for MITRE tags, computers, and Event IDs
  - **Triage dashboard** ("Look Here First") with priority findings, MITRE ATT&CK technique/tactic badges, affected/rare host-user-process panels, per-rule reviewed/false-positive state, and Open Exact Hits / Tag / Bookmark actions
  - **Disabled / Noisy Rules** suppression manager (global + case-specific, synced to Hayabusa `noisy_rules.txt`), compatibility rule downloads, and custom YAML rule import
  - Raw-EVTX triage tools (log metrics, computers, event IDs, logons, pivot IOCs, Base64 decode) and a keyword/regex EVTX search utility
  - Persistent scan history with reopenable results; cancellable scans

- **RDP Bitmap Cache** — New **Tools → Platforms → Windows → RDP Bitmap Cache** workflow wrapping ANSSI-FR `bmc-tools`
  - Recovers bitmap tiles and collages from `bcache*.bmc` / `cache????.bin` Windows profile artifacts
  - Preflight summary (cache file count, size, detected profiles), recursive directory scanning, and image preview
  - Exportable evidence package with `manifest.json`, source/output SHA-256 hashes, copied images, and recorded command line

- **Lateral Movement Tracker expansion** — Seven sub-tabs and operator-centric triage
  - **Accounts** tab — per-identity aggregation with suspicion scoring, PRIV/ADMIN/MACHINE/SERVICE/USER classification, and per-row pivots (created even from Kerberos-only DC events)
  - **Exec Sessions** tab — first-class non-RDP lateral movement (WMI, WinRM, PsExec, Impacket, remote services, scheduled tasks, admin shares, RMM, Cobalt Strike) with Table and Timeline (Gantt) views
  - **Incidents** — pair-based grouping of findings within a 30-minute window
  - **Campaigns** — multi-hop storyline clustering across shared host/user within 2 hours, with hop-path breadcrumbs and auto-generated narratives
  - **Telemetry Coverage** panel surfacing present event categories and detections gated by missing data

### Architecture

- **Codebase refactor (v1.0.5 → v1.0.6)** — The monolithic `App.jsx` and `electron/parser.js` were decomposed into ~200 focused modules across the renderer and main process: per-format `parsers/`, per-domain `ipc/` handlers, `worker_threads`-backed `jobs/`, and modular `analyzers/` (sigma, lateral-movement, process-tree, persistence, rdp-bitmap-cache, network)
- **External tools bundling** — `npm run bundle:tools` now bundles both Hayabusa and `bmc-tools` as `extraResources`

### UI Improvements

- **Tools menu restructure** — Reorganized into Analysis, Detection (Sigma Scan), Platforms (Windows tools, with Linux/macOS/Cloud teasers), and Export sections (v1.0.7 adds **AI Artifacts** under Analysis and **AI Secret Hunt** under Detection)

- **Lateral Movement Tracker** — **15** configurable built-in event rules (added RMM / Remote Access + Scheduled Task execution presets)

## v1.0.5 — March 17, 2026

### New Features

- **Cell context menu (Cmd+Click)** — `Cmd+Click` any cell to instantly access **Filter in**, **Filter out**, and **Hide column** actions. A fast way to drill into specific values without opening the filter editor
- **Right-click Filter in / Filter out** — Right-click any cell to see **Filter in** (show only rows matching that value) and **Filter out** (exclude rows with that value) under a new Filters section in the context menu
- **Multi-row tagging** — Select multiple rows with checkboxes, then right-click to apply a tag to all selected rows at once. The context menu shows the count, e.g., "Tags (4 rows)"
- **Tags hover submenu** — Tags in the right-click context menu are now collapsed into a compact **Tags ▸** submenu with a Manage Tags option, keeping the menu clean

### Bug Fixes

- **Plaso import crash fix** — `LIMIT` clause in `UNION ALL` query for Plaso field discovery must be inside a subquery. Wraps the first `SELECT` in `(SELECT ... LIMIT 300)` to fix a SQLite syntax error on all Plaso files
- **`.timeline` file support** — Files with `.timeline` extension are now auto-detected as Plaso databases. If not a valid Plaso file, they fall through to CSV parsing
- **Cmd+C detail panel fix** — `Cmd+C` now correctly copies selected text in the detail panel instead of intercepting native copy when a DOM selection exists
- **Context menu opacity fix** — Context menu background opacity raised to 0.97 so grid rows no longer bleed through semi-transparent menus
- **formatNumber null safety** — `formatNumber()` handles null/undefined values gracefully instead of crashing

### Performance

- **V8 heap limit for main process** — Sets `--max-old-space-size=16384` via `v8.setFlagsFromString()` for the main process (not just the renderer), enabling import of 20GB+ forensic images without hitting heap limits

### CI / Release

- **Universal binary build** — CI now builds x64 and arm64 slices separately then `lipo`-merges into a universal fat binary, fixing architecture mismatches on Intel Macs
- **macOS runner update** — Switched to `macos-14` runner for reliable universal native module cross-compilation
- **Clean release artifacts** — `release/` directory is cleaned before each build to prevent stale artifact pickup
- **Exact version matching** — Artifact collection matches the exact version from `package.json` instead of first-found glob

---

## v1.0.4 — March 10, 2026

### Performance

- **Stacking analytics — 3 queries → 1** — `getStackingData` now runs a single GROUP BY query and derives totals from the result. Only falls back to a COUNT query in the rare >10K unique values case. Eliminates two full-table scans per stacking panel open
- **CSV parsing rewrite — O(n²) → O(n)** — `parseCSVLine` replaced per-character string concatenation with substring range tracking and array join. Significant speedup on wide rows with many quoted fields
- **Plaso field discovery — single-pass sampling** — Combined two separate sampling queries (start + middle) into a single `UNION ALL` query covering start, middle, and end of the dataset. Eliminates an extra table scan and improves field coverage
- **Timestamp-priority indexing** — `buildIndexesAsync` now builds indexes on timestamp columns first, since users typically sort by time immediately after import. Reduces the chance of hitting the synchronous `_ensureIndex` fallback
- **Concurrent index build cap** — Deferred index builds limited to 2 concurrent tabs to prevent memory exhaustion. Previously, importing 10 files could trigger 10 parallel index builds each allocating 256MB–1GB cache
- **Sample-based empty column detection** — `getEmptyColumns` now samples 50K rows (25K from start + 25K from end) instead of scanning the full table. Reduces a 10–30s UI block to <1s on 30M+ row tables

### Stability

- **MFT attribute buffer overflow protection** — Added bounds checks (`pos + nameOffset + nameLen * 2 <= buf.length`) before `toString("utf16le")` calls on `$DATA` ADS names and `$LOGGED_UTILITY_STREAM` attributes. Prevents reading past buffer on corrupt MFT records
- **Export crash safety** — Both XLSX and CSV/TSV export iterator loops wrapped in try-catch. If a tab is closed mid-export, the partial file is saved and the error is logged instead of crashing
- **IPC error guard on USN path refresh** — Added `__ipcError` check before accessing `result.rows` in `onUsnPathsUpdated`. Prevents setting tab rows to `undefined` which would crash downstream rendering
- **Process tree preview timer leak fix** — Replaced `window._ptPreviewTimer` global with local closure variable, matching the existing `_lmPreviewTimer` pattern. Prevents timer accumulation across modal opens/closes
- **Analysis modal error recovery** — Added `.catch()` handlers to `detectTimestomping`, `getFileActivityHeatmap`, and `analyzeADS` IPC calls. Modals now exit loading state on failure instead of hanging forever
- **VT bulk lookup window guard** — Loop checks `mainWindow.isDestroyed()` before each iteration. Stops wasting API quota when the window is closed mid-lookup
- **VT retry sleep cancellable** — 429 rate-limit retry sleep now polls every 2s checking `job.cancelled`, reducing max cancellation latency from 60s to 2s
- **Preview cache invalidation** — `_invalidateCountCache` now also clears `_ptPreviewCache` and `_lmPreviewCache` entries for the affected tab, preventing stale process tree and lateral movement previews after tag/bookmark changes
- **Import progress null safety** — Added fallback for `prev[tabId]` in `onImportProgress` handler to handle race between `import-start` and `import-progress` events

---

## v1.0.3-beta — March 1, 2026

### New Features

- **Lateral Movement Attack Pattern Detection** — Automated MITRE ATT&CK-mapped findings
  - Brute Force detection (T1110.001): 5+ failed logons from same source within 5-minute window
  - Password Spray detection (T1110.003): same source fails against 3+ targets within 30 minutes
  - Credential Compromise detection (T1078): failed logon followed by success within 10 minutes
  - Impacket Execution detection (T1569.002): 11 patterns across 5 variants (smbexec.py, wmiexec.py, dcomexec.py, atexec.py, psexec.py)
  - RMM Tool detection (T1219): 30 remote monitoring tools scanned in process/service events
  - Lateral Pivot detection (T1021): identifies middle hosts in multi-hop chains
  - First-Seen Connection flagging: connections in first 1% of timeline or first from a source host
  - New Findings tab with severity summary, MITRE badges, and Filter Events / View in Graph actions

- **RDP Session Grouping** — Grouped view mode for RDP Sessions tab
  - Sessions grouped by source/target/user/status with expandable rows
  - Toggle between Grouped and Individual view modes

- **Menu Bar Redesign** — Complete toolbar restructure
  - File menu: Open, Export, Save/Load Session, Open Recent (with submenu), Close Tab
  - View menu: Columns, Color Rules, Tags, Filter Presets, Edit Filter, Merge Tabs
  - Actions menu: Select All/Deselect All/Invert Selection, Copy/Export Selected Rows, IOC Matching, Bulk Tag, Pivot, Find Duplicates
  - Tools menu (v1.0.3 flat layout; reorganized in v1.0.6 into **Analysis** / **Detection** / **Platforms** / **Export** — see [Virtual Grid — Tools](/features/virtual-grid#tools))
  - Help menu: Quick Help, Keyboard Shortcuts, Website, About
  - Glassmorphism styling with backdrop blur and semi-transparent backgrounds

- **Row Checkbox Selection** — Checkbox column in the data grid
  - Per-row checkboxes with master select-all in header
  - Group-level checkboxes in grouped view (with indeterminate state)
  - Select All, Deselect All, Invert Selection from Actions menu
  - Copy Selected Rows (`Cmd+C`) and Export Selected Rows as CSV

- **Recent Files** — Persistent list of recently opened files
  - Up to 10 files tracked across sessions
  - File menu flyout with filename and full path
  - Native macOS "Open Recent" menu integration
  - Stale entries auto-removed when file no longer exists

- **Find Duplicates** — New analysis tool
  - Select any column to scan for duplicate values
  - Shows count of duplicates and total affected rows
  - One-click "Filter to Duplicates" applies checkbox filter

- **Quick Help Modal** — In-app help covering supported formats, search modes, filters, analysis tools, and keyboard shortcuts

- **About Modal** — App info dialog with version, author, and social links

### Performance

- **WAL checkpoint timer** — Periodic `PRAGMA wal_checkpoint(PASSIVE)` every 5 minutes prevents unbounded WAL file growth during long sessions
- **Tags table index** — New `idx_tags_rowid` index speeds up row-specific tag lookups
- **Bookmark/tag query optimization** — Combined `UNION ALL` query replaces two separate queries per batch
- **Rendering optimizations** — Pre-allocated highlight style objects and regex `lastIndex` reset eliminate per-cell object creation
- **Async file writes** — Report generation, session save, and filter preset save converted from `writeFileSync` to `fsp.writeFile`
- **Export stream flush** — Export now properly waits for write stream `finish` event before returning

### UI Improvements

- **Tab bar redesign** — Pill/capsule style tabs with glass backgrounds, active tab orange dot indicator
- **Glassmorphism theme** — New `toolbarBg`, `glassBg`, `glassBorder`, `glassHover` theme tokens for both dark and light themes
- **Search bar** — Glass background and border styling, increased border radius
- **Status bar** — Shows full file path of active tab (with ellipsis overflow)
- **Toolbar buttons** — Increased padding and border radius with hover transitions

## v1.0.2-beta — February 28, 2026

### New Features

- **Detection Rules Library** — 342 parent-child chain rules extracted to `src/detection-rules.js`
  - Covers 12 MITRE ATT&CK tactic categories: Execution, Defense Evasion, C2/RATs, Persistence, Discovery, Credential Access, Lateral Movement, Impact/Ransomware, Collection, Exfiltration, Initial Access, Browser Exploits
  - O(1) chain lookup via pre-built `CHAIN_RULE_MAP` keyed by `parent:child`
  - 13 standalone regex patterns for suspicious paths, encoded PowerShell, credential dumping, NTDS extraction, defense evasion, account manipulation, network scanners, AD recon tools, RMM tools, exfiltration tools, and archive operations
  - Safe process exclusion list prevents false positives on legitimate temp-path executables

- **Import Queue System** — Serialized multi-file import pipeline
  - Imports run one at a time with GC pauses between files
  - Index and FTS builds deferred until entire queue drains
  - Queue status broadcast to renderer via `import-queue` IPC channel
  - UI shows numbered list of queued files with file sizes

- **IOC Matching Enhancements** — Expanded from 9 to 17+ IOC categories
  - New categories: Registry Key, Named Pipe, Mutex, Crypto Wallet (Bitcoin/Ethereum/Monero), User Agent, IPv4:Port, IPv6:Port, JARM Hash, JA3/JA3S Hash
  - Automatic IOC defanging (`hxxps[://]`, `[.]`, `[dot]`, `(.)`, `[@]`)
  - Per-IOC tagging (each matched IOC gets its own tag, e.g., `IOC: cmd.exe`)
  - Inline grid highlighting (orange for IOC matches, amber for search)
  - Multi-format file loading: XLSX, XLS, TSV with structured column auto-detection
  - 3-phase scan progress bar (Scanning → Tagging → Refreshing)
  - File Name vs Domain Name disambiguation using curated extension lists

- **Process Tree Overhaul** — Redesigned with detection-first analysis
  - 10-column table: Timestamp, Detection, Provider, Event ID, Parent Process, Process, PID, PPID, User, Command Line, Integrity
  - Chain-based detection using 342 MITRE ATT&CK-mapped rules with reason strings
  - Process type icons (Explorer, Office, Shell, System, Browser)
  - Integrity level decoding (System/High/Medium/Low/Untrusted with color coding)
  - Security Event 4688 support with reversed PID semantics
  - PID-based tree re-linking for non-GUID data
  - Resizable detail panel with clickable parent navigation
  - Checkbox selection with "Copy Selected" and "Suspicious Only" filter
  - Loading screen with 6-phase progress indicator
  - EvtxECmd Sysmon-aware provider filtering

- **Lateral Movement Expansion** — 16 event IDs with RDP session correlation
  - TerminalServices parsing (LocalSessionManager EIDs 21-25, 39, 40; RemoteConnectionManager EID 1149)
  - 13 built-in lateral-movement detection rules with custom rule support (expanded to 15 in v1.0.6)
  - RDP session correlation engine with lifecycle tracking (connecting → active → disconnected → ended)
  - New RDP Sessions tab with expandable event timelines
  - Event breakdown per edge (pill-shaped EID × count chips)
  - CLEARTEXT badge for logon type 8
  - Expanded logon types: Cleartext (8), RunAs (9), Cached Credentials (11), Cached RDP (12), Cached Unlock (13)
  - Draggable SVG legend

- **Tags as First-Class Column** — Full grid column behavior for the Tags column
  - Sortable, filterable (text + checkbox), stackable, column stats
  - `__tags__` filter support across all 10 query methods

- **Export Formats** — TSV and XLS export added alongside CSV and XLSX

### Performance

- **Histogram drag optimization** — Zero-rerender brush selection on large files
  - DOM-based overlay positioning replaces React state updates during drag
  - Eliminates re-rendering of 8,000+ SVG rect elements on every mouse move

- **Multi-file EVTX import stability** — Fixed crashes when importing 15+ EVTX files
  - Global EVTX message provider cache (created once, reused across all imports)
  - GC pause between sequential imports to prevent memory accumulation
  - Deferred index/FTS builds until import queue fully drains
  - Explicit EvtxFile handle cleanup and large array nulling after parse

- **SQLite query optimization** — Faster column stats, empty column detection, and sorting
  - `getColumnStats` combined 3-6 full table scans into 1 query
  - `getEmptyColumns` combined per-column queries into single combined query
  - COLLATE NOCASE indexes for proper sort alignment
  - `extract_date` / `extract_datetime_minute` charCodeAt fast path (~2x faster than regex)
  - REGEXP function caching (avoids recompilation for same pattern)
  - BFS queue optimization (index-based O(1) replaces shift-based O(n))

- **Render optimization** — Faster cell rendering and column lookups
  - Set-based visible column lookups replacing O(n) Array.includes()
  - Memoized combined highlight regex (IOC + search) avoids per-cell regex creation
  - Process tree detection map cached per data reference

### UI Improvements

- **Welcome screen** — Larger, more prominent welcome card
- **Context menu** — macOS-style glass/blur aesthetic with inline SVG icons
- **Process tree row hover** — Subtle highlight via CSS (added to index.html)

### Robustness

- **Buffered debug logging** — Log writes batched (50 entries / 2s flush) across main.js, db.js, parser.js
- **Memory logging** — Heap and RSS usage logged after each EVTX parse for diagnostics
- **Import queue safety** — Index and FTS builds deferred until all queued imports complete
- **Safer filename decoding** — try/catch on decodeURIComponent prevents crash on malformed URIs
- **React Error Boundary** — Graceful UI crash recovery with "Try to Recover" button

## v1.0.0-beta — February 27, 2026

### New Features

- **Persistence Analyzer** — Automated EVTX and registry persistence detection with risk scoring (expanded to 36 EVTX + 33 registry rules in later releases)
  - Supports EVTX event logs and registry exports (auto-detect mode)
  - 18 EVTX detection rules: Services (7045/4697), Scheduled Tasks (4698/4699/106/141/118/119), WMI subscriptions (5861, Sysmon 19/20/21), Registry autorun (Sysmon 12/13/14), Startup folder drops (Sysmon 11), DLL hijacking (Sysmon 7), Driver loading (Sysmon 6), ADS (Sysmon 15), Process tampering (Sysmon 25), Timestomping (Sysmon 2)
  - 15 registry persistence locations: Run/RunOnce, Services, Winlogon, AppInit_DLLs, IFEO, COM hijacking, Shell extensions, Boot Execute, BHO, LSA packages, Print Monitors, Active Setup, Startup folders, Scheduled Tasks, Network Providers
  - Risk scoring (0-10) based on technique severity, suspicious paths, command-line indicators, and encoding detection
  - Custom Rules Editor — toggle default rules on/off, add custom EVTX/Registry rules from GUI
  - Suspicious detection engine: non-Microsoft tasks, GUID-named tasks, LOLBin execution, user-writable paths, anti-forensics task deletion
  - Three view modes: Grouped, Timeline, Table
  - Cross-event correlation (links task creation to executables, WMI filter-consumer-binding)
  - Bulk tagging and filtering from results
  - Respects all active timeline filters

- **Legacy .xls support** — Binary OLE2/BIFF format files parsed via SheetJS
  - Complements existing XLSX streaming reader
  - Handles date formatting and cell type conversion

- **Lateral Movement outlier detection** — Flags suspicious hostnames in network graph
  - Default Windows names (`DESKTOP-XXXXX`, `WIN-XXXXX`)
  - Penetration testing defaults (`KALI`, `PARROT`)
  - Generic/suspicious names (`ADMIN`, `TEST`, `HACKER`, etc.)
  - Non-ASCII hostnames
  - Highlighted with red pulse in graph

- **React Error Boundary** — Graceful UI crash recovery with "Try to Recover" button

### Performance

- **Import speed** — Significantly faster bulk loading
  - `journal_mode=OFF` during import (temp DB, crash = re-import)
  - 1GB SQLite cache (was 500MB), 64KB page size (was 32KB)
  - 128MB read chunks for CSV (was 16MB)
  - Adaptive batch sizes up to 100,000 rows (was fixed 50,000)
  - Pre-allocated parameter arrays reused across all batches
  - Full SQLite parameter capacity for multi-row INSERT (removed artificial 1000-row cap)
  - Time-based progress reporting every 200ms (was row-count-based)

- **Background indexing** — Column indexes and FTS build after import without blocking UI
  - All columns indexed (not just timestamps), one at a time with event loop yields
  - Sequential index → FTS pipeline to avoid SQLite page cache thrashing
  - Phase-specific SQLite pragmas: 1GB cache + 8 threads during builds, 256MB cache + 512MB mmap during queries
  - ANALYZE runs after index build for query optimizer stats
  - Status bar shows combined column index + FTS build progress

- **Excel serial date support** — Numeric serial dates (e.g., `45566` → `2024-10-05`) recognized in histogram and timeline functions

### Robustness

- **Debug logging** — Shared `dbg()` logger across main.js, db.js, parser.js writing to `~/tle-debug.log`
- **Safe IPC wrappers** — All IPC handlers wrapped with try/catch + debug logging via `safeHandle()`, all sends check window existence via `safeSend()`
- **Crash guards** — `uncaughtException` and `unhandledRejection` handlers with user-facing error dialog
- **Failed import cleanup** — Partially-imported tabs cleaned up on error
- **Build safety** — `_isBuilding()` guard protects bookmark/tag writes during background index builds

### UI Improvements

- **Scroll performance** — `requestAnimationFrame`-throttled scroll handler
- **Per-tab scroll state** — Scroll position, selection, and last-clicked row preserved when switching tabs
- **Window resize tracking** — Viewport height adapts to window resize/zoom
- **Progress bar animation** — CSS `transform: scaleX()` for smoother progress rendering
- **Indexing status indicator** — Toolbar shows column index + FTS build progress with phase labels

## v0.9.1 — February 2026

### Improvements

- **Lateral Movement progress bar** — visual processing feedback during lateral movement analysis on large datasets
- **Stacking glassmorphism** — overlapping histogram sources rendered with backdrop blur transparency for clearer multi-source visualizations
- **Histogram performance** — faster bucket calculation and smoother brush selection on large timelines
- **Histogram heatmap coloring** — bars colored by event density gradient for quick visual identification of activity spikes

## v0.9.0 — February 2026

### New Features

- **Process Tree** — GUID-aware parent-child hierarchy from Sysmon Event ID 1
  - Suspicious pattern detection (Office spawns, LOLBins, temp path execution)
  - Ancestor chain highlighting
  - Click-to-filter integration with main grid
  - EvtxECmd PayloadData extraction support
  - Depth limit controls

- **Lateral Movement Tracker** — Interactive force-directed network graph
  - Auto-detects logon events (4624/4625/4648)
  - Multi-hop chain detection
  - Three sub-tabs: Graph, Chains, Connections
  - Noise filtering (local loopback, service accounts)
  - EvtxECmd RemoteHost parsing

- **EVTX improvements** — Enhanced event log parsing and field extraction

### Improvements

- Release polish and stability improvements
- Beta tester credits added

## v0.1.0 — January 2026

### Core Features

- High-performance virtual scrolling grid
- SQLite-backed data engine with streaming import
- 5 search modes: Mixed, FTS, LIKE, Fuzzy, Regex
- Multi-tab support with independent state
- Bookmarks and tags annotation system
- Color rules with KAPE-aware presets
- Timeline histogram with brush selection
- Gap analysis and burst detection
- IOC matching (IPv4, IPv6, domain, hash, email, URL, file path)
- Stacking (value frequency analysis)
- Log source coverage heatmap
- KAPE profile auto-detection (15+ tools)
- Session save/load (.tle files)
- Export: CSV, XLSX, HTML reports
- Cross-tab search
- Tab merging for super-timeline creation

### Supported Formats

- CSV / TSV / TXT / LOG (auto-delimiter detection)
- XLSX / XLS / XLSM (streaming reader)
- EVTX (Windows Event Log binary)
- Plaso (forensic timeline database)

### Platform

- macOS native (Intel + Apple Silicon universal binary)
- Dark and light themes
- Native menu integration
- File associations for supported formats
