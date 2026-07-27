---
description: IRFlow Timeline changelog — version history, new features, performance improvements, and bug fixes.
---

# Changelog

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
