# Changelog

## v1.0.3-beta

### New Features

- **Lateral Movement Attack Pattern Detection** — Automated MITRE ATT&CK-mapped findings
  - Brute Force detection (T1110.001): 5+ failed logons from same source within 5-minute window
  - Password Spray detection (T1110.003): same source fails against 3+ targets within 30 minutes
  - Credential Compromise detection (T1078): failed logon followed by success within 10 minutes
  - Impacket Execution detection (T1569.002): 10 patterns across 5 variants (smbexec.py, wmiexec.py, dcomexec.py, atexec.py, psexec.py)
  - RMM Tool detection (T1219): 31 remote monitoring tools scanned in process/service events
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
  - Tools menu: Stack Values, Gap Analysis, Log Sources, Burst Detection, Lateral Movement, Process Inspector, Persistence Analyzer, Generate Report
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

## v1.0.2-beta

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
  - Chain-based detection using 344 MITRE ATT&CK-mapped rules with reason strings
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
  - 13 built-in detection rules with custom rule support
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

## v1.0.0-beta

### New Features

- **Persistence Analyzer** — Automated detection of 30+ persistence techniques with risk scoring
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

## v0.9.1

- Lateral Movement progress bar for processing feedback
- Stacking glassmorphism for overlapping histogram sources
- Histogram upgrades and performance improvements

## v0.9.0

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

## v0.1.0

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
