# Changelog

## v1.0.2-beta

### New Features

- **Detection Rules Library** — 344 parent-child chain rules extracted to `src/detection-rules.js`
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
