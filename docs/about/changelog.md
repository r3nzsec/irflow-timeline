# Changelog

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
