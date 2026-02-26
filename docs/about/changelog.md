# Changelog

## v2.1.1

- Lateral Movement progress bar for processing feedback
- Stacking glassmorphism for overlapping histogram sources
- Histogram upgrades and performance improvements

## v2.1.0

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

## v2.0.0

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
