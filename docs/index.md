---
layout: home
description: High-performance DFIR timeline analysis tool for macOS — search, visualize, and investigate 30GB+ forensic timelines.

hero:
  name: IRFlow Timeline
  text: DFIR Timeline Analysis
  tagline: Native macOS forensic timeline analysis. Import, search, and investigate EVTX, CSV, XLSX, and Plaso timelines with the analytics DFIR professionals actually need.
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started/installation
    - theme: alt
      text: View on GitHub
      link: https://github.com/r3nzsec/irflow-timeline

features:
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>'
    title: Blazing Fast
    details: SQLite engine with sub-100ms queries on 10M+ rows. Streams 30GB+ files with zero-copy CSV parsing, memory-capped background indexing, and single-query analytics — no loading into memory.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/><line x1="11" y1="8" x2="11" y2="14"/></svg>'
    title: 5 Search Modes
    details: Mixed, FTS, LIKE, Fuzzy, and Regex. Full-text search, substring matching, typo-tolerant fuzzy, and pattern matching across millions of rows.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v6"/><circle cx="12" cy="12" r="3"/><path d="M12 15v3"/><path d="M8 15l-3 3"/><path d="M16 15l3 3"/><path d="M5 18v2"/><path d="M12 18v2"/><path d="M19 18v2"/></svg>'
    title: Process Inspector
    details: Reconstruct process trees from Sysmon and Security logs with 4-tier threat scoring, 342 chain rules + 13 standalone patterns mapped to MITRE ATT&CK.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="18" r="3"/><line x1="8.5" y1="7.5" x2="15.5" y2="16.5"/><line x1="15.5" y1="7.5" x2="8.5" y2="16.5"/><line x1="6" y1="9" x2="6" y2="15"/><line x1="18" y1="9" x2="18" y2="15"/></svg>'
    title: Lateral Movement Tracker
    details: Network graph with multi-hop chain reconstruction and RDP session correlation. Detects brute force, password spray, Impacket, 33 RMM tools, and 7 network tunnels.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="rgba(232,93,42,0.15)"/><path d="M9 12l2 2 4-4"/></svg>'
    title: Persistence Analyzer
    details: Automated detection of 30+ persistence techniques with risk scoring across services, scheduled tasks, WMI subscriptions, and autorun keys.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><rect x="7" y="10" width="3" height="8" rx="0.5" fill="rgba(232,93,42,0.3)"/><rect x="12" y="6" width="3" height="12" rx="0.5" fill="rgba(232,93,42,0.3)"/><rect x="17" y="13" width="3" height="5" rx="0.5" fill="rgba(232,93,42,0.3)"/></svg>'
    title: Rich Analytics
    details: Histogram with brush-to-filter, gap and burst detection, log source coverage maps, and value frequency stacking.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
    title: IOC Matching
    details: Scan against threat intel lists with 17+ indicator types — hashes, IPs, domains, registry keys, named pipes, and more. Auto-defangs and tags matches inline.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" fill="rgba(232,93,42,0.3)"/></svg>'
    title: Investigation Workflow
    details: Bookmarks, color-coded tags, conditional formatting with KAPE-aware presets, and full session save/restore.
---

## What's New

- **Performance & Stability Hardening** — Stacking analytics now resolve in a single query (3x faster), CSV parsing rewritten with zero-copy field extraction, background index builds prioritize timestamp columns and cap concurrency to prevent memory exhaustion, empty column detection uses sampling instead of full-table scans, and exports are crash-safe if a tab closes mid-write
- **NTFS Analysis Tools** — Six tools for raw `$MFT` and `$J` files: ransomware scanning, timestomping detection, file activity heatmaps, ADS analysis, USN Journal forensics with [UsnJrnl Rewind](https://cybercx.com.au/blog/ntfs-usnjrnl-rewind/) path reconstruction (11 categories), and resident data extraction for recovering deleted threat actor artifacts
- **VirusTotal Integration** — Single and bulk IOC lookups with persistent cache, configurable rate limiting, color-coded verdict badges, and auto-tagging. Bulk lookups are now cancellable mid-retry and stop automatically if the window closes
- **Auto-Update** — In-app update notifications with download progress and one-click install
- **Analyst Profiles** — Suppressions and baselines for Process Inspector false-positive management
- **Attack Pattern Detection** — Automated MITRE ATT&CK-mapped findings for brute force, password spray, credential compromise, Impacket (5 variants), and RMM tool scanning (33 tools + 7 tunnels)

[Full changelog →](/about/changelog)

## What is IRFlow Timeline?

IRFlow Timeline is a native macOS application purpose-built for digital forensics and incident response (DFIR) investigators. Inspired by Eric Zimmerman's Timeline Explorer for Windows, it brings high-performance timeline analysis to macOS with a modern interface and advanced analytics.

### Who Is This For?

- **Incident Responders** — reconstruct kill chains across endpoints on macOS, no Windows VM required
- **SOC Analysts** — triage KAPE collections and hunt through millions of event log entries at native speed
- **Forensic Examiners** — correlate MFT, Prefetch, Amcache, and registry artifacts in a single unified timeline
- **Threat Hunters** — detect lateral movement patterns, stack column values, and sweep IOC lists across your environment
- **IR Consultants** — deliver tagged and bookmarked evidence packages ready for client reporting

If you've hit Excel's 1M-row limit on a super-timeline, or you're tired of spinning up a Windows VM just to run Timeline Explorer — this is the tool that replaces both.

### Supported Formats

| Format | Extensions | Description |
|--------|-----------|-------------|
| **CSV/TSV** | `.csv`, `.tsv`, `.txt`, `.log` | Auto-detects delimiters (comma, tab, pipe) |
| **Excel** | `.xlsx`, `.xls`, `.xlsm` | Streaming reader (XLSX) + legacy binary parser (XLS) with sheet selection |
| **EVTX** | `.evtx` | Windows Event Log binary format |
| **Plaso** | `.plaso`, `.timeline` | Forensic timeline database (`.timeline` auto-detects; falls back to CSV) |
| **Raw $MFT** | `.mft` | NTFS Master File Table — direct import for NTFS analysis tools |
| **Raw $J** | `.$J`, `.usn` | NTFS USN Journal (change journal) |

### Built for Scale

IRFlow Timeline uses a SQLite-backed architecture with streaming import, lazy indexing, and virtual scrolling to deliver responsive performance even on the largest forensic timelines. Handle large CSV files (tested with 30GB+), search across millions of rows, and visualize your timeline — all without freezing. Concurrent index builds are memory-capped, analytics queries are optimized to avoid redundant table scans, and all long-running operations are crash-safe with graceful recovery.

### KAPE-Ready

Automatic detection and pre-configuration for 24 KAPE tool output formats including MFTECmd, EvtxECmd, Hayabusa, Chainsaw, AmcacheParser, PECmd, RECmd, SBECmd, and more. Open your KAPE output and start analyzing immediately with optimized column layouts and color rules.
