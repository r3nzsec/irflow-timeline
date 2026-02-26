---
layout: home

hero:
  name: IRFlow Timeline
  text: DFIR Timeline Analysis
  tagline: High-performance forensic timeline viewer for MacOS. Handles large files for timeline analysis. CSV/TSV/XLSX/EVTX/Plaso
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
    details: SQLite-powered virtual scrolling handles millions of rows. Streaming import handles large CSV files (tested with 30GB+) without breaking a sweat.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/><line x1="11" y1="8" x2="11" y2="14"/></svg>'
    title: 5 Search Modes
    details: Full-text search, LIKE, Regex, Fuzzy matching, and Mixed mode. Find exactly what you need across massive timelines.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v6"/><circle cx="12" cy="12" r="3"/><path d="M12 15v3"/><path d="M8 15l-3 3"/><path d="M16 15l3 3"/><path d="M5 18v2"/><path d="M12 18v2"/><path d="M19 18v2"/></svg>'
    title: Process Tree
    details: GUID-aware process hierarchy visualization from Sysmon and Windows Security logs with suspicious pattern detection for LOLBins, Office spawns, and temp paths.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="18" r="3"/><line x1="8.5" y1="7.5" x2="15.5" y2="16.5"/><line x1="15.5" y1="7.5" x2="8.5" y2="16.5"/><line x1="6" y1="9" x2="6" y2="15"/><line x1="18" y1="9" x2="18" y2="15"/></svg>'
    title: Lateral Movement Tracker
    details: Interactive force-directed network graph showing logon events, movement chains, and multi-hop detection across your environment.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><rect x="7" y="10" width="3" height="8" rx="0.5" fill="rgba(232,93,42,0.3)"/><rect x="12" y="6" width="3" height="12" rx="0.5" fill="rgba(232,93,42,0.3)"/><rect x="17" y="13" width="3" height="5" rx="0.5" fill="rgba(232,93,42,0.3)"/></svg>'
    title: Rich Analytics
    details: Timeline histogram, gap analysis, burst detection, log source coverage heatmaps, and value frequency stacking.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" fill="rgba(232,93,42,0.3)"/></svg>'
    title: Investigation Workflow
    details: Bookmarks, color-coded tags, conditional formatting with KAPE-aware presets, and full session save/restore.
---

## What is IRFlow Timeline?

IRFlow Timeline is a native macOS application purpose-built for digital forensics and incident response (DFIR) investigators. Inspired by Eric Zimmerman's Timeline Explorer for Windows, it brings high-performance timeline analysis to macOS with a modern interface and advanced analytics.

### Supported Formats

| Format | Extensions | Description |
|--------|-----------|-------------|
| **CSV/TSV** | `.csv`, `.tsv`, `.txt`, `.log` | Auto-detects delimiters (comma, tab, pipe) |
| **Excel** | `.xlsx`, `.xls`, `.xlsm` | Streaming reader with sheet selection |
| **EVTX** | `.evtx` | Windows Event Log binary format |
| **Plaso** | `.plaso` | Forensic timeline database |

### Built for Scale

IRFlow Timeline uses a SQLite-backed architecture with streaming import, lazy indexing, and virtual scrolling to deliver responsive performance even on the largest forensic timelines. Handle large CSV files (tested with 30GB+), search across millions of rows, and visualize your timeline — all without freezing.

### KAPE-Ready

Automatic detection and pre-configuration for 15+ KAPE tool output formats including MFTECmd, EvtxECmd, Hayabusa, Chainsaw, AmcacheParser, and more. Open your KAPE output and start analyzing immediately with optimized column layouts and color rules.
