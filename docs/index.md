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
  - icon: "\u26A1"
    title: Blazing Fast
    details: SQLite-powered virtual scrolling handles millions of rows. Streaming import processes 30-50GB+ files without breaking a sweat.
  - icon: "\uD83D\uDD0D"
    title: 5 Search Modes
    details: Full-text search, LIKE, Regex, Fuzzy matching, and Mixed mode. Find exactly what you need across massive timelines.
  - icon: "\uD83C\uDF33"
    title: Process Tree
    details: GUID-aware process hierarchy visualization from Sysmon logs with suspicious pattern detection for LOLBins, Office spawns, and temp paths.
  - icon: "\uD83C\uDF10"
    title: Lateral Movement Tracker
    details: Interactive force-directed network graph showing logon events, movement chains, and multi-hop detection across your environment.
  - icon: "\uD83D\uDCCA"
    title: Rich Analytics
    details: Timeline histogram, gap analysis, burst detection, log source coverage heatmaps, and value frequency stacking.
  - icon: "\uD83C\uDFF7\uFE0F"
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

IRFlow Timeline uses a SQLite-backed architecture with streaming import, lazy indexing, and virtual scrolling to deliver responsive performance even on the largest forensic timelines. Import a 50GB CSV, search across millions of rows, and visualize your timeline — all without freezing.

### KAPE-Ready

Automatic detection and pre-configuration for 15+ KAPE tool output formats including MFTECmd, EvtxECmd, Hayabusa, Chainsaw, AmcacheParser, and more. Open your KAPE output and start analyzing immediately with optimized column layouts and color rules.
