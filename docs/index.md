---
layout: home
description: Native macOS DFIR timeline analysis — EVTX, CSV, XLSX, Plaso, $MFT, $J, and local AI app artifacts with AI Secret Hunt and built-in investigation analytics.

hero:
  name: IRFlow Timeline
  text: DFIR Timeline Analysis
  tagline: Native macOS forensic timeline analysis. Import, search, and investigate EVTX, CSV, XLSX, Plaso, $MFT, $J, and local AI assistant artifacts — with AI Secret Hunt and the analytics DFIR professionals actually need.
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
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v4"/><path d="M12 17v4"/><path d="M3 12h4"/><path d="M17 12h4"/><rect x="7" y="7" width="10" height="10" rx="2" fill="rgba(232,93,42,0.18)"/><path d="M10 11h4M10 14h2"/></svg>'
    title: AI Artifacts
    details: Scan local AI history from ChatGPT Desktop, Claude Code, Codex, Grok Build, Cursor, Copilot, Gemini CLI, Windsurf, and Continue — plus ChatGPT Computer History interaction telemetry. Preserve prompts, responses, tool calls, workspaces, and secret exposure evidence.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/><line x1="11" y1="8" x2="11" y2="14"/></svg>'
    title: 5 Search Modes
    details: Mixed, FTS, LIKE, Fuzzy, and Regex. Full-text search, substring matching, typo-tolerant fuzzy, and pattern matching across millions of rows.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="rgba(232,93,42,0.15)"/><path d="M9 12l2 2 4-4"/></svg>'
    title: Sigma Detection
    details: Dual-engine Sigma scanning — bundled Hayabusa over raw EVTX plus an in-app JS engine for imported timelines, with MITRE ATT&CK-mapped triage, custom rules, and persistent scan history.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v6"/><circle cx="12" cy="12" r="3"/><path d="M12 15v3"/><path d="M8 15l-3 3"/><path d="M16 15l3 3"/><path d="M5 18v2"/><path d="M12 18v2"/><path d="M19 18v2"/></svg>'
    title: Process Inspector
    details: Reconstruct process trees from Sysmon and Security logs — Story/Graph/Raw views, multi-pass enrichment, ~330 chain rules + ~60 standalone detections, rule health coverage, and one-click Filter Grid pivots.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="18" r="3"/><line x1="8.5" y1="7.5" x2="15.5" y2="16.5"/><line x1="15.5" y1="7.5" x2="8.5" y2="16.5"/><line x1="6" y1="9" x2="6" y2="15"/><line x1="18" y1="9" x2="18" y2="15"/></svg>'
    title: Lateral Movement Tracker
    details: Network graph with multi-hop chain reconstruction and RDP session correlation. Detects brute force, password spray, Impacket, 33 RMM tools, and 7 network tunnels.
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#E85D2A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="rgba(232,93,42,0.15)"/><path d="M9 12l2 2 4-4"/></svg>'
    title: Persistence Analyzer
    details: 36 EVTX + 33 registry persistence rules with risk scoring across services, scheduled tasks, WMI subscriptions, and autorun keys.
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

## What's New · v1.0.11

- **Computer History analysis verified against a live capture** — Credential rows are time anchors, not recovered passwords; capture fidelity is measured per application rather than assumed from the app's category; and gaps spanning a recorder restart are reported as unassessed instead of falsely cleared.
- **The copy that outlives the evidence** — Activity consolidated into `~/.codex/memories/` is neither purged at 48 hours nor cleared with Computer History, and is now collected. On a stale host it can be the only surviving record.
- **More of each summary** — The model-inferred user profile and carried-forward prior context become their own rows instead of being flattened into one blob.
- **Grok Build and Claude Desktop stores that outlive the conversation** — Deletion tombstones that date a removed chat, the files staged for upload to it, the Grok search index that mirrors a deleted session's text, and the app log that timestamps tool executions independently of it.
- **Sharper grid** — Mouse modifiers reach `KeyChord` (a command-click opens a link in a background tab), and click multiplicity is named by meaning rather than producing ten numeric Activity values.

[Read the v1.0.11 announcement →](/blog/v1.0.11-computer-history-verified) · [Computer History in v1.0.10 →](/blog/v1.0.10-computer-history) · [Full changelog →](/about/changelog)

## What is IRFlow Timeline?

Native macOS timeline analysis for DFIR — EVTX, KAPE super-timelines, and local AI artifacts in one app. Timeline Explorer–style workflow on Mac, plus built-in detection analytics and **AI Secret Hunt**.

### Who Is This For?

- **Incident Responders** — kill-chain reconstruction on macOS; review AI usage on triaged endpoints
- **SOC Analysts** — triage KAPE collections and hunt millions of events at native speed
- **Forensic Examiners** — MFT, Prefetch, Amcache, and registry in one unified timeline
- **Threat Hunters** — lateral movement detection, column stacking, and IOC sweeps
- **IR Consultants** — tagged, bookmarked evidence packages for client reporting
- **AI-assisted investigations** — collect local AI history, hunt pasted secrets, correlate with endpoint activity

Excel row limits, Windows VM overhead, or missing AI evidence — IRFlow is the macOS alternative to Timeline Explorer.

### Supported Formats

| Format | Extensions | Description |
|--------|-----------|-------------|
| **CSV/TSV** | `.csv`, `.tsv`, `.txt`, `.log` | Auto-detects delimiters (comma, tab, pipe) |
| **Excel** | `.xlsx`, `.xls`, `.xlsm` | Streaming reader (XLSX) + legacy binary parser (XLS) with sheet selection |
| **EVTX** | `.evtx` | Windows Event Log binary format; bounded 64 KiB chunk parsing up to the format's ~4 GiB limit |
| **Plaso** | `.plaso`, `.timeline` | Forensic timeline database (`.timeline` auto-detects; falls back to CSV) |
| **Raw $MFT** | `.mft` | NTFS Master File Table — direct import for NTFS analysis tools |
| **Raw $J** | `.$J`, `.usn` | NTFS USN Journal (change journal) |
| **AI app artifacts** | folders / JSONL / SQLite / LevelDB | Scan local AI history from supported desktop, CLI, and editor assistants |
| **ChatGPT Computer History** | Skysight `events.jsonl` segments + summary `.md` | macOS interaction telemetry — focus, clicks, keystrokes, selections, drags (own tab, 54-column schema) |

### Built for Scale

SQLite streaming import, lazy indexing, and virtual scrolling keep 30GB+ timelines responsive. Search millions of rows without freezing — memory-capped index builds and crash-safe long-running jobs.
