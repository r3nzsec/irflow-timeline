---
title: Interactive Demo
description: Try IRFlow Timeline's search, filter, and sort capabilities directly in your browser — no installation required.
---

# Interactive Demo

Experience IRFlow Timeline's core EVTX timeline workflow on a realistic 50-event attack scenario — directly in your browser. AI Artifacts and AI Secret Hunt are app-only features (not shown in this browser demo).

<InteractiveDemo />

## What You're Seeing

The 50 events above tell the story of a complete attack chain across 7 phases:

| Phase | Events | What Happened |
|-------|--------|---------------|
| **Initial Access** | 1–5 | Phishing email → malicious .docm opened via Outlook |
| **Execution** | 6–12 | Encoded PowerShell, C2 beacon to 185.220.101.42 |
| **Discovery** | 13–18 | whoami, net group, nltest, systeminfo enumeration |
| **Credential Access** | 19–25 | mimikatz, LSASS dump, secretsdump, procdump |
| **Lateral Movement** | 26–35 | PsExec to DC01, RDP to SRV-DB01, WMIC, WinRM |
| **Persistence** | 36–40 | Registry Run key, service install, scheduled tasks |
| **Impact** | 41–50 | Shadow delete, ransomware encryption, log clearing |

## Timeline Histogram

The histogram above the grid buckets events by minute (03:10–03:27). It updates live as you search — try "mimikatz" to see activity spike at 03:15, or "DC01" to watch it shift to the 03:18+ lateral movement window. The **burst label** dynamically identifies the densest 3-minute window.

## Process Inspector

The process tree below the grid reconstructs the attack chain from Sysmon Event ID 1 (process creation). Each node shows the parent-child relationship, with **MITRE ATT&CK technique IDs** (blue badges) and **threat labels** (red badges) on suspicious processes. The tree tells the classic phishing-to-ransomware story: `explorer.exe → outlook.exe → WINWORD.EXE → cmd.exe → powershell.exe → mimikatz/PsExec/procdump`.

## Search Modes

| Mode | How It Works | Example |
|------|-------------|---------|
| **Text** | Case-insensitive substring match across all columns | `mimikatz`, `4624`, `DC01` |
| **Regex** | Full regular expression with `new RegExp(pattern, 'i')` | `\d+\.\d+` matches IP addresses, `PsExec\|wmic` matches either |
| **Fuzzy** | Bigram similarity — tolerates typos and partial matches | `mimkatz` still finds mimikatz, `powrshell` finds powershell |

## Lateral Movement Tracker

Below the grid you'll see a **network graph** showing how the attacker moved between machines. The key insight: IRFlow immediately identifies the threat actor's machine by hostname pattern matching.

In this scenario, the attacker connected via RDP from a machine named **KALI** — the default Kali Linux hostname. IRFlow's two-tier outlier detection automatically flags this:

- **Tier 1 (Red)**: Known attacker OS defaults — `KALI`, `PARROT`, `HACKER`, `ATTACKER`
- **Tier 2 (Orange)**: Suspicious patterns — `DESKTOP-XXXXXXX`, `WIN-XXXXXXXX`, `VPS`, `WINVM`

Click any node in the graph to highlight its connections.

## Tips

- **Click column headers** to sort ascending, click again for descending, third click to reset
- **Click any row** to expand full details (especially useful on mobile)
- **Press Escape** to clear the search field
- The **histogram** updates reactively as you search — watch the burst detection shift
- The **sparkline** in the results bar updates live to show event density as you filter
- **Click graph nodes** to highlight connections in the lateral movement tracker

## Ready for the Real Thing?

The full app handles **30–50 GB+** forensic timelines with 847,000+ rows, DuckDB-backed virtual scrolling, process trees, lateral movement graphs, and 342 detection rules.

<div style="margin-top: 16px;">
  <a href="/irflow-timeline/getting-started/installation" style="display: inline-block; background: #E8613A; color: white; padding: 10px 24px; border-radius: 8px; text-decoration: none; font-weight: 600;">Install IRFlow Timeline</a>
</div>
