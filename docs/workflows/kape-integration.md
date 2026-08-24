---
description: KAPE integration — auto-detect and pre-configure display settings for 26 KAPE and EZ Tools output formats.
---

# KAPE Integration

IRFlow Timeline automatically detects and pre-configures display settings for output from KAPE and Eric Zimmerman's (EZ) tools, giving you an optimized view from the moment you open a file.

## Open Triage Collection

For a full KAPE (or similar) triage **folder** — not a single CSV — use:

**File → Open Triage Collection…**

1. Choose the collection root (for example a KAPE output directory or mounted evidence tree).
2. IRFlow inventories recognizable artifacts (EVTX channels, `$MFT` / `$J`, KAPE CSVs, Prefetch, Amcache, registry hives, LNK/Jump Lists, and more).
3. Review two independent lanes:
   - **Lateral Movement** — pre-selects LM-relevant EVTX (Security, Sysmon, TerminalServices, RDP, …), imports them as timeline tabs, then can hand off to the [Lateral Movement Tracker](/features/lateral-movement).
   - **EVTX → Sigma** — optional Hayabusa/Sigma path over the Windows event-log directory (same dual-engine flow as [Sigma Detection](/features/sigma-detection)).
4. Artifacts that this build cannot parse are **listed with a tool hint** (for example Prefetch → PECmd) rather than dropped silently.

Host attribution (when the collection encodes a hostname) is applied so imported tabs stay tied to the right endpoint. You can still open individual KAPE CSVs with **File → Open** for profile auto-detection below.

## How Auto-Detection Works

When you open a CSV or XLSX file, IRFlow Timeline analyzes the column headers to identify the source tool. If a known profile matches, it automatically applies:

- **Column ordering** — most relevant columns first
- **Hidden columns** — noise columns are hidden by default
- **Auto-color column** — a column is selected for automatic palette coloring

## Supported Profiles

### EZ Tools

| Profile | Tool | Key Columns |
|---------|------|-------------|
| **MFTECmd** | MFT parser | FileName, ParentPath, Extension, FileSize, Created, Modified |
| **EvtxECmd** | Event log parser | TimeCreated, EventId, Channel, Computer, PayloadData1-6 |
| **PECmd** | Prefetch parser | ExecutableName, RunCount, LastRun, Volume |
| **LECmd** | LNK file parser | SourceFile, TargetPath, Arguments, WorkingDirectory |
| **AmcacheParser (Files)** | Amcache files | FullPath, SHA1, FileSize, CompileTime |
| **AmcacheParser (Programs)** | Amcache programs | Name, Version, Publisher, InstallDate |
| **RECmd** | Registry parser | HivePath, Key, ValueName, ValueData, LastWriteTimestamp |
| **SBECmd** | ShellBags parser | AbsolutePath, ShellType, LastWriteTime, MFTEntry |
| **SrumECmd** | SRUM parser | ExeInfo, AppId, NetworkUsage, ForegroundTime |
| **AppCompatcache** | Shimcache | Path, LastModifiedTime, Executed |
| **JLECmd** | Jump Lists | FileName, Arguments, TargetPath, CreatedOn |

### Timeline Formats

| Profile | Description | Key Columns |
|---------|-------------|-------------|
| **ForensicTimeline** | Generic forensic timeline | datetime, timestamp_desc, source, sourcetype, message |
| **Plaso SuperTimeline** | Plaso psort output | datetime, source, sourcetype, type, display_name, message |
| **MacTime** | Bodyfile mactime | Date, Size, Type, Mode, UID, GID, File Name |
| **KapeMiniTimeline** | KAPE mini timeline | Date, Time, Source, Type, Short, Desc |
| **PsortTimeline** | Plaso psort CSV | date, time, timezone, source, sourcetype, type, user, host |

### Security Tools

| Profile | Tool | Key Columns |
|---------|------|-------------|
| **Hayabusa (Standard)** | Windows detection | Timestamp, RuleTitle, Level, Computer, Channel |
| **Hayabusa (Verbose)** | Detailed detection | Timestamp, RuleTitle, Level, Details, ExtraFieldInfo |
| **Chainsaw** | Detection rules | timestamp, name, level, computer, status |
| **BrowsingHistoryView** | Browser history | URL, Title, Visit Time, Browser |

### Miscellaneous

| Profile | Description |
|---------|-------------|
| **KAPE Copy Log** | KAPE collection log |

## Customizing After Detection

Auto-detection sets a starting point, but you can always customize:

- **Show hidden columns** via the Column Manager
- **Unpin columns** via `Cmd+Click`
- **Change column order** via drag-and-drop
- **Override color rules** in the Color Rules editor

Your customizations are preserved when saving a [session](/workflows/sessions).

## Manual Profile Application

If auto-detection doesn't trigger (e.g., modified column names), you can't currently force a profile. The detection relies on exact column header matching.

::: tip Best Practice
When exporting from EZ Tools, use the default column configurations to ensure IRFlow Timeline recognizes the output format. Custom column selections may prevent auto-detection.
:::

## AI App Artifacts in KAPE Collections

KAPE profile auto-detection covers EZ Tools CSV/XLSX output. **AI assistant history** is separate: collect local app paths from user profiles (`.claude`, `.codex`, `.cursor`, `.gemini`, `.continue`, ChatGPT app-data folders, VS Code-family `workspaceStorage/*/chatSessions/`, etc.) into your KAPE or triage package, then run **Tools → Analysis → AI Artifacts → Collect AI Artifacts** on the collection root.

IRFlow walks Windows, Linux, and macOS profile layouts and merges discovered AI stores into one **AI Query History** tab. See [KAPE Triage Workflow](/dfir-tips/kape-triage-workflow) and [AI Query History](/dfir-tips/ai-query-history) for collection paths and investigation tips.

## See Also

- [Color Rules](/features/color-rules) — KAPE profiles auto-apply color rule presets per tool
- [Merging Timelines](/workflows/merge-tabs) — merge multiple KAPE tool outputs into a unified timeline
- [Diff Tabs](/workflows/diff-tabs) — compare two collections or two runs of the same KAPE module
- [Virtual Grid](/features/virtual-grid) — auto-configured column layouts for each KAPE profile
- [KAPE Profiles Reference](/reference/kape-profiles) — full list of supported profiles and column mappings
- [AI Artifacts](/features/ai-artifacts) — collect and review local AI assistant history from KAPE folders
