# KAPE Integration

IRFlow Timeline automatically detects and pre-configures display settings for output from KAPE and Eric Zimmerman's (EZ) tools, giving you an optimized view from the moment you open a file.

## How Auto-Detection Works

When you open a CSV or XLSX file, IRFlow Timeline analyzes the column headers to identify the source tool. If a known profile matches, it automatically applies:

- **Column ordering** — most relevant columns first
- **Pinned columns** — key columns stay visible during horizontal scrolling
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
- **Unpin columns** via right-click
- **Change column order** via drag-and-drop
- **Override color rules** in the Color Rules editor

Your customizations are preserved when saving a [session](/workflows/sessions).

## Manual Profile Application

If auto-detection doesn't trigger (e.g., modified column names), you can't currently force a profile. The detection relies on exact column header matching.

::: tip Best Practice
When exporting from EZ Tools, use the default column configurations to ensure IRFlow Timeline recognizes the output format. Custom column selections may prevent auto-detection.
:::
