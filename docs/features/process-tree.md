# Process Tree

The Process Tree visualizes parent-child process relationships from Sysmon Event ID 1 (Process Create) logs, providing a hierarchical view of execution chains with automatic suspicious pattern detection.

![Process Tree showing GUID-linked parent-child process hierarchy with cmd.exe and powershell.exe execution chains](/dfir-tips/Process-Tree.png)

## Opening the Process Tree

- **Menu:** Tools > Process Tree
- Requires Sysmon Event ID 1 data (from EVTX or CSV export)

## How It Works

The Process Tree builds a hierarchy by linking processes through their parent-child relationships:

1. **GUID-preferred linking** — uses `ProcessGuid` and `ParentProcessGuid` when available, which correctly handles PID reuse (a common forensic challenge)
2. **PID fallback** — falls back to `ProcessId` and `ParentProcessId` for logs without GUIDs
3. **Root detection** — processes without a known parent become root nodes

## Auto-Detected Columns

IRFlow Timeline automatically identifies the relevant columns from your data:

| Column | Purpose |
|--------|---------|
| `ProcessId` | Process identifier |
| `ParentProcessId` | Parent process identifier |
| `ProcessGuid` | Unique GUID (Sysmon) |
| `ParentProcessGuid` | Parent GUID (Sysmon) |
| `Image` | Executable path |
| `CommandLine` | Full command line |
| `User` | Account context |
| `UtcTime` | Timestamp |
| `EventID` | Event identifier |

### EvtxECmd Support

When working with EvtxECmd CSV output, the Process Tree extracts real PID and GUID values from `PayloadData1` and `PayloadData5` fields. This is important because EvtxECmd records the logging service PID by default — the tree uses the extracted values for accurate hierarchy building.

## Suspicious Pattern Detection

The Process Tree automatically highlights suspicious execution patterns using color-coded indicators:

### Red — High Suspicion

- **Office to script spawn** — Microsoft Office applications (Word, Excel, PowerPoint, Outlook) spawning script interpreters or shells
  - Example: `WINWORD.EXE → cmd.exe → powershell.exe`

### Orange — LOLBins (Living off the Land)

Known legitimate binaries commonly abused by attackers:

- `cmd.exe`
- `powershell.exe` / `pwsh.exe`
- `wscript.exe` / `cscript.exe`
- `mshta.exe`
- `certutil.exe`
- `bitsadmin.exe`
- `rundll32.exe`
- `regsvr32.exe`

### Yellow — Temp Path Execution

Processes running from temporary or user-writable directories:

- `\Temp\`
- `\AppData\`
- `\Downloads\`
- `\ProgramData\`

## Navigation

### Expand / Collapse

- Click the arrow next to any process to expand or collapse its children
- Use the depth limit control to set maximum visible tree depth
- Expand All / Collapse All buttons in the toolbar

### Ancestor Chain Highlighting

Click any process node to highlight its full ancestor chain from root to the selected process. This shows the complete execution path that led to the selected process.

### Filter to Process

Click the filter icon on a process node to filter the main data grid to rows matching that process's PID. This lets you see all events associated with a specific process.

## Modal Controls

The Process Tree opens in a resizable, draggable modal:

- Drag the title bar to reposition
- Drag edges to resize
- Depth limit slider controls maximum visible hierarchy depth
- Close with the X button or `Escape`

## Tips

::: tip Sysmon Configuration
For best results, ensure Sysmon is configured to log Event ID 1 (Process Create) with command line logging enabled. The more data available, the richer the process tree.
:::

::: tip Large Datasets
For datasets with thousands of processes, use the depth limit control to start with a shallow view (depth 3-4) and expand specific branches of interest.
:::
