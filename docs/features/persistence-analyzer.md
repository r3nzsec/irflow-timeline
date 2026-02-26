# Persistence Analyzer

The Persistence Analyzer automatically scans your timeline data for Windows persistence mechanisms, scoring each finding by risk level and organizing results by category. It supports both EVTX event logs and registry exports, detecting over 30 distinct persistence techniques across services, scheduled tasks, WMI subscriptions, registry autorun keys, and more.

## Opening the Persistence Analyzer

- **Menu:** Tools > Persistence Analyzer

## Data Source Modes

The analyzer supports three input modes, selectable in the configuration panel:

| Mode | Input Data | Best For |
|------|-----------|----------|
| **Auto-detect** | Analyzes column names to determine type | Quick start -- let the tool decide |
| **EVTX Logs** | EvtxECmd CSV or parsed EVTX output | Event-based persistence (services, tasks, WMI) |
| **Registry Export** | RECmd or other registry CSV output | Registry-based persistence (Run keys, COM hijacks, LSA) |

In auto-detect mode, the analyzer examines your column headers to determine whether the data contains event log fields (`EventId`, `Channel`, `Provider`) or registry fields (`KeyPath`, `ValueName`, `ValueData`).

## EVTX Detection Rules

When analyzing event logs, the Persistence Analyzer scans for 18 indicator types across multiple log channels:

### Services

| Event ID | Source | Description |
|----------|--------|-------------|
| 7045 | System | New service installed |
| 4697 | Security | Service installed (auditing) |

### Scheduled Tasks

| Event ID | Source | Description |
|----------|--------|-------------|
| 4698 | Security | Scheduled task created |
| 4699 | Security | Scheduled task deleted |
| 106 | Task Scheduler | Task registered |
| 129 | Task Scheduler | Task launch attempt |
| 140 | Task Scheduler | Task updated |
| 200 | Task Scheduler | Task action started |

### WMI Persistence

| Event ID | Source | Description |
|----------|--------|-------------|
| 5861 | WMI-Activity | WMI permanent event consumer registered |
| Sysmon 19 | Sysmon | WMI event filter created |
| Sysmon 20 | Sysmon | WMI event consumer created |
| Sysmon 21 | Sysmon | WMI filter-to-consumer binding |

### File System and Process Indicators

| Event ID | Source | Description |
|----------|--------|-------------|
| Sysmon 2 | Sysmon | File creation time changed (timestomping) |
| Sysmon 6 | Sysmon | Driver loaded |
| Sysmon 7 | Sysmon | Image loaded (DLL hijacking) |
| Sysmon 11 | Sysmon | File created (startup folder drops) |
| Sysmon 13 | Sysmon | Registry value set (autorun modifications) |
| Sysmon 15 | Sysmon | Alternate data stream created |
| Sysmon 25 | Sysmon | Process tampering |

## Registry Detection Rules

When analyzing registry exports, the analyzer checks 15 persistence locations:

| Location | Registry Path | Technique |
|----------|--------------|-----------|
| Run / RunOnce | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Autostart execution |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath` | Service DLL/binary |
| Winlogon | `...\Winlogon\Shell`, `Userinit`, `Notify` | Logon persistence |
| AppInit_DLLs | `...\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | DLL injection |
| IFEO Debugger | `...\Image File Execution Options\*\Debugger` | Debugger hijack |
| COM Hijacking | `...\Classes\CLSID\*\InprocServer32`, `LocalServer32` | COM object redirect |
| Shell Extensions | `...\ShellIconOverlayIdentifiers`, `ShellExtensions` | Explorer persistence |
| BootExecute | `...\Session Manager\BootExecute` | Pre-logon execution |
| BHO | `...\Browser Helper Objects` | Browser persistence |
| LSA Packages | `...\LSA\Security Packages`, `Authentication Packages` | Security provider |
| Print Monitors | `...\Print\Monitors\*\Driver` | Spoolsv persistence |
| Active Setup | `...\Active Setup\Installed Components\*\StubPath` | Per-user execution |
| Startup Folder | `...\Explorer\User Shell Folders\Startup` | Startup redirect |
| Scheduled Tasks | `...\Schedule\TaskCache\Tasks` | Task registry entries |
| Network Providers | `...\NetworkProvider\Order` | Network logon persistence |

## Risk Scoring

Each detected persistence mechanism receives a risk score on a 0-10 scale. The score is calculated from:

1. **Base severity** -- determined by the persistence technique category (e.g., WMI subscriptions score higher than Run keys)
2. **Suspicious path indicators** -- execution from `\Temp\`, `\AppData\`, `\Downloads\`, or `\ProgramData\` increases the score
3. **Suspicious commands** -- presence of `powershell`, `cmd.exe`, encoded commands, or known LOLBins raises the score
4. **Encoding detection** -- Base64-encoded command lines or obfuscated payloads add to the score

### Severity Levels

| Level | Score Range | Color |
|-------|-----------|-------|
| **Critical** | 9-10 | Red |
| **High** | 6-8 | Orange |
| **Medium** | 3-5 | Yellow |
| **Low** | 0-2 | Gray |

## Results Interface

After the scan completes, the results panel displays four key statistics:

- **Total Found** -- total number of persistence mechanisms detected
- **Critical** -- count of critical-severity findings
- **Categories** -- number of distinct persistence categories
- **Hosts** -- number of unique hosts with persistence (for multi-host timelines)

### Filtering Results

The results panel includes a filter bar with:

- **Search** -- full-text search across all findings
- **Severity filter** -- show only critical, high, medium, or low findings
- **Category filter** -- filter by persistence type (Services, Scheduled Tasks, WMI, Registry, etc.)

### View Modes

Results can be displayed in three different layouts:

#### Grouped View

Findings organized under collapsible category headers (e.g., "Services", "Scheduled Tasks", "WMI Subscriptions"). Each category shows its finding count. Up to 200 items are displayed per category.

#### Timeline View

Findings sorted chronologically, showing when each persistence mechanism was installed. This view reveals the temporal sequence of persistence activity and is limited to 500 items for performance.

#### Table View

A flat tabular view of all findings with sortable columns. No item limit -- all findings are displayed.

### Item Details

Click any finding to expand its details panel showing:

- Full registry path or event log entry
- Command line or executable path
- Timestamp of installation
- Associated user account
- Source host
- Risk score breakdown

### Bulk Operations

Use the checkbox selection to select multiple findings for:

- Bulk tagging in the source timeline
- Filtering the source tab to selected items
- Exporting selected findings

## Cross-Event Correlation

The analyzer automatically correlates related events. For example:

- A scheduled task creation (Event ID 4698) is enriched with the task executable extracted from the XML task definition
- Service installations (Event ID 7045) are correlated with their `ImagePath` to identify the binary
- WMI subscriptions link filter, consumer, and binding events into a single finding

## Filter Awareness

The Persistence Analyzer respects all active filters on the source tab:

- Column filters
- Checkbox filters
- Search terms
- Date range filters
- Bookmark filter
- Advanced filters

This means you can narrow your timeline to a specific time window or host before running the analysis, focusing results on the scope that matters.

## Investigation Tips

::: tip Start with Auto-Detect
Let the analyzer auto-detect your data mode. It correctly identifies EVTX vs registry data in most cases and saves configuration time.
:::

::: tip Focus on Critical and High
Sort by severity and start with critical/high findings. Low-severity items often represent legitimate system services and can be reviewed later if needed.
:::

::: tip Combine with Process Tree
After identifying a suspicious persistence mechanism, use the [Process Tree](/features/process-tree) to trace what process installed it and what the persisted binary spawns on execution.
:::

::: tip Multi-Host Analysis
When analyzing merged timelines from multiple hosts, use the host filter to isolate findings per system. Persistence on a domain controller carries different weight than on a workstation.
:::

::: tip Correlate with Lateral Movement
Persistence is often installed after lateral movement. Cross-reference persistence timestamps with the [Lateral Movement Tracker](/features/lateral-movement) to identify which hop preceded each persistence installation.
:::
