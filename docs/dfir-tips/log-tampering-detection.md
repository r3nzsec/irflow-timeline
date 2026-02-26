# Log Tampering & Anti-Forensics Detection

Attackers frequently attempt to cover their tracks by clearing event logs, stopping logging services, and manipulating file timestamps. This guide walks through a systematic approach to detecting these anti-forensics techniques using IRFlow Timeline.

::: info Features Used
- [Gap Analysis](/features/gap-burst-analysis) -- identify suspicious voids in log activity
- [Log Source Coverage](/features/log-source-coverage) -- visualize which sources stopped recording and when
- [Stacking](/features/stacking) -- surface anomalous event patterns and rare artifacts
- [Search (Full-Text Search)](/features/search-filtering) -- locate anti-forensic tool names and commands
:::

## Key Event IDs

Before diving into the workflow, familiarize yourself with the Windows Event IDs most relevant to log tampering and anti-forensics.

### Log Clearing Events

| Event ID | Source | Description |
|----------|--------|-------------|
| **1102** | Security | The audit log was cleared |
| **104** | System | The System log file was cleared |
| **1100** | Security | The event logging service has shut down |

### Service Manipulation Events

| Event ID | Source | Description |
|----------|--------|-------------|
| **7045** | System | A new service was installed in the system |
| **7036** | System | A service entered the running or stopped state |
| **7040** | System | The start type of a service was changed |

### Timestamp Manipulation Events

| Event ID | Source | Description |
|----------|--------|-------------|
| **Sysmon 2** | Sysmon | A process changed a file creation time (timestomping indicator) |
| **USN Journal** | NTFS | File creation, deletion, rename, and timestamp change records |

---

## Step-by-Step Workflow

### 1. Assess Log Source Coverage First

Start every anti-forensics investigation by understanding what data you actually have -- and what might be missing.

1. Open **Tools > Log Source Coverage**
2. Examine the heatmap for each log source across the timeline span
3. Look for the following patterns:

| Pattern | Interpretation |
|---------|---------------|
| Security log goes dark while System continues | Targeted Security log clearing or audit policy tampering |
| All Windows event logs stop simultaneously | Host was powered off, or event logging service was killed |
| Sysmon disappears mid-timeline | Sysmon service was stopped or uninstalled |
| A source appears only briefly | Attacker may have enabled logging temporarily, or artifact was partially overwritten |

::: tip Start Here Every Time
Log Source Coverage should be your first stop. If a critical log source is missing entirely or drops out mid-timeline, every subsequent finding must be interpreted with that gap in mind. Document missing sources before proceeding.
:::

### 2. Run Gap Analysis on Individual Log Sources

Use Gap Analysis to pinpoint the exact timestamps where logging ceased and resumed.

1. Filter the main grid to a single log source (e.g., channel = "Security")
2. Open **Tools > Gap Analysis**
3. Set the gap threshold to a value appropriate for the source:
   - **Security logs:** 5-15 minutes (these should be nearly continuous on active systems)
   - **Sysmon logs:** 5-30 minutes depending on system activity
   - **System logs:** 30-60 minutes (lower event frequency is normal)
4. Record any gaps that cannot be explained by normal system idle periods

::: tip Compare Pre-Gap and Post-Gap Events
Examine the last event before each gap and the first event after. If the pre-gap event is Event ID 1102 (log cleared) or 7036 (service stopped), you have strong evidence of deliberate tampering. Bookmark both events for your final report.
:::

### 3. Search for Log Clearing Events

Use Full-Text Search to find explicit evidence that logs were cleared.

1. Press `Cmd+F` to open the search bar
2. Set the search mode to **FTS**
3. Search for each of the following terms:

```
1102
104
"audit log was cleared"
wevtutil
Clear-EventLog
```

4. For each hit, record:
   - The timestamp of the clearing event
   - The user account that performed the action
   - The logon session associated with the account
5. [Bookmark](/features/bookmarks-tags) each log-clearing event and tag it (e.g., "log-tampering")

Pay special attention to `wevtutil cl` commands, which clear specific log channels from the command line, and PowerShell `Clear-EventLog` or `Remove-EventLog` cmdlets.

### 4. Identify Service Manipulation

Attackers often stop or disable logging services rather than clearing logs outright. This avoids generating Event ID 1102 but still creates a gap.

1. Search for Event ID **7036** and filter for service names containing:
   - `EventLog` (Windows Event Log service)
   - `Sysmon` or `Sysmon64`
   - `WinDefend` (Windows Defender)
   - `SysmonDrv` (Sysmon driver)
2. Search for Event ID **7045** to identify new services installed around the time of compromise -- attackers sometimes install a service to disable logging or deploy persistence
3. Search for Event ID **7040** to find services whose start type was changed (e.g., from Automatic to Disabled)

::: tip Stack Service Names
Open [Stacking](/features/stacking) on the service name or description column filtered to Event IDs 7036/7045/7040. Sort ascending by count to surface rare service names. A service that appears only once or twice is far more suspicious than Windows Update or BITS.
:::

### 5. Detect Timestomping

Timestomping -- the deliberate modification of file timestamps -- is a common anti-forensics technique used to make malicious files blend in with legitimate system files.

#### Sysmon Event ID 2

1. Search for Sysmon Event ID **2** ("File creation time changed")
2. These events record:
   - The process that changed the timestamp
   - The original creation time
   - The new creation time
3. Flag entries where the new creation time is significantly older than the original -- this indicates a file was backdated to appear as if it was present before the compromise

#### MFT and USN Journal Analysis

If your timeline includes NTFS artifacts ($MFT, $UsnJrnl, $LogFile):

1. Stack the **reason** or **update reason** column in USN Journal entries to identify `CLOSE + DATA_EXTEND + FILE_CREATE` patterns
2. Compare $MFT `$STANDARD_INFORMATION` timestamps with `$FILE_NAME` timestamps -- discrepancies are a classic timestomping indicator
3. Search for files in suspicious directories (e.g., `\Windows\System32\`, `\Windows\Temp\`) with creation times that predate the OS installation but modification times during the incident window

::: tip $SI vs $FN Timestamp Discrepancy
The `$STANDARD_INFORMATION` attribute timestamps can be modified by user-mode tools like Timestomp, but the `$FILE_NAME` attribute timestamps can only be updated by the kernel. When the $FN creation time is later than the $SI creation time, timestomping has almost certainly occurred.
:::

### 6. Search for Known Anti-Forensic Tools

Use Full-Text Search to sweep the timeline for tool names associated with anti-forensics activity.

1. Set the search mode to **FTS** or **Mixed**
2. Search for the following terms individually:

| Search Term | What It Indicates |
|-------------|-------------------|
| `Timestomp` | Metasploit timestomping module |
| `CCleaner` | System cleaner that wipes logs, temp files, and browser history |
| `SDelete` | Sysinternals secure delete tool (used to wipe files and free space) |
| `BleachBit` | Open-source cleaner that removes logs and artifacts |
| `wevtutil` | Windows command-line utility for managing event logs |
| `Clear-EventLog` | PowerShell cmdlet to clear event logs |
| `Invoke-Phant0m` | PowerShell script that kills Event Log service threads |
| `MoonBounce` | Firmware-level persistence and anti-forensics |
| `cipher /w` | Windows command to overwrite deleted data on a volume |

3. For any matches, examine the full row context -- the parent process, command line arguments, user account, and timestamp
4. [Bookmark and tag](/features/bookmarks-tags) every confirmed anti-forensics artifact

### 7. Use Stacking to Find Anomalous Patterns

Stacking can reveal anti-forensic activity even when you do not know what to search for.

1. Open [Stacking](/features/stacking) on the **EventID** column
   - Look for unexpected Event IDs or an unusually low count of a normally high-volume ID (suggesting partial log clearing)
2. Stack on **Image** or **Process Name**
   - Sort ascending to find rare executables -- anti-forensic tools often appear only once or twice
3. Stack on **Channel** or **Log Source**
   - Compare the event counts per source against baseline expectations; a Security log with far fewer events than the System log is suspicious
4. Stack on **User** filtered to the incident timeframe
   - Identify which accounts were active during log-clearing events

::: tip Combine Stacking with Time Filters
Narrow your date range to the suspected compromise window before stacking. This isolates attacker-related values from the noise of normal system operation, making rare artifacts easier to spot.
:::

### 8. Correlate and Build the Tampering Timeline

With all indicators collected, build a coherent narrative of the anti-forensic activity.

1. Filter the grid to show only [bookmarked](/features/bookmarks-tags) rows tagged with your tampering-related tags
2. Sort by timestamp to see the sequence of events
3. Apply [color rules](/features/color-rules) to distinguish between log clearing (e.g., red), service manipulation (e.g., orange), and timestomping (e.g., purple)
4. Use [Export](/workflows/export-reports) to generate a report of the anti-forensics timeline for inclusion in your final deliverable

---

## Common Anti-Forensics Sequences

The following patterns indicate a deliberate and methodical cover-up:

1. **Service stop, then gap, then service start** -- The attacker stopped the Event Log service, performed their activity, and restarted it. The gap in Gap Analysis corresponds precisely to the service stop/start window.

2. **Log clear immediately after lateral movement** -- Event ID 1102 appears shortly after remote logon events (Event IDs 4624 type 3/10, 4648). The attacker moved to a new host and cleared the logs behind them.

3. **Timestomped files in system directories** -- Sysmon Event ID 2 shows file creation times being backdated for executables dropped in `System32` or `SysWOW64`, attempting to blend in with legitimate OS files.

4. **Bulk USN Journal deletions** -- A cluster of `FILE_DELETE` and `CLOSE` reason codes in the USN Journal during a short window, especially when no corresponding file creation events exist in other log sources.

---

## Next Steps

- [Lateral Movement Tracing](/dfir-tips/lateral-movement-tracing) -- follow the attacker's path across hosts and check for log clearing at each hop
- [Ransomware Investigation](/dfir-tips/ransomware-investigation) -- ransomware operators routinely clear logs before and after encryption
- [Persistence Hunting](/dfir-tips/persistence-hunting) -- services installed for persistence (Event ID 7045) often overlap with anti-forensics activity
- [Malware Execution Analysis](/dfir-tips/malware-execution-analysis) -- trace the execution chain of anti-forensic tools back to the initial payload
- [Building the Final Report](/dfir-tips/building-final-report) -- incorporate your tampering findings as a dedicated section in the investigative report
