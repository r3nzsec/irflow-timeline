# KAPE Triage Workflow: 30 Minutes to Findings

A structured approach to triaging KAPE collection output in IRFlow Timeline, broken into six five-minute blocks. By the end of this workflow you will have identified anomalies, traced execution chains, mapped lateral movement, matched known indicators, and saved your tagged findings for reporting.

::: info Features Used
- [Virtual Grid](/features/virtual-grid) -- loading and navigating KAPE output
- [Stacking](/features/stacking) -- frequency analysis for anomaly detection
- [Process Tree](/features/process-tree) -- visualizing execution chains
- [Lateral Movement](/features/lateral-movement) -- mapping network logon activity
- [IOC Matching](/features/ioc-matching) -- scanning for known indicators
- [Search and Filtering](/features/search-filtering) -- narrowing results
- [Bookmarks and Tags](/features/bookmarks-tags) -- marking findings
- [Color Rules](/features/color-rules) -- visual highlighting
- [Histogram](/features/histogram) -- temporal distribution
- [Log Source Coverage](/features/log-source-coverage) -- verifying evidence completeness
:::

## Prerequisites

Before starting, ensure you have KAPE output collected with one of the common target/module combinations.

### Common KAPE Profiles

| Profile | What It Collects | Typical Modules |
|---------|-----------------|-----------------|
| **KapeTriage** | File system, registry, event logs, prefetch, amcache, shimcache, SRUM | `!EZParser` or `!SANS_Triage` |
| **!EZParser** | Parses all collected artifacts using EZ Tools into CSV | MFTECmd, EvtxECmd, PECmd, LECmd, RECmd, AmcacheParser, SBECmd, AppCompatCacheParser, JLECmd |
| **!SANS_Triage** | Extended parsing with timeline generation | All EZParser modules plus Hayabusa, mini-timeline creation |

### Expected KAPE Output Directory Structure

After a collection with `KapeTriage` targets and `!EZParser` modules, the output directory looks like this:

```
<output_root>/
  <timestamp>_<hostname>/
    Module Results/
      EvtxECmd/
        EvtxECmd_Output.csv
      MFTECmd/
        MFTECmd_$MFT_Output.csv
      PECmd/
        PECmd_Output.csv
      AmcacheParser/
        Amcache_Files.csv
        Amcache_Programs.csv
      RECmd/
        RECmd_Batch_Output.csv
      SBECmd/
        SBECmd_Output.csv
      AppCompatCacheParser/
        AppCompatCacheParser_Output.csv
      JLECmd/
        JLECmd_Output.csv
      LECmd/
        LECmd_Output.csv
      SrumECmd/
        SrumECmd_Output.csv
```

IRFlow Timeline auto-detects each of these formats when opened. See [KAPE Profiles](/reference/kape-profiles) for full column configuration details.

---

## Minutes 0-5: Load KAPE Output

### 1. Open artifact files in separate tabs

Use the [Multi-Tab](/workflows/multi-tab) workflow to load each major artifact type into its own tab. Prioritize in this order:

1. **EvtxECmd output** -- the event logs are your primary timeline source
2. **PECmd output** -- prefetch data shows program execution history
3. **MFTECmd output** -- file system metadata for file creation and modification
4. **AmcacheParser output** -- application execution evidence with hashes

Open each CSV file and IRFlow Timeline will apply the correct [KAPE profile](/workflows/kape-integration) automatically, pinning and ordering columns for that artifact type.

### 2. Set the investigation time window

If you already have a rough incident timeframe, apply a date range filter in the [Search and Filtering](/features/search-filtering) panel on each tab. This narrows every subsequent analysis step to the relevant period.

### 3. Save an initial session

Save a [session](/workflows/sessions) immediately. Name it with the case number and hostname. This gives you a restore point before you begin tagging and filtering.

::: tip Multiple Hosts
If you have KAPE output from several systems, load each host into its own set of tabs. Use tab naming conventions like `HOST01 - EvtxECmd` and `HOST02 - EvtxECmd` to keep them organized. You can also [merge tabs](/workflows/merge-tabs) later to create a unified timeline across hosts.
:::

---

## Minutes 5-10: Log Source Coverage Check

### 4. Run Log Source Coverage

Open **Tools > Log Source Coverage** on your EvtxECmd tab. The heatmap reveals which event log channels are present and where gaps exist.

### 5. Check for expected log sources

Verify the following critical channels are present in the collection:

| Channel | Why It Matters |
|---------|---------------|
| **Security** | Logon events (4624, 4625, 4648), process creation (4688), privilege use |
| **System** | Service installs (7045), system start/stop, driver loads |
| **Sysmon/Operational** | Process creation (1), network connections (3), file creation (11) |
| **PowerShell/Operational** | Script block logging (4104), module loading |
| **Windows Defender/Operational** | Detection and remediation events |
| **TaskScheduler/Operational** | Scheduled task creation and execution |

### 6. Document coverage gaps

If any source shows gaps or is entirely absent, note this early. Gaps during the suspected incident window are especially significant -- they could indicate log tampering or incomplete collection.

::: tip Early Warning
A sudden drop in all log sources at a specific time often indicates a system reboot or shutdown. A drop in a single source (such as Security) while others continue may indicate selective log clearing -- check for Event ID 1102 (audit log cleared) around that time.
:::

---

## Minutes 10-15: Stacking for Anomalies

### 7. Stack event logs by Event ID

On the EvtxECmd tab, open **Tools > Stacking** and stack the **EventId** column. Review the distribution for these key event IDs:

| Event ID | Source | Significance |
|----------|--------|-------------|
| 1 | Sysmon | Process creation |
| 3 | Sysmon | Network connection |
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon |
| 4688 | Security | Process creation (native) |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 7045 | System | Service installed |
| 4104 | PowerShell | Script block logged |

### 8. Stack by rare executables

Switch to the PECmd tab and stack the **ExecutableName** column. Sort ascending to surface the rarest executables. Programs that ran only once or twice are prime candidates for malicious binaries.

### 9. Stack by file paths

On the MFTECmd tab, stack the **ParentPath** column. Look for activity in unusual directories:

- `C:\Users\*\AppData\Local\Temp\`
- `C:\ProgramData\`
- `C:\Windows\Temp\`
- `C:\Perflogs\`
- Recycler paths or deeply nested folders

Click any suspicious value in the stacking chart to filter the grid and inspect the full rows. [Bookmark](/features/bookmarks-tags) anything that warrants further review.

::: tip Stacking Is Filter-Aware
If you already set a date range filter in Step 2, stacking results only reflect that window. This is by design -- you are analyzing frequency within the incident timeframe, not across the entire collection.
:::

---

## Minutes 15-20: Process Tree Analysis

### 10. Build the Process Tree

On the EvtxECmd tab, filter to Sysmon Event ID 1 or Security Event ID 4688, then open **Tools > Process Tree**. IRFlow Timeline builds the parent-child hierarchy automatically.

### 11. Review suspicious pattern highlights

The [Process Tree](/features/process-tree) flags three categories of suspicious activity:

| Color | Pattern | Example |
|-------|---------|---------|
| **Red** | Office application spawning script engine | `WINWORD.EXE` spawning `cmd.exe` or `powershell.exe` |
| **Orange** | LOLBin execution | `certutil.exe`, `mshta.exe`, `bitsadmin.exe`, `rundll32.exe` |
| **Yellow** | Execution from temp/user-writable path | Process image under `\Temp\`, `\AppData\`, `\Downloads\` |

### 12. Trace execution chains

Click on any highlighted node to illuminate its full ancestor chain. Walk the chain from root to leaf to understand how the suspicious process was invoked. Use the depth limit slider to manage large trees -- start at depth 3-4 and expand branches of interest.

For each suspicious chain, click the filter icon on the process node to jump back to the main grid and see all events associated with that process. Tag confirmed findings with a label such as `suspicious-execution`.

---

## Minutes 20-25: Lateral Movement and IOC Sweep

### 13. Map lateral movement

Switch to the EvtxECmd tab (ensure logon events are present) and open **Tools > Lateral Movement**. The tracker builds a force-directed graph of network logon activity.

Review the three sub-tabs:

- **Network Graph** -- look for unexpected connections, especially RDP (Type 10, blue edges) between workstations
- **Chains** -- multi-hop paths with 3+ nodes are high-priority; legitimate administration rarely chains through many systems
- **Connections** -- tabular detail for sorting by count or filtering by user

### 14. Run IOC matching

If you have indicators from threat intelligence, open **Tools > IOC Match** and paste your IOC list. IRFlow Timeline scans all columns across all loaded data for matches.

| IOC Type | Where to Expect Matches |
|----------|------------------------|
| IP addresses | EvtxECmd (Sysmon Event 3, Security 4624) |
| File hashes (SHA1) | AmcacheParser Files output |
| Domain names | EvtxECmd (Sysmon Event 22 DNS), browser history |
| File paths | MFTECmd, PECmd, Shimcache |

After matching, use **Bookmark all matches** or **Tag all matches** to flag every hit. Use the [Histogram](/features/histogram) to check whether IOC-related events cluster at specific times.

::: tip Combine Lateral Movement with IOCs
If your IOC list contains source IPs, cross-reference them with the Lateral Movement graph. An IOC IP appearing as a logon source node is strong evidence of compromise from that address.
:::

---

## Minutes 25-30: Tag Findings and Save Session

### 15. Review and consolidate bookmarks

Open the bookmarks panel to review everything you flagged during the triage. Ensure each bookmarked row has a meaningful tag. Suggested tag taxonomy:

| Tag | Use For |
|-----|---------|
| `initial-access` | First evidence of attacker entry |
| `execution` | Suspicious process executions |
| `lateral-movement` | Network logon anomalies |
| `persistence` | Scheduled tasks, services, registry run keys |
| `ioc-match` | Rows matching known indicators |
| `needs-review` | Items requiring deeper analysis |

### 16. Apply color rules

Set up [Color Rules](/features/color-rules) to visually distinguish your tag categories in the grid. This makes it faster to spot patterns when scrolling through the timeline.

### 17. Save the final session

Save the [session](/workflows/sessions) with all tabs, filters, bookmarks, tags, and color rules preserved. This session becomes your working case file. You can reopen it at any time to continue the investigation or [export a report](/workflows/export-reports).

---

## Quick Reference: KAPE Artifact-to-Tab Mapping

| KAPE Module Output | IRFlow Profile | Best Tab Name |
|--------------------|---------------|---------------|
| `EvtxECmd_Output.csv` | EvtxECmd | Event Logs |
| `PECmd_Output.csv` | PECmd | Prefetch |
| `MFTECmd_$MFT_Output.csv` | MFTECmd | File System |
| `Amcache_Files.csv` | AmcacheParser (Files) | Amcache |
| `RECmd_Batch_Output.csv` | RECmd | Registry |
| `AppCompatCacheParser_Output.csv` | AppCompatcache | Shimcache |
| `SBECmd_Output.csv` | SBECmd | ShellBags |

---

## Next Steps

- [Ransomware Investigation](/dfir-tips/ransomware-investigation) -- extend this workflow for encryption and ransom note artifacts
- [Lateral Movement Tracing](/dfir-tips/lateral-movement-tracing) -- deep-dive into multi-host lateral movement analysis
- [Malware Execution Analysis](/dfir-tips/malware-execution-analysis) -- detailed process tree and prefetch analysis
- [Persistence Hunting](/dfir-tips/persistence-hunting) -- registry, scheduled tasks, and service persistence
- [Threat Intel IOC Sweeps](/dfir-tips/threat-intel-ioc-sweeps) -- bulk IOC matching across large collections
- [Building a Final Report](/dfir-tips/building-final-report) -- turning tagged findings into a deliverable report
