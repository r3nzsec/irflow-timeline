# Ransomware Kill Chain Reconstruction

Ransomware incidents demand a structured approach to timeline analysis. The attacker lifecycle -- from initial access through privilege escalation, lateral movement, defense evasion, staging, and encryption -- leaves artifacts spread across dozens of log sources and host forensic images. This guide walks through reconstructing a complete ransomware kill chain using IRFlow Timeline.

::: info Features Used
- [KAPE Integration](/workflows/kape-integration) -- ingest triage images with auto-detected profiles
- [Histogram](/features/histogram) -- visualize activity bursts across the incident window
- [Process Tree](/features/process-tree) -- trace execution chains from initial payload to ransomware binary
- [Log Source Coverage](/features/log-source-coverage) -- identify evidence gaps across endpoints
- [Bookmarks and Tags](/features/bookmarks-tags) -- tag artifacts by kill chain phase
- [Merge Tabs](/workflows/merge-tabs) -- combine host timelines into a unified view
- [Color Rules](/features/color-rules) -- highlight suspicious processes and known-bad indicators
- [IOC Matching](/features/ioc-matching) -- sweep for threat intel indicators across all sources
:::

## Prerequisites

Before starting, collect the following from each affected endpoint using KAPE or a similar triage tool:

- Windows Event Logs (EVTX) -- Security, System, Sysmon, PowerShell, Defender
- MFT and USN Journal
- Prefetch files
- Amcache and Shimcache
- Registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat)
- SRUM database

Process the collected artifacts through the appropriate EZ Tools (EvtxECmd, MFTECmd, PECmd, AmcacheParser, RECmd, AppCompatcache, SrumECmd) to produce CSV output that IRFlow Timeline can ingest.

## Phase Tags

Throughout this workflow, use the following tags to classify artifacts by kill chain phase. Create these tags in the [Bookmarks and Tags](/features/bookmarks-tags) panel before you begin:

| Tag | Kill Chain Phase | Color |
|-----|-----------------|-------|
| `initial-access` | Phishing, exploit, or external service compromise | Red |
| `execution` | First-stage payload and script execution | Orange |
| `persistence` | Scheduled tasks, services, registry run keys | Yellow |
| `priv-esc` | Privilege escalation to SYSTEM or Domain Admin | Purple |
| `lateral-movement` | RDP, PsExec, WMI, SMB activity between hosts | Blue |
| `defense-evasion` | Log clearing, AV tampering, timestomping | Pink |
| `exfiltration` | Data staging and outbound transfer | Cyan |
| `encryption` | Ransomware binary execution and file modification | Black |

---

### 1. Build a Unified Super-Timeline

Open each KAPE-processed CSV in its own tab. IRFlow Timeline's [KAPE Integration](/workflows/kape-integration) will auto-detect the tool profile and apply optimized column layouts for EvtxECmd, MFTECmd, PECmd, and others.

Once all tabs are loaded, use [Merge Tabs](/workflows/merge-tabs) to combine them into a single unified timeline. Select all tabs and choose a common timestamp column (typically `TimeCreated` for EVTX or `datetime` for super-timelines).

::: tip
If you have triage collections from multiple hosts, merge each host's artifacts first into a per-host timeline, then merge the per-host timelines together. This two-stage merge keeps large investigations manageable and preserves the ability to filter by hostname.
:::

### 2. Assess Evidence Coverage

Open the [Log Source Coverage](/features/log-source-coverage) panel to review which artifact types and time ranges are represented. Look for:

- **Sysmon gaps** -- if Sysmon was installed mid-incident, you may lack early process creation data
- **Security log overwrites** -- high-volume environments may have lost older 4624/4625 events
- **Missing hosts** -- compare your collected endpoints against the known scope of compromise

Document any coverage gaps now so your final report reflects what evidence was and was not available.

### 3. Identify the Initial Access Vector

Filter the merged timeline to the earliest suspicious timeframe. Common initial access artifacts include:

| Event Source | Event ID / Artifact | What It Shows |
|-------------|---------------------|---------------|
| Security.evtx | 4624 (Type 10) | Inbound RDP logon |
| Security.evtx | 4625 | Failed logon (brute force indicator) |
| Sysmon | 1 | Process creation from email attachment |
| Sysmon | 11 | File creation in `\Downloads\` or `\Temp\` |
| Sysmon | 3 | Outbound network connection from Office process |
| Prefetch | `OUTLOOK.EXE`, `WINWORD.EXE` | Office app execution preceding payload |
| MFT | Zone.Identifier ADS | Files downloaded from the internet |

Use the [Histogram](/features/histogram) at hour granularity to find the burst of activity around the initial compromise, then run [Burst Analysis](/features/gap-burst-analysis) with a 1-minute window for precise timing. Tag the relevant rows with `initial-access`.

### 4. Trace the Execution Chain

Open the [Process Tree](/features/process-tree) to visualize the execution flow from the initial payload. Suspicious patterns to look for:

- **Office to shell**: `WINWORD.EXE` -> `cmd.exe` -> `powershell.exe`
- **Script interpreter chains**: `wscript.exe` -> `powershell.exe` -> `IEX(New-Object Net.WebClient).DownloadString(...)`
- **LOLBin abuse**: `certutil.exe -urlcache -split -f http://...`, `bitsadmin.exe /transfer`, `mshta.exe http://...`

Key Sysmon events for this phase:

| Event ID | Description | What to Look For |
|----------|-------------|------------------|
| 1 | Process Create | Command line arguments, parent process, execution path |
| 3 | Network Connection | C2 callbacks from script interpreters |
| 7 | Image Loaded | Unsigned or anomalous DLLs loaded into legitimate processes |
| 11 | File Create | Dropped payloads in `C:\Users\*\AppData\Local\Temp\` |
| 15 | File Stream Create | ADS-based payload staging |
| 25 | Process Tampering | Process hollowing or herpaderping |

Tag execution artifacts with `execution`. Set up a [Color Rule](/features/color-rules) to highlight rows where the Image column contains known LOLBins (`cmd.exe`, `powershell.exe`, `mshta.exe`, `certutil.exe`, `rundll32.exe`).

### 5. Map Persistence Mechanisms

Search for persistence artifacts across the timeline. Common mechanisms in ransomware incidents:

| Persistence Type | Artifact Location | Event/Source |
|-----------------|-------------------|--------------|
| Scheduled Task | `C:\Windows\System32\Tasks\*` | Security 4698, Sysmon 11 |
| Run Key | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Sysmon 13 (Registry Value Set) |
| Service Creation | `HKLM\SYSTEM\CurrentControlSet\Services\*` | System 7045, Security 4697 |
| WMI Subscription | `root\subscription` namespace | Sysmon 19, 20, 21 |
| Startup Folder | `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` | Sysmon 11, MFT |
| DLL Side-Loading | Legitimate application directory with malicious DLL | Sysmon 7 (Image Loaded) |

Tag all confirmed persistence with `persistence`.

::: tip
Stack the `Image` or `TargetFilename` column using the [Stacking](/features/stacking) feature to quickly surface rare executables or files written to startup locations. Entries with a count of 1 across all endpoints deserve close inspection.
:::

### 6. Identify Privilege Escalation

Look for the transition from standard user to elevated privileges:

| Indicator | Source | Details |
|-----------|--------|---------|
| Token Elevation | Security 4672 | Special privileges assigned to new logon -- indicates admin-level access |
| Credential Dumping | Sysmon 10 (Process Access) | Access to `lsass.exe` by unusual processes (e.g., `rundll32.exe`, unsigned binaries) |
| Kerberoasting | Security 4769 | TGS requests with RC4 encryption (`0x17`) for service accounts |
| DCSync | Security 4662 | Replication rights (`DS-Replication-Get-Changes-All`) exercised by non-DC account |
| Named Pipe Impersonation | Sysmon 17, 18 | Pipe creation and connection by unexpected processes |

Tag escalation evidence with `priv-esc`.

### 7. Track Lateral Movement

Filter for lateral movement indicators using the [Lateral Movement](/features/lateral-movement) view. Cross-reference source and destination hosts:

| Technique | Artifacts |
|-----------|-----------|
| PsExec | Service install (System 7045) for `PSEXESVC`, named pipe `\PIPE\psexesvc`, Sysmon 1 for `PSEXESVC.exe` |
| WMI | Process creation via `WmiPrvSE.exe` parent (Sysmon 1), Security 4624 Type 3 |
| RDP | Security 4624 Type 10, `TerminalServices-LocalSessionManager/Operational` Event 21/22/25 |
| SMB File Copy | Sysmon 11 for files written via admin shares (`C$`, `ADMIN$`), Security 5140/5145 |
| WinRM / PowerShell Remoting | `wsmprovhost.exe` process creation (Sysmon 1), `PowerShell/Operational` Event 4103/4104 |

Tag with `lateral-movement`. Use the [Histogram](/features/histogram) to observe the temporal pattern -- ransomware operators often move laterally in clusters, and the histogram will reveal these burst windows.

::: tip
When analyzing lateral movement, open a second tab filtered to just 4624 events and sort by Logon Type. Type 3 (Network), Type 7 (Unlock), and Type 10 (RemoteInteractive) each tell a different story about how the attacker traversed the environment.
:::

### 8. Detect Defense Evasion

Attackers routinely tamper with defenses before deploying ransomware. Search for:

| Evasion Technique | Indicator |
|-------------------|-----------|
| Log clearing | Security 1102, System 104 |
| Defender disabled | `Windows Defender/Operational` Event 5001 (Real-Time Protection disabled) |
| Defender exclusions | Registry key `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` (Sysmon 13) |
| Timestomping | MFT `$SI` vs `$FN` timestamp discrepancy |
| Process injection | Sysmon 8 (CreateRemoteThread), Sysmon 10 (cross-process access) |
| AMSI bypass | `PowerShell/Operational` 4104 containing `AmsiUtils` or `amsiInitFailed` |

Tag with `defense-evasion`. Pay special attention to the gap between defense evasion and encryption -- this window often reveals the attacker's staging activity.

### 9. Find Data Exfiltration

Many ransomware groups exfiltrate data before encrypting. Look for:

- Archive creation: Sysmon Event 1 process creation for `7z.exe`, `rar.exe`, `WinRAR.exe` with command lines pointing to sensitive directories
- Large outbound transfers: Sysmon Event 3 network connections to uncommon external IPs, SRUM data showing unusual `BytesSent` values
- Cloud upload: Browser history entries for `mega.nz`, `anonfiles.com`, `transfer.sh`, or similar file-sharing services
- Staging directories: MFT entries showing large archives created in `C:\ProgramData\`, `C:\Temp\`, or `C:\Windows\Temp\`

Run an [IOC Matching](/features/ioc-matching) sweep with known exfiltration infrastructure from your threat intelligence feed. Tag confirmed exfiltration with `exfiltration`.

### 10. Pinpoint the Encryption Event

The final phase is the ransomware deployment itself. Key indicators:

| Artifact | What to Look For |
|----------|------------------|
| Sysmon 1 | Ransomware binary execution -- note parent process, user context, and working directory |
| Sysmon 11 | Ransom notes (`README.txt`, `DECRYPT_FILES.html`, `HOW_TO_RECOVER.txt`) written to multiple directories |
| MFT | Mass file extension changes (`.encrypted`, `.locked`, `.crypt`) in a short time window |
| Prefetch | Ransomware executable prefetch file with high `RunCount` or recent `LastRun` timestamp |
| USN Journal | Flood of `DATA_OVERWRITE` and `RENAME` entries |
| Security 4688 | Process creation for `vssadmin.exe delete shadows /all /quiet` or `wmic shadowcopy delete` |
| System 7036 | Volume Shadow Copy service stopped |

Switch the [Histogram](/features/histogram) to hour granularity to spot the general encryption window, then use [Burst Analysis](/features/gap-burst-analysis) with a 1-minute window to pinpoint the characteristic spike -- a massive burst of file system events concentrated in a narrow time window. This spike marks the encryption start time.

Tag all encryption-phase artifacts with `encryption`.

::: tip
Bookmark the exact timestamp of the first encrypted file and the last encrypted file. The duration of the encryption window is a critical data point for your incident report and helps estimate the scope of impact.
:::

### 11. Build the Kill Chain Timeline

With all phases tagged, use the [Search and Filtering](/features/search-filtering) panel to filter by tag. Walk through each phase in chronological order:

1. `initial-access` -- When and how did the attacker gain entry?
2. `execution` -- What was the first-stage payload?
3. `persistence` -- How did they maintain access?
4. `priv-esc` -- When did they escalate to admin or SYSTEM?
5. `lateral-movement` -- Which hosts were compromised and in what order?
6. `defense-evasion` -- What did they disable or tamper with?
7. `exfiltration` -- Was data stolen, and how much?
8. `encryption` -- When did ransomware deploy, and what was the blast radius?

Export the tagged and filtered timeline using [Export Reports](/workflows/export-reports) to produce a structured incident summary for stakeholders.

---

## Key Event ID Reference

| Event ID | Log Source | Description |
|----------|-----------|-------------|
| 1102 | Security | Audit log cleared |
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon |
| 4662 | Security | Directory service access (DCSync) |
| 4672 | Security | Special privileges assigned |
| 4688 | Security | Process creation (legacy) |
| 4697 | Security | Service installed |
| 4698 | Security | Scheduled task created |
| 4769 | Security | Kerberos TGS request |
| 5140 | Security | Network share accessed |
| 5145 | Security | Detailed file share access |
| 7045 | System | New service installed |
| 104 | System | Event log cleared |
| 1 | Sysmon | Process creation |
| 3 | Sysmon | Network connection |
| 7 | Sysmon | Image loaded |
| 8 | Sysmon | CreateRemoteThread |
| 10 | Sysmon | Process access |
| 11 | Sysmon | File create |
| 13 | Sysmon | Registry value set |
| 17, 18 | Sysmon | Pipe created / connected |
| 25 | Sysmon | Process tampering |
| 4103, 4104 | PowerShell/Operational | Script block logging |
| 1116 | Windows Defender/Operational | Malware detected |
| 5001 | Windows Defender/Operational | Real-Time Protection state change |

---

## Next Steps

- [Lateral Movement Tracing](/dfir-tips/lateral-movement-tracing) -- deep-dive into cross-host activity mapping
- [Malware Execution Analysis](/dfir-tips/malware-execution-analysis) -- detailed process tree and LOLBin analysis techniques
- [Persistence Hunting](/dfir-tips/persistence-hunting) -- comprehensive persistence mechanism detection
- [Threat Intel IOC Sweeps](/dfir-tips/threat-intel-ioc-sweeps) -- bulk indicator matching across your timeline
- [Building a Final Report](/dfir-tips/building-final-report) -- structuring your findings for legal and executive audiences
- [KAPE Triage Workflow](/dfir-tips/kape-triage-workflow) -- optimizing your collection and processing pipeline
