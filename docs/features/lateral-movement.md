---
description: Lateral Movement Tracker — interactive network graph with RDP session correlation and MITRE ATT&CK detection.
---

# Lateral Movement Tracker

The Lateral Movement Tracker visualizes network logon activity across your environment as an interactive force-directed graph, with built-in RDP session correlation, detection rules, and multi-hop chain reconstruction to help you detect and trace attacker movement between systems.

::: tip Evidence-correlation hardening in v1.0.13
Event IDs are now interpreted with their channel, so consolidated Sysmon 22/23 rows cannot fabricate
TerminalServices sessions. Timestamp and off-hours decisions use parsed instants plus the configured
estate UTC offset. Fixed-cadence service retries and well-known service identities are dampened,
while password spray, alternate credentials, tunnelled RDP, RdpCoreTS failure bursts, session
shadowing, and `ADMIN$` writes receive more precise coverage.
:::

<video autoplay loop muted playsinline style="width: 100%; border-radius: 8px;">
  <source src="/dfir-tips/Lateral-Movement-Network-Graphs.mp4" type="video/mp4">
</video>

## Opening the Tracker

- **Menu:** **Tools → Platforms → Windows → Lateral Movement Tracker**
- **Capability launcher:** **Lateral Movement** on the home screen (after a timeline tab is loaded)
- Correlates Windows Security, Sysmon, TerminalServices, RemoteConnectionManager, and RdpCoreTS telemetry

## Multi-Source Correlation

Correlate logon and lateral-movement evidence across **multiple open tabs** — for example Security EVTX, Sysmon, and Hayabusa output — in a single tracker run instead of analyzing one tab in isolation.

![Lateral Movement Tracker multi-source setup with tab checkboxes to include Security, Sysmon, and other loaded timelines](/dfir-tips/Lateral-Movement-Multi-Source.png)

In the tracker configuration phase, enable **Multi-source** and select the tabs to merge. Each tab’s format (raw EVTX, EvtxECmd, Hayabusa, Chainsaw, etc.) is detected automatically so edges and sessions stitch together correctly. The row budget (`maxRows`) is split across selected tabs so one large Security log cannot starve Sysmon (and vice versa). A detector registry keeps spine Event IDs aligned between single-tab and multi-source runs.

You can also start from **File → Open Triage Collection…**, which pre-selects LM-relevant EVTX channels from a KAPE folder and can hand off into this tracker after import. From the [Process Inspector](/features/process-tree) detail panel, **Lateral** applies host + time filters on the current tab and opens the tracker.

## Detection Rules

![Lateral Movement Tracker configuration on WKS2390 — Analyze and RDP-focused scan options before the run](/dfir-tips/Lateral-Movement-Detection-Rules.png)

The tracker derives acquisition from a registry of **24 built-in detector groups** across authentication, RDP, share access, execution, Kerberos, and credential access. Toggleable groups can be enabled or disabled individually; core graph inputs remain available so the tracker cannot silently remove its own correlation spine. The tables below summarize the principal event inputs.

### RDP Session Rules

| Rule | Event IDs | Severity | Source |
|------|-----------|----------|--------|
| Network Authentication | 1149 | High | RemoteConnectionManager |
| Session Logon | 21 | Medium | LocalSessionManager |
| Shell Start Notification | 22 | Low | LocalSessionManager |
| Session Logoff | 23 | Low | LocalSessionManager |
| Session Disconnected | 24 | Low | LocalSessionManager |
| Session Reconnected | 25 | Medium | LocalSessionManager |
| Disconnect by Other / Reason | 39, 40 | Low | LocalSessionManager |
| NLA Authentication Failure | 131, 140 | High | RdpCoreTS |
| Session Shadowing | 20503, 20504 | High | RemoteConnectionManager/Admin |

### Security Logon Rules

| Rule | Event IDs | Severity | Hint |
|------|-----------|----------|------|
| Successful Logon | 4624 | High | Types 2,3,7,8,9,10,11,12 |
| Failed Logon | 4625 | High | All logon types |
| Explicit Credentials (RunAs) | 4648 | High | Alternate credential usage |

### Privilege Rules

| Rule | Event IDs | Severity | Hint |
|------|-----------|----------|------|
| Admin Privileges Assigned | 4672 | High | Special privileges at logon |

### Session Lifecycle Rules

| Rule | Event IDs | Severity | Hint |
|------|-----------|----------|------|
| Session Reconnect / Disconnect | 4778, 4779 | Medium | Window Station events |
| Account Logoff | 4634, 4647 | Low | Logoff / user-initiated logoff |

### RMM / Remote Access Rules

| Rule | Event IDs | Severity | Hint |
|------|-----------|----------|------|
| RMM Tool Detection | 4688, 1, 7045, 4697 | High | 33 RMM tools + 7 tunnel tools (process/service scan) |
| Scheduled Task Execution | 4698, 4688, 1 | Medium | Remote `schtasks /create /s` |

### Custom Rules

You can add custom detection rules with:

- **Category** — grouping label
- **Rule Name** — descriptive name
- **Event IDs** — comma-separated list
- **Severity** — critical, high, medium, or low
- **Payload Regex Filter** — optional regex to filter on payload content

Custom rules are merged with built-in rules. Event IDs for scanning are dynamically computed from all enabled rules.

### Severity Colors

| Level | Color |
|-------|-------|
| **Critical** | Red |
| **High** | Orange |
| **Medium** | Yellow |
| **Low** | Gray |

## Auto-Detected Columns

The tracker automatically identifies relevant columns:

| Column | Patterns Matched |
|--------|-----------------|
| Source IP | `IpAddress`, `SourceNetworkAddress`, `SourceAddress`, `RemoteHost` |
| Workstation | `WorkstationName`, `SourceHostname`, `SourceComputerName` |
| Target | `Computer`, `ComputerName`, `Hostname` |
| User | `TargetUserName`, `UserName`, (EvtxECmd: `PayloadData1`) |
| Logon Type | `LogonType`, `Logon_Type`, (EvtxECmd: `PayloadData2`) |
| Event ID | `EventID`, `event_id`, `eventid` |
| Timestamp | `datetime`, `UtcTime`, `TimeCreated`, `timestamp` |
| Domain | `TargetDomainName`, `SubjectDomainName` |
| Client Name | `ClientName`, `Client_Name` |
| Client Address | `ClientAddress`, `Client_Address`, `ClientIP` |
| Channel | `Channel`, `SourceName`, `Provider` |

### EvtxECmd Support

For EvtxECmd CSV output, the tracker parses `RemoteHost` (format: `WorkstationName (IP)`), and `PayloadData1`/`PayloadData2`/`PayloadData3` fields for TerminalServices event parsing.

### TerminalServices Event Parsing

The tracker includes dedicated parsing for TerminalServices log channels:

- **LocalSessionManager** (EIDs 21–25, 39, 40) — extracts user from `PayloadData1` (`User: DOMAIN\User` format), session ID from `PayloadData2`, and source network address from `PayloadData3`
- **RemoteConnectionManager** (EID 1149) — extracts user and source network address from `PayloadData1`/`PayloadData3`

Channel detection uses the `Channel` column value to route events to the correct parser.

## Stats Cards

Eight summary cards are displayed at the top of the modal:

| Metric | Color | Description |
|--------|-------|-------------|
| **Findings** | Red/Orange | Attack pattern detections (clickable — opens Findings tab). Red if critical findings exist |
| **Unique Hosts** | Orange | Total distinct hosts in the graph |
| **Connections** | Blue | Unique source→target pairs |
| **Users** | Purple | Distinct user accounts |
| **RDP Sessions** | Blue | Correlated RDP sessions |
| **Longest Chain** | Yellow | Deepest multi-hop path |
| **Outliers** | Red | Flagged suspicious hostnames (clickable — zooms to first outlier) |
| **Logon Events** | Green | Total events analyzed |

## Network Graph

The primary view is an interactive SVG force-directed graph.

### Node Types

| Shape | Type | Description |
|-------|------|-------------|
| **Dashed circle** | IP Address | Source hosts identified by IP |
| **Square** | Domain Controller | Servers identified as DCs |
| **Rounded rectangle** | Workstation | Client machines |

### Edge Styling

Connections between nodes indicate logon activity:

- **Directional arrows** — show the direction of the logon (source → target)
- **Count labels** — number of logon events between two nodes
- **Color-coded by logon type:**

| Color | Logon Type | Description |
|-------|-----------|-------------|
| **Blue** | Type 10, 12 | RDP / Cached RDP |
| **Green** | Type 3 | Network logon (SMB, etc.) |
| **Amber** | Type 2 | Interactive logon |
| **Purple** | Type 7, 13 | Unlock / Cached Unlock |
| **Orange** | Type 9 | RunAs (explicit credentials) |
| **Gray** | Type 5 | Service logon |
| **Red** | Type 8 | Network Cleartext (dangerous) |
| **Red dashed** | — | Failed logon |

### Edge Detail Panel

Click an edge to see a detailed breakdown:

- **Source and target badges** — highlighted in orange when a suspicious host is involved
- **Event count**, **users**, **logon type** with color coding
- **CLEARTEXT badge** — red warning when logon type 8 (cleartext credentials over the network) is present
- **First seen / Last seen** timestamps
- **Event breakdown** — pill-shaped chips showing count per event ID (e.g., `4624 ×47`, `1149 ×12`)

### Draggable Legend

The graph legend is draggable — click and drag to reposition it. It shows all connection types (RDP, Network, Interactive, RunAs, Service, Cleartext, Failed) and node types (IP, DC, Host, Outlier, Suspicious Host).

### Toolbar Controls

- **Zoom in / out** — adjust the view scale
- **Pan** — click and drag the background to pan
- **Reset view** — return to default zoom and position
- **Redraw** — re-run the force layout algorithm
- **Find Flagged** — cycle through outlier/suspicious hosts (appears when flagged hosts exist)

## Telemetry Coverage Panel

Above the sub-tabs the tracker shows a **Telemetry Coverage** panel that summarizes which event categories are present in the current dataset and which detections are gated by missing data. Categories: Auth (Logon), Explicit Creds, Process Creation, Service Install, Scheduled Task, RDP Session, Share Access, Kerberos, NTLM. Each category turns green when at least one event of that type is present and grey when absent. A coverage warning list highlights detections that cannot run because their feeder events are missing — for example, "No Kerberos service ticket events (4769) — Kerberoasting detection unavailable".

Click any host in the Network Graph to see that host's individual telemetry coverage and identify which hops in a chain have the weakest evidence.

## Sub-Tabs

The tracker has seven sub-tabs (Exec Sessions and Findings only appear when detections are present). The UI tab order is: **Network Graph**, **RDP Sessions**, **Accounts**, **Chains**, **Exec Sessions**, **Connections**, **Findings**. The sections below describe each tab; numbering is independent of the UI ordering.

![Lateral Movement Tracker Accounts tab on WKS2390 — 250 identities scored with successes, failures, and suspicion reasons](/dfir-tips/Lateral-Movement-Tabs.png)

### 1. Network Graph

The interactive force-directed visualization described above.

### 2. Findings

![Lateral Movement Tracker Findings on WKS2390 — LSASS access, brute force, credential compromise, and WMI persistence](/dfir-tips/Lateral-Movement-Findings.png)

The Findings tab displays automated attack pattern detections with MITRE ATT&CK mapping. Each finding is a card showing severity, MITRE technique badge (clickable — links to attack.mitre.org), title, description, source/target hosts, time range, and event count.

**Attack pattern detections:**

| Detection | MITRE ID | Severity | Trigger |
|-----------|----------|----------|---------|
| **Brute Force** | T1110.001 | High | 5+ failed logons (4625) from same source to same target within 5 minutes |
| **Password Spray** | T1110.003 | High | Same source fails against 3+ different targets within 30 minutes |
| **Credential Compromise** | T1078 | Critical | Failed logon (4625) followed by successful logon (4624) from same source to same target within 10 minutes |
| **Impacket Execution** | T1569.002 | Critical | 11 detection patterns across 5 Impacket variants (see below) |
| **RMM Tool Detection** | T1219 | High | 33 remote monitoring tools + 7 network tunneling tools detected in process/service events |
| **Lateral Pivot** | T1021 | High | Host identified as middle node in multi-hop lateral movement chain |
| **First Seen Connection** | T1021 | Low | Connection is within the first 1% of the timeline or is the first connection from a source host |

#### Impacket Detection

The Impacket detection engine scans process creation (EID 4688/1), service installation (EID 7045/4697), and scheduled task (EID 4698) events for signatures of 5 Impacket tools:

| Variant | Key Indicators |
|---------|---------------|
| **smbexec.py** | `cmd.exe /Q /c` with `\\127.0.0.1\ADMIN$` redirect, `__output` pattern, `%COMSPEC%` with `.bat` chains, legacy service name `BTOBTO` |
| **wmiexec.py** | `wmiprvse.exe` spawning `cmd.exe /Q`, `\\127.0.0.1\ADMIN$` output redirect |
| **dcomexec.py** | `mmc.exe -Embedding` (DCOM execution) |
| **atexec.py** | Output to `\Temp\*.tmp` with redirect, hardcoded `StartBoundary 2015-07-15T20:35:13` |
| **psexec.py** | RemCom named pipes (`remcom_communicat`, `remcom_stdin/stdout/stderr`), random 4-char service names, service binary using command interpreter |

Service-based detections (EID 7045/4697) also flag random service names — 4-character names (psexec.py pattern) and 7-character names (smbexec.py pattern) — with a common English word exclusion list to reduce false positives.

#### RMM Tool Detection

Scans process and service events for 33 remote monitoring and management tools commonly abused in intrusions, plus 7 network tunneling tools:

**RMM Tools (33):** ConnectWise ScreenConnect, AnyDesk, TeamViewer, Atera, NetSupport Manager, Splashtop, RustDesk, PDQ Connect, MeshAgent/MeshCentral, Action1, Ammyy Admin, Remote Utilities, SimpleHelp, TacticalRMM, FleetDeck, Level.io, DWService, ISL Online, HopToDesk, Lite Manager, UltraVNC, TigerVNC, RAdmin, Zoho Assist, Pulseway, LabTech/Automate, Kaseya VSA, N-able/SolarWinds, GoTo Resolve/LogMeIn, BeyondTrust (Bomgar), Dameware, Supremo, FixMe.IT

**Network Tunnels (7):** ngrok, Tailscale, Cloudflared, Chisel, ligolo-ng, ZeroTier, WireGuard

::: tip Process Inspector
The in-app [Process Inspector](/features/process-tree) also flags **frp** (`frpc`/`frps`) and other tunnel/RMM aliases via `src/detection-rules/tool-aliases.js` — separate from the Lateral Movement Tracker’s process/service RMM detector above.
:::

#### Finding Actions

Each finding card has two action buttons:

- **Filter Events** — closes the modal and applies targeted filters to the main grid: sets a checkbox filter on Event ID with relevant IDs for the finding category, sets a date range filter padded +/-5 minutes around the finding's time range, and clears other filters to avoid interference
- **View in Graph** — switches to the Graph tab and zooms/selects the relevant edge

#### Incidents

Pair-based incidents group 2+ findings on the same source-target pair within a 30-minute window. Each incident shows severity, triage score, MITRE techniques, narrative, and member findings. Actions: **Show in Timeline**, **View in Graph**, **Copy IOC**.

#### Campaigns

Campaign clustering rolls up pair-based incidents into multi-hop storylines. Two incidents join the same campaign when they share a **host** (hop continuity) or a **user** (same operator) and are within **2 hours** of each other. Connected-component analysis then groups the entire operator storyline into a single campaign.

Each campaign card shows:

- Severity, triage score, incident/finding/event counts
- **Hop path** — visual breadcrumb of the movement chain (e.g. `WKS01 → SRV01 → DC01`)
- Auto-generated narrative summarizing the operator's activity
- User and technique pills
- Expandable detail with member incidents (clickable to navigate to Incidents view), movement path visualization, **Show in Timeline**, **View in Graph**, **View Incidents**, and **Copy Summary**

Campaigns only appear when 2+ incidents exist that share context. This is the highest-level view for operator/campaign-centric triage.

### 3. Chains

Detected lateral movement chains showing multi-hop paths:

```
Host A → Host B → Host C → Host D
```

The chain detection algorithm uses depth-first search to trace connected logon sequences, identifying potential attacker movement paths through the network. Each chain shows first seen and last seen timestamps per connection.

### 4. RDP Sessions

![Lateral Movement Tracker RDP Sessions tab showing session correlation with status, source, target, user, and duration columns](/dfir-tips/Lateral-Movement-RDP-Sessions.png)

A complete RDP session correlation view that reconstructs the full lifecycle of each RDP session by linking related events across multiple log sources. Two view modes are available via a toggle in the tab header:

#### Grouped View (Default)

Sessions are grouped by source, target, user, and status into collapsible rows. Each group row shows:

- Status badge, source → target, user, session count (highlighted orange if > 5), and time range
- Click to expand and reveal individual sessions within the group with full details

#### Individual View

The detailed table view with one row per session:

**Session columns:**

| Column | Description |
|--------|-------------|
| **Status** | Session state badge (see below) |
| **Source** | Origin host/IP |
| **Target** | Destination computer |
| **User** | Account used |
| **Session ID** | RDP session identifier |
| **Events** | Number of correlated events |
| **Start Time** | Session start timestamp |
| **End Time** | Session end timestamp |
| **Duration** | Human-readable duration (red if >24h, orange if >1h) |
| **Flags** | ADMIN badge (red) and/or RECONNECT badge (purple) |

**Session states:**

| Status | Color | Meaning |
|--------|-------|---------|
| **ACTIVE** | Green | Session currently active |
| **NO LOGOFF** | Orange | Multiple events but no logoff recorded |
| **DISCONNECTED** | Yellow | Session disconnected but not ended |
| **ENDED** | Gray | Session cleanly terminated |
| **FAILED** | Red | Logon attempt failed |
| **CONNECTING** | Blue | Initial connection in progress |
| **INCOMPLETE** | Gray | Only one event, insufficient for correlation |

**Session correlation algorithm:**

The engine processes all RDP-related events chronologically, linking them into sessions using session keys (source→target|user|sessionId). Events are matched to sessions using time-window proximity:

| Event Type | Time Window |
|------------|-------------|
| Admin privilege events (4672) | 5 seconds |
| Active session events (21, 22, 25, 4648, 4778) | 30 seconds |
| Disconnect/logoff events (24, 39, 40, 23, 4634, 4647, 4779) | 60 seconds |

**Features:**
- **Expandable rows** — click a session to reveal a timeline of all correlated events, shown as a vertical dot-line visualization with color-coded dots, event ID badges, descriptions, and timestamps
- **Column sorting** — click headers to sort ascending/descending
- **Per-column checkbox filters** — dropdown filters with search, select all/clear
- **Column resizing** — drag column borders to resize
- **Checkbox selection** — select sessions for copy operations
- **Copy** — exports selected or all sessions as tab-separated text

### 5. Exec Sessions

The Execution Sessions tab provides a first-class view of non-RDP lateral movement — WMI, WinRM, PsExec, Impacket, remote service installs, scheduled tasks, admin share access, RMM tools, and Cobalt Strike activity. It mirrors the RDP Sessions tab in interaction model but shows execution-specific data.

Sessions are built from findings: the analyzer clusters execution-tool findings by (technique, source-target pair, user, time-window) so each session represents a distinct operator action. Sessions inherit severity, triage scores, evidence pills, and user attribution from their underlying findings.

**Columns:** Score, Severity, Technique, Source, Target, User(s), Findings, Events, Start, End, Status (EXECUTED or OBSERVED).

**View modes:**

- **Table** (default) — sortable table with expandable row detail. Expanded detail shows evidence pills, session metadata, and clickable related findings that navigate to the Findings tab.
- **Timeline** — Gantt chart with technique-colored bars positioned proportionally within the global time range. Each bar is clickable (switches to table view with that session expanded). A legend maps technique to color.

**Actions per session:**

- **Timeline** — closes modal and filters the main grid to the session's EIDs, hosts, and time window.
- **Graph** — switches to the Network Graph tab and highlights the source-target edge.
- **Copy All / Export CSV** — toolbar buttons for clipboard and file export.

### 6. Connections

![Lateral Movement Tracker Connections tab showing tabular view of all source-target-user-logon type pairs with event counts](/dfir-tips/Lateral-Movement-Connections.png)

A tabular view of all connections with full details:

| Column | Description |
|--------|-------------|
| Source | Origin host/IP |
| Target | Destination computer |
| User | Account used |
| Logon Type | Windows logon type |
| Count | Number of events |

### 7. Accounts

The Accounts tab pivots the analysis from connections (host→host edges) to identities (per-user aggregates). Every distinct user the tracker observed across the dataset gets one row, scored and classified to surface the identities most likely to need triage.

Each account is built from four data sources:

1. **Logon graph events** — every 4624/4625/4634/4647/4648/4672/4769/4776/4778/4779 row with a parseable user contributes source/target hosts, logon types, success/failure counts, and first/last seen.
2. **RDP session correlation** — RDP-specific stats (concurrent sessions, admin sessions, failed/reconnect counts) come from the Sessions correlator.
3. **Findings** — any finding that names this user adds its `id` and `category` to the account's findingIds / findingCategories.
4. **Raw per-user event counts** — Kerberos (4768/4769/4771), NTLM (4776), explicit credentials (4648), and admin privilege (4672) counts. Crucially, accounts are **created** from this source even if they never produced a graph edge — so a domain account that appears only in DC Kerberos events still surfaces in the tab.

**Columns**

| Column | Description |
|--------|-------------|
| Score | Suspicion score 0–100. Color-coded: red ≥50, orange ≥25, yellow ≥10. |
| User | Username (DOMAIN prefix stripped). |
| Class | Classification pill: PRIV, ADMIN, MACHINE, SERVICE, USER. |
| Successes | Count of successful logons (4624). |
| Failures | Count of failed logons (4625). |
| Sources | Number of distinct source hosts the account touched. |
| Targets | Number of distinct target hosts. |
| Admin | Count of 4672 (admin privilege assigned) events. |
| Kerb | Combined 4768 + 4769 + 4771 count. |
| NTLM | Count of 4776 events. |
| Explicit | Count of 4648 explicit credential use events. |
| First Seen / Last Seen | Time bounds for this account's activity. |
| Why Suspicious | Pills summarizing the analyzer's `flags[]` for the account. |

**Suspicion scoring** combines admin privilege use, failures-before-first-success, concurrent RDP, explicit credential use, target diversity, finding references, outlier source hits, NTLM-only authentication, privileged naming, and RDP-suspicion contribution. Machine accounts and well-known service accounts are dampened unless they have admin privilege or finding references.

**Classification tiers** (highest precedence first):

- **PRIV** (red) — name matches privileged-name regex (`Administrator`, `Admin`, `Root`, `DA_`, `Domain Admin`, `Enterprise Admin`, `Schema Admin`, `Backup`)
- **ADMIN** (orange) — has 4672 events or admin RDP sessions
- **MACHINE** (gray) — username ends in `$`
- **SERVICE** (purple) — name matches service-account regex (`SVC_`, `SERVICE_`, etc.)
- **USER** (green) — none of the above

**Features**

- **Click-to-sort** on every header. Default sort is Score descending.
- **Copy All** exports the visible (sorted) rows as TSV including the header row.
- **Per-row actions** — each account row has inline pivot buttons:
  - **Findings (N)** — navigates to the Findings tab showing detections involving this user. Only appears when the user has linked findings.
  - **Timeline** — closes the modal and filters the main grid to logon events (4624/4625/4648/4768/4769/4776) for this user within their first-to-last-seen window.
  - **Graph** — switches to the Network Graph tab and highlights the first edge involving this user.
- **Empty-state hint** points back at the Telemetry Coverage panel when no accounts can be extracted from the dataset.
- The **Users** stats card above the tabs is the entry point — click it to jump straight here. The card sub-chip shows how many of the surfaced accounts have a suspicion score of ≥25.

## Outlier and Suspicious Host Detection

![Lateral Movement Tracker outlier detection highlighting suspicious hostnames in red with pulsing rings](/dfir-tips/Lateral%20Movement-Outlier.png)

The tracker uses a two-tier detection system to flag hosts that may indicate attacker-controlled machines.

### Tier 1 — Outliers (Red)

Detected server-side during analysis. These are hostnames that strongly suggest non-corporate, default, or attacker-controlled machines:

| Pattern | Reason |
|---------|--------|
| `DESKTOP-XXXXX` | Default Windows hostname (not renamed after install) |
| `WIN-XXXXX` | Default Windows hostname |
| `KALI` | Kali Linux default hostname |
| `PARROT` | Parrot OS default hostname |
| `USER-PC`, `YOURNAME`, `ADMIN`, `TEST`, `HACKER`, `ATTACKER`, `ROOT`, etc. | Generic or suspicious hostname |
| `WIN10`, `WIN11`, `OWNER-PC`, `LOCALHOST` | Generic hostname |
| Non-ASCII characters | Unusual encoding in hostname |

### Tier 2 — Suspicious Hosts (Orange)

Detected client-side as an additional layer. These catch patterns that may overlap with some legitimate names but warrant investigation:

| Pattern | Reason |
|---------|--------|
| `VPS` | Virtual private server — common attacker infrastructure |
| `DESKTOP-` + 7 alphanumeric chars | Precise default Windows 10/11 naming pattern |
| `WIN-` + 8+ alphanumeric chars | Longer default Windows Server naming pattern |
| `WINVM` | Virtual machine default name |

### Visual Treatment

Each tier receives distinct visual treatment in the graph:

**Outlier nodes (Tier 1):**
- **Red node color** — rendered in red instead of the default node color
- **Pulsing dashed ring** — a dashed circle animates around the node with a 2-second pulse, drawing the eye to the host
- **Hover tooltip** — displays the specific detection reason

**Suspicious hosts (Tier 2):**
- **Orange node color** — rendered in amber/orange to distinguish from confirmed outliers
- **Warning triangle badge** — a small orange triangle with "!" appears on the node
- **Hover tooltip** — "Suspicious hostname pattern — possible threat actor workstation"

**Both tiers share:**
- **Warning icons in Connections table** — orange caution markers appear next to flagged hostnames
- **Warning badges in edge detail panel** — source/target badges are highlighted when a flagged host is involved

### Find Flagged Button

When outliers or suspicious hosts are detected, a **Find Flagged** button appears in the graph toolbar showing the total count of flagged nodes. Clicking it cycles through each flagged host one by one, auto-zooming the graph to center on the node and selecting it for detail inspection.

### Outlier Stats Card

The summary stats panel displays an outlier count card. When outliers are present, clicking the card zooms directly to the first outlier in the graph.

## Noise Filtering

The tracker automatically excludes noise that would clutter the graph:

### Excluded Sources
- `127.0.0.1` and `::1` — local loopback
- `0.0.0.0` — unspecified address
- `-` and empty values — missing source addresses

### Excluded Accounts
- `SYSTEM`
- `LOCAL SERVICE`
- `NETWORK SERVICE`
- `ANONYMOUS LOGON`
- `DWM-*` (Desktop Window Manager)
- `UMFD-*` (User Mode Font Driver)
- Machine accounts (`*$`)

### Session-Only Events

Events that provide session context but don't represent new connections (EIDs 23, 24, 39, 40, 4634, 4647, 4672, 4779) are collected for RDP session correlation but do not create graph edges.

## Progress Bar

For large datasets, the lateral movement analysis shows a progress bar as it processes logon events. The analysis runs asynchronously so the UI remains responsive.

## Investigation Tips

::: tip Focus on RDP
RDP connections (Type 10, blue edges) are often the most interesting for lateral movement investigations. Look for unexpected RDP connections between workstations or from unusual source IPs.
:::

::: tip Cleartext Logons
Watch for red Type 8 edges — these indicate cleartext credentials sent over the network, which is both a security risk and a strong indicator of compromise.
:::

::: tip RDP Sessions Tab
Use the RDP Sessions tab to see full session lifecycles. Long-duration sessions (>24h, shown in red) or sessions with the ADMIN flag warrant close investigation.
:::

::: tip Multi-Hop Chains
Check the Chains tab for paths with 3+ hops. Legitimate administration rarely involves chain movements, while attackers often pivot through multiple systems.
:::

::: tip Custom Detection Rules
Add custom rules to detect environment-specific lateral movement patterns. For example, add event IDs from your EDR or custom log sources with payload regex filters.
:::

::: tip Combine with Timeline
After identifying suspicious connections in the graph, click through to the main grid to see the full context of those logon events in the timeline.
:::

## See Also

- [Process Inspector](/features/process-tree) — trace what processes executed on hosts reached via lateral movement
- [Persistence Analyzer](/features/persistence-analyzer) — detect persistence installed after each lateral movement hop
- [IOC Matching](/features/ioc-matching) — scan for network indicators tied to known threat actors
- [Gap & Burst Analysis](/features/gap-burst-analysis) — identify authentication bursts that signal brute force or spray attacks
