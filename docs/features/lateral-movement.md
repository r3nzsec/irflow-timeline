# Lateral Movement Tracker

The Lateral Movement Tracker visualizes network logon activity across your environment as an interactive force-directed graph, helping you detect and trace attacker movement between systems.

![Lateral Movement Tracker network graph showing host-to-host logon connections with RDP, Network, and Interactive connection types](/dfir-tips/lateral-movement-tracker.png)

## Opening the Tracker

- **Menu:** Tools > Lateral Movement
- Requires Windows Security event logs with logon events (Event IDs 4624, 4625, 4648)

## Auto-Detected Columns

The tracker automatically identifies relevant columns:

| Column | Purpose |
|--------|---------|
| `IpAddress` | Source IP of the logon |
| `Computer` | Target computer name |
| `TargetUserName` | Account used for logon |
| `LogonType` | Windows logon type code |
| `EventID` | Event identifier |

### EvtxECmd Support

For EvtxECmd CSV output, the tracker parses the `RemoteHost` field which uses the format `WorkstationName (IP)`, extracting both the source workstation name and IP address.

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
| **Blue** | Type 10 | RDP (Remote Desktop) |
| **Green** | Type 3 | Network logon (SMB, etc.) |
| **Amber** | Type 2 | Interactive logon |

### Toolbar Controls

- **Zoom in / out** — adjust the view scale
- **Pan** — click and drag the background to pan
- **Reset view** — return to default zoom and position
- **Redraw** — re-run the force layout algorithm

### Interaction

- **Click a node** — see all connections to/from that host
- **Click an edge** — see detailed breakdown of logon events between two hosts
- **Drag nodes** — reposition nodes for better visibility

## Three Sub-Tabs

### 1. Network Graph

The interactive force-directed visualization described above.

### 2. Chains

Detected lateral movement chains showing multi-hop paths:

```
Host A → Host B → Host C → Host D
```

The chain detection algorithm traces connected logon sequences to identify potential attacker movement paths through the network.

### 3. Connections

A tabular view of all connections with full details:

| Column | Description |
|--------|-------------|
| Source | Origin host/IP |
| Target | Destination computer |
| User | Account used |
| Logon Type | Windows logon type |
| Count | Number of events |

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
- **Hover tooltip** — displays the specific detection reason (e.g., "Default Windows hostname", "Kali Linux default")

**Suspicious hosts (Tier 2):**
- **Orange node color** — rendered in amber/orange to distinguish from confirmed outliers
- **Warning triangle badge** — a small orange triangle with "!" appears on the node
- **Hover tooltip** — "Suspicious hostname pattern — possible threat actor workstation"

**Both tiers share:**
- **Warning icons in Connections table** — orange caution markers appear next to flagged hostnames in the source and target columns
- **Warning badges in edge detail panel** — source/target badges are highlighted when a flagged host is involved

### Find Flagged Button

When outliers or suspicious hosts are detected, a **Find Flagged** button appears in the graph toolbar showing the total count of flagged nodes. Clicking it cycles through each flagged host one by one, auto-zooming the graph to center on the node and selecting it for detail inspection.

### Outlier Stats Card

The summary stats panel displays an outlier count card. When outliers are present, clicking the card zooms directly to the first outlier in the graph.

## Noise Filtering

The tracker automatically excludes noise that would clutter the graph:

### Excluded Sources
- `127.0.0.1` and `::1` — local loopback
- `-` — empty source addresses

### Excluded Accounts
- `SYSTEM`
- `LOCAL SERVICE`
- `NETWORK SERVICE`
- `DWM-*` (Desktop Window Manager)
- `UMFD-*` (User Mode Font Driver)
- Machine accounts (`*$`)

## Progress Bar

For large datasets, the lateral movement analysis shows a progress bar as it processes logon events. The analysis runs asynchronously so the UI remains responsive.

## Investigation Tips

::: tip Focus on RDP
RDP connections (Type 10, blue edges) are often the most interesting for lateral movement investigations. Look for unexpected RDP connections between workstations or from unusual source IPs.
:::

::: tip Multi-Hop Chains
Check the Chains tab for paths with 3+ hops. Legitimate administration rarely involves chain movements, while attackers often pivot through multiple systems.
:::

::: tip Combine with Timeline
After identifying suspicious connections in the graph, click through to the main grid to see the full context of those logon events in the timeline.
:::
