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

## Outlier Host Detection

The tracker automatically flags hosts with suspicious or default hostnames that may indicate attacker-controlled machines:

| Pattern | Reason |
|---------|--------|
| `DESKTOP-XXXXX` | Default Windows hostname (not renamed after install) |
| `WIN-XXXXX` | Default Windows hostname |
| `KALI` | Kali Linux default hostname |
| `PARROT` | Parrot OS default hostname |
| `USER-PC`, `ADMIN`, `TEST`, `HACKER`, etc. | Generic or suspicious hostname |
| Non-ASCII characters | Unusual encoding in hostname |

### Visual Treatment

Outlier nodes receive distinct visual treatment in the graph so they stand out immediately:

- **Red node color** — outlier nodes are rendered in red instead of the default node color
- **Pulsing dashed ring** — a dashed circle animates around each outlier node with a 2-second pulse, drawing the eye to suspicious hosts
- **Hover tooltip** — hovering over an outlier node displays the specific detection reason (e.g., "Default Windows hostname", "Kali Linux default")
- **Stats card** — the summary stats panel includes an outlier count so you can see at a glance how many suspicious hostnames were detected

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
