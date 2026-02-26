# Brute Force & Account Compromise Detection

Brute force and password spraying attacks generate distinctive authentication patterns that are straightforward to detect when you know what to look for. This guide walks through a systematic approach to identifying these attacks, isolating the compromised account, and building a timeline of attacker activity using IRFlow Timeline.

::: info Features Used
- [Burst Analysis](/features/gap-burst-analysis) -- detect high-frequency authentication spikes
- [Histogram](/features/histogram) -- visualize attack windows at minute granularity
- [Stacking](/features/stacking) -- identify targeted accounts and source addresses
- [Checkbox Filters](/features/search-filtering) -- isolate specific logon types and event IDs
- [Bookmarks & Tags](/features/bookmarks-tags) -- mark key events for reporting
- [Color Rules](/features/color-rules) -- highlight failed vs. successful logons
:::

## Key Event IDs

| Event ID | Source | Description |
|----------|--------|-------------|
| **4625** | Security | Failed logon attempt |
| **4624** | Security | Successful logon |
| **4776** | Security | NTLM credential validation (success or failure) |
| **4740** | Security | Account lockout |
| **4767** | Security | Account unlocked |

### 4625 Sub-Status Codes

The sub-status field in Event ID 4625 reveals why the logon failed, which is critical for distinguishing attack patterns.

| Sub-Status | Meaning | Implication |
|------------|---------|-------------|
| `0xC000006A` | Wrong password | Correct username, incorrect password -- classic brute force |
| `0xC0000064` | Bad username | Username does not exist -- attacker is guessing usernames |
| `0xC0000072` | Disabled account | Account is disabled -- attacker found a valid but inactive account |
| `0xC0000234` | Account locked | Account was locked due to too many failures |
| `0xC000006D` | Generic logon failure | Catch-all for other authentication errors |

## Brute Force vs. Password Spraying

Before diving into the analysis, understand the two patterns you are looking for:

- **Brute force** -- many passwords tried against a single account from one or few sources. Look for a high volume of 4625 events with the same `TargetUserName` and varying sub-status codes, concentrated in a narrow time window.
- **Password spraying** -- one or two common passwords tried against many accounts. Look for 4625 events with many distinct `TargetUserName` values but a consistent source IP, often with a uniform sub-status of `0xC000006A`.

## Step-by-Step Investigation

### 1. Load and Filter to Authentication Events

Open your KAPE triage output or EVTX collection in IRFlow Timeline. Use the search bar (`Cmd+F`) to filter to authentication events:

1. Open the **Checkbox Filter** on the `EventID` column
2. Select **4624**, **4625**, **4776**, and **4740**
3. Apply the filter to narrow the grid to authentication activity only

This dramatically reduces noise and focuses the investigation on logon events.

::: tip Pre-Filter by Log Source
If your timeline contains mixed artifacts (registry, file system, event logs), use the Checkbox Filter on the `Channel` or `Source` column first to isolate `Security` log entries before filtering by Event ID.
:::

### 2. Run Burst Analysis to Find Attack Windows

With authentication events filtered, run Burst Analysis to detect spikes.

1. Open **Tools > Burst Analysis**
2. Set **Window size** to **1 minute**
3. Set **Burst factor** to **5x**
4. Review the results sorted by burst ratio

A brute force attack will produce windows with 50-200+ authentication events per minute, far exceeding normal baseline activity. Look for burst ratios of 10x or higher -- these are almost certainly automated attacks rather than a user mistyping their password.

Note the timestamps of the highest-ratio bursts. These define your attack windows.

::: tip Refine the Window
If burst analysis returns too many results, increase the burst factor to 10x or 15x. If you are looking for slower password spraying (one attempt per account every few seconds), widen the window to 5 or 10 minutes.
:::

### 3. Visualize the Attack with the Histogram

Click the **Histogram** button in the main toolbar and set granularity to **Minute**.

With your authentication filter still active, the histogram will show clear spikes during the attack windows identified by Burst Analysis. Look for:

- **Sharp isolated spikes** -- single-target brute force, typically lasting 5-30 minutes
- **Sustained elevated bars over a longer period** -- password spraying that iterates through an account list slowly
- **A spike in 4625 events followed by a single 4624 event** -- the moment the attacker found valid credentials

Use the histogram's **brush selection** to click and drag over the attack window. This filters the grid to only events within that range, allowing detailed row-by-row examination.

### 4. Stack on TargetUserName to Find Targeted Accounts

With the attack time window selected via the histogram brush:

1. Open **Tools > Stacking**
2. Stack on the `TargetUserName` column
3. Sort by **Count (descending)**

**Brute force pattern:** One account dominates with hundreds or thousands of failed attempts. For example, you might see `svc-backup` with 1,247 failures while all other accounts have fewer than 5.

**Password spraying pattern:** Many accounts have a similar low count (1-3 attempts each). The attacker tried one or two passwords per account before moving on.

Click the top account name to filter the grid to that account for deeper analysis.

### 5. Stack on Source IP to Identify the Attacker

Next, stack on the `IpAddress` or `SourceNetworkAddress` column.

- A single source like `10.0.5.23` generating hundreds of failed logons is a clear indicator of a compromised internal host or an attacker's foothold
- External-facing attacks may show a source like `192.168.1.105` if the logs were collected from a VPN gateway or web server

::: tip Multiple Source IPs
If you see the same attack pattern from multiple IPs (e.g., `10.0.5.23`, `10.0.5.24`, `10.0.5.25`), the attacker may be distributing attempts across hosts to evade lockout policies. Stack on the `WorkstationName` field for additional correlation.
:::

### 6. Identify the Compromised Account

The critical question: did the attacker succeed? Look for a **4624 (successful logon)** that follows the burst of **4625 (failed logon)** events.

1. Clear the histogram brush selection
2. Filter `EventID` to **4624** and **4625** using Checkbox Filters
3. Filter `TargetUserName` to the account(s) identified in Step 4
4. Sort by timestamp ascending
5. Scroll through the sequence: a wall of 4625 failures ending with a 4624 success is the compromise moment

Set up a **Color Rule** to make this pattern visually obvious:

- **Red background** for rows where `EventID = 4625`
- **Green background** for rows where `EventID = 4624`

The transition from red to green in the grid is the exact moment the attacker gained access.

::: tip Bookmark the Pivot Point
Bookmark the successful 4624 event and tag it as `initial-access`. This is a critical event in your final timeline. Also note the `LogonType` value -- Type 3 (network) and Type 10 (RemoteInteractive/RDP) are common for remote attackers.
:::

### 7. Determine What Happened After Compromise

Once you have identified the successful logon, the investigation shifts to post-compromise activity.

1. Clear all filters except the source IP identified in Step 5 (`10.0.5.23`)
2. Set the histogram brush to start from the successful logon timestamp
3. Look for:
   - Additional 4624 events on other hosts (lateral movement)
   - Process creation events (Event ID 4688) from the compromised account
   - Service installations (Event ID 7045)
   - Scheduled task creation (Event ID 4698)

Use the [Lateral Movement Map](/features/lateral-movement) to visualize whether the compromised credentials were used to pivot to other systems.

### 8. Check for NTLM Authentication (Event ID 4776)

Event ID 4776 logs NTLM credential validation attempts at the domain controller. These events are particularly useful because they capture attacks that may not generate 4625 events on the target host.

1. Filter to `EventID = 4776`
2. Stack on `TargetUserName`
3. Look for accounts with a high count of `Audit Failure` results

Cross-reference the timestamps and accounts with the 4625-based findings to build a complete picture.

### 9. Establish the Full Attack Timeline

Use [Bookmarks & Tags](/features/bookmarks-tags) to mark the key events:

| Tag | Event |
|-----|-------|
| `recon` | First failed logon from attacker source IP |
| `brute-force-start` | Beginning of the authentication burst |
| `brute-force-end` | Last failed logon before success |
| `initial-access` | The successful 4624 logon |
| `lateral-movement` | Any subsequent logons to other hosts |
| `persistence` | Service or scheduled task creation events |

Filter to bookmarked rows only (`Cmd+B`) for a clean attack narrative, then [export the report](/workflows/export-reports).

## Common Logon Types Reference

| Logon Type | Name | Typical Use |
|------------|------|-------------|
| 2 | Interactive | Console logon |
| 3 | Network | SMB, net use, WMI |
| 7 | Unlock | Workstation unlock |
| 10 | RemoteInteractive | RDP |

## Next Steps

- [Lateral Movement Tracing](/dfir-tips/lateral-movement-tracing) -- follow the attacker after they gained credentials
- [Persistence Hunting](/dfir-tips/persistence-hunting) -- find what the attacker installed to maintain access
- [Ransomware Investigation](/dfir-tips/ransomware-investigation) -- if the compromise led to ransomware deployment
- [Building a Final Report](/dfir-tips/building-final-report) -- compile your findings for stakeholders
- [Log Tampering Detection](/dfir-tips/log-tampering-detection) -- check whether the attacker attempted to cover their tracks
