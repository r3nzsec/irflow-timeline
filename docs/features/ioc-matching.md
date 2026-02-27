# IOC Matching

IRFlow Timeline can scan your timeline data for Indicators of Compromise (IOCs), automatically identifying network indicators, file hashes, and other forensic artifacts across all columns.

![Known-Bad IOC Matching dialog with IOC list input supporting IPs, domains, hashes, and file paths](/dfir-tips/IOC-Matching.png)

## Opening IOC Matching

- **Menu:** Tools > IOC Match

## Supported IOC Types

IOC types are auto-detected from the input using pattern matching:

| Type | Pattern | Example |
|------|---------|---------|
| **IPv4** | Dotted notation with optional CIDR | `192.168.1.100`, `10.0.0.0/24` |
| **IPv6** | Full and compressed notation | `fe80::1`, `2001:db8::1` |
| **Domain** | FQDN patterns | `evil.example.com` |
| **MD5** | 32-character hex | `d41d8cd98f00b204e9800998ecf8427e` |
| **SHA1** | 40-character hex | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| **SHA256** | 64-character hex | `e3b0c44298fc1c149afbf4c8996fb924...` |
| **Email** | Standard email format | `attacker@evil.com` |
| **URL** | HTTP/HTTPS URLs | `https://evil.com/payload.exe` |
| **File Path** | Windows or Unix paths | `C:\Temp\malware.exe`, `/tmp/payload` |
| **Other** | Anything not matching above | Custom indicators |

A category breakdown badge displays the count per detected type before you run the scan.

## How to Use

### Load IOC List

Two methods to input IOCs:

**File load** — click the load button to select a `.txt`, `.csv`, or `.ioc` file. The IOC set name is auto-derived from the filename.

**Paste** — paste IOCs directly into the text area, one per line. Comments are supported:

```
# Q1 Threat Intel IOCs
192.168.1.100
evil.example.com    # C2 domain
d41d8cd98f00b204e9800998ecf8427e
C:\Temp\malware.exe
```

Lines starting with `#` and inline `# comments` are stripped. Duplicate values (case-insensitive) are automatically removed.

### IOC Set Name

Optionally name your IOC set. This name becomes the tag label suffix when auto-tagging matches (e.g., `IOC: Q1 Malware IOCs`).

### Run Scan

Click **Match** to scan. The matching engine works in two phases:

1. **Batched REGEXP scan** — IOCs are grouped into batches of 200 and combined into alternation patterns (`pattern1|pattern2|...`). Each batch runs a single SQL query testing all columns with `REGEXP`, collecting matching row IDs
2. **Per-IOC hit counting** — matched rows are fetched in 500-row batches and each IOC pattern is tested individually (case-insensitive regex) against all columns to count hits per indicator

## Results

**Summary cards** display three metrics:

- **Matching rows** — total rows with at least one IOC hit (red if any found)
- **IOCs hit** — number of IOC patterns that matched at least one row (orange if any found)
- **IOCs not found** — number of IOC patterns with zero matches

**Per-IOC results list** shows every indicator sorted by hit count (highest first):

- IOC value and detected category label
- Hit count (red for matches, muted dash for zero)

## Bulk Operations

After matching:

- **Tag matched rows** — applies a tag named `IOC: {set name}` with orange color to all matching rows in a single bulk operation
- **Show only matches** — filters the grid to show only IOC-tagged rows
- **Re-scan** — modify the IOC list and run again

## Tips

::: tip Threat Intel Integration
Export IOC match results to share with your threat intelligence team, or import IOC lists from threat feeds (STIX, CSV) by pasting the indicator values.
:::

::: tip Combine with Histogram
After matching IOCs, use the timeline histogram to see when IOC-related events cluster. This helps establish the attack timeline.
:::

::: tip False Positives
Review matches in context. Common internal IPs or system paths may match IOC patterns. Use the grid's full row detail to verify each match before escalating.
:::

::: tip Name Your IOC Sets
Use descriptive IOC set names so tags clearly identify the source intelligence. Tags like `IOC: TA505 Infrastructure` or `IOC: Q1-2026 Hash List` make report writing easier.
:::
