# IOC Matching

IRFlow Timeline can scan your timeline data for Indicators of Compromise (IOCs), automatically identifying network indicators, file hashes, and other forensic artifacts.

## Opening IOC Matching

- **Menu:** Tools > IOC Match

## Supported IOC Types

| Type | Pattern | Example |
|------|---------|---------|
| **IPv4** | Standard dotted notation | `192.168.1.100` |
| **IPv6** | Full and compressed notation | `fe80::1`, `2001:db8::1` |
| **Domain** | FQDN patterns | `evil.example.com` |
| **Hash (MD5)** | 32-character hex | `d41d8cd98f00b204e9800998ecf8427e` |
| **Hash (SHA1)** | 40-character hex | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| **Hash (SHA256)** | 64-character hex | `e3b0c44298fc1c149afbf4c8996fb924...` |
| **Email** | Standard email format | `attacker@evil.com` |
| **URL** | HTTP/HTTPS URLs | `https://evil.com/payload.exe` |
| **File Path** | Windows/Unix paths | `C:\Temp\malware.exe` |

## How to Use

### Paste IOC List

1. Open the IOC matcher
2. Paste your IOC list — one indicator per line
3. IRFlow Timeline auto-detects the type of each IOC
4. Click **Match** to scan all data

### Results

The matcher returns:

- **Match count** per IOC
- **Matched rows** with full context
- Ability to **filter the grid** to matching rows
- Option to **bookmark** or **tag** all matches

## Matching Logic

IOCs are matched against all columns in the dataset:

- String matching is case-insensitive
- Partial matches are supported (an IP in a URL field will match)
- Results include the column name where each match was found

## Bulk Operations

After matching:

- **Bookmark all matches** — flag matched rows for reporting
- **Tag all matches** — apply a tag (e.g., "IOC Match") to matched rows
- **Export matches** — export only matched rows to CSV/XLSX

## Tips

::: tip Threat Intel Integration
Export IOC match results to share with your threat intelligence team, or import IOC lists from threat feeds (STIX, CSV) by pasting the indicator values.
:::

::: tip Combine with Filters
After matching IOCs, use the timeline histogram to see when IOC-related events cluster. This helps establish the attack timeline.
:::

::: tip False Positives
Review matches in context. Common internal IPs or system paths may match IOC patterns. Use the grid's full row detail to verify each match before escalating.
:::
