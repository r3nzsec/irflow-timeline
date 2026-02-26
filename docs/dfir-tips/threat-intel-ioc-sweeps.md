# Threat Intel IOC Sweeps

Sweeping a forensic timeline against known Indicators of Compromise (IOCs) is one of the fastest ways to determine whether a host was impacted by a specific threat actor or campaign. IRFlow Timeline lets you load structured IOC lists, match them across every artifact type in your timeline, and tag all hits for downstream reporting.

::: info Features Used
- [IOC Matching](/features/ioc-matching) -- Load and match indicator lists against timeline data
- [Search and Filtering](/features/search-filtering) -- Cross-Tab Search, Regex, and Fuzzy matching
- [Bookmarks and Tags](/features/bookmarks-tags) -- Bulk Tagging of matched rows
- [Color Rules](/features/color-rules) -- Visual highlighting of IOC hits
- [Virtual Grid](/features/virtual-grid) -- High-performance review of match results
- [Stacking](/features/stacking) -- Aggregate matched values to find prevalence
:::

---

## Preparing Your IOC List

Before loading indicators into IRFlow Timeline, you need a well-structured IOC list. Most threat intelligence platforms export in formats that are compatible with the IOC Matching feature.

### 1. Gather Indicators from Threat Intel Feeds

Pull IOCs from the platform that corresponds to the threat you are investigating. Common sources include:

| Source | Export Format | Typical IOC Types |
|---|---|---|
| MISP | CSV, JSON, STIX | Hashes, IPs, domains, URLs, file names |
| AlienVault OTX | CSV, STIX | IPs, domains, hashes, email addresses |
| VirusTotal | CSV (via Livehunt or Retrohunt) | MD5, SHA1, SHA256 hashes, contacted IPs/domains |
| Abuse.ch (ThreatFox, URLhaus) | CSV | C2 IPs, malicious URLs, payload hashes |
| Internal TIP or SOAR | CSV | Mixed, depending on case |

### 2. Structure the CSV for Import

IRFlow Timeline expects a CSV file with at minimum one column containing the indicator values. A well-formed IOC list looks like this:

```
indicator_type,indicator_value,description
md5,e99a18c428cb38d5f260853678922e03,Cobalt Strike beacon payload
sha256,a1b2c3d4e5f6...,Backdoor dropper associated with APT29
ip,198.51.100.47,C2 callback server
domain,update-service.badactor.com,Phishing infrastructure
filename,svchost32.exe,Masquerading service binary
```

::: tip
Keep the `indicator_type` column even if you are only sweeping one type. It helps you filter and interpret results when the match list is large. If your feed exports without a type column, add one manually before import.
:::

### 3. Normalize Indicator Values

Before import, clean up your list:

- Convert all hashes to lowercase to avoid case-sensitivity mismatches.
- Remove protocol prefixes from URLs (`https://` or `http://`) unless you specifically need to match full URLs.
- Strip trailing dots from FQDNs if present.
- Deduplicate entries so that match counts accurately reflect unique timeline events rather than duplicate indicators.

---

## Loading IOCs into IRFlow Timeline

### 4. Open the IOC Matching Panel

Navigate to **IOC Matching** from the toolbar or use the keyboard shortcut. This opens the indicator import dialog where you can load one or more IOC lists.

### 5. Import Your Prepared CSV

Click **Load IOC List** and select your CSV file. Map the columns when prompted:

- **Value Column** -- the column containing the actual indicator (e.g., `indicator_value`).
- **Type Column** (optional) -- the column describing the indicator type (e.g., `indicator_type`).
- **Description Column** (optional) -- any context you want carried through to the results.

### 6. Select Target Columns in the Timeline

Choose which timeline columns to match against. The right mapping depends on the indicator type:

| IOC Type | Timeline Columns to Target |
|---|---|
| MD5 / SHA256 hashes | `SHA256`, `MD5`, `Hash`, `FileHash` |
| IP addresses | `SourceIP`, `DestinationIP`, `RemoteAddress`, `Details` |
| Domain names | `Domain`, `Host`, `URL`, `Details`, `DestinationHostname` |
| File names | `FileName`, `TargetFilename`, `ImagePath`, `Details` |

::: tip
When in doubt, include the `Details` or `Message` column as a catch-all. Many log sources embed IOC-relevant data in free-text fields that dedicated columns might not capture.
:::

### 7. Run the Match

Click **Execute Match**. IRFlow Timeline compares every indicator in your list against the selected columns across all loaded rows. Results appear as a filterable overlay indicating which rows contain hits and which specific indicator was matched.

---

## Interpreting Match Results

### 8. Review the Match Summary

After the sweep completes, the IOC Matching panel displays a summary:

- **Total Matches** -- the number of timeline rows that contain at least one IOC hit.
- **Unique Indicators Matched** -- how many distinct indicators from your list were found.
- **Unmatched Indicators** -- indicators in your list that had zero hits (useful for scoping).

A high number of unmatched indicators is normal. Most IOC lists are broad, and a clean host will only match a subset (or none) of a campaign's full indicator set.

### 9. Filter the Grid to Matched Rows

Use the match filter to display only rows with IOC hits. This immediately narrows a timeline of hundreds of thousands of rows down to the events that matter. From here, review each hit in context:

- What artifact type generated the row (Prefetch, MFT, Registry, Event Log)?
- What was the timestamp relative to other known activity?
- Does the matched value appear in a context that confirms compromise (execution vs. mere presence on disk)?

### 10. Use Stacking to Assess Prevalence

Open [Stacking](/features/stacking) on the matched indicator column to count how many times each IOC appears. A C2 domain that appears once may indicate a single callback, while one that appears hundreds of times suggests sustained beaconing.

---

## Expanding the Search with Cross-Tab and Advanced Matching

### 11. Run Cross-Tab Search for IOC Values

If you have multiple evidence sources loaded in separate tabs (e.g., one tab for MFT artifacts, another for event logs, another for network connections), use **Cross-Tab Search** to find IOC hits across all tabs simultaneously.

Enter a matched indicator value into the search bar and enable **Search All Tabs**. This returns results from every loaded data source, giving you a complete picture of where that indicator appears across the host's forensic artifacts.

### 12. Use Regex Search for Domain Patterns

Threat actors frequently rotate through subdomains or use domain generation algorithms (DGAs). Use Regex search to catch variants that a static IOC list might miss:

| Pattern Goal | Example Regex |
|---|---|
| All subdomains of a known malicious domain | `.*\.badactor\.com` |
| IP addresses in a known C2 range | `198\.51\.100\.\d{1,3}` |
| DGA-style domains (random lowercase, fixed TLD) | `[a-z]{8,15}\.(xyz\|top\|click)` |
| Base64-encoded PowerShell pattern in command lines | `powershell.*-enc[odedcommand]*\s+[A-Za-z0-9+/=]{20,}` |

::: tip
Combine Regex search with Cross-Tab Search to sweep all loaded tabs for pattern-based indicators in a single pass. This is particularly effective for identifying C2 infrastructure that was not in your original IOC list.
:::

### 13. Use Fuzzy Search for Obfuscated Variants

Attackers may rename malicious binaries with slight misspellings or character substitutions to evade simple string matching. Enable **Fuzzy Search** to catch near-matches:

- `svch0st.exe` instead of `svchost.exe`
- `csrs.exe` instead of `csrss.exe`
- `update-servlce.badactor.com` (lowercase L instead of i)

Fuzzy matching uses edit-distance scoring to surface these variants. Review each fuzzy hit carefully, as false positives are more likely than with exact matching.

---

## Tagging and Reporting

### 14. Bulk Tag All IOC Matches

Select all matched rows using the filtered view, then apply a **Bulk Tag** such as `IOC-Hit` or a campaign-specific tag like `APT29-IOC`. This preserves your findings regardless of subsequent filtering and makes it easy to pull all IOC-related events into a final report.

Suggested tagging taxonomy:

| Tag | Use Case |
|---|---|
| `IOC-Hash` | Rows matching file hash indicators |
| `IOC-Network` | Rows matching IP or domain indicators |
| `IOC-Filename` | Rows matching known malicious file names |
| `IOC-Unconfirmed` | Fuzzy or regex matches that need manual validation |

### 15. Apply Color Rules to IOC Tags

Use [Color Rules](/features/color-rules) to visually distinguish IOC matches from the rest of the timeline. Assign a high-contrast color (red background, white text) to rows tagged with your IOC tags. This makes hits immediately visible when scrolling through the full timeline in context.

### 16. Export Tagged Results

Use [Export and Reports](/workflows/export-reports) to generate a filtered export containing only IOC-tagged rows. This output can be handed to a threat intelligence team for further enrichment or included directly in an incident report.

---

## Key Event IDs for IOC Correlation

When sweeping IOCs against Windows Event Logs, pay attention to these sources where indicators commonly surface:

| Event ID | Log Source | IOC Relevance |
|---|---|---|
| 1 | Sysmon (Process Create) | Hashes, file names, command lines |
| 3 | Sysmon (Network Connection) | Destination IPs and hostnames |
| 7 | Sysmon (Image Loaded) | DLL hashes and paths |
| 22 | Sysmon (DNS Query) | Queried domain names |
| 4688 | Security | Process creation with command line |
| 5156 | Security | Network connection with destination IP |
| 7045 | System | New service with binary path |

---

## Next Steps

- [Malware Execution Analysis](/dfir-tips/malware-execution-analysis) -- Trace what happened after an IOC match confirms execution
- [Lateral Movement Tracing](/dfir-tips/lateral-movement-tracing) -- Follow the attacker's path across hosts after identifying initial compromise
- [Persistence Hunting](/dfir-tips/persistence-hunting) -- Check whether matched indicators are tied to persistence mechanisms
- [Building a Final Report](/dfir-tips/building-final-report) -- Compile IOC sweep results into a structured incident report
- [Ransomware Investigation](/dfir-tips/ransomware-investigation) -- Apply IOC sweeps in the context of ransomware triage
