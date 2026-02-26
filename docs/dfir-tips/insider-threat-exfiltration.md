# Insider Threat: Unauthorized Data Access and Exfiltration

Insider threat investigations require correlating file access patterns, folder navigation, cloud upload activity, and removable media usage across multiple forensic artifact types. IRFlow Timeline's Multi-Tab workspace lets you load MFT entries, ShellBags, browser history, and Jump Lists side by side, then use the Histogram to surface after-hours activity and Date Filters to isolate the suspect's notice period.

::: info Features Used
- [Multi-Tab Workspace](/workflows/multi-tab) -- Load MFT, ShellBags, Browser History, and Jump Lists in parallel tabs
- [Histogram](/features/histogram) -- Identify after-hours and weekend activity spikes
- [Date Filters](/features/search-filtering) -- Narrow the timeline to the employee's notice period
- [Virtual Grid](/features/virtual-grid) -- Browse and sort large artifact sets efficiently
- [Bookmarks and Tags](/features/bookmarks-tags) -- Mark evidence of staging, access, and exfiltration
- [Color Rules](/features/color-rules) -- Highlight sensitive paths, USB activity, and cloud uploads
- [Stacking](/features/stacking) -- Aggregate file extensions and destination paths
- [IOC Matching](/features/ioc-matching) -- Flag known cloud storage and personal email domains
- [Export and Reports](/workflows/export-reports) -- Produce a final evidence package
:::

## Background

A typical insider exfiltration case follows a predictable pattern: the subject accesses sensitive directories they may or may not be authorized to view, stages files to a local or removable location, and then transfers data out via USB, cloud storage, or personal email. The investigation window is usually the period between the employee's resignation or termination notice and their last day of access.

## Artifact Sources

| Artifact | Source Tool / Path | What It Reveals |
|---|---|---|
| MFT ($MFT) | KAPE, FTK Imager | File creation, modification, and access timestamps on sensitive directories |
| ShellBags | Registry Explorer, SBECmd | Folder navigation history including network shares and removable media |
| Browser History | Hindsight, BrowsingHistoryView | Cloud storage uploads, personal webmail access, file transfer sites |
| Jump Lists | JLECmd | Recently accessed files, application usage, and automatic destination entries |
| USB Device Logs | Registry, setupapi.dev.log | USB device first-connect and last-connect timestamps |

::: tip
Use [KAPE Triage](/workflows/kape-integration) to collect all four artifact types in a single acquisition pass. Target the `!SANS_Triage` collection, which captures MFT, registry hives, browser databases, and Jump List files.
:::

## Investigation Steps

### 1. Define the Investigation Window with Date Filters

Before loading any data, establish the critical date range. If the employee submitted a two-week notice on 2026-01-12 and their last day was 2026-01-26, set the global Date Filter to that window.

1. Open **Filter Panel** and set **Start Date** to `2026-01-12` and **End Date** to `2026-01-26`.
2. Apply the filter so all tabs respect the same time boundary.
3. Consider extending the window one to two weeks earlier to capture any pre-notice reconnaissance.

### 2. Load Artifacts into a Multi-Tab Workspace

Open each artifact type in its own tab using [Multi-Tab](/workflows/multi-tab) so you can pivot between them without losing context.

| Tab | File to Load | Parser |
|---|---|---|
| MFT | `$MFT` parsed via MFTECmd | MFTECmd CSV |
| ShellBags | `SBECmd_Output.csv` | SBECmd CSV |
| Browser History | `BrowsingHistory.csv` or Hindsight output | Browser History CSV |
| Jump Lists | `AutomaticDestinations.csv` from JLECmd | JLECmd CSV |

### 3. Configure Color Rules for Key Indicators

Set up [Color Rules](/features/color-rules) to visually flag activity categories at a glance.

| Color | Rule Pattern | Purpose |
|---|---|---|
| Red | `\\FILESERVER\Finance`, `\\FILESERVER\HR`, `\\FILESERVER\Legal` | Access to sensitive network shares |
| Orange | `USB`, `Removable`, `E:\`, `F:\`, `G:\` | Removable media paths |
| Yellow | `drive.google.com`, `dropbox.com`, `onedrive.live.com`, `wetransfer.com` | Cloud storage and file transfer |
| Purple | `gmail.com`, `outlook.com`, `yahoo.com`, `protonmail.com` | Personal email services |

### 4. Analyze MFT for Sensitive File Access

In the **MFT** tab, filter for paths containing sensitive directory names to identify which files the subject touched.

1. Use the search bar to filter for `\\FILESERVER\Finance\Q4-Reports`.
2. Sort by **LastAccessTime** descending to see the most recent access first.
3. Look for clusters of `.xlsx`, `.pdf`, and `.docx` files accessed in rapid succession -- this suggests bulk browsing rather than normal work activity.
4. Check for files created in staging directories such as `C:\Users\jdoe\Desktop\Backup` or `C:\Users\jdoe\Documents\Personal`.

::: tip
Use [Stacking](/features/stacking) on the file extension column to quickly see the distribution of accessed file types. A sudden spike in `.zip` or `.7z` files during the notice period often indicates archive creation for exfiltration.
:::

### 5. Review ShellBags for Folder Navigation Patterns

ShellBags record every folder a user opened in Explorer, even if the folder no longer exists or the network share is disconnected.

1. Switch to the **ShellBags** tab.
2. Filter for network paths: `\\FILESERVER\`.
3. Look for navigation into directories the subject would not normally access for their role, such as:
   - `\\FILESERVER\Finance\Q4-Reports\Board-Presentations`
   - `\\FILESERVER\HR\Compensation-Data`
   - `\\FILESERVER\Legal\Contracts\Vendor-Agreements`
4. Check for removable media paths like `E:\Backup` or `F:\Export` that indicate USB staging.
5. Note the **Last Interacted** timestamps and [bookmark](/features/bookmarks-tags) entries that fall within the notice period.

### 6. Examine Browser History for Cloud Uploads

Cloud storage services are one of the most common exfiltration vectors for insiders.

1. Switch to the **Browser History** tab.
2. Apply [IOC Matching](/features/ioc-matching) with a list of cloud storage and personal email domains:
   - `drive.google.com/upload`
   - `dropbox.com/home`
   - `onedrive.live.com`
   - `wetransfer.com`
   - `mail.google.com/mail/u/0/#compose`
3. Sort by timestamp and look for upload activity that correlates with the MFT file access times from Step 4.
4. Pay attention to URL patterns that indicate file uploads versus normal browsing -- for example, `drive.google.com/upload` or `dropbox.com/request`.

Key browser history entries to flag:

| Timestamp | URL Pattern | Interpretation |
|---|---|---|
| 2026-01-18 21:43 | `https://drive.google.com/upload` | File upload to personal Google Drive |
| 2026-01-19 22:15 | `https://www.dropbox.com/home/Work-Files` | Dropbox folder creation and upload |
| 2026-01-22 20:07 | `https://mail.google.com/mail/u/0/#compose` | Personal Gmail with potential attachment |
| 2026-01-24 23:31 | `https://wetransfer.com/uploads` | Large file transfer via WeTransfer |

::: tip
After-hours browser activity to cloud storage sites is one of the strongest indicators. Use the [Histogram](/features/histogram) to see if these uploads cluster outside of the 08:00--17:00 business hours window.
:::

### 7. Inspect Jump Lists for Recently Accessed Files

Jump Lists capture files opened through specific applications, providing a record of what the user worked with most recently.

1. Switch to the **Jump Lists** tab.
2. Filter for application IDs corresponding to file managers and archive tools (Explorer, 7-Zip, WinRAR).
3. Look for entries pointing to sensitive paths or staging locations:
   - `\\FILESERVER\Finance\Q4-Reports\Revenue-Forecast-2026.xlsx`
   - `C:\Users\jdoe\Desktop\Backup\Q4-Data.zip`
   - `E:\Transfer\Finance-Export.7z`
4. Cross-reference timestamps with MFT entries to confirm file copy operations.

### 8. Use the Histogram to Identify After-Hours Patterns

The [Histogram](/features/histogram) aggregates activity across all loaded tabs by time, making it straightforward to spot unusual working patterns.

1. Set the Histogram resolution to **1 hour**.
2. Look for activity spikes between 19:00 and 06:00 on weekdays, or any weekend activity.
3. Click on a spike to filter the active tab to that time window.
4. Compare the notice period histogram shape to the prior 30 days -- a dramatic increase in after-hours activity is a strong behavioral indicator.

### 9. Correlate Across Tabs with Bookmarks

As you identify evidence in each tab, use [Bookmarks and Tags](/features/bookmarks-tags) to build a unified evidence trail.

| Tag | Use For |
|---|---|
| `recon` | ShellBag entries showing folder browsing of sensitive directories |
| `staging` | MFT entries showing file copies to Desktop, USB, or temp directories |
| `exfil-cloud` | Browser history entries for cloud upload activity |
| `exfil-usb` | MFT and Jump List entries referencing removable media paths |
| `after-hours` | Any bookmarked entry with a timestamp outside business hours |

### 10. Build the Exfiltration Timeline

Once all evidence is tagged, [merge](/workflows/merge-tabs) the bookmarked entries into a single consolidated tab.

1. Use **Merge Tabs** to combine bookmarked rows from all four artifact tabs.
2. Sort the merged view by timestamp to produce a chronological narrative.
3. The resulting timeline should show a pattern similar to:
   - **Reconnaissance**: ShellBag entries for sensitive directories (early in the notice period).
   - **Collection**: MFT entries showing file access and local staging (mid-period).
   - **Exfiltration**: Browser uploads and USB file writes (late in the period, often after hours).
4. [Export](/workflows/export-reports) the merged timeline for inclusion in your investigation report.

::: tip
Save your workspace as a [Session](/workflows/sessions) before exporting. This preserves all tab configurations, color rules, filters, and bookmarks so you can return to the analysis if legal counsel or HR requests additional review.
:::

## Key Indicators Summary

| Indicator | Artifact Source | What to Look For |
|---|---|---|
| Sensitive directory access | MFT, ShellBags | Paths like `\\FILESERVER\Finance\*`, `\\FILESERVER\HR\*` |
| Local staging | MFT, Jump Lists | Files copied to `Desktop\Backup`, `Documents\Personal`, temp folders |
| Archive creation | MFT | New `.zip`, `.7z`, `.rar` files in staging directories |
| USB device usage | MFT, ShellBags | Paths referencing `E:\`, `F:\`, or `Removable Disk` |
| Cloud upload activity | Browser History | URLs for Google Drive, Dropbox, WeTransfer, OneDrive |
| Personal email use | Browser History | Gmail, Outlook.com, Yahoo Mail, ProtonMail compose pages |
| After-hours activity | Histogram (all tabs) | Spikes outside 08:00--17:00 or on weekends |
| Bulk file access | MFT | Large clusters of file reads within short time windows |

## Next Steps

- [Building a Final Report](/dfir-tips/building-final-report) -- Package your insider threat findings for legal and HR review
- [Lateral Movement Tracing](/dfir-tips/lateral-movement-tracing) -- Determine if the insider accessed additional systems beyond the file server
- [KAPE Triage Workflow](/dfir-tips/kape-triage-workflow) -- Streamline artifact collection from the suspect's workstation
- [Threat Intel and IOC Sweeps](/dfir-tips/threat-intel-ioc-sweeps) -- Cross-reference exfiltration destinations with known threat intelligence
- [Log Tampering Detection](/dfir-tips/log-tampering-detection) -- Check whether the insider attempted to cover their tracks
