# Building a Final Report

Every investigation culminates in a report. The analysis work -- the searching, filtering, tagging, and correlating -- only delivers value when it is distilled into a clear, structured document that stakeholders can act on. This guide walks through the process of transforming your IRFlow Timeline investigation into a polished incident report, pulling together bookmarks, tags, merged timelines, exports, and HTML reports into a single deliverable.

::: info Features Used
- [Bookmarks & Tags](/features/bookmarks-tags) -- review and organize all annotated findings
- [Merging Timelines](/workflows/merge-tabs) -- combine relevant tabs into a unified view
- [Export & Reports](/workflows/export-reports) -- generate CSV, XLSX, and HTML outputs
- [Sessions](/workflows/sessions) -- save the complete analysis state for peer review
- [Histogram](/features/histogram) -- visualize the incident timeline for report graphics
- [Stacking](/features/stacking) -- produce frequency summaries for key columns
- [Search & Filtering](/features/search-filtering) -- isolate bookmarked and tagged rows
- [Color Rules](/features/color-rules) -- create visual emphasis for report screenshots
:::

## Report Structure

Before touching IRFlow Timeline, establish the structure of your report. A well-organized incident report follows a predictable outline that readers -- whether executives, legal counsel, or fellow analysts -- can navigate quickly.

| Section | Purpose | IRFlow Source |
|---------|---------|---------------|
| **Executive Summary** | One-paragraph overview for leadership | Written narrative from your tagged events |
| **Scope & Methodology** | What evidence was examined and how | Session metadata, tab list, filter criteria |
| **Timeline of Events** | Chronological account of attacker activity | Merged timeline filtered to bookmarked rows |
| **Key Findings** | Detailed analysis of each attack phase | Tagged event groups with context |
| **Indicators of Compromise** | Actionable IOCs for detection teams | Stacking results on IPs, hashes, domains |
| **Affected Systems & Accounts** | Scope of the compromise | Stacking results on hosts and usernames |
| **Recommendations** | Remediation and hardening actions | Written narrative informed by findings |
| **Appendix** | Raw data exports and supporting evidence | CSV/XLSX exports, HTML report attachment |

## Step-by-Step Workflow

### 1. Review All Bookmarks Across Tabs

Before merging or exporting, audit the bookmarks in every open tab. Each tab may contain rows you flagged during different stages of the investigation.

1. Switch to each tab individually
2. Toggle the bookmark filter (`Cmd+B`) to see only starred rows
3. Verify that each bookmarked row is genuinely relevant to the final report
4. Remove bookmarks from rows that were useful during analysis but are not part of the incident narrative (use `Cmd+Click` > **Unbookmark**)
5. Repeat for every tab

::: tip Clean Before You Merge
It is much easier to clean up bookmarks per-tab before merging than to sort through a combined timeline afterward. Spend five minutes reviewing each tab now to save thirty minutes of confusion later.
:::

### 2. Review and Consolidate Tags

Tags categorize your findings by attack phase or significance. Review them for consistency.

1. In each tab, open the **tag filter dropdown** to see all tags in use
2. Ensure consistent naming -- if one tab uses `lateral-movement` and another uses `Lateral Movement`, standardize before merging
3. Use **Edit > Tag All Filtered** to bulk-apply missing tags where appropriate
4. Verify that critical events carry the right tags:

| Tag | Expected Content |
|-----|-----------------|
| `initial-access` | The first successful compromise event |
| `lateral-movement` | Logons or connections to additional hosts |
| `persistence` | Scheduled tasks, services, registry modifications |
| `exfiltration` | File access, archive creation, outbound transfers |
| `c2` | Command and control network connections |
| `credential-access` | Credential dumping or harvesting events |

### 3. Merge Relevant Tabs into a Unified Timeline

A single merged timeline provides the chronological backbone of your report.

1. Open **Tools > Merge Tabs**
2. Select all tabs that contain bookmarked or tagged events relevant to the incident
3. A new merged tab is created with a `_Source` column identifying the origin of each row
4. Sort the merged tab by timestamp ascending

Do not merge every tab indiscriminately. If your session includes tabs that were exploratory dead ends, leave them out of the merge. The merged tab should represent the curated incident timeline.

::: tip Filter Before Merging
If individual tabs contain millions of rows but only a few hundred are bookmarked, consider filtering each tab to bookmarked rows (`Cmd+B`) and then exporting those subsets to CSV. Re-import the filtered CSVs and merge those instead. This keeps the merged timeline lean and report-focused.
:::

### 4. Filter the Merged Timeline to Key Events

With the merged tab active:

1. Toggle the bookmark filter (`Cmd+B`) to show only bookmarked rows
2. Alternatively, use the tag filter to show rows matching specific tags
3. Verify the chronological sequence makes sense -- are there gaps that need narrative explanation?
4. Sort by timestamp ascending to confirm the story reads correctly from start to finish

This filtered view is the core of your "Timeline of Events" report section.

### 5. Capture the Histogram Visualization

The histogram provides a visual summary of the incident timeline that is immediately understandable to non-technical stakeholders.

1. Click the **Histogram** button in the main toolbar on the merged tab
2. Set the granularity to match your incident scope (hours for multi-day incidents, minutes for short attacks)
3. The multi-source coloring shows which artifact types contributed events at each point
4. Take a screenshot of the histogram for inclusion in the Executive Summary or Timeline section

::: tip Brush to the Incident Window
Use the histogram's brush selection to highlight just the active attack window. This creates a focused view that emphasizes the incident period against the baseline of normal activity before and after.
:::

### 6. Generate Frequency Summaries with Stacking

Stacking produces the data you need for the "Indicators of Compromise" and "Affected Systems" sections.

1. On the merged tab (filtered to bookmarked/tagged rows), open **Tools > Stacking**
2. Stack on key columns and record the results:

| Stack Column | Report Section | What to Record |
|-------------|----------------|----------------|
| `IpAddress` / `SourceAddress` | IOCs | Attacker IP addresses and frequency |
| `Computer` / `HostName` | Affected Systems | Every host the attacker touched |
| `TargetUserName` | Affected Accounts | Compromised and targeted accounts |
| `Image` / `ProcessName` | IOCs / Key Findings | Malicious executables and tools |
| `_Source` | Methodology | Which log sources contributed the most evidence |

### 7. Export Data for the Appendix

Produce the raw data exports that support your report narrative.

1. With the merged tab active and bookmarks filtered, go to **File > Export** (`Cmd+E`)
2. Export as **CSV** for tool-agnostic archival -- this file can be ingested by SIEMs, shared with other analysts, or attached to tickets
3. Export as **XLSX** for stakeholders who prefer spreadsheets -- the styled headers and auto-fit columns make it immediately readable
4. Consider separate exports for different audiences:
   - Full bookmarked timeline (all columns) for the technical appendix
   - Filtered to specific tags (e.g., only `c2` tagged rows) for the network team
   - Filtered to `credential-access` and `lateral-movement` tags for the identity team

### 8. Generate the HTML Report

The HTML report is a self-contained deliverable that combines summary statistics, tagged event tables, and bookmarked rows.

1. Go to **File > Generate Report**
2. Choose a save location (use a descriptive name like `incident-2026-0042-report.html`)
3. The report opens in your browser and includes:
   - Summary cards with row counts, bookmark counts, and tag counts
   - Timeline span showing the earliest and latest events
   - Tag breakdown with colored chips and counts
   - Bookmarked events table with full row data
   - Tagged events grouped by tag with complete details

The HTML file has no external dependencies. It can be emailed, uploaded to a case management system, or printed to PDF directly from the browser.

::: tip Pair the HTML Report with Data Exports
The HTML report is for human consumption -- it tells the story. The CSV/XLSX exports are for machine consumption and detailed review. Include both in your case file. Reference the HTML report in the body of your written report and attach the data exports as appendices.
:::

### 9. Save the Session for Peer Review

Before closing IRFlow Timeline, save your complete analysis state.

1. Go to **File > Save Session** (`Cmd+S`)
2. Save as a `.tle` file alongside your evidence and exports
3. The session preserves all tabs, filters, bookmarks, tags, color rules, and column configurations

A saved session allows a peer reviewer to open the exact same view you used to reach your conclusions. This is critical for:

- **Quality assurance** -- a senior analyst can verify your findings by walking through the same filtered views
- **Handoffs** -- if the investigation transfers to another analyst, they inherit your full analysis context
- **Court preparation** -- if the case proceeds to legal action, the session file demonstrates your analytical methodology

::: tip Version Your Sessions
Save sessions at key milestones during the investigation, not just at the end. Use filenames like `incident-0042-initial-triage.tle`, `incident-0042-lateral-movement-analysis.tle`, and `incident-0042-final-report.tle`. This creates an audit trail of your analytical process.
:::

### 10. Assemble the Written Report

With all data exported and the HTML report generated, write the final document. Use the following outline as a template, pulling data from the IRFlow Timeline outputs at each step.

**Executive Summary** -- Write 3-5 sentences summarizing the incident. State when it was detected, what the attacker did, what systems were affected, and whether the threat has been contained. Reference the histogram screenshot to show the activity window.

**Scope and Methodology** -- List the evidence sources examined (reference the `_Source` stacking results), the tools used (IRFlow Timeline, KAPE), and the analysis period. Mention the session file by name so reviewers can reproduce your analysis.

**Timeline of Events** -- Transcribe the bookmarked rows from your merged timeline into a chronological narrative. For each key event, include the timestamp, the source artifact, the event description, and why it matters. The HTML report's bookmarked events table serves as the raw reference here.

**Key Findings** -- Organize findings by attack phase using your tag categories. Each finding should reference specific rows from the exported data. Use the tagged event groups from the HTML report as the foundation.

**Indicators of Compromise** -- List all IOCs identified during the investigation. Pull these from your stacking results on IP addresses, process names, file hashes, and domain names. Format them for easy ingestion by detection teams.

**Affected Systems and Accounts** -- List every host and account the attacker interacted with. Pull from stacking results on hostname and username columns.

**Recommendations** -- Provide actionable remediation steps based on the findings. Password resets, host re-imaging, firewall rules, detection rule creation -- each recommendation should trace back to a specific finding.

**Appendix** -- Attach the CSV/XLSX exports and the HTML report. Reference the saved `.tle` session file for anyone who wants to review the raw analysis.

## Checklist Before Submission

Use this checklist to verify report completeness:

- [ ] All bookmarks reviewed and irrelevant ones removed
- [ ] Tags are consistent across all tabs
- [ ] Merged timeline sorted chronologically and verified
- [ ] Histogram screenshot captured for the executive summary
- [ ] CSV export of bookmarked timeline attached
- [ ] XLSX export for stakeholder review attached
- [ ] HTML report generated and attached
- [ ] Session file saved alongside evidence
- [ ] IOC list extracted from stacking results
- [ ] Affected systems and accounts enumerated
- [ ] Written narrative references specific timestamps and event details
- [ ] Report reviewed by a second analyst before submission

## Next Steps

This is the capstone of your investigation workflow. If you need to revisit specific analysis techniques, refer to the following guides:

- [Ransomware Investigation](/dfir-tips/ransomware-investigation) -- analyze ransomware deployment and encryption activity
- [Lateral Movement Tracing](/dfir-tips/lateral-movement-tracing) -- follow attacker movement between hosts
- [Malware Execution Analysis](/dfir-tips/malware-execution-analysis) -- investigate process execution chains and payloads
- [Brute Force & Account Compromise](/dfir-tips/brute-force-account-compromise) -- detect authentication attacks
- [Insider Threat & Exfiltration](/dfir-tips/insider-threat-exfiltration) -- investigate data theft by internal actors
- [Log Tampering Detection](/dfir-tips/log-tampering-detection) -- identify evidence of anti-forensics
- [Persistence Hunting](/dfir-tips/persistence-hunting) -- find attacker footholds and backdoors
- [KAPE Triage Workflow](/dfir-tips/kape-triage-workflow) -- streamline evidence collection and ingestion
- [Threat Intel IOC Sweeps](/dfir-tips/threat-intel-ioc-sweeps) -- match indicators against your timeline data
