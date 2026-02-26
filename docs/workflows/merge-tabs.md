# Merging Timelines

IRFlow Timeline can merge multiple open tabs into a single unified timeline, creating a comprehensive super-timeline from diverse log sources.

## How to Merge

1. Open two or more files in separate tabs
2. **Menu:** Tools > Merge Tabs
3. Select which tabs to merge
4. A new tab is created containing all rows from the selected sources

## What Happens During Merge

- All rows from selected tabs are combined into a single SQLite database
- A `_Source` column is added to identify the origin of each row
- Columns are unified — matching column names are aligned, unique columns are preserved
- The merged tab can be sorted by any timestamp column for chronological analysis

## Merged Tab Features

The merged tab works like any other tab:

- Full search and filter capabilities
- Histogram with multi-source coloring (each source gets a distinct color)
- Bookmarks and tags
- Export and reporting
- Stacking analysis across all sources

## Multi-Source Histogram

The histogram in a merged tab is especially powerful:

- Each source is color-coded
- Stacking glassmorphism shows overlapping sources
- Brush selection filters across all sources simultaneously
- Visually correlate activity spikes across different log types

## Use Cases

### Super-Timeline Analysis

Combine all KAPE output into a single chronological view:

1. Open MFTECmd, EvtxECmd, PECmd, AmcacheParser outputs
2. Merge all tabs
3. Sort by timestamp
4. Analyze the unified timeline

### Cross-Source Correlation

Merge specific sources to correlate activity:

- Security EVTX + Sysmon EVTX → correlate logon events with process creation
- MFT + Prefetch → correlate file creation with execution
- Browser history + DNS logs → correlate web activity with network indicators

### Incident Timeline Construction

Build the final incident timeline:

1. Open all relevant evidence sources
2. Filter each to the investigation time window
3. Bookmark key events in each tab
4. Merge bookmarked/filtered data
5. Generate the report from the merged view

## Tips

::: tip Column Alignment
For best results, ensure timestamp columns have consistent naming across sources. If one source uses "TimeCreated" and another uses "datetime", they will appear as separate columns in the merged view.
:::

::: tip Merge Selectively
Rather than merging everything, merge only the sources relevant to your current investigation question. This keeps the merged timeline focused and manageable.
:::

::: warning Performance
Merging very large tabs (millions of rows each) creates a proportionally large merged database. Consider filtering each tab before merging to reduce the combined size.
:::
