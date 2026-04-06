---
description: Five search modes — full-text, regex, fuzzy, LIKE, and mixed — to find evidence across massive forensic timelines.
---

# Search & Filtering

IRFlow Timeline provides multiple search modes and filter types to help you find exactly what you need in massive timelines.

![Search and Filtering interface showing a search for cmd.exe with forensic regex patterns panel](/dfir-tips/Search-Filtering.png)

## Search Modes

Access the search bar with `Cmd+F`. Select a search mode from the dropdown next to the search input.

### Mixed (Default)

Combines full-text search and substring matching for the broadest results. Runs an FTS query first, then supplements with LIKE matching for partial terms.

Best for: General-purpose searching when you're not sure of exact phrasing.

### FTS (Full-Text Search)

Uses SQLite FTS5 for word-level tokenized search. Matches whole words and supports prefix queries.

```
powershell          → matches "powershell.exe", "PowerShell"
"lateral movement"  → matches the exact phrase
power*              → prefix match: powershell, powerpoint, etc.
```

Best for: Fast keyword searches across large datasets.

::: info FTS Index
The FTS index is built lazily on first search. Building processes 300,000 rows per chunk asynchronously so the UI remains responsive. If the index isn't ready yet, the search transparently falls back to LIKE mode.
:::

### LIKE (Substring)

Case-insensitive substring matching using SQL `LIKE '%term%'`.

```
cmd.exe     → matches any cell containing "cmd.exe"
\temp\      → matches paths containing "\temp\"
```

Best for: Exact substring matching, file paths, specific strings.

### Fuzzy

N-gram similarity matching that tolerates typos and minor variations.

```
powrshell   → still matches "powershell"
mimkatz     → still matches "mimikatz"
```

Best for: When you're unsure of exact spelling or dealing with obfuscated strings.

### Regex

Full regular expression pattern matching.

```
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}   → matches IPv4 addresses
(?i)invoke-.*                           → matches PowerShell cmdlets
```

Best for: Complex pattern matching, IP addresses, structured data extraction.

## Filter Types

### Column Filters

Click the filter icon on any column header to open column-specific filtering:

- **Text filter** — type to match values within that column
- Filters are additive — multiple column filters create an AND condition

### Filter In / Filter Out

Quickly filter by a specific cell value without opening the filter editor:

- **Right-click any cell** — select **Filter in** to show only rows matching that value, or **Filter out** to exclude rows with that value
- **`Cmd+Click` any cell** — opens a compact context menu with **Filter in**, **Filter out**, and **Hide column** actions

**Filter in** sets a checkbox filter on the column to show only the clicked value. **Filter out** adds an advanced filter condition (`not_equals`) to exclude the value. Both methods work alongside existing filters.

### Checkbox Filters

For columns with a manageable number of unique values:

1. Click the filter icon on a column header
2. Switch to the checkbox tab
3. Select or deselect specific values to include/exclude

Useful for filtering by event type, log source, computer name, etc.

### Date Range Filters

For timestamp columns:

1. Click the filter icon on a timestamp column
2. Switch to the date range tab
3. Select a start date/time and end date/time
4. Only events within the range are shown

You can also set date ranges by brush-selecting on the [Histogram](/features/histogram).

### Advanced Filter Editor

Open **View > Edit Filter** to build multi-condition filters with a visual editor:

- **AND/OR logic** — each condition has a logic toggle to combine with AND or OR
- **Column selector** — pick any column in the dataset
- **Operators** — equals, not equals, contains, not contains, starts with, ends with, greater than, less than, is empty, is not empty, regex
- **Multi-condition** — add as many conditions as needed; each row is a separate filter clause
- **Live preview** — the grid updates as you build the filter

Advanced filters are applied alongside column filters and checkbox filters, giving you layered filter composition.

### Filter Presets

Save frequently used filter configurations as named presets:

1. Build your filter (column filters, advanced filters, checkbox filters)
2. Open **View > Filter Presets**
3. Enter a name and click **Save**
4. Reload presets from the same menu in any session

Presets persist to disk and are available across app restarts.

### Tag Filters

Filter rows by their assigned tags:

- Show only rows with a specific tag
- Combine with other filters for targeted analysis

### Bookmark Filter

Toggle `Cmd+B` to show only bookmarked rows. Useful for reviewing rows you've already flagged as important.

## Cross-Tab Search

Use `Cmd+Shift+F` to search across all open tabs simultaneously. Results show the match count per tab, letting you quickly identify which timelines contain your search term.

## Search Caching

IRFlow Timeline caches the 4 most recent search queries per tab. When switching between tabs or toggling between search terms, cached results are returned instantly without re-querying the database.

## Search Highlighting

Toggle the highlight button in the search bar to visually highlight matching terms within the grid cells. Matched text is marked with a yellow/amber background for easy identification.

When [IOC Matching](/features/ioc-matching) highlights are also active, both work simultaneously — IOC matches appear in orange and search matches appear in amber, so you can distinguish between the two at a glance.

## Find Duplicates

Open **Actions > Find Duplicates** to identify repeated values in any column:

1. Select a column from the dropdown
2. Click **Find Duplicates** to scan
3. Results show duplicate values and their occurrence counts (up to 100 displayed)
4. Click **Filter to Duplicates** to apply a checkbox filter showing only rows with duplicate values

This is useful for spotting reused filenames, repeated process command lines, duplicate IP connections, or any pattern where the same value appearing multiple times is significant.

## See Also

- [Virtual Grid](/features/virtual-grid) — the core data interface where search results are displayed
- [Bookmarks & Tags](/features/bookmarks-tags) — tag search results for later review
- [Histogram](/features/histogram) — brush-select a time range to filter before searching
- [Stacking](/features/stacking) — frequency analysis to find outliers before targeted searching
- [IOC Matching](/features/ioc-matching) — scan against threat intel indicator lists
- [NTFS Analysis](/features/ntfs-analysis) — filter MFT and USN Journal data with advanced conditions
