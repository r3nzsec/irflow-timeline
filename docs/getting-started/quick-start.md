# Quick Start

Get up and running with your first timeline analysis in under a minute.

## Open a File

There are three ways to open a file:

1. **Menu:** File > Open (`Cmd+O`)
2. **Drag and drop:** Drag a file onto the application window
3. **Double-click:** Double-click a supported file in Finder

IRFlow Timeline will automatically detect the file format and begin streaming the import.

## Import Progress

During import you will see:

- A progress bar showing rows imported
- Automatic delimiter detection for CSV/TSV files
- Sheet selection dialog for multi-sheet Excel files
- Column discovery for EVTX files

::: info Large Files
Files over 1GB may take a minute to import. The streaming architecture processes data in 16MB chunks with 50,000-row batches, so the UI remains responsive throughout.
:::

## Navigate the Grid

Once imported, your data appears in a virtual-scrolling grid:

- **Scroll** through millions of rows smoothly — only ~5,000 rows are loaded at a time
- **Sort** by clicking any column header (click again to toggle ASC/DESC)
- **Resize columns** by dragging the column header borders
- **Pin columns** by `Cmd+Click` on a header and selecting Pin Left
- **Select rows** by clicking; hold `Shift` for range selection

## Search Your Data

Use the search bar at the top (`Cmd+F`):

1. Type your search term
2. Select a search mode from the dropdown:
   - **Mixed** — Combines full-text and substring search (default)
   - **FTS** — Full-text search (word-level matching)
   - **LIKE** — Substring match
   - **Fuzzy** — Tolerates typos
   - **Regex** — Regular expression patterns

Results update as you type (debounced at 500ms).

## Filter by Column

Click the filter icon on any column header to:

- **Text filter:** Type to match values in that column
- **Checkbox filter:** Select/deselect specific unique values
- **Date range:** For timestamp columns, pick a start and end date

## Bookmark Important Rows

Click the star icon on any row to bookmark it. Bookmarked rows are preserved across sessions and included in exported reports.

Toggle `Cmd+B` to show only bookmarked rows.

## Add Tags

`Cmd+Click` a row and select **Add Tag** to annotate it. Tags are color-coded and can be used for filtering and reporting. Common tags include:

- Suspicious
- Lateral Movement
- Exfiltration
- Persistence
- C2

## View the Histogram

Click **Tools > Histogram** to open the timeline visualization:

- See event distribution across days, hours, or minutes
- Click and drag to brush-select a time range — the grid filters automatically
- Color-coded by artifact source when using merged timelines

## Next Steps

- Learn about all [search modes and filters](/features/search-filtering)
- Set up [color rules](/features/color-rules) for visual pattern matching
- Explore the [Process Tree](/features/process-tree) for Sysmon analysis
- Track [Lateral Movement](/features/lateral-movement) across your network
- Configure [KAPE integration](/workflows/kape-integration) for auto-detection
