# Virtual Grid

The data grid is the primary interface for viewing and interacting with timeline data. It uses virtual scrolling backed by SQLite pagination to handle millions of rows without performance degradation.

![Virtual Grid displaying EvtxECmd timeline data with sortable columns, row detail panel, and histogram](/dfir-tips/Virtual-Grid.png)

## How It Works

Rather than loading all rows into memory, the grid maintains a sliding window of 10,000 rows centered on your scroll position. As you scroll, new rows are fetched from SQLite using `LIMIT`/`OFFSET` queries with a 2,000-row prefetch threshold. This means:

- **Memory usage stays constant** regardless of dataset size — only ~10K rows in the JS heap at any moment
- **Scrolling is smooth** with 20-row overscan padding above and below the viewport and `requestAnimationFrame`-throttled scroll handling
- **Initial load is instant** — no waiting for millions of rows to render
- **Skeleton placeholders** appear briefly during fast scrolling while the next data window loads

## Column Operations

### Sorting

Click any column header to sort. Click again to toggle ascending/descending, click a third time to clear. A sort indicator appears on the active column.

Sorting is type-aware and handled entirely in SQL:

| Column Type | Sort Method |
|-------------|-------------|
| **Timestamp** | Custom `sort_datetime()` function — handles ISO, US date, Unix seconds/milliseconds, Excel serial dates, and 12-hour AM/PM formats |
| **Numeric** | `CAST(column AS REAL)` — detected automatically when 80%+ of sampled values are numeric |
| **Text** | `COLLATE NOCASE` — case-insensitive alphabetical |

Indexes are created lazily on first sort for optimal performance. Background async indexing builds indexes for all columns after import without blocking the UI.

### Resizing

Drag the right edge of any column header to resize it. Minimum width is 60px. Column widths are preserved per tab and saved in sessions.

### Pinning

Right-click a column header and select **Pin Left** to pin it to the left side of the grid. Pinned columns use sticky positioning so they stay visible as you scroll horizontally — useful for keeping timestamp or event name columns always in view.

### Hiding / Showing

Open the Column Manager from the toolbar to:

- Hide columns you don't need
- Show previously hidden columns
- Show All / Hide All with one click
- Reorder columns via drag-and-drop
- Reset to default column order

Empty columns are auto-hidden on import so your grid starts clean.

### Reordering

Drag column headers to rearrange them directly in the grid. Column order is persisted per tab and saved in sessions.

### Auto-Fit

Right-click a column header and select **Best Fit** to auto-size the column width to its content with 10% padding.

### Column Quick Stats

Right-click a column header and select **Column Stats** to see value distribution, fill rate, and type-specific statistics for that column.

## Row Selection

- **Single click** — selects a row and displays it in the detail panel
- **Shift+Click** — selects a range of rows from the last clicked row to the current
- **Cmd+Click** — toggles individual rows in/out of the selection without clearing existing selections
- **Arrow Up/Down** — navigates selection with auto-scroll to keep the selected row visible

Selection state (selected rows, last clicked row, scroll position) is preserved per tab — switching tabs and back restores exactly where you left off.

The status bar shows "Row: X" for single selection or "N rows selected" for multi-select.

## Detail Panel

Clicking a row opens a resizable detail panel at the bottom of the window. It displays all column values for the selected row in a readable format with per-value copy buttons, which is especially useful when rows contain long values that are truncated in the grid. Drag the top edge to resize (80px–600px).

## Cell Rendering

### Color Rules

Rows are colored by the first matching color rule. Rules support four conditions: **contains**, **equals**, **starts with**, and **regex**. Rules are pre-compiled once for performance — regex patterns are not re-created per row.

Color priority: selection highlight > color rule > bookmark highlight > alternating row stripes.

Eight built-in presets are available for common forensic patterns (PowerShell, Mimikatz, LSASS, Critical events, etc.).

### Search Highlighting

When search is active in highlight mode, matching terms are marked with yellow background within each cell. Supports regex and multi-word mixed/AND search term highlighting.

### Timestamp Formatting

Timestamp columns are formatted according to your selected datetime format and timezone setting. All other columns are rendered as-is with text truncation and ellipsis overflow.

## Grouped View

Group rows by any column using the context menu or by dragging column headers to the group bar. Multiple grouping levels are supported for hierarchical views.

Groups display:

- **Collapsible headers** showing the value and row count per group
- **Multi-level nesting** — each expand fetches the next grouping level from SQLite
- **Leaf-level data** — expanding the deepest group loads actual rows (batched at 100K) with a "Load More" button for large groups
- **Clear button** to remove all grouping at once

## Filtering

### Per-Column Text Filters

A filter row below the column headers provides a text input per column. Typing filters using case-insensitive SQL `LIKE` matching. Filters are debounced at 500ms to avoid excessive queries while typing.

### Checkbox Filters

Right-click a column header to open a checkbox filter showing the top 25 values for that column. Search within the value list to find specific entries. Toggle values on/off to include or exclude them.

### Disable Individual Filters

Active filters can be individually toggled on/off without removing them, useful for A/B comparison while preserving your filter setup.

### Filter Caching

Query results are cached per unique filter configuration (up to 4 cache entries per tab). This enables instant toggling between highlight and filter mode, and fast tab switching.

## Context Menu

### Column Header (Right-Click)

- **Pin / Unpin** column
- **Hide Column**
- **Group by** / Remove Grouping
- **Best Fit** column width
- **Sort Ascending / Descending**
- **Stacking** — open value frequency analysis for this column
- **Column Stats** — value distribution and type statistics

### Row / Cell (Right-Click)

- **Copy Cell** value
- **Copy Row** as TSV
- **Bookmark / Remove Bookmark**
- **Add Tag**
- **Bulk Tag / Untag** selected rows

## Bookmarks and Tags

### Bookmarks

Click the star icon in the bookmark column to flag important rows. Bookmarked rows receive a subtle orange background overlay. The status bar shows a "Flagged: N" count. Use the bookmarked-only filter to show only flagged rows.

### Tags

The tags column displays color-coded tag pills per row. Add tags via the context menu with tag name suggestions. Tags support bulk operations — select multiple rows and apply or remove tags in one action.

## Performance Characteristics

| Metric | Value |
|--------|-------|
| **Row height** | 26px fixed |
| **Cached window** | 10,000 rows centered on scroll position |
| **Prefetch threshold** | Re-fetch when within 2,000 rows of cache edge |
| **Overscan** | 20 rows above/below viewport |
| **Query debounce** | 500ms for search/filter changes |
| **Scroll fetch debounce** | 50ms for scroll-driven window fetches |
| **Search result cache** | Up to 4 entries per tab |
| **Count cache** | Per filter signature, invalidated on bookmark/tag changes |
| **Index creation** | Background async — all columns indexed after import without blocking UI |
| **Stale request prevention** | Monotonic fetch IDs discard out-of-order responses |
| **Min column width** | 60px |
| **Group batch size** | 100,000 rows per expand |
