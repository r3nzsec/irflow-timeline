# Virtual Grid

The data grid is the primary interface for viewing and interacting with timeline data. It uses virtual scrolling backed by SQLite pagination to handle millions of rows without performance degradation.

## How It Works

Rather than loading all rows into memory, the grid maintains a window of approximately 5,000 rows. As you scroll, new rows are fetched from SQLite using `LIMIT`/`OFFSET` queries. This means:

- **Memory usage stays constant** regardless of dataset size
- **Scrolling is smooth** with 20-row overscan padding above and below the viewport
- **Initial load is fast** — no waiting for millions of rows to render

## Column Operations

### Sorting

Click any column header to sort by that column. Click again to toggle between ascending and descending order. A sort indicator appears on the active column.

Sorting triggers a new SQL `ORDER BY` query. Indexes are created lazily on first sort for optimal performance.

### Resizing

Drag the right edge of any column header to resize it. Column widths are preserved per tab and saved in sessions.

### Pinning

Right-click a column header and select **Pin Left** to pin it to the left side of the grid. Pinned columns stay visible as you scroll horizontally, which is useful for keeping timestamp or event name columns always in view.

### Hiding / Showing

Open the Column Manager from the toolbar to:

- Hide columns you don't need
- Show previously hidden columns
- Reorder columns via drag-and-drop
- Reset to default column order

### Auto-Fit

Right-click a column header to auto-fit the column width to its content.

## Row Selection

- **Single click** selects a row and displays it in the detail panel
- **Shift+Click** selects a range of rows
- Selected rows are highlighted in the grid

## Detail Panel

Clicking a row opens the detail panel at the bottom of the window. It displays all column values for the selected row in a readable format, which is especially useful when rows contain long values that are truncated in the grid.

## Grouped View

You can group rows by any column:

1. Right-click a column header
2. Select **Group by this column**

Rows are organized into collapsible groups with:

- Group header showing the value and row count
- Expand/collapse toggle for each group
- Groups sorted by value

## Context Menu

Right-click any cell to access:

- **Copy cell value**
- **Copy row**
- **Bookmark row**
- **Add tag**
- **Filter to this value**
- **Exclude this value**
- **Pin/unpin column**
- **Group by column**

## Performance Characteristics

| Metric | Value |
|--------|-------|
| **Visible rows** | ~50 (depending on window height) |
| **Cached window** | ~5,000 rows |
| **Overscan** | 20 rows above/below viewport |
| **Query debounce** | 500ms for search/filter changes |
| **Index creation** | Lazy — built on first sort/search |
