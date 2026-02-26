# Multi-Tab Analysis

IRFlow Timeline supports opening multiple files simultaneously in separate tabs, enabling cross-source correlation and parallel investigation.

## Opening Multiple Files

Each file you open creates a new tab:

- **Cmd+O** to open additional files
- **Drag and drop** multiple files onto the window
- Each tab operates independently with its own filters, bookmarks, and tags

## Tab Management

### Navigation

- Click a tab to switch to it
- Tabs show the filename and row count
- The active tab is highlighted

### Closing Tabs

- Click the close button on a tab
- **Cmd+W** closes the active tab
- Bookmarks and tags for closed tabs are lost unless saved in a session

### Reordering

Drag tabs to reorder them. This is useful for organizing related files next to each other.

## Independent State

Each tab maintains its own:

- Filter configuration
- Search term and mode
- Bookmarks
- Tags
- Color rules
- Column layout (pinned, hidden, widths)
- Sort order
- Histogram cache

## Cross-Tab Search

Use **Cmd+Shift+F** to search across all open tabs simultaneously:

1. Enter your search term
2. Results show the match count per tab
3. Click a result to jump to that tab with the search applied

This is useful for answering questions like:
- "Does this IP appear in any other log source?"
- "Which timelines contain references to this executable?"

## Multi-Tab Investigation Workflow

A common workflow for multi-source investigations:

1. **Open all sources** — Security EVTX, Sysmon EVTX, MFTECmd CSV, etc.
2. **Cross-tab search** — find a suspicious indicator across all sources
3. **Correlate timestamps** — check the same time window in each source
4. **Bookmark consistently** — star related events in each tab
5. **Tag with categories** — use the same tags across tabs for consistency
6. **Merge tabs** — combine into a unified timeline for the final report

## Tips

::: tip Memory Management
Each tab creates its own SQLite database. For very large investigations (10+ tabs with large files), monitor system memory usage.
:::

::: tip Tab Naming
Tabs are named after the source filename. Use descriptive filenames for your evidence files to make tab navigation easier.
:::
