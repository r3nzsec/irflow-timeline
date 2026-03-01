# Bookmarks & Tags

Bookmarks and tags are the core annotation tools for building your investigation narrative within IRFlow Timeline.

![Bookmarks and Tags showing tagged rows with context menu for applying DFIR tags like Suspicious, Lateral Movement, and C2](/dfir-tips/Bookmarks-Tags.png)

## Bookmarks

Bookmarks let you flag individual rows as important for later review and reporting.

### Adding Bookmarks

- Click the **star icon** on any row to toggle its bookmark
- `Cmd+Click` a row and select **Bookmark**
- Bookmarks are stored per-tab in the SQLite database

### Bulk Bookmarking

- Apply current filters, then use **Edit > Bookmark All Filtered** to bookmark every visible row
- Use **Edit > Unbookmark All Filtered** to remove bookmarks from filtered results

### Viewing Bookmarks

- Toggle `Cmd+B` to show only bookmarked rows
- The tab badge shows the bookmarked row count
- Bookmarked rows display a filled star icon in the grid

### In Reports

Bookmarked rows are included in HTML reports with their full data. They appear in a dedicated "Bookmarked Events" section.

## Tags

Tags are free-form labels you attach to rows for categorization. Each row can have multiple tags, and tags are color-coded for visual distinction. The Tags column is a full first-class grid column — you can sort, filter, and stack by tags just like any other column.

### Adding Tags

1. `Cmd+Click` a row
2. Select **Add Tag**
3. Type a tag name or choose from presets
4. The tag appears as a colored chip in the Tags column

### Tag Presets

IRFlow Timeline includes common DFIR investigation tags:

| Tag | Use Case |
|-----|----------|
| **Suspicious** | General suspicious activity |
| **Lateral Movement** | Evidence of movement between hosts |
| **Exfiltration** | Data exfiltration indicators |
| **Persistence** | Persistence mechanism installation |
| **C2** | Command and control communication |
| **Initial Access** | Entry point indicators |
| **Execution** | Malicious execution events |
| **Credential Access** | Credential harvesting/dumping |

You can also create custom tags — just type any name. IOC Matching automatically creates per-indicator tags (e.g., `IOC: cmd.exe`, `IOC: 185.220.101.34`) with orange coloring.

### Bulk Tagging

**By Time Range:**

1. Open **Tools > Bulk Tag**
2. Select a start and end timestamp
3. Choose or type a tag name
4. All rows in the time range receive the tag

This is useful for marking an entire activity window (e.g., "Attacker Active 14:30-15:45").

**By Filter:**

Apply any combination of filters, then use **Edit > Tag All Filtered** to tag every visible row.

### Removing Tags

- `Cmd+Click` a tagged row and select **Remove Tag**
- Choose which tag to remove (if multiple)
- Use **Edit > Remove Tag from All Filtered** for bulk removal

### Tag Colors

Each unique tag is assigned a color from the palette. Colors are consistent within a session and persist when saving/loading sessions.

### Tags Column Features

The Tags column behaves as a full grid column with:

- **Sorting** — click the Tags column header to sort rows by their tag values
- **Text filtering** — type in the Tags filter cell to search for specific tags using SQL `LIKE` matching
- **Checkbox filtering** — click the dropdown button in the Tags filter cell to select specific tags from a checkbox list
- **Stacking** — `Cmd+Click` the Tags header and select Stack Values to see tag frequency distribution
- **Column Stats** — view tag statistics including total tagged rows, unique tags, and top values
- **Disable/enable** — toggle the tag filter on/off without removing it (shown with strikethrough when disabled)

### Filtering by Tag

- Type in the Tags filter cell to filter by tag name
- Use the dropdown checkbox filter to select one or more specific tags
- Click a tag chip in a row to filter to rows with that tag
- Combine tag filters with other filter types

### In Reports

HTML reports include:

- Summary count of tagged rows
- Tag breakdown chips showing each tag and its count
- Grouped tables showing rows organized by tag
- Color-coded tag indicators matching the in-app palette
