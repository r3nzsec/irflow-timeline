# Bookmarks & Tags

Bookmarks and tags are the core annotation tools for building your investigation narrative within IRFlow Timeline.

## Bookmarks

Bookmarks let you flag individual rows as important for later review and reporting.

### Adding Bookmarks

- Click the **star icon** on any row to toggle its bookmark
- Right-click a row and select **Bookmark**
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

Tags are free-form labels you attach to rows for categorization. Each row can have multiple tags, and tags are color-coded for visual distinction.

### Adding Tags

1. Right-click a row
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
| **Privilege Escalation** | Privilege elevation events |
| **Credential Access** | Credential harvesting/dumping |

You can also create custom tags — just type any name.

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

- Right-click a tagged row and select **Remove Tag**
- Choose which tag to remove (if multiple)
- Use **Edit > Remove Tag from All Filtered** for bulk removal

### Tag Colors

Each unique tag is assigned a color from the palette. Colors are consistent within a session and persist when saving/loading sessions.

### Filtering by Tag

- Click a tag chip to filter the grid to rows with that tag
- Use the tag filter dropdown to select one or more tags
- Combine tag filters with other filter types

### In Reports

HTML reports include:

- Summary count of tagged rows
- Tag breakdown chips showing each tag and its count
- Grouped tables showing rows organized by tag
- Color-coded tag indicators matching the in-app palette
