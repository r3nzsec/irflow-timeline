# Sessions

Sessions let you save and restore your complete analysis state, including all open tabs, filters, bookmarks, tags, and customizations.

## Save a Session

- **Menu:** File > Save Session (`Cmd+S`)
- Choose a location and filename
- Sessions are saved as `.tle` files (JSON format)

## Load a Session

- **Menu:** File > Load Session (`Cmd+Shift+O`)
- Select a `.tle` file
- IRFlow Timeline restores all tabs and their state

## What Gets Saved

A session file preserves the complete state of your analysis:

| State | Details |
|-------|---------|
| **Open tabs** | All tabs with file paths and sheet names |
| **Column configuration** | Pinned columns, hidden columns, column widths, column order |
| **Filter state** | Column filters, checkbox filters, date ranges, advanced filters |
| **Bookmarks** | All bookmarked row identifiers |
| **Tags** | All tags with their row assignments |
| **Color rules** | Custom conditional formatting rules |
| **Grouping** | Active group-by column settings |
| **Search state** | Last search term and mode |

## How Restoration Works

When loading a session:

1. The `.tle` file is parsed for tab metadata
2. Each original file is re-imported (lazy loading)
3. Column configurations are applied
4. Filters, bookmarks, tags, and color rules are restored
5. The active tab is selected

::: warning File Paths
Sessions store the original file paths. If you move the source files after saving a session, the load will fail for those tabs. Keep your evidence files in a stable location.
:::

## Session File Format

The `.tle` file is a JSON structure:

```json
{
  "version": "2.1",
  "tabs": [
    {
      "name": "Security.evtx",
      "filePath": "/path/to/Security.evtx",
      "sheetName": null,
      "columns": { ... },
      "filters": { ... },
      "bookmarks": [1, 42, 156, ...],
      "tags": { "1": ["Suspicious"], "42": ["Lateral Movement"] },
      "colorRules": [ ... ],
      "groupBy": null
    }
  ],
  "activeTab": 0
}
```

## Tips

::: tip Save Often
Save your session periodically during long investigations. If the app closes unexpectedly, you can restore from your last save.
:::

::: tip Share Sessions
Session files can be shared with other analysts, provided they have access to the same source files at the same paths. This is useful for team handoffs.
:::

::: tip Multiple Sessions
Create separate session files for different investigation tracks. For example, save one session focused on lateral movement and another on data exfiltration.
:::
