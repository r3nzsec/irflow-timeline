# Export & Reports

IRFlow Timeline supports exporting filtered data and generating investigation reports.

## Data Export

### Export to CSV

1. **Menu:** File > Export (`Cmd+E`)
2. Select **CSV** format
3. Choose a save location
4. Exported data respects all active filters — only visible rows are exported

### Export to TSV

1. **Menu:** File > Export (`Cmd+E`)
2. Select **TSV** format
3. Choose a save location
4. Tab-separated output with the same filtering as CSV

### Export to XLSX

1. **Menu:** File > Export (`Cmd+E`)
2. Select **XLSX** format
3. Choose a save location
4. Excel files include:
   - Auto-fit column widths
   - Styled header row (bold, colored)
   - All filtered data

### Export to XLS

1. **Menu:** File > Export (`Cmd+E`)
2. Select **XLS** format (legacy binary Excel)
3. Choose a save location
4. Compatible with older Excel versions and third-party tools

### What Gets Exported

Exports include:

- All columns (visible and hidden)
- Only rows matching current filters, search, and date range
- Bookmarked/tagged rows if those filters are active
- Data in the current sort order

::: tip Export Bookmarked Only
Enable the bookmark filter (`Cmd+B`) before exporting to create a file containing only your flagged rows.
:::

## HTML Reports

Generate a formatted investigation report from your bookmarks and tags.

### Generate a Report

1. **Menu:** File > Generate Report
2. Choose a save location
3. The HTML report opens in your default browser

### Report Contents

The generated report includes:

#### Summary Cards

- Total rows in the dataset
- Number of bookmarked rows
- Number of tagged rows
- Count of unique tags

#### Timeline Span

- Earliest timestamp in the data
- Latest timestamp in the data
- Total time span covered

#### Tag Breakdown

- Colored chips showing each tag and its count
- Colors match your in-app tag palette

#### Bookmarked Events Table

- Full data for every bookmarked row
- All columns included
- Sortable in the browser

#### Tagged Events (Grouped)

- Separate tables for each tag
- Rows grouped under their tag heading
- Shows all columns with full data

### Report Styling

Reports are self-contained HTML with embedded CSS:

- Clean, professional layout
- Print-friendly formatting
- Works in light and dark browser themes
- No external dependencies — can be shared as a single file

## Export Workflow Example

A typical investigation export workflow:

1. **Analyze** — use search, filters, and analytics to investigate
2. **Bookmark** — star important rows as you find them
3. **Tag** — categorize findings (Suspicious, Lateral Movement, etc.)
4. **Generate Report** — create the HTML summary
5. **Export Data** — export filtered CSV/XLSX for further analysis or archival
6. **Share** — send the report to your team or include in your case file
