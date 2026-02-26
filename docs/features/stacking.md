# Stacking

Stacking provides frequency analysis of unique values in any column, presented as bar charts. This technique is fundamental to DFIR analysis — unusual or rare values often indicate malicious activity.

## Opening Stacking

- **Menu:** Tools > Stacking
- Or right-click a column header and select **Stack this column**

## How It Works

1. Select a column to analyze
2. IRFlow Timeline queries SQLite for distinct values and their counts
3. Results are displayed as a horizontal bar chart with:
   - Value name
   - Count (absolute number)
   - Percentage of total rows
   - Visual bar proportional to count

## Filter Awareness

Stacking respects all active filters. If you have a search term, date range, or column filter active, the stacking analysis only considers the filtered rows. This lets you answer questions like:

- "What executables ran during the suspicious time window?"
- "What event types are associated with this user account?"
- "Which computers generated the most logon failures?"

## Sorting

Results can be sorted by:

- **Count (descending)** — most frequent values first (default)
- **Count (ascending)** — least frequent / rarest values first
- **Alphabetical** — sorted by value name

::: tip Rare Values
Sort ascending to find rare values. In many forensic scenarios, the most interesting entries are the ones that appear only once or a handful of times — a rare executable, an unusual path, or a one-time network connection.
:::

## Click-to-Filter

Click any value in the stacking chart to instantly filter the main grid to rows containing that value. This provides a quick drill-down workflow:

1. Stack a column to see the distribution
2. Click an interesting value
3. Examine the matching rows in full detail

## Common DFIR Use Cases

| Column | What to Look For |
|--------|-----------------|
| **Image / Process Name** | Unusual executables, LOLBins |
| **EventID** | Unexpected event types |
| **Computer** | Hosts with unusual activity volume |
| **User** | Accounts with anomalous behavior |
| **Channel** | Log source distribution |
| **Source Address** | Unusual network origins |
| **Parent Process** | Unexpected parent-child relationships |
| **Target Path** | Unusual file access patterns |
