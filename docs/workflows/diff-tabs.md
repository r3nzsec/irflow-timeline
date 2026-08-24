---
description: Diff any two imported tabs in IRFlow Timeline and inspect Added, Removed, and Changed rows interactively.
---

# Diff Tabs

View → **Diff Tabs** compares two open tabs of any imported format — CSV, EVTX, MFT, Prefetch, AI Query History, Computer History, or a previous merge — and opens a result tab that is a first-class timeline.

This is not a Computer History feature. Matching is by identity columns (or entire-row content) that exist on the files you picked.

Merge Tabs is a union. Diff Tabs is a comparison.

## How to Diff

1. Open two (or more) files as separate tabs
2. **Menu:** View → Diff Tabs
3. Choose **Baseline** (older / expected) and **Compare** (newer / current)
4. Keep **Auto keys**, pick identity columns, or match entire rows
5. Run Diff

A new tab opens with color-coded `_Diff` values. Diff Explorer opens on top of the grid; the Diff banner stays on the result tab after you close the explorer.

## Match modes

| Mode | What it does |
|------|----------------|
| **Auto keys** | Suggests identity columns from header names that work across DFIR formats (`EventRecordId`, `SHA1`, `SourceFile` + `Timestamp` + `EventKind`, …) |
| **Choose columns** | You pick the columns that identify the same event in both files. Remaining columns become the field-level comparison |
| **Entire row** | Identical rows are Unchanged. Anything without an exact counterpart is Added or Removed |

Duplicate identity values are matched as a multiset: the first unmatched baseline row pairs with the first unmatched compare row.

## Result tab

| Column | Meaning |
|--------|---------|
| `_Diff` | `Added` (compare only), `Removed` (baseline only), `Changed` (same identity, different values), `Unchanged` |
| `_ChangedFields` | Comma-separated fields that differ |
| `_DiffSummary` | Short `field: old → new` preview |
| `_MatchKey` | Identity values used to pair the rows |
| `_Baseline` / `_Compare` | Source tab names |
| `datetime` | Timestamp from the compare side when present, otherwise baseline |
| other columns | Union of both schemas. Compare values for Added/Changed/Unchanged; baseline values for Removed |

Unchanged rows are omitted by default so large identical files stay scannable. The explorer still reports how many were identical. Turn **Include Unchanged rows** on in the setup dialog if you need them in the grid.

Rows are colored: green Added, red Removed, amber Changed. Click the banner pills or Diff Explorer cards to filter the grid. Click a field name under **Fields that changed most** to isolate Changed rows that touched that column.

Open a Changed row's detail pane (or the explorer's **Selected row** panel) for a field-by-field before/after table.

## Use cases

- Two exports of the same artifact (v2 vs v3 Computer History, two EvtxECmd runs, two MFT dumps)
- A host timeline before and after remediation
- AI Query History collected on two dates
- Any two CSVs that share an identity column, even when extra columns appeared in the newer file

## See Also

- [Merging Timelines](/workflows/merge-tabs) — union of tabs, not a comparison
- [Multi-Tab Analysis](/workflows/multi-tab) — open the files before diffing
- [Color Rules](/features/color-rules) — Diff Tabs installs `_Diff` color rules automatically
