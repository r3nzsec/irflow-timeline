# Log Source Coverage

Log Source Coverage provides a heatmap view of which log sources are present across your timeline, helping you identify collection gaps and verify evidence completeness.

## Opening Log Source Coverage

- **Menu:** Tools > Log Source Coverage

## What It Shows

The coverage heatmap displays:

- **Rows:** Each log source / artifact type in your timeline
- **Columns:** Time periods across your timeline span
- **Cells:** Color intensity indicating event density per source per time period

## Identifying Gaps

Coverage gaps are visually apparent as empty or light cells in the heatmap. Common reasons for gaps:

| Gap Pattern | Possible Cause |
|-------------|---------------|
| Single source goes dark | Log tampering, service stopped |
| All sources go dark | System offline, power loss |
| Source starts late | Collection began after incident |
| Source ends early | Collection stopped prematurely |
| Intermittent gaps | Rotation issues, storage limits |

## Investigation Workflow

1. Open Log Source Coverage to get the big picture
2. Identify any gaps in expected log sources
3. Cross-reference with [Gap Analysis](/features/gap-burst-analysis) for precise timestamps
4. Verify whether gaps align with known maintenance windows or are suspicious

## Tips

::: tip Evidence Validation
Run coverage analysis early in your investigation to ensure you have complete data before drawing conclusions. Missing log sources can lead to incorrect timelines.
:::

::: tip Multi-Source Correlation
When merging multiple timelines, check coverage to ensure overlapping time ranges. Sources that don't overlap in time provide limited correlation value.
:::
