# Gap & Burst Analysis

Gap and burst analysis help you identify temporal anomalies in your timeline — periods of unusual inactivity or suspicious spikes of activity.

## Gap Analysis

### What It Detects

Gap analysis identifies periods where no events were recorded, which may indicate:

- **Log tampering** — attacker cleared or stopped logging
- **System downtime** — host was offline
- **Collection gaps** — incomplete log collection
- **Normal idle periods** — after-hours quiet time

### How to Use

1. Open **Tools > Gap Analysis**
2. Set the **gap threshold** — minimum duration to consider as a gap (e.g., 1 hour, 4 hours, 24 hours)
3. Results show each detected gap with:
   - Start timestamp (last event before the gap)
   - End timestamp (first event after the gap)
   - Duration of the gap
   - Number of events before and after

### How It Works

The analysis runs entirely in SQL:

1. Events are ordered by timestamp
2. Time difference between consecutive events is calculated
3. Gaps exceeding the threshold are reported
4. No in-memory sorting required — SQLite handles the ordering

### Investigation Tips

::: tip Compare Sources
Run gap analysis on individual log sources (filter by channel/source first). A gap in Security logs while System logs continue recording is a strong indicator of log tampering.
:::

::: tip Correlate with Activity
Check what happened immediately before and after each gap. If the pre-gap event is suspicious (e.g., service stop, audit policy change), investigate further.
:::

## Burst Analysis

### What It Detects

Burst analysis identifies abnormal spikes in event volume that stand out from the baseline activity. Spikes may indicate:

- **Brute force attacks** — rapid authentication attempts
- **Data exfiltration** — high-volume file access
- **Automated tools** — scripts or malware generating many events
- **Lateral movement** — rapid logon events across systems

### How to Use

1. Open **Tools > Burst Analysis**
2. Configure:
   - **Window size** — aggregation interval (1-60 minutes)
   - **Burst factor** — how many times above baseline qualifies as a burst (e.g., 3x)
3. Results show:
   - Time window of each burst
   - Event count in the burst window
   - Baseline (median) event count
   - Burst ratio (burst count / baseline)
   - Sparkline visualization

### How It Works

1. Events are bucketed into fixed-width time windows
2. The **median** event count across all windows becomes the baseline
3. Windows exceeding `baseline × burst_factor` are flagged
4. Results are sorted by burst ratio (highest spikes first)

### Sparkline

Each burst result includes a sparkline showing the event density around the burst window, providing visual context for whether the spike is isolated or part of a trend.

### Configuration

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| **Window size** | 5 minutes | 1-60 min | Aggregation bucket width |
| **Burst factor** | 3x | 2-20x | Multiplier above baseline |

### Investigation Tips

::: tip Narrow the Window
Start with a larger window (15-30 min) to find general areas of interest, then narrow to 1-5 minutes for precise spike identification.
:::

::: tip Filter First
Apply filters before running burst analysis. For example, filter to authentication events only and then look for bursts to find brute force attempts.
:::

::: tip Cross-Reference
After identifying a burst, filter the main grid to that time range and examine the individual events. Look for repeated patterns (same source, same target, same event type).
:::
