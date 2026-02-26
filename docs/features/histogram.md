# Histogram

The histogram provides a visual timeline of event distribution, helping you identify activity patterns, quiet periods, and suspicious bursts at a glance.

## Opening the Histogram

- **Menu:** Tools > Histogram
- The histogram panel appears above the data grid and can be resized by dragging its bottom edge

## Granularity

Choose the time bucketing level from the histogram toolbar:

| Granularity | Bucket Size | Best For |
|-------------|-------------|----------|
| **Day** | 1 calendar day | Long timelines (weeks/months) |
| **Hour** | 1 hour | Multi-day investigations |
| **Minute** | 1 minute | Detailed activity analysis |

## Brush Selection

Click and drag on the histogram to select a time range:

1. The selected range is highlighted
2. The data grid immediately filters to show only events within that range
3. Clear the selection to restore the full view

This is the fastest way to zoom into a specific activity window.

## Multi-Source Coloring

When viewing merged timelines or files with multiple artifact types, the histogram bars are color-coded by source. Each artifact type or log channel gets a distinct color, making it easy to see which sources contributed events at each time period.

## Stacking Glassmorphism

In v2.1, the histogram introduces stacking glassmorphism — when multiple event sources overlap in the same time bucket, bars stack with a subtle transparency effect. This lets you see the composition of each time bucket without sources hiding behind each other.

## Filter Awareness

The histogram respects all active filters:

- Column filters
- Checkbox filters
- Search terms
- Tag filters
- Bookmark filter

When filters are active, the histogram shows the distribution of **filtered** rows only, helping you visualize the temporal distribution of your search results.

## Caching

Histogram data is cached per-tab. When switching between tabs, the histogram updates instantly from cache rather than re-querying the database. Cache is invalidated when filters change.

## Timestamp Detection

The histogram automatically identifies timestamp columns in your data. If multiple timestamp columns exist, you can select which one to use from the histogram controls.

Supported timestamp formats include:

- ISO 8601 (`2024-01-15T14:30:00Z`)
- US format (`01/15/2024 2:30:00 PM`)
- European format (`15/01/2024 14:30:00`)
- Date-only (`2024-01-15`)
- Various forensic tool output formats
