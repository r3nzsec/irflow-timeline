# IRFlow Timeline

A high-performance native macOS application for DFIR timeline analysis. Built on Electron + SQLite to handle **30-50GB+** forensic timelines (CSV, TSV, XLSX, EVTX, Plaso) without breaking a sweat.

Inspired by Eric Zimmerman's Timeline Explorer for Windows.

## Quick Start

```bash
npm install
npx electron-rebuild -f -w better-sqlite3   # build native SQLite module
npm run start                                 # build + launch
```

## Supported Formats

| Format | Description |
|--------|-------------|
| **CSV / TSV** | Comma, tab, pipe delimited (auto-detected) |
| **XLSX** | Excel files with multi-sheet picker |
| **EVTX** | Windows Event Logs (native parsing via `@ts-evtx/core`) |
| **Plaso** | Plaso SQLite databases (auto-detects schema version, handles zlib-compressed event data) |

## Architecture

```
+----------------------------------------------------+
|  React UI (renderer)                               |
|  - Virtual scroll (only renders visible rows)      |
|  - Requests 5,000-row windows via IPC              |
|  - Inline SVG histogram, modals, context menus     |
+------------------------+---------------------------+
                         | IPC
+------------------------v---------------------------+
|  Electron Main Process                             |
|  - File dialog, native menus, export streaming     |
|  - HTML report generation                          |
|  - Coordinates parser <-> DB <-> renderer          |
+------------------------+---------------------------+
                         |
+------------------------v---------------------------+
|  SQLite Engine (better-sqlite3)                    |
|  - WAL mode, 500MB cache, 2GB mmap                |
|  - FTS5 full-text search index                     |
|  - B-tree indexes on timestamp/numeric columns     |
|  - SQL filtering, sorting, pagination              |
|  - Gap analysis, burst detection, coverage maps    |
|  - Temp DB in /tmp, auto-cleaned on close          |
+------------------------+---------------------------+
                         |
+------------------------v---------------------------+
|  Streaming Parsers                                 |
|  - CSV: readline stream, 50K-row batch inserts     |
|  - XLSX: ExcelJS streaming reader                  |
|  - EVTX: @ts-evtx/core async generator            |
|  - Plaso: SQLite ATTACH + zlib decompress          |
|  - Never loads full file into memory               |
+----------------------------------------------------+
```

### Key design decisions

| Problem | Solution |
|---------|----------|
| V8 heap limit (~4GB) | Stream rows into SQLite, never hold all in JS |
| Sorting 50GB of data | SQL `ORDER BY` with B-tree indexes |
| Full-text search across millions of rows | SQLite FTS5 virtual table |
| Smooth scrolling with millions of rows | Virtual scroll + `LIMIT 5000 OFFSET n` |
| EVTX parsing without external tools | `@ts-evtx/core` with single-pass schema discovery |
| Plaso import without psort.py | Direct SQLite-to-SQLite with zlib decompression |
| Export filtered view of 50GB file | Stream from SQLite cursor to disk |

## Features

### Search

Powered by SQLite FTS5 for near-instant search across millions of rows:

| Syntax | Behavior |
|--------|----------|
| `word1 word2` | OR -- matches either term |
| `+word` | AND -- must include |
| `-word` | EXCLUDE |
| `"exact phrase"` | Phrase match |
| `Column:value` | Column-specific filter |

**Search modes:** Mixed, OR, AND, Exact, Regex, Fuzzy

**Search conditions:** Contains, Starts With, Like, Equals

**Regex Pattern Palette** -- built-in quick-insert buttons for common forensic patterns (IPv4/v6, domains, email, MD5/SHA1/SHA256, Base64, Windows SIDs, UNC paths, file paths, URLs, registry keys, MAC addresses).

### Column Management

- **Show/hide columns** -- auto-detects and hides empty columns on import
- **Pin columns** -- keep important columns visible while scrolling
- **Reorder columns** -- drag headers to rearrange
- **Resize columns** -- drag column borders
- **KAPE profile detection** -- auto-applies layout for known KAPE output formats
- **Column Quick Stats** -- right-click a header for value distribution, fill rate, timestamp range, numeric stats, top 25 values bar chart

### Filtering

- **Per-column text filters** with SQL LIKE queries
- **Checkbox filters** -- select specific values from a dropdown
- **Date range filters** -- constrain any timestamp column to a time window
- **Filter presets** -- save and load filter configurations
- **Regex column filters** -- toggle regex mode per column
- **Bookmarked-only view** -- show only flagged rows
- **Disabled filters** -- temporarily disable individual filters without removing them

### Timeline Visualization

- **Interactive histogram** -- event density over time with heatmap coloring
- **Click-to-filter** -- click a histogram bar to zoom into that day
- **Resizable histogram** -- drag the bottom edge to adjust height
- **Multi-column support** -- choose which timestamp column to visualize

### Investigation Tools

| Tool | Description |
|------|-------------|
| **Stack Values** | Frequency distribution of any column's values with counts, percentages, and bar chart |
| **IOC Matching** | Load IOC lists (IPs, domains, hashes) and highlight matches across all columns |
| **Gap Analysis** | Detect activity sessions and quiet periods in the timeline. Auto-tag sessions. |
| **Log Source Coverage Map** | Gantt-style visualization of which log sources are present, their time span, and event counts. Click to filter by source. |
| **Burst Detection** | Find windows with abnormally high event density (N x median baseline). Sparkline chart, click-to-zoom, auto-tag bursts. |
| **Temporal Proximity Search** | Find events within a configurable time window around a pivot timestamp |
| **Cross-Tab Search** | Search for a term across all open tabs simultaneously |
| **Color Rules** | Conditional row highlighting with regex support and DFIR presets |
| **Multi-Tab Merge** | Combine 2+ tabs into a single chronological timeline with `_Source` column |

### Tagging & Bookmarking

- **Row bookmarking** -- flag important events (persisted in SQLite)
- **Custom tags** -- apply named, color-coded tags to rows
- **Bulk tagging** -- tag events by time range (used by Gap Analysis and Burst Detection)
- **Tag management** -- view, rename, recolor tags

### Export & Reporting

- **Export filtered view** -- stream filtered/sorted data to CSV without memory limits
- **HTML Report Generation** -- self-contained report with bookmarked events, tagged event groups, summary cards, tag breakdown. Print-friendly with light-mode `@media print` overrides.
- **Session save/load** -- persist bookmarks, tags, filters, column layout across sessions

### Themes

- **Dark mode** -- Unit 42-inspired dark theme (default)
- **Light mode** -- clean light theme
- Custom scrollbars styled to match the active theme

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Cmd+O | Open file |
| Cmd+F | Focus search |
| Cmd+E | Export filtered view |
| Cmd+B | Toggle bookmarked-only |
| Cmd+Shift+R | Generate HTML report |
| Cmd+Shift+C | Column manager |
| Cmd+Shift+K | Color rules |
| Cmd+Shift+F | Cross-tab search |
| Cmd+S | Save session |
| Cmd+Shift+S | Load session |
| Cmd+W | Close current tab |
| Cmd+Shift+W | Close all tabs |
| F3 | Next search match |
| Shift+F3 | Previous search match |
| Up/Down | Navigate rows |
| Cmd+Shift+H | Toggle histogram |
| Esc | Close modal |

## Building

```bash
# Development (hot-reload)
npm run dev

# Build + launch
npm run start

# Package as .dmg
npm run dist

# Universal binary (Intel + Apple Silicon)
npm run dist:universal
```

Output in `release/`. The DMG is fully standalone -- no Node.js required on target Macs.

## Prerequisites

- **Node.js 18+**: `brew install node`
- **Xcode CLI tools**: `xcode-select --install` (for native module compilation)
- **macOS 11+** (Big Sur or later)

## Performance

- **Import speed**: ~500K rows/sec (CSV), ~200K rows/sec (XLSX), ~150K rows/sec (Plaso)
- **Query speed**: <100ms for filtered queries on 10M+ row datasets
- **Memory usage**: ~200-500MB regardless of file size (SQLite handles the rest)
- **Disk usage**: SQLite temp DB is roughly 2-3x the original file size
- **Search debounce**: 500ms with 2-character minimum to prevent UI freezes on large datasets

## Credits

Inspired by [Eric Zimmerman's Timeline Explorer](https://ericzimmerman.github.io/).

## License

MIT
