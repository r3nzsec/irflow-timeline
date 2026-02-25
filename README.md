# IRFlow Timeline
<img width="731" height="410" alt="image" src="https://github.com/user-attachments/assets/23e50080-85a6-4a25-ad7c-3779076aeb20" />

A high-performance native macOS application for DFIR timeline analysis. Built on Electron + SQLite to handle large files for forensic timelines (CSV, TSV, XLSX, EVTX, Plaso) without breaking a sweat.

Inspired by Eric Zimmerman's Timeline Explorer for Windows.

## Download & Install

1. Download the latest DMG from [Releases](https://github.com/r3nzsec/irflow-timeline/releases)
2. Open the DMG and drag **IRFlow Timeline** to Applications
3. On first launch: right-click the app > **Open** > **Open** (required because the app is unsigned)

**Requirements:** macOS 10.13+ (High Sierra or later). No other dependencies needed.

## Supported Formats

| Format | Description |
|--------|-------------|
| **CSV / TSV** | Comma, tab, pipe delimited (auto-detected) |
| **XLSX** | Excel files with multi-sheet picker |
| **EVTX** | Windows Event Logs up to 3GB (native parsing via `@ts-evtx/core`) |
| **Plaso** | Plaso SQLite databases (auto-detects schema version, handles zlib-compressed event data) |

## Features

### Data Import
- **Multi-file parallel import** -- drag multiple files or select via dialog; all import concurrently with per-tab progress
- **Multi-tab workspace** -- each file gets its own tab with independent state
- **Tab merging** -- combine 2+ tabs into a single chronological timeline with `_Source` column

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

**Cross-tab search** -- search across all open tabs simultaneously with per-tab match counts

**Regex Pattern Palette** -- built-in quick-insert buttons for common forensic patterns (IPv4/v6, domains, email, MD5/SHA1/SHA256, Base64, Windows SIDs, UNC paths, file paths, URLs, registry keys, MAC addresses).

### Column Management
- **Show/hide columns** -- auto-detects and hides empty columns on import
- **Pin columns** -- keep important columns visible while scrolling
- **Reorder columns** -- drag headers to rearrange
- **Resize columns** -- drag column borders
- **Group by** -- drag column headers to the group bar for hierarchical views
- **Column Quick Stats** -- right-click a header for value distribution, fill rate, timestamp range, numeric stats, top 25 values bar chart

### Filtering
- **Per-column text filters** with SQL LIKE queries
- **Checkbox filters** -- select specific values from a dropdown
- **Date range filters** -- constrain any timestamp column to a time window
- **Advanced Edit Filter** -- multi-condition builder with AND/OR logic, 11 operators (contains, not contains, equals, not equals, starts with, ends with, greater than, less than, is empty, is not empty, regex), and live preview
- **Filter presets** -- save and load named filter configurations
- **Bookmarked-only view** -- show only flagged rows

### Timeline Visualization
- **Interactive histogram** -- event density over time with heatmap coloring
- **Click-and-drag** -- select a time range on the histogram to filter
- **Resizable** -- drag the bottom edge to adjust height
- **Per-tab caching** -- instant histogram display when switching tabs

### Investigation Tools

| Tool | Description |
|------|-------------|
| **Stack Values** | Frequency distribution of any column's values with counts, percentages, and bar chart |
| **IOC Matching** | Load IOC lists (IPs, domains, hashes, URLs) and highlight matches across all columns |
| **Gap Analysis** | Detect activity sessions and quiet periods in the timeline. Auto-tag sessions. |
| **Log Source Coverage Map** | Gantt-style visualization of which log sources are present, their time span, and event counts |
| **Burst Detection** | Find windows with abnormally high event density. Sparkline chart, click-to-zoom, auto-tag bursts |

### Tagging & Bookmarking
- **Row bookmarking** -- flag important events
- **Custom tags** -- apply named, color-coded tags to rows
- **Bulk tagging** -- tag events by time range
- **Tag management** -- view, rename, recolor tags

### Export & Reporting
- **Export filtered view** -- stream filtered/sorted data to CSV
- **HTML Report** -- self-contained report with bookmarked events, tagged groups, summary cards
- **Session save/restore** -- persist bookmarks, tags, filters, column layout across sessions (.tle files)

### Display
- **Dark/Light theme** -- Unit 42-inspired dark theme (default)
- **Timezone selector** -- UTC or local
- **Datetime format** -- configurable display format
- **Adjustable font size**

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Cmd+O | Open file |
| Cmd+F | Focus search |
| Cmd+E | Export filtered view |
| Cmd+B | Toggle bookmarked-only |
| Cmd+S | Save session |
| Cmd+W | Close current tab |
| Cmd+Plus / Cmd+Minus | Increase / decrease font size |
| Esc | Close modal / clear search |

## Performance

- **Import speed**: ~500K rows/sec (CSV), ~200K rows/sec (XLSX), ~150K rows/sec (Plaso)
- **Query speed**: <100ms for filtered queries on 10M+ row datasets
- **Memory usage**: ~200-500MB regardless of file size (SQLite handles the rest)
- **Disk usage**: SQLite temp DB is roughly 2-3x the original file size

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
|  - WAL mode, 500MB cache, 2GB mmap                 |
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
|  - EVTX: @ts-evtx/core async generator             |
|  - Plaso: SQLite ATTACH + zlib decompress          |
|  - Never loads full file into memory               |
+----------------------------------------------------+
```

## Building from Source

**Prerequisites (for developers only):**
- Node.js 18+: `brew install node`
- Xcode CLI tools: `xcode-select --install` (for native module compilation)
- macOS 11+ (Big Sur or later)

```bash
git clone https://github.com/r3nzsec/irflow-timeline.git
cd irflow-timeline
npm install
npx electron-rebuild -f -w better-sqlite3

# Development (hot-reload)
npm run dev

# Build + launch
npm run start

# Package as universal DMG
npm run dist:universal
```

Output in `release/`.

## Credits & Acknowledgments

Inspired by [Eric Zimmerman's Timeline Explorer](https://ericzimmerman.github.io/).

### Open Source Projects

| Project | Usage | Link |
|---------|-------|------|
| **Electron** | Application framework | [electron/electron](https://github.com/electron/electron) |
| **better-sqlite3** | High-performance SQLite engine with WAL mode, FTS5 | [WiseLibs/better-sqlite3](https://github.com/WiseLibs/better-sqlite3) |
| **@ts-evtx/core** | Native Windows EVTX event log parsing | [nicholasgasior/ts-evtx](https://github.com/nicholasgasior/ts-evtx) |
| **Plaso (log2timeline)** | Forensic timeline generation (we import Plaso SQLite output) | [log2timeline/plaso](https://github.com/log2timeline/plaso) |
| **ExcelJS** | XLSX streaming reader | [exceljs/exceljs](https://github.com/exceljs/exceljs) |
| **csv-parser** | CSV/TSV streaming parser | [mafintosh/csv-parser](https://github.com/mafintosh/csv-parser) |
| **React** | UI rendering | [facebook/react](https://github.com/facebook/react) |
| **Vite** | Build tooling and hot-reload | [vitejs/vite](https://github.com/vitejs/vite) |
| **electron-builder** | macOS DMG packaging | [electron-userland/electron-builder](https://github.com/electron-userland/electron-builder) |

### DFIR Community

- [Eric Zimmerman](https://ericzimmerman.github.io/) -- Timeline Explorer for Windows, the original inspiration for this project
- [log2timeline/Plaso](https://github.com/log2timeline/plaso) -- Super timeline generation framework by Kristinn Gudjonsson and contributors
- [SANS DFIR](https://www.sans.org/digital-forensics-incident-response/) -- DFIR training and community resources

### Beta Testers

Thanks to the following people for testing and providing feedback:

- Maddy Keller
- Omar Jbari
- Nicolas Bareil
- Dominic Rathmann

## License

MIT
