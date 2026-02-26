# Performance Tips

IRFlow Timeline is engineered for large datasets, but these tips will help you get the best performance.

## Import Performance

### Streaming Architecture

Files are imported in streaming chunks — the full file is never loaded into memory:

| Format | Chunk Size | Batch Size |
|--------|-----------|------------|
| **CSV/TSV** | 128 MB | Adaptive (up to 100,000 rows) |
| **XLSX** | Streaming (ExcelJS) | Adaptive (up to 100,000 rows) |
| **XLS** | Full file (SheetJS) | Adaptive (up to 100,000 rows) |
| **EVTX** | Full file (binary) | Adaptive (up to 100,000 rows) |
| **Plaso** | Single SQLite query | All rows |

### Expected Import Times

These are approximate times on an Apple Silicon Mac:

| File Size | Rows | Import Time |
|-----------|------|-------------|
| 100 MB | ~500K | 5-10 seconds |
| 1 GB | ~5M | 30-60 seconds |
| 10 GB | ~50M | 5-8 minutes |
| 30 GB+ | ~150M+ | 15-25 minutes |

### Tips for Faster Import

- **Close unused tabs** before importing large files to free memory
- **Use CSV over XLSX** for very large datasets — CSV streaming is faster than Excel parsing
- **Pre-filter with external tools** if you only need a subset of the data

## Search Performance

### Background Indexing

After import, two background build phases run automatically:

1. **Column indexes** — one B-tree index per column, built sequentially (yields to event loop between each)
2. **FTS5 search index** — full-text search index built in 200,000-row chunks

Both phases run asynchronously so the UI remains interactive. A status indicator in the toolbar shows progress. If you search before the FTS index is ready, LIKE mode is used as a fallback.

### Search Mode Performance

| Mode | Speed | Best For |
|------|-------|---------|
| **FTS** | Fastest | Keyword searches |
| **LIKE** | Fast | Substring matching |
| **Mixed** | Fast | General use (runs both) |
| **Regex** | Moderate | Pattern matching |
| **Fuzzy** | Slowest | Typo-tolerant search |

### Debouncing

Search queries are debounced at 500ms — the query only executes after you stop typing for half a second. This prevents unnecessary queries while typing.

## Scrolling Performance

### Virtual Scrolling

The grid maintains a window of ~5,000 rows:

- Only visible rows (~50) are rendered in the DOM
- 20-row overscan above and below for smooth scrolling
- New data is fetched via SQLite `LIMIT`/`OFFSET` as you scroll

### Sorting

Column indexes are built automatically in the background after import:

- Sorting is fast once background indexing completes
- A status indicator shows indexing progress in the toolbar
- All columns are indexed (not just timestamp columns)

## Memory Management

### SQLite Configuration

IRFlow Timeline uses aggressive SQLite tuning for performance:

SQLite pragmas are tuned per-phase for maximum throughput:

**During import:**

| Setting | Value | Purpose |
|---------|-------|---------|
| **Journal mode** | OFF | No journal overhead for temp databases |
| **Synchronous** | OFF | Fast async writes |
| **Cache size** | 1 GB | Keep entire B-tree in memory |
| **MMAP size** | 0 | Disabled during writes |
| **Page size** | 64 KB | Fewer B-tree nodes, faster bulk writes |
| **Threads** | 4 | Parallel sort for internal operations |

**During background index/FTS build:**

| Setting | Value | Purpose |
|---------|-------|---------|
| **Journal mode** | OFF | No journal overhead |
| **Cache size** | 1 GB | Keep data + index pages in memory |
| **Threads** | 8 | Parallel sort/merge for CREATE INDEX |

**During query mode:**

| Setting | Value | Purpose |
|---------|-------|---------|
| **Journal mode** | WAL | Concurrent reads |
| **Synchronous** | NORMAL | Safe for queries |
| **Cache size** | 256 MB | Query cache |
| **MMAP size** | 512 MB | Memory-mapped reads |

### Temporary Files

Each tab creates a temporary SQLite database file. These are stored in the system temp directory and cleaned up when the tab is closed or the app exits.

For large datasets, ensure you have sufficient disk space:

| Dataset Size | Approximate DB Size |
|-------------|-------------------|
| 1 GB CSV | ~1.5 GB SQLite DB |
| 10 GB CSV | ~15 GB SQLite DB |
| 30 GB+ CSV | ~45 GB+ SQLite DB |

### Search Result Caching

The 4 most recent search queries per tab are cached in memory. This provides instant results when toggling between searches or switching tabs.

## Recommendations for Large Investigations

1. **Start with targeted files** — open the most relevant logs first, add more as needed
2. **Use date range filters early** — narrow to the investigation window before running analytics
3. **Merge selectively** — merge only the tabs relevant to your current question
4. **Save sessions frequently** — protect your work against unexpected issues
5. **Export subsets** — when sharing or reporting, export filtered data rather than full datasets
6. **Close completed tabs** — free memory by closing tabs you're done analyzing

## Hardware Recommendations

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 8 GB | 16-32 GB |
| **Storage** | SSD (any) | NVMe SSD |
| **CPU** | Any 64-bit | Apple Silicon (M1+) |
| **Free disk** | 2x largest file | 3x total evidence size |
