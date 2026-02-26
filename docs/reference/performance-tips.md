# Performance Tips

IRFlow Timeline is engineered for large datasets, but these tips will help you get the best performance.

## Import Performance

### Streaming Architecture

Files are imported in streaming chunks — the full file is never loaded into memory:

| Format | Chunk Size | Batch Size |
|--------|-----------|------------|
| **CSV/TSV** | 16 MB | 50,000 rows |
| **XLSX** | Streaming (ExcelJS) | 50,000 rows |
| **EVTX** | Full file (binary) | 50,000 rows |
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

### FTS Index

The full-text search index is built lazily on your first search:

- Building processes 100,000 rows per chunk
- The UI remains responsive during index creation
- Subsequent searches are near-instant
- If you search before the index is ready, LIKE mode is used as a fallback

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

The first time you sort by a column, a SQLite index is created:

- Initial sort may take a moment for large datasets
- Subsequent sorts on the same column are instant
- Indexes are created lazily to keep initial load fast

## Memory Management

### SQLite Configuration

IRFlow Timeline uses aggressive SQLite tuning for performance:

| Setting | Value | Purpose |
|---------|-------|---------|
| **Journal mode** | WAL | Concurrent reads during writes |
| **Synchronous** | OFF (during import) | Fast async writes |
| **Cache size** | 512 MB | Large memory buffer |
| **MMAP size** | 2 GB | Memory-mapped I/O |
| **Page size** | 32 KB | Larger page transfers |
| **Temp store** | Memory | Fast intermediate operations |

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
