---
description: Performance optimization tips for IRFlow Timeline — streaming architecture, memory management, and large file handling.
---

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
| **Plaso** | Single query on the Plaso SQLite file | All rows |

### Expected Import Times

These are approximate times on an Apple Silicon Mac:

| File Size | Rows | Import Time |
|-----------|------|-------------|
| 100 MB | ~500K | 5-10 seconds |
| 1 GB | ~5M | 30-60 seconds |
| 10 GB | ~50M | 5-8 minutes |
| 30 GB+ | ~150M+ | 15-25 minutes |

### Benchmarks

The following benchmarks were measured on an **Apple M1 Pro (16 GB RAM, NVMe SSD)** using EvtxECmd CSV output, with the earlier SQLite engine. Times may vary based on column count, data complexity, and system load. The DuckDB engine needs no column-index or full-text-index build, so the last two build columns no longer apply.

#### Import + Indexing

| Dataset | Rows | Columns | Import | Column Indexes | FTS5 Build | Total |
|---------|------|---------|--------|---------------|------------|-------|
| Small (KAPE single host) | 500K | 22 | ~6s | ~3s | ~4s | ~13s |
| Medium (multi-host merge) | 5M | 22 | ~45s | ~25s | ~35s | ~2 min |
| Large (enterprise triage) | 50M | 22 | ~7 min | ~4 min | ~6 min | ~17 min |
| Very large (full super-timeline) | 150M+ | 22 | ~22 min | ~12 min | ~18 min | ~52 min |

#### Query Response Times (after indexing)

| Operation | 500K rows | 5M rows | 50M rows |
|-----------|----------|---------|----------|
| FTS keyword search | <10ms | <30ms | <80ms |
| Regex search | ~20ms | ~150ms | ~1.5s |
| Fuzzy search | ~50ms | ~400ms | ~4s |
| Column sort (indexed) | <10ms | <20ms | <50ms |
| Checkbox filter | <10ms | <15ms | <40ms |
| Scroll to new page | <5ms | <10ms | <15ms |

#### Analytics Tools

| Tool | 500K rows | 5M rows | 50M rows |
|------|----------|---------|----------|
| Histogram build | <100ms | ~300ms | ~2s |
| Stacking (single column) | ~50ms | ~200ms | ~1.5s |
| Gap Analysis | ~30ms | ~150ms | ~1s |
| Burst Detection | ~40ms | ~200ms | ~1.5s |
| Log Source Coverage | ~20ms | ~100ms | ~800ms |
| Process Inspector build | ~100ms | ~500ms | ~3s |
| Lateral Movement scan | ~80ms | ~400ms | ~2.5s |
| Persistence Analyzer | ~60ms | ~300ms | ~2s |
| IOC Match (1,000 IOCs) | ~200ms | ~1s | ~8s |

::: tip
Analytics tools run against the currently filtered dataset. Applying date range or column filters before running analytics significantly reduces processing time on large datasets.
:::

### Tips for Faster Import

- **Restart IRFlow** before importing multi-GB files if the app has been open for hours — a high main-process memory footprint before import is a common crash trigger
- **Close unused tabs** before importing large files to free memory
- **Wait for the background build** ("indexes ready") before opening column filter dropdowns on files over 5 GB: until it finishes, filter value lists on those files are sampled.
- **Use CSV over XLSX** for very large datasets — CSV streaming is faster than Excel parsing
- **Pre-filter with external tools** if you only need a subset of the data

DuckDB compresses each column, so a tab's database is usually **smaller than the source file** (a 41 MB Hayabusa CSV took 35 MB, a 29 MB MFT CSV 8 MB; with the SQLite engine they took 242 MB and 178 MB including indexes). Keep extra free space on the temp volume anyway: DuckDB writes overflow files there for sorts and aggregations larger than its memory limit.

## AI History Performance

**Collect AI Artifacts** and large folder imports run in a worker thread so the UI stays responsive.

| Tip | Why |
|-----|-----|
| **Main sessions only** on first pass | Skips `subagents/` and sidechain rows — much faster on hosts with 80k+ JSONL lines |
| **Browse folder scope** | Point at the KAPE/triage root so discovery does not also read unrelated local Mac paths |
| **Filter before export** | **Export AI History Package** respects active filters — narrow to tagged secret findings or a date window before writing the CSV |
| **Scroll large AI tabs** | AI Query History tabs with 100k+ rows use the same virtual scroll window as EVTX timelines; avoid keeping many huge AI tabs open at once |

Merged AI timelines stop at **3,000,000** rows and report truncation in the import notice. Malformed JSONL lines are skipped and counted so you know when a source may be incomplete.

## Search Performance

### No search index

Search needs no index: the DuckDB engine checks each column with a case-insensitive substring match, in parallel, so complete results are available as soon as a tab opens. Regex search runs in DuckDB's own regex engine (RE2) and falls back to JavaScript only for patterns RE2 does not support (lookarounds, backreferences).

### Search Mode Performance

| Mode | Speed | Best For |
|------|-------|---------|
| **LIKE** | Fast | Substring matching |
| **Mixed** | Fast | General use |
| **Regex** | Moderate | Pattern matching |
| **Fuzzy** | Slowest | Typo-tolerant search |

### Debouncing

Search queries are debounced at 500ms — the query only executes after you stop typing for half a second. This prevents unnecessary queries while typing.

## Scrolling Performance

### Virtual Scrolling

The grid maintains a window of ~10,000 rows:

- Only visible rows (~50) are rendered in the DOM
- 20-row overscan above and below for smooth scrolling
- New data is fetched via `LIMIT`/`OFFSET` as you scroll

### Sorting

DuckDB sorts without indexes. Timestamp columns sort chronologically through `sort_datetime()`, which converts zoned timestamps (for example Hayabusa's `+09:00`) to UTC:

- Plain ISO timestamps are converted inside DuckDB
- For other formats, a background step after import stores each timestamp column's sort key (the toolbar shows its progress); until it finishes, sorting those columns is slower

## Memory Management

### DuckDB Configuration

All tabs share one DuckDB instance on a dedicated worker thread:

| Setting | Value | Purpose |
|---------|-------|---------|
| **Memory limit** | Half of system memory | Leaves room for Electron, the renderer and the JavaScript analyzers |
| **Threads** | All cores | Parallel scans, sorts and aggregations |
| **Temp directory** | The temp storage folder | Overflow files for sorts and aggregations larger than the memory limit |
| **Extensions** | Never downloaded | Only the built-in JSON, ICU and Parquet extensions are used |

`IRFLOW_DUCKDB_MEMORY_MB` and `IRFLOW_DUCKDB_THREADS` override the memory limit and thread count.

### Temp storage folder

Each tab creates a temporary DuckDB database, and DuckDB writes overflow files for large sorts and aggregations to the same folder. By default these files live under the macOS system temp directory. For large cases, point temp storage at an external or scratch volume so imports do not fill your boot disk.

**macOS menu bar → Tools → Set Temp Storage Folder…**

- Applies to **new imports only** (existing tabs keep their current database path)
- **Tools → Use Default Temp Folder** clears a custom path
- The read-only **Temp Storage:** label shows the active setting

IRFlow estimates required free space before import (roughly a few times the source file size) and blocks the import with a clear error if the temp volume is too full.

See [Preferences — Temp storage folder](/reference/preferences#temp-storage-folder) for full details and the optional `TLE_TEMP_DIR` environment variable.

#### Approximate on-disk size per tab

DuckDB compresses each column, so a tab's database is usually smaller than the source CSV; how much smaller depends on how repetitive the columns are (see the examples under [Tips for Faster Import](#tips-for-faster-import)).

Temp databases are removed when you close the tab or quit the app.

### Search Result Caching

The 4 most recent search queries per tab are cached in memory. This provides instant results when toggling between searches or switching tabs.

## JS Sigma scan (imported tab / EvtxECmd CSV)

The in-app **JS Sigma** engine scans rows already loaded into the tab's database. On multi-million-row timelines it is CPU-heavy because each candidate row is checked against every rule in its logsource group.

### Faster JS scans

1. **Use the “Fast high-confidence only” preset** — fewer rules (`core` set, critical/high, stable/test) cuts evaluation time sharply versus “Full hunt” (~3,800+ rules).
2. **Prefer Hayabusa on raw EVTX** when you have `.evtx` folders — the bundled Hayabusa binary is optimized for EVTX and usually beats re-scanning a giant EvtxECmd CSV inside the app.
3. **Narrow the timeline first** — apply a date range filter on the tab before scanning so fewer rows match broad channel queries.

::: warning
An 8 GB EvtxECmd CSV (~6M rows) with **all** severity levels and **all** rules can take a long time even after these optimizations. Treat full-rule JS scans as batch jobs; use presets or Hayabusa for interactive triage.
:::

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
| **Free disk** | 2x largest file on temp volume | 3x total evidence size (use **Set Temp Storage Folder…** if needed) |
