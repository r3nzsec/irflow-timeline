# Supported Formats

IRFlow Timeline supports the most common forensic timeline and log formats used in DFIR investigations.

## CSV / TSV / TXT / LOG

**Extensions:** `.csv`, `.tsv`, `.txt`, `.log`

The most versatile import format. IRFlow Timeline auto-detects the delimiter by analyzing the first lines of the file.

| Delimiter | Detection Priority |
|-----------|-------------------|
| Tab (`\t`) | Highest — checked first |
| Pipe (`\|`) | Second |
| Comma (`,`) | Default fallback |

### Features

- **Streaming import** — 16MB chunks, never loads the full file into memory
- **RFC 4180 compliant** — proper quote handling for embedded delimiters
- **Fast-path parsing** — tab and pipe delimited files skip quote analysis for speed
- **Header deduplication** — duplicate column names are auto-renamed with numeric suffixes
- **Batch insertion** — 50,000 rows per SQLite batch for optimal write throughput

### Common DFIR CSV Sources

- KAPE / EZ Tools output (MFTECmd, PECmd, LECmd, etc.)
- Hayabusa and Chainsaw detection results
- BrowsingHistoryView exports
- Plaso `psort` CSV output
- Custom log parsers and scripts

## Excel (XLSX / XLS / XLSM)

**Extensions:** `.xlsx`, `.xls`, `.xlsm`

Excel files are read using a streaming reader that avoids loading the entire workbook into memory.

### Features

- **Sheet selection** — for multi-sheet workbooks, a dialog lets you choose which sheet to import
- **Streaming reader** — uses ExcelJS WorkbookReader for memory efficiency
- **Cell type handling:**
  - Dates are converted to ISO format
  - Formulas resolve to their computed values
  - Objects are converted to text representation
- **Empty cell padding** — sparse rows are padded to match the header column count

### Common DFIR Excel Sources

- KAPE / EZ Tools XLSX output
- Analyst spreadsheets and triage worksheets
- Threat intelligence feeds

## EVTX (Windows Event Logs)

**Extensions:** `.evtx`

Native binary parsing of Windows Event Log files using the `@ts-evtx` library. No need to pre-convert with external tools.

### Features

- **Binary parsing** — reads EVTX format directly, no conversion step
- **Dynamic schema discovery** — samples the first 10,000 events to discover all available fields
- **Fixed fields** extracted from every event:

| Field | Description |
|-------|-------------|
| `RecordNumber` | Sequential event record number |
| `TimeCreated` | Event timestamp |
| `EventId` | Windows event identifier |
| `Provider` | Event source provider name |
| `Channel` | Log channel (Security, System, etc.) |
| `Computer` | Source computer name |
| `UserId` | Security identifier (SID) |

- **Discovered fields** — provider-specific payload fields are extracted automatically based on the events found during schema discovery
- **Batch insertion** — 50,000 events per batch

### Supported Event Types

EVTX parsing works with all Windows event logs including:

- **Security** — Logon events (4624, 4625, 4648), privilege use, audit changes
- **Sysmon** — Process creation (Event ID 1), network connections, file operations
- **System** — Service changes, driver loads, shutdown/startup
- **Application** — Application errors, warnings
- **PowerShell** — Script block logging, module logging

## Plaso (Forensic Timeline Database)

**Extensions:** `.plaso`

Plaso is the forensic timeline format created by the `log2timeline` / `plaso` framework. IRFlow Timeline reads Plaso SQLite databases natively.

### Features

- **Native SQLite reading** — uses `better-sqlite3` to query the Plaso database directly
- **Schema validation** — verifies the `metadata` table and `format_version` field
- **Row count estimation** — reads total count from metadata for progress reporting
- **Full data extraction** — imports all rows with all available columns

### Plaso Workflow

1. Run `log2timeline` to create a `.plaso` file from your evidence
2. Open the `.plaso` file directly in IRFlow Timeline — no need to run `psort` first
3. All timeline entries are imported with their original columns

::: tip Performance
For very large Plaso databases (10GB+), consider using `psort` to export a filtered CSV first, as the Plaso reader loads all rows in a single query.
:::

## Format Detection

IRFlow Timeline determines the file format by extension:

```
.csv, .tsv, .txt, .log  →  CSV/TSV Parser (auto-detect delimiter)
.xlsx, .xls, .xlsm      →  Excel Streaming Parser
.evtx                    →  EVTX Binary Parser
.plaso                   →  Plaso SQLite Reader
```

All formats feed into the same SQLite-backed data engine, so once imported, all features (search, filter, histogram, process tree, etc.) work identically regardless of the source format.
