# Architecture

Technical overview of IRFlow Timeline's architecture for developers and contributors.

## System Architecture

```
┌─────────────────────────────────────────────────┐
│  React UI Layer (src/App.jsx)                   │
│  - Virtual scrolling grid                       │
│  - Search, filter, and annotation UI            │
│  - Analytics visualizations                     │
│  - State: 40+ useState hooks                    │
└──────────────────────┬──────────────────────────┘
                       │ IPC (contextBridge)
                       ▼
┌─────────────────────────────────────────────────┐
│  Electron Main Process (main.js)                │
│  - 30+ IPC handlers                             │
│  - File dialogs, native menus                   │
│  - Session management, export orchestration     │
└──────────────────────┬──────────────────────────┘
                       │ Synchronous/Async API
                       ▼
┌─────────────────────────────────────────────────┐
│  SQLite Data Engine (db.js)                     │
│  - TimelineDB class (40+ methods)               │
│  - FTS5 full-text search                        │
│  - Custom functions: REGEXP, FUZZY_MATCH        │
│  - Analytics: histogram, process tree, etc.     │
└──────────────────────┬──────────────────────────┘
                       │ Streaming I/O
                       ▼
┌─────────────────────────────────────────────────┐
│  Parser Layer (parser.js)                       │
│  - CSV/TSV: 16MB chunk streaming                │
│  - XLSX: ExcelJS streaming reader               │
│  - EVTX: @ts-evtx binary parser                │
│  - Plaso: SQLite direct query                   │
└─────────────────────────────────────────────────┘
```

## Layer Responsibilities

### Renderer Process (React)

**File:** `src/App.jsx` (~5,753 lines)

The renderer runs in a sandboxed browser context with no direct Node.js access. All system operations go through the IPC bridge.

Responsibilities:
- Grid rendering with virtual scrolling
- User interaction handling
- State management (React hooks)
- Visualization rendering (histogram, process tree, lateral movement graphs)
- Theme management (dark/light)

### Preload Bridge

**File:** `preload.js` (~194 lines)

The preload script creates a secure bridge between the renderer and main process using Electron's `contextBridge` API. It exposes a controlled set of IPC methods as `window.electronAPI`.

### Main Process (Electron)

**File:** `main.js` (~893 lines)

The main process runs with full Node.js access and manages:
- Window lifecycle and native menus
- IPC handler registration (30+ handlers)
- File dialog management
- Export orchestration (CSV, XLSX, HTML)
- Session save/load coordination
- macOS integration (vibrancy, dark mode, traffic lights)

### Data Engine (SQLite)

**File:** `db.js` (~2,706 lines)

The `TimelineDB` class wraps `better-sqlite3` with forensic-analysis-specific operations:

**Schema per tab:**
```sql
CREATE TABLE data (rowid INTEGER PRIMARY KEY, c0 TEXT, c1 TEXT, ...);
CREATE VIRTUAL TABLE data_fts USING fts5(c0, c1, ..., content=data);
CREATE TABLE bookmarks (rowid INTEGER PRIMARY KEY);
CREATE TABLE tags (rowid INTEGER, tag TEXT, PRIMARY KEY(rowid, tag));
CREATE TABLE color_rules (id, col_name, condition, value, bg_color, fg_color);
```

**Custom SQL functions:**
- `REGEXP(pattern, value)` — deterministic regex matching
- `FUZZY_MATCH(text, term)` — n-gram similarity for typo tolerance
- `EXTRACT_DATE(value)` — normalize any timestamp to `yyyy-MM-dd`
- `EXTRACT_DATETIME_MINUTE(value)` — normalize to `yyyy-MM-dd HH:mm`

**Performance tuning:**
- WAL journal mode for concurrent reads
- 512MB cache, 2GB MMAP
- Exclusive locking (single-user optimization)
- 32KB page size
- Lazy index creation

### Parser Layer

**File:** `parser.js` (~916 lines)

Streaming parsers convert source files into SQLite batch inserts:

- **CSV:** 16MB chunk reader, RFC 4180 compliant, auto-delimiter detection
- **XLSX:** ExcelJS `WorkbookReader` for memory-efficient streaming
- **EVTX:** `@ts-evtx` binary parsing with dynamic schema discovery
- **Plaso:** Direct SQLite query via `better-sqlite3`

## Data Flow

### Import Pipeline

```
File → Parser (streaming chunks) → Batch Arrays → SQLite INSERT
                                    (50K rows)     (prepared statements)
```

1. Parser reads file in chunks (16MB for CSV)
2. Rows are accumulated into 50,000-row batches
3. Batches are inserted using pre-built multi-row INSERT statements
4. Progress callbacks update the UI
5. After import: type detection, lazy index creation

### Query Pipeline

```
UI Action → IPC → db.queryRows() → SQL Query → Result Set → IPC → Grid Render
              ↓                        ↓
         Debounce (500ms)       LIMIT/OFFSET
                                 (pagination)
```

1. User scrolls, searches, or filters
2. Request is debounced (500ms for search/filter)
3. SQL query is built with active filters, sort, and pagination
4. Results (up to 5,000 rows) returned via IPC
5. Grid renders visible rows from the cached window

## Technology Stack

| Technology | Version | Purpose |
|-----------|---------|---------|
| **Electron** | ^33.2.1 | Native app container |
| **React** | ^18.3.1 | UI framework |
| **Vite** | ^6.0.7 | Build tooling |
| **better-sqlite3** | ^11.7.0 | SQLite bindings (zero-copy) |
| **ExcelJS** | ^4.4.0 | XLSX streaming |
| **@ts-evtx** | ^1.1.1 | EVTX binary parsing |
| **csv-parser** | ^3.0.0 | CSV parsing |
| **electron-builder** | ^25.1.8 | App packaging |

## Build Targets

| Target | Command | Output |
|--------|---------|--------|
| **Development** | `npm run dev` | Vite + Electron hot reload |
| **Quick start** | `npm run start` | Build + run |
| **DMG** | `npm run dist:dmg` | macOS installer |
| **Universal** | `npm run dist:universal` | Intel + Apple Silicon |

## Security Model

- **Context isolation** enabled — renderer has no Node.js access
- **Preload bridge** exposes only whitelisted IPC methods
- **No remote content** — purely local data processing
- **Hardened runtime** enabled for macOS distribution
- **No network requests** — all processing is offline
