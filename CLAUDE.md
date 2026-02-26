# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IRFlow Timeline is a high-performance macOS Electron app for DFIR (Digital Forensics & Incident Response) timeline analysis. It handles 30-50GB+ forensic timeline files (CSV, TSV, XLSX, EVTX, Plaso) using SQLite as the data engine so files never fully load into memory.

## Development Commands

```bash
# Install dependencies (runs patch-package via postinstall)
npm install

# Rebuild better-sqlite3 native module for Electron (required after install)
npx electron-rebuild -f -w better-sqlite3

# Development with hot-reload (Vite dev server + Electron)
npm run dev

# Build renderer and launch (production-like local run)
npm run start

# Build renderer only
npm run build:renderer

# Package as macOS DMG
npm run dist:dmg

# Package as universal binary (Intel + Apple Silicon)
npm run dist:universal

# Documentation site (VitePress)
npm run docs:dev
npm run docs:build
```

## Architecture

The app has a three-layer architecture: **React renderer** <-> **Electron main process (IPC)** <-> **SQLite engine + streaming parsers**.

### Main Process (Node.js / Electron)

- **`main.js`** — Electron main process. Creates the BrowserWindow, builds the native macOS menu, handles all IPC channels between renderer and backend. Orchestrates file import flow (dialog -> parser -> DB -> send results to renderer). Generates HTML reports.
- **`db.js`** — SQLite data engine (`TimelineDB` class). Each open tab gets its own temp SQLite database in `/tmp`. Handles: schema creation, batch row insertion, SQL-based filtering/sorting/pagination, FTS5 full-text search, column indexing, histogram/gap/burst analysis, process tree reconstruction, lateral movement tracking, IOC matching, bookmarks, tags, and export.
- **`parser.js`** — Streaming file parsers. Handles CSV (RFC 4180, auto-detects delimiter), XLSX (ExcelJS streaming), EVTX (@ts-evtx/core async generator), and Plaso (SQLite ATTACH + zlib decompress). Rows stream in 50K-row batches into SQLite, never loading full files into memory.
- **`preload.js`** — Context bridge exposing `window.tle` API to the renderer. All renderer<->main communication goes through IPC channels defined here.

### Renderer (React / Vite)

- **`src/App.jsx`** — Single-file React application (~10K+ lines). Contains all UI components, state management, virtual scrolling, modals, histogram, and analysis panels. No component splitting — everything is in this one file.
- **`src/main.jsx`** — React entry point with ErrorBoundary wrapper.
- **`vite.config.js`** — Vite config. Dev server on port 5173, builds to `dist/`.

### Key Design Patterns

- **Tab isolation**: Each imported file gets a unique `tabId` and its own SQLite temp database. Tabs can be merged into a unified chronological timeline.
- **Virtual scrolling**: The renderer only holds ~5,000 rows in memory at a time. SQL `LIMIT/OFFSET` queries fetch windows of data as the user scrolls.
- **IPC via `safeHandle`/`safeSend`**: All IPC handlers in `main.js` use `safeHandle()` which wraps handlers with error catching and debug logging. Renderer events use `safeSend()` which checks window existence.
- **Background indexing**: After import, column indexes and FTS5 search indexes build asynchronously without blocking the UI.
- **Theme system**: Dark (default) and Light themes defined as `THEMES` object in `App.jsx`. Accent color is `#E85D2A` (Unit 42 orange).

### Data Flow for File Import

1. User opens file (dialog or drag-drop) → `main.js:importFile()`
2. For XLSX with multiple sheets, renderer shows sheet picker
3. `parser.js:parseFile()` streams rows into `db.js:createTab()` in 50K-row batches
4. Progress updates sent to renderer via `import-progress` IPC
5. On completion, initial 5K-row window + metadata sent via `import-complete`
6. Background: column indexes built, then FTS5 index built

### Native Module Note

`better-sqlite3` is a native Node module that must be compiled for Electron's Node version. Always run `npx electron-rebuild -f -w better-sqlite3` after `npm install`. A patch exists for `@ts-evtx/core` via `patch-package` (applied automatically on `npm install`).

## Digital Forensics Capabilities

- Capable of reviewing process and network artifacts for forensic analysis
