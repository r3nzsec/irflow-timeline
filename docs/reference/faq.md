---
description: FAQ and troubleshooting for IRFlow Timeline — common questions about platform support (macOS, Linux, Windows), licensing, and usage.
---

# FAQ & Troubleshooting

## General Questions

### Which platforms does IRFlow Timeline support?

IRFlow Timeline runs on **macOS** (Intel and Apple Silicon, via a universal DMG), **Linux** (AppImage + `.deb`, x86_64 and arm64), and **Windows** (planned for a future release — see the [Roadmap](/about/roadmap)). The project started on macOS and was ported to Linux by the community.

### Is IRFlow Timeline free and open source?

Yes. IRFlow Timeline is released under the [Apache 2.0 license](https://github.com/r3nzsec/irflow-timeline/blob/main/LICENSE) and the full source code is available on [GitHub](https://github.com/r3nzsec/irflow-timeline).

### How large of a file can IRFlow Timeline handle?

IRFlow Timeline has been tested with files exceeding **30 GB** and **150 million+ rows**. Files are never fully loaded into memory — they stream into a temporary SQLite database in chunks. The practical limit is your available disk space (the SQLite database is roughly 1.5x the original file size). See [Performance Tips](/reference/performance-tips) for hardware recommendations.

### What makes this different from Timeline Explorer on Windows?

IRFlow Timeline is inspired by Eric Zimmerman's Timeline Explorer but adds capabilities beyond a data viewer:

- Runs natively on macOS (Intel and Apple Silicon) and Linux (x86_64 / arm64)
- Dual-engine Sigma detection (Hayabusa + in-app JS Sigma)
- Process Inspector with MITRE ATT&CK detection rules
- Lateral Movement Tracker with interactive network graphs
- Persistence Analyzer with 36 EVTX and 33 registry detection rules
- IOC Matching with 17+ indicator types
- Gap & Burst Analysis for anomaly detection
- Log Source Coverage heatmap
- Handles 30GB+ files via SQLite streaming (no row limits)

### Does it run Sigma rules?

Yes. **Tools → Detection → Sigma Scan** provides a dual-engine detection workflow. The bundled [Hayabusa](https://github.com/Yamato-Security/hayabusa) engine scans folders of raw `.evtx` files at full speed, and an in-app JavaScript Sigma engine scans data you have already imported (the current tab) or EvtxECmd CSV/XLS/XLSX output when raw EVTX is unavailable. It supports scan presets, custom rule collections, noisy-rule suppression, GeoIP enrichment, and a MITRE ATT&CK-mapped triage dashboard with persistent scan history. See [Sigma Detection](/features/sigma-detection) for the full workflow.

### Does it support KAPE output?

Yes. IRFlow Timeline auto-detects 26 KAPE / EZ Tools profiles including MFTECmd, EvtxECmd, PECmd, AmcacheParser, RECmd, SBECmd, AppCompatCache, JLECmd, LECmd, SrumECmd, Hayabusa, and Chainsaw. Columns are automatically pinned, ordered, and formatted for each profile. See [KAPE Integration](/workflows/kape-integration) and [KAPE Profiles](/reference/kape-profiles) for details.

---

## Installation Issues

### macOS blocks the app with "Apple cannot check it for malicious software"

Download builds from [GitHub Releases](https://github.com/r3nzsec/irflow-timeline/releases) — they are signed and notarized. If Gatekeeper still blocks a quarantined copy, use one of these once:

1. **Right-click** the app in Applications and select **Open** (not double-click)
2. Click **Open** in the dialog that appears
3. The app will launch and macOS will remember your choice

Alternatively: go to **System Settings → Privacy & Security**, scroll down, and click **Open Anyway** next to the IRFlow Timeline message.

::: tip
You only need to do this once. After the first launch, macOS will open the app normally.
:::

### `electron-rebuild` fails during build from source

The `better-sqlite3` native module must be compiled for Electron's specific Node.js version. Common fixes:

**Missing build tools:**
```bash
xcode-select --install
```

**Wrong Node.js version:**
```bash
# Ensure you're using Node.js 18+
node --version

# Clear node_modules and rebuild
rm -rf node_modules
npm install
npm run rebuild
```

**Apple Silicon with Rosetta conflicts:**
```bash
# Ensure you're running native arm64 Node.js, not x86_64 via Rosetta
arch
# Should output: arm64

# If it says i386, reinstall Node.js natively
```

### The app crashes on launch

1. Check that your macOS version is **12 (Monterey) or later**
2. Try deleting the app preferences: `rm -rf ~/Library/Application\ Support/irflow-timeline`
3. Check the debug log for errors: `cat ~/tle-debug.log | tail -50`
4. If building from source, ensure you ran `npm run rebuild` after `npm install`

---

## Import & Performance Issues

### Import seems stuck or frozen

Large file imports can take several minutes. The app is not frozen — check the progress indicator in the toolbar. Expected import times on Apple Silicon:

| File Size | Approximate Time |
|-----------|-----------------|
| 100 MB | 5-10 seconds |
| 1 GB | 30-60 seconds |
| 10 GB | 5-8 minutes |
| 30 GB+ | 15-25 minutes |

::: tip
The UI remains interactive during import. You can continue working in other tabs while a file loads.
:::

### Search returns no results even though the data exists

The full-text search (FTS) index builds in the background after import. If you search before it completes, the app falls back to LIKE-based search, which may miss some matches. Check the toolbar for the FTS build progress indicator. Once it shows complete, FTS search will return comprehensive results.

### The app uses a lot of disk space

Each open tab creates a temporary SQLite database approximately **1.5x the size** of the original file. These are stored in your system temp directory (`/tmp`) and are cleaned up when the tab is closed or the app exits.

| Original File | Temp DB Size |
|--------------|-------------|
| 1 GB | ~1.5 GB |
| 10 GB | ~15 GB |
| 30 GB | ~45 GB |

Ensure you have sufficient free disk space before importing large files. Close tabs you are no longer using to reclaim space.

### Importing multiple EVTX files causes high memory usage

EVTX files are imported sequentially through an internal queue system. If you drag-drop many EVTX files at once, they are queued and processed one at a time with garbage collection pauses between each file. Column indexes and FTS builds are deferred until the entire queue drains.

If you experience memory pressure, import EVTX files in smaller batches (5-10 at a time) rather than all at once.

---

## Feature Questions

### Can I search across all open tabs at once?

Yes. Enable **Search All Tabs** in the search bar to run your query across every loaded tab simultaneously. Results are returned per-tab so you can see which data source contains the matches.

### How do I export only my bookmarked or tagged rows?

1. Toggle the bookmark filter (`Cmd+B`) to show only bookmarked rows
2. Or use the tag filter dropdown to show rows with specific tags
3. Go to **File → Export** (`Cmd+E`) — only the currently filtered/visible rows will be exported

### Can I save my analysis and reopen it later?

Yes. Go to **File → Save Session** (`Cmd+S`) to save a `.tle` session file. This preserves all open tabs, filters, bookmarks, tags, color rules, and column configurations. Use **File → Load Session** to restore it. See [Sessions](/workflows/sessions) for details.

### Does IRFlow Timeline send any data externally?

No. All processing happens locally on your machine. No timeline data, file contents, or analysis results are transmitted anywhere. The documentation site uses [GoatCounter](https://www.goatcounter.com/) for anonymous page view analytics, but the desktop application itself has no telemetry or network calls.

---

## Still need help?

- Check the debug log at `~/tle-debug.log` for detailed error information
- [Open an issue](https://github.com/r3nzsec/irflow-timeline/issues) on GitHub with your macOS version, app version, and the relevant log output
- Review [Performance Tips](/reference/performance-tips) for optimization guidance
