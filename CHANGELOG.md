# Changelog

All notable changes to IRFlow Timeline. The macOS release workflow
(`.github/workflows/release-macos.yml`) publishes the section matching the
released version as the GitHub release notes — keep version headers in the form
`## Unreleased

### Fixed

- Preserve the source timestamp's sub-millisecond digits in seven-digit display and UTC sort keys, including offset-bearing Hayabusa timestamps; raw evidence remains unchanged.
- Apply temporal pivots to Hayabusa timestamps with a space before their UTC offset. Close the dialog on success and report invalid timestamps or windows.
- Keep the pivot source event selected and centered after filtering, including when removing a severity filter places it outside the currently loaded rows. Keep the histogram and UTC date controls synchronized with the active filters and ignore stale histogram responses.

### Added

- **Apply and remove filters** in the temporal-pivot dialog, alongside **Apply**, which preserves existing filters.
- Timestamp-cell context menus with **Pivot with filters** and **Pivot and clear filters** for ±30s, ±1m, ±5m, and ±10m. Right-click the Tags column for direct tag choices and **Clear**.

## v<MAJOR.MINOR.PATCH>`.

## v1.0.10

IRFlow Timeline 1.0.10 adds **ChatGPT Computer History** as a new forensic artifact family, and hardens the app for long-running investigations.

### ChatGPT Computer History (new)

- **New artifact family** — collect and analyze the opt-in macOS ChatGPT "Computer History" feature: the raw interaction-event stream (kept for roughly 48 hours) and the activity summaries that persist until the user clears them.
- **A timeline of real user activity** — see what was typed, clicked, selected, and dragged between applications, along with the window and website in view at the time. Not just that an application ran.
- **Credential entry is flagged** — typing into a password field is identified as credential entry, with a clear note that macOS hides the value while the keystrokes themselves are still recorded.
- **File and menu selections captured** — Finder file selections and menu commands now appear on the timeline; previously these arrived as empty rows.
- **Cleared history is detected** — each recording segment is reconciled against its own metadata, so records removed by the app's "clear last 10 minutes / hour / day" control are surfaced as a deletion lead rather than passing unnoticed.
- **Deleted summaries recovered** — activity summaries the user cleared are recovered read-only, together with when they were removed.
- **Deleted AI conversations flagged** — conversations marked deleted are identified, and the model chosen and text typed into them are often still recoverable from the activity timeline.
- **Host attribution** — identify the ChatGPT account and signed-in user behind a capture. Every identifier is labelled with how strongly it identifies an account rather than just a device, and no authentication tokens are ever stored or exported.
- **Analyst caveats travel with the evidence** — capture depth varies by application, and in hardened messaging apps only outbound typing is recorded. The import notice states these limits so they reach the report.

### Stability and Crash Resilience

- Worker threads are retired properly once finished, so they no longer accumulate during long sessions.
- Autosaves are written safely and validated on restore, with the previous snapshot kept as a fallback.
- Closing the macOS window now hides the workspace instead of tearing it down; Dock activation restores it with tabs and background work intact.
- Unexpected crashes trigger a clean shutdown of workers and databases followed by one controlled restart.
- A memory-aware worker budget now spans imports, indexing, analyzers, Sigma scans, and AI extraction.
- Cancelling a Hayabusa EVTX scan reliably stops the process and cleans up its temporary output.

### Additional Improvements

- Upgraded to Electron 43 with refreshed native dependencies.
- Minimum supported macOS is now 12 (Monterey).
- Building and testing now require Node.js 22.14 or newer.

**Full artifact paths, schema, and investigation guidance:** [AI Query History and AI App Artifacts](https://r3nzsec.github.io/irflow-timeline/dfir-tips/ai-query-history)

## v1.0.9

IRFlow Timeline 1.0.9 is a focused reliability patch for large Windows Event Log investigations.

### Large EVTX Imports

- **Issue #22 fixed** — Raw EVTX files are no longer opened through Node's whole-file `readFile()` path, removing the 2 GiB Buffer ceiling that rejected large `Security.evtx` files before the first record was parsed.
- **Bounded native chunk parsing** — Reads the 4 KiB EVTX header once, then processes one native 64 KiB EVTX chunk at a time instead of retaining the complete source file in memory.
- **Approximately 4 GiB EVTX support** — Handles logs up to the EVTX format's 65,535-chunk limit, including the reported 4,109,438,976-byte (~3.83 GiB) file.
- **Accurate large-file progress** — Progress now follows physical EVTX chunk offsets rather than record-local offsets.

### Import Reliability

- Duplicate requests for the same pending source are suppressed while preserving distinct workbook sheets and AI-history scopes.
- Repeated identical import failures collapse into one actionable notification instead of filling the screen with duplicate toasts.
- Regression coverage exercises the exact issue #22 file size and verifies that individual reads remain bounded to 64 KiB.

## v1.0.8

IRFlow Timeline 1.0.8 significantly expands **AI application forensics**, adding deeper artifact collection and parsing across popular AI assistants.

### AI Application Forensics

- **Grok Build support (new)** — collect and analyze Grok AI prompts, responses, reasoning, exact terminal commands, tool results, session context, and file-change records.
- **Claude expanded** — recursively parse Claude Code and Claude Desktop/Cowork sessions, transcripts, audit records, tool activity, and actual shell commands.
- **Codex expanded** — recover versioned SQLite data with WAL/SHM support, dated rollout sessions, commands, tool calls, and bounded outputs.
- Improved parsing for ChatGPT Desktop, GitHub Copilot CLI, Gemini CLI, Cursor, and other supported assistants.
- Better provenance, session relationships, and AI Secret Hunt safeguards.

### Additional Improvements

- New guided workflow for importing KAPE and triage collections.
- Enhanced Process Inspector, Persistence Analyzer, and Lateral Movement Tracker.
- Improved timeline navigation, bulk actions, and evidence review.
- Memory-safe queries and bounded workers for greater stability with large datasets.
- Signed and notarized universal macOS release for Apple Silicon and Intel.

## v1.0.7

Brings **AI assistant query history** into the timeline as a first-class forensic artifact: collect it from a host or triage package, normalize every tool into one tab, and **hunt for secrets that were leaked into AI chats** — passwords, API keys, tokens, and private keys.

### AI Query History (new)

- **Collect AI Artifacts** — choose **This Mac** or **Browse folder** (KAPE / triage / mounted disk); a forensic tree scan finds Windows, Linux, and macOS user-profile layouts, attributes each row to its `Users\<user>` / `home/<user>` profile and host, and merges every source into one **AI Query History** tab with verbose progress. Available from the **Tools** menu and the startup screen.
- **Native, offline extractors — no third-party AI binary:**
  - **Claude Code** — `history.jsonl` + project session JSONL under `.claude/` (Timestamp, Role, Summary, SessionId, Model, token counts, per-user/host attribution). Opening or dropping a `.claude` folder consolidates all JSONL into one tab (fixes JSONL mis-importing as broken CSV columns).
  - **ChatGPT Desktop** — LevelDB conversation metadata + SQLite message tables.
  - **Gemini CLI** — `~/.gemini/tmp/.../chats/session-*.json` (user + model messages, token counts, reasoning flag).
  - **Cursor**, **GitHub Copilot**, **OpenAI Codex**, **Continue**, **Windsurf**, and **Claude Desktop** — chat/session stores decoded into the same unified column schema.
- **Copilot JSONL depth** — replays `kind:0`/`1`/`2`, Code Insiders, and `emptyWindowChatSessions`; flags metadata-only sessions on import.
- **Cursor workspace decode** — project slugs map to filesystem paths where possible; transcript timestamps estimated from file birth/mtime.
- **AI Apps menu** — per-brand-tinted launchers for each supported assistant.

### AI Secret Hunt (new)

- **Automated secret & credential leak detection over collected AI history** — surfaces passwords, API keys, tokens, and private keys that were pasted into AI assistants. Lives under **Detection**, beside Sigma Scan.
- **Two-stage, precision-first detector** — a ReDoS-guarded regex catalog proposes candidates, then a validation layer (format/checksum validators, Shannon entropy, and an allow-list of well-known public test values) confirms them, so the default **Quick** scan favors precision. A **Deep** toggle adds PII (emails, phone numbers, and similar).
- **Redact-by-default** — findings are masked in the UI and **cleartext is never written to disk**; reveal per-row on demand, and each match carries a salted fingerprint for dedup/correlation.
- **Threat-report results view** — a liquid-glass UI on a Unit 42–style palette with progressive disclosure: group findings **by Tool or by Session**, provider badges per finding, and confidence / leak-direction / category chips.
- **Exposure brief** — export a polished **PDF or HTML** report of the findings.

### Under the hood

- New unit coverage across every AI-history extractor (Claude Code, ChatGPT, Gemini, Cursor, Copilot, Codex, Continue, Windsurf, Claude Desktop) and the secret detector, plus the path-attribution and profile-scan helpers.

## v1.0.6

A major release: IRFlow Timeline was rebuilt into ~150 focused modules and gained a full Sigma/Hayabusa detection layer plus RDP bitmap-cache recovery.

### Sigma Detection (new)

- **Dual detection engine** — run Sigma rules over **raw `.evtx` folders** via the bundled **Hayabusa** engine (universal binary, no setup, works offline), or over **imported timelines / EvtxECmd output** via an in-app JS Sigma engine.
- **MITRE ATT&CK-mapped triage dashboard** with severity/status filtering and a reopenable **scan history**.
- Scan **presets**, **custom YAML rules**, and **noisy-rule suppression**.

### RDP Bitmap Cache (new)

- Recover bitmap **tiles and collages** from Windows `bcache*.bmc` / `cache????.bin` artifacts (bundled **bmc-tools**).
- Records source/output hashes, keeps prior extraction history, and exports an **evidence package** for reporting.

### Lateral Movement — Accounts Accuracy

- Privilege/credential counts are now **scoped to lateral-movement activity** instead of host-wide totals, so suspicion scores aren't inflated by background noise.
- **Admin-logon correlation (4624 ↔ 4672)** recovers the ADMIN signal for network logons; machine/service accounts are no longer mislabeled.
- **Per-channel Sources/Targets breakdown** (logon / explicit-cred / RDP) explains why those columns can exceed the logon count.

### Under the Hood

- Full modular refactor of the renderer and main process (~150 focused modules).
- Import, indexing, and Sigma scans now run on **worker threads** for a smoother UI on large (30–50 GB) timelines.

### Build & Security

- **Universal** build (Apple Silicon + Intel), **signed and notarized**.
- Upgraded **xlsx (SheetJS) to 0.20.3**, addressing known vulnerabilities in 0.18.5.

### First-Run Notes

- **Sigma scans work fully offline out of the box.** Both the **EVTX Folder** (Hayabusa) and **Current Timeline Tab / EvtxECmd** (JS engine) scans use rules bundled inside the app — no install or network download is required (important on TLS-intercepting corporate/DFIR networks). When online, you can still refresh the JS Sigma rule set from SigmaHQ via the rule manager.
- **RDP Bitmap Cache** requires **Python 3** installed on your machine.

## v1.0.5

### Bug Fixes

- **Plaso import crash fixed** — all Plaso/log2timeline `.plaso` and `.timeline` files now import correctly (a malformed `LIMIT` clause in the column-discovery query caused a SQLite error on every Plaso file).
- **Intel Mac crash fixed** — `better-sqlite3` is now compiled as a universal fat binary (x86_64 + arm64), so the app no longer crashes on Intel MacBooks when opening a file.

### Context Menu Improvements

- **Filter in / Filter out** — right-click any cell to filter the grid to rows matching that value, or exclude them.
- **Tags submenu** — tags are collapsed into a submenu to keep the context menu compact.
- **Multi-row tagging** — select multiple rows, right-click, and apply a tag to all selected rows at once.
- **Opaque menu background** — grid content no longer bleeds through the context menu.

### Copy Behaviour Fix

- **⌘C respects text selection** — when text is selected in the detail panel, ⌘C copies the selection instead of intercepting it and copying the whole row.
