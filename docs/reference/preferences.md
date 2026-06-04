---
description: Configure date/time display format, timezone, font size, theme, and temp storage in IRFlow Timeline.
---

# Preferences

Display and storage preferences are split across the **in-app toolbar** (inside the window) and the **macOS application menu** (system menu bar when IRFlow Timeline is focused). Both paths change the same settings.

## In-app toolbar

The settings capsule to the right of **File / View / Actions / Tools / Help** provides the fastest day-to-day controls:

| Control | What it does |
|---------|----------------|
| **Datetime format** dropdown | How timestamp columns render in the grid (raw or formatted) |
| **Timezone** dropdown | Display timezone for timestamps (data in SQLite stays unchanged) |
| **☀ / 🌙** button | Toggle **Dark** and **Light** theme |
| **A − / +** | Decrease or increase grid font size (9–18px) |
| **Histogram** icon | Show or hide the timeline histogram panel |

These mirror the options under the native **Tools** menu described below.

## Native menu (Tools)

The native **Tools** menu includes additional items. On macOS it lives at the top of the screen (in the system menu bar); on Linux and Windows it lives inside the app window. The items below are the same on every platform — the menu is the primary way to reach the items that don't have an in-window control.

### Datetime Format

Control how timestamp columns are displayed in the grid. The underlying data is unchanged — formatting is applied at render time.

**Tools → Datetime Format**, or use the toolbar dropdown:

| Format | Example |
|--------|---------|
| **Default (raw)** | Displays the original value as-is |
| `yyyy-MM-dd HH:mm:ss` | `2025-03-15 14:30:45` |
| `yyyy-MM-dd HH:mm:ss.fff` | `2025-03-15 14:30:45.123` |
| `yyyy-MM-dd HH:mm:ss.fffffff` | `2025-03-15 14:30:45.1234567` |
| `MM/dd/yyyy HH:mm:ss` | `03/15/2025 14:30:45` |
| `dd/MM/yyyy HH:mm:ss` | `15/03/2025 14:30:45` |
| `yyyy-MM-dd` | `2025-03-15` |

::: tip Sub-Second Precision
Use `yyyy-MM-dd HH:mm:ss.fffffff` for Sysmon and EVTX data where sub-second precision is forensically relevant — especially when correlating process creation with network connections.
:::

### Timezone

Convert timestamp display to a specific timezone. **Tools → Timezone**, or use the toolbar dropdown.

| Timezone | IANA Identifier |
|----------|----------------|
| **UTC** | `UTC` |
| **US/Eastern** (EST/EDT) | `America/New_York` |
| **US/Central** (CST/CDT) | `America/Chicago` |
| **US/Mountain** (MST/MDT) | `America/Denver` |
| **US/Pacific** (PST/PDT) | `America/Los_Angeles` |
| **Europe/London** (GMT/BST) | `Europe/London` |
| **Europe/Berlin** (CET/CEST) | `Europe/Berlin` |
| **Asia/Tokyo** (JST) | `Asia/Tokyo` |
| **Asia/Shanghai** (CST) | `Asia/Shanghai` |
| **Australia/Sydney** (AEST/AEDT) | `Australia/Sydney` |
| **Local (system)** | Uses your macOS system timezone |

Timezone conversion is display-only. The raw timestamp values in the database remain unchanged, and exports use the original values.

::: tip DFIR Best Practice
Work in UTC during analysis to maintain consistency with log sources and other analysts. Switch to the local timezone of the compromised host only when correlating user activity or system events with physical-world timelines.
:::

### Font Size

**Tools → Font Size**, or the toolbar **− / +** buttons:

- **Increase** — `Cmd+Plus` (macOS Tools menu)
- **Decrease** — `Cmd+-` (macOS Tools menu)
- Fixed sizes: 9px, 10px, 11px, 12px, 13px, 14px, 16px, 18px

Smaller sizes (9–10px) are useful for wide timelines with many columns. Larger sizes (14–18px) help when presenting findings or working on high-resolution displays.

### Theme

- **Toolbar:** click the **☀ / 🌙** button next to the timezone selector
- **macOS menu:** **Tools → Theme → Dark** or **Light**

There is no `Cmd+T` theme shortcut.

- **Dark** (default) — optimized for extended analysis sessions with a dark background and the Unit 42 orange accent color (`#E85D2A`)
- **Light** — white background with the same orange accent, designed for screen sharing and report preparation

Both themes apply consistently across the grid, modals, histogram, analytics panels, and all other UI elements.

### Histogram

- **Toolbar:** histogram bar-chart icon
- **macOS menu:** **Tools → Toggle Histogram**

### VirusTotal API Key

**Tools → VirusTotal API Key…** opens IOC matching settings for your API key and rate limits. See [VirusTotal Integration](/features/virustotal).

## Temp storage folder

Large imports build a per-tab SQLite database plus column indexes and FTS5 on disk. By default that work uses the macOS system temp directory (often on your boot volume). For 10–50GB+ timelines, redirect temp storage to a folder on a volume with plenty of free space.

| Menu item | Description |
|-----------|-------------|
| **Temp Storage:** *(read-only label)* | Shows the current folder or “Default (system temp)” |
| **Set Temp Storage Folder…** | Pick a writable directory; applies to **the next import** onward |
| **Use Default Temp Folder** | Clears the custom path (enabled only when a custom folder is set) |

::: warning Applies on next import
Changing temp storage does not move databases for tabs already open. Close and re-import, or start new imports after changing the folder.
:::

IRFlow checks free space on the temp volume before import and refuses the job if there is not enough room for the database and indexes (roughly a few times the source file size). The error message suggests freeing space or choosing **Set Temp Storage Folder…**.

Power users can also set the `TLE_TEMP_DIR` environment variable before launch; the menu setting takes precedence when both are set.

See [Performance Tips — Temp storage](/reference/performance-tips#temp-storage-folder) for sizing guidance.

## See Also

- [Keyboard Shortcuts](/reference/keyboard-shortcuts) — accelerators that overlap with these settings
- [Performance Tips](/reference/performance-tips) — disk space, temp storage, and large-file guidance
- [Virtual Grid](/features/virtual-grid) — toolbar and menu bar overview
