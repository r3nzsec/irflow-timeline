---
description: Configure date/time display format, timezone, font size, color scheme, and temp storage in IRFlow Timeline.
---

# Preferences

Display and storage preferences are split across the **in-app toolbar** (inside the window) and the **macOS application menu** (system menu bar when IRFlow Timeline is focused). Both paths change the same settings.

## In-app toolbar

The settings capsule to the right of **File / View / Actions / Tools / Help** provides the fastest day-to-day controls:

| Control | What it does |
|---------|----------------|
| **Datetime format** dropdown | How timestamp columns render in the grid (raw or formatted) |
| **Timezone** dropdown | Display timezone for timestamps (data in SQLite stays unchanged) |
| **Color scheme** dropdown | Switch between **Dark Mode**, **Light Mode**, **Spring**, **Sakura**, **Summer**, **Autumn**, **Winter** and **Christmas** |
| **A − / +** | Decrease or increase grid font size (9–18px) |
| **Histogram** icon | Show or hide the timeline histogram panel |

These mirror the options under the macOS **Tools** menu described below.

## macOS application menu (Tools)

The native **Tools** menu (top of the screen on macOS) includes additional items:

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

### Color Scheme

- **Toolbar:** the color-scheme dropdown next to the timezone selector
- **macOS menu:** **Tools → Color Scheme**, where the active scheme is checked

There is no `Cmd+T` theme shortcut.

| Scheme | Base | Look |
|--------|------|------|
| **Dark Mode** (default) | dark | Charcoal background with the Unit 42 orange accent (`#E85D2A`); optimized for long analysis sessions |
| **Light Mode** | light | Soft gray chrome, white rows, navy text, teal and blue controls, blue selections and amber bookmarks |
| **Spring** | light | Light Forest Green timeline with near-black text; fresh `#678215` green bars with pale-yellow (`#FAE3A0`) text; pale-yellow buttons, dropdowns and filter boxes with purple (`#6F5497`) text |
| **Sakura** | light | Reference blossom pinks, cream and pale blue, with bright rose controls and dark plum lettering |
| **Summer** | light | Aqua blue, pale-yellow headers and controls (`#F3E2B3`), sunny-yellow chart panels and inputs (`#EDC02C`), with citrus/green accents |
| **Autumn** | dark | Red-brown timeline and toolbar (`#6B3C2C`), momiji-red group strip, column headers, menus and status bar (`#C93036`), with yellow text and dark orange lines |
| **Winter** | light | Icy blue panels, snow-white rows and pale glacier-blue controls |
| **Christmas** | dark | SchemeColor Christmas HEX: Motherboard Green `#165B33` and Jewel `#146B3A` backgrounds, Beautiful Red `#BB2528` headers and controls, Vermillion `#EA4630` and Classic Orange `#F8B229` chart accents |

Shared theme colors apply across the grid, modals, histogram, analytics panels and scrollbars. Text and control contrast is checked by the color-scheme tests. Features that only distinguish dark from light (native form controls and the auto-color palettes) follow the scheme's *base*. User-defined row colors and artifact-specific charts can have their own palettes.

The choice is saved in `ui-prefs.json` in the app's data folder and restored on the next launch; the window is painted in the scheme's background before the interface loads.

### Seasonal colors and readability

The seasonal palettes extend to the timeline, histogram, menus, dialogs, bookmarks and selection highlights. Spring, Sakura, Summer and Winter use a **light** base; Autumn and Christmas use a **dark** base. Christmas is separate from the icy Winter scheme. It uses warm-white lettering on forest/jewel green and red surfaces, with gold accents. Severity labels retain distinct colors. User-defined conditional formatting and artifact-specific charts retain their own colors. Decorative colors do not change detection levels or evidence.

Light Mode uses neutral surfaces for long reading sessions, with separate colors for selections, bookmarks and controls. The color tests cover text contrast on Light Mode and seasonal panels, inputs and rows, selected/bookmarked rows, and the normal and hover colors of filled controls. The scheme is remembered across launches, including Light Mode and Christmas. Older Christmas and Christmas-2 selections open the remaining Christmas palette.

### Reference palettes

- **Spring:** [Uplifting Spring (SPA1006)](https://stitchpalettes.com/palette/uplifting-spring-spa1006/) publishes `#6F5497`, `#B2A5CD`, `#E2A6BE`, `#FAE3A0`, `#A6B784` and `#748C7C`. The theme replaces the reference's Blue Green `#748C7C` with the requested fresh green `#678215`, including translucent toolbar backgrounds. Light Forest Green and the new green dominate; near-black text keeps the darker green readable.
- **Sakura:** [Sakura Blossom palette](https://img.magnific.com/premium-vector/color-element-trendy-pallete-color-sakura-color-pallete-swatch-summer-shade-tone-with-hex-code_615232-1235.jpg): `#D4E0EE`, `#FFDBDB`, `#FFA7A6`, `#FFF4F3`, `#F25477` and `#EC275F`. Dark plum foregrounds keep the pale surfaces and rose controls readable.
- **Summer:** [Summer palette 6](https://avemateiu.com/wp-content/uploads/2019/06/summer-color-palette-6.png): `#F03613`, `#EDC02C`, `#27B46E`, `#A2EEEB` and `#F3E2B3`. Aqua remains the main timeline color. Pale yellow `#F3E2B3` frames the headers and controls; sunny yellow `#EDC02C` fills chart panels, inputs and dialogs. Citrus and green are supporting accents. Deep blue remains on chart bars and provides readable contrast.
- **Autumn:** [Japanese fall palette](https://branding-lab.net/wp-content/uploads/2026/11/japanese-fall-color-palette.jpg): `#C93036`, `#F08300`, `#E9B626`, `#83A33C`, `#A34C66` and `#6B3C2C`, with cream foregrounds.
- **Christmas:** [Christmas HEX Color Scheme](https://www.schemecolor.com/christmas-hex-color-codes.php) ([reference image](https://www.schemecolor.com/images/scheme/christmas-hex-color-codes.png)): Motherboard Green `#165B33`, Jewel `#146B3A`, Classic Orange `#F8B229`, Vermillion `#EA4630` and Beautiful Red `#BB2528`.

Christmas uses the two reference greens for most of the workspace, red headers and primary controls, and vermillion-to-gold histogram bars. Darker green chart panels separate the bars from their background. Warm-white main text provides approximately **7.72:1** contrast on the main green background and **5.84:1** on the red headers and primary controls. Muted text, highlighted rows and control hover states are also checked for readability. While a search is typed, the search conditions bar is Beautiful Red like the headers (4.4 to 5.8:1). The **Clear All** links in the group strip and the status bar are Vermillion `#EA4630`: 3.4:1 on the dark green strip, but only 1.7:1 on the green status bar.

In Spring, text on the Light Forest Green surfaces (the timeline, column headers, group strip, search conditions bar, menus and dialogs) is near-black (9.5:1). Text on the `#678215` green bars (the top row, the tab bar and the status bar) is pale yellow `#FAE3A0`: 3.4:1, and 2.7:1 on the lighter boxes in the top row, below WCAG AA. The filter boxes under the column headers, filled buttons and the toolbar and match mode dropdowns are pale yellow with purple `#6F5497` text (4.9:1); other buttons are `#678215` green.

In Autumn, `#6B3C2C` is the background of the timeline, the menu bar and the tab bar. The search conditions bar, the group strip, the column headers, the menus and the status bar are red `#C93036`. Text on all of them is yellow `#EAC910` (5.6:1 on the red-brown, 3.3:1 on the red, below WCAG AA), except the column names, which stay cream `#FFF8ED` (5.0:1), and the text in the timestamp format, time zone, color scheme and match mode dropdowns and the search box, which is Spring's light green `#A6B784` (4.2:1). Lines and outlines above the timeline are dark orange `#FF8C00`. Autumn main text on the timeline targets WCAG AA (4.5:1); the other palettes retain their 7:1 main-text target. The existing standard-palette checks still cover muted text, inputs, headers, controls and selections.

Accent lettering and opaque control fills are separate theme tokens. This lets the reference palettes retain their colors without drawing a label or checkmark in the same color as its button background.


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
