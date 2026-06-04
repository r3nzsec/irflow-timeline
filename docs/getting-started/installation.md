---
description: Install IRFlow Timeline on macOS, Linux, or Windows — system requirements, download links, and setup for each platform.
---

# Installation

## System Requirements

| Requirement | Minimum |
|------------|---------|
| **OS** | macOS 12 (Monterey) or later, OR a modern Linux distro (Ubuntu 20.04+, Debian 11+, Arch, Fedora, etc.), OR Windows 10/11 |
| **Architecture** | x86_64 (Intel/AMD) or arm64 (Apple Silicon / Linux ARM / Windows ARM) |
| **RAM** | 8 GB (16 GB recommended for large files) |
| **Disk** | 500 MB for app + space for temporary SQLite databases |

## Download

Download the latest installer for your platform from the [GitHub Releases](https://github.com/jo3rg/irflow-timeline-multios/releases) page (or, for the original macOS-only build, the [r3nzsec/irflow-timeline releases](https://github.com/r3nzsec/irflow-timeline/releases) page).

## macOS

IRFlow Timeline is distributed as a **Universal Binary** that runs natively on both Intel and Apple Silicon Macs.

1. Open the downloaded `.dmg` file
2. Drag **IRFlow Timeline** to the **Applications** folder
3. Eject the DMG
4. Launch IRFlow Timeline from Applications or Spotlight

::: tip First Launch
Official [GitHub release](https://github.com/r3nzsec/irflow-timeline/releases) builds are signed and notarized. If macOS still quarantines the download, right-click **IRFlow Timeline** in Applications and choose **Open** once, or use **System Settings → Privacy & Security → Open Anyway**.
:::

## Linux

Two distribution formats are provided. Choose whichever fits your workflow.

### AppImage (portable, no install)

1. Download the `.AppImage` file from the [GitHub Releases](https://github.com/jo3rg/irflow-timeline-multios/releases) page
2. Make it executable: `chmod +x IRFlow-Timeline-*.AppImage`
3. Run it: `./IRFlow-Timeline-*.AppImage`

The AppImage is fully self-contained — no install, no root, no system changes. User data is stored under `~/.config/irflow-timeline/`.

::: tip FUSE requirement
Running an AppImage directly requires `libfuse2` (FUSE 2). Most modern distros ship `fuse3` only; install the v2 compatibility package (`sudo pacman -S fuse2` on Arch / CachyOS, `sudo apt install libfuse2` on Debian/Ubuntu). As a fallback, you can always extract it and run the inner binary directly: `./IRFlow-Timeline-*.AppImage --appimage-extract && ./squashfs-root/AppRun`.
:::

### Debian / Ubuntu package

```bash
sudo dpkg -i IRFlow-Timeline-*.deb
sudo apt install -f   # resolve any missing dependencies
irflow-timeline
```

Tested on Ubuntu 20.04+, Debian 11+, Linux Mint, Pop!_OS, and derivatives.

## Windows (planned)

A Windows installer is planned for a future release. For now, IRFlow Timeline runs on macOS and Linux.

## Build from Source

If you prefer to build from source:

```bash
# Clone the repository
git clone https://github.com/r3nzsec/irflow-timeline.git
cd irflow-timeline

# Install dependencies (Node.js 18+ required, plus python3 for node-gyp)
npm install

# Rebuild native modules for Electron
npm run rebuild

# Run in development mode
npm run dev

# Platform-specific packaging:
npm run dist:universal   # macOS: universal (Intel + Apple Silicon) DMG
npm run dist:linux       # Linux: AppImage + deb for host arch
npm run dist:appimage    # Linux: AppImage only
npm run dist:deb         # Linux: deb only
```

Release build commands automatically bundle external analyzer tools used by IRFlow Timeline, including Hayabusa and ANSSI-FR `bmc-tools`.

### Build Script

The project includes an interactive `build.sh` script. It detects your host OS (macOS / Linux / MinGW) and shows the appropriate install hints and packaging options:

```bash
chmod +x build.sh
./build.sh
```

| Host | Options shown |
|------|---------------|
| **macOS** | Dev mode, quick start, .app bundle, .dmg, universal DMG |
| **Linux** | Dev mode, quick start, AppImage, .deb, both |
| **Windows** | Dev mode, quick start, NSIS installer, portable .exe |

## File Associations

After installation, IRFlow Timeline registers as a viewer for the following file types. You can double-click these files to open them directly:

- `.csv` — CSV files
- `.tsv` — TSV files
- `.xlsx` — Excel files (OpenXML)
- `.xls` — Legacy Excel files (binary)
- `.xlsm` — Macro-enabled Excel files
- `.plaso` — Plaso timeline databases
- `.evtx` — Windows Event Log files
