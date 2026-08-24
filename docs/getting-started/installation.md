---
description: Install IRFlow Timeline on macOS — system requirements, download links, and setup for Intel and Apple Silicon.
---

# Installation

## System Requirements

| Requirement | Minimum |
|------------|---------|
| **OS** | macOS 12 (Monterey) or later |
| **Architecture** | Intel (x86_64) or Apple Silicon (arm64) |
| **RAM** | 8 GB (16 GB recommended for large files) |
| **Disk** | 500 MB for app + space for temporary SQLite databases |

## Download

Download the latest `.dmg` installer from the [GitHub Releases](https://github.com/r3nzsec/irflow-timeline/releases) page.

IRFlow Timeline is distributed as a **Universal Binary** that runs natively on both Intel and Apple Silicon Macs.

## Install from DMG

1. Open the downloaded `.dmg` file
2. Drag **IRFlow Timeline** to the **Applications** folder
3. Eject the DMG
4. Launch IRFlow Timeline from Applications or Spotlight

::: tip First Launch
From **v1.0.12** the disk image itself is signed, notarized and stapled, alongside the application inside it — so the DMG opens and the app launches with no Gatekeeper prompt.

Earlier releases shipped an unsigned disk image. If you are installing v1.0.11 or older, macOS will warn on first open: right-click **IRFlow Timeline** in Applications and choose **Open** once, or use **System Settings → Privacy & Security → Open Anyway**.
:::

## Build from Source

If you prefer to build from source:

```bash
# Clone the repository
git clone https://github.com/r3nzsec/irflow-timeline.git
cd irflow-timeline

# Install dependencies
npm install

# Rebuild native modules for Electron
npm run rebuild

# Run in development mode
npm run dev

# Build DMG installer
npm run dist:dmg

# Build universal binary (Intel + Apple Silicon)
npm run dist:universal
```

Release build commands automatically bundle external analyzer tools used by IRFlow Timeline, including Hayabusa and ANSSI-FR `bmc-tools`.

### Build Script

The project includes an interactive `build.sh` script with multiple options:

| Option | Description |
|--------|-------------|
| **Dev Mode** | Vite hot-reload + Electron |
| **Quick Start** | Build renderer and launch |
| **.app Bundle** | Distributable app with ad-hoc signing |
| **DMG Installer** | Full installer package |
| **Universal Binary** | Intel + Apple Silicon combined |

```bash
chmod +x build.sh
./build.sh
```

## File Associations

After installation, IRFlow Timeline registers as a viewer for the following file types. You can double-click these files to open them directly:

- `.csv` — CSV files
- `.tsv` — TSV files
- `.xlsx` — Excel files (OpenXML)
- `.xls` — Legacy Excel files (binary)
- `.xlsm` — Macro-enabled Excel files
- `.plaso` — Plaso timeline databases
- `.evtx` — Windows Event Log files
