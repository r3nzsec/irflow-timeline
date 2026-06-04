# IRFlow Timeline
<img width="1297" height="771" alt="IRFlow-Timeline-Github" src="https://github.com/user-attachments/assets/4e966f3f-6b82-4efa-990c-d201ebd0c23f" />

https://github.com/user-attachments/assets/d0a94f52-8b2a-4735-bd01-c55e2459f7b4

A high-performance native DFIR timeline analysis tool, originally written for macOS and now ported to Linux (Windows builds planned). Built on Electron + SQLite to handle millions of rows from CSV, TSV, XLSX, EVTX, Plaso, raw `$MFT`, and `$J` (`$UsnJrnl`) files without breaking a sweat.

Inspired by Eric Zimmerman's Timeline Explorer for Windows.

### Key Features

- **Raw NTFS Artifact Import** — Direct ingestion of `$MFT` and `$UsnJrnl` (`$J`) with full path reconstruction, SI/FN timestamps, and change reason mapping
- **Ransomware Analytics** — Automated impact analysis from `$MFT` data: bulk rename detection, entropy-based extension analysis, ransom note identification, and temporal clustering
- **VirusTotal Enrichment** — IOC matching with bulk VT lookups, malware family extraction, verdict badges, relationship pivoting, and local caching
- **Process Inspector** — Parent-child process tree analysis with 340+ MITRE ATT&CK detection rules
- **Lateral Movement Tracker** — Network logon and RDP session visualization as interactive force-directed graphs
- **RDP Bitmap Cache Recovery** — Recover `bcache*.bmc` and `cache????.bin` artifacts with bundled bmc-tools, preview images, and export evidence packages
- **Persistence Analyzer** — 30+ persistence techniques with account chain detection, cross-technique correlation, and PowerShell 4104 script block reassembly
- **IOC Matching** — 17+ indicator categories with auto-defanging, inline highlighting, CSV/HTML export with VT enrichment data

For the full feature list and documentation, visit the **[IRFlow Timeline Docs](https://r3nzsec.github.io/irflow-timeline/)**.

## Building from Source

**Prerequisites (for developers only):**
- Node.js 18+
- `python3` (for `node-gyp` compiling `better-sqlite3`)
- macOS 11+ (Big Sur or later) **or** a modern Linux distro (Ubuntu 20.04+, Debian 11+, Arch, Fedora, etc.)
- **macOS:** Xcode CLI tools: `xcode-select --install`
- **Linux:** standard `dpkg` / `fakeroot` (for the deb target; AppImage doesn't need them) and the usual X11/Wayland libs Electron already ships

```bash
git clone https://github.com/jo3rg/irflow-timeline-multios.git   # this fork
cd irflow-timeline-multios
npm install
npx electron-rebuild -f -w better-sqlite3

# Development (hot-reload)
npm run dev

# Build + launch (renderer bundle + run)
npm run start

# Platform-specific packaging:
npm run dist:universal   # macOS: universal (Intel + Apple Silicon) DMG
npm run dist:linux       # Linux: AppImage + deb for host arch
npm run dist:appimage    # Linux: AppImage only
npm run dist:deb         # Linux: deb only
```

The interactive `build.sh` wrapper picks the right choices for your host OS (mac menus vs. Linux AppImage/deb menus).

Output in `release/`.

## Credits & Acknowledgments

Inspired by [Eric Zimmerman's Timeline Explorer](https://ericzimmerman.github.io/).

### Open Source Projects

| Project | Usage | Link |
|---------|-------|------|
| **Electron** | Application framework | [electron/electron](https://github.com/electron/electron) |
| **better-sqlite3** | High-performance SQLite engine with WAL mode, FTS5 | [WiseLibs/better-sqlite3](https://github.com/WiseLibs/better-sqlite3) |
| **@ts-evtx/core** | Native Windows EVTX event log parsing | [NickSmet/ts-evtx](https://github.com/NickSmet/ts-evtx) |
| **Plaso (log2timeline)** | Forensic timeline generation (we import Plaso SQLite output) | [log2timeline/plaso](https://github.com/log2timeline/plaso) |
| **ExcelJS** | XLSX streaming reader | [exceljs/exceljs](https://github.com/exceljs/exceljs) |
| **SheetJS (xlsx)** | XLSX parsing | [SheetJS/sheetjs](https://github.com/SheetJS/sheetjs) |
| **csv-parser** | CSV/TSV streaming parser | [mafintosh/csv-parser](https://github.com/mafintosh/csv-parser) |
| **React** | UI rendering | [facebook/react](https://github.com/facebook/react) |
| **Vite** | Build tooling and hot-reload | [vitejs/vite](https://github.com/vitejs/vite) |
| **VitePress** | Documentation site | [vuejs/vitepress](https://github.com/vuejs/vitepress) |
| **electron-builder** | macOS DMG packaging | [electron-userland/electron-builder](https://github.com/electron-userland/electron-builder) |
| **bmc-tools** | RDP Bitmap Cache recovery | [ANSSI-FR/bmc-tools](https://github.com/ANSSI-FR/bmc-tools) |

### DFIR Community

- [Eric Zimmerman](https://ericzimmerman.github.io/) -- Timeline Explorer for Windows, the original inspiration for this project
- [log2timeline/Plaso](https://github.com/log2timeline/plaso) -- Super timeline generation framework by Kristinn Gudjonsson and contributors
- [SANS DFIR](https://www.sans.org/digital-forensics-incident-response/) -- DFIR training and community resources
- [The DFIR Report](https://thedfirreport.com/) -- Real-world intrusion analysis reports that informed threat detection patterns
- [CyberCX](https://cybercx.com.au/blog/ntfs-usnjrnl-rewind/) -- NTFS $UsnJrnl research that informed $J parsing implementation

### Beta Testers

Thanks to the following people for testing and providing feedback:

- [Maddy Keller](https://www.linkedin.com/in/madeleinekeller98/)
- [Omar Jbari](https://www.linkedin.com/in/jbariomar/)
- [Nicolas Bareil](https://www.linkedin.com/in/nbareil/)
- [Dominic Rathmann](https://www.linkedin.com/in/dominic-rathmann-77664323b/)
- [Chip Riley](https://www.linkedin.com/in/criley4640/)

## License

Apache-2.0
