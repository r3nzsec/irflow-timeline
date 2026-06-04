# Cross-platform support: add Linux build, make the codebase portable

## Why

`irflow-timeline` is described everywhere in the README, the docs, and the UI
as "a native macOS application for DFIR timeline analysis". That's accurate
historically, but the codebase is already 95% cross-platform — the few
`process.platform === "darwin"` paths in `electron/main.js`, the macOS-only
roles in `electron/menu.js`, and the hard-coded `~/Library/...` error
message in the Sigma hayabusa binary manager are the only things keeping
it from running on Linux.

This PR:

1. **Makes the app run on Linux** (and prepares the ground for Windows).
2. **Adds an `npm run dist:linux` pipeline** that produces an AppImage and
   a `.deb` for x86_64 + arm64.
3. **Removes the "for macOS" marketing copy** from the UI and the docs.
4. **Updates docs that were wrong** now that Linux is supported (the FAQ
   "Why is IRFlow Timeline macOS only?" question, the Roadmap section
   promising a Linux build, etc.).

End-to-end verified on CachyOS / Arch Linux x86_64 with Node 26.1.0:
- Dev mode (`./node_modules/.bin/electron .`) launches and IPC works
- Renderer build (`npm run build:renderer`) is clean
- `npx electron-builder --linux AppImage` produces a working 176 MB AppImage
- `npx @electron/rebuild -f -w better-sqlite3` succeeds
- All 643 unit tests pass

(I'm submitting this from the fork `jo3rg/irflow-timeline-multios` because
the multi-OS work and the upstream rebrand are best reviewed together.)

## What changed

### 1. Code port (no behaviour change on macOS)

- **`electron/main.js`**: `titleBarStyle: "hiddenInset"`,
  `trafficLightPosition`, and `vibrancy: "under-window"` in
  `createWindow` are now gated behind `process.platform === "darwin"`.
  Non-mac builds get a clean window with the platform's standard chrome.
  The `window-all-closed` handler was already correctly gated.

- **`electron/menu.js`**: the App menu (with macOS-only roles `services`,
  `hide`, `hideOthers`, `unhide`) is now built per-platform. On macOS the
  first menu is the application menu (unchanged); on Linux/Windows,
  About and Quit surface inside the File menu instead. The macOS-only
  `role: "front"` in the Window menu is also gated.

- **`electron/analyzers/sigma/evtx-scanner/binary-manager.js`**: the
  TLS-inspection error message no longer tells the user to drop the
  manual Hayabusa binary at `~/Library/Application Support/...` (a macOS
  path). It now uses `app.getPath("userData")` and adds the `.exe`
  extension on Windows. The rest of the file (Hayabusa download,
  `hayabusaAssetPattern` for `linux` → `lin-x64-gnu`/`lin-aarch64-gnu`)
  was already cross-platform.

- **`electron/updater.js`**: the "Updates Not Configured" dialog text
  used to say "publish signed macOS builds with a zip target...".
  Reworded to be platform-neutral (mentions mac zip, win nupkg, linux
  AppImage).

### 2. Linux packaging (new)

- **`electron-builder.config.cjs`**: added a `linux:` block
  (`{ target: ["AppImage", "deb"], arch: ["x64", "arm64"] }`,
  `executableName: "irflow-timeline"`, etc.). The existing `mac:` block is
  unchanged. The `package.json` `author` field was promoted to
  `{ name, email }` so the deb target has a maintainer string (deb
  packaging rejects the plain-string form).

- **`build.sh`**: rewritten as a host-aware wrapper. The install hints,
  the prerequisite check, and the menu choices now match whatever OS the
  script is running on (Darwin/Linux/MinGW). The original was macOS-only.

- **`package.json`**: added `dist:linux`, `dist:appimage`, `dist:deb`
  scripts. Description field updated to "for macOS, Linux, and Windows".

- **`assets/256x256.png` and `assets/512x512.png`**: generated from
  `assets/icon.svg` via `rsvg-convert`. electron-builder's `linux.icon`
  is a single PNG whose filename must encode the size (`WxH.png`).

- **`README.md`**: added Linux build commands and prereqs; description
  no longer says "macOS" exclusively. The macOS section is unchanged.

### 3. UI + docs rebrand

- **User-visible strings**: `src/App.jsx` and `src/components/InlineModals.jsx`
  had the home-screen subtitle "DFIR Timeline Analysis for macOS". Removed
  the "for macOS" qualifier. Same fix in
  `docs/public/irflow-hero-graphic.jsx`.

- **`docs/.vitepress/config.mjs` + `docs/index.md`**: site description
  and og:description / twitter:description updated to mention macOS,
  Linux, and Windows. `operatingSystem: 'macOS'` → `'macOS, Linux, Windows'`.

- **`docs/getting-started/installation.md`**: full rewrite as a
  multi-OS page. macOS DMG, Linux AppImage + `.deb`, and a
  "Windows (planned)" stub. Adds the FUSE 2 note for AppImages on
  modern distros that ship fuse3 only.

- **`docs/reference/faq.md`**: replaced "Why is IRFlow Timeline macOS
  only?" with "Which platforms does IRFlow Timeline support?". The
  feature-comparison line now mentions Linux alongside macOS.

- **`docs/about/roadmap.md`**: "Windows and Linux builds" was the
  planned section. Updated to note that Linux shipped in v1.0.6 via
  this fork; Windows is still planned.

- **`docs/features/virtual-grid.md`** (Platforms section): the old text
  said "Windows is fully enabled today; Linux, macOS, and Cloud list
  upcoming analyzers as disabled menu placeholders until those
  platforms ship in a future release." Reworded to make it explicit
  that the app itself runs on Linux and macOS — only the *per-OS
  analyzers* are still in development. Generalised "macOS menu bar"
  references to "native menu" (top of screen on macOS, in-window on
  Linux/Windows).

- **`docs/reference/preferences.md`**: "macOS application menu (Tools)"
  → "Native menu (Tools)" with an explanation of where it lives per
  platform.

- **`docs/about/credits.md`**: electron-builder credit now mentions
  AppImage/deb alongside DMG.

- **`docs/dfir-tips/building-final-report.md`**: "macOS **File →
  Generate Report…**" → "**File → Generate Report…** in the native menu,
  `Cmd+Shift+R` / `Ctrl+Shift+R`".

- **`docs/index.md`**: tagline and "Incident Responders" bullet
  updated to reflect multi-OS host support.

The historical `CHANGELOG.md` and `docs/about/changelog.md` are
intentionally not rewritten — they describe what shipped at each
version, and that's still accurate.

### 4. Toolchain bumps required to install/build on Node 24+

The fork uses Node 26.1.0, which is what CachyOS / Arch and most
up-to-date Linux distros ship in 2026. The original `package.json`
targeted older toolchains and wouldn't build:

- **`better-sqlite3: ^11.7.0` → `^12.4.1`**: 11.7.0 uses V8 APIs
  that were removed in V8 13.x (`GetPrototype` was renamed
  `GetPrototypeV2`; `PropertyCallbackInfo` lost the `This` member;
  `v8::Context` no longer exposes `GetIsolate`). 12.x builds cleanly
  against the V8 headers shipped with Node 24+ and Electron 33+.

- **`yargs` pinned to `17.5.1` via `overrides` + `patches/yargs+17.5.1.patch`**:
  17.5.1 and 17.7.2 both declare `"type": "module"` in `package.json`
  while shipping a CJS entry file (`yargs/yargs`) with no `.cjs`
  extension. Under Node 26's strict ESM detection the entry is loaded
  as ESM and the top-level `require('./build/index.cjs')` throws. The
  patch removes `"type": "module"` from yargs' `package.json`; the
  rest of yargs' dual ESM/CJS export map already prefers CJS for
  `require()`, so the entry file loads correctly. This affects
  `@electron/rebuild`'s CLI startup.

Both changes are additive — they don't change the public API or
require any user-visible config tweaks. Anyone on an older Node (18-22)
can keep using the old `better-sqlite3@11.x`; the new version still
works there.

## Test plan

- [x] `npm install` succeeds on Node 26.1.0 (CachyOS)
- [x] `npx @electron/rebuild -f -w better-sqlite3` succeeds
- [x] `npm run build:renderer` (vite) is clean
- [x] `./node_modules/.bin/electron .` launches the dev app, IPC
      handlers respond, file dialog round-trips
- [x] `npx electron-builder --linux --dir` produces
      `release/linux-unpacked/irflow-timeline`
- [x] `npx electron-builder --linux AppImage` produces a 176 MB
      `release/IRFlow-Timeline-1.0.6-x86_64.AppImage`; running the
      inner AppRun starts the app
- [x] `npm test`: 643 pass / 0 fail / 34 skipped (no regressions)
- [x] `npm run docs:build` is clean
- [x] Hayabusa bundler (`bash scripts/bundle-hayabusa.sh`) produces a
      Linux x86_64 binary
- [x] bmc-tools bundler (`bash scripts/bundle-bmc-tools.sh`) works

The deb target fails on CachyOS specifically because the system
ships glibc 2.36 (no `libcrypt.so.1`); that's a CachyOS environment
quirk, not a port issue. `sudo pacman -S libxcrypt-compat` fixes it
on Arch derivatives. Ubuntu / Debian ship `libcrypt.so.1` natively,
so the deb target works out of the box there.

The AppImage also needs `libfuse2` to mount directly on hosts that
ship `fuse3` only (Arch / CachyOS). The `--appimage-extract` fallback
is documented in the installation page.

## Out of scope (for follow-up PRs)

- **Windows port**: most of the code changes in this PR are
  already Windows-friendly (the `process.platform !== "darwin"` paths
  in `main.js` and the Linux/Windows menu branch in `menu.js` both
  apply on Windows). The remaining work is a Windows CI workflow,
  Windows-shaped fpm/NSIS tweaks, and a few shell-quoting fixes in
  `scripts/bundle-bmc-tools.sh`.
- **A Windows release workflow** (`.github/workflows/release-windows.yml`)
  parallel to the existing `release-macos.yml`.
- **Per-OS analyzers**: the macOS and Linux groups in
  `src/components/MenuBar.jsx` still show the planned
  artifact analyzers as disabled stubs. Those features are independent
  of the platform-port work and should be tracked separately.
