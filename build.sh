#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   IRFlow Timeline — Cross-platform Build                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Detect host OS up front so install hints and menu choices match where this
# script is actually running. The original script was macOS-only — the cross-
# platform fork supports macOS (universal), Linux (AppImage + deb), and the dev
# runtime on any host.
HOST_OS="$(uname -s)"
case "$HOST_OS" in
    Darwin) HOST_LABEL="macOS" ;;
    Linux)  HOST_LABEL="Linux" ;;
    MINGW*|MSYS*|CYGWIN*) HOST_LABEL="Windows" ;;
    *) HOST_LABEL="$HOST_OS" ;;
esac
echo "🖥  Detected host: $HOST_LABEL"
echo ""

# Check prerequisites
check_cmd() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ $1 is required but not installed."
        echo "   Install with: $2"
        exit 1
    fi
}

# Pick the right install command + message per platform. The macOS hint is
# `brew install ...`; on Linux we just point at the distro's package manager
# without auto-installing (some envs forbid sudo) — the analyst can re-run.
case "$HOST_OS" in
    Darwin)
        check_cmd "node" "brew install node"
        check_cmd "npm"  "brew install node"
        PY_HINT="xcode-select --install  # provides python3 + CLT"
        ;;
    Linux)
        check_cmd "node" "your distro's package manager, e.g. 'sudo pacman -S nodejs npm' (Arch) / 'sudo apt install nodejs npm' (Debian/Ubuntu) / 'sudo dnf install nodejs npm' (Fedora)"
        check_cmd "npm"  "usually bundled with the nodejs package above"
        PY_HINT="your distro's package manager, e.g. 'sudo pacman -S python' / 'sudo apt install python3'"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        check_cmd "node" "winget install OpenJS.NodeJS.LTS  # or download from nodejs.org"
        check_cmd "npm"  "bundled with the Node.js install above"
        PY_HINT="the Microsoft Store / 'winget install Python.Python.3' (needed by node-gyp)"
        ;;
    *)
        check_cmd "node" "see https://nodejs.org/"
        check_cmd "npm"  "bundled with the Node.js install above"
        PY_HINT="install python3 from your platform's package manager"
        ;;
esac

NODE_VER=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VER" -lt 18 ]; then
    echo "❌ Node.js 18+ required (found $(node -v))"
    exit 1
fi

# Python3 needed for node-gyp (better-sqlite3 native build)
if ! command -v python3 &> /dev/null; then
    echo "⚠️  python3 not found — needed for native module compilation"
    echo "   Install with: $PY_HINT"
fi

# Linux-only: building a deb / AppImage requires the distro's packaging tools.
# The AppImage target itself doesn't strictly need dpkg / fakeroot (it just
# produces a self-extracting squashfs), but `npm run dist:deb` does.
if [ "$HOST_OS" = "Linux" ]; then
    if ! command -v dpkg &> /dev/null; then
        echo "⚠️  dpkg not found — 'npm run dist:deb' will fail. AppImage will still work."
        echo "   Install with: sudo apt install dpkg fakeroot  # Debian/Ubuntu"
    fi
fi

echo "✅ Node.js $(node -v) | npm $(npm -v)"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
npm install 2>&1 | grep -E "(added|npm warn|up to date)" | head -5
echo ""

# Rebuild native modules (better-sqlite3) for Electron
echo "🔧 Rebuilding native modules for Electron..."
npx electron-rebuild -f -w better-sqlite3 2>&1 | tail -3
echo ""

# Build choice — show the targets that actually make sense for this host.
echo "Choose build type:"
echo "  1) Development mode (hot reload + dev tools)"
echo "  2) Quick start (build renderer + run)"
case "$HOST_OS" in
    Darwin)
        echo "  3) .app bundle (macOS, distributable)"
        echo "  4) .dmg installer (macOS)"
        echo "  5) Universal binary DMG (Intel + Apple Silicon)"
        ;;
    Linux)
        echo "  3) AppImage (portable, no install)"
        echo "  4) .deb installer (Debian/Ubuntu/Mint/Pop!_OS)"
        echo "  5) Both AppImage and .deb"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo "  3) NSIS installer (Windows)"
        echo "  4) Portable .exe"
        ;;
esac
echo ""
read -p "Enter choice [1-5]: " choice

case "$choice" in
    1)
        echo ""
        echo "🚀 Starting dev mode..."
        echo "   Renderer: http://localhost:5173"
        echo "   App opens automatically when ready"
        npm run dev
        ;;
    2)
        echo ""
        echo "🔨 Building renderer..."
        npm run build:renderer
        echo "🚀 Starting app..."
        npx electron .
        ;;
    3)
        echo ""
        echo "🔨 Building renderer + packaging..."
        npm run build:renderer
        case "$HOST_OS" in
            Darwin)
                npx electron-builder --mac dir
                APP_PATH=$(ls -d release/mac*/"IRFlow Timeline.app" 2>/dev/null | head -1)
                if [ -n "$APP_PATH" ]; then
                    echo "🔏 Ad-hoc signing app bundle..."
                    codesign --force --deep --sign - "$APP_PATH" 2>/dev/null && echo "   Signed successfully" || echo "   Signing skipped (no Xcode CLI tools?)"
                fi
                echo ""
                echo "✅ App bundle is in: release/mac*/"
                open release/mac* 2>/dev/null || echo "   Check the release/ folder"
                ;;
            Linux)
                npx electron-builder --linux AppImage
                echo ""
                echo "✅ AppImage is in: release/"
                ls -la release/*.AppImage 2>/dev/null || ls -la release/ | head
                ;;
            MINGW*|MSYS*|CYGWIN*)
                npx electron-builder --win nsis
                echo ""
                echo "✅ NSIS installer is in: release/"
                ;;
        esac
        ;;
    4)
        echo ""
        echo "🔨 Building renderer + packaging installer..."
        case "$HOST_OS" in
            Darwin)
                npm run dist:dmg
                echo ""
                echo "✅ DMG is in: release/"
                open release/ 2>/dev/null
                ;;
            Linux)
                npm run dist:deb
                echo ""
                echo "✅ .deb is in: release/"
                ls -la release/*.deb 2>/dev/null
                echo ""
                echo "Install with: sudo dpkg -i release/IRFlow-Timeline-*.deb"
                echo "  (use 'sudo apt install -f' afterward if any deps are missing)"
                ;;
            MINGW*|MSYS*|CYGWIN*)
                npm run dist
                echo ""
                echo "✅ Installer is in: release/"
                ;;
        esac
        ;;
    5)
        echo ""
        echo "🔨 Building renderer + packaging universal target..."
        case "$HOST_OS" in
            Darwin)
                npm run dist:universal
                echo ""
                echo "✅ Universal DMG is in: release/"
                open release/ 2>/dev/null
                ;;
            Linux)
                echo "Building both AppImage + deb..."
                npx electron-builder --linux AppImage deb
                echo ""
                echo "✅ Artifacts are in: release/"
                ls -la release/ | head
                ;;
        esac
        ;;
    *)
        echo "Running quick start..."
        npm run build:renderer && npx electron .
        ;;
esac
