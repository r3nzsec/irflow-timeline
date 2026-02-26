#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   IRFlow Timeline v2.1 — macOS Build (SQLite-backed)     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
check_cmd() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ $1 is required but not installed."
        echo "   Install with: $2"
        exit 1
    fi
}

check_cmd "node" "brew install node"
check_cmd "npm" "brew install node"

NODE_VER=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VER" -lt 18 ]; then
    echo "❌ Node.js 18+ required (found $(node -v))"
    exit 1
fi

# Python3 needed for node-gyp (better-sqlite3 native build)
if ! command -v python3 &> /dev/null; then
    echo "⚠️  python3 not found — needed for native module compilation"
    echo "   Install with: xcode-select --install"
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

# Build choice
echo "Choose build type:"
echo "  1) Development mode (hot reload + dev tools)"
echo "  2) Quick start (build + run)"
echo "  3) .app bundle (distributable)"
echo "  4) .dmg installer (share with team)"
echo "  5) Universal binary DMG (Intel + Apple Silicon)"
echo ""
read -p "Enter choice [1-5]: " choice

case $choice in
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
        echo "📦 Building .app bundle..."
        npm run build:renderer
        npx electron-builder --mac dir
        # Ad-hoc sign to reduce Gatekeeper friction
        APP_PATH=$(ls -d release/mac*/"IRFlow Timeline.app" 2>/dev/null | head -1)
        if [ -n "$APP_PATH" ]; then
            echo "🔏 Ad-hoc signing app bundle..."
            codesign --force --deep --sign - "$APP_PATH" 2>/dev/null && echo "   Signed successfully" || echo "   Signing skipped (no Xcode CLI tools?)"
        fi
        echo ""
        echo "✅ App bundle is in: release/mac*/"
        open release/mac* 2>/dev/null || echo "   Check the release/ folder"
        ;;
    4)
        echo ""
        echo "📦 Building .dmg installer..."
        npm run dist:dmg
        echo ""
        echo "✅ DMG is in: release/"
        open release/ 2>/dev/null
        ;;
    5)
        echo ""
        echo "📦 Building universal binary (Intel + Apple Silicon)..."
        npm run dist:universal
        echo ""
        echo "✅ Universal DMG is in: release/"
        open release/ 2>/dev/null
        ;;
    *)
        echo "Running quick start..."
        npm run build:renderer && npx electron .
        ;;
esac
