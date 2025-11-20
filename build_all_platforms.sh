#!/bin/bash
# Build script for all platforms

set -e

echo "🔨 Building Valid8 for all platforms..."

# macOS (current platform)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📦 Building macOS binary..."
    python3 -m PyInstaller --clean --noconfirm valid8-macos.spec
    if [ -f "dist/valid8" ]; then
        chmod +x dist/valid8
        zip -j valid8-binaries/valid8-macos-arm64.zip dist/valid8
        echo "✅ macOS binary created"
    fi
fi

# Note: Windows and Linux need to be built on their respective platforms
# or using Docker/cross-compilation

echo ""
echo "📋 To build for other platforms:"
echo "   Windows: Run on Windows with PyInstaller"
echo "   Linux: Run on Linux with PyInstaller"
echo ""
echo "   Or use Docker for cross-platform builds"
