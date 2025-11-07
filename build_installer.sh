#!/bin/bash
# Build Parry One-Click Installer
# Creates standalone binaries for distribution

set -e

echo "🚀 Building Parry One-Click Installer"
echo "====================================="

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Navigate to installer directory
cd installer

# Install build dependencies
echo "📦 Installing build dependencies..."
python3 -m pip install --user pyinstaller

# Build the installer
echo "🔨 Building installer..."
python3 build_installer.py

echo ""
echo "✅ Installer build complete!"
echo ""
echo "📦 Generated files:"
ls -la ../installer/dist/

echo ""
echo "🚀 Ready for distribution!"
echo "   Upload files from installer/dist/ to GitHub releases"
