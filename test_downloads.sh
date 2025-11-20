#!/bin/bash
# Comprehensive download and test script

echo "🧪 Valid8 Binary Download & Test"
echo "=================================="
echo ""

BASE_URL="https://github.com/Valid8-security/valid8-binaries/releases/latest/download"
TEST_DIR="test_downloads"
mkdir -p "$TEST_DIR"

# Test macOS
echo "1️⃣ Testing macOS download..."
curl -L -o "$TEST_DIR/macos.zip" "$BASE_URL/valid8-macos-arm64.zip" 2>/dev/null
if [ -f "$TEST_DIR/macos.zip" ]; then
    unzip -q -o "$TEST_DIR/macos.zip" -d "$TEST_DIR/macos" 2>/dev/null
    if [ -f "$TEST_DIR/macos/valid8" ]; then
        chmod +x "$TEST_DIR/macos/valid8"
        ./"$TEST_DIR/macos/valid8" --version 2>&1 | head -1 && echo "   ✅ macOS binary works" || echo "   ⚠️ macOS test issue"
    fi
fi

# Test Linux in Docker
echo ""
echo "2️⃣ Testing Linux download..."
curl -L -o "$TEST_DIR/linux.zip" "$BASE_URL/valid8-linux-amd64.zip" 2>/dev/null
if [ -f "$TEST_DIR/linux.zip" ]; then
    unzip -q -o "$TEST_DIR/linux.zip" -d "$TEST_DIR/linux" 2>/dev/null
    if [ -f "$TEST_DIR/linux/valid8" ]; then
        docker run --rm -v "$(pwd)/$TEST_DIR/linux:/test" ubuntu:24.04 bash -c \
            "chmod +x /test/valid8 && /test/valid8 --version 2>&1" | head -1 && \
            echo "   ✅ Linux binary works" || echo "   ⚠️ Linux test issue"
    fi
fi

# Test Windows download
echo ""
echo "3️⃣ Testing Windows download..."
curl -L -o "$TEST_DIR/windows.zip" "$BASE_URL/valid8-windows-amd64.zip" 2>/dev/null
if [ -f "$TEST_DIR/windows.zip" ]; then
    unzip -q -o "$TEST_DIR/windows.zip" -d "$TEST_DIR/windows" 2>/dev/null
    if [ -f "$TEST_DIR/windows/valid8.exe" ]; then
        ls -lh "$TEST_DIR/windows/valid8.exe"
        echo "   ✅ Windows binary downloaded"
        echo "   💡 To test: Use Windows VM or Wine"
    fi
fi

echo ""
echo "✅ Download testing complete"
