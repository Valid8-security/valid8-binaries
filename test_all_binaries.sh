#!/bin/bash
# Comprehensive binary testing script

echo "🧪 Testing All Valid8 Binaries"
echo "================================"
echo ""

# Test macOS binary
echo "1️⃣ Testing macOS binary..."
if [ -f "dist/valid8" ]; then
    ./dist/valid8 --version && echo "   ✅ macOS binary works" || echo "   ❌ macOS binary failed"
else
    echo "   ⚠️ macOS binary not found"
fi

# Test Linux binary in Docker
echo ""
echo "2️⃣ Testing Linux binary (Docker)..."
if [ -f "valid8-linux" ] || [ -f "test_binaries/valid8" ]; then
    BINARY="valid8-linux"
    [ -f "test_binaries/valid8" ] && BINARY="test_binaries/valid8"
    
    docker run --rm -v "$(pwd):/workspace" ubuntu:22.04 bash -c \
        "chmod +x /workspace/$BINARY && /workspace/$BINARY --version 2>&1" && \
        echo "   ✅ Linux binary works" || echo "   ⚠️ Linux binary test issue"
else
    echo "   ⚠️ Linux binary not found"
fi

# Windows binary info
echo ""
echo "3️⃣ Windows binary status..."
if [ -f "test_binaries/valid8.exe" ]; then
    ls -lh test_binaries/valid8.exe
    echo "   ✅ Windows binary downloaded"
    echo "   💡 To test: Use Windows VM or Wine"
else
    echo "   ⚠️ Windows binary not available"
fi

echo ""
echo "✅ Testing complete"
