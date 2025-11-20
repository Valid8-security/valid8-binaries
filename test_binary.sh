#!/bin/bash
# Valid8 Binary Test Script
# Run this on macOS, Linux, or Windows (via Git Bash)

echo "🧪 Valid8 Binary Test"
echo "===================="
echo ""

BINARY_NAME="valid8"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    BINARY_NAME="valid8.exe"
fi

if [ -f "$BINARY_NAME" ]; then
    echo "✅ Binary found: $BINARY_NAME"
    chmod +x "$BINARY_NAME" 2>/dev/null
    
    echo ""
    echo "Testing version command..."
    ./"$BINARY_NAME" --version
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ Binary works correctly!"
        echo ""
        echo "Testing help command..."
        ./"$BINARY_NAME" --help | head -20
    else
        echo "❌ Binary test failed"
        exit 1
    fi
else
    echo "❌ Binary not found: $BINARY_NAME"
    exit 1
fi
