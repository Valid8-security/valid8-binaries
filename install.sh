#!/bin/bash
# Parry Security Scanner - Installation Script for macOS

set -e

echo "🔒 Parry Security Scanner - Installation"
echo "=========================================="
echo ""

# Check macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ This installer is designed for macOS"
    exit 1
fi

# Check architecture
ARCH=$(uname -m)
if [[ "$ARCH" != "arm64" ]]; then
    echo "⚠️  Warning: Parry is optimized for Apple Silicon (M1/M2/M3)"
    echo "   It may work on Intel Macs but performance will be slower"
    read -p "   Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check Python
echo "Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    echo "   Install with: brew install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✓ Python $PYTHON_VERSION found"

# Check Homebrew
echo "Checking Homebrew..."
if ! command -v brew &> /dev/null; then
    echo "⚠️  Homebrew not found"
    read -p "   Install Homebrew? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
        echo "❌ Homebrew is required for installation"
        exit 1
    fi
fi
echo "✓ Homebrew found"

# Install Ollama
echo ""
echo "Installing Ollama..."
if ! command -v ollama &> /dev/null; then
    brew install ollama
    echo "✓ Ollama installed"
else
    echo "✓ Ollama already installed"
fi

# Start Ollama service
echo "Starting Ollama service..."
if ! pgrep -x "ollama" > /dev/null; then
    brew services start ollama
    sleep 3
    echo "✓ Ollama service started"
else
    echo "✓ Ollama already running"
fi

# Pull CodeLlama model
echo ""
echo "Downloading CodeLlama 7B model..."
echo "(This may take several minutes - ~4GB download)"
ollama pull codellama:7b-instruct
echo "✓ Model downloaded"

# Install Parry
echo ""
echo "Installing Parry..."
if [ -f "pyproject.toml" ]; then
    # Development install
    pip3 install -e .
    echo "✓ Parry installed (development mode)"
else
    # User install
    pip3 install parry-security
    echo "✓ Parry installed"
fi

# Verify installation
echo ""
echo "Verifying installation..."
parry doctor

echo ""
echo "✅ Installation complete!"
echo ""
echo "Quick start:"
echo "  parry scan /path/to/your/code"
echo "  parry patch /path/to/file.py"
echo "  parry compare snyk /path/to/your/code"
echo ""
echo "For more information: parry --help"


