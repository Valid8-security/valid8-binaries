#!/bin/bash

# Valid8 Free Trial Installation Script
# Provides automatic limited free trial access

set -e

echo "🚀 Valid8 Free Trial Installation"
echo "=================================="
echo ""

# Check if Python 3.8+ is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3.8+ is required but not found."
    echo "Please install Python 3.8 or higher from https://python.org"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python $PYTHON_VERSION found, but Python $REQUIRED_VERSION+ is required."
    exit 1
fi

echo "✅ Python $PYTHON_VERSION found"

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not found."
    echo "Please install pip3"
    exit 1
fi

echo "✅ pip3 found"

# Install Valid8 with trial limitations
echo ""
echo "📦 Installing Valid8 with free trial limitations..."

# Install from GitHub
pip3 install git+https://github.com/Valid8-security/parry-scanner.git --quiet

if [ $? -eq 0 ]; then
    echo "✅ Valid8 installed successfully!"
    echo ""
    
    # Generate a trial license automatically
    echo "🎫 Generating free trial license..."
    python3 -c "
import sys
import os
sys.path.insert(0, os.path.expanduser('~/.local/lib/python*/site-packages'))

try:
    from valid8.license import LicenseManager
    # Install free trial license automatically
    if LicenseManager.install_beta_license('trial-user@valid8.com'):
        print('✅ Free trial license activated!')
        print('📊 Trial limits: 100 files, 7 days')
        print('')
        print('🚀 Ready to scan! Try:')
        print('  valid8 scan /path/to/your/code')
        print('')
        print('📚 Need help? Run: valid8 --help')
    else:
        print('❌ Failed to activate trial license')
        print('Please contact support@valid8.dev')
except ImportError as e:
    print(f'❌ Installation verification failed: {e}')
    print('Please try reinstalling or contact support@valid8.dev')
"

else
    echo "❌ Installation failed. Please try again or contact support@valid8.dev"
    exit 1
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "Your free trial includes:"
echo "  • 100 files scanning limit"  
echo "  • 7-day trial period"
echo "  • AI-powered analysis"
echo "  • Basic fix suggestions"
echo ""
echo "Upgrade anytime at: https://valid8.dev/pricing"
echo ""
echo "Happy scanning! 🔒✨"

