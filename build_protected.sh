#!/bin/bash
# Build Protected Parry Distribution
#
# This script creates a distribution where core modules are compiled to C extensions,
# preventing source code access while maintaining full functionality.

set -e  # Exit on error

echo "🔒 Building Protected Parry Distribution"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if virtual environment is active
if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${YELLOW}⚠ Warning: No virtual environment detected${NC}"
    echo "It's recommended to build in a virtual environment"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install build requirements
echo -e "${GREEN}📦 Installing build requirements...${NC}"
pip install -q -r requirements-build.txt
echo -e "${GREEN}✓${NC} Build requirements installed"
echo ""

# Clean previous builds
echo -e "${GREEN}🧹 Cleaning previous builds...${NC}"
rm -rf build/ dist/ *.egg-info
find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find . -type f -name '*.pyc' -delete 2>/dev/null || true
find . -type f -name '*.so' -delete 2>/dev/null || true
find . -type f -name '*.c' -delete 2>/dev/null || true
echo -e "${GREEN}✓${NC} Cleaned"
echo ""

# Ask for build type
echo "Select build type:"
echo "  1) Development (source code visible, for testing)"
echo "  2) Distribution (compiled, for PyPI/public release)"
echo "  3) Enterprise (compiled + obfuscated, for commercial)"
echo ""
read -p "Enter choice [1-3]: " BUILD_CHOICE

case $BUILD_CHOICE in
    1)
        BUILD_TYPE="development"
        echo -e "${GREEN}Building Development version${NC}"
        ;;
    2)
        BUILD_TYPE="distribution"
        echo -e "${GREEN}Building Distribution version (compiled)${NC}"
        ;;
    3)
        BUILD_TYPE="enterprise"
        echo -e "${GREEN}Building Enterprise version (compiled + obfuscated)${NC}"
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""

# Build based on type
if [ "$BUILD_TYPE" = "development" ]; then
    echo -e "${GREEN}🔨 Building development version...${NC}"
    python setup.py build
    python setup.py sdist bdist_wheel
    
elif [ "$BUILD_TYPE" = "distribution" ]; then
    echo -e "${GREEN}🔨 Compiling modules with Cython...${NC}"
    python setup_compiled.py --distribution build_ext --inplace
    echo -e "${GREEN}✓${NC} Modules compiled"
    echo ""
    
    echo -e "${GREEN}📦 Creating wheel distribution...${NC}"
    python setup_compiled.py --distribution bdist_wheel
    echo -e "${GREEN}✓${NC} Wheel created"
    echo ""
    
    echo -e "${GREEN}📦 Creating source distribution...${NC}"
    python setup_compiled.py --distribution sdist
    echo -e "${GREEN}✓${NC} Source dist created"
    
elif [ "$BUILD_TYPE" = "enterprise" ]; then
    echo -e "${GREEN}🔨 Compiling modules with Cython...${NC}"
    python setup_compiled.py --enterprise build_ext --inplace
    echo -e "${GREEN}✓${NC} Modules compiled"
    echo ""
    
    echo -e "${GREEN}🔐 Obfuscating with PyArmor...${NC}"
    pyarmor gen --recursive --output dist_obfuscated parry/*.py || echo "PyArmor obfuscation optional"
    echo -e "${GREEN}✓${NC} Obfuscation complete (if PyArmor installed)"
    echo ""
    
    echo -e "${GREEN}📦 Creating wheel distribution...${NC}"
    python setup_compiled.py --enterprise bdist_wheel
    echo -e "${GREEN}✓${NC} Wheel created"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Show output
if [ -d "dist" ]; then
    echo "📦 Distribution files:"
    ls -lh dist/
    echo ""
fi

# Provide next steps
case $BUILD_TYPE in
    development)
        echo "Next steps:"
        echo "  • Install locally: pip install -e ."
        echo "  • Test: parry --version"
        ;;
    distribution)
        echo "Next steps:"
        echo "  • Test locally: pip install dist/*.whl"
        echo "  • Upload to PyPI: twine upload dist/*"
        echo "  • Test from PyPI: pip install parry-scanner"
        ;;
    enterprise)
        echo "Next steps:"
        echo "  • Test locally: pip install dist/*.whl"
        echo "  • Distribute to enterprise customers"
        echo "  • Note: Source code is protected"
        ;;
esac

echo ""
echo -e "${YELLOW}⚠ Security Note:${NC}"
echo "  While compilation makes reverse engineering much harder,"
echo "  no protection is 100% unbreakable. Use license keys for"
echo "  additional protection in commercial versions."
echo ""

