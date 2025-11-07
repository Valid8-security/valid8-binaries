#!/bin/bash
# Clean up repository by removing non-critical files before GitHub push

echo "🧹 Cleaning up Parry repository for GitHub release..."

# Remove non-critical MD files (internal development notes, test results, etc.)
echo "Removing non-critical markdown files..."

# Remove root-level internal development files
rm -f *.md 2>/dev/null || true

# Remove benchmark and test result files
rm -rf benchmark_results/ 2>/dev/null || true

# Remove UI prototype (not core to scanner)
rm -rf parry-ui-prototype/ 2>/dev/null || true

# Remove virtual environments
rm -rf venv/ .venv/ 2>/dev/null || true

# Remove IDE and cache files
rm -rf .pytest_cache/ .vscode/ .idea/ *.pyc __pycache__/ 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Remove build artifacts
rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true

# Remove test and temporary files
rm -rf test_data/ complex_test_codebase/ 2>/dev/null || true

# Remove archive documentation (keep only current docs)
rm -rf docs/archive/ 2>/dev/null || true

# Keep only essential documentation
echo "Keeping essential documentation:"
echo "  - README.md"
echo "  - docs/ directory (organized docs)"
echo "  - CONTRIBUTING.md"
echo "  - QUICKSTART.md"
echo "  - SETUP_GUIDE.md"
echo "  - API_REFERENCE.md"

# Create .gitignore to prevent future clutter
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual environments
venv/
.venv/
ENV/
env/

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/
.cache

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Logs
*.log
logs/

# Temporary files
test_data/
benchmark_results/
complex_test_codebase/
*.tmp
*.bak

# LaTeX build files
*.aux
*.log
*.out
*.toc
*.lof
*.lot
*.fls
*.fdb_latexmk
*.synctex.gz
EOF

echo "✅ Repository cleaned and .gitignore created"
echo "📊 Repository status:"
echo "  - Removed virtual environments and build artifacts"
echo "  - Removed internal development notes and test results"
echo "  - Kept essential documentation and source code"
echo "  - Added comprehensive .gitignore"
