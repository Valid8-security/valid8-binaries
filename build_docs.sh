#!/bin/bash
# Build LaTeX architecture documentation

echo "Building Parry Architecture Documentation..."

# Check if pdflatex is available
if ! command -v pdflatex &> /dev/null; then
    echo "Error: pdflatex not found. Please install LaTeX (e.g., 'brew install mactex' on macOS)"
    exit 1
fi

# Build the PDF
pdflatex -interaction=nonstopmode architecture.tex
pdflatex -interaction=nonstopmode architecture.tex  # Run twice for references

# Clean up auxiliary files
rm -f *.aux *.log *.out *.toc *.lof *.lot *.fls *.fdb_latexmk *.synctex.gz

echo "✅ Architecture documentation built: architecture.pdf"
echo "📖 Document includes:"
echo "   - System architecture diagrams"
echo "   - Performance optimization details"
echo "   - AI integration pipeline"
echo "   - Competitive analysis"
echo "   - Implementation algorithms"
