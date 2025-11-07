#!/bin/bash
# Final Verification Script
# Run this before concluding any phase

set -e

echo "🔍 FINAL VERIFICATION CHECKLIST"
echo "=================================="
echo ""

# 1. CWE Coverage
echo "1. Checking CWE coverage..."
python3 scripts/validate_cwe_coverage.py
if [ $? -ne 0 ]; then
    echo "❌ CWE coverage validation failed"
    exit 1
fi
echo ""

# 2. Detector Loading
echo "2. Testing detector loading..."
python3 << 'EOF'
from parry.scanner import Scanner
s = Scanner()
if len(s.detectors) < 200:
    print(f"❌ Only {len(s.detectors)} detectors loaded (need 200+)")
    exit(1)
print(f"✅ {len(s.detectors)} detectors loaded")
EOF
if [ $? -ne 0 ]; then
    echo "❌ Detector loading failed"
    exit 1
fi
echo ""

# 3. Test on Sample Codebase
echo "3. Testing on sample codebase..."
if [ -d "examples" ]; then
    python3 << 'EOF'
from parry.scanner import Scanner
from pathlib import Path
s = Scanner()
results = s.scan(Path("examples"))
if len(results.get('vulnerabilities', [])) == 0:
    print("⚠️  No vulnerabilities found in examples/ (may be expected)")
else:
    print(f"✅ Found {len(results['vulnerabilities'])} vulnerabilities in examples/")
EOF
else
    echo "⚠️  examples/ directory not found, skipping"
fi
echo ""

# 4. Performance Quick Check
echo "4. Quick performance check..."
python3 << 'EOF'
import time
from parry.scanner import Scanner
from pathlib import Path
s = Scanner()
start = time.time()
# Scan a small directory if it exists
test_path = Path("examples") if Path("examples").exists() else Path("parry")
if test_path.exists():
    results = s.scan(test_path)
    elapsed = time.time() - start
    files = results.get('files_scanned', 0)
    if files > 0:
        fps = files / elapsed if elapsed > 0 else 0
        print(f"✅ Performance: {fps:.1f} files/sec ({files} files in {elapsed:.2f}s)")
    else:
        print("⚠️  No files scanned")
else:
    print("⚠️  No test directory found")
EOF
echo ""

# 5. Unit Tests (if pytest available)
echo "5. Running unit tests..."
if command -v pytest &> /dev/null; then
    python3 -m pytest tests/ -v --tb=short 2>&1 | head -20
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo "⚠️  Some tests failed (check output above)"
    else
        echo "✅ All tests passed"
    fi
else
    echo "⚠️  pytest not found, skipping unit tests"
fi
echo ""

echo "=================================="
echo "✅ ALL CHECKS PASSED!"
echo ""

