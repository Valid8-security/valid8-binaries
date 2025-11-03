# Parry Testing Instructions

## Quick Test (30 seconds)

Run the comprehensive test suite to verify Parry is working correctly:

```bash
# Make sure you're in the project directory
cd /Users/sathvikkurapati/Downloads/parry-local

# Activate virtual environment (if you have one)
source venv/bin/activate  # macOS/Linux
# OR
venv\Scripts\activate  # Windows

# Run the test suite
python scripts/test_parry_comprehensive.py
```

**Expected Result:** All 12 tests should pass ✅

---

## What Gets Tested

### Basic Functionality (5 tests)
- ✅ Imports - All modules load correctly
- ✅ Scanner Basic - Core scanning works
- ✅ Fast Mode - Fast mode scanning
- ✅ Vulnerability Types - Detects multiple CWE types
- ✅ Severity Levels - Assigns severity correctly

### System Integration (3 tests)
- ✅ License Manager - License system works
- ✅ Setup Helper - Setup utilities functional
- ✅ Reporter - Reporting system works

### AI Features (1 test)
- ✅ Patch Generator - AI fix generation (if Ollama available)

### Documentation & Tools (3 tests)
- ✅ Demo Script - Demo script exists and works
- ✅ Benchmark Results - Benchmark docs present
- ✅ Documentation - All docs exist

---

## Test Output Example

```
╭──────────────────────────────────────────────╮
│ Parry Comprehensive Test Suite               │
│ Testing all major features and functionality │
╰──────────────────────────────────────────────╯

Testing: Scanner Basic
✓ Passed in 0.01s

...

======================================================================
Test Summary
======================================================================

Total: 12 tests
Passed: 12
Failed: 0
Skipped: 0

╭───────────────────╮
│ ALL TESTS PASSED! │
╰───────────────────╯
```

---

## Test Results Interpretation

### ✅ All Tests Pass
**Status:** Parry is fully functional and ready to use!

**Next Steps:**
- Run the demo: `python scripts/demo_scan_with_fixes.py examples/vulnerable_code.py`
- Scan your code: `parry scan /path/to/your/code`
- Check docs: Read SETUP_GUIDE.md

### ⚠️ Some Tests Skipped
**Status:** OK - Non-critical tests skipped (usually AI features)

**Common Reasons:**
- Ollama not running (AI features skipped)
- Demo script not found (not critical)

**What to do:**
- This is normal if you don't have Ollama set up
- Core functionality still works
- Set up Ollama for AI features: `parry setup`

### ❌ Tests Failed
**Status:** Problem detected - Needs investigation

**Common Issues:**

#### "Import error"
```bash
# Install dependencies
pip install -e ".[dev]"
# OR
pip install rich click
```

#### "Scanner error"
```bash
# Check file exists
ls examples/vulnerable_code.py

# Reinstall Parry
pip install -e .
```

#### "Ollama not running"
```bash
# Start Ollama
ollama serve

# Download model
ollama pull codellama:7b
```

---

## Advanced Testing

### Test Specific Components

```bash
# Test just the scanner
python -c "from parry.scanner import Scanner; s = Scanner(); print('OK')"

# Test license system
python -c "from parry.license import LicenseManager; print(LicenseManager.get_tier())"

# Test setup helper
python -c "from parry.setup import SetupHelper; h = SetupHelper(); print(h.check_ollama_running())"
```

### Test on Your Own Code

```bash
# Create a test directory
mkdir test_scan
cd test_scan

# Create vulnerable test file
cat > test.py << 'EOF'
import os
import subprocess

# Vulnerable code
def bad_ping(host):
    return os.system(f"ping {host}")

# Safe code
def good_ping(host):
    return subprocess.run(["ping", host], check=True)
EOF

# Run comprehensive test
cd ..
python scripts/test_parry_comprehensive.py
```

### Generate Test Report

```bash
# Run tests and save output
python scripts/test_parry_comprehensive.py > test_results.txt 2>&1

# View results
cat test_results.txt
```

---

## Continuous Integration

### GitHub Actions Example

```yaml
name: Test Parry

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
      
      - name: Run comprehensive tests
        run: |
          python scripts/test_parry_comprehensive.py
      
      - name: Run demo
        run: |
          python scripts/demo_scan_with_fixes.py examples/vulnerable_code.py
```

---

## Troubleshooting

### "No module named 'rich'"
```bash
pip install rich
```

### "No module named 'parry'"
```bash
# Make sure you're in the right directory
cd /Users/sathvikkurapati/Downloads/parry-local

# Install in development mode
pip install -e .
```

### "Permission denied"
```bash
chmod +x scripts/test_parry_comprehensive.py
```

### "Ollama connection refused"
```bash
# Check Ollama is running
ps aux | grep ollama

# Start Ollama if not running
ollama serve

# In another terminal, test connection
curl http://localhost:11434/api/tags
```

---

## Test Coverage

### What's Tested ✅
- Core scanning functionality
- All scanner modes
- Vulnerability detection
- License management
- Setup utilities
- Reporter system
- AI features (if available)
- Documentation completeness

### What's Not Tested (Yet) ⏸️
- Performance benchmarks
- Multi-threading edge cases
- Large file handling (>1MB)
- Network security scanning
- Container/IaC scanning depth

---

## Next Steps After Testing

### If All Tests Pass ✅

1. **Run the demo:**
   ```bash
   python scripts/demo_scan_with_fixes.py examples/vulnerable_code.py
   ```

2. **Scan your code:**
   ```bash
   parry scan /path/to/your/project
   ```

3. **Set up for production:**
   - Read SETUP_GUIDE.md
   - Configure Ollama if needed
   - Get a beta token: parry license --install beta --token YOUR_TOKEN

### If Tests Fail ❌

1. **Check the error message**
2. **Review troubleshooting section above**
3. **Check GitHub issues:**
   ```bash
   # Open an issue with:
   - Error message
   - Output from: python scripts/test_parry_comprehensive.py > failure.log
   - System info: python --version, uname -a
   ```

---

## Summary

**Quick Command:**
```bash
python scripts/test_parry_comprehensive.py
```

**Expected Result:** `ALL TESTS PASSED!` 🎉

**Time:** ~30 seconds (less if Ollama not running)

**What it proves:** Parry is fully functional and ready for beta launch!

---

**Questions?** See SETUP_GUIDE.md or contact support@parry.ai

