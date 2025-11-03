# Deep Mode Testing Instructions

## Overview

This guide provides detailed instructions for testing Parry's Deep Mode - the AI-powered vulnerability detection that achieves 90.9% recall.

---

## Prerequisites

### Required
- ✅ Python 3.9+
- ✅ Ollama installed
- ✅ CodeLlama model downloaded
- ✅ Ollama service running

### Optional but Recommended
- ✅ Virtual environment activated
- ✅ Beta license (for full features)
- ✅ At least 8GB RAM (for AI models)

---

## Quick Start

### 1. Setup Ollama (5 minutes)

```bash
# Install Ollama (macOS)
brew install ollama

# Install Ollama (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Install Ollama (Windows)
# Download from: https://ollama.com/download

# Start Ollama service
ollama serve

# In another terminal, download the model
ollama pull codellama:7b

# Verify setup
ollama list
```

**Or use Parry's setup wizard:**
```bash
parry setup
```

### 2. Run the Deep Mode Test

```bash
cd /Users/sathvikkurapati/Downloads/parry-local

# Activate virtual environment (if you have one)
source venv/bin/activate  # macOS/Linux

# Run the test
python scripts/test_deep_mode.py examples/vulnerable_code.py
```

**Expected Result:** You should see Fast Mode vs Deep Mode comparison ✅

---

## What the Test Does

### 1. Prerequisites Check
- Verifies Ollama is running
- Checks if CodeLlama model is available
- Guides you to set up if missing

### 2. Fast Mode Scan
- Runs pattern-based detection
- Baseline vulnerability count
- Measures scan time

### 3. Deep Mode Scan
- Runs AI-powered detection
- Uses LLM semantic analysis
- Measures scan time

### 4. Comparison
- Compares vulnerability counts
- Shows which mode found more issues
- Calculates improvement percentage

### 5. Specific Pattern Tests
- Tests SQL injection detection
- Tests command injection detection
- Tests hardcoded credential detection

---

## Expected Results

### Successful Test Output

```
╭──────────────────────────────────────────────╮
│ Parry Deep Mode Test Suite                   │
│ Testing AI-powered vulnerability detection   │
╰──────────────────────────────────────────────╯

Checking Ollama setup...
✓ Ollama is running and model is available

Test Target: examples/vulnerable_code.py

Testing Pattern-Based (Fast) Mode...
✓ Pattern scan complete in 0.01s
✓ Found 24 vulnerabilities

Testing Deep Mode on: examples/vulnerable_code.py
✓ AI scan complete in 5.23s
✓ Found 28 vulnerabilities

Mode Comparison
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━╳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Metric           ┃ Fast Mode    ┃ Deep Mode    ┃ Difference   ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ Total Vulns      │            24 │            28 │          +4  │
│ Percentage       │            — │            — │      +16.7%  │
└──────────────────┴──────────────┴──────────────┴──────────────┘

✓ Deep Mode found 4 more vulnerabilities!
```

---

## Testing Different Codebases

### Test on Example File
```bash
python scripts/test_deep_mode.py examples/vulnerable_code.py
```

### Test on Your Own Code
```bash
python scripts/test_deep_mode.py /path/to/your/file.py

# Or scan a directory
python scripts/test_deep_mode.py ./src
```

### Test on Multiple Files
```bash
# Test each file individually
for file in src/*.py; do
    python scripts/test_deep_mode.py "$file"
done
```

---

## Understanding the Results

### What "More Vulnerabilities" Means

**Fast Mode finds:**
- ✅ Known pattern-based issues
- ✅ Common security anti-patterns
- ✅ Easy-to-spot vulnerabilities
- ⏱️ Fast (~0.01s per file)

**Deep Mode finds:**
- ✅ Everything Fast Mode finds
- ✅ **+ Complex semantic issues**
- ✅ **+ Context-aware vulnerabilities**
- ✅ **+ Hidden security flaws**
- ⏱️ Slower (~5-10s per file)

**Expected Improvement:** Deep Mode typically finds 15-25% more vulnerabilities

### Example Scenario

**Fast Mode finds:**
```python
query = "SELECT * FROM users WHERE id = " + user_id  # ✅ SQL Injection
```

**Deep Mode also finds:**
```python
# Complex logic that's harder to detect:
def get_user_profile(username):
    sanitized = username.replace("'", "''")  # Attempted sanitization
    query = f"SELECT * FROM users WHERE name='{sanitized}'"  # ❌ Still vulnerable!
    # Fast Mode misses this because sanitization looks correct
    # Deep Mode catches it because the sanitization is incomplete
```

---

## Advanced Testing

### Test on Large Codebases

```bash
# Scan entire project
python scripts/test_deep_mode.py .

# With time measurement
time python scripts/test_deep_mode.py ./src
```

### Compare Modes Side-by-Side

```bash
# Run Fast Mode
parry scan examples/vulnerable_code.py --mode fast --format json > fast_results.json

# Run Deep Mode
parry scan examples/vulnerable_code.py --mode deep --format json > deep_results.json

# Compare
diff fast_results.json deep_results.json
```

### Test Hybrid Mode

```bash
# Hybrid combines both modes
parry scan examples/vulnerable_code.py --mode hybrid

# This should find the most vulnerabilities (Fast + Deep)
```

---

## Troubleshooting

### "Ollama is not running"

**Problem:** Ollama service isn't running

**Solution:**
```bash
# Start Ollama
ollama serve

# Verify it's running
curl http://localhost:11434/api/tags
```

### "Model not found"

**Problem:** CodeLlama model not downloaded

**Solution:**
```bash
# Download the model
ollama pull codellama:7b

# Verify
ollama list
```

### "Connection refused"

**Problem:** Ollama running on different port

**Solution:**
```bash
# Check Ollama port
ps aux | grep ollama

# Set custom port if needed
export OLLAMA_HOST=http://localhost:11434
```

### "Out of memory"

**Problem:** Not enough RAM for AI model

**Solutions:**
```bash
# Use smaller model
ollama pull codellama:3b

# Close other applications
# Increase swap space
# Use machine with more RAM
```

### "Scan hangs"

**Problem:** LLM taking too long

**Solutions:**
```bash
# Check Ollama logs
tail -f ~/.ollama/logs/server.log

# Restart Ollama
pkill ollama
ollama serve
```

### "No vulnerabilities found"

**Problem:** Test file has no vulnerabilities

**Solutions:**
```bash
# Use provided example
python scripts/test_deep_mode.py examples/vulnerable_code.py

# Or create test file
cat > test_vuln.py << 'EOF'
import os
result = os.system(f"ping {user_input}")  # Command injection
EOF

python scripts/test_deep_mode.py test_vuln.py
```

---

## Performance Benchmarks

### Expected Scan Times

| Codebase Size | Fast Mode | Deep Mode | Improvement |
|---------------|-----------|-----------|-------------|
| 50 files      | 0.5s      | 25s       | +20% vulns  |
| 200 files     | 2s        | 100s      | +18% vulns  |
| 500 files     | 5s        | 250s      | +22% vulns  |

**Note:** Deep Mode is slower but catches more vulnerabilities

### Memory Usage

- **Fast Mode:** <100MB RAM
- **Deep Mode:** ~8GB RAM (model loaded)
- **After scan:** RAM usage returns to baseline

---

## Validating Results

### Are the Results Accurate?

**Good Signs:**
- ✅ Deep Mode finds more vulnerabilities than Fast
- ✅ Vulnerabilities have explanations
- ✅ CWEs are correctly classified
- ✅ Severities are reasonable

**Red Flags:**
- ❌ Deep Mode finds fewer vulnerabilities
- ❌ Most findings are false positives
- ❌ Same vulnerability found multiple times
- ❌ CWEs don't match issues

### Manual Verification

```bash
# Get detailed output
python scripts/test_deep_mode.py examples/vulnerable_code.py > results.txt

# Review specific vulnerabilities
grep -A 10 "CWE-89" results.txt  # SQL Injection
grep -A 10 "CWE-78" results.txt  # Command Injection
```

### Compare with Known Baselines

```bash
# Run on known vulnerable code
python scripts/test_deep_mode.py examples/vulnerable_code.py

# Should find specific vulnerabilities:
# - SQL Injection (line 25)
# - Command Injection (line 42)
# - Hardcoded credentials (lines 16-17)
# - XSS (line 34)
# - etc.
```

---

## Best Practices

### For Development
```bash
# Use Fast Mode in pre-commit hooks
parry scan . --mode fast

# Use Deep Mode for weekly audits
parry scan . --mode deep
```

### For Production
```bash
# Use Hybrid Mode for comprehensive coverage
parry scan . --mode hybrid --validate
```

### For CI/CD
```bash
# Fast Mode for every commit (quick feedback)
parry scan ./changed_files --mode fast

# Deep Mode nightly (comprehensive)
parry scan . --mode deep --schedule nightly
```

---

## Next Steps

### After Running Test

1. **Review Results**
   - Compare Fast vs Deep findings
   - Look for unique Deep Mode catches

2. **Validate Findings**
   - Check false positive rate
   - Verify CWE classifications

3. **Apply Fixes**
   - Use suggested fixes
   - Re-run test to verify

4. **Integrate into Workflow**
   - Add to CI/CD pipeline
   - Schedule regular deep scans

### Learn More

- 📊 **Benchmarks:** See COMPREHENSIVE_BENCHMARK_RESULTS.md
- 🚀 **Demo:** Run `python scripts/demo_scan_with_fixes.py`
- 📚 **Documentation:** See SETUP_GUIDE.md
- 🔍 **Comparison:** See COMPETITIVE_ANALYSIS.md

---

## Summary

### Quick Command
```bash
python scripts/test_deep_mode.py examples/vulnerable_code.py
```

### What It Tests
- ✅ Ollama setup verification
- ✅ Fast Mode baseline
- ✅ Deep Mode AI detection
- ✅ Comparison and improvement
- ✅ Specific vulnerability patterns

### Expected Result
Deep Mode finds 15-25% more vulnerabilities than Fast Mode

### Next Steps
- Review found vulnerabilities
- Apply suggested fixes
- Integrate into your workflow

---

**Questions?** See SETUP_GUIDE.md or contact support@parry.ai

