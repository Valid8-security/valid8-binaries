# Parry Quick Start Guide

Get up and running with Parry in 5 minutes!

## Prerequisites

- macOS with Apple Silicon (M1/M2/M3) or Intel
- Python 3.9+
- 40GB+ free disk space
- 16GB+ RAM recommended

## Installation

### Option 1: Automatic Installation (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/parry-security/parry/main/install.sh | bash
```

### Option 2: Manual Installation

```bash
# Install Ollama
brew install ollama

# Start Ollama service
brew services start ollama

# Pull the model (this takes a few minutes)
ollama pull codellama:7b-instruct

# Install Parry
git clone https://github.com/parry-security/parry.git
cd parry
pip install -e .

# Verify installation
parry doctor
```

## Your First Scan

### 1. Scan a Single File

```bash
parry scan examples/vulnerable_code.py
```

You should see output like:

```
┌─────────────── Scan Summary ───────────────┐
│ Target: examples/vulnerable_code.py        │
│ Files Scanned: 1                           │
│ Vulnerabilities: 8                         │
└────────────────────────────────────────────┘

Found 8 vulnerabilities:

HIGH SQL Injection (CWE-89)
File: examples/vulnerable_code.py:18
```

### 2. Scan a Directory

```bash
parry scan /path/to/your/project
```

### 3. Generate JSON Report

```bash
parry scan ./src --format json --output report.json
```

### 4. Filter by Severity

```bash
parry scan ./src --severity high
```

## Generate Patches

### Interactive Mode (Recommended)

```bash
parry patch examples/vulnerable_code.py --interactive
```

This will:
1. Detect vulnerabilities
2. Generate AI-powered fixes
3. Show you each fix
4. Ask for confirmation before applying

### Automatic Mode

```bash
parry patch examples/vulnerable_code.py --apply
```

⚠️ **Warning:** This automatically applies all patches without confirmation!

## Benchmark Against Snyk

```bash
# Compare with Snyk
parry compare snyk /path/to/your/project

# Save comparison report
parry compare snyk /path/to/your/project --output comparison.json
```

## Example Workflow

Here's a complete workflow for securing a project:

```bash
# 1. Initial scan
parry scan ./myproject --format markdown --output initial-scan.md

# 2. Filter critical issues
parry scan ./myproject --severity critical

# 3. Generate patches for a specific file
parry patch ./myproject/api.py --interactive

# 4. Re-scan to verify fixes
parry scan ./myproject

# 5. Compare with Snyk
parry compare snyk ./myproject
```

## Configuration

Create a `.parry.yml` file in your project root:

```yaml
# Parry configuration
exclude:
  - "*/node_modules/*"
  - "*/test/*"
  - "*.test.js"

severity_threshold: medium

llm:
  model: codellama:7b-instruct
  temperature: 0.1
```

## Troubleshooting

### Ollama Not Running

```bash
# Start Ollama
brew services start ollama

# Or run in foreground
ollama serve
```

### Model Not Found

```bash
# List installed models
ollama list

# Pull the model if missing
ollama pull codellama:7b-instruct
```

### Check System Status

```bash
parry doctor
```

This will verify:
- Python version
- Ollama installation
- Model availability

## Performance Tips

### For Faster Scans

1. **Use exclusion patterns** to skip unnecessary files:
   ```bash
   parry scan ./src --exclude "*/node_modules/*" --exclude "*/dist/*"
   ```

2. **Scan specific file types** by organizing scans:
   ```bash
   parry scan ./src --format json > python-results.json
   ```

### For Better LLM Performance

1. **Use quantized models** (default: 7B Q4)
2. **Close other applications** to free up RAM
3. **Use Apple Neural Engine** (automatic on M-series Macs)

## Next Steps

- Read the [full documentation](README.md)
- Check out [example vulnerable code](examples/)
- Run the [benchmark suite](scripts/benchmark.py)
- Integrate with your [CI/CD pipeline](#cicd-integration)

## CI/CD Integration

### GitHub Actions

```yaml
name: Parry Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Parry
        run: |
          brew install ollama
          ollama pull codellama:7b-instruct
          pip install parry-security
      
      - name: Run Parry Scan
        run: |
          parry scan . --format json --output parry-results.json
          
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: parry-results.json
```

## Getting Help

- 📖 [Documentation](README.md)
- 🐛 [Issue Tracker](https://github.com/parry-security/parry/issues)
- 💬 [Discussions](https://github.com/parry-security/parry/discussions)

## Support

Found a bug? Have a feature request? [Open an issue](https://github.com/parry-security/parry/issues)!


