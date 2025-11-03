# Parry Security Scanner - Complete Setup Guide

This guide will help you set up Parry on your Mac M3 machine for local security scanning.

## System Requirements

- **OS**: macOS 12+ (Monterey or later)
- **Chip**: Apple Silicon (M1/M2/M3) or Intel
- **RAM**: 16GB+ recommended (8GB minimum)
- **Storage**: 40GB+ free space
- **Python**: 3.9 or higher

## Installation Steps

### Step 1: Verify Prerequisites

```bash
# Check Python version
python3 --version  # Should be 3.9+

# Check available disk space
df -h /  # Should show 40GB+ available

# Check RAM
sysctl hw.memsize | awk '{print $2/1073741824 " GB"}'
```

### Step 2: Install Dependencies

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Update Homebrew
brew update
```

### Step 3: Run Automated Installer

```bash
cd /Users/sathvikkurapati/Downloads/parry-local
chmod +x install.sh
./install.sh
```

The installer will:
1. ✓ Check system requirements
2. ✓ Install Ollama
3. ✓ Download CodeLlama 7B model (~4GB)
4. ✓ Install Parry and dependencies
5. ✓ Verify installation

### Step 4: Verify Installation

```bash
# Check Parry installation
parry --version

# Run system check
parry doctor
```

Expected output:
```
┌─────────── System Status ───────────┐
│ Component  │ Status   │ Result     │
├────────────┼──────────┼────────────┤
│ Python     │ 3.11.x   │ ✓          │
│ Ollama     │ Running  │ ✓          │
│ Code Model │ Found    │ ✓          │
└────────────┴──────────┴────────────┘
```

## Testing the Installation

### Test 1: Scan Example Code

```bash
# Scan the example vulnerable code
parry scan examples/vulnerable_code.py
```

You should see multiple vulnerabilities detected:
- SQL Injection (CWE-89)
- XSS (CWE-79)
- Hardcoded Credentials (CWE-798)
- Command Injection (CWE-78)
- And more...

### Test 2: Generate Patches

```bash
# Generate AI-powered patches
parry patch examples/vulnerable_code.py --interactive
```

### Test 3: Test Ollama Connection

```bash
# Run Ollama test script
python3 scripts/test_ollama.py
```

Expected output:
```
Testing Ollama connection...
--------------------------------------------------
✓ Connected to Ollama

Available models:
  - codellama:7b-instruct

Testing code generation...

LLM Response:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

✓ All tests passed!
```

## Manual Installation (Alternative)

If the automated installer fails, follow these manual steps:

### 1. Install Ollama

```bash
brew install ollama
```

### 2. Start Ollama Service

```bash
# Option A: Run as background service
brew services start ollama

# Option B: Run in foreground (for debugging)
ollama serve
```

### 3. Pull CodeLlama Model

```bash
# This downloads ~4GB and may take 5-10 minutes
ollama pull codellama:7b-instruct

# Verify model is installed
ollama list
```

### 4. Install Parry

```bash
cd /Users/sathvikkurapati/Downloads/parry-local

# Install in development mode
pip3 install -e .

# Or install from requirements
pip3 install -r requirements.txt
```

### 5. Verify Installation

```bash
parry doctor
```

## Configuration

### Create Configuration File

```bash
# Copy example config
cp .parry.example.yml .parry.yml

# Edit as needed
nano .parry.yml
```

### Key Configuration Options

```yaml
# Exclude patterns
exclude:
  - "*/node_modules/*"
  - "*/venv/*"

# Severity threshold
severity_threshold: medium

# LLM settings
llm:
  model: codellama:7b-instruct
  temperature: 0.1
```

## Troubleshooting

### Issue: "Cannot connect to Ollama"

**Solution 1**: Check if Ollama is running
```bash
ps aux | grep ollama
```

**Solution 2**: Start Ollama manually
```bash
ollama serve
```

**Solution 3**: Check Ollama port
```bash
lsof -i :11434
```

### Issue: "Model not found"

**Solution**: Pull the model
```bash
ollama pull codellama:7b-instruct
ollama list  # Verify it's installed
```

### Issue: "Python version too old"

**Solution**: Update Python
```bash
brew install python@3.11
```

### Issue: "Out of memory"

**Solution 1**: Close other applications

**Solution 2**: Use a smaller model
```bash
ollama pull codellama:7b-instruct  # Already the smallest recommended
```

**Solution 3**: Increase swap space
```bash
# Check current swap
sysctl vm.swapusage

# macOS manages swap automatically, but you can free memory:
sudo purge
```

### Issue: "Scan is too slow"

**Solution 1**: Use exclusion patterns
```bash
parry scan ./src --exclude "*/node_modules/*" --exclude "*/test/*"
```

**Solution 2**: Scan only specific file types
```bash
# Only Python files
find . -name "*.py" | xargs -I {} parry scan {}
```

**Solution 3**: Check CPU usage
```bash
# Ollama should use ~100-200% CPU during inference
top -pid $(pgrep ollama)
```

## Performance Optimization

### For Faster Scanning

1. **Use SSD**: Ensure project is on SSD, not external drive
2. **Close Apps**: Free up RAM by closing unused applications
3. **Exclude Paths**: Skip node_modules, venv, etc.
4. **Batch Scans**: Scan directories instead of individual files

### For Better LLM Performance

1. **Apple Neural Engine**: Automatic on M-series Macs
2. **Model Selection**: Stick with 7B models for M3
3. **Temperature**: Use 0.0-0.2 for more deterministic output
4. **Context**: Limit context length for faster generation

### Recommended Settings by Machine

**Mac M3 with 16GB RAM:**
```yaml
llm:
  model: codellama:7b-instruct
  temperature: 0.1
  max_tokens: 2048
```

**Mac M3 with 32GB+ RAM:**
```yaml
llm:
  model: codellama:13b-instruct
  temperature: 0.1
  max_tokens: 4096
```

## Running Tests

```bash
# Install test dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=parry --cov-report=html
```

## Next Steps

1. ✅ **Read the Quick Start**: [QUICKSTART.md](QUICKSTART.md)
2. 🔍 **Scan Your Project**: `parry scan /path/to/your/code`
3. 🔧 **Generate Patches**: `parry patch /path/to/file.py --interactive`
4. 📊 **Run Benchmarks**: `python scripts/benchmark.py /path/to/project`
5. 📖 **Full Documentation**: [README.md](README.md)

## Getting Help

- **System Check**: `parry doctor`
- **Help Command**: `parry --help`
- **Issues**: https://github.com/parry-security/parry/issues
- **Discussions**: https://github.com/parry-security/parry/discussions

## Uninstallation

To completely remove Parry:

```bash
# Remove Parry
pip uninstall parry-security

# Remove Ollama (optional)
brew uninstall ollama
rm -rf ~/.ollama

# Remove models (frees ~4GB+)
rm -rf ~/.ollama/models
```

---

**Ready to scan?** 🚀

```bash
parry scan /path/to/your/code
```


