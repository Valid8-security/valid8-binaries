# Parry Setup Guide

Complete guide to installing and configuring Parry Security Scanner.

---

## Quick Start (5 Minutes)

```bash
# 1. Install Parry
pip install parry-scanner

# 2. Run setup wizard
parry setup

# 3. Verify installation
parry doctor

# 4. Scan your code
parry scan . --mode hybrid
```

---

## System Requirements

### Minimum Requirements

- **OS:** macOS 12+, Linux (Ubuntu 18.04+), Windows 10+
- **CPU:** 4 cores (8+ recommended)
- **RAM:** 8GB (16GB+ recommended)
- **Storage:** 40GB free space
- **Python:** 3.9 or higher

### Recommended for Best Performance

- **CPU:** 8+ cores, Apple Silicon (M1/M2/M3) or Intel 11th gen+
- **RAM:** 16GB+ (32GB for Deep/Hybrid modes)
- **Storage:** SSD with 50GB+ free space
- **Network:** Internet for initial model download

---

## Installation Methods

### Method 1: PyPI (Recommended)

```bash
pip install parry-scanner
```

### Method 2: From Source

```bash
# Clone repository
git clone https://github.com/Parry-AI/parry-scanner.git
cd parry-scanner

# Install in development mode
pip install -e .

# Or install production build
pip install .
```

### Method 3: Homebrew (macOS)

```bash
brew install parry-scanner
```

**Note:** Homebrew formula coming soon

---

## Ollama Setup (Required for AI Features)

Parry uses Ollama for local AI processing. This is **required** for Deep and Hybrid modes.

### Automatic Setup (Recommended)

```bash
# Interactive setup wizard handles everything
parry setup
```

The wizard will:
1. ✅ Check system requirements
2. ✅ Install Ollama if missing
3. ✅ Download CodeLlama 7B model (~4GB)
4. ✅ Verify installation
5. ✅ Test AI connection

### Manual Setup

#### Install Ollama

**macOS:**
```bash
brew install ollama
```

**Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Windows:**
Download from: https://ollama.com/download

#### Start Ollama Service

```bash
# macOS/Linux: Start as background service
brew services start ollama  # macOS
sudo systemctl start ollama  # Linux

# Or run in foreground (for debugging)
ollama serve
```

#### Download CodeLlama Model

```bash
# This downloads ~4GB and takes 5-10 minutes
ollama pull codellama:7b-instruct

# Verify model installed
ollama list
```

**Expected output:**
```
NAME                   ID             SIZE   MODIFIED
codellama:7b-instruct  abc123...      4.1GB  2 hours ago
```

---

## Configuration

### Interactive Configuration

```bash
parry configure
```

This creates `.parry.yml` in your home directory with recommended settings.

### Manual Configuration

Create `.parry.yml` in your project root or home directory:

```yaml
# Parry configuration
version: 1.0

# Default scan mode
default_mode: hybrid  # fast, deep, or hybrid

# Exclude patterns
exclude:
  - "*/node_modules/*"
  - "*/venv/*"
  - "*/__pycache__/*"
  - "*.test.js"
  - "*/tests/*"

# Severity threshold
severity_threshold: medium  # critical, high, medium, low

# AI/LLM settings
llm:
  model: codellama:7b-instruct
  temperature: 0.1
  max_tokens: 2048
  timeout: 30

# Output settings
output:
  format: table  # table, json, markdown
  color: true
  verbose: false

# SCA settings (Software Composition Analysis)
sca:
  enabled: false
  check_updates: true
  
# Custom rules
custom_rules:
  enabled: true
  path: .parry-rules/
  
# CI/CD settings
ci:
  fail_on_critical: true
  fail_on_high: false
  fail_on_medium: false
```

---

## Verification

### System Check

```bash
parry doctor
```

**Expected output:**
```
┌─────────────── Parry System Status ───────────────┐
│ Component         │ Status    │ Result           │
├───────────────────┼───────────┼──────────────────┤
│ Parry Version     │ 0.7.0     │ ✓                │
│ Python            │ 3.11.5    │ ✓                │
│ Ollama            │ Running   │ ✓                │
│ CodeLlama Model   │ Found     │ ✓                │
│ Disk Space        │ 50 GB     │ ✓                │
│ RAM Available     │ 16 GB     │ ✓                │
└───────────────────┴───────────┴──────────────────┘

✓ All systems operational
```

### Test Scan

```bash
# Scan example vulnerable code
parry scan examples/vulnerable_code.py

# Or create a test file
echo 'import subprocess; subprocess.call(["/usr/bin/whoami"])' > test.py
parry scan test.py
```

**Expected output:**
```
Found 1 vulnerability:

HIGH Command Injection (CWE-78)
File: test.py:1
Line: 1
Impact: Command execution vulnerability detected
✓ System is working correctly
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Parry Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install Parry
      run: pip install parry-scanner
    
    - name: Install Ollama
      run: |
        curl -fsSL https://ollama.com/install.sh | sh
    
    - name: Download CodeLlama
      run: ollama pull codellama:7b-instruct
    
    - name: Run Parry Scan
      run: |
        ollama serve &
        sleep 5
        parry scan . --mode fast --format json --output results.json
    
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: security-results
        path: results.json
    
    - name: Fail on Critical
      if: failure()
      run: |
        cat results.json | jq '.vulnerabilities[] | select(.severity=="critical")'
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: python:3.9
  before_script:
    - pip install parry-scanner
    - curl -fsSL https://ollama.com/install.sh | sh
    - ollama pull codellama:7b-instruct
  script:
    - ollama serve &
    - sleep 5
    - parry scan . --mode hybrid --format json --output results.json
  artifacts:
    paths:
      - results.json
    expire_in: 1 week
```

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    pip install parry-scanner
                    curl -fsSL https://ollama.com/install.sh | sh
                    ollama pull codellama:7b-instruct
                    ollama serve &
                    sleep 5
                    parry scan . --mode hybrid --format json --output results.json
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'results.json'
        }
    }
}
```

---

## Troubleshooting

### Issue: "Cannot connect to Ollama"

**Solution 1: Check if Ollama is running**
```bash
# Check process
ps aux | grep ollama

# Check port
lsof -i :11434
```

**Solution 2: Start Ollama manually**
```bash
# macOS
brew services start ollama

# Linux
sudo systemctl start ollama

# Windows (run in terminal)
ollama serve
```

**Solution 3: Check firewall**
```bash
# macOS
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getappblocked /usr/local/bin/ollama

# Linux
sudo iptables -L | grep 11434
```

---

### Issue: "Model not found"

**Solution: Pull the model**
```bash
# List installed models
ollama list

# Pull if missing
ollama pull codellama:7b-instruct

# Verify
ollama list | grep codellama
```

---

### Issue: "Out of memory"

**Possible causes:**
1. Not enough RAM for model
2. Model too large for system
3. Multiple processes using memory

**Solutions:**

**1. Use smaller model (if available)**
```bash
# 7B is smallest recommended
# Check if quantized version available
ollama pull codellama:7b-instruct-q4_0
```

**2. Free up RAM**
```bash
# macOS
sudo purge

# Linux
sync && echo 3 | sudo tee /proc/sys/vm/drop_caches
```

**3. Close other applications**
```bash
# Check memory usage
# macOS
vm_stat

# Linux
free -h

# Windows
wmic OS get TotalVisibleMemorySize,FreePhysicalMemory
```

---

### Issue: "Scan is too slow"

**Solution 1: Use Fast Mode**
```bash
parry scan . --mode fast  # 222 files/sec
```

**Solution 2: Exclude files**
```bash
parry scan . --exclude "*/node_modules/*" --exclude "*/venv/*"
```

**Solution 3: Scan specific directories**
```bash
parry scan ./src  # Only scan source directory
```

**Solution 4: Check system resources**
```bash
# CPU usage
top -pid $(pgrep ollama)

# Disk I/O
iostat -x 1
```

---

### Issue: "Permission denied"

**Solution: Check Python permissions**
```bash
# macOS/Linux
which python3
python3 --version

# Install in user space
pip install --user parry-scanner

# Or use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install parry-scanner
```

---

### Issue: "Import errors"

**Solution: Reinstall dependencies**
```bash
# Uninstall
pip uninstall parry-scanner

# Clear cache
pip cache purge

# Reinstall
pip install parry-scanner --no-cache-dir
```

---

## Performance Optimization

### For Faster Scanning

**1. Use Fast Mode for CI/CD**
```bash
parry scan . --mode fast  # 222 files/sec
```

**2. Configure exclusions**
```yaml
# .parry.yml
exclude:
  - "*/node_modules/*"
  - "*/venv/*"
  - "*/__pycache__/*"
  - "*/dist/*"
  - "*/build/*"
```

**3. Enable incremental scanning**
```bash
parry scan . --incremental  # Only scan changed files
```

**4. Parallel processing**
```bash
parry scan . --workers 8  # Use 8 CPU cores
```

---

### For Better AI Performance

**1. Use Apple Neural Engine (macOS)**
```bash
# Automatic on M1/M2/M3 Macs
# Ensure:
export DYLD_LIBRARY_PATH=/opt/homebrew/lib:$DYLD_LIBRARY_PATH
```

**2. Optimize model settings**
```yaml
# .parry.yml
llm:
  temperature: 0.0  # Deterministic output
  max_tokens: 1024  # Reduce for speed
  timeout: 15       # Faster timeout
```

**3. Use quantized models**
```bash
# Default Q4 quantization is best
# For older machines, try Q3
```

---

### Recommended Settings by System

**Mac M1/M2/M3 (16GB):**
```yaml
default_mode: hybrid
llm:
  model: codellama:7b-instruct
  temperature: 0.1
  max_tokens: 2048
workers: 4
```

**Linux (32GB):**
```yaml
default_mode: deep
llm:
  model: codellama:13b-instruct  # If available
  temperature: 0.2
  max_tokens: 4096
workers: 8
```

**Windows (16GB):**
```yaml
default_mode: fast
llm:
  model: codellama:7b-instruct
  temperature: 0.1
  max_tokens: 1024
workers: 4
```

---

## Upgrading

### Check Current Version

```bash
parry --version
```

### Upgrade Parry

```bash
# PyPI
pip install --upgrade parry-scanner

# From source
git pull
pip install --upgrade .
```

### Upgrade Ollama

```bash
# macOS
brew upgrade ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Windows: Download latest from ollama.com
```

### Update CodeLlama Model

```bash
# Pull latest version
ollama pull codellama:7b-instruct

# Or specific version
ollama pull codellama:7b-instruct-v1.0
```

---

## Uninstallation

### Remove Parry

```bash
# Uninstall package
pip uninstall parry-scanner

# Remove config
rm -rf ~/.parry
rm -f ~/.parry.yml
```

### Remove Ollama (Optional)

```bash
# macOS
brew uninstall ollama
rm -rf ~/.ollama

# Linux
sudo systemctl stop ollama
sudo rm /usr/local/bin/ollama
rm -rf ~/.ollama

# Windows: Use Control Panel > Uninstall
```

### Clean Up Models (~4GB freed)

```bash
rm -rf ~/.ollama/models
```

---

## Air-Gapped Installation

For environments without internet access:

### 1. Prepare Offline Package

On a machine with internet:
```bash
# Export model
ollama pull codellama:7b-instruct
tar -czf codellama-7b.tar.gz ~/.ollama/models/

# Export Parry
pip download parry-scanner -d parry-packages/
```

### 2. Transfer to Air-Gapped System

```bash
# Copy files via USB or internal network
cp codellama-7b.tar.gz parry-packages/ /path/to/airgapped/
```

### 3. Install on Air-Gapped System

```bash
# Install Parry from packages
pip install --no-index --find-links parry-packages/ parry-scanner

# Install Ollama manually
# (See Ollama docs for offline installation)

# Import model
tar -xzf codellama-7b.tar.gz -C ~/.ollama/

# Verify
parry doctor
```

---

## Next Steps

1. ✅ **Read Quick Start:** [QUICKSTART.md](QUICKSTART.md)
2. 🔍 **Scan Your Code:** `parry scan /path/to/your/code`
3. 📊 **Review Results:** Check output format options
4. 🔧 **Configure:** Set up `.parry.yml` for your needs
5. 🚀 **Integrate:** Add to CI/CD pipeline

---

## Getting Help

- 📖 **Documentation:** [README.md](README.md)
- 🐛 **Issue Tracker:** https://github.com/Parry-AI/parry-scanner/issues
- 💬 **Discussions:** https://github.com/Parry-AI/parry-scanner/discussions
- 📧 **Email:** support@parry.dev

---

**Last Updated:** November 2025  
**Version:** 0.7.0 Beta

