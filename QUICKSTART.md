# Parry Quick Start Guide

Get up and running with Parry security scanner in under 5 minutes.

## ⚡ Quick Installation

### Option 1: Pip Install (Recommended)
```bash
pip install parry-scanner
```

### Option 2: From Source
```bash
git clone https://github.com/Parry-AI/parry-scanner.git
cd parry-scanner
pip install -e .
```

## 🤖 AI Setup (Optional but Recommended)

Parry works without AI, but AI features dramatically improve accuracy.

### Install Ollama
```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Windows (PowerShell)
scoop install ollama
```

### Download AI Models
```bash
# Fast model (recommended for most users)
ollama pull qwen2.5-coder:0.5b

# High-accuracy model (requires more resources)
ollama pull qwen2.5-coder:1.5b
```

## 🚀 Your First Scan

### Basic Scan (No AI)
```bash
# Scan current directory
parry scan .

# Scan specific directory
parry scan /path/to/your/code

# Scan with output to file
parry scan . --output results.json --format json
```

### AI-Powered Scan (Recommended)
```bash
# Hybrid mode: Pattern-based + AI validation
parry scan . --mode hybrid --validate

# Deep mode: Full AI analysis (slower but most accurate)
parry scan . --mode deep
```

## 📊 Understanding Results

### Terminal Output
```
🔍 Scanning 1,247 files across 45 directories...
⚡ Fast scan completed in 8.3 seconds
📊 Results Summary:
   Files scanned: 1,247
   Vulnerabilities found: 23
   High severity: 3
   Medium severity: 12
   Low severity: 8

🚨 High Severity Issues:
   CWE-79: Cross-site Scripting in login.js:42
   CWE-89: SQL Injection in user.py:156
   CWE-434: File Upload Vulnerability in upload.py:78
```

### Output Formats
```bash
# JSON (machine-readable)
parry scan . --format json --output results.json

# SARIF (GitHub Security tab)
parry scan . --format sarif --output results.sarif

# HTML Dashboard
parry scan . --format html --output dashboard.html
```

## 🎯 Scan Modes

| Mode | Speed | Accuracy | Use Case |
|------|-------|----------|----------|
| **fast** | ⚡ Fastest | 85% precision | Quick checks, CI/CD |
| **hybrid** | ⚖️ Balanced | 92% precision | Most projects |
| **deep** | 🎯 Slowest | 95%+ precision | Critical code |

## 🔧 Common Commands

### Custom Rules
```bash
# Create custom rules template
parry init-rules --output my-rules.yaml

# Edit my-rules.yaml with your custom patterns
# Then scan with custom rules
parry scan . --custom-rules my-rules.yaml
```

### Natural Language Filtering
```bash
# Add filter for known false positives
parry add-nl-filter "eval() in test files is always safe"

# List all filters
parry list-nl-filters

# Remove filter
parry remove-nl-filter nl_filter_1
```

### CI/CD Integration
```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install parry-scanner
    parry scan . --mode hybrid --validate --format sarif > results.sarif
```

### API Server
```bash
# Start local API server
parry serve --host 127.0.0.1 --port 8000

# Webhook endpoint available at /api/v1/webhook
# REST API at /api/v1/scan
```

## 🎨 Customization

### Configuration File
Create `~/.parry/config.yaml`:
```yaml
# Default scan settings
mode: hybrid
validate: true
format: terminal
severity: medium
exclude_patterns:
  - "**/test/**"
  - "**/node_modules/**"
  - "**/*.min.js"
```

### Environment Variables
```bash
# Ollama configuration
export OLLAMA_HOST=127.0.0.1:11434

# Parry configuration
export PARRY_CONFIG=~/.parry/config.yaml
export PARRY_CACHE_DIR=~/.parry/cache
```

## 🚨 Troubleshooting

### Common Issues

**"Ollama not found"**
```bash
# Install Ollama
brew install ollama  # macOS
ollama serve         # Start Ollama service
```

**"Model not found"**
```bash
ollama pull qwen2.5-coder:0.5b
```

**"Permission denied"**
```bash
# Fix permissions
chmod +x $(which parry)
```

**Slow scans**
```bash
# Use fast mode for large codebases
parry scan . --mode fast

# Exclude unnecessary directories
parry scan . --exclude "**/node_modules/**" --exclude "**/build/**"
```

### Getting Help
```bash
# Show all options
parry --help

# Show scan options
parry scan --help

# Doctor command for diagnostics
parry doctor
```

## 📚 Next Steps

- **Documentation**: See `docs/` directory for detailed guides
- **API Reference**: Check `docs/api/API_REFERENCE.md`
- **Contributing**: Read `CONTRIBUTING.md`
- **Examples**: Explore the `examples/` directory

## 🎯 Pro Tips

1. **Use hybrid mode** for the best balance of speed and accuracy
2. **Enable validation** (`--validate`) for significantly reduced false positives
3. **Create custom rules** for project-specific security patterns
4. **Use natural language filtering** for recurring false positives
5. **Integrate into CI/CD** for automated security checks

Happy scanning! 🛡️
