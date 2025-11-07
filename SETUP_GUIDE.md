# Parry Setup Guide

Complete installation and setup instructions for Parry security scanner.

## 📋 System Requirements

### Minimum Requirements
- **OS**: Linux, macOS, Windows
- **Python**: 3.8 or higher
- **RAM**: 4GB
- **Disk**: 500MB free space
- **Network**: Internet connection for initial setup

### Recommended Requirements
- **OS**: Linux or macOS
- **Python**: 3.9+
- **RAM**: 8GB+
- **Disk**: 2GB free space
- **CPU**: Multi-core processor
- **Ollama**: For AI features

## 🚀 Installation

### Option 1: Pip Install (Recommended)

#### Install Python
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv

# macOS (with Homebrew)
brew install python

# Windows (Chocolatey)
choco install python

# Verify installation
python3 --version  # Should be 3.8+
pip3 --version
```

#### Install Parry
```bash
# Install Parry
pip3 install parry-scanner

# Verify installation
parry --version
```

### Option 2: From Source Code

#### Clone Repository
```bash
git clone https://github.com/Parry-AI/parry-scanner.git
cd parry-scanner
```

#### Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv parry-env

# Activate virtual environment
source parry-env/bin/activate  # Linux/macOS
# parry-env\Scripts\activate    # Windows
```

#### Install Dependencies
```bash
# Install Parry in development mode
pip install -e .

# Verify installation
parry --version
```

### Option 3: Docker Installation

#### Build Docker Image
```bash
# Clone repository
git clone https://github.com/Parry-AI/parry-scanner.git
cd parry-scanner

# Build Docker image
docker build -t parry-scanner .

# Run Parry in Docker
docker run -v $(pwd):/app parry-scanner parry scan /app
```

## 🤖 AI Setup (Optional but Recommended)

### Install Ollama

#### macOS
```bash
# Install Ollama
brew install ollama

# Start Ollama service
ollama serve
```

#### Linux
```bash
# Download and install
curl -fsSL https://ollama.ai/install.sh | sh

# Start service
systemctl start ollama  # systemd
# or
ollama serve            # manual start
```

#### Windows
```bash
# Using Scoop
scoop install ollama
ollama serve

# Using PowerShell
# Download from https://ollama.ai/download
# Run installer
```

### Download AI Models

#### Basic Model (Recommended)
```bash
# Fast, lightweight model
ollama pull qwen2.5-coder:0.5b
```

#### Advanced Model (High Accuracy)
```bash
# Slower but more accurate
ollama pull qwen2.5-coder:1.5b
```

#### Verify Models
```bash
# List installed models
ollama list

# Expected output:
# NAME                    SIZE
# qwen2.5-coder:0.5b      1.5 GB
# qwen2.5-coder:1.5b      4.7 GB
```

## ⚙️ Configuration

### Configuration File

Create configuration file at `~/.parry/config.yaml`:

```yaml
# Default scan settings
mode: hybrid
validate: true
format: terminal
severity: medium

# Performance settings
max_workers: 4
batch_size: 10
timeout: 30

# Output settings
output_dir: ./parry-results
reports:
  - format: json
  - format: html

# Exclusions
exclude_patterns:
  - "**/test/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/venv/**"
  - "**/.venv/**"
  - "**/__pycache__/**"
  - "**/*.min.js"
  - "**/*.min.css"
  - "**/build/**"
  - "**/dist/**"
  - "**/.git/**"

# Custom rules
custom_rules_dir: ~/.parry/rules

# AI settings
ollama:
  host: http://127.0.0.1:11434
  models:
    fast: qwen2.5-coder:0.5b
    accurate: qwen2.5-coder:1.5b
  timeout: 30
  max_tokens: 512
```

### Environment Variables

```bash
# Ollama configuration
export OLLAMA_HOST=http://127.0.0.1:11434

# Parry configuration
export PARRY_CONFIG=~/.parry/config.yaml
export PARRY_CACHE_DIR=~/.parry/cache
export PARRY_LOG_LEVEL=INFO

# Proxy settings (if needed)
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
```

## 🧪 Testing Installation

### Basic Functionality Test
```bash
# Test basic scan
parry scan --help

# Create test file
echo "print('hello')" > test.py

# Test scan on test file
parry scan test.py

# Expected output: No vulnerabilities found
```

### AI Functionality Test
```bash
# Test AI features (requires Ollama)
echo "eval(input('Enter code: '))" > dangerous.py
parry scan dangerous.py --mode hybrid --validate

# Expected output: Should detect CWE-95 (Code Injection)
```

### Custom Rules Test
```bash
# Create custom rules
parry init-rules --output test-rules.yaml

# Test custom rules
parry scan . --custom-rules test-rules.yaml
```

## 🚨 Troubleshooting

### Common Issues

#### "parry command not found"
```bash
# Check if virtual environment is activated
source parry-env/bin/activate

# Or add to PATH
export PATH="$PATH:~/.local/bin"
```

#### "Ollama connection failed"
```bash
# Check if Ollama is running
ollama list

# Start Ollama service
ollama serve

# Check Ollama version
ollama --version
```

#### "ImportError: No module named 'parry'"
```bash
# Install in development mode
pip install -e .

# Or install normally
pip install parry-scanner
```

#### Permission Errors
```bash
# Fix permissions
chmod +x $(which parry)

# Or run with sudo (not recommended)
sudo parry scan .
```

#### Memory Issues
```bash
# Reduce batch size
parry scan . --batch-size 5

# Use fast mode
parry scan . --mode fast

# Increase system memory or use smaller codebases
```

### Performance Tuning

#### For Large Codebases
```yaml
# In ~/.parry/config.yaml
max_workers: 8
batch_size: 20
streaming_chunk_size: 8192
cache_enabled: true
smart_prefilter: true
```

#### For Limited Resources
```yaml
# In ~/.parry/config.yaml
max_workers: 2
batch_size: 5
ai_timeout: 10
disable_cache: false  # Keep cache enabled
```

## 🔧 Advanced Setup

### CI/CD Integration

#### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    - name: Install Parry
      run: pip install parry-scanner
    - name: Install Ollama
      run: |
        curl -fsSL https://ollama.ai/install.sh | sh
        ollama serve &
        sleep 5
        ollama pull qwen2.5-coder:0.5b
    - name: Run Security Scan
      run: parry scan . --mode hybrid --validate --format sarif > results.sarif
    - name: Upload results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results.sarif
```

#### GitLab CI
```yaml
security_scan:
  image: python:3.9
  before_script:
    - pip install parry-scanner
    - curl -fsSL https://ollama.ai/install.sh | sh
    - ollama serve &
    - sleep 5
    - ollama pull qwen2.5-coder:0.5b
  script:
    - parry scan . --mode hybrid --validate --format json --output results.json
  artifacts:
    reports:
      sast: results.json
```

### IDE Integration

#### VS Code Extension
```bash
# Install VS Code extension
code --install-extension parry.parry-vscode

# Configure in settings.json
{
  "parry.scanOnSave": true,
  "parry.scanMode": "hybrid",
  "parry.enableValidation": true
}
```

### API Server Setup

#### Basic API Server
```bash
# Start API server
parry serve --host 0.0.0.0 --port 8000

# Test API
curl http://localhost:8000/api/v1/health

# Scan via API
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": ".", "mode": "hybrid"}'
```

#### Production Deployment
```bash
# Using Gunicorn
pip install gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 4 parry.api:app

# Using Docker Compose
version: '3.8'
services:
  parry:
    build: .
    ports:
      - "8000:8000"
    environment:
      - OLLAMA_HOST=http://ollama:11434
    depends_on:
      - ollama

  ollama:
    image: ollama/ollama
    volumes:
      - ollama_data:/root/.ollama
    command: serve

volumes:
  ollama_data:
```

## 📊 Monitoring and Maintenance

### Log Files
```bash
# View logs
tail -f ~/.parry/logs/parry.log

# Log levels
export PARRY_LOG_LEVEL=DEBUG  # For troubleshooting
```

### Cache Management
```bash
# View cache stats
parry cache --stats

# Clear cache
parry cache --clear

# Prune old cache entries
parry cache --prune 7  # Remove entries older than 7 days
```

### Update Management
```bash
# Check for updates
pip show parry-scanner

# Update Parry
pip install --upgrade parry-scanner

# Update AI models
ollama pull qwen2.5-coder:0.5b  # Latest version
```

## 📞 Support

### Getting Help
```bash
# Show help
parry --help

# Run diagnostics
parry doctor

# Check version and components
parry --version
```

### Community Support
- **Documentation**: `docs/` directory
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: General questions and community support

### Enterprise Support
For enterprise deployment and support:
- Contact: enterprise@parry.ai
- SLA options available
- Custom integrations
- Training and consulting

---

🎉 **Setup Complete!** You're ready to start securing your code with Parry.
