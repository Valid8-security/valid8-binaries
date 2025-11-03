# Parry API Reference

Complete reference for Parry Security Scanner command-line interface and REST API.

---

## CLI Commands

### Core Commands

#### `parry scan`

Scan code for vulnerabilities.

```bash
parry scan [PATH] [OPTIONS]
```

**Arguments:**
- `PATH` - Directory or file to scan (default: current directory)

**Options:**
```bash
--mode fast|deep|hybrid       Detection mode (default: hybrid)
--format table|json|markdown   Output format (default: table)
--output FILE                  Save results to file
--severity critical|high|medium|low  Filter by severity
--exclude PATTERN             Exclude files/directories (repeatable)
--incremental                Only scan changed files
--sca                        Enable SCA scanning
--custom-rules PATH          Use custom rules directory
--workers N                  Number of parallel workers
--verbose                    Detailed output
--quiet                      Minimal output
```

**Examples:**
```bash
# Basic scan
parry scan .

# Fast mode with JSON output
parry scan ./src --mode fast --format json --output results.json

# Hybrid mode with critical vulnerabilities only
parry scan . --mode hybrid --severity critical

# Scan with exclusions
parry scan . --exclude "*/node_modules/*" --exclude "*/venv/*"

# Incremental scan
parry scan . --incremental

# SCA enabled
parry scan . --sca
```

---

#### `parry setup`

Interactive setup wizard for Ollama and AI models.

```bash
parry setup [OPTIONS]
```

**Options:**
```bash
--skip-checks    Skip system requirement checks
--model NAME     Use specific model (default: codellama:7b-instruct)
--quiet          Non-interactive mode
```

**Examples:**
```bash
# Interactive setup
parry setup

# Quick setup without checks
parry setup --skip-checks

# Use specific model
parry setup --model codellama:13b-instruct
```

---

#### `parry doctor`

System health check and diagnostics.

```bash
parry doctor [OPTIONS]
```

**Options:**
```bash
--verbose    Detailed system information
--fix        Attempt to fix issues
```

**Examples:**
```bash
# Basic health check
parry doctor

# Detailed diagnostics
parry doctor --verbose

# Auto-fix issues
parry doctor --fix
```

---

#### `parry configure`

Create or edit configuration file.

```bash
parry configure [OPTIONS]
```

**Options:**
```bash
--global       Edit global config (~/.parry.yml)
--project      Edit project config (.parry.yml)
--reset        Reset to defaults
```

**Examples:**
```bash
# Interactive configuration
parry configure

# Configure project-specific
parry configure --project

# Reset to defaults
parry configure --reset
```

---

#### `parry license`

Manage license and subscriptions.

```bash
parry license [COMMAND] [OPTIONS]
```

**Commands:**
- `info` - Show current license information (default)
- `install` - Install a license key
- `revoke` - Revoke current license

**Install Options:**
```bash
--install beta --email EMAIL      Install beta license
--install beta --token TOKEN      Install beta license with token
--install pro --key KEY           Install Pro license
--install enterprise --key KEY    Install Enterprise license
```

**Examples:**
```bash
# Show license info
parry license

# Install beta license
parry license --install beta --email user@example.com

# Install beta with token
parry license --install beta --token your_token_here

# Install Pro
parry license --install pro --key your_pro_key
```

---

#### `parry admin`

Admin commands for beta token management.

```bash
parry admin COMMAND [OPTIONS]
```

**Commands:**
- `generate-token` - Generate beta token for user
- `list-tokens` - List all issued tokens

**Generate Token Options:**
```bash
--email EMAIL    User's email address (required)
--days N         Days until expiration (default: 60)
```

**Examples:**
```bash
# Generate beta token
parry admin generate-token --email user@example.com

# Generate 30-day token
parry admin generate-token --email user@example.com --days 30

# List all tokens
parry admin list-tokens
```

---

#### `parry feedback`

Submit feedback or bug reports.

```bash
parry feedback MESSAGE [OPTIONS]
```

**Options:**
```bash
--type bug|feature|general    Feedback type (default: general)
--email EMAIL                  Your email address
```

**Examples:**
```bash
# Submit bug report
parry feedback "Found false positive in SQL detection" --type bug

# Feature request
parry feedback "Support for TypeScript" --type feature

# General feedback
parry feedback "Great tool!" --type general
```

---

#### `parry renew`

Request beta license renewal.

```bash
parry renew [FEEDBACK]
```

**Options:**
```bash
--feedback TEXT    Renewal feedback (min 20 chars)
```

**Examples:**
```bash
# Interactive renewal
parry renew

# Renew with feedback
parry renew --feedback "Found 15 critical bugs, improving our security significantly"
```

---

#### `parry compare`

Compare scan results with other tools.

```bash
parry compare TOOL PATH [OPTIONS]
```

**Tools:**
- `snyk` - Compare with Snyk
- `semgrep` - Compare with Semgrep

**Options:**
```bash
--baseline FILE    Use baseline results file
--output FILE      Save comparison report
--format json|markdown  Output format
```

**Examples:**
```bash
# Compare with Snyk
parry compare snyk .

# Compare with baseline
parry compare snyk . --baseline snyk-results.json

# Save comparison
parry compare snyk . --output comparison.json
```

---

## REST API

Parry includes a REST API for programmatic integration.

### Starting the API Server

```bash
# Start API server (default port 8080)
parry api

# Custom port
parry api --port 3000

# Background mode
parry api --daemon

# With authentication
parry api --auth --token your_api_token
```

---

### API Endpoints

#### `POST /api/v1/scan`

Submit code for scanning.

**Request:**
```bash
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/path/to/code",
    "mode": "hybrid",
    "options": {
      "severity": "high",
      "exclude": ["*/node_modules/*"]
    }
  }'
```

**Response:**
```json
{
  "scan_id": "abc123",
  "status": "running",
  "files_scanned": 0,
  "vulnerabilities": []
}
```

---

#### `GET /api/v1/scan/{scan_id}`

Get scan results.

**Request:**
```bash
curl http://localhost:8080/api/v1/scan/abc123
```

**Response:**
```json
{
  "scan_id": "abc123",
  "status": "completed",
  "files_scanned": 150,
  "vulnerabilities": [
    {
      "cwe": "CWE-89",
      "severity": "high",
      "title": "SQL Injection",
      "file": "src/api.py",
      "line": 42,
      "confidence": "high"
    }
  ]
}
```

---

#### `POST /api/v1/health`

Health check endpoint.

**Request:**
```bash
curl http://localhost:8080/api/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "0.7.0",
  "ollama_connected": true
}
```

---

## Configuration Reference

### Config File: `.parry.yml`

**Location:**
- Global: `~/.parry.yml`
- Project: `.parry.yml` (project root)

**Structure:**
```yaml
version: 1.0

# Default scan mode
default_mode: hybrid  # fast, deep, hybrid

# Exclude patterns (glob)
exclude:
  - "*/node_modules/*"
  - "*/venv/*"
  - "*.test.js"

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

# SCA settings
sca:
  enabled: false
  check_updates: true
  fail_on_vulnerable: true

# Custom rules
custom_rules:
  enabled: true
  path: .parry-rules/

# CI/CD settings
ci:
  fail_on_critical: true
  fail_on_high: false
  fail_on_medium: false
  fail_on_low: false
  exit_code: 1  # Exit code on failure

# Performance settings
performance:
  workers: auto  # Number of parallel workers
  incremental: false
  cache_enabled: true
  
# API settings
api:
  enabled: false
  port: 8080
  host: localhost
  auth:
    enabled: false
    token: ""
```

---

## Environment Variables

```bash
# API Settings
PARRY_API_PORT=8080
PARRY_API_HOST=localhost
PARRY_API_TOKEN=your_token_here

# LLM Settings
PARRY_LLM_MODEL=codellama:7b-instruct
PARRY_LLM_TEMPERATURE=0.1
PARRY_LLM_TIMEOUT=30

# Ollama Settings
OLLAMA_HOST=localhost
OLLAMA_PORT=11434

# Beta License Settings
PARRY_ADMIN_SECRET=your_admin_secret

# Logging
PARRY_LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
PARRY_LOG_FILE=/path/to/log
```

---

## Output Formats

### Table Format (Default)

```
Found 12 vulnerabilities:

┌────────┬──────────────────────────────────┬──────────┬─────────────┐
│ Severity│ Title                            │ CWE      │ File        │
├─────────┼──────────────────────────────────┼──────────┼─────────────┤
│ CRITICAL│ Command Injection                │ CWE-78   │ api.py:42   │
│ HIGH    │ SQL Injection                    │ CWE-89   │ db.py:15    │
│ MEDIUM  │ Hardcoded Credentials            │ CWE-798  │ config.py:8 │
└─────────┴──────────────────────────────────┴──────────┴─────────────┘

Summary:
  Files Scanned: 150
  Vulnerabilities: 12
  Critical: 2
  High: 7
  Medium: 3
```

### JSON Format

```json
{
  "scan_id": "abc123",
  "timestamp": "2025-11-02T10:30:00Z",
  "files_scanned": 150,
  "vulnerabilities": [
    {
      "cwe": "CWE-78",
      "severity": "critical",
      "title": "Command Injection",
      "description": "User input in command execution",
      "file": "src/api.py",
      "line": 42,
      "column": 15,
      "confidence": "high",
      "code": "subprocess.call([cmd])",
      "recommendation": "Use subprocess.run with shlex"
    }
  ],
  "summary": {
    "total": 12,
    "critical": 2,
    "high": 7,
    "medium": 3,
    "low": 0
  }
}
```

### Markdown Format

```markdown
# Parry Security Scan Report

**Date:** 2025-11-02  
**Files Scanned:** 150  
**Vulnerabilities:** 12

## Summary

- Critical: 2
- High: 7
- Medium: 3

## Vulnerabilities

### CRITICAL: Command Injection (CWE-78)

**File:** `src/api.py:42`

```python
subprocess.call([cmd])
```

**Recommendation:** Use `subprocess.run()` with `shlex`

---
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no vulnerabilities or below threshold |
| 1 | Vulnerabilities found (CI/CD failure) |
| 2 | Configuration error |
| 3 | System error (Ollama not available, etc.) |
| 4 | Installation error |
| 5 | License error |

---

## Error Codes

| Code | Description |
|------|-------------|
| ERR_001 | Ollama not running |
| ERR_002 | Model not found |
| ERR_003 | Invalid configuration |
| ERR_004 | File/directory not found |
| ERR_005 | Permission denied |
| ERR_006 | Network error |
| ERR_007 | License expired |
| ERR_008 | Rate limit exceeded |

---

## Python SDK (Coming Soon)

```python
from parry import Scanner

# Initialize scanner
scanner = Scanner(mode='hybrid')

# Scan directory
results = scanner.scan('./src')

# Process results
for vuln in results.vulnerabilities:
    print(f"{vuln.severity}: {vuln.title}")
    
# Generate report
results.save_markdown('report.md')
```

---

## Best Practices

### 1. Exclude Unnecessary Files

```bash
parry scan . --exclude "*/node_modules/*" --exclude "*/venv/*"
```

### 2. Use Incremental Scanning

```bash
parry scan . --incremental  # Faster for CI/CD
```

### 3. Set Appropriate Thresholds

```bash
# CI/CD: only fail on critical
parry scan . --severity critical

# Pre-deploy: high and above
parry scan . --severity high
```

### 4. Output to JSON for Processing

```bash
parry scan . --format json --output results.json
```

### 5. Use Fast Mode in CI/CD

```bash
parry scan . --mode fast  # 222 files/sec
```

---

## Troubleshooting

### Common Issues

**Issue:** "Cannot connect to Ollama"
```bash
# Solution: Start Ollama
brew services start ollama  # macOS
sudo systemctl start ollama  # Linux
```

**Issue:** "Model not found"
```bash
# Solution: Pull model
ollama pull codellama:7b-instruct
```

**Issue:** "Permission denied"
```bash
# Solution: Check Python permissions
python3 --version
pip install --user parry-scanner
```

---

## Examples

### Basic Workflow

```bash
# 1. Setup
parry setup

# 2. Scan
parry scan .

# 3. Review results
parry scan . --format markdown --output report.md

# 4. Scan specific severity
parry scan . --severity critical

# 5. Generate JSON
parry scan . --format json --output results.json
```

### CI/CD Workflow

```bash
# GitHub Actions
- name: Install Parry
  run: pip install parry-scanner

- name: Run Scan
  run: parry scan . --mode fast --format json --output results.json

- name: Upload Results
  uses: actions/upload-artifact@v3
  with:
    name: security-results
    path: results.json
```

### Custom Rules Workflow

```bash
# 1. Create rules directory
mkdir .parry-rules

# 2. Add custom rules
cat > .parry-rules/custom.yaml << EOF
rules:
  - pattern: "dangerous_function"
    severity: high
    message: "Dangerous function detected"
EOF

# 3. Scan with custom rules
parry scan . --custom-rules .parry-rules
```

---

## Support

- 📖 **Documentation:** [README.md](README.md)
- 🐛 **Issues:** https://github.com/Parry-AI/parry-scanner/issues
- 💬 **Discussions:** https://github.com/Parry-AI/parry-scanner/discussions

---

**Last Updated:** November 2025  
**Version:** 0.7.0 Beta

