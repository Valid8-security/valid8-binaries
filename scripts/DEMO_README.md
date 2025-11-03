# Parry Demo Script - Live Security Scanning with Fixes

## Overview

This interactive demo showcases Parry's complete vulnerability detection and AI-powered fix generation capabilities in real-time.

## What It Does

1. **Scans** your codebase for security vulnerabilities
2. **Displays** findings in a beautiful formatted table
3. **Shows detailed** information for each vulnerability
4. **Generates AI-powered fixes** with before/after code comparisons
5. **Provides guidance** for remediation

## Quick Start

```bash
# Make sure you have Ollama running for AI features
parry setup

# Run the demo on the example vulnerable code
python scripts/demo_scan_with_fixes.py examples/vulnerable_code.py

# Or scan your own codebase
python scripts/demo_scan_with_fixes.py /path/to/your/code
```

## Example Output

```
╭────────────────────────────────────────────────────────────────╮
│ 🔒 Parry Security Scanner - Live Demo                          │
│ Scanning code, detecting vulnerabilities, and suggesting fixes │
╰────────────────────────────────────────────────────────────────╯

📋 Step 1: Scanning codebase...
Target: examples/vulnerable_code.py

✓ Scan complete in 0.01 seconds
✓ Files scanned: 1
✓ Vulnerabilities found: 24

📊 Vulnerabilities Detected:

┏┳━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃┃ S… ┃ CWE    ┃ Title                              ┃ Location                 ┃
┡╇━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━┩
││ C… │ CWE-78 │ OS Command Injection               │ examples/vulnerable_cod… │
││ C… │ CWE-89 │ SQL Injection                      │ examples/vulnerable_cod… │
││ H… │ CWE-79 │ Cross-Site Scripting (XSS)        │ examples/vulnerable_cod… │
└┴────┴────────┴────────────────────────────────────┴──────────────────────────┘

🤖 Step 2: Generating AI-powered fixes...

Original Code:
    result = os.system(f"ping -c 1 {host}")

Fixed Code:
result = subprocess.run(["ping", "-c", "1", host], check=True)

Explanation:
Use safe APIs like subprocess with argument lists instead of shell commands.
```

## Features

### 1. Vulnerability Detection
- **Fast scan** - Completes in seconds
- **Comprehensive** - Finds 24 vulnerabilities in example
- **Detailed** - Shows severity, CWE, title, and location

### 2. AI-Powered Fixes
When Ollama is available:
- ✅ Generates **secure, working code fixes**
- ✅ Shows **before/after comparison**
- ✅ Provides **clear explanations**
- ✅ Follows **security best practices**

When Ollama is not available:
- ✅ Shows **basic remediation guidance**
- ✅ Provides **CWE-specific recommendations**
- ✅ Lists **security best practices**

### 3. Beautiful Output
- 📊 Rich terminal formatting
- 🎨 Color-coded severity
- 📝 Syntax highlighting
- 📋 Clean tables and panels

## Requirements

### For Basic Scanning
- Python 3.9+
- Parry installed
- No additional requirements

### For AI Fix Generation
- ✅ Ollama installed and running
- ✅ CodeLlama model downloaded
- ✅ Pro/Enterprise license (or beta)

```bash
# Setup AI features
parry setup

# Check status
parry doctor
```

## Use Cases

### 1. Learning Security
```bash
# See how Parry detects vulnerabilities
python scripts/demo_scan_with_fixes.py examples/vulnerable_code.py
```

### 2. Testing Your Code
```bash
# Scan your own codebase
python scripts/demo_scan_with_fixes.py ./src
```

### 3. Demonstrating Parry
```bash
# Show Parry in action
python scripts/demo_scan_with_fixes.py /path/to/demo/project
```

## Output Sections

### 1. Scan Results Summary
- Files scanned
- Vulnerabilities found
- Scan duration

### 2. Vulnerability Table
- Severity (Critical/High/Medium/Low)
- CWE classification
- Vulnerability title
- File location

### 3. Detailed Information
- Severity and confidence level
- Full description
- Code snippets
- Line numbers

### 4. AI Fixes (if available)
- Original vulnerable code
- Fixed secure code
- Clear explanations
- Best practices

### 5. Summary & Next Steps
- Severity breakdown
- Top vulnerability types
- Recommended actions
- Help resources

## Advanced Usage

### Run on Multiple Files
```bash
# The demo can scan directories or individual files
python scripts/demo_scan_with_fixes.py ./src/  # Directory
python scripts/demo_scan_with_fixes.py app.py  # Single file
```

### Integrate with CI/CD
```bash
# Run as part of automated testing
python scripts/demo_scan_with_fixes.py . > security-report.txt
```

### Customize Output
The script uses Parry's internal modules. You can modify it to:
- Export results as JSON
- Filter by severity
- Focus on specific CWEs
- Generate reports

## Troubleshooting

### "Ollama not available"
```bash
# Setup Ollama
parry setup

# Verify
parry doctor
```

### "Rich module not found"
```bash
# Install in development mode
pip install -e ".[dev]"

# Or manually
pip install rich
```

### "License required"
```bash
# Install beta license
parry license --install beta --token YOUR_TOKEN

# Or use free tier (basic scanning only)
```

## Understanding the Output

### Severity Levels
- 🔴 **Critical** - Immediate security risk
- 🟠 **High** - Serious security issue
- 🟡 **Medium** - Moderate security concern
- 🟢 **Low** - Minor security suggestion

### CWE Classifications
- **CWE-78** - OS Command Injection
- **CWE-79** - Cross-Site Scripting (XSS)
- **CWE-89** - SQL Injection
- **CWE-798** - Hardcoded Credentials
- And many more...

### Fix Quality
AI-generated fixes:
- ✅ Use secure APIs
- ✅ Follow OWASP guidelines
- ✅ Include proper validation
- ✅ Add explanatory comments

## Examples

### Example 1: SQL Injection
**Detected:** SQL injection in Flask route  
**Fix:** Use parameterized queries  
**Impact:** Prevents database compromise

### Example 2: Hardcoded Credentials
**Detected:** API key in source code  
**Fix:** Use environment variables  
**Impact:** Prevents credential exposure

### Example 3: Command Injection
**Detected:** Unsafe os.system() call  
**Fix:** Use subprocess.run() safely  
**Impact:** Prevents RCE attacks

## Next Steps

After running the demo:

1. **Review** the detected vulnerabilities
2. **Apply** the suggested fixes
3. **Re-scan** to verify remediation
4. **Integrate** into your workflow
5. **Automate** with CI/CD

## Learn More

- 📚 [COMPREHENSIVE_BENCHMARK_RESULTS.md](../COMPREHENSIVE_BENCHMARK_RESULTS.md) - Performance metrics
- 📖 [SETUP_GUIDE.md](../SETUP_GUIDE.md) - Installation instructions
- 📊 [COMPETITIVE_ANALYSIS.md](../COMPETITIVE_ANALYSIS.md) - Parry vs competitors
- 🚀 [QUICKSTART.md](../QUICKSTART.md) - Quick tutorial

## Support

Questions? Issues?
- 📧 Email: support@parry.ai
- 🌐 Web: https://parry.dev
- 📚 Docs: https://parry.dev/docs

---

**Ready to secure your code? Run the demo now!** 🚀

```bash
python scripts/demo_scan_with_fixes.py examples/vulnerable_code.py
```

