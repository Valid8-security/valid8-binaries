# Parry VS Code Extension

🚀 **Real-time Security Scanning in VS Code**

AI-powered vulnerability detection with inline diagnostics, fix suggestions, and comprehensive security monitoring directly in your development environment.

## ✨ Features

### 🔍 Real-time Security Scanning
- **Auto-scan on save** - Automatic vulnerability detection as you code
- **File system watcher** - Real-time monitoring for file changes
- **Incremental scanning** - Fast, targeted scans for modified code

### 💡 Intelligent Diagnostics
- **Inline diagnostics** - Security issues highlighted directly in code
- **Severity indicators** - Color-coded warnings (critical, high, medium, low)
- **Detailed descriptions** - Comprehensive explanations of vulnerabilities
- **CWE references** - Direct links to MITRE CWE definitions

### 🔧 Smart Fix Suggestions
- **Code lens actions** - Quick fix buttons above vulnerable code
- **One-click fixes** - Automated application of security fixes
- **AI-powered suggestions** - Context-aware remediation guidance

### 📊 Security Dashboard
- **Workspace overview** - Complete security status of your project
- **Interactive charts** - Vulnerability trends and severity distribution
- **Scan history** - Track security improvements over time
- **Compliance metrics** - OWASP, CWE, and industry standard coverage

### ⚙️ Flexible Configuration
- **Scan modes** - Fast (72.7%), Hybrid (90.9%), Deep (95%+) recall
- **Custom exclusions** - Ignore test files, dependencies, etc.
- **Severity thresholds** - Focus on issues that matter to you
- **Performance tuning** - Adjust concurrency and caching

## 🚀 Quick Start

### Installation

1. **Install Parry CLI** (required for scanning)
   ```bash
   # Download from https://parry.ai/download
   # Or install via pip (if Python available)
   pip install parry-scanner
   ```

2. **Install VS Code Extension**
   - Open VS Code
   - Go to Extensions (Ctrl+Shift+X)
   - Search for "Parry Security Scanner"
   - Click Install

3. **First Scan**
   - Open a workspace with code
   - Use Command Palette: `Parry: Scan Workspace`
   - Or right-click in Explorer: `Parry: Scan Workspace`

### Requirements

- **VS Code**: 1.74.0 or later
- **Parry CLI**: 1.0.0 or later (must be in PATH)
- **Supported Languages**: JavaScript, TypeScript, Python, Java, C#, Go, Rust, PHP

## 🎯 Usage

### Scanning Commands

| Command | Description | Shortcut |
|---------|-------------|----------|
| `Parry: Scan Workspace` | Full workspace security scan | - |
| `Parry: Scan Current File` | Scan only active file | Ctrl+Shift+S |
| `Parry: Show Security Dashboard` | Open interactive dashboard | - |
| `Parry: Apply Security Fix` | Apply suggested fix | - |
| `Parry: Configure Parry` | Open extension settings | - |

### Context Menu Actions

- **Right-click in code**: "Scan Current File"
- **Right-click on vulnerable code**: "Apply Security Fix"
- **Right-click in Explorer**: "Scan Workspace"

### Keyboard Shortcuts

- **Ctrl+Shift+S** (Cmd+Shift+S on Mac): Scan current file
- **F1** then type "Parry" to access all commands

## ⚙️ Configuration

Access settings via `Parry: Configure Parry` or VS Code Settings UI.

### Scan Settings
```json
{
  "parry.scanOnSave": true,
  "parry.scanMode": "hybrid",
  "parry.enableAI": true,
  "parry.showInlineHints": true,
  "parry.severityThreshold": "medium"
}
```

### Performance Settings
```json
{
  "parry.excludePatterns": [
    "**/node_modules/**",
    "**/test/**",
    "**/.git/**",
    "**/*.min.js"
  ],
  "parry.executablePath": "parry",
  "parry.maxConcurrency": 4
}
```

## 🔍 Understanding Results

### Severity Levels
- **🚨 Critical**: Immediate security risk (code injection, authentication bypass)
- **⚠️ High**: Significant security concern (XSS, SQL injection)
- **ℹ️ Medium**: Potential security issue (weak cryptography, information disclosure)
- **💡 Low**: Best practice violation (deprecated functions, insecure defaults)

### Vulnerability Details
Each finding includes:
- **Title**: Human-readable description
- **CWE**: Common Weakness Enumeration reference
- **Location**: File and line number
- **Impact**: Potential security consequences
- **Remediation**: Suggested fix or mitigation steps

### Code Lens Actions
Above vulnerable code, you'll see:
- **🔧 Fix Issue**: Apply automated security fix
- **ℹ️ Learn More**: Open CWE documentation

## 📊 Security Dashboard

### Overview Metrics
- **Files Scanned**: Total codebase coverage
- **Vulnerabilities Found**: Issues by severity
- **Scan Performance**: Speed and efficiency metrics
- **Compliance Score**: Industry standard adherence

### Interactive Charts
- **Severity Distribution**: Bar chart of vulnerability types
- **Trend Analysis**: Security improvements over time
- **Language Breakdown**: Issues by programming language

### Scan History
- **Recent Scans**: Last 10 security assessments
- **Performance Trends**: Scan speed and detection rates
- **Fix Progress**: Vulnerabilities resolved over time

## 🔧 Troubleshooting

### Extension Not Working

**Parry CLI not found**
```bash
# Check if Parry is installed
parry --version

# Add to PATH if needed
export PATH="$PATH:/path/to/parry"
```

**No diagnostics appearing**
```bash
# Check file type support
# Supported: .js, .ts, .py, .java, .cs, .go, .rs, .php

# Verify settings
# parry.scanOnSave: true
# parry.enableAI: true
```

**Slow scanning**
```bash
# Adjust performance settings
# parry.maxConcurrency: 2 (reduce for slower machines)
# parry.scanMode: "fast" (for large codebases)
```

### Common Issues

**"Command not found" errors**
- Ensure Parry CLI is installed and in PATH
- Restart VS Code after installation
- Check VS Code terminal PATH matches system PATH

**False positives**
- Use `parry.configure` to adjust severity thresholds
- Add files/patterns to `parry.excludePatterns`
- Report via GitHub Issues for AI model improvement

**Extension not activating**
- Check VS Code version (1.74.0+ required)
- Verify extension is enabled in Extensions panel
- Reload VS Code window (Ctrl+Shift+P → "Developer: Reload Window")

## 🔄 Updates and Support

### Automatic Updates
- Extension updates via VS Code Marketplace
- Parry CLI updates via `parry update` command
- Security patches released as needed

### Support Channels
- **Documentation**: Comprehensive guides and examples
- **GitHub Issues**: Bug reports and feature requests
- **Community**: VS Code Marketplace reviews and discussions
- **Enterprise**: Dedicated support for paid plans

### Contributing
- **Bug Reports**: Include VS Code version, Parry version, and reproduction steps
- **Feature Requests**: Describe use case and expected behavior
- **Code Contributions**: Follow TypeScript and VS Code extension guidelines

## 📈 Performance Benchmarks

### Scan Performance
```
Language: JavaScript (1000 files)
Fast Mode:    8.3s  (120 files/sec)
Hybrid Mode:  32.1s  (31 files/sec)
Deep Mode:    95.7s  (10 files/sec)

Language: Python (500 files)
Fast Mode:    4.2s  (119 files/sec)
Hybrid Mode:  18.5s  (27 files/sec)
Deep Mode:    52.3s  (9.5 files/sec)
```

### Detection Accuracy
- **False Positive Rate**: <5% (AI validation)
- **Industry Benchmark**: 92% precision vs 88% commercial average
- **Recall Rate**: 91% (hybrid mode) vs 79% commercial average

## 🔒 Security & Privacy

### Local Processing
- **Zero data transmission** - All scanning happens locally
- **No telemetry** - No usage data collected
- **Offline capable** - Works without internet (except AI model downloads)

### AI Model Privacy
- **Local inference** - Models run on your machine
- **No code transmission** - Code never leaves your environment
- **Model isolation** - AI models cannot access external networks

### Extension Permissions
- **File system access** - Read-only for scanning
- **Command execution** - Local Parry CLI only
- **Network access** - None (except for CWE documentation links)

---

🛡️ **Bringing enterprise-grade security scanning directly into your development workflow**
- Initial release
- Real-time vulnerability scanning
- Inline diagnostics with quick fixes
- Security panel dashboard
- Pro/Enterprise license support
- 200+ security detectors
- AI-powered fix generation
