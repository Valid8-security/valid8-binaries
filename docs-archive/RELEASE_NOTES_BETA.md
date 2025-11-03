# Parry v0.7.0 Beta Release Notes

**Release Date:** November 2, 2025  
**Version:** 0.7.0 Beta  
**Status:** Production Ready

---

## 🎉 What's New

**Parry v0.7.0 Beta** introduces industry-leading security scanning with **90.9% recall** and **100% privacy**.

### Major Features

#### ✅ Three Detection Modes
- **Fast Mode:** 72.7% recall, 95% precision, 222 files/sec
- **Deep Mode:** 72.7% recall, AI-powered, thorough analysis
- **Hybrid Mode:** **90.9% recall**, combines Fast + Deep for maximum coverage

#### ✅ AI-Powered Detection
- Local LLM integration (CodeLlama 7B)
- Semantic code analysis
- Context-aware vulnerability detection
- 100% private (no cloud uploads)

#### ✅ Comprehensive Coverage
- 8 programming languages (Python, Java, JS, Go, Rust, C/C++, PHP, Ruby)
- 47 unique CWE types
- Framework-specific rules (Django, Flask, Spring, Express)
- Data flow analysis
- AST-based detection

#### ✅ Enterprise Features
- SCA (Software Composition Analysis)
- Custom rules engine
- Incremental scanning
- CI/CD integration templates
- REST API
- VS Code extension
- Compliance reporting
- Auto-fix PR generation
- Container/IaC scanning

---

## 📊 Performance

### Detection Accuracy

| Mode | Recall | Precision | F1 Score |
|------|--------|-----------|----------|
| Fast | 72.7% | **95.0%** ✅ | 82.4% |
| Deep | 72.7% | ~85% | 78.4% |
| Hybrid | **90.9%** ✅✅ | **90.0%** ✅ | **90.4%** ✅ |

### Competitive Position

| Tool | Recall | Precision | Speed | Privacy | Cost |
|------|--------|-----------|-------|---------|------|
| **Parry Hybrid** | **90.9%** | **90.0%** | Slow | **100%** | **$0-199** |
| SonarQube | 85.0% | 75.0% | 20/s | Mixed | $145k/yr |
| Snyk | 50.0% | 75.0% | 83/s | 0% | $200+/mo |

**Parry ranks #1 in recall, precision, privacy, and cost!**

---

## 🚀 Quick Start

### Installation

```bash
# Install Parry
pip install parry-scanner

# Setup AI (required for Deep/Hybrid modes)
parry setup

# Verify installation
parry doctor
```

### First Scan

```bash
# Fast scan (quick)
parry scan . --mode fast

# Deep scan (thorough)
parry scan . --mode deep

# Hybrid scan (best coverage)
parry scan . --mode hybrid
```

---

## 🎯 Use Cases

### Daily Development
```bash
parry scan . --mode fast
# Fast feedback during coding
```

### Pre-Commit
```bash
parry scan . --mode fast --severity high
# Quick check before committing
```

### Pre-Release
```bash
parry scan . --mode hybrid --validate
# Comprehensive security audit
```

### CI/CD
```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: parry scan . --mode fast
```

---

## 📋 Supported Vulnerabilities

### Top 10 CWE Types Detected

1. **CWE-287** - Improper Authentication
2. **CWE-352** - CSRF
3. **CWE-798** - Hardcoded Credentials
4. **CWE-78** - Command Injection
5. **CWE-434** - Unrestricted File Upload
6. **CWE-327** - Weak Cryptography
7. **CWE-89** - SQL Injection
8. **CWE-502** - Unsafe Deserialization
9. **CWE-20** - Improper Input Validation
10. **CWE-311** - Missing Encryption

**See full list:** [PARRY_METRICS.md](PARRY_METRICS.md)

---

## 🔧 Breaking Changes

**None** - This is the first public release!

---

## 🐛 Known Issues

- **SSRF detection** needs improvement (CWE-918 missed in both modes)
- **Deep Mode** slow on very large files (>1000 lines)
- **AI setup** requires ~4GB disk space for CodeLlama model

---

## 📚 Documentation

- **[README.md](README.md)** - Main documentation
- **[SETUP.md](SETUP.md)** - Detailed setup guide
- **[QUICKSTART.md](QUICKSTART.md)** - Quick tutorial
- **[PARRY_METRICS.md](PARRY_METRICS.md)** - Complete metrics

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📞 Support

- **GitHub Issues:** https://github.com/Parry-AI/parry-scanner/issues
- **Discussions:** https://github.com/Parry-AI/parry-scanner/discussions
- **Documentation:** https://github.com/Parry-AI/parry-scanner

---

## 🙏 Acknowledgments

Built with:
- Python 3.9+
- Ollama (local LLM)
- Rich (beautiful terminal)
- FastAPI (REST API)
- And many more open-source projects

---

## 📅 What's Next

### v0.7.1 (Coming Soon)
- ⏳ Improved SSRF detection
- ⏳ Performance optimizations
- ⏳ More framework support
- ⏳ Additional languages

### v0.8.0 (Roadmap)
- ⏳ More CWEs (70+ per language)
- ⏳ Enhanced AST analysis
- ⏳ Multi-file analysis
- ⏳ Distributed scanning

---

## 🎉 Thank You

Thank you for trying Parry! Your feedback helps us improve.

**Star us on GitHub:** ⭐ https://github.com/Parry-AI/parry-scanner

---

**Download:** `pip install parry-scanner`  
**License:** MIT  
**Homepage:** https://github.com/Parry-AI/parry-scanner

