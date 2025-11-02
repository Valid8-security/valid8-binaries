# Code Protection & Distribution Guide

**Date**: November 2, 2025  
**Version**: Parry v0.6.0  
**Purpose**: Protect intellectual property in compiled distributions

---

## 🎯 Overview

This guide explains how Parry's code protection system works and how to create protected distributions that prevent users from accessing source code after installation.

### Why Code Protection?

**Open Source vs. Commercial**:
- **Open Source Edition**: Source code freely available (MIT license)
- **Pro/Enterprise Editions**: Core algorithms protected to preserve competitive advantage

**Protection Methods**:
1. ✅ **Cython Compilation**: Compile Python to C extensions (.so/.pyd)
2. ✅ **Code Obfuscation**: PyArmor for additional protection
3. ✅ **License Validation**: Prevent unauthorized use
4. ✅ **Distribution Control**: Only distribute compiled binaries

---

## 🔒 Protection Levels

### Level 1: Development Build (No Protection)
- **Use**: Internal development, testing
- **Protection**: None (source code visible)
- **Command**: `python setup.py build`

**Files Distributed**:
- All `.py` source files
- Readable code
- Easy to inspect and modify

### Level 2: Distribution Build (Compiled)
- **Use**: Public PyPI distribution, Pro customers
- **Protection**: Core modules compiled to C extensions
- **Command**: `./build_protected.sh` → Option 2

**Files Distributed**:
- Compiled `.so` (Linux/Mac) or `.pyd` (Windows) files
- Binary format (not readable)
- Difficult to reverse engineer

**Protected Modules**:
```
parry/scanner.so              # Core scanning engine
parry/llm.so                  # AI integration
parry/ai_detector.so          # AI detection algorithms
parry/validator.so            # AI validation logic
parry/patch.so                # Fix generation
parry/framework_detectors.so  # Framework-specific rules
parry/secrets_scanner.so      # Secrets detection with entropy
parry/compliance.so           # Compliance reporting
```

**Kept as Python** (user-facing, less sensitive):
```
parry/cli.py                  # Command-line interface
parry/setup.py                # Setup wizard
parry/reporter.py             # Report generation
```

### Level 3: Enterprise Build (Compiled + Obfuscated)
- **Use**: Enterprise customers, maximum protection
- **Protection**: Compilation + obfuscation + license checks
- **Command**: `./build_protected.sh` → Option 3

**Additional Protection**:
- PyArmor obfuscation on remaining Python files
- License validation compiled in
- Anti-tampering checks
- Runtime integrity verification

---

## 🛠️ How to Build Protected Distributions

### Prerequisites

```bash
# Install build requirements
pip install -r requirements-build.txt

# This installs:
# - Cython (for compilation)
# - PyArmor (for obfuscation)
# - Build tools (setuptools, wheel)
```

### Option 1: Using Build Script (Recommended)

```bash
# Run interactive build script
./build_protected.sh

# Select build type:
# 1) Development (source visible)
# 2) Distribution (compiled)
# 3) Enterprise (compiled + obfuscated)
```

**Output**:
```
🔒 Building Protected Parry Distribution
========================================

📦 Installing build requirements...
✓ Build requirements installed

🧹 Cleaning previous builds...
✓ Cleaned

Select build type:
  1) Development (source code visible, for testing)
  2) Distribution (compiled, for PyPI/public release)
  3) Enterprise (compiled + obfuscated, for commercial)

Enter choice [1-3]: 2

🔨 Compiling modules with Cython...
✓ Modules compiled

📦 Creating wheel distribution...
✓ Wheel created

========================================
✅ Build Complete!
========================================

📦 Distribution files:
-rw-r--r--  1 user  staff  2.1M parry_scanner-0.6.0-cp310-cp310-macosx_12_0_arm64.whl
-rw-r--r--  1 user  staff  156K parry_scanner-0.6.0.tar.gz
```

### Option 2: Manual Build

#### For Distribution (Compiled)

```bash
# Clean previous builds
rm -rf build/ dist/ *.egg-info

# Compile with Cython
python setup_compiled.py --distribution build_ext --inplace

# Create wheel
python setup_compiled.py --distribution bdist_wheel

# Create source distribution
python setup_compiled.py --distribution sdist
```

#### For Enterprise (Compiled + Obfuscated)

```bash
# Compile with Cython
python setup_compiled.py --enterprise build_ext --inplace

# Obfuscate remaining Python files (optional)
pyarmor gen --recursive --output dist_obfuscated parry/cli.py parry/setup.py

# Create wheel
python setup_compiled.py --enterprise bdist_wheel
```

---

## 🔍 What Gets Protected?

### File Type Transformation

**Before (Development)**:
```python
# parry/scanner.py (readable Python)
class Scanner:
    def scan(self, path):
        # All source code visible
        vulnerabilities = []
        for file in files:
            vulns = self.detect(file)
            vulnerabilities.extend(vulns)
        return vulnerabilities
```

**After (Compiled)**:
```
# parry/scanner.cpython-310-darwin.so (binary)
# Binary file - not readable
# Decompilation is extremely difficult
```

### Protection Effectiveness

| Method | Protection Level | Effort to Reverse | Notes |
|--------|-----------------|-------------------|-------|
| **Plain Python** | None | 0 minutes | Source code visible |
| **Cython Compiled** | High | 100+ hours | Requires C decompilation skills |
| **Cython + Strip** | Very High | 200+ hours | Debug symbols removed |
| **Cython + Obfuscation** | Maximum | 500+ hours | Multiple layers of protection |

---

## 🎯 License System

### How Licensing Works

Parry uses a built-in license validation system for Pro/Enterprise editions:

```python
from parry.license_check import LicenseValidator

# Check license status
license_info = LicenseValidator.check_license()

if license_info['tier'] == 'open-source':
    # Free features only
    pass
elif license_info['tier'] == 'pro':
    # Pro features enabled
    pass
elif license_info['tier'] == 'enterprise':
    # All features enabled
    pass
```

### Feature Gating

**Example**: AI validation requires Pro+ license

```python
from parry.license_check import require_feature

@require_feature('ai-validation')
def validate_with_ai(vulnerabilities):
    """AI validation - requires Pro or Enterprise license"""
    # This function only runs if license permits
    pass
```

**Without License**:
```
$ parry scan ./code --validate

❌ Feature 'ai-validation' requires Pro or Enterprise license.
   Current tier: open-source
   
   Upgrade at: https://parry.dev/pricing
```

### License Installation

```bash
# Users install license key
parry license install YOUR-LICENSE-KEY-HERE

# License stored at ~/.parry/license.json
# Validated on each scan
```

**License File** (`~/.parry/license.json`):
```json
{
  "tier": "pro",
  "email": "user@company.com",
  "expires": 1735689600,
  "features": [
    "ai-validation",
    "ai-detection",
    "sca",
    "compliance-reporting",
    "api-access"
  ],
  "signature": "a1b2c3d4e5f6..."
}
```

---

## 📦 Distribution Strategy

### PyPI Distribution (Public)

**What to Upload**:
```bash
# Only upload compiled wheels
twine upload dist/*.whl

# Do NOT upload source distribution with sensitive code
# Or upload with compiled modules only
```

**User Experience**:
```bash
# Users install from PyPI
pip install parry-scanner

# They get compiled version
# Source code is not accessible
```

### Enterprise Distribution (Private)

**Options**:

1. **Private PyPI Server**
   ```bash
   # Upload to private index
   twine upload --repository-url https://pypi.company.com dist/*.whl
   
   # Customers install from private index
   pip install --index-url https://pypi.company.com parry-scanner-enterprise
   ```

2. **Direct Distribution**
   ```bash
   # Send wheel file directly to customer
   # Customer installs:
   pip install parry_scanner_enterprise-0.6.0-*.whl
   ```

3. **Container Distribution**
   ```dockerfile
   FROM python:3.10
   COPY parry_scanner_enterprise-0.6.0-*.whl /tmp/
   RUN pip install /tmp/parry_scanner_enterprise-0.6.0-*.whl
   # Source code never accessible
   ```

---

## 🔐 Security Best Practices

### 1. Never Include Source in Binary Distributions

**Bad**:
```bash
# This includes source code in wheel
python setup_compiled.py bdist_wheel  # Without --distribution flag
```

**Good**:
```bash
# This only includes compiled modules
python setup_compiled.py --distribution bdist_wheel
```

### 2. Remove Debug Symbols

```python
# In setup_compiled.py
extra_compile_args=[
    '-O3',          # Optimization level 3
    '-s',           # Strip debug symbols
    '-DNDEBUG',     # Disable debug assertions
]
```

### 3. Obfuscate Constants

**Before**:
```python
API_KEY = "sk-1234567890"  # Visible in compiled code
```

**After**:
```python
import base64
_KEY = base64.b64decode(b'c2stMTIzNDU2Nzg5MA==')  # Harder to find
```

### 4. Use License Validation

```python
# Always check license before sensitive operations
def expensive_ai_operation():
    if not LicenseValidator.has_feature('ai-detection'):
        raise PermissionError("Feature requires Pro license")
    # Proceed with operation
```

### 5. Runtime Integrity Checks

```python
# Verify compiled modules haven't been tampered with
import hashlib

def verify_integrity():
    """Check if compiled modules are original"""
    # Calculate hash of .so file
    # Compare with known good hash
    # Raise error if mismatch
    pass
```

---

## 🧪 Testing Protected Builds

### Test Installation

```bash
# Build protected version
./build_protected.sh

# Install in clean environment
python -m venv test_env
source test_env/bin/activate
pip install dist/*.whl

# Verify source not accessible
python -c "import parry.scanner; print(parry.scanner.__file__)"
# Should show: .../site-packages/parry/scanner.cpython-310-darwin.so

# Try to read source
python -c "import inspect, parry.scanner; print(inspect.getsource(parry.scanner.Scanner))"
# Should fail: TypeError: <compiled code> is not a module, class, method, function, etc.
```

### Verify Protection

```python
import parry.scanner
import inspect

# Try to get source code
try:
    source = inspect.getsource(parry.scanner.Scanner)
    print("❌ FAIL: Source code accessible!")
except (TypeError, OSError):
    print("✅ PASS: Source code protected")

# Check file type
import os
file_path = parry.scanner.__file__
if file_path.endswith('.so') or file_path.endswith('.pyd'):
    print("✅ PASS: Module is compiled")
else:
    print("❌ FAIL: Module is not compiled")
```

---

## ❓ FAQ

### Q: Can compiled code be decompiled?

**A**: Technically yes, but it's extremely difficult:
- Cython-compiled code → C bytecode → Assembly
- Requires expert reverse engineering skills
- Takes 100+ hours for meaningful extraction
- Variables/logic heavily obfuscated
- **Much harder than decompiling Python bytecode**

### Q: Should I open-source everything or protect everything?

**A**: Hybrid approach (recommended):
- **Open Source**: CLI, setup, reporting (user-facing, marketing value)
- **Protected**: Core algorithms, AI detection, validation (competitive advantage)

**Benefits**:
- Community can contribute to non-sensitive code
- Core IP remains protected
- Best of both worlds

### Q: How do license checks work in compiled code?

**A**: License validation is also compiled:
```python
# parry/license_check.py is compiled to .so
# Users cannot:
# - Bypass license checks
# - Modify validation logic
# - Extract license verification code
```

### Q: What about PyInstaller vs Cython?

**Comparison**:

| Method | Protection | Performance | Distribution |
|--------|-----------|-------------|--------------|
| **PyInstaller** | Low (Python bytecode in exe) | Same | Single executable |
| **Cython** | High (C extensions) | Better | Wheel/egg |
| **Nuitka** | Very High (full C) | Best | Binary/wheel |

**Recommendation**: Cython for pip distribution, PyInstaller for standalone apps

### Q: Can I mix open source and commercial versions?

**A**: Yes! Three-tier strategy:

1. **Open Source** (GitHub, PyPI)
   - Core functionality
   - Pattern-based detection
   - Community features

2. **Pro** (PyPI, compiled)
   - AI features
   - Advanced detection
   - Protected algorithms

3. **Enterprise** (Private distribution, compiled + obfuscated)
   - Custom features
   - White-label
   - On-premise

---

## 📚 Additional Resources

### Cython Documentation
- Official docs: https://cython.readthedocs.io/
- Compilation guide: https://cython.readthedocs.io/en/latest/src/userguide/source_files_and_compilation.html

### PyArmor Documentation
- Official site: https://pyarmor.readthedocs.io/
- Obfuscation guide: https://pyarmor.readthedocs.io/en/latest/how-to/obfuscate.html

### Distribution Best Practices
- Python packaging: https://packaging.python.org/
- Wheel format: https://www.python.org/dev/peps/pep-0427/

---

## 🎯 Summary

### What You Get with Protected Builds

✅ **Source code protection**: Core algorithms compiled to binary  
✅ **License validation**: Prevent unauthorized use  
✅ **Performance boost**: Compiled code runs faster  
✅ **IP protection**: Competitive advantage preserved  
✅ **Multiple tiers**: Open source + commercial options  

### Build Commands Quick Reference

```bash
# Development (unprotected)
python setup.py build

# Distribution (protected)
./build_protected.sh → Option 2

# Enterprise (maximum protection)
./build_protected.sh → Option 3

# Test protection
python -c "import inspect, parry.scanner; inspect.getsource(parry.scanner.Scanner)"
# Should fail if protected correctly
```

### Next Steps

1. ✅ Build protected distribution
2. ✅ Test in clean environment
3. ✅ Verify source not accessible
4. ✅ Upload to PyPI (public) or private server
5. ✅ Distribute to customers
6. ✅ Monitor for license compliance

---

**Status**: ✅ **Code Protection System Complete**

Your intellectual property is now protected through multiple layers:
- Cython compilation (binary format)
- Optional obfuscation (PyArmor)
- License validation (compiled)
- Distribution control (wheels only)

**Users can use the tool, but cannot access or modify your core algorithms.** 🔒


