# Parry Release & Version Management Guide

## Overview

This document describes how to release new versions of Parry, push updates, and manage version distribution.

---

## Version Numbering

### Semantic Versioning (SemVer)
```
MAJOR.MINOR.PATCH

- MAJOR: Breaking changes, major API changes
- MINOR: New features, non-breaking additions
- PATCH: Bug fixes, minor updates
```

**Current Version:** `0.6.0` (Beta)
**Example Progression:**
- `0.6.0` → `0.6.1` (patch: bug fix)
- `0.6.0` → `0.7.0` (minor: new features)
- `0.6.0` → `1.0.0` (major: stable release)

---

## Release Process

### Step 1: Preparation

**Check Current State:**
```bash
# Verify all tests pass
pytest tests/ -v

# Check version in multiple places
grep -r "version.*=" setup.py pyproject.toml parry/cli.py | grep -v "^Binary"

# Verify no blocking issues
parry scan . --mode fast
```

**Update Version Numbers:**
1. `setup.py` - Main version
2. `setup_compiled.py` - Build version
3. `pyproject.toml` - Package version
4. `parry/cli.py` - CLI version display
5. `README.md` - Documentation version

**Example:**
```bash
# Update all versions at once
sed -i '' 's/version="0.6.0"/version="0.6.1"/g' setup.py setup_compiled.py pyproject.toml
sed -i '' 's/version="0.6.0"/version="0.6.1"/g' parry/cli.py README.md
```

---

### Step 2: Build Distribution

#### Standard Build (Development/Source)
```bash
# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build wheel and source distribution
python -m build --wheel --sdist

# Verify build
ls -lh dist/
# Should see: parry_scanner-0.6.0-py3-none-any.whl
#            parry_scanner-0.6.0.tar.gz
```

#### Protected Build (Enterprise/IP Protection)
```bash
# Use the protected build script
bash build_protected.sh

# Choose option:
# 1. Development (source visible)
# 2. Distribution (Cython compiled)
# 3. Enterprise (compiled + obfuscated)
```

---

### Step 3: Testing Distribution

**Test Local Installation:**
```bash
# Install from wheel locally
pip install dist/parry_scanner-0.6.0-py3-none-any.whl --force-reinstall

# Verify installation
parry --version
parry license
parry scan examples/ --mode fast

# Run smoke tests
python -m pytest tests/ -v --tb=short
```

**Test on Clean Environment:**
```bash
# Create new virtual environment
python -m venv test_install
source test_install/bin/activate

# Install from wheel
pip install dist/parry_scanner-0.6.0-py3-none-any.whl

# Test basic functionality
parry scan examples/ -f json
parry license

# Clean up
deactivate
rm -rf test_install
```

---

### Step 4: Create Release Notes

**Generate Release Notes:**
```bash
# Create changelog entry
cat > CHANGELOG_v0.6.0.md << 'EOF'
# Parry v0.6.0 Release Notes

## Release Date
November 2, 2025

## Overview
Beta release with comprehensive language support, AI detection, and enterprise features.

## What's New
### Features
- Multi-language support (8 languages)
- AI-powered deep mode (75% recall)
- License protection system
- [Add key features]

### Improvements
- Enhanced Java AST detection
- Expanded CWE coverage to 15+ per language
- [Add improvements]

### Bug Fixes
- Fixed [specific issue]
- [Another fix]

## Breaking Changes
None

## Migration Guide
No migration needed for 0.6.0 beta.
EOF
```

---

### Step 5: Tag and Commit

**Create Git Tag:**
```bash
# Commit all changes
git add .
git commit -m "Release v0.6.0: Beta with comprehensive features"

# Create and push tag
git tag -a v0.6.0 -m "Release v0.6.0"
git push origin main --tags
```

**Alternative: Release Branch**
```bash
# Create release branch
git checkout -b release/v0.6.0
git push origin release/v0.6.0

# Merge to main after testing
git checkout main
git merge release/v0.6.0
git push origin main
```

---

### Step 6: Publish to PyPI

**Prerequisites:**
- PyPI account: https://pypi.org/account/register/
- API token: https://pypi.org/manage/account/token/

**First-Time Setup:**
```bash
# Create ~/.pypirc
cat > ~/.pypirc << EOF
[distutils]
index-servers =
    pypi

[pypi]
username = __token__
password = pypi-XXXXXXXXXXXXXXXXXXXXX
EOF

chmod 600 ~/.pypirc
```

**Upload to PyPI:**
```bash
# Upload using twine (recommended)
pip install twine
twine upload dist/*

# Alternative: Use python -m build + twine
twine upload dist/parry_scanner-0.6.0-*

# Test first with TestPyPI
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ parry-scanner
```

---

### Step 7: GitHub Release

**Create GitHub Release:**

1. Go to: https://github.com/yourusername/parry/releases/new
2. **Tag:** Select `v0.6.0` or create new tag
3. **Title:** "Parry v0.6.0 - Beta Release"
4. **Description:** Copy from `CHANGELOG_v0.6.0.md`
5. **Attach files:**
   - `parry_scanner-0.6.0-py3-none-any.whl`
   - `parry_scanner-0.6.0.tar.gz`
   - `README.md`
6. **Publish** release

**Or use GitHub CLI:**
```bash
# Install GitHub CLI if not installed
brew install gh  # macOS
# or: curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | ...

# Create release
gh release create v0.6.0 \
  --title "Parry v0.6.0 - Beta Release" \
  --notes "$(cat CHANGELOG_v0.6.0.md)" \
  dist/parry_scanner-0.6.0-*
```

---

### Step 8: Update Documentation

**Documentation Updates:**
```bash
# Update README with new version
sed -i '' 's/v0.4.0/v0.6.0/g' README.md

# Commit and push
git add README.md
git commit -m "Update README for v0.6.0"
git push origin main
```

**Website Updates:**
- Update version number on website
- Add release notes to blog
- Update pricing if changed
- Deploy website with new info

---

## Distribution Channels

### 1. PyPI (Primary)
**Command:** `pip install parry-scanner`

**Advantages:**
- Standard Python distribution
- Automatic updates: `pip install --upgrade parry-scanner`
- Works with all Python package managers

**Upload Command:**
```bash
twine upload dist/parry_scanner-0.6.0-*
```

---

### 2. GitHub Releases (Manual Download)
**URL:** https://github.com/yourusername/parry/releases

**Advantages:**
- Direct download for non-Python users
- Release notes and changelogs
- Source code downloads

**Upload Command:**
```bash
gh release upload v0.6.0 dist/*
```

---

### 3. Docker Hub (Optional)
**Future:** Containerized distribution

```dockerfile
# Dockerfile
FROM python:3.11-slim
RUN pip install parry-scanner
ENTRYPOINT ["parry"]
```

**Build and Push:**
```bash
docker build -t parry/parry:0.6.0 .
docker tag parry/parry:0.6.0 parry/parry:latest
docker push parry/parry:0.6.0
docker push parry/parry:latest
```

---

### 4. Homebrew (macOS, Optional)
**Future:** Native macOS installation

```bash
# Create formula
brew create --tap parry/tap https://github.com/parry/parry/releases/download/v0.6.0/parry-scaner-0.6.0.tar.gz

# Install via Homebrew
brew install parry/tap/parry-scanner
```

---

## Automatic Updates

### For Users (How They Get Updates)

**PyPI Installation:**
```bash
# Check current version
parry --version

# Update to latest
pip install --upgrade parry-scanner

# Update to specific version
pip install parry-scanner==0.6.0

# Check for updates
pip list --outdated | grep parry-scanner
```

**Git Installation:**
```bash
# Pull latest changes
cd /path/to/parry
git pull origin main

# Reinstall
pip install -e .
```

---

## Protected Distribution (Enterprise)

### Building Protected Versions

**Three Build Types:**

1. **Development:** Standard Python, source visible
   ```bash
   python setup.py bdist_wheel
   ```

2. **Distribution:** Cython compiled, source hidden
   ```bash
   python setup_compiled.py bdist_wheel --distribution
   ```

3. **Enterprise:** Compiled + obfuscated + license checks
   ```bash
   python setup_compiled.py bdist_wheel --enterprise
   ```

**Using Build Script:**
```bash
bash build_protected.sh

# Interactive menu:
# 1. Development build
# 2. Distribution build
# 3. Enterprise build
```

---

## Version Compatibility

### Backward Compatibility

**0.6.0 → 0.6.1 (Patch):**
- ✅ Same CLI interface
- ✅ Same API interface
- ✅ Same file formats
- ✅ Same configuration

**0.6.0 → 0.7.0 (Minor):**
- ✅ CLI commands work
- ✅ API endpoints work
- ⚠️ New features added
- ⚠️ New configuration options

**0.6.0 → 1.0.0 (Major):**
- ⚠️ Breaking API changes
- ⚠️ Breaking CLI changes
- ⚠️ Configuration format changes
- 📝 Migration guide provided

---

## Hotfix Process

### Critical Bug Fixes

**Emergency Release (0.6.0 → 0.6.1):**

1. **Create hotfix branch:**
   ```bash
   git checkout -b hotfix/v0.6.1 main
   ```

2. **Fix critical bug:**
   ```bash
   # Make fix
   git add .
   git commit -m "Fix: Critical issue with [describe]"
   ```

3. **Test extensively:**
   ```bash
   pytest tests/
   parry scan [critical codebases]
   ```

4. **Release quickly:**
   ```bash
   # Update version
   sed -i '' 's/0.6.0/0.6.1/g' setup.py pyproject.toml parry/cli.py
   
   # Build and publish
   python -m build
   twine upload dist/*
   
   # Tag
   git tag v0.6.1
   git push origin main --tags
   ```

5. **Notify users:**
   - GitHub release notes
   - Email to customers (if you have list)
   - Social media announcement

---

## Continuous Deployment (CI/CD)

### GitHub Actions Integration

**Automated Release:**
```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install build twine
      
      - name: Build distribution
        run: python -m build
      
      - name: Upload to PyPI
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: twine upload dist/*
      
      - name: Create GitHub Release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ github.ref }}
```

**Trigger:** Push a tag starting with `v`
```bash
git tag v0.6.1
git push origin v0.6.1
```

---

## Rollback Process

### If Release Has Critical Issues

**Immediate Actions:**

1. **Mark version deprecated on PyPI:**
   ```bash
   # Go to PyPI project page
   # https://pypi.org/project/parry-scanner/0.6.0/
   # Click "Manage" → "Remove release"
   ```

2. **Publish hotfix immediately:**
   ```bash
   # Version 0.6.1 with critical fix
   # Fast-track through testing
   # Publish within 24 hours
   ```

3. **Notify all users:**
   - GitHub release notes (mark as deprecated)
   - Email customers with upgrade instructions
   - Social media announcement

**Rollback Commands:**
```bash
# Unpublish from PyPI (requires special permissions)
# Contact PyPI admins if needed

# Recommend users downgrade
pip install parry-scanner==0.5.0  # Previous stable
```

---

## License Key Distribution

### For Paid Versions

**Enterprise Distribution:**

1. **Generate License Keys:**
   ```bash
   # Your license server generates keys
   python scripts/generate_license.py --tier=enterprise --duration=365
   # Output: ENTERPRISE-XXXX-XXXX-XXXX
   ```

2. **Distribute Keys:**
   - Send to customer via secure channel
   - Customer installs: `parry license install ENTERPRISE-XXXX-XXXX-XXXX`
   - Key validates with your server

3. **Track Distribution:**
   - License server logs all validations
   - Monitor usage patterns
   - Detect piracy attempts

---

## Version Check on Startup

**Automatic Update Notifications:**

```python
# In parry/cli.py main()
def check_for_updates():
    """Check if newer version is available"""
    try:
        response = requests.get('https://pypi.org/pypi/parry-scanner/json', timeout=2)
        latest_version = response.json()['info']['version']
        current_version = get_version()
        
        if version_compare(latest_version, current_version) > 0:
            console.print(f"\n[yellow]📦 Update available: {latest_version}[/yellow]")
            console.print(f"[dim]Run: pip install --upgrade parry-scanner[/dim]\n")
    except:
        pass  # Fail silently
```

**User Experience:**
```
$ parry scan code/

📦 Update available: v0.6.1
Run: pip install --upgrade parry-scanner

Scanning codebase...
```

---

## Release Checklist

### Pre-Release
- [ ] All tests passing (62/62)
- [ ] Version numbers updated in all files
- [ ] Changelog written
- [ ] Release notes prepared
- [ ] Documentation updated
- [ ] Protected build tested (if applicable)

### Build
- [ ] Standard wheel built successfully
- [ ] Source distribution created
- [ ] Protected version built (if applicable)
- [ ] All artifacts tested locally

### Release
- [ ] Git tag created
- [ ] Tag pushed to repository
- [ ] PyPI upload successful
- [ ] GitHub release created
- [ ] Website updated

### Post-Release
- [ ] Announcement sent
- [ ] Users notified (if applicable)
- [ ] Monitoring release for issues
- [ ] Customer support ready

---

## Quick Commands Reference

### Build
```bash
# Standard
python -m build

# Protected
bash build_protected.sh

# Specific version
python setup.py bdist_wheel sdist
```

### Test
```bash
pytest tests/
parry scan examples/
parry --version
```

### Release
```bash
# Tag
git tag -a v0.6.0 -m "Release v0.6.0"
git push origin v0.6.0

# Upload to PyPI
twine upload dist/*

# GitHub release
gh release create v0.6.0 dist/* --notes-file CHANGELOG.md
```

### Rollback
```bash
# Downgrade users
pip install parry-scanner==0.5.0

# Remove tag (local)
git tag -d v0.6.0

# Remove tag (remote)
git push origin --delete v0.6.0
```

---

## Summary

**Release Process Flow:**
```
1. Prepare → 2. Build → 3. Test → 4. Tag → 5. Publish
   ↓           ↓           ↓        ↓         ↓
Version   Compile     Verify    Git tag   PyPI/GitHub
Update    Package    Quality   Release   Distribution
```

**Estimated Time:**
- Preparation: 30 minutes
- Build: 5 minutes
- Testing: 15 minutes
- Publishing: 10 minutes
- **Total: ~1 hour**

**Frequency:**
- **Hotfixes:** As needed
- **Minor releases:** Monthly
- **Major releases:** Quarterly

---

**Questions?** See `COMPETITIVE_ANALYSIS.md` and `FINAL_BETA_READINESS.md` for more context.

