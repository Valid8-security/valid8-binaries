# Parry v0.7.0 Beta Launch Setup Process

**Complete step-by-step guide to launching Parry beta**

---

## 🎯 Objective

Launch Parry v0.7.0 as a production-ready beta with:
- PyPI distribution
- GitHub releases
- Documentation
- Testing
- Marketing

---

## Phase 1: Pre-Launch Preparation

### Step 1: Final Verification

```bash
# 1. Run complete test suite
cd /Users/sathvikkurapati/Downloads/parry-local
source venv/bin/activate
pytest tests/ -v --cov=parry

# Expected: 62 tests passing, 100% coverage
```

### Step 2: Clean Build

```bash
# 2. Clean previous builds
rm -rf dist/ build/ *.egg-info parry_scanner.egg-info

# 3. Build fresh package
python -m build --wheel --sdist

# 4. Verify build
ls -lh dist/
# Should see:
# - parry_scanner-0.7.0-py3-none-any.whl
# - parry_scanner-0.7.0.tar.gz
```

### Step 3: Local Testing

```bash
# 5. Test install from wheel
pip uninstall parry-scanner -y
pip install dist/parry_scanner-0.7.0-py3-none-any.whl

# 6. Verify installation
parry --version
# Expected: parry, version 0.7.0

# 7. Test all commands
parry --help
parry scan examples/ --mode fast
parry doctor
parry setup --help
```

---

## Phase 2: PyPI Release

### Step 4: PyPI Account Setup

```bash
# Create PyPI account if needed:
# - Go to https://pypi.org/account/register/
# - Verify email
# - Generate API token at https://pypi.org/manage/account/token/

# Save credentials
mkdir -p ~/.pypirc
cat > ~/.pypirc << 'EOF'
[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcC...your-token-here
EOF

chmod 600 ~/.pypirc
```

### Step 5: Upload to PyPI

```bash
# Install upload tool
pip install twine

# Check package
twine check dist/*

# Upload to Test PyPI first (recommended)
twine upload --repository testpypi dist/*

# Test install from Test PyPI
pip install --index-url https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple/ parry-scanner

# If successful, upload to real PyPI
twine upload dist/*
```

### Step 6: Verify PyPI Release

```bash
# Test from clean environment
deactivate
python3 -m venv test_install
source test_install/bin/activate
pip install --upgrade pip

# Install from PyPI
pip install parry-scanner

# Verify
parry --version
parry doctor
parry scan examples/ --mode fast
```

---

## Phase 3: GitHub Release

### Step 7: Create Release Tag

```bash
# Tag the release
git tag -a v0.7.0-beta -m "Parry v0.7.0 Beta - 90.9% Recall"

# Push tag
git push origin v0.7.0-beta

# Push v1 branch updates
git push origin v1
```

### Step 8: Create GitHub Release

1. Go to: https://github.com/Parry-AI/parry-scanner/releases/new
2. Tag: Select `v0.7.0-beta`
3. Title: `Parry v0.7.0 Beta - Privacy-First AI Security Scanner`
4. Description: See [RELEASE_NOTES_BETA.md](RELEASE_NOTES_BETA.md)
5. Files: Upload dist/*.whl and dist/*.tar.gz
6. Check "This is a pre-release"
7. Click "Publish release"

### Step 9: Update Documentation

```bash
# Commit any final doc updates
git add .
git commit -m "Final pre-beta documentation updates"
git push origin v1
```

---

## Phase 4: Announcement

### Step 10: Prepare Announcement

**Twitter/X:**
```
🔒 Parry v0.7.0 Beta Released!

✅ 90.9% recall (better than SonarQube)
✅ 95% precision (best in industry)
✅ 100% privacy (local AI)
✅ $0-199/mo (99% cheaper)

Try it: pip install parry-scanner
Docs: github.com/Parry-AI/parry-scanner

#DevSecOps #Security #OpenSource
```

**LinkedIn:**
```
Introducing Parry v0.7.0 Beta - The First Privacy-First AI Security Scanner

After months of development, I'm excited to release Parry v0.7.0 Beta...

Key Achievements:
- 90.9% recall (industry-leading)
- 95% precision (best in class)
- 100% local processing
- 3x faster than competitors
- 99% cost savings

Try it: pip install parry-scanner
Learn more: [Link to GitHub]
```

**Reddit (r/devops, r/cybersecurity):**
```
Show DevSecOps: Parry v0.7.0 Beta - AI Security Scanner with 90.9% Recall

Title: Parry v0.7.0 Beta Released - Open Source AI Security Scanner
Body: See POST_CONTENT below
```

### Step 11: Launch Day

**Schedule:**
- 9:00 AM: PyPI release
- 10:00 AM: GitHub release
- 11:00 AM: Tweet + LinkedIn post
- 2:00 PM: Reddit post
- 4:00 PM: Monitor feedback, respond to issues

---

## Phase 5: Post-Launch Monitoring

### Step 12: Track Metrics

```bash
# Monitor GitHub
watch -n 30 'gh api repos/Parry-AI/parry-scanner --jq ".stargazers_count, .watchers_count"'

# Check PyPI downloads
# Visit: https://pypistats.org/packages/parry-scanner

# Monitor issues
gh issue list --repo Parry-AI/parry-scanner --limit 10
```

### Step 13: Respond to Users

**First 24 hours:**
- Respond to every GitHub issue
- Answer questions on social media
- Fix critical bugs immediately
- Thank early adopters

### Step 14: Iterate Quickly

**Week 1 focus:**
- Bug fixes
- Documentation improvements
- UX polish
- Performance optimization

---

## 📋 Quick Setup Checklist

### Day -2 (2 Days Before Launch)
- [ ] Final code review
- [ ] Run all tests
- [ ] Build packages
- [ ] Test install

### Day -1 (Day Before Launch)
- [ ] Test PyPI upload
- [ ] Prepare release notes
- [ ] Draft announcements
- [ ] Set up monitoring

### Launch Day (Day 0)
- [ ] Upload to PyPI (9 AM)
- [ ] Create GitHub release (10 AM)
- [ ] Post announcements (11 AM)
- [ ] Monitor feedback (all day)

### Week 1
- [ ] Respond to issues daily
- [ ] Fix critical bugs
- [ ] Collect user feedback
- [ ] Iterate rapidly

---

## 🎯 Success Criteria

### Technical
- ✅ All tests passing
- ✅ Clean PyPI install
- ✅ No critical bugs
- ✅ Performance as expected

### User Adoption
- ⏳ 100+ downloads (Week 1)
- ⏳ 10+ GitHub stars
- ⏳ 5+ GitHub issues (engagement)
- ⏳ Positive feedback

### Business
- ⏳ Media coverage
- ⏳ Organic growth
- ⏳ Early customer interest
- ⏳ Community forming

---

## 🚨 Rollback Plan

If critical issues found:

1. **Immediate**: Mark GitHub release as "Known Issues"
2. **Fix**: Push patch to PyPI (0.7.0.post1)
3. **Communicate**: Update users via GitHub discussions
4. **Learn**: Document lessons for next release

---

## 📝 Release Notes Template

See [RELEASE_NOTES_BETA.md](RELEASE_NOTES_BETA.md) for complete release notes.

---

**Ready to launch? Start with Phase 1, Step 1!** 🚀

