# Parry Repository Reorganization Plan

**Date**: November 3, 2025  
**Goal**: Create a clean, professional file hierarchy following Python best practices  
**Principle**: Zero functionality loss, improved maintainability  

---

## Current Issues

1. **Root Directory Clutter**: 30+ files in root directory
2. **Mixed Concerns**: Documentation, scripts, builds, configs all at root level
3. **Inconsistent Naming**: Some use underscores, some use hyphens
4. **Poor Discoverability**: Hard to find specific files
5. **No Clear Separation**: Dev tools mixed with distribution files

## Proposed New Structure

```
parry-scanner/
├── README.md                          # Main documentation (keep at root)
├── LICENSE                            # License file (keep at root)
├── pyproject.toml                     # Modern Python config (keep at root)
├── setup.py                           # Package setup (keep at root)
├── requirements.txt                   # Dependencies (keep at root)
├── .gitignore                         # Git config (keep at root)
├── .gitlab-ci.yml                     # CI config (keep at root)
├── Jenkinsfile                        # CI config (keep at root)
├── MANIFEST.in                        # Package manifest (keep at root)
│
├── parry/                             # Main package (no changes)
│   ├── __init__.py
│   ├── scanner.py
│   ├── cli.py
│   ├── (all existing modules)
│   └── language_support/
│
├── tests/                             # Test suite (no changes)
│   ├── __init__.py
│   ├── test_scanner.py
│   └── (all test files)
│
├── examples/                          # Example vulnerable code (no changes)
│   ├── vulnerable_code.py
│   ├── vulnerable_code.js
│   └── (all example files)
│
├── docs/                              # All documentation (NEW)
│   ├── api/                           # API documentation
│   │   └── API_REFERENCE.md
│   ├── guides/                        # User guides
│   │   ├── QUICKSTART.md
│   │   ├── SETUP_GUIDE.md
│   │   ├── CONTRIBUTING.md
│   │   └── QUICK_DEMO.md
│   ├── benchmarks/                    # Performance docs
│   │   ├── BENCHMARK_SUMMARY.md
│   │   ├── COMPREHENSIVE_BENCHMARK_RESULTS.md
│   │   ├── COMPETITIVE_ANALYSIS.md
│   │   ├── PARRY_METRICS.md
│   │   └── SCAN_SPEED_EXAMPLES.md
│   ├── testing/                       # Test documentation
│   │   ├── TEST_INSTRUCTIONS.md
│   │   └── DEEP_MODE_TEST_INSTRUCTIONS.md
│   ├── security/                      # Security documentation
│   │   └── SECURITY_COVERAGE_ANALYSIS.md
│   ├── development/                   # Developer docs
│   │   ├── DOCUMENTATION_COMPLETE.md
│   │   ├── UPDATE_SUMMARY.md
│   │   └── REPOSITORY_STRUCTURE.md
│   └── archive/                       # Old docs (move from docs-archive/)
│       └── (existing docs-archive content)
│
├── scripts/                           # Development scripts (REORGANIZE)
│   ├── dev/                           # Development helpers
│   │   ├── add_copyright_headers.py
│   │   ├── add_comprehensive_comments.py
│   │   └── verify_install.py
│   ├── build/                         # Build scripts
│   │   ├── build_protected.sh
│   │   ├── setup_compiled.py
│   │   └── install.sh
│   ├── benchmark/                     # Benchmarking
│   │   ├── benchmark_results.py
│   │   └── benchmark_results.json
│   └── (existing script files organized)
│
├── config/                            # Configuration files (NEW)
│   ├── .parry.example.yml             # Example config
│   └── requirements-build.txt         # Build requirements
│
├── integrations/                      # External integrations (NEW)
│   ├── homebrew/                      # Homebrew tap
│   │   └── parry.rb
│   ├── vscode/                        # VS Code extension
│   │   └── (move vscode-extension/* here)
│   └── website/                       # Website/landing page
│       └── (move website/* here)
│
└── .archive/                          # Deprecated/old files (NEW)
    └── docs-archive/ -> docs/archive/ # Symlink or move
```

## Detailed Migration Plan

### Phase 1: Create New Directory Structure (No Breaking Changes)

**Step 1.1: Create new directories**
```bash
mkdir -p docs/{api,guides,benchmarks,testing,security,development}
mkdir -p scripts/{dev,build,benchmark}
mkdir -p config
mkdir -p integrations/{homebrew,vscode,website}
```

**Step 1.2: Move documentation files**
```bash
# API documentation
mv API_REFERENCE.md docs/api/

# User guides
mv QUICKSTART.md docs/guides/
mv SETUP_GUIDE.md docs/guides/
mv CONTRIBUTING.md docs/guides/
mv QUICK_DEMO.md docs/guides/

# Benchmarks
mv BENCHMARK_SUMMARY.md docs/benchmarks/
mv COMPREHENSIVE_BENCHMARK_RESULTS.md docs/benchmarks/
mv COMPETITIVE_ANALYSIS.md docs/benchmarks/
mv PARRY_METRICS.md docs/benchmarks/
mv SCAN_SPEED_EXAMPLES.md docs/benchmarks/

# Testing
mv TEST_INSTRUCTIONS.md docs/testing/
mv DEEP_MODE_TEST_INSTRUCTIONS.md docs/testing/

# Security
mv SECURITY_COVERAGE_ANALYSIS.md docs/security/

# Development
mv DOCUMENTATION_COMPLETE.md docs/development/
mv UPDATE_SUMMARY.md docs/development/
mv REPOSITORY_STRUCTURE.md docs/development/

# Archive old docs
mv docs-archive docs/archive
```

**Step 1.3: Move scripts**
```bash
# Development scripts
mv add_copyright_headers.py scripts/dev/
mv add_comprehensive_comments.py scripts/dev/
mv verify_install.py scripts/dev/

# Build scripts
mv build_protected.sh scripts/build/
mv setup_compiled.py scripts/build/
mv install.sh scripts/build/

# Benchmark scripts
mv benchmark_results.py scripts/benchmark/
mv benchmark_results.json scripts/benchmark/
```

**Step 1.4: Move config files**
```bash
mv .parry.example.yml config/
mv requirements-build.txt config/
```

**Step 1.5: Move integrations**
```bash
mv parry.rb integrations/homebrew/
mv vscode-extension/* integrations/vscode/
rmdir vscode-extension
mv website/* integrations/website/
rmdir website
```

### Phase 2: Update Import Paths and References

**Step 2.1: Update setup.py**
- Update `scripts` entry points if any reference moved files
- Update `package_data` to include new paths

**Step 2.2: Update setup_compiled.py** (now at scripts/build/setup_compiled.py)
- Update paths to point to correct locations

**Step 2.3: Update CI/CD configs**
- `.gitlab-ci.yml`: Update script paths
- `Jenkinsfile`: Update script paths
- GitHub Actions (if any in `.github/`): Update paths

**Step 2.4: Update documentation cross-references**
- Update README.md links to point to new doc locations
- Update internal doc links in moved files

**Step 2.5: Create convenience symlinks (optional)**
```bash
# For commonly accessed files, create symlinks at root
ln -s scripts/build/install.sh install.sh
ln -s scripts/dev/verify_install.py verify_install.py
```

### Phase 3: Update Package Metadata

**Step 3.1: Update pyproject.toml**
```toml
[project.scripts]
parry = "parry.cli:main"

[tool.setuptools]
packages = ["parry", "parry.language_support"]

[tool.setuptools.package-data]
parry = ["config/*.yml"]
```

**Step 3.2: Update MANIFEST.in**
```
include README.md
include LICENSE
include requirements.txt
include pyproject.toml
recursive-include parry *.py
recursive-include docs *.md
recursive-include config *.yml
recursive-include scripts *.py *.sh
```

### Phase 4: Improve Naming Consistency

**Step 4.1: Standardize script names** (use underscores)
- `build_protected.sh` ✓ (already good)
- `install.sh` ✓ (already good)
- All Python scripts use underscores ✓

**Step 4.2: Standardize documentation names** (use hyphens or underscores consistently)
Currently using UPPERCASE, which is fine for documentation.

### Phase 5: Add Navigation Files

**Step 5.1: Create docs/README.md**
```markdown
# Parry Documentation

## Quick Links
- [Getting Started](guides/QUICKSTART.md)
- [API Reference](api/API_REFERENCE.md)
- [Benchmarks](benchmarks/BENCHMARK_SUMMARY.md)
- [Contributing](guides/CONTRIBUTING.md)

## Documentation Structure
- `api/` - API documentation
- `guides/` - User guides and tutorials
- `benchmarks/` - Performance metrics
- `testing/` - Testing guides
- `security/` - Security coverage analysis
- `development/` - Developer documentation
```

**Step 5.2: Create scripts/README.md**
```markdown
# Parry Scripts

## Development Scripts (`dev/`)
- `add_copyright_headers.py` - Adds copyright to all files
- `verify_install.py` - Verifies installation

## Build Scripts (`build/`)
- `install.sh` - Installation script
- `build_protected.sh` - Creates protected build
- `setup_compiled.py` - Cython compilation

## Benchmark Scripts (`benchmark/`)
- `benchmark_results.py` - Runs competitive benchmarks
```

### Phase 6: Update README.md

**Step 6.1: Update root README.md**
```markdown
# Parry Security Scanner

## Documentation
- 📖 [Full Documentation](docs/)
- 🚀 [Quick Start Guide](docs/guides/QUICKSTART.md)
- 📊 [Benchmarks](docs/benchmarks/)
- 🔒 [Security Coverage](docs/security/SECURITY_COVERAGE_ANALYSIS.md)

## Installation
```bash
# Quick install
curl -sSL https://install.parry.dev | bash

# Or manually
./scripts/build/install.sh
```

## Development
See [CONTRIBUTING.md](docs/guides/CONTRIBUTING.md)
```

## Benefits of New Structure

### ✅ Improved Organization
- Clear separation of concerns (docs, scripts, code, tests)
- Logical grouping (API docs together, build scripts together)
- Reduced root directory clutter (30+ files → 10 files)

### ✅ Better Discoverability
- All docs in `docs/` with logical subdirectories
- All scripts in `scripts/` by purpose
- Clear integration boundaries

### ✅ Professional Structure
- Follows Python packaging best practices
- Similar to major open-source projects (requests, flask, django)
- Easy for contributors to navigate

### ✅ Maintainability
- Easier to find and update related files
- Clear ownership (docs team owns docs/, dev team owns scripts/)
- Reduced cognitive load

### ✅ Scalability
- Room to grow (add more docs, scripts, integrations)
- Clear patterns for new additions
- Modular structure

## Compatibility Considerations

### ⚠️ Breaking Changes to Address

1. **Import Paths**: None (package structure unchanged)
2. **Script Paths**: Update CI/CD, installation docs
3. **Config Paths**: Update references to .parry.example.yml
4. **Documentation Links**: Update cross-references

### ✅ Non-Breaking

1. **Package imports**: `from parry import Scanner` (unchanged)
2. **CLI commands**: `parry scan` (unchanged)
3. **Test discovery**: pytest still finds tests/ (unchanged)
4. **pip install**: Works same way (unchanged)

## Implementation Timeline

### Week 1: Preparation
- [ ] Create migration scripts
- [ ] Document all current references
- [ ] Test migration in branch

### Week 2: Migration
- [ ] Execute Phase 1 (directory structure)
- [ ] Execute Phase 2 (update references)
- [ ] Execute Phase 3 (update metadata)

### Week 3: Validation
- [ ] Run full test suite
- [ ] Verify CI/CD pipelines
- [ ] Test installation process
- [ ] Verify documentation links

### Week 4: Cleanup
- [ ] Update README and docs
- [ ] Create migration guide for contributors
- [ ] Archive old structure documentation

## Rollback Plan

If issues arise:
1. Revert git commits (all changes in one PR)
2. Restore from backup (if needed)
3. All code changes are additive (safe to revert)

## Alternative: Gradual Migration

If full migration is too risky:

### Phase 1: Documentation only
- Move docs, keep scripts at root
- Test for 1 week

### Phase 2: Scripts
- Move scripts after docs stable
- Test for 1 week

### Phase 3: Integrations
- Move vscode, website, homebrew
- Final cleanup

## Validation Checklist

After migration, verify:
- [ ] `pip install -e .` works
- [ ] `parry scan examples/` works
- [ ] All tests pass (`pytest tests/`)
- [ ] CI/CD pipelines pass
- [ ] Documentation links work
- [ ] Installation script works
- [ ] VS Code extension builds
- [ ] Homebrew formula works

## Success Metrics

- ✅ Root directory: ≤10 files (vs current 30+)
- ✅ All tests passing
- ✅ CI/CD green
- ✅ Zero functionality loss
- ✅ Improved contributor experience
- ✅ Faster onboarding for new developers

---

**Recommendation**: Execute this plan in a feature branch, test thoroughly, then merge to main.

**Risk Level**: LOW (no code changes, only file moves)

**Time Estimate**: 2-4 hours for execution, 1 day for validation

**Impact**: HIGH (significant improvement in maintainability and professionalism)
