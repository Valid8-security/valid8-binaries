# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra

# Repository File Structure and Functions

## Root Directory Files

### Python Files
- **setup.py**: Package installation and distribution configuration using setuptools
- **setup_compiled.py**: Alternative setup configuration for compiled/protected code distribution
- **verify_install.py**: Installation verification script that tests if Parry is correctly installed
- **benchmark_results.py**: Script to generate and display benchmark results from security scans
- **add_copyright_headers.py**: Utility script to add copyright headers to all source files

### Configuration Files
- **pyproject.toml**: Modern Python project metadata and build system configuration (PEP 517/518)
- **requirements.txt**: Python package dependencies for runtime
- **requirements-build.txt**: Python package dependencies for build process
- **MANIFEST.in**: Specifies additional files to include in source distributions

### Shell Scripts
- **install.sh**: Unix/Linux installation script for setting up Parry
- **build_protected.sh**: Script to build protected/compiled versions of the code

### Homebrew
- **parry.rb**: Homebrew formula for installing Parry on macOS

### CI/CD
- **Jenkinsfile**: Jenkins pipeline configuration for continuous integration

## Documentation Files (.md files - now in .gitignore except README and LICENSE)

### Main Documentation
- **README.md**: Main project documentation with features, installation, and usage
- **LICENSE**: MIT license file
- **API_REFERENCE.md**: API documentation for developers
- **QUICKSTART.md**: Quick start guide for new users
- **QUICK_DEMO.md**: Quick demonstration of key features
- **SETUP_GUIDE.md**: Detailed setup instructions
- **CONTRIBUTING.md**: Guidelines for contributing to the project
- **TEST_INSTRUCTIONS.md**: Instructions for running tests
- **DEEP_MODE_TEST_INSTRUCTIONS.md**: Instructions for testing deep analysis mode

### Performance & Analysis
- **BENCHMARK_SUMMARY.md**: Summary of benchmark test results
- **COMPREHENSIVE_BENCHMARK_RESULTS.md**: Detailed benchmark results
- **COMPETITIVE_ANALYSIS.md**: Comparison with competing security scanners
- **PARRY_METRICS.md**: Performance metrics and statistics
- **SCAN_SPEED_EXAMPLES.md**: Examples of scan speed benchmarks

## Core Parry Package (`parry/` directory)

### Main Scanner Components
- **__init__.py**: Package initialization, exports Scanner, LLMClient, and PatchGenerator
- **scanner.py**: Core vulnerability scanner with multi-language support
- **cli.py**: Command-line interface implementation using Click
- **api.py**: REST API server for remote scanning capabilities

### AI/LLM Integration
- **llm.py**: Large Language Model client for AI-powered fix generation
- **ai_detector.py**: AI-based vulnerability detection using machine learning
- **prompts.py**: Prompt templates for LLM interactions

### Vulnerability Analysis
- **secrets_scanner.py**: Detects hardcoded secrets, API keys, and credentials
- **sca.py**: Software Composition Analysis - dependency vulnerability scanning
- **framework_detectors.py**: Framework-specific security checks (Django, Rails, etc.)
- **data_flow_analyzer.py**: Tracks data flow to detect complex vulnerabilities
- **container_iac_scanner.py**: Scans Docker/Kubernetes configs and infrastructure-as-code

### Remediation & Reporting
- **patch.py**: Generates code patches to fix vulnerabilities
- **reporter.py**: Formats scan results in JSON, Markdown, or terminal output
- **validator.py**: Validates detected vulnerabilities to reduce false positives

### Integration & Workflow
- **github_pr.py**: GitHub Pull Request integration for automated code review
- **compare.py**: Compares scan results between versions
- **feedback.py**: User feedback collection system
- **cache.py**: Caching mechanism for faster repeated scans

### Configuration & Rules
- **custom_rules.py**: Engine for custom security rules and policies
- **compliance.py**: Compliance checking (OWASP, PCI-DSS, etc.)
- **setup.py**: Setup wizard for initial configuration

### Licensing & Authentication
- **license.py**: License management and feature gating
- **beta_token.py**: Beta access token validation

## Language Support (`parry/language_support/` directory)

### Core Language Support
- **__init__.py**: Language support package initialization
- **base.py**: Base classes for language analyzers
- **cwe_standards.py**: CWE (Common Weakness Enumeration) definitions

### Language-Specific Analyzers
- **python_analyzer.py**: Python-specific vulnerability detection
- **javascript_analyzer.py**: JavaScript/TypeScript vulnerability detection
- **java_analyzer.py**: Java vulnerability detection
- **go_analyzer.py**: Go vulnerability detection
- **php_analyzer.py**: PHP vulnerability detection
- **ruby_analyzer.py**: Ruby vulnerability detection
- **rust_analyzer.py**: Rust vulnerability detection
- **cpp_analyzer.py**: C/C++ vulnerability detection

### Cross-Language Detection
- **universal_detectors.py**: Language-agnostic vulnerability patterns

## Examples (`examples/` directory)

### Test Files
- **__init__.py**: Examples package initialization
- **vulnerable_code.py**: Python code with intentional vulnerabilities for testing
- **vulnerable_advanced.py**: Advanced vulnerability test cases
- **vulnerable_code.js**: JavaScript code with security issues
- **vulnerable_test.java**: Java vulnerable code samples
- **vulnerable_test.go**: Go vulnerable code samples
- **vulnerable_test.php**: PHP vulnerable code samples
- **vulnerable_test.rb**: Ruby vulnerable code samples
- **vulnerable_test.rs**: Rust vulnerable code samples

### Extended Testing
- **test_extended_cwes.py**: Tests for extended CWE coverage
- **test_shreyan_patterns.py**: Tests for Shreyan's detection patterns

## Scripts (`scripts/` directory)

### Benchmarking
- **benchmark.py**: Core benchmarking script
- **comprehensive_benchmark.py**: Comprehensive benchmark suite
- **generate_owasp_scorecard.py**: Generates OWASP Top 10 scorecard
- **fp_fn_analysis.py**: False positive/false negative analysis
- **fp_fn_analysis_v2.py**: Enhanced FP/FN analysis

### Testing & Demos
- **demo_scan_with_fixes.py**: Demonstration of scanning with AI fixes
- **showcase_parry_benefits.py**: Showcase script for marketing
- **test_parry_comprehensive.py**: Comprehensive test suite
- **test_deep_mode.py**: Tests for deep analysis mode
- **test_ollama.py**: Tests for Ollama LLM integration

### User Management
- **signup_beta.py**: Beta user signup workflow
- **__init__.py**: Scripts package initialization

## Tests (`tests/` directory)

- **__init__.py**: Test package initialization
- **test_scanner.py**: Unit tests for scanner functionality
- **test_comprehensive.py**: Comprehensive integration tests
- **test_parallel_performance.py**: Performance tests for parallel scanning

## Documentation Archive (`docs-archive/` directory)

Contains historical documentation including:
- Beta launch materials
- License enforcement strategies
- Integration summaries
- Marketing materials
- Feedback system documentation
- Revenue analysis
- Setup guides
- Launch checklists

## VS Code Extension (`vscode-extension/` directory)

VS Code extension for real-time security scanning in the editor

## Website (`website/` directory)

Marketing website and documentation site
