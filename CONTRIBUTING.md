# Contributing to Parry

Thank you for your interest in contributing to Parry! We welcome contributions from the community.

## 🚀 Ways to Contribute

### Code Contributions
- Bug fixes
- Feature implementations
- Performance optimizations
- Documentation improvements

### Non-Code Contributions
- Bug reports
- Feature requests
- Documentation
- Testing

## 🛠️ Development Setup

### Prerequisites
- Python 3.8+
- Ollama (for AI features)
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/Parry-AI/parry-scanner.git
cd parry-scanner

# Install dependencies
pip install -r requirements.txt

# Install Ollama and models (optional, for AI features)
ollama pull qwen2.5-coder:0.5b
ollama pull qwen2.5-coder:1.5b
```

### Testing
```bash
# Run tests
python -m pytest

# Run specific test categories
python -m pytest tests/test_scanner.py
python -m pytest tests/test_ai.py
```

## 📝 Code Style

- Follow PEP 8 style guidelines
- Use type hints for function parameters and return values
- Write docstrings for all public functions and classes
- Keep functions focused and modular

### Example
```python
def scan_file(file_path: Path, config: ScanConfig) -> ScanResult:
    """
    Scan a single file for security vulnerabilities.

    Args:
        file_path: Path to the file to scan
        config: Scanning configuration

    Returns:
        ScanResult with findings and metadata
    """
    # Implementation here
    pass
```

## 🐛 Reporting Bugs

Please use the GitHub issue tracker to report bugs. Include:

- Clear title describing the issue
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (OS, Python version, etc.)
- Relevant logs or error messages

## 💡 Feature Requests

We welcome feature requests! Please:

- Use the GitHub issue tracker
- Clearly describe the proposed feature
- Explain the use case and benefits
- Consider if it's within Parry's scope

## 📚 Documentation

- Update documentation for any new features
- Fix typos and improve clarity
- Add examples and tutorials
- Keep the README up to date

## 🔒 Security

- Report security vulnerabilities privately via email
- Do not create public issues for security problems
- Allow time for fixes before public disclosure

## 📋 Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`python -m pytest`)
5. Update documentation if needed
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### PR Requirements

- All tests pass
- Code follows style guidelines
- Documentation updated
- Clear description of changes
- Screenshots for UI changes (if applicable)

## 🎯 Areas for Contribution

### High Priority
- Additional CWE coverage
- Performance optimizations
- Language support expansion
- Integration improvements

### Medium Priority
- UI/UX improvements
- Advanced reporting features
- Custom rule enhancements
- API extensions

### Future
- Machine learning enhancements
- Advanced analytics
- Enterprise features

## 📞 Getting Help

- **Documentation**: Check the `docs/` directory
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for questions

## 🙏 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for contributing to Parry! 🛡️
