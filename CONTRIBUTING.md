# Contributing to Parry

Thank you for your interest in contributing to Parry! This document provides guidelines and instructions for contributing.

## Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR-USERNAME/parry.git
cd parry
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

### 3. Install Development Dependencies

```bash
pip install -e ".[dev]"
```

### 4. Install Ollama and Model

```bash
brew install ollama
ollama serve &
ollama pull codellama:7b-instruct
```

### 5. Run Tests

```bash
pytest tests/ -v
```

## Project Structure

```
parry/
├── parry/              # Main package
│   ├── cli.py         # Command-line interface
│   ├── scanner.py     # Vulnerability detection
│   ├── llm.py         # LLM client
│   ├── patch.py       # Patch generation
│   ├── reporter.py    # Report generation
│   ├── compare.py     # Benchmarking
│   └── prompts.py     # LLM prompts
├── tests/             # Test suite
├── examples/          # Example vulnerable code
├── scripts/           # Utility scripts
└── docs/             # Documentation
```

## Adding New Vulnerability Detectors

To add a new vulnerability detector:

1. Create a new detector class in `parry/scanner.py`:

```python
class MyNewDetector(VulnerabilityDetector):
    """Detects MY-VULNERABILITY (CWE-XXX)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        patterns = [
            r'vulnerable_pattern_1',
            r'vulnerable_pattern_2',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-XXX",
                        severity="high",
                        title="My Vulnerability",
                        description="Description of the vulnerability",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence="medium",
                        category="category"
                    ))
        
        return vulnerabilities
```

2. Add the detector to the scanner's `__init__` method:

```python
self.detectors = [
    # ... existing detectors
    MyNewDetector(),
]
```

3. Add a prompt template in `parry/prompts.py`:

```python
PATCH_PROMPTS = {
    # ... existing prompts
    "CWE-XXX": """
Fix this vulnerability by:
1. Step one
2. Step two
3. Step three

Example:
BAD:  vulnerable_code
GOOD: secure_code
""",
}
```

4. Add tests in `tests/test_scanner.py`:

```python
def test_my_new_detector():
    """Test MY-VULNERABILITY detection"""
    detector = MyNewDetector()
    
    code = '''
    vulnerable_code_example
    '''
    
    vulns = detector.detect(Path("test.py"), code, code.split("\n"))
    assert len(vulns) > 0
    assert vulns[0].cwe == "CWE-XXX"
```

## Code Style

We use Black for code formatting and Ruff for linting:

```bash
# Format code
black parry/

# Lint code
ruff check parry/

# Type checking
mypy parry/
```

## Testing

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test

```bash
pytest tests/test_scanner.py::test_sql_injection_detection -v
```

### Test Coverage

```bash
pytest tests/ --cov=parry --cov-report=html
```

## Submitting Changes

### 1. Create a Branch

```bash
git checkout -b feature/my-new-feature
```

### 2. Make Your Changes

- Write code
- Add tests
- Update documentation

### 3. Run Tests and Linting

```bash
pytest tests/ -v
black parry/
ruff check parry/
```

### 4. Commit Changes

```bash
git add .
git commit -m "Add new feature: description"
```

Use conventional commit messages:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test changes
- `refactor:` - Code refactoring

### 5. Push and Create PR

```bash
git push origin feature/my-new-feature
```

Then create a Pull Request on GitHub.

## PR Guidelines

- Provide a clear description of changes
- Reference any related issues
- Include tests for new features
- Update documentation as needed
- Ensure all CI checks pass

## Reporting Bugs

When reporting bugs, please include:

1. **Description**: Clear description of the bug
2. **Steps to Reproduce**: Detailed steps to reproduce
3. **Expected Behavior**: What you expected to happen
4. **Actual Behavior**: What actually happened
5. **Environment**:
   - OS version
   - Python version
   - Parry version
   - Ollama version
6. **Logs**: Relevant error messages or logs

## Feature Requests

We welcome feature requests! Please:

1. Check if the feature already exists or is planned
2. Provide a clear use case
3. Describe the expected behavior
4. Consider submitting a PR if you can implement it

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Help others learn and grow

## Questions?

- 💬 [GitHub Discussions](https://github.com/parry-security/parry/discussions)
- 📧 Email: dev@parry.dev

Thank you for contributing to Parry! 🔒


