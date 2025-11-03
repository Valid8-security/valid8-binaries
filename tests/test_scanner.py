# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Unit tests for Parry scanner core functionality

This test suite validates:
- Individual detector classes (SQL injection, XSS, secrets, etc.)
- Scanner integration (end-to-end file scanning)
- Vulnerability detection accuracy
- CWE classification correctness
- Severity scoring
- Multi-language support

Test Coverage:
- test_sql_injection_detection(): Validates SQL injection patterns
- test_xss_detection(): Validates XSS detection in JavaScript
- test_secrets_detection(): Validates hardcoded credential detection
- test_scanner_integration(): End-to-end scanner test

Usage:
    pytest tests/test_scanner.py -v
    pytest tests/test_scanner.py::test_sql_injection_detection

CI/CD Integration:
- Run automatically on every commit
- Must pass before merging PRs
- Part of release validation

Requirements:
- pytest >= 7.0
- Parry installed (pip install -e .)
"""

import pytest
from pathlib import Path
from parry.scanner import Scanner, SQLInjectionDetector, XSSDetector, SecretsDetector


def test_sql_injection_detection():
    """Test SQL injection detection"""
    detector = SQLInjectionDetector()
    
    code = '''
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    '''
    
    vulns = detector.detect(Path("test.py"), code, code.split("\n"))
    assert len(vulns) > 0
    assert vulns[0].cwe == "CWE-89"
    assert vulns[0].severity == "high"


def test_xss_detection():
    """Test XSS detection"""
    detector = XSSDetector()
    
    code = '''
    element.innerHTML = userInput;
    '''
    
    vulns = detector.detect(Path("test.js"), code, code.split("\n"))
    assert len(vulns) > 0
    assert vulns[0].cwe == "CWE-79"


def test_secrets_detection():
    """Test secrets detection"""
    detector = SecretsDetector()
    
    code = '''
    password = "mysecretpassword123"
    api_key = "sk-1234567890abcdefghijklmnop"
    '''
    
    vulns = detector.detect(Path("test.py"), code, code.split("\n"))
    assert len(vulns) > 0
    assert any(v.cwe == "CWE-798" for v in vulns)


def test_scanner_integration(tmp_path):
    """Test full scanner on a file"""
    # Create a test file with vulnerabilities
    test_file = tmp_path / "test.py"
    test_file.write_text('''
import sqlite3
import os

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

def insecure_command(user_input):
    os.system("ls " + user_input)

password = "hardcoded_secret_123"
    ''')
    
    scanner = Scanner()
    results = scanner.scan(test_file)
    
    assert results["files_scanned"] == 1
    assert results["vulnerabilities_found"] > 0
    # Should detect command injection or secrets at minimum
    cwes = [v["cwe"] for v in results["vulnerabilities"]]
    assert any(cwe in cwes for cwe in ["CWE-78", "CWE-798", "CWE-89"])


def test_scanner_exclude_patterns(tmp_path):
    """Test that scanner respects exclude patterns"""
    # Create test files
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "test.js").write_text("password = 'secret'")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("password = 'secret'")
    
    scanner = Scanner()
    results = scanner.scan(tmp_path)
    
    # Should only scan src/app.py, not node_modules
    assert results["files_scanned"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


