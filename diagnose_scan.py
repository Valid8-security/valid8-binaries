#!/usr/bin/env python3
"""Diagnostic script to see what's happening with scanning"""

import sys
import os
from pathlib import Path
sys.path.insert(0, os.getcwd())

from valid8.scanner import Scanner

# Test on a small known vulnerable file
test_code = """
import hashlib
password = "secret123"
hash = hashlib.md5(password.encode()).hexdigest()  # CWE-327: Weak crypto
"""

# Write test file
test_file = Path("/tmp/test_weak_crypto.py")
test_file.write_text(test_code)

print("Testing scanner with known vulnerable code...")
print(f"Test file: {test_file}")
print(f"Code:\n{test_code}")

scanner = Scanner()

# Test fast mode (no filtering)
print("\n" + "="*80)
print("FAST MODE (no AI validation, no test file filtering):")
print("="*80)
fast_results = scanner.scan(str(test_file), mode="fast")
print(f"Findings: {len(fast_results.get('vulnerabilities', []))}")
for vuln in fast_results.get('vulnerabilities', [])[:5]:
    if hasattr(vuln, 'to_dict'):
        v = vuln.to_dict()
    else:
        v = vuln
    print(f"  - {v.get('cwe', 'N/A')}: {v.get('title', 'N/A')}")

# Test hybrid mode (with filtering)
print("\n" + "="*80)
print("HYBRID MODE (with AI validation and test file filtering):")
print("="*80)
hybrid_results = scanner.scan(str(test_file), mode="hybrid")
print(f"Findings: {len(hybrid_results.get('vulnerabilities', []))}")
for vuln in hybrid_results.get('vulnerabilities', [])[:5]:
    if hasattr(vuln, 'to_dict'):
        v = vuln.to_dict()
    else:
        v = vuln
    print(f"  - {v.get('cwe', 'N/A')}: {v.get('title', 'N/A')}")

# Check if test file detector is working
print("\n" + "="*80)
print("TEST FILE DETECTOR TEST:")
print("="*80)
from valid8.test_file_detector import get_test_file_detector
detector = get_test_file_detector()
is_test, confidence, reason = detector.is_test_file(str(test_file), test_code)
print(f"File: {test_file}")
print(f"Is test file: {is_test}")
print(f"Confidence: {confidence}")
print(f"Reason: {reason}")

# Test on actual repository
print("\n" + "="*80)
print("TESTING ON ACTUAL REPOSITORY (flask):")
print("="*80)
flask_dir = Path("/tmp/bug_bounty_test/flask")
if flask_dir.exists():
    # Find a non-test Python file
    for py_file in flask_dir.rglob("*.py"):
        if "test" not in str(py_file).lower() and "example" not in str(py_file).lower():
            print(f"\nScanning: {py_file}")
            results = scanner.scan(str(py_file), mode="hybrid")
            findings = len(results.get('vulnerabilities', []))
            print(f"  Findings: {findings}")
            if findings > 0:
                for vuln in results.get('vulnerabilities', [])[:3]:
                    if hasattr(vuln, 'to_dict'):
                        v = vuln.to_dict()
                    else:
                        v = vuln
                    print(f"    - {v.get('cwe', 'N/A')}: {v.get('title', 'N/A')}")
            break
else:
    print("Flask directory not found")



