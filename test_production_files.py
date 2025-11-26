#!/usr/bin/env python3
"""Test on actual production files from repositories"""

import sys
import os
from pathlib import Path
sys.path.insert(0, os.getcwd())

from valid8.scanner import Scanner
from valid8.test_file_detector import get_test_file_detector

scanner = Scanner()
test_detector = get_test_file_detector()

# Test on Flask production files
flask_dir = Path("/tmp/bug_bounty_test/flask")
if not flask_dir.exists():
    print("Flask directory not found. Please run bug_bounty_comprehensive_test.py first.")
    sys.exit(1)

print("="*80)
print("TESTING ON PRODUCTION FILES (Flask)")
print("="*80)

# Find production Python files (not test files)
production_files = []
for py_file in flask_dir.rglob("*.py"):
    file_str = str(py_file)
    # Skip obvious test files
    if any(x in file_str.lower() for x in ['test', 'example', 'demo', 'mock', 'fixture']):
        continue
    # Skip docs
    if 'doc' in file_str.lower():
        continue
    production_files.append(py_file)
    if len(production_files) >= 10:  # Test first 10 production files
        break

print(f"\nFound {len(production_files)} production files to test\n")

total_fast = 0
total_hybrid = 0
filtered_count = 0

for py_file in production_files:
    print(f"\n{'='*80}")
    print(f"File: {py_file.relative_to(flask_dir)}")
    print(f"{'='*80}")
    
    # Check if test file detector thinks it's a test file
    try:
        content = py_file.read_text(errors='ignore')
        is_test, confidence, reason = test_detector.is_test_file(str(py_file), content)
        print(f"Test file detector: is_test={is_test}, confidence={confidence:.2f}, reason={reason}")
    except:
        is_test = False
        confidence = 0.0
    
    # Fast mode
    fast_results = scanner.scan(str(py_file), mode="fast")
    fast_count = len(fast_results.get('vulnerabilities', []))
    total_fast += fast_count
    print(f"Fast mode findings: {fast_count}")
    
    # Hybrid mode
    hybrid_results = scanner.scan(str(py_file), mode="hybrid")
    hybrid_count = len(hybrid_results.get('vulnerabilities', []))
    total_hybrid += hybrid_count
    print(f"Hybrid mode findings: {hybrid_count}")
    
    if fast_count > 0 and hybrid_count == 0:
        filtered_count += fast_count
        print(f"⚠️  FILTERED: {fast_count} findings removed by hybrid mode")
        # Show what was filtered
        for vuln in fast_results.get('vulnerabilities', [])[:3]:
            if hasattr(vuln, 'to_dict'):
                v = vuln.to_dict()
            else:
                v = vuln
            print(f"    - {v.get('cwe', 'N/A')}: {v.get('title', 'N/A')}")
    elif hybrid_count > 0:
        print(f"✅ KEPT: {hybrid_count} findings passed validation")
        for vuln in hybrid_results.get('vulnerabilities', [])[:3]:
            if hasattr(vuln, 'to_dict'):
                v = vuln.to_dict()
            else:
                v = vuln
            print(f"    - {v.get('cwe', 'N/A')}: {v.get('title', 'N/A')}")

print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"Total files tested: {len(production_files)}")
print(f"Fast mode total findings: {total_fast}")
print(f"Hybrid mode total findings: {total_hybrid}")
print(f"Filtered findings: {filtered_count}")
if total_fast > 0:
    precision = (total_hybrid / total_fast) * 100
    print(f"Effective precision: {precision:.1f}% (hybrid/fast)")
else:
    print("No findings in fast mode - scanner may not be detecting vulnerabilities")




