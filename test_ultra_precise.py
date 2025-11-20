#!/usr/bin/env python3
"""
Quick test of Valid8 Ultra-Precise Scanner
"""

import sys
import tempfile
import os
from pathlib import Path

# Add valid8 to path
sys.path.insert(0, str(Path(__file__).parent))

def create_test_file():
    """Create a test file with known vulnerabilities"""
    temp_dir = Path(tempfile.mkdtemp())
    test_file = temp_dir / "test_vuln.py"

    test_file.write_text('''
import sqlite3
import subprocess

def sql_vulnerable(user_input):
    # CWE-89: SQL Injection - should be detected
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"  # VULNERABLE
    cursor.execute(query)
    return cursor.fetchall()

def cmd_vulnerable(user_cmd):
    # CWE-78: Command Injection - should be detected
    result = subprocess.run(user_cmd, shell=True)  # VULNERABLE
    return result.returncode

def safe_code():
    return "This is safe"
''')

    return temp_dir, test_file

def main():
    try:
        print("🧪 Testing Valid8 Ultra-Precise Scanner")
        print("=" * 50)

        # Create test file
        temp_dir, test_file = create_test_file()
        print(f"📝 Created test file: {test_file}")

        # Test ultra-permissive detector
        print("\\n🔍 Testing Ultra-Permissive Pattern Detector...")

        from valid8.ultra_permissive_detector import UltraPermissivePatternDetector
        detector = UltraPermissivePatternDetector()

        results = detector.scan_file(test_file)
        print(f"   📊 Detected {len(results)} potential vulnerabilities")

        for i, result in enumerate(results[:3]):  # Show first 3
            vuln = result.vulnerability
            print(f"   {i+1}. {vuln['title']} ({vuln['cwe']}) - confidence: {result.confidence}")

        # Test AI validator
        print("\\n🤖 Testing AI True Positive Validator...")

        from valid8.ai_true_positive_validator import AITruePositiveValidator
        validator = AITruePositiveValidator()

        if results:
            test_result = validator.validate_vulnerability(results[0].vulnerability)
            print(f"   📊 AI Validation: {'TRUE POSITIVE' if test_result.is_true_positive else 'FALSE POSITIVE'}")
            print(".3f")

        # Test full scanner
        print("\\n🚀 Testing Full Ultra-Precise Scanner...")

        from valid8.scanner import Scanner
        scanner = Scanner()

        scan_results = scanner.scan_ultra_precise(str(temp_dir))
        print(f"   📊 Scan completed in {scan_results['scan_time_seconds']:.2f}s")
        print(f"   📁 Files scanned: {scan_results['files_scanned']}")
        print(f"   🎯 Vulnerabilities found: {scan_results['vulnerabilities_found']}")
        print(".3f")

        print("\\n✅ Test completed successfully!")

        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
        print(f"🧹 Cleaned up test directory: {temp_dir}")

        return 0

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())

