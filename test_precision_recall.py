#!/usr/bin/env python3
"""
Simple Precision and Recall Test for Valid8
"""

import os
import sys
import tempfile
import json
from pathlib import Path

# Add the valid8 package to the path
sys.path.insert(0, str(Path(__file__).parent / 'valid8'))

def create_test_files():
    """Create test files with known vulnerabilities."""
    test_dir = Path(tempfile.mkdtemp())

    # Create a Python file with SQL injection
    python_file = test_dir / "test_vuln.py"
    python_file.write_text("""
import sqlite3

def vulnerable_function(user_input):
    # CWE-89: SQL Injection
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"  # Vulnerable!
    cursor.execute(query)
    return cursor.fetchall()
""")

    # Create a JavaScript file with XSS
    js_file = test_dir / "test_xss.js"
    js_file.write_text("""
function vulnerableFunction(userInput) {
    // CWE-79: Cross-Site Scripting
    const element = document.getElementById('output');
    element.innerHTML = userInput;  // Vulnerable!
}
""")

    # Create a clean file
    clean_file = test_dir / "clean.py"
    clean_file.write_text("""
def safe_function():
    return "This is safe code"
""")

    return test_dir

def test_precision_recall():
    """Test precision and recall of the scanner."""
    print("🧪 Testing Valid8 Precision and Recall")
    print("=" * 40)

    try:
        # Create test files
        test_dir = create_test_files()
        print(f"📁 Created test files in: {test_dir}")

        # Import and initialize scanner
        from scanner import Scanner

        scanner = Scanner()
        print("\n📈 RESULTS:")✅ Scanner initialized")

        # Scan the test files
        print("\n📈 RESULTS:")🔍 Scanning test files...")
        results = scanner.scan(test_dir)

        # Analyze results
        vulnerabilities = results.get('vulnerabilities', [])
        print(f"📊 Found {len(vulnerabilities)} vulnerabilities")

        # Expected vulnerabilities
        expected_vulns = [
            {'cwe': 'CWE-89', 'title': 'SQL Injection'},
            {'cwe': 'CWE-79', 'title': 'Cross-Site Scripting'}
        ]

        # Calculate precision and recall
        true_positives = 0
        false_positives = 0
        false_negatives = len(expected_vulns)

        for vuln in vulnerabilities:
            found = False
            for expected in expected_vulns:
                if (vuln.get('cwe') == expected['cwe'] or
                    expected['title'].lower() in vuln.get('title', '').lower()):
                    true_positives += 1
                    false_negatives -= 1
                    found = True
                    break
            if not found:
                false_positives += 1

        # Calculate metrics
        total_predictions = len(vulnerabilities)
        total_actual = len(expected_vulns)

        precision = true_positives / total_predictions if total_predictions > 0 else 0
        recall = true_positives / total_actual if total_actual > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        print("\n📈 RESULTS:")
📈 RESULTS:"        print(f"  True Positives: {true_positives}")
        print(f"  False Positives: {false_positives}")
        print(f"  False Negatives: {false_negatives}")
        print("\n📈 RESULTS:").1%")
        print("\n📈 RESULTS:").1%")
        print("\n📈 RESULTS:").1%")

        # Clean up
        import shutil
        shutil.rmtree(test_dir)

        return precision, recall, f1_score

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 0, 0, 0

if __name__ == "__main__":
    precision, recall, f1_score = test_precision_recall()

    if f1_score > 0.8:
        print("\n📈 RESULTS:")✅ PASSED: High precision and recall achieved!")
        sys.exit(0)
    else:
        print("\n📈 RESULTS:")❌ FAILED: Precision/recall too low")
        sys.exit(1)
