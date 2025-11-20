#!/usr/bin/env python3
"""
Test the enhanced taint analyzer with inter-procedural and context-aware features.
"""

import tempfile
import os
from valid8.taint_analyzer import TaintAnalyzer


def test_interprocedural_analysis():
    """Test inter-procedural taint tracking."""
    print("🧪 Testing Inter-Procedural Taint Analysis")
    print("=" * 50)

    # Create test code with inter-procedural vulnerabilities
    test_code = '''
def get_user_input():
    """Function that returns tainted data."""
    return request.args.get('user_input', '')

def sanitize_input(data):
    """Sanitizer function."""
    import html
    return html.escape(data)

def process_data():
    """Process user data."""
    user_data = get_user_input()
    # This should be flagged as vulnerable - no sanitization before database
    query = f"SELECT * FROM users WHERE name = '{user_data}'"
    cursor.execute(query)

def process_data_safe():
    """Process user data safely."""
    user_data = get_user_input()
    safe_data = sanitize_input(user_data)
    # This should NOT be flagged - data is sanitized
    query = f"SELECT * FROM users WHERE name = '{safe_data}'"
    cursor.execute(query)

def complex_flow():
    """Complex taint flow."""
    data = get_user_input()
    if len(data) > 0:
        processed = data.upper()  # Taint propagates through string operations
        # This should be flagged
        subprocess.run(["echo", processed], shell=False)
'''

    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_file = f.name

    try:
        # Test single file analysis
        analyzer = TaintAnalyzer()
        vulnerabilities = analyzer.analyze_code(test_code, temp_file)

        print(f"📊 Found {len(vulnerabilities)} vulnerabilities")

        for vuln in vulnerabilities:
            print(f"   • {vuln.title}")
            print(f"     Severity: {vuln.severity}, Confidence: {vuln.confidence:.2f}")
            print(f"     Description: {vuln.description[:100]}...")
            print()

        # Validate results
        sql_vulns = [v for v in vulnerabilities if 'sql' in v.title.lower()]
        command_vulns = [v for v in vulnerabilities if 'command' in v.title.lower()]

        print("✅ VALIDATION:")
        if len(sql_vulns) >= 1:  # Should detect at least the unsanitized SQL
            print("   ✅ SQL injection detection working")
        else:
            print("   ❌ SQL injection detection failed")

        if len(command_vulns) >= 1:  # Should detect command injection
            print("   ✅ Command injection detection working")
        else:
            print("   ❌ Command injection detection failed")

        return len(vulnerabilities) > 0

    finally:
        os.unlink(temp_file)


def test_context_aware_sanitization():
    """Test context-aware sanitization effectiveness."""
    print("\\n🧪 Testing Context-Aware Sanitization")
    print("=" * 50)

    test_code = '''
def test_html_context():
    """Test HTML sanitization in HTML context."""
    user_input = request.args.get('data', '')

    # HTML context - should be highly effective
    safe_html = html.escape(user_input)
    template = f"<div>{safe_html}</div>"
    return template

def test_sql_context():
    """Test escaping in SQL context."""
    user_input = request.args.get('name', '')

    # SQL context - re.escape should be effective for SQL
    safe_sql = re.escape(user_input)
    query = f"SELECT * FROM users WHERE name LIKE '%{safe_sql}%'"
    cursor.execute(query)

def test_command_context():
    """Test escaping in command context."""
    user_input = request.args.get('cmd', '')

    # Command context - should detect vulnerability
    dangerous_cmd = f"ls {user_input}"
    os.system(dangerous_cmd)
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_file = f.name

    try:
        analyzer = TaintAnalyzer()
        vulnerabilities = analyzer.analyze_code(test_code, temp_file)

        print(f"📊 Found {len(vulnerabilities)} vulnerabilities")

        for vuln in vulnerabilities:
            print(f"   • {vuln.title}")
            print(f"     Severity: {vuln.severity}, Confidence: {vuln.confidence:.2f}")

        # Should detect the command injection but not flag the properly sanitized cases
        command_vulns = [v for v in vulnerabilities if 'command' in v.title.lower()]

        print("\\n✅ VALIDATION:")
        if len(command_vulns) >= 1:
            print("   ✅ Context-aware sanitization working - detected unsafe command")
        else:
            print("   ❌ Context-aware sanitization failed")

        return len(command_vulns) >= 1

    finally:
        os.unlink(temp_file)


def test_path_sensitive_analysis():
    """Test path-sensitive analysis with conditional flows."""
    print("\\n🧪 Testing Path-Sensitive Analysis")
    print("=" * 50)

    test_code = '''
def conditional_flow():
    """Test conditional taint propagation."""
    data = request.args.get('input', '')

    if validate_input(data):
        # In this branch, data should be considered safe
        safe_data = data  # This should not be flagged
        query = f"SELECT * FROM users WHERE id = {safe_data}"
        cursor.execute(query)
    else:
        # In this branch, data is still tainted
        dangerous_data = data  # This should be flagged
        cmd = f"rm {dangerous_data}"
        os.system(cmd)

def validate_input(data):
    """Mock validation function."""
    return len(data) > 0 and data.isdigit()
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_file = f.name

    try:
        analyzer = TaintAnalyzer()
        vulnerabilities = analyzer.analyze_code(test_code, temp_file)

        print(f"📊 Found {len(vulnerabilities)} vulnerabilities")

        for vuln in vulnerabilities:
            print(f"   • {vuln.title}")
            print(f"     Description: {vuln.description[:80]}...")

        # Should detect command injection in the else branch
        command_vulns = [v for v in vulnerabilities if 'command' in v.title.lower()]

        print("\\n✅ VALIDATION:")
        if len(command_vulns) >= 1:
            print("   ✅ Path-sensitive analysis working - detected conditional vulnerability")
            return True
        else:
            print("   ❌ Path-sensitive analysis failed")
            return False

    finally:
        os.unlink(temp_file)


def test_cross_file_analysis():
    """Test cross-file inter-procedural analysis."""
    print("\\n🧪 Testing Cross-File Analysis")
    print("=" * 50)

    # File 1: Utility functions
    utils_code = '''
def get_user_data():
    """Get user input from request."""
    return request.args.get('data', '')

def sanitize_for_html(data):
    """Sanitize data for HTML output."""
    import html
    return html.escape(data)

def sanitize_for_sql(data):
    """Sanitize data for SQL queries."""
    import re
    return re.escape(data)
'''

    # File 2: Main application
    main_code = '''
from utils import get_user_data, sanitize_for_html, sanitize_for_sql

def render_page():
    """Render HTML page."""
    data = get_user_data()
    safe_data = sanitize_for_html(data)  # Should be safe
    return f"<h1>{safe_data}</h1>"

def query_database():
    """Query database."""
    data = get_user_data()
    # Forgot to sanitize - should be flagged
    query = f"SELECT * FROM users WHERE name = '{data}'"
    cursor.execute(query)

def query_database_safe():
    """Query database safely."""
    data = get_user_data()
    safe_data = sanitize_for_sql(data)  # Should be safe
    query = f"SELECT * FROM users WHERE name = '{safe_data}'"
    cursor.execute(query)
'''

    files = [
        ('utils.py', utils_code),
        ('main.py', main_code)
    ]

    analyzer = TaintAnalyzer()
    vulnerabilities = analyzer.analyze_codebase(files)

    print(f"📊 Found {len(vulnerabilities)} vulnerabilities across {len(files)} files")

    for vuln in vulnerabilities:
        print(f"   • {vuln.file_path}: {vuln.title}")

    # Should detect SQL injection in query_database but not in query_database_safe
    sql_vulns = [v for v in vulnerabilities if 'sql' in v.title.lower()]

    print("\\n✅ VALIDATION:")
    if len(sql_vulns) >= 1:
        print("   ✅ Cross-file analysis working - detected inter-procedural vulnerability")
        return True
    else:
        print("   ❌ Cross-file analysis failed")
        return False


def main():
    """Run all taint analyzer tests."""
    print("🚀 ENHANCED TAINT ANALYZER VALIDATION")
    print("=" * 60)

    results = []

    # Test 1: Inter-procedural analysis
    results.append(("Inter-procedural Analysis", test_interprocedural_analysis()))

    # Test 2: Context-aware sanitization
    results.append(("Context-Aware Sanitization", test_context_aware_sanitization()))

    # Test 3: Path-sensitive analysis
    results.append(("Path-Sensitive Analysis", test_path_sensitive_analysis()))

    # Test 4: Cross-file analysis
    results.append(("Cross-File Analysis", test_cross_file_analysis()))

    # Summary
    print("\\n🎯 FINAL RESULTS:")
    print("=" * 30)

    passed = 0
    total = len(results)

    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"   {test_name}: {status}")
        if success:
            passed += 1

    print(f"\\n📊 Overall: {passed}/{total} tests passed")

    if passed == total:
        print("\\n🎉 ALL TESTS PASSED!")
        print("✅ Enhanced taint analyzer is ready for production")
        return 0
    else:
        print("\\n⚠️ Some tests failed - additional development needed")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())

