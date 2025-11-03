#!/usr/bin/env python3
"""
Test script for compliance report PDF export

This script tests the new compliance report functionality including:
- Scanning code for vulnerabilities
- Generating compliance reports for multiple standards
- Exporting to JSON, Markdown, and PDF formats
"""

from pathlib import Path
from parry.scanner import scan_directory
from parry.compliance import ComplianceReporter

def test_compliance_report():
    """Test compliance report generation"""
    print("🔒 Testing Parry Compliance Report Generation\n")
    
    # Step 1: Scan the examples directory
    print("Step 1: Scanning examples directory...")
    examples_path = Path("examples")
    
    if not examples_path.exists():
        print("❌ Examples directory not found. Creating test file...")
        examples_path.mkdir(exist_ok=True)
        
        # Create a test file with vulnerabilities
        test_file = examples_path / "test_vulnerable.py"
        test_file.write_text("""
# Test file with vulnerabilities for compliance testing

import os

# CWE-89: SQL Injection
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return execute_query(query)

# CWE-78: Command Injection
def backup_file(filename):
    os.system(f"cp {filename} /backup/")

# CWE-798: Hardcoded Credentials
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123"

# CWE-327: Weak Cryptography
from hashlib import md5
def hash_password(password):
    return md5(password.encode()).hexdigest()
""")
        print("✓ Created test file with sample vulnerabilities\n")
    
    try:
        vulnerabilities = scan_directory(str(examples_path))
        print(f"✓ Found {len(vulnerabilities)} vulnerabilities\n")
        
        # Display sample vulnerabilities
        if vulnerabilities:
            print("Sample vulnerabilities:")
            for vuln in vulnerabilities[:5]:
                print(f"  - {vuln.cwe}: {vuln.title} ({vuln.severity})")
            if len(vulnerabilities) > 5:
                print(f"  ... and {len(vulnerabilities) - 5} more\n")
    except Exception as e:
        print(f"❌ Error scanning: {e}\n")
        return False
    
    # Step 2: Generate compliance reports
    print("\nStep 2: Generating compliance reports...")
    try:
        reporter = ComplianceReporter()
        standards = ['soc2', 'iso27001', 'pci-dss', 'owasp']
        reports = reporter.generate_report(vulnerabilities, standards=standards)
        print("✓ Generated compliance reports\n")
        
        # Display compliance scores
        print("Compliance Scores:")
        for std_key, std_report in reports.items():
            if std_key == 'summary':
                continue
            std_name = std_report.get('standard', std_key.upper())
            score = std_report.get('compliance_score', 0)
            status = std_report.get('overall_status', 'UNKNOWN')
            print(f"  • {std_name}: {score:.1f}% ({status})")
        print()
    except Exception as e:
        print(f"❌ Error generating reports: {e}\n")
        import traceback
        traceback.print_exc()
        return False
    
    # Step 3: Export to different formats
    print("\nStep 3: Exporting reports...")
    
    # JSON export
    try:
        json_path = Path("test_compliance_report.json")
        reporter.export_to_json(reports, json_path)
        print(f"✓ JSON report: {json_path}")
    except Exception as e:
        print(f"❌ JSON export failed: {e}")
    
    # Markdown export
    try:
        md_path = Path("test_compliance_report.md")
        md_content = reporter.generate_markdown_report(reports)
        with open(md_path, 'w') as f:
            f.write(md_content)
        print(f"✓ Markdown report: {md_path}")
    except Exception as e:
        print(f"❌ Markdown export failed: {e}")
    
    # PDF export
    try:
        pdf_path = Path("test_compliance_report.pdf")
        reporter.export_to_pdf(
            reports, 
            pdf_path,
            company_name="Parry Test Company"
        )
        print(f"✓ PDF report: {pdf_path}")
    except ImportError:
        print("⚠️  PDF export skipped (reportlab not installed)")
        print("   Install with: pip install reportlab")
    except Exception as e:
        print(f"❌ PDF export failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n✅ Compliance report generation test complete!")
    print("\nGenerated files:")
    print("  • test_compliance_report.json")
    print("  • test_compliance_report.md")
    print("  • test_compliance_report.pdf (if reportlab installed)")
    
    return True

if __name__ == "__main__":
    test_compliance_report()
