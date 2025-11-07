#!/usr/bin/env python3
"""
Test Parry on a codebase and collect metrics
"""
import sys
import argparse
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def test_on_codebase(target_path, min_findings=0):
    """Test Parry on a codebase"""
    from parry.scanner import Scanner
    
    target = Path(target_path)
    if not target.exists():
        print(f"❌ Target path does not exist: {target_path}")
        return False
    
    print(f"🔍 Scanning: {target_path}")
    print("=" * 70)
    
    scanner = Scanner()
    start_time = time.time()
    
    try:
        results = scanner.scan(target)
        elapsed = time.time() - start_time
        
        vulnerabilities = results.get('vulnerabilities', [])
        files_scanned = results.get('files_scanned', 0)
        
        print(f"\n📊 Results:")
        print(f"   Files scanned: {files_scanned}")
        print(f"   Vulnerabilities found: {len(vulnerabilities)}")
        print(f"   Scan time: {elapsed:.2f}s")
        
        if files_scanned > 0:
            print(f"   Files/sec: {files_scanned / elapsed:.2f}")
        
        # Severity breakdown
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            print(f"\n📈 Severity Breakdown:")
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in severity_counts:
                    print(f"   {severity.capitalize()}: {severity_counts[severity]}")
        
        # CWE breakdown
        cwe_counts = {}
        for vuln in vulnerabilities:
            cwe = vuln.get('cwe', 'unknown')
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        if cwe_counts:
            print(f"\n🔍 Top 10 CWEs:")
            for cwe, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"   {cwe}: {count}")
        
        if len(vulnerabilities) < min_findings:
            print(f"\n⚠️  Warning: Found {len(vulnerabilities)} vulnerabilities, expected at least {min_findings}")
            return False
        
        print(f"\n✅ Test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error scanning codebase: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Parry on a codebase")
    parser.add_argument("--target", default="examples", help="Target directory to scan")
    parser.add_argument("--min-findings", type=int, default=0, help="Minimum number of findings expected")
    args = parser.parse_args()
    
    success = test_on_codebase(args.target, args.min_findings)
    sys.exit(0 if success else 1)

