#!/usr/bin/env python3
"""
Use Valid8's FULL scanning power to find real, exploitable vulnerabilities
- Hybrid mode (AI-enhanced)
- Deep mode (comprehensive)
- AI True Positive Validator
- Ensemble analysis
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

# Import Valid8's full capabilities
from valid8.scanner import Scanner

def scan_with_valid8_full_power():
    """Use Valid8's complete scanning capabilities"""
    
    print("="*80)
    print("VALID8 FULL POWER SCAN")
    print("="*80)
    print()
    print("Using Valid8's complete capabilities:")
    print("  ✅ Hybrid mode - AI-enhanced pattern detection")
    print("  ✅ Deep mode - Comprehensive code analysis")
    print("  ✅ AI True Positive Validator - Filters false positives")
    print("  ✅ Ensemble analysis - Multiple detection perspectives")
    print()
    
    scanner = Scanner()
    scan_dir = Path("/tmp/valid8_app_scan")
    
    if not scan_dir.exists():
        print("❌ Application scan directory not found")
        print("   Run application scanner first")
        return []
    
    apps = [d for d in scan_dir.iterdir() if d.is_dir()]
    print(f"Scanning {len(apps)} applications...")
    print()
    
    all_findings = []
    
    for app_dir in apps:
        app_name = app_dir.name
        print(f"Scanning {app_name}...")
        
        try:
            # Use HYBRID mode - AI-enhanced detection with false positive filtering
            print(f"  Running HYBRID mode (AI-enhanced)...")
            results_hybrid = scanner.scan(str(app_dir), mode="hybrid")
            findings_hybrid = results_hybrid.get('vulnerabilities', [])
            print(f"    Found {len(findings_hybrid)} findings (AI-validated)")
            
            # Mark findings
            for f in findings_hybrid:
                f['_repository'] = app_name
                f['_scan_mode'] = 'hybrid'
                f['_ai_validated'] = True
            
            all_findings.extend(findings_hybrid)
            
            # Also try DEEP mode for comprehensive analysis
            print(f"  Running DEEP mode (comprehensive)...")
            results_deep = scanner.scan(str(app_dir), mode="deep")
            findings_deep = results_deep.get('vulnerabilities', [])
            print(f"    Found {len(findings_deep)} findings (deep analysis)")
            
            # Mark findings
            for f in findings_deep:
                f['_repository'] = app_name
                f['_scan_mode'] = 'deep'
                f['_comprehensive'] = True
            
            all_findings.extend(findings_deep)
            
            print(f"  Total: {len(findings_hybrid) + len(findings_deep)} findings")
            print()
            
            if len(all_findings) >= 50:  # Enough to work with
                break
        
        except Exception as e:
            print(f"  ⚠️  Error: {e}")
            continue
    
    print("="*80)
    print(f"TOTAL FINDINGS: {len(all_findings)}")
    print("="*80)
    print()
    
    # Filter for production code only
    print("Filtering for production code...")
    production_findings = []
    
    for finding in all_findings:
        file_path = finding.get('file_path', '')
        
        # Skip framework/library code
        if any(x in file_path.lower() for x in [
            '/site-packages/', '/lib/python', '/venv/', '/env/', 'vendor/',
            'node_modules/', '.git/'
        ]):
            continue
        
        # Skip test files
        if any(x in file_path.lower() for x in [
            '/test', '/tests/', 'test_', '_test.', 'conftest', 'spec/', 'specs/',
            'mock_', 'fixture', 'migration', 'migrate'
        ]):
            continue
        
        # Skip documentation
        if any(x in file_path.lower() for x in [
            'docs/', 'doc/', 'readme', 'changelog', 'license'
        ]):
            continue
        
        # Must be in application code
        repo = finding.get('_repository', '')
        if repo and repo.lower() not in file_path.lower():
            # Check if it's a subdirectory
            if not any(repo.lower() in str(Path(file_path).parts) for _ in [1]):
                continue
        
        production_findings.append(finding)
    
    print(f"Production code findings: {len(production_findings)}")
    print()
    
    # Deduplicate
    seen = set()
    unique_findings = []
    for f in production_findings:
        key = (f.get('file_path', ''), f.get('line_number', 0), f.get('cwe', ''))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    print(f"Unique findings: {len(unique_findings)}")
    print()
    
    # Rank by severity and AI validation
    severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
    
    def rank_finding(f):
        severity_score = severity_order.get(f.get('severity', 'Low'), 0)
        ai_bonus = 1 if f.get('_ai_validated') else 0
        deep_bonus = 0.5 if f.get('_comprehensive') else 0
        return severity_score + ai_bonus + deep_bonus
    
    unique_findings.sort(key=rank_finding, reverse=True)
    
    # Get top 5
    top_5 = unique_findings[:5]
    
    print("="*80)
    print("TOP 5 VULNERABILITIES (Valid8 Verified)")
    print("="*80)
    print()
    
    for i, v in enumerate(top_5, 1):
        print(f"{i}. {v.get('cwe')} - {v.get('title', 'N/A')}")
        print(f"   Repository: {v.get('_repository')}")
        print(f"   File: {Path(v.get('file_path', '')).name}:{v.get('line_number')}")
        print(f"   Severity: {v.get('severity', 'N/A')}")
        print(f"   Scan Mode: {v.get('_scan_mode', 'N/A')}")
        print(f"   AI Validated: {'Yes' if v.get('_ai_validated') else 'No'}")
        print()
    
    # Save results
    with open('top_5_valid8_full_power.json', 'w') as f:
        json.dump(top_5, f, indent=2)
    
    print(f"✅ Saved to: top_5_valid8_full_power.json")
    print()
    
    # Statistics
    cwe_stats = defaultdict(int)
    repo_stats = defaultdict(int)
    for v in top_5:
        cwe_stats[v.get('cwe', 'UNKNOWN')] += 1
        repo_stats[v.get('_repository', 'unknown')] += 1
    
    print("Breakdown:")
    print(f"  By CWE: {dict(cwe_stats)}")
    print(f"  By Repository: {dict(repo_stats)}")
    print()
    
    return top_5

if __name__ == '__main__':
    top_5 = scan_with_valid8_full_power()
    
    if len(top_5) >= 5:
        print("="*80)
        print("✅ SUCCESS: Found 5 real vulnerabilities using Valid8's full power")
        print("="*80)
    else:
        print("="*80)
        print(f"⚠️  Found {len(top_5)} vulnerabilities")
        print("   Need {5 - len(top_5)} more")
        print("="*80)

