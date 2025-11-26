#!/usr/bin/env python3
"""Check progress of the 200 codebase scan"""

import json
from pathlib import Path

def check_progress():
    progress_file = Path("verified_exploitable_vulnerabilities.json")
    
    if not progress_file.exists():
        print("⚠️  Scan not started or no progress file found")
        print("   Check scan_200_output.log for status")
        return
    
    with open(progress_file, 'r') as f:
        data = json.load(f)
    
    stats = data.get('stats', {})
    vulns = data.get('verified_vulnerabilities', [])
    
    print("="*80)
    print("📊 SCAN PROGRESS")
    print("="*80)
    print()
    print(f"Codebases Scanned: {stats.get('codebases_scanned', 0)}")
    print(f"Total Findings: {stats.get('total_findings', 0)}")
    print(f"Filtered Noise: {stats.get('filtered_noise', 0)}")
    print(f"Verified Exploitable: {len(vulns)}/{stats.get('target', 150)}")
    print()
    
    if vulns:
        # Group by CWE
        from collections import defaultdict
        cwe_stats = defaultdict(int)
        repo_stats = defaultdict(int)
        
        for vuln in vulns:
            cwe_stats[vuln.get('cwe', 'UNKNOWN')] += 1
            repo_stats[vuln.get('_repository', 'unknown')] += 1
        
        print("Findings by CWE:")
        for cwe, count in sorted(cwe_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {cwe}: {count}")
        print()
        
        print("Top 10 Repositories:")
        for repo, count in sorted(repo_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {repo}: {count}")
        print()
    
    print(f"Progress: {len(vulns)/stats.get('target', 150)*100:.1f}%")
    print()
    
    if len(vulns) >= stats.get('target', 150):
        print("✅ TARGET REACHED!")
        print(f"   Found {len(vulns)} verified exploitable vulnerabilities")
    else:
        print(f"⏳ Still scanning... Need {stats.get('target', 150) - len(vulns)} more")

if __name__ == '__main__':
    check_progress()




