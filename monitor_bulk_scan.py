#!/usr/bin/env python3
"""Monitor bulk scan progress"""

import json
import time
from pathlib import Path
from collections import defaultdict

def monitor_scan():
    progress_file = Path("bulk_scan_100_exploitable.json")
    
    print("="*80)
    print("📊 BULK SCAN MONITOR")
    print("="*80)
    print()
    
    if not progress_file.exists():
        print("⏳ Scan not started or progress file not found")
        return
    
    with open(progress_file, 'r') as f:
        data = json.load(f)
    
    stats = data.get('stats', {})
    vulns = data.get('verified_vulnerabilities', [])
    distinct = data.get('distinct_issues', [])
    
    print(f"Target: {stats.get('target', 100)} distinct exploitable vulnerabilities")
    print(f"Current: {len(vulns)} verified exploitable")
    print(f"Distinct Issues: {len(distinct)}")
    print(f"Progress: {len(vulns)/stats.get('target', 100)*100:.1f}%")
    print()
    
    print(f"Codebases Scanned: {stats.get('codebases_scanned', 0)}")
    print(f"Total Findings: {stats.get('total_findings', 0)}")
    print(f"Filtered Noise: {stats.get('filtered_noise', 0)}")
    print()
    
    # Group by CWE
    cwe_stats = defaultdict(int)
    for v in vulns:
        cwe_stats[v.get('cwe', 'UNKNOWN')] += 1
    
    print("Findings by CWE:")
    for cwe, count in sorted(cwe_stats.items(), key=lambda x: x[1], reverse=True):
        print(f"  {cwe}: {count}")
    print()
    
    # Group by repository
    repo_stats = defaultdict(int)
    for v in vulns:
        repo_stats[v.get('_repository', 'unknown')] += 1
    
    print("Top 10 Repositories:")
    for repo, count in sorted(repo_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {repo}: {count}")
    print()
    
    if len(vulns) >= stats.get('target', 100):
        print("="*80)
        print("✅ TARGET REACHED!")
        print("="*80)
        print(f"Found {len(vulns)} verified exploitable vulnerabilities")
        print(f"Found {len(distinct)} distinct issues")
    else:
        remaining = stats.get('target', 100) - len(vulns)
        print(f"⏳ Still scanning... {remaining} more needed")
        print()
        print("Recent findings:")
        for v in vulns[-5:]:
            print(f"  - {v.get('cwe')} in {v.get('_repository')} - {Path(v.get('file_path', '')).name}:{v.get('line_number')}")

if __name__ == '__main__':
    monitor_scan()




