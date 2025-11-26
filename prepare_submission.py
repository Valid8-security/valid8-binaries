#!/usr/bin/env python3
"""
Prepare Bug Bounty Submissions
Helps prepare and format reports for submission to bug bounty platforms
"""

import sys
import os
from pathlib import Path
import json
from typing import Dict, List, Any

def load_report(report_path: Path) -> Dict[str, Any]:
    """Load a JSON report"""
    with open(report_path, 'r') as f:
        return json.load(f)

def format_for_hackerone(report: Dict[str, Any]) -> str:
    """Format report for HackerOne submission"""
    return f"""# {report['title']}

## Summary
{report['description']}

## Description
{report['description']}

## Impact
{report['impact']}

## Steps to Reproduce
{report['proof_of_concept']}

## Remediation
{report['remediation']}

## References
{chr(10).join(f"- {ref}" for ref in report['references'])}

---
*Reported via Valid8 Security Scanner v{report['scanner_version']}*
*Confidence: {report['confidence']}*
"""

def format_for_bugcrowd(report: Dict[str, Any]) -> str:
    """Format report for Bugcrowd submission"""
    return f"""# {report['title']}

## Description
{report['description']}

## Impact
{report['impact']}

## Steps to Reproduce
{report['proof_of_concept']}

## Remediation
{report['remediation']}

## References
{chr(10).join(f"- {ref}" for ref in report['references'])}

---
*Severity: {report['severity']} | CVSS: {report['cvss_score']} | CWE: {report['cwe']}*
"""

def create_submission_package(platform: str, output_dir: Path):
    """Create submission package for a platform"""
    reports_dir = Path("bug_bounty_reports/json")
    if not reports_dir.exists():
        print("❌ Reports directory not found. Run generate_all_bug_bounty_reports.py first.")
        return
    
    output_dir.mkdir(exist_ok=True)
    
    reports = list(reports_dir.glob("*.json"))
    
    print(f"📦 Preparing {len(reports)} reports for {platform}...")
    
    for i, report_file in enumerate(reports, 1):
        try:
            report = load_report(report_file)
            
            if platform == "hackerone":
                formatted = format_for_hackerone(report)
            elif platform == "bugcrowd":
                formatted = format_for_bugcrowd(report)
            else:
                formatted = format_for_hackerone(report)  # Default
            
            # Save formatted report
            output_file = output_dir / f"{report_file.stem}_{platform}.md"
            with open(output_file, 'w') as f:
                f.write(formatted)
            
            if i % 20 == 0:
                print(f"  Processed {i}/{len(reports)} reports...")
        except Exception as e:
            print(f"  ⚠️  Error processing {report_file}: {e}")
    
    print(f"✅ Prepared {len(reports)} reports in {output_dir}")

def create_priority_list():
    """Create prioritized list of reports for submission"""
    reports_dir = Path("bug_bounty_reports/json")
    if not reports_dir.exists():
        print("❌ Reports directory not found.")
        return
    
    reports = []
    for report_file in reports_dir.glob("*.json"):
        try:
            report = load_report(report_file)
            reports.append({
                'file': report_file.name,
                'severity': report.get('severity', 'Unknown'),
                'cvss': report.get('cvss_score', 0),
                'cwe': report.get('cwe', 'UNKNOWN'),
                'repository': report.get('repository', 'unknown'),
            })
        except:
            continue
    
    # Sort by severity and CVSS
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Unknown': 4}
    reports.sort(key=lambda x: (severity_order.get(x['severity'], 4), -x['cvss']))
    
    # Save priority list
    output_file = Path("submission_priority.json")
    with open(output_file, 'w') as f:
        json.dump({
            'total': len(reports),
            'priority_order': reports
        }, f, indent=2)
    
    print(f"✅ Created priority list: {output_file}")
    print(f"   Total reports: {len(reports)}")
    print(f"   Critical: {sum(1 for r in reports if r['severity'] == 'Critical')}")
    print(f"   High: {sum(1 for r in reports if r['severity'] == 'High')}")
    print(f"   Medium: {sum(1 for r in reports if r['severity'] == 'Medium')}")

def main():
    print("="*80)
    print("📝 Prepare Bug Bounty Submissions")
    print("="*80)
    print()
    
    if len(sys.argv) > 1:
        platform = sys.argv[1].lower()
        if platform in ['hackerone', 'bugcrowd']:
            output_dir = Path(f"submissions_{platform}")
            create_submission_package(platform, output_dir)
        else:
            print(f"❌ Unknown platform: {platform}")
            print("   Supported: hackerone, bugcrowd")
    else:
        # Create priority list
        create_priority_list()
        print()
        print("💡 Usage:")
        print("   python3 prepare_submission.py hackerone  # Prepare for HackerOne")
        print("   python3 prepare_submission.py bugcrowd  # Prepare for Bugcrowd")

if __name__ == '__main__':
    main()




