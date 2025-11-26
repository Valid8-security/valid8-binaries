#!/usr/bin/env python3
"""
Automated Bug Bounty Submission System
Automates the submission process to bug bounty platforms
"""

import sys
import os
from pathlib import Path
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

sys.path.insert(0, os.getcwd())

class BugBountyAutomator:
    """Automated bug bounty submission system"""
    
    def __init__(self):
        self.reports_dir = Path("bug_bounty_reports/json")
        self.submissions_log = Path("submissions_log.json")
        self.load_submissions_log()
    
    def load_submissions_log(self):
        """Load submission tracking log"""
        if self.submissions_log.exists():
            with open(self.submissions_log, 'r') as f:
                self.log = json.load(f)
        else:
            self.log = {
                'submitted': [],
                'pending': [],
                'accepted': [],
                'rejected': [],
                'duplicates': []
            }
    
    def save_submissions_log(self):
        """Save submission tracking log"""
        with open(self.submissions_log, 'w') as f:
            json.dump(self.log, f, indent=2)
    
    def rank_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Rank all vulnerabilities by importance"""
        if not self.reports_dir.exists():
            return []
        
        reports = []
        for report_file in self.reports_dir.glob("*.json"):
            try:
                with open(report_file, 'r') as f:
                    report = json.load(f)
                    
                    # Calculate priority score
                    score = self._calculate_priority_score(report)
                    
                    reports.append({
                        'file': report_file.name,
                        'report': report,
                        'score': score
                    })
            except:
                continue
        
        # Sort by score (highest first)
        reports.sort(key=lambda x: x['score'], reverse=True)
        
        return reports
    
    def _calculate_priority_score(self, report: Dict[str, Any]) -> float:
        """Calculate priority score for a vulnerability"""
        score = 0.0
        
        # Severity weight (Critical=100, High=75, Medium=50, Low=25)
        severity_weights = {
            'Critical': 100,
            'High': 75,
            'Medium': 50,
            'Low': 25,
            'Unknown': 25
        }
        severity = report.get('severity', 'Unknown')
        score += severity_weights.get(severity, 25)
        
        # CVSS score (0-10, multiply by 5)
        cvss = report.get('cvss_score', 0)
        score += cvss * 5
        
        # CWE priority (some CWEs are more valuable)
        cwe_priority = {
            'CWE-089': 30,  # SQL Injection - very valuable
            'CWE-502': 25,  # Deserialization - RCE
            'CWE-78': 25,   # Command Injection - RCE
            'CWE-22': 20,   # Path Traversal
            'CWE-798': 15,  # Hardcoded Credentials
            'CWE-327': 10,  # Weak Crypto
            'CWE-79': 15,   # XSS
        }
        cwe = report.get('cwe', '')
        score += cwe_priority.get(cwe, 5)
        
        # Repository importance (some repos are more valuable)
        repo_importance = {
            'django': 20,
            'flask': 15,
            'cryptography': 20,
            'sqlalchemy': 15,
            'requests': 10,
            'twisted': 15,
            'pillow': 10,
            'pydantic': 10,
        }
        repo = report.get('repository', '')
        score += repo_importance.get(repo, 5)
        
        # Validation confidence (higher confidence = higher score)
        confidence = report.get('confidence', 'High')
        if 'High' in confidence or '97' in confidence:
            score += 10
        elif 'Medium' in confidence:
            score += 5
        
        return score
    
    def format_for_platform(self, report: Dict[str, Any], platform: str) -> str:
        """Format report for specific platform"""
        if platform == "hackerone":
            return self._format_hackerone(report)
        elif platform == "bugcrowd":
            return self._format_bugcrowd(report)
        else:
            return self._format_generic(report)
    
    def _format_hackerone(self, report: Dict[str, Any]) -> str:
        """Format for HackerOne"""
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
*CWE: {report['cwe']} | CVSS: {report['cvss_score']}*
"""
    
    def _format_bugcrowd(self, report: Dict[str, Any]) -> str:
        """Format for Bugcrowd"""
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
    
    def _format_generic(self, report: Dict[str, Any]) -> str:
        """Generic format"""
        return f"""# {report['title']}

**Severity:** {report['severity']} | **CVSS:** {report['cvss_score']} | **CWE:** {report['cwe']}

## Description
{report['description']}

## Impact
{report['impact']}

## Proof of Concept
{report['proof_of_concept']}

## Remediation
{report['remediation']}

## References
{chr(10).join(f"- {ref}" for ref in report['references'])}
"""
    
    def prepare_top_submissions(self, count: int = 5, diverse: bool = True) -> List[Dict[str, Any]]:
        """Prepare top N vulnerabilities for submission (with diversity option)"""
        ranked = self.rank_vulnerabilities()
        
        top_submissions = []
        seen_cwe = set()
        seen_repo = set()
        
        for item in ranked:
            if len(top_submissions) >= count:
                break
            
            report = item['report']
            cwe = report.get('cwe', '')
            repo = report.get('repository', '')
            
            # If diverse mode, prioritize different CWEs and repos
            if diverse:
                # First 2 can be any, then prefer diversity
                if len(top_submissions) < 2:
                    include = True
                elif cwe not in seen_cwe or repo not in seen_repo:
                    include = True
                else:
                    # Skip if we already have this CWE and repo
                    continue
            else:
                include = True
            
            if include:
                submission = {
                    'rank': len(top_submissions) + 1,
                    'score': item['score'],
                    'file': item['file'],
                    'title': report['title'],
                    'severity': report['severity'],
                    'cvss': report['cvss_score'],
                    'cwe': report['cwe'],
                    'repository': report['repository'],
                    'file_path': report['file_path'],
                    'line_number': report['line_number'],
                    'hackerone_format': self.format_for_platform(report, 'hackerone'),
                    'bugcrowd_format': self.format_for_platform(report, 'bugcrowd'),
                    'generic_format': self.format_for_platform(report, 'generic'),
                    'report_data': report
                }
                top_submissions.append(submission)
                seen_cwe.add(cwe)
                seen_repo.add(repo)
        
        return top_submissions
    
    def save_top_submissions(self, submissions: List[Dict[str, Any]], output_dir: Path):
        """Save top submissions to files"""
        output_dir.mkdir(exist_ok=True)
        
        # Save individual files
        for sub in submissions:
            # Save HackerOne format
            h1_file = output_dir / f"rank{sub['rank']}_{sub['cwe']}_hackerone.md"
            with open(h1_file, 'w') as f:
                f.write(sub['hackerone_format'])
            
            # Save Bugcrowd format
            bc_file = output_dir / f"rank{sub['rank']}_{sub['cwe']}_bugcrowd.md"
            with open(bc_file, 'w') as f:
                f.write(sub['bugcrowd_format'])
        
        # Save summary
        summary = {
            'generated': datetime.now().isoformat(),
            'total_ranked': len(self.rank_vulnerabilities()),
            'top_submissions': [
                {
                    'rank': s['rank'],
                    'score': s['score'],
                    'title': s['title'],
                    'severity': s['severity'],
                    'cvss': s['cvss'],
                    'cwe': s['cwe'],
                    'repository': s['repository'],
                    'file_path': s['file_path'],
                    'line_number': s['line_number']
                }
                for s in submissions
            ]
        }
        
        summary_file = output_dir / "TOP_5_SUBMISSIONS.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return summary_file

def main():
    print("="*80)
    print("🤖 Automated Bug Bounty Submission System")
    print("="*80)
    print()
    
    automator = BugBountyAutomator()
    
    # Rank all vulnerabilities
    print("📊 Ranking all vulnerabilities...")
    ranked = automator.rank_vulnerabilities()
    print(f"✅ Ranked {len(ranked)} vulnerabilities")
    print()
    
    # Save full ranking
    ranking_file = Path("vulnerability_ranking.json")
    with open(ranking_file, 'w') as f:
        json.dump({
            'total': len(ranked),
            'ranked': [
                {
                    'rank': i+1,
                    'score': item['score'],
                    'title': item['report']['title'],
                    'severity': item['report']['severity'],
                    'cvss': item['report']['cvss_score'],
                    'cwe': item['report']['cwe'],
                    'repository': item['report']['repository'],
                    'file': item['file']
                }
                for i, item in enumerate(ranked)
            ]
        }, f, indent=2)
    print(f"📄 Full ranking saved to: {ranking_file}")
    print()
    
    # Prepare top 5
    print("🎯 Preparing top 5 submissions...")
    top_5 = automator.prepare_top_submissions(count=5)
    
    # Save top 5
    output_dir = Path("top_5_submissions")
    summary_file = automator.save_top_submissions(top_5, output_dir)
    
    print(f"✅ Top 5 submissions prepared in: {output_dir}")
    print(f"📄 Summary saved to: {summary_file}")
    print()
    
    # Display top 5
    print("="*80)
    print("🏆 TOP 5 VULNERABILITIES FOR IMMEDIATE SUBMISSION")
    print("="*80)
    print()
    
    for sub in top_5:
        print(f"Rank #{sub['rank']} (Score: {sub['score']:.1f})")
        print(f"  Title: {sub['title']}")
        print(f"  Severity: {sub['severity']} | CVSS: {sub['cvss']} | CWE: {sub['cwe']}")
        print(f"  Repository: {sub['repository']}")
        print(f"  File: {sub['file_path']}:{sub['line_number']}")
        print(f"  Formats: {output_dir}/rank{sub['rank']}_{sub['cwe']}_*.md")
        print()
    
    print("="*80)
    print("📋 NEXT STEPS")
    print("="*80)
    print()
    print("1. Review top 5 submissions in: top_5_submissions/")
    print("2. Choose target platform (HackerOne/Bugcrowd)")
    print("3. Find appropriate program accepting automated tools")
    print("4. Copy formatted report and submit")
    print("5. Track submission in submissions_log.json")
    print()
    print("💡 See HOW_TO_REPORT_BOUNTIES.md for detailed submission guide")
    print("="*80)

if __name__ == '__main__':
    main()

