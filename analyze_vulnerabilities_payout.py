#!/usr/bin/env python3
"""
Analyze all vulnerabilities for exploitability and potential bug bounty payout
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

class VulnerabilityAnalyzer:
    """Analyze vulnerabilities for exploitability and payout potential"""
    
    def __init__(self):
        # Bug bounty payout ranges (based on HackerOne/Bugcrowd averages)
        # Adjusted for framework vulnerabilities (typically higher value)
        self.payout_ranges = {
            'Critical': {'min': 10000, 'max': 100000, 'avg': 30000},
            'High': {'min': 2000, 'max': 20000, 'avg': 6000},
            'Medium': {'min': 500, 'max': 5000, 'avg': 1500},
            'Low': {'min': 100, 'max': 1000, 'avg': 300},
        }
        
        # CWE-specific multipliers
        self.cwe_multipliers = {
            'CWE-502': 1.5,  # Deserialization - high value
            'CWE-89': 1.3,   # SQL Injection - high value
            'CWE-78': 1.4,   # Command Injection - very high value
            'CWE-22': 1.2,   # Path Traversal - medium-high
            'CWE-79': 1.0,   # XSS - standard
            'CWE-918': 1.6,  # SSRF - very high value
            'CWE-352': 0.8,  # CSRF - lower value
            'CWE-434': 1.3,  # File Upload - high value
        }
    
    def verify_exploitability(self, vuln: Dict) -> Tuple[bool, str, float]:
        """
        Verify if vulnerability is actually exploitable
        Returns: (is_exploitable, reason, confidence)
        """
        file_path = vuln.get('file_path', '')
        cwe = vuln.get('cwe', '')
        line_num = vuln.get('line_number', 0)
        verification_reason = vuln.get('_verification_reason', '')
        
        # Filter test files
        if any(x in file_path.lower() for x in ['/test', '/tests/', 'test_', '_test.py', '/test/', 'test.py']):
            return False, "Test file - not production code", 0.0
        
        # Check if file exists
        fp = Path(file_path)
        if not fp.exists():
            return False, "File not found", 0.0
        
        try:
            with open(fp, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            if line_num > len(lines) or line_num < 1:
                return False, "Line out of range", 0.0
            
            # Get context
            start = max(0, line_num - 40)
            end = min(len(lines), line_num + 40)
            context = ''.join(lines[start:end])
            vulnerable_line = lines[line_num - 1]
            
            # Check for user input indicators
            user_input_patterns = [
                r'request\.(get|post|args|form|json|data|cookies|headers|query)',
                r'input\s*=',
                r'form\[',
                r'query_params',
                r'\.get\(.*request',
                r'POST\[',
                r'GET\[',
                r'args\[',
                r'kwargs\[',
                r'body',
                r'params',
                r'\.input',
            ]
            
            has_user_input = any(re.search(pattern, context, re.IGNORECASE) for pattern in user_input_patterns)
            
            # CWE-specific verification
            if cwe == 'CWE-89':  # SQL Injection
                if not has_user_input:
                    return False, "No user input in SQL query", 0.0
                if '%' in vulnerable_line or 'f"' in vulnerable_line or '.format(' in vulnerable_line:
                    # Check if ORM (safe)
                    if any(x in context.lower() for x in ['.objects.', 'queryset', 'session.query', 'db.session']):
                        return False, "Uses ORM (safe)", 0.0
                    # Check if parameterized
                    if 'params' in context.lower() and '%s' in vulnerable_line:
                        return False, "Uses parameterized queries", 0.0
                    return True, "SQL injection with user input - exploitable", 0.9
            
            elif cwe == 'CWE-78':  # Command Injection
                if not has_user_input:
                    return False, "No user input in command", 0.0
                if any(x in context.lower() for x in ['os.system', 'subprocess', '.call(']):
                    if any(x in context.lower() for x in ['shlex.quote', 'escape', 'sanitize']):
                        return False, "Uses sanitization", 0.0
                    return True, "Command injection with user input - exploitable", 0.95
            
            elif cwe == 'CWE-22':  # Path Traversal
                if not has_user_input:
                    return False, "No user-controlled path", 0.0
                if any(x in context.lower() for x in ['open(', 'file(', '.read(', '.write(']):
                    if any(x in context.lower() for x in ['abspath', 'realpath', 'normpath']):
                        # Might still be exploitable
                        return True, "Path traversal with weak validation", 0.7
                    return True, "Path traversal with user input - exploitable", 0.9
            
            elif cwe == 'CWE-79':  # XSS
                if not has_user_input:
                    return False, "No user input", 0.0
                # Check if in template/view
                if 'template' in file_path.lower() or 'view' in file_path.lower() or 'jinja' in file_path.lower():
                    if any(x in context.lower() for x in ['|safe', 'mark_safe', 'autoescape false']):
                        return True, "XSS with escaping disabled", 0.9
                    if 'escape' not in context.lower() and 'autoescape' not in context.lower():
                        return True, "XSS without escaping", 0.8
                return False, "Not in exploitable context", 0.0
            
            elif cwe == 'CWE-502':  # Deserialization
                if not has_user_input:
                    return False, "No user input in deserialization", 0.0
                if 'pickle.loads' in context or 'pickle.load' in context:
                    # Check if from cache (requires infrastructure)
                    if any(x in file_path.lower() for x in ['cache', 'redis', 'db']):
                        if has_user_input:
                            return True, "Deserialization from user input (not just cache)", 0.85
                        return False, "Requires cache compromise", 0.0
                    return True, "Deserialization from user input - exploitable", 0.9
            
            # If has user input and passed basic checks
            if has_user_input:
                return True, verification_reason or "User input vulnerability", 0.75
            
            return False, "No user input detected", 0.0
            
        except Exception as e:
            return False, f"Error analyzing: {e}", 0.0
    
    def estimate_payout(self, vuln: Dict, is_exploitable: bool, confidence: float) -> Dict:
        """Estimate bug bounty payout for a vulnerability"""
        severity = vuln.get('severity', 'Medium')
        cwe = vuln.get('cwe', '')
        cvss = vuln.get('cvss_score', 5.0)
        
        # Base payout from severity
        base_range = self.payout_ranges.get(severity, self.payout_ranges['Medium'])
        
        # Apply CWE multiplier
        multiplier = self.cwe_multipliers.get(cwe, 1.0)
        
        # Apply confidence multiplier
        confidence_mult = 0.5 + (confidence * 0.5)  # 0.5 to 1.0
        
        # Calculate payout
        min_payout = int(base_range['min'] * multiplier * confidence_mult)
        max_payout = int(base_range['max'] * multiplier * confidence_mult)
        avg_payout = int(base_range['avg'] * multiplier * confidence_mult)
        
        # Adjust based on CVSS
        if cvss >= 9.0:
            min_payout = int(min_payout * 1.5)
            max_payout = int(max_payout * 1.5)
            avg_payout = int(avg_payout * 1.5)
        elif cvss >= 7.0:
            min_payout = int(min_payout * 1.2)
            max_payout = int(max_payout * 1.2)
            avg_payout = int(avg_payout * 1.2)
        
        return {
            'min': min_payout,
            'max': max_payout,
            'avg': avg_payout,
            'confidence': confidence,
            'is_exploitable': is_exploitable
        }
    
    def analyze_all(self, vulns: List[Dict]) -> Dict:
        """Analyze all vulnerabilities"""
        results = {
            'total': len(vulns),
            'verified_exploitable': 0,
            'not_exploitable': 0,
            'total_payout_min': 0,
            'total_payout_max': 0,
            'total_payout_avg': 0,
            'vulnerabilities': []
        }
        
        for vuln in vulns:
            # Verify exploitability
            is_exploitable, reason, confidence = self.verify_exploitability(vuln)
            
            # Estimate payout
            payout = self.estimate_payout(vuln, is_exploitable, confidence)
            
            analysis = {
                'vulnerability': vuln,
                'is_exploitable': is_exploitable,
                'exploitability_reason': reason,
                'confidence': confidence,
                'payout': payout,
                'repository': vuln.get('_repository', 'unknown'),
                'cwe': vuln.get('cwe', ''),
                'severity': vuln.get('severity', 'Medium'),
                'cvss': vuln.get('cvss_score', 5.0),
            }
            
            results['vulnerabilities'].append(analysis)
            
            if is_exploitable:
                results['verified_exploitable'] += 1
                results['total_payout_min'] += payout['min']
                results['total_payout_max'] += payout['max']
                results['total_payout_avg'] += payout['avg']
            else:
                results['not_exploitable'] += 1
        
        return results

def main():
    print("="*80)
    print("🔍 ANALYZING ALL VULNERABILITIES FOR EXPLOITABILITY & PAYOUT")
    print("="*80)
    print()
    
    # Load vulnerabilities
    vulns_file = Path("all_vulnerabilities_for_analysis.json")
    if not vulns_file.exists():
        # Try bulk scan file
        bulk_file = Path("bulk_scan_100_exploitable.json")
        if bulk_file.exists():
            with open(bulk_file, 'r') as f:
                data = json.load(f)
            vulns = data.get('verified_vulnerabilities', [])
            # Filter Rust files
            vulns = [v for v in vulns if not v.get('file_path', '').endswith('.rs')]
        else:
            print("❌ No vulnerability data found")
            return
    else:
        with open(vulns_file, 'r') as f:
            vulns = json.load(f)
    
    print(f"Analyzing {len(vulns)} vulnerabilities...")
    print()
    
    # Analyze
    analyzer = VulnerabilityAnalyzer()
    results = analyzer.analyze_all(vulns)
    
    # Print summary
    print("="*80)
    print("📊 ANALYSIS RESULTS")
    print("="*80)
    print()
    print(f"Total Vulnerabilities: {results['total']}")
    print(f"✅ Verified Exploitable: {results['verified_exploitable']}")
    print(f"❌ Not Exploitable: {results['not_exploitable']}")
    print(f"Precision: {results['verified_exploitable']/results['total']*100:.1f}%")
    print()
    
    print("="*80)
    print("💰 POTENTIAL BUG BOUNTY PAYOUT")
    print("="*80)
    print()
    print(f"Minimum Total Payout: ${results['total_payout_min']:,}")
    print(f"Maximum Total Payout: ${results['total_payout_max']:,}")
    print(f"Average Total Payout: ${results['total_payout_avg']:,}")
    print()
    
    # Group by exploitability
    exploitable = [v for v in results['vulnerabilities'] if v['is_exploitable']]
    not_exploitable = [v for v in results['vulnerabilities'] if not v['is_exploitable']]
    
    # Group exploitable by CWE
    cwe_stats = defaultdict(lambda: {'count': 0, 'total_payout': 0})
    for v in exploitable:
        cwe = v['cwe']
        cwe_stats[cwe]['count'] += 1
        cwe_stats[cwe]['total_payout'] += v['payout']['avg']
    
    print("Exploitable Vulnerabilities by CWE:")
    for cwe, stats in sorted(cwe_stats.items(), key=lambda x: x[1]['total_payout'], reverse=True):
        print(f"  {cwe}: {stats['count']} findings - ${stats['total_payout']:,} avg payout")
    print()
    
    # Group by repository
    repo_stats = defaultdict(lambda: {'count': 0, 'total_payout': 0})
    for v in exploitable:
        repo = v['repository']
        repo_stats[repo]['count'] += 1
        repo_stats[repo]['total_payout'] += v['payout']['avg']
    
    print("Top 10 Repositories by Payout Potential:")
    for repo, stats in sorted(repo_stats.items(), key=lambda x: x[1]['total_payout'], reverse=True)[:10]:
        print(f"  {repo}: {stats['count']} findings - ${stats['total_payout']:,} avg payout")
    print()
    
    # Save detailed results
    output_file = Path("vulnerability_analysis_payout.json")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"✅ Detailed analysis saved to: {output_file}")
    print()
    
    # Show top 10 by payout
    print("="*80)
    print("🏆 TOP 10 VULNERABILITIES BY PAYOUT POTENTIAL")
    print("="*80)
    print()
    
    top_10 = sorted(exploitable, key=lambda x: x['payout']['avg'], reverse=True)[:10]
    for i, v in enumerate(top_10, 1):
        vuln = v['vulnerability']
        print(f"{i}. {v['cwe']} - {vuln.get('title', 'N/A')}")
        print(f"   Repository: {v['repository']}")
        print(f"   File: {Path(vuln.get('file_path', '')).name}:{vuln.get('line_number')}")
        print(f"   Severity: {v['severity']} | CVSS: {v['cvss']}")
        print(f"   Payout: ${v['payout']['min']:,} - ${v['payout']['max']:,} (avg: ${v['payout']['avg']:,})")
        print(f"   Confidence: {v['confidence']:.1%}")
        print(f"   Reason: {v['exploitability_reason']}")
        print()

if __name__ == '__main__':
    main()

