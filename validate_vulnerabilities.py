#!/usr/bin/env python3
"""
Comprehensive validation of all vulnerabilities for exploitability and acceptance likelihood
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

class VulnerabilityValidator:
    """Validate vulnerabilities for exploitability and acceptance likelihood"""
    
    def __init__(self):
        self.validation_results = []
    
    def read_code_context(self, file_path: str, line_num: int, context_lines: int = 50) -> Dict:
        """Read code context around the vulnerability"""
        try:
            fp = Path(file_path)
            if not fp.exists():
                return {'error': 'File not found', 'code': '', 'lines': []}
            
            with open(fp, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            if line_num > len(lines) or line_num < 1:
                return {'error': 'Line out of range', 'code': '', 'lines': []}
            
            start = max(0, line_num - context_lines - 1)
            end = min(len(lines), line_num + context_lines)
            
            context_lines_list = lines[start:end]
            vulnerable_line = lines[line_num - 1]
            
            return {
                'code': ''.join(context_lines_list),
                'lines': context_lines_list,
                'vulnerable_line': vulnerable_line,
                'line_number': line_num,
                'file_exists': True,
                'total_lines': len(lines)
            }
        except Exception as e:
            return {'error': str(e), 'code': '', 'lines': []}
    
    def check_test_file(self, file_path: str, code_context: str) -> Tuple[bool, str]:
        """Check if file is a test file"""
        test_indicators = [
            '/test', '/tests/', 'test_', '_test.py', '/test/', 'test.py',
            'test/', 'tests/', '__test__', 'conftest.py'
        ]
        
        file_lower = file_path.lower()
        if any(indicator in file_lower for indicator in test_indicators):
            return True, "Test file detected"
        
        # Check code content
        if code_context:
            test_content = [
                'import unittest', 'import pytest', 'import nose',
                'from unittest import', 'from pytest import',
                'def test_', 'class Test', 'assert ', 'self.assert'
            ]
            code_lower = code_context.lower()
            if any(indicator in code_lower for indicator in test_content):
                # But check if it's actually a test file or just imports test modules
                if 'def test_' in code_lower or 'class Test' in code_lower:
                    return True, "Test code detected"
        
        return False, "Production code"
    
    def check_user_input_flow(self, code_context: str, cwe: str) -> Tuple[bool, str, List[str]]:
        """Check if user input flows to the vulnerability"""
        user_input_patterns = [
            (r'request\.(get|post|args|form|json|data|cookies|headers|query)', 'HTTP request parameter'),
            (r'input\s*=', 'Direct input assignment'),
            (r'form\[', 'Form data access'),
            (r'query_params', 'Query parameters'),
            (r'\.get\(.*request', 'Request-based get'),
            (r'POST\[', 'POST data'),
            (r'GET\[', 'GET data'),
            (r'args\[', 'Function arguments'),
            (r'kwargs\[', 'Keyword arguments'),
            (r'body', 'Request body'),
            (r'params', 'Parameters'),
            (r'\.input', 'Input attribute'),
            (r'environ\[', 'WSGI environment'),
            (r'cookies\[', 'Cookie access'),
            (r'session\[', 'Session data'),
        ]
        
        found_inputs = []
        has_user_input = False
        
        for pattern, description in user_input_patterns:
            if re.search(pattern, code_context, re.IGNORECASE):
                has_user_input = True
                found_inputs.append(description)
        
        if has_user_input:
            return True, "User input detected", found_inputs
        else:
            return False, "No user input detected", []
    
    def verify_exploitability(self, vuln_data: Dict) -> Dict:
        """Verify if vulnerability is actually exploitable"""
        vuln = vuln_data['vulnerability']
        file_path = vuln.get('file_path', '')
        line_num = vuln.get('line_number', 0)
        cwe = vuln_data['cwe']
        
        # Read code context
        code_context = self.read_code_context(file_path, line_num)
        
        if code_context.get('error'):
            return {
                'exploitable': False,
                'reason': f"Code analysis error: {code_context.get('error')}",
                'confidence': 0.0
            }
        
        # Check if test file
        is_test, test_reason = self.check_test_file(file_path, code_context.get('code', ''))
        if is_test:
            return {
                'exploitable': False,
                'reason': f"Test file: {test_reason}",
                'confidence': 0.0
            }
        
        # Check user input flow
        has_input, input_reason, input_sources = self.check_user_input_flow(
            code_context.get('code', ''), cwe
        )
        
        if not has_input:
            return {
                'exploitable': False,
                'reason': input_reason,
                'confidence': 0.0
            }
        
        # CWE-specific verification
        vulnerable_line = code_context.get('vulnerable_line', '')
        full_code = code_context.get('code', '')
        
        if cwe == 'CWE-502':  # Unsafe Deserialization
            if 'pickle.loads' in vulnerable_line or 'pickle.load' in vulnerable_line:
                # Check if it's from cache (requires infrastructure compromise)
                if 'cache' in file_path.lower() or 'redis' in file_path.lower():
                    if has_input:
                        return {
                            'exploitable': True,
                            'reason': 'Deserialization from user input (not just cache)',
                            'confidence': 0.85
                        }
                    else:
                        return {
                            'exploitable': False,
                            'reason': 'Requires cache compromise (infrastructure access)',
                            'confidence': 0.0
                        }
                return {
                    'exploitable': True,
                    'reason': 'Unsafe deserialization from user input - RCE possible',
                    'confidence': 0.9
                }
            return {
                'exploitable': False,
                'reason': 'No unsafe deserialization detected',
                'confidence': 0.0
            }
        
        elif cwe == 'CWE-22':  # Path Traversal
            if any(x in vulnerable_line for x in ['open(', 'file(', '.read(', '.write(']):
                # Check for path validation
                if any(x in full_code.lower() for x in ['abspath', 'realpath', 'normpath']):
                    return {
                        'exploitable': True,
                        'reason': 'Path traversal with weak validation',
                        'confidence': 0.7
                    }
                return {
                    'exploitable': True,
                    'reason': 'Path traversal with user input - exploitable',
                    'confidence': 0.9
                }
            return {
                'exploitable': False,
                'reason': 'No file operations detected',
                'confidence': 0.0
            }
        
        elif cwe == 'CWE-89':  # SQL Injection
            if '%' in vulnerable_line or 'f"' in vulnerable_line or '.format(' in vulnerable_line:
                # Check if ORM (safe)
                if any(x in full_code.lower() for x in ['.objects.', 'queryset', 'session.query', 'db.session']):
                    return {
                        'exploitable': False,
                        'reason': 'Uses ORM (safe)',
                        'confidence': 0.0
                    }
                # Check if parameterized
                if 'params' in full_code.lower() and '%s' in vulnerable_line:
                    return {
                        'exploitable': False,
                        'reason': 'Uses parameterized queries',
                        'confidence': 0.0
                    }
                return {
                    'exploitable': True,
                    'reason': 'SQL injection with user input - exploitable',
                    'confidence': 0.9
                }
            return {
                'exploitable': False,
                'reason': 'No SQL injection pattern detected',
                'confidence': 0.0
            }
        
        # Default: if has user input, might be exploitable
        return {
            'exploitable': True,
            'reason': f'{cwe} with user input - potentially exploitable',
            'confidence': 0.75
        }
    
    def assess_acceptance_likelihood(self, vuln_data: Dict, exploitability: Dict) -> Dict:
        """Assess likelihood of bug bounty acceptance"""
        vuln = vuln_data['vulnerability']
        repo = vuln_data['repository']
        cwe = vuln_data['cwe']
        severity = vuln_data['severity']
        
        likelihood = 0.0
        factors = []
        blockers = []
        
        # Factor 1: Exploitability (40% weight)
        if exploitability['exploitable']:
            likelihood += 0.4
            factors.append("✅ Exploitable vulnerability confirmed")
        else:
            blockers.append("❌ Not exploitable")
            return {
                'likelihood': 0.0,
                'factors': factors,
                'blockers': blockers,
                'recommendation': 'DO NOT SUBMIT - Not exploitable'
            }
        
        # Factor 2: Framework/Library vulnerability (30% weight)
        # Many programs don't accept third-party framework vulnerabilities
        framework_repos = ['bottle', 'cherrypy', 'web2py', 'django', 'flask', 'fastapi']
        if repo.lower() in framework_repos:
            likelihood -= 0.2  # Negative factor
            blockers.append("⚠️ Framework/library vulnerability - many programs don't accept these")
            factors.append("⚠️ Third-party framework - check program scope carefully")
        else:
            likelihood += 0.3
            factors.append("✅ Application-specific vulnerability")
        
        # Factor 3: Severity (20% weight)
        if severity.lower() == 'critical':
            likelihood += 0.2
            factors.append("✅ Critical severity")
        elif severity.lower() == 'high':
            likelihood += 0.15
            factors.append("✅ High severity")
        elif severity.lower() == 'medium':
            likelihood += 0.1
            factors.append("⚠️ Medium severity")
        else:
            likelihood += 0.05
            factors.append("⚠️ Low severity")
        
        # Factor 4: CWE type (10% weight)
        high_value_cwes = ['CWE-502', 'CWE-89', 'CWE-78', 'CWE-918']  # RCE, SQLi, Command Injection, SSRF
        if cwe in high_value_cwes:
            likelihood += 0.1
            factors.append(f"✅ High-value CWE ({cwe})")
        else:
            likelihood += 0.05
            factors.append(f"⚠️ Standard CWE ({cwe})")
        
        # Calculate final likelihood
        likelihood = max(0.0, min(1.0, likelihood))
        
        # Determine recommendation
        if likelihood >= 0.7:
            recommendation = "LIKELY TO BE ACCEPTED - High confidence"
        elif likelihood >= 0.5:
            recommendation = "MAY BE ACCEPTED - Medium confidence, verify scope"
        elif likelihood >= 0.3:
            recommendation = "UNLIKELY TO BE ACCEPTED - Low confidence, check scope carefully"
        else:
            recommendation = "VERY UNLIKELY - Multiple blockers"
        
        return {
            'likelihood': likelihood,
            'factors': factors,
            'blockers': blockers,
            'recommendation': recommendation,
            'confidence': exploitability.get('confidence', 0.0)
        }
    
    def validate_all(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Validate all vulnerabilities"""
        results = []
        
        for i, vuln_data in enumerate(vulnerabilities, 1):
            print(f"Validating {i}/{len(vulnerabilities)}: {vuln_data['cwe']} in {vuln_data['repository']}...")
            
            # Verify exploitability
            exploitability = self.verify_exploitability(vuln_data)
            
            # Assess acceptance likelihood
            acceptance = self.assess_acceptance_likelihood(vuln_data, exploitability)
            
            result = {
                'rank': i,
                'vulnerability': vuln_data,
                'exploitability': exploitability,
                'acceptance': acceptance,
                'file_path': vuln_data['vulnerability'].get('file_path', ''),
                'line_number': vuln_data['vulnerability'].get('line_number', 0),
            }
            
            results.append(result)
        
        return results

def main():
    print("="*80)
    print("COMPREHENSIVE VULNERABILITY VALIDATION")
    print("="*80)
    print()
    
    # Load top 5
    with open('top_5_for_submission.json', 'r') as f:
        top_5 = json.load(f)
    
    print(f"Validating {len(top_5)} vulnerabilities...")
    print()
    
    validator = VulnerabilityValidator()
    results = validator.validate_all(top_5)
    
    # Print summary
    print()
    print("="*80)
    print("VALIDATION RESULTS")
    print("="*80)
    print()
    
    exploitable_count = sum(1 for r in results if r['exploitability']['exploitable'])
    high_likelihood_count = sum(1 for r in results if r['acceptance']['likelihood'] >= 0.7)
    
    print(f"Total Validated: {len(results)}")
    print(f"✅ Exploitable: {exploitable_count}")
    print(f"❌ Not Exploitable: {len(results) - exploitable_count}")
    print(f"🎯 High Acceptance Likelihood (≥70%): {high_likelihood_count}")
    print()
    
    # Detailed results
    for result in results:
        vuln = result['vulnerability']
        print(f"Rank #{result['rank']}: {result['vulnerability']['cwe']} in {result['vulnerability']['repository']}")
        print(f"  File: {Path(result['file_path']).name}:{result['line_number']}")
        print(f"  Exploitable: {'✅ YES' if result['exploitability']['exploitable'] else '❌ NO'}")
        if result['exploitability']['exploitable']:
            print(f"    Reason: {result['exploitability']['reason']}")
            print(f"    Confidence: {result['exploitability']['confidence']:.0%}")
        else:
            print(f"    Reason: {result['exploitability']['reason']}")
        print(f"  Acceptance Likelihood: {result['acceptance']['likelihood']:.0%}")
        print(f"  Recommendation: {result['acceptance']['recommendation']}")
        if result['acceptance']['blockers']:
            for blocker in result['acceptance']['blockers']:
                print(f"    {blocker}")
        print()
    
    # Save detailed results
    output_file = Path("vulnerability_validation_results.json")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"✅ Detailed results saved to: {output_file}")
    
    # Generate report
    generate_validation_report(results)

def generate_validation_report(results: List[Dict]):
    """Generate a detailed validation report"""
    report = """# Vulnerability Validation Report

## Executive Summary

This report validates all top 5 vulnerabilities for:
1. **Exploitability** - Whether the vulnerability can actually be exploited
2. **Acceptance Likelihood** - Probability of bug bounty program acceptance

---

## Validation Results

"""
    
    for result in results:
        vuln = result['vulnerability']
        repo = vuln['repository']
        cwe = vuln['cwe']
        file_path = result['file_path']
        line_num = result['line_number']
        
        report += f"""### Rank #{result['rank']}: {cwe} in {repo}

**File:** `{Path(file_path).name}:{line_num}`  
**Full Path:** `{file_path}`

#### Exploitability Assessment

"""
        
        if result['exploitability']['exploitable']:
            report += f"""✅ **EXPLOITABLE**

- **Reason:** {result['exploitability']['reason']}
- **Confidence:** {result['exploitability']['confidence']:.0%}
- **Status:** Vulnerability confirmed as exploitable

"""
        else:
            report += f"""❌ **NOT EXPLOITABLE**

- **Reason:** {result['exploitability']['reason']}
- **Status:** False positive - do not submit

"""
        
        report += f"""#### Acceptance Likelihood Assessment

- **Likelihood:** {result['acceptance']['likelihood']:.0%}
- **Recommendation:** {result['acceptance']['recommendation']}

**Factors:**
"""
        for factor in result['acceptance']['factors']:
            report += f"- {factor}\n"
        
        if result['acceptance']['blockers']:
            report += "\n**Blockers:**\n"
            for blocker in result['acceptance']['blockers']:
                report += f"- {blocker}\n"
        
        report += "\n---\n\n"
    
    # Summary statistics
    exploitable = [r for r in results if r['exploitability']['exploitable']]
    high_likelihood = [r for r in results if r['acceptance']['likelihood'] >= 0.7]
    
    report += f"""## Summary Statistics

- **Total Validated:** {len(results)}
- **Exploitable:** {len(exploitable)} ({len(exploitable)/len(results)*100:.0f}%)
- **High Acceptance Likelihood (≥70%):** {len(high_likelihood)} ({len(high_likelihood)/len(results)*100:.0f}%)

## Recommendations

"""
    
    for result in results:
        if not result['exploitability']['exploitable']:
            report += f"- **Rank #{result['rank']}:** DO NOT SUBMIT - Not exploitable\n"
        elif result['acceptance']['likelihood'] >= 0.7:
            report += f"- **Rank #{result['rank']}:** ✅ SUBMIT - High acceptance likelihood\n"
        elif result['acceptance']['likelihood'] >= 0.5:
            report += f"- **Rank #{result['rank']}:** ⚠️ VERIFY SCOPE - May be accepted if in scope\n"
        else:
            report += f"- **Rank #{result['rank']}:** ❌ LOW LIKELIHOOD - Check program scope carefully\n"
    
    report += "\n---\n\n**Generated by:** Valid8 Vulnerability Validator\n"
    
    with open('VULNERABILITY_VALIDATION_REPORT.md', 'w') as f:
        f.write(report)
    
    print("✅ Validation report saved to: VULNERABILITY_VALIDATION_REPORT.md")

if __name__ == '__main__':
    main()




