#!/usr/bin/env python3
"""
Noise Elimination Filters
Filters out non-exploitable findings to reduce false positives
"""

from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re

class NoiseEliminationFilter:
    """Filters out noise and non-exploitable findings"""
    
    def __init__(self):
        # Patterns that indicate non-exploitable code
        self.safe_patterns = {
            'quote_name': r'quote_name\s*\(',
            'escape': r'escape\s*\(',
            'sanitize': r'sanitize\s*\(',
            'validate': r'validate\s*\(',
        }
        
        # Internal code indicators
        self.internal_code_indicators = [
            'settings',
            'operations',
            'internal',
            'private',
            '_',
        ]
        
        # Static file patterns
        self.static_file_patterns = [
            r'/static/',
            r'/admin/static/',
            r'\.js$',
            r'flamegraph',
            r'profiling',
        ]
        
        # Test file patterns
        self.test_file_patterns = [
            r'/test',
            r'/tests/',
            r'test_',
            r'_test\.py',
            r'bench',
            r'example',
        ]
    
    def requires_infrastructure_compromise(self, report: Dict) -> bool:
        """Check if finding requires infrastructure compromise"""
        cwe = report.get('cwe', '')
        file_path = report.get('file_path', '')
        
        # CWE-502 (pickle deserialization) requires cache/DB access
        if cwe == 'CWE-502':
            if any(x in file_path.lower() for x in ['cache', 'redis', 'db', 'database']):
                return True
        
        return False
    
    def requires_config_control(self, report: Dict, code_context: str) -> bool:
        """Check if finding requires configuration control"""
        cwe = report.get('cwe', '')
        
        if cwe == 'CWE-89':  # SQL injection
            # Check if it uses settings, connection URLs, or config
            if any(x in code_context.lower() for x in [
                'settings',
                'connection',
                'url.password',
                'url.query',
                'schema_name',
                'charset_name',
                'transaction_mode',
            ]):
                return True
        
        return False
    
    def is_internal_code(self, report: Dict, code_context: str) -> bool:
        """Check if finding is in internal framework code"""
        file_path = report.get('file_path', '')
        
        # Check file path
        if any(indicator in file_path.lower() for indicator in self.internal_code_indicators):
            return True
        
        # Check code context
        if any(indicator in code_context.lower() for indicator in [
            'internal',
            'private method',
            'framework',
        ]):
            return True
        
        return False
    
    def is_static_file(self, report: Dict) -> bool:
        """Check if finding is in static files"""
        file_path = report.get('file_path', '')
        
        for pattern in self.static_file_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        
        return False
    
    def is_test_file(self, report: Dict) -> bool:
        """Check if finding is in test files"""
        file_path = report.get('file_path', '')
        
        for pattern in self.test_file_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        
        return False
    
    def is_wrong_language(self, report: Dict) -> bool:
        """Check if finding is in wrong language (Rust/C for Python vulnerabilities)"""
        file_path = report.get('file_path', '')
        
        if file_path.endswith(('.rs', '.c', '.h', '.cpp', '.cc')):
            return True
        
        return False
    
    def uses_safe_methods(self, code_context: str) -> bool:
        """Check if code uses safe sanitization methods"""
        for pattern_name, pattern in self.safe_patterns.items():
            if re.search(pattern, code_context, re.IGNORECASE):
                return True
        return False
    
    def is_oid_definition(self, report: Dict, code_context: str) -> bool:
        """Check if finding is just OID definition, not actual usage"""
        file_path = report.get('file_path', '')
        cwe = report.get('cwe', '')
        
        if cwe == 'CWE-327' and 'oid' in file_path.lower():
            # Check if it's just defining OIDs, not using weak crypto
            if 'ObjectIdentifier' in code_context and 'MD5()' not in code_context:
                return True
        
        return False
    
    def has_user_controllable_input(self, report: Dict, code_context: str) -> bool:
        """Check if finding involves user-controllable input"""
        # Look for user input indicators
        user_input_indicators = [
            r'request\.',
            r'input\s*=',
            r'user\.',
            r'form\.',
            r'POST\[',
            r'GET\[',
            r'query_params',
            r'args\[',
        ]
        
        for pattern in user_input_indicators:
            if re.search(pattern, code_context, re.IGNORECASE):
                return True
        
        return False
    
    def is_exploitable(self, report: Dict, code_context: str = '') -> Tuple[bool, str]:
        """
        Determine if a finding is actually exploitable
        Returns: (is_exploitable, reason)
        """
        file_path = report.get('file_path', '')
        cwe = report.get('cwe', '')
        
        # Filter 1: Wrong language
        if self.is_wrong_language(report):
            return False, "Wrong language (Rust/C code, not Python)"
        
        # Filter 2: Static files
        if self.is_static_file(report):
            return False, "Static file (not exploitable)"
        
        # Filter 3: Test files
        if self.is_test_file(report):
            return False, "Test file (not production code)"
        
        # Filter 4: OID definitions
        if self.is_oid_definition(report, code_context):
            return False, "OID definition only (not actual usage)"
        
        # Filter 5: Infrastructure compromise required
        if self.requires_infrastructure_compromise(report):
            return False, "Requires infrastructure compromise (Redis/DB access)"
        
        # Filter 6: Configuration control required
        if self.requires_config_control(report, code_context):
            return False, "Requires configuration control (not user input)"
        
        # Filter 7: Internal code
        if self.is_internal_code(report, code_context):
            return False, "Internal framework code (not user-controllable)"
        
        # Filter 8: Uses safe methods
        if self.uses_safe_methods(code_context):
            return False, "Uses safe sanitization methods"
        
        # Filter 9: No user-controllable input
        if not self.has_user_controllable_input(report, code_context):
            # For some CWEs, user input might not be required
            # But for most, it's essential
            if cwe in ['CWE-89', 'CWE-78', 'CWE-22', 'CWE-79']:
                return False, "No user-controllable input detected"
        
        # If we get here, it might be exploitable
        return True, "Potentially exploitable - needs manual review"
    
    def filter_findings(self, findings: List[Dict]) -> List[Dict]:
        """Filter a list of findings to remove noise"""
        exploitable = []
        filtered_out = []
        
        for finding in findings:
            # Get code context if available
            vulnerable_code = finding.get('vulnerable_code', {})
            code_context = vulnerable_code.get('context', '') or vulnerable_code.get('snippet', '') or ''
            
            is_exploitable, reason = self.is_exploitable(finding, code_context)
            
            if is_exploitable:
                exploitable.append(finding)
            else:
                finding['_filter_reason'] = reason
                filtered_out.append(finding)
        
        return exploitable, filtered_out

def main():
    """Test the noise elimination filters"""
    from pathlib import Path
    import json
    
    print("="*80)
    print("🔇 Noise Elimination Filter Test")
    print("="*80)
    print()
    
    filter_system = NoiseEliminationFilter()
    
    # Load all reports
    reports_dir = Path("bug_bounty_reports/json")
    all_findings = []
    
    for report_file in reports_dir.glob("*.json"):
        try:
            with open(report_file, 'r') as f:
                report = json.load(f)
                all_findings.append(report)
        except:
            continue
    
    print(f"Total findings: {len(all_findings)}")
    print()
    
    # Filter
    exploitable, filtered = filter_system.filter_findings(all_findings)
    
    print(f"✅ Exploitable: {len(exploitable)}")
    print(f"❌ Filtered out: {len(filtered)}")
    print(f"📊 Noise reduction: {len(filtered)/len(all_findings)*100:.1f}%")
    print()
    
    # Show filter reasons
    filter_reasons = {}
    for f in filtered:
        reason = f.get('_filter_reason', 'Unknown')
        filter_reasons[reason] = filter_reasons.get(reason, 0) + 1
    
    print("Filter reasons:")
    for reason, count in sorted(filter_reasons.items(), key=lambda x: x[1], reverse=True):
        print(f"  {reason}: {count}")
    print()
    
    if exploitable:
        print("Potentially exploitable findings:")
        for i, finding in enumerate(exploitable[:10], 1):
            print(f"  {i}. {finding.get('cwe')} - {finding.get('title')}")
            print(f"     {finding.get('repository')} - {Path(finding.get('file_path', '')).name}")
    else:
        print("⚠️  No exploitable findings found after filtering")

if __name__ == '__main__':
    main()




