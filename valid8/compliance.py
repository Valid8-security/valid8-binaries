#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Compliance Reporting Module

Generates compliance reports for various standards:
- SOC2 (System and Organization Controls 2)
- ISO 27001 (Information Security Management)
- PCI-DSS (Payment Card Industry Data Security Standard)
- HIPAA (Health Insurance Portability and Accountability Act)
- GDPR (General Data Protection Regulation)
- OWASP Top 10
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class ComplianceRequirement:
    """A single compliance requirement"""
    control_id: str
    control_name: str
    description: str
    standard: str
    severity: str
    cwes: List[str]
    passed: bool
    findings: List[Dict[str, Any]]
    remediation: str


class SOC2Compliance:
    """SOC2 compliance checker"""
    
    # SOC2 Trust Service Criteria mapped to CWEs
    CONTROLS = {
        'CC6.1': {
            'name': 'Logical and Physical Access Controls',
            'description': 'The entity implements logical access security software, infrastructure, and architectures over protected information assets.',
            'cwes': ['CWE-287', 'CWE-288', 'CWE-290', 'CWE-306', 'CWE-862']
        },
        'CC6.2': {
            'name': 'Authentication and Authorization',
            'description': 'Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.',
            'cwes': ['CWE-287', 'CWE-798', 'CWE-640']
        },
        'CC6.6': {
            'name': 'Encryption of Data at Rest and in Transit',
            'description': 'The entity implements logical access security measures to protect against threats from sources outside its system boundaries.',
            'cwes': ['CWE-311', 'CWE-319', 'CWE-327', 'CWE-328']
        },
        'CC6.7': {
            'name': 'Data Loss Prevention',
            'description': 'The entity restricts the transmission, movement, and removal of information.',
            'cwes': ['CWE-200', 'CWE-532', 'CWE-538']
        },
        'CC6.8': {
            'name': 'Vulnerability Management',
            'description': 'The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.',
            'cwes': ['CWE-78', 'CWE-89', 'CWE-79', 'CWE-502', 'CWE-094']
        },
        'CC7.1': {
            'name': 'Security Incident Detection',
            'description': 'To meet its objectives, the entity uses detection and monitoring procedures to identify anomalies.',
            'cwes': ['CWE-778', 'CWE-779', 'CWE-823']
        },
        'CC7.2': {
            'name': 'Security Incident Response',
            'description': 'The entity monitors system components and the operation of those components for anomalies.',
            'cwes': ['CWE-390', 'CWE-391', 'CWE-755']
        }
    }
    
    def generate_report(self, vulnerabilities: List[Any]) -> Dict[str, Any]:
        """Generate SOC2 compliance report"""
        requirements = []
        
        for control_id, control_data in self.CONTROLS.items():
            # Find relevant vulnerabilities
            findings = []
            for vuln in vulnerabilities:
                if vuln.cwe in control_data['cwes']:
                    findings.append({
                        'cwe': vuln.cwe,
                        'file': vuln.file_path,
                        'line': vuln.line_number,
                        'severity': vuln.severity,
                        'title': vuln.title
                    })
            
            requirements.append(ComplianceRequirement(
                control_id=control_id,
                control_name=control_data['name'],
                description=control_data['description'],
                standard='SOC2',
                severity='high' if findings else 'info',
                cwes=control_data['cwes'],
                passed=len(findings) == 0,
                findings=findings,
                remediation=f"Address {len(findings)} finding(s) related to {control_data['name']}"
            ))
        
        # Calculate compliance score
        passed_controls = sum(1 for req in requirements if req.passed)
        total_controls = len(requirements)
        compliance_score = (passed_controls / total_controls * 100) if total_controls > 0 else 0
        
        return {
            'standard': 'SOC2',
            'timestamp': datetime.now().isoformat(),
            'compliance_score': round(compliance_score, 2),
            'passed_controls': passed_controls,
            'total_controls': total_controls,
            'requirements': [asdict(req) for req in requirements],
            'overall_status': 'COMPLIANT' if compliance_score >= 90 else 'NON-COMPLIANT',
            'critical_findings': len([v for v in vulnerabilities if v.severity == 'critical'])
        }


class ISO27001Compliance:
    """ISO 27001 compliance checker"""
    
    CONTROLS = {
        'A.9.2.1': {
            'name': 'User Registration and De-registration',
            'description': 'A formal user registration and de-registration process shall be implemented.',
            'cwes': ['CWE-287', 'CWE-306', 'CWE-862']
        },
        'A.9.2.4': {
            'name': 'Management of Secret Authentication Information',
            'description': 'The allocation of secret authentication information shall be controlled through a formal management process.',
            'cwes': ['CWE-798', 'CWE-259', 'CWE-321', 'CWE-522']
        },
        'A.9.4.1': {
            'name': 'Information Access Restriction',
            'description': 'Access to information and application system functions shall be restricted in accordance with the access control policy.',
            'cwes': ['CWE-284', 'CWE-285', 'CWE-862']
        },
        'A.10.1.1': {
            'name': 'Policy on Use of Cryptographic Controls',
            'description': 'A policy on the use of cryptographic controls shall be developed and implemented.',
            'cwes': ['CWE-311', 'CWE-327', 'CWE-328', 'CWE-329']
        },
        'A.12.6.1': {
            'name': 'Management of Technical Vulnerabilities',
            'description': 'Information about technical vulnerabilities shall be obtained in a timely fashion.',
            'cwes': ['CWE-1035', 'CWE-937']
        },
        'A.14.2.1': {
            'name': 'Secure Development Policy',
            'description': 'Rules for the development of software and systems shall be established and applied.',
            'cwes': ['CWE-20', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94', 'CWE-502']
        },
        'A.14.2.5': {
            'name': 'Secure System Engineering Principles',
            'description': 'Principles for engineering secure systems shall be established, documented, maintained and applied.',
            'cwes': ['CWE-693', 'CWE-754', 'CWE-841']
        }
    }
    
    def generate_report(self, vulnerabilities: List[Any]) -> Dict[str, Any]:
        """Generate ISO 27001 compliance report"""
        requirements = []
        
        for control_id, control_data in self.CONTROLS.items():
            findings = []
            for vuln in vulnerabilities:
                if vuln.cwe in control_data['cwes']:
                    findings.append({
                        'cwe': vuln.cwe,
                        'file': vuln.file_path,
                        'line': vuln.line_number,
                        'severity': vuln.severity,
                        'title': vuln.title
                    })
            
            requirements.append(ComplianceRequirement(
                control_id=control_id,
                control_name=control_data['name'],
                description=control_data['description'],
                standard='ISO27001',
                severity='high' if findings else 'info',
                cwes=control_data['cwes'],
                passed=len(findings) == 0,
                findings=findings,
                remediation=f"Address {len(findings)} finding(s) related to {control_data['name']}"
            ))
        
        passed_controls = sum(1 for req in requirements if req.passed)
        total_controls = len(requirements)
        compliance_score = (passed_controls / total_controls * 100) if total_controls > 0 else 0
        
        return {
            'standard': 'ISO27001',
            'timestamp': datetime.now().isoformat(),
            'compliance_score': round(compliance_score, 2),
            'passed_controls': passed_controls,
            'total_controls': total_controls,
            'requirements': [asdict(req) for req in requirements],
            'overall_status': 'COMPLIANT' if compliance_score >= 90 else 'NON-COMPLIANT',
            'critical_findings': len([v for v in vulnerabilities if v.severity == 'critical'])
        }


class PCIDSSCompliance:
    """PCI-DSS compliance checker"""
    
    REQUIREMENTS = {
        'Req-2.2.4': {
            'name': 'Configure System Security Parameters',
            'description': 'Configure system security parameters to prevent misuse.',
            'cwes': ['CWE-16', 'CWE-183', 'CWE-489']
        },
        'Req-6.5.1': {
            'name': 'Injection Flaws',
            'description': 'Address common coding vulnerabilities in software-development processes: Injection flaws (particularly SQL injection).',
            'cwes': ['CWE-89', 'CWE-78', 'CWE-94', 'CWE-943']
        },
        'Req-6.5.3': {
            'name': 'Insecure Cryptographic Storage',
            'description': 'Insecure cryptographic storage.',
            'cwes': ['CWE-311', 'CWE-312', 'CWE-313', 'CWE-327', 'CWE-759']
        },
        'Req-6.5.7': {
            'name': 'Cross-Site Scripting (XSS)',
            'description': 'Address common coding vulnerabilities in software-development processes: Cross-site scripting (XSS).',
            'cwes': ['CWE-79', 'CWE-80', 'CWE-81', 'CWE-83', 'CWE-87']
        },
        'Req-6.5.8': {
            'name': 'Improper Access Control',
            'description': 'Improper access control (such as insecure direct object references, failure to restrict URL access).',
            'cwes': ['CWE-284', 'CWE-285', 'CWE-639', 'CWE-862']
        },
        'Req-6.5.9': {
            'name': 'Cross-Site Request Forgery (CSRF)',
            'description': 'Address common coding vulnerabilities in software-development processes: Cross-site request forgery (CSRF).',
            'cwes': ['CWE-352']
        },
        'Req-6.5.10': {
            'name': 'Broken Authentication and Session Management',
            'description': 'Broken authentication and session management.',
            'cwes': ['CWE-287', 'CWE-306', 'CWE-384', 'CWE-613', 'CWE-798']
        }
    }
    
    def generate_report(self, vulnerabilities: List[Any]) -> Dict[str, Any]:
        """Generate PCI-DSS compliance report"""
        requirements = []
        
        for req_id, req_data in self.REQUIREMENTS.items():
            findings = []
            for vuln in vulnerabilities:
                if vuln.cwe in req_data['cwes']:
                    findings.append({
                        'cwe': vuln.cwe,
                        'file': vuln.file_path,
                        'line': vuln.line_number,
                        'severity': vuln.severity,
                        'title': vuln.title
                    })
            
            requirements.append(ComplianceRequirement(
                control_id=req_id,
                control_name=req_data['name'],
                description=req_data['description'],
                standard='PCI-DSS',
                severity='critical' if findings and any(f['severity'] == 'critical' for f in findings) else 'high' if findings else 'info',
                cwes=req_data['cwes'],
                passed=len(findings) == 0,
                findings=findings,
                remediation=f"Address {len(findings)} finding(s) related to {req_data['name']}"
            ))
        
        passed_controls = sum(1 for req in requirements if req.passed)
        total_controls = len(requirements)
        compliance_score = (passed_controls / total_controls * 100) if total_controls > 0 else 0
        
        return {
            'standard': 'PCI-DSS',
            'timestamp': datetime.now().isoformat(),
            'compliance_score': round(compliance_score, 2),
            'passed_requirements': passed_controls,
            'total_requirements': total_controls,
            'requirements': [asdict(req) for req in requirements],
            'overall_status': 'COMPLIANT' if compliance_score == 100 else 'NON-COMPLIANT',
            'critical_findings': len([v for v in vulnerabilities if v.severity == 'critical']),
            'note': 'PCI-DSS requires 100% compliance for certification'
        }


class OWASP2021Compliance:
    """OWASP Top 10 (2021) compliance checker"""
    
    CATEGORIES = {
        'A01:2021': {
            'name': 'Broken Access Control',
            'description': 'Restrictions on what authenticated users are allowed to do are often not properly enforced.',
            'cwes': ['CWE-284', 'CWE-285', 'CWE-862', 'CWE-639', 'CWE-918']
        },
        'A02:2021': {
            'name': 'Cryptographic Failures',
            'description': 'Failures related to cryptography which often lead to exposure of sensitive data.',
            'cwes': ['CWE-259', 'CWE-327', 'CWE-311', 'CWE-319', 'CWE-321', 'CWE-322', 'CWE-323']
        },
        'A03:2021': {
            'name': 'Injection',
            'description': 'Application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized.',
            'cwes': ['CWE-79', 'CWE-89', 'CWE-73', 'CWE-78', 'CWE-94']
        },
        'A04:2021': {
            'name': 'Insecure Design',
            'description': 'Missing or ineffective control design.',
            'cwes': ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522']
        },
        'A05:2021': {
            'name': 'Security Misconfiguration',
            'description': 'Missing appropriate security hardening or improperly configured permissions.',
            'cwes': ['CWE-16', 'CWE-611', 'CWE-489', 'CWE-732']
        },
        'A06:2021': {
            'name': 'Vulnerable and Outdated Components',
            'description': 'Using components with known vulnerabilities.',
            'cwes': ['CWE-1035', 'CWE-1104']
        },
        'A07:2021': {
            'name': 'Identification and Authentication Failures',
            'description': 'Confirmation of the user\'s identity, authentication, and session management.',
            'cwes': ['CWE-287', 'CWE-288', 'CWE-290', 'CWE-306', 'CWE-307', 'CWE-798']
        },
        'A08:2021': {
            'name': 'Software and Data Integrity Failures',
            'description': 'Code and infrastructure that does not protect against integrity violations.',
            'cwes': ['CWE-502', 'CWE-494', 'CWE-829']
        },
        'A09:2021': {
            'name': 'Security Logging and Monitoring Failures',
            'description': 'Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response.',
            'cwes': ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778']
        },
        'A10:2021': {
            'name': 'Server-Side Request Forgery (SSRF)',
            'description': 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.',
            'cwes': ['CWE-918']
        }
    }
    
    def generate_report(self, vulnerabilities: List[Any]) -> Dict[str, Any]:
        """Generate OWASP Top 10 2021 compliance report"""
        categories = []
        
        for cat_id, cat_data in self.CATEGORIES.items():
            findings = []
            for vuln in vulnerabilities:
                if vuln.cwe in cat_data['cwes']:
                    findings.append({
                        'cwe': vuln.cwe,
                        'file': vuln.file_path,
                        'line': vuln.line_number,
                        'severity': vuln.severity,
                        'title': vuln.title
                    })
            
            categories.append(ComplianceRequirement(
                control_id=cat_id,
                control_name=cat_data['name'],
                description=cat_data['description'],
                standard='OWASP Top 10 2021',
                severity='high' if findings else 'info',
                cwes=cat_data['cwes'],
                passed=len(findings) == 0,
                findings=findings,
                remediation=f"Address {len(findings)} finding(s) in category {cat_data['name']}"
            ))
        
        passed_categories = sum(1 for cat in categories if cat.passed)
        total_categories = len(categories)
        coverage_score = (passed_categories / total_categories * 100) if total_categories > 0 else 0
        
        return {
            'standard': 'OWASP Top 10 2021',
            'timestamp': datetime.now().isoformat(),
            'coverage_score': round(coverage_score, 2),
            'clean_categories': passed_categories,
            'total_categories': total_categories,
            'categories': [asdict(cat) for cat in categories],
            'risk_level': 'LOW' if coverage_score >= 80 else 'MEDIUM' if coverage_score >= 50 else 'HIGH',
            'critical_findings': len([v for v in vulnerabilities if v.severity == 'critical'])
        }


class ComplianceReporter:
    """Main compliance reporting engine"""
    
    def __init__(self):
        self.reporters = {
            'soc2': SOC2Compliance(),
            'iso27001': ISO27001Compliance(),
            'pci-dss': PCIDSSCompliance(),
            'owasp': OWASP2021Compliance()
        }
    
    def generate_report(self, vulnerabilities: List[Any], standards: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Generate compliance reports for specified standards
        
        Args:
            vulnerabilities: List of vulnerabilities from scan
            standards: List of standards to check (default: all)
        
        Returns:
            Dictionary with compliance reports for each standard
        """
        if standards is None:
            standards = list(self.reporters.keys())
        
        reports = {}
        for standard in standards:
            if standard.lower() in self.reporters:
                reporter = self.reporters[standard.lower()]
                reports[standard.lower()] = reporter.generate_report(vulnerabilities)
        
        # Add summary
        reports['summary'] = {
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': self._count_by_severity(vulnerabilities),
            'standards_checked': standards,
            'timestamp': datetime.now().isoformat()
        }
        
        return reports
    
    def _count_by_severity(self, vulnerabilities: List[Any]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            if vuln.severity in counts:
                counts[vuln.severity] += 1
        return counts
    
    def export_to_json(self, reports: Dict[str, Any], output_path: Path):
        """Export reports to JSON file"""
        with open(output_path, 'w') as f:
            json.dump(reports, f, indent=2)
    
    def generate_markdown_report(self, reports: Dict[str, Any]) -> str:
        """Generate markdown-formatted compliance report"""
        md = ["# Compliance Report\n"]
        md.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Summary
        summary = reports.get('summary', {})
        md.append("## Summary\n")
        md.append(f"- **Total Vulnerabilities**: {summary.get('total_vulnerabilities', 0)}\n")
        md.append(f"- **Standards Checked**: {', '.join(summary.get('standards_checked', []))}\n\n")
        
        # By severity
        by_sev = summary.get('by_severity', {})
        md.append("### Vulnerabilities by Severity\n")
        md.append(f"- 🔴 Critical: {by_sev.get('critical', 0)}\n")
        md.append(f"- 🟠 High: {by_sev.get('high', 0)}\n")
        md.append(f"- 🟡 Medium: {by_sev.get('medium', 0)}\n")
        md.append(f"- 🟢 Low: {by_sev.get('low', 0)}\n\n")
        
        # Individual standards
        for standard_key, report in reports.items():
            if standard_key == 'summary':
                continue
            
            md.append(f"## {report.get('standard', standard_key.upper())}\n\n")
            md.append(f"**Compliance Score**: {report.get('compliance_score', 0):.2f}%\n")
            md.append(f"**Status**: {report.get('overall_status', 'UNKNOWN')}\n")
            md.append(f"**Critical Findings**: {report.get('critical_findings', 0)}\n\n")
            
            # Requirements/controls
            requirements = report.get('requirements', report.get('categories', []))
            if requirements:
                md.append("### Controls\n\n")
                md.append("| Control | Name | Status | Findings |\n")
                md.append("|---------|------|--------|----------|\n")
                
                for req in requirements:
                    status = "✅ PASS" if req.get('passed') else "❌ FAIL"
                    findings_count = len(req.get('findings', []))
                    md.append(f"| {req.get('control_id')} | {req.get('control_name')} | {status} | {findings_count} |\n")
                
                md.append("\n")
        
        return ''.join(md)

