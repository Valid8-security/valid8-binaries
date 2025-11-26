#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""Information Disclosure Vulnerability Detectors - 15+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class InformationExposureEnvDetector(VulnerabilityDetector):
    """CWE-526: Information Exposure Through Environment"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'print\(.*os\.environ|.*process\.env', "CWE-526", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-526", severity=severity, title="Information Exposure Through Environment", description="Environment variables exposed.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="information-disclosure"))
        return vulnerabilities

class InformationExposureCommentsDetector(VulnerabilityDetector):
    """CWE-615: Information Exposure Through Comments"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'//.*password.*:|.*#.*password.*:', "CWE-615", "low")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-615", severity=severity, title="Information Exposure Through Comments", description="Sensitive info in comments.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="information-disclosure"))
        return vulnerabilities

class SensitiveDataInGETDetector(VulnerabilityDetector):
    """CWE-598: Use of GET Request With Sensitive Query"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'@(get|GET)\([^)]*\).*password|.*token|.*secret', "CWE-598", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-598", severity=severity, title="Sensitive Data in GET Request", description="Sensitive data in GET query string.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="information-disclosure"))
        return vulnerabilities

class InformationExposureLogDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'console\.log\(.*(password|secret|key)', "CWE-200", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-200", severity=severity, title="Information Exposure", description="Sensitive information exposed in logs.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="information-disclosure"))
        return vulnerabilities

class InformationExposureDebugDetector(VulnerabilityDetector):
    """CWE-489: Active Debug Code"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'debug\s*=\s*True|DEBUG\s*=\s*True', "CWE-489", "medium"),
            (r'console\.debug\(|logging\.debug\(.*password', "CWE-489", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Active Debug Code",
                        description="Debug mode enabled or debug information exposed.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureErrorDetector(VulnerabilityDetector):
    """CWE-209: Information Exposure Through Error Message"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'catch.*Exception.*print|except.*Exception.*print', "CWE-209", "medium"),
            (r'error.*stack.*trace|traceback\.print_exc', "CWE-209", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Information Exposure Through Error",
                        description="Sensitive information leaked through error messages.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureVersionDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure - Version Information"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'X-Powered-By|X-AspNet-Version|Server:', "CWE-200", "low"),
            (r'version.*=.*[\d\.]+|VERSION.*=.*[\d\.]+', "CWE-200", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Version Information Exposure",
                        description="Application version information exposed.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureDirectoryListingDetector(VulnerabilityDetector):
    """CWE-548: Information Exposure Through Directory Listing"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'directory.*listing|list.*directory|opendir', "CWE-548", "low"),
            (r'autoindex|Indexes.*Options', "CWE-548", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Directory Listing Enabled",
                        description="Directory listing may expose sensitive file information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureInternalIPDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure - Internal IP Address"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.', "CWE-200", "medium"),
            (r'internal.*ip|local.*ip|private.*ip', "CWE-200", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Internal IP Address Exposure",
                        description="Internal network information exposed.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureConfigDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure - Configuration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'config\.|settings\.|properties\.', "CWE-200", "low"),
            (r'expose.*config|show.*settings', "CWE-200", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                    if 'secret' in context.lower() or 'password' in context.lower():
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Configuration Exposure",
                            description="Sensitive configuration information exposed.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="information-disclosure"
                        ))
        return vulnerabilities

class InformationExposureDatabaseDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure - Database Schema"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'SELECT.*FROM.*information_schema|SHOW.*TABLES', "CWE-200", "high"),
            (r'describe.*table|DESCRIBE.*TABLE', "CWE-200", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Database Schema Exposure",
                        description="Database schema information exposed.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureFingerprintingDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure - Fingerprinting"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'User-Agent|Accept-Language|Accept-Encoding', "CWE-200", "low"),
            (r'browser.*fingerprint|fingerprint.*browser', "CWE-200", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Browser Fingerprinting",
                        description="Browser fingerprinting may compromise privacy.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureCacheDetector(VulnerabilityDetector):
    """CWE-524: Information Exposure Through Caching"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Cache-Control.*no-cache|Pragma.*no-cache', "CWE-524", "low"),
            (r'cache.*sensitive|cached.*password', "CWE-524", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Information Exposure Through Caching",
                        description="Sensitive information may be cached and exposed.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureTimingDetector(VulnerabilityDetector):
    """CWE-208: Observable Timing Discrepancy"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'time\.sleep|Thread\.sleep|delay', "CWE-208", "low"),
            (r'timing.*attack|timing.*discrepancy', "CWE-208", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Observable Timing Discrepancy",
                        description="Timing differences may leak sensitive information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureMemoryDetector(VulnerabilityDetector):
    """CWE-591: Sensitive Data Storage in Improperly Locked Memory"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc.*password|new.*password', "CWE-591", "medium"),
            (r'sensitive.*memory|password.*heap', "CWE-591", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Sensitive Data in Memory",
                        description="Sensitive data stored in unlocked memory.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureBackupDetector(VulnerabilityDetector):
    """CWE-530: Information Exposure Through Backup Files"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\.bak|\.backup|\.old|\.orig', "CWE-530", "medium"),
            (r'backup.*file|file.*backup', "CWE-530", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Backup File Exposure",
                        description="Backup files may contain sensitive information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureSourceCodeDetector(VulnerabilityDetector):
    """CWE-540: Information Exposure Through Source Code"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\.php\~\$\.|\.jsp\~\$\.|\.asp\~\$\.', "CWE-540", "high"),
            (r'source.*code.*exposure|expose.*source', "CWE-540", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Source Code Exposure",
                        description="Source code files may be exposed to users.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureSystemDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure - System Information"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'os\.name|platform\.system|uname', "CWE-200", "low"),
            (r'system.*info|system.*information', "CWE-200", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="System Information Exposure",
                        description="System information may aid attackers.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureHTTPHeadersDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through HTTP Headers"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'response\.setHeader|addHeader.*X-', "CWE-200", "low"),
            (r'X-Custom-Header|X-Internal-', "CWE-200", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="HTTP Header Information Exposure",
                        description="Custom headers may leak sensitive information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureSessionDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Session ID"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'session_id.*url|session.*query|sid.*parameter', "CWE-200", "medium"),
            (r'expose.*session|session.*url', "CWE-200", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Session ID in URL",
                        description="Session ID exposed in URL parameters.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureUserEnumerationDetector(VulnerabilityDetector):
    """CWE-204: Observable Response Discrepancy"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'user.*not.*found|invalid.*username', "CWE-204", "medium"),
            (r'user.*exists|user.*already.*exists', "CWE-204", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="User Enumeration",
                        description="Different responses for valid/invalid users enable enumeration.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposurePathDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through File Path"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'/etc/passwd|/etc/shadow|/var/log', "CWE-200", "high"),
            (r'C:\\\\Windows|C:\\\\Program Files', "CWE-200", "high"),
            (r'path.*disclosure|path.*leak', "CWE-200", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="File Path Exposure",
                        description="File system paths exposed to users.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureCacheDetector(VulnerabilityDetector):
    """CWE-524: Use of Cache Containing Sensitive Information"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'cache.*password', "CWE-524", "medium"),
            (r'cache.*session.*id', "CWE-524", "medium"),
            (r'browser.*cache.*sensitive', "CWE-524", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Cache Containing Sensitive Information",
                        description="Sensitive information stored in cache.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureTimingDetector(VulnerabilityDetector):
    """CWE-208: Observable Timing Discrepancy"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'time.*comparison.*password', "CWE-208", "low"),
            (r'timing.*attack.*possible', "CWE-208", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Observable Timing Discrepancy",
                        description="Timing differences may reveal sensitive information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureMemoryDetector(VulnerabilityDetector):
    """CWE-591: Sensitive Data Storage in Improperly Locked Memory"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'memory.*dump.*password', "CWE-591", "high"),
            (r'core.*dump.*sensitive', "CWE-591", "high"),
            (r'swap.*file.*secret', "CWE-591", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Sensitive Data in Memory",
                        description="Sensitive data may be exposed in memory dumps.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureBackupDetector(VulnerabilityDetector):
    """CWE-530: Exposure of Backup File to an Unauthorized Control Sphere"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\.bak.*accessible', "CWE-530", "medium"),
            (r'\.backup.*web', "CWE-530", "medium"),
            (r'temp.*file.*exposed', "CWE-530", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Backup File Exposure",
                        description="Backup or temporary files accessible to unauthorized users.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureHTTPDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Server:.*version', "CWE-200", "low"),
            (r'X-Powered-By:.*exposed', "CWE-200", "low"),
            (r'stack.*trace.*response', "CWE-200", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="HTTP Information Exposure",
                        description="Server information exposed in HTTP responses.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureDatabaseDetector(VulnerabilityDetector):
    """CWE-201: Information Exposure Through Sent Data"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'database.*error.*message', "CWE-201", "medium"),
            (r'sql.*exception.*details', "CWE-201", "medium"),
            (r'db.*query.*result.*exposed', "CWE-201", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Database Information Exposure",
                        description="Database information exposed through error messages.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureHardwareFingerprintingDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Hardware Fingerprinting"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'hardware|device.*id|fingerprint|uuid|mac.*address', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'log|print|response', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="low", title="Hardware Information Exposure",
                        description="Hardware fingerprinting information exposed to users.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureBuildMetadataDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Build Metadata"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'build.*version|commit.*hash|build.*time|git.*hash', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'public|client|response|header', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="low", title="Build Metadata Information Exposure",
                        description="Build metadata exposed that could help attackers identify vulnerabilities.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureInternalNetworkDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Internal Network Information"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'log|error|response', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="medium", title="Internal Network Information Exposure",
                        description="Internal network addresses exposed in logs or responses.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureDebugSymbolsDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Debug Symbols"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        if str(file_path).endswith(('.exe', '.dll', '.so', '.dylib')):
            for i, line in enumerate(lines, 1):
                if re.search(r'debug|symbol|pdb|dwarf', line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="low", title="Debug Symbols Information Exposure",
                        description="Debug symbols included in production binaries.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureThirdPartyCredentialsDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Third-Party Credentials"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'api.*key|secret.*key|access.*token|auth.*token', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'console\.log|print|log|response', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="high", title="Third-Party Credentials Exposure",
                        description="Third-party service credentials exposed in logs or responses.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="information-disclosure"
                    ))
        return vulnerabilities

def get_information_disclosure_detectors():
    return [
        InformationExposureEnvDetector(),
        InformationExposureCommentsDetector(),
        SensitiveDataInGETDetector(),
        InformationExposureLogDetector(),
        InformationExposureDebugDetector(),
        InformationExposureErrorDetector(),
        InformationExposureVersionDetector(),
        InformationExposureDirectoryListingDetector(),
        InformationExposureInternalIPDetector(),
        InformationExposureConfigDetector(),
        InformationExposureFingerprintingDetector(),
        InformationExposureCacheDetector(),
        InformationExposureTimingDetector(),
        InformationExposureMemoryDetector(),
        InformationExposureBackupDetector(),
        InformationExposureHTTPDetector(),
        InformationExposureDatabaseDetector(),
        InformationExposureSourceCodeDetector(),
        InformationExposureSystemDetector(),
        InformationExposureHTTPHeadersDetector(),
        InformationExposureSessionDetector(),
        InformationExposureUserEnumerationDetector(),
        InformationExposurePathDetector(),
        InformationExposureEnvironmentVariablesDetector(),
        InformationExposureLogFilesDetector(),
        InformationExposureCommentsDetector(),
        InformationExposureSQLQueriesDetector(),
        InformationExposureStackTraceDetector(),
        InformationExposureServerVersionDetector(),
        InformationExposureDatabaseErrorsDetector(),
        InformationExposureFilePermissionsDetector(),
        InformationExposureMemoryDumpDetector(),
        InformationExposureGitHistoryDetector(),
        InformationExposureURLParametersDetector(),
        InformationExposureBrowserStorageDetector(),
        InformationExposureProcessEnvironmentDetector(),
        InformationExposureThirdPartyLibrariesDetector(),
        InformationExposureSystemPropertiesDetector(),
        InformationExposureNetworkInterfacesDetector(),
        InformationExposureHardwareFingerprintingDetector(),
        InformationExposureBuildMetadataDetector(),
        InformationExposureInternalNetworkDetector(),
        InformationExposureDebugSymbolsDetector(),
        InformationExposureThirdPartyCredentialsDetector(),
    ]

class InformationExposureEnvironmentVariablesDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Environment Variables"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'os\.environ|process\.env|ENV\[|System\.getenv', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'password|secret|key|token|api', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="high", title="Environment Variable Information Exposure",
                        description="Sensitive information accessed through environment variables.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureLogFilesDetector(VulnerabilityDetector):
    """CWE-532: Information Exposure Through Log Files"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'logger\.|log\.|print.*password|debug.*secret', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-532", severity="medium", title="Sensitive Data in Log Files",
                    description="Sensitive information may be exposed through logging.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="information-disclosure"
                ))
        return vulnerabilities

class InformationExposureCommentsDetector(VulnerabilityDetector):
    """CWE-615: Information Exposure Through Comments"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'#.*password|//.*secret|/\*.*api.*key', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-615", severity="low", title="Sensitive Data in Comments",
                    description="Sensitive information exposed in source code comments.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="information-disclosure"
                ))
        return vulnerabilities

class InformationExposureSQLQueriesDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through SQL Query Structure"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'SELECT.*FROM.*WHERE.*=.*["\'][^"\']*\+', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-200", severity="medium", title="SQL Query Information Exposure",
                    description="SQL query structure may reveal database schema information.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="information-disclosure"
                ))
        return vulnerabilities

class InformationExposureStackTraceDetector(VulnerabilityDetector):
    """CWE-209: Information Exposure Through an Error Message"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'printStackTrace|traceback\.print|full_traceback', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'logger\.error|log\.error', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-209", severity="medium", title="Stack Trace Information Exposure",
                        description="Stack traces exposed to users may reveal sensitive system information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureServerVersionDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Server Banner"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'Server.*version|server.*banner|X-Powered-By', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-200", severity="low", title="Server Version Information Exposure",
                    description="Server version information may help attackers identify vulnerabilities.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="information-disclosure"
                ))
        return vulnerabilities

class InformationExposureDatabaseErrorsDetector(VulnerabilityDetector):
    """CWE-209: Information Exposure Through Database Error Messages"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'except.*sqlite|except.*mysql|except.*postgres', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i):min(len(lines), i+5)])
                if re.search(r'print|return.*str\(.*\)|response\.write', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-209", severity="medium", title="Database Error Information Exposure",
                        description="Database error messages may reveal sensitive database information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureFilePermissionsDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through File Permissions"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'chmod.*777|0o777|stat\.S_IRWX', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'config|secret|private', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="high", title="Insecure File Permissions",
                        description="Sensitive files have overly permissive access permissions.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureMemoryDumpDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Memory Dump"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'core.*dump|memory.*dump|heap.*dump', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-200", severity="high", title="Memory Dump Information Exposure",
                    description="Memory dumps may contain sensitive information.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="information-disclosure"
                ))
        return vulnerabilities

class InformationExposureGitHistoryDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Git History"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        if '.git' in str(file_path) or 'git' in content.lower():
            for i, line in enumerate(lines, 1):
                if re.search(r'password|secret|key|token', line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="medium", title="Sensitive Data in Git History",
                        description="Sensitive information may be exposed in Git history.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureURLParametersDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through URL Parameters"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'request\.GET|req\.query|url\.searchParams', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'debug|admin|config|internal', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="medium", title="URL Parameter Information Exposure",
                        description="Sensitive information exposed through URL parameters.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureBrowserStorageDetector(VulnerabilityDetector):
    """CWE-922: Information Exposure Through Browser Storage"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'localStorage|sessionStorage', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'password|token|secret|key', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-922", severity="high", title="Browser Storage Information Exposure",
                        description="Sensitive information stored in browser storage may be accessed by malicious scripts.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureProcessEnvironmentDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Process Environment"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'process\.env|os\.environ|getenv', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if re.search(r'console\.log|print|response\.|return', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="medium", title="Process Environment Information Exposure",
                        description="Process environment variables exposed to users.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureThirdPartyLibrariesDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Third-Party Libraries"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'import.*requests|import.*axios|import.*jquery', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'version|integrity|subresource', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="low", title="Third-Party Library Information Exposure",
                        description="Third-party libraries may expose version information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureSystemPropertiesDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through System Properties"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'System\.getProperty|os\.name|platform\.system', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'response\.|print|log', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="low", title="System Properties Information Exposure",
                        description="System properties exposed to users may reveal system information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="information-disclosure"
                    ))
        return vulnerabilities

class InformationExposureNetworkInterfacesDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Network Interfaces"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'getNetworkInterfaces|getaddrinfo|network.*interface', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'response\.|print|log', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="medium", title="Network Interface Information Exposure",
                        description="Network interface information may reveal internal network topology.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="information-disclosure"
                    ))
        return vulnerabilities
    return [InformationExposureEnvDetector(), InformationExposureCommentsDetector(), SensitiveDataInGETDetector(), InformationExposureLogDetector()]