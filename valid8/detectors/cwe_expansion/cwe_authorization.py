"""Authorization Vulnerability Detectors - 15+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class ImproperAccessControlDetector(VulnerabilityDetector):
    """CWE-284: Improper Access Control"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'if.*admin.*==.*True', "CWE-284", "high"),
            (r'if.*role.*==.*admin', "CWE-284", "high"),
            (r'access.*check.*missing', "CWE-284", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
                    if not re.search(r'@permission|@auth|@require|can_access|has_permission', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Access Control",
                            description="Improper access control check. Use proper authorization mechanisms.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authorization"
                        ))
        return vulnerabilities

class ImproperAuthorizationDetector(VulnerabilityDetector):
    """CWE-285: Improper Authorization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'def.*admin.*function', "CWE-285", "high"),
            (r'def.*delete.*user', "CWE-285", "high"),
            (r'def.*update.*settings', "CWE-285", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
                    if not re.search(r'@permission|@auth|@require|authorize|can_|has_', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Authorization",
                            description="Critical function lacks proper authorization check.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authorization"
                        ))
        return vulnerabilities

class AuthorizationBypassDetector(VulnerabilityDetector):
    """CWE-639: Authorization Bypass Through User-Controlled Key"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'user_id.*=.*param', "CWE-639", "critical"),
            (r'user.*=.*request', "CWE-639", "critical"),
            (r'access.*user.*input', "CWE-639", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+5)])
                    if re.search(r'profile|data|record', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Authorization Bypass",
                            description="Authorization bypass through user-controlled key. Validate ownership.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authorization"
                        ))
        return vulnerabilities

class ImproperPrivilegeManagementDetector(VulnerabilityDetector):
    """CWE-269: Improper Privilege Management"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'setuid.*root', "CWE-269", "critical"),
            (r'sudo.*password', "CWE-269", "high"),
            (r'elevate.*privilege', "CWE-269", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'check|validate|authorize', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Privilege Management",
                            description="Privilege escalation without proper validation.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authorization"
                        ))
        return vulnerabilities

class DirectObjectReferenceDetector(VulnerabilityDetector):
    """CWE-639: Direct Object Reference"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'file.*=.*open.*param', "CWE-639", "high"),
            (r'record.*=.*get.*id', "CWE-639", "high"),
            (r'data.*=.*load.*request', "CWE-639", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+5)])
                    if not re.search(r'check.*owner|validate.*access|authorize', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Direct Object Reference",
                            description="Direct object reference without access control. Check ownership.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authorization"
                        ))
        return vulnerabilities

class InsufficientAuthorizationDetector(VulnerabilityDetector):
    """CWE-862: Missing Authorization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        critical_operations = [
            r'delete.*record', r'update.*user', r'modify.*settings',
            r'access.*admin', r'view.*sensitive', r'export.*data'
        ]
        for i, line in enumerate(lines, 1):
            for pattern in critical_operations:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'@auth|@login|@permission|authorize|can_|has_|check_', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe="CWE-862", severity="high", title="Missing Authorization",
                            description="Critical operation lacks authorization check.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authorization"
                        ))
                        break
        return vulnerabilities

class IncorrectPermissionAssignmentDetector(VulnerabilityDetector):
    """CWE-732: Incorrect Permission Assignment for Critical Resource"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'chmod.*777', "CWE-732", "high"),
            (r'permission.*=.*777', "CWE-732", "high"),
            (r'0o777', "CWE-732", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Incorrect Permission Assignment",
                        description="Overly permissive file permissions. Use least privilege principle.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="authorization"
                    ))
        return vulnerabilities

class PrivilegeEscalationDetector(VulnerabilityDetector):
    """CWE-275: Permission Issues"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'setuid.*0', "CWE-275", "critical"),
            (r'seteuid.*0', "CWE-275", "critical"),
            (r'elevate.*root', "CWE-275", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'validate|check|authorize', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Privilege Escalation",
                            description="Privilege escalation without proper validation.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authorization"
                        ))
        return vulnerabilities

class AuthorizationRaceConditionDetector(VulnerabilityDetector):
    """CWE-279: Incorrect Execution-Assigned Permissions"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'chmod.*after.*write', "CWE-279", "medium"),
            (r'permission.*after.*create', "CWE-279", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Incorrect Execution Permissions",
                        description="Permissions set after file creation. Set restrictive permissions initially.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="authorization"
                    ))
        return vulnerabilities

class InsecureDefaultPermissionsDetector(VulnerabilityDetector):
    """CWE-280: Improper Handling of Insufficient Permissions or Privileges"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'default.*permission.*777', "CWE-280", "high"),
            (r'umask.*000', "CWE-280", "high"),
            (r'create.*file.*777', "CWE-280", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insecure Default Permissions",
                        description="Insecure default permissions. Use restrictive defaults.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="authorization"
                    ))
        return vulnerabilities

class ImproperResourcePermissionsDetector(VulnerabilityDetector):
    """CWE-281: Improper Preservation of Permissions"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'copy.*file.*preserve.*permission', "CWE-281", "medium"),
            (r'move.*preserve.*mode', "CWE-281", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'restrict|check|validate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Permission Preservation",
                            description="Preserving permissions during file operations may leak sensitive access.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="authorization"
                        ))
        return vulnerabilities

class InsufficientAuthorizationScopeDetector(VulnerabilityDetector):
    """CWE-282: Improper Ownership Management"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'chown.*root', "CWE-282", "high"),
            (r'chown.*0', "CWE-282", "high"),
            (r'chown.*user.*input', "CWE-282", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'validate|check|authorize', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Ownership Management",
                            description="Improper file ownership assignment. Validate ownership changes.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authorization"
                        ))
        return vulnerabilities

class AuthorizationBypassThroughSQLDetector(VulnerabilityDetector):
    """CWE-283: Unverified Ownership"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'SELECT.*WHERE.*user_id.*=', "CWE-283", "high"),
            (r'UPDATE.*WHERE.*owner.*=', "CWE-283", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+5)])
                    if not re.search(r'session|get_current_user|auth_user', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Unverified Ownership",
                            description="Database query doesn't verify ownership. Use session user ID.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authorization"
                        ))
        return vulnerabilities

class IncorrectDefaultPermissionsDetector(VulnerabilityDetector):
    """CWE-286: Incorrect User Management"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'create.*user.*admin', "CWE-286", "high"),
            (r'default.*role.*admin', "CWE-286", "high"),
            (r'new.*user.*superuser', "CWE-286", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'approve|review|validate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Incorrect User Management",
                            description="New users getting excessive privileges by default.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authorization"
                        ))
        return vulnerabilities

class ImproperAuthorizationCheckDetector(VulnerabilityDetector):
    """CWE-287: Improper Authentication/Authorization Check"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'if.*logged_in.*continue', "CWE-287", "medium"),
            (r'if.*is_admin.*return', "CWE-287", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'exit|throw|redirect|forbidden', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Authorization Check",
                            description="Authorization check doesn't properly deny access on failure.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authorization"
                        ))
        return vulnerabilities


class IncorrectPermissionAssignmentCriticalResourceDetector(VulnerabilityDetector):
    """CWE-732: Incorrect Permission Assignment for Critical Resource"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'chmod\s*0o777', "CWE-732", "high"),  # World-writable permissions
            (r'chmod\s*0777', "CWE-732", "high"),
            (r'777.*permission', "CWE-732", "high"),
            (r'world.*writable', "CWE-732", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'config|secret|key|database|ssl', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Incorrect Permission Assignment for Critical Resource",
                            description="Critical resource has overly permissive permissions. Use restrictive permissions.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authorization"
                        ))
        return vulnerabilities


class IncorrectPrivilegeAssignmentDetector(VulnerabilityDetector):
    """CWE-266: Incorrect Privilege Assignment"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'root.*user', "CWE-266", "high"),  # Running as root unnecessarily
            (r'admin.*privilege', "CWE-266", "high"),
            (r'sudo.*\bevery\b', "CWE-266", "high"),  # NOPASSWD for all commands
            (r'NOPASSWD.*ALL', "CWE-266", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'necessary|required|minimal|least.*privilege', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Incorrect Privilege Assignment",
                            description="Excessive privileges assigned. Use principle of least privilege.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authorization"
                        ))
        return vulnerabilities


class ImproperHandlingInsufficientPrivilegesDetector(VulnerabilityDetector):
    """CWE-274: Improper Handling of Insufficient Privileges"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'catch.*Exception', "CWE-274", "medium"),  # Generic exception handling for auth failures
            (r'AccessDeniedException', "CWE-274", "medium"),
            (r'insufficient.*privilege', "CWE-274", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'log|audit|alert|notify|proper.*error', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Handling of Insufficient Privileges",
                            description="Insufficient privilege errors not properly handled. Log security events and return appropriate error messages.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authorization"
                        ))
        return vulnerabilities


def get_authorization_detectors():
    """Get all authorization detectors"""
    return [
        ImproperAccessControlDetector(),
        ImproperAuthorizationDetector(),
        AuthorizationBypassDetector(),
        ImproperPrivilegeManagementDetector(),
        DirectObjectReferenceDetector(),
        InsufficientAuthorizationDetector(),
        IncorrectPermissionAssignmentDetector(),
        PrivilegeEscalationDetector(),
        AuthorizationRaceConditionDetector(),
        InsecureDefaultPermissionsDetector(),
        ImproperResourcePermissionsDetector(),
        InsufficientAuthorizationScopeDetector(),
        AuthorizationBypassThroughSQLDetector(),
        IncorrectDefaultPermissionsDetector(),
        ImproperAuthorizationCheckDetector(),

        # Additional Authorization Detectors
        IncorrectPermissionAssignmentCriticalResourceDetector(),
        IncorrectPrivilegeAssignmentDetector(),
        ImproperHandlingInsufficientPrivilegesDetector(),
    ]