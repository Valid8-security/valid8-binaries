"""Authentication Vulnerability Detectors - 15+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class ImproperAuthenticationDetector(VulnerabilityDetector):
    """CWE-287: Improper Authentication"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'def authenticate.*password.*==', "CWE-287", "critical"),
            (r'if.*password.*==', "CWE-287", "critical"),
            (r'login.*password.*equals', "CWE-287", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'hash|bcrypt|scrypt|argon', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Authentication",
                            description="Weak password comparison. Use secure hashing for passwords.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authentication"
                        ))
        return vulnerabilities

class WeakPasswordRequirementsDetector(VulnerabilityDetector):
    """CWE-521: Weak Password Requirements"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'min.*length.*[0-6]', "CWE-521", "high"),
            (r'password.*length.*<.*[0-6]', "CWE-521", "high"),
            (r'len\(password\).*[<>=].*[0-6]', "CWE-521", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Password Requirements",
                        description="Password requirements too weak. Require minimum 8+ characters.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="authentication"
                    ))
        return vulnerabilities

class WeakPasswordRecoveryDetector(VulnerabilityDetector):
    """CWE-640: Weak Password Recovery Mechanism"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'reset.*password.*email', "CWE-640", "high"),
            (r'forgot.*password.*security.*question', "CWE-640", "high"),
            (r'password.*reset.*birthday', "CWE-640", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
                    if not re.search(r'token|otp|2fa|verification', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Weak Password Recovery",
                            description="Weak password recovery mechanism. Use secure tokens or 2FA.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authentication"
                        ))
        return vulnerabilities

class MissingAuthenticationDetector(VulnerabilityDetector):
    """CWE-306: Missing Authentication for Critical Function"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        critical_functions = [
            r'def.*delete.*user', r'def.*admin', r'def.*config', r'def.*settings',
            r'def.*update.*profile', r'def.*change.*password', r'def.*reset'
        ]
        for i, line in enumerate(lines, 1):
            for pattern in critical_functions:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'@auth|@login|@permission|@require|session|token|authenticate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe="CWE-306", severity="high", title="Missing Authentication",
                            description="Critical function lacks authentication check.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authentication"
                        ))
                        break
        return vulnerabilities

class SessionFixationDetector(VulnerabilityDetector):
    """CWE-384: Session Fixation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'session_id.*=.*param', "CWE-384", "high"),
            (r'session.*=.*request', "CWE-384", "high"),
            (r'SET.*SESSION.*=.*GET', "CWE-384", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'regenerate|new.*session', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Session Fixation",
                            description="Session fixation vulnerability. Regenerate session after login.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authentication"
                        ))
        return vulnerabilities

class ImproperSessionManagementDetector(VulnerabilityDetector):
    """CWE-613: Insufficient Session Expiration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'session.*timeout.*3600', "CWE-613", "medium"),  # 1 hour
            (r'session.*expire.*3600', "CWE-613", "medium"),
            (r'MAX_AGE.*3600', "CWE-613", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'activity|sliding|extend', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Insufficient Session Expiration",
                            description="Session timeout too long. Use shorter timeouts with activity extension.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authentication"
                        ))
        return vulnerabilities

class ConcurrentSessionDetector(VulnerabilityDetector):
    """CWE-308: Use of Single-factor Authentication"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'login.*password.*only', "CWE-308", "medium"),
            (r'authenticate.*single.*factor', "CWE-308", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
                    if not re.search(r'2fa|otp|token|mfa|biometric', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Single-factor Authentication",
                            description="Only single-factor authentication used. Consider 2FA.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="authentication"
                        ))
        return vulnerabilities

class WeakCredentialStorageDetector(VulnerabilityDetector):
    """CWE-309: Use of Password System for Primary Authentication"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'password.*plain.*text', "CWE-309", "critical"),
            (r'store.*password.*clear', "CWE-309", "critical"),
            (r'password.*base64', "CWE-309", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Credential Storage",
                        description="Weak password storage. Use secure hashing with salt.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="authentication"
                    ))
        return vulnerabilities

class AuthenticationBypassDetector(VulnerabilityDetector):
    """CWE-295: Improper Certificate Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'verify.*=.*False', "CWE-295", "critical"),
            (r'check_hostname.*=.*False', "CWE-295", "critical"),
            (r'ssl.*verify.*False', "CWE-295", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'auth|login|certificate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Certificate Validation",
                            description="Certificate validation disabled. Enable proper SSL verification.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authentication"
                        ))
        return vulnerabilities

class WeakTokenValidationDetector(VulnerabilityDetector):
    """CWE-296: Improper Following of a Certificate's Chain of Trust"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'jwt.*decode.*verify.*False', "CWE-296", "critical"),
            (r'token.*verify.*False', "CWE-296", "critical"),
            (r'validate.*token.*False', "CWE-296", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Token Validation",
                        description="Token validation disabled. Enable proper token verification.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="authentication"
                    ))
        return vulnerabilities

class AuthenticationRaceConditionDetector(VulnerabilityDetector):
    """CWE-297: Improper Validation of Certificate with Host Mismatch"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'host.*mismatch.*ignore', "CWE-297", "high"),
            (r'hostname.*check.*False', "CWE-297", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Certificate Host Mismatch",
                        description="Certificate host validation disabled. Enable hostname checking.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="authentication"
                    ))
        return vulnerabilities

class WeakAuthenticationProtocolDetector(VulnerabilityDetector):
    """CWE-298: Use of Weak Hash"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'hashlib\.md5.*password', "CWE-298", "high"),
            (r'hashlib\.sha1.*password', "CWE-298", "high"),
            (r'MessageDigest.*MD5', "CWE-298", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Hash for Authentication",
                        description="Weak hash algorithm used for authentication. Use bcrypt/scrypt/argon2.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="authentication"
                    ))
        return vulnerabilities

class InsufficientAuthenticationDetector(VulnerabilityDetector):
    """CWE-299: Improper Check for Certificate Revocation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'revocation.*check.*False', "CWE-299", "medium"),
            (r'crl.*check.*False', "CWE-299", "medium"),
            (r'ocsp.*False', "CWE-299", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insufficient Certificate Revocation",
                        description="Certificate revocation checking disabled. Enable CRL/OCSP checking.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="authentication"
                    ))
        return vulnerabilities

class AuthenticationTimingAttackDetector(VulnerabilityDetector):
    """CWE-301: Reflection Attack in an Authentication Protocol"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'if.*password.*==.*return', "CWE-301", "medium"),
            (r'password.*equals.*return', "CWE-301", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'constant.*time|timing.*safe', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Timing Attack Vulnerability",
                            description="Timing attack possible in authentication. Use constant-time comparison.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authentication"
                        ))
        return vulnerabilities


class AccountLockoutMechanismDetector(VulnerabilityDetector):
    """CWE-645: Overly Restrictive Account Lockout Mechanism"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'lockout.*\b\d+\b.*attempt', "CWE-645", "medium"),  # Lockout after few attempts
            (r'account.*lock.*\b[123]\b', "CWE-645", "medium"),
            (r'failed.*login.*lock', "CWE-645", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'exponential|progressive|time.*delay', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Overly Restrictive Account Lockout",
                            description="Account lockout after few failed attempts enables brute force attacks. Use progressive delays.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authentication"
                        ))
        return vulnerabilities


class UnverifiedPasswordChangeDetector(VulnerabilityDetector):
    """CWE-620: Unverified Password Change"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'password.*change', "CWE-620", "high"),
            (r'updatePassword', "CWE-620", "high"),
            (r'changePassword', "CWE-620", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'verify|confirm|current.*password|old.*password', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Unverified Password Change",
                            description="Password change without verification. Require current password confirmation.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authentication"
                        ))
        return vulnerabilities


class WeakPasswordRecoveryMechanismDetector(VulnerabilityDetector):
    """CWE-640: Weak Password Recovery Mechanism"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'password.*reset.*email', "CWE-640", "high"),  # Email-based reset without verification
            (r'forgot.*password.*email', "CWE-640", "high"),
            (r'security.*question', "CWE-640", "medium"),  # Security questions alone
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'token|otp|2fa|mfa|time.*limit', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Weak Password Recovery Mechanism",
                            description="Weak password recovery. Use time-limited tokens or multi-factor verification.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="authentication"
                        ))
        return vulnerabilities


class MissingPasswordFieldMaskingDetector(VulnerabilityDetector):
    """CWE-549: Missing Password Field Masking"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'type\s*=\s*["\']text["\']', "CWE-549", "low"),  # Text input for password
            (r'input.*password.*text', "CWE-549", "low"),
            (r'password.*visible', "CWE-549", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'password|pwd|pass', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Missing Password Field Masking",
                            description="Password field using text input type. Use password input type.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="authentication"
                        ))
        return vulnerabilities


def get_authentication_detectors():
    """Get all authentication detectors"""
    return [
        ImproperAuthenticationDetector(),
        WeakPasswordRequirementsDetector(),
        WeakPasswordRecoveryDetector(),
        MissingAuthenticationDetector(),
        SessionFixationDetector(),
        ImproperSessionManagementDetector(),
        ConcurrentSessionDetector(),
        WeakCredentialStorageDetector(),
        AuthenticationBypassDetector(),
        WeakTokenValidationDetector(),
        AuthenticationRaceConditionDetector(),
        WeakAuthenticationProtocolDetector(),
        InsufficientAuthenticationDetector(),
        AuthenticationTimingAttackDetector(),

        # Additional Authentication Detectors
        AccountLockoutMechanismDetector(),
        UnverifiedPasswordChangeDetector(),
        WeakPasswordRecoveryMechanismDetector(),
        MissingPasswordFieldMaskingDetector(),
    ]