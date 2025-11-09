"""Configuration Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from parry.scanner import Vulnerability, VulnerabilityDetector

class SecurityMisconfigurationDetector(VulnerabilityDetector):
    """CWE-16: Configuration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'DEBUG\s*=\s*True|.*debug.*true', "CWE-16", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-16", severity=severity, title="Security Misconfiguration", description="Insecure configuration detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="configuration"))
        return vulnerabilities

class IncorrectPermissionDetector(VulnerabilityDetector):
    """CWE-732: Incorrect Permission Assignment"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'chmod\([^)]*0[67]77|.*0777', "CWE-732", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-732", severity=severity, title="Incorrect Permission Assignment", description="Insecure file permissions.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="permissions"))
        return vulnerabilities

class HardcodedCredentialsDetector(VulnerabilityDetector):
    """CWE-798: Use of Hard-coded Credentials"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "CWE-798", "high"),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "CWE-798", "high"),
            (r'secret\s*=\s*["\'][^"\']+["\']', "CWE-798", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                    if not re.search(r'os\.environ|getenv|config|env', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Hardcoded Credentials",
                            description="Hardcoded credentials in configuration.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="configuration"
                        ))
        return vulnerabilities

class InsecureDefaultConfigurationDetector(VulnerabilityDetector):
    """CWE-1188: Insecure Default Initialization of Resource"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'default.*password.*admin', "CWE-1188", "high"),
            (r'default.*user.*root', "CWE-1188", "high"),
            (r'default.*port.*22', "CWE-1188", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insecure Default Configuration",
                        description="Insecure default configuration values.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class MissingSecurityHeadersDetector(VulnerabilityDetector):
    """CWE-693: Protection Mechanism Failure"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'X-Frame-Options.*missing', "CWE-693", "medium"),
            (r'Content-Security-Policy.*missing', "CWE-693", "medium"),
            (r'X-Content-Type-Options.*missing', "CWE-693", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Missing Security Headers",
                        description="Security headers not configured.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="configuration"
                    ))
        return vulnerabilities

class WeakSSLConfigurationDetector(VulnerabilityDetector):
    """CWE-326: Inadequate Encryption Strength"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'SSLv2|SSLv3', "CWE-326", "high"),
            (r'TLSv1\.0|TLSv1\.1', "CWE-326", "medium"),
            (r'RC4|DES', "CWE-326", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak SSL/TLS Configuration",
                        description="Weak SSL/TLS configuration or deprecated protocols.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="configuration"
                    ))
        return vulnerabilities

class DatabaseMisconfigurationDetector(VulnerabilityDetector):
    """CWE-16: Configuration - Database"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'database.*root.*password', "CWE-16", "critical"),
            (r'db.*user.*root', "CWE-16", "high"),
            (r'exposed.*database.*port', "CWE-16", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Database Misconfiguration",
                        description="Insecure database configuration.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class LoggingMisconfigurationDetector(VulnerabilityDetector):
    """CWE-532: Information Exposure Through Log Files"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'log.*password', "CWE-532", "high"),
            (r'log.*secret', "CWE-532", "high"),
            (r'log.*api.*key', "CWE-532", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Logging Sensitive Information",
                        description="Sensitive information being logged.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="configuration"
                    ))
        return vulnerabilities

class SessionMisconfigurationDetector(VulnerabilityDetector):
    """CWE-613: Insufficient Session Expiration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'session.*timeout.*0', "CWE-613", "high"),
            (r'session.*lifetime.*unlimited', "CWE-613", "high"),
            (r'cookie.*secure.*false', "CWE-613", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Session Misconfiguration",
                        description="Insecure session configuration.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class BackupMisconfigurationDetector(VulnerabilityDetector):
    """CWE-530: Exposure of Backup File to an Unauthorized Control Sphere"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'backup.*path.*web', "CWE-530", "medium"),
            (r'\.bak.*accessible', "CWE-530", "medium"),
            (r'backup.*public', "CWE-530", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Backup File Exposure",
                        description="Backup files accessible to unauthorized users.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class CacheMisconfigurationDetector(VulnerabilityDetector):
    """CWE-525: Information Exposure Through Browser Cache"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Cache-Control.*no-cache.*missing', "CWE-525", "low"),
            (r'cache.*sensitive.*data', "CWE-525", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Cache Misconfiguration",
                        description="Sensitive data may be cached inappropriately.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="configuration"
                    ))
        return vulnerabilities

class EnvironmentMisconfigurationDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure - Environment Variables"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'expose.*env', "CWE-200", "medium"),
            (r'print.*environment', "CWE-200", "medium"),
            (r'debug.*env.*variables', "CWE-200", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Environment Information Exposure",
                        description="Environment variables or configuration exposed.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class InsecureFilePermissionsConfigurationDetector(VulnerabilityDetector):
    """CWE-732: Incorrect Permission Assignment for Critical Resource"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'chmod.*777|0o777|stat\.S_IRWX', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'config|secret|private|key', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-732", severity="high", title="Insecure File Permissions Configuration",
                        description="Critical configuration files have overly permissive access permissions.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="configuration"
                    ))
        return vulnerabilities

class MissingConfigurationValidationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation - Configuration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'config\.|settings\.|properties\.|env\.', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'validate|sanitiz|check', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="medium", title="Missing Configuration Validation",
                        description="Configuration values used without proper validation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class InsecureDebugConfigurationDetector(VulnerabilityDetector):
    """CWE-489: Active Debug Code"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'debug.*=.*true|DEBUG.*=.*True|debug.*enabled', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'production|prod|environment.*prod', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-489", severity="medium", title="Insecure Debug Configuration",
                        description="Debug features enabled in potentially production environment.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class MissingRateLimitingConfigurationDetector(VulnerabilityDetector):
    """CWE-770: Allocation of Resources Without Limits"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'app\.listen|server\.listen|createServer', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-15):min(len(lines), i+15)])
                if not re.search(r'rate.*limit|throttle|limit.*request', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-770", severity="medium", title="Missing Rate Limiting Configuration",
                        description="Server configured without rate limiting protection.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="configuration"
                    ))
        return vulnerabilities

class InsecureCORSConfigurationDetector(VulnerabilityDetector):
    """CWE-346: Origin Validation Error"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'Access-Control-Allow-Origin.*\*|origins.*\*', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-346", severity="high", title="Insecure CORS Configuration",
                    description="CORS policy allows all origins (*) which may enable cross-origin attacks.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="configuration"
                ))
        return vulnerabilities

class MissingSecurityHeadersConfigurationDetector(VulnerabilityDetector):
    """CWE-693: Protection Mechanism Failure"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'response\.|res\.|headers\.', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'X-Frame-Options|Content-Security-Policy|X-Content-Type-Options', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-693", severity="medium", title="Missing Security Headers Configuration",
                        description="HTTP responses lack important security headers.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="configuration"
                    ))
        return vulnerabilities

class InsecureSessionConfigurationDetector(VulnerabilityDetector):
    """CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'session.*cookie|cookie.*session', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'secure.*true|httpOnly.*true|sameSite', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-614", severity="high", title="Insecure Session Configuration",
                        description="Session cookies lack proper security attributes.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class DatabaseConnectionStringExposureDetector(VulnerabilityDetector):
    """CWE-200: Information Exposure Through Configuration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'connection.*string|DATABASE_URL|db.*url', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'console\.log|print|log', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-200", severity="high", title="Database Connection String Exposure",
                        description="Database connection strings exposed through logging or output.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="configuration"
                    ))
        return vulnerabilities

class MissingInputValidationConfigurationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation - Missing Configuration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@RequestBody|@RequestParam|req\.body|req\.query', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'@Valid|@Validated|validate|joi|yup', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="medium", title="Missing Input Validation Configuration",
                        description="Input handling lacks validation configuration.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class InsecureDefaultCredentialsConfigurationDetector(VulnerabilityDetector):
    """CWE-798: Use of Hard-coded Credentials"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'password.*=|username.*=|admin.*=|root.*=', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                if re.search(r'123456|password|admin|qwerty|letmein', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-798", severity="critical", title="Insecure Default Credentials",
                        description="Default or weak credentials configured in the system.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="configuration"
                    ))
        return vulnerabilities

class MissingBackupEncryptionConfigurationDetector(VulnerabilityDetector):
    """CWE-311: Missing Encryption of Sensitive Data"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'backup|export.*data|dump.*database', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'encrypt|aes|gpg|ssl', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-311", severity="high", title="Missing Backup Encryption Configuration",
                        description="Data backups lack encryption protection.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class MissingEncryptionConfigurationDetector(VulnerabilityDetector):
    """CWE-311: Missing Encryption of Sensitive Data - Configuration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'store.*password|save.*secret|persist.*key', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'encrypt|hash|cipher|bcrypt', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-311", severity="high", title="Missing Encryption Configuration",
                        description="Sensitive data stored without encryption in configuration.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

class InsecureRandomNumberGeneratorDetector(VulnerabilityDetector):
    """CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'Math\.random|Random\(\)|rand\(\)', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'token|session|secret|key', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-338", severity="high", title="Weak Random Number Generator",
                        description="Cryptographically weak random number generator used for security-sensitive operations.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="configuration"
                    ))
        return vulnerabilities

class MissingAuditLoggingConfigurationDetector(VulnerabilityDetector):
    """CWE-778: Insufficient Logging - Audit Configuration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'login|auth|access|modify', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'log.*audit|audit.*log|logger\.|log\.', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-778", severity="low", title="Missing Audit Logging Configuration",
                        description="Security-relevant operations not configured for audit logging.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="configuration"
                    ))
        return vulnerabilities

class InsecureDefaultTimeoutsDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - Default Timeouts"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'timeout.*=.*60000|timeout.*=.*60', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-400", severity="medium", title="Insecure Default Timeout Configuration",
                    description="Default timeout values may allow resource exhaustion attacks.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="low", category="configuration"
                ))
        return vulnerabilities

class MissingDataBackupConfigurationDetector(VulnerabilityDetector):
    """CWE-19: Data Loss - Missing Backup Configuration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'database|data.*store|persistent', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-15):min(len(lines), i+15)])
                if not re.search(r'backup|replica|redundant|snapshot', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-19", severity="low", title="Missing Data Backup Configuration",
                        description="Critical data storage without backup configuration.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="configuration"
                    ))
        return vulnerabilities

class InsecureFileUploadConfigurationDetector(VulnerabilityDetector):
    """CWE-434: Unrestricted Upload of File with Dangerous Type"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'multer|upload|file.*upload', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'fileFilter|check.*type|validate.*extension', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-434", severity="high", title="Insecure File Upload Configuration",
                        description="File upload functionality without proper type restrictions.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="configuration"
                    ))
        return vulnerabilities

def get_configuration_detectors():
    return [
        SecurityMisconfigurationDetector(),
        IncorrectPermissionDetector(),
        HardcodedCredentialsDetector(),
        InsecureDefaultConfigurationDetector(),
        MissingSecurityHeadersDetector(),
        WeakSSLConfigurationDetector(),
        DatabaseMisconfigurationDetector(),
        LoggingMisconfigurationDetector(),
        SessionMisconfigurationDetector(),
        BackupMisconfigurationDetector(),
        CacheMisconfigurationDetector(),
        EnvironmentMisconfigurationDetector(),
        InsecureFilePermissionsConfigurationDetector(),
        MissingConfigurationValidationDetector(),
        InsecureDebugConfigurationDetector(),
        MissingRateLimitingConfigurationDetector(),
        InsecureCORSConfigurationDetector(),
        MissingSecurityHeadersConfigurationDetector(),
        InsecureSessionConfigurationDetector(),
        DatabaseConnectionStringExposureDetector(),
        MissingInputValidationConfigurationDetector(),
        InsecureDefaultCredentialsConfigurationDetector(),
        MissingBackupEncryptionConfigurationDetector(),
        MissingEncryptionConfigurationDetector(),
        InsecureRandomNumberGeneratorDetector(),
        MissingAuditLoggingConfigurationDetector(),
        InsecureDefaultTimeoutsDetector(),
        MissingDataBackupConfigurationDetector(),
        InsecureFileUploadConfigurationDetector(),
    ]
    return [SecurityMisconfigurationDetector(), IncorrectPermissionDetector()]