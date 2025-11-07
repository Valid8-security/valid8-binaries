"""Framework-Specific Vulnerability Detectors - 15+ CWEs"""
import re
from pathlib import Path
from typing import List
from parry.scanner import Vulnerability, VulnerabilityDetector

class DjangoCSRFDetector(VulnerabilityDetector):
    """CWE-352: CSRF - Django"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'@csrf_exempt|.*csrf.*disable', "CWE-352", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-352", severity=severity, title="CSRF - Django", description="CSRF protection disabled in Django.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="csrf"))
        return vulnerabilities

class ReactXSSDetector(VulnerabilityDetector):
    """CWE-79: XSS - React"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'dangerouslySetInnerHTML', "CWE-79", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-79", severity=severity, title="XSS - React", description="Dangerous React pattern detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="xss"))
        return vulnerabilities

class SpringSecurityMisconfigDetector(VulnerabilityDetector):
    """CWE-862: Spring Security Misconfiguration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'@EnableWebSecurity.*missing', "CWE-862", "high"),
            (r'permitAll\(\)', "CWE-862", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Spring Security Misconfiguration",
                        description="Spring Security not properly configured.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-security"
                    ))
        return vulnerabilities

class FlaskDebugModeDetector(VulnerabilityDetector):
    """CWE-489: Flask Debug Mode"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'app\.run\(.*debug\s*=\s*True', "CWE-489", "high"),
            (r'FLASK_ENV.*development', "CWE-489", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Flask Debug Mode",
                        description="Flask debug mode enabled in production.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-security"
                    ))
        return vulnerabilities

class LaravelMassAssignmentDetector(VulnerabilityDetector):
    """CWE-915: Laravel Mass Assignment"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\$request->all\(\)', "CWE-915", "high"),
            (r'fill\(.*\$request', "CWE-915", "high"),
            (r'\$fillable.*missing', "CWE-915", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'\$fillable|\$guarded', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Laravel Mass Assignment",
                            description="Laravel mass assignment vulnerability.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="framework-security"
                        ))
        return vulnerabilities

class AngularTemplateInjectionDetector(VulnerabilityDetector):
    """CWE-94: Angular Template Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\{\{.*constructor', "CWE-94", "high"),
            (r'\{\{.*alert\(.*\}\}', "CWE-94", "high"),
            (r'ng-bind-html-unsafe', "CWE-94", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Angular Template Injection",
                        description="Angular template injection vulnerability.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-security"
                    ))
        return vulnerabilities

class ExpressCORSDetector(VulnerabilityDetector):
    """CWE-942: Express.js CORS Misconfiguration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'app\.use\(cors\(\)\)', "CWE-942", "medium"),
            (r'cors\(\{\s*origin:\s*\*\s*\}\)', "CWE-942", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Express CORS Misconfiguration",
                        description="Express.js CORS allows all origins.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="framework-security"
                    ))
        return vulnerabilities

class RubyOnRailsSQLInjectionDetector(VulnerabilityDetector):
    """CWE-89: Ruby on Rails SQL Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'find_by_sql\(.*\+', "CWE-89", "high"),
            (r'where\(.*\#\{', "CWE-89", "high"),
            (r'execute\(.*\+', "CWE-89", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'sanitize|sanitized', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Rails SQL Injection",
                            description="Ruby on Rails SQL injection vulnerability.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="framework-security"
                        ))
        return vulnerabilities

class ASPNETViewStateDetector(VulnerabilityDetector):
    """CWE-642: ASP.NET ViewState Issues"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'EnableViewStateMac.*false', "CWE-642", "high"),
            (r'ViewStateEncryptionMode.*Never', "CWE-642", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="ASP.NET ViewState Issue",
                        description="ASP.NET ViewState security not properly configured.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-security"
                    ))
        return vulnerabilities

class SymfonySecurityDetector(VulnerabilityDetector):
    """CWE-285: Symfony Access Control"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'@Security.*missing', "CWE-285", "medium"),
            (r'is_granted\(.*false', "CWE-285", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Symfony Access Control",
                        description="Symfony access control not properly configured.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="framework-security"
                    ))
        return vulnerabilities

class VueJSDOMPurifyDetector(VulnerabilityDetector):
    """CWE-79: Vue.js XSS without DOMPurify"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'v-html.*\$', "CWE-79", "medium"),
            (r'innerHTML.*\$', "CWE-79", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'DOMPurify\.sanitize|escape|sanitize', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Vue.js XSS",
                            description="Vue.js XSS without proper sanitization.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="framework-security"
                        ))
        return vulnerabilities

class NodeJSEvalDetector(VulnerabilityDetector):
    """CWE-95: Node.js Code Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'eval\(.*req', "CWE-95", "critical"),
            (r'new Function\(.*req', "CWE-95", "critical"),
            (r'vm\.runInContext.*req', "CWE-95", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Node.js Code Injection",
                        description="Node.js code injection via eval or vm.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-security"
                    ))
        return vulnerabilities

class Struts2OGNLDetector(VulnerabilityDetector):
    """CWE-917: Struts2 OGNL Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'%\{.*#.*\}', "CWE-917", "critical"),
            (r'\$\{.*#.*\}', "CWE-917", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Struts2 OGNL Injection",
                        description="Struts2 OGNL expression injection.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="critical", category="framework-security"
                    ))
        return vulnerabilities

class PlayFrameworkXSSDetector(VulnerabilityDetector):
    """CWE-79: Play Framework XSS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'@Html.*raw\(.*\$', "CWE-79", "high"),
            (r'@.*formatRaw', "CWE-79", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Play Framework XSS",
                        description="Play Framework XSS via raw HTML output.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-security"
                    ))
        return vulnerabilities

class HibernateLazyLoadingDetector(VulnerabilityDetector):
    """CWE-200: Hibernate Lazy Loading Leak"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'FetchType\.LAZY.*not.*checked', "CWE-200", "medium"),
            (r'lazy.*loading.*exposed', "CWE-200", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Hibernate Lazy Loading",
                        description="Hibernate lazy loading may expose sensitive data.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="framework-security"
                    ))
        return vulnerabilities

class WordPressSQLInjectionDetector(VulnerabilityDetector):
    """CWE-89: WordPress SQL Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\$wpdb->query\(.*\$', "CWE-89", "high"),
            (r'get_results\(.*\$', "CWE-89", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'prepare|esc_sql', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="WordPress SQL Injection",
                            description="WordPress SQL injection without proper escaping.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="framework-security"
                        ))
        return vulnerabilities

class DjangoORMInjectionDetector(VulnerabilityDetector):
    """CWE-89: SQL Injection - Django ORM"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'\.raw\(|extra\(|\.filter\(.*\+', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-89", severity="high", title="Django ORM SQL Injection",
                    description="Django ORM raw SQL or extra() usage may be vulnerable to injection.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="framework-specific"
                ))
        return vulnerabilities

class ReactStateInjectionDetector(VulnerabilityDetector):
    """CWE-79: XSS - React State Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'dangerouslySetInnerHTML|innerHTML', line) and 'react' in content.lower():
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-79", severity="high", title="React dangerouslySetInnerHTML XSS",
                    description="dangerouslySetInnerHTML used without sanitization in React.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="framework-specific"
                ))
        return vulnerabilities

class SpringJPAInjectionDetector(VulnerabilityDetector):
    """CWE-89: SQL Injection - Spring JPA"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@Query.*\+|createQuery.*\+', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-89", severity="high", title="Spring JPA Query Injection",
                    description="Spring JPA @Query with string concatenation vulnerable to injection.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="framework-specific"
                ))
        return vulnerabilities

class FlaskSessionSecretDetector(VulnerabilityDetector):
    """CWE-798: Hard-coded Credentials - Flask Secret Key"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'SECRET_KEY.*=.*["\'][^"\']{0,10}["\']', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-798", severity="high", title="Weak Flask Secret Key",
                    description="Flask SECRET_KEY is too short or hardcoded.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="framework-specific"
                ))
        return vulnerabilities

class LaravelEloquentInjectionDetector(VulnerabilityDetector):
    """CWE-89: SQL Injection - Laravel Eloquent"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'DB::raw\(|whereRaw.*\$|orderByRaw.*\$', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-89", severity="high", title="Laravel Eloquent Raw Query Injection",
                    description="Laravel DB::raw or raw query methods may be vulnerable to injection.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="framework-specific"
                ))
        return vulnerabilities

class AngularSanitizationBypassDetector(VulnerabilityDetector):
    """CWE-79: XSS - Angular Sanitization Bypass"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'bypassSecurityTrustHtml|bypassSecurityTrustScript', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-79", severity="critical", title="Angular Sanitization Bypass",
                    description="Angular bypassSecurityTrust* methods used to bypass XSS protection.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="framework-specific"
                ))
        return vulnerabilities

class ExpressBodyParserVulnDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - Express Body Parser"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'bodyParser|express.*body', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'limit|size', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-400", severity="medium", title="Express Body Parser DoS",
                        description="Express body parser without size limits vulnerable to DoS.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="framework-specific"
                    ))
        return vulnerabilities

class RailsMassAssignmentDetector(VulnerabilityDetector):
    """CWE-915: Object Injection - Rails Mass Assignment"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'update_attributes|update.*params|assign_attributes', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'permit|slice|only', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-915", severity="high", title="Rails Mass Assignment Vulnerability",
                        description="Rails mass assignment without proper attribute whitelisting.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-specific"
                    ))
        return vulnerabilities

class ASPNETRequestValidationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation - ASP.NET Request Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'ValidateRequest.*false|requestValidationMode.*Disabled', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-20", severity="medium", title="ASP.NET Request Validation Disabled",
                    description="ASP.NET request validation disabled, allowing potential XSS.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="framework-specific"
                ))
        return vulnerabilities

class SymfonyTwigInjectionDetector(VulnerabilityDetector):
    """CWE-94: Code Injection - Symfony Twig"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'twig.*render.*\$|template_from_string', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'\$_|\$request|\$this->', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-94", severity="high", title="Symfony Twig Template Injection",
                        description="Symfony Twig template rendering with user input vulnerable to injection.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="framework-specific"
                    ))
        return vulnerabilities

class VueJSDataBindingVulnerabilityDetector(VulnerabilityDetector):
    """CWE-79: XSS - Vue.js Data Binding"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'v-html|v-text.*\$|innerHTML', line) and 'vue' in content.lower():
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-79", severity="high", title="Vue.js XSS via Data Binding",
                    description="Vue.js data binding used without proper sanitization.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="framework-specific"
                ))
        return vulnerabilities

class NodeJSEvalInjectionDetector(VulnerabilityDetector):
    """CWE-95: Eval Injection - Node.js"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'eval\(|new Function|vm\.runIn', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'req\.|request|user.*input', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-95", severity="critical", title="Node.js Eval Code Injection",
                        description="Dynamic code execution with user input in Node.js.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-specific"
                    ))
        return vulnerabilities

class PHPUnsafeSerializationDetector(VulnerabilityDetector):
    """CWE-502: Deserialization of Untrusted Data - PHP"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'unserialize\(|__wakeup|__destruct', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if re.search(r'\$_|\$_GET|\$_POST', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-502", severity="critical", title="PHP Unsafe Deserialization",
                        description="PHP deserialization of untrusted user data.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-specific"
                    ))
        return vulnerabilities

class GoPanicRecoveryDetector(VulnerabilityDetector):
    """CWE-755: Improper Handling of Exceptional Conditions - Go Panic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'recover\(\)|defer.*recover', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'log\.|error|handle', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-755", severity="medium", title="Go Panic Recovery Without Logging",
                        description="Go panic recovery without proper error logging or handling.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="framework-specific"
                    ))
        return vulnerabilities

class RubyMassAssignmentDetector(VulnerabilityDetector):
    """CWE-915: Object Injection - Ruby Mass Assignment"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'update_attributes|assign_attributes|update.*params', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'permit|slice|only|strong_parameters', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-915", severity="high", title="Ruby Mass Assignment Vulnerability",
                        description="Ruby mass assignment without proper attribute whitelisting.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="framework-specific"
                    ))
        return vulnerabilities

def get_framework_specific_detectors():
    return [
        DjangoCSRFDetector(),
        ReactXSSDetector(),
        SpringSecurityMisconfigDetector(),
        FlaskDebugModeDetector(),
        LaravelMassAssignmentDetector(),
        AngularTemplateInjectionDetector(),
        ExpressCORSDetector(),
        RubyOnRailsSQLInjectionDetector(),
        ASPNETViewStateDetector(),
        SymfonySecurityDetector(),
        VueJSDOMPurifyDetector(),
        NodeJSEvalDetector(),
        Struts2OGNLDetector(),
        PlayFrameworkXSSDetector(),
        HibernateLazyLoadingDetector(),
        WordPressSQLInjectionDetector(),
        DjangoORMInjectionDetector(),
        ReactStateInjectionDetector(),
        SpringJPAInjectionDetector(),
        FlaskSessionSecretDetector(),
        LaravelEloquentInjectionDetector(),
        AngularSanitizationBypassDetector(),
        ExpressBodyParserVulnDetector(),
        RailsMassAssignmentDetector(),
        ASPNETRequestValidationDetector(),
        SymfonyTwigInjectionDetector(),
        VueJSDataBindingVulnerabilityDetector(),
        NodeJSEvalInjectionDetector(),
        PHPUnsafeSerializationDetector(),
        GoPanicRecoveryDetector(),
        RubyMassAssignmentDetector(),
    ]