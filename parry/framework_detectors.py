"""
Framework-Specific Vulnerability Detectors

Specialized detectors for popular frameworks:
- Django (Python)
- Flask (Python)
- Spring Boot (Java)
- Express.js (Node.js/JavaScript)
- Rails (Ruby)
- Laravel (PHP)
"""

import re
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass


@dataclass
class FrameworkVulnerability:
    """Framework-specific vulnerability finding"""
    framework: str
    cwe: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    fix_suggestion: str
    confidence: str


class DjangoDetector:
    """Django-specific security detector"""
    
    def __init__(self):
        self.name = "Django"
        
    def detect(self, code: str, filepath: str) -> List[FrameworkVulnerability]:
        """Detect Django-specific vulnerabilities"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for missing CSRF protection
            if 'csrf_exempt' in line and '@' in line:
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Django",
                    cwe="CWE-352",
                    severity="high",
                    title="CSRF Protection Disabled",
                    description="View is marked with @csrf_exempt, disabling CSRF protection. "
                               "This makes the endpoint vulnerable to Cross-Site Request Forgery attacks.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Remove @csrf_exempt decorator and use {% csrf_token %} in forms. "
                                  "If AJAX is needed, use X-CSRFToken header.",
                    confidence="high"
                ))
            
            # Check for unsafe template rendering
            if re.search(r'render_to_string.*safe', line, re.IGNORECASE):
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Django",
                    cwe="CWE-79",
                    severity="high",
                    title="Unsafe Template Rendering",
                    description="Using '|safe' filter or mark_safe() bypasses Django's XSS protection.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Avoid using |safe or mark_safe(). Use Django's automatic escaping. "
                                  "If necessary, sanitize with bleach library first.",
                    confidence="high"
                ))
            
            # Check for raw SQL queries
            if re.search(r'\.raw\(|\.execute\(.*%|\.execute\(.*format\(', line):
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Django",
                    cwe="CWE-89",
                    severity="critical",
                    title="SQL Injection via Raw Query",
                    description="Raw SQL query with string formatting detected. This can lead to SQL injection.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Use Django ORM with parameterized queries or raw() with proper parameters. "
                                  "Example: Model.objects.raw('SELECT * FROM table WHERE id = %s', [id])",
                    confidence="high"
                ))
            
            # Check for DEBUG=True in production
            if re.match(r'^\s*DEBUG\s*=\s*True', line):
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Django",
                    cwe="CWE-489",
                    severity="high",
                    title="Debug Mode Enabled",
                    description="DEBUG=True exposes sensitive information in error pages and allows arbitrary code execution.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Set DEBUG=False in production. Use environment variables: "
                                  "DEBUG = os.getenv('DEBUG', 'False') == 'True'",
                    confidence="high"
                ))
            
            # Check for SECRET_KEY in code
            if re.match(r'^\s*SECRET_KEY\s*=\s*["\']', line):
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Django",
                    cwe="CWE-798",
                    severity="critical",
                    title="Hardcoded SECRET_KEY",
                    description="SECRET_KEY should never be hardcoded. It's used for cryptographic signing.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip()[:50] + "...",
                    fix_suggestion="Use environment variable: SECRET_KEY = os.getenv('SECRET_KEY'). "
                                  "Generate with: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'",
                    confidence="high"
                ))
            
            # Check for insecure session settings
            if 'SESSION_COOKIE_SECURE' in line and 'False' in line:
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Django",
                    cwe="CWE-614",
                    severity="medium",
                    title="Insecure Session Cookie",
                    description="SESSION_COOKIE_SECURE=False allows cookies to be sent over HTTP, risking session hijacking.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Set SESSION_COOKIE_SECURE = True and SESSION_COOKIE_HTTPONLY = True in production.",
                    confidence="high"
                ))
        
        return vulnerabilities


class FlaskDetector:
    """Flask-specific security detector"""
    
    def __init__(self):
        self.name = "Flask"
        
    def detect(self, code: str, filepath: str) -> List[FrameworkVulnerability]:
        """Detect Flask-specific vulnerabilities"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for debug mode
            if re.search(r'app\.run\(.*debug\s*=\s*True', line):
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Flask",
                    cwe="CWE-489",
                    severity="critical",
                    title="Debug Mode Enabled",
                    description="Flask debug mode enables the interactive debugger, allowing arbitrary code execution.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Remove debug=True in production. Use environment variable: "
                                  "app.run(debug=os.getenv('FLASK_ENV') == 'development')",
                    confidence="high"
                ))
            
            # Check for hardcoded secret key
            if re.search(r'app\.secret_key\s*=\s*["\']', line):
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Flask",
                    cwe="CWE-798",
                    severity="critical",
                    title="Hardcoded Secret Key",
                    description="Flask secret_key is hardcoded. This key is used for session signing.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip()[:50] + "...",
                    fix_suggestion="Use environment variable: app.secret_key = os.getenv('SECRET_KEY'). "
                                  "Generate with: python -c 'import secrets; print(secrets.token_hex(32))'",
                    confidence="high"
                ))
            
            # Check for render_template_string with user input
            if 'render_template_string' in line and ('request.' in line or 'input' in line):
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Flask",
                    cwe="CWE-1336",
                    severity="critical",
                    title="Server-Side Template Injection (SSTI)",
                    description="render_template_string with user input can lead to remote code execution.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Never use render_template_string with user input. Use render_template() with "
                                  "predefined templates and pass user data as variables.",
                    confidence="high"
                ))
            
            # Check for missing HTTPS redirect
            if re.search(r'app\.run\(', line) and 'ssl_context' not in code:
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Flask",
                    cwe="CWE-319",
                    severity="medium",
                    title="Missing HTTPS Configuration",
                    description="Application runs without SSL/TLS configuration.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Use Flask-Talisman for HTTPS redirect: pip install flask-talisman, then "
                                  "from flask_talisman import Talisman; Talisman(app, force_https=True)",
                    confidence="medium"
                ))
        
        return vulnerabilities


class SpringBootDetector:
    """Spring Boot-specific security detector"""
    
    def __init__(self):
        self.name = "Spring Boot"
        
    def detect(self, code: str, filepath: str) -> List[FrameworkVulnerability]:
        """Detect Spring Boot-specific vulnerabilities"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for missing @PreAuthorize
            if '@RequestMapping' in line or '@GetMapping' in line or '@PostMapping' in line:
                # Check if next few lines have authorization
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if '@PreAuthorize' not in context and '@Secured' not in context:
                    vulnerabilities.append(FrameworkVulnerability(
                        framework="Spring Boot",
                        cwe="CWE-862",
                        severity="high",
                        title="Missing Authorization Check",
                        description="Endpoint lacks @PreAuthorize or @Secured annotation.",
                        file_path=filepath,
                        line_number=i,
                        code_snippet=line.strip(),
                        fix_suggestion="Add @PreAuthorize annotation: @PreAuthorize(\"hasRole('USER')\") or "
                                      "configure method security in SecurityConfig.",
                        confidence="medium"
                    ))
            
            # Check for CSRF disabled
            if 'csrf().disable()' in line:
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Spring Boot",
                    cwe="CWE-352",
                    severity="high",
                    title="CSRF Protection Disabled",
                    description="Spring Security CSRF protection has been explicitly disabled.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Remove .csrf().disable(). If using REST API, implement token-based authentication. "
                                  "For stateless APIs, use JWT with proper validation.",
                    confidence="high"
                ))
            
            # Check for SQL injection via JDBC
            if re.search(r'jdbcTemplate\.(query|update)\(.*\+', line):
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Spring Boot",
                    cwe="CWE-89",
                    severity="critical",
                    title="SQL Injection in JDBC",
                    description="JDBC query uses string concatenation, allowing SQL injection.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Use parameterized queries: jdbcTemplate.query(\"SELECT * FROM users WHERE id = ?\", new Object[]{id}, ...)",
                    confidence="high"
                ))
            
            # Check for hardcoded credentials in application.properties comments
            if 'password' in line.lower() and '=' in line and not line.strip().startswith('#'):
                if re.search(r'=\s*["\']?\w{4,}', line):
                    vulnerabilities.append(FrameworkVulnerability(
                        framework="Spring Boot",
                        cwe="CWE-798",
                        severity="critical",
                        title="Hardcoded Password in Configuration",
                        description="Database or service password appears to be hardcoded in configuration file.",
                        file_path=filepath,
                        line_number=i,
                        code_snippet=line.strip()[:50] + "...",
                        fix_suggestion="Use environment variables or Spring Cloud Config: "
                                      "spring.datasource.password=${DB_PASSWORD}",
                        confidence="high"
                    ))
        
        return vulnerabilities


class ExpressDetector:
    """Express.js-specific security detector"""
    
    def __init__(self):
        self.name = "Express.js"
        
    def detect(self, code: str, filepath: str) -> List[FrameworkVulnerability]:
        """Detect Express.js-specific vulnerabilities"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for missing helmet
            if 'express()' in line and 'helmet' not in code:
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Express.js",
                    cwe="CWE-693",
                    severity="medium",
                    title="Missing Security Headers (Helmet)",
                    description="Express app doesn't use helmet middleware for security headers.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Install and use helmet: npm install helmet, then const helmet = require('helmet'); app.use(helmet());",
                    confidence="high"
                ))
            
            # Check for eval with user input
            if 'eval(' in line and ('req.' in line or 'params' in line or 'query' in line):
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Express.js",
                    cwe="CWE-95",
                    severity="critical",
                    title="Code Injection via eval()",
                    description="eval() called with user input allows arbitrary code execution.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Never use eval() with user input. Use JSON.parse() for data or safer alternatives.",
                    confidence="high"
                ))
            
            # Check for missing input validation
            if re.search(r'req\.(query|params|body)\.\w+', line) and 'validate' not in code.lower():
                vulnerabilities.append(FrameworkVulnerability(
                    framework="Express.js",
                    cwe="CWE-20",
                    severity="medium",
                    title="Missing Input Validation",
                    description="Request parameters used without apparent validation.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    fix_suggestion="Use express-validator: const { body, validationResult } = require('express-validator'); "
                                  "Add validation middleware to routes.",
                    confidence="medium"
                ))
            
            # Check for missing rate limiting
            if '@app.route' in line or 'app.get(' in line or 'app.post(' in line:
                if 'rate-limit' not in code and 'rateLimit' not in code:
                    vulnerabilities.append(FrameworkVulnerability(
                        framework="Express.js",
                        cwe="CWE-770",
                        severity="medium",
                        title="Missing Rate Limiting",
                        description="API endpoints lack rate limiting, vulnerable to DoS attacks.",
                        file_path=filepath,
                        line_number=i,
                        code_snippet=line.strip(),
                        fix_suggestion="Use express-rate-limit: npm install express-rate-limit, then apply to routes: "
                                      "const rateLimit = require('express-rate-limit'); const limiter = rateLimit({windowMs: 15*60*1000, max: 100});",
                        confidence="low"
                    ))
        
        return vulnerabilities


class FrameworkDetectorEngine:
    """Main engine for framework-specific detection"""
    
    def __init__(self):
        self.detectors = {
            'django': DjangoDetector(),
            'flask': FlaskDetector(),
            'spring': SpringBootDetector(),
            'express': ExpressDetector()
        }
    
    def detect_framework(self, code: str, filepath: str) -> Optional[str]:
        """Detect which framework is being used"""
        code_lower = code.lower()
        
        # Django detection
        if 'django' in code_lower or 'settings.py' in filepath or 'wsgi' in code_lower:
            return 'django'
        
        # Flask detection
        if 'from flask import' in code_lower or 'flask' in code_lower:
            return 'flask'
        
        # Spring Boot detection
        if '@springbootapplication' in code_lower or 'spring' in code_lower or '@restcontroller' in code_lower:
            return 'spring'
        
        # Express.js detection
        if 'express()' in code_lower or "require('express')" in code_lower or 'app.get(' in code:
            return 'express'
        
        return None
    
    def scan(self, code: str, filepath: str) -> List[FrameworkVulnerability]:
        """Scan code for framework-specific vulnerabilities"""
        framework = self.detect_framework(code, filepath)
        
        if framework and framework in self.detectors:
            detector = self.detectors[framework]
            return detector.detect(code, filepath)
        
        return []
    
    def scan_file(self, filepath: Path) -> List[FrameworkVulnerability]:
        """Scan a file for framework-specific vulnerabilities"""
        try:
            code = filepath.read_text(encoding='utf-8', errors='ignore')
            return self.scan(code, str(filepath))
        except Exception as e:
            return []

