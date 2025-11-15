# Parry (C) by Valid8 Security. Written by Andy Kurapati and Shreyan Mitra
"""
Framework-Specific Security Detectors

Detectors for popular web frameworks and libraries:
- Spring Framework (Java)
- Django (Python)
- Ruby on Rails (Ruby)
- Express.js (JavaScript)
- Laravel (PHP)
- ASP.NET Core (C#)
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class FrameworkDetector:
    """Base class for framework-specific detectors"""
    name: str
    language: str
    framework: str
    cwe: str
    severity: str
    description: str
    pattern: re.Pattern
    fix_suggestion: str


class SpringSecurityDetectors:
    """Spring Framework security detectors"""
    
    DETECTORS = [
        # CWE-352: CSRF Protection Disabled
        FrameworkDetector(
            name="spring-csrf-disabled",
            language="java",
            framework="Spring",
            cwe="CWE-352",
            severity="high",
            description="CSRF protection is explicitly disabled in Spring Security configuration",
            pattern=re.compile(r'\.csrf\(\)\.disable\(\)'),
            fix_suggestion="Enable CSRF protection: .csrf() without .disable()"
        ),
        
        # CWE-307: Mass Assignment Vulnerability
        FrameworkDetector(
            name="spring-mass-assignment",
            language="java",
            framework="Spring",
            cwe="CWE-915",
            severity="high",
            description="Direct binding of request parameters to domain objects without whitelist",
            pattern=re.compile(r'@RequestMapping.*@ModelAttribute\s+(?!@Valid)(\w+)\s+\w+'),
            fix_suggestion="Use @Valid with DTO classes and explicit field mappings"
        ),
        
        # CWE-284: Missing Authorization Checks
        FrameworkDetector(
            name="spring-missing-authorization",
            language="java",
            framework="Spring",
            cwe="CWE-284",
            severity="critical",
            description="Controller method lacks authorization annotation (@PreAuthorize/@Secured)",
            pattern=re.compile(r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping).*\n\s*(?!@PreAuthorize|@Secured|@RolesAllowed)public'),
            fix_suggestion="Add @PreAuthorize(\"hasRole('USER')\") or @Secured(\"ROLE_USER\")"
        ),
        
        # CWE-89: JPA Injection via Native Queries
        FrameworkDetector(
            name="spring-jpa-injection",
            language="java",
            framework="Spring",
            cwe="CWE-89",
            severity="critical",
            description="String concatenation in JPA native query can lead to SQL injection",
            pattern=re.compile(r'createNativeQuery\([^)]*\+[^)]*\)'),
            fix_suggestion="Use parameterized queries with setParameter() or named parameters"
        ),
        
        # CWE-614: Secure Cookie Flag Missing
        FrameworkDetector(
            name="spring-insecure-cookie",
            language="properties",
            framework="Spring",
            cwe="CWE-614",
            severity="medium",
            description="Session cookie not configured with secure flag in Spring Boot",
            pattern=re.compile(r'server\.servlet\.session\.cookie\.secure\s*=\s*false'),
            fix_suggestion="Set server.servlet.session.cookie.secure=true in application.properties"
        ),
        
        # CWE-601: Open Redirect
        FrameworkDetector(
            name="spring-open-redirect",
            language="java",
            framework="Spring",
            cwe="CWE-601",
            severity="medium",
            description="Unvalidated redirect using user-controlled input",
            pattern=re.compile(r'return\s+"redirect:"\s*\+\s*\w+'),
            fix_suggestion="Validate redirect URLs against a whitelist before redirecting"
        ),
        
        # CWE-327: Weak Encryption Algorithm
        FrameworkDetector(
            name="spring-weak-password-encoder",
            language="java",
            framework="Spring",
            cwe="CWE-327",
            severity="high",
            description="Using deprecated or weak password encoder in Spring Security",
            pattern=re.compile(r'new\s+(NoOpPasswordEncoder|StandardPasswordEncoder|Md5PasswordEncoder|ShaPasswordEncoder)'),
            fix_suggestion="Use BCryptPasswordEncoder or Argon2PasswordEncoder"
        ),
    ]


class DjangoSecurityDetectors:
    """Django framework security detectors"""
    
    DETECTORS = [
        # CWE-352: CSRF Exempt Decorator
        FrameworkDetector(
            name="django-csrf-exempt",
            language="python",
            framework="Django",
            cwe="CWE-352",
            severity="high",
            description="View function decorated with @csrf_exempt disables CSRF protection",
            pattern=re.compile(r'@csrf_exempt\s+def\s+\w+\(request'),
            fix_suggestion="Remove @csrf_exempt and use Django's built-in CSRF middleware"
        ),
        
        # CWE-89: Raw SQL Query with String Formatting
        FrameworkDetector(
            name="django-sql-injection",
            language="python",
            framework="Django",
            cwe="CWE-89",
            severity="critical",
            description="Using string formatting/concatenation in raw SQL queries",
            pattern=re.compile(r'\.raw\([f\'\"].*{.*}|\.raw\(.*%.*%|\.raw\(.*\+'),
            fix_suggestion="Use parameterized queries: .raw('SELECT * FROM table WHERE id = %s', [user_id])"
        ),
        
        # CWE-502: Unsafe Deserialization
        FrameworkDetector(
            name="django-unsafe-pickle",
            language="python",
            framework="Django",
            cwe="CWE-502",
            severity="critical",
            description="Using pickle for session serialization can lead to RCE",
            pattern=re.compile(r'SESSION_SERIALIZER\s*=\s*[\'"]django\.contrib\.sessions\.serializers\.PickleSerializer[\'"]'),
            fix_suggestion="Use JSONSerializer: SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'"
        ),
        
        # CWE-79: XSS via mark_safe
        FrameworkDetector(
            name="django-mark-safe-xss",
            language="python",
            framework="Django",
            cwe="CWE-79",
            severity="medium",
            description="Using mark_safe() on user-controlled data can introduce XSS",
            pattern=re.compile(r'mark_safe\([^)]*request\.(GET|POST|body|data)'),
            fix_suggestion="Avoid mark_safe() on user input; use Django's auto-escaping"
        ),
        
        # CWE-284: Missing Login Required Decorator
        FrameworkDetector(
            name="django-missing-auth",
            language="python",
            framework="Django",
            cwe="CWE-284",
            severity="high",
            description="View handling sensitive operations lacks @login_required decorator",
            pattern=re.compile(r'def\s+(delete|update|create|modify|edit)\w*\(request\):\s*(?!.*@login_required)', re.DOTALL),
            fix_suggestion="Add @login_required decorator to protect sensitive views"
        ),
        
        # CWE-326: DEBUG Mode Enabled in Production
        FrameworkDetector(
            name="django-debug-enabled",
            language="python",
            framework="Django",
            cwe="CWE-215",
            severity="high",
            description="DEBUG=True in settings.py exposes sensitive information",
            pattern=re.compile(r'DEBUG\s*=\s*True'),
            fix_suggestion="Set DEBUG=False in production and use environment variables"
        ),
        
        # CWE-798: Secret Key Hardcoded
        FrameworkDetector(
            name="django-hardcoded-secret",
            language="python",
            framework="Django",
            cwe="CWE-798",
            severity="critical",
            description="Django SECRET_KEY is hardcoded instead of using environment variable",
            pattern=re.compile(r'SECRET_KEY\s*=\s*[\'"][^\'"]{20,}[\'"]'),
            fix_suggestion="Load from environment: SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')"
        ),
    ]


class RailsSecurityDetectors:
    """Ruby on Rails security detectors"""
    
    DETECTORS = [
        # CWE-89: SQL Injection in ActiveRecord
        FrameworkDetector(
            name="rails-sql-injection",
            language="ruby",
            framework="Rails",
            cwe="CWE-89",
            severity="critical",
            description="String interpolation in ActiveRecord where() can cause SQL injection",
            pattern=re.compile(r'\.where\(["\'].*#{.*}["\']'),
            fix_suggestion="Use parameterized queries: .where('name = ?', params[:name])"
        ),
        
        # CWE-915: Mass Assignment Vulnerability
        FrameworkDetector(
            name="rails-mass-assignment",
            language="ruby",
            framework="Rails",
            cwe="CWE-915",
            severity="high",
            description="Missing strong parameters can allow mass assignment attacks",
            pattern=re.compile(r'\.new\(params\[:\w+\]\)(?!.*permit)'),
            fix_suggestion="Use strong parameters: params.require(:user).permit(:name, :email)"
        ),
        
        # CWE-352: CSRF Protection Disabled
        FrameworkDetector(
            name="rails-csrf-disabled",
            language="ruby",
            framework="Rails",
            cwe="CWE-352",
            severity="high",
            description="CSRF protection disabled in controller",
            pattern=re.compile(r'protect_from_forgery\s+(?:with:\s+:null_session|:skip_before_action)'),
            fix_suggestion="Enable CSRF protection with protect_from_forgery with: :exception"
        ),
        
        # CWE-79: XSS via raw() or html_safe
        FrameworkDetector(
            name="rails-xss-html-safe",
            language="ruby",
            framework="Rails",
            cwe="CWE-79",
            severity="medium",
            description="Using html_safe or raw() on user input can introduce XSS",
            pattern=re.compile(r'(params\[:\w+\]|request\.\w+)\.html_safe|raw\(params'),
            fix_suggestion="Remove html_safe/raw and let Rails auto-escape user input"
        ),
        
        # CWE-22: Path Traversal via send_file
        FrameworkDetector(
            name="rails-path-traversal",
            language="ruby",
            framework="Rails",
            cwe="CWE-22",
            severity="high",
            description="Unvalidated file path in send_file can lead to path traversal",
            pattern=re.compile(r'send_file\([^)]*params'),
            fix_suggestion="Validate and sanitize file paths, use File.basename() to remove directory components"
        ),
        
        # CWE-327: Weak Session Key
        FrameworkDetector(
            name="rails-weak-session-key",
            language="ruby",
            framework="Rails",
            cwe="CWE-327",
            severity="high",
            description="Hardcoded or weak secret_key_base in secrets.yml",
            pattern=re.compile(r'secret_key_base:\s*[\'"][a-f0-9]{1,127}[\'"]'),
            fix_suggestion="Generate strong secret with 'rails secret' and use environment variables"
        ),
    ]


class ExpressSecurityDetectors:
    """Express.js security detectors"""
    
    DETECTORS = [
        # CWE-352: CSRF Middleware Missing
        FrameworkDetector(
            name="express-no-csrf",
            language="javascript",
            framework="Express",
            cwe="CWE-352",
            severity="high",
            description="Express app lacks CSRF protection middleware",
            pattern=re.compile(r'app\.use\(.*(?!csrf|csurf).*\).*app\.(post|put|delete)'),
            fix_suggestion="Install and use csurf middleware: app.use(csrf({ cookie: true }))"
        ),
        
        # CWE-1321: Prototype Pollution
        FrameworkDetector(
            name="express-prototype-pollution",
            language="javascript",
            framework="Express",
            cwe="CWE-1321",
            severity="high",
            description="Merging user input directly into objects can cause prototype pollution",
            pattern=re.compile(r'Object\.(assign|merge)\([^,]+,\s*req\.(body|query|params)'),
            fix_suggestion="Validate and sanitize input before merging, use Object.create(null)"
        ),
        
        # CWE-89: NoSQL Injection in MongoDB
        FrameworkDetector(
            name="express-nosql-injection",
            language="javascript",
            framework="Express",
            cwe="CWE-943",
            severity="critical",
            description="Direct use of req.body/query in MongoDB queries can cause NoSQL injection",
            pattern=re.compile(r'\.find\(req\.(body|query)|\.findOne\(req\.(body|query)'),
            fix_suggestion="Validate and sanitize inputs, use schema validation (Mongoose)"
        ),
        
        # CWE-94: eval() with User Input
        FrameworkDetector(
            name="express-eval-injection",
            language="javascript",
            framework="Express",
            cwe="CWE-94",
            severity="critical",
            description="Using eval() with user-controlled input can lead to code injection",
            pattern=re.compile(r'eval\([^)]*req\.(body|query|params)'),
            fix_suggestion="Never use eval() with user input, use JSON.parse() or safe alternatives"
        ),
        
        # CWE-614: Secure Cookie Flag Missing
        FrameworkDetector(
            name="express-insecure-session",
            language="javascript",
            framework="Express",
            cwe="CWE-614",
            severity="medium",
            description="Session cookie configured without secure flag",
            pattern=re.compile(r'cookie:\s*{[^}]*secure:\s*false'),
            fix_suggestion="Set secure: true in session configuration for HTTPS-only cookies"
        ),
    ]


def get_all_framework_detectors() -> List[FrameworkDetector]:
    """Get all framework-specific detectors"""
    detectors = []
    detectors.extend(SpringSecurityDetectors.DETECTORS)
    detectors.extend(DjangoSecurityDetectors.DETECTORS)
    detectors.extend(RailsSecurityDetectors.DETECTORS)
    detectors.extend(ExpressSecurityDetectors.DETECTORS)
    return detectors
