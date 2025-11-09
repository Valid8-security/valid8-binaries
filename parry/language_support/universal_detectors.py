"""
Universal CWE detectors that apply to all or most languages.

These detectors implement vulnerability patterns that are language-agnostic
or can be adapted across multiple languages with minimal changes.
"""

import re
from typing import List
from .base import Vulnerability


class UniversalDetectors:
    """Mixin class providing universal vulnerability detection methods."""
    
    def detect_improper_input_validation(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-20: Improper Input Validation."""
        patterns = [
            # Direct use of user input without validation
            (r'(request|req|input|user_input|params|args)\[.*\].*(?!validate|sanitize|check|verify)', 'Direct use of user input'),
            # Missing validation before critical operations
            (r'(execute|eval|exec|system|open|read|write)\s*\([^)]*?(request|input|params)', 'Critical operation with unvalidated input'),
            # No length checks before operations
            (r'(malloc|alloc|buffer|array)\s*\([^)]*?(request|input)', 'Memory operation without size validation'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Skip comments
            if self._is_comment(line):
                continue
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-20',
                        severity='high',
                        title='Improper Input Validation',
                        description=f'{desc}. Always validate and sanitize user input before use.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_information_exposure(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-200: Exposure of Sensitive Information."""
        patterns = [
            # Sensitive data in logs
            (r'(log|console|print|echo|write)\s*\([^)]*?(password|token|key|secret|credential)', 'Sensitive data in logs'),
            # Error messages with sensitive data
            (r'(error|exception|throw)\s*\([^)]*?(password|token|key|sql|query)', 'Sensitive data in error messages'),
            # Exposing internal paths
            (r'(error|exception)\s*\([^)]*?(__file__|__dir__|filepath|path)', 'Internal paths in error messages'),
            # Stack traces to user
            (r'(print|echo|write|send)\s*\([^)]*?(traceback|stacktrace|backtrace)', 'Stack trace exposure'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-200',
                        severity='medium',
                        title='Exposure of Sensitive Information',
                        description=f'{desc}. Avoid exposing sensitive data in logs or error messages.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_improper_authentication(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-287: Improper Authentication."""
        patterns = [
            # Weak authentication checks
            (r'if\s+.*(?:password|pwd|pass)\s*==\s*["\'][^"\']+["\']', 'Hard-coded password comparison'),
            # Authentication bypass
            (r'if\s+.*(?:auth|authenticated|logged_in)\s*==\s*(?:false|0|null)', 'Potential authentication bypass'),
            # Weak session checks
            (r'if\s+.*session\[.*\]\s*==\s*["\'][^"\']+["\']', 'Weak session validation'),
            # Only flag authentication-related endpoints without decorators
            (r'@app\.route.*def\s+(?:login|auth|authenticate|signin)', 'Authentication endpoint without proper security'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-287',
                        severity='high',
                        title='Improper Authentication',
                        description=f'{desc}. Implement proper authentication mechanisms.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_csrf(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-352: Cross-Site Request Forgery."""
        patterns = [
            # POST without CSRF token
            (r'(?:@route|@post|\.post|POST).*(?!csrf|token|@csrf_protect)', 'POST endpoint without CSRF protection'),
            # Form without CSRF token
            (r'<form[^>]*method\s*=\s*["\']post["\'][^>]*(?!csrf)', 'Form without CSRF token'),
            # State-changing operation without CSRF
            (r'(?:update|delete|create|modify).*(?!csrf|token)', 'State-changing operation without CSRF protection'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-352',
                        severity='high',
                        title='Cross-Site Request Forgery (CSRF)',
                        description=f'{desc}. Implement CSRF tokens for state-changing operations.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_incorrect_permissions(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-732: Incorrect Permission Assignment."""
        patterns = [
            # Overly permissive file permissions
            (r'chmod\s*\([^,]*,\s*0?[67]77', 'World-writable file permissions'),
            (r'os\.chmod\s*\([^,]*,\s*0o?[67]77', 'World-writable file permissions'),
            (r'umask\s*\(\s*0+\s*\)', 'Permissive umask (000)'),
            # Directory permissions
            (r'mkdir\s*\([^,]*,\s*0?777', 'World-writable directory'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-732',
                        severity='medium',
                        title='Incorrect Permission Assignment',
                        description=f'{desc}. Use restrictive file permissions (e.g., 0644 or 0600).',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_graphql_security(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect GraphQL-specific vulnerabilities (CWE-400, CWE-306, CWE-209, CWE-200)."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            # Depth limiting
            if re.search(r'new\s+GraphQLServer\s*\([^)]*\)', line, re.IGNORECASE) or re.search(r'new\s+GraphQLSchema\s*\([^)]*\)', line, re.IGNORECASE):
                # Check next 200 chars for depth limiting
                context = ' '.join(lines[max(0, i-1):min(len(lines), i+10)])
                if not re.search(r'(depthLimit|queryDepth|maxDepth)', context, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-400',
                        severity='high',
                        title='GraphQL Server Without Query Depth Limiting',
                        description='GraphQL server without query depth limiting can lead to DoS attacks through deeply nested queries. Implement depthLimit, queryDepth, or maxDepth.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
            
            # Complexity limiting
            if re.search(r'graphql\s*\([^)]*\)', line, re.IGNORECASE):
                context = ' '.join(lines[max(0, i-1):min(len(lines), i+10)])
                if not re.search(r'(validationRules|complexityLimit|maxComplexity)', context, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-400',
                        severity='high',
                        title='GraphQL Without Complexity Limiting',
                        description='GraphQL execution without complexity limiting. Implement query complexity analysis to prevent DoS.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
            
            # Introspection enabled in production
            if re.search(r'introspection\s*:\s*true', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-200',
                    severity='medium',
                    title='GraphQL Introspection Enabled in Production',
                    description='GraphQL introspection is enabled in production. Disable introspection in production environments.',
                    code=code,
                    filepath=filepath,
                    line_number=i,
                    confidence='high'
                ))
            
            # Stack trace exposure in GraphQL errors
            if re.search(r'GraphQLError\s*\([^)]*error\.stack', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-209',
                    severity='medium',
                    title='GraphQL Error Exposing Stack Trace',
                    description='GraphQL error exposing stack trace. Avoid exposing internal error details to clients.',
                    code=code,
                    filepath=filepath,
                    line_number=i,
                    confidence='high'
                ))
        
        return vulnerabilities
    
    def detect_jwt_security(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect JWT-related vulnerabilities (CWE-327, CWE-295, CWE-798)."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            # Weak algorithms (HS256, none)
            if re.search(r'(jwt\.(sign|encode)|jwt\.decode|jsonwebtoken)', line, re.IGNORECASE):
                context = ' '.join(lines[max(0, i-1):min(len(lines), i+10)])
                if re.search(r'(algorithm.*none|algorithm.*HS256|algorithm\s*=\s*["\']HS256)', context, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-327',
                        severity='high',
                        title='Weak JWT Algorithm',
                        description='Using weak JWT algorithm (HS256 or none). Use RS256 or stronger algorithms.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='high'
                    ))
            
            # Hardcoded JWT secret
            if re.search(r'(JWT_SECRET|JWT_KEY|JWT_ALGORITHM)\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-798',
                    severity='critical',
                    title='Hardcoded JWT Secret',
                    description='Hardcoded JWT secret found. Store secrets in environment variables.',
                    code=code,
                    filepath=filepath,
                    line_number=i,
                    confidence='high'
                ))
            
            # Missing signature verification
            if re.search(r'jwt\.decode\s*\([^)]*\)(?![\s\S]{0,200}verify|verifier)', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-295',
                    severity='high',
                    title='Missing JWT Signature Verification',
                    description='JWT decoding without signature verification. Always verify JWT signatures.',
                    code=code,
                    filepath=filepath,
                    line_number=i,
                    confidence='medium'
                ))
            
            # No expiration check
            if re.search(r'jwt\.verify\s*\([^)]*\)(?![\s\S]{0,200}exp|expiration)', line, re.IGNORECASE):
                context = ' '.join(lines[max(0, i-1):min(len(lines), i+10)])
                if 'exp' not in context.lower():
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-613',
                        severity='medium',
                        title='Missing JWT Expiration Check',
                        description='JWT verification without expiration check. Tokens should have exp claims.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_nosql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect NoSQL injection vulnerabilities (CWE-943)."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            # MongoDB with user input
            patterns = [
                (r'(db\.|collection\.|mongo\.).*\.find\s*\([^)]*(\$where|\$where|this\.)', 'NoSQL injection via $where'),
                (r'(db\.|collection\.|mongo\.).*\.find\s*\([^)]*\.(req|request|params)\[', 'NoSQL injection via user input'),
                (r'(db\.|collection\.|mongo\.).*\.findOne\s*\([^)]*\.(req|request|params)\[', 'NoSQL injection via user input'),
                (r'(db\.|collection\.).*\.aggregate\s*\([^)]*\.(req|request|params)\[', 'NoSQL injection in aggregation'),
                (r'eval\s*\([^)]*\.(req|request|params)', 'JavaScript eval with user input in NoSQL'),
            ]
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-943',
                        severity='high',
                        title='NoSQL Injection',
                        description=f'{desc}. Sanitize and validate user input before use in NoSQL queries.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_ssti(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect Server-Side Template Injection (CWE-94)."""
        vulnerabilities = []
        lines = code.split('\n')
        
        templates = {
            'python': ['render_template_string', 'jinja2', 'jinja', 'mako', 'tornado'],
            'javascript': ['ejs', 'handlebars', 'mustache', 'nunjucks'],
            'ruby': ['erb', 'haml', 'slim'],
            'php': ['twig', 'smarty'],
        }
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            # Check for unsafe template rendering
            patterns = [
                (r'render_template_string\s*\([^)]*\.(req|request|params|input)', 'Unsafe template rendering in Python'),
                (r'\.render\s*\([^)]*\.(req|request|params)', 'Unsafe template rendering'),
                (r'ejs\.render\s*\([^)]*\.(req|request|params)', 'Unsafe EJS rendering'),
                (r'twig\.render\s*\([^)]*\.(req|request|params)', 'Unsafe Twig rendering'),
                (r'ERB\.new\s*\([^)]*\.(req|request|params)', 'Unsafe ERB rendering'),
            ]
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-94',
                        severity='high',
                        title='Server-Side Template Injection (SSTI)',
                        description=f'{desc}. Template rendering with user input can allow code execution. Escape and validate input.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_redos(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect Regular Expression Denial of Service (CWE-1333)."""
        vulnerabilities = []
        lines = code.split('\n')
        
        redos_patterns = [
            (r'\+\+|\*\*|\??\?|\{\d*,\}\{\d*,\}', 'Nested quantifiers'),
            (r'\(.*\+.*\)\+|\(.*\*.*\)\*', 'Nested repeating groups'),
            (r'\(.*\|.*\)\{2,}', 'Expensive alternation'),
            (r'a\+\+', 'Repeated nested quantifiers'),
            (r'\(a\|b\)\+.*\*', 'Expensive alternation with repetition'),
        ]
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            # Look for regex definitions
            if re.search(r'(re\.|regex|RegExp|new RegExp|match|search|test)\s*\(', line):
                for pattern, desc in redos_patterns:
                    if re.search(pattern, line):
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-1333',
                            severity='high',
                            title='Regular Expression Denial of Service (ReDoS)',
                            description=f'Potentially vulnerable regex pattern: {desc}. Catastrophic backtracking can cause DoS.',
                            code=code,
                            filepath=filepath,
                            line_number=i,
                            confidence='medium'
                        ))
                        break
        
        return vulnerabilities
    
    def _is_comment(self, line: str) -> bool:
        """Check if line is a comment (basic check for common languages)."""
        stripped = line.strip()
        return (
            stripped.startswith('#') or
            stripped.startswith('//') or
            stripped.startswith('/*') or
            stripped.startswith('*') or
            stripped.startswith('<!--')
        )


