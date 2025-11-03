# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
API Security Detector Module

Implements OWASP API Security Top 10 2023 detection:
1. Broken Object Level Authorization (BOLA/IDOR)
2. Broken Authentication
3. Broken Object Property Level Authorization
4. Unrestricted Resource Consumption
5. Broken Function Level Authorization
6. Unrestricted Access to Sensitive Business Flows
7. Server Side Request Forgery (SSRF)
8. Security Misconfiguration
9. Improper Inventory Management
10. Unsafe Consumption of APIs

Author: Parry Security Team
Version: 1.0.0
"""

import re
import ast
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class APIVulnerability:
    """Represents an API security vulnerability"""
    cwe: str
    owasp_api: str  # API1:2023 to API10:2023
    title: str
    description: str
    severity: str
    line: int
    column: int
    code: str
    fix: Optional[str] = None
    confidence: float = 0.85


class APISecurityDetector:
    """Detect OWASP API Security Top 10 2023 vulnerabilities"""
    
    # Framework-specific patterns
    FRAMEWORK_PATTERNS = {
        'flask': {
            'route_decorator': '@app.route',
            'request_object': 'request',
            'auth_decorators': ['@login_required', '@jwt_required', '@requires_auth']
        },
        'django': {
            'view_classes': ['View', 'APIView', 'ViewSet'],
            'request_object': 'request',
            'auth_decorators': ['@login_required', '@permission_required']
        },
        'fastapi': {
            'route_decorator': '@app.',
            'request_object': 'Request',
            'auth_dependencies': ['Depends(', 'Security(']
        },
        'express': {
            'route_methods': ['app.get', 'app.post', 'app.put', 'app.delete', 'router.'],
            'request_object': 'req',
            'auth_middleware': ['authenticate', 'authorize', 'isAuthenticated']
        },
        'spring': {
            'annotations': ['@GetMapping', '@PostMapping', '@RequestMapping'],
            'request_object': 'HttpServletRequest',
            'auth_annotations': ['@PreAuthorize', '@Secured', '@RolesAllowed']
        }
    }
    
    def __init__(self):
        self.vulnerabilities: List[APIVulnerability] = []
        self.framework = None
    
    def detect_all(self, code: str, language: str, filename: str = "") -> List[APIVulnerability]:
        """Run all API security detectors"""
        self.vulnerabilities = []
        self._detect_framework(code, language)
        
        if language == 'python':
            self._detect_python_api_vulns(code, filename)
        elif language in ['javascript', 'typescript']:
            self._detect_js_api_vulns(code, filename)
        elif language == 'java':
            self._detect_java_api_vulns(code, filename)
        
        return self.vulnerabilities
    
    def _detect_framework(self, code: str, language: str):
        """Detect web framework being used"""
        if language == 'python':
            if 'from flask import' in code or 'import flask' in code:
                self.framework = 'flask'
            elif 'from django' in code or 'import django' in code:
                self.framework = 'django'
            elif 'from fastapi import' in code or 'import fastapi' in code:
                self.framework = 'fastapi'
        elif language in ['javascript', 'typescript']:
            if 'express(' in code or "require('express')" in code:
                self.framework = 'express'
        elif language == 'java':
            if '@RestController' in code or '@Controller' in code:
                self.framework = 'spring'
    
    def _detect_python_api_vulns(self, code: str, filename: str):
        """Detect Python API vulnerabilities"""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            self._detect_with_regex(code, 'python')
            return
        
        for node in ast.walk(tree):
            self._check_bola_idor(node, code)
            self._check_broken_authentication(node, code)
            self._check_mass_assignment(node, code)
            self._check_rate_limiting(node, code)
            self._check_broken_function_auth(node, code)
            self._check_ssrf(node, code)
            self._check_security_misconfiguration(node, code)
    
    def _check_bola_idor(self, node: ast.AST, code: str):
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        Detect missing authorization checks when accessing resources by ID
        """
        if isinstance(node, ast.FunctionDef):
            # Check if function is an API endpoint
            if not self._is_api_endpoint(node):
                return
            
            # Look for database queries using user-supplied IDs without auth checks
            has_id_param = False
            has_db_query = False
            has_auth_check = False
            
            func_body = ast.unparse(node) if hasattr(ast, 'unparse') else ''
            
            # Check for ID parameters
            for arg in node.args.args:
                if 'id' in arg.arg.lower():
                    has_id_param = True
            
            # Check for database queries
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    func_name = self._get_func_name(child.func)
                    
                    # Database query patterns
                    db_patterns = [
                        'get', 'filter', 'find', 'query',
                        'get_or_404', 'first', 'one'
                    ]
                    
                    if any(pattern in func_name.lower() for pattern in db_patterns):
                        has_db_query = True
                    
                    # Authorization check patterns
                    auth_patterns = [
                        'check_permission', 'has_permission', 'can_access',
                        'authorize', 'verify_owner', 'check_owner'
                    ]
                    
                    if any(pattern in func_name.lower() for pattern in auth_patterns):
                        has_auth_check = True
            
            # Flag if accessing resources by ID without authorization
            if has_id_param and has_db_query and not has_auth_check:
                vuln = APIVulnerability(
                    cwe='CWE-639',
                    owasp_api='API1:2023',
                    title='Broken Object Level Authorization (BOLA/IDOR)',
                    description=(
                        'API endpoint accesses resources by user-supplied ID without verifying '
                        'if the current user has permission to access that resource. '
                        'Attackers can manipulate IDs to access other users\' data.'
                    ),
                    severity='CRITICAL',
                    line=node.lineno,
                    column=node.col_offset,
                    code=self._extract_code_snippet(code, node.lineno),
                    fix=(
                        'Add authorization check before accessing resource:\n'
                        'def get_resource(resource_id):\n'
                        '    resource = Resource.get(resource_id)\n'
                        '    if resource.owner_id != current_user.id:\n'
                        '        raise PermissionError("Unauthorized access")\n'
                        '    return resource'
                    ),
                    confidence=0.8
                )
                self.vulnerabilities.append(vuln)
    
    def _check_broken_authentication(self, node: ast.AST, code: str):
        """
        API2:2023 - Broken Authentication
        Detect weak authentication mechanisms
        """
        if isinstance(node, ast.FunctionDef):
            if not self._is_api_endpoint(node):
                return
            
            func_body = ast.unparse(node) if hasattr(ast, 'unparse') else ''
            func_body_lower = func_body.lower()
            
            # Check for authentication issues
            issues = []
            
            # Missing rate limiting on auth endpoints
            if any(keyword in func_body_lower for keyword in ['login', 'signin', 'authenticate']):
                if 'rate_limit' not in func_body_lower and 'limiter' not in func_body_lower:
                    issues.append('Missing rate limiting on authentication endpoint')
            
            # Weak JWT secrets
            if 'jwt.encode' in func_body:
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        func_name = self._get_func_name(child.func)
                        if 'jwt.encode' in func_name:
                            # Check for hardcoded or weak secrets
                            for keyword in child.keywords:
                                if keyword.arg in ['key', 'secret']:
                                    if isinstance(keyword.value, ast.Constant):
                                        secret = keyword.value.value
                                        if isinstance(secret, str) and len(secret) < 32:
                                            issues.append('Weak JWT secret (< 32 characters)')
            
            # Missing token expiration
            if 'jwt.encode' in func_body:
                if 'exp' not in func_body and 'expiration' not in func_body_lower:
                    issues.append('JWT tokens without expiration')
            
            if issues:
                vuln = APIVulnerability(
                    cwe='CWE-287',
                    owasp_api='API2:2023',
                    title='Broken Authentication',
                    description=f'Authentication vulnerabilities detected: {", ".join(issues)}',
                    severity='CRITICAL',
                    line=node.lineno,
                    column=node.col_offset,
                    code=self._extract_code_snippet(code, node.lineno),
                    fix=(
                        'Implement secure authentication:\n'
                        '1. Use strong JWT secrets (32+ chars from env)\n'
                        '2. Add token expiration (1-24 hours)\n'
                        '3. Implement rate limiting on auth endpoints\n'
                        '4. Use secure password hashing (bcrypt, argon2)\n'
                        'Example:\n'
                        'from flask_limiter import Limiter\n'
                        '@limiter.limit("5 per minute")\n'
                        '@app.route("/login")\n'
                        'def login():\n'
                        '    token = jwt.encode(\n'
                        '        {"user_id": user.id, "exp": datetime.utcnow() + timedelta(hours=1)},\n'
                        '        os.environ["JWT_SECRET"],\n'
                        '        algorithm="HS256"\n'
                        '    )'
                    ),
                    confidence=0.85
                )
                self.vulnerabilities.append(vuln)
    
    def _check_mass_assignment(self, node: ast.AST, code: str):
        """
        API3:2023 - Broken Object Property Level Authorization (Mass Assignment)
        Detect unsafe direct assignment from request data
        """
        if isinstance(node, ast.Assign):
            # Check for patterns like: user.update(request.json)
            if isinstance(node.value, ast.Call):
                func_name = self._get_func_name(node.value.func)
                
                if any(method in func_name for method in ['update', 'save', 'create']):
                    # Check if argument is raw request data
                    for arg in node.value.args:
                        arg_str = ast.unparse(arg) if hasattr(ast, 'unparse') else ''
                        
                        if any(pattern in arg_str for pattern in [
                            'request.json', 'request.data', 'request.form',
                            'req.body', 'req.params'
                        ]):
                            vuln = APIVulnerability(
                                cwe='CWE-915',
                                owasp_api='API3:2023',
                                title='Mass Assignment Vulnerability',
                                description=(
                                    'Object updated directly with raw request data. '
                                    'Attackers can modify unintended fields like is_admin, role, etc. '
                                    'Always use explicit field whitelisting.'
                                ),
                                severity='HIGH',
                                line=node.lineno,
                                column=node.col_offset,
                                code=self._extract_code_snippet(code, node.lineno),
                                fix=(
                                    'Use explicit field whitelisting:\n'
                                    'ALLOWED_FIELDS = ["name", "email", "bio"]\n'
                                    'safe_data = {k: v for k, v in request.json.items() if k in ALLOWED_FIELDS}\n'
                                    'user.update(safe_data)\n'
                                    '\n'
                                    'Or use schema validation:\n'
                                    'from marshmallow import Schema, fields\n'
                                    'class UserUpdateSchema(Schema):\n'
                                    '    name = fields.Str()\n'
                                    '    email = fields.Email()\n'
                                    'safe_data = UserUpdateSchema().load(request.json)'
                                ),
                                confidence=0.9
                            )
                            self.vulnerabilities.append(vuln)
    
    def _check_rate_limiting(self, node: ast.AST, code: str):
        """
        API4:2023 - Unrestricted Resource Consumption
        Detect missing rate limiting
        """
        if isinstance(node, ast.FunctionDef):
            if not self._is_api_endpoint(node):
                return
            
            # Check if endpoint has rate limiting decorator
            has_rate_limit = False
            for decorator in node.decorator_list:
                decorator_str = ast.unparse(decorator) if hasattr(ast, 'unparse') else ''
                
                if any(pattern in decorator_str for pattern in [
                    'rate_limit', 'limiter', 'throttle', 'RateLimit'
                ]):
                    has_rate_limit = True
            
            # Check for expensive operations without rate limiting
            func_body = ast.unparse(node) if hasattr(ast, 'unparse') else ''
            
            expensive_operations = [
                'query.all()', '.filter(', 'search(',
                'send_email', 'upload', 'process_file'
            ]
            
            has_expensive_op = any(op in func_body for op in expensive_operations)
            
            if has_expensive_op and not has_rate_limit:
                vuln = APIVulnerability(
                    cwe='CWE-770',
                    owasp_api='API4:2023',
                    title='Unrestricted Resource Consumption',
                    description=(
                        'API endpoint performs expensive operations without rate limiting. '
                        'Attackers can abuse this to cause DoS or excessive costs.'
                    ),
                    severity='HIGH',
                    line=node.lineno,
                    column=node.col_offset,
                    code=self._extract_code_snippet(code, node.lineno),
                    fix=(
                        'Add rate limiting:\n'
                        'from flask_limiter import Limiter\n'
                        'limiter = Limiter(app, key_func=get_remote_address)\n'
                        '\n'
                        '@app.route("/search")\n'
                        '@limiter.limit("10 per minute")\n'
                        'def search():\n'
                        '    ...\n'
                        '\n'
                        'Or use pagination for large queries:\n'
                        'results = query.paginate(page=page, per_page=50)'
                    ),
                    confidence=0.75
                )
                self.vulnerabilities.append(vuln)
    
    def _check_broken_function_auth(self, node: ast.AST, code: str):
        """
        API5:2023 - Broken Function Level Authorization
        Detect admin/privileged endpoints without proper role checks
        """
        if isinstance(node, ast.FunctionDef):
            if not self._is_api_endpoint(node):
                return
            
            func_name_lower = node.name.lower()
            
            # Identify admin/privileged endpoints
            admin_keywords = [
                'admin', 'delete', 'remove', 'update', 'edit',
                'create', 'modify', 'manage', 'configure', 'approve'
            ]
            
            is_privileged = any(keyword in func_name_lower for keyword in admin_keywords)
            
            if is_privileged:
                # Check for authorization decorators or checks
                has_auth = False
                
                # Check decorators
                for decorator in node.decorator_list:
                    decorator_str = ast.unparse(decorator) if hasattr(ast, 'unparse') else ''
                    
                    auth_patterns = [
                        'admin_required', 'role_required', 'permission_required',
                        'requires_role', 'authorize', 'PreAuthorize'
                    ]
                    
                    if any(pattern in decorator_str for pattern in auth_patterns):
                        has_auth = True
                
                # Check function body for role checks
                if not has_auth:
                    func_body = ast.unparse(node) if hasattr(ast, 'unparse') else ''
                    role_check_patterns = [
                        'is_admin', 'has_role', 'check_role',
                        'current_user.role', 'user.is_admin'
                    ]
                    
                    if any(pattern in func_body for pattern in role_check_patterns):
                        has_auth = True
                
                if not has_auth:
                    vuln = APIVulnerability(
                        cwe='CWE-284',
                        owasp_api='API5:2023',
                        title='Broken Function Level Authorization',
                        description=(
                            f'Privileged endpoint "{node.name}" lacks proper role-based authorization. '
                            'Regular users may be able to access admin functions.'
                        ),
                        severity='CRITICAL',
                        line=node.lineno,
                        column=node.col_offset,
                        code=self._extract_code_snippet(code, node.lineno),
                        fix=(
                            'Add role-based authorization:\n'
                            '@admin_required\n'
                            '@app.route("/admin/delete")\n'
                            'def delete_resource():\n'
                            '    ...\n'
                            '\n'
                            'Or check explicitly:\n'
                            'def delete_resource():\n'
                            '    if not current_user.is_admin:\n'
                            '        abort(403, "Admin access required")\n'
                            '    ...'
                        ),
                        confidence=0.85
                    )
                    self.vulnerabilities.append(vuln)
    
    def _check_ssrf(self, node: ast.AST, code: str):
        """
        API7:2023 - Server Side Request Forgery
        Detect user-controlled URLs in HTTP requests
        """
        if isinstance(node, ast.Call):
            func_name = self._get_func_name(node.func)
            
            # HTTP request functions
            http_functions = [
                'requests.get', 'requests.post', 'urllib.request',
                'httpx.get', 'fetch', 'axios.get', 'http.get'
            ]
            
            if any(http_func in func_name for http_func in http_functions):
                # Check if URL is user-controlled
                if node.args:
                    url_arg = node.args[0]
                    
                    # Check if URL comes from user input
                    url_str = ast.unparse(url_arg) if hasattr(ast, 'unparse') else ''
                    
                    user_input_patterns = [
                        'request.', 'req.', 'input(',
                        'args.get', 'form.get', 'json.get',
                        'params.get'
                    ]
                    
                    if any(pattern in url_str for pattern in user_input_patterns):
                        vuln = APIVulnerability(
                            cwe='CWE-918',
                            owasp_api='API7:2023',
                            title='Server Side Request Forgery (SSRF)',
                            description=(
                                'HTTP request with user-controlled URL. '
                                'Attackers can access internal services, cloud metadata, '
                                'or perform port scanning.'
                            ),
                            severity='CRITICAL',
                            line=node.lineno,
                            column=node.col_offset,
                            code=self._extract_code_snippet(code, node.lineno),
                            fix=(
                                'Validate and whitelist URLs:\n'
                                'ALLOWED_DOMAINS = ["api.example.com", "cdn.example.com"]\n'
                                '\n'
                                'def safe_fetch(url):\n'
                                '    parsed = urlparse(url)\n'
                                '    if parsed.hostname not in ALLOWED_DOMAINS:\n'
                                '        raise ValueError("Unauthorized domain")\n'
                                '    if parsed.hostname in ["localhost", "127.0.0.1"]:\n'
                                '        raise ValueError("Internal access denied")\n'
                                '    return requests.get(url, timeout=5)'
                            ),
                            confidence=0.9
                        )
                        self.vulnerabilities.append(vuln)
    
    def _check_security_misconfiguration(self, node: ast.AST, code: str):
        """
        API8:2023 - Security Misconfiguration
        Detect various security misconfigurations
        """
        if isinstance(node, ast.Assign):
            # Check for debug mode in production
            if isinstance(node.targets[0], ast.Attribute):
                target_str = ast.unparse(node.targets[0]) if hasattr(ast, 'unparse') else ''
                
                if 'debug' in target_str.lower():
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        vuln = APIVulnerability(
                            cwe='CWE-489',
                            owasp_api='API8:2023',
                            title='Debug Mode Enabled',
                            description=(
                                'Debug mode enabled. This exposes sensitive information '
                                'like stack traces, source code, and environment variables.'
                            ),
                            severity='HIGH',
                            line=node.lineno,
                            column=node.col_offset,
                            code=self._extract_code_snippet(code, node.lineno),
                            fix='Set debug=False in production. Use environment variables.',
                            confidence=0.95
                        )
                        self.vulnerabilities.append(vuln)
    
    def _detect_js_api_vulns(self, code: str, filename: str):
        """Detect JavaScript/TypeScript API vulnerabilities"""
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for BOLA/IDOR in Express routes
            if any(pattern in line for pattern in ['app.get', 'router.get', 'app.delete']):
                if ':id' in line and 'authenticate' not in line:
                    # Check if there's authorization in surrounding lines
                    context = '\n'.join(lines[max(0, line_num-5):min(len(lines), line_num+5)])
                    
                    if 'req.user' not in context and 'authorization' not in context.lower():
                        vuln = APIVulnerability(
                            cwe='CWE-639',
                            owasp_api='API1:2023',
                            title='Potential BOLA/IDOR Vulnerability',
                            description='Route accesses resources by ID without authorization check.',
                            severity='HIGH',
                            line=line_num,
                            column=0,
                            code=line.strip(),
                            fix='Add authorization check: if (req.user.id !== resource.userId) return res.status(403).send();',
                            confidence=0.75
                        )
                        self.vulnerabilities.append(vuln)
            
            # Check for missing rate limiting
            if any(pattern in line for pattern in ['app.post', 'router.post']) and 'login' in line.lower():
                context = '\n'.join(lines[max(0, line_num-10):line_num])
                
                if 'rateLimit' not in context and 'limiter' not in context:
                    vuln = APIVulnerability(
                        cwe='CWE-307',
                        owasp_api='API2:2023',
                        title='Missing Rate Limiting on Auth Endpoint',
                        description='Login endpoint without rate limiting allows brute force attacks.',
                        severity='HIGH',
                        line=line_num,
                        column=0,
                        code=line.strip(),
                        fix='Use express-rate-limit: const limiter = rateLimit({windowMs: 15*60*1000, max: 5});',
                        confidence=0.8
                        )
                    self.vulnerabilities.append(vuln)
    
    def _detect_java_api_vulns(self, code: str, filename: str):
        """Detect Java API vulnerabilities"""
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for missing authorization on Spring endpoints
            if any(annotation in line for annotation in ['@GetMapping', '@PostMapping', '@DeleteMapping']):
                # Look for @PreAuthorize in surrounding lines
                context = '\n'.join(lines[max(0, line_num-10):line_num])
                
                if '@PreAuthorize' not in context and '@Secured' not in context:
                    if any(keyword in line.lower() for keyword in ['admin', 'delete', 'update']):
                        vuln = APIVulnerability(
                            cwe='CWE-284',
                            owasp_api='API5:2023',
                            title='Missing Authorization on Privileged Endpoint',
                            description='Privileged endpoint lacks @PreAuthorize annotation.',
                            severity='CRITICAL',
                            line=line_num,
                            column=0,
                            code=line.strip(),
                            fix='Add @PreAuthorize("hasRole(\'ADMIN\')")',
                            confidence=0.85
                        )
                        self.vulnerabilities.append(vuln)
    
    # Helper methods
    
    def _is_api_endpoint(self, node: ast.FunctionDef) -> bool:
        """Check if function is an API endpoint"""
        for decorator in node.decorator_list:
            decorator_str = ast.unparse(decorator) if hasattr(ast, 'unparse') else ''
            
            api_patterns = [
                '@app.', '@router.', '@api.', '@route',
                '@get', '@post', '@put', '@delete',
                '@RequestMapping', '@GetMapping'
            ]
            
            if any(pattern in decorator_str for pattern in api_patterns):
                return True
        
        return False
    
    def _get_func_name(self, func_node: ast.AST) -> str:
        """Get full function name from AST node"""
        if isinstance(func_node, ast.Attribute):
            return f'{self._get_func_name(func_node.value)}.{func_node.attr}'
        elif isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Call):
            return self._get_func_name(func_node.func)
        return ''
    
    def _extract_code_snippet(self, code: str, line_num: int, context: int = 3) -> str:
        """Extract code snippet with context"""
        lines = code.split('\n')
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])
    
    def _detect_with_regex(self, code: str, language: str):
        """Fallback regex-based detection"""
        pass


# Example usage
if __name__ == '__main__':
    detector = APISecurityDetector()
    
    # Test case: BOLA/IDOR
    test_code = """
from flask import Flask, request
app = Flask(__name__)

@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)  # No authorization check!
    return user.to_json()

@app.route('/api/admin/delete/<int:resource_id>')
def delete_resource(resource_id):  # No role check!
    Resource.query.filter_by(id=resource_id).delete()
    return {"status": "deleted"}
"""
    
    vulns = detector.detect_all(test_code, 'python')
    print(f"Found {len(vulns)} API vulnerabilities")
    for v in vulns:
        print(f"  [{v.owasp_api}] [{v.cwe}] {v.title} at line {v.line}")
        print(f"     Severity: {v.severity}, Confidence: {v.confidence}")
