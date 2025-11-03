"""
Missing Critical CWE Detectors
Implements detectors for MITRE CWE Top 25 2024 gaps
"""
from typing import List, Dict, Any
import re


class MissingCriticalCWEDetector:
    """Detects critical CWEs that were missing from Parry's coverage"""
    
    def detect_all(self, code: str, language: str, filepath: str) -> List[Dict[str, Any]]:
        """Run all missing critical CWE detectors"""
        vulnerabilities = []
        
        # CWE-787: Out-of-bounds Write
        vulnerabilities.extend(self.detect_cwe_787(code, language, filepath))
        
        # CWE-125: Out-of-bounds Read
        vulnerabilities.extend(self.detect_cwe_125(code, language, filepath))
        
        # CWE-77: Command Injection (Improper Neutralization)
        vulnerabilities.extend(self.detect_cwe_77(code, language, filepath))
        
        # CWE-269: Improper Privilege Management
        vulnerabilities.extend(self.detect_cwe_269(code, language, filepath))
        
        # CWE-863: Incorrect Authorization
        vulnerabilities.extend(self.detect_cwe_863(code, language, filepath))
        
        # CWE-276: Incorrect Default Permissions
        vulnerabilities.extend(self.detect_cwe_276(code, language, filepath))
        
        return vulnerabilities
    
    def detect_cwe_787(self, code: str, language: str, filepath: str) -> List[Dict[str, Any]]:
        """
        CWE-787: Out-of-bounds Write
        Detect unsafe array/buffer writes without bounds checking
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # C/C++ patterns
        if language in ['c', 'cpp', 'c++']:
            patterns = [
                # strcpy without bounds check
                r'strcpy\s*\(',
                # sprintf without bounds check
                r'sprintf\s*\(',
                # gets() is inherently unsafe
                r'\bgets\s*\(',
                # memcpy without size validation
                r'memcpy\s*\([^)]*\b(len|size|count)\b[^)]*\)',
                # Array indexing without bounds check
                r'\w+\s*\[\s*\w+\s*\]\s*=',
            ]
            
            for i, line in enumerate(lines):
                for pattern in patterns:
                    if re.search(pattern, line):
                        vulnerabilities.append({
                            'type': 'Out-of-bounds Write',
                            'cwe': 'CWE-787',
                            'severity': 'CRITICAL',
                            'line': i + 1,
                            'code': line.strip(),
                            'filepath': filepath,
                            'description': 'Potential out-of-bounds write detected. This can lead to buffer overflow and remote code execution.',
                            'recommendation': 'Use bounds-checked functions like strncpy(), snprintf(), or fgets(). Always validate array indices.'
                        })
                        break
        
        # Python: list/array index assignments without bounds check
        elif language == 'python':
            for i, line in enumerate(lines):
                # arr[index] = value without bounds check
                if re.search(r'\w+\s*\[\s*\w+\s*\]\s*=', line):
                    # Check if there's no bounds validation nearby
                    context_start = max(0, i - 3)
                    context = '\n'.join(lines[context_start:i+1])
                    if not re.search(r'(if|assert|check|validate).*(len|length|size|bounds)', context, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Potential Out-of-bounds Write',
                            'cwe': 'CWE-787',
                            'severity': 'HIGH',
                            'line': i + 1,
                            'code': line.strip(),
                            'filepath': filepath,
                            'description': 'Array index assignment without visible bounds checking.',
                            'recommendation': 'Always validate array indices before writing: if 0 <= index < len(arr): arr[index] = value'
                        })
        
        # Java: array assignments
        elif language == 'java':
            for i, line in enumerate(lines):
                if re.search(r'\w+\s*\[\s*\w+\s*\]\s*=', line):
                    vulnerabilities.append({
                        'type': 'Potential Out-of-bounds Write',
                        'cwe': 'CWE-787',
                        'severity': 'HIGH',
                        'line': i + 1,
                        'code': line.strip(),
                        'filepath': filepath,
                        'description': 'Array index assignment without visible bounds checking.',
                        'recommendation': 'Java throws ArrayIndexOutOfBoundsException, but explicit checks improve security.'
                    })
        
        return vulnerabilities
    
    def detect_cwe_125(self, code: str, language: str, filepath: str) -> List[Dict[str, Any]]:
        """
        CWE-125: Out-of-bounds Read
        Detect unsafe array/buffer reads without bounds checking
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # C/C++ patterns
        if language in ['c', 'cpp', 'c++']:
            patterns = [
                # Array read without bounds check
                r'=\s*\w+\s*\[\s*\w+\s*\]',
                # Pointer arithmetic
                r'\*\s*\(\s*\w+\s*\+\s*\w+\s*\)',
            ]
            
            for i, line in enumerate(lines):
                for pattern in patterns:
                    if re.search(pattern, line):
                        context_start = max(0, i - 3)
                        context = '\n'.join(lines[context_start:i+1])
                        if not re.search(r'(if|assert|check).*(len|length|size|bounds)', context, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'Out-of-bounds Read',
                                'cwe': 'CWE-125',
                                'severity': 'HIGH',
                                'line': i + 1,
                                'code': line.strip(),
                                'filepath': filepath,
                                'description': 'Potential out-of-bounds read. Can leak sensitive memory contents.',
                                'recommendation': 'Validate array indices before reading. Check: if (index >= 0 && index < size)'
                            })
                            break
        
        # Python: list access without bounds check
        elif language == 'python':
            for i, line in enumerate(lines):
                if re.search(r'=\s*\w+\s*\[\s*\w+\s*\]', line) and 'dict' not in line.lower():
                    context_start = max(0, i - 3)
                    context = '\n'.join(lines[context_start:i+1])
                    if not re.search(r'(if|assert|try|except|check).*(len|length|size|bounds|IndexError)', context, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Potential Out-of-bounds Read',
                            'cwe': 'CWE-125',
                            'severity': 'MEDIUM',
                            'line': i + 1,
                            'code': line.strip(),
                            'filepath': filepath,
                            'description': 'Array access without visible bounds checking or exception handling.',
                            'recommendation': 'Validate indices: if 0 <= index < len(arr): value = arr[index], or use try/except IndexError'
                        })
        
        return vulnerabilities
    
    def detect_cwe_77(self, code: str, language: str, filepath: str) -> List[Dict[str, Any]]:
        """
        CWE-77: Improper Neutralization of Special Elements used in a Command
        Similar to CWE-78 but focuses on command separators and special characters
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # Shell metacharacters and command separators
        dangerous_chars = [';', '|', '&', '$', '`', '>', '<', '\n', '\\']
        
        for i, line in enumerate(lines):
            # Python: subprocess, os.system with user input
            if language == 'python':
                if re.search(r'(subprocess|os\.system|os\.popen|commands\.getoutput|popen)', line):
                    # Check if user input is involved
                    context_start = max(0, i - 5)
                    context = '\n'.join(lines[context_start:i+2])
                    
                    user_input_patterns = [
                        r'input\s*\(',
                        r'request\.',
                        r'request\[',
                        r'argv\[',
                        r'sys\.argv',
                        r'params\[',
                        r'args\.',
                    ]
                    
                    has_user_input = any(re.search(p, context) for p in user_input_patterns)
                    has_sanitization = re.search(r'(shlex\.quote|pipes\.quote|sanitize|escape|whitelist)', context)
                    
                    if has_user_input and not has_sanitization:
                        vulnerabilities.append({
                            'type': 'Command Injection via Special Elements',
                            'cwe': 'CWE-77',
                            'severity': 'CRITICAL',
                            'line': i + 1,
                            'code': line.strip(),
                            'filepath': filepath,
                            'description': 'User input in command execution without neutralizing shell metacharacters (;|&$`>< etc).',
                            'recommendation': 'Use shlex.quote() to escape shell metacharacters, or use subprocess with shell=False and argument lists.'
                        })
            
            # JavaScript/Node.js
            elif language == 'javascript':
                if re.search(r'(child_process\.exec|child_process\.spawn|shell\.exec)', line):
                    context_start = max(0, i - 5)
                    context = '\n'.join(lines[context_start:i+2])
                    
                    if re.search(r'(req\.|request\.|params\.|query\.|body\.)', context):
                        vulnerabilities.append({
                            'type': 'Command Injection via Special Elements',
                            'cwe': 'CWE-77',
                            'severity': 'CRITICAL',
                            'line': i + 1,
                            'code': line.strip(),
                            'filepath': filepath,
                            'description': 'User input in command execution without sanitizing shell metacharacters.',
                            'recommendation': 'Use child_process.execFile() or spawn() with argument arrays instead of shell commands.'
                        })
        
        return vulnerabilities
    
    def detect_cwe_269(self, code: str, language: str, filepath: str) -> List[Dict[str, Any]]:
        """
        CWE-269: Improper Privilege Management
        Detect privilege escalation risks and improper privilege handling
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        privilege_patterns = {
            'python': [
                (r'os\.setuid\s*\(\s*0\s*\)', 'Setting UID to root (0) - privilege escalation risk'),
                (r'os\.seteuid\s*\(\s*0\s*\)', 'Setting effective UID to root'),
                (r'os\.setgid\s*\(\s*0\s*\)', 'Setting GID to root'),
                (r'import\s+ctypes.*CDLL.*sudo', 'Loading native libraries with elevated privileges'),
                (r'subprocess.*sudo', 'Executing commands with sudo'),
            ],
            'javascript': [
                (r'process\.setuid\s*\(\s*0\s*\)', 'Setting UID to root in Node.js'),
                (r'process\.setgid\s*\(\s*0\s*\)', 'Setting GID to root in Node.js'),
                (r'child_process.*sudo', 'Executing sudo commands'),
            ],
            'java': [
                (r'System\.setProperty\s*\(\s*["\']java\.security\.policy', 'Modifying security policy at runtime'),
                (r'AccessController\.doPrivileged', 'Using privileged blocks - review for necessity'),
                (r'Runtime\.getRuntime\(\)\.exec\s*\(.*sudo', 'Executing sudo commands'),
            ],
            'go': [
                (r'syscall\.Setuid\s*\(\s*0\s*\)', 'Setting UID to root'),
                (r'syscall\.Setgid\s*\(\s*0\s*\)', 'Setting GID to root'),
                (r'exec\.Command\s*\(.*sudo', 'Executing sudo commands'),
            ],
        }
        
        if language in privilege_patterns:
            for i, line in enumerate(lines):
                for pattern, description in privilege_patterns[language]:
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Improper Privilege Management',
                            'cwe': 'CWE-269',
                            'severity': 'CRITICAL',
                            'line': i + 1,
                            'code': line.strip(),
                            'filepath': filepath,
                            'description': f'{description}. Improper privilege management can lead to privilege escalation.',
                            'recommendation': 'Minimize privilege usage. Drop privileges immediately after use. Use principle of least privilege.'
                        })
        
        # Check for running as root without dropping privileges
        if language in ['python', 'bash', 'shell']:
            for i, line in enumerate(lines):
                if re.search(r'if\s+.*getuid.*==\s*0', line) or re.search(r'os\.getuid\s*\(\s*\)\s*==\s*0', line):
                    # Check if privileges are dropped in next few lines
                    context = '\n'.join(lines[i:min(i+10, len(lines))])
                    if not re.search(r'(setuid|seteuid|drop.*priv|lower.*priv)', context, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Running as Root Without Dropping Privileges',
                            'cwe': 'CWE-269',
                            'severity': 'HIGH',
                            'line': i + 1,
                            'code': line.strip(),
                            'filepath': filepath,
                            'description': 'Code detects running as root but does not drop privileges.',
                            'recommendation': 'Drop privileges immediately: os.setuid(non_root_uid) after initialization.'
                        })
        
        return vulnerabilities
    
    def detect_cwe_863(self, code: str, language: str, filepath: str) -> List[Dict[str, Any]]:
        """
        CWE-863: Incorrect Authorization
        Detect missing or incorrect authorization checks
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # Sensitive operations that require authorization
        sensitive_operations = {
            'python': [
                r'@app\.route.*delete',
                r'@app\.route.*update',
                r'@app\.route.*admin',
                r'def\s+delete_\w+',
                r'def\s+update_\w+',
                r'def\s+admin_\w+',
                r'\.delete\s*\(',
                r'\.update\s*\(',
            ],
            'javascript': [
                r'router\.(delete|put|patch)',
                r'app\.(delete|put|patch)',
                r'function\s+(delete|update|admin)',
                r'const\s+(delete|update|admin)\w*\s*=',
            ],
            'java': [
                r'@(Delete|Put|Patch)Mapping',
                r'@RequestMapping.*method\s*=\s*RequestMethod\.(DELETE|PUT|PATCH)',
                r'public\s+.*delete\w*\s*\(',
                r'public\s+.*update\w*\s*\(',
            ],
        }
        
        authorization_keywords = [
            'authorize', 'permission', 'role', 'access_control', 'check_auth',
            '@require', '@login_required', '@permission_required', 'hasRole',
            'hasPermission', 'checkPermission', 'isAuthorized', '@PreAuthorize',
            '@Secured', 'authorize', 'can?', 'authorize!', 'policy'
        ]
        
        if language in sensitive_operations:
            for i, line in enumerate(lines):
                for pattern in sensitive_operations[language]:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check surrounding context for authorization
                        context_start = max(0, i - 5)
                        context_end = min(len(lines), i + 15)
                        context = '\n'.join(lines[context_start:context_end])
                        
                        has_authorization = any(keyword in context.lower() for keyword in authorization_keywords)
                        
                        if not has_authorization:
                            vulnerabilities.append({
                                'type': 'Missing Authorization Check',
                                'cwe': 'CWE-863',
                                'severity': 'CRITICAL',
                                'line': i + 1,
                                'code': line.strip(),
                                'filepath': filepath,
                                'description': 'Sensitive operation (delete/update/admin) without visible authorization check.',
                                'recommendation': 'Add authorization check: verify user has permission to perform this action. Use @require_permission or similar decorators.'
                            })
        
        # Check for IDOR patterns (changing resource ID without ownership check)
        for i, line in enumerate(lines):
            if re.search(r'(\.get|\.find|\.filter|\.query).*\(.*\bid\b.*\)', line):
                context_start = max(0, i - 3)
                context_end = min(len(lines), i + 10)
                context = '\n'.join(lines[context_start:context_end])
                
                # Check for ownership validation
                ownership_check = re.search(r'(user_id|owner|belongs_to|created_by|check_owner)', context, re.IGNORECASE)
                
                if not ownership_check and ('request' in context or 'param' in context or 'arg' in context):
                    vulnerabilities.append({
                        'type': 'Potential IDOR - Missing Ownership Check',
                        'cwe': 'CWE-863',
                        'severity': 'HIGH',
                        'line': i + 1,
                        'code': line.strip(),
                        'filepath': filepath,
                        'description': 'Resource accessed by ID without ownership validation. User could access others\' resources.',
                        'recommendation': 'Verify ownership: check if current_user owns the resource before returning it.'
                    })
        
        return vulnerabilities
    
    def detect_cwe_276(self, code: str, language: str, filepath: str) -> List[Dict[str, Any]]:
        """
        CWE-276: Incorrect Default Permissions
        Detect overly permissive file/directory permissions
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # Dangerous permission patterns
        permission_patterns = {
            'python': [
                (r'os\.chmod.*0o777', '777 permissions - world-writable'),
                (r'os\.chmod.*0o666', '666 permissions - world-writable file'),
                (r'os\.chmod.*511', '777 in decimal'),
                (r'os\.makedirs.*mode\s*=\s*0o777', 'Creating directory with 777'),
                (r'open\(.*mode\s*=\s*["\']w\+["\'].*\)', 'Opening file in w+ mode without permission specification'),
            ],
            'bash': [
                (r'chmod\s+777', '777 permissions'),
                (r'chmod\s+-R\s+777', 'Recursive 777 permissions'),
                (r'umask\s+000', 'umask 000 - no restrictions'),
            ],
            'javascript': [
                (r'fs\.chmod.*0o777', '777 permissions'),
                (r'fs\.writeFile.*mode:\s*0o777', 'Creating file with 777'),
            ],
            'java': [
                (r'Files\.setPosixFilePermissions.*ALL', 'Setting all permissions'),
                (r'PosixFilePermission\.OTHERS_WRITE', 'Granting write permission to others'),
            ],
        }
        
        if language in permission_patterns:
            for i, line in enumerate(lines):
                for pattern, description in permission_patterns[language]:
                    if re.search(pattern, line):
                        vulnerabilities.append({
                            'type': 'Incorrect Default Permissions',
                            'cwe': 'CWE-276',
                            'severity': 'HIGH',
                            'line': i + 1,
                            'code': line.strip(),
                            'filepath': filepath,
                            'description': f'{description}. Overly permissive permissions allow unauthorized access.',
                            'recommendation': 'Use restrictive permissions: 644 for files (rw-r--r--), 755 for directories (rwxr-xr-x). Never use 777.'
                        })
        
        # Dockerfile: Running as root
        if filepath.lower().endswith('dockerfile') or 'dockerfile' in filepath.lower():
            for i, line in enumerate(lines):
                if not re.search(r'^\s*USER\s+', line, re.IGNORECASE):
                    if re.search(r'^\s*(RUN|CMD|ENTRYPOINT)', line, re.IGNORECASE):
                        # Check if USER directive appears before this
                        previous_context = '\n'.join(lines[:i])
                        if not re.search(r'USER\s+\w+', previous_context, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'Container Running as Root',
                                'cwe': 'CWE-276',
                                'severity': 'HIGH',
                                'line': i + 1,
                                'code': line.strip(),
                                'filepath': filepath,
                                'description': 'Container command executing as root. Default permissions are too permissive.',
                                'recommendation': 'Add USER directive before RUN/CMD/ENTRYPOINT: USER nonroot'
                            })
                            break
        
        return vulnerabilities


# Singleton instance
missing_cwe_detector = MissingCriticalCWEDetector()


def detect_missing_critical_cwes(code: str, language: str, filepath: str) -> List[Dict[str, Any]]:
    """
    Main entry point for detecting missing critical CWEs
    
    Args:
        code: Source code to analyze
        language: Programming language
        filepath: Path to the file being analyzed
    
    Returns:
        List of vulnerability dictionaries
    """
    return missing_cwe_detector.detect_all(code, language, filepath)
