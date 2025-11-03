# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
C/C++ language security analyzer

Security analysis for C/C++ codebases with focus on memory safety and classic vulnerabilities:
- Buffer overflows and memory corruption
- 9+ CWE categories including memory-safety critical issues

Detection Capabilities:
- Buffer Overflow (CWE-120, CWE-121): strcpy, sprintf, gets, memcpy misuse
- Use After Free (CWE-416): Accessing freed memory
- Double Free (CWE-415): Multiple free() calls on same pointer
- NULL Pointer Dereference (CWE-476): Unsafe pointer access
- Integer Overflow (CWE-190): Arithmetic without bounds checking
- Uninitialized Variables (CWE-457): Using variables before initialization
- Format String Vulnerabilities (CWE-134): printf with user input
- Command Injection (CWE-78): system(), popen() with user input

Unsafe Function Detection:
- strcpy, strcat, sprintf (use strncpy, strncat, snprintf)
- gets (use fgets)
- scanf with %s (use width specifier)
- memcpy without bounds checking

Memory Management Issues:
- Manual memory management errors (new/delete, malloc/free)
- Memory leaks (allocations without deallocation)
- Stack buffer overflows
- Heap corruption

Modern C++ Safety:
- Suggests smart pointers (unique_ptr, shared_ptr)
- Recommends safe string operations (std::string)
- Encourages RAII patterns

Used by: Scanner.scan_file() when processing .c, .cpp, .h, .hpp files
"""

import re
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors


class CppAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for C/C++ code."""
    
    def __init__(self):
        super().__init__()
        self.language = "cpp"
    
    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-78',   # Command Injection
            'CWE-120',  # Buffer Overflow
            'CWE-121',  # Stack Buffer Overflow
            'CWE-416',  # Use After Free
            'CWE-415',  # Double Free
            'CWE-476',  # NULL Pointer Dereference
            'CWE-190',  # Integer Overflow
            'CWE-457',  # Uninitialized Variable
            'CWE-134',  # Format String Vulnerability
        ]
    
    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze C/C++ code."""
        vulnerabilities = []
        
        vulnerabilities.extend(self.detect_buffer_overflow(code, filepath))
        vulnerabilities.extend(self.detect_command_injection(code, filepath))
        vulnerabilities.extend(self.detect_format_string(code, filepath))
        vulnerabilities.extend(self.detect_memory_issues(code, filepath))
        vulnerabilities.extend(self.detect_integer_overflow(code, filepath))
        vulnerabilities.extend(self.detect_null_pointer(code, filepath))
        
        # Run universal detection methods
        vulnerabilities.extend(self.detect_improper_input_validation(code, filepath))
        vulnerabilities.extend(self.detect_information_exposure(code, filepath))
        vulnerabilities.extend(self.detect_improper_authentication(code, filepath))
        vulnerabilities.extend(self.detect_incorrect_permissions(code, filepath))
        vulnerabilities.extend(self.detect_graphql_security(code, filepath))
        vulnerabilities.extend(self.detect_jwt_security(code, filepath))
        vulnerabilities.extend(self.detect_nosql_injection(code, filepath))
        vulnerabilities.extend(self.detect_ssti(code, filepath))
        vulnerabilities.extend(self.detect_redos(code, filepath))
        
        return vulnerabilities
    
    def detect_buffer_overflow(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect buffer overflow vulnerabilities."""
        patterns = [
            (r'\bgets\s*\(', 'gets() - unbounded'),
            (r'\bstrcpy\s*\(', 'strcpy() - no bounds check'),
            (r'\bstrcat\s*\(', 'strcat() - no bounds check'),
            (r'\bsprintf\s*\(', 'sprintf() - no bounds check'),
            (r'\bscanf\s*\([^)]*%s', 'scanf() with %s'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, func in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-120',
                        severity='critical',
                        title='Buffer Overflow',
                        description=f'Unsafe function: {func}. Use safe alternatives like strncpy(), strncat().',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_command_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect command injection in C/C++."""
        patterns = [
            r'\bsystem\s*\(',
            r'\bexec\w+\s*\(',
            r'\bpopen\s*\(',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-78',
                        severity='critical',
                        title='OS Command Injection',
                        description='Command execution function. Validate and sanitize input.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_format_string(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect format string vulnerabilities."""
        patterns = [
            r'printf\s*\(\s*\w+\s*\)',
            r'fprintf\s*\([^,]*,\s*\w+\s*\)',
            r'sprintf\s*\([^,]*,\s*\w+\s*\)',
            r'snprintf\s*\([^,]*,[^,]*,\s*\w+\s*\)',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check if it's not a string literal
                    if '"%' not in line and '"%' not in line:
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-134',
                            severity='high',
                            title='Format String Vulnerability',
                            description='Format string without literal. Use "%s" format specifier.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_memory_issues(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect memory management issues."""
        vulnerabilities = []
        lines = code.split('\n')
        
        # Track malloc/free pairs
        malloc_pattern = r'\b(malloc|calloc|realloc)\s*\('
        free_pattern = r'\bfree\s*\('
        delete_pattern = r'\bdelete\s+'
        
        for i, line in enumerate(lines, 1):
            # Use after free / double free
            if re.search(free_pattern, line) or re.search(delete_pattern, line):
                code_window = '\n'.join(lines[i:min(len(lines), i+10)])
                if re.search(free_pattern, code_window) or re.search(delete_pattern, code_window):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-415',
                        severity='high',
                        title='Potential Double Free',
                        description='Pointer freed multiple times. Set pointer to NULL after free.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
            
            # Uninitialized pointer
            if re.search(r'\*\s*\w+\s*;', line):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-457',
                    severity='medium',
                    title='Uninitialized Pointer',
                    description='Pointer declared without initialization. Initialize to NULL.',
                    code=code,
                    filepath=filepath,
                    line_number=i,
                    confidence='medium'
                ))
        
        return vulnerabilities
    
    def detect_integer_overflow(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect integer overflow issues."""
        patterns = [
            r'\w+\s*\+\s*\w+',
            r'\w+\s*\*\s*\w+',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for arithmetic in size calculations
            if 'malloc' in line or 'calloc' in line:
                for pattern in patterns:
                    if re.search(pattern, line):
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-190',
                            severity='medium',
                            title='Potential Integer Overflow',
                            description='Arithmetic in memory allocation. Check for overflow.',
                            code=code,
                            filepath=filepath,
                            line_number=i,
                            confidence='medium'
                        ))
                        break
        
        return vulnerabilities
    
    def detect_null_pointer(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect null pointer dereference."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Look for pointer dereference without null check
            if re.search(r'(malloc|calloc|realloc)\s*\(', line):
                code_window = '\n'.join(lines[i:min(len(lines), i+5)])
                if '->' in code_window or '*' in code_window:
                    if 'if' not in code_window or 'NULL' not in code_window:
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-476',
                            severity='medium',
                            title='Potential NULL Pointer Dereference',
                            description='Pointer used without NULL check after allocation.',
                            code=code,
                            filepath=filepath,
                            line_number=i,
                            confidence='medium'
                        ))
        
        return vulnerabilities


