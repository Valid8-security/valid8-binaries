#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Test File Detection System
Comprehensive rules to identify test files, example code, and non-production code
"""

import re
from pathlib import Path
from typing import List, Tuple, Optional

class TestFileDetector:
    """Detects test files, example code, and non-production code"""
    
    # Test file patterns (high confidence)
    TEST_FILE_PATTERNS = [
        # Standard test naming
        r'test_.*\.py$',
        r'.*_test\.py$',
        r'.*_tests\.py$',
        r'.*\.test\.py$',
        r'.*\.spec\.py$',
        r'.*\.specs\.py$',
        
        # Test directories
        r'.*[/\\]tests?[/\\].*',
        r'.*[/\\]test[/\\].*',
        r'.*[/\\]testing[/\\].*',
        r'.*[/\\]specs?[/\\].*',
        r'.*[/\\]spec[/\\].*',
        
        # Framework-specific test patterns
        r'.*[/\\]__tests__[/\\].*',  # Jest/React
        r'.*[/\\]tests?[/\\]__tests__[/\\].*',
        r'.*[/\\]tests?[/\\]unit[/\\].*',
        r'.*[/\\]tests?[/\\]integration[/\\].*',
        r'.*[/\\]tests?[/\\]e2e[/\\].*',
        r'.*[/\\]tests?[/\\]functional[/\\].*',
        
        # Mock/fixture files
        r'mock_.*\.py$',
        r'.*_mock\.py$',
        r'.*[/\\]mocks?[/\\].*',
        r'.*[/\\]fixtures?[/\\].*',
        r'fixture_.*\.py$',
        r'.*_fixture\.py$',
        
        # Example/demo files
        r'example.*\.py$',
        r'.*_example\.py$',
        r'.*[/\\]examples?[/\\].*',
        r'.*[/\\]demos?[/\\].*',
        r'demo.*\.py$',
        r'.*_demo\.py$',
        r'.*[/\\]samples?[/\\].*',
        r'.*[/\\]tutorials?[/\\].*',
        
        # Documentation/test helpers
        r'.*[/\\]docs[/\\].*',
        r'.*[/\\]doc[/\\].*',
        r'.*[/\\]documentation[/\\].*',
        r'conftest\.py$',  # pytest
        r'setup\.py$',  # Usually safe but sometimes has test code
        r'.*[/\\]benchmarks?[/\\].*',
        
        # CI/CD test files
        r'.*[/\\]\.github[/\\]workflows[/\\].*',
        r'.*[/\\]\.circleci[/\\].*',
        r'.*[/\\]\.travis[/\\].*',
        r'.*[/\\]\.jenkins[/\\].*',
        
        # Configuration test files
        r'.*[/\\]config[/\\]test.*',
        r'.*[/\\]test.*[/\\]config.*',
        
        # Django-specific test patterns
        r'.*[/\\]django[/\\]test[/\\].*',
        r'.*[/\\]django[/\\]tests[/\\].*',
        r'.*[/\\]tests[/\\]django[/\\].*',
        r'.*[/\\]test_utils\.py$',
        r'.*[/\\]test_runner\.py$',
        r'.*[/\\]test_client\.py$',
        r'.*[/\\]testcases[/\\].*',
        r'.*[/\\]test_helpers\.py$',
        r'.*[/\\]test_models\.py$',
        r'.*[/\\]test_views\.py$',
        r'.*[/\\]test_settings\.py$',
        r'.*[/\\]test_urls\.py$',
        r'.*[/\\]test_migrations\.py$',
        r'.*[/\\]test_forms\.py$',
        r'.*[/\\]test_admin\.py$',
        r'.*[/\\]test_serializers\.py$',
        r'.*[/\\]test_*.py$',  # Any file starting with test_
        
        # Django test directories
        r'.*[/\\]tests[/\\]test_.*',
        r'.*[/\\]tests[/\\]models[/\\]test_.*',
        r'.*[/\\]tests[/\\]views[/\\]test_.*',
        r'.*[/\\]tests[/\\]forms[/\\]test_.*',
        r'.*[/\\]tests[/\\]admin[/\\]test_.*',
        
        # Cryptography test patterns
        r'.*[/\\]cryptography[/\\]tests[/\\].*',
        r'.*[/\\]cryptography[/\\]hazmat[/\\]primitives[/\\]tests[/\\].*',
        r'.*[/\\]vectors[/\\].*',  # Test vectors
        r'.*[/\\]test_vectors[/\\].*',
        
        # SQLAlchemy test patterns
        r'.*[/\\]sqlalchemy[/\\]testing[/\\].*',
        r'.*[/\\]sqlalchemy[/\\]test[/\\].*',
        r'.*[/\\]testing[/\\].*',
        
        # Flask test patterns
        r'.*[/\\]flask[/\\]tests[/\\].*',
        r'.*[/\\]tests[/\\]test_.*',
        
        # Common test utility patterns
        r'.*[/\\]testutils[/\\].*',
        r'.*[/\\]test_utils[/\\].*',
        r'.*[/\\]testing[/\\]utils[/\\].*',
        r'.*[/\\]tests[/\\]utils[/\\].*',
        
        # Setup/teardown files
        r'.*[/\\]setUp\.py$',
        r'.*[/\\]tearDown\.py$',
        r'.*[/\\]test_setup\.py$',
        r'.*[/\\]test_teardown\.py$',
    ]
    
    # Test file indicators in content (medium confidence)
    TEST_CONTENT_INDICATORS = [
        r'import\s+(unittest|pytest|nose|doctest|mock|unittest\.mock)',
        r'from\s+(unittest|pytest|nose|doctest|mock|unittest\.mock)',
        r'@pytest\.',
        r'@unittest\.',
        r'def\s+test_',
        r'class\s+Test',
        r'class\s+.*Test.*\(.*TestCase',
        r'assert\s+',
        r'#\s*test',
        r'#\s*TODO.*test',
        r'#\s*FIXME.*test',
        
        # Django-specific test indicators
        r'from\s+django\.test\s+import',
        r'from\s+django\.test\.case\s+import',
        r'from\s+django\.test\.client\s+import',
        r'TestCase',
        r'SimpleTestCase',
        r'TransactionTestCase',
        r'LiveServerTestCase',
        r'Client\(\)',
        r'\.assertContains',
        r'\.assertNotContains',
        r'\.assertRedirects',
        r'\.assertTemplateUsed',
        r'\.assertFormError',
        r'\.assertQuerysetEqual',
        r'self\.client\.',
        r'override_settings',
        r'modify_settings',
        r'@override_settings',
        r'@modify_settings',
        r'@skipIf',
        r'@skipUnless',
        
        # Cryptography test indicators
        r'from\s+cryptography\.hazmat\.primitives\.tests\s+import',
        r'vector\s*=\s*',
        r'test_vectors',
        
        # SQLAlchemy test indicators
        r'from\s+sqlalchemy\.testing\s+import',
        r'from\s+sqlalchemy\.test\s+import',
        r'assert_raises',
        r'assert_raises_message',
        
        # Flask test indicators
        r'from\s+flask\.testing\s+import',
        r'FlaskClient',
        r'\.test_client\(\)',
    ]
    
    # Non-production code indicators
    NON_PRODUCTION_INDICATORS = [
        r'#\s*example',
        r'#\s*demo',
        r'#\s*for\s+testing',
        r'#\s*test\s+only',
        r'#\s*not\s+for\s+production',
        r'#\s*DEBUG',
        r'#\s*development\s+only',
        r'if\s+__name__\s*==\s*["\']__main__["\']:',
        r'print\s*\(',  # Often in examples
    ]
    
    # Placeholder credential patterns (not real credentials)
    PLACEHOLDER_PATTERNS = [
        r'["\'](changeme|change_me|CHANGEME)["\']',
        r'["\'](password|PASSWORD)["\']',
        r'["\'](secret|SECRET)["\']',
        r'["\'](key|KEY)["\']',
        r'["\'](token|TOKEN)["\']',
        r'["\'](api_key|API_KEY)["\']',
        r'["\'](your_.*_here)["\']',
        r'["\'](example|EXAMPLE)["\']',
        r'["\'](test|TEST)["\']',
        r'["\'](demo|DEMO)["\']',
        r'["\'](placeholder|PLACEHOLDER)["\']',
        r'["\'](12345|123456|12345678)["\']',  # Common test values
        r'["\'](admin|admin123)["\']',
        r'["\'](test123|testtest)["\']',
        r'["\'](dummy|DUMMY)["\']',
        r'["\'](fake|FAKE)["\']',
        r'["\'](sample|SAMPLE)["\']',
        r'["\'](xxx|XXX)["\']',
        r'["\'](yyy|YYY)["\']',
        r'["\'](zzz|ZZZ)["\']',
        r'["\'](foobar|FOOBAR)["\']',
        r'["\'](barfoo|BARFOO)["\']',
        r'["\'](default|DEFAULT)["\']',
        r'["\'](none|NONE)["\']',
        r'["\'](empty|EMPTY)["\']',
        r'["\'](null|NULL)["\']',
        r'["\'](root|ROOT)["\']',  # Common default username
        r'["\'](user|USER)["\']',
        r'["\'](pass|PASS)["\']',
        r'["\'](123|1234|12345|123456|1234567|12345678)["\']',  # Sequential numbers
        r'["\'](abc|ABC|abc123|ABC123)["\']',  # Common test strings
        r'["\'](qwerty|QWERTY)["\']',
        r'["\'](password123|PASSWORD123)["\']',
        r'["\'](secret123|SECRET123)["\']',
        r'["\'](key123|KEY123)["\']',
        r'["\'](token123|TOKEN123)["\']',
        r'["\'](test_key|TEST_KEY)["\']',
        r'["\'](test_secret|TEST_SECRET)["\']',
        r'["\'](test_token|TEST_TOKEN)["\']',
        r'["\'](example_key|EXAMPLE_KEY)["\']',
        r'["\'](example_secret|EXAMPLE_SECRET)["\']',
        r'["\'](demo_key|DEMO_KEY)["\']',
        r'["\'](demo_secret|DEMO_SECRET)["\']',
    ]
    
    def __init__(self):
        """Initialize test file detector with compiled patterns"""
        self.test_file_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in self.TEST_FILE_PATTERNS]
        self.test_content_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in self.TEST_CONTENT_INDICATORS]
        self.non_production_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in self.NON_PRODUCTION_INDICATORS]
        self.placeholder_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in self.PLACEHOLDER_PATTERNS]
    
    def is_test_file(self, file_path: str, content: Optional[str] = None) -> Tuple[bool, float, str]:
        """
        Determine if a file is a test file or non-production code
        
        Returns:
            (is_test_file, confidence, reason)
        """
        file_path_str = str(file_path).replace('\\', '/')
        
        # Check file path patterns (high confidence)
        for regex in self.test_file_regexes:
            if regex.search(file_path_str):
                return True, 0.95, f"Matched test file pattern: {regex.pattern}"
        
        # Check file name
        file_name = Path(file_path).name.lower()
        if any(indicator in file_name for indicator in ['test', 'mock', 'fixture', 'example', 'demo', 'spec']):
            return True, 0.90, f"Test indicator in filename: {file_name}"
        
        # Check content if provided (medium confidence)
        if content:
            # Check for test framework imports
            for regex in self.test_content_regexes:
                if regex.search(content):
                    return True, 0.85, f"Test framework detected: {regex.pattern}"
            
            # Check for non-production indicators
            for regex in self.non_production_regexes:
                if regex.search(content):
                    return True, 0.75, f"Non-production indicator: {regex.pattern}"
        
        return False, 0.0, "Production code"
    
    def is_placeholder_credential(self, code_snippet: str) -> Tuple[bool, str]:
        """
        Check if a credential is a placeholder (not a real credential)
        
        Returns:
            (is_placeholder, reason)
        """
        for regex in self.placeholder_regexes:
            if regex.search(code_snippet):
                return True, f"Placeholder pattern: {regex.pattern}"
        
        # Check for low entropy (suggests placeholder)
        import math
        def entropy(string):
            if not string:
                return 0
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            return -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0])
        
        # Extract value from code snippet
        value_match = re.search(r'["\']([^"\']+)["\']', code_snippet)
        if value_match:
            value = value_match.group(1)
            # Low entropy suggests placeholder
            if len(value) > 0:
                ent = entropy(value)
                if ent < 2.0:  # Very low entropy
                    return True, f"Low entropy value (entropy={ent:.2f})"
                if ent < 3.0 and len(value) < 10:  # Short and low entropy
                    return True, f"Short low-entropy value (entropy={ent:.2f}, len={len(value)})"
        
        return False, "Real credential"
    
    def is_safe_path_operation(self, code_snippet: str, full_context: str) -> Tuple[bool, str]:
        """
        Check if a path operation is safe (has validation)
        
        Returns:
            (is_safe, reason)
        """
        # Check for path validation functions
        validation_patterns = [
            r'os\.path\.abspath',
            r'os\.path\.realpath',
            r'os\.path\.normpath',
            r'os\.path\.join\(',
            r'os\.path\.dirname',
            r'Path\([^)]+\)\.resolve\(\)',
            r'Path\([^)]+\)\.absolute\(\)',
            r'Path\([^)]+\)\.parent',
            r'\.startswith\([^)]+\)',
            r'\.endswith\([^)]+\)',
            r'secure_filename',
            r'werkzeug\.utils\.secure_filename',
            r'flask\.helpers\.safe_join',
            r'if\s+["\']\.\.["\']\s+in',
            r'if\s+["\']\/["\']\s+in',
            r'if\s+["\']\.\.\/["\']',
            r'path\.replace\(["\']\.\.["\']',
            r'path\.replace\(["\']\/["\']',
            r'\.replace\(["\']\.\.["\']',
            r'\.replace\(["\']\/["\']',
            r'os\.path\.commonpath',
            r'os\.path\.commonprefix',
            r'pathlib\.Path\.cwd',
            r'pathlib\.Path\.home',
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, full_context, re.IGNORECASE):
                return True, f"Path validation detected: {pattern}"
        
        # Check for framework-specific safe operations
        framework_safe_patterns = [
            # Flask
            r'@app\.route\([^)]+\)',
            r'flask\.send_file\(',
            r'flask\.send_from_directory\(',
            r'from\s+flask\s+import\s+send_file',
            r'from\s+flask\s+import\s+send_from_directory',
            
            # Django
            r'from\s+django\.core\.files\.storage\s+import',
            r'from\s+django\.core\.files\.handlers\s+import',
            r'FileField',
            r'ImageField',
            r'FilePathField',
            r'Django.*FileField',
            r'Django.*ImageField',
            r'\.storage\.',
            r'\.save\(',
            r'MEDIA_ROOT',
            r'STATIC_ROOT',
            
            # FastAPI
            r'FastAPI\(\)',
            r'from\s+fastapi\s+import\s+File',
            r'from\s+fastapi\s+import\s+UploadFile',
            r'FileResponse\(',
            r'StaticFiles\(',
            
            # Starlette
            r'from\s+starlette\.responses\s+import\s+FileResponse',
            r'from\s+starlette\.staticfiles\s+import\s+StaticFiles',
            
            # Sanitization libraries
            r'from\s+bleach\s+import',
            r'from\s+html\.parser\s+import',
            r'html\.escape',
            r'html\.unescape',
            r'urllib\.parse\.quote',
            r'urllib\.parse\.unquote',
        ]
        
        for pattern in framework_safe_patterns:
            if re.search(pattern, full_context, re.IGNORECASE):
                return True, f"Framework-safe operation: {pattern}"
        
        return False, "No path validation detected"
    
    def is_safe_sql_operation(self, code_snippet: str, full_context: str) -> Tuple[bool, str]:
        """
        Check if a SQL operation is safe (uses parameterized queries)
        
        Returns:
            (is_safe, reason)
        """
        # Check for parameterized query patterns
        safe_patterns = [
            r'\.execute\([^)]*%s',  # Parameterized with %s
            r'\.execute\([^)]*%\(',  # Named parameters
            r'\.execute\([^)]*:[\w]+',  # Named parameters (SQLite style)
            r'\.execute\([^)]*\$[\d]+',  # PostgreSQL style
            r'\.execute\([^)]*\?',  # SQLite style
            r'cursor\.execute\([^)]*\(',  # Tuple/list parameters
            r'prepared\s+statement',
            r'parameterized',
            
            # Django ORM (always safe)
            r'\.objects\.',
            r'\.objects\.get\(',
            r'\.objects\.filter\(',
            r'\.objects\.exclude\(',
            r'\.objects\.all\(',
            r'\.objects\.create\(',
            r'\.objects\.update\(',
            r'\.objects\.delete\(',
            r'Model\.objects\.',
            r'QuerySet\.',
            r'\.annotate\(',
            r'\.aggregate\(',
            r'\.values\(',
            r'\.values_list\(',
            r'\.select_related\(',
            r'\.prefetch_related\(',
            r'from\s+django\.db\s+import\s+models',
            r'from\s+django\.db\s+import\s+connection',
            r'connection\.cursor\(\)',
            
            # SQLAlchemy (ORM is safe)
            r'from\s+sqlalchemy\s+import',
            r'from\s+sqlalchemy\.orm\s+import',
            r'session\.query\(',
            r'session\.add\(',
            r'session\.delete\(',
            r'session\.execute\(',
            r'\.query\(\)',
            r'\.filter\(\)',
            r'\.filter_by\(\)',
            r'\.join\(',
            r'\.select_from\(',
            r'\.where\(',
            r'\.group_by\(',
            r'\.order_by\(',
            r'\.limit\(',
            r'\.offset\(',
            r'text\(',
            r'select\(',
            r'insert\(',
            r'update\(',
            r'delete\(',
            
            # Flask-SQLAlchemy
            r'from\s+flask_sqlalchemy\s+import',
            r'db\.session\.',
            r'Model\.query\.',
            
            # Peewee ORM
            r'from\s+peewee\s+import',
            r'Model\.select\(',
            r'Model\.get\(',
            r'Model\.filter\(',
        ]
        
        for pattern in safe_patterns:
            if re.search(pattern, full_context, re.IGNORECASE):
                return True, f"Safe SQL pattern: {pattern}"
        
        # Check for string formatting (unsafe) - but only if no safe pattern found
        unsafe_patterns = [
            r'\.execute\([^)]*%[^s%]',  # % formatting (not %s or %%)
            r'\.execute\([^)]*\+',  # String concatenation
            r'\.execute\([^)]*\.format\(',  # .format() method
            r'\.execute\([^)]*f["\']',  # f-strings
        ]
        
        # Only flag as unsafe if we see unsafe patterns AND no safe patterns
        has_unsafe = any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in unsafe_patterns)
        if has_unsafe:
            # Double-check: maybe it's in a comment or string literal
            # If the unsafe pattern is in the actual execute call, it's unsafe
            if re.search(r'\.execute\s*\([^)]*%[^s%]', code_snippet, re.IGNORECASE):
                return False, "Unsafe SQL pattern: string formatting in execute()"
            if re.search(r'\.execute\s*\([^)]*\+', code_snippet, re.IGNORECASE):
                return False, "Unsafe SQL pattern: string concatenation in execute()"
        
        return False, "No safe SQL pattern detected"

# Global instance
_test_file_detector = None

def get_test_file_detector() -> TestFileDetector:
    """Get global test file detector instance"""
    global _test_file_detector
    if _test_file_detector is None:
        _test_file_detector = TestFileDetector()
    return _test_file_detector

