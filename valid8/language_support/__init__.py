#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Multi-language support for Valid8 Security Scanner.

This package provides language-specific vulnerability detection
for various programming languages.
"""

from typing import Dict, Type

# Robust imports that work in different contexts
LanguageAnalyzer = None
PythonAnalyzer = None
JavaScriptAnalyzer = None
JavaAnalyzer = None
GoAnalyzer = None
RustAnalyzer = None
CppAnalyzer = None
PHPAnalyzer = None
RubyAnalyzer = None
UniversalDetectors = None

try:
    from .base import LanguageAnalyzer
    print("✅ LanguageAnalyzer imported")
except ImportError as e:
    print(f"⚠️  LanguageAnalyzer import failed: {e}")

try:
    from .python_analyzer import PythonAnalyzer
    print("✅ PythonAnalyzer imported")
except ImportError as e:
    print(f"⚠️  PythonAnalyzer import failed: {e}")

try:
    from .javascript_analyzer import JavaScriptAnalyzer
    print("✅ JavaScriptAnalyzer imported")
except ImportError as e:
    print(f"⚠️  JavaScriptAnalyzer import failed: {e}")

try:
    from .java_analyzer import JavaAnalyzer
    print("✅ JavaAnalyzer imported")
except ImportError as e:
    print(f"⚠️  JavaAnalyzer import failed: {e}")

try:
    from .go_analyzer import GoAnalyzer
    print("✅ GoAnalyzer imported")
except ImportError as e:
    print(f"⚠️  GoAnalyzer import failed: {e}")

try:
    from .rust_analyzer import RustAnalyzer
    print("✅ RustAnalyzer imported")
except ImportError as e:
    print(f"⚠️  RustAnalyzer import failed: {e}")

try:
    from .cpp_analyzer import CppAnalyzer
    print("✅ CppAnalyzer imported")
except ImportError as e:
    print(f"⚠️  CppAnalyzer import failed: {e}")

try:
    from .php_analyzer import PHPAnalyzer
    print("✅ PHPAnalyzer imported")
except ImportError as e:
    print(f"⚠️  PHPAnalyzer import failed: {e}")

try:
    from .ruby_analyzer import RubyAnalyzer
    print("✅ RubyAnalyzer imported")
except ImportError as e:
    print(f"⚠️  RubyAnalyzer import failed: {e}")

try:
    from .universal_detectors import UniversalDetectors
    print("✅ UniversalDetectors imported")
except ImportError as e:
    print(f"⚠️  UniversalDetectors import failed: {e}")

# Language registry (25+ languages supported)
LANGUAGE_ANALYZERS: Dict[str, Type[LanguageAnalyzer]] = {}

# Register available analyzers (don't require all to be present)
if LanguageAnalyzer:  # Base class is required
    analyzers_to_register = {}

    if PythonAnalyzer:
        analyzers_to_register.update({
            'python': PythonAnalyzer,
        })

    if JavaScriptAnalyzer:
        analyzers_to_register.update({
            'javascript': JavaScriptAnalyzer,
            'typescript': JavaScriptAnalyzer,  # TypeScript uses same analyzer
        })

    if JavaAnalyzer:
        analyzers_to_register.update({
            'java': JavaAnalyzer,
            'kotlin': JavaAnalyzer,  # Kotlin uses Java analyzer (JVM)
            'scala': JavaAnalyzer,  # Scala uses Java analyzer (JVM)
            'groovy': JavaAnalyzer,  # Groovy uses Java analyzer (JVM)
        })

    if GoAnalyzer:
        analyzers_to_register.update({
            'go': GoAnalyzer,
        })

    if RustAnalyzer:
        analyzers_to_register.update({
            'rust': RustAnalyzer,
        })

    if CppAnalyzer:
        analyzers_to_register.update({
            'cpp': CppAnalyzer,
            'c': CppAnalyzer,  # C uses same analyzer as C++
            'csharp': CppAnalyzer,  # C# uses C++ analyzer (similar syntax)
            'fsharp': CppAnalyzer,  # F# uses C++ analyzer (fallback)
            'vbnet': CppAnalyzer,  # VB.NET uses C++ analyzer (fallback)
        })

    if PHPAnalyzer:
        analyzers_to_register.update({
            'php': PHPAnalyzer,
        })

    LANGUAGE_ANALYZERS = analyzers_to_register
    print(f"✅ Registered {len(LANGUAGE_ANALYZERS)} language analyzers: {list(LANGUAGE_ANALYZERS.keys())}")
else:
    print("❌ LanguageAnalyzer base class not available")

# Legacy fallbacks for unsupported languages (only if no analyzers loaded)
if not LANGUAGE_ANALYZERS and UniversalDetectors:
    LANGUAGE_ANALYZERS = {
        'ruby': UniversalDetectors,  # Ruby uses universal detectors
        'swift': UniversalDetectors,  # Swift uses universal detectors
        'perl': UniversalDetectors,  # Perl uses universal detectors
        'lua': UniversalDetectors,  # Lua uses universal detectors
        'haskell': UniversalDetectors,  # Haskell uses universal detectors
        'clojure': UniversalDetectors,  # Clojure uses universal detectors
        'erlang': UniversalDetectors,  # Erlang uses universal detectors

        # Data/Configuration languages (universal detectors)
        'sql': UniversalDetectors,
        'yaml': UniversalDetectors,
        'json': UniversalDetectors,
        'xml': UniversalDetectors,
        'bash': UniversalDetectors,
        'powershell': UniversalDetectors,
    }
    print(f"⚠️  Using universal detectors for {len(LANGUAGE_ANALYZERS)} languages")

# File extension to language mapping (25+ languages)
FILE_EXTENSIONS = {
    # Python
    '.py': 'python',
    '.pyx': 'python',
    '.pyw': 'python',
    '.pyi': 'python',

    # JavaScript/TypeScript
    '.js': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.d.ts': 'typescript',

    # JVM Languages
    '.java': 'java',
    '.kt': 'kotlin',
    '.kts': 'kotlin',
    '.scala': 'scala',
    '.sc': 'scala',
    '.groovy': 'groovy',
    '.gvy': 'groovy',
    '.gy': 'groovy',
    '.gsh': 'groovy',

    # .NET Languages
    '.cs': 'csharp',
    '.csx': 'csharp',
    '.fs': 'fsharp',
    '.fsi': 'fsharp',
    '.fsx': 'fsharp',
    '.fsscript': 'fsharp',
    '.vb': 'vbnet',

    # Systems Languages
    '.go': 'go',
    '.rs': 'rust',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.c++': 'cpp',
    '.c': 'c',
    '.h': 'cpp',
    '.hpp': 'cpp',
    '.hxx': 'cpp',
    '.h++': 'cpp',
    '.swift': 'swift',

    # Web Languages
    '.php': 'php',
    '.phtml': 'php',
    '.php3': 'php',
    '.php4': 'php',
    '.php5': 'php',
    '.php7': 'php',
    '.phps': 'php',
    '.rb': 'ruby',
    '.rbw': 'ruby',
    '.rake': 'ruby',
    '.gemspec': 'ruby',
    '.pl': 'perl',
    '.pm': 'perl',
    '.t': 'perl',
    '.lua': 'lua',

    # Functional Languages
    '.hs': 'haskell',
    '.lhs': 'haskell',
    '.clj': 'clojure',
    '.cljs': 'clojure',
    '.cljc': 'clojure',
    '.edn': 'clojure',
    '.erl': 'erlang',
    '.hrl': 'erlang',

    # Data/Configuration
    '.sql': 'sql',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.json': 'json',
    '.xml': 'xml',
    '.xsd': 'xml',
    '.xsl': 'xml',

    # Shell/Scripting
    '.sh': 'bash',
    '.bash': 'bash',
    '.ps1': 'powershell',
    '.psm1': 'powershell',
    '.psd1': 'powershell',
}


def get_language_from_file(filepath: str) -> str:
    """Detect language from file extension."""
    import os
    _, ext = os.path.splitext(filepath)
    return FILE_EXTENSIONS.get(ext.lower(), 'unknown')


def get_analyzer(language: str) -> LanguageAnalyzer:
    """Get analyzer instance for a language."""
    analyzer_class = LANGUAGE_ANALYZERS.get(language)
    if analyzer_class:
        return analyzer_class()
    return None


__all__ = [
    'LanguageAnalyzer',
    'PythonAnalyzer',
    'JavaScriptAnalyzer',
    'JavaAnalyzer',
    'GoAnalyzer',
    'RustAnalyzer',
    'CppAnalyzer',
    'PHPAnalyzer',
    'RubyAnalyzer',
    'LANGUAGE_ANALYZERS',
    'FILE_EXTENSIONS',
    'get_language_from_file',
    'get_analyzer',
]
