"""
Multi-language support for Parry Security Scanner.

This package provides language-specific vulnerability detection
for various programming languages.
"""

from typing import Dict, Type
from .base import LanguageAnalyzer
from .python_analyzer import PythonAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from .java_analyzer import JavaAnalyzer
from .go_analyzer import GoAnalyzer
from .rust_analyzer import RustAnalyzer
from .cpp_analyzer import CppAnalyzer
from .php_analyzer import PHPAnalyzer
from .ruby_analyzer import RubyAnalyzer

# Language registry
LANGUAGE_ANALYZERS: Dict[str, Type[LanguageAnalyzer]] = {
    'python': PythonAnalyzer,
    'javascript': JavaScriptAnalyzer,
    'typescript': JavaScriptAnalyzer,  # TypeScript uses same analyzer
    'java': JavaAnalyzer,
    'go': GoAnalyzer,
    'rust': RustAnalyzer,
    'cpp': CppAnalyzer,
    'c': CppAnalyzer,  # C uses same analyzer as C++
    'php': PHPAnalyzer,
    'ruby': RubyAnalyzer,
}

# File extension to language mapping
FILE_EXTENSIONS = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.java': 'java',
    '.go': 'go',
    '.rs': 'rust',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.c': 'c',
    '.h': 'cpp',
    '.hpp': 'cpp',
    '.php': 'php',
    '.rb': 'ruby',
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


