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

# Additional language analyzers (using existing analyzers as fallbacks)
from .universal_detectors import UniversalDetectors

# Language registry (25+ languages supported)
LANGUAGE_ANALYZERS: Dict[str, Type[LanguageAnalyzer]] = {
    # Core languages with dedicated analyzers
    'python': PythonAnalyzer,
    'javascript': JavaScriptAnalyzer,
    'typescript': JavaScriptAnalyzer,  # TypeScript uses same analyzer
    'java': JavaAnalyzer,
    'kotlin': JavaAnalyzer,  # Kotlin uses Java analyzer (JVM)
    'scala': JavaAnalyzer,  # Scala uses Java analyzer (JVM)
    'groovy': JavaAnalyzer,  # Groovy uses Java analyzer (JVM)
    'go': GoAnalyzer,
    'rust': RustAnalyzer,
    'cpp': CppAnalyzer,
    'c': CppAnalyzer,  # C uses same analyzer as C++
    'csharp': CppAnalyzer,  # C# uses C++ analyzer (similar syntax)
    'fsharp': CppAnalyzer,  # F# uses C++ analyzer (fallback)
    'vbnet': CppAnalyzer,  # VB.NET uses C++ analyzer (fallback)
    'php': PHPAnalyzer,
    'ruby': RubyAnalyzer,
    'swift': CppAnalyzer,  # Swift uses C++ analyzer (similar syntax)
    'perl': PHPAnalyzer,  # Perl uses PHP analyzer (similar syntax)
    'lua': JavaScriptAnalyzer,  # Lua uses JS analyzer (similar syntax)
    'haskell': CppAnalyzer,  # Haskell uses C++ analyzer (fallback)
    'clojure': JavaScriptAnalyzer,  # Clojure uses JS analyzer (similar syntax)
    'erlang': JavaScriptAnalyzer,  # Erlang uses JS analyzer (fallback)

    # Data/Configuration languages (universal detectors)
    'sql': UniversalDetectors,
    'yaml': UniversalDetectors,
    'json': UniversalDetectors,
    'xml': UniversalDetectors,
    'bash': UniversalDetectors,
    'powershell': UniversalDetectors,
}

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


