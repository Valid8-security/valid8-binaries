#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""Language support registry for Valid8 security scanner."""

from typing import Dict, List, Type
from .language_support.base import LanguageAnalyzer

# Import all analyzers
from .language_support.python_analyzer import PythonAnalyzer
from .language_support.javascript_analyzer import JavaScriptAnalyzer
from .language_support.typescript_analyzer import TypeScriptAnalyzer
from .language_support.java_analyzer import JavaAnalyzer
from .language_support.csharp_analyzer import CSharpAnalyzer
from .language_support.golang_analyzer import GoAnalyzer
from .language_support.kotlin_analyzer import KotlinAnalyzer
from .language_support.rust_analyzer import RustAnalyzer
from .language_support.cpp_analyzer import CPPAnalyzer
from .language_support.php_analyzer import PHPAnalyzer
from .language_support.ruby_analyzer import RubyAnalyzer
from .language_support.sql_analyzer import SQLAnalyzer
from .language_support.yaml_analyzer import YAMLAnalyzer

# Language mappings
LANGUAGE_ANALYZERS: Dict[str, Type[LanguageAnalyzer]] = {
    # Core languages
    'python': PythonAnalyzer,
    'javascript': JavaScriptAnalyzer,
    'typescript': TypeScriptAnalyzer,
    'java': JavaAnalyzer,
    'csharp': CSharpAnalyzer,
    'c#': CSharpAnalyzer,
    'golang': GoAnalyzer,
    'go': GoAnalyzer,
    'kotlin': KotlinAnalyzer,
    'rust': RustAnalyzer,
    'cpp': CPPAnalyzer,
    'c++': CPPAnalyzer,
    'c': CPPAnalyzer,
    'php': PHPAnalyzer,
    'ruby': RubyAnalyzer,

    # Configuration and data languages
    'sql': SQLAnalyzer,
    'yaml': YAMLAnalyzer,
    'yml': YAMLAnalyzer,

    # Additional supported languages (frameworks)
    'scala': JavaAnalyzer,  # Use Java analyzer as fallback
    'groovy': JavaAnalyzer,  # Use Java analyzer as fallback
    'swift': CSharpAnalyzer,  # Use C# analyzer as fallback
    'perl': PHPAnalyzer,     # Use PHP analyzer as fallback
    'lua': PHPAnalyzer,      # Use PHP analyzer as fallback
    'haskell': RustAnalyzer,  # Use Rust analyzer as fallback
    'clojure': JavaAnalyzer,  # Use Java analyzer as fallback
    'erlang': JavaAnalyzer,   # Use Java analyzer as fallback
    'bash': PHPAnalyzer,     # Use PHP analyzer as fallback
    'powershell': CSharpAnalyzer,  # Use C# analyzer as fallback
    'fsharp': CSharpAnalyzer, # Use C# analyzer as fallback
    'f#': CSharpAnalyzer,
    'vbnet': CSharpAnalyzer,  # Use C# analyzer as fallback
    'vb.net': CSharpAnalyzer,

    # Web and config formats
    'json': JavaScriptAnalyzer,  # Use JS analyzer for JSON
    'xml': JavaAnalyzer,         # Use Java analyzer for XML
    'html': JavaScriptAnalyzer,  # Use JS analyzer for HTML
    'css': PHPAnalyzer,         # Use PHP analyzer as fallback
}

# File extension mappings
EXTENSION_TO_LANGUAGE: Dict[str, str] = {
    # Python
    '.py': 'python',
    '.pyw': 'python',
    '.pyx': 'python',

    # JavaScript/TypeScript
    '.js': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.jsx': 'javascript',

    # Java/Kotlin/Scala
    '.java': 'java',
    '.kt': 'kotlin',
    '.kts': 'kotlin',
    '.scala': 'scala',
    '.groovy': 'groovy',

    # C#/F#/VB.NET
    '.cs': 'csharp',
    '.fs': 'fsharp',
    '.fsi': 'fsharp',
    '.fsx': 'fsharp',
    '.vb': 'vbnet',

    # Go
    '.go': 'go',

    # Rust
    '.rs': 'rust',

    # C/C++
    '.c': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.h': 'cpp',
    '.hpp': 'cpp',

    # PHP
    '.php': 'php',
    '.phtml': 'php',

    # Ruby
    '.rb': 'ruby',
    '.rbw': 'ruby',

    # Swift
    '.swift': 'swift',

    # Perl
    '.pl': 'perl',
    '.pm': 'perl',

    # Lua
    '.lua': 'lua',

    # Haskell
    '.hs': 'haskell',
    '.lhs': 'haskell',

    # Clojure
    '.clj': 'clojure',
    '.cljs': 'clojure',
    '.cljc': 'clojure',

    # Erlang
    '.erl': 'erlang',
    '.hrl': 'erlang',

    # Shell scripts
    '.sh': 'bash',
    '.bash': 'bash',
    '.zsh': 'bash',
    '.ps1': 'powershell',

    # SQL
    '.sql': 'sql',

    # Configuration formats
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.json': 'json',
    '.xml': 'xml',
    '.html': 'html',
    '.htm': 'html',
    '.css': 'css',
}

def get_analyzer_for_language(language: str) -> Type[LanguageAnalyzer]:
    """Get the analyzer class for a given language."""
    return LANGUAGE_ANALYZERS.get(language.lower())

def get_analyzer_for_file(filepath: str) -> Type[LanguageAnalyzer]:
    """Get the analyzer class for a given file based on its extension."""
    import os
    _, ext = os.path.splitext(filepath.lower())
    language = EXTENSION_TO_LANGUAGE.get(ext)
    if language:
        return get_analyzer_for_language(language)
    return None

def get_supported_languages() -> List[str]:
    """Get list of all supported languages."""
    return list(LANGUAGE_ANALYZERS.keys())

def get_supported_extensions() -> List[str]:
    """Get list of all supported file extensions."""
    return list(EXTENSION_TO_LANGUAGE.keys())

def is_language_supported(language: str) -> bool:
    """Check if a language is supported."""
    return language.lower() in LANGUAGE_ANALYZERS

def is_file_supported(filepath: str) -> bool:
    """Check if a file extension is supported."""
    import os
    _, ext = os.path.splitext(filepath.lower())
    return ext in EXTENSION_TO_LANGUAGE
