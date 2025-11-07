"""
Language Support Module for Parry Security Scanner

Provides comprehensive support for 25+ programming languages with syntax highlighting,
file extensions, and language-specific features.
"""

from typing import Dict, List, Set, Optional
from pathlib import Path

class LanguageSupport:
    """Comprehensive language support for Parry"""

    # Core supported languages with file extensions and metadata
    LANGUAGE_CONFIG = {
        # Interpreted Languages
        "python": {
            "name": "Python",
            "extensions": [".py", ".pyx", ".pyw", ".pyi"],
            "comment_styles": ["#"],
            "string_delimiters": ['"', "'", '"""', "'''"],
            "keywords": ["def", "class", "import", "from", "if", "for", "while", "try", "except"],
            "frameworks": ["Django", "Flask", "FastAPI", "Pyramid"],
            "package_managers": ["pip", "poetry", "conda"]
        },
        "javascript": {
            "name": "JavaScript",
            "extensions": [".js", ".mjs", ".cjs"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "'", "`"],
            "keywords": ["function", "class", "import", "export", "if", "for", "while", "try", "catch"],
            "frameworks": ["React", "Vue", "Angular", "Express", "Next.js"],
            "package_managers": ["npm", "yarn", "pnpm"]
        },
        "typescript": {
            "name": "TypeScript",
            "extensions": [".ts", ".tsx", ".d.ts"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "'", "`"],
            "keywords": ["function", "class", "import", "export", "interface", "type", "if", "for", "while", "try", "catch"],
            "frameworks": ["React", "Vue", "Angular", "NestJS", "Next.js"],
            "package_managers": ["npm", "yarn", "pnpm"]
        },

        # JVM Languages
        "java": {
            "name": "Java",
            "extensions": [".java"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "'"],
            "keywords": ["public", "private", "class", "interface", "if", "for", "while", "try", "catch"],
            "frameworks": ["Spring", "Hibernate", "Jakarta EE", "Quarkus", "Micronaut"],
            "package_managers": ["Maven", "Gradle"]
        },
        "kotlin": {
            "name": "Kotlin",
            "extensions": [".kt", ".kts"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "'", '"""'],
            "keywords": ["fun", "class", "val", "var", "if", "for", "while", "try", "catch"],
            "frameworks": ["Spring", "Ktor", "Android"],
            "package_managers": ["Maven", "Gradle"]
        },
        "scala": {
            "name": "Scala",
            "extensions": [".scala", ".sc"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "'", '"""'],
            "keywords": ["def", "class", "val", "var", "if", "for", "while", "try", "catch"],
            "frameworks": ["Play", "Akka", "Spark"],
            "package_managers": ["sbt", "Maven"]
        },
        "groovy": {
            "name": "Groovy",
            "extensions": [".groovy", ".gvy", ".gy", ".gsh"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "'", "'''", '"""'],
            "keywords": ["def", "class", "if", "for", "while", "try", "catch"],
            "frameworks": ["Grails", "Gradle"],
            "package_managers": ["Maven", "Gradle"]
        },

        # .NET Languages
        "csharp": {
            "name": "C#",
            "extensions": [".cs", ".csx"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "@\""],
            "keywords": ["public", "private", "class", "interface", "if", "for", "while", "try", "catch"],
            "frameworks": ["ASP.NET", ".NET Core", "Entity Framework", "Blazor"],
            "package_managers": ["NuGet", "dotnet CLI"]
        },
        "fsharp": {
            "name": "F#",
            "extensions": [".fs", ".fsi", ".fsx", ".fsscript"],
            "comment_styles": ["//", "(* *)"],
            "string_delimiters": ['"', '"""'],
            "keywords": ["let", "type", "module", "if", "for", "while", "try", "with"],
            "frameworks": [".NET Core", "Suave"],
            "package_managers": ["NuGet", "Paket"]
        },
        "vbnet": {
            "name": "VB.NET",
            "extensions": [".vb"],
            "comment_styles": ["'"],
            "string_delimiters": ['"', '"""'],
            "keywords": ["Public", "Private", "Class", "If", "For", "While", "Try", "Catch"],
            "frameworks": ["ASP.NET", ".NET Framework"],
            "package_managers": ["NuGet"]
        },

        # Systems Languages
        "cpp": {
            "name": "C++",
            "extensions": [".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hxx", ".h++"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "'"],
            "keywords": ["class", "struct", "if", "for", "while", "try", "catch"],
            "frameworks": ["Qt", "Boost", "STL"],
            "package_managers": ["CMake", "Conan", "vcpkg"]
        },
        "c": {
            "name": "C",
            "extensions": [".c", ".h"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "'"],
            "keywords": ["int", "char", "if", "for", "while"],
            "frameworks": ["GLib", "POSIX"],
            "package_managers": ["Make", "CMake"]
        },
        "rust": {
            "name": "Rust",
            "extensions": [".rs"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "'"],
            "keywords": ["fn", "struct", "enum", "if", "for", "while", "match"],
            "frameworks": ["Tokio", "Rocket", "Actix"],
            "package_managers": ["Cargo"]
        },
        "go": {
            "name": "Go",
            "extensions": [".go"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', "`"],
            "keywords": ["func", "type", "struct", "if", "for", "go", "defer"],
            "frameworks": ["Gin", "Echo", "Fiber"],
            "package_managers": ["go mod"]
        },
        "swift": {
            "name": "Swift",
            "extensions": [".swift"],
            "comment_styles": ["//", "/* */"],
            "string_delimiters": ['"', '"""'],
            "keywords": ["func", "class", "struct", "if", "for", "while", "do", "try", "catch"],
            "frameworks": ["SwiftUI", "Vapor", "Perfect"],
            "package_managers": ["Swift Package Manager", "CocoaPods"]
        },

        # Web & Scripting Languages
        "php": {
            "name": "PHP",
            "extensions": [".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps"],
            "comment_styles": ["//", "#", "/* */"],
            "string_delimiters": ['"', "'"],
            "keywords": ["function", "class", "if", "for", "while", "try", "catch"],
            "frameworks": ["Laravel", "Symfony", "CodeIgniter", "Yii", "CakePHP"],
            "package_managers": ["Composer"]
        },
        "ruby": {
            "name": "Ruby",
            "extensions": [".rb", ".rbw", ".rake", ".gemspec"],
            "comment_styles": ["#"],
            "string_delimiters": ['"', "'", "%q{", "%Q{"],
            "keywords": ["def", "class", "module", "if", "for", "while", "begin", "rescue"],
            "frameworks": ["Rails", "Sinatra", "Hanami"],
            "package_managers": ["Bundler", "RubyGems"]
        },
        "perl": {
            "name": "Perl",
            "extensions": [".pl", ".pm", ".t"],
            "comment_styles": ["#"],
            "string_delimiters": ['"', "'"],
            "keywords": ["sub", "package", "if", "for", "while", "eval"],
            "frameworks": ["Mojolicious", "Dancer", "Catalyst"],
            "package_managers": ["CPAN"]
        },
        "lua": {
            "name": "Lua",
            "extensions": [".lua"],
            "comment_styles": ["--", "--[[ ]]"],
            "string_delimiters": ['"', "'", "[["],
            "keywords": ["function", "local", "if", "for", "while"],
            "frameworks": ["Lapis", "OpenResty"],
            "package_managers": ["LuaRocks"]
        },

        # Functional Languages
        "haskell": {
            "name": "Haskell",
            "extensions": [".hs", ".lhs"],
            "comment_styles": ["--", "{- -}"],
            "string_delimiters": ['"', '"""'],
            "keywords": ["data", "type", "class", "instance", "if", "case", "do"],
            "frameworks": ["Yesod", "Snap", "Servant"],
            "package_managers": ["Cabal", "Stack"]
        },
        "clojure": {
            "name": "Clojure",
            "extensions": [".clj", ".cljs", ".cljc", ".edn"],
            "comment_styles": [";"],
            "string_delimiters": ['"', '"""'],
            "keywords": ["defn", "def", "if", "for", "while", "try", "catch"],
            "frameworks": ["Ring", "Compojure", "Luminus"],
            "package_managers": ["Leiningen", "Boot"]
        },
        "erlang": {
            "name": "Erlang",
            "extensions": [".erl", ".hrl"],
            "comment_styles": ["%"],
            "string_delimiters": ['"', '"""'],
            "keywords": ["-module", "-export", "if", "case", "fun"],
            "frameworks": ["Chicago Boss", "N2O"],
            "package_managers": ["Rebar3"]
        },

        # Data & Configuration
        "sql": {
            "name": "SQL",
            "extensions": [".sql"],
            "comment_styles": ["--", "/* */"],
            "string_delimiters": ['"', "'"],
            "keywords": ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP"],
            "frameworks": ["PostgreSQL", "MySQL", "SQLite", "Oracle"],
            "package_managers": []
        },
        "yaml": {
            "name": "YAML",
            "extensions": [".yaml", ".yml"],
            "comment_styles": ["#"],
            "string_delimiters": ['"', "'"],
            "keywords": [],
            "frameworks": ["Kubernetes", "Docker Compose", "Ansible"],
            "package_managers": []
        },
        "json": {
            "name": "JSON",
            "extensions": [".json"],
            "comment_styles": [],
            "string_delimiters": ['"'],
            "keywords": [],
            "frameworks": ["REST APIs", "Configuration"],
            "package_managers": []
        },
        "xml": {
            "name": "XML",
            "extensions": [".xml", ".xsd", ".xsl"],
            "comment_styles": ["<!-- -->"],
            "string_delimiters": ['"', "'"],
            "keywords": [],
            "frameworks": ["SOAP", "XML-RPC", "Configuration"],
            "package_managers": []
        },

        # Shell & Scripting
        "bash": {
            "name": "Bash",
            "extensions": [".sh", ".bash"],
            "comment_styles": ["#"],
            "string_delimiters": ['"', "'"],
            "keywords": ["function", "if", "for", "while", "case"],
            "frameworks": ["Shell scripting"],
            "package_managers": []
        },
        "powershell": {
            "name": "PowerShell",
            "extensions": [".ps1", ".psm1", ".psd1"],
            "comment_styles": ["#"],
            "string_delimiters": ['"', "'"],
            "keywords": ["function", "if", "for", "while", "try", "catch"],
            "frameworks": ["Windows PowerShell"],
            "package_managers": ["PowerShell Gallery"]
        }
    }

    def __init__(self):
        self._all_extensions = set()
        for lang_config in self.LANGUAGE_CONFIG.values():
            self._all_extensions.update(lang_config["extensions"])

    def get_supported_languages(self) -> List[str]:
        """Get list of all supported language names"""
        return list(self.LANGUAGE_CONFIG.keys())

    def get_language_extensions(self, language: str) -> List[str]:
        """Get file extensions for a specific language"""
        config = self.LANGUAGE_CONFIG.get(language.lower())
        return config["extensions"] if config else []

    def get_all_extensions(self) -> Set[str]:
        """Get all supported file extensions"""
        return self._all_extensions.copy()

    def detect_language(self, file_path: Path) -> Optional[str]:
        """Detect language from file extension"""
        extension = file_path.suffix.lower()
        for lang_name, config in self.LANGUAGE_CONFIG.items():
            if extension in config["extensions"]:
                return lang_name
        return None

    def get_language_info(self, language: str) -> Optional[Dict]:
        """Get detailed information about a language"""
        return self.LANGUAGE_CONFIG.get(language.lower())

    def get_frameworks_for_language(self, language: str) -> List[str]:
        """Get frameworks supported for a language"""
        config = self.LANGUAGE_CONFIG.get(language.lower())
        return config.get("frameworks", []) if config else []

    def get_package_managers_for_language(self, language: str) -> List[str]:
        """Get package managers for a language"""
        config = self.LANGUAGE_CONFIG.get(language.lower())
        return config.get("package_managers", []) if config else []

    def supports_syntax_highlighting(self, language: str) -> bool:
        """Check if language supports syntax highlighting"""
        config = self.LANGUAGE_CONFIG.get(language.lower())
        return bool(config and (config["comment_styles"] or config["keywords"]))

    def get_comment_styles(self, language: str) -> List[str]:
        """Get comment styles for a language"""
        config = self.LANGUAGE_CONFIG.get(language.lower())
        return config.get("comment_styles", []) if config else []

    def get_string_delimiters(self, language: str) -> List[str]:
        """Get string delimiters for a language"""
        config = self.LANGUAGE_CONFIG.get(language.lower())
        return config.get("string_delimiters", []) if config else []


# Global instance
language_support = LanguageSupport()

def get_language_support() -> LanguageSupport:
    """Get the global language support instance"""
    return language_support
