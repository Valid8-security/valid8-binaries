#!/usr/bin/env python3
"""
Smart Recommendations Engine for Valid8

Provides deterministic, pattern-based fix suggestions for vulnerabilities
without machine learning dependencies. Generates actionable remediation
guidance based on vulnerability type and code context.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..models import Vulnerability


@dataclass
class FixSuggestion:
    """Represents a fix suggestion for a vulnerability"""
    title: str
    description: str
    code_example: str
    priority: str  # 'immediate', 'high', 'medium', 'low'
    effort: str    # 'minimal', 'moderate', 'significant'
    framework_notes: Optional[str] = None


class SmartRecommendations:
    """Deterministic fix recommendation engine"""

    def __init__(self):
        self.fix_patterns = self._initialize_fix_patterns()

    def _initialize_fix_patterns(self) -> Dict[VulnerabilityType, List[FixSuggestion]]:
        """Initialize fix patterns for different vulnerability types"""

        return {
            "injection": [  # SQL injection, command injection
                FixSuggestion(
                    title="Use Parameterized Queries",
                    description="Replace string concatenation with parameterized queries to prevent SQL injection",
                    code_example="""
# ❌ Vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# ✅ Secure
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
""",
                    priority="immediate",
                    effort="minimal"
                ),
                FixSuggestion(
                    title="Use ORM Prepared Statements",
                    description="Use your ORM's built-in parameterized query methods",
                    code_example="""
# Django ORM
User.objects.filter(id=user_id)

# SQLAlchemy
session.query(User).filter(User.id == user_id)
""",
                    priority="immediate",
                    effort="minimal"
                ),
                FixSuggestion(
                    title="Input Validation & Sanitization",
                    description="Validate and sanitize user input before using in queries",
                    code_example="""
import re

def validate_user_id(user_id):
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("Invalid user ID")
    return user_id

user_id = validate_user_id(request.args.get('id'))
""",
                    priority="high",
                    effort="moderate"
                )
            ],

            "xss": [
                FixSuggestion(
                    title="Use Auto-Escaping Templates",
                    description="Use template engines with automatic HTML escaping",
                    code_example="""
# Jinja2 (auto-escapes by default)
{{ user_input }}

# React JSX (auto-escapes)
<div>{userInput}</div>

# Vue.js (auto-escapes)
<div>{{ userInput }}</div>
""",
                    priority="immediate",
                    effort="minimal"
                ),
                FixSuggestion(
                    title="Manual HTML Escaping",
                    description="Manually escape HTML entities in user input",
                    code_example="""
import html

# Escape user input before inserting into HTML
safe_content = html.escape(user_input)
html_output = f"<div>{safe_content}</div>"
""",
                    priority="immediate",
                    effort="minimal"
                ),
                FixSuggestion(
                    title="Content Security Policy (CSP)",
                    description="Implement CSP headers to mitigate XSS impact",
                    code_example="""
# Flask
from flask import Flask
app = Flask(__name__)

@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
""",
                    priority="high",
                    effort="moderate"
                )
            ],

            "injection": [  # Command injection (same as SQL injection)
                FixSuggestion(
                    title="Use Safe APIs Instead of Shell Commands",
                    description="Replace shell command execution with safe API calls",
                    code_example="""
# ❌ Vulnerable
os.system(f"rm {filename}")

# ✅ Secure - Use pathlib
from pathlib import Path
Path(filename).unlink()
""",
                    priority="immediate",
                    effort="moderate"
                ),
                FixSuggestion(
                    title="Whitelist Allowed Commands",
                    description="Maintain a whitelist of allowed commands and validate input",
                    code_example="""
ALLOWED_COMMANDS = {'ls', 'cat', 'head', 'tail'}

def execute_safe_command(command, args):
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command}")

    # Validate args are safe
    safe_args = [arg for arg in args if is_safe_argument(arg)]
    subprocess.run([command] + safe_args, shell=False)
""",
                    priority="high",
                    effort="significant"
                ),
                FixSuggestion(
                    title="Use subprocess with List Arguments",
                    description="Pass command arguments as a list instead of string",
                    code_example="""
# ❌ Vulnerable
subprocess.call(f"grep {pattern} {filename}")

# ✅ Secure
subprocess.call(['grep', pattern, filename])
""",
                    priority="immediate",
                    effort="minimal"
                )
            ],

            "access": [  # Path traversal
                FixSuggestion(
                    title="Use Path Libraries Instead of String Concatenation",
                    description="Use pathlib or os.path.join instead of manual path construction",
                    code_example="""
# ❌ Vulnerable
filepath = base_path + "/" + user_input

# ✅ Secure - pathlib
from pathlib import Path
filepath = Path(base_path) / user_input

# ✅ Secure - os.path
import os
filepath = os.path.join(base_path, user_input)
""",
                    priority="immediate",
                    effort="minimal"
                ),
                FixSuggestion(
                    title="Path Normalization & Validation",
                    description="Normalize paths and validate they stay within allowed directories",
                    code_example="""
import os
from pathlib import Path

def secure_path_join(base_path: str, user_path: str) -> Path:
    # Normalize the path
    full_path = Path(base_path) / user_path
    resolved_path = full_path.resolve()

    # Ensure it stays within base directory
    base_resolved = Path(base_path).resolve()
    if not str(resolved_path).startswith(str(base_resolved)):
        raise ValueError("Path traversal detected")

    return resolved_path
""",
                    priority="immediate",
                    effort="moderate"
                )
            ],

            "crypto": [
                FixSuggestion(
                    title="Use Cryptographically Secure Algorithms",
                    description="Replace weak algorithms with modern secure alternatives",
                    code_example="""
# ❌ Weak
import hashlib
hashlib.md5(data)

# ✅ Secure
import hashlib
hashlib.sha256(data)

# For password hashing
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# For encryption
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)
""",
                    priority="immediate",
                    effort="moderate"
                ),
                FixSuggestion(
                    title="Use Established Crypto Libraries",
                    description="Use well-audited cryptography libraries instead of built-in modules",
                    code_example="""
# Install: pip install cryptography

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Secure key derivation
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = kdf.derive(password)
""",
                    priority="high",
                    effort="significant"
                )
            ],

            "secrets": [
                FixSuggestion(
                    title="Use Environment Variables",
                    description="Move secrets to environment variables",
                    code_example="""
# ❌ Hardcoded
API_KEY = "sk-1234567890abcdef"

# ✅ Environment variable
import os
API_KEY = os.environ['API_KEY']
""",
                    priority="immediate",
                    effort="minimal"
                ),
                FixSuggestion(
                    title="Use Secret Management Services",
                    description="Store secrets in dedicated secret management systems",
                    code_example="""
# AWS Secrets Manager
import boto3
client = boto3.client('secretsmanager')
response = client.get_secret_value(SecretId='my-api-key')

# Azure Key Vault
from azure.keyvault.secrets import SecretClient
client = SecretClient(vault_url=url, credential=credential)
secret = client.get_secret('my-secret')

# HashiCorp Vault
import hvac
client = hvac.Client(url='https://vault.example.com')
secret = client.secrets.kv.v1.read_secret_version(path='my-secret')
""",
                    priority="high",
                    effort="significant"
                )
            ]
        }

    def get_recommendations(self, vulnerability: Vulnerability) -> List[FixSuggestion]:
        """
        Get fix recommendations for a vulnerability

        Args:
            vulnerability: The vulnerability to generate recommendations for

        Returns:
            List of applicable fix suggestions
        """

        # Get base recommendations for this vulnerability category
        vuln_category = getattr(vulnerability, 'category', 'unknown')
        base_recommendations = self.fix_patterns.get(vuln_category, [])

        # Customize recommendations based on code context
        customized_recommendations = []
        for rec in base_recommendations:
            customized_rec = self._customize_recommendation(rec, vulnerability)
            customized_recommendations.append(customized_rec)

        return customized_recommendations

    def _customize_recommendation(self, recommendation: FixSuggestion, vulnerability: Vulnerability) -> FixSuggestion:
        """Customize recommendation based on vulnerability context"""

        # Analyze the vulnerable code to provide more specific advice
        code = vulnerability.code_snippet.lower()

        # Framework-specific customizations
        if 'django' in code or 'django' in str(vulnerability.file_path).lower():
            if vulnerability.type == VulnerabilityType.SQL_INJECTION:
                recommendation.framework_notes = "Django ORM automatically escapes SQL, but raw() queries need manual protection."
            elif vulnerability.type == VulnerabilityType.XSS:
                recommendation.framework_notes = "Django templates auto-escape. Use |safe filter only when absolutely necessary."

        elif 'flask' in code or 'flask' in str(vulnerability.file_path).lower():
            if vulnerability.type == VulnerabilityType.XSS:
                recommendation.framework_notes = "Flask templates don't auto-escape. Use Jinja2 with autoescape enabled."

        elif 'express' in code or 'express' in str(vulnerability.file_path).lower():
            if vulnerability.type == VulnerabilityType.XSS:
                recommendation.framework_notes = "Use DOMPurify or equivalent for HTML sanitization in Node.js."

        # SQL library specific advice
        if 'sqlite3' in code:
            recommendation.framework_notes = "Use sqlite3 parameterized queries: cursor.execute('SELECT * FROM table WHERE id=?', (user_id,))"
        elif 'psycopg2' in code or 'postgresql' in code:
            recommendation.framework_notes = "Use psycopg2 parameterized queries: cursor.execute('SELECT * FROM table WHERE id=%s', (user_id,))"
        elif 'pymysql' in code or 'mysql' in code:
            recommendation.framework_notes = "Use PyMySQL parameterized queries: cursor.execute('SELECT * FROM table WHERE id=%s', (user_id,))"

        return recommendation

    def get_quick_fix(self, vulnerability: Vulnerability) -> Optional[str]:
        """
        Get a one-line fix suggestion for immediate action

        Args:
            vulnerability: The vulnerability

        Returns:
            Quick fix string or None
        """

        quick_fixes = {
            "injection": "Use parameterized queries: cursor.execute('SELECT * FROM table WHERE id=%s', (user_id,))",
            "xss": "Escape HTML output: html.escape(user_input)",
            "access": "Use pathlib: Path(base_path) / user_input",
            "secrets": "Move to environment variable: os.environ['SECRET_KEY']",
            "crypto": "Use hashlib.sha256() instead of hashlib.md5()"
        }

        vuln_category = getattr(vulnerability, 'category', 'unknown')
        return quick_fixes.get(vuln_category)

    def prioritize_fixes(self, recommendations: List[FixSuggestion]) -> List[FixSuggestion]:
        """
        Sort recommendations by priority and effort

        Args:
            recommendations: List of fix suggestions

        Returns:
            Sorted list with highest priority, lowest effort first
        """

        priority_order = {'immediate': 0, 'high': 1, 'medium': 2, 'low': 3}
        effort_order = {'minimal': 0, 'moderate': 1, 'significant': 2}

        def sort_key(rec: FixSuggestion) -> tuple:
            return (priority_order.get(rec.priority, 99), effort_order.get(rec.effort, 99))

        return sorted(recommendations, key=sort_key)

    def generate_fix_summary(self, vulnerability: Vulnerability) -> str:
        """
        Generate a human-readable fix summary

        Args:
            vulnerability: The vulnerability

        Returns:
            Formatted fix summary
        """

        recommendations = self.get_recommendations(vulnerability)
        quick_fix = self.get_quick_fix(vulnerability)

        summary = f"🔧 FIX SUMMARY: {vulnerability.title}\n\n"

        if quick_fix:
            summary += f"⚡ QUICK FIX: {quick_fix}\n\n"

        summary += "📋 RECOMMENDED SOLUTIONS:\n"

        prioritized = self.prioritize_fixes(recommendations)
        for i, rec in enumerate(prioritized[:3], 1):  # Show top 3
            summary += f"{i}. {rec.title} ({rec.priority} priority, {rec.effort} effort)\n"
            summary += f"   {rec.description}\n\n"

        if recommendations:
            summary += "💡 EXAMPLE IMPLEMENTATION:\n"
            summary += recommendations[0].code_example

        return summary
