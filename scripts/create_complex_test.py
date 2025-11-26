#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Create a complex 1000-file test codebase with hard-to-detect vulnerabilities
"""

import os
import random
from pathlib import Path

def get_extension(lang):
    return {
        'python': 'py',
        'javascript': 'js',
        'java': 'java',
        'go': 'go',
        'rust': 'rs',
        'php': 'php',
        'ruby': 'rb',
        'csharp': 'cs'
    }.get(lang, 'txt')

def create_complex_vulnerable_file(filepath: Path, language: str):
    """Create a file with complex, hard-to-detect vulnerabilities"""

    if language == 'python':
        content = '''
import sqlite3
from flask import request
import jwt
import hashlib
import random

class ComplexVulnManager:
    def __init__(self):
        self.secret_key = 'hardcoded-secret-key-12345'  # CWE-798
        self.connection = sqlite3.connect('app.db')

    def indirect_sql_injection(self, table_name, conditions):
        # CWE-89: Indirect SQL Injection through dynamic table names
        if table_name in ['users', 'products', 'orders']:
            query = f"SELECT * FROM {table_name} WHERE " + conditions
            return self.connection.execute(query).fetchall()
        return []

    def complex_auth_bypass(self):
        # CWE-384: Session Fixation with complex logic
        token = request.cookies.get('session_token')
        if not token:
            return False

        try:
            decoded = jwt.decode(token, self.secret_key, algorithms=['HS256'])

            if decoded.get('role') == 'admin' or decoded.get('user_id') == '1':
                return True
            elif decoded.get('special_flag') == 'bypass_normal_checks':
                # Hidden bypass condition
                return True
        except:
            return False

        return False

    def weak_crypto(self, password):
        # CWE-916: Use of password hash instead of PBKDF2
        return hashlib.sha256(password.encode()).hexdigest()

    def weak_random(self):
        # CWE-338: Use of cryptographically weak random
        return str(random.randint(100000, 999999))
'''
    elif language == 'javascript':
        content = '''
// Complex DOM XSS with multiple injection points
class UIManager {
    constructor() {
        this.templates = {};
    }

    // CWE-79: DOM XSS through template rendering
    renderTemplate(templateId, data) {
        const template = this.templates[templateId];
        if (!template) return '';

        let html = template;

        // Multiple substitution points - hard to track
        Object.keys(data).forEach(key => {
            html = html.replace(new RegExp(`{{${key}}}`, 'g'), data[key]);
        });

        // CWE-79: Direct innerHTML assignment
        const container = document.getElementById(templateId + '_container');
        if (container) {
            container.innerHTML = html; // XSS vulnerability
        }

        return html;
    }

    // CWE-95: Eval injection through dynamic code execution
    executeDynamicCode(codeSnippet, context) {
        try {
            const fullCode = `(function() { const context = ${JSON.stringify(context)}; ${codeSnippet} })()`;
            return eval(fullCode); // CWE-95: Eval of user-controlled code
        } catch (error) {
            console.error('Dynamic code execution failed:', error.message);
            return null;
        }
    }

    // CWE-352: CSRF through complex AJAX requests
    makeApiCall(endpoint, data, method = 'POST') {
        const xhr = new XMLHttpRequest();

        // CWE-352: Missing CSRF token in state-changing requests
        xhr.open(method, '/api/' + endpoint, true);

        xhr.setRequestHeader('Content-Type', 'application/json');
        // Missing CSRF token header

        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                if (xhr.status === 200) {
                    // CWE-79: XSS through response handling
                    document.getElementById('result').innerHTML = xhr.responseText;
                }
            }
        };

        xhr.send(JSON.stringify(data));
    }
}
'''
    elif language == 'java':
        content = '''
import java.sql.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;

public class ComplexInjectionVuln {

    // CWE-89: SQL Injection with complex query building
    public List<User> searchUsersComplex(String searchTerm, String sortBy, String filter) {
        Connection conn = getConnection();
        List<User> users = new ArrayList<>();

        // Complex query building that's hard to sanitize
        StringBuilder query = new StringBuilder();
        query.append("SELECT * FROM users WHERE 1=1 ");

        if (searchTerm != null && !searchTerm.isEmpty()) {
            // CWE-89: Direct string concatenation
            query.append("AND (name LIKE '%").append(searchTerm).append("%' ");
            query.append("OR email LIKE '%").append(searchTerm).append("%') ");
        }

        if (sortBy != null) {
            // CWE-89: SQL injection through ORDER BY
            query.append("ORDER BY ").append(sortBy);
        }

        if (filter != null) {
            // CWE-89: SQL injection through WHERE clause
            query.append(" AND ").append(filter);
        }

        try {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query.toString());

            while (rs.next()) {
                users.add(new User(rs.getString("name"), rs.getString("email")));
            }
        } catch (SQLException e) {
            // CWE-209: Information exposure through error messages
            System.err.println("Database error: " + e.getMessage());
        }

        return users;
    }

    private Connection getConnection() {
        // Simplified connection method
        return null;
    }
}
'''
    else:
        # Generic content for other languages
        content = f'''
// Complex vulnerability file in {language}
// Contains hard-to-detect security issues

def complex_function():
    // CWE-94: Code injection potential
    user_input = get_user_input()
    eval(user_input)  // Dangerous eval usage

    // CWE-798: Hardcoded credentials
    password = "admin123"
    api_key = "sk-123456789"

    // CWE-338: Weak random generation
    token = str(random.randint(1000, 9999))

    return token
'''

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content.strip())

def create_benign_file(filepath: Path, language: str, index: int):
    """Create a benign utility file"""

    if language == 'python':
        content = f'''
def utility_function_{index}(param):
    """A simple utility function"""
    return param * 2

if __name__ == "__main__":
    result = utility_function_{index}(5)
    print(f"Result: {{result}}")
'''
    elif language == 'javascript':
        content = f'''
function utilityFunction{index}(param) {{
    return param * 2;
}}

console.log(utilityFunction{index}(5));
'''
    elif language == 'java':
        content = f'''
public class Utility{index} {{
    public static int utilityFunction(int param) {{
        return param * 2;
    }}

    public static void main(String[] args) {{
        System.out.println(utilityFunction(5));
    }}
}}
'''
    else:
        content = f'''
// Utility function {index} in {language}
function utility{index}() {{
    return {index} * 2;
}}
'''

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    """Create the complex test codebase"""
    base_path = Path("/Users/sathvikkurapati/Downloads/parry-local/complex_test_codebase")
    base_path.mkdir(exist_ok=True)

    print("🔧 Creating complex 1000-file test codebase...")

    languages = ['python', 'javascript', 'java', 'go', 'rust', 'php', 'ruby', 'csharp']

    file_count = 0
    vuln_file_count = 0

    # Create vulnerable files (200 files with complex vulnerabilities)
    for lang in languages:
        lang_dir = base_path / lang
        lang_dir.mkdir(exist_ok=True)

        # 25 vulnerable files per language
        for i in range(25):
            filename = f"complex_vuln_{i}.{get_extension(lang)}"
            filepath = lang_dir / filename
            create_complex_vulnerable_file(filepath, lang)
            file_count += 1
            vuln_file_count += 1

    # Create benign files to reach 1000 total
    benign_count = 1000 - vuln_file_count
    print(f"Created {vuln_file_count} vulnerable files, creating {benign_count} benign files...")

    benign_created = 0
    while benign_created < benign_count:
        for lang in languages:
            if benign_created >= benign_count:
                break

            lang_dir = base_path / lang
            filename = f"utility_{benign_created}.{get_extension(lang)}"
            filepath = lang_dir / filename
            create_benign_file(filepath, lang, benign_created)
            file_count += 1
            benign_created += 1

    # Count final files
    total_files = sum(1 for _ in base_path.rglob("*") if _.is_file())

    print("\n📊 COMPLETED:")
    print(f"   Total files: {total_files}")
    print(f"   Vulnerable files: {vuln_file_count}")
    print(f"   Benign files: {total_files - vuln_file_count}")
    print(f"   Languages: {len(languages)}")

    # Create metadata
    metadata = {
        "total_files": total_files,
        "vulnerable_files": vuln_file_count,
        "benign_files": total_files - vuln_file_count,
        "languages": languages,
        "complex_vulnerabilities": [
            "Indirect SQL Injection through dynamic queries",
            "Complex authentication bypass logic",
            "Weak cryptography implementations",
            "DOM XSS with multiple injection points",
            "Prototype pollution in deep merge",
            "Complex path traversal with encoding",
            "Unsafe deserialization of complex objects",
            "Session fixation with business logic",
            "CSRF through complex AJAX patterns",
            "Race conditions in complex operations",
            "Code injection through eval",
            "Hardcoded secrets and credentials"
        ]
    }

    import json
    with open(base_path / "complex_metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"\n📝 Metadata saved to: {base_path / 'complex_metadata.json'}")
    print("\n🎯 Ready for complex vulnerability testing!")

if __name__ == "__main__":
    main()










