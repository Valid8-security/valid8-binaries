#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Generate a test codebase with ~100 files containing various security vulnerabilities
for testing Parry hybrid mode performance and accuracy.
"""

import os
import random
from pathlib import Path
import json

# Test files with known vulnerabilities
TEST_FILES = {
    "python": [
        # SQL Injection
        ("sql_injection.py", """
import sqlite3

def vulnerable_query(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # CWE-89: SQL Injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()
"""),
        # XSS
        ("xss_vuln.py", """
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # CWE-79: Cross-Site Scripting
    return f'<h1>Search results for: {query}</h1>'
"""),
        # Command Injection
        ("command_injection.py", """
import subprocess
import os

def run_command(user_cmd):
    # CWE-78: Command Injection
    os.system(f"ls -la {user_cmd}")
"""),
        # Path Traversal
        ("path_traversal.py", """
def read_file(filename):
    # CWE-22: Path Traversal
    with open(filename, 'r') as f:
        return f.read()
"""),
        # Weak Cryptography
        ("weak_crypto.py", """
import hashlib

def hash_password(password):
    # CWE-327: Weak Cryptography
    return hashlib.md5(password.encode()).hexdigest()
"""),
        # Hardcoded Credentials
        ("hardcoded_creds.py", """
# CWE-798: Hardcoded Credentials
DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
"""),
    ],
    "javascript": [
        ("unsafe_eval.js", """
function executeCode(code) {
    // CWE-95: Eval Injection
    eval(code);
}
"""),
        ("innerHTML_vuln.js", """
function updateContent(data) {
    // CWE-79: XSS via innerHTML
    document.getElementById('content').innerHTML = data;
}
"""),
        ("weak_random.js", """
function generateToken() {
    // CWE-338: Weak Random Number Generation
    return Math.random().toString(36);
}
"""),
    ],
    "java": [
        ("sql_injection.java", """
import java.sql.*;

public class DatabaseHelper {
    public ResultSet getUser(String username) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass");
        // CWE-89: SQL Injection
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }
}
"""),
        ("weak_crypto.java", """
import java.security.MessageDigest;

public class CryptoUtils {
    public static String hashPassword(String password) {
        try {
            // CWE-327: Weak Cryptography
            MessageDigest md = MessageDigest.getInstance("MD5");
            return new String(md.digest(password.getBytes()));
        } catch (Exception e) {
            return null;
        }
    }
}
"""),
    ],
    "go": [
        ("sql_injection.go", """
package main

import (
    "database/sql"
    "fmt"
)

func getUser(db *sql.DB, username string) (*sql.Row, error) {
    // CWE-89: SQL Injection
    query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
    return db.QueryRow(query), nil
}
"""),
        ("weak_crypto.go", """
package main

import (
    "crypto/md5"
    "fmt"
)

func hashPassword(password string) string {
    // CWE-327: Weak Cryptography
    hash := md5.Sum([]byte(password))
    return fmt.Sprintf("%x", hash)
}
"""),
    ],
    "php": [
        ("sql_injection.php", """
<?php
function getUser($username) {
    $conn = mysqli_connect("localhost", "user", "pass", "db");
    // CWE-89: SQL Injection
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    return mysqli_query($conn, $query);
}
?>
"""),
        ("xss_vuln.php", """
<?php
$search = $_GET['q'];
// CWE-79: Cross-Site Scripting
echo "<h1>Search: " . $search . "</h1>";
?>
"""),
    ],
    "ruby": [
        ("sql_injection.rb", """
require 'sqlite3'

def get_user(username)
  db = SQLite3::Database.new 'test.db'
  # CWE-89: SQL Injection
  query = "SELECT * FROM users WHERE name = '#{username}'"
  db.execute(query)
end
"""),
        ("command_injection.rb", """
def run_cmd(cmd)
  # CWE-78: Command Injection
  system("ls #{cmd}")
end
"""),
    ],
    "rust": [
        ("unsafe_code.rs", """
fn read_file(filename: &str) -> String {
    // CWE-22: Path Traversal (simplified example)
    std::fs::read_to_string(filename).unwrap()
}

fn weak_hash(password: &str) -> String {
    // CWE-327: Weak Cryptography
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}
"""),
    ],
    "csharp": [
        ("sql_injection.cs", """
using System.Data.SqlClient;

public class DatabaseHelper
{
    public SqlDataReader GetUser(string username)
    {
        var conn = new SqlConnection("Server=localhost;Database=test;User Id=user;Password=pass;");
        // CWE-89: SQL Injection
        string query = $"SELECT * FROM users WHERE username = '{username}'";
        var cmd = new SqlCommand(query, conn);
        return cmd.ExecuteReader();
    }
}
"""),
    ],
}

def create_test_file(filepath: Path, content: str):
    """Create a test file with vulnerable code"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content.strip())

def generate_benign_files(base_path: Path, count: int):
    """Generate benign files to reach target count"""
    languages = ['python', 'javascript', 'java', 'go', 'php', 'ruby', 'rust', 'csharp']

    for i in range(count):
        lang = random.choice(languages)

        if lang == 'python':
            content = f"""
def calculate_sum(a, b):
    \"\"\"A simple function to calculate sum\"\"\"
    return a + b

def main():
    result = calculate_sum(5, 3)
    print(f"Result: {{result}}")

if __name__ == "__main__":
    main()
"""
            filename = f"benign_{i}.py"

        elif lang == 'javascript':
            content = """
function calculateSum(a, b) {
    return a + b;
}

function main() {
    const result = calculateSum(5, 3);
    console.log(`Result: ${result}`);
}

main();
"""
            filename = f"benign_{i}.js"

        elif lang == 'java':
            content = """
public class Calculator {
    public static int calculateSum(int a, int b) {
        return a + b;
    }

    public static void main(String[] args) {
        int result = calculateSum(5, 3);
        System.out.println("Result: " + result);
    }
}
"""
            filename = f"Calculator{i}.java"

        elif lang == 'go':
            content = """
package main

import "fmt"

func calculateSum(a, b int) int {
    return a + b
}

func main() {
    result := calculateSum(5, 3)
    fmt.Printf("Result: %d\\n", result)
}
"""
            filename = f"calculator{i}.go"

        elif lang == 'php':
            content = """
<?php
function calculate_sum($a, $b) {
    return $a + $b;
}

$result = calculate_sum(5, 3);
echo "Result: " . $result . "\\n";
?>
"""
            filename = f"calculator{i}.php"

        elif lang == 'ruby':
            content = """
def calculate_sum(a, b)
  a + b
end

result = calculate_sum(5, 3)
puts "Result: #{result}"
"""
            filename = f"calculator{i}.rb"

        elif lang == 'rust':
            content = """
fn calculate_sum(a: i32, b: i32) -> i32 {
    a + b
}

fn main() {
    let result = calculate_sum(5, 3);
    println!("Result: {}", result);
}
"""
            filename = f"calculator{i}.rs"

        else:  # csharp
            content = """
using System;

public class Calculator
{
    public static int CalculateSum(int a, int b)
    {
        return a + b;
    }

    public static void Main(string[] args)
    {
        int result = CalculateSum(5, 3);
        Console.WriteLine($"Result: {result}");
    }
}
"""
            filename = f"Calculator{i}.cs"

        create_test_file(base_path / filename, content)

def main():
    """Generate test codebase"""
    base_path = Path("/Users/sathvikkurapati/Downloads/parry-local/test_codebase")

    print("🧪 Generating test codebase with ~100 files...")

    # Create vulnerable files
    vuln_count = 0
    for lang, files in TEST_FILES.items():
        for filename, content in files:
            filepath = base_path / lang / filename
            create_test_file(filepath, content)
            vuln_count += 1
            print(f"✅ Created vulnerable file: {filepath}")

    # Create benign files to reach ~100 total
    total_target = 100
    benign_count = total_target - vuln_count
    generate_benign_files(base_path, benign_count)

    # Count total files created
    total_files = sum(1 for _ in base_path.rglob("*") if _.is_file())

    print("\n📊 Test Codebase Summary:")
    print(f"   Vulnerable files: {vuln_count}")
    print(f"   Benign files: {total_files - vuln_count}")
    print(f"   Total files: {total_files}")
    print(f"   Languages: {len(TEST_FILES)}")

    # Create metadata file
    metadata = {
        "total_files": total_files,
        "vulnerable_files": vuln_count,
        "benign_files": total_files - vuln_count,
        "languages": list(TEST_FILES.keys()),
        "vulnerabilities": [
            "SQL Injection (CWE-89)",
            "Cross-Site Scripting (CWE-79)",
            "Command Injection (CWE-78)",
            "Path Traversal (CWE-22)",
            "Weak Cryptography (CWE-327)",
            "Hardcoded Credentials (CWE-798)",
            "Eval Injection (CWE-95)",
            "Weak Random Generation (CWE-338)"
        ]
    }

    with open(base_path / "metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"📝 Metadata saved to: {base_path / 'metadata.json'}")
    print("🎯 Ready for testing Parry hybrid mode!")

if __name__ == "__main__":
    main()










