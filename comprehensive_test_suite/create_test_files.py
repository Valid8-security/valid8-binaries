#!/usr/bin/env python3
"""
Create comprehensive test files with known vulnerabilities for all supported languages
"""

import os
import random
import string
from pathlib import Path

# Known vulnerabilities for each language
VULNERABILITIES = {
    'python': [
        ('CWE-78', 'subprocess.call(user_input, shell=True)'),
        ('CWE-79', 'return f"<div>{user_input}</div>"'),
        ('CWE-89', 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'),
        ('CWE-22', 'with open(filename, "r") as f:'),  # Path traversal potential
        ('CWE-502', 'import pickle; pickle.loads(data)'),
        ('CWE-327', 'import hashlib; hashlib.md5(data)'),  # Weak crypto
    ],
    'javascript': [
        ('CWE-79', 'document.write(userInput)'),
        ('CWE-89', 'db.query("SELECT * FROM users WHERE id = " + userId)'),
        ('CWE-22', 'fs.readFileSync(filename)'),  # Path traversal potential
        ('CWE-79', 'innerHTML = userInput'),
        ('CWE-200', 'console.log("Debug: " + sensitiveData)'),  # Info disclosure
        ('CWE-798', 'const apiKey = "hardcoded_key_123"'),  # Hardcoded secret
    ],
    'java': [
        ('CWE-89', 'stmt.executeQuery("SELECT * FROM users WHERE id = " + userId)'),
        ('CWE-79', 'out.println("<div>" + userInput + "</div>")'),
        ('CWE-22', 'new FileInputStream(filename)'),  # Path traversal potential
        ('CWE-502', 'ObjectInputStream ois = new ObjectInputStream(data)'),
        ('CWE-798', 'String password = "admin123"'),  # Hardcoded password
        ('CWE-200', 'log.info("User data: " + userData)'),  # Info disclosure
    ],
    'go': [
        ('CWE-89', 'db.Query("SELECT * FROM users WHERE id = " + userId)'),
        ('CWE-79', 'fmt.Sprintf("<div>%s</div>", userInput)'),
        ('CWE-22', 'ioutil.ReadFile(filename)'),  # Path traversal potential
        ('CWE-502', 'json.Unmarshal(data, &obj)'),  # Potential unsafe unmarshal
        ('CWE-798', 'const secretKey = "my_secret_key"'),  # Hardcoded secret
        ('CWE-200', 'log.Printf("Debug: %v", sensitiveData)'),  # Info disclosure
    ],
    'rust': [
        ('CWE-78', 'Command::new("sh").arg("-c").arg(&user_input).spawn()'),
        ('CWE-79', 'format!("<div>{}</div>", user_input)'),
        ('CWE-22', 'File::open(filename)'),  # Path traversal potential
        ('CWE-200', 'println!("Debug: {:?}", sensitive_data)'),  # Info disclosure
        ('CWE-798', 'const API_KEY: &str = "hardcoded_key"'),  # Hardcoded secret
        ('CWE-190', 'let result = a + b;'),  # Potential integer overflow
    ],
    'php': [
        ('CWE-89', 'mysql_query("SELECT * FROM users WHERE id = " . $userId)'),
        ('CWE-79', 'echo "<div>" . $userInput . "</div>"'),
        ('CWE-22', 'include($filename)'),  # Path traversal potential
        ('CWE-502', 'unserialize($data)'),
        ('CWE-798', '$password = "admin123"'),  # Hardcoded password
        ('CWE-200', 'error_log("Debug: " . $sensitiveData)'),  # Info disclosure
    ],
    'cpp': [
        ('CWE-78', 'system(user_input.c_str())'),
        ('CWE-79', 'sprintf(buffer, "<div>%s</div>", user_input)'),
        ('CWE-22', 'ifstream file(filename)'),  # Path traversal potential
        ('CWE-119', 'strcpy(buffer, user_input)'),  # Buffer overflow
        ('CWE-200', 'cout << "Debug: " << sensitive_data << endl'),  # Info disclosure
        ('CWE-798', 'const char* key = "hardcoded_key"'),  # Hardcoded secret
    ],
    'ruby': [
        ('CWE-89', 'db.execute("SELECT * FROM users WHERE id = #{user_id}")'),
        ('CWE-79', '"<div>#{user_input}</div>"'),
        ('CWE-22', 'File.open(filename)'),  # Path traversal potential
        ('CWE-502', 'Marshal.load(data)'),
        ('CWE-798', 'PASSWORD = "admin123"'),  # Hardcoded password
        ('CWE-200', 'puts "Debug: #{sensitive_data}"'),  # Info disclosure
    ]
}

def generate_random_code(lines=100):
    """Generate random, non-vulnerable code to pad file size"""
    code_lines = []
    for _ in range(lines):
        # Generate random variable assignments and function calls
        var_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        if random.choice([True, False]):
            code_lines.append(f'{var_name} = {random.randint(1, 100)}')
        else:
            code_lines.append(f'print({var_name})')
    return '\n'.join(code_lines)

def create_test_file(language, size_category, vuln_count=5):
    """Create a test file with known vulnerabilities"""
    
    base_dir = Path(f'comprehensive_test_suite/{size_category}/{language}')
    base_dir.mkdir(parents=True, exist_ok=True)
    
    # Determine file size
    if size_category == 'small':
        total_lines = 50
        vuln_lines = [10, 20, 30, 40, 50]
    elif size_category == 'medium':
        total_lines = 500
        vuln_lines = [50, 150, 250, 350, 450]
    elif size_category == 'large':
        total_lines = 5000
        vuln_lines = [500, 1500, 2500, 3500, 4500]
    else:  # huge
        total_lines = 50000
        vuln_lines = [5000, 15000, 25000, 35000, 45000]
    
    # File extension
    extensions = {
        'python': '.py',
        'javascript': '.js',
        'java': '.java',
        'go': '.go',
        'rust': '.rs',
        'php': '.php',
        'cpp': '.cpp',
        'ruby': '.rb'
    }
    
    filename = f'test_{language}_{size_category}{extensions[language]}'
    filepath = base_dir / filename
    
    # Generate file content
    lines = []
    vuln_index = 0
    
    for i in range(total_lines):
        if vuln_index < len(vuln_lines) and i == vuln_lines[vuln_index] - 1:
            # Insert vulnerability
            vuln_code = VULNERABILITIES[language][vuln_index % len(VULNERABILITIES[language])][1]
            lines.append(f'# Line {i+1}: Known vulnerability')
            lines.append(f'{vuln_code}  # CWE-{VULNERABILITIES[language][vuln_index % len(VULNERABILITIES[language])][0]}')
            vuln_index += 1
        else:
            # Generate random code
            if random.random() < 0.1:  # 10% chance of actual code
                lines.append(generate_random_code(1))
            else:
                lines.append(f'# Line {i+1}: Normal code')
    
    # Write file
    with open(filepath, 'w') as f:
        f.write('\n'.join(lines))
    
    print(f'Created {filepath} with {total_lines} lines and {vuln_index} vulnerabilities')

def create_all_test_files():
    """Create test files for all combinations"""
    languages = ['python', 'javascript', 'java', 'go', 'rust', 'php', 'cpp', 'ruby']
    sizes = ['small', 'medium', 'large', 'huge']
    
    for language in languages:
        for size in sizes:
            create_test_file(language, size)

if __name__ == '__main__':
    create_all_test_files()
