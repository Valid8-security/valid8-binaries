# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Prompt templates for LLM-based vulnerability patching

This module contains CWE-specific prompt templates that guide the LLM in generating
secure code fixes. Each template includes:
- Explanation of the vulnerability
- Best practices for fixing it
- Code examples showing BAD and GOOD patterns

These prompts are used by the PatchGenerator to create context-aware fixes.
"""

PATCH_PROMPTS = {
    "CWE-89": """
Fix this SQL injection vulnerability by:
1. Using parameterized queries or prepared statements
2. Never concatenating user input directly into SQL
3. Using proper escaping if parameterization is not possible

Example:
BAD:  cursor.execute("SELECT * FROM users WHERE id = " + user_id)
GOOD: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
""",

    "CWE-79": """
Fix this XSS vulnerability by:
1. Using textContent instead of innerHTML
2. Properly escaping HTML entities
3. Using framework-specific safe rendering methods
4. Sanitizing user input before rendering

Example:
BAD:  element.innerHTML = userInput
GOOD: element.textContent = userInput
""",

    "CWE-798": """
Fix this hardcoded credential by:
1. Moving the credential to an environment variable
2. Using a secure configuration management system
3. Never committing secrets to version control

Example:
BAD:  password = "supersecret123"
GOOD: password = os.environ.get("DB_PASSWORD")
""",

    "CWE-22": """
Fix this path traversal vulnerability by:
1. Validating and sanitizing file paths
2. Using os.path.basename() to strip directory components
3. Checking that resolved paths stay within allowed directories
4. Using a whitelist of allowed files

Example:
BAD:  open(user_input)
GOOD: open(os.path.join(SAFE_DIR, os.path.basename(user_input)))
""",

    "CWE-78": """
Fix this command injection vulnerability by:
1. Using subprocess.run() with a list of arguments (not shell=True)
2. Avoiding os.system() and shell commands
3. Validating and sanitizing any user input
4. Using safe APIs provided by libraries

Example:
BAD:  os.system("ls " + user_input)
GOOD: subprocess.run(["ls", user_input], check=True)
""",

    "CWE-502": """
Fix this unsafe deserialization by:
1. Avoiding pickle.loads() on untrusted data
2. Using safer formats like JSON
3. Implementing strict validation
4. Using yaml.safe_load() instead of yaml.load()

Example:
BAD:  data = pickle.loads(user_input)
GOOD: data = json.loads(user_input)
""",

    "CWE-327": """
Fix this weak cryptography by:
1. Using SHA-256 or stronger hash functions
2. Avoiding MD5 and SHA-1
3. Using proper encryption algorithms (AES-256)
4. Following current cryptographic standards

Example:
BAD:  hash = hashlib.md5(data).hexdigest()
GOOD: hash = hashlib.sha256(data).hexdigest()
""",

    "CWE-611": """
Fix this XXE vulnerability by:
1. Disabling external entity resolution
2. Using defusedxml library
3. Setting parser options to prevent XXE

Example:
BAD:  tree = ET.parse(xml_file)
GOOD: parser = ET.XMLParser(resolve_entities=False)
      tree = ET.parse(xml_file, parser=parser)
""",

    "CWE-918": """
Fix this SSRF vulnerability by:
1. Validating and whitelisting URLs
2. Blocking internal IP ranges
3. Using URL parsing to check domains
4. Implementing proper access controls

Example:
BAD:  response = requests.get(user_url)
GOOD: if is_safe_url(user_url):
          response = requests.get(user_url)
""",

    "CWE-732": """
Fix this permission issue by:
1. Using restrictive file permissions
2. Setting mode to 0o644 for files, 0o755 for directories
3. Avoiding world-writable permissions (777)

Example:
BAD:  os.chmod(file_path, 0o777)
GOOD: os.chmod(file_path, 0o644)
""",

    "default": """
Fix this security vulnerability by:
1. Following security best practices for your language
2. Validating and sanitizing all user input
3. Using safe APIs and frameworks
4. Applying the principle of least privilege
"""
}


# SCAN_PROMPTS: Dictionary of prompts used for AI-powered vulnerability detection (--deep mode)
# These guide the LLM to analyze code for security issues and provide structured output
SCAN_PROMPTS = {
    "code_review": """
You are a security expert reviewing code for vulnerabilities.
Analyze the following code and identify security issues.

Code:
{code}

For each vulnerability found, provide:
- CWE classification
- Severity (low, medium, high, critical)
- Description of the issue
- Recommended fix
""",

    "cwe_detection": """
Analyze this code for CWE vulnerabilities:
- CWE-89: SQL Injection
- CWE-79: XSS
- CWE-798: Hardcoded Credentials
- CWE-22: Path Traversal
- CWE-78: Command Injection
- CWE-502: Unsafe Deserialization
- CWE-327: Weak Crypto
- CWE-611: XXE
- CWE-918: SSRF
- CWE-732: Wrong Permissions

Code:
{code}

List all detected vulnerabilities with line numbers.
""",
}


