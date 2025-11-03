# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Patch Generator - Uses LLM to generate secure code fixes

This module provides functionality to automatically generate secure code
patches for detected vulnerabilities using a local LLM. It analyzes the
vulnerable code, generates fixes, and provides explanations.
"""

# Import Path for file system operations
from pathlib import Path
# Import typing utilities for type hints
from typing import Dict, Any, List
# Import LLM client for AI-powered fix generation
from parry.llm import LLMClient
# Import patch prompts for CWE-specific instructions
from parry.prompts import PATCH_PROMPTS


class PatchGenerator:
    """
    Generates secure code patches using local LLM
    
    This class uses an LLM (via Ollama) to analyze vulnerable code and
    generate secure fixes. It handles prompt construction, code extraction,
    and fallback to template-based fixes when needed.
    """
    
    def __init__(self, llm_client: LLMClient):
        """
        Initialize patch generator
        
        Args:
            llm_client: LLM client instance for generating patches
        """
        # Store reference to LLM client
        self.llm = llm_client
    
    def generate_patch(self, file_path: Path, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a secure patch for a vulnerability
        
        Reads the vulnerable file, extracts context around the vulnerable line,
        sends it to the LLM for analysis, and generates a secure fix with
        explanation.
        
        Args:
            file_path: Path to the vulnerable file
            vulnerability: Vulnerability dict from scanner containing CWE, line number, etc.
            
        Returns:
            Patch dict with original code, fixed code, and explanation
        """
        # Read file content
        # Read entire file as text (ignore encoding errors)
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        # Split content into lines for line number access
        lines = content.split("\n")
        
        # Get vulnerable line and context
        # Extract line number from vulnerability
        line_num = vulnerability["line_number"]
        # Calculate start of context window (5 lines before)
        start_line = max(0, line_num - 5)
        # Calculate end of context window (5 lines after)
        end_line = min(len(lines), line_num + 5)
        
        # Extract context window around vulnerable line
        context = "\n".join(lines[start_line:end_line])
        # Extract the vulnerable line itself
        vulnerable_line = lines[line_num - 1] if line_num <= len(lines) else ""
        
        # Build prompt based on CWE
        # Get CWE identifier
        cwe = vulnerability["cwe"]
        # Construct LLM prompt with vulnerability details
        prompt = self._build_prompt(
            cwe=cwe,  # CWE identifier
            file_path=file_path,  # File being fixed
            vulnerable_line=vulnerable_line,  # The vulnerable code
            context=context,  # Surrounding code
            vulnerability=vulnerability  # Full vulnerability details
        )
        
        # Generate fix using LLM
        try:
            # Send prompt to LLM and get fix
            fixed_code = self.llm.generate(prompt)
            
            # Extract code from response (remove markdown if present)
            # Clean up LLM response to get just the code
            fixed_code = self._extract_code(fixed_code)
            
        # Catch any LLM errors
        except Exception as e:
            # Fallback to template-based fix
            # Use pre-defined templates if LLM fails
            fixed_code = self._template_fix(cwe, vulnerable_line)
        
        # Return patch dictionary
        return {
            "cwe": cwe,  # CWE identifier
            "severity": vulnerability["severity"],  # Severity level
            "file_path": str(file_path),  # File path as string
            "line_number": line_num,  # Line number of vulnerability
            "original_code": vulnerable_line,  # Original vulnerable code
            "fixed_code": fixed_code,  # Generated secure code
            "explanation": self._get_explanation(cwe),  # Human-readable explanation
            "confidence": "medium"  # Confidence level of fix
        }
    
    def _build_prompt(self, cwe: str, file_path: Path, vulnerable_line: str, 
                     context: str, vulnerability: Dict[str, Any]) -> str:
        """
        Build LLM prompt for patch generation
        
        Constructs a detailed prompt for the LLM including vulnerability type,
        vulnerable code, context, and CWE-specific instructions.
        
        Args:
            cwe: CWE identifier
            file_path: Path to vulnerable file
            vulnerable_line: The vulnerable line of code
            context: Surrounding code context
            vulnerability: Full vulnerability dictionary
            
        Returns:
            Formatted prompt string for LLM
        """
        
        # Get CWE-specific prompt template
        # Retrieve template for this CWE, or use default
        template = PATCH_PROMPTS.get(cwe, PATCH_PROMPTS["default"])
        
        # Detect programming language
        # Get file extension
        file_ext = file_path.suffix
        # Determine language from extension
        language = self._detect_language(file_ext)
        
        # Construct prompt with vulnerability details
        prompt = f"""You are a security-focused code assistant. Fix the following security vulnerability.

Language: {language}
Vulnerability: {vulnerability['title']} ({cwe})
Description: {vulnerability['description']}

Vulnerable code:
```
{vulnerable_line}
```

Context (surrounding code):
```
{context}
```

{template}

Provide ONLY the fixed code line without explanations or markdown. Keep the same indentation and style.
"""
        # Return constructed prompt
        return prompt
    
    def _detect_language(self, file_ext: str) -> str:
        """
        Detect programming language from file extension
        
        Maps file extensions to human-readable language names for
        inclusion in LLM prompts.
        
        Args:
            file_ext: File extension (e.g., ".py", ".js")
            
        Returns:
            Language name (e.g., "Python", "JavaScript")
        """
        # Map of file extensions to language names
        lang_map = {
            ".py": "Python",  # Python files
            ".js": "JavaScript",  # JavaScript files
            ".ts": "TypeScript",  # TypeScript files
            ".jsx": "React JSX",  # React JavaScript
            ".tsx": "React TSX",  # React TypeScript
            ".java": "Java",  # Java files
            ".go": "Go",  # Go files
            ".rb": "Ruby",  # Ruby files
            ".php": "PHP",  # PHP files
            ".cs": "C#",  # C# files
            ".cpp": "C++",  # C++ files
            ".c": "C",  # C files
            ".rs": "Rust",  # Rust files
            ".swift": "Swift",  # Swift files
            ".kt": "Kotlin",  # Kotlin files
        }
        # Return language name or "Unknown" if not found
        return lang_map.get(file_ext, "Unknown")
    
    def _extract_code(self, response: str) -> str:
        """
        Extract code from LLM response, removing markdown
        
        LLMs often wrap code in markdown blocks (```). This method
        extracts just the code, removing formatting and comments.
        
        Args:
            response: Raw response from LLM
            
        Returns:
            Extracted code string
        """
        # Import regex module for pattern matching
        import re
        
        # Try to extract code from markdown blocks
        # Look for code wrapped in ``` markers
        code_blocks = re.findall(r'```(?:\w+)?\n(.*?)\n```', response, re.DOTALL)
        # Check if any code blocks found
        if code_blocks:
            # Return first code block (stripped)
            return code_blocks[0].strip()
        
        # Try to extract single-line code
        # Split response into lines
        lines = response.split("\n")
        # Iterate through lines
        for line in lines:
            # Check if line has content and isn't a comment
            if line.strip() and not line.startswith("#") and not line.startswith("//"):
                # Return first non-comment line
                return line.strip()
        
        # Fallback: return entire response stripped
        return response.strip()
    
    def _template_fix(self, cwe: str, vulnerable_line: str) -> str:
        """
        Generate template-based fix when LLM fails
        
        Provides fallback fixes using simple string replacements for
        common vulnerability patterns. Used when LLM is unavailable or
        fails to generate a fix.
        
        Args:
            cwe: CWE identifier
            vulnerable_line: The vulnerable code line
            
        Returns:
            Fixed code using template replacement
        """
        
        # Simple template fixes based on CWE
        # Dictionary mapping CWE to fix lambda functions
        templates = {
            # CWE-89: SQL Injection - use prepared statements
            "CWE-89": lambda l: l.replace("execute(", "execute_prepared("),
            # CWE-79: XSS - use textContent instead of innerHTML
            "CWE-79": lambda l: l.replace("innerHTML", "textContent"),
            # CWE-798: Hardcoded credentials - use environment variables
            "CWE-798": lambda l: 'password = os.environ.get("PASSWORD")',
            # CWE-22: Path traversal - use basename to sanitize
            "CWE-22": lambda l: l.replace("open(", "open(os.path.basename("),
            # CWE-78: Command injection - use subprocess instead of system
            "CWE-78": lambda l: l.replace("os.system", "subprocess.run"),
        }
        
        # Get fix function for this CWE
        fix_fn = templates.get(cwe)
        # Check if template exists for this CWE
        if fix_fn:
            # Apply template fix
            return fix_fn(vulnerable_line)
        
        # No template available, add TODO comment
        return vulnerable_line + "  # TODO: Fix security vulnerability"
    
    def _get_explanation(self, cwe: str) -> str:
        """
        Get explanation for the fix
        
        Provides human-readable explanations of security fixes for
        common vulnerability types.
        
        Args:
            cwe: CWE identifier
            
        Returns:
            Explanation string describing the fix
        """
        # Dictionary of CWE-specific explanations
        explanations = {
            # SQL Injection fix explanation
            "CWE-89": "Use parameterized queries or prepared statements to prevent SQL injection.",
            # XSS fix explanation
            "CWE-79": "Use textContent or proper escaping to prevent XSS attacks.",
            # Hardcoded credentials fix explanation
            "CWE-798": "Store credentials in environment variables or secure vaults, never hardcode them.",
            # Path traversal fix explanation
            "CWE-22": "Validate and sanitize file paths to prevent directory traversal.",
            # Command injection fix explanation
            "CWE-78": "Use safe APIs like subprocess with argument lists instead of shell commands.",
            # Deserialization fix explanation
            "CWE-502": "Avoid deserializing untrusted data or use safe deserialization methods.",
            # Weak crypto fix explanation
            "CWE-327": "Use strong cryptographic algorithms like SHA-256 or AES.",
            # XXE fix explanation
            "CWE-611": "Disable external entity resolution in XML parsers.",
            # SSRF fix explanation
            "CWE-918": "Validate and whitelist URLs to prevent SSRF attacks.",
            # File permissions fix explanation
            "CWE-732": "Use restrictive file permissions (e.g., 644 for files, 755 for directories).",
        }
        # Return explanation for CWE or generic message
        return explanations.get(cwe, "Apply security best practices to fix this vulnerability.")
    
    def apply_patch(self, file_path: Path, patch: Dict[str, Any]) -> None:
        """
        Apply a patch to a file
        
        Writes the fixed code back to the file, replacing the vulnerable
        line with the secure version.
        
        Args:
            file_path: Path to the file to patch
            patch: Patch dict with line number, original code, and fixed code
        """
        # Read current file content
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        # Split into lines for line-by-line access
        lines = content.split("\n")
        
        # Get line number to patch
        line_num = patch["line_number"]
        # Check if line number is valid
        if line_num <= len(lines):
            # Replace the vulnerable line with fixed code
            lines[line_num - 1] = patch["fixed_code"]
            
            # Write back to file
            # Join lines and write to file
            file_path.write_text("\n".join(lines), encoding="utf-8")
    
    def generate_batch_patches(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate patches for multiple vulnerabilities
        
        Processes a list of vulnerabilities and generates patches for each,
        skipping any that fail.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of patch dictionaries
        """
        # Initialize list to collect patches
        patches = []
        
        # Iterate through all vulnerabilities
        for vuln in vulnerabilities:
            try:
                # Get file path from vulnerability
                file_path = Path(vuln["file_path"])
                # Generate patch for this vulnerability
                patch = self.generate_patch(file_path, vuln)
                # Add patch to list
                patches.append(patch)
            # Catch any errors
            except Exception as e:
                # Skip vulnerabilities that fail
                # Continue to next vulnerability
                continue
        
        # Return all generated patches
        return patches

