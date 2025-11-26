#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Patch Generator - Uses LLM to generate secure code fixes
"""

from pathlib import Path
from typing import Dict, Any, List
from valid8.llm import LLMClient
from valid8.prompts import PATCH_PROMPTS


class PatchGenerator:
    """Generates secure code patches using local LLM"""
    
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
    
    def generate_patch(self, file_path: Path, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a secure patch for a vulnerability
        
        Args:
            file_path: Path to the vulnerable file
            vulnerability: Vulnerability dict from scanner
            
        Returns:
            Patch dict with original and fixed code
        """
        # Read file content
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.split("\n")
        
        # Get vulnerable line and context
        line_num = vulnerability["line_number"]
        start_line = max(0, line_num - 5)
        end_line = min(len(lines), line_num + 5)
        
        context = "\n".join(lines[start_line:end_line])
        vulnerable_line = lines[line_num - 1] if line_num <= len(lines) else ""
        
        # Build prompt based on CWE
        cwe = vulnerability["cwe"]
        prompt = self._build_prompt(
            cwe=cwe,
            file_path=file_path,
            vulnerable_line=vulnerable_line,
            context=context,
            vulnerability=vulnerability
        )
        
        # Generate fix using LLM
        try:
            fixed_code = self.llm.generate(prompt)
            
            # Extract code from response (remove markdown if present)
            fixed_code = self._extract_code(fixed_code)
            
        except Exception as e:
            # Fallback to template-based fix
            fixed_code = self._template_fix(cwe, vulnerable_line)
        
        return {
            "cwe": cwe,
            "severity": vulnerability["severity"],
            "file_path": str(file_path),
            "line_number": line_num,
            "original_code": vulnerable_line,
            "fixed_code": fixed_code,
            "explanation": self._get_explanation(cwe),
            "confidence": "medium"
        }
    
    def _build_prompt(self, cwe: str, file_path: Path, vulnerable_line: str, 
                     context: str, vulnerability: Dict[str, Any]) -> str:
        """Build LLM prompt for patch generation"""
        
        # Get CWE-specific prompt template
        template = PATCH_PROMPTS.get(cwe, PATCH_PROMPTS["default"])
        
        file_ext = file_path.suffix
        language = self._detect_language(file_ext)
        
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
        return prompt
    
    def _detect_language(self, file_ext: str) -> str:
        """Detect programming language from file extension"""
        lang_map = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".jsx": "React JSX",
            ".tsx": "React TSX",
            ".java": "Java",
            ".go": "Go",
            ".rb": "Ruby",
            ".php": "PHP",
            ".cs": "C#",
            ".cpp": "C++",
            ".c": "C",
            ".rs": "Rust",
            ".swift": "Swift",
            ".kt": "Kotlin",
        }
        return lang_map.get(file_ext, "Unknown")
    
    def _extract_code(self, response: str) -> str:
        """Extract code from LLM response, removing markdown"""
        import re
        
        # Try to extract code from markdown blocks
        code_blocks = re.findall(r'```(?:\w+)?\n(.*?)\n```', response, re.DOTALL)
        if code_blocks:
            return code_blocks[0].strip()
        
        # Try to extract single-line code
        lines = response.split("\n")
        for line in lines:
            if line.strip() and not line.startswith("#") and not line.startswith("//"):
                return line.strip()
        
        return response.strip()
    
    def _template_fix(self, cwe: str, vulnerable_line: str) -> str:
        """Generate template-based fix when LLM fails"""
        
        # Simple template fixes based on CWE
        templates = {
            "CWE-89": lambda l: l.replace("execute(", "execute_prepared("),
            "CWE-79": lambda l: l.replace("innerHTML", "textContent"),
            "CWE-798": lambda l: 'password = os.environ.get("PASSWORD")',
            "CWE-22": lambda l: l.replace("open(", "open(os.path.basename("),
            "CWE-78": lambda l: l.replace("os.system", "subprocess.run"),
        }
        
        fix_fn = templates.get(cwe)
        if fix_fn:
            return fix_fn(vulnerable_line)
        
        return vulnerable_line + "  # TODO: Fix security vulnerability"
    
    def _get_explanation(self, cwe: str) -> str:
        """Get explanation for the fix"""
        explanations = {
            "CWE-89": "Use parameterized queries or prepared statements to prevent SQL injection.",
            "CWE-79": "Use textContent or proper escaping to prevent XSS attacks.",
            "CWE-798": "Store credentials in environment variables or secure vaults, never hardcode them.",
            "CWE-22": "Validate and sanitize file paths to prevent directory traversal.",
            "CWE-78": "Use safe APIs like subprocess with argument lists instead of shell commands.",
            "CWE-502": "Avoid deserializing untrusted data or use safe deserialization methods.",
            "CWE-327": "Use strong cryptographic algorithms like SHA-256 or AES.",
            "CWE-611": "Disable external entity resolution in XML parsers.",
            "CWE-918": "Validate and whitelist URLs to prevent SSRF attacks.",
            "CWE-732": "Use restrictive file permissions (e.g., 644 for files, 755 for directories).",
        }
        return explanations.get(cwe, "Apply security best practices to fix this vulnerability.")
    
    def apply_patch(self, file_path: Path, patch: Dict[str, Any]) -> None:
        """
        Apply a patch to a file
        
        Args:
            file_path: Path to the file
            patch: Patch dict with original and fixed code
        """
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.split("\n")
        
        line_num = patch["line_number"]
        if line_num <= len(lines):
            # Replace the vulnerable line
            lines[line_num - 1] = patch["fixed_code"]
            
            # Write back to file
            file_path.write_text("\n".join(lines), encoding="utf-8")
    
    def generate_batch_patches(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate patches for multiple vulnerabilities"""
        patches = []
        
        for vuln in vulnerabilities:
            try:
                file_path = Path(vuln["file_path"])
                patch = self.generate_patch(file_path, vuln)
                patches.append(patch)
            except Exception as e:
                # Skip vulnerabilities that fail
                continue
        
        return patches


