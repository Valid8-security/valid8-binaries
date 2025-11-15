"""
Dependency vulnerability checking using Safety and pip-audit.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any

class DependencyChecker:
    """Check for vulnerable dependencies in Python projects."""
    
    def check_requirements_file(self, requirements_path: str) -> List[Dict]:
        """Check requirements.txt for vulnerabilities."""
        vulnerabilities = []
        
        if not Path(requirements_path).exists():
            return vulnerabilities
        
        # Try Safety first
        try:
            cmd = ["safety", "check", "--json", "-r", requirements_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode in [0, 1] and result.stdout:
                data = json.loads(result.stdout)
                for vuln in data.get("vulnerable_packages", []):
                    vulnerability = {
                        "cwe": "CWE-937",  # OWASP vulnerable dependency
                        "severity": "HIGH",
                        "title": f"Vulnerable dependency: {vuln.get('package', 'unknown')}",
                        "description": f"Version {vuln.get('installed_version', 'unknown')} has known vulnerabilities",
                        "file_path": requirements_path,
                        "line_number": 1,  # Requirements files don't have line numbers
                        "code_snippet": f"{vuln.get('package', 'unknown')}=={vuln.get('installed_version', 'unknown')}",
                        "confidence": 0.95  # Safety DB is authoritative
                    }
                    vulnerabilities.append(vulnerability)
                    
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        
        # Try pip-audit as fallback
        try:
            cmd = ["pip-audit", "--format", "json", "-r", requirements_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                for vuln in data.get("vulnerabilities", []):
                    vulnerability = {
                        "cwe": "CWE-937",
                        "severity": "HIGH", 
                        "title": f"Vulnerable dependency: {vuln.get('name', 'unknown')}",
                        "description": vuln.get('description', 'Known vulnerability'),
                        "file_path": requirements_path,
                        "line_number": 1,
                        "code_snippet": f"{vuln.get('name', 'unknown')} {vuln.get('version', 'unknown')}",
                        "confidence": 0.95
                    }
                    vulnerabilities.append(vulnerability)
                    
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
            
        return vulnerabilities
    
    def check_project_dependencies(self, project_path: str) -> List[Dict]:
        """Check dependencies for a Python project."""
        vulnerabilities = []
        
        # Look for requirements files
        req_files = [
            Path(project_path) / "requirements.txt",
            Path(project_path) / "requirements-dev.txt", 
            Path(project_path) / "setup.py",
            Path(project_path) / "pyproject.toml"
        ]
        
        for req_file in req_files:
            if req_file.exists():
                vulns = self.check_requirements_file(str(req_file))
                vulnerabilities.extend(vulns)
                
        return vulnerabilities
    
    def scan_code_string(self, code: str, filepath: str) -> List[Dict]:
        """Scan code for import statements and check those dependencies."""
        vulnerabilities = []
        
        # Extract imports
        imports = set()
        lines = code.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                if 'import ' in line:
                    parts = line.split('import ')
                    if len(parts) > 1:
                        module = parts[1].split('.')[0].strip()
                        imports.add(module)
                elif 'from ' in line:
                    parts = line.split('from ')
                    if len(parts) > 1:
                        module = parts[1].split(' import')[0].split('.')[0].strip()
                        imports.add(module)
        
        # Check for known vulnerable packages
        vulnerable_packages = {
            'django': 'CWE-937',
            'flask': 'CWE-937', 
            'requests': 'CWE-937',
            'urllib3': 'CWE-937',
            'cryptography': 'CWE-327',
            'pycrypto': 'CWE-327',
            'paramiko': 'CWE-327',
            'pyjwt': 'CWE-327',
            'sqlalchemy': 'CWE-89',
            'psycopg2': 'CWE-89',
            'pymongo': 'CWE-89',
            'redis': 'CWE-200',
            'celery': 'CWE-400',
            'pillow': 'CWE-400',
            'numpy': 'CWE-400'
        }
        
        for imp in imports:
            if imp in vulnerable_packages:
                vuln = {
                    "cwe": vulnerable_packages[imp],
                    "severity": "MEDIUM",
                    "title": f"Potentially vulnerable import: {imp}",
                    "description": f"Import of {imp} detected - check for known vulnerabilities",
                    "file_path": filepath,
                    "line_number": 1,
                    "code_snippet": f"import {imp}",
                    "confidence": 0.6
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities
