"""
Semgrep integration for high-precision vulnerability detection.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any

class SemgrepDetector:
    """Integrate Semgrep for advanced pattern matching."""
    
    def __init__(self):
        self.rules_path = Path(__file__).parent / "semgrep_rules"
        self.rules_path.mkdir(exist_ok=True)
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Set up default Semgrep rules for common vulnerabilities."""
        rules = {
            "python-sql-injection": {
                "rules": [
                    {
                        "id": "python-sql-injection-exec",
                        "pattern": '$DB.execute(f"...{$VAR}...")',
                        "message": "Potential SQL injection via f-string formatting",
                        "cwe": "CWE-89",
                        "severity": "HIGH"
                    },
                    {
                        "id": "python-sql-injection-format",
                        "pattern": '$DB.execute("...%s..." % $VAR)',
                        "message": "Potential SQL injection via string formatting",
                        "cwe": "CWE-89", 
                        "severity": "HIGH"
                    }
                ]
            }
        }
        
        for category, data in rules.items():
            rule_file = self.rules_path / f"{category}.yml"
            if not rule_file.exists():
                yaml_content = "rules:\n"
                for rule in data["rules"]:
                    yaml_content += f"""- id: {rule["id"]}
  pattern: {rule["pattern"]}
  message: {rule["message"]}
  severity: {rule["severity"]}
  metadata:
    cwe: {rule["cwe"]}

"""
                rule_file.write_text(yaml_content)
    
    def scan_code_string(self, code: str, filepath: str) -> List[Dict]:
        """Scan code string with Semgrep."""
        vulnerabilities = []
        
        try:
            # Write to temp file and scan
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(code)
                temp_path = f.name
            
            # Run semgrep on the file
            cmd = [
                "semgrep", "--json", "--config", str(self.rules_path),
                temp_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                for finding in data.get("results", []):
                    vuln = {
                        "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe", "CWE-UNKNOWN"),
                        "severity": finding.get("extra", {}).get("severity", "medium").upper(),
                        "title": f"Semgrep: {finding.get('check_id', 'Unknown')}",
                        "description": finding.get("extra", {}).get("message", "Semgrep finding"),
                        "file_path": filepath,
                        "line_number": finding.get("start", {}).get("line", 1),
                        "code_snippet": finding.get("extra", {}).get("lines", ""),
                        "confidence": 0.9
                    }
                    vulnerabilities.append(vuln)
                    
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            # If semgrep not available, return empty
            pass
        finally:
            try:
                Path(temp_path).unlink()
            except:
                pass
            
        return vulnerabilities
