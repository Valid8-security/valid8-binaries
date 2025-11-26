#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Bandit integration for Python security linting.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any

class BanditDetector:
    """Integrate Bandit for Python security analysis."""
    
    CWE_MAPPING = {
        "B101": "CWE-703",  # Assert used
        "B102": "CWE-703",  # Exec used
        "B103": "CWE-703",  # Set bad file permissions
        "B104": "CWE-400",  # Hardcoded bind all interfaces
        "B105": "CWE-798",  # Hardcoded password
        "B106": "CWE-798",  # Hardcoded password
        "B107": "CWE-798",  # Hardcoded password
        "B108": "CWE-400",  # Hardcoded temp file
        "B109": "CWE-400",  # Password in URL
        "B110": "CWE-400",  # Try except pass
        "B111": "CWE-400",  # Execute with run
        "B112": "CWE-400",  # Try except continue
        "B201": "CWE-327",  # Flask debug true
        "B202": "CWE-200",  # Flask debug true
        "B301": "CWE-502",  # Pickle usage
        "B302": "CWE-502",  # Pickle usage
        "B303": "CWE-502",  # Pickle usage
        "B304": "CWE-502",  # Pickle usage
        "B305": "CWE-502",  # Pickle usage
        "B306": "CWE-502",  # Pickle usage
        "B307": "CWE-78",   # Eval usage
        "B308": "CWE-78",   # Mark safe usage
        "B309": "CWE-78",   # HTTPS connection
        "B310": "CWE-78",   # Blacklist calls
        "B311": "CWE-338",  # Random usage
        "B312": "CWE-400",  # Telnet usage
        "B313": "CWE-400",  # XML bad cElementTree
        "B314": "CWE-400",  # XML bad ElementTree
        "B315": "CWE-400",  # XML bad expatreader
        "B316": "CWE-400",  # XML bad expatbuilder
        "B317": "CWE-400",  # XML bad pulldom
        "B318": "CWE-400",  # XML bad minidom
        "B319": "CWE-400",  # XML bad sax
        "B320": "CWE-400",  # XML bad etree
        "B321": "CWE-400",  # FTP usage
        "B322": "CWE-400",  # Input usage
        "B323": "CWE-400",  # Unverified context
        "B324": "CWE-400",  # Hashlib insecure
        "B325": "CWE-400",  # Temp file creation
        "B401": "CWE-327",  # Import telnetlib
        "B402": "CWE-327",  # Import ftplib
        "B403": "CWE-327",  # Import pickle
        "B404": "CWE-327",  # Import subprocess
        "B405": "CWE-327",  # Import xml etree
        "B406": "CWE-327",  # Import xml sax
        "B407": "CWE-327",  # Import xml expat
        "B408": "CWE-327",  # Import xml minidom
        "B409": "CWE-327",  # Import xml pulldom
        "B410": "CWE-327",  # Import lxml
        "B411": "CWE-327",  # Import xmlrpc
        "B412": "CWE-327",  # Import httpoxy
        "B413": "CWE-327",  # Import requests
        "B414": "CWE-400",  # Import logging
        "B415": "CWE-400",  # Import os
        "B416": "CWE-400",  # Import sys
        "B417": "CWE-400",  # Import re
        "B418": "CWE-400",  # Import urlopen
        "B419": "CWE-400",  # Import urllib
        "B420": "CWE-400",  # Import urllib2
        "B421": "CWE-400",  # Import urllib3
        "B422": "CWE-400",  # Import httplib
        "B423": "CWE-400",  # Import six.moves.urllib
        "B501": "CWE-327",  # Request with no cert validation
        "B502": "CWE-327",  # SSL with bad defaults
        "B503": "CWE-327",  # SSL with bad version
        "B504": "CWE-327",  # SSL with weak ciphers
        "B505": "CWE-327",  # Weak cryptographic key
        "B506": "CWE-327",  # Unsafe yaml load
        "B507": "CWE-327",  # Unsafe yaml load
        "B508": "CWE-327",  # Unsafe yaml load
        "B509": "CWE-327",  # Unsafe yaml load
        "B601": "CWE-78",   # Shell true
        "B602": "CWE-78",   # Subprocess without shell
        "B603": "CWE-78",   # Subprocess without shell
        "B604": "CWE-78",   # Call with shell
        "B605": "CWE-78",   # Start process with shell
        "B606": "CWE-78",   # Start process with shell
        "B607": "CWE-78",   # Start process with partial path
        "B608": "CWE-89",   # SQL injection
        "B609": "CWE-89",   # SQL injection
        "B610": "CWE-89",   # SQL injection
        "B611": "CWE-89",   # SQL injection
        "B612": "CWE-89",   # SQL injection
        "B613": "CWE-89",   # SQL injection
        "B614": "CWE-89",   # SQL injection
        "B615": "CWE-89",   # SQL injection
        "B616": "CWE-89",   # SQL injection
        "B617": "CWE-89",   # SQL injection
        "B701": "CWE-79",   # XSS
        "B702": "CWE-79",   # XSS
        "B703": "CWE-79",   # XSS
    }
    
    def scan_code_string(self, code: str, filepath: str) -> List[Dict]:
        """Scan code string with Bandit."""
        vulnerabilities = []
        
        try:
            # Write to temp file and scan
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(code)
                temp_path = f.name
            
            # Run bandit on the file
            cmd = [
                "bandit", "-f", "json", "-o", "-", temp_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode in [0, 1] and result.stdout:
                data = json.loads(result.stdout)
                for finding in data.get("results", []):
                    test_id = finding.get("test_id", "")
                    cwe = self.CWE_MAPPING.get(test_id, "CWE-UNKNOWN")
                    
                    vuln = {
                        "cwe": cwe,
                        "severity": finding.get("issue_severity", "medium").upper(),
                        "title": f"Bandit: {test_id}",
                        "description": finding.get("issue_text", "Bandit finding"),
                        "file_path": filepath,
                        "line_number": finding.get("line_number", 1),
                        "code_snippet": finding.get("line_range", [1])[0] if finding.get("line_range") else "",
                        "confidence": 0.85  # Bandit has good accuracy
                    }
                    vulnerabilities.append(vuln)
                    
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            # If bandit not available, return empty
            pass
        finally:
            try:
                Path(temp_path).unlink()
            except:
                pass
            
        return vulnerabilities
