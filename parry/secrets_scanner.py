# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Advanced Secrets Scanner with Entropy Analysis

Detects hardcoded secrets, API keys, passwords, tokens, and other sensitive information
using multiple techniques:
- Pattern matching (regex)
- Entropy analysis (Shannon entropy)
- Context analysis
- Base64 detection
- Common secret formats
"""

import re
import math
import base64
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Secret:
    """Detected secret"""
    type: str
    value: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float
    entropy: float
    context: str


class EntropyAnalyzer:
    """Calculate Shannon entropy for strings"""
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Higher entropy indicates more random/complex strings (likely secrets)
        Typical entropy ranges:
        - < 3.0: Low (e.g., "password", "admin")
        - 3.0-4.0: Medium (e.g., "MyP@ssw0rd")
        - 4.0-5.0: High (e.g., "aB3$xY9@mK")
        - > 5.0: Very high (e.g., API keys, tokens)
        """
        if not data:
            return 0.0
        
        # Calculate frequency of each character
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in freq.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def is_high_entropy(data: str, min_entropy: float = 4.5) -> bool:
        """Check if string has high entropy (likely a secret)"""
        if len(data) < 8:  # Too short to be meaningful
            return False
        
        entropy = EntropyAnalyzer.calculate_entropy(data)
        return entropy >= min_entropy
    
    @staticmethod
    def is_base64(data: str) -> bool:
        """Check if string is valid base64"""
        if len(data) < 16:  # Too short
            return False
        
        # Base64 pattern
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
        if not base64_pattern.match(data):
            return False
        
        # Try to decode
        try:
            decoded = base64.b64decode(data)
            # Check if it decodes to printable characters
            return all(32 <= byte < 127 or byte in [9, 10, 13] for byte in decoded[:50])
        except Exception:
            return False


class SecretPatterns:
    """Secret detection patterns"""
    
    # API Keys and Tokens
    API_KEYS = [
        (r'(?i)(api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API Key', 0.9),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Secret Key', 0.9),
        (r'(?i)(access[_-]?token|accesstoken)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'Access Token', 0.9),
        (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI/Stripe Secret Key', 0.95),
        (r'pk_live_[a-zA-Z0-9]{20,}', 'Stripe Publishable Key', 0.95),
        (r'sk_live_[a-zA-Z0-9]{20,}', 'Stripe Secret Key', 0.95),
    ]
    
    # AWS Credentials
    AWS_PATTERNS = [
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 0.95),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[=:]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Access Key', 0.9),
        (r'(?i)aws[_-]?session[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9/+=]{100,})["\']', 'AWS Session Token', 0.85),
    ]
    
    # Cloud Provider Keys
    CLOUD_KEYS = [
        (r'AIza[0-9A-Za-z_\-]{35}', 'Google API Key', 0.9),
        (r'ya29\.[0-9A-Za-z_\-]{68,}', 'Google OAuth Token', 0.9),
        (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 'Google OAuth Client ID', 0.85),
        (r'sq0atp-[0-9A-Za-z\-_]{22}', 'Square Access Token', 0.9),
        (r'sq0csp-[0-9A-Za-z\-_]{43}', 'Square OAuth Secret', 0.9),
    ]
    
    # Database Credentials
    DATABASE_PATTERNS = [
        (r'(?i)(database[_-]?password|db[_-]?password|db[_-]?pass)\s*[=:]\s*["\']([^"\']{6,})["\']', 'Database Password', 0.85),
        (r'(?i)(mysql|postgres|postgresql|mongodb)[_-]?password\s*[=:]\s*["\']([^"\']{6,})["\']', 'Database Password', 0.85),
        (r'(mongodb(\+srv)?://[^:]+:)([^@]+)(@[^/]+)', 'MongoDB Connection String', 0.9),
        (r'(postgres(?:ql)?://[^:]+:)([^@]+)(@[^/]+)', 'PostgreSQL Connection String', 0.9),
    ]
    
    # Generic Passwords
    PASSWORD_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', 'Password', 0.7),
        (r'(?i)(pass|password)["\']?\s*:\s*["\']([^"\']{6,})["\']', 'Password', 0.7),
    ]
    
    # Private Keys
    PRIVATE_KEYS = [
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----', 'Private Key', 0.95),
        (r'-----BEGIN (RSA |EC |DSA )?ENCRYPTED PRIVATE KEY-----', 'Encrypted Private Key', 0.95),
    ]
    
    # Tokens
    TOKEN_PATTERNS = [
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token', 0.95),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token', 0.95),
        (r'ghs_[a-zA-Z0-9]{36}', 'GitHub App Token', 0.95),
        (r'xox[pbar]-[a-zA-Z0-9-]{50,}', 'Slack Token', 0.9),
        (r'[0-9]{10}:[a-zA-Z0-9_-]{35}', 'Telegram Bot Token', 0.9),
    ]
    
    # JWT Tokens
    JWT_PATTERN = (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT Token', 0.85)
    
    # Generic High-Entropy Strings (catch-all for unknown secrets)
    GENERIC_SECRET = (r'(?i)(secret|token|key|password|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-\+\/=]{32,})["\']', 'Generic Secret', 0.6)


class AdvancedSecretsScanner:
    """Advanced secrets scanner with entropy analysis"""
    
    def __init__(self, min_entropy: float = 4.5, check_entropy: bool = True):
        """
        Initialize scanner
        
        Args:
            min_entropy: Minimum entropy threshold for high-entropy detection
            check_entropy: Whether to perform entropy analysis
        """
        self.min_entropy = min_entropy
        self.check_entropy = check_entropy
        self.entropy_analyzer = EntropyAnalyzer()
        self.patterns = SecretPatterns()
        
        # Compile all patterns
        self.compiled_patterns = self._compile_patterns()
        
        # False positive filters (common non-secrets)
        self.false_positive_patterns = [
            r'^[xX]+$',  # All X's (placeholder)
            r'^[*]+$',  # All asterisks (masked)
            r'^(your|my|test|example|sample|demo)',  # Common placeholders
            r'^\$\{.*\}$',  # Environment variable reference
            r'^<.*>$',  # XML/HTML tag or placeholder
            r'^(true|false|null|undefined|none)$',  # Literals
        ]
    
    def _compile_patterns(self) -> List[Tuple[re.Pattern, str, float]]:
        """Compile all regex patterns"""
        all_patterns = (
            self.patterns.API_KEYS +
            self.patterns.AWS_PATTERNS +
            self.patterns.CLOUD_KEYS +
            self.patterns.DATABASE_PATTERNS +
            self.patterns.PASSWORD_PATTERNS +
            self.patterns.PRIVATE_KEYS +
            self.patterns.TOKEN_PATTERNS +
            [self.patterns.JWT_PATTERN, self.patterns.GENERIC_SECRET]
        )
        
        return [(re.compile(pattern), name, confidence) for pattern, name, confidence in all_patterns]
    
    def is_false_positive(self, value: str) -> bool:
        """Check if value is likely a false positive"""
        value_lower = value.lower()
        
        # Check against false positive patterns
        for pattern in self.false_positive_patterns:
            if re.match(pattern, value_lower):
                return True
        
        # Check if it's a common placeholder
        placeholders = ['password', 'secret', 'token', 'key', 'example', 'test', 'demo', 'sample']
        if value_lower in placeholders:
            return True
        
        # Check if it's too short
        if len(value) < 6:
            return True
        
        return False
    
    def scan_line(self, line: str, line_number: int, filepath: str) -> List[Secret]:
        """Scan a single line for secrets"""
        secrets = []
        
        # Skip comments (basic detection)
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
            return secrets
        
        # Pattern matching
        for pattern, secret_type, base_confidence in self.compiled_patterns:
            matches = pattern.finditer(line)
            for match in matches:
                # Extract the secret value (usually in group 2, sometimes group 0)
                try:
                    secret_value = match.group(2) if match.groups() and len(match.groups()) >= 2 else match.group(0)
                except IndexError:
                    secret_value = match.group(0)
                
                # Skip false positives
                if self.is_false_positive(secret_value):
                    continue
                
                # Calculate entropy
                entropy = self.entropy_analyzer.calculate_entropy(secret_value)
                
                # Adjust confidence based on entropy
                confidence = base_confidence
                if self.check_entropy:
                    if entropy >= 5.0:
                        confidence = min(0.95, confidence + 0.1)
                    elif entropy < 3.0:
                        confidence = max(0.3, confidence - 0.2)
                
                # Check if base64
                is_b64 = self.entropy_analyzer.is_base64(secret_value)
                if is_b64:
                    confidence = min(0.95, confidence + 0.05)
                    secret_type += " (Base64)"
                
                # Extract context (surrounding code)
                context = line.strip()
                
                secrets.append(Secret(
                    type=secret_type,
                    value=secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
                    file_path=filepath,
                    line_number=line_number,
                    code_snippet=context,
                    confidence=round(confidence, 2),
                    entropy=round(entropy, 2),
                    context=context
                ))
        
        # High-entropy string detection (catch-all for unknown secret formats)
        if self.check_entropy:
            # Look for potential secrets using word boundaries
            words = re.findall(r'["\']([a-zA-Z0-9_\-\+\/=]{16,})["\']', line)
            for word in words:
                if self.is_false_positive(word):
                    continue
                
                # Skip if already detected by pattern matching
                if any(secret.value.startswith(word[:20]) for secret in secrets):
                    continue
                
                if self.entropy_analyzer.is_high_entropy(word, self.min_entropy):
                    entropy = self.entropy_analyzer.calculate_entropy(word)
                    
                    # Determine type based on context
                    secret_type = "High-Entropy String"
                    if 'key' in line.lower():
                        secret_type = "Possible API Key (High Entropy)"
                    elif 'token' in line.lower():
                        secret_type = "Possible Token (High Entropy)"
                    elif 'password' in line.lower():
                        secret_type = "Possible Password (High Entropy)"
                    
                    confidence = 0.6 + (entropy - 4.5) * 0.1  # Scale confidence with entropy
                    
                    secrets.append(Secret(
                        type=secret_type,
                        value=word[:20] + "..." if len(word) > 20 else word,
                        file_path=filepath,
                        line_number=line_number,
                        code_snippet=line.strip(),
                        confidence=round(min(0.9, confidence), 2),
                        entropy=round(entropy, 2),
                        context=line.strip()
                    ))
        
        return secrets
    
    def scan_file(self, filepath: Path) -> List[Secret]:
        """Scan a file for secrets"""
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            return self.scan_content(content, str(filepath))
        except Exception as e:
            return []
    
    def scan_content(self, content: str, filepath: str = "unknown") -> List[Secret]:
        """Scan content for secrets"""
        secrets = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_secrets = self.scan_line(line, i, filepath)
            secrets.extend(line_secrets)
        
        # Deduplicate secrets (same value in same file)
        seen = set()
        unique_secrets = []
        for secret in secrets:
            key = (secret.type, secret.value, secret.file_path)
            if key not in seen:
                seen.add(key)
                unique_secrets.append(secret)
        
        return unique_secrets
    
    def generate_report(self, secrets: List[Secret]) -> Dict[str, Any]:
        """Generate secrets scanning report"""
        # Group by type
        by_type = {}
        for secret in secrets:
            if secret.type not in by_type:
                by_type[secret.type] = []
            by_type[secret.type].append({
                'file': secret.file_path,
                'line': secret.line_number,
                'confidence': secret.confidence,
                'entropy': secret.entropy
            })
        
        # Group by file
        by_file = {}
        for secret in secrets:
            if secret.file_path not in by_file:
                by_file[secret.file_path] = []
            by_file[secret.file_path].append({
                'type': secret.type,
                'line': secret.line_number,
                'confidence': secret.confidence
            })
        
        # Calculate statistics
        total_secrets = len(secrets)
        high_confidence = len([s for s in secrets if s.confidence >= 0.8])
        avg_entropy = sum(s.entropy for s in secrets) / total_secrets if total_secrets > 0 else 0
        
        return {
            'total_secrets_found': total_secrets,
            'high_confidence_secrets': high_confidence,
            'unique_secret_types': len(by_type),
            'affected_files': len(by_file),
            'average_entropy': round(avg_entropy, 2),
            'by_type': by_type,
            'by_file': by_file,
            'secrets': [
                {
                    'type': s.type,
                    'file': s.file_path,
                    'line': s.line_number,
                    'confidence': s.confidence,
                    'entropy': s.entropy,
                    'snippet': s.code_snippet
                }
                for s in secrets
            ]
        }


def scan_for_secrets(filepath: Path, min_entropy: float = 4.5) -> List[Secret]:
    """
    Convenience function to scan a file for secrets
    
    Args:
        filepath: Path to file to scan
        min_entropy: Minimum entropy threshold
    
    Returns:
        List of detected secrets
    """
    scanner = AdvancedSecretsScanner(min_entropy=min_entropy)
    return scanner.scan_file(filepath)

