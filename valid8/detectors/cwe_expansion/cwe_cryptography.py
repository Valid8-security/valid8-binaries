#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""Cryptography Vulnerability Detectors - 30+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class WeakCryptoProtocolDetector(VulnerabilityDetector):
    """CWE-295: Improper Certificate Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'SSLContext\(.*verify\s*=\s*False|.*verify_mode\s*=\s*CERT_NONE', "CWE-295", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-295", severity=severity, title="Improper Certificate Validation", description="SSL/TLS certificate validation disabled.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class WeakRandomNumberDetector(VulnerabilityDetector):
    """CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'random\.(randint|random|uniform)\(|Math\.random\(\)', "CWE-338", "medium")]
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
            if re.search(r'(password|token|session|key|nonce|salt).*=', context, re.IGNORECASE):
                for pattern, cwe, severity in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        if not re.search(r'SecureRandom|Crypto|cryptographically|secrets\.', context, re.IGNORECASE):
                            vulnerabilities.append(Vulnerability(cwe="CWE-338", severity=severity, title="Weak Random Number Generator", description="Weak PRNG used for security-critical value.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="cryptography"))
        return vulnerabilities

class WeakHashDetector(VulnerabilityDetector):
    """CWE-916: Use of Password Hash With Insufficient Computational Effort"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'hashlib\.(md5|sha1)\(.*password|.*MessageDigest\.getInstance\(["\']MD5', "CWE-916", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = content[max(0, i-10):i+10]
                    if 'bcrypt' not in context.lower():
                        vulnerabilities.append(Vulnerability(cwe="CWE-916", severity=severity, title="Weak Password Hash", description="Weak password hashing. Use bcrypt, scrypt, or Argon2.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class WeakCipherDetector(VulnerabilityDetector):
    """CWE-326: Inadequate Encryption Strength"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'DES\s*\(|.*DES[_-]?KeySpec|.*RC4|.*RC2', "CWE-326", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-326", severity=severity, title="Weak Cipher", description="Weak encryption algorithm detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class PredictableSaltDetector(VulnerabilityDetector):
    """CWE-760: Use of One-Way Hash without a Salt"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'hashlib\.(md5|sha1|sha256)\(.*password[^,)]*\)', "CWE-760", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'salt|bcrypt|scrypt|argon', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-760", severity=severity, title="Hash Without Salt", description="Password hash without salt detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class WeakKeyExchangeDetector(VulnerabilityDetector):
    """CWE-310: Cryptographic Issues"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'DiffieHellman.*512|.*DH.*512|.*RSA.*1024', "CWE-310", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-310", severity=severity, title="Weak Cryptographic Key Size", description="Weak key size detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class HardcodedKeyDetector(VulnerabilityDetector):
    """CWE-321: Use of Hard-coded Cryptographic Key"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'key\s*=\s*["\'][a-fA-F0-9]{16,}["\']', "CWE-321", "critical"),
            (r'secret\s*=\s*["\'][a-fA-F0-9]{16,}["\']', "CWE-321", "critical"),
            (r'KEY\s*=\s*["\'][a-fA-F0-9]{16,}["\']', "CWE-321", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Hard-coded Cryptographic Key",
                        description="Hard-coded cryptographic key detected. Use environment variables or key management.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities

class ECBModeDetector(VulnerabilityDetector):
    """CWE-329: Not Using a Random IV with CBC Mode"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Cipher\.getInstance\(["\'].*ECB', "CWE-329", "high"),
            (r'cipher.*mode.*ECB', "CWE-329", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="ECB Mode Usage",
                        description="ECB mode is deterministic and not secure for most use cases.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities

class MissingIVDetector(VulnerabilityDetector):
    """CWE-329 variant: Missing Initialization Vector"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Cipher\.getInstance\(["\'].*CBC|.*GCM', "CWE-329", "medium"),
            (r'cipher.*CBC|.*GCM', "CWE-329", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if 'iv' not in context.lower() and 'initialization' not in context.lower():
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Missing Initialization Vector",
                            description="CBC/GCM mode without explicit IV. Use random IVs.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="cryptography"
                        ))
        return vulnerabilities

class WeakMACDetector(VulnerabilityDetector):
    """CWE-328: Use of Weak Hash"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Mac\.getInstance\(["\']HmacMD5', "CWE-328", "high"),
            (r'Mac\.getInstance\(["\']HmacSHA1', "CWE-328", "high"),
            (r'hmac\.new.*md5|sha1', "CWE-328", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak MAC Algorithm",
                        description="Weak MAC algorithm. Use HMAC-SHA256 or better.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities

class PaddingOracleDetector(VulnerabilityDetector):
    """CWE-696: Incorrect Behavior Order"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'padding.*error|decryption.*fail', "CWE-696", "medium"),
            (r'BadPaddingException', "CWE-696", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if 'different' in context.lower() or 'same' in context.lower():
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Potential Padding Oracle",
                            description="Timing leak in padding error handling may enable padding oracle attack.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="cryptography"
                        ))
        return vulnerabilities

class KeyReuseDetector(VulnerabilityDetector):
    """CWE-323: Use of Known Cryptographically Weak PRNG"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'key.*reuse|same.*key', "CWE-323", "high"),
            (r'KeyPairGenerator.*reuse', "CWE-323", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Key Reuse",
                        description="Cryptographic key reuse detected. Generate unique keys.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="cryptography"
                    ))
        return vulnerabilities

class InsufficientKeySizeDetector(VulnerabilityDetector):
    """CWE-326 variant: Insufficient Key Size"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'RSA.*1024|DSA.*1024', "CWE-326", "high"),
            (r'generateKeyPair.*1024', "CWE-326", "high"),
            (r'KeyPairGenerator.*1024', "CWE-326", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insufficient Key Size",
                        description="Key size too small for current security requirements. Use 2048+ bits.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities

class PredictableIVDetector(VulnerabilityDetector):
    """CWE-329 variant: Predictable IV"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'iv\s*=\s*["\']0+["\']', "CWE-329", "high"),
            (r'IV\s*=\s*new byte\[', "CWE-329", "high"),
            (r'initialization.*vector.*=.*0', "CWE-329", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Predictable Initialization Vector",
                        description="Predictable IV detected. Use cryptographically secure random IV.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities

class WeakKDFDetector(VulnerabilityDetector):
    """CWE-916 variant: Weak Key Derivation Function"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'PBKDF2WithHmacSHA1', "CWE-916", "medium"),
            (r'PKCS5S1|PKCS5S2.*1', "CWE-916", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Key Derivation Function",
                        description="Weak KDF parameters. Use PBKDF2 with sufficient iterations.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="cryptography"
                    ))
        return vulnerabilities

class InsecureRandomSeedDetector(VulnerabilityDetector):
    """CWE-338 variant: Insecure Random Seed"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Random\(.*System\.currentTimeMillis|new Random\(\)', "CWE-338", "medium"),
            (r'srand\(.*time\(', "CWE-338", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if 'secure' not in context.lower() and 'crypto' not in context.lower():
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Insecure Random Seed",
                            description="Insecure random seed. Use SecureRandom for cryptographic purposes.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="cryptography"
                        ))
        return vulnerabilities

class CertificatePinningBypassDetector(VulnerabilityDetector):
    """CWE-295 variant: Certificate Pinning Bypass"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'certificate.*pinning.*disable', "CWE-295", "high"),
            (r'pinning.*bypass', "CWE-295", "high"),
            (r'trust.*all.*certificates', "CWE-295", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Certificate Pinning Bypass",
                        description="Certificate pinning disabled or bypassed.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities

class WeakSignatureAlgorithmDetector(VulnerabilityDetector):
    """CWE-347: Improper Verification of Cryptographic Signature"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Signature\.getInstance\(["\']SHA1withRSA', "CWE-347", "high"),
            (r'Signature\.getInstance\(["\']MD5withRSA', "CWE-347", "high"),
            (r'sign.*SHA1|MD5.*sign', "CWE-347", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Signature Algorithm",
                        description="Weak signature algorithm. Use SHA256 or better.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities

class TimingAttackDetector(VulnerabilityDetector):
    """CWE-208: Observable Timing Discrepancy"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'strcmp.*password|strcmp.*secret', "CWE-208", "medium"),
            (r'password.*equals|secret.*equals', "CWE-208", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if 'constant' not in context.lower() and 'timing' not in context.lower():
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Timing Attack Vulnerability",
                            description="Timing discrepancy in cryptographic comparison. Use constant-time comparison.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="cryptography"
                        ))
        return vulnerabilities

class InsufficientEntropyDetector(VulnerabilityDetector):
    """CWE-331: Insufficient Entropy"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'rand\(\)|random\(\)|mt_rand\(\)', "CWE-331", "medium"),
            (r'Math\.random\(\)', "CWE-331", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'key|token|secret|password', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Insufficient Entropy",
                            description="Insufficient entropy for cryptographic key generation.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="cryptography"
                        ))
        return vulnerabilities

class RaceConditionCryptoDetector(VulnerabilityDetector):
    """CWE-362 variant: Race Condition in Cryptographic Operations"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'encrypt.*thread|decrypt.*thread', "CWE-362", "low"),
            (r'crypto.*concurrent', "CWE-362", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Race Condition in Crypto",
                        description="Potential race condition in cryptographic operations.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="cryptography"
                    ))
        return vulnerabilities

class WeakCertificateChainDetector(VulnerabilityDetector):
    """CWE-296 variant: Weak Certificate Chain"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'X509TrustManager.*accept', "CWE-296", "medium"),
            (r'trust.*all.*hosts', "CWE-296", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Certificate Chain Validation",
                        description="Certificate chain validation bypassed.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="cryptography"
                    ))
        return vulnerabilities

class CryptographicFailureDetector(VulnerabilityDetector):
    """CWE-310 variant: Cryptographic Failure"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'crypto.*error.*ignore', "CWE-310", "high"),
            (r'cipher.*exception.*catch', "CWE-310", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if 'continue' in context.lower() or 'ignore' in context.lower():
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Cryptographic Failure Handling",
                            description="Cryptographic failures not properly handled.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="cryptography"
                        ))
        return vulnerabilities

class KeyStorageDetector(VulnerabilityDetector):
    """CWE-922: Insecure Storage of Sensitive Information"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'private.*key.*file', "CWE-922", "high"),
            (r'secret.*key.*disk', "CWE-922", "high"),
            (r'key.*store.*plain', "CWE-922", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insecure Key Storage",
                        description="Cryptographic keys stored insecurely.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities


class WeakTLSVersionDetector(VulnerabilityDetector):
    """CWE-326: Use of Weak TLS Version"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'TLSv1\.0|TLSv1\.1|SSLv3', "CWE-326", "high"),
            (r'PROTOCOL_TLSv1|PROTOCOL_TLSv1_1', "CWE-326", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak TLS Version",
                        description="Weak TLS/SSL version in use. Upgrade to TLS 1.2 or higher.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities


class NullCipherDetector(VulnerabilityDetector):
    """CWE-327: Use of a Known Cryptographically Weak PRNG"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Cipher\.getInstance\(["\']NONE', "CWE-327", "critical"),
            (r'cipher.*none', "CWE-327", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Null Cipher Usage",
                        description="Null cipher (no encryption) detected.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="critical", category="cryptography"
                    ))
        return vulnerabilities


class WeakBlockModeDetector(VulnerabilityDetector):
    """CWE-329: Use of Cryptographically Weak Pseudo-Random Number Generator"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'AES.*ECB|DES.*ECB|.*ECB.*mode', "CWE-329", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Block Cipher Mode",
                        description="ECB mode detected. Use CBC, GCM, or CTR mode instead.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities


class InsecureKeyDerivationDetector(VulnerabilityDetector):
    """CWE-916: Use of Password Hash With Insufficient Computational Effort"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'PBKDF2.*1000|PBKDF2.*10000', "CWE-916", "medium"),
            (r'hashlib\.pbkdf2.*1000', "CWE-916", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insecure Key Derivation",
                        description="PBKDF2 with insufficient iterations. Use 100,000+ iterations.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="cryptography"
                    ))
        return vulnerabilities


class CryptographicOracleDetector(VulnerabilityDetector):
    """CWE-300: Channel Accessible by Non-Endpoint"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'padding.*oracle', "CWE-300", "high"),
            (r'oracle.*attack', "CWE-300", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'constant.*time|timing.*safe', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Cryptographic Oracle",
                            description="Potential cryptographic oracle vulnerability.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="cryptography"
                        ))
        return vulnerabilities


class WeakHMACDetector(VulnerabilityDetector):
    """CWE-328: Use of Weak Hash"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'HMAC.*MD5|HMAC.*SHA1', "CWE-328", "high"),
            (r'hmac\.new.*md5', "CWE-328", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak HMAC Algorithm",
                        description="Weak HMAC hash algorithm. Use SHA-256 or stronger.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities


class KeyCompromiseDetector(VulnerabilityDetector):
    """CWE-321: Use of Hard-coded Cryptographic Key"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'key.*log|log.*key', "CWE-321", "critical"),
            (r'print.*key|debug.*key', "CWE-321", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Key Compromise",
                        description="Cryptographic keys logged or exposed in debug output.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities


class InsecureSignatureDetector(VulnerabilityDetector):
    """CWE-347: Improper Verification of Cryptographic Signature"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'verify.*signature.*false', "CWE-347", "critical"),
            (r'signature.*check.*skip', "CWE-347", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insecure Signature Verification",
                        description="Cryptographic signature verification disabled or bypassed.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="critical", category="cryptography"
                    ))
        return vulnerabilities


class WeakCertificateValidationDetector(VulnerabilityDetector):
    """CWE-599: Missing Validation of OpenSSL Certificate"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'X509_VERIFY_PARAM.*flags.*0', "CWE-599", "high"),
            (r'X509.*verify.*false', "CWE-599", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Certificate Validation",
                        description="Certificate validation flags not properly set.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities


class CryptographicKeyReuseDetector(VulnerabilityDetector):
    """CWE-323: Use of Known Cryptographically Weak PRNG"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'same.*key.*multiple|key.*reuse', "CWE-323", "medium"),
            (r'global.*key|static.*key', "CWE-323", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Cryptographic Key Reuse",
                        description="Same cryptographic key used multiple times.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="cryptography"
                    ))
        return vulnerabilities


class InsufficientKeyLengthDetector(VulnerabilityDetector):
    """CWE-326: Inadequate Encryption Strength"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'AES.*128|RSA.*2048', "CWE-326", "medium"),
            (r'DH.*1024|ECDH.*160', "CWE-326", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insufficient Key Length",
                        description="Key length may be insufficient for current security requirements.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="cryptography"
                    ))
        return vulnerabilities


class CryptographicTimingAttackDetector(VulnerabilityDetector):
    """CWE-208: Observable Timing Discrepancy"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'strcmp.*password|memcmp.*key', "CWE-208", "medium"),
            (r'==.*password|equals.*key', "CWE-208", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'constant.*time|timing.*safe|cryptographically', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Timing Attack Vulnerability",
                            description="Potential timing attack vulnerability in cryptographic comparison.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="cryptography"
                        ))
        return vulnerabilities


class WeakCryptographicStorageDetector(VulnerabilityDetector):
    """CWE-922: Insecure Storage of Sensitive Information"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'password.*localStorage|token.*localStorage', "CWE-922", "high"),
            (r'secret.*cookie|key.*cookie', "CWE-922", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Cryptographic Storage",
                        description="Sensitive cryptographic data stored insecurely.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities


class InsecureKeyGenerationDetector(VulnerabilityDetector):
    """CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'KeyPairGenerator.*initialize\(1024', "CWE-338", "high"),
            (r'KeyGenerator.*init\(128', "CWE-338", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insecure Key Generation",
                        description="Key generated with insufficient strength.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="cryptography"
                    ))
        return vulnerabilities


class CryptographicRaceConditionDetector(VulnerabilityDetector):
    """CWE-362: Concurrent Execution using Shared Resource"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'global.*crypto|shared.*cipher', "CWE-362", "medium"),
            (r'static.*key.*crypto', "CWE-362", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Cryptographic Race Condition",
                        description="Shared cryptographic resources may cause race conditions.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="cryptography"
                    ))
        return vulnerabilities


class WeakEntropyDetector(VulnerabilityDetector):
    """CWE-331: Insufficient Entropy"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'random\(\).*seed|seed.*time', "CWE-331", "high"),
            (r'Math\.random\(\).*seed', "CWE-331", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Entropy Source",
                        description="Insufficient entropy for cryptographic operations.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities


class CryptographicSideChannelDetector(VulnerabilityDetector):
    """CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'power.*analysis|side.*channel', "CWE-200", "low"),
            (r'cache.*timing|branch.*prediction', "CWE-200", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Cryptographic Side Channel",
                        description="Potential side channel vulnerability in cryptographic implementation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="cryptography"
                    ))
        return vulnerabilities


class WeakCertificateChainDetector(VulnerabilityDetector):
    """CWE-295: Improper Certificate Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'chain.*validation.*false', "CWE-295", "high"),
            (r'certificate.*chain.*skip', "CWE-295", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Weak Certificate Chain Validation",
                        description="Certificate chain validation not properly implemented.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="cryptography"
                    ))
        return vulnerabilities


class CryptographicStateManagementDetector(VulnerabilityDetector):
    """CWE-573: Improper Following of Specification by Caller"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'state.*reset.*crypto|cipher.*reset', "CWE-573", "medium"),
            (r'context.*reuse|state.*reuse', "CWE-573", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Cryptographic State Management",
                        description="Improper cryptographic state management.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="cryptography"
                    ))
        return vulnerabilities

class WeakKeySizeDetector(VulnerabilityDetector):
    """CWE-326: Inadequate Encryption Strength"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'RSA.*1024|AES.*128|DES|RC4', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-326", severity="high", title="Weak Cryptographic Key Size",
                    description="Cryptographic algorithm uses inadequate key size.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="cryptography"
                ))
        return vulnerabilities

class PredictableRandomDetector(VulnerabilityDetector):
    """CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'Math\.random\(\)|Random\(\)|rand\(\)', line) and re.search(r'key|token|secret|salt', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-338", severity="critical", title="Predictable Random Values in Cryptography",
                    description="Cryptographically weak random number generator used for security-critical values.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="cryptography"
                ))
        return vulnerabilities

class HardcodedSaltDetector(VulnerabilityDetector):
    """CWE-329: Not Using a Random IV with CBC Mode"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'salt.*=.*["\'][^"\']+["\']|iv.*=.*["\'][^"\']+["\']', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-329", severity="high", title="Hardcoded Salt/IV Values",
                    description="Cryptographic salt or IV is hardcoded instead of randomly generated.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="cryptography"
                ))
        return vulnerabilities

def get_cryptography_detectors():
    return [
        WeakCryptoProtocolDetector(),
        WeakRandomNumberDetector(),
        WeakHashDetector(),
        WeakCipherDetector(),
        PredictableSaltDetector(),
        WeakKeyExchangeDetector(),
        HardcodedKeyDetector(),
        ECBModeDetector(),
        MissingIVDetector(),
        WeakMACDetector(),
        PaddingOracleDetector(),
        KeyReuseDetector(),
        InsufficientKeySizeDetector(),
        PredictableIVDetector(),
        WeakKDFDetector(),
        InsecureRandomSeedDetector(),
        CertificatePinningBypassDetector(),
        WeakSignatureAlgorithmDetector(),
        TimingAttackDetector(),
        InsufficientEntropyDetector(),
        RaceConditionCryptoDetector(),
        WeakCertificateChainDetector(),
        CryptographicFailureDetector(),
        KeyStorageDetector(),
        WeakTLSVersionDetector(),
        NullCipherDetector(),
        WeakBlockModeDetector(),
        InsecureKeyDerivationDetector(),
        CryptographicOracleDetector(),
        WeakHMACDetector(),
        KeyCompromiseDetector(),
        InsecureSignatureDetector(),
        WeakCertificateValidationDetector(),
        CryptographicKeyReuseDetector(),
        InsufficientKeyLengthDetector(),
        CryptographicTimingAttackDetector(),
        WeakCryptographicStorageDetector(),
        InsecureKeyGenerationDetector(),
        CryptographicRaceConditionDetector(),
        WeakEntropyDetector(),
        CryptographicSideChannelDetector(),
        WeakCertificateChainDetector(),
        CryptographicStateManagementDetector(),
        WeakCryptographicSeedDetector(),
        InsufficientVerificationDetector(),
        CryptographicKeyLeakDetector(),
        WeakCryptographicPaddingDetector(),
        CryptographicObfuscationDetector(),
        InsufficientCryptographicStrengthDetector(),
        CryptographicKeyManagementDetector(),
        WeakCryptographicProtocolDetector(),
        CryptographicDataValidationDetector(),
        InsufficientCryptographicRobustnessDetector(),
        WeakKeySizeDetector(),
        PredictableRandomDetector(),
        HardcodedSaltDetector(),
    ]

class WeakCryptographicSeedDetector(VulnerabilityDetector):
    """CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'seed.*time|random\.seed\(.*time', "CWE-335", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-335", severity=severity, title="Weak Cryptographic Seed", description="Weak seed for PRNG.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="cryptography"))
        return vulnerabilities

class InsufficientVerificationDetector(VulnerabilityDetector):
    """CWE-299: Improper Check for Certificate Revocation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'certificate.*revocation.*disabled|no.*crl.*check', "CWE-299", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-299", severity=severity, title="Insufficient Certificate Verification", description="Certificate revocation not checked.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class CryptographicKeyLeakDetector(VulnerabilityDetector):
    """CWE-316: Cleartext Storage of Sensitive Information in Memory"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'key.*memory.*clear|plaintext.*key.*stored', "CWE-316", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-316", severity=severity, title="Cryptographic Key Leak", description="Cryptographic keys stored in cleartext memory.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="critical", category="cryptography"))
        return vulnerabilities

class WeakCryptographicPaddingDetector(VulnerabilityDetector):
    """CWE-323: Use of Known Cryptographically Weak PRNGs"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'rand\(\)|srand\(.*1\)|weak.*padding', "CWE-323", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-323", severity=severity, title="Weak Cryptographic Padding", description="Weak padding in cryptographic operations.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class CryptographicObfuscationDetector(VulnerabilityDetector):
    """CWE-327: Use of a Known Cryptographically Weak PRNG"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'obfuscated.*crypto|hidden.*encryption', "CWE-327", "low")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-327", severity=severity, title="Cryptographic Obfuscation", description="Cryptographic code obfuscation may hide weaknesses.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="cryptography"))
        return vulnerabilities

class InsufficientCryptographicStrengthDetector(VulnerabilityDetector):
    """CWE-326: Inadequate Encryption Strength"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'encryption.*56.*bit|weak.*algorithm', "CWE-326", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-326", severity=severity, title="Insufficient Cryptographic Strength", description="Cryptographic algorithm too weak.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class CryptographicKeyManagementDetector(VulnerabilityDetector):
    """CWE-320: Key Management Errors"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'key.*hardcoded|embedded.*key', "CWE-320", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-320", severity=severity, title="Cryptographic Key Management Error", description="Cryptographic keys improperly managed.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="critical", category="cryptography"))
        return vulnerabilities

class WeakCryptographicProtocolDetector(VulnerabilityDetector):
    """CWE-326: Inadequate Encryption Strength"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'SSLv2|SSLv3.*enabled|weak.*protocol', "CWE-326", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-326", severity=severity, title="Weak Cryptographic Protocol", description="Deprecated cryptographic protocol in use.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="critical", category="cryptography"))
        return vulnerabilities

class CryptographicDataValidationDetector(VulnerabilityDetector):
    """CWE-354: Improper Validation of Integrity Check Value"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'hmac.*not.*verified|hmac.*bypass', "CWE-354", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-354", severity=severity, title="Cryptographic Data Validation Failure", description="Integrity check values not properly validated.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class InsufficientCryptographicRobustnessDetector(VulnerabilityDetector):
    """CWE-358: Improperly Implemented Protection Mechanism"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'crypto.*bypass|weak.*protection.*mechanism', "CWE-358", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-358", severity=severity, title="Insufficient Cryptographic Robustness", description="Cryptographic protection mechanism improperly implemented.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities
