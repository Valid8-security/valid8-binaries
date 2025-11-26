#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

# Parry (C) by Valid8 Security. Written by Andy Kurapati and Shreyan Mitra
"""
Modern Cryptography Security Detectors

Detects outdated and insecure cryptographic configurations:
- Weak TLS/SSL versions (TLS 1.0, 1.1, SSL v2/v3)
- Weak RSA key sizes (< 2048 bits)
- Weak cipher suites (RC4, DES, 3DES)
- Insecure hashing algorithms (MD5, SHA1 for signatures)
- Weak Diffie-Hellman parameters
- Certificate validation bypass
- Insecure random number generation

CWEs Covered:
- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-328: Use of Weak Hash
- CWE-330: Use of Insufficiently Random Values
- CWE-295: Improper Certificate Validation
"""

import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class CryptoDetector:
    """Cryptography security detector"""
    name: str
    language: str
    cwe: str
    severity: str
    description: str
    pattern: re.Pattern
    fix_suggestion: str
    references: List[str]


class ModernCryptoDetectors:
    """Detectors for modern cryptography vulnerabilities"""
    
    DETECTORS = [
        # TLS 1.0 / 1.1 Usage
        CryptoDetector(
            name="tls-1.0-1.1-deprecated",
            language="all",
            cwe="CWE-327",
            severity="high",
            description="TLS 1.0 and 1.1 are deprecated and vulnerable to BEAST, POODLE, and other attacks",
            pattern=re.compile(r'TLS(_v)?1[._]?[01]|SSL(_v)?[23]|PROTOCOL_TLS(v1)?[._]?[01]', re.IGNORECASE),
            fix_suggestion="Use TLS 1.2 or TLS 1.3. Set minimum version: ssl.PROTOCOL_TLSv1_2 or TLS 1.3",
            references=[
                "https://datatracker.ietf.org/doc/html/rfc8996",
                "https://www.nist.gov/news-events/news/2020/10/nist-retiring-sha-1-cryptographic-algorithm"
            ]
        ),
        
        # Weak RSA Key Size
        CryptoDetector(
            name="rsa-key-size-weak",
            language="all",
            cwe="CWE-326",
            severity="high",
            description="RSA key size less than 2048 bits is considered weak and can be factored",
            pattern=re.compile(r'RSA.*key.*(?:512|768|1024)|\b(?:512|768|1024)\s*(?:bit|bits)?\s*RSA', re.IGNORECASE),
            fix_suggestion="Use RSA keys of at least 2048 bits (3072 or 4096 recommended for long-term security)",
            references=[
                "https://www.keylength.com/",
                "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"
            ]
        ),
        
        # Weak Cipher Suites
        CryptoDetector(
            name="weak-cipher-suites",
            language="all",
            cwe="CWE-327",
            severity="high",
            description="Weak or deprecated cipher suites (RC4, DES, 3DES, MD5, NULL) are vulnerable",
            pattern=re.compile(r'\b(RC4|DES(?!C)|3DES|NULL|EXPORT|anon|MD5)[-_]?(CBC|GCM|SHA)?', re.IGNORECASE),
            fix_suggestion="Use modern cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256",
            references=[
                "https://wiki.mozilla.org/Security/Server_Side_TLS",
                "https://ciphersuite.info/"
            ]
        ),
        
        # SHA-1 for Signatures
        CryptoDetector(
            name="sha1-for-signatures",
            language="all",
            cwe="CWE-328",
            severity="high",
            description="SHA-1 is cryptographically broken for digital signatures (collision attacks)",
            pattern=re.compile(r'(SHA-?1|sha1).*(?:sign|signature|HMAC)|RSA.*SHA-?1|withSHA1', re.IGNORECASE),
            fix_suggestion="Use SHA-256 or SHA-3 for digital signatures. SHA-1 acceptable only for HMAC",
            references=[
                "https://shattered.io/",
                "https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm"
            ]
        ),
        
        # MD5 for Security
        CryptoDetector(
            name="md5-for-security",
            language="all",
            cwe="CWE-328",
            severity="critical",
            description="MD5 is cryptographically broken and should not be used for security purposes",
            pattern=re.compile(r'\bMD5\b.*(?:hash|crypt|password|sign|auth)', re.IGNORECASE),
            fix_suggestion="Use SHA-256, SHA-3, or bcrypt/argon2 for passwords. Avoid MD5 except for checksums",
            references=[
                "https://www.kb.cert.org/vuls/id/836068",
                "https://tools.ietf.org/html/rfc6151"
            ]
        ),
        
        # Insecure Random
        CryptoDetector(
            name="insecure-random-crypto",
            language="python",
            cwe="CWE-330",
            severity="high",
            description="Using non-cryptographic random for security purposes (tokens, keys, nonces)",
            pattern=re.compile(r'random\.(randint|choice|random|shuffle).*(?:token|key|nonce|salt|iv|secret)', re.IGNORECASE),
            fix_suggestion="Use secrets module in Python: secrets.token_hex(), secrets.token_urlsafe(), secrets.SystemRandom()",
            references=[
                "https://docs.python.org/3/library/secrets.html"
            ]
        ),
        
        # Certificate Validation Bypass
        CryptoDetector(
            name="cert-validation-bypass",
            language="all",
            cwe="CWE-295",
            severity="critical",
            description="SSL/TLS certificate validation is disabled, allowing MITM attacks",
            pattern=re.compile(r'verify\s*=\s*False|SSL_VERIFY_NONE|check_hostname\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'"]?0', re.IGNORECASE),
            fix_suggestion="Enable certificate verification. Remove verify=False, use SSL_VERIFY_PEER, check_hostname=True",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Improper_Certificate_Validation"
            ]
        ),
        
        # Weak Elliptic Curves
        CryptoDetector(
            name="weak-elliptic-curves",
            language="all",
            cwe="CWE-327",
            severity="medium",
            description="Weak or non-standard elliptic curves are vulnerable to attacks",
            pattern=re.compile(r'\b(secp160|prime192|prime256v1|brainpool)\b', re.IGNORECASE),
            fix_suggestion="Use NIST P-256 (secp256r1), P-384, P-521, or Curve25519 for modern security",
            references=[
                "https://safecurves.cr.yp.to/"
            ]
        ),
        
        # Weak Diffie-Hellman
        CryptoDetector(
            name="weak-dh-params",
            language="all",
            cwe="CWE-326",
            severity="high",
            description="Diffie-Hellman parameters smaller than 2048 bits are vulnerable to Logjam attack",
            pattern=re.compile(r'DH.*(?:512|768|1024)\b|DHE?.*1024', re.IGNORECASE),
            fix_suggestion="Use DH parameters of at least 2048 bits (3072 recommended)",
            references=[
                "https://weakdh.org/"
            ]
        ),
        
        # ECB Mode Usage
        CryptoDetector(
            name="ecb-mode-encryption",
            language="all",
            cwe="CWE-327",
            severity="high",
            description="ECB mode does not provide semantic security and leaks patterns",
            pattern=re.compile(r'\bECB\b|AES\.MODE_ECB|CIPHER_MODE_ECB', re.IGNORECASE),
            fix_suggestion="Use GCM mode for authenticated encryption: AES-256-GCM, or CBC with HMAC",
            references=[
                "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)"
            ]
        ),
        
        # Hardcoded Cryptographic Keys
        CryptoDetector(
            name="hardcoded-crypto-key",
            language="all",
            cwe="CWE-321",
            severity="critical",
            description="Cryptographic key is hardcoded in source code",
            pattern=re.compile(r'(?:aes|rsa|hmac).*(?:key|secret)\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']', re.IGNORECASE),
            fix_suggestion="Load keys from secure key management system (KMS, HSM, Vault) or environment variables",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key"
            ]
        ),
        
        # Weak PBKDF2 Iterations
        CryptoDetector(
            name="weak-pbkdf2-iterations",
            language="all",
            cwe="CWE-326",
            severity="medium",
            description="PBKDF2 iterations count is too low (< 100,000), making brute force easier",
            pattern=re.compile(r'pbkdf2.*(?:iterations?|rounds?)\s*=\s*(?:[1-9]\d{0,3}|[1-9]\d{4})\b', re.IGNORECASE),
            fix_suggestion="Use at least 100,000 iterations for PBKDF2 (OWASP 2023), or use Argon2id",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
            ]
        ),
    ]


class JavaCryptoDetectors:
    """Java-specific crypto detectors"""
    
    DETECTORS = [
        CryptoDetector(
            name="java-insecure-ssl-context",
            language="java",
            cwe="CWE-327",
            severity="high",
            description="Using SSLv3 or TLSv1 context in Java",
            pattern=re.compile(r'SSLContext\.getInstance\(["\'](?:SSL|SSLv[23]|TLSv1(?:\.[01])?)["\']'),
            fix_suggestion="Use SSLContext.getInstance(\"TLSv1.2\") or \"TLSv1.3\"",
            references=["https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html"]
        ),
        
        CryptoDetector(
            name="java-weak-key-generator",
            language="java",
            cwe="CWE-326",
            severity="high",
            description="KeyGenerator initialized with weak key size",
            pattern=re.compile(r'KeyGenerator\.init\s*\(\s*(?:64|128|512|1024)\s*\)'),
            fix_suggestion="Use 256-bit keys for AES, 2048+ bits for RSA",
            references=["https://docs.oracle.com/javase/8/docs/api/javax/crypto/KeyGenerator.html"]
        ),
    ]


class PythonCryptoDetectors:
    """Python-specific crypto detectors"""
    
    DETECTORS = [
        CryptoDetector(
            name="python-pycrypto-deprecated",
            language="python",
            cwe="CWE-327",
            severity="high",
            description="PyCrypto is deprecated and unmaintained, has known vulnerabilities",
            pattern=re.compile(r'from\s+Crypto\.|import\s+Crypto(?!graphy)'),
            fix_suggestion="Use cryptography library: from cryptography.hazmat.primitives import ...",
            references=["https://github.com/dlitz/pycrypto/issues/301"]
        ),
        
        CryptoDetector(
            name="python-ssl-unverified-context",
            language="python",
            cwe="CWE-295",
            severity="critical",
            description="Creating unverified SSL context bypasses certificate validation",
            pattern=re.compile(r'ssl\._create_unverified_context|ssl\.CERT_NONE'),
            fix_suggestion="Use ssl.create_default_context() which validates certificates by default",
            references=["https://docs.python.org/3/library/ssl.html#ssl.create_default_context"]
        ),
    ]


class JavaScriptCryptoDetectors:
    """JavaScript/Node.js-specific crypto detectors"""
    
    DETECTORS = [
        CryptoDetector(
            name="nodejs-crypto-md5",
            language="javascript",
            cwe="CWE-328",
            severity="high",
            description="Using MD5 in Node.js crypto module for security",
            pattern=re.compile(r'crypto\.createHash\(["\']md5["\']'),
            fix_suggestion="Use crypto.createHash('sha256') or 'sha3-256'",
            references=["https://nodejs.org/api/crypto.html"]
        ),
        
        CryptoDetector(
            name="nodejs-tls-reject-unauthorized",
            language="javascript",
            cwe="CWE-295",
            severity="critical",
            description="Disabling TLS certificate validation in Node.js",
            pattern=re.compile(r'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'"]?0'),
            fix_suggestion="Remove rejectUnauthorized: false and fix certificate issues properly",
            references=["https://nodejs.org/api/tls.html#tls_tls_connect_options_callback"]
        ),
    ]


def get_all_crypto_detectors() -> List[CryptoDetector]:
    """Get all modern crypto detectors"""
    detectors = []
    detectors.extend(ModernCryptoDetectors.DETECTORS)
    detectors.extend(JavaCryptoDetectors.DETECTORS)
    detectors.extend(PythonCryptoDetectors.DETECTORS)
    detectors.extend(JavaScriptCryptoDetectors.DETECTORS)
    return detectors


# Statistics
def get_crypto_coverage_stats():
    """Get statistics on crypto detector coverage"""
    all_detectors = get_all_crypto_detectors()
    
    by_severity = {}
    by_language = {}
    by_cwe = {}
    
    for detector in all_detectors:
        by_severity[detector.severity] = by_severity.get(detector.severity, 0) + 1
        by_language[detector.language] = by_language.get(detector.language, 0) + 1
        by_cwe[detector.cwe] = by_cwe.get(detector.cwe, 0) + 1
    
    return {
        'total_detectors': len(all_detectors),
        'by_severity': by_severity,
        'by_language': by_language,
        'by_cwe': by_cwe,
        'covered_cwes': list(by_cwe.keys())
    }


if __name__ == '__main__':
    stats = get_crypto_coverage_stats()
    print(f"Total Crypto Detectors: {stats['total_detectors']}")
    print(f"By Severity: {stats['by_severity']}")
    print(f"By Language: {stats['by_language']}")
    print(f"CWEs Covered: {stats['covered_cwes']}")
