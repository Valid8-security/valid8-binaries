#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Comprehensive CWE mappings based on:
- OWASP Top 10 2021
- CWE Top 25 (2023/2024)
- SANS Top 25
- Language-specific vulnerability research

This module provides standardized CWE coverage for all supported languages.
"""

# OWASP Top 10 2021 to CWE Mapping
OWASP_TOP_10_2021 = {
    'A01:2021-Broken Access Control': [
        'CWE-200',  # Exposure of Sensitive Information
        'CWE-201',  # Exposure of Sensitive Information Through Sent Data
        'CWE-352',  # Cross-Site Request Forgery (CSRF)
        'CWE-425',  # Direct Request ('Forced Browsing')
        'CWE-639',  # Authorization Bypass Through User-Controlled Key
    ],
    'A02:2021-Cryptographic Failures': [
        'CWE-259',  # Use of Hard-coded Password
        'CWE-327',  # Use of a Broken or Risky Cryptographic Algorithm
        'CWE-328',  # Use of Weak Hash
        'CWE-329',  # Generation of Predictable IV with CBC Mode
        'CWE-798',  # Use of Hard-coded Credentials
    ],
    'A03:2021-Injection': [
        'CWE-73',   # External Control of File Name or Path
        'CWE-74',   # Improper Neutralization of Special Elements
        'CWE-75',   # Special Element Injection
        'CWE-77',   # Command Injection
        'CWE-78',   # OS Command Injection
        'CWE-79',   # Cross-site Scripting (XSS)
        'CWE-88',   # Argument Injection
        'CWE-89',   # SQL Injection
        'CWE-90',   # LDAP Injection
        'CWE-91',   # XML Injection
        'CWE-94',   # Code Injection
        'CWE-943',  # Improper Neutralization of Special Elements in Data Query Logic
    ],
    'A04:2021-Insecure Design': [
        'CWE-209',  # Generation of Error Message Containing Sensitive Information
        'CWE-256',  # Plaintext Storage of a Password
        'CWE-257',  # Storing Passwords in a Recoverable Format
        'CWE-269',  # Improper Privilege Management
        'CWE-280',  # Improper Handling of Insufficient Permissions
        'CWE-311',  # Missing Encryption of Sensitive Data
        'CWE-312',  # Cleartext Storage of Sensitive Information
        'CWE-313',  # Cleartext Storage in a File or on Disk
        'CWE-316',  # Cleartext Storage of Sensitive Information in Memory
        'CWE-419',  # Unprotected Primary Channel
        'CWE-430',  # Deployment of Wrong Handler
        'CWE-434',  # Unrestricted Upload of File with Dangerous Type
        'CWE-693',  # Protection Mechanism Failure
    ],
    'A05:2021-Security Misconfiguration': [
        'CWE-2',    # Environmental Security Flaws
        'CWE-11',   # ASP.NET Misconfiguration
        'CWE-13',   # ASP.NET Misconfiguration: Password in Configuration File
        'CWE-15',   # External Control of System or Configuration Setting
        'CWE-16',   # Configuration
        'CWE-260',  # Password in Configuration File
        'CWE-315',  # Cleartext Storage of Sensitive Information in a Cookie
        'CWE-520',  # .NET Misconfiguration: Use of Impersonation
        'CWE-526',  # Exposure of Sensitive Information Through Environmental Variables
        'CWE-537',  # Java Runtime Error Message Containing Sensitive Information
        'CWE-541',  # Inclusion of Sensitive Information in an Include File
        'CWE-547',  # Use of Hard-coded, Security-relevant Constants
        'CWE-611',  # Improper Restriction of XML External Entity Reference (XXE)
        'CWE-614',  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
        'CWE-756',  # Missing Custom Error Page
        'CWE-776',  # Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
        'CWE-942',  # Overly Permissive Cross-domain Whitelist
        'CWE-1004', # Sensitive Cookie Without 'HttpOnly' Flag
        'CWE-1032', # OWASP Top Ten 2017 Category A6 - Security Misconfiguration
        'CWE-1174', # ASP.NET Misconfiguration: Improper Model Validation
    ],
    'A06:2021-Vulnerable and Outdated Components': [
        'CWE-1035', # 2020 CWE Top 25
        'CWE-1104', # Use of Unmaintained Third Party Components
    ],
    'A07:2021-Identification and Authentication Failures': [
        'CWE-255',  # Credentials Management Errors
        'CWE-259',  # Use of Hard-coded Password
        'CWE-287',  # Improper Authentication
        'CWE-288',  # Authentication Bypass Using an Alternate Path or Channel
        'CWE-290',  # Authentication Bypass by Spoofing
        'CWE-294',  # Authentication Bypass by Capture-replay
        'CWE-295',  # Improper Certificate Validation
        'CWE-297',  # Improper Validation of Certificate with Host Mismatch
        'CWE-300',  # Channel Accessible by Non-Endpoint
        'CWE-302',  # Authentication Bypass by Assumed-Immutable Data
        'CWE-304',  # Missing Critical Step in Authentication
        'CWE-306',  # Missing Authentication for Critical Function
        'CWE-307',  # Improper Restriction of Excessive Authentication Attempts
        'CWE-384',  # Session Fixation
        'CWE-521',  # Weak Password Requirements
        'CWE-522',  # Insufficiently Protected Credentials
        'CWE-640',  # Weak Password Recovery Mechanism for Forgotten Password
        'CWE-798',  # Use of Hard-coded Credentials
        'CWE-940',  # Improper Verification of Source of a Communication Channel
        'CWE-1216', # Lockout Mechanism Errors
    ],
    'A08:2021-Software and Data Integrity Failures': [
        'CWE-345',  # Insufficient Verification of Data Authenticity
        'CWE-353',  # Missing Support for Integrity Check
        'CWE-426',  # Untrusted Search Path
        'CWE-494',  # Download of Code Without Integrity Check
        'CWE-502',  # Deserialization of Untrusted Data
        'CWE-565',  # Reliance on Cookies without Validation and Integrity Checking
        'CWE-784',  # Reliance on Cookies without Validation and Integrity Checking in a Security Decision
        'CWE-829',  # Inclusion of Functionality from Untrusted Control Sphere
        'CWE-830',  # Inclusion of Web Functionality from an Untrusted Source
        'CWE-915',  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
    ],
    'A09:2021-Security Logging and Monitoring Failures': [
        'CWE-117',  # Improper Output Neutralization for Logs
        'CWE-223',  # Omission of Security-relevant Information
        'CWE-532',  # Insertion of Sensitive Information into Log File
        'CWE-778',  # Insufficient Logging
    ],
    'A10:2021-Server-Side Request Forgery (SSRF)': [
        'CWE-918',  # Server-Side Request Forgery (SSRF)
    ],
}

# CWE Top 25 Most Dangerous Software Weaknesses (2023)
CWE_TOP_25_2023 = [
    'CWE-787',  # Out-of-bounds Write
    'CWE-79',   # Cross-site Scripting
    'CWE-89',   # SQL Injection
    'CWE-20',   # Improper Input Validation
    'CWE-78',   # OS Command Injection
    'CWE-125',  # Out-of-bounds Read
    'CWE-22',   # Path Traversal
    'CWE-352',  # Cross-Site Request Forgery (CSRF)
    'CWE-434',  # Unrestricted Upload of File with Dangerous Type
    'CWE-862',  # Missing Authorization
    'CWE-476',  # NULL Pointer Dereference
    'CWE-287',  # Improper Authentication
    'CWE-190',  # Integer Overflow or Wraparound
    'CWE-502',  # Deserialization of Untrusted Data
    'CWE-77',   # Command Injection
    'CWE-119',  # Improper Restriction of Operations within Bounds of Memory Buffer
    'CWE-798',  # Use of Hard-coded Credentials
    'CWE-918',  # Server-Side Request Forgery (SSRF)
    'CWE-306',  # Missing Authentication for Critical Function
    'CWE-362',  # Concurrent Execution using Shared Resource with Improper Synchronization
    'CWE-269',  # Improper Privilege Management
    'CWE-94',   # Improper Control of Generation of Code
    'CWE-863',  # Incorrect Authorization
    'CWE-276',  # Incorrect Default Permissions
    'CWE-200',  # Exposure of Sensitive Information to an Unauthorized Actor
]

# Universal CWEs (Apply to ALL languages)
UNIVERSAL_CWES = [
    'CWE-20',   # Improper Input Validation
    'CWE-22',   # Path Traversal
    'CWE-78',   # OS Command Injection
    'CWE-79',   # Cross-site Scripting (if web-facing)
    'CWE-89',   # SQL Injection (if database access)
    'CWE-200',  # Information Exposure
    'CWE-259',  # Use of Hard-coded Password
    'CWE-287',  # Improper Authentication
    'CWE-327',  # Use of Broken/Risky Crypto
    'CWE-352',  # CSRF (if web-facing)
    'CWE-502',  # Deserialization of Untrusted Data
    'CWE-732',  # Incorrect Permission Assignment
    'CWE-798',  # Use of Hard-coded Credentials
    'CWE-918',  # SSRF (if network access)
]

# Language-Specific CWE Priority Lists
LANGUAGE_CWE_MAPPING = {
    'python': [
        # Universal (apply to all)
        *UNIVERSAL_CWES,
        # Python-specific
        'CWE-94',   # Code Injection (eval, exec)
        'CWE-95',   # Improper Neutralization of Directives in Dynamically Evaluated Code
        'CWE-377',  # Insecure Temporary File
        'CWE-611',  # XXE
        'CWE-776',  # Unrestricted XML External Entity Reference
        'CWE-943',  # Improper Neutralization of Special Elements in Data Query
        # Web frameworks (Django, Flask)
        'CWE-1321', # Improperly Controlled Modification of Object Prototype Attributes
        'CWE-613',  # Insufficient Session Expiration
        'CWE-614',  # Sensitive Cookie Without Secure Flag
    ],
    
    'java': [
        # Universal
        *UNIVERSAL_CWES,
        # Java-specific
        'CWE-90',   # LDAP Injection
        'CWE-91',   # XML Injection
        'CWE-113',  # HTTP Response Splitting
        'CWE-129',  # Improper Validation of Array Index
        'CWE-134',  # Uncontrolled Format String
        'CWE-330',  # Use of Insufficiently Random Values
        'CWE-470',  # Use of Externally-Controlled Input to Select Classes or Code
        'CWE-476',  # NULL Pointer Dereference
        'CWE-611',  # XXE
        'CWE-643',  # XPath Injection
        'CWE-652',  # Improper Neutralization of Data within XQuery Expressions
        'CWE-776',  # Unrestricted XML Entity Reference
        # Java EE / Spring specific
        'CWE-501',  # Trust Boundary Violation
        'CWE-564',  # SQL Injection through Hibernate
        'CWE-1204', # Generation of Weak Initialization Vector (IV)
    ],
    
    'javascript': [
        # Universal
        *UNIVERSAL_CWES,
        # JavaScript-specific
        'CWE-94',   # Code Injection (eval)
        'CWE-95',   # Improper Neutralization of Directives in Dynamically Evaluated Code
        'CWE-1321', # Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)
        'CWE-915',  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
        'CWE-601',  # URL Redirection to Untrusted Site ('Open Redirect')
        'CWE-611',  # XXE (if XML processing)
        'CWE-913',  # Improper Control of Dynamically-Managed Code Resources
        # Node.js specific
        'CWE-426',  # Untrusted Search Path
        'CWE-494',  # Download of Code Without Integrity Check
        'CWE-829',  # Inclusion of Functionality from Untrusted Control Sphere
    ],
    
    'go': [
        # Universal
        *UNIVERSAL_CWES,
        # Go-specific
        'CWE-362',  # Concurrent Execution using Shared Resource (Race Condition)
        'CWE-367',  # Time-of-check Time-of-use (TOCTOU) Race Condition
        'CWE-404',  # Improper Resource Shutdown or Release
        'CWE-459',  # Incomplete Cleanup
        'CWE-665',  # Improper Initialization
        'CWE-674',  # Uncontrolled Recursion
        'CWE-835',  # Loop with Unreachable Exit Condition
        'CWE-1209', # Failure to Disable Reserved Bits and Processor Features
    ],
    
    'rust': [
        # Universal (reduced - Rust's safety prevents many)
        'CWE-20',   # Improper Input Validation
        'CWE-22',   # Path Traversal
        'CWE-78',   # OS Command Injection
        'CWE-89',   # SQL Injection
        'CWE-327',  # Weak Crypto
        'CWE-798',  # Hard-coded Credentials
        # Rust-specific (unsafe code)
        'CWE-119',  # Improper Restriction of Operations within Bounds (in unsafe)
        'CWE-125',  # Out-of-bounds Read (in unsafe)
        'CWE-415',  # Double Free (in unsafe)
        'CWE-416',  # Use After Free (in unsafe)
        'CWE-476',  # NULL Pointer Dereference (in unsafe)
        'CWE-676',  # Use of Potentially Dangerous Function
        'CWE-787',  # Out-of-bounds Write (in unsafe)
        'CWE-911',  # Improper Update of Reference Count
    ],
    
    'cpp': [
        # Universal
        *UNIVERSAL_CWES,
        # C/C++-specific (memory safety)
        'CWE-119',  # Improper Restriction of Operations within Bounds of Memory Buffer
        'CWE-120',  # Buffer Copy without Checking Size of Input
        'CWE-121',  # Stack-based Buffer Overflow
        'CWE-122',  # Heap-based Buffer Overflow
        'CWE-125',  # Out-of-bounds Read
        'CWE-126',  # Buffer Over-read
        'CWE-127',  # Buffer Under-read
        'CWE-128',  # Wrap-around Error
        'CWE-129',  # Improper Validation of Array Index
        'CWE-134',  # Use of Externally-Controlled Format String
        'CWE-190',  # Integer Overflow or Wraparound
        'CWE-191',  # Integer Underflow
        'CWE-252',  # Unchecked Return Value
        'CWE-401',  # Missing Release of Memory after Effective Lifetime
        'CWE-404',  # Improper Resource Shutdown or Release
        'CWE-415',  # Double Free
        'CWE-416',  # Use After Free
        'CWE-457',  # Use of Uninitialized Variable
        'CWE-476',  # NULL Pointer Dereference
        'CWE-665',  # Improper Initialization
        'CWE-667',  # Improper Locking
        'CWE-676',  # Use of Potentially Dangerous Function
        'CWE-704',  # Incorrect Type Conversion or Cast
        'CWE-762',  # Mismatched Memory Management Routines
        'CWE-783',  # Operator Precedence Logic Error
        'CWE-787',  # Out-of-bounds Write
        'CWE-824',  # Access of Uninitialized Pointer
        'CWE-825',  # Expired Pointer Dereference
    ],
    
    'php': [
        # Universal
        *UNIVERSAL_CWES,
        # PHP-specific
        'CWE-94',   # Code Injection (eval)
        'CWE-95',   # Improper Neutralization of Directives in Dynamically Evaluated Code
        'CWE-98',   # Improper Control of Filename for Include/Require Statement (File Inclusion)
        'CWE-113',  # HTTP Response Splitting
        'CWE-134',  # Uncontrolled Format String
        'CWE-601',  # URL Redirection to Untrusted Site
        'CWE-611',  # XXE
        'CWE-643',  # XPath Injection
        'CWE-652',  # Improper Neutralization of Data within XQuery Expressions
        # PHP session/cookie
        'CWE-384',  # Session Fixation
        'CWE-613',  # Insufficient Session Expiration
        'CWE-614',  # Sensitive Cookie Without Secure Flag
        'CWE-1004', # Sensitive Cookie Without 'HttpOnly' Flag
    ],
    
    'ruby': [
        # Universal
        *UNIVERSAL_CWES,
        # Ruby/Rails-specific
        'CWE-94',   # Code Injection (eval)
        'CWE-95',   # Improper Neutralization of Directives in Dynamically Evaluated Code
        'CWE-601',  # URL Redirection to Untrusted Site
        'CWE-611',  # XXE
        'CWE-915',  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
        'CWE-1321', # Mass Assignment
        # Rails-specific
        'CWE-384',  # Session Fixation
        'CWE-565',  # Reliance on Cookies without Validation
        'CWE-613',  # Insufficient Session Expiration
        'CWE-614',  # Sensitive Cookie Without Secure Flag
    ],
}


def get_cwes_for_language(language: str) -> list:
    """Get comprehensive list of CWEs for a specific language."""
    return LANGUAGE_CWE_MAPPING.get(language, UNIVERSAL_CWES)


def get_all_unique_cwes() -> list:
    """Get all unique CWEs across all languages."""
    all_cwes = set()
    for cwes in LANGUAGE_CWE_MAPPING.values():
        all_cwes.update(cwes)
    return sorted(list(all_cwes))


def get_owasp_cwes() -> list:
    """Get all CWEs from OWASP Top 10."""
    all_cwes = set()
    for cwes in OWASP_TOP_10_2021.values():
        all_cwes.update(cwes)
    return sorted(list(all_cwes))


# CWE to description mapping (for reporting)
CWE_DESCRIPTIONS = {
    'CWE-20': 'Improper Input Validation',
    'CWE-22': 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
    'CWE-78': 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
    'CWE-79': 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
    'CWE-89': 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
    'CWE-90': 'Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)',
    'CWE-94': 'Improper Control of Generation of Code (Code Injection)',
    'CWE-119': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
    'CWE-125': 'Out-of-bounds Read',
    'CWE-190': 'Integer Overflow or Wraparound',
    'CWE-200': 'Exposure of Sensitive Information to an Unauthorized Actor',
    'CWE-259': 'Use of Hard-coded Password',
    'CWE-287': 'Improper Authentication',
    'CWE-327': 'Use of a Broken or Risky Cryptographic Algorithm',
    'CWE-352': 'Cross-Site Request Forgery (CSRF)',
    'CWE-362': 'Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)',
    'CWE-416': 'Use After Free',
    'CWE-476': 'NULL Pointer Dereference',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-611': 'Improper Restriction of XML External Entity Reference',
    'CWE-732': 'Incorrect Permission Assignment for Critical Resource',
    'CWE-787': 'Out-of-bounds Write',
    'CWE-798': 'Use of Hard-coded Credentials',
    'CWE-918': 'Server-Side Request Forgery (SSRF)',
    'CWE-1321': 'Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution / Mass Assignment)',
}


if __name__ == '__main__':
    # Print statistics
    print("=== CWE Coverage Statistics ===\n")
    
    for lang, cwes in LANGUAGE_CWE_MAPPING.items():
        print(f"{lang.upper()}: {len(cwes)} CWEs")
    
    print(f"\nTotal Unique CWEs: {len(get_all_unique_cwes())}")
    print(f"OWASP Top 10 CWEs: {len(get_owasp_cwes())}")
    print(f"CWE Top 25: {len(CWE_TOP_25_2023)}")


