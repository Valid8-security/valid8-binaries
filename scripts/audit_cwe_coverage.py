#!/usr/bin/env python3
"""
CWE Coverage Audit Script
Analyzes Parry's detector files to map CWE coverage
"""
import re
from pathlib import Path
from collections import defaultdict

# Detector source files
DETECTOR_FILES = [
    "parry/scanner.py",
    "parry/language_support/python_analyzer.py",
    "parry/language_support/javascript_analyzer.py",
    "parry/language_support/java_analyzer.py",
    "parry/language_support/go_analyzer.py",
    "parry/language_support/ruby_analyzer.py",
    "parry/language_support/rust_analyzer.py",
    "parry/language_support/php_analyzer.py",
    "parry/language_support/cpp_analyzer.py",
    "parry/security_domains/ai_ml_security.py",
    "parry/security_domains/api_security.py",
    "parry/detectors/framework_specific.py",
    "parry/detectors/language_advanced.py",
    "parry/detectors/crypto_modern.py",
    "parry/detectors/missing_critical_cwes.py",  # NEW: MITRE Top 25 gaps
    "parry/container_iac_scanner.py",
    "parry/symbolic_execution.py",
    "parry/advanced_static_analysis.py",
]

# OWASP Top 10 2021 CWE mappings
OWASP_2021 = {
    "A01:2021 - Broken Access Control": [
        "CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201",
        "CWE-219", "CWE-264", "CWE-275", "CWE-284", "CWE-285", "CWE-352",
        "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497",
        "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601",
        "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863",
        "CWE-913", "CWE-922", "CWE-1275"
    ],
    "A02:2021 - Cryptographic Failures": [
        "CWE-259", "CWE-295", "CWE-297", "CWE-311", "CWE-312", "CWE-319",
        "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326",
        "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335",
        "CWE-336", "CWE-337", "CWE-338", "CWE-340", "CWE-347", "CWE-523",
        "CWE-720", "CWE-757"
    ],
    "A03:2021 - Injection": [
        "CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79",
        "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90",
        "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97",
        "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138",
        "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643",
        "CWE-917", "CWE-943"
    ],
    "A04:2021 - Insecure Design": [
        "CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256",
        "CWE-257", "CWE-258", "CWE-259", "CWE-266", "CWE-269", "CWE-280",
        "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-419", "CWE-430",
        "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501", "CWE-522",
        "CWE-525", "CWE-539", "CWE-579", "CWE-602", "CWE-642", "CWE-646",
        "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807",
        "CWE-840", "CWE-841", "CWE-942", "CWE-1192", "CWE-1220", "CWE-1173"
    ],
    "A05:2021 - Security Misconfiguration": [
        "CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260",
        "CWE-315", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547",
        "CWE-614", "CWE-732", "CWE-749", "CWE-942"
    ],
    "A06:2021 - Vulnerable and Outdated Components": [
        "CWE-1104", "CWE-1035", "CWE-494", "CWE-506", "CWE-829", "CWE-830"
    ],
    "A07:2021 - Identification and Authentication Failures": [
        "CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294",
        "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306",
        "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620",
        "CWE-640", "CWE-798", "CWE-940"
    ],
    "A08:2021 - Software and Data Integrity Failures": [
        "CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565",
        "CWE-784", "CWE-829", "CWE-830", "CWE-913"
    ],
    "A09:2021 - Security Logging and Monitoring Failures": [
        "CWE-117", "CWE-223", "CWE-532", "CWE-778"
    ],
    "A10:2021 - Server-Side Request Forgery": [
        "CWE-918"
    ]
}

# OWASP Top 10 2025 Draft CWE mappings
OWASP_2025 = {
    "A01:2025 - Broken Access Control": [
        "CWE-22", "CWE-284", "CWE-285", "CWE-352", "CWE-639", "CWE-862", "CWE-863"
    ],
    "A02:2025 - Cryptographic Failures": [
        "CWE-259", "CWE-295", "CWE-311", "CWE-319", "CWE-321", "CWE-326", "CWE-327", "CWE-328", "CWE-330"
    ],
    "A03:2025 - Injection": [
        "CWE-20", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-94", "CWE-95", "CWE-98", "CWE-643", "CWE-917", "CWE-943"
    ],
    "A04:2025 - Insecure Design": [
        "CWE-209", "CWE-256", "CWE-257", "CWE-258", "CWE-259", "CWE-266", "CWE-269", "CWE-311", "CWE-312", "CWE-313", "CWE-434", "CWE-522", "CWE-525", "CWE-602"
    ],
    "A05:2025 - Security Misconfiguration": [
        "CWE-16", "CWE-215", "CWE-250", "CWE-489", "CWE-614", "CWE-732", "CWE-749"
    ],
    "A06:2025 - Vulnerable and Outdated Components": [
        "CWE-494", "CWE-506", "CWE-829", "CWE-830", "CWE-1035", "CWE-1104"
    ],
    "A07:2025 - Identification and Authentication Failures": [
        "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-306", "CWE-307", "CWE-384", "CWE-521", "CWE-613", "CWE-798", "CWE-940"
    ],
    "A08:2025 - Software and Data Integrity Failures": [
        "CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-913"
    ],
    "A09:2025 - Security Logging and Monitoring Failures": [
        "CWE-117", "CWE-223", "CWE-532", "CWE-778"
    ],
    "A10:2025 - Server-Side Request Forgery": [
        "CWE-918"
    ]
}

# MITRE CWE Top 25 2024
MITRE_TOP_25 = [
    "CWE-79", "CWE-787", "CWE-89", "CWE-20", "CWE-125", "CWE-78",
    "CWE-416", "CWE-22", "CWE-352", "CWE-434", "CWE-862", "CWE-476",
    "CWE-287", "CWE-190", "CWE-502", "CWE-77", "CWE-119", "CWE-798",
    "CWE-918", "CWE-306", "CWE-362", "CWE-269", "CWE-94", "CWE-863",
    "CWE-276"
]

def extract_cwes_from_file(filepath):
    """Extract all CWE references from a file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            return set(re.findall(r'CWE-\d+', content))
    except Exception as e:
        print(f"Warning: Could not read {filepath}: {e}")
        return set()

def main():
    print("=" * 80)
    print("PARRY SECURITY SCANNER - CWE COVERAGE AUDIT")
    print("=" * 80)
    print()
    
    # Extract all CWEs
    all_cwes = set()
    cwe_by_file = defaultdict(set)
    
    base_path = Path(__file__).parent.parent
    for detector_file in DETECTOR_FILES:
        filepath = base_path / detector_file
        cwes = extract_cwes_from_file(filepath)
        all_cwes.update(cwes)
        cwe_by_file[detector_file] = cwes
    
    print(f"📊 TOTAL UNIQUE CWEs DETECTED: {len(all_cwes)}")
    print()
    
    # Print all CWEs sorted
    print("🔍 All Covered CWEs:")
    for cwe in sorted(all_cwes, key=lambda x: int(x.split('-')[1])):
        print(f"  • {cwe}")
    print()
    
    # OWASP Top 10 2021 Coverage
    print("=" * 80)
    print("OWASP TOP 10 2021 COVERAGE")
    print("=" * 80)
    total_owasp_2021 = 0
    covered_owasp_2021 = 0
    for category, cwes in OWASP_2021.items():
        total_owasp_2021 += len(cwes)
        covered = [cwe for cwe in cwes if cwe in all_cwes]
        covered_owasp_2021 += len(covered)
        coverage = (len(covered) / len(cwes)) * 100
        print(f"\n{category}")
        print(f"  Coverage: {len(covered)}/{len(cwes)} ({coverage:.1f}%)")
        if covered:
            print(f"  ✅ Covered: {', '.join(sorted(covered))}")
        missing = [cwe for cwe in cwes if cwe not in all_cwes]
        if missing:
            print(f"  ❌ Missing: {', '.join(sorted(missing))}")
    
    overall_owasp_2021 = (covered_owasp_2021 / total_owasp_2021) * 100
    print(f"\n📈 OVERALL OWASP 2021 COVERAGE: {covered_owasp_2021}/{total_owasp_2021} ({overall_owasp_2021:.1f}%)")
    print()
    
    # OWASP Top 10 2025 Coverage
    print("=" * 80)
    print("OWASP TOP 10 2025 (DRAFT) COVERAGE")
    print("=" * 80)
    total_owasp_2025 = 0
    covered_owasp_2025 = 0
    for category, cwes in OWASP_2025.items():
        total_owasp_2025 += len(set(cwes))
        covered = [cwe for cwe in set(cwes) if cwe in all_cwes]
        covered_owasp_2025 += len(covered)
        coverage = (len(covered) / len(set(cwes))) * 100
        print(f"\n{category}")
        print(f"  Coverage: {len(covered)}/{len(set(cwes))} ({coverage:.1f}%)")
        if covered:
            print(f"  ✅ Covered: {', '.join(sorted(covered))}")
        missing = [cwe for cwe in set(cwes) if cwe not in all_cwes]
        if missing:
            print(f"  ❌ Missing: {', '.join(sorted(missing))}")
    
    overall_owasp_2025 = (covered_owasp_2025 / total_owasp_2025) * 100
    print(f"\n📈 OVERALL OWASP 2025 COVERAGE: {covered_owasp_2025}/{total_owasp_2025} ({overall_owasp_2025:.1f}%)")
    print()
    
    # MITRE CWE Top 25 Coverage
    print("=" * 80)
    print("MITRE CWE TOP 25 2024 COVERAGE")
    print("=" * 80)
    covered_mitre = [cwe for cwe in MITRE_TOP_25 if cwe in all_cwes]
    missing_mitre = [cwe for cwe in MITRE_TOP_25 if cwe not in all_cwes]
    mitre_coverage = (len(covered_mitre) / len(MITRE_TOP_25)) * 100
    
    print(f"\n✅ Covered ({len(covered_mitre)}/{len(MITRE_TOP_25)} - {mitre_coverage:.1f}%):")
    for cwe in covered_mitre:
        print(f"  • {cwe}")
    
    if missing_mitre:
        print(f"\n❌ Missing ({len(missing_mitre)}/{len(MITRE_TOP_25)} - {100-mitre_coverage:.1f}%):")
        for cwe in missing_mitre:
            print(f"  • {cwe}")
    print()
    
    # Summary
    print("=" * 80)
    print("COVERAGE SUMMARY")
    print("=" * 80)
    print(f"✅ Total Unique CWEs Covered: {len(all_cwes)}")
    print(f"📊 OWASP Top 10 2021: {overall_owasp_2021:.1f}% ({covered_owasp_2021}/{total_owasp_2021})")
    print(f"📊 OWASP Top 10 2025: {overall_owasp_2025:.1f}% ({covered_owasp_2025}/{total_owasp_2025})")
    print(f"📊 MITRE CWE Top 25: {mitre_coverage:.1f}% ({len(covered_mitre)}/{len(MITRE_TOP_25)})")
    print()
    
    # Recommendations
    print("=" * 80)
    print("RECOMMENDATIONS FOR MISSING CRITICAL CWEs")
    print("=" * 80)
    critical_missing = []
    for cwe in missing_mitre:
        critical_missing.append(cwe)
    
    if critical_missing:
        print("\n🔴 CRITICAL: These CWEs are in MITRE Top 25 but not covered:")
        for cwe in critical_missing:
            print(f"  • {cwe} - PRIORITY: HIGH")
    
    print()
    print("=" * 80)
    print("END OF AUDIT")
    print("=" * 80)

if __name__ == "__main__":
    main()
