#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Validate CWE Coverage
Checks that all CWE detectors are loaded and counts unique CWEs
"""
import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def validate_cwe_coverage():
    """Validate CWE expansion coverage"""
    try:
        from parry.detectors.cwe_expansion import get_all_cwe_expansion_detectors
        from parry.scanner import Scanner
        
        print("=" * 70)
        print("CWE COVERAGE VALIDATION")
        print("=" * 70)
        
        # Load detectors
        detectors = get_all_cwe_expansion_detectors()
        print(f"\n✅ Loaded {len(detectors)} detector classes")
        
        # Count unique CWEs
        cwe_set = set()
        detector_cwes = {}
        
        for det in detectors:
            doc = det.__class__.__doc__ or ""
            cwes = re.findall(r'CWE-\d+', doc)
            cwe_set.update(cwes)
            detector_cwes[det.__class__.__name__] = cwes
        
        print(f"📊 Unique CWEs: {len(cwe_set)}")
        print(f"🎯 Target: 200-300 CWEs")
        print(f"📈 Progress: {len(cwe_set)}/250 = {len(cwe_set)/250*100:.1f}%")
        
        # Check for duplicates
        all_cwes = []
        for det in detectors:
            doc = det.__class__.__doc__ or ""
            all_cwes.extend(re.findall(r'CWE-\d+', doc))
        
        duplicates = [cwe for cwe in set(all_cwes) if all_cwes.count(cwe) > 1]
        if duplicates:
            print(f"\n⚠️  Found {len(duplicates)} CWEs covered by multiple detectors:")
            for cwe in sorted(duplicates)[:10]:
                print(f"   - {cwe}")
        
        # Test scanner integration
        scanner = Scanner()
        print(f"\n✅ Scanner integration: {len(scanner.detectors)} total detectors")
        print(f"   - Legacy: 10")
        print(f"   - CWE Expansion: {len(scanner.detectors) - 10}")
        
        # Validate CWE numbers
        invalid_cwes = []
        for cwe in cwe_set:
            cwe_num = cwe.replace('CWE-', '')
            try:
                num = int(cwe_num)
                if num < 1 or num > 10000:
                    invalid_cwes.append(cwe)
            except ValueError:
                invalid_cwes.append(cwe)
        
        if invalid_cwes:
            print(f"\n❌ Found {len(invalid_cwes)} invalid CWE numbers:")
            for cwe in invalid_cwes[:10]:
                print(f"   - {cwe}")
            return False
        
        # Summary
        print("\n" + "=" * 70)
        if len(cwe_set) >= 200:
            print("✅ SUCCESS: CWE coverage target met!")
            return True
        else:
            print(f"⚠️  WARNING: Need {200 - len(cwe_set)} more CWEs to reach target")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = validate_cwe_coverage()
    sys.exit(0 if success else 1)


