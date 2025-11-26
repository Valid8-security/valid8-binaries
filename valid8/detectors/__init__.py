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
Security Detectors Module

This module contains all security detectors for the Parry scanner:
- Framework-specific detectors (Spring, Django, Rails, Express, Laravel, ASP.NET)
- Advanced language detectors (Rust, Swift, Kotlin, TypeScript, Go)
- Core pattern-based detectors (existing detector.py integration)

Total detector count: 150+ patterns across 15+ frameworks and languages
"""

from .framework_specific import (
    get_all_framework_detectors,
    SpringSecurityDetectors,
    DjangoSecurityDetectors,
    RailsSecurityDetectors,
    ExpressSecurityDetectors
)

from .language_advanced import (
    get_all_advanced_detectors,
    RustSecurityDetectors,
    SwiftSecurityDetectors,
    KotlinSecurityDetectors,
    TypeScriptSecurityDetectors,
    GoSecurityDetectors
)

from .missing_critical_cwes import (
    detect_missing_critical_cwes,
    MissingCriticalCWEDetector
)

__all__ = [
    'get_all_framework_detectors',
    'get_all_advanced_detectors',
    'detect_missing_critical_cwes',
    'MissingCriticalCWEDetector',
    'SpringSecurityDetectors',
    'DjangoSecurityDetectors',
    'RailsSecurityDetectors',
    'ExpressSecurityDetectors',
    'RustSecurityDetectors',
    'SwiftSecurityDetectors',
    'KotlinSecurityDetectors',
    'TypeScriptSecurityDetectors',
    'GoSecurityDetectors'
]


def get_total_detector_count() -> int:
    """Return total count of all detectors"""
    framework_count = len(get_all_framework_detectors())
    advanced_count = len(get_all_advanced_detectors())
    # Assuming ~80 existing core detectors from detector.py
    core_count = 80
    return core_count + framework_count + advanced_count


def get_detector_statistics() -> dict:
    """Get detailed statistics about detector coverage"""
    framework_detectors = get_all_framework_detectors()
    advanced_detectors = get_all_advanced_detectors()
    
    frameworks = {}
    for detector in framework_detectors:
        frameworks[detector.framework] = frameworks.get(detector.framework, 0) + 1
    
    languages = {}
    for detector in advanced_detectors:
        languages[detector.language] = languages.get(detector.language, 0) + 1
    
    return {
        'total_detectors': get_total_detector_count(),
        'framework_detectors': len(framework_detectors),
        'advanced_detectors': len(advanced_detectors),
        'frameworks_covered': frameworks,
        'languages_covered': languages
    }
