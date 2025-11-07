"""
CWE Expansion Module - Comprehensive CWE Coverage (200+ CWEs)

This module contains detectors for all CWE categories to achieve 100% coverage.
Organized by OWASP Top 10, CWE Top 25, and comprehensive categories.
"""

# Import all detector modules
try:
    from .cwe_top25 import get_cwe_top25_detectors
except ImportError:
    get_cwe_top25_detectors = lambda: []

try:
    from .cwe_cryptography import get_cryptography_detectors
except ImportError:
    get_cryptography_detectors = lambda: []

try:
    from .cwe_injection import get_injection_detectors
except ImportError:
    get_injection_detectors = lambda: []

try:
    from .cwe_authentication import get_authentication_detectors
except ImportError:
    get_authentication_detectors = lambda: []

try:
    from .cwe_authorization import get_authorization_detectors
except ImportError:
    get_authorization_detectors = lambda: []

try:
    from .cwe_input_validation import get_input_validation_detectors
except ImportError:
    get_input_validation_detectors = lambda: []

try:
    from .cwe_memory_safety import get_memory_safety_detectors
except ImportError:
    get_memory_safety_detectors = lambda: []

try:
    from .cwe_error_handling import get_error_handling_detectors
except ImportError:
    get_error_handling_detectors = lambda: []

try:
    from .cwe_resource_management import get_resource_management_detectors
except ImportError:
    get_resource_management_detectors = lambda: []

try:
    from .cwe_api_security import get_api_security_detectors
except ImportError:
    get_api_security_detectors = lambda: []

try:
    from .cwe_information_disclosure import get_information_disclosure_detectors
except ImportError:
    get_information_disclosure_detectors = lambda: []

try:
    from .cwe_business_logic import get_business_logic_detectors
except ImportError:
    get_business_logic_detectors = lambda: []

try:
    from .cwe_configuration import get_configuration_detectors
except ImportError:
    get_configuration_detectors = lambda: []

try:
    from .cwe_concurrency import get_concurrency_detectors
except ImportError:
    get_concurrency_detectors = lambda: []

try:
    from .cwe_framework_specific import get_framework_specific_detectors
except ImportError:
    get_framework_specific_detectors = lambda: []

try:
    from .cwe_xss import get_xss_detectors
except ImportError:
    get_xss_detectors = lambda: []

try:
    from .cwe_file_handling import get_file_handling_detectors
except ImportError:
    get_file_handling_detectors = lambda: []

try:
    from .cwe_session import get_session_detectors
except ImportError:
    get_session_detectors = lambda: []

try:
    from .cwe_deserialization import get_deserialization_detectors
except ImportError:
    get_deserialization_detectors = lambda: []

try:
    from .cwe_code_quality import get_code_quality_detectors
except ImportError:
    get_code_quality_detectors = lambda: []

try:
    from .cwe_path_traversal import get_path_traversal_detectors
except ImportError:
    get_path_traversal_detectors = lambda: []


def get_all_cwe_expansion_detectors():
    """Get all CWE expansion detectors (200+ CWEs)"""
    detectors = []
    
    # CWE Top 25 (Most Dangerous)
    detectors.extend(get_cwe_top25_detectors())
    
    # Cryptography (30+ CWEs)
    detectors.extend(get_cryptography_detectors())
    
    # Injection variants (25+ CWEs)
    detectors.extend(get_injection_detectors())
    
    # XSS variants (10+ CWEs)
    detectors.extend(get_xss_detectors())
    
    # Authentication & Authorization (25+ CWEs)
    detectors.extend(get_authentication_detectors())
    detectors.extend(get_authorization_detectors())
    
    # Input Validation (15+ CWEs)
    detectors.extend(get_input_validation_detectors())
    
    # Memory Safety (20+ CWEs)
    detectors.extend(get_memory_safety_detectors())
    
    # Error Handling (10+ CWEs)
    detectors.extend(get_error_handling_detectors())
    
    # Resource Management (15+ CWEs)
    detectors.extend(get_resource_management_detectors())
    
    # API Security (10+ CWEs)
    detectors.extend(get_api_security_detectors())
    
    # Information Disclosure (15+ CWEs)
    detectors.extend(get_information_disclosure_detectors())
    
    # Business Logic (10+ CWEs)
    detectors.extend(get_business_logic_detectors())
    
    # Configuration (10+ CWEs)
    detectors.extend(get_configuration_detectors())
    
    # Concurrency (10+ CWEs)
    detectors.extend(get_concurrency_detectors())
    
    # Framework-specific (15+ CWEs)
    detectors.extend(get_framework_specific_detectors())
    
    # File Handling (10+ CWEs)
    detectors.extend(get_file_handling_detectors())
    
    # Session Management (10+ CWEs)
    detectors.extend(get_session_detectors())
    
    # Deserialization (5+ CWEs)
    detectors.extend(get_deserialization_detectors())
    
    # Code Quality (10+ CWEs)
    detectors.extend(get_code_quality_detectors())
    
    # Path Traversal (10+ CWEs)
    detectors.extend(get_path_traversal_detectors())
    
    return detectors
