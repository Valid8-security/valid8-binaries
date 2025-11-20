"""
CWE Expansion Detectors - 200+ CWE coverage
"""
from valid8.scanner import VulnerabilityDetector

def get_all_cwe_expansion_detectors():
    """Load all CWE expansion detectors"""
    detectors = []
    
    # Import all CWE modules
    modules = [
        'cwe_injection',
        'cwe_xss', 
        'cwe_path_traversal',
        'cwe_top25',
        'cwe_input_validation',
        'cwe_api_security',
        'cwe_authentication',
        'cwe_authorization',
        'cwe_business_logic',
        'cwe_code_quality',
        'cwe_concurrency',
        'cwe_configuration',
        'cwe_cryptography',
        'cwe_deserialization',
        'cwe_error_handling',
        'cwe_file_handling',
        'cwe_framework_specific',
        'cwe_memory_safety',
        'cwe_resource_management',
        'cwe_session',
    ]
    
    for module_name in modules:
        try:
            module = __import__(f'valid8.detectors.cwe_expansion.{module_name}', 
                              fromlist=[module_name])
            
            # Get all classes that are VulnerabilityDetector subclasses
            for attr_name in dir(module):
                if attr_name.startswith('_'):
                    continue
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, VulnerabilityDetector) and 
                    attr != VulnerabilityDetector):
                    try:
                        detectors.append(attr())
                    except Exception as e:
                        # Skip if instantiation fails
                        pass
        except Exception as e:
            # Skip modules that fail to import
            pass
    
    return detectors
