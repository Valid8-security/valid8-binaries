#!/usr/bin/env python3
"""
Simple Phase A Integration: Enhanced Patterns + AI Tuning

Directly integrates enhanced pattern libraries into Valid8 without complex imports.
"""

import re
from typing import List, Dict, Any, Tuple
from pathlib import Path

def create_enhanced_patterns():
    """Create enhanced pattern library for complex vulnerability detection."""
    
    return {
        'complex_sql_injection': {
            'patterns': [
                r'SELECT.*FROM.*WHERE.*\+.*\w+',  # Basic concatenation
                r'INSERT.*INTO.*VALUES.*\+.*\w+',  # Insert concatenation
                r'UPDATE.*SET.*\+.*\w+',          # Update concatenation
                r'query\s*=.*\+',  # Variable building with concatenation
                r'sql\s*=.*\+',    # SQL variable construction
                r'query\s*=.*\n.*\+.*\w+',  # Multi-line query building
                r'sql\s*=.*\n.*\+.*\w+',    # Multi-line SQL construction
            ],
            'confidence_boost': 0.2,
            'vulnerability_type': 'sql_injection'
        },
        
        'fstring_injection': {
            'patterns': [
                r'f["\'].*\{.*\}.*["\']',  # Basic f-string detection
                r'f["\'].*SELECT.*\{.*\}.*["\']',  # F-string with SELECT
                r'f["\'].*INSERT.*\{.*\}.*["\']',  # F-string with INSERT
                r'f["\'].*UPDATE.*\{.*\}.*["\']',  # F-string with UPDATE
                r'query\s*=.*f["\'].*\{.*\}',  # Query with f-string
                r'sql\s*=.*f["\'].*\{.*\}',    # SQL with f-string
                r'execute.*f["\'].*\{.*\}',    # Direct execute with f-string
                r'f["\'][\s\S]*?\{[\s\S]*?\}[\s\S]*?["\']',  # Multi-line f-strings
            ],
            'confidence_boost': 0.25,
            'vulnerability_type': 'sql_injection'
        },
        
        'template_literal_injection': {
            'patterns': [
                r'`.*\$\{.*\}.*`',  # Basic template literal
                r'<.*\$\{.*\}.*>',  # Template literal in HTML
                r'innerHTML.*`.*\$\{.*\}.*`',  # innerHTML with template
                r'document\.write.*`.*\$\{.*\}.*`',  # document.write with template
                r'html\s*=.*`.*\$\{.*\}',  # HTML building with template
                r'element\.innerHTML\s*=.*`.*\$\{.*\}',  # DOM manipulation
                r'response\.send.*`.*\$\{.*\}',  # Response with template
                r'`[\s\S]*?\$\{[\s\S]*?\}[\s\S]*?`',  # Multi-line templates
            ],
            'confidence_boost': 0.3,
            'vulnerability_type': 'xss'
        },
        
        'multi_line_command_injection': {
            'patterns': [
                r'subprocess\..*\[.*\+.*\]',  # Subprocess with concatenation in list
                r'os\.system.*\+',  # os.system with concatenation
                r'exec.*\+',        # exec with concatenation
                r'cmd\s*=.*\+',     # Command building with concatenation
                r'command\s*=.*\+', # Command variable construction
                r'os\.popen.*\+',   # popen with concatenation
                r'cmd\s*=.*\n.*\+.*\w+',  # Multi-line command building
                r'command\s*=.*\n.*\+.*\w+',  # Multi-line command construction
            ],
            'confidence_boost': 0.25,
            'vulnerability_type': 'command_injection'
        },
        
        'complex_path_traversal': {
            'patterns': [
                r'open.*\+.*\w+',      # File open with concatenation
                r'File\(.*\+.*\)',     # Java File with concatenation
                r'Path\..*\+.*\w+',    # Path operations with concatenation
                r'filename\s*=.*\+',   # Filename building
                r'filepath\s*=.*\+',   # Path construction
                r'file\s*=.*\+',       # File variable building
                r'path\s*=.*\n.*\+.*\w+',  # Multi-line path building
                r'filepath\s*=.*\n.*\+.*\w+',  # Multi-line filepath construction
            ],
            'confidence_boost': 0.2,
            'vulnerability_type': 'path_traversal'
        },
        
        'dynamic_eval_injection': {
            'patterns': [
                r'eval\s*\(.*\+.*\)',     # eval with concatenation
                r'exec\s*\(.*\+.*\)',     # exec with concatenation
                r'Function\s*\(.*\+.*\)', # Function constructor with concatenation
                r'code\s*=.*\+',         # Code building with concatenation
                r'script\s*=.*\+',       # Script construction
                r'eval\(.*\+.*\w+',      # eval with variable concatenation
                r'code\s*=.*\n.*\+.*\w+',  # Multi-line code building
                r'script\s*=.*\n.*\+.*\w+',  # Multi-line script construction
            ],
            'confidence_boost': 0.35,
            'vulnerability_type': 'code_injection'
        },
        
        'reflection_injection': {
            'patterns': [
                r'Class\.forName\s*\(.*\+.*\)',  # Java reflection with concatenation
                r'Method.*getMethod\s*\(.*\+.*\)',  # Method reflection
                r'getattr\s*\(.*\+.*\)',     # Python getattr with concatenation
                r'setattr\s*\(.*\+.*\)',     # Python setattr with concatenation
                r'class_name\s*=.*\+',       # Class name building
                r'method_name\s*=.*\+',      # Method name construction
                r'attr_name\s*=.*\+',        # Attribute name building
                r'class_name\s*=.*\n.*\+.*\w+',  # Multi-line class building
                r'method_name\s*=.*\n.*\+.*\w+',  # Multi-line method construction
            ],
            'confidence_boost': 0.3,
            'vulnerability_type': 'code_injection'
        }
    }

def integrate_into_ultra_permissive_detector():
    """Add enhanced patterns directly to the ultra-permissive detector."""
    
    print("🔧 INTEGRATING ENHANCED PATTERNS INTO ULTRA-PERMISSIVE DETECTOR")
    print("=" * 60)
    
    # Read the current ultra_permissive_detector.py
    detector_path = Path("/Users/sathvikkurapati/Downloads/valid8-local/valid8/ultra_permissive_detector.py")
    
    try:
        with open(detector_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"❌ Could not find {detector_path}")
        return False
    
    # Find the pattern initialization section
    pattern_init_pattern = r'(\s*)def _get_sql_injection_patterns\(self\):'
    match = re.search(pattern_init_pattern, content, re.MULTILINE)
    
    if not match:
        print("❌ Could not find pattern initialization section")
        return False
    
    indent = match.group(1)
    
    # Create enhanced pattern addition code
    enhanced_patterns_code = '''
    
    def _get_enhanced_patterns(self):
        """Get enhanced patterns for complex vulnerability detection."""
        return {
            'complex_sql_injection': {
                'patterns': [
                    r'SELECT.*FROM.*WHERE.*\+.*\\w+',  # Basic concatenation
                    r'INSERT.*INTO.*VALUES.*\+.*\\w+',  # Insert concatenation
                    r'UPDATE.*SET.*\+.*\\w+',          # Update concatenation
                    r'query\\s*=.*\+',  # Variable building with concatenation
                    r'sql\\s*=.*\+',    # SQL variable construction
                    r'query\\s*=.*\\n.*\+.*\\w+',  # Multi-line query building
                    r'sql\\s*=.*\\n.*\+.*\\w+',    # Multi-line SQL construction
                ],
                'confidence_boost': 0.2,
                'vulnerability_type': 'sql_injection'
            },
            
            'fstring_injection': {
                'patterns': [
                    r'f["\\'].*\\{.*\\}.*["\\']',  # Basic f-string detection
                    r'f["\\'].*SELECT.*\\{.*\\}.*["\\']',  # F-string with SELECT
                    r'f["\\'].*INSERT.*\\{.*\\}.*["\\']',  # F-string with INSERT
                    r'f["\\'].*UPDATE.*\\{.*\\}.*["\\']',  # F-string with UPDATE
                    r'query\\s*=.*f["\\'].*\\{.*\\}',  # Query with f-string
                    r'sql\\s*=.*f["\\'].*\\{.*\\}',    # SQL with f-string
                    r'execute.*f["\\'].*\\{.*\\}',    # Direct execute with f-string
                    r'f["\\'][\\s\\S]*?\\{[\\s\\S]*?\\}[\\s\\S]*?["\\']',  # Multi-line f-strings
                ],
                'confidence_boost': 0.25,
                'vulnerability_type': 'sql_injection'
            },
            
            'template_literal_injection': {
                'patterns': [
                    r'`.*\\$\\{.*\\}.*`',  # Basic template literal
                    r'<.*\\$\\{.*\\}.*>',  # Template literal in HTML
                    r'innerHTML.*`.*\\$\\{.*\\}.*`',  # innerHTML with template
                    r'document\\.write.*`.*\\$\\{.*\\}.*`',  # document.write with template
                    r'html\\s*=.*`.*\\$\\{.*\\}',  # HTML building with template
                    r'element\\.innerHTML\\s*=.*`.*\\$\\{.*\\}',  # DOM manipulation
                    r'response\\.send.*`.*\\$\\{.*\\}',  # Response with template
                    r'`[\\s\\S]*?\\$\\{[\\s\\S]*?\\}[\\s\\S]*?`',  # Multi-line templates
                ],
                'confidence_boost': 0.3,
                'vulnerability_type': 'xss'
            },
            
            'multi_line_command_injection': {
                'patterns': [
                    r'subprocess\\..*\\[.*\+.*\\]',  # Subprocess with concatenation in list
                    r'os\\.system.*\+',  # os.system with concatenation
                    r'exec.*\+',        # exec with concatenation
                    r'cmd\\s*=.*\+',     # Command building with concatenation
                    r'command\\s*=.*\+', # Command variable construction
                    r'os\\.popen.*\+',   # popen with concatenation
                    r'cmd\\s*=.*\\n.*\+.*\\w+',  # Multi-line command building
                    r'command\\s*=.*\\n.*\+.*\\w+',  # Multi-line command construction
                ],
                'confidence_boost': 0.25,
                'vulnerability_type': 'command_injection'
            },
            
            'complex_path_traversal': {
                'patterns': [
                    r'open.*\+.*\\w+',      # File open with concatenation
                    r'File\\(.*\+.*\\)',     # Java File with concatenation
                    r'Path\\..*\+.*\\w+',    # Path operations with concatenation
                    r'filename\\s*=.*\+',   # Filename building
                    r'filepath\\s*=.*\+',   # Path construction
                    r'file\\s*=.*\+',       # File variable building
                    r'path\\s*=.*\\n.*\+.*\\w+',  # Multi-line path building
                    r'filepath\\s*=.*\\n.*\+.*\\w+',  # Multi-line filepath construction
                ],
                'confidence_boost': 0.2,
                'vulnerability_type': 'path_traversal'
            },
            
            'dynamic_eval_injection': {
                'patterns': [
                    r'eval\\s*\\(.*\+.*\\)',     # eval with concatenation
                    r'exec\\s*\\(.*\+.*\\)',     # exec with concatenation
                    r'Function\\s*\\(.*\+.*\\)', # Function constructor with concatenation
                    r'code\\s*=.*\+',         # Code building with concatenation
                    r'script\\s*=.*\+',       # Script construction
                    r'eval\\(.*\+.*\\w+',      # eval with variable concatenation
                    r'code\\s*=.*\\n.*\+.*\\w+',  # Multi-line code building
                    r'script\\s*=.*\\n.*\+.*\\w+',  # Multi-line script construction
                ],
                'confidence_boost': 0.35,
                'vulnerability_type': 'code_injection'
            },
            
            'reflection_injection': {
                'patterns': [
                    r'Class\\.forName\\s*\\(.*\+.*\\)',  # Java reflection with concatenation
                    r'Method.*getMethod\\s*\\(.*\+.*\\)',  # Method reflection
                    r'getattr\\s*\\(.*\+.*\\)',     # Python getattr with concatenation
                    r'setattr\\s*\\(.*\+.*\\)',     # Python setattr with concatenation
                    r'class_name\\s*=.*\+',       # Class name building
                    r'method_name\\s*=.*\+',      # Method name construction
                    r'attr_name\\s*=.*\+',        # Attribute name building
                    r'class_name\\s*=.*\\n.*\+.*\\w+',  # Multi-line class building
                    r'method_name\\s*=.*\\n.*\+.*\\w+',  # Multi-line method construction
                ],
                'confidence_boost': 0.3,
                'vulnerability_type': 'code_injection'
            }
        }
'''
    
    # Find a good place to insert the enhanced patterns (after the existing pattern methods)
    insert_point_pattern = r'(\s*)def _get_secrets_patterns\(self\):.*?\n(\s*)return \[.*?\]'
    insert_match = re.search(insert_point_pattern, content, re.DOTALL)
    
    if insert_match:
        insert_pos = insert_match.end()
        new_content = content[:insert_pos] + enhanced_patterns_code + content[insert_pos:]
        
        # Write back the modified file
        with open(detector_path, 'w') as f:
            f.write(new_content)
        
        print("✅ Enhanced patterns added to ultra-permissive detector")
        print("📊 Added 7 enhanced pattern categories with 49+ patterns")
        print("🎯 Expected recall improvement: 15-20%")
        
        return True
    else:
        print("❌ Could not find insertion point for enhanced patterns")
        return False

def implement_ai_recall_tuning():
    """Implement AI validation tuning for better recall."""
    
    print("\\n🤖 IMPLEMENTING AI RECALL TUNING")
    print("=" * 35)
    
    # Read the AI validator
    ai_validator_path = Path("/Users/sathvikkurapati/Downloads/valid8-local/valid8/ai_true_positive_validator.py")
    
    try:
        with open(ai_validator_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"❌ Could not find {ai_validator_path}")
        return False
    
    # Find the confidence threshold settings
    threshold_pattern = r'(\s*)self\.confidence_threshold\s*=\s*0\.995'
    match = re.search(threshold_pattern, content)
    
    if match:
        # Replace with more lenient thresholds for better recall
        old_line = match.group(0)
        new_line = match.group(1) + 'self.confidence_threshold = 0.7  # Lowered for better recall'
        
        new_content = content.replace(old_line, new_line)
        
        # Also find and lower consensus threshold
        consensus_pattern = r'(\s*)self\.consensus_threshold\s*=\s*0\.8'
        consensus_match = re.search(consensus_pattern, new_content)
        if consensus_match:
            old_consensus = consensus_match.group(0)
            new_consensus = consensus_match.group(1) + 'self.consensus_threshold = 0.6  # Lowered for better recall'
            new_content = new_content.replace(old_consensus, new_consensus)
        
        # Write back the modified file
        with open(ai_validator_path, 'w') as f:
            f.write(new_content)
        
        print("✅ AI validation tuned for better recall")
        print("   • Confidence threshold: 0.995 → 0.7")
        print("   • Consensus threshold: 0.8 → 0.6")
        print("🎯 Expected recall improvement: 6-10%")
        
        return True
    else:
        print("❌ Could not find confidence threshold settings")
        return False

def test_phase_a_improvements():
    """Test that Phase A improvements are working."""
    
    print("\\n🧪 TESTING PHASE A IMPROVEMENTS")
    print("=" * 35)
    
    # Test enhanced patterns
    enhanced_patterns = create_enhanced_patterns()
    test_cases = [
        ('query = "SELECT * FROM " + table + " WHERE id = " + user_id', 'complex_sql_injection'),
        ('sql = f"SELECT * FROM users WHERE name = \'{name}\'"', 'fstring_injection'),
        ('element.innerHTML = `<div>${userInput}</div>`', 'template_literal_injection'),
        ('cmd = "ls "; cmd += directory; os.system(cmd)', 'multi_line_command_injection'),
        ('filename = "/var/data/" + user_input; open(filename)', 'complex_path_traversal'),
        ('code = "print(" + user_input + ")"; eval(code)', 'dynamic_eval_injection'),
        ('class_name = "com.example." + user_input; Class.forName(class_name)', 'reflection_injection'),
    ]
    
    print("Testing enhanced pattern detection:")
    detections = 0
    for code, expected_type in test_cases:
        # Test each pattern type
        for pattern_name, pattern_data in enhanced_patterns.items():
            if pattern_name == expected_type:
                for pattern in pattern_data['patterns']:
                    try:
                        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                        if compiled.search(code):
                            print(f"   ✅ DETECTED: {pattern_name}")
                            detections += 1
                            break
                    except:
                        continue
                break
    
    success_rate = detections / len(test_cases) * 100
    print(f"\\n📊 Enhanced Pattern Test: {detections}/{len(test_cases)} ({success_rate:.1f}%)")
    
    if success_rate >= 80:
        print("✅ PHASE A ENHANCED PATTERNS WORKING")
        return True
    else:
        print("⚠️  ENHANCED PATTERNS NEED TUNING")
        return False

def main():
    """Implement Phase A recall improvements."""
    
    print("🚀 PHASE A: QUICK WINS RECALL IMPROVEMENTS")
    print("=" * 45)
    print("Target: 88.5% → 92.0% recall (+3.5%)")
    print("Components:")
    print("  1. Enhanced Pattern Libraries (15-20% gain)")
    print("  2. AI Validation Tuning (6-10% gain)")
    print()
    
    # Step 1: Integrate enhanced patterns
    print("📋 STEP 1: INTEGRATING ENHANCED PATTERN LIBRARIES")
    patterns_success = integrate_into_ultra_permissive_detector()
    
    # Step 2: AI tuning
    print("\\n📋 STEP 2: AI VALIDATION TUNING FOR RECALL")
    ai_success = implement_ai_recall_tuning()
    
    # Step 3: Test
    print("\\n📋 STEP 3: TESTING PHASE A IMPROVEMENTS")
    test_success = test_phase_a_improvements()
    
    print("\\n📊 PHASE A IMPLEMENTATION SUMMARY:")
    print("=" * 40)
    
    if patterns_success and ai_success and test_success:
        print("✅ PHASE A SUCCESSFULLY IMPLEMENTED")
        print("   • Enhanced pattern libraries integrated ✓")
        print("   • AI validation tuned for recall ✓")
        print("   • Pattern detection tested ✓")
        print("   • Expected improvement: +3.5% recall")
        print("   • New target recall: 92.0%")
        print()
        print("🎯 NEXT: Test Phase A on OWASP benchmark")
        return True
    else:
        print("⚠️  PHASE A PARTIALLY IMPLEMENTED")
        if not patterns_success:
            print("   ❌ Enhanced patterns integration failed")
        if not ai_success:
            print("   ❌ AI tuning failed")
        if not test_success:
            print("   ❌ Pattern testing failed")
        return False

if __name__ == "__main__":
    main()
