#!/usr/bin/env python3
"""
CWE Detector Generator for Parry Security Scanner

This script helps add new CWE detectors using the official CWE database.
It generates detector code templates based on CWE characteristics.

Usage:
    python3 scripts/add_cwe_detector.py --cwe-id 89 --category injection
    python3 scripts/add_cwe_detector.py --search "sql injection"
    python3 scripts/add_cwe_detector.py --uncovered --limit 10
"""

import argparse
import re
from pathlib import Path
from typing import List, Dict, Any
import sys

# Add parry to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from parry.cwe_database import get_cwe_database

class CWEDetectorGenerator:
    """Generate CWE detector code from database"""

    def __init__(self):
        self.db = get_cwe_database()

    def generate_detector_code(self, cwe_id: str, category: str = "general") -> str:
        """Generate detector code for a CWE"""
        cwe_data = self.db.get_cwe(cwe_id)
        if not cwe_data:
            return f"# CWE-{cwe_id} not found in database"

        # Generate class name
        name_parts = re.sub(r'[^\w\s]', '', cwe_data['name']).split()
        class_name = ''.join(word.capitalize() for word in name_parts[:4]) + 'Detector'

        # Get suggested patterns
        patterns_data = self.db.get_cwe_patterns(cwe_id)
        suggested_patterns = patterns_data.get('suggested_patterns', [])

        # Generate patterns list
        patterns_code = "\n".join(f'            (r"{pattern}", "CWE-{cwe_id}", "{self._get_severity(cwe_data)}"),'
                                 for pattern in suggested_patterns[:5])

        # Generate detector code
        code = f'''class {class_name}(VulnerabilityDetector):
    """CWE-{cwe_id}: {cwe_data['name']}"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
{patterns_code}
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="{cwe_data['name']}",
                        description="{cwe_data['description'][:200]}...",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="{category}"
                    ))
        return vulnerabilities
'''
        return code

    def _get_severity(self, cwe_data: Dict[str, Any]) -> str:
        """Determine severity based on CWE data"""
        likelihood = cwe_data.get('likelihood', 'Unknown')

        if likelihood == 'High':
            return 'high'
        elif likelihood == 'Medium':
            return 'medium'
        else:
            return 'low'

    def find_detector_file(self, category: str) -> Path:
        """Find the appropriate detector file for a category"""
        category_map = {
            'injection': 'cwe_injection.py',
            'authentication': 'cwe_authentication.py',
            'authorization': 'cwe_authorization.py',
            'cryptography': 'cwe_cryptography.py',
            'memory-safety': 'cwe_memory_safety.py',
            'information-disclosure': 'cwe_information_disclosure.py',
            'error-handling': 'cwe_error_handling.py',
            'resource-management': 'cwe_resource_management.py',
            'business-logic': 'cwe_business_logic.py',
            'configuration': 'cwe_configuration.py',
            'concurrency': 'cwe_concurrency.py',
            'framework-specific': 'cwe_framework_specific.py'
        }

        filename = category_map.get(category, 'cwe_general.py')
        return Path(__file__).parent.parent / 'parry' / 'detectors' / 'cwe_expansion' / filename

    def add_detector_to_file(self, cwe_id: str, category: str) -> bool:
        """Add a detector to the appropriate file"""
        code = self.generate_detector_code(cwe_id, category)
        if "# not found" in code:
            print(f"Error: CWE-{cwe_id} not found")
            return False

        file_path = self.find_detector_file(category)

        # Read current file
        if file_path.exists():
            content = file_path.read_text()
        else:
            # Create new file with imports
            content = f'''"""CWE {category.title()} Vulnerability Detectors"""
import re
from pathlib import Path
from typing import List
from parry.scanner import Vulnerability, VulnerabilityDetector

'''

        # Find the get function and add detector before it
        get_pattern = r'def get_.*_detectors\(\):'
        match = re.search(get_pattern, content)

        if match:
            # Insert detector before get function
            insert_pos = match.start()
            content = content[:insert_pos] + '\n' + code + '\n' + content[insert_pos:]

            # Add to detector list
            list_pattern = r'(\w+)\(\)'
            list_match = re.search(list_pattern, content[match.end():])
            if list_match:
                detector_name = code.split('class ')[1].split('(')[0]
                # Find the return statement and add detector
                return_match = re.search(r'return \[([^\]]*)\]', content[match.end():], re.DOTALL)
                if return_match:
                    detector_list = return_match.group(1)
                    if detector_list.strip():
                        detector_list = detector_list.rstrip() + ',\n        ' + detector_name + '(),'
                    else:
                        detector_list = detector_name + '(),'

                    content = content[:match.end() + return_match.start(1)] + detector_list + content[match.end() + return_match.end(1):]

        file_path.write_text(content)
        print(f"Added CWE-{cwe_id} detector to {file_path}")
        return True

def main():
    parser = argparse.ArgumentParser(description='Add CWE detectors to Parry')
    parser.add_argument('--cwe-id', help='CWE ID to add')
    parser.add_argument('--category', default='general', help='Detector category')
    parser.add_argument('--search', help='Search for CWEs by name')
    parser.add_argument('--uncovered', action='store_true', help='Show uncovered CWEs')
    parser.add_argument('--limit', type=int, default=10, help='Limit results')

    args = parser.parse_args()
    generator = CWEDetectorGenerator()

    if args.search:
        results = generator.db.search_cwes(args.search, args.limit)
        print(f"Search results for '{args.search}':")
        for result in results:
            print(f"  CWE-{result['id']}: {result['name']}")

    elif args.uncovered:
        # Get covered CWEs
        from parry.detectors.cwe_expansion import get_all_cwe_expansion_detectors
        detectors = get_all_cwe_expansion_detectors()
        covered_cwes = set()
        for d in detectors:
            doc = d.__class__.__doc__ or ''
            matches = re.findall(r'CWE-\d+', doc)
            covered_cwes.update(matches)

        uncovered = generator.db.get_uncovered_cwes(list(covered_cwes))
        print(f"Uncovered CWEs ({len(uncovered)} total, showing {args.limit}):")
        for cwe in uncovered[:args.limit]:
            print(f"  CWE-{cwe['id']}: {cwe['name']}")

    elif args.cwe_id:
        print(f"Generating detector for CWE-{args.cwe_id}...")

        # Show CWE info
        cwe_data = generator.db.get_cwe(args.cwe_id)
        if cwe_data:
            print(f"Name: {cwe_data['name']}")
            print(f"Likelihood: {cwe_data['likelihood']}")
            print(f"Description: {cwe_data['description'][:200]}...")

            # Generate code
            code = generator.generate_detector_code(args.cwe_id, args.category)
            print("\nGenerated detector code:")
            print(code)

            # Ask to add
            response = input(f"\nAdd CWE-{args.cwe_id} detector to {args.category} category? (y/N): ")
            if response.lower() == 'y':
                if generator.add_detector_to_file(args.cwe_id, args.category):
                    print("Detector added successfully!")
                else:
                    print("Failed to add detector.")
        else:
            print(f"CWE-{args.cwe_id} not found in database.")

    else:
        parser.print_help()

if __name__ == '__main__':
    main()










