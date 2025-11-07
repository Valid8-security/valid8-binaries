"""
CWE Database Module for Parry Security Scanner

This module provides access to the official CWE (Common Weakness Enumeration)
database from MITRE, enabling systematic addition of new vulnerability detectors.

Database Source: https://cwe.mitre.org/data/xml/cwec_v4.13.xml.zip
Total CWEs: 959 (as of CWE v4.13, October 2023)
"""

import xml.etree.ElementTree as ET
import requests
import zipfile
import io
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import time

logger = logging.getLogger(__name__)

class CWEDatabase:
    """Official CWE Database interface for Parry"""

    CWE_DATABASE_URL = "https://cwe.mitre.org/data/xml/cwec_v4.13.xml.zip"
    CACHE_FILE = Path.home() / ".parry" / "cwe_cache.json"
    CACHE_DURATION = 86400 * 7  # 7 days

    def __init__(self):
        self._database = None
        self._load_database()

    def _load_database(self) -> None:
        """Load CWE database with caching"""
        if self._try_load_cache():
            return

        logger.info("Downloading CWE database from MITRE...")
        try:
            response = requests.get(self.CWE_DATABASE_URL, timeout=30)
            response.raise_for_status()

            zip_content = zipfile.ZipFile(io.BytesIO(response.content))
            xml_content = zip_content.read('cwec_v4.13.xml').decode('utf-8')

            self._database = self._parse_xml(xml_content)
            self._save_cache()

            logger.info(f"Loaded {len(self._database)} CWE entries")

        except Exception as e:
            logger.error(f"Failed to load CWE database: {e}")
            self._database = {}

    def _parse_xml(self, xml_content: str) -> Dict[str, Dict[str, Any]]:
        """Parse CWE XML into structured dictionary"""
        root = ET.fromstring(xml_content)
        database = {}

        for weakness in root.findall('.//{http://cwe.mitre.org/cwe-7}Weakness'):
            cwe_id = weakness.get('ID')
            if not cwe_id:
                continue

            # Basic information
            entry = {
                'id': cwe_id,
                'name': weakness.get('Name', ''),
                'abstraction': weakness.get('Abstraction', ''),
                'structure': weakness.get('Structure', ''),
                'status': weakness.get('Status', ''),
            }

            # Description
            desc_elem = weakness.find('.//{http://cwe.mitre.org/cwe-7}Description')
            entry['description'] = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ''

            # Extended description
            ext_desc_elem = weakness.find('.//{http://cwe.mitre.org/cwe-7}Extended_Description')
            entry['extended_description'] = ext_desc_elem.text.strip() if ext_desc_elem is not None and ext_desc_elem.text else ''

            # Likelihood
            likelihood_elem = weakness.find('.//{http://cwe.mitre.org/cwe-7}Likelihood_Of_Exploit')
            entry['likelihood'] = likelihood_elem.text if likelihood_elem is not None else 'Unknown'

            # Consequences
            consequences = []
            for cons in weakness.findall('.//{http://cwe.mitre.org/cwe-7}Consequence'):
                scope_elem = cons.find('.//{http://cwe.mitre.org/cwe-7}Scope')
                impact_elem = cons.find('.//{http://cwe.mitre.org/cwe-7}Impact')
                if scope_elem is not None and impact_elem is not None:
                    consequences.append({
                        'scope': scope_elem.text,
                        'impact': impact_elem.text
                    })
            entry['consequences'] = consequences

            # Applicable platforms
            platforms = []
            for platform in weakness.findall('.//{http://cwe.mitre.org/cwe-7}Applicable_Platforms//{http://cwe.mitre.org/cwe-7}Language'):
                lang_class = platform.get('Class', '')
                prevalence = platform.get('Prevalence', '')
                if lang_class and lang_class != 'Not Language-Specific':
                    platforms.append({
                        'type': 'language',
                        'name': lang_class,
                        'prevalence': prevalence
                    })
            entry['platforms'] = platforms

            # Detection methods
            detection_methods = []
            for method in weakness.findall('.//{http://cwe.mitre.org/cwe-7}Detection_Methods//{http://cwe.mitre.org/cwe-7}Detection_Method'):
                method_elem = method.find('.//{http://cwe.mitre.org/cwe-7}Method')
                if method_elem is not None and method_elem.text:
                    detection_methods.append(method_elem.text)
            entry['detection_methods'] = detection_methods

            # Potential mitigations
            mitigations = []
            for mitigation in weakness.findall('.//{http://cwe.mitre.org/cwe-7}Potential_Mitigations//{http://cwe.mitre.org/cwe-7}Mitigation'):
                phase_elem = mitigation.find('.//{http://cwe.mitre.org/cwe-7}Phase')
                desc_elem = mitigation.find('.//{http://cwe.mitre.org/cwe-7}Description')
                if desc_elem is not None and desc_elem.text:
                    mitigations.append({
                        'phase': phase_elem.text if phase_elem is not None else '',
                        'description': desc_elem.text.strip()
                    })
            entry['mitigations'] = mitigations

            database[cwe_id] = entry

        return database

    def _try_load_cache(self) -> bool:
        """Try to load from cache if recent"""
        if not self.CACHE_FILE.exists():
            return False

        try:
            cache_data = json.loads(self.CACHE_FILE.read_text())
            cache_time = cache_data.get('timestamp', 0)
            if time.time() - cache_time < self.CACHE_DURATION:
                self._database = cache_data['database']
                logger.info(f"Loaded CWE database from cache ({len(self._database)} entries)")
                return True
        except Exception as e:
            logger.warning(f"Failed to load CWE cache: {e}")

        return False

    def _save_cache(self) -> None:
        """Save database to cache"""
        try:
            self.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            cache_data = {
                'timestamp': time.time(),
                'database': self._database
            }
            self.CACHE_FILE.write_text(json.dumps(cache_data, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save CWE cache: {e}")

    def get_cwe(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Get CWE entry by ID"""
        return self._database.get(str(cwe_id))

    def get_all_cwes(self) -> Dict[str, Dict[str, Any]]:
        """Get all CWE entries"""
        return self._database.copy()

    def search_cwes(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search CWEs by name or description"""
        query = query.lower()
        results = []

        for cwe_id, entry in self._database.items():
            if (query in entry.get('name', '').lower() or
                query in entry.get('description', '').lower()):
                results.append(entry)
                if len(results) >= limit:
                    break

        return results

    def get_cwes_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get CWEs by category/abstraction"""
        results = []
        for entry in self._database.values():
            if entry.get('abstraction', '').lower() == category.lower():
                results.append(entry)
        return results

    def get_uncovered_cwes(self, covered_cwe_ids: List[str]) -> List[Dict[str, Any]]:
        """Get CWEs not yet covered by Parry"""
        covered_set = set(str(cwe_id) for cwe_id in covered_cwe_ids)
        return [entry for cwe_id, entry in self._database.items()
                if cwe_id not in covered_set]

    def get_high_impact_cwes(self) -> List[Dict[str, Any]]:
        """Get CWEs with High likelihood of exploit"""
        return [entry for entry in self._database.values()
                if entry.get('likelihood') == 'High']

    def get_cwe_patterns(self, cwe_id: str) -> Dict[str, Any]:
        """Generate pattern suggestions for a CWE (for detector development)"""
        entry = self.get_cwe(cwe_id)
        if not entry:
            return {}

        patterns = {
            'name': entry.get('name', ''),
            'description': entry.get('description', ''),
            'likelihood': entry.get('likelihood', 'Unknown'),
            'platforms': entry.get('platforms', []),
            'suggested_patterns': self._generate_pattern_suggestions(entry)
        }

        return patterns

    def _generate_pattern_suggestions(self, entry: Dict[str, Any]) -> List[str]:
        """Generate regex pattern suggestions based on CWE characteristics"""
        suggestions = []
        name = entry.get('name', '').lower()
        description = entry.get('description', '').lower()

        # Common pattern templates based on CWE characteristics
        if 'sql' in name or 'sql' in description:
            suggestions.extend([
                r'execute\(.+\+.*\)',
                r'query\(.+\+.*\)',
                r'raw\(.+\+.*\)'
            ])
        elif 'xss' in name or 'cross-site' in description:
            suggestions.extend([
                r'innerHTML.*\+',
                r'document\.write.*\+',
                r'<script.*\+'
            ])
        elif 'command' in name or 'command' in description:
            suggestions.extend([
                r'exec\(.+\+.*\)',
                r'system\(.+\+.*\)',
                r'popen\(.+\+.*\)'
            ])
        elif 'path' in name or 'traversal' in description:
            suggestions.extend([
                r'open\(.+/.+\)',
                r'file_get_contents\(.+/.+\)',
                r'include\(.+/.+\)'
            ])

        return suggestions


# Global instance
cwe_db = CWEDatabase()

def get_cwe_database() -> CWEDatabase:
    """Get the global CWE database instance"""
    return cwe_db
