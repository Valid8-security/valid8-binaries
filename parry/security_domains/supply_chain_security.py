# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Supply Chain Security Detector Module

Detects supply chain and dependency vulnerabilities:
- Dependency confusion attacks
- Typosquatting packages
- Malicious packages
- Unsigned artifacts
- Outdated/vulnerable dependencies
- Compromised build pipelines
- Package integrity issues
- Suspicious package behaviors

Author: Parry Security Team
Version: 1.0.0
"""

import re
import json
import hashlib
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from pathlib import Path

@dataclass
class SupplyChainVulnerability:
    """Represents a supply chain security vulnerability"""
    cwe: str
    title: str
    description: str
    severity: str
    file: str
    line: int
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fix: Optional[str] = None
    confidence: float = 0.85


class SupplyChainSecurityDetector:
    """Detect supply chain and dependency security issues"""
    
    # Known typosquatting patterns for popular packages
    POPULAR_PACKAGES = {
        'python': [
            'requests', 'numpy', 'pandas', 'tensorflow', 'django', 'flask',
            'pytorch', 'scikit-learn', 'matplotlib', 'boto3', 'pillow',
            'beautifulsoup4', 'pytest', 'sqlalchemy', 'celery', 'redis'
        ],
        'javascript': [
            'react', 'vue', 'angular', 'express', 'axios', 'lodash',
            'webpack', 'jest', 'eslint', 'typescript', 'moment', 'chalk',
            'commander', 'yargs', 'dotenv', 'cors', 'bcrypt', 'jsonwebtoken'
        ],
        'java': [
            'spring-boot', 'hibernate', 'junit', 'slf4j', 'jackson',
            'gson', 'guava', 'apache-commons', 'mockito', 'log4j'
        ],
        'ruby': [
            'rails', 'devise', 'rspec', 'sidekiq', 'capistrano',
            'puma', 'nokogiri', 'activerecord', 'rack', 'sinatra'
        ]
    }
    
    # Suspicious package name patterns
    SUSPICIOUS_PATTERNS = [
        r'.*-?utils?-?.*',  # *-util, *utils, util-*
        r'.*-?helper-?.*',   # *-helper, helper-*
        r'.*-?test-?.*',     # test packages
        r'.*-?admin-?.*',    # admin tools
        r'^[a-z]{1,3}$',     # Very short names
        r'.*\d{3,}.*',       # Excessive numbers
        r'.*[_-]{2,}.*',     # Multiple separators
    ]
    
    # Known vulnerable packages (simplified - real implementation would use CVE database)
    KNOWN_VULNERABLE = {
        'log4j': ['<2.17.0', 'CVE-2021-44228 (Log4Shell)'],
        'spring-core': ['<5.3.18', 'CVE-2022-22965 (Spring4Shell)'],
        'pyyaml': ['<5.4', 'CVE-2020-14343'],
        'pillow': ['<8.3.2', 'CVE-2021-34552'],
        'django': ['<3.2.13', 'Multiple CVEs'],
        'requests': ['<2.20.0', 'CVE-2018-18074'],
    }
    
    def __init__(self):
        self.vulnerabilities: List[SupplyChainVulnerability] = []
        self.package_files = {
            'python': ['requirements.txt', 'Pipfile', 'setup.py', 'pyproject.toml'],
            'javascript': ['package.json', 'package-lock.json', 'yarn.lock'],
            'java': ['pom.xml', 'build.gradle', 'gradle.lockfile'],
            'ruby': ['Gemfile', 'Gemfile.lock'],
            'go': ['go.mod', 'go.sum'],
            'rust': ['Cargo.toml', 'Cargo.lock']
        }
    
    def detect_all(self, file_path: str, content: str, language: str = None) -> List[SupplyChainVulnerability]:
        """Run all supply chain security detectors"""
        self.vulnerabilities = []
        
        # Detect language from file
        if not language:
            language = self._detect_language(file_path)
        
        if file_path.endswith('requirements.txt') or file_path.endswith('Pipfile'):
            self._check_python_dependencies(content, file_path)
        elif file_path.endswith('package.json'):
            self._check_npm_dependencies(content, file_path)
        elif file_path.endswith('pom.xml') or file_path.endswith('build.gradle'):
            self._check_java_dependencies(content, file_path)
        elif file_path.endswith('Gemfile'):
            self._check_ruby_dependencies(content, file_path)
        elif file_path.endswith('go.mod'):
            self._check_go_dependencies(content, file_path)
        elif file_path.endswith('Cargo.toml'):
            self._check_rust_dependencies(content, file_path)
        
        # Check for dependency confusion in any language
        self._check_dependency_confusion(content, file_path, language)
        
        # Check for unsigned artifacts
        self._check_unsigned_artifacts(content, file_path)
        
        return self.vulnerabilities
    
    def _check_python_dependencies(self, content: str, file_path: str):
        """Check Python dependencies for vulnerabilities"""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            # Parse package name and version
            package_info = self._parse_python_package(line)
            if not package_info:
                continue
            
            package_name, version = package_info
            
            # Check for typosquatting
            self._check_typosquatting(package_name, 'python', file_path, line_num, line)
            
            # Check for known vulnerabilities
            self._check_known_vulnerabilities(package_name, version, file_path, line_num, line)
            
            # Check for missing version pinning
            if not version or version == '*':
                vuln = SupplyChainVulnerability(
                    cwe='CWE-1104',
                    title='Unpinned Dependency Version',
                    description=(
                        f'Package "{package_name}" has no version constraint. '
                        'This allows automatic updates that may introduce vulnerabilities or breaking changes. '
                        'Always pin dependencies to specific versions.'
                    ),
                    severity='MEDIUM',
                    file=file_path,
                    line=line_num,
                    package_name=package_name,
                    package_version=version,
                    fix=f'Pin to specific version: {package_name}==X.Y.Z',
                    confidence=0.9
                )
                self.vulnerabilities.append(vuln)
            
            # Check for HTTP package sources
            if 'http://' in line and 'pypi.org' not in line:
                vuln = SupplyChainVulnerability(
                    cwe='CWE-494',
                    title='Insecure Package Source (HTTP)',
                    description=(
                        f'Package "{package_name}" loaded from insecure HTTP source. '
                        'Use HTTPS to prevent man-in-the-middle attacks.'
                    ),
                    severity='HIGH',
                    file=file_path,
                    line=line_num,
                    package_name=package_name,
                    fix='Use HTTPS URLs only for package sources',
                    confidence=1.0
                )
                self.vulnerabilities.append(vuln)
    
    def _check_npm_dependencies(self, content: str, file_path: str):
        """Check npm dependencies for vulnerabilities"""
        try:
            package_json = json.loads(content)
        except json.JSONDecodeError:
            return
        
        all_deps = {}
        all_deps.update(package_json.get('dependencies', {}))
        all_deps.update(package_json.get('devDependencies', {}))
        
        for package_name, version in all_deps.items():
            # Check for typosquatting
            self._check_typosquatting(package_name, 'javascript', file_path, 0, f'{package_name}: {version}')
            
            # Check for known vulnerabilities
            self._check_known_vulnerabilities(package_name, version, file_path, 0, f'{package_name}: {version}')
            
            # Check for wildcard versions
            if version in ['*', 'latest', '^*', '~*']:
                vuln = SupplyChainVulnerability(
                    cwe='CWE-1104',
                    title='Wildcard Dependency Version',
                    description=(
                        f'Package "{package_name}" uses wildcard version "{version}". '
                        'This is dangerous as it allows any version to be installed.'
                    ),
                    severity='HIGH',
                    file=file_path,
                    line=0,
                    package_name=package_name,
                    package_version=version,
                    fix=f'Pin to specific version: "{package_name}": "1.2.3"',
                    confidence=0.95
                )
                self.vulnerabilities.append(vuln)
            
            # Check for suspicious package names
            if self._is_suspicious_package_name(package_name):
                vuln = SupplyChainVulnerability(
                    cwe='CWE-506',
                    title='Suspicious Package Name',
                    description=(
                        f'Package "{package_name}" has suspicious naming pattern. '
                        'Verify this is a legitimate package and not a typosquatting attempt.'
                    ),
                    severity='MEDIUM',
                    file=file_path,
                    line=0,
                    package_name=package_name,
                    package_version=version,
                    fix='Verify package legitimacy on npmjs.com',
                    confidence=0.6
                )
                self.vulnerabilities.append(vuln)
        
        # Check for missing lock file
        if file_path.endswith('package.json'):
            # This would need to check if package-lock.json exists in the same directory
            pass
    
    def _check_java_dependencies(self, content: str, file_path: str):
        """Check Java dependencies (Maven/Gradle) for vulnerabilities"""
        if file_path.endswith('pom.xml'):
            # Parse Maven dependencies
            dependency_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
            matches = re.finditer(dependency_pattern, content, re.DOTALL)
            
            for match in matches:
                group_id, artifact_id, version = match.groups()
                package_name = f'{group_id}:{artifact_id}'
                
                # Check for known vulnerabilities
                self._check_known_vulnerabilities(artifact_id, version, file_path, 0, match.group(0))
        
        elif file_path.endswith('build.gradle'):
            # Parse Gradle dependencies
            dependency_pattern = r"(?:implementation|compile|api)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
            matches = re.finditer(dependency_pattern, content)
            
            for match in matches:
                group_id, artifact_id, version = match.groups()
                package_name = f'{group_id}:{artifact_id}'
                
                # Check for known vulnerabilities
                self._check_known_vulnerabilities(artifact_id, version, file_path, 0, match.group(0))
    
    def _check_ruby_dependencies(self, content: str, file_path: str):
        """Check Ruby dependencies for vulnerabilities"""
        gem_pattern = r"gem\s+['\"]([^'\"]+)['\"](?:,\s+['\"]([^'\"]+)['\"])?"
        matches = re.finditer(gem_pattern, content)
        
        for match in matches:
            gem_name = match.group(1)
            version = match.group(2) if match.group(2) else None
            
            # Check for typosquatting
            self._check_typosquatting(gem_name, 'ruby', file_path, 0, match.group(0))
            
            # Check for known vulnerabilities
            self._check_known_vulnerabilities(gem_name, version, file_path, 0, match.group(0))
    
    def _check_go_dependencies(self, content: str, file_path: str):
        """Check Go dependencies for vulnerabilities"""
        require_pattern = r'require\s+([^\s]+)\s+v([^\s]+)'
        matches = re.finditer(require_pattern, content)
        
        for match in matches:
            module_name, version = match.groups()
            
            # Check for known vulnerabilities
            self._check_known_vulnerabilities(module_name, version, file_path, 0, match.group(0))
    
    def _check_rust_dependencies(self, content: str, file_path: str):
        """Check Rust dependencies for vulnerabilities"""
        dependency_pattern = r'([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"'
        matches = re.finditer(dependency_pattern, content)
        
        for match in matches:
            crate_name, version = match.groups()
            
            # Check for known vulnerabilities
            self._check_known_vulnerabilities(crate_name, version, file_path, 0, match.group(0))
    
    def _check_typosquatting(self, package_name: str, language: str, file_path: str, line_num: int, code: str):
        """Check for typosquatting attacks"""
        popular_packages = self.POPULAR_PACKAGES.get(language, [])
        
        for popular_package in popular_packages:
            # Calculate similarity
            similarity = self._calculate_similarity(package_name.lower(), popular_package.lower())
            
            # Flag if very similar but not exact match
            if similarity > 0.8 and package_name != popular_package:
                vuln = SupplyChainVulnerability(
                    cwe='CWE-506',
                    title='Potential Typosquatting Attack',
                    description=(
                        f'Package "{package_name}" is very similar to popular package "{popular_package}". '
                        f'Similarity: {similarity:.2%}. This could be a typosquatting attack. '
                        'Verify this is the correct package name.'
                    ),
                    severity='CRITICAL',
                    file=file_path,
                    line=line_num,
                    package_name=package_name,
                    fix=f'Did you mean: {popular_package}?',
                    confidence=similarity
                )
                self.vulnerabilities.append(vuln)
                break
    
    def _check_known_vulnerabilities(self, package_name: str, version: str, file_path: str, line_num: int, code: str):
        """Check against known vulnerable package versions"""
        package_lower = package_name.lower()
        
        for vuln_package, (vuln_version, cve_info) in self.KNOWN_VULNERABLE.items():
            if vuln_package in package_lower:
                # Simple version comparison (real implementation would use packaging.version)
                if version and self._version_matches_constraint(version, vuln_version):
                    vuln = SupplyChainVulnerability(
                        cwe='CWE-1035',
                        title=f'Known Vulnerable Dependency: {package_name}',
                        description=(
                            f'Package "{package_name}" version {version} has known vulnerability: {cve_info}. '
                            'Update to a patched version immediately.'
                        ),
                        severity='CRITICAL',
                        file=file_path,
                        line=line_num,
                        package_name=package_name,
                        package_version=version,
                        fix=f'Update {package_name} to version {vuln_version.replace("<", ">=")}',
                        confidence=1.0
                    )
                    self.vulnerabilities.append(vuln)
    
    def _check_dependency_confusion(self, content: str, file_path: str, language: str):
        """Check for dependency confusion vulnerabilities"""
        # Look for private package registries
        if language == 'python':
            if '--index-url' in content or '--extra-index-url' in content:
                private_registry_pattern = r'--(?:extra-)?index-url\s+(https?://[^\s]+)'
                matches = re.finditer(private_registry_pattern, content)
                
                for match in matches:
                    registry_url = match.group(1)
                    
                    if 'pypi.org' not in registry_url:
                        vuln = SupplyChainVulnerability(
                            cwe='CWE-830',
                            title='Dependency Confusion Risk',
                            description=(
                                f'Private package registry detected: {registry_url}. '
                                'Ensure private package names are unique and cannot be hijacked on public PyPI. '
                                'Use package name prefixes/scopes to prevent confusion attacks.'
                            ),
                            severity='HIGH',
                            file=file_path,
                            line=0,
                            fix=(
                                '1. Use scoped package names (e.g., @yourcompany/package)\n'
                                '2. Configure pip to ONLY use private registry for private packages\n'
                                '3. Verify package signatures'
                            ),
                            confidence=0.75
                        )
                        self.vulnerabilities.append(vuln)
        
        elif language == 'javascript':
            try:
                package_json = json.loads(content)
                
                # Check for custom registry configuration
                if 'publishConfig' in package_json:
                    registry = package_json['publishConfig'].get('registry', '')
                    
                    if registry and 'npmjs.org' not in registry:
                        vuln = SupplyChainVulnerability(
                            cwe='CWE-830',
                            title='Dependency Confusion Risk (npm)',
                            description=(
                                f'Private npm registry configured: {registry}. '
                                'Ensure package names use scopes (@org/package) to prevent confusion attacks.'
                            ),
                            severity='HIGH',
                            file=file_path,
                            line=0,
                            fix='Use scoped packages: "@yourcompany/package-name"',
                            confidence=0.8
                        )
                        self.vulnerabilities.append(vuln)
                
                # Check for unscoped package names in private projects
                if 'private' in package_json and package_json['private']:
                    package_name = package_json.get('name', '')
                    
                    if package_name and not package_name.startswith('@'):
                        vuln = SupplyChainVulnerability(
                            cwe='CWE-830',
                            title='Unscoped Private Package Name',
                            description=(
                                f'Private package "{package_name}" is not scoped. '
                                'Attackers can publish same name to public npm, causing dependency confusion.'
                            ),
                            severity='MEDIUM',
                            file=file_path,
                            line=0,
                            package_name=package_name,
                            fix=f'Rename to scoped package: "@yourorg/{package_name}"',
                            confidence=0.85
                        )
                        self.vulnerabilities.append(vuln)
            except json.JSONDecodeError:
                pass
    
    def _check_unsigned_artifacts(self, content: str, file_path: str):
        """Check for unsigned/unverified artifacts"""
        # Check for downloading artifacts without verification
        download_patterns = [
            r'wget\s+https?://[^\s]+',
            r'curl.*https?://[^\s]+',
            r'urllib\.request\.urlretrieve',
            r'requests\.get.*\.content',
            r'download\(',
        ]
        
        for pattern in download_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                # Check if there's checksum verification nearby
                context_start = max(0, match.start() - 500)
                context_end = min(len(content), match.end() + 500)
                context = content[context_start:context_end]
                
                has_verification = any(keyword in context.lower() for keyword in [
                    'sha256', 'sha512', 'checksum', 'verify', 'signature',
                    'gpg', 'pgp', 'hash'
                ])
                
                if not has_verification:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vuln = SupplyChainVulnerability(
                        cwe='CWE-494',
                        title='Downloading Artifact Without Verification',
                        description=(
                            'Artifact downloaded without integrity verification (checksum/signature). '
                            'Attackers can perform man-in-the-middle attacks to inject malicious code.'
                        ),
                        severity='HIGH',
                        file=file_path,
                        line=line_num,
                        fix=(
                            'Verify artifact integrity:\n'
                            '1. Download expected checksum\n'
                            '2. Compute file checksum\n'
                            '3. Compare before using:\n'
                            '   import hashlib\n'
                            '   with open(file, "rb") as f:\n'
                            '       if hashlib.sha256(f.read()).hexdigest() != expected_sha:\n'
                            '           raise ValueError("Checksum mismatch!")'
                        ),
                        confidence=0.75
                    )
                    self.vulnerabilities.append(vuln)
    
    # Helper methods
    
    def _detect_language(self, file_path: str) -> Optional[str]:
        """Detect language from file path"""
        for language, files in self.package_files.items():
            if any(file_path.endswith(f) for f in files):
                return language
        return None
    
    def _parse_python_package(self, line: str) -> Optional[tuple]:
        """Parse Python package line (requirements.txt format)"""
        # Remove comments
        line = line.split('#')[0].strip()
        
        if not line:
            return None
        
        # Parse package==version, package>=version, etc.
        match = re.match(r'([a-zA-Z0-9_-]+)\s*([=<>!]+)\s*([^\s;]+)', line)
        if match:
            return match.group(1), match.group(3)
        
        # Package without version
        match = re.match(r'([a-zA-Z0-9_-]+)', line)
        if match:
            return match.group(1), None
        
        return None
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate Levenshtein-based similarity between strings"""
        # Simple Levenshtein distance implementation
        if len(str1) < len(str2):
            return self._calculate_similarity(str2, str1)
        
        if len(str2) == 0:
            return 0.0
        
        previous_row = range(len(str2) + 1)
        for i, c1 in enumerate(str1):
            current_row = [i + 1]
            for j, c2 in enumerate(str2):
                # Cost of insertions, deletions, substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        distance = previous_row[-1]
        max_len = max(len(str1), len(str2))
        similarity = 1.0 - (distance / max_len)
        return similarity
    
    def _version_matches_constraint(self, version: str, constraint: str) -> bool:
        """Check if version matches constraint (simplified)"""
        # Remove 'v' prefix if present
        version = version.lstrip('v')
        
        # Simple constraint matching
        if constraint.startswith('<'):
            constraint_version = constraint[1:].strip()
            # Simplified: just do string comparison
            # Real implementation would use packaging.version.parse
            return version < constraint_version
        elif constraint.startswith('>='):
            constraint_version = constraint[2:].strip()
            return version >= constraint_version
        elif constraint.startswith('>'):
            constraint_version = constraint[1:].strip()
            return version > constraint_version
        
        return False
    
    def _is_suspicious_package_name(self, package_name: str) -> bool:
        """Check if package name matches suspicious patterns"""
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.match(pattern, package_name, re.IGNORECASE):
                return True
        return False


# Example usage
if __name__ == '__main__':
    detector = SupplyChainSecurityDetector()
    
    # Test case: requirements.txt with vulnerabilities
    test_requirements = """
# Test requirements
requests==2.19.0
django<3.0.0
log4j==2.14.1
reqeusts==2.28.0
numpy
http://insecure-repo.com/packages/mypackage
"""
    
    vulns = detector.detect_all('requirements.txt', test_requirements, 'python')
    print(f"Found {len(vulns)} supply chain vulnerabilities")
    for v in vulns:
        print(f"  [{v.cwe}] {v.title}")
        print(f"     Package: {v.package_name}, Severity: {v.severity}")
