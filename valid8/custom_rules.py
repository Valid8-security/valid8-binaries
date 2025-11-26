#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Custom Rules Engine
Allows users to define custom security rules in YAML format
Compatible with Semgrep rule format for easy migration
"""
import yaml
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class CustomRule:
    """Represents a custom security rule"""
    id: str
    message: str
    severity: str
    languages: List[str]
    patterns: List[str]
    pattern_eithers: List[List[str]]
    pattern_not: List[str]
    metadata: Dict[str, Any]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CustomRule':
        """Create CustomRule from dictionary"""
        return cls(
            id=data.get('id', 'custom-rule'),
            message=data.get('message', 'Custom rule violation'),
            severity=data.get('severity', 'WARNING'),
            languages=data.get('languages', []),
            patterns=data.get('patterns', []),
            pattern_eithers=data.get('pattern-either', []),
            pattern_not=data.get('pattern-not', []),
            metadata=data.get('metadata', {})
        )


class CustomRulesEngine:
    """Engine for loading and executing custom security rules"""
    
    def __init__(self):
        self.rules: List[CustomRule] = []
        self.rules_dir = Path.home() / ".parry" / "rules"
        self.rules_dir.mkdir(parents=True, exist_ok=True)
    
    def load_rules(self, rules_path: Optional[Path] = None):
        """Load rules from YAML files"""
        if rules_path:
            self._load_rules_from_path(rules_path)
        else:
            # Load from default directory
            for rule_file in self.rules_dir.glob("*.yaml"):
                self._load_rules_from_path(rule_file)
            for rule_file in self.rules_dir.glob("*.yml"):
                self._load_rules_from_path(rule_file)
    
    def _load_rules_from_path(self, path: Path):
        """Load rules from a specific YAML file"""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
                
                if not data:
                    return
                
                # Handle Semgrep format
                if 'rules' in data:
                    for rule_data in data['rules']:
                        rule = self._parse_rule(rule_data)
                        if rule:
                            self.rules.append(rule)
                # Handle simple format
                elif isinstance(data, list):
                    for rule_data in data:
                        rule = self._parse_rule(rule_data)
                        if rule:
                            self.rules.append(rule)
                # Single rule
                else:
                    rule = self._parse_rule(data)
                    if rule:
                        self.rules.append(rule)
            
            logger.info(f"Loaded {len(self.rules)} custom rules from {path}")
        
        except Exception as e:
            logger.error(f"Error loading rules from {path}: {e}")
    
    def _parse_rule(self, rule_data: Dict[str, Any]) -> Optional[CustomRule]:
        """Parse a single rule from YAML data"""
        try:
            # Extract patterns from various formats
            patterns = []
            pattern_eithers = []
            pattern_not = []
            
            # Handle pattern field
            if 'pattern' in rule_data:
                patterns.append(rule_data['pattern'])
            
            # Handle patterns field (list)
            if 'patterns' in rule_data:
                if isinstance(rule_data['patterns'], list):
                    for p in rule_data['patterns']:
                        if isinstance(p, dict):
                            if 'pattern' in p:
                                patterns.append(p['pattern'])
                            if 'pattern-either' in p:
                                pattern_eithers.append(p['pattern-either'])
                            if 'pattern-not' in p:
                                pattern_not.append(p['pattern-not'])
                        else:
                            patterns.append(p)
            
            # Handle pattern-either
            if 'pattern-either' in rule_data:
                either_patterns = []
                for p in rule_data['pattern-either']:
                    if isinstance(p, dict) and 'pattern' in p:
                        either_patterns.append(p['pattern'])
                    else:
                        either_patterns.append(p)
                if either_patterns:
                    pattern_eithers.append(either_patterns)
            
            # Handle pattern-not
            if 'pattern-not' in rule_data:
                if isinstance(rule_data['pattern-not'], list):
                    pattern_not.extend(rule_data['pattern-not'])
                else:
                    pattern_not.append(rule_data['pattern-not'])
            
            return CustomRule(
                id=rule_data.get('id', 'unknown'),
                message=rule_data.get('message', 'Custom rule violation'),
                severity=rule_data.get('severity', 'WARNING').upper(),
                languages=rule_data.get('languages', []),
                patterns=patterns,
                pattern_eithers=pattern_eithers,
                pattern_not=pattern_not,
                metadata=rule_data.get('metadata', {})
            )
        
        except Exception as e:
            logger.error(f"Error parsing rule: {e}")
            return None
    
    def check_file(self, file_path: Path, content: str, language: str) -> List[Dict[str, Any]]:
        """Check a file against all custom rules"""
        violations = []
        
        for rule in self.rules:
            # Check if rule applies to this language
            if rule.languages and language not in rule.languages:
                continue
            
            # Check patterns
            findings = self._check_patterns(content, rule)
            for line_num, matched_text in findings:
                violations.append({
                    "rule_id": rule.id,
                    "file": str(file_path),
                    "line": line_num,
                    "severity": rule.severity,
                    "message": rule.message,
                    "matched_text": matched_text,
                    "metadata": rule.metadata
                })
        
        return violations
    
    def _check_patterns(self, content: str, rule: CustomRule) -> List[tuple]:
        """Check if content matches rule patterns"""
        findings = []
        lines = content.split('\n')
        
        # Check main patterns (all must match)
        if rule.patterns:
            for pattern in rule.patterns:
                regex_pattern = self._convert_pattern_to_regex(pattern)
                for i, line in enumerate(lines, 1):
                    if re.search(regex_pattern, line, re.IGNORECASE):
                        # Check pattern-not (exclusions)
                        excluded = False
                        for not_pattern in rule.pattern_not:
                            not_regex = self._convert_pattern_to_regex(not_pattern)
                            if re.search(not_regex, line, re.IGNORECASE):
                                excluded = True
                                break
                        
                        if not excluded:
                            findings.append((i, line.strip()))
        
        # Check pattern-either (at least one must match)
        for either_group in rule.pattern_eithers:
            for pattern in either_group:
                regex_pattern = self._convert_pattern_to_regex(pattern)
                for i, line in enumerate(lines, 1):
                    if re.search(regex_pattern, line, re.IGNORECASE):
                        # Check pattern-not
                        excluded = False
                        for not_pattern in rule.pattern_not:
                            not_regex = self._convert_pattern_to_regex(not_pattern)
                            if re.search(not_regex, line, re.IGNORECASE):
                                excluded = True
                                break
                        
                        if not excluded:
                            findings.append((i, line.strip()))
        
        return findings
    
    def _convert_pattern_to_regex(self, pattern: str) -> str:
        """Convert Semgrep-style pattern to regex"""
        # Replace $VAR with regex wildcards
        pattern = re.sub(r'\$\w+', r'[\\w\\d_]+', pattern)
        
        # Replace ... with wildcards
        pattern = pattern.replace('...', '.*?')
        
        # Escape special regex characters except wildcards
        special_chars = ['.', '^', '$', '*', '+', '?', '{', '}', '[', ']', '\\', '|', '(', ')']
        for char in special_chars:
            if char not in ['*', '.', '?']:  # Keep wildcards
                pattern = pattern.replace(char, '\\' + char)
        
        return pattern
    
    def create_rule_template(self, output_path: Path):
        """Create a template YAML file for custom rules"""
        template = """# Parry Custom Security Rules
# Compatible with Semgrep rule format

rules:
  - id: custom-sql-injection
    message: Potential SQL injection vulnerability detected
    severity: HIGH
    languages:
      - python
      - java
    patterns:
      - pattern: execute($QUERY)
      - pattern-not: execute(cursor.mogrify(...))
    metadata:
      cwe: CWE-89
      owasp: A03:2021 - Injection
      references:
        - https://owasp.org/www-community/attacks/SQL_Injection
  
  - id: custom-hardcoded-secret
    message: Hardcoded secret or API key detected
    severity: CRITICAL
    languages:
      - python
      - javascript
      - java
    pattern-either:
      - pattern: api_key = "$VALUE"
      - pattern: API_KEY = "$VALUE"
      - pattern: password = "$VALUE"
      - pattern: secret = "$VALUE"
    pattern-not:
      - pattern: api_key = os.getenv(...)
      - pattern: api_key = config.get(...)
    metadata:
      cwe: CWE-798
  
  - id: custom-unsafe-deserialization
    message: Unsafe deserialization can lead to RCE
    severity: CRITICAL
    languages:
      - python
    pattern-either:
      - pattern: pickle.loads($DATA)
      - pattern: yaml.load($DATA)
    pattern-not:
      - pattern: yaml.safe_load($DATA)
    metadata:
      cwe: CWE-502
"""
        
        with open(output_path, 'w') as f:
            f.write(template)
        
        logger.info(f"Created rule template at {output_path}")


def create_default_rules():
    """Create default custom rules in user's home directory"""
    engine = CustomRulesEngine()
    rules_file = engine.rules_dir / "default-rules.yaml"
    
    if not rules_file.exists():
        engine.create_rule_template(rules_file)
        print(f"Created default rules at: {rules_file}")
        print("Edit this file to add your own custom security rules!")


