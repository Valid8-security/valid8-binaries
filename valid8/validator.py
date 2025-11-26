#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
AI-Powered Vulnerability Validator

This module uses LLM to review detected vulnerabilities in the context
of the full codebase before generating fixes. This reduces false positives
by understanding the actual usage context.
"""

import re
from typing import List, Dict, Any, Optional
from pathlib import Path
from .llm import LLMClient
from .scanner import Vulnerability


class VulnerabilityValidator:
    """
    Validates vulnerabilities using AI to reduce false positives.
    
    Workflow:
    1. Static analysis finds potential issues
    2. AI reviews each issue in codebase context
    3. AI classifies as: confirmed, likely_fp, or needs_review
    4. Only confirmed issues proceed to fix generation
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()
        self.validation_cache = {}
    
    def validate_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        codebase_path: str,
        batch_size: int = 5  # CPU-optimized: reduced for CPU machines
    ) -> Dict[str, Any]:
        """
        Validate all vulnerabilities using AI analysis.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            codebase_path: Path to the codebase for context
            batch_size: Number of vulnerabilities to validate at once
            
        Returns:
            Dictionary with validated vulnerabilities categorized by confidence
        """
        results = {
            'confirmed': [],
            'likely_false_positive': [],
            'needs_review': [],
            'validation_summary': {}
        }
        
        # Load codebase context
        codebase_context = self._load_codebase_context(codebase_path)
        
        # Validate in batches
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i + batch_size]
            validated_batch = self._validate_batch(batch, codebase_context)
            
            # Categorize results
            for vuln, validation in validated_batch.items():
                if validation['confidence'] == 'confirmed':
                    results['confirmed'].append({
                        'vulnerability': vuln,
                        'validation': validation
                    })
                elif validation['confidence'] == 'likely_false_positive':
                    results['likely_false_positive'].append({
                        'vulnerability': vuln,
                        'validation': validation
                    })
                else:
                    results['needs_review'].append({
                        'vulnerability': vuln,
                        'validation': validation
                    })
        
        # Generate summary
        results['validation_summary'] = {
            'total_scanned': len(vulnerabilities),
            'confirmed': len(results['confirmed']),
            'likely_false_positives': len(results['likely_false_positive']),
            'needs_review': len(results['needs_review']),
            'false_positive_rate': len(results['likely_false_positive']) / len(vulnerabilities) if vulnerabilities else 0,
            'confidence_rate': len(results['confirmed']) / len(vulnerabilities) if vulnerabilities else 0
        }
        
        return results
    
    def _validate_batch(
        self,
        vulnerabilities: List[Vulnerability],
        codebase_context: Dict[str, str]
    ) -> Dict[Vulnerability, Dict[str, Any]]:
        """Validate a batch of vulnerabilities."""
        results = {}
        
        for vuln in vulnerabilities:
            # Check cache first
            cache_key = self._get_cache_key(vuln)
            if cache_key in self.validation_cache:
                results[vuln] = self.validation_cache[cache_key]
                continue
            
            # Validate with AI
            validation = self._validate_single(vuln, codebase_context)
            results[vuln] = validation
            self.validation_cache[cache_key] = validation
        
        return results
    
    def _validate_single(
        self,
        vuln: Vulnerability,
        codebase_context: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Validate a single vulnerability using AI.
        
        Returns validation with:
        - confidence: 'confirmed', 'likely_false_positive', 'needs_review'
        - reasoning: Explanation of the decision
        - score: Confidence score 0-100
        """
        # Load the vulnerable file and surrounding context
        file_content = self._load_file_context(vuln.file_path)
        
        # Get related files (imports, usage)
        related_files = self._get_related_files(vuln.file_path, codebase_context)
        
        # Build validation prompt
        prompt = self._build_validation_prompt(vuln, file_content, related_files)
        
        # Get AI validation
        try:
            response = self.llm.generate(prompt, max_tokens=500)
            validation = self._parse_validation_response(response)
        except Exception as e:
            # If AI validation fails, mark for manual review
            validation = {
                'confidence': 'needs_review',
                'reasoning': f'AI validation failed: {str(e)}',
                'score': 50
            }
        
        return validation
    
    def _build_validation_prompt(
        self,
        vuln: Vulnerability,
        file_content: str,
        related_files: Dict[str, str]
    ) -> str:
        """Build prompt for AI validation."""
        prompt = f"""You are a security expert reviewing a potential vulnerability.

VULNERABILITY DETAILS:
- Type: {vuln.cwe} - {vuln.title}
- Severity: {vuln.severity}
- Location: {vuln.file_path}:{vuln.line_number}
- Description: {vuln.description}

VULNERABLE CODE:
```
{vuln.code_snippet}
```

FULL FILE CONTEXT (lines {max(1, vuln.line_number - 10)}-{vuln.line_number + 10}):
```
{self._get_code_window(file_content, vuln.line_number, 10)}
```

RELATED CODE CONTEXT:
{self._format_related_files(related_files)}

TASK:
Analyze this potential vulnerability in context. Consider:
1. Is this actually exploitable or just a pattern match?
2. Are there mitigating controls (input validation, sanitization)?
3. Is this test code, example code, or production code?
4. Is the data source trusted or user-controlled?
5. Are there framework protections in place?

Respond in this format:
CONFIDENCE: [confirmed/likely_false_positive/needs_review]
SCORE: [0-100]
REASONING: [Your detailed analysis]

Be conservative - mark as 'confirmed' only if you're confident it's exploitable.
Mark as 'likely_false_positive' if there are clear mitigations.
Mark as 'needs_review' if you're uncertain."""

        return prompt
    
    def _parse_validation_response(self, response: str) -> Dict[str, Any]:
        """Parse AI validation response."""
        validation = {
            'confidence': 'needs_review',
            'reasoning': '',
            'score': 50
        }
        
        # Extract confidence
        conf_match = re.search(r'CONFIDENCE:\s*(confirmed|likely_false_positive|needs_review)', response, re.IGNORECASE)
        if conf_match:
            validation['confidence'] = conf_match.group(1).lower()
        
        # Extract score
        score_match = re.search(r'SCORE:\s*(\d+)', response)
        if score_match:
            validation['score'] = int(score_match.group(1))
        
        # Extract reasoning
        reasoning_match = re.search(r'REASONING:\s*(.+?)(?:\n\n|\Z)', response, re.DOTALL)
        if reasoning_match:
            validation['reasoning'] = reasoning_match.group(1).strip()
        else:
            validation['reasoning'] = response
        
        return validation
    
    def _load_codebase_context(self, codebase_path: str) -> Dict[str, str]:
        """Load overview of codebase structure."""
        context = {}
        path = Path(codebase_path)
        
        if path.is_file():
            context[str(path)] = path.read_text(errors='ignore')
        else:
            # Load structure (files, imports, etc.)
            for file_path in path.rglob('*'):
                if file_path.is_file() and file_path.suffix in ['.py', '.java', '.js', '.go', '.rs', '.php', '.rb']:
                    try:
                        context[str(file_path)] = file_path.read_text(errors='ignore')
                    except:
                        pass
        
        return context
    
    def _load_file_context(self, file_path: str) -> str:
        """Load full file content."""
        try:
            return Path(file_path).read_text(errors='ignore')
        except:
            return ""
    
    def _get_code_window(self, content: str, line_number: int, window: int = 10) -> str:
        """Get code window around the vulnerable line."""
        lines = content.split('\n')
        start = max(0, line_number - window - 1)
        end = min(len(lines), line_number + window)
        
        window_lines = []
        for i in range(start, end):
            marker = ">>> " if i == line_number - 1 else "    "
            window_lines.append(f"{marker}{i+1:4d} | {lines[i]}")
        
        return '\n'.join(window_lines)
    
    def _get_related_files(
        self,
        file_path: str,
        codebase_context: Dict[str, str]
    ) -> Dict[str, str]:
        """Get related files (imports, callers, etc.)."""
        related = {}
        
        # For now, return empty - could be enhanced to parse imports
        # and find related files based on call graphs
        
        return related
    
    def _format_related_files(self, related_files: Dict[str, str]) -> str:
        """Format related files for prompt."""
        if not related_files:
            return "(No related files found)"
        
        formatted = []
        for path, content in list(related_files.items())[:3]:  # Limit to 3 files
            formatted.append(f"File: {path}\n```\n{content[:500]}...\n```")
        
        return '\n\n'.join(formatted)
    
    def _get_cache_key(self, vuln: Vulnerability) -> str:
        """Generate cache key for vulnerability."""
        return f"{vuln.cwe}:{vuln.file_path}:{vuln.line_number}:{vuln.code_snippet}"
    
    def generate_validation_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable validation report."""
        summary = results['validation_summary']
        
        report = f"""
╭─────────────────────────────────────────────────────────╮
│         AI Vulnerability Validation Report              │
╰─────────────────────────────────────────────────────────╯

Total Vulnerabilities Scanned: {summary['total_scanned']}

Results:
  ✅ Confirmed:              {summary['confirmed']} ({summary['confidence_rate']:.1%})
  ❌ Likely False Positives: {summary['likely_false_positives']} ({summary['false_positive_rate']:.1%})
  ⚠️  Needs Review:          {summary['needs_review']}

False Positive Reduction: {summary['false_positive_rate']:.1%} of findings filtered

Recommendation:
  - Generate fixes for {summary['confirmed']} confirmed vulnerabilities
  - Review {summary['needs_review']} uncertain cases manually
  - Ignore {summary['likely_false_positives']} likely false positives
"""
        
        return report

