# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
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
    
    Uses LLM to analyze vulnerabilities in full codebase context, categorizing them as:
    - confirmed: Real security issues that need fixing
    - likely_false_positive: Not actually vulnerable in this context
    - needs_review: Uncertain, requires human review
    
    This significantly improves precision by understanding data flow, sanitization,
    and other contextual factors that static analysis misses.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None):
        """Initialize validator with LLM client and validation cache."""
        self.llm = llm_client or LLMClient()
        self.validation_cache = {}  # Cache results to avoid re-validating same issues
    
    def validate_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        codebase_path: str,
        batch_size: int = 10
    ) -> Dict[str, Any]:
        """
        Validate all vulnerabilities using AI analysis.
        
        Process:
        1. Load codebase context for understanding data flow
        2. Validate vulnerabilities in batches for efficiency
        3. Categorize each as confirmed/false_positive/needs_review
        4. Generate summary statistics
        
        Returns dict with categorized vulnerabilities and validation metrics.
        """
        results = {
            'confirmed': [],
            'likely_false_positive': [],
            'needs_review': [],
            'validation_summary': {}
        }
        
        # Load codebase context (imports, function definitions, data flow)
        codebase_context = self._load_codebase_context(codebase_path)
        
        # Process vulnerabilities in batches to optimize LLM calls
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i + batch_size]
            validated_batch = self._validate_batch(batch, codebase_context)
            
            # Categorize results based on AI confidence level
            for vuln, validation in validated_batch.items():
                category = validation['confidence']
                if category == 'confirmed':
                    results['confirmed'].append({'vulnerability': vuln, 'validation': validation})
                elif category == 'likely_false_positive':
                    results['likely_false_positive'].append({'vulnerability': vuln, 'validation': validation})
                else:
                    results['needs_review'].append({'vulnerability': vuln, 'validation': validation})
        
        # Calculate validation metrics
        total = len(vulnerabilities)
        results['validation_summary'] = {
            'total_scanned': total,
            'confirmed': len(results['confirmed']),
            'likely_false_positives': len(results['likely_false_positive']),
            'needs_review': len(results['needs_review']),
            'false_positive_rate': len(results['likely_false_positive']) / total if total else 0,
            'confidence_rate': len(results['confirmed']) / total if total else 0
        }
        
        return results
    
    def _validate_batch(
        self,
        vulnerabilities: List[Vulnerability],
        codebase_context: Dict[str, str]
    ) -> Dict[Vulnerability, Dict[str, Any]]:
        """
        Validate a batch of vulnerabilities using LLM.
        
        For each vulnerability:
        - Build context-aware prompt with surrounding code
        - Ask LLM to assess if it's a real vulnerability
        - Parse confidence level and reasoning from response
        """
        results = {}
        
        for vuln in vulnerabilities:
            # Check cache to avoid re-validating same issues
            cache_key = self._get_cache_key(vuln)
            if cache_key in self.validation_cache:
                results[vuln] = self.validation_cache[cache_key]
                continue
            
            # Perform AI validation and cache result
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
        Validate a single vulnerability using AI context analysis.
        
        Process:
        1. Load vulnerable file and extract code window
        2. Find related files (imports, function calls)
        3. Build comprehensive validation prompt
        4. Get LLM assessment with confidence level
        5. Parse and return structured validation result
        """
        # Load full file content for context
        file_content = self._load_file_context(vuln.file_path)
        
        # Find related files that might contain mitigations
        related_files = self._get_related_files(vuln.file_path, codebase_context)
        
        # Build detailed validation prompt with all context
        prompt = self._build_validation_prompt(vuln, file_content, related_files)
        
        # Get AI assessment
        try:
            response = self.llm.generate(prompt, max_tokens=500)
            validation = self._parse_validation_response(response)
        except Exception as e:
            # If AI fails, mark for manual review rather than auto-confirming
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
        """
        Build detailed validation prompt for LLM.
        
        Includes vulnerability details, code context, related files, and
        specific questions to guide the AI's analysis.
        """
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
        """Parse structured fields from AI validation response using regex."""
        validation = {
            'confidence': 'needs_review',
            'reasoning': '',
            'score': 50
        }
        
        # Extract confidence level
        conf_match = re.search(r'CONFIDENCE:\s*(confirmed|likely_false_positive|needs_review)', response, re.IGNORECASE)
        if conf_match:
            validation['confidence'] = conf_match.group(1).lower()
        
        # Extract numeric score
        score_match = re.search(r'SCORE:\s*(\d+)', response)
        if score_match:
            validation['score'] = int(score_match.group(1))
        
        # Extract reasoning text
        reasoning_match = re.search(r'REASONING:\s*(.+?)(?:\n\n|\Z)', response, re.DOTALL)
        if reasoning_match:
            validation['reasoning'] = reasoning_match.group(1).strip()
        else:
            validation['reasoning'] = response
        
        return validation
    
    def _load_codebase_context(self, codebase_path: str) -> Dict[str, str]:
        """Load codebase structure by reading all source files."""
        context = {}
        path = Path(codebase_path)
        
        if path.is_file():
            # Single file scan
            context[str(path)] = path.read_text(errors='ignore')
        else:
            # Directory scan - load all source files
            for file_path in path.rglob('*'):
                if file_path.is_file() and file_path.suffix in ['.py', '.java', '.js', '.go', '.rs', '.php', '.rb']:
                    try:
                        context[str(file_path)] = file_path.read_text(errors='ignore')
                    except:
                        pass  # Skip files that can't be read
        
        return context
    
    def _load_file_context(self, file_path: str) -> str:
        """Load full content of a single file."""
        try:
            return Path(file_path).read_text(errors='ignore')
        except:
            return ""
    
    def _get_code_window(self, content: str, line_number: int, window: int = 10) -> str:
        """Extract code window around vulnerable line with line numbers and highlighting."""
        lines = content.split('\n')
        start = max(0, line_number - window - 1)
        end = min(len(lines), line_number + window)
        
        window_lines = []
        for i in range(start, end):
            # Mark the vulnerable line with >>>
            marker = ">>> " if i == line_number - 1 else "    "
            window_lines.append(f"{marker}{i+1:4d} | {lines[i]}")
        
        return '\n'.join(window_lines)
    
    def _get_related_files(
        self,
        file_path: str,
        codebase_context: Dict[str, str]
    ) -> Dict[str, str]:
        """
        Find related files (imports, callers, etc.).
        
        TODO: Could be enhanced to:
        - Parse import statements
        - Build call graph
        - Find test files
        - Identify configuration files
        """
        related = {}
        
        # For now, return empty - enhancement opportunity
        # Could parse imports and find related files based on call graphs
        
        return related
    
    def _format_related_files(self, related_files: Dict[str, str]) -> str:
        """Format related files for inclusion in prompt (limited to first 3)."""
        if not related_files:
            return "(No related files found)"
        
        formatted = []
        for path, content in list(related_files.items())[:3]:  # Limit to 3 files to fit in context
            formatted.append(f"File: {path}\n```\n{content[:500]}...\n```")
        
        return '\n\n'.join(formatted)
    
    def _get_cache_key(self, vuln: Vulnerability) -> str:
        """Generate unique cache key for vulnerability based on CWE, location, and code."""
        return f"{vuln.cwe}:{vuln.file_path}:{vuln.line_number}:{vuln.code_snippet}"
    
    def generate_validation_report(self, results: Dict[str, Any]) -> str:
        """
        Generate human-readable validation report with summary and recommendations.
        
        Shows validation statistics and actionable next steps.
        """
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
