"""
🚀 NATURAL LANGUAGE SLM FILTERING FOR FALSE POSITIVES
Allows users to specify false positives through natural language descriptions
Uses SLMs to understand context and filter similar findings automatically
"""

import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class NaturalLanguageFilter:
    """Represents a natural language filtering rule"""
    id: str
    description: str  # Natural language description
    pattern_hash: str  # Hash of the pattern to match against
    confidence: float  # How confident the SLM is in this filter
    created_at: str
    examples: List[str]  # Example findings that match this filter
    metadata: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NaturalLanguageFilter':
        """Create from dictionary"""
        return cls(
            id=data.get('id', ''),
            description=data.get('description', ''),
            pattern_hash=data.get('pattern_hash', ''),
            confidence=data.get('confidence', 0.5),
            created_at=data.get('created_at', datetime.now().isoformat()),
            examples=data.get('examples', []),
            metadata=data.get('metadata', {})
        )


class NaturalLanguageSLMFilter:
    """
    🚀 SLM-BASED NATURAL LANGUAGE FALSE POSITIVE FILTERING

    Allows users to specify false positives in natural language:
    "eval() usage in test files is always a false positive"
    "SQL injection warnings in ORM code are not real issues"

    The SLM learns to identify similar patterns automatically.
    """

    def __init__(self):
        self.filters_dir = Path.home() / ".parry" / "nl_filters"
        self.filters_dir.mkdir(parents=True, exist_ok=True)
        self.filters_file = self.filters_dir / "filters.json"

        # Load existing filters
        self.filters: List[NaturalLanguageFilter] = self._load_filters()

        # Initialize SLM client for natural language processing
        self.slm_client = None
        try:
            from parry.llm import LLMClient, LLMConfig
            self.slm_client = LLMClient()
        except Exception as e:
            logger.warning(f"SLM client not available: {e}")

    def _load_filters(self) -> List[NaturalLanguageFilter]:
        """Load existing natural language filters"""
        if not self.filters_file.exists():
            return []

        try:
            with open(self.filters_file, 'r') as f:
                data = json.load(f)
                return [NaturalLanguageFilter.from_dict(item) for item in data.get('filters', [])]
        except Exception as e:
            logger.error(f"Error loading filters: {e}")
            return []

    def _save_filters(self) -> None:
        """Save filters to disk"""
        try:
            data = {
                'filters': [asdict(f) for f in self.filters],
                'updated_at': datetime.now().isoformat()
            }
            with open(self.filters_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving filters: {e}")

    def add_natural_language_filter(
        self,
        description: str,
        example_findings: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        🚀 Add a natural language filter for false positives

        Args:
            description: Natural language description (e.g., "eval() in test files is false positive")
            example_findings: Optional example vulnerability findings that match this filter

        Returns:
            Filter creation result
        """
        if not self.slm_client:
            return {
                'success': False,
                'error': 'SLM client not available',
                'message': 'Cannot create natural language filters without SLM support'
            }

        # Generate pattern hash from examples or description
        if example_findings:
            # Create hash from example findings
            pattern_data = json.dumps(example_findings, sort_keys=True)
            pattern_hash = hashlib.md5(pattern_data.encode()).hexdigest()
        else:
            # Use description hash
            pattern_hash = hashlib.md5(description.encode()).hexdigest()

        # Check if filter already exists
        existing = next((f for f in self.filters if f.pattern_hash == pattern_hash), None)
        if existing:
            return {
                'success': False,
                'error': 'Filter already exists',
                'filter_id': existing.id
            }

        # Create new filter
        filter_id = f"nl_filter_{len(self.filters) + 1}"
        new_filter = NaturalLanguageFilter(
            id=filter_id,
            description=description,
            pattern_hash=pattern_hash,
            confidence=0.8,  # Start with high confidence
            created_at=datetime.now().isoformat(),
            examples=[json.dumps(ex, sort_keys=True) for ex in (example_findings or [])],
            metadata={
                'source': 'user_provided',
                'type': 'natural_language'
            }
        )

        self.filters.append(new_filter)
        self._save_filters()

        return {
            'success': True,
            'filter_id': filter_id,
            'message': f'Created natural language filter: {description}',
            'confidence': new_filter.confidence
        }

    def should_filter_finding(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Tuple[bool, float, str]:
        """
        🚀 Check if a finding should be filtered based on natural language rules

        Args:
            finding: Vulnerability finding dictionary
            context: Additional context (file path, code snippet, etc.)

        Returns:
            (should_filter, confidence, reason)
        """
        if not self.slm_client or not self.filters:
            return False, 0.0, "No SLM client or filters available"

        context = context or {}

        # Check each filter
        for filter_rule in self.filters:
            try:
                # Use SLM to determine if this finding matches the filter
                match_result = self._slm_evaluate_match(finding, filter_rule, context)

                if match_result['matches']:
                    confidence = match_result['confidence'] * filter_rule.confidence
                    if confidence > 0.6:  # Confidence threshold
                        return True, confidence, f"Matches filter: {filter_rule.description}"

            except Exception as e:
                logger.error(f"Error evaluating filter {filter_rule.id}: {e}")
                continue

        return False, 0.0, "No matching filters"

    def _slm_evaluate_match(
        self,
        finding: Dict[str, Any],
        filter_rule: NaturalLanguageFilter,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Use SLM to evaluate if a finding matches a natural language filter
        """
        if not self.slm_client:
            return {'matches': False, 'confidence': 0.0}

        # Prepare prompt for SLM
        prompt = f"""
Analyze if this security finding matches the natural language filter rule.

FILTER RULE: "{filter_rule.description}"

FINDING DETAILS:
- CWE: {finding.get('cwe', 'Unknown')}
- Title: {finding.get('title', 'Unknown')}
- File: {finding.get('file_path', 'Unknown')}
- Severity: {finding.get('severity', 'Unknown')}
- Code: {finding.get('code_snippet', 'No code available')[:200]}

CONTEXT:
- Language: {context.get('language', 'Unknown')}
- File type: {context.get('file_type', 'Unknown')}
- Location: {context.get('location', 'Unknown')}

Does this finding match the filter rule? Answer with YES or NO, and explain why.
Also provide a confidence score from 0.0 to 1.0.
"""

        try:
            response = self.slm_client.generate(prompt, max_tokens=100)

            # Parse response
            response_lower = response.lower()
            matches = 'yes' in response_lower

            # Extract confidence score
            confidence = 0.5  # Default
            if 'confidence:' in response_lower:
                try:
                    conf_text = response_lower.split('confidence:')[1].strip()
                    confidence = float(conf_text.split()[0])
                except:
                    pass

            return {
                'matches': matches,
                'confidence': min(max(confidence, 0.0), 1.0),
                'reason': response
            }

        except Exception as e:
            logger.error(f"SLM evaluation error: {e}")
            return {'matches': False, 'confidence': 0.0, 'reason': str(e)}

    def get_filter_statistics(self) -> Dict[str, Any]:
        """Get statistics about natural language filters"""
        return {
            'total_filters': len(self.filters),
            'avg_confidence': sum(f.confidence for f in self.filters) / max(len(self.filters), 1),
            'filters_by_confidence': {
                'high': len([f for f in self.filters if f.confidence >= 0.8]),
                'medium': len([f for f in self.filters if 0.6 <= f.confidence < 0.8]),
                'low': len([f for f in self.filters if f.confidence < 0.6])
            },
            'slm_available': self.slm_client is not None
        }

    def list_filters(self) -> List[Dict[str, Any]]:
        """List all natural language filters"""
        return [asdict(f) for f in self.filters]

    def remove_filter(self, filter_id: str) -> bool:
        """Remove a natural language filter"""
        original_count = len(self.filters)
        self.filters = [f for f in self.filters if f.id != filter_id]

        if len(self.filters) < original_count:
            self._save_filters()
            return True
        return False


# Global instance
nl_slm_filter = NaturalLanguageSLMFilter()
