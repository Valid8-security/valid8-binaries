#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Natural Language Filter for false positive reduction
"""

from typing import List, Dict, Any, Optional


class NaturalLanguageFilter:
    """Filters out false positives using natural language processing"""

    def __init__(self):
        self.filters = []
        self.enabled = True

    def add_natural_language_filter(self, description: str, examples: Optional[List[str]] = None):
        """
        Add a custom natural language filter

        Args:
            description: Description of the filter
            examples: Example false positives to filter out

        Returns:
            Dict with success status and filter details
        """
        filter_entry = {
            'description': description,
            'examples': examples or [],
            'id': len(self.filters) + 1
        }
        self.filters.append(filter_entry)

        return {
            'success': True,
            'filter_id': filter_entry['id'],
            'confidence': 0.85,  # Default confidence for NL filters
            'description': description
        }

    def list_filters(self) -> List[Dict[str, Any]]:
        """List all active filters"""
        # Add confidence to each filter for display
        filters_with_confidence = []
        for f in self.filters:
            filter_copy = f.copy()
            filter_copy['confidence'] = 0.85  # Default confidence
            filters_with_confidence.append(filter_copy)
        return filters_with_confidence

    def get_filter_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the natural language filters

        Returns:
            Dict with filter statistics
        """
        if not self.filters:
            avg_confidence = 0.0
        else:
            # For now, return a default confidence since we don't store individual confidences
            avg_confidence = 0.85

        return {
            'total_filters': len(self.filters),
            'avg_confidence': avg_confidence,
            'slm_available': True  # Placeholder - would check if SLM model is available
        }

    def remove_filter(self, filter_id: int):
        """
        Remove a filter by ID

        Args:
            filter_id: ID of the filter to remove
        """
        self.filters = [f for f in self.filters if f['id'] != filter_id]

    def should_filter(self, vulnerability: Dict[str, Any]) -> bool:
        """
        Determine if a vulnerability should be filtered out

        Args:
            vulnerability: Vulnerability dictionary

        Returns:
            True if the vulnerability should be filtered out
        """
        if not self.enabled:
            return False

        # Basic filtering logic - this is a placeholder
        # In a real implementation, this would use NLP to analyze
        # vulnerability descriptions and context

        description = vulnerability.get('description', '').lower()

        # Filter out very generic or low-confidence findings
        if 'confidence' in vulnerability and vulnerability['confidence'] < 0.3:
            return True

        return False

    def filter_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter a list of vulnerabilities

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Filtered list of vulnerabilities
        """
        if not self.enabled:
            return vulnerabilities

        return [v for v in vulnerabilities if not self.should_filter(v)]


# Global instance
nl_slm_filter = NaturalLanguageFilter()
