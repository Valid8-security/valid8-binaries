#!/usr/bin/env python3
"""
Rule-based contextual scoring system for Valid8

Provides intelligent vulnerability prioritization based on deterministic rules
without machine learning dependencies. Scores vulnerabilities on a 1-10 scale
based on exploitability, impact, and environmental factors.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path

from ..models import Vulnerability


@dataclass
class RiskFactors:
    """Risk factors for vulnerability scoring"""
    exploitability: float  # 1-10: How easy is it to exploit
    impact: float         # 1-10: What damage can it cause
    prevalence: float     # 1-10: How common is this type of vuln
    detectability: float  # 1-10: How easy is it to detect exploitation
    environmental: float  # 1-10: Environment-specific risk factors

    @property
    def overall_risk(self) -> float:
        """Calculate overall risk score (1-10)"""
        # Weighted average with emphasis on exploitability and impact
        weights = {
            'exploitability': 0.3,
            'impact': 0.3,
            'prevalence': 0.15,
            'detectability': 0.15,
            'environmental': 0.1
        }

        score = (
            self.exploitability * weights['exploitability'] +
            self.impact * weights['impact'] +
            self.prevalence * weights['prevalence'] +
            self.detectability * weights['detectability'] +
            self.environmental * weights['environmental']
        )

        return min(10.0, max(1.0, score))


class ContextualScorer:
    """Rule-based vulnerability scoring system"""

    def __init__(self):
        # Base risk scores for different vulnerability categories
        self.vulnerability_base_scores = {
            "injection": RiskFactors(  # SQL injection, command injection
                exploitability=8.5, impact=9.0, prevalence=7.0, detectability=6.0, environmental=1.0
            ),
            "xss": RiskFactors(  # Cross-site scripting
                exploitability=7.0, impact=7.5, prevalence=8.0, detectability=5.0, environmental=1.0
            ),
            "crypto": RiskFactors(  # Weak cryptography
                exploitability=4.0, impact=7.0, prevalence=7.0, detectability=8.0, environmental=1.0
            ),
            "secrets": RiskFactors(  # Hardcoded secrets
                exploitability=9.0, impact=8.5, prevalence=8.0, detectability=9.0, environmental=1.0
            ),
            "auth": RiskFactors(  # Authentication issues
                exploitability=8.0, impact=9.0, prevalence=6.0, detectability=7.0, environmental=1.0
            ),
            "access": RiskFactors(  # Authorization/access control
                exploitability=7.5, impact=8.5, prevalence=7.0, detectability=6.0, environmental=1.0
            ),
        }

        # Environmental risk multipliers
        self.environmental_multipliers = {
            'production': 2.0,      # Highest risk
            'staging': 1.5,         # Medium-high risk
            'development': 1.0,     # Baseline risk
            'test': 0.8,           # Lower risk
        }

        # Data sensitivity multipliers
        self.data_sensitivity_multipliers = {
            'critical': 2.5,       # PII, financial data, secrets
            'high': 2.0,          # User data, API keys
            'medium': 1.5,        # Application data
            'low': 1.0,           # Public information
        }

    def score_vulnerability(
        self,
        vulnerability: Vulnerability,
        context: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Score a vulnerability based on deterministic rules

        Args:
            vulnerability: The vulnerability to score
            context: Additional context (environment, data sensitivity, etc.)

        Returns:
            Risk score from 1.0 to 10.0
        """
        context = context or {}

        # Get base risk factors for this vulnerability category
        base_factors = self.vulnerability_base_scores.get(
            getattr(vulnerability, 'category', 'unknown'),
            RiskFactors(5.0, 5.0, 5.0, 5.0, 1.0)  # Default moderate risk
        )

        # Apply contextual adjustments
        adjusted_factors = self._apply_contextual_adjustments(base_factors, vulnerability, context)

        # Calculate final score
        final_score = adjusted_factors.overall_risk

        # Apply confidence adjustment
        confidence_multiplier = self._get_confidence_multiplier(vulnerability.confidence)
        final_score *= confidence_multiplier

        # Ensure score is within bounds
        return min(10.0, max(1.0, round(final_score, 1)))

    def _apply_contextual_adjustments(
        self,
        base_factors: RiskFactors,
        vulnerability: Vulnerability,
        context: Dict[str, Any]
    ) -> RiskFactors:
        """Apply contextual adjustments to risk factors"""

        # Create a copy of base factors
        factors = RiskFactors(
            exploitability=base_factors.exploitability,
            impact=base_factors.impact,
            prevalence=base_factors.prevalence,
            detectability=base_factors.detectability,
            environmental=base_factors.environmental
        )

        # Environmental adjustment
        environment = context.get('environment', 'development').lower()
        env_multiplier = self.environmental_multipliers.get(environment, 1.0)
        factors.environmental *= env_multiplier

        # Data sensitivity adjustment
        data_sensitivity = self._assess_data_sensitivity(vulnerability, context)
        sensitivity_multiplier = self.data_sensitivity_multipliers.get(data_sensitivity, 1.0)
        factors.impact *= sensitivity_multiplier

        # Code location adjustments
        factors = self._adjust_for_code_location(factors, vulnerability, context)

        # User access pattern adjustments
        factors = self._adjust_for_user_access(factors, vulnerability, context)

        # Input validation adjustments
        factors = self._adjust_for_input_validation(factors, vulnerability, context)

        # Network exposure adjustments
        factors = self._adjust_for_network_exposure(factors, vulnerability, context)

        return factors

    def _assess_data_sensitivity(self, vulnerability: Vulnerability, context: Dict[str, Any]) -> str:
        """Assess data sensitivity based on vulnerability context"""

        # Check vulnerability description and code for sensitive data indicators
        sensitive_indicators = [
            'password', 'secret', 'key', 'token', 'api_key', 'apikey',
            'credit', 'card', 'ssn', 'social', 'pii', 'personal',
            'financial', 'bank', 'payment', 'medical', 'health'
        ]

        text_to_check = (
            vulnerability.description.lower() + ' ' +
            vulnerability.code_snippet.lower() + ' ' +
            str(vulnerability.title).lower()
        )

        if any(indicator in text_to_check for indicator in sensitive_indicators):
            return 'critical'

        # Check for database operations (often involve sensitive data)
        if 'sql' in text_to_check or 'database' in text_to_check or 'query' in text_to_check:
            return 'high'

        # Check for file operations (might involve sensitive files)
        if 'file' in text_to_check or 'path' in text_to_check or 'upload' in text_to_check:
            return 'medium'

        return 'low'

    def _adjust_for_code_location(self, factors: RiskFactors, vulnerability: Vulnerability, context: Dict[str, Any]) -> RiskFactors:
        """Adjust risk based on where the vulnerability is located"""

        file_path = str(vulnerability.file_path).lower()

        # API endpoints are higher risk
        if any(term in file_path for term in ['api', 'endpoint', 'route', 'controller']):
            factors.exploitability *= 1.3
            factors.impact *= 1.2

        # Authentication code is critical
        if any(term in file_path for term in ['auth', 'login', 'security', 'permission']):
            factors.impact *= 1.5
            factors.exploitability *= 1.2

        # Database-related files are high risk
        if any(term in file_path for term in ['model', 'db', 'database', 'query', 'sql']):
            factors.impact *= 1.3

        # Test files are lower risk
        if any(term in file_path for term in ['test', 'spec', 'mock']):
            factors.impact *= 0.7
            factors.exploitability *= 0.8

        return factors

    def _adjust_for_user_access(self, factors: RiskFactors, vulnerability: Vulnerability, context: Dict[str, Any]) -> RiskFactors:
        """Adjust risk based on user access patterns"""

        # Public endpoints are higher risk
        if context.get('is_public_endpoint', False):
            factors.exploitability *= 1.4

        # Admin-only functions are lower external risk but higher impact
        if context.get('requires_admin', False):
            factors.exploitability *= 0.8
            factors.impact *= 1.3

        # API endpoints accessed by external systems
        if context.get('external_api', False):
            factors.exploitability *= 1.2
            factors.prevalence *= 1.3

        return factors

    def _adjust_for_input_validation(self, factors: RiskFactors, vulnerability: Vulnerability, context: Dict[str, Any]) -> RiskFactors:
        """Adjust risk based on input validation presence"""

        code = vulnerability.code_snippet.lower()

        # Strong input validation reduces risk
        validation_indicators = [
            'sanitize', 'validate', 'escape', 'filter',
            'whitelist', 'blacklist', 'regex', 'pattern'
        ]

        has_validation = any(indicator in code for indicator in validation_indicators)

        if has_validation:
            factors.exploitability *= 0.7  # Harder to exploit
            factors.impact *= 0.8  # Less damage possible

        # No validation increases risk
        elif context.get('no_validation', False):
            factors.exploitability *= 1.3

        return factors

    def _adjust_for_network_exposure(self, factors: RiskFactors, vulnerability: Vulnerability, context: Dict[str, Any]) -> RiskFactors:
        """Adjust risk based on network exposure"""

        # Internet-facing applications are higher risk
        if context.get('internet_exposed', True):  # Default to exposed
            factors.exploitability *= 1.2
            factors.prevalence *= 1.3

        # Internal-only systems are lower risk
        else:
            factors.exploitability *= 0.8
            factors.prevalence *= 0.7

        return factors

    def _get_confidence_multiplier(self, confidence: str) -> float:
        """Get confidence multiplier for scoring"""

        confidence_multipliers = {
            'CRITICAL': 1.2,  # High confidence increases perceived risk
            'HIGH': 1.0,
            'MEDIUM': 0.9,
            'LOW': 0.8,
        }

        return confidence_multipliers.get(confidence.upper(), 1.0)

    def get_recommendation(self, vulnerability: Vulnerability, score: float) -> str:
        """
        Get remediation recommendation based on vulnerability and score

        Args:
            vulnerability: The vulnerability
            score: Calculated risk score

        Returns:
            Actionable recommendation
        """

        # High-risk recommendations
        if score >= 8.0:
            return "CRITICAL: Immediate remediation required. This vulnerability poses severe risk."

        # Medium-high risk
        elif score >= 6.0:
            return "HIGH PRIORITY: Remediate within 1-2 weeks. Significant security risk present."

        # Medium risk
        elif score >= 4.0:
            return "MEDIUM PRIORITY: Address in next sprint. Moderate security concern."

        # Low risk
        else:
            return "LOW PRIORITY: Consider fixing when convenient. Minimal immediate risk."

    def categorize_by_business_impact(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[Vulnerability]]:
        """
        Categorize vulnerabilities by business impact areas

        Returns:
            Dictionary with categories: 'data_breach', 'compliance', 'operational', 'financial'
        """

        categories = {
            'data_breach': [],
            'compliance': [],
            'operational': [],
            'financial': []
        }

        for vuln in vulnerabilities:
            score = self.score_vulnerability(vuln)

            # Data breach risk (high impact vulnerabilities)
            vuln_category = getattr(vuln, 'category', 'unknown')
            if score >= 7.0 and vuln_category in ['injection', 'xss', 'secrets']:
                categories['data_breach'].append(vuln)

            # Compliance risk (regulated data handling)
            elif score >= 6.0 and 'pii' in str(vuln.description).lower():
                categories['compliance'].append(vuln)

            # Operational risk (system availability)
            elif vuln_category in ['injection']:
                categories['operational'].append(vuln)

            # Financial risk (payment processing)
            elif 'payment' in str(vuln.description).lower() or 'financial' in str(vuln.description).lower():
                categories['financial'].append(vuln)

        return categories
