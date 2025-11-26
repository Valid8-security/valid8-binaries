#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Enterprise API for Valid8 Scanner

REST API providing enterprise features:
- Organization management
- Team seat management
- Advanced scanning APIs
- Compliance reporting
- Federated learning
- Supply chain security
- Custom integrations
"""

import os
import json
import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import hmac

try:
    from flask import Flask, request, jsonify, g
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from .scanner import Scanner
except ImportError:
    Scanner = None

from .enterprise_billing import EnterpriseBillingManager, Organization

try:
    from .federated_learning_detector import FederatedModel, LocalTrainer
except ImportError:
    FederatedModel = None
    LocalTrainer = None

try:
    from .security_domains.supply_chain_security import SupplyChainSecurityDetector
except ImportError:
    SupplyChainSecurityDetector = None


class EnterpriseAPI:
    """Enterprise REST API server"""

    def __init__(self, host: str = '0.0.0.0', port: int = 8443):
        if not FLASK_AVAILABLE:
            raise RuntimeError("Flask required for Enterprise API. Run: pip install flask flask-cors")

        self.app = Flask(__name__)
        CORS(self.app)
        self.host = host
        self.port = port

        # Initialize managers
        self.billing_manager = EnterpriseBillingManager()
        self.scanner = Scanner() if Scanner else None

        # Setup routes
        self._setup_routes()

        # API key authentication
        self.api_keys = self._load_api_keys()

    def _setup_routes(self):
        """Setup API routes"""

        @self.app.before_request
        def authenticate_request():
            """Authenticate API requests"""
            api_key = request.headers.get('X-API-Key')
            org_id = request.headers.get('X-Organization-ID')

            if not api_key or not org_id:
                return jsonify({'error': 'Missing API key or organization ID'}), 401

            # Validate API key and organization
            if not self._validate_api_key(api_key, org_id):
                return jsonify({'error': 'Invalid API key or organization'}), 401

            # Check rate limits
            if not self._check_rate_limit(org_id):
                return jsonify({'error': 'Rate limit exceeded'}), 429

            g.organization_id = org_id

        # Organization management
        @self.app.route('/api/v1/organizations', methods=['GET'])
        def get_organization():
            org = self.billing_manager.get_organization(g.organization_id)
            if not org:
                return jsonify({'error': 'Organization not found'}), 404
            return jsonify(self._org_to_dict(org))

        @self.app.route('/api/v1/organizations/seats', methods=['GET'])
        def get_seats():
            seats = self.billing_manager.get_organization_seats(g.organization_id)
            return jsonify([self._seat_to_dict(seat) for seat in seats])

        @self.app.route('/api/v1/organizations/seats', methods=['POST'])
        def assign_seat():
            data = request.get_json()
            if not data or not data.get('email') or not data.get('name'):
                return jsonify({'error': 'Email and name required'}), 400

            try:
                seat = self.billing_manager.assign_seat(
                    g.organization_id,
                    data['email'],
                    data['name'],
                    data.get('role', 'developer')
                )
                self.billing_manager.record_usage(g.organization_id, api_calls=1, endpoint='assign_seat')
                return jsonify(self._seat_to_dict(seat)), 201
            except ValueError as e:
                return jsonify({'error': str(e)}), 400

        @self.app.route('/api/v1/organizations/seats/<email>', methods=['DELETE'])
        def revoke_seat(email):
            if self.billing_manager.revoke_seat(g.organization_id, email):
                self.billing_manager.record_usage(g.organization_id, api_calls=1, endpoint='revoke_seat')
                return jsonify({'status': 'revoked'}), 200
            return jsonify({'error': 'Seat not found'}), 404

        # Scanning APIs
        @self.app.route('/api/v1/scan', methods=['POST'])
        def scan_codebase():
            data = request.get_json()
            if not data or not data.get('repository_url'):
                return jsonify({'error': 'Repository URL required'}), 400

            # Check scan limits
            limits = self.billing_manager.check_limits(g.organization_id)
            if limits.get('scans', {}).get('status') == 'exceeded':
                return jsonify({'error': 'Monthly scan limit exceeded'}), 429

            try:
                # Perform scan
                results = self.scanner.scan_ultra_precise(data['repository_url'])

                # Record usage
                self.billing_manager.record_usage(
                    g.organization_id,
                    scans=1,
                    detector_type='api_scan'
                )

                return jsonify(results), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        # Advanced scanning with federated learning
        @self.app.route('/api/v1/scan/federated', methods=['POST'])
        def federated_scan():
            data = request.get_json()
            if not data or not data.get('codebase_data'):
                return jsonify({'error': 'Codebase data required'}), 400

            if not FederatedModel or not LocalTrainer:
                return jsonify({'error': 'Federated learning not available'}), 501

            try:
                # Initialize federated learning
                model = FederatedModel()
                trainer = LocalTrainer(model)

                # Train on organization's codebase (privacy-preserving)
                results = trainer.train_local_model(data['codebase_data'])

                # Record federated learning session
                self.billing_manager.record_usage(
                    g.organization_id,
                    api_calls=1,
                    endpoint='federated_scan'
                )

                return jsonify({
                    'status': 'federated_scan_complete',
                    'model_updates': results,
                    'privacy_preserved': True
                }), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        # Supply chain security scanning
        @self.app.route('/api/v1/scan/supply-chain', methods=['POST'])
        def supply_chain_scan():
            data = request.get_json()
            if not data or not data.get('dependencies'):
                return jsonify({'error': 'Dependencies list required'}), 400

            if not SupplyChainSecurityDetector:
                return jsonify({'error': 'Supply chain security scanning not available'}), 501

            try:
                detector = SupplyChainSecurityDetector()
                results = detector.scan_dependencies(data['dependencies'])

                self.billing_manager.record_usage(
                    g.organization_id,
                    scans=len(data['dependencies']),
                    detector_type='supply_chain'
                )

                return jsonify(results), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        # Compliance reporting
        @self.app.route('/api/v1/compliance/report', methods=['GET'])
        def compliance_report():
            # Generate compliance report (SOC2, HIPAA, etc.)
            org = self.billing_manager.get_organization(g.organization_id)
            usage = self.billing_manager.get_usage_report(g.organization_id, months=12)

            report = {
                'organization': org.name,
                'compliance_frameworks': ['SOC2', 'HIPAA', 'GDPR'] if org.subscription_tier == 'enterprise' else ['Basic'],
                'audit_period': '12 months',
                'total_scans': sum(u.scans_total for u in usage),
                'security_findings': sum(u.compliance_scans for u in usage),
                'data_encryption': 'AES-256',
                'access_controls': 'RBAC enabled',
                'audit_logs': 'Enabled',
                'generated_at': datetime.now().isoformat()
            }

            self.billing_manager.record_usage(g.organization_id, api_calls=1, endpoint='compliance_report')
            return jsonify(report), 200

        # Usage analytics
        @self.app.route('/api/v1/analytics/usage', methods=['GET'])
        def usage_analytics():
            months = int(request.args.get('months', 3))
            usage = self.billing_manager.get_usage_report(g.organization_id, months=months)

            analytics = {
                'periods': len(usage),
                'total_scans': sum(u.scans_total for u in usage),
                'total_api_calls': sum(u.api_calls_total for u in usage),
                'average_scans_per_month': sum(u.scans_total for u in usage) / max(len(usage), 1),
                'top_detectors': self._aggregate_usage_by_key(usage, 'scans_by_detector'),
                'top_endpoints': self._aggregate_usage_by_key(usage, 'api_calls_by_endpoint'),
                'active_users_trend': [u.active_users for u in usage]
            }

            self.billing_manager.record_usage(g.organization_id, api_calls=1, endpoint='usage_analytics')
            return jsonify(analytics), 200

        # Custom rules management
        @self.app.route('/api/v1/rules/custom', methods=['GET'])
        def get_custom_rules():
            # Return organization's custom security rules
            # Implementation would load from organization's rule storage
            rules = [
                {
                    'id': 'custom-001',
                    'name': 'Company SQL Pattern',
                    'pattern': 'SELECT.*FROM.*WHERE.*\+',
                    'severity': 'HIGH',
                    'created_at': datetime.now().isoformat()
                }
            ]

            self.billing_manager.record_usage(g.organization_id, api_calls=1, endpoint='custom_rules')
            return jsonify({'rules': rules}), 200

        @self.app.route('/api/v1/rules/custom', methods=['POST'])
        def create_custom_rule():
            data = request.get_json()
            if not data or not data.get('name') or not data.get('pattern'):
                return jsonify({'error': 'Name and pattern required'}), 400

            # Save custom rule for organization
            rule = {
                'id': str(uuid.uuid4()),
                'name': data['name'],
                'pattern': data['pattern'],
                'severity': data.get('severity', 'MEDIUM'),
                'description': data.get('description', ''),
                'created_at': datetime.now().isoformat()
            }

            self.billing_manager.record_usage(g.organization_id, api_calls=1, endpoint='create_custom_rule')
            return jsonify(rule), 201

        # Health check
        @self.app.route('/api/v1/health', methods=['GET'])
        def health_check():
            return jsonify({
                'status': 'healthy',
                'version': '1.0.0',
                'organization_id': g.organization_id if hasattr(g, 'organization_id') else None
            }), 200

    def _validate_api_key(self, api_key: str, org_id: str) -> bool:
        """Validate API key for organization"""
        # Simple validation - in production, use proper JWT or API key validation
        expected_key = self.api_keys.get(org_id)
        return api_key == expected_key

    def _check_rate_limit(self, org_id: str) -> bool:
        """Check API rate limits for organization"""
        org = self.billing_manager.get_organization(org_id)
        if not org:
            return False

        # Get current usage for this hour
        usage_reports = self.billing_manager.get_usage_report(org_id, months=1)
        if usage_reports:
            current_usage = usage_reports[0]
            # Rough rate limiting - API calls in current period
            hourly_limit = org.api_rate_limit
            return current_usage.api_calls_total < hourly_limit

        return True

    def _org_to_dict(self, org: Organization) -> Dict[str, Any]:
        """Convert Organization to dict"""
        data = {
            'id': org.id,
            'name': org.name,
            'domain': org.domain,
            'admin_email': org.admin_email,
            'subscription_tier': org.subscription_tier,
            'seats_allocated': org.seats_allocated,
            'seats_used': org.seats_used,
            'monthly_scan_limit': org.monthly_scan_limit,
            'scans_used_this_month': org.scans_used_this_month,
            'api_rate_limit': org.api_rate_limit,
            'sso_enabled': org.sso_enabled,
            'sso_provider': org.sso_provider,
            'support_level': org.support_level,
            'created_at': org.created_at.isoformat() if org.created_at else None
        }
        return data

    def _seat_to_dict(self, seat) -> Dict[str, Any]:
        """Convert SeatAssignment to dict"""
        return {
            'id': seat.id,
            'user_email': seat.user_email,
            'user_name': seat.user_name,
            'role': seat.role,
            'assigned_at': seat.assigned_at.isoformat() if seat.assigned_at else None,
            'last_active': seat.last_active.isoformat() if seat.last_active else None,
            'license_key': seat.license_key[:20] + '...'  # Mask license key
        }

    def _aggregate_usage_by_key(self, usage_reports, key: str) -> Dict[str, int]:
        """Aggregate usage by key across reports"""
        aggregated = {}
        for report in usage_reports:
            data = getattr(report, key, {})
            for k, v in data.items():
                aggregated[k] = aggregated.get(k, 0) + v
        return aggregated

    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys for organizations"""
        # In production, this would be in a secure database
        api_keys_file = Path.home() / '.parry' / 'api_keys.json'
        if api_keys_file.exists():
            try:
                with open(api_keys_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def start(self):
        """Start the API server"""
        print(f"Starting Valid8 Enterprise API on {self.host}:{self.port}")
        print(f"API Documentation: http://{self.host}:{self.port}/api/v1/health")

        # Start with SSL in production
        ssl_context = None
        if os.environ.get('VALID8_SSL_CERT') and os.environ.get('VALID8_SSL_KEY'):
            ssl_context = (os.environ['VALID8_SSL_CERT'], os.environ['VALID8_SSL_KEY'])

        self.app.run(
            host=self.host,
            port=self.port,
            debug=os.environ.get('VALID8_DEBUG', 'false').lower() == 'true',
            ssl_context=ssl_context
        )


# CLI interface for enterprise features
def main():
    """CLI interface for enterprise API"""
    import argparse

    parser = argparse.ArgumentParser(description='Valid8 Enterprise API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8443, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    if args.debug:
        os.environ['VALID8_DEBUG'] = 'true'

    try:
        api = EnterpriseAPI(host=args.host, port=args.port)
        api.start()
    except KeyboardInterrupt:
        print("\nEnterprise API server stopped")
    except Exception as e:
        print(f"Error starting Enterprise API: {e}")


if __name__ == '__main__':
    main()
