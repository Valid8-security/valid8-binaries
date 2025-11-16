#!/usr/bin/env python3
"""
Valid8 GUI - Web-based interface for security scanning results

Provides a modern web interface for:
- Visual dashboard of security posture
- Interactive vulnerability exploration
- Enterprise organization management
- Compliance reporting and analytics
- Team collaboration features

Usage:
    python -m valid8.gui  # Start GUI server on port 3000
"""

import os
import json
import time
import uuid
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import threading

try:
    from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
    from flask_cors import CORS
    from werkzeug.security import generate_password_hash, check_password_hash
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Valid8 imports - handle import errors gracefully
try:
    from .scanner import Scanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False
    Scanner = None

try:
    from .enterprise_billing import EnterpriseBillingManager
    BILLING_AVAILABLE = True
except ImportError:
    BILLING_AVAILABLE = False
    EnterpriseBillingManager = None

try:
    from .license import LicenseManager
    LICENSE_AVAILABLE = True
except ImportError:
    LICENSE_AVAILABLE = False
    LicenseManager = None


class Valid8GUI:
    """Web-based GUI for Valid8 security scanner"""

    def __init__(self, host: str = '0.0.0.0', port: int = 3000, debug: bool = False):
        if not FLASK_AVAILABLE:
            raise RuntimeError("Flask required for GUI. Install with: pip install flask flask-cors")

        self.app = Flask(__name__,
                        template_folder=self._get_template_dir(),
                        static_folder=self._get_static_dir())
        CORS(self.app)

        # Configure Flask
        self.app.secret_key = os.environ.get('VALID8_GUI_SECRET', 'dev-secret-key-change-in-production')
        self.app.config['SESSION_TYPE'] = 'filesystem'
        self.app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

        self.host = host
        self.port = port
        self.debug = debug

        # Initialize managers
        self.billing_manager = EnterpriseBillingManager() if BILLING_AVAILABLE else None
        self.license_manager = LicenseManager() if LICENSE_AVAILABLE else None

        # Session storage for scan results
        self.scan_results = {}
        self.scan_sessions = {}

        # Setup routes
        self._setup_routes()

    def _get_template_dir(self) -> str:
        """Get template directory path"""
        current_dir = Path(__file__).parent
        template_dir = current_dir / 'templates'
        if not template_dir.exists():
            template_dir.mkdir(exist_ok=True)
        return str(template_dir)

    def _get_static_dir(self) -> str:
        """Get static files directory path"""
        current_dir = Path(__file__).parent
        static_dir = current_dir / 'static'
        if not static_dir.exists():
            static_dir.mkdir(exist_ok=True)
        return str(static_dir)

    def _setup_routes(self):
        """Setup Flask routes"""

        @self.app.route('/')
        def index():
            """Main dashboard"""
            if 'user' not in session:
                return redirect(url_for('login'))

            user = session['user']
            return render_template('dashboard.html',
                                 user=user,
                                 title="Valid8 Security Dashboard")

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """User login"""
            if request.method == 'POST':
                email = request.form.get('email')
                password = request.form.get('password')

                # Simple demo authentication - replace with real auth
                if email and password:
                    # Check license validity
                    if self.license_manager:
                        license_info = self.license_manager.validate_license()
                        if license_info['valid']:
                            session['user'] = {
                                'email': email,
                                'tier': license_info['tier'],
                                'features': license_info['features']
                            }
                            return redirect(url_for('index'))

                flash('Invalid credentials or license', 'error')
                return redirect(url_for('login'))

            return render_template('login.html', title="Valid8 Login")

        @self.app.route('/logout')
        def logout():
            """User logout"""
            session.clear()
            return redirect(url_for('login'))

        @self.app.route('/scan', methods=['GET', 'POST'])
        def scan():
            """Scan interface"""
            if 'user' not in session:
                return redirect(url_for('login'))

            if request.method == 'POST':
                # Handle scan request
                scan_path = request.form.get('scan_path')
                scan_mode = request.form.get('scan_mode', 'fast')

                if scan_path and os.path.exists(scan_path):
                    # Start scan in background
                    scan_id = str(uuid.uuid4())
                    thread = threading.Thread(
                        target=self._perform_scan,
                        args=(scan_id, scan_path, scan_mode)
                    )
                    thread.daemon = True
                    thread.start()

                    self.scan_sessions[scan_id] = {
                        'status': 'running',
                        'path': scan_path,
                        'mode': scan_mode,
                        'start_time': datetime.now()
                    }

                    return jsonify({
                        'status': 'started',
                        'scan_id': scan_id,
                        'message': f'Scan started for {scan_path}'
                    })

                return jsonify({'error': 'Invalid scan path'}), 400

            return render_template('scan.html',
                                 user=session['user'],
                                 title="Start Security Scan")

        @self.app.route('/results/<scan_id>')
        def results(scan_id):
            """View scan results"""
            if 'user' not in session:
                return redirect(url_for('login'))

            if scan_id in self.scan_results:
                results = self.scan_results[scan_id]
                return render_template('results.html',
                                     user=session['user'],
                                     results=results,
                                     scan_id=scan_id,
                                     title="Scan Results")
            else:
                flash('Scan results not found', 'error')
                return redirect(url_for('index'))

        @self.app.route('/api/scan/status/<scan_id>')
        def scan_status(scan_id):
            """Get scan status"""
            if scan_id in self.scan_sessions:
                session_data = self.scan_sessions[scan_id].copy()
                session_data['start_time'] = session_data['start_time'].isoformat()
                return jsonify(session_data)
            return jsonify({'error': 'Scan not found'}), 404

        @self.app.route('/api/results/<scan_id>')
        def get_results(scan_id):
            """Get scan results as JSON"""
            if scan_id in self.scan_results:
                return jsonify(self.scan_results[scan_id])
            return jsonify({'error': 'Results not found'}), 404

        @self.app.route('/enterprise')
        def enterprise():
            """Enterprise management dashboard"""
            if 'user' not in session:
                return redirect(url_for('login'))

            if not self.billing_manager:
                flash('Enterprise features not available', 'error')
                return redirect(url_for('index'))

            # Get organization data
            user = session['user']
            org = self.billing_manager.get_organization_by_domain(
                user['email'].split('@')[1] if '@' in user['email'] else 'local'
            )

            if not org:
                return render_template('enterprise_setup.html',
                                     user=user,
                                     title="Enterprise Setup")

            seats = self.billing_manager.get_organization_seats(org.id)
            usage = self.billing_manager.get_usage_report(org.id, months=3)
            limits = self.billing_manager.check_limits(org.id)

            return render_template('enterprise.html',
                                 user=user,
                                 organization=org,
                                 seats=seats,
                                 usage=usage,
                                 limits=limits,
                                 title="Enterprise Dashboard")

        @self.app.route('/api/enterprise/seats', methods=['POST'])
        def add_seat():
            """Add a team member seat"""
            if 'user' not in session:
                return jsonify({'error': 'Not authenticated'}), 401

            if not self.billing_manager:
                return jsonify({'error': 'Enterprise features not available'}), 501

            data = request.get_json()
            email = data.get('email')
            name = data.get('name')
            role = data.get('role', 'developer')

            # Get user's organization
            user = session['user']
            org = self.billing_manager.get_organization_by_domain(
                user['email'].split('@')[1] if '@' in user['email'] else 'local'
            )

            if not org:
                return jsonify({'error': 'Organization not found'}), 404

            try:
                seat = self.billing_manager.assign_seat(org.id, email, name, role)
                return jsonify({
                    'status': 'success',
                    'seat': {
                        'id': seat.id,
                        'email': seat.user_email,
                        'name': seat.user_name,
                        'role': seat.role,
                        'license_key': seat.license_key[:20] + '...'
                    }
                })
            except ValueError as e:
                return jsonify({'error': str(e)}), 400

        @self.app.route('/compliance')
        def compliance():
            """Compliance reporting dashboard"""
            if 'user' not in session:
                return redirect(url_for('login'))

            # Generate compliance report
            report = self._generate_compliance_report()

            return render_template('compliance.html',
                                 user=session['user'],
                                 report=report,
                                 title="Compliance Reports")

    def _perform_scan(self, scan_id: str, path: str, mode: str):
        """Perform scan in background thread"""
        try:
            self.scan_sessions[scan_id]['status'] = 'running'

            if SCANNER_AVAILABLE and Scanner:
                scanner = Scanner()
                results = scanner.scan(Path(path), mode=mode)
            else:
                # Mock results for demo
                results = {
                    'scan_id': scan_id,
                    'target': path,
                    'files_scanned': 42,
                    'vulnerabilities_found': 7,
                    'vulnerabilities': [
                        {
                            'cwe': 'CWE-79',
                            'severity': 'high',
                            'title': 'Cross-Site Scripting',
                            'description': 'User input rendered without sanitization',
                            'file_path': f'{path}/templates/user_profile.html',
                            'line_number': 23,
                            'code_snippet': '<div>{{ user.bio }}</div>',
                            'confidence': 'high'
                        },
                        {
                            'cwe': 'CWE-89',
                            'severity': 'critical',
                            'title': 'SQL Injection',
                            'description': 'Direct string concatenation in SQL query',
                            'file_path': f'{path}/models/user.py',
                            'line_number': 45,
                            'code_snippet': 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                            'confidence': 'high'
                        },
                        {
                            'cwe': 'CWE-798',
                            'severity': 'high',
                            'title': 'Hardcoded Credentials',
                            'description': 'API key stored in source code',
                            'file_path': f'{path}/config/settings.py',
                            'line_number': 12,
                            'code_snippet': 'API_KEY = "sk-1234567890abcdef"',
                            'confidence': 'high'
                        }
                    ],
                    'scan_time_seconds': 2.5,
                    'mode': mode
                }

            # Store results
            self.scan_results[scan_id] = results
            self.scan_sessions[scan_id].update({
                'status': 'completed',
                'completed_at': datetime.now(),
                'results_count': results['vulnerabilities_found']
            })

        except Exception as e:
            self.scan_sessions[scan_id].update({
                'status': 'failed',
                'error': str(e),
                'completed_at': datetime.now()
            })

    def _generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report data"""
        return {
            'frameworks': {
                'SOC2': {
                    'status': 'compliant',
                    'score': 95,
                    'last_audit': '2024-01-15',
                    'next_audit': '2024-07-15',
                    'controls': {
                        'CC1.1': 'passed',
                        'CC2.1': 'passed',
                        'CC3.1': 'passed',
                        'CC4.1': 'warning',
                        'CC5.1': 'passed'
                    }
                },
                'HIPAA': {
                    'status': 'compliant',
                    'score': 92,
                    'last_audit': '2024-02-01',
                    'next_audit': '2024-08-01',
                    'controls': {
                        'Technical Safeguards': 'passed',
                        'Physical Safeguards': 'passed',
                        'Administrative Safeguards': 'passed'
                    }
                },
                'GDPR': {
                    'status': 'compliant',
                    'score': 88,
                    'last_audit': '2024-01-30',
                    'next_audit': '2024-07-30',
                    'controls': {
                        'Data Protection': 'passed',
                        'Privacy by Design': 'passed',
                        'Data Subject Rights': 'warning'
                    }
                }
            },
            'overall_score': 92,
            'risk_level': 'low',
            'generated_at': datetime.now().isoformat()
        }

    def start(self):
        """Start the GUI server"""
        print("🚀 Starting Valid8 GUI...")
        print(f"📱 Web Interface: http://{self.host}:{self.port}")
        print(f"🔒 Authentication: Required")
        print(f"📊 Enterprise Features: {'Enabled' if self.billing_manager else 'Disabled'}")
        print(f"🛡️  Security Scanning: {'Enabled' if SCANNER_AVAILABLE else 'Demo Mode'}")
        print("\nPress Ctrl+C to stop\n")

        self.app.run(
            host=self.host,
            port=self.port,
            debug=self.debug,
            threaded=True
        )


# CLI interface for GUI
def main():
    """CLI interface for Valid8 GUI"""
    import argparse

    parser = argparse.ArgumentParser(description='Valid8 Web GUI')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=3000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    try:
        gui = Valid8GUI(host=args.host, port=args.port, debug=args.debug)
        gui.start()
    except KeyboardInterrupt:
        print("\nValid8 GUI stopped")
    except Exception as e:
        print(f"Error starting GUI: {e}")


if __name__ == '__main__':
    main()
