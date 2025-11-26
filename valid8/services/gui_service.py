#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
GUI Service - Handles web interface operations
"""
from pathlib import Path
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

from ..interfaces.scanner import IScanner, ScanResult
from ..core.config_manager import config_manager


class IGUIComponent(ABC):
    """Interface for GUI components"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Component name"""
        pass

    @abstractmethod
    def render(self, **kwargs) -> str:
        """Render component HTML"""
        pass

    @abstractmethod
    def get_routes(self) -> Dict[str, callable]:
        """Get Flask routes for this component"""
        pass


class ScanComponent(IGUIComponent):
    """GUI component for scanning functionality"""

    @property
    def name(self) -> str:
        return "scan"

    def render(self, **kwargs) -> str:
        """Render scan interface"""
        return """
        <div class="card">
            <div class="card-header">
                <h5>Start Security Scan</h5>
            </div>
            <div class="card-body">
                <form id="scanForm">
                    <div class="mb-3">
                        <label for="scanPath" class="form-label">Scan Path</label>
                        <input type="text" class="form-control" id="scanPath"
                               placeholder="/path/to/scan" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Scan Mode</label>
                        <div class="form-check">
                            <input class="form-check-input" type="radio" name="scanMode" value="fast" checked>
                            <label class="form-check-label">Fast Mode</label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="radio" name="scanMode" value="hybrid">
                            <label class="form-check-label">Hybrid Mode (AI)</label>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Start Scan</button>
                </form>
                <div id="scanProgress" class="mt-3" style="display: none;">
                    <div class="progress">
                        <div class="progress-bar" id="progressBar"></div>
                    </div>
                    <div id="scanStatus" class="mt-2"></div>
                </div>
            </div>
        </div>
        """

    def get_routes(self) -> Dict[str, callable]:
        """Get routes for scan component"""
        def handle_scan():
            # Implementation would go here
            return {"status": "not_implemented"}

        return {
            "/api/scan": handle_scan
        }


class ResultsComponent(IGUIComponent):
    """GUI component for displaying results"""

    @property
    def name(self) -> str:
        return "results"

    def render(self, scan_result: Optional[ScanResult] = None, **kwargs) -> str:
        """Render results interface"""
        if not scan_result:
            return "<div class='alert alert-info'>No scan results available</div>"

        vuln_count = len(scan_result.vulnerabilities)

        html = f"""
        <div class="card">
            <div class="card-header">
                <h5>Scan Results</h5>
                <small class="text-muted">Target: {scan_result.target}</small>
            </div>
            <div class="card-body">
                <div class="row mb-3">
                    <div class="col-md-3">
                        <div class="text-center">
                            <h4 class="text-primary">{scan_result.files_scanned}</h4>
                            <small>Files Scanned</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="text-center">
                            <h4 class="text-danger">{vuln_count}</h4>
                            <small>Vulnerabilities</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="text-center">
                            <h4 class="text-info">{scan_result.scan_time:.1f}s</h4>
                            <small>Scan Time</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="text-center">
                            <h4 class="text-success">{scan_result.mode.title()}</h4>
                            <small>Mode</small>
                        </div>
                    </div>
                </div>
        """

        if vuln_count > 0:
            html += """
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>CWE</th>
                                <th>Title</th>
                                <th>File</th>
                                <th>Line</th>
                            </tr>
                        </thead>
                        <tbody>
            """

            severity_badges = {
                'critical': 'badge bg-danger',
                'high': 'badge bg-danger',
                'medium': 'badge bg-warning',
                'low': 'badge bg-success'
            }

            for vuln in scan_result.vulnerabilities[:50]:  # Limit for display
                severity = vuln.get('severity', 'unknown')
                badge_class = severity_badges.get(severity, 'badge bg-secondary')

                html += f"""
                    <tr>
                        <td><span class="{badge_class}">{severity.upper()}</span></td>
                        <td><code>{vuln.get('cwe', 'N/A')}</code></td>
                        <td>{vuln.get('title', 'Unknown')}</td>
                        <td>{Path(vuln.get('file_path', '')).name}</td>
                        <td>{vuln.get('line_number', 'N/A')}</td>
                    </tr>
                """

            html += """
                        </tbody>
                    </table>
                </div>
            """

            if vuln_count > 50:
                html += f"<div class='alert alert-info'>... and {vuln_count - 50} more vulnerabilities</div>"

        else:
            html += '<div class="alert alert-success">✅ No vulnerabilities found!</div>'

        html += """
            </div>
        </div>
        """

        return html

    def get_routes(self) -> Dict[str, callable]:
        """Get routes for results component"""
        def get_results(scan_id):
            # Implementation would go here
            return {"error": "not_implemented"}

        return {
            "/api/results/<scan_id>": get_results
        }


class DashboardComponent(IGUIComponent):
    """GUI component for dashboard"""

    @property
    def name(self) -> str:
        return "dashboard"

    def render(self, stats: Optional[Dict[str, Any]] = None, **kwargs) -> str:
        """Render dashboard"""
        stats = stats or {
            'total_scans': 0,
            'total_vulnerabilities': 0,
            'avg_scan_time': 0,
            'recent_scans': []
        }

        return f"""
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <i class="bi bi-search text-primary" style="font-size: 2rem;"></i>
                        <h4 class="mt-2">{stats['total_scans']}</h4>
                        <small>Total Scans</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <i class="bi bi-exclamation-triangle text-danger" style="font-size: 2rem;"></i>
                        <h4 class="mt-2">{stats['total_vulnerabilities']}</h4>
                        <small>Vulnerabilities Found</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <i class="bi bi-clock text-info" style="font-size: 2rem;"></i>
                        <h4 class="mt-2">{stats['avg_scan_time']:.1f}s</h4>
                        <small>Avg Scan Time</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <i class="bi bi-shield-check text-success" style="font-size: 2rem;"></i>
                        <h4 class="mt-2">95%</h4>
                        <small>Precision Rate</small>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h6>Recent Scans</h6>
                    </div>
                    <div class="card-body">
                        {"<p class='text-muted'>No recent scans</p>" if not stats['recent_scans'] else ""}
                        {"".join([f"<div class='mb-2'><strong>{scan['target']}</strong><br><small>{scan['timestamp']}</small></div>" for scan in stats['recent_scans']])}}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h6>Quick Actions</h6>
                    </div>
                    <div class="card-body">
                        <a href="/scan" class="btn btn-primary w-100 mb-2">Start New Scan</a>
                        <a href="/enterprise" class="btn btn-outline-primary w-100">Enterprise Dashboard</a>
                    </div>
                </div>
            </div>
        </div>
        """

    def get_routes(self) -> Dict[str, callable]:
        """Get routes for dashboard component"""
        def get_stats():
            # Implementation would go here
            return {
                'total_scans': 0,
                'total_vulnerabilities': 0,
                'avg_scan_time': 0,
                'recent_scans': []
            }

        return {
            "/api/dashboard/stats": get_stats
        }


class GUIComponentRegistry:
    """Registry for GUI components"""

    def __init__(self):
        self._components: Dict[str, IGUIComponent] = {}

    def register_component(self, component: IGUIComponent) -> None:
        """Register a GUI component"""
        self._components[component.name] = component

    def get_component(self, name: str) -> Optional[IGUIComponent]:
        """Get registered component"""
        return self._components.get(name)

    def list_components(self) -> Dict[str, IGUIComponent]:
        """List all registered components"""
        return self._components.copy()

    def get_all_routes(self) -> Dict[str, callable]:
        """Get all routes from all components"""
        routes = {}
        for component in self._components.values():
            routes.update(component.get_routes())
        return routes


# Global registry instance
gui_registry = GUIComponentRegistry()

# Register built-in components
gui_registry.register_component(ScanComponent())
gui_registry.register_component(ResultsComponent())
gui_registry.register_component(DashboardComponent())

