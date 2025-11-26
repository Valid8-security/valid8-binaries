#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Report Generator - Creates formatted security reports
"""

import json
import csv
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import pandas as pd
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from jinja2 import Template


class Reporter:
    """Generates security scan reports in various formats"""
    
    def __init__(self, scan_results: Dict[str, Any]):
        self.results = scan_results
        self.console = Console()
    
    def generate_json(self) -> str:
        """Generate JSON report"""
        report = {
            "scan_id": self.results["scan_id"],
            "timestamp": datetime.utcnow().isoformat(),
            "target": self.results["target"],
            "summary": {
                "files_scanned": self.results["files_scanned"],
                "vulnerabilities_found": self.results["vulnerabilities_found"],
                "by_severity": self._count_by_severity(),
                "by_cwe": self._count_by_cwe(),
            },
            "vulnerabilities": self.results["vulnerabilities"],
        }

        # Include SCA results if available
        if "sca_results" in self.results:
            report["sca_results"] = self.results["sca_results"]
        return json.dumps(report, indent=2)
    
    def generate_markdown(self) -> str:
        """Generate Markdown report"""
        md = []
        
        # Header
        md.append("# Parry Security Scan Report")
        md.append(f"\n**Scan ID:** {self.results['scan_id']}")
        md.append(f"**Target:** {self.results['target']}")
        md.append(f"**Timestamp:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        # Summary
        md.append("\n## Summary")
        md.append(f"\n- **Files Scanned:** {self.results['files_scanned']}")
        md.append(f"- **Vulnerabilities Found:** {self.results['vulnerabilities_found']}")
        
        # By severity
        md.append("\n### By Severity")
        severity_counts = self._count_by_severity()
        for severity, count in severity_counts.items():
            md.append(f"- **{severity.capitalize()}:** {count}")
        
        # By CWE
        md.append("\n### By CWE")
        cwe_counts = self._count_by_cwe()
        for cwe, count in sorted(cwe_counts.items()):
            md.append(f"- **{cwe}:** {count}")
        
        # Vulnerabilities
        md.append("\n## Vulnerabilities")
        
        for i, vuln in enumerate(self.results["vulnerabilities"], 1):
            md.append(f"\n### {i}. {vuln['title']}")
            md.append(f"\n- **CWE:** {vuln['cwe']}")
            md.append(f"- **Severity:** {vuln['severity'].upper()}")
            md.append(f"- **Confidence:** {vuln['confidence']}")
            md.append(f"- **File:** `{vuln['file_path']}`")
            md.append(f"- **Line:** {vuln['line_number']}")
            md.append(f"\n**Description:**")
            md.append(f"\n{vuln['description']}")
            md.append(f"\n**Code:**")
            md.append(f"```")
            md.append(f"{vuln['code_snippet']}")
            md.append(f"```")
        
        return "\n".join(md)
    
    def print_terminal(self, verbose: bool = False):
        """Print formatted report to terminal"""
        
        # Summary panel
        summary_text = (
            f"[cyan]Target:[/cyan] {self.results['target']}\n"
            f"[cyan]Files Scanned:[/cyan] {self.results['files_scanned']}\n"
            f"[cyan]Vulnerabilities:[/cyan] {self.results['vulnerabilities_found']}"
        )
        
        self.console.print(Panel(summary_text, title="Scan Summary", border_style="cyan"))
        
        # Severity counts
        severity_counts = self._count_by_severity()
        if severity_counts:
            self.console.print("\n[bold]Vulnerabilities by Severity:[/bold]")
            
            severity_table = Table(show_header=False, box=None)
            severity_table.add_column("Severity", style="bold")
            severity_table.add_column("Count", justify="right")
            
            severity_colors = {
                "critical": "red",
                "high": "orange3",
                "medium": "yellow",
                "low": "blue"
            }
            
            for severity in ["critical", "high", "medium", "low"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = severity_colors.get(severity, "white")
                    severity_table.add_row(
                        f"[{color}]{severity.upper()}[/{color}]",
                        f"[{color}]{count}[/{color}]"
                    )
            
            self.console.print(severity_table)
        
        # Vulnerabilities
        if self.results["vulnerabilities"]:
            self.console.print(f"\n[bold]Found {len(self.results['vulnerabilities'])} vulnerabilities:[/bold]\n")
            
            for i, vuln in enumerate(self.results["vulnerabilities"], 1):
                severity_color = {
                    "critical": "red",
                    "high": "orange3",
                    "medium": "yellow",
                    "low": "blue"
                }.get(vuln["severity"], "white")
                
                title = f"[{severity_color}]{vuln['severity'].upper()}[/{severity_color}] {vuln['title']} ({vuln['cwe']})"
                
                vuln_text = (
                    f"[dim]File:[/dim] {vuln['file_path']}:{vuln['line_number']}\n"
                    f"[dim]Confidence:[/dim] {vuln['confidence']}\n"
                )
                
                if verbose:
                    vuln_text += f"\n{vuln['description']}\n\n[dim]Code:[/dim]\n{vuln['code_snippet']}"
                
                self.console.print(Panel(vuln_text, title=f"{i}. {title}", border_style=severity_color))
        else:
            self.console.print("\n[green]✓ No vulnerabilities found![/green]")

    def generate_csv(self) -> str:
        """Generate CSV report"""
        import io
        output = io.StringIO()

        writer = csv.writer(output)

        # Header
        writer.writerow([
            'CWE', 'Severity', 'Title', 'File Path', 'Line Number',
            'Confidence', 'Category', 'Code Snippet'
        ])

        # Data rows
        for vuln in self.results["vulnerabilities"]:
            writer.writerow([
                vuln.get('cwe', ''),
                vuln.get('severity', ''),
                vuln.get('title', ''),
                vuln.get('file_path', ''),
                vuln.get('line_number', ''),
                vuln.get('confidence', ''),
                vuln.get('category', ''),
                vuln.get('code_snippet', '').replace('\n', ' ').strip()
            ])

        return output.getvalue()

    def generate_xml(self) -> str:
        """Generate XML report"""
        root = ET.Element("parry-report")
        root.set("scan-id", self.results["scan_id"])
        root.set("timestamp", datetime.utcnow().isoformat())

        # Summary
        summary = ET.SubElement(root, "summary")
        ET.SubElement(summary, "files-scanned").text = str(self.results["files_scanned"])
        ET.SubElement(summary, "vulnerabilities-found").text = str(self.results["vulnerabilities_found"])

        # Severity breakdown
        severity_breakdown = ET.SubElement(summary, "severity-breakdown")
        for severity, count in self._count_by_severity().items():
            sev_elem = ET.SubElement(severity_breakdown, "severity")
            sev_elem.set("level", severity)
            sev_elem.text = str(count)

        # Vulnerabilities
        vulnerabilities = ET.SubElement(root, "vulnerabilities")
        for vuln in self.results["vulnerabilities"]:
            vuln_elem = ET.SubElement(vulnerabilities, "vulnerability")

            for key, value in vuln.items():
                if isinstance(value, str):
                    ET.SubElement(vuln_elem, key).text = value
                else:
                    ET.SubElement(vuln_elem, key).text = str(value)

        # Convert to string
        rough_string = ET.tostring(root, 'utf-8')
        reparsed = ET.fromstring(rough_string)
        return ET.tostring(reparsed, encoding='unicode', method='xml')

    def generate_html_dashboard(self) -> str:
        """Generate interactive HTML dashboard with charts"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Parry Security Dashboard</title>
            <script src="https://cdn.plotly.com/plotly-latest.min.js"></script>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
                .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
                .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .metric { font-size: 2em; font-weight: bold; color: #333; }
                .label { color: #666; font-size: 0.9em; }
                .charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
                .vulnerabilities { background: white; padding: 20px; border-radius: 10px; margin-top: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .vuln-item { border-left: 4px solid; padding: 10px; margin: 10px 0; }
                .critical { border-left-color: #dc3545; background: #f8d7da; }
                .high { border-left-color: #fd7e14; background: #ffeaa7; }
                .medium { border-left-color: #ffc107; background: #fff3cd; }
                .low { border-left-color: #28a745; background: #d4edda; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔒 Parry Security Dashboard</h1>
                <p>Scan ID: {{ scan_id }} | Generated: {{ timestamp }}</p>
            </div>

            <div class="summary-cards">
                <div class="card">
                    <div class="metric">{{ files_scanned }}</div>
                    <div class="label">Files Scanned</div>
                </div>
                <div class="card">
                    <div class="metric">{{ vulnerabilities_found }}</div>
                    <div class="label">Vulnerabilities Found</div>
                </div>
                <div class="card">
                    <div class="metric">{{ critical_count }}</div>
                    <div class="label">Critical Issues</div>
                </div>
                <div class="card">
                    <div class="metric">{{ high_count }}</div>
                    <div class="label">High Severity</div>
                </div>
            </div>

            <div class="charts">
                <div id="severity-chart" class="card"></div>
                <div id="cwe-chart" class="card"></div>
            </div>

            <div class="vulnerabilities">
                <h2>🚨 Vulnerabilities ({{ vulnerabilities_found }})</h2>
                {% for vuln in vulnerabilities %}
                <div class="vuln-item {{ vuln.severity }}">
                    <h4>{{ vuln.title }} ({{ vuln.cwe }})</h4>
                    <p><strong>File:</strong> {{ vuln.file_path }}:{{ vuln.line_number }}</p>
                    <p><strong>Confidence:</strong> {{ vuln.confidence }}</p>
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    <pre><code>{{ vuln.code_snippet }}</code></pre>
                </div>
                {% endfor %}
            </div>

            <script>
                // Severity Chart
                const severityData = {{ severity_data | tojson }};
                const severityChart = {
                    type: 'pie',
                    labels: severityData.map(d => d.severity),
                    values: severityData.map(d => d.count),
                    marker: {
                        colors: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                    }
                };

                Plotly.newPlot('severity-chart', [severityChart], {
                    title: 'Vulnerabilities by Severity'
                });

                // CWE Chart
                const cweData = {{ cwe_data | tojson }};
                const topCweData = cweData.slice(0, 10);
                const cweChart = {
                    type: 'bar',
                    x: topCweData.map(d => d.cwe),
                    y: topCweData.map(d => d.count),
                    marker: { color: '#667eea' }
                };

                Plotly.newPlot('cwe-chart', [cweChart], {
                    title: 'Top 10 CWE Categories'
                });
            </script>
        </body>
        </html>
        """

        # Prepare data for template
        severity_counts = self._count_by_severity()
        cwe_counts = self._count_by_cwe()

        severity_data = [{"severity": k, "count": v} for k, v in severity_counts.items()]
        cwe_data = [{"cwe": k, "count": v} for k, v in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)]

        template = Template(html_template)
        return template.render(
            scan_id=self.results["scan_id"],
            timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            files_scanned=self.results["files_scanned"],
            vulnerabilities_found=self.results["vulnerabilities_found"],
            critical_count=severity_counts.get('critical', 0),
            high_count=severity_counts.get('high', 0),
            severity_data=severity_data,
            cwe_data=cwe_data,
            vulnerabilities=self.results["vulnerabilities"][:50]  # Limit to first 50 for performance
        )

    def generate_sarif(self) -> str:
        """Generate SARIF (Static Analysis Results Interchange Format) report"""
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Parry",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-org/parry",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        # Add rules (CWEs)
        cwe_rules = set()
        for vuln in self.results["vulnerabilities"]:
            cwe_rules.add(vuln["cwe"])

        for cwe in cwe_rules:
            rule = {
                "id": cwe,
                "name": cwe,
                "shortDescription": {
                    "text": f"{cwe} vulnerability"
                },
                "help": {
                    "text": f"Security vulnerability classified as {cwe}"
                }
            }
            sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)

        # Add results
        for vuln in self.results["vulnerabilities"]:
            result = {
                "ruleId": vuln["cwe"],
                "level": self._map_severity_to_sarif_level(vuln["severity"]),
                "message": {
                    "text": vuln["title"]
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vuln["file_path"]
                        },
                        "region": {
                            "startLine": vuln["line_number"]
                        }
                    }
                }],
                "properties": {
                    "confidence": vuln.get("confidence", "unknown"),
                    "category": vuln.get("category", "unknown")
                }
            }

            if "code_snippet" in vuln:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": vuln["code_snippet"]
                }

            sarif_report["runs"][0]["results"].append(result)

        return json.dumps(sarif_report, indent=2)

    def _map_severity_to_sarif_level(self, severity: str) -> str:
        """Map Parry severity to SARIF level"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note"
        }
        return mapping.get(severity.lower(), "note")

    def save_report(self, content: str, filename: str, format: str) -> None:
        """Save report to file with appropriate extension"""
        if not filename.endswith(f'.{format}'):
            filename += f'.{format}'

        Path(filename).write_text(content)
        self.console.print(f"[green]Report saved to: {filename}[/green]")

    def _count_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {}
        for vuln in self.results["vulnerabilities"]:
            severity = vuln["severity"]
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_by_cwe(self) -> Dict[str, int]:
        """Count vulnerabilities by CWE"""
        counts = {}
        for vuln in self.results["vulnerabilities"]:
            cwe = vuln["cwe"]
            counts[cwe] = counts.get(cwe, 0) + 1
        return counts


