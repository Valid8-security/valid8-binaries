"""
Report Generator - Creates formatted security reports
"""

import json
from typing import Dict, Any
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax


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


