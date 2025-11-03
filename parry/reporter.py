# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Report Generator - Creates formatted security reports

This module provides functionality to generate security scan reports in
multiple formats (JSON, Markdown, terminal output) with comprehensive
vulnerability details, severity breakdowns, and CWE statistics.
"""

# Import JSON for serialization
import json
# Import typing utilities for type hints
from typing import Dict, Any
# Import datetime for timestamps
from datetime import datetime
# Import Rich Console for terminal output
from rich.console import Console
# Import Rich Table for tabular display
from rich.table import Table
# Import Rich Panel for bordered sections
from rich.panel import Panel
# Import Rich Syntax for code highlighting
from rich.syntax import Syntax


class Reporter:
    """
    Generates security scan reports in various formats
    
    This class takes scan results and formats them as JSON, Markdown, or
    styled terminal output with tables, colors, and code highlighting.
    """
    
    def __init__(self, scan_results: Dict[str, Any]):
        """
        Initialize reporter with scan results
        
        Args:
            scan_results: Dictionary containing scan metadata and vulnerabilities
        """
        # Store scan results
        self.results = scan_results
        # Create Rich console for terminal output
        self.console = Console()
    
    def generate_json(self) -> str:
        """
        Generate JSON report
        
        Creates a machine-readable JSON report with scan metadata,
        summary statistics, and full vulnerability details.
        
        Returns:
            JSON string with indented formatting
        """
        # Build report dictionary
        report = {
            "scan_id": self.results["scan_id"],  # Unique scan identifier
            "timestamp": datetime.utcnow().isoformat(),  # ISO timestamp
            "target": self.results["target"],  # Scan target path
            "summary": {  # Summary statistics
                "files_scanned": self.results["files_scanned"],  # File count
                "vulnerabilities_found": self.results["vulnerabilities_found"],  # Vuln count
                "by_severity": self._count_by_severity(),  # Severity breakdown
                "by_cwe": self._count_by_cwe(),  # CWE breakdown
            },
            "vulnerabilities": self.results["vulnerabilities"],  # Full vulnerability list
        }
        # Serialize to JSON with 2-space indentation
        return json.dumps(report, indent=2)
    
    def generate_markdown(self) -> str:
        """
        Generate Markdown report
        
        Creates a human-readable Markdown report suitable for GitHub,
        documentation sites, or conversion to other formats.
        
        Returns:
            Markdown-formatted string
        """
        # Initialize list to collect markdown lines
        md = []
        
        # Header
        # Add main title
        md.append("# Parry Security Scan Report")
        # Add scan ID
        md.append(f"\n**Scan ID:** {self.results['scan_id']}")
        # Add target path
        md.append(f"**Target:** {self.results['target']}")
        # Add timestamp in readable format
        md.append(f"**Timestamp:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        # Summary
        # Add summary section header
        md.append("\n## Summary")
        # Add files scanned count
        md.append(f"\n- **Files Scanned:** {self.results['files_scanned']}")
        # Add vulnerabilities found count
        md.append(f"- **Vulnerabilities Found:** {self.results['vulnerabilities_found']}")
        
        # By severity
        # Add severity breakdown header
        md.append("\n### By Severity")
        # Get severity counts
        severity_counts = self._count_by_severity()
        # Iterate through each severity level
        for severity, count in severity_counts.items():
            # Add severity count line
            md.append(f"- **{severity.capitalize()}:** {count}")
        
        # By CWE
        # Add CWE breakdown header
        md.append("\n### By CWE")
        # Get CWE counts
        cwe_counts = self._count_by_cwe()
        # Iterate through each CWE (sorted)
        for cwe, count in sorted(cwe_counts.items()):
            # Add CWE count line
            md.append(f"- **{cwe}:** {count}")
        
        # Vulnerabilities
        # Add vulnerabilities section header
        md.append("\n## Vulnerabilities")
        
        # Iterate through each vulnerability
        for i, vuln in enumerate(self.results["vulnerabilities"], 1):
            # Add vulnerability title with number
            md.append(f"\n### {i}. {vuln['title']}")
            # Add CWE identifier
            md.append(f"\n- **CWE:** {vuln['cwe']}")
            # Add severity level
            md.append(f"- **Severity:** {vuln['severity'].upper()}")
            # Add confidence level
            md.append(f"- **Confidence:** {vuln['confidence']}")
            # Add file path (in code formatting)
            md.append(f"- **File:** `{vuln['file_path']}`")
            # Add line number
            md.append(f"- **Line:** {vuln['line_number']}")
            # Add description label
            md.append(f"\n**Description:**")
            # Add description text
            md.append(f"\n{vuln['description']}")
            # Add code label
            md.append(f"\n**Code:**")
            # Start code block
            md.append(f"```")
            # Add code snippet
            md.append(f"{vuln['code_snippet']}")
            # End code block
            md.append(f"```")
        
        # Join all lines with newlines
        return "\n".join(md)
    
    def print_terminal(self, verbose: bool = False):
        """
        Print formatted report to terminal
        
        Displays scan results in the terminal with colors, tables, and
        styled output using the Rich library.
        
        Args:
            verbose: If True, show additional details
        """
        
        # Summary panel
        # Build summary text with Rich markup
        summary_text = (
            f"[cyan]Target:[/cyan] {self.results['target']}\n"  # Target path
            f"[cyan]Files Scanned:[/cyan] {self.results['files_scanned']}\n"  # File count
            f"[cyan]Vulnerabilities:[/cyan] {self.results['vulnerabilities_found']}"  # Vuln count
        )
        
        # Print summary in bordered panel
        self.console.print(Panel(summary_text, title="Scan Summary", border_style="cyan"))
        
        # Severity counts
        # Get severity breakdown
        severity_counts = self._count_by_severity()
        # Check if any vulnerabilities found
        if severity_counts:
            # Print severity header
            self.console.print("\n[bold]Vulnerabilities by Severity:[/bold]")
            
            # Create table without header or box
            severity_table = Table(show_header=False, box=None)
            # Add column for severity name
            severity_table.add_column("Severity", style="bold")
            # Add column for count (right-aligned)
            severity_table.add_column("Count", justify="right")
            
            # Define colors for each severity level
            severity_colors = {
                "critical": "red",  # Red for critical
                "high": "orange3",  # Orange for high
                "medium": "yellow",  # Yellow for medium
                "low": "blue"  # Blue for low
            }
            
            # Iterate through severities in priority order
            for severity in ["critical", "high", "medium", "low"]:
                # Get count for this severity
                count = severity_counts.get(severity, 0)
                # Only show if count > 0
                if count > 0:
                    # Get color for this severity
                    color = severity_colors.get(severity, "white")
                    # Add row with colored severity and count
                    severity_table.add_row(
                        f"[{color}]{severity.upper()}[/{color}]",  # Severity name
                        f"[{color}]{count}[/{color}]"  # Count
                    )
            
            # Print the severity table
            self.console.print(severity_table)
        
        # Vulnerabilities
        # Check if any vulnerabilities found
        if self.results["vulnerabilities"]:
            # Print vulnerabilities header with count
            self.console.print(f"\n[bold]Found {len(self.results['vulnerabilities'])} vulnerabilities:[/bold]\n")
            
            # Iterate through each vulnerability
            for i, vuln in enumerate(self.results["vulnerabilities"], 1):
                # Determine color based on severity
                severity_color = {
                    "critical": "red",  # Red for critical
                    "high": "orange3",  # Orange for high
                    "medium": "yellow",  # Yellow for medium
                    "low": "blue"  # Blue for low
                }.get(vuln["severity"], "white")  # Default white
                
                # Format title with severity, name, and CWE
                title = f"[{severity_color}]{vuln['severity'].upper()}[/{severity_color}] {vuln['title']} ({vuln['cwe']})"
                
                # Build vulnerability text with file location and confidence
                vuln_text = (
                    f"[dim]File:[/dim] {vuln['file_path']}:{vuln['line_number']}\n"  # File and line
                    f"[dim]Confidence:[/dim] {vuln['confidence']}\n"  # Confidence level
                )
                
                # Add verbose details if requested
                if verbose:
                    # Add description and code snippet
                    vuln_text += f"\n{vuln['description']}\n\n[dim]Code:[/dim]\n{vuln['code_snippet']}"
                
                # Print vulnerability in bordered panel
                self.console.print(Panel(vuln_text, title=f"{i}. {title}", border_style=severity_color))
        else:
            # No vulnerabilities found
            self.console.print("\n[green]✓ No vulnerabilities found![/green]")
    
    def _count_by_severity(self) -> Dict[str, int]:
        """
        Count vulnerabilities by severity
        
        Aggregates vulnerability counts for each severity level
        (critical, high, medium, low).
        
        Returns:
            Dictionary mapping severity to count
        """
        # Initialize counts dictionary
        counts = {}
        # Iterate through all vulnerabilities
        for vuln in self.results["vulnerabilities"]:
            # Get severity level
            severity = vuln["severity"]
            # Increment count for this severity
            counts[severity] = counts.get(severity, 0) + 1
        # Return counts dictionary
        return counts
    
    def _count_by_cwe(self) -> Dict[str, int]:
        """
        Count vulnerabilities by CWE
        
        Aggregates vulnerability counts for each CWE identifier,
        useful for understanding which vulnerability types are most common.
        
        Returns:
            Dictionary mapping CWE to count
        """
        # Initialize counts dictionary
        counts = {}
        # Iterate through all vulnerabilities
        for vuln in self.results["vulnerabilities"]:
            # Get CWE identifier
            cwe = vuln["cwe"]
            # Increment count for this CWE
            counts[cwe] = counts.get(cwe, 0) + 1
        # Return counts dictionary
        return counts

