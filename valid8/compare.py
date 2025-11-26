#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Comparator - Benchmark Valid8 against other security tools
"""

import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table


class Comparator:
    """Compare Valid8 results with other security tools"""
    
    def __init__(self):
        self.console = Console()
    
    def run_tool(self, tool: str, path: Path) -> Dict[str, Any]:
        """
        Run an external security tool
        
        Args:
            tool: Tool name (snyk, semgrep)
            path: Path to scan
            
        Returns:
            Tool results in standardized format
        """
        if tool == "snyk":
            return self._run_snyk(path)
        elif tool == "semgrep":
            return self._run_semgrep(path)
        else:
            raise ValueError(f"Unsupported tool: {tool}")
    
    def _run_snyk(self, path: Path) -> Dict[str, Any]:
        """Run Snyk security scanner"""
        try:
            # Run snyk test with JSON output
            result = subprocess.run(
                ["snyk", "code", "test", str(path), "--json"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                return self._normalize_snyk(data)
            
            return {"vulnerabilities": [], "tool": "snyk"}
        
        except FileNotFoundError:
            raise RuntimeError(
                "Snyk not found. Install with: npm install -g snyk"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Snyk scan timed out")
        except json.JSONDecodeError:
            raise RuntimeError("Failed to parse Snyk output")
    
    def _run_semgrep(self, path: Path) -> Dict[str, Any]:
        """Run Semgrep security scanner"""
        try:
            result = subprocess.run(
                ["semgrep", "--config=auto", "--json", str(path)],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                return self._normalize_semgrep(data)
            
            return {"vulnerabilities": [], "tool": "semgrep"}
        
        except FileNotFoundError:
            raise RuntimeError(
                "Semgrep not found. Install with: pip install semgrep"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Semgrep scan timed out")
        except json.JSONDecodeError:
            raise RuntimeError("Failed to parse Semgrep output")
    
    def _normalize_snyk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Snyk results to common format"""
        vulnerabilities = []
        
        for vuln in data.get("runs", [{}])[0].get("results", []):
            vulnerabilities.append({
                "file": vuln.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                "line": vuln.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0),
                "severity": vuln.get("level", "warning"),
                "title": vuln.get("message", {}).get("text", ""),
                "rule_id": vuln.get("ruleId", ""),
            })
        
        return {
            "tool": "snyk",
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities)
        }
    
    def _normalize_semgrep(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Semgrep results to common format"""
        vulnerabilities = []
        
        for vuln in data.get("results", []):
            vulnerabilities.append({
                "file": vuln.get("path", ""),
                "line": vuln.get("start", {}).get("line", 0),
                "severity": vuln.get("extra", {}).get("severity", "WARNING"),
                "title": vuln.get("extra", {}).get("message", ""),
                "rule_id": vuln.get("check_id", ""),
            })
        
        return {
            "tool": "semgrep",
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities)
        }
    
    def compare(self, valid8_results: Dict[str, Any], tool_results: Dict[str, Any],
                tool_name: str) -> Dict[str, Any]:
        """
        Compare Valid8 results with another tool

        Returns:
            Comparison statistics
        """
        valid8_vulns = valid8_results["vulnerabilities"]
        tool_vulns = tool_results["vulnerabilities"]
        
        # Create sets of (file, line) tuples for comparison
        valid8_locations = {
            (v["file_path"], v["line_number"]) for v in valid8_vulns
        }
        tool_locations = {
            (v["file"], v["line"]) for v in tool_vulns
        }
        
        # Calculate overlap
        both = valid8_locations & tool_locations
        valid8_only = valid8_locations - tool_locations
        tool_only = tool_locations - valid8_locations
        
        return {
            "tool": tool_name,
            "valid8": {
                "total": len(valid8_vulns),
                "unique": len(valid8_only),
                "by_severity": self._count_by_field(valid8_vulns, "severity"),
            },
            "other_tool": {
                "total": len(tool_vulns),
                "unique": len(tool_only),
            },
            "overlap": {
                "count": len(both),
                "percentage": (len(both) / max(len(valid8_vulns), 1)) * 100,
            },
            "details": {
                "valid8_only": list(valid8_only),
                "tool_only": list(tool_only),
                "both": list(both),
            }
        }
    
    def _count_by_field(self, vulnerabilities: List[Dict], field: str) -> Dict[str, int]:
        """Count vulnerabilities by a specific field"""
        counts = {}
        for vuln in vulnerabilities:
            value = vuln.get(field, "unknown")
            counts[value] = counts.get(value, 0) + 1
        return counts
    
    def generate_markdown(self, comparison: Dict[str, Any]) -> str:
        """Generate Markdown comparison report"""
        md = []
        
        md.append(f"# Valid8 vs {comparison['tool'].capitalize()} Comparison")
        md.append(f"\n## Summary")
        md.append(f"\n| Tool | Total Vulnerabilities | Unique Findings |")
        md.append(f"|------|----------------------|-----------------|")
        md.append(f"| Valid8 | {comparison['valid8']['total']} | {comparison['valid8']['unique']} |")
        md.append(f"| {comparison['tool'].capitalize()} | {comparison['other_tool']['total']} | {comparison['other_tool']['unique']} |")
        
        md.append(f"\n## Overlap")
        md.append(f"\n- **Both tools found:** {comparison['overlap']['count']} vulnerabilities")
        md.append(f"- **Overlap percentage:** {comparison['overlap']['percentage']:.1f}%")
        
        md.append(f"\n## Valid8 Severity Breakdown")
        for severity, count in comparison['valid8']['by_severity'].items():
            md.append(f"- **{severity.upper()}:** {count}")
        
        return "\n".join(md)
    
    def print_terminal(self, comparison: Dict[str, Any]):
        """Print comparison to terminal"""
        
        # Summary table
        table = Table(title=f"Valid8 vs {comparison['tool'].capitalize()}")
        table.add_column("Tool", style="cyan bold")
        table.add_column("Total Vulnerabilities", justify="right")
        table.add_column("Unique Findings", justify="right")
        
        table.add_row(
            "Valid8",
            str(comparison['valid8']['total']),
            str(comparison['valid8']['unique'])
        )
        table.add_row(
            comparison['tool'].capitalize(),
            str(comparison['other_tool']['total']),
            str(comparison['other_tool']['unique'])
        )
        
        self.console.print(table)
        
        # Overlap
        self.console.print(f"\n[bold]Overlap:[/bold]")
        self.console.print(f"  Both tools found: {comparison['overlap']['count']} vulnerabilities")
        self.console.print(f"  Overlap percentage: {comparison['overlap']['percentage']:.1f}%")
        
        # Severity breakdown
        if comparison['valid8']['by_severity']:
            self.console.print(f"\n[bold]Valid8 Severity Breakdown:[/bold]")
            for severity, count in comparison['valid8']['by_severity'].items():
                color = {
                    "critical": "red",
                    "high": "orange3",
                    "medium": "yellow",
                    "low": "blue"
                }.get(severity, "white")
                self.console.print(f"  [{color}]{severity.upper()}:[/{color}] {count}")


