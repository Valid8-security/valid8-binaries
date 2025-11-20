"""
CLI Service - Handles command-line interface operations
"""
from pathlib import Path
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

from ..interfaces.scanner import IScanner, ScanResult
from ..core.config_manager import config_manager
from ..core.dependency_container import get_service


class ICLICommand(ABC):
    """Interface for CLI commands"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Command name"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Command description"""
        pass

    @abstractmethod
    def execute(self, **kwargs) -> int:
        """Execute command and return exit code"""
        pass

    @abstractmethod
    def get_parser_config(self) -> Dict[str, Any]:
        """Get click parser configuration"""
        pass


class ScanCommand(ICLICommand):
    """Scan command implementation"""

    @property
    def name(self) -> str:
        return "scan"

    @property
    def description(self) -> str:
        return "Scan a codebase for security vulnerabilities"

    def get_parser_config(self) -> Dict[str, Any]:
        return {
            'arguments': [
                {
                    'name': 'path',
                    'type': str,
                    'help': 'Path to scan (file or directory)'
                }
            ],
            'options': [
                {
                    'flags': ['--format', '-f'],
                    'type': str,
                    'default': 'terminal',
                    'help': 'Output format (json, markdown, terminal)'
                },
                {
                    'flags': ['--output', '-o'],
                    'type': str,
                    'help': 'Output file path'
                },
                {
                    'flags': ['--mode', '-m'],
                    'type': str,
                    'default': 'fast',
                    'help': 'Scan mode (fast, hybrid, deep)'
                },
                {
                    'flags': ['--severity', '-s'],
                    'type': str,
                    'help': 'Minimum severity level'
                },
                {
                    'flags': ['--validate'],
                    'is_flag': True,
                    'help': 'Use AI to validate findings'
                }
            ]
        }

    def execute(self, **kwargs) -> int:
        """Execute scan command"""
        path = kwargs.get('path')
        if not path:
            print("Error: No path specified")
            return 1

        target_path = Path(path)
        if not target_path.exists():
            print(f"Error: Path does not exist: {path}")
            return 1

        # Get scanner service
        try:
            scanner = get_service(IScanner)
        except ValueError:
            print("Error: Scanner service not available")
            return 1

        print(f"🔍 Scanning {path}...")

        # Prepare scan arguments
        scan_kwargs = {
            'mode': kwargs.get('mode', 'fast'),
            'validate': kwargs.get('validate', False)
        }

        # Execute scan
        try:
            result = scanner.scan(target_path, **scan_kwargs)
            return self._display_results(result, kwargs.get('format'), kwargs.get('output'))
        except Exception as e:
            print(f"Error during scan: {e}")
            return 1

    def _display_results(self, result: ScanResult, format_type: str, output_file: Optional[str]) -> int:
        """Display scan results"""
        if format_type == 'json':
            import json
            output = json.dumps({
                'scan_id': result.scan_id,
                'target': result.target,
                'files_scanned': result.files_scanned,
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities,
                'scan_time': result.scan_time,
                'mode': result.mode
            }, indent=2)

            if output_file:
                Path(output_file).write_text(output)
                print(f"✅ Results saved to {output_file}")
            else:
                print(output)

        elif format_type == 'markdown':
            output = self._generate_markdown_report(result)
            if output_file:
                Path(output_file).write_text(output)
                print(f"✅ Report saved to {output_file}")
            else:
                print(output)

        else:  # terminal format
            self._display_terminal_results(result)

        # Return appropriate exit code
        critical_count = sum(1 for v in result.vulnerabilities if v.get('severity') == 'critical')
        high_count = sum(1 for v in result.vulnerabilities if v.get('severity') == 'high')

        if critical_count > 0:
            return 2
        elif high_count > 0:
            return 1
        else:
            return 0

    def _display_terminal_results(self, result: ScanResult) -> None:
        """Display results in terminal format"""
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel

        console = Console()

        # Summary panel
        summary = f"""
📊 Scan Summary
Target: {result.target}
Files Scanned: {result.files_scanned}
Vulnerabilities Found: {len(result.vulnerabilities)}
Scan Time: {result.scan_time:.2f}s
Mode: {result.mode}
        """.strip()

        console.print(Panel.fit(summary, border_style="blue"))

        if result.vulnerabilities:
            # Vulnerabilities table
            table = Table(title="Vulnerabilities Found")
            table.add_column("Severity", style="bold")
            table.add_column("CWE", style="cyan")
            table.add_column("Title")
            table.add_column("File")
            table.add_column("Line")

            severity_colors = {
                'critical': 'red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'green'
            }

            for vuln in result.vulnerabilities[:20]:  # Show first 20
                severity = vuln.get('severity', 'unknown')
                color = severity_colors.get(severity, 'white')

                table.add_row(
                    f"[{color}]{severity.upper()}[/{color}]",
                    vuln.get('cwe', 'N/A'),
                    vuln.get('title', 'Unknown'),
                    Path(vuln.get('file_path', '')).name,
                    str(vuln.get('line_number', 'N/A'))
                )

            console.print(table)

            if len(result.vulnerabilities) > 20:
                console.print(f"[dim]... and {len(result.vulnerabilities) - 20} more vulnerabilities[/dim]")

        else:
            console.print("✅ No vulnerabilities found!", style="green")

    def _generate_markdown_report(self, result: ScanResult) -> str:
        """Generate markdown report"""
        lines = [
            "# Valid8 Security Scan Report",
            "",
            f"**Scan ID:** {result.scan_id}",
            f"**Target:** {result.target}",
            f"**Files Scanned:** {result.files_scanned}",
            f"**Vulnerabilities Found:** {len(result.vulnerabilities)}",
            f"**Scan Time:** {result.scan_time:.2f}s",
            f"**Mode:** {result.mode}",
            ""
        ]

        if result.vulnerabilities:
            lines.extend([
                "## Vulnerabilities",
                "",
                "| Severity | CWE | Title | File | Line |",
                "|----------|-----|-------|------|------|"
            ])

            for vuln in result.vulnerabilities:
                severity = vuln.get('severity', 'unknown').upper()
                cwe = vuln.get('cwe', 'N/A')
                title = vuln.get('title', 'Unknown')
                file_path = Path(vuln.get('file_path', '')).name
                line = vuln.get('line_number', 'N/A')

                lines.append(f"| {severity} | {cwe} | {title} | {file_path} | {line} |")

        return "\n".join(lines)


class CLICommandRegistry:
    """Registry for CLI commands"""

    def __init__(self):
        self._commands: Dict[str, ICLICommand] = {}

    def register_command(self, command: ICLICommand) -> None:
        """Register a CLI command"""
        self._commands[command.name] = command

    def get_command(self, name: str) -> Optional[ICLICommand]:
        """Get registered command"""
        return self._commands.get(name)

    def list_commands(self) -> Dict[str, ICLICommand]:
        """List all registered commands"""
        return self._commands.copy()


# Global registry instance
command_registry = CLICommandRegistry()

# Register built-in commands
command_registry.register_command(ScanCommand())

