#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Demo script showcasing Parry scanning with real feedback and fix suggestions
"""

import sys
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown
import time

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from parry.scanner import Scanner
from parry.patch import PatchGenerator
from parry.llm import LLMClient
from parry.license import LicenseManager

console = Console()


def print_header():
    """Print demo header"""
    console.print(Panel.fit(
        "[bold cyan]🔒 Parry Security Scanner - Live Demo[/bold cyan]\n"
        "[dim]Scanning code, detecting vulnerabilities, and suggesting fixes[/dim]",
        border_style="cyan"
    ))


def scan_codebase(target_path):
    """Scan the codebase and return results"""
    console.print("\n[cyan]📋 Step 1: Scanning codebase...[/cyan]")
    console.print(f"[dim]Target: {target_path}[/dim]\n")
    
    # Initialize scanner
    scanner = Scanner()
    
    # Run scan
    start_time = time.time()
    results = scanner.scan(Path(target_path))
    elapsed = time.time() - start_time
    
    # Display stats
    console.print(f"\n[green]✓ Scan complete in {elapsed:.2f} seconds[/green]")
    console.print(f"[green]✓ Files scanned: {results.get('files_scanned', 0)}[/green]")
    console.print(f"[green]✓ Vulnerabilities found: {results.get('vulnerabilities_found', 0)}[/green]\n")
    
    return results


def display_vulnerabilities(results):
    """Display found vulnerabilities in a table"""
    vulns = results.get('vulnerabilities', [])
    
    if not vulns:
        console.print(Panel(
            "[bold green]No vulnerabilities found![/bold green]",
            border_style="green"
        ))
        return
    
    console.print("\n[cyan]📊 Vulnerabilities Detected:[/cyan]\n")
    
    # Create table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", style="red", width=8)
    table.add_column("CWE", width=12)
    table.add_column("Title", width=40)
    table.add_column("Location", width=30)
    
    # Add rows
    for i, vuln in enumerate(vulns, 1):
        severity = vuln.get('severity', 'unknown')
        cwe = vuln.get('cwe', 'Unknown')
        title = vuln.get('title', 'No title')[:38]
        filepath = vuln.get('file_path', 'unknown')
        line_num = vuln.get('line_number', 0)
        location = f"{filepath}:{line_num}"[:28]
        
        # Color severity
        if severity == 'critical':
            severity_style = "[bold red]Critical[/bold red]"
        elif severity == 'high':
            severity_style = "[red]High[/red]"
        elif severity == 'medium':
            severity_style = "[yellow]Medium[/yellow]"
        else:
            severity_style = f"[dim]{severity.capitalize()}[/dim]"
        
        table.add_row(str(i), severity_style, cwe, title, location)
    
    console.print(table)


def show_detailed_vulnerability(vuln, index):
    """Show detailed information about a vulnerability"""
    console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
    console.print(f"[bold cyan]Vulnerability #{index}: {vuln.get('title', 'Unknown')}[/bold cyan]")
    console.print(f"[bold cyan]{'='*70}[/bold cyan]\n")
    
    # Basic info
    console.print(f"[bold]Severity:[/bold] {vuln.get('severity', 'unknown').upper()}")
    console.print(f"[bold]CWE:[/bold] {vuln.get('cwe', 'Unknown')}")
    console.print(f"[bold]Location:[/bold] {vuln.get('file_path', 'unknown')}:{vuln.get('line_number', 0)}")
    console.print(f"[bold]Confidence:[/bold] {vuln.get('confidence', 'unknown')}\n")
    
    # Description
    description = vuln.get('description', 'No description available.')
    console.print(Panel(
        description,
        title="[bold yellow]Description[/bold yellow]",
        border_style="yellow"
    ))
    
    # Show code snippet
    code_snippet = vuln.get('code_snippet', vuln.get('code', 'No code available.'))
    if code_snippet and code_snippet != 'No code available.':
        console.print("\n[bold]Vulnerable Code:[/bold]\n")
        syntax = Syntax(code_snippet, "python", theme="monokai", line_numbers=True, 
                       start_line=max(1, vuln.get('line_number', 1) - 5))
        console.print(syntax)


def generate_and_display_fixes(results):
    """Generate and display fix suggestions"""
    vulns = results.get('vulnerabilities', [])
    
    if not vulns:
        return
    
    # Check if AI features are available
    tier = LicenseManager.get_tier()
    has_feature = LicenseManager.has_feature('ai-detection')
    
    if not has_feature:
        console.print(Panel(
            "[yellow]⚠️  AI-powered fixes require Pro/Enterprise license[/yellow]\n"
            f"Current tier: [bold]{tier}[/bold]\n\n"
            "[dim]Showing basic remediation guidance instead...[/dim]",
            border_style="yellow"
        ))
        
        # Show basic guidance
        show_basic_guidance(vulns)
        return
    
    # Check if Ollama is available
    from parry.setup import SetupHelper
    helper = SetupHelper()
    
    if not (helper.check_ollama_running() and helper.check_model_available()):
        console.print(Panel(
            "[yellow]⚠️  Ollama not available for AI fix generation[/yellow]\n"
            "[dim]Showing basic remediation guidance instead...[/dim]",
            border_style="yellow"
        ))
        show_basic_guidance(vulns)
        return
    
    console.print("\n[cyan]🤖 Step 2: Generating AI-powered fixes...[/cyan]")
    console.print("[dim]This may take a moment...[/dim]\n")
    
    # Initialize AI components
    llm_client = LLMClient()
    patch_generator = PatchGenerator(llm_client)
    
    # Generate fixes for first 5 vulnerabilities
    fixed_count = 0
    for i, vuln in enumerate(vulns[:5], 1):
        console.print(f"\n[yellow]Generating fix for vulnerability #{i}...[/yellow]")
        
        try:
            file_path = Path(vuln.get('file_path', ''))
            if not file_path.exists():
                console.print(f"[dim]Skipping {file_path} (file not found)[/dim]")
                continue
            
            patch = patch_generator.generate_patch(file_path, vuln)
            
            if patch and patch.get('fixed_code'):
                fixed_count += 1
                display_patch(vuln, patch)
            
        except Exception as e:
            console.print(f"[red]Error generating patch: {e}[/red]")
    
    if fixed_count == 0:
        console.print("\n[yellow]⚠️  Could not generate AI fixes. Showing basic guidance instead.[/yellow]\n")
        show_basic_guidance(vulns)


def display_patch(vuln, patch):
    """Display a generated patch"""
    console.print(f"\n[bold green]{'─'*70}[/bold green]")
    console.print(f"[bold green]Fix for: {vuln.get('title', 'Unknown')}[/bold green]")
    console.print(f"[bold green]{'─'*70}[/bold green]\n")
    
    # Show original code
    console.print("[bold red]Original Code:[/bold red]\n")
    original_code = patch.get('original_code', 'No code available.')
    syntax_orig = Syntax(original_code, "python", theme="monokai", line_numbers=False)
    console.print(syntax_orig)
    
    console.print()
    
    # Show fixed code
    console.print("[bold green]Fixed Code:[/bold green]\n")
    fixed_code = patch.get('fixed_code', 'No fix available.')
    syntax_fixed = Syntax(fixed_code, "python", theme="monokai", line_numbers=False)
    console.print(syntax_fixed)
    
    # Show explanation
    explanation = patch.get('explanation', 'No explanation available.')
    if explanation:
        console.print("\n[bold cyan]Explanation:[/bold cyan]")
        console.print(Panel(
            explanation,
            border_style="cyan"
        ))


def show_basic_guidance(vulns):
    """Show basic remediation guidance without AI"""
    console.print("\n[cyan]📖 Basic Remediation Guidance[/cyan]\n")
    
    # Common fixes by CWE
    common_fixes = {
        'CWE-79': [
            "Escape user input using proper HTML escaping functions",
            "Use template engines with auto-escaping (Jinja2, etc.)",
            "Never render user input directly in HTML",
            "Use CSP headers to prevent XSS"
        ],
        'CWE-89': [
            "Use parameterized queries or prepared statements",
            "Never concatenate user input into SQL strings",
            "Use ORM frameworks with built-in protection",
            "Validate and sanitize all database inputs"
        ],
        'CWE-78': [
            "Avoid using os.system() or subprocess with user input",
            "Use subprocess.run() with explicit arguments list",
            "Validate all input against allowlists",
            "Run with least privilege"
        ],
        'CWE-22': [
            "Validate file paths against allowlists",
            "Use path normalization functions",
            "Ensure file paths stay within allowed directories",
            "Check for path traversal sequences (../)"
        ],
        'CWE-502': [
            "Never deserialize untrusted data",
            "Use safer serialization formats (JSON)",
            "Implement integrity checks on serialized data",
            "Use allowlists for allowed types"
        ],
        'CWE-327': [
            "Use strong cryptographic algorithms (bcrypt, Argon2)",
            "Never use MD5 or SHA-1 for passwords",
            "Use appropriate key lengths",
            "Follow NIST guidelines"
        ],
        'CWE-798': [
            "Store secrets in environment variables",
            "Use secret management systems (HashiCorp Vault, etc.)",
            "Never hardcode credentials",
            "Rotate secrets regularly"
        ],
        'CWE-918': [
            "Validate URLs against allowlists",
            "Use proper URL parsing libraries",
            "Block internal network access",
            "Implement request timeouts"
        ]
    }
    
    # Show guidance for detected CWEs
    detected_cwes = set()
    for vuln in vulns:
        cwe = vuln.get('cwe', '')
        if cwe:
            detected_cwes.add(cwe)
    
    guidance_shown = False
    for cwe in detected_cwes:
        if cwe in common_fixes:
            guidance_shown = True
            console.print(f"[bold]{cwe} Remediation:[/bold]\n")
            for i, fix in enumerate(common_fixes[cwe], 1):
                console.print(f"  {i}. {fix}")
            console.print()
    
    if not guidance_shown:
        console.print("[dim]No specific guidance available for detected vulnerabilities.[/dim]\n")


def print_summary(results):
    """Print summary and next steps"""
    vulns = results.get('vulnerabilities', [])
    
    console.print("\n[cyan]📋 Summary[/cyan]\n")
    
    # Count by severity
    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    by_cwe = {}
    
    for vuln in vulns:
        severity = vuln.get('severity', 'unknown')
        if severity in by_severity:
            by_severity[severity] += 1
        
        cwe = vuln.get('cwe', 'Unknown')
        by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
    
    # Severity breakdown
    console.print("[bold]Severity Breakdown:[/bold]")
    for severity, count in by_severity.items():
        if count > 0:
            console.print(f"  {severity.capitalize()}: {count}")
    
    # Top CWEs
    console.print(f"\n[bold]Top Vulnerability Types:[/bold]")
    sorted_cwes = sorted(by_cwe.items(), key=lambda x: x[1], reverse=True)[:5]
    for cwe, count in sorted_cwes:
        console.print(f"  {cwe}: {count} occurrence(s)")
    
    # Next steps
    console.print("\n[bold cyan]Recommended Next Steps:[/bold cyan]\n")
    console.print("1. [bold]Review high-priority vulnerabilities first[/bold]")
    console.print("2. [bold]Apply suggested fixes or basic guidance[/bold]")
    console.print("3. [bold]Re-scan to verify fixes[/bold]")
    console.print("4. [bold]Consider integrating into CI/CD pipeline[/bold]\n")
    
    console.print(Panel(
        "[bold cyan]Want to run this again?[/bold cyan]\n"
        "[dim]python scripts/demo_scan_with_fixes.py examples/vulnerable_code.py[/dim]\n\n"
        "[bold cyan]Need help?[/bold cyan]\n"
        "[dim]https://parry.dev/docs[/dim]",
        border_style="cyan",
        title="[bold cyan]Questions?[/bold cyan]"
    ))


def main():
    """Main demo function"""
    print_header()
    
    # Determine target
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        # Default to vulnerable code example
        target = "examples/vulnerable_code.py"
    
    # Check if target exists
    if not Path(target).exists():
        console.print(f"[red]Error: {target} does not exist[/red]")
        return 1
    
    try:
        # Step 1: Scan
        results = scan_codebase(target)
        
        # Step 2: Display vulnerabilities
        display_vulnerabilities(results)
        
        # Step 3: Show details for first few
        vulns = results.get('vulnerabilities', [])
        if vulns:
            console.print("\n[cyan]🔍 Detailed Vulnerability Information:[/cyan]")
            for i, vuln in enumerate(vulns[:3], 1):  # Show first 3 details
                show_detailed_vulnerability(vuln, i)
            
            # Ask if user wants to see more
            if len(vulns) > 3:
                console.print(f"\n[dim]... and {len(vulns) - 3} more vulnerabilities[/dim]\n")
        
        # Step 4: Generate fixes
        generate_and_display_fixes(results)
        
        # Step 5: Summary
        print_summary(results)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo interrupted by user[/yellow]")
        return 130
    except Exception as e:
        console.print(f"\n[red]Error during demo: {e}[/red]")
        import traceback
        console.print(Panel(
            traceback.format_exc(),
            title="[bold red]Traceback[/bold red]",
            border_style="red"
        ))
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())

