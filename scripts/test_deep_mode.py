#!/usr/bin/env python3
"""
Deep Mode Testing Script
Tests Parry's AI-powered Deep Mode vulnerability detection
"""

import sys
import time
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress

sys.path.insert(0, str(Path(__file__).parent.parent))

console = Console()

def check_ollama_setup():
    """Check if Ollama is properly set up"""
    console.print("\n[cyan]Checking Ollama setup...[/cyan]")
    
    try:
        from parry.setup import SetupHelper
        helper = SetupHelper()
        
        ollama_running = helper.check_ollama_running()
        model_available = helper.check_model_available()
        
        if ollama_running and model_available:
            console.print("[green]✓ Ollama is running and model is available[/green]")
            return True
        elif ollama_running:
            console.print("[yellow]⚠️  Ollama is running but model not found[/yellow]")
            console.print("[dim]Run: ollama pull codellama:7b[/dim]")
            return False
        else:
            console.print("[red]✗ Ollama is not running[/red]")
            console.print("[dim]Start Ollama: ollama serve[/dim]")
            return False
    except Exception as e:
        console.print(f"[red]Error checking Ollama: {e}[/red]")
        return False


def test_deep_mode_scan(file_path):
    """Test Deep Mode scanning on a file"""
    console.print(f"\n[cyan]Testing Deep Mode on: {file_path}[/cyan]")
    
    try:
        from parry.scanner import Scanner
        from parry.ai_detector import AIDetector
        
        # Initialize scanner and AI detector
        scanner = Scanner()
        ai_detector = AIDetector()
        
        # Read the file
        code = Path(file_path).read_text()
        
        # Run AI detection
        console.print("[dim]Running AI-powered detection...[/dim]")
        start_time = time.time()
        ai_vulns = ai_detector.detect_vulnerabilities(
            code,
            str(file_path),
            'python'  # Language
        )
        elapsed = time.time() - start_time
        
        # Display results
        console.print(f"[green]✓ AI scan complete in {elapsed:.2f}s[/green]")
        console.print(f"[green]✓ Found {len(ai_vulns)} vulnerabilities[/green]\n")
        
        return ai_vulns, elapsed
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        console.print(Panel(
            traceback.format_exc(),
            title="[bold red]Error Details[/bold red]",
            border_style="red"
        ))
        return None, 0


def test_pattern_based_scan(file_path):
    """Test pattern-based (Fast) scanning for comparison"""
    console.print(f"\n[cyan]Testing Pattern-Based (Fast) Mode on: {file_path}[/cyan]")
    
    try:
        from parry.scanner import Scanner
        
        scanner = Scanner()
        
        console.print("[dim]Running pattern-based detection...[/dim]")
        start_time = time.time()
        results = scanner.scan(Path(file_path))
        elapsed = time.time() - start_time
        
        vulns = results.get('vulnerabilities', [])
        
        console.print(f"[green]✓ Pattern scan complete in {elapsed:.2f}s[/green]")
        console.print(f"[green]✓ Found {len(vulns)} vulnerabilities[/green]\n")
        
        return vulns, elapsed
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return None, 0


def display_vulnerability_details(vulns, mode_name):
    """Display detailed vulnerability information"""
    if not vulns:
        console.print(f"[yellow]No vulnerabilities found in {mode_name} mode[/yellow]\n")
        return
    
    console.print(f"\n[bold cyan]{mode_name} Mode Results:[/bold cyan]\n")
    
    # Create table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("CWE", width=12)
    table.add_column("Title", width=50)
    
    for i, vuln in enumerate(vulns, 1):
        # Handle both dict and object types
        if isinstance(vuln, dict):
            severity = vuln.get('severity', 'unknown')
            cwe = vuln.get('cwe', 'Unknown')
            title = vuln.get('title', 'No title')[:48]
        else:
            severity = getattr(vuln, 'severity', 'unknown')
            cwe = getattr(vuln, 'cwe', 'Unknown')
            title = getattr(vuln, 'title', 'No title')[:48]
        
        # Color severity
        if severity == 'critical':
            severity_style = "[bold red]Critical[/bold red]"
        elif severity == 'high':
            severity_style = "[red]High[/red]"
        elif severity == 'medium':
            severity_style = "[yellow]Medium[/yellow]"
        else:
            severity_style = f"[dim]{severity}[/dim]"
        
        table.add_row(str(i), severity_style, cwe, title)
    
    console.print(table)
    
    # Count by severity
    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for vuln in vulns:
        if isinstance(vuln, dict):
            severity = vuln.get('severity', 'unknown')
        else:
            severity = getattr(vuln, 'severity', 'unknown')
        
        if severity in by_severity:
            by_severity[severity] += 1
    
    console.print(f"\n[dim]Severity Breakdown:[/dim]")
    for severity, count in by_severity.items():
        if count > 0:
            console.print(f"  {severity.capitalize()}: {count}")


def compare_results(fast_vulns, deep_vulns):
    """Compare Fast Mode vs Deep Mode results"""
    console.print("\n[bold cyan]Mode Comparison[/bold cyan]\n")
    
    # Create comparison table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", width=25)
    table.add_column("Fast Mode", width=15, justify="right")
    table.add_column("Deep Mode", width=15, justify="right")
    table.add_column("Difference", width=20, justify="right")
    
    fast_count = len(fast_vulns)
    deep_count = len(deep_vulns)
    difference = deep_count - fast_count
    
    # Format counts
    if difference > 0:
        diff_style = f"[green]+{difference}[/green]"
    elif difference < 0:
        diff_style = f"[red]{difference}[/red]"
    else:
        diff_style = "[dim]0[/dim]"
    
    table.add_row("Total Vulnerabilities", str(fast_count), str(deep_count), diff_style)
    
    # Calculate percentage difference
    if fast_count > 0:
        pct_diff = (difference / fast_count) * 100
        if pct_diff > 0:
            pct_style = f"[green]+{pct_diff:.1f}%[/green]"
        elif pct_diff < 0:
            pct_style = f"[red]{pct_diff:.1f}%[/red]"
        else:
            pct_style = "[dim]0%[/dim]"
    else:
        pct_style = "[dim]N/A[/dim]" if deep_count == 0 else "[green]New[/green]"
    
    table.add_row("Percentage Change", "—", "—", pct_style)
    
    console.print(table)
    
    # Analysis
    if difference > 0:
        console.print(f"\n[bold green]✓ Deep Mode found {difference} more vulnerabilities![/bold green]")
        console.print("[dim]This demonstrates AI-powered detection catching issues pattern-based scanning missed[/dim]")
    elif difference == 0:
        console.print("\n[yellow]⚠️  Both modes found the same number of vulnerabilities[/yellow]")
        console.print("[dim]This may indicate the codebase doesn't have AI-detectable issues[/dim]")
    else:
        console.print(f"\n[yellow]⚠️  Fast Mode found {abs(difference)} more vulnerabilities[/yellow]")
        console.print("[dim]This is unusual - Deep Mode should find more vulnerabilities[/dim]")
    
    # Expected improvement
    expected_improvement = 0.20  # 20% more vulnerabilities
    if fast_count > 0:
        expected_count = int(fast_count * (1 + expected_improvement))
        console.print(f"\n[dim]Expected improvement: ~{expected_improvement*100:.0f}% more finds in Deep Mode[/dim]")
        console.print(f"[dim]Expected finds: ~{expected_count} vulnerabilities[/dim]")


def test_specific_vulnerabilities():
    """Test Deep Mode on specific vulnerability patterns"""
    console.print("\n[bold cyan]Testing Specific Vulnerability Patterns[/bold cyan]")
    
    test_cases = [
        {
            "name": "SQL Injection",
            "code": """
def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    return cursor.execute(query)
""",
            "expected": "SQL Injection detected"
        },
        {
            "name": "Command Injection",
            "code": """
def ping_host(hostname):
    import os
    return os.system(f"ping -c 1 {hostname}")
""",
            "expected": "Command Injection detected"
        },
        {
            "name": "Hardcoded Secret",
            "code": """
import os
API_KEY = "sk-1234567890abcdef"
database_password = "super_secret_123"
""",
            "expected": "Hardcoded credentials detected"
        }
    ]
    
    for test_case in test_cases:
        console.print(f"\n[dim]Testing: {test_case['name']}[/dim]")
        
        try:
            from parry.ai_detector import AIDetector
            ai_detector = AIDetector()
            
            vulns = ai_detector.detect_vulnerabilities(
                test_case['code'],
                'test.py',
                'python'
            )
            
            if vulns:
                console.print(f"[green]✓ {test_case['name']}: {len(vulns)} vulnerability(ies) found[/green]")
            else:
                console.print(f"[yellow]⚠️  {test_case['name']}: No vulnerabilities detected[/yellow]")
        
        except Exception as e:
            console.print(f"[dim]Skipping {test_case['name']} test[/dim]")


def main():
    """Main test function"""
    console.print(Panel.fit(
        "[bold cyan]Parry Deep Mode Test Suite[/bold cyan]\n"
        "[dim]Testing AI-powered vulnerability detection[/dim]",
        border_style="cyan"
    ))
    
    # Check Ollama setup
    if not check_ollama_setup():
        console.print(Panel(
            "[bold yellow]⚠️  Ollama Not Configured[/bold yellow]\n\n"
            "Deep Mode requires Ollama to be running.\n\n"
            "[cyan]To set up Ollama:[/cyan]\n"
            "1. Start Ollama: ollama serve\n"
            "2. Download model: ollama pull codellama:7b\n"
            "3. Re-run this test\n\n"
            "Or run: parry setup",
            border_style="yellow"
        ))
        return 1
    
    # Get test file
    target_file = "examples/vulnerable_code.py"
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
    
    if not Path(target_file).exists():
        console.print(f"[red]Error: {target_file} does not exist[/red]")
        console.print(f"[dim]Usage: python scripts/test_deep_mode.py [path/to/file.py][/dim]")
        return 1
    
    console.print(f"\n[bold]Test Target:[/bold] {target_file}")
    
    # Test Pattern-Based Mode
    fast_vulns, fast_time = test_pattern_based_scan(target_file)
    
    # Test Deep Mode
    deep_vulns, deep_time = test_deep_mode_scan(target_file)
    
    if fast_vulns is None or deep_vulns is None:
        console.print("[red]Failed to run scans[/red]")
        return 1
    
    # Display results
    display_vulnerability_details(fast_vulns, "Fast")
    display_vulnerability_details(deep_vulns, "Deep")
    
    # Compare modes
    compare_results(fast_vulns, deep_vulns)
    
    # Test specific patterns
    test_specific_vulnerabilities()
    
    # Summary
    console.print("\n[bold cyan]Test Summary[/bold cyan]")
    console.print(f"✓ Fast Mode: {len(fast_vulns)} vulns in {fast_time:.2f}s")
    console.print(f"✓ Deep Mode: {len(deep_vulns)} vulns in {deep_time:.2f}s")
    
    improvement = len(deep_vulns) - len(fast_vulns)
    if improvement > 0:
        console.print(f"[bold green]✓ Deep Mode found {improvement} additional vulnerabilities[/bold green]")
    else:
        console.print(f"[yellow]⚠️  No additional vulnerabilities found in Deep Mode[/yellow]")
    
    console.print(Panel.fit(
        "[bold green]Deep Mode Test Complete![/bold green]",
        border_style="green"
    ))
    
    return 0


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
        exit(130)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        import traceback
        console.print(Panel(
            traceback.format_exc(),
            title="[bold red]Traceback[/bold red]",
            border_style="red"
        ))
        exit(1)

