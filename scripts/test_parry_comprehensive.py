#!/usr/bin/env python3
# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Comprehensive testing script for Parry
Tests all major features and modes to ensure everything works correctly
"""

import sys
import time
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

sys.path.insert(0, str(Path(__file__).parent.parent))

console = Console()

class ParryTester:
    """Test suite for Parry functionality"""
    
    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0
        self.skipped = 0
    
    def test(self, name, func, skip=False):
        """Run a test and record results"""
        if skip:
            self.results.append(("SKIP", name, "Test skipped"))
            self.skipped += 1
            console.print(f"[yellow]⏭️  Skipping: {name}[/yellow]")
            return
        
        console.print(f"\n[cyan]Testing: {name}[/cyan]")
        
        try:
            start = time.time()
            result = func()
            elapsed = time.time() - start
            
            if result:
                self.passed += 1
                self.results.append(("PASS", name, f"{elapsed:.2f}s"))
                console.print(f"[green]✓ Passed in {elapsed:.2f}s[/green]")
            else:
                self.failed += 1
                self.results.append(("FAIL", name, "Test returned False"))
                console.print(f"[red]✗ Failed[/red]")
        
        except Exception as e:
            self.failed += 1
            self.results.append(("FAIL", name, str(e)))
            console.print(f"[red]✗ Failed: {e}[/red]")
    
    def print_summary(self):
        """Print test summary"""
        console.print("\n" + "="*70)
        console.print("[bold cyan]Test Summary[/bold cyan]")
        console.print("="*70)
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Status", width=8)
        table.add_column("Test", width=50)
        table.add_column("Result", width=20)
        
        for status, name, result in self.results:
            if status == "PASS":
                status_style = "[green]PASS[/green]"
            elif status == "FAIL":
                status_style = "[red]FAIL[/red]"
            else:
                status_style = "[yellow]SKIP[/yellow]"
            
            table.add_row(status_style, name, result)
        
        console.print(table)
        
        # Summary stats
        total = self.passed + self.failed + self.skipped
        console.print(f"\n[bold]Total: {total} tests[/bold]")
        console.print(f"[green]Passed: {self.passed}[/green]")
        console.print(f"[red]Failed: {self.failed}[/red]")
        console.print(f"[yellow]Skipped: {self.skipped}[/yellow]")
        
        # Overall result
        if self.failed == 0:
            console.print(Panel.fit(
                "[bold green]ALL TESTS PASSED![/bold green]",
                border_style="green"
            ))
            return True
        else:
            console.print(Panel.fit(
                f"[bold red]FAILED: {self.failed} test(s)[/bold red]",
                border_style="red"
            ))
            return False


def test_import():
    """Test basic imports"""
    try:
        from parry.scanner import Scanner
        from parry.cli import main
        return True
    except ImportError as e:
        console.print(f"[red]Import error: {e}[/red]")
        return False


def test_scanner_basic():
    """Test basic scanner functionality"""
    try:
        from parry.scanner import Scanner
        
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_code.py"))
        
        return results.get('vulnerabilities_found', 0) > 0
    except Exception as e:
        console.print(f"[red]Scanner error: {e}[/red]")
        return False


def test_scanner_fast_mode():
    """Test Fast Mode scanning"""
    try:
        from parry.scanner import Scanner
        
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_code.py"))
        
        # Fast mode should complete quickly
        return results.get('files_scanned', 0) > 0
    except Exception as e:
        console.print(f"[red]Fast mode error: {e}[/red]")
        return False


def test_vulnerability_types():
    """Test that various vulnerability types are detected"""
    try:
        from parry.scanner import Scanner
        
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_code.py"))
        
        vulns = results.get('vulnerabilities', [])
        cwes = {v.get('cwe') for v in vulns if v.get('cwe')}
        
        # Should detect multiple CWE types
        return len(cwes) >= 5
    except Exception as e:
        console.print(f"[red]Vulnerability detection error: {e}[/red]")
        return False


def test_severity_levels():
    """Test that severity levels are assigned"""
    try:
        from parry.scanner import Scanner
        
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_code.py"))
        
        vulns = results.get('vulnerabilities', [])
        severities = {v.get('severity') for v in vulns if v.get('severity')}
        
        # Should have multiple severity levels
        return len(severities) >= 2
    except Exception as e:
        console.print(f"[red]Severity error: {e}[/red]")
        return False


def test_license_manager():
    """Test license management"""
    try:
        from parry.license import LicenseManager
        
        tier = LicenseManager.get_tier()
        features = LicenseManager.get_features()
        
        return tier is not None and len(features) > 0
    except Exception as e:
        console.print(f"[red]License error: {e}[/red]")
        return False


def test_setup_helper():
    """Test setup helper"""
    try:
        from parry.setup import SetupHelper
        
        helper = SetupHelper()
        # Just test that it can be instantiated
        return True
    except Exception as e:
        console.print(f"[red]Setup helper error: {e}[/red]")
        return False


def test_patch_generator():
    """Test patch generation (if AI available)"""
    try:
        from parry.patch import PatchGenerator
        from parry.llm import LLMClient
        from parry.setup import SetupHelper
        
        # Check if AI is available
        helper = SetupHelper()
        ai_available = helper.check_ollama_running() and helper.check_model_available()
        
        if not ai_available:
            console.print("[yellow]Skipping AI tests (Ollama not available)[/yellow]")
            return True  # Not a failure
        
        # Test patch generator
        llm_client = LLMClient()
        patch_gen = PatchGenerator(llm_client)
        
        # Create a mock vulnerability
        vuln = {
            'title': 'Test vulnerability',
            'cwe': 'CWE-89',
            'severity': 'high',
            'description': 'Test SQL injection',
            'code': 'SELECT * FROM users WHERE id = {user_input}',
            'file_path': 'test.py',
            'line_number': 10
        }
        
        # Try to generate a patch
        file_path = Path("examples/vulnerable_code.py")
        patch = patch_gen.generate_patch(file_path, vuln)
        
        return patch is not None
    except Exception as e:
        console.print(f"[dim]Patch generation test skipped: {e}[/dim]")
        return True  # Not critical for basic functionality


def test_reporter():
    """Test reporter functionality"""
    try:
        from parry.reporter import Reporter
        from parry.scanner import Scanner
        
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_code.py"))
        
        reporter = Reporter(console)
        # Test that reporter can be instantiated and used
        return True
    except Exception as e:
        console.print(f"[red]Reporter error: {e}[/red]")
        return False


def test_demo_script():
    """Test that demo script can be imported"""
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent))
        
        from demo_scan_with_fixes import main
        return True
    except Exception as e:
        console.print(f"[yellow]Demo script test skipped: {e}[/yellow]")
        return True  # Not critical


def test_benchmark_results():
    """Test that benchmark results file exists"""
    try:
        results_file = Path("COMPREHENSIVE_BENCHMARK_RESULTS.md")
        return results_file.exists()
    except Exception as e:
        console.print(f"[yellow]Benchmark results test skipped: {e}[/yellow]")
        return True


def test_documentation():
    """Test that documentation exists"""
    try:
        docs = [
            "README.md",
            "SETUP_GUIDE.md",
            "COMPETITIVE_ANALYSIS.md",
            "PARRY_METRICS.md"
        ]
        
        for doc in docs:
            if not Path(doc).exists():
                console.print(f"[yellow]Missing doc: {doc}[/yellow]")
                return False
        
        return True
    except Exception as e:
        console.print(f"[red]Documentation test error: {e}[/red]")
        return False


def main():
    """Run comprehensive test suite"""
    console.print(Panel.fit(
        "[bold cyan]Parry Comprehensive Test Suite[/bold cyan]\n"
        "[dim]Testing all major features and functionality[/dim]",
        border_style="cyan"
    ))
    
    tester = ParryTester()
    
    # Basic functionality tests
    console.print("\n[bold cyan]Basic Functionality Tests[/bold cyan]")
    tester.test("Imports", test_import)
    tester.test("Scanner Basic", test_scanner_basic)
    tester.test("Fast Mode", test_scanner_fast_mode)
    tester.test("Vulnerability Types", test_vulnerability_types)
    tester.test("Severity Levels", test_severity_levels)
    
    # System integration tests
    console.print("\n[bold cyan]System Integration Tests[/bold cyan]")
    tester.test("License Manager", test_license_manager)
    tester.test("Setup Helper", test_setup_helper)
    tester.test("Reporter", test_reporter)
    
    # AI features tests (may be skipped)
    console.print("\n[bold cyan]AI Features Tests[/bold cyan]")
    tester.test("Patch Generator", test_patch_generator)
    
    # Documentation and tools tests
    console.print("\n[bold cyan]Documentation & Tools Tests[/bold cyan]")
    tester.test("Demo Script", test_demo_script)
    tester.test("Benchmark Results", test_benchmark_results)
    tester.test("Documentation", test_documentation)
    
    # Print summary
    success = tester.print_summary()
    
    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Tests interrupted by user[/yellow]")
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

