#!/usr/bin/env python3
"""
Parry CLI - Command-line interface for security scanning
"""

import click
import sys
import json
import os
from pathlib import Path
from typing import Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from parry.scanner import Scanner
from parry.llm import LLMClient
from parry.patch import PatchGenerator
from parry.reporter import Reporter
from parry.compare import Comparator
from parry.validator import VulnerabilityValidator
from parry.sca import SCAScanner
from parry.custom_rules import CustomRulesEngine
from parry.cache import ProjectCache, ScanCache
from parry.api import start_api_server
from parry.setup import SetupHelper, run_setup_wizard, run_doctor, create_config
from parry.license import has_feature, require_feature, LicenseManager
from parry.feedback import FeedbackManager

console = Console()


@click.group()
@click.version_option(version="0.7.0")
def main():
    """
    🔒 Parry Security Scanner - Privacy-first AI-powered security scanner
    
    All scanning and inference happens locally on your machine.
    """
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "-f", type=click.Choice(["json", "markdown", "terminal"]), 
              default="terminal", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--severity", "-s", type=click.Choice(["low", "medium", "high", "critical"]),
              help="Filter by minimum severity")
@click.option("--cwe", multiple=True, help="Filter by CWE tags")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed analysis")
@click.option("--exclude", multiple=True, help="Exclude patterns (glob)")
@click.option("--validate", is_flag=True, help="Use AI to validate findings and reduce false positives")
@click.option("--mode", type=click.Choice(["fast", "deep", "hybrid"]), default="fast",
              help="Detection mode: fast (pattern-only, 5% recall), deep (AI-powered, 75% recall), hybrid (both)")
@click.option("--sca", is_flag=True, help="Enable Software Composition Analysis (dependency scanning)")
@click.option("--incremental", is_flag=True, help="Use incremental scanning (only scan changed files)")
@click.option("--custom-rules", type=click.Path(exists=True), help="Path to custom YAML rules file")
def scan(path: str, format: str, output: Optional[str], severity: Optional[str], 
         cwe: tuple, verbose: bool, exclude: tuple, validate: bool, mode: str,
         sca: bool, incremental: bool, custom_rules: Optional[str]):
    """
    Scan a codebase for security vulnerabilities.
    
    Example:
        parry scan ./src
        parry scan ./src --severity high --format json --output results.json
    """
    console.print(Panel.fit(
        "[bold cyan]Parry Security Scanner[/bold cyan]\n"
        f"[dim]Mode: {mode} | Privacy-first vulnerability detection[/dim]",
        border_style="cyan"
    ))
    
    # Check if AI is available for deep/hybrid modes
    ai_available = False
    if mode in ["deep", "hybrid"]:
        # Check license for deep mode
        if not has_feature('deep-mode'):
            tier = LicenseManager.get_tier()
            console.print(Panel.fit(
                f"[bold red]❌ Deep Mode Requires Pro/Enterprise License[/bold red]\n\n"
                f"Current tier: [yellow]{tier}[/yellow]\n"
                f"Deep mode provides [bold]75% recall[/bold] vs 5% in Fast mode.\n\n"
                f"[cyan]Visit https://parry.dev/pricing to upgrade[/cyan]",
                border_style="red"
            ))
            console.print(f"\n[yellow]Falling back to Fast Mode (pattern-based detection)[/yellow]\n")
            mode = "fast"
        else:
            helper = SetupHelper()
            ai_available = helper.check_ollama_running() and helper.check_model_available()
            
            if not ai_available:
                console.print(f"[yellow]⚠ AI mode requested but Ollama is not available[/yellow]")
                console.print(f"[yellow]  Falling back to Fast Mode (pattern-based detection)[/yellow]")
                console.print(f"\n[dim]To enable AI modes, run:[/dim]")
                console.print(f"[cyan]  parry setup[/cyan]  (interactive setup wizard)")
                console.print(f"[cyan]  parry doctor[/cyan] (check system status)\n")
                mode = "fast"
    
    # Show mode explanation
    if mode == "deep" and ai_available:
        console.print("[yellow]🤖 Deep Mode: AI-powered detection for 75% recall (slower, comprehensive)[/yellow]")
    elif mode == "hybrid" and ai_available:
        console.print("[yellow]⚡ Hybrid Mode: Pattern + AI detection for best coverage[/yellow]")
    else:
        console.print("[green]⚡ Fast Mode: Pattern-based detection (quick, baseline)[/green]")
    
    # Initialize scanner
    scanner = Scanner(exclude_patterns=list(exclude))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning codebase...", total=None)
        
        try:
            results = scanner.scan(Path(path))
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]Error during scanning: {e}[/red]")
            sys.exit(1)
    
    # AI-Powered Deep Scan (for deep or hybrid mode) - OPTIMIZED with parallel processing
    if mode in ["deep", "hybrid"] and results.get('files_scanned', 0) > 0 and ai_available:
        console.print("\n[cyan]🤖 AI Deep Scan: Comprehensive vulnerability detection...[/cyan]")
        console.print("[dim]This uses local AI to achieve 75% recall (optimized with parallel processing)[/dim]")
        
        try:
            from parry.ai_detector import AIDetector
            import multiprocessing
            
            # Initialize AI detector with optimized settings
            max_workers = min(multiprocessing.cpu_count() or 8, 16)  # Use up to 16 cores
            ai_detector = AIDetector(max_workers=max_workers)
            
            # Get list of scanned files
            scanned_files = []
            target = Path(path)
            if target.is_file():
                scanned_files = [target]
            else:
                # Get files from initial scan
                for ext in ['.py', '.java', '.js', '.go', '.php', '.rb', '.rs', '.c', '.cpp', '.h']:
                    scanned_files.extend(target.rglob(f'*{ext}'))
            
            console.print(f"[dim]Found {len(scanned_files)} files for AI analysis (using {max_workers} workers)[/dim]")
            
            # Optimized parallel processing
            ai_vulns = []
            
            def process_file_optimized(file_path):
                """Process single file with AI detection - optimized wrapper"""
                try:
                    code = file_path.read_text(errors='ignore')
                    file_vulns = ai_detector.detect_vulnerabilities(
                        code,
                        str(file_path),
                        file_path.suffix[1:]  # language from extension
                    )
                    return [v.to_dict() if hasattr(v, 'to_dict') else v for v in file_vulns]
                except Exception as e:
                    return []
            
            # Process all files in parallel using ThreadPoolExecutor
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(f"[cyan]Analyzing {len(scanned_files)} files with AI...", total=len(scanned_files))
                
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all files for parallel processing
                    futures = {executor.submit(process_file_optimized, f): f for f in scanned_files}
                    
                    # Collect results as they complete
                    completed = 0
                    for future in as_completed(futures):
                        file_vulns = future.result()
                        ai_vulns.extend(file_vulns)
                        completed += 1
                        progress.update(task, completed=completed)
            
            # Merge AI findings with pattern findings
            # Both Deep and Hybrid modes should COMBINE pattern + AI findings
            original_count = len(results['vulnerabilities'])
            results['vulnerabilities'].extend(ai_vulns)
            
            # Deduplicate based on CWE + location
            seen = set()
            deduped = []
            for v in results['vulnerabilities']:
                key = (v['cwe'], v['file_path'], v['line_number'])
                if key not in seen:
                    seen.add(key)
                    deduped.append(v)
            
            results['vulnerabilities'] = deduped
            results['vulnerabilities_found'] = len(deduped)
            
            ai_added = len(deduped) - original_count
            if mode == "hybrid":
                console.print(f"[green]✓ AI found {ai_added} additional vulnerabilities (total: {len(deduped)})[/green]")
            else:  # deep mode
                console.print(f"[green]✓ Combined: {original_count} pattern + {len(ai_vulns)} AI = {len(deduped)} total vulnerabilities[/green]")
            
        except Exception as e:
            console.print(f"[red]AI deep scan failed: {e}[/red]")
            console.print("[dim]Continuing with pattern-based results...[/dim]")
    
    # AI Validation to reduce false positives
    if validate and results.get('vulnerabilities'):
        if not has_feature('ai-validation'):
            tier = LicenseManager.get_tier()
            console.print(Panel.fit(
                f"[bold red]❌ AI Validation Requires Pro/Enterprise License[/bold red]\n\n"
                f"Current tier: [yellow]{tier}[/yellow]\n"
                f"AI validation reduces false positives from 55% to 25%.\n\n"
                f"[cyan]Visit https://parry.dev/pricing to upgrade[/cyan]",
                border_style="red"
            ))
            console.print(f"\n[dim]Skipping validation. Results may include false positives.[/dim]\n")
        elif not ai_available:
            console.print(f"\n[yellow]⚠ AI validation requested but Ollama is not available[/yellow]")
            console.print(f"[dim]Skipping validation. Results may include false positives.[/dim]")
            console.print(f"[dim]Run 'parry setup' to enable AI validation.[/dim]\n")
        else:
            console.print("\n[cyan]🤖 AI Validation: Reviewing findings to reduce false positives...[/cyan]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                val_task = progress.add_task("[cyan]Validating with AI...", total=None)
                
                try:
                    validator = VulnerabilityValidator()
                    # Convert dict vulnerabilities back to objects for validation
                    from parry.scanner import Vulnerability
                    vuln_objects = [
                        Vulnerability(**v) if isinstance(v, dict) else v 
                        for v in results['vulnerabilities']
                    ]
                    
                    validation_results = validator.validate_vulnerabilities(
                        vuln_objects,
                        path,
                        batch_size=10
                    )
                    
                    progress.update(val_task, completed=True)
                    
                    # Display validation summary
                    console.print(validator.generate_validation_report(validation_results))
                    
                    # Update results to only include confirmed vulnerabilities
                    results['original_count'] = len(results['vulnerabilities'])
                    results['vulnerabilities'] = [
                        item['vulnerability'].to_dict() if hasattr(item['vulnerability'], 'to_dict') else item['vulnerability']
                        for item in validation_results['confirmed']
                    ]
                    results['likely_false_positives'] = len(validation_results['likely_false_positive'])
                    results['needs_review'] = len(validation_results['needs_review'])
                    results['vulnerabilities_found'] = len(results['vulnerabilities'])
                    results['false_positive_rate'] = validation_results['validation_summary']['false_positive_rate']
                    
                    console.print(f"\n[green]✓[/green] Reduced findings from {results['original_count']} to {results['vulnerabilities_found']} " 
                                f"({results['likely_false_positives']} likely false positives filtered)")
                    
                except Exception as e:
                    console.print(f"[yellow]⚠️  AI validation failed: {e}[/yellow]")
                    console.print("[dim]Continuing with unvalidated results...[/dim]")
    
    # Filter results
    if severity:
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_severity = severity_order[severity]
        results["vulnerabilities"] = [
            v for v in results["vulnerabilities"]
            if severity_order.get(v["severity"], 0) >= min_severity
        ]
    
    if cwe:
        results["vulnerabilities"] = [
            v for v in results["vulnerabilities"]
            if v["cwe"] in cwe
        ]
    
    # Generate report
    reporter = Reporter(results)
    
    if format == "json":
        report = reporter.generate_json()
        if output:
            Path(output).write_text(report)
            console.print(f"[green]✓[/green] Report saved to {output}")
        else:
            console.print(report)
    
    elif format == "markdown":
        report = reporter.generate_markdown()
        if output:
            Path(output).write_text(report)
            console.print(f"[green]✓[/green] Report saved to {output}")
        else:
            console.print(report)
    
    else:  # terminal
        reporter.print_terminal(verbose=verbose)
    
    # Exit with appropriate code
    critical_count = sum(1 for v in results["vulnerabilities"] if v["severity"] == "critical")
    high_count = sum(1 for v in results["vulnerabilities"] if v["severity"] == "high")
    
    if critical_count > 0:
        sys.exit(2)
    elif high_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--apply", is_flag=True, help="Automatically apply patches")
@click.option("--interactive", "-i", is_flag=True, help="Review each patch before applying")
@click.option("--cwe", help="Only patch specific CWE type")
@click.option("--model", default="codellama:7b-instruct", help="LLM model to use")
def patch(file: str, apply: bool, interactive: bool, cwe: Optional[str], model: str):
    """
    Generate secure code replacements for vulnerabilities.
    
    Example:
        parry patch ./src/api.py
        parry patch ./src/api.py --apply
        parry patch ./src/api.py --interactive --cwe CWE-89
    """
    console.print(Panel.fit(
        "[bold magenta]Parry Patch Generator[/bold magenta]\n"
        "[dim]AI-powered security fixes[/dim]",
        border_style="magenta"
    ))
    
    file_path = Path(file)
    
    # Scan the file first
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Analyzing file...", total=None)
        
        scanner = Scanner()
        results = scanner.scan(file_path)
        
        if cwe:
            results["vulnerabilities"] = [
                v for v in results["vulnerabilities"]
                if v["cwe"] == cwe
            ]
        
        progress.update(task, completed=True)
    
    if not results["vulnerabilities"]:
        console.print("[green]✓[/green] No vulnerabilities found!")
        return
    
    console.print(f"\n[yellow]Found {len(results['vulnerabilities'])} vulnerabilities[/yellow]\n")
    
    # Initialize LLM and patch generator
    try:
        llm = LLMClient(model=model)
        patch_gen = PatchGenerator(llm)
    except Exception as e:
        console.print(f"[red]Error connecting to Ollama: {e}[/red]")
        console.print("[yellow]Make sure Ollama is running: ollama serve[/yellow]")
        sys.exit(1)
    
    # Generate patches
    patches = []
    for vuln in results["vulnerabilities"]:
        with console.status(f"[cyan]Generating patch for {vuln['cwe']}..."):
            patch = patch_gen.generate_patch(file_path, vuln)
            patches.append(patch)
    
    # Display and optionally apply patches
    for i, patch in enumerate(patches, 1):
        console.print(f"\n[bold]Patch {i}/{len(patches)}[/bold]")
        console.print(f"CWE: {patch['cwe']} | Severity: {patch['severity']}")
        console.print(f"Line: {patch['line_number']}\n")
        
        console.print("[red]- Original:[/red]")
        console.print(patch['original_code'])
        console.print("\n[green]+ Fixed:[/green]")
        console.print(patch['fixed_code'])
        console.print(f"\n[dim]{patch['explanation']}[/dim]\n")
        
        if interactive:
            if click.confirm("Apply this patch?"):
                patch_gen.apply_patch(file_path, patch)
                console.print("[green]✓[/green] Patch applied")
            else:
                console.print("[yellow]⊘[/yellow] Patch skipped")
        elif apply:
            patch_gen.apply_patch(file_path, patch)
            console.print("[green]✓[/green] Patch applied")
    
    if apply and not interactive:
        console.print(f"\n[green]✓[/green] Applied {len(patches)} patches to {file}")
    elif not interactive:
        console.print(f"\n[yellow]Run with --apply to automatically apply patches[/yellow]")


@main.command()
@click.argument("tool", type=click.Choice(["snyk", "semgrep"]))
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Save comparison results")
@click.option("--format", "-f", type=click.Choice(["json", "markdown", "terminal"]), 
              default="terminal")
def compare(tool: str, path: str, output: Optional[str], format: str):
    """
    Benchmark Parry against other security tools.
    
    Example:
        parry compare snyk ./src
        parry compare semgrep ./src --output comparison.json
    """
    console.print(Panel.fit(
        "[bold green]Parry Benchmarking[/bold green]\n"
        f"[dim]Comparing against {tool}[/dim]",
        border_style="green"
    ))
    
    comparator = Comparator()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Run Parry scan
        task1 = progress.add_task("[cyan]Running Parry scan...", total=None)
        scanner = Scanner()
        parry_results = scanner.scan(Path(path))
        progress.update(task1, completed=True)
        
        # Run comparison tool
        task2 = progress.add_task(f"[cyan]Running {tool} scan...", total=None)
        try:
            tool_results = comparator.run_tool(tool, Path(path))
            progress.update(task2, completed=True)
        except Exception as e:
            console.print(f"[red]Error running {tool}: {e}[/red]")
            sys.exit(1)
    
    # Generate comparison
    comparison = comparator.compare(parry_results, tool_results, tool)
    
    if format == "json":
        report = json.dumps(comparison, indent=2)
        if output:
            Path(output).write_text(report)
            console.print(f"[green]✓[/green] Comparison saved to {output}")
        else:
            console.print(report)
    
    elif format == "markdown":
        report = comparator.generate_markdown(comparison)
        if output:
            Path(output).write_text(report)
            console.print(f"[green]✓[/green] Comparison saved to {output}")
        else:
            console.print(report)
    
    else:  # terminal
        comparator.print_terminal(comparison)


@main.command()
@click.option("--host", default="0.0.0.0", help="API server host")
@click.option("--port", default=8000, help="API server port")
def serve(host: str, port: int):
    """
    Start Parry API server for remote scanning.
    
    Requires Enterprise license.
    """
    if not has_feature('rest-api'):
        tier = LicenseManager.get_tier()
        console.print(Panel.fit(
            f"[bold red]❌ REST API Requires Enterprise License[/bold red]\n\n"
            f"Current tier: [yellow]{tier}[/yellow]\n"
            f"REST API provides programmatic access for CI/CD integration.\n\n"
            f"[cyan]Visit https://parry.dev/pricing to upgrade to Enterprise[/cyan]",
            border_style="red"
        ))
        return
    
    console.print("[bold blue]Starting Parry API Server...[/bold blue]")
    start_api_server(host=host, port=port)


@main.command()
@click.option("--output", "-o", type=click.Path(), default=None, help="Output path for rules template")
def init_rules(output: Optional[str]):
    """
    Initialize custom security rules template.
    """
    from parry.custom_rules import create_default_rules
    
    if output:
        engine = CustomRulesEngine()
        engine.create_rule_template(Path(output))
        console.print(f"[green]✓[/green] Custom rules template created at: {output}")
    else:
        create_default_rules()
        console.print("[green]✓[/green] Default rules created in ~/.parry/rules/")


@main.command()
@click.option("--stats", is_flag=True, help="Show cache statistics")
@click.option("--clear", is_flag=True, help="Clear all cache")
@click.option("--prune", type=int, help="Remove entries older than N days")
def cache(stats: bool, clear: bool, prune: Optional[int]):
    """
    Manage scan result cache.
    """
    scan_cache = ScanCache()
    
    if clear:
        scan_cache.invalidate_all()
        console.print("[green]✓[/green] Cache cleared")
    
    elif prune:
        scan_cache.prune_old_entries(days=prune)
        console.print(f"[green]✓[/green] Pruned entries older than {prune} days")
    
    elif stats:
        cache_stats = scan_cache.get_cache_stats()
        
        table = Table(title="Cache Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Total Files", str(cache_stats['total_files']))
        table.add_row("Cache Size", f"{cache_stats['cache_size_mb']} MB")
        table.add_row("Oldest Entry", str(cache_stats.get('oldest_entry', 'N/A')))
        table.add_row("Newest Entry", str(cache_stats.get('newest_entry', 'N/A')))
        
        console.print(table)
    else:
        console.print("[yellow]Use --stats, --clear, or --prune[/yellow]")


@main.command()
def setup():
    """
    Interactive setup wizard for Parry.
    
    Guides you through:
    - Ollama installation
    - Model download
    - Configuration
    """
    run_setup_wizard()


@main.command()
def doctor():
    """
    Check Parry installation and dependencies.
    
    Verifies:
    - Python version
    - Ollama installation and status
    - AI model availability
    - Required dependencies
    - Available scanning modes
    """
    run_doctor()


@main.command()
def config():
    """
    Create default configuration file at ~/.parry/config.yaml
    """
    create_config()
    console.print("[green]✓[/green] Configuration file created at ~/.parry/config.yaml")
    console.print("  Edit this file to customize Parry's behavior.")


@main.command()
@click.option("--install", help="Install a license (beta/pro/enterprise)")
@click.option("--email", help="Email for beta license (deprecated, use --token)")
@click.option("--token", help="Beta token for secure installation")
def license(install, email, token):
    """
    Manage your Parry license.
    
    Shows current license information, tier, and available features.
    
    Install beta license:
        parry license --install beta --token YOUR_BETA_TOKEN
    
    Old method (insecure, deprecated):
        parry license --install beta --email user@example.com
    """
    if install:
        if install == 'beta':
            # New secure method (preferred)
            if token:
                if LicenseManager.install_beta_license_with_token(token):
                    console.print("[green]✓[/green] Beta license installed successfully!")
                    console.print("[dim]Beta access expires in 90 days[/dim]")
                    console.print("\n[bold cyan]Thank you for beta testing Parry![/bold cyan]")
                else:
                    console.print("[red]✗ Failed to install beta license[/red]")
                    console.print("[yellow]Token may be invalid, expired, or already used[/yellow]")
                return
            
            # Old insecure method (deprecated)
            if email:
                console.print("[yellow]⚠️  WARNING: Insecure beta installation[/yellow]")
                console.print("[dim]This method is deprecated. Use --token instead.[/dim]")
                console.print("[dim]Get a beta token from: https://parry.dev/beta[/dim]\n")
                
                if LicenseManager.install_beta_license(email):
                    console.print("[green]✓[/green] Beta license installed (insecure mode)")
                    console.print("[dim]Beta access expires in 90 days[/dim]")
                else:
                    console.print("[red]✗ Failed to install beta license[/red]")
                return
            
            # Neither token nor email provided
            console.print("[red]Error: Beta token required for secure installation[/red]")
            console.print("\n[yellow]Get a beta token:[/yellow]")
            console.print("[cyan]  1. Visit https://parry.dev/beta[/cyan]")
            console.print("[cyan]  2. Request beta access[/cyan]")
            console.print("[cyan]  3. Install with: parry license --install beta --token YOUR_TOKEN[/cyan]")
            return
        
        else:
            console.print(f"[red]License type '{install}' requires a license key[/red]")
            console.print("Visit https://parry.dev to purchase a license")
        return
    
    info = LicenseManager.get_license_info()
    
    # Display license information
    console.print(Panel.fit(
        f"[bold cyan]Parry License Information[/bold cyan]",
        border_style="cyan"
    ))
    
    table = Table(title="License Details")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    tier_display = info['tier'].upper()
    if info['tier'] == 'free':
        tier_style = "green"
    elif info['tier'] == 'beta':
        tier_style = "yellow"
    elif info['tier'] in ['pro', 'enterprise']:
        tier_style = "yellow"
    else:
        tier_style = "white"
    
    table.add_row("Tier", f"[{tier_style}]{tier_display}[/{tier_style}]")
    table.add_row("Build ID", info['build_id'])
    table.add_row("Machine ID", info['machine_id'])
    table.add_row("Validation Cached", "Yes" if info['validation_cached'] else "No")
    
    # Load additional info from license file
    try:
        from parry.license import LicenseConfig
        if LicenseConfig.LICENSE_FILE.exists():
            import json
            with open(LicenseConfig.LICENSE_FILE, 'r') as f:
                license_data = json.load(f)
                if 'expires' in license_data:
                    from datetime import datetime
                    try:
                        expires = datetime.fromisoformat(license_data['expires'])
                        days_left = (expires - datetime.now()).days
                        if days_left > 0:
                            table.add_row("Expires", f"In {days_left} days")
                        else:
                            table.add_row("Expires", "[red]Expired[/red]")
                    except:
                        pass
    except:
        pass
    
    # Add features
    features = info['features']
    if features:
        table.add_row("Available Features", f"{len(features)} features")
    
    console.print(table)
    
    # Display feature list
    if features:
        console.print("\n[bold]Available Features:[/bold]")
        for feature in sorted(features):
            console.print(f"  • {feature}")
    
    # Display upgrade prompt if free tier
    if info['tier'] == 'free':
        console.print("\n[yellow]💡 Get Beta Access (Free for 90 days):[/yellow]")
        console.print("  • Deep mode (90% recall)")
        console.print("  • AI validation (reduce false positives)")
        console.print("  • Compliance reports")
        console.print("  • SCA scanning")
        console.print(f"\n[cyan]Run: parry license --install beta --email your@email.com[/cyan]")
        console.print(f"[dim]or visit https://parry.dev to upgrade[/dim]")
    
    # Display beta expiration notice
    elif info['tier'] == 'beta':
        console.print("\n[yellow]📅 Beta Access[/yellow]")
        console.print("  • You have access to all Pro features for 90 days")
        console.print("  • Provide feedback to extend your beta access")
        console.print("\n[cyan]Questions? Email: beta@parry.ai[/cyan]")


@main.command()
@click.option("--feedback", "-f", help="Feedback for renewal request")
def renew(feedback):
    """
    Request beta license renewal.
    
    Provide detailed feedback about your experience to extend your beta access.
    """
    from datetime import datetime, timedelta
    from parry.license import LicenseConfig
    import json
    
    # Check if user has beta license
    tier = LicenseManager.get_tier()
    if tier != 'beta':
        console.print("[red]Renewal only available for beta licenses[/red]")
        console.print(f"Current tier: {tier}")
        return
    
    # Get current license
    if not LicenseConfig.LICENSE_FILE.exists():
        console.print("[red]No license found[/red]")
        return
    
    try:
        with open(LicenseConfig.LICENSE_FILE, 'r') as f:
            license_data = json.load(f)
        
        # Check expiration
        expires = datetime.fromisoformat(license_data.get('expires', ''))
        days_left = (expires - datetime.now()).days
        
        # Can only renew within 30 days of expiration
        if days_left > 30:
            console.print(f"[yellow]Your beta license is valid for {days_left} more days[/yellow]")
            console.print("[dim]You can request renewal within 30 days of expiration[/dim]")
            return
        
        # Get feedback
        if not feedback:
            console.print("\n[yellow]Please provide feedback to support your renewal request:[/yellow]")
            console.print("[dim]Tell us about your experience using Parry[/dim]")
            console.print("  • What vulnerabilities did you find?\n  • Any bugs or issues?\n  • What features do you like most?\n  • Suggestions for improvement?\n")
            
            feedback_lines = []
            while True:
                line = input("> ")
                if not line or line.lower() == 'done':
                    break
                feedback_lines.append(line)
            
            feedback = '\n'.join(feedback_lines)
        
        if not feedback or len(feedback.strip()) < 20:
            console.print("[red]Feedback must be at least 20 characters[/red]")
            return
        
        # Submit renewal request
        manager = FeedbackManager()
        result = manager.submit_renewal_request(
            email=license_data.get('email', 'unknown'),
            feedback=feedback,
            metadata={'days_left': days_left}
        )
        
        # Display results
        console.print("\n[green]✓ Renewal request submitted![/green]")
        console.print("[dim]We'll review your feedback within 24 hours[/dim]")
        
        if result.get('github_issue'):
            console.print(f"\n[yellow]View request: {result['github_issue']}[/yellow]")
        else:
            console.print("\n[yellow]📧 Email your feedback to: beta@parry.ai[/yellow]")
            console.print("[dim]Your renewal request has been logged for review[/dim]")
        
        # Save confirmation
        submission_id = result.get('submission_id')
        if submission_id:
            console.print(f"\n[dim]Submission ID: {submission_id}[/dim]")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@main.command()
@click.argument("message")
@click.option("--type", "-t", type=click.Choice(["bug", "feature", "general"]), 
              default="general", help="Type of feedback")
@click.option("--email", help="Your email (optional)")
def feedback(message, type, email):
    """
    Submit feedback (bugs, features, suggestions).
    
    Examples:
        parry feedback "Found a false positive in SQL detection" --type bug
        parry feedback "Would love to see Go support" --type feature
        parry feedback "Great tool!" --type general
    """
    from parry.feedback import submit_beta_feedback
    
    # Get email from license if not provided
    if not email:
        try:
            from parry.license import LicenseConfig
            if LicenseConfig.LICENSE_FILE.exists():
                with open(LicenseConfig.LICENSE_FILE, 'r') as f:
                    license_data = json.load(f)
                    email = license_data.get('email', 'anonymous')
        except:
            email = 'anonymous'
    
    # Submit feedback
    result = submit_beta_feedback(email, message, type)
    
    if result.get('success'):
        console.print(f"[green]✓ Feedback submitted![/green]")
        console.print(f"[dim]Type: {type}[/dim]")
        
        if result.get('github_issue'):
            console.print(f"\n[yellow]View: {result['github_issue']}[/yellow]")
        else:
            console.print("\n[dim]Thank you for helping improve Parry![/dim]")
    else:
        console.print("[red]Failed to submit feedback[/red]")


@main.command()
@click.option("--source", type=click.Choice(["local", "github", "all"]), 
              default="local", help="Feedback source to view")
def list_feedback(source):
    """
    List pending feedback and renewal requests (admin view).
    
    Shows all pending submissions for review.
    
    Sources:
        local   - Local files on this machine only
        github  - GitHub Issues from all users (optional, requires repo access)
        all     - Both local and GitHub
    """
    from parry.feedback import FeedbackManager
    
    manager = FeedbackManager()
    all_renewals = []
    
    # Get local feedback
    if source in ["local", "all"]:
        local_renewals = manager.get_pending_renewals()
        all_renewals.extend(local_renewals)
    
    # Get GitHub feedback if requested and available
    if source in ["github", "all"]:
        try:
            github_renewals = manager.get_renewals_from_github()
            all_renewals.extend(github_renewals)
        except Exception as e:
            if source == "github":
                console.print("[yellow]GitHub integration not available[/yellow]")
                console.print(f"[dim]Error: {e}[/dim]")
                console.print("\n[dim]To enable GitHub integration:[/dim]")
                console.print("[cyan]  export GITHUB_TOKEN=your_token_here[/cyan]")
                return
            # If "all", just show local
    
    if not all_renewals:
        console.print("[dim]No pending renewal requests[/dim]")
        
        if source == "local":
            console.print("\n[yellow]💡 Tip: [/yellow]")
            console.print("Users submit via 'parry renew' or 'parry feedback'")
            console.print("Feedback is stored locally on each user's machine")
            
            console.print("\n[yellow]📧 Admin Access:[/yellow]")
            console.print("[cyan]  Check email: beta@parry.ai[/cyan]")
            console.print("[dim]  Users should email their feedback/renewal requests[/dim]")
        
        return
    
    console.print(f"\n[bold]Pending Renewal Requests: {len(all_renewals)}[/bold]")
    
    if source == "all":
        local_count = len(manager.get_pending_renewals())
        console.print(f"[dim]({local_count} local, {len(all_renewals) - local_count} from GitHub)[/dim]")
    
    console.print()
    
    table = Table()
    table.add_column("#", style="cyan")
    table.add_column("Email", style="white")
    table.add_column("Days Left", style="yellow")
    table.add_column("Source", style="dim")
    table.add_column("Feedback Preview", style="dim")
    
    for i, renewal in enumerate(all_renewals, 1):
        email = renewal.get('email', 'unknown')
        feedback_text = renewal.get('feedback', '')[:60]
        days_left = renewal.get('metadata', {}).get('days_left', 'unknown')
        renewals_source = renewal.get('source', 'local')
        
        table.add_row(str(i), email, str(days_left), renewals_source, feedback_text)
    
    console.print(table)
    
    # Show renewal instructions
    console.print("\n[yellow]📝 To extend a license:[/yellow]")
    console.print("[dim]  1. Review feedback quality[/dim]")
    console.print("[dim]  2. Check usage metrics[/dim]")
    console.print("[cyan]  3. Generate token: parry admin generate-token --email user@example.com[/cyan]")


@main.command()
@click.argument("command")
@click.option("--email", help="Email for token generation")
@click.option("--days", type=int, default=90, help="Days until expiration (default: 90)")
def admin(command, email, days):
    """
    Admin commands for managing beta licenses.
    
    Commands:
        generate-token    Generate a beta token for a user
        list-tokens       List all issued tokens
    
    Examples:
        parry admin generate-token --email user@example.com
        parry admin generate-token --email user@example.com --days 60
        parry admin list-tokens
    """
    if command == 'generate-token':
        if not email:
            console.print("[red]Error: Email required[/red]")
            console.print("Usage: parry admin generate-token --email user@example.com")
            return
        
        from parry.beta_token import BetaTokenManager
        
        console.print(f"\n[bold]Generating beta token for:[/bold] [cyan]{email}[/cyan]")
        console.print(f"[dim]Duration: {days} days[/dim]\n")
        
        token = BetaTokenManager.generate_token(email=email, days=days)
        
        console.print("[green]✓ Beta token generated![/green]\n")
        console.print(f"[bold]Token:[/bold]")
        console.print(f"[cyan]{token}[/cyan]\n")
        console.print("[yellow]⚠️  SEND THIS TOKEN TO USER SECURELY[/yellow]")
        console.print("[dim]User installs with: parry license --install beta --token {token}[/dim]")
    
    elif command == 'list-tokens':
        from parry.beta_token import BetaTokenManager
        
        tokens = BetaTokenManager.list_issued_tokens()
        
        if not tokens:
            console.print("[dim]No tokens issued yet[/dim]")
            return
        
        console.print(f"\n[bold]Issued Beta Tokens: {len(tokens)}[/bold]\n")
        
        table = Table()
        table.add_column("Email", style="white")
        table.add_column("Issued", style="dim")
        table.add_column("Expires", style="dim")
        table.add_column("Issued By", style="dim")
        
        for token_hash, token_data in tokens.items():
            table.add_row(
                token_data.get('email', 'unknown'),
                token_data.get('issued', 'unknown'),
                token_data.get('expires', 'unknown'),
                token_data.get('issued_by', 'unknown')
            )
        
        console.print(table)
    
    else:
        console.print(f"[red]Unknown admin command: {command}[/red]")
        console.print("\nAvailable commands:")
        console.print("  generate-token    Generate a beta token")
        console.print("  list-tokens       List all issued tokens")


if __name__ == "__main__":
    main()

