#!/usr/bin/env python3
# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Parry CLI - Command-line interface for security scanning

This module implements the command-line interface for the Parry Security Scanner.
It provides commands for scanning code, managing configuration, running API servers,
and handling user feedback. Built using Click for command parsing and Rich for
beautiful terminal output.
"""

# Import click library for creating command-line interfaces with decorators
import click
# Import sys for system-specific parameters and functions like exit()
import sys
# Import json for reading and writing JSON-formatted scan results
import json
# Import os for operating system interface functions
import os
# Import Path from pathlib for object-oriented filesystem path manipulation
from pathlib import Path
# Import datetime for time-based operations
from datetime import datetime
# Import type hints for better code documentation and type checking
from typing import Optional, List, Tuple
# Import concurrent.futures for parallel processing of scan tasks
from concurrent.futures import ThreadPoolExecutor, as_completed
# Import Console from rich for enhanced terminal output with colors and formatting
from rich.console import Console
# Import Table from rich for displaying tabular data in the terminal
from rich.table import Table
# Import Panel from rich for creating bordered text boxes in terminal
from rich.panel import Panel
# Import Progress and related components from rich for progress bars
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import Scanner class which performs the actual vulnerability detection
from parry.scanner import Scanner
# Import LLMClient for interfacing with Large Language Models for AI fixes
from parry.llm import LLMClient
# Import PatchGenerator for creating code patches to fix vulnerabilities
from parry.patch import PatchGenerator
# Import Reporter for formatting and outputting scan results
from parry.reporter import Reporter
# Import Comparator for comparing scan results between different runs
from parry.compare import Comparator
# Import VulnerabilityValidator for reducing false positives using AI
from parry.validator import VulnerabilityValidator
# Import SCAScanner for Software Composition Analysis (dependency scanning)
from parry.sca import SCAScanner
# Import CustomRulesEngine for loading and processing custom security rules
from parry.custom_rules import CustomRulesEngine
# Import caching classes for faster repeated scans
from parry.cache import ProjectCache, ScanCache
# Import function to start API server for remote scanning
from parry.api import start_api_server
# Import setup helper functions for initial configuration and diagnostics
from parry.setup import SetupHelper, run_setup_wizard, run_doctor, create_config
# Import license management functions for feature gating
from parry.license import has_feature, require_feature, LicenseManager
# Import FeedbackManager for collecting user feedback
from parry.feedback import FeedbackManager
# Import payment system for subscription management
from parry.payment import StripePaymentManager, LicenseManager, PaymentConfig

# Create a global Console instance for all terminal output throughout the CLI
console = Console()


@click.group()  # Decorator to create a CLI command group (allows subcommands)
@click.version_option(version="0.7.0")  # Add --version flag to display version number
def main():
    """
    🔒 Parry Security Scanner - Privacy-first AI-powered security scanner
    
    All scanning and inference happens locally on your machine.
    
    This is the main entry point for the Parry CLI. It serves as a command
    group that contains subcommands like 'scan', 'setup', 'doctor', etc.
    """
    # pass statement - no initialization needed, subcommands handle their own logic
    pass


@main.command()  # Register 'scan' as a subcommand of the main group
@click.argument("path", type=click.Path(exists=True))  # Required positional argument for scan target path
@click.option("--format", "-f", type=click.Choice(["json", "markdown", "terminal"]),   # Output format selection
              default="terminal", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")  # Optional output file path
@click.option("--severity", "-s", type=click.Choice(["low", "medium", "high", "critical"]),  # Filter by severity level
              help="Filter by minimum severity")
@click.option("--cwe", multiple=True, help="Filter by CWE tags")  # Filter by specific CWE identifiers
@click.option("--verbose", "-v", is_flag=True, help="Show detailed analysis")  # Enable verbose output
@click.option("--exclude", multiple=True, help="Exclude patterns (glob)")  # Exclude files/directories from scan
@click.option("--validate", is_flag=True, help="Use AI to validate findings and reduce false positives")  # Enable AI validation
@click.option("--mode", type=click.Choice(["fast", "deep", "hybrid"]), default="fast",  # Scanning mode selection
              help="Detection mode: fast (pattern-only, 5% recall), deep (AI-powered, 75% recall), hybrid (both)")
@click.option("--sca", is_flag=True, help="Enable Software Composition Analysis (dependency scanning)")  # Enable SCA scanning
@click.option("--incremental", is_flag=True, help="Use incremental scanning (only scan changed files)")  # Enable incremental mode
@click.option("--custom-rules", type=click.Path(exists=True), help="Path to custom YAML rules file")  # Custom rules file path
def scan(path: str, format: str, output: Optional[str], severity: Optional[str], 
         cwe: tuple, verbose: bool, exclude: tuple, validate: bool, mode: str,
         sca: bool, incremental: bool, custom_rules: Optional[str]):
    """
    Scan a codebase for security vulnerabilities.
    
    This is the main scanning command that analyzes code for security issues.
    It supports multiple scanning modes (fast/deep/hybrid), output formats,
    filtering options, and can integrate with AI for enhanced detection.
    
    Example:
        parry scan ./src
        parry scan ./src --severity high --format json --output results.json
    
    Args:
        path: Directory or file path to scan
        format: Output format (json, markdown, or terminal)
        output: File path to write results to
        severity: Minimum severity level to report
        cwe: Tuple of CWE identifiers to filter by
        verbose: Whether to show detailed analysis
        exclude: Tuple of glob patterns to exclude
        validate: Whether to use AI validation
        mode: Scanning mode (fast, deep, or hybrid)
        sca: Whether to enable dependency scanning
        incremental: Whether to only scan changed files
        custom_rules: Path to custom security rules file
    """
    # Check and enforce license limits
    license_manager = LicenseManager()
    license_info = license_manager.validate_license()
    
    # Count files to scan
    target_path = Path(path)
    if target_path.is_file():
        file_count = 1
    else:
        file_count = sum(1 for _ in target_path.rglob('*') if _.is_file())
    
    # Enforce file limit for free tier
    if not license_manager.enforce_file_limit(file_count):
        console.print(Panel.fit(
            f"[bold red]❌ File Limit Exceeded[/bold red]\n\n"
            f"Free tier limit: {license_info['file_limit']} files\n"
            f"Files in scan: {file_count}\n\n"
            f"[cyan]Upgrade to Pro for unlimited files:[/cyan]\n"
            f"[bold]parry subscribe --tier pro[/bold]",
            border_style="red"
        ))
        sys.exit(1)
    
    # Display a visually appealing header panel with scanner information
    console.print(Panel.fit(
        "[bold cyan]Parry Security Scanner[/bold cyan]\n"  # Title in bold cyan
        f"[dim]Mode: {mode} | Privacy-first vulnerability detection[/dim]\n"  # Subtitle with mode
        f"[dim]License: {license_info['tier'].upper()} | Files: {file_count}[/dim]",  # License info
        border_style="cyan"  # Cyan colored border
    ))
    
    # Check if AI is available for deep/hybrid modes
    # Initialize flag to track AI availability
    ai_available = False
    # Check if user requested deep or hybrid mode which require AI
    if mode in ["deep", "hybrid"]:
        # Check license for deep mode - verify user has appropriate license tier
        if not has_feature('deep-mode'):
            # Get current license tier for display
            tier = LicenseManager.get_tier()
            # Display error message about license requirement
            console.print(Panel.fit(
                f"[bold red]❌ Deep Mode Requires Pro/Enterprise License[/bold red]\n\n"  # Error header
                f"Current tier: [yellow]{tier}[/yellow]\n"  # Current license tier
                f"Deep mode provides [bold]75% recall[/bold] vs 5% in Fast mode.\n\n"  # Feature explanation
                f"[cyan]Visit https://parry.dev/pricing to upgrade[/cyan]",  # Upgrade call-to-action
                border_style="red"  # Red border for error
            ))
            # Inform user about fallback to fast mode
            console.print(f"\n[yellow]Falling back to Fast Mode (pattern-based detection)[/yellow]\n")
            # Override mode to fast since deep mode is not available
            mode = "fast"
        else:
            # License check passed, now check if Ollama AI is available
            # Create SetupHelper instance to check system status
            helper = SetupHelper()
            # Verify Ollama is running AND model is downloaded
            ai_available = helper.check_ollama_running() and helper.check_model_available()
            
            # If AI is not available despite having the license
            if not ai_available:
                # Display warning about missing AI components
                console.print(f"[yellow]⚠ AI mode requested but Ollama is not available[/yellow]")
                # Explain fallback behavior
                console.print(f"[yellow]  Falling back to Fast Mode (pattern-based detection)[/yellow]")
                # Provide helpful instructions for enabling AI modes
                console.print(f"\n[dim]To enable AI modes, run:[/dim]")
                # Show command for interactive setup
                console.print(f"[cyan]  parry setup[/cyan]  (interactive setup wizard)")
                # Show command for system diagnostics
                console.print(f"[cyan]  parry doctor[/cyan] (check system status)\n")
                # Override mode to fast mode since AI is unavailable
                mode = "fast"
    
    # Show mode explanation to user based on selected mode
    # Check if deep mode is active with AI available
    if mode == "deep" and ai_available:
        # Display deep mode information with emoji and description
        console.print("[yellow]🤖 Deep Mode: AI-powered detection for 75% recall (slower, comprehensive)[/yellow]")
    # Check if hybrid mode is active with AI available
    elif mode == "hybrid" and ai_available:
        # Display hybrid mode information combining pattern and AI
        console.print("[yellow]⚡ Hybrid Mode: Pattern + AI detection for best coverage[/yellow]")
    else:
        # Display fast mode information (default or fallback)
        console.print("[green]⚡ Fast Mode: Pattern-based detection (quick, baseline)[/green]")
    
    # Initialize scanner with exclusion patterns
    # Convert exclude tuple to list for Scanner initialization
    scanner = Scanner(exclude_patterns=list(exclude))
    
    # Create progress bar context for scanning operation
    with Progress(
        SpinnerColumn(),  # Add spinning animation
        TextColumn("[progress.description]{task.description}"),  # Add progress text
        console=console,  # Use global console for output
    ) as progress:
        # Add a task to track scanning progress with indeterminate total
        task = progress.add_task("[cyan]Scanning codebase...", total=None)
        
        # Execute the scan within a try-except block for error handling
        try:
            # Perform the actual scan by calling scanner.scan with target path
            results = scanner.scan(Path(path))
            # Update progress to show completion
            progress.update(task, completed=True)
        # Catch any exceptions that occur during scanning
        except Exception as e:
            # Display error message in red to user
            console.print(f"[red]Error during scanning: {e}[/red]")
            # Exit with error code 1 to indicate failure
            sys.exit(1)
    
    # AI-Powered Deep Scan (for deep or hybrid mode) - OPTIMIZED with parallel processing & smart prioritization
    # Check if AI-enhanced scanning should be performed
    if mode in ["deep", "hybrid"] and results.get('files_scanned', 0) > 0 and ai_available:
        # Display header for AI scanning phase
        console.print("\n[cyan]🤖 AI Deep Scan: Comprehensive vulnerability detection...[/cyan]")
        # Explain what AI scanning does and its benefits
        console.print("[dim]This uses local AI with smart prioritization (TinyLlama for 5-7x speed)[/dim]")
        
        # Attempt AI scanning with error handling
        try:
            # Import AIDetector class for AI-powered vulnerability detection
            from parry.ai_detector import AIDetector
            # Import SmartFilePrioritizer for intelligent file selection
            from parry.smart_prioritizer import SmartFilePrioritizer
            # Import multiprocessing to determine optimal worker count
            import multiprocessing
            
            # Initialize AI detector with optimized settings for parallel processing
            # Calculate max workers: use CPU count but cap at 16 to avoid overwhelming system
            max_workers = min(multiprocessing.cpu_count() or 8, 16)  # Use up to 16 cores, default to 8 if count unavailable
            # Create AIDetector instance with calculated worker count
            ai_detector = AIDetector(max_workers=max_workers)
            
            # Get list of scanned files for AI analysis
            # Initialize empty list to collect file paths
            scanned_files = []
            # Convert path string to Path object for manipulation
            target = Path(path)
            # Check if scanning a single file
            if target.is_file():
                # Add the single file to the list
                scanned_files = [target]
            else:
                # Get files from initial scan by searching for supported file extensions
                # Iterate through common programming language extensions
                for ext in ['.py', '.java', '.js', '.go', '.php', '.rb', '.rs', '.c', '.cpp', '.h']:
                    # Recursively find all files with this extension and add to list
                    scanned_files.extend(target.rglob(f'*{ext}'))
            
            # Smart Prioritization: Only analyze high-risk files with AI (Hybrid mode only)
            if mode == "hybrid":
                # Initialize smart prioritizer
                prioritizer = SmartFilePrioritizer(min_risk_score=0.3)
                # Select high-risk files for AI analysis
                high_risk_files = prioritizer.prioritize_files(
                    scanned_files,
                    results.get('vulnerabilities', [])
                )
                # Get statistics for display
                stats = prioritizer.get_statistics(len(scanned_files), len(high_risk_files))
                # Display prioritization info
                console.print(f"[dim]Smart prioritization: {len(high_risk_files)}/{len(scanned_files)} files ({stats['percentage']}) selected for AI analysis[/dim]")
                console.print(f"[dim]Expected speedup: {stats['expected_speedup']} | Using {max_workers} workers[/dim]")
                # Use only high-risk files
                scanned_files = high_risk_files
                
                # Prepare Fast Mode findings context for AI (avoid duplication)
                fast_mode_findings_by_file = {}
                for vuln in results.get('vulnerabilities', []):
                    file_path = vuln.get('file_path', '')
                    if file_path not in fast_mode_findings_by_file:
                        fast_mode_findings_by_file[file_path] = []
                    fast_mode_findings_by_file[file_path].append(vuln)
            else:
                # Deep mode: analyze all files
                console.print(f"[dim]Found {len(scanned_files)} files for AI analysis (using {max_workers} workers)[/dim]")
                fast_mode_findings_by_file = {}
            
            # Optimized parallel processing for AI vulnerability detection
            # Initialize list to collect AI-detected vulnerabilities
            ai_vulns = []
            
            def process_file_optimized(file_path):
                """
                Process single file with AI detection - optimized wrapper function
                
                This function is designed to be called in parallel for efficient
                processing of multiple files simultaneously.
                
                Args:
                    file_path: Path object pointing to file to analyze
                    
                Returns:
                    List of vulnerability dictionaries found in the file
                """
                # Wrap in try-except to handle individual file errors gracefully
                try:
                    # Read the file content, ignoring encoding errors
                    code = file_path.read_text(errors='ignore')
                    
                    # Build context with Fast Mode findings to avoid duplication
                    context = {}
                    if mode == "hybrid" and str(file_path) in fast_mode_findings_by_file:
                        context['fast_mode_findings'] = fast_mode_findings_by_file[str(file_path)]
                    
                    # Call AI detector to analyze the code for vulnerabilities
                    file_vulns = ai_detector.detect_vulnerabilities(
                        code,  # Source code to analyze
                        str(file_path),  # File path as string
                        file_path.suffix[1:],  # Language extracted from file extension (remove leading dot)
                        context  # Context with Fast Mode findings
                    )
                    # Convert vulnerability objects to dictionaries for JSON serialization
                    return [v.to_dict() if hasattr(v, 'to_dict') else v for v in file_vulns]
                # Catch any exceptions during file processing
                except Exception as e:
                    # Return empty list on error to continue processing other files
                    return []
            
            # Process all files in parallel using ThreadPoolExecutor for I/O-bound AI tasks
            # Create progress context for AI analysis phase
            with Progress(
                SpinnerColumn(),  # Spinning animation
                TextColumn("[progress.description]{task.description}"),  # Progress description
                console=console,  # Output console
            ) as progress:
                # Add task to track AI analysis progress with known total
                task = progress.add_task(f"[cyan]Analyzing {len(scanned_files)} files with AI...", total=len(scanned_files))
                
                # Create ThreadPoolExecutor with calculated number of workers
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all files for parallel processing, creating a future for each
                    futures = {executor.submit(process_file_optimized, f): f for f in scanned_files}
                    
                    # Collect results as they complete
                    # Initialize counter for completed files
                    completed = 0
                    # Iterate through futures as they complete (not in submission order)
                    for future in as_completed(futures):
                        # Get the result from the completed future (list of vulnerabilities)
                        file_vulns = future.result()
                        # Add vulnerabilities from this file to the overall list
                        ai_vulns.extend(file_vulns)
                        # Increment completed counter
                        completed += 1
                        # Update progress bar with current completion count
                        progress.update(task, completed=completed)
            
            # Merge AI findings with pattern findings based on mode
            # Check if hybrid mode (combines pattern and AI results)
            if mode == "hybrid":
                # Combine both pattern-based and AI-based results
                # Store original count for reporting
                original_count = len(results['vulnerabilities'])
                # Add AI vulnerabilities to existing results
                results['vulnerabilities'].extend(ai_vulns)
                # Deduplicate vulnerabilities that appear in both pattern and AI results
                # Use set to track unique vulnerabilities by key attributes
                seen = set()
                # List to store deduplicated vulnerabilities
                deduped = []
                # Iterate through all vulnerabilities (pattern + AI)
                for v in results['vulnerabilities']:
                    # Create unique key using CWE, file path, and line number
                    key = (v['cwe'], v['file_path'], v['line_number'])
                    # Check if this vulnerability hasn't been seen before
                    if key not in seen:
                        # Add to seen set
                        seen.add(key)
                        # Add to deduplicated list
                        deduped.append(v)
                # Replace vulnerabilities with deduplicated list
                results['vulnerabilities'] = deduped
                # Update vulnerability count
                results['vulnerabilities_found'] = len(deduped)
                # Display success message with AI contribution
                console.print(f"[green]✓ AI found {len(ai_vulns)} additional vulnerabilities (total: {len(deduped)})[/green]")
            else:  # deep mode
                # Replace with AI findings only (don't use pattern results)
                # Set vulnerabilities to AI-detected only
                results['vulnerabilities'] = ai_vulns
                # Update count with AI results only
                results['vulnerabilities_found'] = len(ai_vulns)
                # Display AI detection count
                console.print(f"[green]✓ AI detected {len(ai_vulns)} vulnerabilities[/green]")
            
        # Catch any exceptions during AI scanning
        except Exception as e:
            # Display error message about AI scan failure
            console.print(f"[red]AI deep scan failed: {e}[/red]")
            # Inform user that pattern-based results will still be used
            console.print("[dim]Continuing with pattern-based results...[/dim]")
    
    # ADVANCED STATIC ANALYSIS (Deep Mode Only)
    # Perform advanced static analysis using CFG, data flow, and symbolic execution
    if mode == "deep" and ai_available and results.get('files_scanned', 0) > 0:
        console.print("\n[cyan]🔬 Advanced Static Analysis: CFG, Data Flow & Symbolic Execution...[/cyan]")
        console.print("[dim]This enhances precision with path-sensitive analysis[/dim]")
        
        try:
            from parry.advanced_static_analysis import AdvancedStaticAnalyzer
            
            advanced_analyzer = AdvancedStaticAnalyzer()
            advanced_vulns = []
            
            # Get Python files for advanced analysis
            python_files = []
            target = Path(path)
            if target.is_file() and target.suffix == '.py':
                python_files = [target]
            else:
                python_files = list(target.rglob('*.py'))
            
            if python_files:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        "[cyan]Running advanced analysis...",
                        total=len(python_files)
                    )
                    
                    for file_path in python_files:
                        try:
                            code = file_path.read_text(errors='ignore')
                            
                            # Run advanced analysis
                            file_vulns = advanced_analyzer.analyze(
                                code,
                                str(file_path),
                                'python'
                            )
                            
                            # Convert to dict format
                            for v in file_vulns:
                                advanced_vulns.append({
                                    'cwe': v.cwe,
                                    'severity': v.severity,
                                    'title': v.title,
                                    'description': v.description,
                                    'file_path': str(file_path),
                                    'line_number': v.line,
                                    'code': v.code,
                                    'confidence': v.confidence,
                                    'source': 'advanced_static_analysis'
                                })
                        except Exception:
                            pass
                        
                        progress.update(task, advance=1)
                
                # Merge advanced findings with existing results
                if advanced_vulns:
                    original_count = len(results['vulnerabilities'])
                    results['vulnerabilities'].extend(advanced_vulns)
                    
                    # Deduplicate
                    seen = set()
                    deduped = []
                    for v in results['vulnerabilities']:
                        key = (v['cwe'], v['file_path'], v['line_number'])
                        if key not in seen:
                            seen.add(key)
                            deduped.append(v)
                    
                    results['vulnerabilities'] = deduped
                    results['vulnerabilities_found'] = len(deduped)
                    
                    new_count = len(deduped) - original_count
                    console.print(f"[green]✓ Advanced analysis found {len(advanced_vulns)} issues ({new_count} new)[/green]")
                else:
                    console.print("[dim]No additional issues found by advanced analysis[/dim]")
        
        except ImportError:
            console.print("[yellow]⚠️  Advanced static analysis modules not available[/yellow]")
        except Exception as e:
            console.print(f"[red]Advanced analysis failed: {e}[/red]")
    
    # AI Validation to reduce false positives
    # Check if validation was requested and there are vulnerabilities to validate
    if validate and results.get('vulnerabilities'):
        # Check if user has the AI validation feature in their license
        if not has_feature('ai-validation'):
            # Get current license tier for display
            tier = LicenseManager.get_tier()
            # Display error panel about license requirement
            console.print(Panel.fit(
                f"[bold red]❌ AI Validation Requires Pro/Enterprise License[/bold red]\n\n"  # Error header
                f"Current tier: [yellow]{tier}[/yellow]\n"  # Current license tier
                f"AI validation reduces false positives from 55% to 25%.\n\n"  # Feature benefit
                f"[cyan]Visit https://parry.dev/pricing to upgrade[/cyan]",  # Upgrade CTA
                border_style="red"  # Red border for error
            ))
            # Warn user about potential false positives
            console.print(f"\n[dim]Skipping validation. Results may include false positives.[/dim]\n")
        # Check if AI is available even if license allows it
        elif not ai_available:
            # Display warning that AI validation is unavailable
            console.print(f"\n[yellow]⚠ AI validation requested but Ollama is not available[/yellow]")
            # Inform user about skipping validation
            console.print(f"[dim]Skipping validation. Results may include false positives.[/dim]")
            # Provide guidance on enabling AI
            console.print(f"[dim]Run 'parry setup' to enable AI validation.[/dim]\n")
        else:
            # AI validation is available and licensed - proceed with validation
            # Display header for validation phase
            console.print("\n[cyan]🤖 AI Validation: Reviewing findings to reduce false positives...[/cyan]")
            
            # Create progress context for validation
            with Progress(
                SpinnerColumn(),  # Spinning animation
                TextColumn("[progress.description]{task.description}"),  # Progress text
                console=console,  # Output console
            ) as progress:
                # Add validation task with indeterminate progress
                val_task = progress.add_task("[cyan]Validating with AI...", total=None)
                
                # Attempt validation with error handling
                try:
                    # Create VulnerabilityValidator instance for AI validation
                    validator = VulnerabilityValidator()
                    # Convert dict vulnerabilities back to objects for validation
                    # Import Vulnerability class for object construction
                    from parry.scanner import Vulnerability
                    # Convert each dictionary to Vulnerability object (or keep if already object)
                    vuln_objects = [
                        Vulnerability(**v) if isinstance(v, dict) else v 
                        for v in results['vulnerabilities']
                    ]
                    
                    # Perform AI validation on vulnerabilities
                    validation_results = validator.validate_vulnerabilities(
                        vuln_objects,  # List of Vulnerability objects to validate
                        path,  # Source path for context
                        batch_size=10  # Process in batches of 10 for efficiency
                    )
                    
                    # Mark validation task as complete
                    progress.update(val_task, completed=True)
                    
                    # Display validation summary report to user
                    console.print(validator.generate_validation_report(validation_results))
                    
                    # Update results to only include confirmed vulnerabilities
                    # Store original count before filtering
                    results['original_count'] = len(results['vulnerabilities'])
                    # Filter to only confirmed vulnerabilities (not likely false positives)
                    results['vulnerabilities'] = [
                        item['vulnerability'].to_dict() if hasattr(item['vulnerability'], 'to_dict') else item['vulnerability']
                        for item in validation_results['confirmed']
                    ]
                    # Store count of likely false positives filtered out
                    results['likely_false_positives'] = len(validation_results['likely_false_positive'])
                    # Store count of vulnerabilities needing manual review
                    results['needs_review'] = len(validation_results['needs_review'])
                    # Update final count of confirmed vulnerabilities
                    results['vulnerabilities_found'] = len(results['vulnerabilities'])
                    # Store calculated false positive rate
                    results['false_positive_rate'] = validation_results['validation_summary']['false_positive_rate']
                    
                    # Display summary of validation filtering
                    console.print(f"\n[green]✓[/green] Reduced findings from {results['original_count']} to {results['vulnerabilities_found']} " 
                                f"({results['likely_false_positives']} likely false positives filtered)")
                    
                # Catch validation errors
                except Exception as e:
                    # Display warning about validation failure
                    console.print(f"[yellow]⚠️  AI validation failed: {e}[/yellow]")
                    # Inform user results are unvalidated
                    console.print("[dim]Continuing with unvalidated results...[/dim]")
    
    # Filter results based on user-specified criteria
    # Check if severity filter was requested
    if severity:
        # Define severity ordering for comparison (low=0, medium=1, high=2, critical=3)
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        # Get numeric value for minimum severity threshold
        min_severity = severity_order[severity]
        # Filter vulnerabilities to only include those at or above minimum severity
        results["vulnerabilities"] = [
            v for v in results["vulnerabilities"]
            if severity_order.get(v["severity"], 0) >= min_severity
        ]
    
    # Check if CWE filter was requested
    if cwe:
        # Filter vulnerabilities to only include specified CWE identifiers
        results["vulnerabilities"] = [
            v for v in results["vulnerabilities"]
            if v["cwe"] in cwe
        ]
    
    # Generate report from scan results
    # Create Reporter instance with filtered results
    reporter = Reporter(results)
    
    # Check output format and generate appropriate report
    # Check if JSON format was requested
    if format == "json":
        # Generate JSON-formatted report
        report = reporter.generate_json()
        # Check if output file path was specified
        if output:
            # Write report to specified file
            Path(output).write_text(report)
            # Display success message with file path
            console.print(f"[green]✓[/green] Report saved to {output}")
        else:
            # No output file specified, print to console
            console.print(report)
    
    # Check if Markdown format was requested
    elif format == "markdown":
        # Generate Markdown-formatted report
        report = reporter.generate_markdown()
        # Check if output file path was specified
        if output:
            # Write report to specified file
            Path(output).write_text(report)
            # Display success message with file path
            console.print(f"[green]✓[/green] Report saved to {output}")
        else:
            # No output file specified, print to console
            console.print(report)
    
    else:  # terminal
        # Default to terminal output format with colors and formatting
        # Print report directly to terminal with optional verbose mode
        reporter.print_terminal(verbose=verbose)
    
    # Exit with appropriate code based on vulnerability severity
    # Count critical severity vulnerabilities
    critical_count = sum(1 for v in results["vulnerabilities"] if v["severity"] == "critical")
    # Count high severity vulnerabilities
    high_count = sum(1 for v in results["vulnerabilities"] if v["severity"] == "high")
    
    # Exit with code 2 if any critical vulnerabilities found
    if critical_count > 0:
        sys.exit(2)
    # Exit with code 1 if any high severity vulnerabilities found
    elif high_count > 0:
        sys.exit(1)
    else:
        # Exit with code 0 (success) if no high/critical vulnerabilities
        sys.exit(0)


@main.command()  # Register 'patch' as a subcommand
@click.argument("file", type=click.Path(exists=True))  # Required file argument
@click.option("--apply", is_flag=True, help="Automatically apply patches")  # Auto-apply flag
@click.option("--interactive", "-i", is_flag=True, help="Review each patch before applying")  # Interactive mode
@click.option("--cwe", help="Only patch specific CWE type")  # Filter by CWE
@click.option("--model", default="codellama:7b-instruct", help="LLM model to use")  # LLM model selection
def patch(file: str, apply: bool, interactive: bool, cwe: Optional[str], model: str):
    """
    Generate secure code replacements for vulnerabilities.
    
    This command uses AI to generate secure code patches that fix detected
    vulnerabilities. Patches can be reviewed interactively or applied automatically.
    
    Example:
        parry patch ./src/api.py
        parry patch ./src/api.py --apply
        parry patch ./src/api.py --interactive --cwe CWE-89
    
    Args:
        file: Path to file to patch
        apply: Whether to automatically apply all patches
        interactive: Whether to review each patch before applying
        cwe: Optional CWE identifier to filter patches
        model: LLM model name to use for patch generation
    """
    # Display header panel for patch command
    console.print(Panel.fit(
        "[bold magenta]Parry Patch Generator[/bold magenta]\n"  # Title
        "[dim]AI-powered security fixes[/dim]",  # Subtitle
        border_style="magenta"  # Magenta border color
    ))
    
    # Convert file string to Path object
    file_path = Path(file)
    
    # Scan the file first to identify vulnerabilities
    # Create progress context for scanning phase
    with Progress(
        SpinnerColumn(),  # Spinning animation
        TextColumn("[progress.description]{task.description}"),  # Progress text
        console=console,  # Output console
    ) as progress:
        # Add task for file analysis
        task = progress.add_task("[cyan]Analyzing file...", total=None)
        
        # Create Scanner instance for vulnerability detection
        scanner = Scanner()
        # Scan the target file
        results = scanner.scan(file_path)
        
        # Check if CWE filter was specified
        if cwe:
            # Filter vulnerabilities to only the specified CWE type
            results["vulnerabilities"] = [
                v for v in results["vulnerabilities"]
                if v["cwe"] == cwe
            ]
        
        # Mark scanning task as complete
        progress.update(task, completed=True)
    
    # Check if any vulnerabilities were found
    if not results["vulnerabilities"]:
        # No vulnerabilities found - display success message and exit
        console.print("[green]✓[/green] No vulnerabilities found!")
        # Return early since there's nothing to patch
        return
    
    # Display count of vulnerabilities found
    console.print(f"\n[yellow]Found {len(results['vulnerabilities'])} vulnerabilities[/yellow]\n")
    
    # Initialize LLM and patch generator for AI-powered fix generation
    try:
        # Create LLMClient instance with specified model
        llm = LLMClient(model=model)
        # Create PatchGenerator instance with LLM client
        patch_gen = PatchGenerator(llm)
    # Catch connection errors
    except Exception as e:
        # Display error message about Ollama connection failure
        console.print(f"[red]Error connecting to Ollama: {e}[/red]")
        # Provide guidance on starting Ollama
        console.print("[yellow]Make sure Ollama is running: ollama serve[/yellow]")
        # Exit with error code
        sys.exit(1)
    
    # Generate patches for each vulnerability
    # Initialize list to store generated patches
    patches = []
    # Iterate through each vulnerability
    for vuln in results["vulnerabilities"]:
        # Display status message while generating patch
        with console.status(f"[cyan]Generating patch for {vuln['cwe']}..."):
            # Generate patch using AI for this specific vulnerability
            patch = patch_gen.generate_patch(file_path, vuln)
            # Add generated patch to list
            patches.append(patch)
    
    # Display and optionally apply patches
    # Iterate through patches with numbering starting from 1
    for i, patch in enumerate(patches, 1):
        # Display patch header with number
        console.print(f"\n[bold]Patch {i}/{len(patches)}[/bold]")
        # Display CWE identifier and severity level
        console.print(f"CWE: {patch['cwe']} | Severity: {patch['severity']}")
        # Display line number where vulnerability exists
        console.print(f"Line: {patch['line_number']}\n")
        
        # Display original vulnerable code
        console.print("[red]- Original:[/red]")
        # Print the original insecure code
        console.print(patch['original_code'])
        # Add blank line for readability
        console.print("\n[green]+ Fixed:[/green]")
        # Display the secure fixed code
        console.print(patch['fixed_code'])
        # Display explanation of the fix
        console.print(f"\n[dim]{patch['explanation']}[/dim]\n")
        
        # Check if interactive mode is enabled
        if interactive:
            # Prompt user to confirm applying this patch
            if click.confirm("Apply this patch?"):
                # User confirmed - apply the patch to the file
                patch_gen.apply_patch(file_path, patch)
                # Display success message
                console.print("[green]✓[/green] Patch applied")
            else:
                # User declined - skip this patch
                console.print("[yellow]⊘[/yellow] Patch skipped")
        # Check if auto-apply mode is enabled
        elif apply:
            # Automatically apply patch without confirmation
            patch_gen.apply_patch(file_path, patch)
            # Display success message
            console.print("[green]✓[/green] Patch applied")
    
    # Display final summary based on mode
    # Check if auto-apply mode was used (non-interactive)
    if apply and not interactive:
        # Display summary of automatically applied patches
        console.print(f"\n[green]✓[/green] Applied {len(patches)} patches to {file}")
    # Check if patches were only displayed (not applied)
    elif not interactive:
        # Inform user how to apply patches automatically
        console.print(f"\n[yellow]Run with --apply to automatically apply patches[/yellow]")


@main.command()  # Register 'compare' as a subcommand
@click.argument("tool", type=click.Choice(["snyk", "semgrep"]))  # Tool to compare against
@click.argument("path", type=click.Path(exists=True))  # Path to scan
@click.option("--output", "-o", type=click.Path(), help="Save comparison results")  # Output file
@click.option("--format", "-f", type=click.Choice(["json", "markdown", "terminal"]),   # Output format
              default="terminal")
def compare(tool: str, path: str, output: Optional[str], format: str):
    """
    Benchmark Parry against other security tools.
    
    This command runs both Parry and another security tool (Snyk or Semgrep)
    on the same codebase and compares the results to evaluate detection rates,
    false positives, and performance.
    
    Example:
        parry compare snyk ./src
        parry compare semgrep ./src --output comparison.json
    
    Args:
        tool: Name of tool to compare against (snyk or semgrep)
        path: Path to codebase to scan
        output: Optional file path to save comparison results
        format: Output format (json, markdown, or terminal)
    """
    # Display header panel for comparison command
    console.print(Panel.fit(
        "[bold green]Parry Benchmarking[/bold green]\n"  # Title
        f"[dim]Comparing against {tool}[/dim]",  # Subtitle with tool name
        border_style="green"  # Green border
    ))
    
    # Create Comparator instance for running and comparing tools
    comparator = Comparator()
    
    # Create progress context for dual-scan operation
    with Progress(
        SpinnerColumn(),  # Spinning animation
        TextColumn("[progress.description]{task.description}"),  # Progress text
        console=console,  # Output console
    ) as progress:
        # Run Parry scan first
        # Add task for Parry scanning
        task1 = progress.add_task("[cyan]Running Parry scan...", total=None)
        # Create Scanner instance
        scanner = Scanner()
        # Perform Parry scan on target path
        parry_results = scanner.scan(Path(path))
        # Mark Parry scan as complete
        progress.update(task1, completed=True)
        
        # Run comparison tool (Snyk or Semgrep)
        # Add task for comparison tool scanning
        task2 = progress.add_task(f"[cyan]Running {tool} scan...", total=None)
        # Attempt to run the comparison tool
        try:
            # Run the specified tool on the same path
            tool_results = comparator.run_tool(tool, Path(path))
            # Mark comparison tool scan as complete
            progress.update(task2, completed=True)
        # Catch errors running the comparison tool
        except Exception as e:
            # Display error message
            console.print(f"[red]Error running {tool}: {e}[/red]")
            # Exit with error code
            sys.exit(1)
    
    # Generate comparison between Parry and the other tool
    # Compare results from both tools
    comparison = comparator.compare(parry_results, tool_results, tool)
    
    # Output comparison results in requested format
    # Check if JSON format was requested
    if format == "json":
        # Convert comparison to JSON with indentation
        report = json.dumps(comparison, indent=2)
        # Check if output file was specified
        if output:
            # Write JSON report to file
            Path(output).write_text(report)
            # Display success message
            console.print(f"[green]✓[/green] Comparison saved to {output}")
        else:
            # Print JSON to console
            console.print(report)
    
    # Check if Markdown format was requested
    elif format == "markdown":
        # Generate Markdown-formatted comparison report
        report = comparator.generate_markdown(comparison)
        # Check if output file was specified
        if output:
            # Write Markdown report to file
            Path(output).write_text(report)
            # Display success message
            console.print(f"[green]✓[/green] Comparison saved to {output}")
        else:
            # Print Markdown to console
            console.print(report)
    
    else:  # terminal
        # Display comparison in terminal with colors and formatting
        comparator.print_terminal(comparison)


@main.command()  # Register 'serve' as a subcommand
@click.option("--host", default="0.0.0.0", help="API server host")  # Host address
@click.option("--port", default=8000, help="API server port")  # Port number
def serve(host: str, port: int):
    """
    Start Parry API server for remote scanning.
    
    This command launches a REST API server that allows remote scanning
    via HTTP endpoints. This is useful for CI/CD integration and 
    programmatic scanning from other tools.
    
    Requires Enterprise license.
    
    Args:
        host: Host address to bind server (default: 0.0.0.0 for all interfaces)
        port: Port number to listen on (default: 8000)
    """
    # Check if user has Enterprise license for REST API feature
    if not has_feature('rest-api'):
        # Get current license tier
        tier = LicenseManager.get_tier()
        # Display licensing error message
        console.print(Panel.fit(
            f"[bold red]❌ REST API Requires Enterprise License[/bold red]\n\n"  # Error title
            f"Current tier: [yellow]{tier}[/yellow]\n"  # Show current tier
            f"REST API provides programmatic access for CI/CD integration.\n\n"  # Feature description
            f"[cyan]Visit https://parry.dev/pricing to upgrade to Enterprise[/cyan]",  # Upgrade link
            border_style="red"  # Red border for error
        ))
        # Exit function without starting server
        return
    
    # Display server startup message
    console.print("[bold blue]Starting Parry API Server...[/bold blue]")
    # Start the API server with specified host and port
    start_api_server(host=host, port=port)


@main.command()  # Register 'init-rules' as a subcommand
@click.option("--output", "-o", type=click.Path(), default=None, help="Output path for rules template")  # Template path
def init_rules(output: Optional[str]):
    """
    Initialize custom security rules template.
    
    This command creates a YAML template file for defining custom
    security detection rules. Users can edit this template to add
    project-specific vulnerability patterns.
    
    Args:
        output: Optional path where template file should be created.
                If not specified, creates in ~/.parry/rules/
    """
    # Import custom rules module
    from parry.custom_rules import create_default_rules
    
    # Check if user specified output path
    if output:
        # Create CustomRulesEngine instance
        engine = CustomRulesEngine()
        # Generate rule template at specified path
        engine.create_rule_template(Path(output))
        # Display success message with output path
        console.print(f"[green]✓[/green] Custom rules template created at: {output}")
    else:
        # No output path specified, use default location
        create_default_rules()
        # Display success message for default location
        console.print("[green]✓[/green] Default rules created in ~/.parry/rules/")


@main.command()  # Register 'cache' as a subcommand
@click.option("--stats", is_flag=True, help="Show cache statistics")  # Display stats flag
@click.option("--clear", is_flag=True, help="Clear all cache")  # Clear cache flag
@click.option("--prune", type=int, help="Remove entries older than N days")  # Prune by age
def cache(stats: bool, clear: bool, prune: Optional[int]):
    """
    Manage scan result cache.
    
    Parry caches scan results to avoid re-scanning unchanged files.
    This command allows viewing cache stats, clearing cache, or pruning
    old entries.
    
    Examples:
        parry cache --stats              # Show cache statistics
        parry cache --clear              # Clear all cached results
        parry cache --prune 30           # Remove entries older than 30 days
    
    Args:
        stats: Display cache statistics (size, entry count, etc.)
        clear: Remove all cached scan results
        prune: Remove cache entries older than N days
    """
    # Create ScanCache instance for cache operations
    scan_cache = ScanCache()
    
    # Check if clear flag was provided
    if clear:
        # Remove all cache entries
        scan_cache.invalidate_all()
        # Display success message
        console.print("[green]✓[/green] Cache cleared")
    
    # Check if prune flag was provided
    elif prune:
        # Remove cache entries older than specified days
        scan_cache.prune_old_entries(days=prune)
        # Display success message with days
        console.print(f"[green]✓[/green] Pruned entries older than {prune} days")
    
    # Check if stats flag was provided
    elif stats:
        # Retrieve cache statistics dictionary
        cache_stats = scan_cache.get_cache_stats()
        
        # Create table for displaying cache statistics
        table = Table(title="Cache Statistics")
        # Add column for metric names
        table.add_column("Metric", style="cyan")
        # Add column for metric values
        table.add_column("Value", style="white")
        
        # Add row showing total number of cached files
        table.add_row("Total Files", str(cache_stats['total_files']))
        # Add row showing cache size in megabytes
        table.add_row("Cache Size", f"{cache_stats['cache_size_mb']} MB")
        # Add row showing timestamp of oldest cached entry
        table.add_row("Oldest Entry", str(cache_stats.get('oldest_entry', 'N/A')))
        # Add row showing timestamp of newest cached entry
        table.add_row("Newest Entry", str(cache_stats.get('newest_entry', 'N/A')))
        
        # Print the statistics table to console
        console.print(table)
    else:
        # No flags provided, show usage hint
        console.print("[yellow]Use --stats, --clear, or --prune[/yellow]")


@main.command()  # Register 'setup' as a subcommand
def setup():
    """
    Interactive setup wizard for Parry.
    
    This command launches an interactive wizard that guides users through
    the initial setup process, including installing Ollama, downloading
    AI models, and configuring Parry for optimal performance.
    
    Guides you through:
    - Ollama installation and verification
    - AI model download (codellama, deepseek-coder, etc.)
    - Configuration file creation
    - Testing the installation
    """
    # Launch the interactive setup wizard
    run_setup_wizard()


@main.command()  # Register 'doctor' as a subcommand
def doctor():
    """
    Check Parry installation and dependencies.
    
    This command runs diagnostics to verify that Parry is properly
    installed and all dependencies are available. It checks for
    common issues and provides recommendations for fixes.
    
    Verifies:
    - Python version (3.8+)
    - Ollama installation and running status
    - AI model availability and compatibility
    - Required Python dependencies
    - Available scanning modes (basic, fast, hybrid, deep)
    - License status and features
    """
    # Run comprehensive diagnostic checks
    run_doctor()


@main.command()  # Register 'config' as a subcommand
def config():
    """
    Create default configuration file at ~/.parry/config.yaml
    
    This command generates a default configuration file that allows
    users to customize Parry's behavior, including scan settings,
    output formats, LLM parameters, and more.
    """
    # Create the default configuration file
    create_config()
    # Display success message with config file location
    console.print("[green]✓[/green] Configuration file created at ~/.parry/config.yaml")
    # Provide additional instructions for customization
    console.print("  Edit this file to customize Parry's behavior.")


@main.command()  # Register 'license' as a subcommand
@click.option("--install", help="Install a license (beta/pro/enterprise)")  # License installation type
@click.option("--email", help="Email for beta license (deprecated, use --token)")  # Legacy email-based auth
@click.option("--token", help="Beta token for secure installation")  # Secure token-based auth
def license(install, email, token):
    """
    Manage your Parry license.
    
    Shows current license information, tier, and available features.
    Use this command to install beta/pro/enterprise licenses or
    check your current license status.
    
    Install beta license (recommended method):
        parry license --install beta --token YOUR_BETA_TOKEN
    
    Old method (insecure, deprecated):
        parry license --install beta --email user@example.com
    
    Args:
        install: Type of license to install (beta/pro/enterprise)
        email: User email for legacy beta license installation
        token: Secure token for beta license installation (preferred)
    """
    # Check if user wants to install a license
    if install:
        # Check if installing beta license
        if install == 'beta':
            # New secure method (preferred)
            # Check if secure token provided
            if token:
                # Attempt to install beta license with token
                if LicenseManager.install_beta_license_with_token(token):
                    # Installation successful
                    console.print("[green]✓[/green] Beta license installed successfully!")
                    # Show expiration notice
                    console.print("[dim]Beta access expires in 90 days[/dim]")
                    # Thank user for beta testing
                    console.print("\n[bold cyan]Thank you for beta testing Parry![/bold cyan]")
                else:
                    # Installation failed
                    console.print("[red]✗ Failed to install beta license[/red]")
                    # Show possible reasons for failure
                    console.print("[yellow]Token may be invalid, expired, or already used[/yellow]")
                # Return after processing token method
                return
            
            # Old insecure method (deprecated)
            # Check if email provided (legacy method)
            if email:
                # Warn about insecure installation
                console.print("[yellow]⚠️  WARNING: Insecure beta installation[/yellow]")
                # Show deprecation notice
                console.print("[dim]This method is deprecated. Use --token instead.[/dim]")
                # Provide link to get token
                console.print("[dim]Get a beta token from: https://parry.dev/beta[/dim]\n")
                
                # Attempt legacy email-based installation
                if LicenseManager.install_beta_license(email):
                    # Installation successful
                    console.print("[green]✓[/green] Beta license installed (insecure mode)")
                    # Show expiration notice
                    console.print("[dim]Beta access expires in 90 days[/dim]")
                else:
                    # Installation failed
                    console.print("[red]✗ Failed to install beta license[/red]")
                # Return after processing email method
                return
            
            # Neither token nor email provided
            # Display error message
            console.print("[red]Error: Beta token required for secure installation[/red]")
            # Show instructions for getting beta token
            console.print("\n[yellow]Get a beta token:[/yellow]")
            console.print("[cyan]  1. Visit https://parry.dev/beta[/cyan]")
            console.print("[cyan]  2. Request beta access[/cyan]")
            console.print("[cyan]  3. Install with: parry license --install beta --token YOUR_TOKEN[/cyan]")
            # Exit function
            return
        
        else:
            # Non-beta license type requires purchase
            console.print(f"[red]License type '{install}' requires a license key[/red]")
            # Show link to purchase
            console.print("Visit https://parry.dev to purchase a license")
        # Exit function after handling install
        return
    
    # No install flag, show current license info
    # Retrieve license information
    info = LicenseManager.get_license_info()
    
    # Display license information header
    console.print(Panel.fit(
        f"[bold cyan]Parry License Information[/bold cyan]",  # Panel title
        border_style="cyan"  # Cyan border
    ))
    
    # Create table for license details
    table = Table(title="License Details")
    # Add column for property names
    table.add_column("Property", style="cyan")
    # Add column for property values
    table.add_column("Value", style="white")
    
    # Format tier name for display (uppercase)
    tier_display = info['tier'].upper()
    # Determine color styling based on tier
    if info['tier'] == 'free':
        # Green for free tier
        tier_style = "green"
    elif info['tier'] == 'beta':
        # Yellow for beta tier
        tier_style = "yellow"
    elif info['tier'] in ['pro', 'enterprise']:
        # Yellow for paid tiers
        tier_style = "yellow"
    else:
        # Default white styling for unknown tiers
        tier_style = "white"
    
    # Add license tier row
    table.add_row("Tier", f"[{tier_style}]{tier_display}[/{tier_style}]")
    # Add build ID row for version tracking
    table.add_row("Build ID", info['build_id'])
    # Add machine ID row for device tracking
    table.add_row("Machine ID", info['machine_id'])
    # Add validation cache status row
    table.add_row("Validation Cached", "Yes" if info['validation_cached'] else "No")
    
    # Load additional info from license file
    try:
        # Import license configuration
        from parry.license import LicenseConfig
        # Check if license file exists
        if LicenseConfig.LICENSE_FILE.exists():
            # Import JSON parser
            import json
            # Open license file
            with open(LicenseConfig.LICENSE_FILE, 'r') as f:
                # Parse license JSON data
                license_data = json.load(f)
                # Check if expiration date is present
                if 'expires' in license_data:
                    # Import datetime for date calculations
                    from datetime import datetime
                    try:
                        # Parse expiration date from ISO format
                        expires = datetime.fromisoformat(license_data['expires'])
                        # Calculate days until expiration
                        days_left = (expires - datetime.now()).days
                        # Check if license is still valid
                        if days_left > 0:
                            # Show days remaining
                            table.add_row("Expires", f"In {days_left} days")
                        else:
                            # License has expired
                            table.add_row("Expires", "[red]Expired[/red]")
                    except:
                        # Date parsing failed, skip expiration display
                        pass
    except:
        # License file reading failed, skip additional info
        pass
    
    # Add features section
    # Get list of available features
    features = info['features']
    # Check if any features are available
    if features:
        # Add feature count row
        table.add_row("Available Features", f"{len(features)} features")
    
    # Display the license information table
    console.print(table)
    
    # Display feature list
    # Check if features are available
    if features:
        # Print feature list header
        console.print("\n[bold]Available Features:[/bold]")
        # Iterate through each feature in sorted order
        for feature in sorted(features):
            # Display feature with bullet point
            console.print(f"  • {feature}")
    
    # Display upgrade prompt if free tier
    # Check if user is on free tier
    if info['tier'] == 'free':
        # Show beta access promotion
        console.print("\n[yellow]💡 Get Beta Access (Free for 90 days):[/yellow]")
        # List beta features
        console.print("  • Deep mode (90% recall)")
        console.print("  • AI validation (reduce false positives)")
        console.print("  • Compliance reports")
        console.print("  • SCA scanning")
        # Show installation command (deprecated email method)
        console.print(f"\n[cyan]Run: parry license --install beta --email your@email.com[/cyan]")
        # Show upgrade link
        console.print(f"[dim]or visit https://parry.dev to upgrade[/dim]")
    
    # Display beta expiration notice
    # Check if user is on beta tier
    elif info['tier'] == 'beta':
        # Show beta access information
        console.print("\n[yellow]📅 Beta Access[/yellow]")
        # Explain beta access duration
        console.print("  • You have access to all Pro features for 90 days")
        # Encourage feedback for extension
        console.print("  • Provide feedback to extend your beta access")
        # Show contact email
        console.print("\n[cyan]Questions? Email: beta@parry.ai[/cyan]")


@main.command()  # Register 'renew' as a subcommand
@click.option("--feedback", "-f", help="Feedback for renewal request")  # Feedback text option
def renew(feedback):
    """
    Request beta license renewal.
    
    This command allows beta users to request an extension of their
    beta access period by providing feedback about their experience
    using Parry. Renewal is only available within 30 days of license
    expiration.
    
    Provide detailed feedback about your experience to extend your beta access.
    
    Args:
        feedback: Optional feedback text (can also be entered interactively)
    """
    # Import datetime for date calculations
    from datetime import datetime, timedelta
    # Import license configuration
    from parry.license import LicenseConfig
    # Import JSON parser
    import json
    
    # Check if user has beta license
    # Get current license tier
    tier = LicenseManager.get_tier()
    # Check if tier is beta
    if tier != 'beta':
        # Only beta licenses can be renewed
        console.print("[red]Renewal only available for beta licenses[/red]")
        # Show current tier
        console.print(f"Current tier: {tier}")
        # Exit function
        return
    
    # Get current license
    # Check if license file exists
    if not LicenseConfig.LICENSE_FILE.exists():
        # No license found
        console.print("[red]No license found[/red]")
        # Exit function
        return
    
    try:
        # Open license file
        with open(LicenseConfig.LICENSE_FILE, 'r') as f:
            # Parse license JSON data
            license_data = json.load(f)
        
        # Check expiration
        # Get expiration date from license
        expires = datetime.fromisoformat(license_data.get('expires', ''))
        # Calculate days until expiration
        days_left = (expires - datetime.now()).days
        
        # Can only renew within 30 days of expiration
        # Check if more than 30 days remaining
        if days_left > 30:
            # Too early to renew
            console.print(f"[yellow]Your beta license is valid for {days_left} more days[/yellow]")
            # Show renewal window information
            console.print("[dim]You can request renewal within 30 days of expiration[/dim]")
            # Exit function
            return
        
        # Get feedback
        # Check if feedback was provided via command line
        if not feedback:
            # No feedback provided, prompt interactively
            console.print("\n[yellow]Please provide feedback to support your renewal request:[/yellow]")
            # Show instructions
            console.print("[dim]Tell us about your experience using Parry[/dim]")
            # Show example feedback topics
            console.print("  • What vulnerabilities did you find?\n  • Any bugs or issues?\n  • What features do you like most?\n  • Suggestions for improvement?\n")
            
            # Collect feedback lines
            feedback_lines = []
            # Loop to collect multi-line feedback
            while True:
                # Read one line of input
                line = input("> ")
                # Check if user is done (empty line or 'done')
                if not line or line.lower() == 'done':
                    # Exit feedback collection
                    break
                # Add line to feedback list
                feedback_lines.append(line)
            
            # Join all feedback lines into single string
            feedback = '\n'.join(feedback_lines)
        
        # Validate feedback length
        # Check if feedback is too short
        if not feedback or len(feedback.strip()) < 20:
            # Feedback must be substantive
            console.print("[red]Feedback must be at least 20 characters[/red]")
            # Exit function
            return
        
        # Submit renewal request
        # Create FeedbackManager instance
        manager = FeedbackManager()
        # Submit the renewal request with user email and feedback
        result = manager.submit_renewal_request(
            email=license_data.get('email', 'unknown'),  # User's email from license
            feedback=feedback,  # User's feedback text
            metadata={'days_left': days_left}  # Additional context (days until expiration)
        )
        
        # Display results
        # Show success message
        console.print("\n[green]✓ Renewal request submitted![/green]")
        # Explain review timeline
        console.print("[dim]We'll review your feedback within 24 hours[/dim]")
        
        # Check if GitHub issue was created
        if result.get('github_issue'):
            # Show link to GitHub issue
            console.print(f"\n[yellow]View request: {result['github_issue']}[/yellow]")
        else:
            # Fallback if GitHub integration unavailable
            console.print("\n[yellow]📧 Email your feedback to: beta@parry.ai[/yellow]")
            # Confirm request was logged
            console.print("[dim]Your renewal request has been logged for review[/dim]")
        
        # Save confirmation
        # Get submission ID from result
        submission_id = result.get('submission_id')
        # Check if submission ID exists
        if submission_id:
            # Display submission ID for reference
            console.print(f"\n[dim]Submission ID: {submission_id}[/dim]")
        
    # Catch any errors during renewal process
    except Exception as e:
        # Display error message
        console.print(f"[red]Error: {e}[/red]")


@main.command()  # Register 'feedback' as a subcommand
@click.argument("message")  # Required feedback message argument
@click.option("--type", "-t", type=click.Choice(["bug", "feature", "general"]),  # Feedback type
              default="general", help="Type of feedback")  # Default to general
@click.option("--email", help="Your email (optional)")  # Optional email for follow-up
def feedback(message, type, email):
    """
    Submit feedback (bugs, features, suggestions).
    
    This command allows users to submit feedback about Parry directly
    from the command line. Feedback is sent to the developers and helps
    improve the tool.
    
    Examples:
        parry feedback "Found a false positive in SQL detection" --type bug
        parry feedback "Would love to see Go support" --type feature
        parry feedback "Great tool!" --type general
    
    Args:
        message: The feedback message text
        type: Category of feedback (bug/feature/general)
        email: Optional email address for follow-up
    """
    # Import feedback submission function
    from parry.feedback import submit_beta_feedback
    
    # Get email from license if not provided
    # Check if email was not provided
    if not email:
        try:
            # Import license configuration
            from parry.license import LicenseConfig
            # Check if license file exists
            if LicenseConfig.LICENSE_FILE.exists():
                # Open license file
                with open(LicenseConfig.LICENSE_FILE, 'r') as f:
                    # Parse license data
                    license_data = json.load(f)
                    # Get email from license
                    email = license_data.get('email', 'anonymous')
        except:
            # Failed to get email from license, use anonymous
            email = 'anonymous'
    
    # Submit feedback
    # Send feedback to server
    result = submit_beta_feedback(email, message, type)
    
    # Check if submission was successful
    if result.get('success'):
        # Display success message
        console.print(f"[green]✓ Feedback submitted![/green]")
        # Show feedback type
        console.print(f"[dim]Type: {type}[/dim]")
        
        # Check if GitHub issue was created
        if result.get('github_issue'):
            # Show link to GitHub issue
            console.print(f"\n[yellow]View: {result['github_issue']}[/yellow]")
        else:
            # Fallback thank you message
            console.print("\n[dim]Thank you for helping improve Parry![/dim]")
    else:
        # Submission failed
        console.print("[red]Failed to submit feedback[/red]")


@main.command()  # Register 'list-feedback' as a subcommand
@click.option("--source", type=click.Choice(["local", "github", "all"]),  # Feedback source filter
              default="local", help="Feedback source to view")  # Default to local
def list_feedback(source):
    """
    List pending feedback and renewal requests (admin view).
    
    This command is for administrators to review pending feedback
    and renewal requests from beta users. It can show local submissions
    stored on this machine, or integrate with GitHub Issues if configured.
    
    Shows all pending submissions for review.
    
    Sources:
        local   - Local files on this machine only
        github  - GitHub Issues from all users (optional, requires repo access)
        all     - Both local and GitHub
    
    Args:
        source: Where to fetch feedback from (local/github/all)
    """
    # Import feedback management functionality
    from parry.feedback import FeedbackManager
    
    # Create FeedbackManager instance
    manager = FeedbackManager()
    # Initialize list to collect all renewal requests
    all_renewals = []
    
    # Get local feedback
    # Check if local source requested
    if source in ["local", "all"]:
        # Retrieve renewal requests from local storage
        local_renewals = manager.get_pending_renewals()
        # Add local renewals to combined list
        all_renewals.extend(local_renewals)
    
    # Get GitHub feedback if requested and available
    # Check if GitHub source requested
    if source in ["github", "all"]:
        try:
            # Attempt to fetch renewals from GitHub Issues
            github_renewals = manager.get_renewals_from_github()
            # Add GitHub renewals to combined list
            all_renewals.extend(github_renewals)
        # Catch errors accessing GitHub
        except Exception as e:
            # Only error if GitHub was specifically requested
            if source == "github":
                # Show GitHub unavailable warning
                console.print("[yellow]GitHub integration not available[/yellow]")
                # Show error details
                console.print(f"[dim]Error: {e}[/dim]")
                # Show setup instructions
                console.print("\n[dim]To enable GitHub integration:[/dim]")
                console.print("[cyan]  export GITHUB_TOKEN=your_token_here[/cyan]")
                # Exit function
                return
            # If "all", just show local (GitHub failed but continue)
    
    # Check if any renewal requests found
    if not all_renewals:
        # No pending requests
        console.print("[dim]No pending renewal requests[/dim]")
        
        # Show additional tips for local source
        if source == "local":
            # Show tip about user submission
            console.print("\n[yellow]💡 Tip: [/yellow]")
            console.print("Users submit via 'parry renew' or 'parry feedback'")
            console.print("Feedback is stored locally on each user's machine")
            
            # Show admin access instructions
            console.print("\n[yellow]📧 Admin Access:[/yellow]")
            console.print("[cyan]  Check email: beta@parry.ai[/cyan]")
            console.print("[dim]  Users should email their feedback/renewal requests[/dim]")
        
        # Exit function
        return
    
    # Display renewal requests
    # Show header with count
    console.print(f"\n[bold]Pending Renewal Requests: {len(all_renewals)}[/bold]")
    
    # Show source breakdown if viewing all
    if source == "all":
        # Count local requests
        local_count = len(manager.get_pending_renewals())
        # Show local vs GitHub breakdown
        console.print(f"[dim]({local_count} local, {len(all_renewals) - local_count} from GitHub)[/dim]")
    
    # Add spacing before list
    console.print()
    
    # Create table for displaying renewal requests
    table = Table()
    # Add column for request number
    table.add_column("#", style="cyan")
    # Add column for user email
    table.add_column("Email", style="white")
    # Add column for days left until expiration
    table.add_column("Days Left", style="yellow")
    # Add column for request source (local/github)
    table.add_column("Source", style="dim")
    # Add column for feedback preview
    table.add_column("Feedback Preview", style="dim")
    
    # Iterate through all renewal requests
    for i, renewal in enumerate(all_renewals, 1):
        # Get user email from renewal request
        email = renewal.get('email', 'unknown')
        # Get feedback text and truncate to 60 characters
        feedback_text = renewal.get('feedback', '')[:60]
        # Get days left from metadata
        days_left = renewal.get('metadata', {}).get('days_left', 'unknown')
        # Get source of renewal request
        renewals_source = renewal.get('source', 'local')
        
        # Add row to table with renewal data
        table.add_row(str(i), email, str(days_left), renewals_source, feedback_text)
    
    # Display the table
    console.print(table)
    
    # Show renewal instructions
    # Show instructions header
    console.print("\n[yellow]📝 To extend a license:[/yellow]")
    # Step 1: review feedback
    console.print("[dim]  1. Review feedback quality[/dim]")
    # Step 2: check usage metrics
    console.print("[dim]  2. Check usage metrics[/dim]")
    # Step 3: generate token
    console.print("[cyan]  3. Generate token: parry admin generate-token --email user@example.com[/cyan]")


@main.command()  # Register 'admin' as a subcommand
@click.argument("command")  # Required command argument
@click.option("--email", help="Email for token generation")  # Email for token recipient
@click.option("--days", type=int, default=90, help="Days until expiration (default: 90)")  # Token validity period
def admin(command, email, days):
    """
    Admin commands for managing beta licenses.
    
    This command provides administrative functions for managing beta
    licenses, including generating secure tokens for users and listing
    all issued tokens for tracking purposes.
    
    Commands:
        generate-token    Generate a beta token for a user
        list-tokens       List all issued tokens
    
    Examples:
        parry admin generate-token --email user@example.com
        parry admin generate-token --email user@example.com --days 60
        parry admin list-tokens
    
    Args:
        command: Admin command to execute (generate-token/list-tokens)
        email: User email for token generation
        days: Number of days token should be valid
    """
    # Check if command is generate-token
    if command == 'generate-token':
        # Validate email was provided
        if not email:
            # Show error for missing email
            console.print("[red]Error: Email required[/red]")
            # Show usage instructions
            console.print("Usage: parry admin generate-token --email user@example.com")
            # Exit function
            return
        
        # Import beta token manager
        from parry.beta_token import BetaTokenManager
        
        # Display token generation header
        console.print(f"\n[bold]Generating beta token for:[/bold] [cyan]{email}[/cyan]")
        # Show token duration
        console.print(f"[dim]Duration: {days} days[/dim]\n")
        
        # Generate the beta token
        token = BetaTokenManager.generate_token(email=email, days=days)
        
        # Display success message
        console.print("[green]✓ Beta token generated![/green]\n")
        # Show token label
        console.print(f"[bold]Token:[/bold]")
        # Display the generated token
        console.print(f"[cyan]{token}[/cyan]\n")
        # Show security warning
        console.print("[yellow]⚠️  SEND THIS TOKEN TO USER SECURELY[/yellow]")
        # Show installation instructions for user
        console.print("[dim]User installs with: parry license --install beta --token {token}[/dim]")
    
    # Check if command is list-tokens
    elif command == 'list-tokens':
        # Import beta token manager
        from parry.beta_token import BetaTokenManager
        
        # Get all issued tokens
        tokens = BetaTokenManager.list_issued_tokens()
        
        # Check if any tokens exist
        if not tokens:
            # No tokens issued yet
            console.print("[dim]No tokens issued yet[/dim]")
            # Exit function
            return
        
        # Display header with token count
        console.print(f"\n[bold]Issued Beta Tokens: {len(tokens)}[/bold]\n")
        
        # Create table for token list
        table = Table()
        # Add column for user email
        table.add_column("Email", style="white")
        # Add column for issuance date
        table.add_column("Issued", style="dim")
        # Add column for expiration date
        table.add_column("Expires", style="dim")
        # Add column for admin who issued token
        table.add_column("Issued By", style="dim")
        
        # Iterate through all tokens
        for token_hash, token_data in tokens.items():
            # Add row with token information
            table.add_row(
                token_data.get('email', 'unknown'),  # User email
                token_data.get('issued', 'unknown'),  # Issuance date
                token_data.get('expires', 'unknown'),  # Expiration date
                token_data.get('issued_by', 'unknown')  # Issuing admin
            )
        
        # Display the tokens table
        console.print(table)
    
    else:
        # Unknown command
        # Show error message
        console.print(f"[red]Unknown admin command: {command}[/red]")
        # Show available commands
        console.print("\nAvailable commands:")
        console.print("  generate-token    Generate a beta token")
        console.print("  list-tokens       List all issued tokens")


@main.command()
@click.option("--tier", type=click.Choice(["pro", "enterprise"]), required=True,
              help="Subscription tier to purchase")
@click.option("--billing", type=click.Choice(["monthly", "yearly"]), default="monthly",
              help="Billing cycle")
@click.option("--email", prompt="Email address", help="Customer email")
def subscribe(tier: str, billing: str, email: str):
    """
    🚀 Subscribe to Parry Pro or Enterprise
    
    Opens Stripe checkout to complete payment and receive license key.
    
    Tiers:
    - Pro ($49/month): Hosted LLM, IDE extensions, unlimited files
    - Enterprise ($299/month): Everything + API, SSO, on-premise
    """
    from parry.payment import PaymentConfig
    
    # Display tier information
    tier_info = PaymentConfig.TIERS[tier]
    price = tier_info.price_monthly if billing == 'monthly' else tier_info.price_yearly
    price_display = f"${price / 100:.2f}/{billing}"
    
    console.print(Panel(
        f"[bold]{tier_info.name} Subscription[/bold]\n\n"
        f"[cyan]Price: {price_display}[/cyan]\n\n"
        f"[green]Features:[/green]\n" + 
        "\n".join([f"  • {feat}" for feat in tier_info.features]),
        title="📦 Subscription Details",
        border_style="cyan"
    ))
    
    # Create checkout session
    with console.status("[bold cyan]Creating checkout session..."):
        try:
            payment_manager = StripePaymentManager()
            session = payment_manager.create_checkout_session(
                tier=tier,
                billing_cycle=billing,
                customer_email=email,
                success_url="https://parry.dev/success",
                cancel_url="https://parry.dev/cancel",
                metadata={
                    'cli_version': '3.0.0',
                    'platform': sys.platform
                }
            )
            
            checkout_url = session['url']
            
            console.print("\n[bold green]✓ Checkout session created![/bold green]\n")
            console.print(f"[cyan]Open this URL to complete payment:[/cyan]\n{checkout_url}\n")
            console.print("[dim]After payment, you'll receive your license key via email.[/dim]")
            
            # Optionally open browser
            if click.confirm("Open browser now?"):
                import webbrowser
                webbrowser.open(checkout_url)
                
        except Exception as e:
            console.print(f"[red]Error creating checkout: {e}[/red]")
            sys.exit(1)


@main.command()
@click.argument("license_key")
def activate(license_key: str):
    """
    🔑 Activate Parry license
    
    Install license key received after subscription purchase.
    """
    with console.status("[bold cyan]Validating license..."):
        license_manager = LicenseManager()
        
        if license_manager.install_license(license_key):
            # Get license info
            license_info = license_manager.validate_license()
            
            console.print("\n[bold green]✓ License activated successfully![/bold green]\n")
            console.print(Panel(
                f"[cyan]Tier: {license_info['tier'].upper()}[/cyan]\n"
                f"[cyan]LLM Mode: {license_info['llm_mode']}[/cyan]\n"
                f"[cyan]File Limit: {license_info['file_limit'] or 'Unlimited'}[/cyan]\n\n"
                f"[green]Features:[/green]\n" +
                "\n".join([f"  • {feat}" for feat in license_info['features']]),
                title="📜 License Details",
                border_style="green"
            ))
        else:
            console.print("[red]✗ License activation failed![/red]")
            console.print("[dim]Please check your license key and try again.[/dim]")
            sys.exit(1)


@main.command()
def license_info():
    """
    📜 Display current license information
    
    Shows active subscription tier, features, and expiration.
    """
    license_manager = LicenseManager()
    license_info = license_manager.validate_license()
    
    if not license_info['valid'] and license_info['tier'] == 'free':
        console.print(Panel(
            "[yellow]No active subscription[/yellow]\n\n"
            "[dim]You're using the Free tier with:[/dim]\n"
            "  • CLI tool with local Ollama\n"
            "  • Basic security detectors (30+)\n"
            "  • Fast mode scanning\n"
            "  • 100 file limit\n\n"
            "[cyan]Upgrade to Pro for:[/cyan]\n"
            "  • Hosted LLM (no setup)\n"
            "  • IDE extensions\n"
            "  • GitHub Actions\n"
            "  • All detectors (150+)\n"
            "  • Unlimited files\n\n"
            "[bold]Run: parry subscribe --tier pro[/bold]",
            title="📜 License Information",
            border_style="yellow"
        ))
    else:
        # Display active license
        tier_name = license_info['tier'].upper()
        expires = license_info.get('expires')
        expires_str = "Never" if not expires else datetime.fromtimestamp(expires).strftime('%Y-%m-%d')
        
        console.print(Panel(
            f"[bold green]{tier_name} Subscription[/bold green]\n\n"
            f"[cyan]Status: {'Active' if license_info['valid'] else 'Expired'}[/cyan]\n"
            f"[cyan]LLM Mode: {license_info['llm_mode']}[/cyan]\n"
            f"[cyan]File Limit: {license_info['file_limit'] or 'Unlimited'}[/cyan]\n"
            f"[cyan]Expires: {expires_str}[/cyan]\n\n"
            f"[green]Features:[/green]\n" +
            "\n".join([f"  • {feat}" for feat in license_info['features']]),
            title="📜 License Information",
            border_style="green"
        ))


@main.command()
def pricing():
    """
    💰 Display Parry pricing tiers
    
    Shows detailed pricing and features for all subscription tiers.
    """
    tiers = PaymentConfig.TIERS
    
    console.print("\n[bold cyan]Parry Security Scanner - Pricing[/bold cyan]\n")
    
    # Free tier
    free = tiers['free']
    console.print(Panel(
        f"[bold]{free.name}[/bold] - [green]$0/month[/green]\n\n" +
        "\n".join([f"  • {feat}" for feat in free.features]) +
        f"\n\n[dim]File Limit: {free.file_limit} files[/dim]",
        border_style="green"
    ))
    
    # Pro tier
    pro = tiers['pro']
    monthly = f"${pro.price_monthly / 100:.0f}"
    yearly = f"${pro.price_yearly / 100:.0f}"
    console.print(Panel(
        f"[bold]{pro.name}[/bold] - [cyan]{monthly}/month or {yearly}/year[/cyan]\n\n" +
        "\n".join([f"  • {feat}" for feat in pro.features]) +
        "\n\n[dim]No file limits, hosted LLM[/dim]",
        border_style="cyan"
    ))
    
    # Enterprise tier
    ent = tiers['enterprise']
    monthly = f"${ent.price_monthly / 100:.0f}"
    yearly = f"${ent.price_yearly / 100:.0f}"
    console.print(Panel(
        f"[bold]{ent.name}[/bold] - [yellow]{monthly}/month or {yearly}/year[/yellow]\n\n" +
        "\n".join([f"  • {feat}" for feat in ent.features]) +
        "\n\n[dim]Everything + API, SSO, on-premise[/dim]",
        border_style="yellow"
    ))
    
    console.print("\n[bold]To subscribe:[/bold] parry subscribe --tier <pro|enterprise>\n")


@main.command(name="ask")
@click.argument("path", type=click.Path(exists=True))
@click.option("--line", type=int, help="Single line number to analyze")
@click.option("--lines", help="Line range to analyze (e.g., '10-20')")
@click.option("--context", type=int, default=3, help="Lines of context around selection")
def ask_llm(path: str, line: int, lines: str, context: int):
    """
    🤖 Ask LLM to analyze specific code for security issues
    
    This command allows you to highlight specific lines and directly query the LLM
    for security analysis, bypassing automated pattern detection.
    
    Requires Pro or Enterprise tier (hosted LLM).
    
    Examples:
        parry ask myfile.py --line 42
        parry ask myfile.py --lines 10-20
        parry ask myfile.py --line 15 --context 5
    """
    from pathlib import Path
    import os
    
    # Check license
    license_mgr = LicenseManager()
    license_info = license_mgr.load_license()
    
    if not license_info or license_info.get('tier') == 'free':
        console.print("[red]❌ Direct LLM queries require Pro or Enterprise tier (hosted LLM)[/red]")
        console.print("\n[yellow]Subscribe to Pro or Enterprise:[/yellow]")
        console.print("  parry subscribe --tier pro")
        return
    
    file_path = Path(path)
    
    if not file_path.is_file():
        console.print(f"[red]Error: {path} is not a file[/red]")
        return
    
    # Read file
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        return
    
    # Determine lines to analyze
    if lines:
        # Parse range like "10-20"
        try:
            start, end = map(int, lines.split('-'))
            start_line = start - 1  # Convert to 0-indexed
            end_line = end - 1
        except ValueError:
            console.print("[red]Error: --lines must be in format 'START-END' (e.g., '10-20')[/red]")
            return
    elif line:
        # Single line with context
        start_line = max(0, line - 1 - context)
        end_line = min(len(all_lines) - 1, line - 1 + context)
    else:
        console.print("[red]Error: Must specify either --line or --lines[/red]")
        return
    
    # Extract code
    code_lines = all_lines[start_line:end_line + 1]
    code = ''.join(code_lines)
    
    # Detect language
    extension = file_path.suffix.lstrip('.')
    language_map = {
        'py': 'python', 'js': 'javascript', 'ts': 'typescript',
        'java': 'java', 'go': 'go', 'rs': 'rust', 'rb': 'ruby',
        'php': 'php', 'cpp': 'c++', 'c': 'c', 'cs': 'c#'
    }
    language = language_map.get(extension, extension)
    
    # Display code being analyzed
    console.print(f"\n[bold cyan]Analyzing {file_path.name}[/bold cyan]")
    console.print(f"[dim]Lines {start_line + 1}-{end_line + 1} ({language})[/dim]\n")
    
    console.print("[bold]Code:[/bold]")
    console.print("─" * 80)
    for i, line_text in enumerate(code_lines):
        line_num = start_line + i + 1
        console.print(f"[dim]{line_num:4d}[/dim] │ {line_text}", end='')
    console.print("─" * 80)
    
    # Query LLM
    console.print("\n[yellow]Querying LLM for security analysis...[/yellow]\n")
    
    try:
        # Import LLM client
        from parry.llm import LLMClient
        
        llm_client = LLMClient()
        
        # Construct prompt
        prompt = f"""You are an expert security analyst. Analyze the following code for security vulnerabilities.

File: {file_path.name}
Language: {language}
Lines: {start_line + 1}-{end_line + 1}

Focus on:
- Injection attacks (SQL, command, code, XSS)
- Authentication and authorization issues
- Cryptographic problems
- Access control flaws
- Data exposure and privacy issues
- Insecure configurations
- Race conditions
- Logic errors with security implications

CODE:
```{language}
{code}
```

Provide:
1. A summary of security findings
2. For each issue found:
   - Title and severity (Critical/High/Medium/Low)
   - Description of the vulnerability
   - Specific line numbers
   - Recommendation for fixing

If no obvious issues are found, explain what security aspects look acceptable.
"""
        
        # Get LLM response
        response = llm_client.chat(prompt)
        
        # Display results
        console.print("[bold green]LLM Security Analysis:[/bold green]")
        console.print("═" * 80)
        console.print(response)
        console.print("═" * 80)
        
        console.print(f"\n[dim]Analysis completed using {llm_client.model}[/dim]")
        
    except ImportError:
        console.print("[red]Error: LLM client not available. Check installation.[/red]")
    except Exception as e:
        console.print(f"[red]Error querying LLM: {e}[/red]")


@main.command(name='compliance-report')  # Register 'compliance-report' as a subcommand
@click.argument("path", type=click.Path(exists=True))  # Path to scan
@click.option("--standard", "-s", 
              type=click.Choice(["soc2", "iso27001", "pci-dss", "owasp", "all"]),
              multiple=True,
              default=["all"],
              help="Compliance standards to check (can specify multiple)")
@click.option("--format", "-f",
              type=click.Choice(["json", "markdown", "pdf", "html"]),
              default="pdf",
              help="Output format for the report")
@click.option("--output", "-o",
              type=click.Path(),
              help="Output file path (if not specified, prints to stdout or saves as compliance_report.<format>)")
@click.option("--company-name", "-c",
              default="Your Company",
              help="Company name for report branding (PDF/HTML only)")
@click.option("--logo",
              type=click.Path(exists=True),
              help="Path to company logo image (PDF only)")
@click.option("--severity", 
              type=click.Choice(["low", "medium", "high", "critical"]),
              help="Minimum severity level to include in report")
def compliance_report(path: str, 
                     standard: tuple, 
                     format: str, 
                     output: Optional[str],
                     company_name: str,
                     logo: Optional[str],
                     severity: Optional[str]):
    """
    Generate compliance reports for security audits
    
    Scans the specified path and generates a compliance report for one or more
    security standards (SOC2, ISO 27001, PCI-DSS, OWASP Top 10).
    
    This feature is available for Pro and Business tier users only.
    
    Examples:
        parry compliance-report ./src --standard soc2 --format pdf
        
        parry compliance-report ./app --standard soc2 --standard owasp -o report.pdf
        
        parry compliance-report ./backend --standard all --company-name "Acme Corp"
    """
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from pathlib import Path
    from parry.compliance import ComplianceReporter
    from parry.scanner import scan_directory
    
    console = Console()
    
    # Check license tier (Pro or Business only)
    try:
        from parry.beta_token import BetaTokenManager
        token_manager = BetaTokenManager()
        license_info = token_manager.get_license_info()
        
        if license_info:
            tier = license_info.get('tier', 'free').lower()
            if tier not in ['pro', 'business']:
                console.print(
                    "[red]❌ Compliance reporting is only available for Pro and Business tiers.[/red]\n"
                    f"[yellow]Current tier: {tier}[/yellow]\n\n"
                    "Upgrade your license to access this feature:\n"
                    "  parry license --tier pro\n"
                )
                return
        else:
            console.print(
                "[yellow]⚠️  No active license found. Compliance reporting requires Pro or Business tier.[/yellow]\n\n"
                "Get a license to access this feature:\n"
                "  parry license --tier pro\n"
            )
            return
    except Exception as e:
        console.print(f"[yellow]Warning: Could not verify license: {e}[/yellow]")
        console.print("[yellow]Continuing anyway (development mode)...[/yellow]\n")
    
    # Convert standards
    standards_list = list(standard)
    if "all" in standards_list:
        standards_list = ["soc2", "iso27001", "pci-dss", "owasp"]
    
    console.print("[bold cyan]🔒 Parry Compliance Report Generator[/bold cyan]\n")
    console.print(f"[dim]Scanning:[/dim] {path}")
    console.print(f"[dim]Standards:[/dim] {', '.join(s.upper() for s in standards_list)}")
    console.print(f"[dim]Format:[/dim] {format}\n")
    
    # Step 1: Scan the codebase
    console.print("[bold]Step 1: Scanning codebase for vulnerabilities...[/bold]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        scan_task = progress.add_task("Analyzing code...", total=None)
        
        try:
            vulnerabilities = scan_directory(path)
            progress.update(scan_task, completed=True)
        except Exception as e:
            console.print(f"[red]Error scanning directory: {e}[/red]")
            return
    
    # Filter by severity if specified
    if severity:
        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        min_level = severity_order.get(severity, 0)
        vulnerabilities = [
            v for v in vulnerabilities 
            if severity_order.get(v.severity, 0) >= min_level
        ]
    
    console.print(f"[green]✓[/green] Found {len(vulnerabilities)} vulnerabilities\n")
    
    # Step 2: Generate compliance reports
    console.print("[bold]Step 2: Generating compliance reports...[/bold]")
    
    try:
        reporter = ComplianceReporter()
        reports = reporter.generate_report(vulnerabilities, standards=standards_list)
    except Exception as e:
        console.print(f"[red]Error generating compliance reports: {e}[/red]")
        return
    
    # Display summary
    console.print("\n[bold]Compliance Summary:[/bold]")
    for std_key, std_report in reports.items():
        if std_key == 'summary':
            continue
        
        std_name = std_report.get('standard', std_key.upper())
        score = std_report.get('compliance_score', 0)
        status = std_report.get('overall_status', 'UNKNOWN')
        
        # Color code based on score
        if score >= 90:
            color = "green"
            emoji = "✓"
        elif score >= 70:
            color = "yellow"
            emoji = "⚠"
        else:
            color = "red"
            emoji = "✗"
        
        console.print(f"  [{color}]{emoji} {std_name}: {score:.1f}% ({status})[/{color}]")
    
    console.print()
    
    # Step 3: Export report
    console.print("[bold]Step 3: Exporting report...[/bold]")
    
    # Determine output path
    if output:
        output_path = Path(output)
    else:
        if format == "json":
            output_path = Path(f"compliance_report.json")
        elif format == "markdown":
            output_path = Path(f"compliance_report.md")
        elif format == "pdf":
            output_path = Path(f"compliance_report.pdf")
        elif format == "html":
            output_path = Path(f"compliance_report.html")
    
    try:
        if format == "json":
            reporter.export_to_json(reports, output_path)
        
        elif format == "markdown":
            md_content = reporter.generate_markdown_report(reports)
            with open(output_path, 'w') as f:
                f.write(md_content)
        
        elif format == "pdf":
            # Check if reportlab is available
            try:
                logo_path = Path(logo) if logo else None
                reporter.export_to_pdf(
                    reports, 
                    output_path,
                    company_name=company_name,
                    logo_path=logo_path
                )
            except ImportError:
                console.print(
                    "[red]PDF export requires reportlab library.[/red]\n"
                    "Install with: pip install reportlab\n"
                )
                return
        
        elif format == "html":
            # TODO: Implement HTML export in future
            console.print(
                "[yellow]HTML export is not yet implemented.[/yellow]\n"
                "Use --format pdf or --format markdown instead.\n"
            )
            return
        
        console.print(f"[green]✓ Report saved to:[/green] {output_path}")
        console.print(f"\n[dim]Full path:[/dim] {output_path.absolute()}\n")
        
    except Exception as e:
        console.print(f"[red]Error exporting report: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return
    
    # Final summary
    summary = reports.get('summary', {})
    total_vulns = summary.get('total_vulnerabilities', 0)
    by_severity = summary.get('by_severity', {})
    
    console.print("[bold]Report Generated Successfully![/bold]")
    console.print(f"Total Vulnerabilities: {total_vulns}")
    console.print(f"  • Critical: {by_severity.get('critical', 0)}")
    console.print(f"  • High: {by_severity.get('high', 0)}")
    console.print(f"  • Medium: {by_severity.get('medium', 0)}")
    console.print(f"  • Low: {by_severity.get('low', 0)}")


# Main entry point
# Check if script is run directly
if __name__ == "__main__":
    # Execute the main CLI group
    main()


