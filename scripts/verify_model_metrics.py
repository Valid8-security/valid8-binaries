#!/usr/bin/env python3
"""
Script to verify and test actual model performance metrics
Tests speed and accuracy for different model sizes
"""
import time
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Test codebase for benchmarking
TEST_CODEBASE = Path(__file__).parent.parent / "valid8"  # Use valid8 codebase itself

def count_files(directory: Path) -> int:
    """Count Python files in directory"""
    count = 0
    for ext in ['.py']:
        count += len(list(directory.rglob(f'*{ext}')))
    return count

def test_scan_speed(model: Optional[str] = None, mode: str = "hybrid") -> Dict:
    """Test actual scan speed"""
    console.print(f"\n[cyan]Testing scan speed (model: {model or 'default'}, mode: {mode})...[/cyan]")
    
    if not TEST_CODEBASE.exists():
        console.print(f"[yellow]Test codebase not found: {TEST_CODEBASE}[/yellow]")
        return {"error": "Test codebase not found"}
    
    file_count = count_files(TEST_CODEBASE)
    console.print(f"[dim]Scanning {file_count} Python files...[/dim]")
    
    # Build command
    cmd = ['python3', '-m', 'valid8.cli', 'scan', str(TEST_CODEBASE), '--mode', mode, '--format', 'json']
    if model:
        # Note: Model selection would need to be implemented in CLI
        pass
    
    try:
        start_time = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            files_per_sec = file_count / elapsed if elapsed > 0 else 0
            return {
                "success": True,
                "file_count": file_count,
                "elapsed_seconds": elapsed,
                "files_per_second": files_per_sec,
                "model": model or "default",
                "mode": mode
            }
        else:
            return {
                "success": False,
                "error": result.stderr[:200],
                "model": model or "default",
                "mode": mode
            }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Timeout (>300s)",
            "model": model or "default",
            "mode": mode
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)[:200],
            "model": model or "default",
            "mode": mode
        }

def test_owasp_benchmark() -> Dict:
    """Test against OWASP Benchmark if available"""
    console.print("\n[cyan]Testing OWASP Benchmark accuracy...[/cyan]")
    
    # Check if OWASP benchmark exists
    owasp_path = Path(__file__).parent.parent / "benchmarks" / "owasp-benchmark"
    
    if not owasp_path.exists():
        console.print("[yellow]OWASP Benchmark not found. Skipping accuracy test.[/yellow]")
        return {"error": "OWASP Benchmark not available"}
    
    # This would run actual OWASP benchmark test
    # For now, return placeholder
    return {
        "note": "OWASP benchmark test requires full benchmark setup",
        "status": "not_available"
    }

def main():
    console.print(Panel.fit(
        "[bold cyan]Valid8 Model Metrics Verification[/bold cyan]\n"
        "[dim]Testing actual performance vs claimed metrics[/dim]",
        border_style="cyan"
    ))
    
    results = {
        "speed_tests": [],
        "accuracy_tests": {},
        "test_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "test_codebase": str(TEST_CODEBASE),
        "file_count": count_files(TEST_CODEBASE) if TEST_CODEBASE.exists() else 0
    }
    
    # Test different modes
    for mode in ["fast", "hybrid", "deep"]:
        result = test_scan_speed(model=None, mode=mode)
        if result.get("success"):
            results["speed_tests"].append(result)
    
    # Test OWASP benchmark
    owasp_result = test_owasp_benchmark()
    results["accuracy_tests"]["owasp"] = owasp_result
    
    # Display results
    console.print("\n")
    console.print(Panel.fit(
        "[bold green]Test Results[/bold green]",
        border_style="green"
    ))
    
    if results["speed_tests"]:
        table = Table(title="Speed Test Results")
        table.add_column("Mode", style="cyan")
        table.add_column("Files", justify="right")
        table.add_column("Time (s)", justify="right")
        table.add_column("Files/Sec", justify="right", style="green")
        
        for test in results["speed_tests"]:
            table.add_row(
                test.get("mode", "unknown"),
                str(test.get("file_count", 0)),
                f"{test.get('elapsed_seconds', 0):.2f}",
                f"{test.get('files_per_second', 0):.1f}"
            )
        
        console.print(table)
    else:
        console.print("[yellow]No successful speed tests[/yellow]")
    
    # Save results
    output_file = Path(__file__).parent.parent / "verified_metrics.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    console.print(f"\n[dim]Results saved to: {output_file}[/dim]")
    
    # Compare to claimed metrics
    console.print("\n[bold]Comparison to Claimed Metrics:[/bold]")
    console.print("[yellow]⚠️  Note: Model-specific tests require model switching implementation[/yellow]")
    console.print("[yellow]⚠️  Current tests use default model configuration[/yellow]")

if __name__ == '__main__':
    main()




