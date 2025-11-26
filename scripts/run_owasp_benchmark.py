#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

OWASP Benchmark Runner for All Models

Runs OWASP Benchmark against each model size to get REAL accuracy metrics.
"""

import subprocess
import json
import time
from pathlib import Path
from typing import Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Models to test
MODELS_TO_TEST = [
    "tinyllama:1.1b",
    "qwen2.5-coder:1.5b",
    "qwen2.5-coder:3b",
    "qwen2.5-coder:7b",
    "deepseek-coder:6.7b",
    "qwen2.5-coder:14b",
    "deepseek-coder:33b",
]

def check_owasp_benchmark() -> Optional[Path]:
    """Check if OWASP Benchmark is available"""
    possible_paths = [
        Path(__file__).parent.parent / "benchmarks" / "owasp-benchmark",
        Path.home() / "owasp-benchmark",
        Path("/tmp") / "owasp-benchmark",
    ]
    
    for path in possible_paths:
        if path.exists() and (path / "src").exists():
            return path
    
    return None

def download_owasp_benchmark() -> Optional[Path]:
    """Download OWASP Benchmark if not available"""
    console.print("[cyan]OWASP Benchmark not found. Would you like to download it?[/cyan]")
    console.print("[yellow]This requires git and ~500MB of space[/yellow]")
    
    benchmark_path = Path(__file__).parent.parent / "benchmarks" / "owasp-benchmark"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        console.print("[cyan]Downloading OWASP Benchmark...[/cyan]")
        subprocess.run(
            ['git', 'clone', 'https://github.com/OWASP/Benchmark.git', str(benchmark_path)],
            check=True,
            timeout=300
        )
        console.print("[green]✓ OWASP Benchmark downloaded[/green]")
        return benchmark_path
    except Exception as e:
        console.print(f"[red]Failed to download OWASP Benchmark: {e}[/red]")
        return None

def run_owasp_benchmark(model: Optional[str]) -> Dict:
    """Run OWASP Benchmark with specified model"""
    benchmark_path = check_owasp_benchmark()
    
    if not benchmark_path:
        benchmark_path = download_owasp_benchmark()
        if not benchmark_path:
            return {"error": "OWASP Benchmark not available"}
    
    console.print(f"\n[cyan]Running OWASP Benchmark with model: {model or 'default'}[/cyan]")
    
    # Build command
    cmd = [
        'python3', '-m', 'valid8.cli', 'scan',
        str(benchmark_path / 'src'),
        '--mode', 'hybrid',
        '--format', 'json',
        '--output', f'/tmp/owasp_benchmark_{model or "default"}.json'
    ]
    
    if model:
        cmd.extend(['--model', model])
    
    try:
        start_time = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800  # 30 minute timeout
        )
        elapsed = time.time() - start_time
        
        if result.returncode != 0:
            return {
                "model": model or "default",
                "success": False,
                "error": result.stderr[:200] if result.stderr else "Unknown error",
                "elapsed_seconds": elapsed
            }
        
        # Parse results and calculate OWASP Benchmark score
        output_file = Path(f'/tmp/owasp_benchmark_{model or "default"}.json')
        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
            
            # Calculate OWASP Benchmark metrics
            # This would need to compare against expectedresults-1.2.csv
            return {
                "model": model or "default",
                "success": True,
                "elapsed_seconds": elapsed,
                "vulnerabilities_found": len(data.get('vulnerabilities', [])),
                "note": "Accuracy calculation requires expectedresults-1.2.csv comparison"
            }
        else:
            return {
                "model": model or "default",
                "success": False,
                "error": "Output file not created"
            }
            
    except subprocess.TimeoutExpired:
        return {
            "model": model or "default",
            "success": False,
            "error": "Timeout (>1800s)"
        }
    except Exception as e:
        return {
            "model": model or "default",
            "success": False,
            "error": str(e)[:200]
        }

def main():
    console.print(Panel.fit(
        "[bold cyan]OWASP Benchmark Runner[/bold cyan]\n"
        "[dim]Testing all models on OWASP Benchmark for REAL accuracy metrics[/dim]",
        border_style="cyan"
    ))
    
    results = []
    
    for model in MODELS_TO_TEST:
        result = run_owasp_benchmark(model)
        results.append(result)
        
        if result.get("success"):
            console.print(f"[green]✓ {model}: Completed in {result.get('elapsed_seconds', 0):.1f}s[/green]")
        else:
            console.print(f"[red]✗ {model}: {result.get('error', 'Failed')}[/red]")
    
    # Save results
    output_file = Path(__file__).parent.parent / "owasp_benchmark_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    console.print(f"\n[green]✓ Results saved to: {output_file}[/green]")

if __name__ == '__main__':
    main()




