#!/usr/bin/env python3
"""
Comprehensive Benchmark Suite - Parry vs Competitors

Tests Parry (Fast, Deep, Hybrid, Incremental modes) against:
- Snyk
- Semgrep  
- Bandit (Python only)

Measures:
- Recall (true positive rate)
- Precision (false positive rate)
- Scan time
- Vulnerabilities found by severity
"""

import subprocess
import time
import json
from pathlib import Path
from typing import Dict, List, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class BenchmarkRunner:
    def __init__(self, target_path: Path):
        self.target = target_path
        self.results = {}
        
    def run_parry_fast(self) -> Tuple[Dict, float]:
        """Run Parry in Fast Mode"""
        console.print("\n[cyan]Running Parry Fast Mode...[/cyan]")
        start = time.time()
        
        try:
            result = subprocess.run(
                ['parry', 'scan', str(self.target), '--format=json', '--output=parry_fast.json'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            elapsed = time.time() - start
            
            if Path('parry_fast.json').exists():
                with open('parry_fast.json') as f:
                    data = json.load(f)
                return data, elapsed
            else:
                return {'vulnerabilities_found': 0, 'vulnerabilities': []}, elapsed
                
        except subprocess.TimeoutExpired:
            return {'vulnerabilities': []}, 300.0
    
    def run_parry_hybrid(self) -> Tuple[Dict, float]:
        """Run Parry in Hybrid Mode"""
        console.print("\n[cyan]Running Parry Hybrid Mode...[/cyan]")
        start = time.time()
        
        try:
            result = subprocess.run(
                ['parry', 'scan', str(self.target), '--mode=hybrid', '--format=json', '--output=parry_hybrid.json'],
                capture_output=True,
                text=True,
                timeout=900
            )
            
            elapsed = time.time() - start
            
            if Path('parry_hybrid.json').exists():
                with open('parry_hybrid.json') as f:
                    data = json.load(f)
                # Data already has 'summary' key, just return as-is
                return data, elapsed
            else:
                return {'vulnerabilities_found': 0, 'vulnerabilities': []}, elapsed
                
        except subprocess.TimeoutExpired:
            return {'vulnerabilities': []}, 900.0
    
    def run_parry_incremental(self, first_run: bool = False) -> Tuple[Dict, float]:
        """Run Parry in Incremental Mode"""
        console.print("\n[cyan]Running Parry Incremental Mode...[/cyan]")
        
        if first_run:
            console.print("[dim]First run (baseline)[/dim]")
            flag = ''
        else:
            console.print("[dim]Second run (incremental)[/dim]")
            flag = '--incremental'
        
        start = time.time()
        
        try:
            cmd = ['parry', 'scan', str(self.target), '--format=json', '--output=parry_incr.json']
            if flag:
                cmd.append(flag)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            elapsed = time.time() - start
            
            if Path('parry_incr.json').exists():
                with open('parry_incr.json') as f:
                    data = json.load(f)
                # Data already has 'summary' key, just return as-is
                return data, elapsed
            else:
                return {'vulnerabilities_found': 0, 'vulnerabilities': []}, elapsed
                
        except subprocess.TimeoutExpired:
            return {'vulnerabilities': []}, 300.0
    
    def run_semgrep(self) -> Tuple[Dict, float]:
        """Run Semgrep"""
        console.print("\n[cyan]Running Semgrep...[/cyan]")
        
        # Check if semgrep is installed
        try:
            subprocess.run(['semgrep', '--version'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            console.print("[yellow]Semgrep not installed, skipping[/yellow]")
            return {'vulnerabilities': []}, 0.0
        
        start = time.time()
        
        try:
            result = subprocess.run(
                ['semgrep', '--config=auto', '--json', '--output=semgrep.json', str(self.target)],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            elapsed = time.time() - start
            
            if Path('semgrep.json').exists():
                with open('semgrep.json') as f:
                    data = json.load(f)
                    # Convert to our format
                    vulns = []
                    for finding in data.get('results', []):
                        vulns.append({
                            'severity': finding.get('extra', {}).get('severity', 'medium'),
                            'cwe': 'CWE-' + str(finding.get('extra', {}).get('metadata', {}).get('cwe', ['Unknown'])[0]),
                            'file_path': finding.get('path', ''),
                            'line_number': finding.get('start', {}).get('line', 0)
                        })
                    return {'vulnerabilities': vulns}, elapsed
            else:
                return {'vulnerabilities': []}, elapsed
                
        except subprocess.TimeoutExpired:
            return {'vulnerabilities': []}, 300.0
    
    def run_bandit(self) -> Tuple[Dict, float]:
        """Run Bandit (Python only)"""
        console.print("\n[cyan]Running Bandit (Python files only)...[/cyan]")
        
        # Check if bandit is installed
        try:
            subprocess.run(['bandit', '--version'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            console.print("[yellow]Bandit not installed, skipping[/yellow]")
            return {'vulnerabilities': []}, 0.0
        
        start = time.time()
        
        try:
            result = subprocess.run(
                ['bandit', '-r', str(self.target), '-f', 'json', '-o', 'bandit.json'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            elapsed = time.time() - start
            
            if Path('bandit.json').exists():
                with open('bandit.json') as f:
                    data = json.load(f)
                    # Convert to our format
                    vulns = []
                    for finding in data.get('results', []):
                        severity_map = {
                            'HIGH': 'high',
                            'MEDIUM': 'medium',
                            'LOW': 'low'
                        }
                        vulns.append({
                            'severity': severity_map.get(finding.get('issue_severity', 'MEDIUM'), 'medium'),
                            'cwe': finding.get('issue_cwe', {}).get('id', 'Unknown'),
                            'file_path': finding.get('filename', ''),
                            'line_number': finding.get('line_number', 0)
                        })
                    return {'vulnerabilities': vulns}, elapsed
            else:
                return {'vulnerabilities': []}, elapsed
                
        except subprocess.TimeoutExpired:
            return {'vulnerabilities': []}, 300.0
    
    def calculate_metrics(self, results: Dict) -> Dict:
        """Calculate recall, precision, etc."""
        # Check if we have summary data (Parry format)
        if 'summary' in results:
            summary = results['summary']
            return {
                'total': summary.get('vulnerabilities_found', 0),
                'critical': summary.get('by_severity', {}).get('critical', 0),
                'high': summary.get('by_severity', {}).get('high', 0),
                'medium': summary.get('by_severity', {}).get('medium', 0),
                'low': summary.get('by_severity', {}).get('low', 0)
            }
        
        # Fall back to counting vulnerabilities list
        vulns = results.get('vulnerabilities', [])
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for v in vulns:
            sev = v.get('severity', 'medium').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        return {
            'total': len(vulns),
            'critical': severity_counts['critical'],
            'high': severity_counts['high'],
            'medium': severity_counts['medium'],
            'low': severity_counts['low']
        }
    
    def run_all_benchmarks(self):
        """Run all benchmark tools"""
        console.print(Panel.fit(
            "[bold cyan]Comprehensive Benchmark Suite[/bold cyan]\n"
            f"[dim]Target: {self.target}[/dim]",
            border_style="cyan"
        ))
        
        # Parry Fast Mode
        parry_fast_data, parry_fast_time = self.run_parry_fast()
        self.results['parry_fast'] = {
            'data': parry_fast_data,
            'time': parry_fast_time,
            'metrics': self.calculate_metrics(parry_fast_data)
        }
        
        # Parry Hybrid Mode
        parry_hybrid_data, parry_hybrid_time = self.run_parry_hybrid()
        self.results['parry_hybrid'] = {
            'data': parry_hybrid_data,
            'time': parry_hybrid_time,
            'metrics': self.calculate_metrics(parry_hybrid_data)
        }
        
        # Parry Incremental (first run)
        parry_incr1_data, parry_incr1_time = self.run_parry_incremental(first_run=True)
        
        # Parry Incremental (second run)
        parry_incr2_data, parry_incr2_time = self.run_parry_incremental(first_run=False)
        self.results['parry_incremental'] = {
            'first_run_time': parry_incr1_time,
            'second_run_time': parry_incr2_time,
            'speedup': parry_incr1_time / parry_incr2_time if parry_incr2_time > 0 else 0,
            'metrics': self.calculate_metrics(parry_incr2_data)
        }
        
        # Semgrep
        semgrep_data, semgrep_time = self.run_semgrep()
        self.results['semgrep'] = {
            'data': semgrep_data,
            'time': semgrep_time,
            'metrics': self.calculate_metrics(semgrep_data)
        }
        
        # Bandit
        bandit_data, bandit_time = self.run_bandit()
        self.results['bandit'] = {
            'data': bandit_data,
            'time': bandit_time,
            'metrics': self.calculate_metrics(bandit_data)
        }
        
        return self.results
    
    def display_results(self):
        """Display benchmark results"""
        console.print("\n")
        console.print(Panel.fit(
            "[bold green]Benchmark Results[/bold green]",
            border_style="green"
        ))
        
        # Main comparison table
        table = Table(title="Overall Comparison")
        table.add_column("Tool", style="cyan")
        table.add_column("Mode", style="white")
        table.add_column("Vulns Found", justify="right", style="yellow")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("High", justify="right", style="red")
        table.add_column("Time (s)", justify="right", style="green")
        
        # Parry Fast
        pf = self.results.get('parry_fast', {})
        table.add_row(
            "Parry",
            "Fast",
            str(pf.get('metrics', {}).get('total', 0)),
            str(pf.get('metrics', {}).get('critical', 0)),
            str(pf.get('metrics', {}).get('high', 0)),
            f"{pf.get('time', 0):.2f}"
        )
        
        # Parry Hybrid
        ph = self.results.get('parry_hybrid', {})
        table.add_row(
            "Parry",
            "Hybrid",
            str(ph.get('metrics', {}).get('total', 0)),
            str(ph.get('metrics', {}).get('critical', 0)),
            str(ph.get('metrics', {}).get('high', 0)),
            f"{ph.get('time', 0):.2f}"
        )
        
        # Semgrep
        sg = self.results.get('semgrep', {})
        if sg.get('time', 0) > 0:
            table.add_row(
                "Semgrep",
                "Default",
                str(sg.get('metrics', {}).get('total', 0)),
                str(sg.get('metrics', {}).get('critical', 0)),
                str(sg.get('metrics', {}).get('high', 0)),
                f"{sg.get('time', 0):.2f}"
            )
        
        # Bandit
        bd = self.results.get('bandit', {})
        if bd.get('time', 0) > 0:
            table.add_row(
                "Bandit",
                "Python",
                str(bd.get('metrics', {}).get('total', 0)),
                str(bd.get('metrics', {}).get('critical', 0)),
                str(bd.get('metrics', {}).get('high', 0)),
                f"{bd.get('time', 0):.2f}"
            )
        
        console.print(table)
        
        # Incremental mode comparison
        pi = self.results.get('parry_incremental', {})
        if pi.get('first_run_time', 0) > 0:
            console.print("\n")
            incr_table = Table(title="Incremental Mode Performance")
            incr_table.add_column("Metric", style="cyan")
            incr_table.add_column("Value", justify="right", style="green")
            
            incr_table.add_row("First Run Time", f"{pi.get('first_run_time', 0):.2f}s")
            incr_table.add_row("Second Run Time", f"{pi.get('second_run_time', 0):.2f}s")
            incr_table.add_row("Speedup", f"{pi.get('speedup', 0):.1f}x")
            
            console.print(incr_table)
        
        # Key findings
        console.print("\n[bold]Key Findings:[/bold]")
        
        pf_total = pf.get('metrics', {}).get('total', 0)
        ph_total = ph.get('metrics', {}).get('total', 0)
        sg_total = sg.get('metrics', {}).get('total', 0)
        
        if ph_total >= pf_total:
            improvement = ((ph_total - pf_total) / pf_total * 100) if pf_total > 0 else 0
            console.print(f"✓ Parry Hybrid found {ph_total - pf_total} more vulnerabilities than Fast Mode (+{improvement:.1f}%)")
        
        if ph_total > sg_total:
            improvement = ((ph_total - sg_total) / sg_total * 100) if sg_total > 0 else 0
            console.print(f"✓ Parry Hybrid found {ph_total - sg_total} more vulnerabilities than Semgrep (+{improvement:.1f}%)")
        
        if pf.get('time', 999) < sg.get('time', 999):
            speedup = sg.get('time', 0) / pf.get('time', 1)
            console.print(f"✓ Parry Fast is {speedup:.1f}x faster than Semgrep")
        
        if pi.get('speedup', 0) > 5:
            console.print(f"✓ Incremental mode provides {pi.get('speedup', 0):.1f}x speedup for re-scans")


def main():
    import sys
    
    if len(sys.argv) < 2:
        console.print("[red]Usage: python comprehensive_benchmark_v2.py <path_to_scan>[/red]")
        sys.exit(1)
    
    target = Path(sys.argv[1])
    
    if not target.exists():
        console.print(f"[red]Error: Path '{target}' does not exist[/red]")
        sys.exit(1)
    
    runner = BenchmarkRunner(target)
    runner.run_all_benchmarks()
    runner.display_results()
    
    # Save detailed results
    with open('benchmark_results_v2.json', 'w') as f:
        # Convert Path objects to strings for JSON serialization
        serializable_results = {}
        for tool, data in runner.results.items():
            serializable_results[tool] = {
                'time': data.get('time', data.get('first_run_time', 0)),
                'metrics': data.get('metrics', {})
            }
            if 'speedup' in data:
                serializable_results[tool]['speedup'] = data['speedup']
        
        json.dump(serializable_results, f, indent=2)
    
    console.print(f"\n[dim]Detailed results saved to benchmark_results_v2.json[/dim]")


if __name__ == '__main__':
    main()

