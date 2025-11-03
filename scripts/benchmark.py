#!/usr/bin/env python3
# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Benchmark script for comparing Parry against Snyk and Semgrep
"""

import json
import time
import argparse
from pathlib import Path
from datetime import datetime

from parry.scanner import Scanner
from parry.compare import Comparator


def run_benchmark(target_path: Path, output_file: Path):
    """Run comprehensive benchmark comparing all tools"""
    
    results = {
        "benchmark_id": datetime.now().isoformat(),
        "target": str(target_path),
        "results": {}
    }
    
    print("=" * 60)
    print("Parry Security Benchmark")
    print("=" * 60)
    print()
    
    # Run Parry
    print("[1/3] Running Parry scan...")
    start = time.time()
    scanner = Scanner()
    parry_results = scanner.scan(target_path)
    parry_time = time.time() - start
    
    results["results"]["parry"] = {
        "vulnerabilities": len(parry_results["vulnerabilities"]),
        "files_scanned": parry_results["files_scanned"],
        "time_seconds": parry_time,
        "by_severity": _count_by_severity(parry_results["vulnerabilities"]),
    }
    
    print(f"   ✓ Found {len(parry_results['vulnerabilities'])} vulnerabilities in {parry_time:.2f}s")
    
    # Run Snyk
    print("\n[2/3] Running Snyk scan...")
    comparator = Comparator()
    try:
        start = time.time()
        snyk_results = comparator.run_tool("snyk", target_path)
        snyk_time = time.time() - start
        
        results["results"]["snyk"] = {
            "vulnerabilities": len(snyk_results["vulnerabilities"]),
            "time_seconds": snyk_time,
        }
        
        print(f"   ✓ Found {len(snyk_results['vulnerabilities'])} vulnerabilities in {snyk_time:.2f}s")
        
        # Compare with Snyk
        snyk_comparison = comparator.compare(parry_results, snyk_results, "snyk")
        results["comparisons"] = {"snyk": snyk_comparison}
        
    except Exception as e:
        print(f"   ✗ Snyk failed: {e}")
        results["results"]["snyk"] = {"error": str(e)}
    
    # Run Semgrep
    print("\n[3/3] Running Semgrep scan...")
    try:
        start = time.time()
        semgrep_results = comparator.run_tool("semgrep", target_path)
        semgrep_time = time.time() - start
        
        results["results"]["semgrep"] = {
            "vulnerabilities": len(semgrep_results["vulnerabilities"]),
            "time_seconds": semgrep_time,
        }
        
        print(f"   ✓ Found {len(semgrep_results['vulnerabilities'])} vulnerabilities in {semgrep_time:.2f}s")
        
        # Compare with Semgrep
        if "comparisons" not in results:
            results["comparisons"] = {}
        semgrep_comparison = comparator.compare(parry_results, semgrep_results, "semgrep")
        results["comparisons"]["semgrep"] = semgrep_comparison
        
    except Exception as e:
        print(f"   ✗ Semgrep failed: {e}")
        results["results"]["semgrep"] = {"error": str(e)}
    
    # Save results
    output_file.write_text(json.dumps(results, indent=2))
    
    # Print summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    for tool, data in results["results"].items():
        if "error" not in data:
            print(f"\n{tool.upper()}:")
            print(f"  Vulnerabilities: {data.get('vulnerabilities', 0)}")
            print(f"  Time: {data.get('time_seconds', 0):.2f}s")
            
            if tool == "parry":
                print(f"  Files scanned: {data['files_scanned']}")
                print(f"  By severity:")
                for severity, count in data["by_severity"].items():
                    print(f"    {severity}: {count}")
    
    print(f"\n✓ Results saved to {output_file}")


def _count_by_severity(vulnerabilities):
    """Count vulnerabilities by severity"""
    counts = {}
    for vuln in vulnerabilities:
        severity = vuln["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def main():
    parser = argparse.ArgumentParser(description="Benchmark Parry against other tools")
    parser.add_argument("target", help="Directory or file to scan")
    parser.add_argument("--output", "-o", default="benchmark_results.json",
                       help="Output file for results")
    
    args = parser.parse_args()
    
    target = Path(args.target)
    if not target.exists():
        print(f"Error: {target} does not exist")
        return 1
    
    output = Path(args.output)
    
    run_benchmark(target, output)
    return 0


if __name__ == "__main__":
    exit(main())


