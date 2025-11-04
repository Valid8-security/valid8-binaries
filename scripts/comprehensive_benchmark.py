#!/usr/bin/env python3
"""
Comprehensive benchmarking suite - Test Parry against competitors
on multiple real-world codebases with rigorous metrics
"""

import sys
import time
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

def find_codebases():
    """Find available codebases for testing"""
    codebases = []
    
    # Parry codebase itself
    if Path("parry").exists():
        codebases.append({
            "name": "Parry Project",
            "path": ".",
            "size": "Medium (~56 files)",
            "languages": ["Python"]
        })
    
    # Test if we can find other projects
    home = Path.home()
    
    # Common project locations
    potential_paths = [
        home / "Projects",
        home / "Code",
        home / "Development",
        Path("/tmp"),
    ]
    
    for base_path in potential_paths:
        if base_path.exists():
            # Look for Python projects
            for proj in list(base_path.glob("*"))[:5]:  # Limit to 5
                if (proj.is_dir() and 
                    not proj.name.startswith('.') and
                    any((proj / f).exists() for f in ['requirements.txt', 'setup.py', 'package.json', 'pom.xml'])):
                    # Count files
                    py_files = len(list(proj.rglob("*.py"))) if (proj / "*.py").exists() else 0
                    js_files = len(list(proj.rglob("*.js"))) if (proj / "*.js").exists() else 0
                    java_files = len(list(proj.rglob("*.java"))) if (proj / "*.java").exists() else 0
                    
                    if py_files + js_files + java_files > 10:  # At least 10 files
                        lang = []
                        if py_files > 0: lang.append("Python")
                        if js_files > 0: lang.append("JavaScript")
                        if java_files > 0: lang.append("Java")
                        
                        codebases.append({
                            "name": proj.name,
                            "path": str(proj),
                            "size": f"{py_files + js_files + java_files} files",
                            "languages": lang
                        })
    
    return codebases


def run_parry_scan(path: str, mode: str) -> Optional[Dict[str, Any]]:
    """Run Parry scanner"""
    try:
        cmd = [
            sys.executable, "-m", "parry.cli",
            "scan", path,
            "--mode", mode,
            "--format", "json"
        ]
        
        start = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=Path(__file__).parent.parent,
            env={**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)}
        )
        elapsed = time.time() - start
        
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            files_scanned = data.get('files_scanned', 0)
            vulns = data.get('vulnerabilities', [])
            
            return {
                "status": "success",
                "time": elapsed,
                "files_scanned": files_scanned,
                "vulnerabilities": len(vulns),
                "vuln_details": data.get('vulnerabilities', [])[:5],  # Sample
            }
        else:
            return {
                "status": "error",
                "error": result.stderr[:200] if result.stderr else "Unknown error"
            }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def run_snyk_scan(path: str) -> Optional[Dict[str, Any]]:
    """Run Snyk scanner"""
    try:
        cmd = ["snyk", "code", "test", path, "--json"]
        
        start = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=Path(path)
        )
        elapsed = time.time() - start
        
        if result.returncode == 0 or result.stdout:
            # Snyk outputs JSON even on failure
            data = json.loads(result.stdout) if result.stdout else {}
            runs = data.get('runs', [])
            
            if runs:
                results = runs[0].get('results', {})
                rules = results.get('rules', [])
                vuln_count = len(rules)
                
                return {
                    "status": "success",
                    "time": elapsed,
                    "vulnerabilities": vuln_count,
                }
            else:
                return {
                    "status": "success",
                    "time": elapsed,
                    "vulnerabilities": 0,
                }
        else:
            return {
                "status": "error",
                "error": result.stderr[:200] if result.stderr else "Unknown error"
            }
    except FileNotFoundError:
        return {"status": "not_installed"}
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def run_semgrep_scan(path: str) -> Optional[Dict[str, Any]]:
    """Run Semgrep scanner"""
    try:
        cmd = ["semgrep", "--config=auto", "--json", path]
        
        start = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=Path(path)
        )
        elapsed = time.time() - start
        
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            results = data.get('results', [])
            
            return {
                "status": "success",
                "time": elapsed,
                "vulnerabilities": len(results),
            }
        else:
            return {
                "status": "error",
                "error": result.stderr[:200] if result.stderr else "Unknown error"
            }
    except FileNotFoundError:
        return {"status": "not_installed"}
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def count_files(path: str) -> Dict[str, int]:
    """Count files by type"""
    p = Path(path)
    
    counts = {
        "python": len(list(p.rglob("*.py"))) - len(list(p.rglob("*/venv/*/*.py"))) - len(list(p.rglob("*/__pycache__/*.py"))),
        "javascript": len(list(p.rglob("*.js"))) - len(list(p.rglob("*/node_modules/*/*.js"))),
        "java": len(list(p.rglob("*.java"))) - len(list(p.rglob("*/target/*/*.java"))),
    }
    
    counts["total"] = sum(counts.values())
    return counts


def run_comprehensive_benchmark(codebase_info: Dict[str, str]):
    """Run full benchmark on a codebase"""
    name = codebase_info["name"]
    path = codebase_info["path"]
    
    print(f"\n{'='*70}")
    print(f"Testing: {name}")
    print(f"Path: {path}")
    print(f"Size: {codebase_info['size']}")
    print(f"Languages: {', '.join(codebase_info['languages'])}")
    print(f"{'='*70}\n")
    
    # Count files
    file_counts = count_files(path)
    print(f"Files found: {file_counts}")
    
    if file_counts["total"] == 0:
        print("⚠️  No scanable files found, skipping")
        return None
    
    results = {
        "codebase": name,
        "path": path,
        "file_counts": file_counts,
        "timestamp": datetime.now().isoformat(),
        "results": {}
    }
    
    # Test Parry Fast Mode
    print("\n[1/5] Parry Fast Mode...")
    fast_result = run_parry_scan(path, "fast")
    results["results"]["parry_fast"] = fast_result
    if fast_result.get("status") == "success":
        print(f"   ✓ {fast_result['vulnerabilities']} vulns in {fast_result['time']:.2f}s")
        print(f"   Files: {fast_result['files_scanned']}")
    else:
        print(f"   ✗ {fast_result.get('error', 'Unknown error')}")
    
    # Test Parry Deep Mode (skip if Ollama not available)
    print("\n[2/5] Parry Deep Mode...")
    deep_result = run_parry_scan(path, "deep")
    results["results"]["parry_deep"] = deep_result
    if deep_result.get("status") == "success":
        print(f"   ✓ {deep_result['vulnerabilities']} vulns in {deep_result['time']:.2f}s")
    elif deep_result.get("error", "").startswith("AI"):
        print("   ⚠️  Skipped (AI not available)")
    else:
        print(f"   ✗ {deep_result.get('error', 'Unknown error')}")
    
    # Test Parry Hybrid Mode
    print("\n[3/5] Parry Hybrid Mode...")
    hybrid_result = run_parry_scan(path, "hybrid")
    results["results"]["parry_hybrid"] = hybrid_result
    if hybrid_result.get("status") == "success":
        print(f"   ✓ {hybrid_result['vulnerabilities']} vulns in {hybrid_result['time']:.2f}s")
    elif hybrid_result.get("error", "").startswith("AI"):
        print("   ⚠️  Skipped (AI not available)")
    else:
        print(f"   ✗ {hybrid_result.get('error', 'Unknown error')}")
    
    # Test Snyk
    print("\n[4/5] Snyk Code...")
    snyk_result = run_snyk_scan(path)
    results["results"]["snyk"] = snyk_result
    if snyk_result.get("status") == "success":
        print(f"   ✓ {snyk_result['vulnerabilities']} vulns in {snyk_result['time']:.2f}s")
    elif snyk_result.get("status") == "not_installed":
        print("   ⚠️  Not installed")
    else:
        print(f"   ✗ {snyk_result.get('error', 'Unknown error')}")
    
    # Test Semgrep
    print("\n[5/5] Semgrep...")
    semgrep_result = run_semgrep_scan(path)
    results["results"]["semgrep"] = semgrep_result
    if semgrep_result.get("status") == "success":
        print(f"   ✓ {semgrep_result['vulnerabilities']} vulns in {semgrep_result['time']:.2f}s")
    elif semgrep_result.get("status") == "not_installed":
        print("   ⚠️  Not installed")
    else:
        print(f"   ✗ {semgrep_result.get('error', 'Unknown error')}")
    
    return results


def print_summary(all_results: List[Dict]):
    """Print comprehensive summary of all benchmarks"""
    print("\n" + "="*70)
    print("COMPREHENSIVE BENCHMARK SUMMARY")
    print("="*70 + "\n")
    
    # Build comparison table
    table_data = []
    
    for result in all_results:
        if not result or not result.get("results"):
            continue
        
        name = result["codebase"]
        file_counts = result["file_counts"]
        total_files = file_counts.get("total", 0)
        
        row = {"codebase": name, "files": total_files, "tools": {}}
        
        # Collect results for each tool
        for tool, tool_result in result["results"].items():
            if tool_result.get("status") == "success":
                row["tools"][tool] = {
                    "vulns": tool_result.get("vulnerabilities", 0),
                    "time": tool_result.get("time", 0)
                }
        
        table_data.append(row)
    
    if not table_data:
        print("⚠️  No successful benchmark results")
        return
    
    # Print table
    print(f"{'Codebase':<20} {'Files':<10} {'Tool':<15} {'Vulns':<10} {'Time (s)':<12} {'Speed (f/s)':<15}")
    print("-" * 70)
    
    for row in table_data:
        codebase = row["codebase"][:18]
        files = str(row["files"])
        
        # Show each tool result
        first_tool = True
        for tool, data in row["tools"].items():
            vulns = str(data["vulns"])
            time_sec = f"{data['time']:.2f}"
            speed = f"{row['files'] / data['time']:.2f}" if data['time'] > 0 else "0"
            
            tool_display = tool.replace("parry_", "Parry ")
            tool_display = tool_display.replace("_", " ").title()
            
            if first_tool:
                print(f"{codebase:<20} {files:<10} {tool_display:<15} {vulns:<10} {time_sec:<12} {speed:<15}")
                first_tool = False
            else:
                print(f"{'':20} {'':10} {tool_display:<15} {vulns:<10} {time_sec:<12} {speed:<15}")
        
        print()
    
    # Calculate averages and comparisons
    print("\n" + "="*70)
    print("METRICS COMPARISON")
    print("="*70 + "\n")
    
    tools_to_compare = ["parry_fast", "parry_hybrid", "snyk", "semgrep"]
    tool_stats = {tool: {"times": [], "vulns": [], "speeds": []} for tool in tools_to_compare}
    
    for row in table_data:
        for tool in tools_to_compare:
            if tool in row["tools"]:
                data = row["tools"][tool]
                tool_stats[tool]["times"].append(data["time"])
                tool_stats[tool]["vulns"].append(data["vulns"])
                if data["time"] > 0:
                    tool_stats[tool]["speeds"].append(row["files"] / data["time"])
    
    # Print statistics
    for tool, stats in tool_stats.items():
        if stats["times"]:
            tool_name = tool.replace("parry_", "Parry ").replace("_", " ").title()
            
            avg_time = sum(stats["times"]) / len(stats["times"])
            avg_vulns = sum(stats["vulns"]) / len(stats["vulns"])
            avg_speed = sum(stats["speeds"]) / len(stats["speeds"]) if stats["speeds"] else 0
            
            print(f"{tool_name}:")
            print(f"  Tests: {len(stats['times'])}")
            print(f"  Avg Vulns: {avg_vulns:.1f}")
            print(f"  Avg Time: {avg_time:.2f}s")
            print(f"  Avg Speed: {avg_speed:.2f} files/sec")
            print()


def main():
    import os
    
    print("\n" + "="*70)
    print("PARRY COMPREHENSIVE BENCHMARK SUITE")
    print("="*70)
    
    # Find available codebases
    codebases = find_codebases()
    
    if not codebases:
        print("\n⚠️  No suitable codebases found for testing")
        print("Testing on Parry codebase only...")
        
        # Test on current Parry project
        if Path("parry").exists():
            codebases = [{
                "name": "Parry Project",
                "path": ".",
                "size": "Medium",
                "languages": ["Python"]
            }]
        else:
            print("Error: Cannot find any codebase to test")
            return 1
    
    print(f"\nFound {len(codebases)} codebase(s) for testing:")
    for i, cb in enumerate(codebases, 1):
        print(f"  {i}. {cb['name']} ({cb['size']})")
    
    # Ask user to select
    if len(codebases) == 1:
        selected = codebases
    else:
        print("\nSelect codebases to test:")
        print("  Enter numbers separated by commas (e.g., 1,2,3)")
        print("  Or 'all' for all codebases")
        
        choice = input("\nChoice: ").strip()
        
        if choice.lower() == 'all':
            selected = codebases
        else:
            try:
                indices = [int(x.strip()) - 1 for x in choice.split(',')]
                selected = [codebases[i] for i in indices if 0 <= i < len(codebases)]
            except:
                print("Invalid input, testing all")
                selected = codebases
    
    # Run benchmarks
    all_results = []
    
    for codebase in selected:
        result = run_comprehensive_benchmark(codebase)
        if result:
            all_results.append(result)
    
    # Print summary
    print_summary(all_results)
    
    # Save results
    output_file = Path("comprehensive_benchmark_results.json")
    output_file.write_text(json.dumps(all_results, indent=2))
    print(f"\n✓ Results saved to: {output_file}")
    
    return 0


if __name__ == "__main__":
    import os
    sys.path.insert(0, str(Path(__file__).parent.parent))
    exit(main())

