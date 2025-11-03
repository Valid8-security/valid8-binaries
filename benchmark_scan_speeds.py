#!/usr/bin/env python3
"""
Benchmark Parry scan speeds on different codebase sizes
"""

import sys
import time
from pathlib import Path

def benchmark_mode(mode, path, name):
    """Benchmark a specific scan mode"""
    print(f"\n{'='*60}")
    print(f"Testing {mode.upper()} Mode on {name}")
    print(f"{'='*60}")
    
    try:
        import subprocess
        import json
        
        start_time = time.time()
        
        result = subprocess.run(
            ["parry", "scan", str(path), "--mode", mode, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        elapsed = time.time() - start_time
        
        if result.returncode == 0 and result.stdout:
            try:
                data = json.loads(result.stdout)
                files_scanned = data.get('files_scanned', 0)
                vulns_found = data.get('vulnerabilities_found', 0)
                
                if files_scanned > 0:
                    speed = files_scanned / elapsed
                    
                    print(f"✓ Scan completed in {elapsed:.2f}s")
                    print(f"  Files scanned: {files_scanned}")
                    print(f"  Vulnerabilities: {vulns_found}")
                    print(f"  Speed: {speed:.2f} files/sec")
                    
                    return {
                        'mode': mode,
                        'name': name,
                        'time': elapsed,
                        'files': files_scanned,
                        'vulns': vulns_found,
                        'speed': speed
                    }
            except json.JSONDecodeError:
                print(f"✗ Failed to parse output: {result.stdout[:200]}")
        
        print(f"✗ Scan failed: {result.stderr[:200]}")
        return None
        
    except subprocess.TimeoutExpired:
        print(f"✗ Scan timed out after 600s")
        return None
    except FileNotFoundError:
        print(f"✗ Parry not found (run: pip install parry-scanner)")
        return None
    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def main():
    print("\n" + "="*60)
    print("PARRY SCAN SPEED BENCHMARKS")
    print("="*60 + "\n")
    
    results = []
    
    # Test on current Parry codebase
    current_dir = Path.cwd()
    file_count = len(list(current_dir.rglob("*.py"))) - len(list(current_dir.rglob("*/venv/*/*.py"))) - len(list(current_dir.rglob("*/build/*/*.py")))
    
    print(f"Codebase: Parry Project")
    print(f"Files: ~{file_count} Python files")
    print(f"Lines: ~29,000 LOC")
    
    # Test Fast Mode
    result = benchmark_mode("fast", ".", "Parry Project")
    if result:
        results.append(result)
    
    # Test Hybrid Mode (if AI available)
    try:
        import subprocess
        check = subprocess.run(["ollama", "list"], capture_output=True, timeout=5)
        if check.returncode == 0:
            result = benchmark_mode("hybrid", ".", "Parry Project")
            if result:
                results.append(result)
    except:
        print("\n⚠ Skipping Hybrid Mode (Ollama not available)")
    
    # Summary
    if results:
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        
        for r in results:
            print(f"\n{r['mode'].upper()} Mode:")
            print(f"  Speed: {r['speed']:.2f} files/sec")
            print(f"  Time: {r['time']:.2f}s for {r['files']} files")
            print(f"  Found: {r['vulns']} vulnerabilities")
        
        # Projections
        print("\n" + "="*60)
        print("PROJECTED PERFORMANCE ON LARGE CODEBASES")
        print("="*60)
        
        if results:
            fast_result = next((r for r in results if r['mode'] == 'fast'), None)
            hybrid_result = next((r for r in results if r['mode'] == 'hybrid'), None)
            
            if fast_result:
                print(f"\nFAST MODE ({fast_result['speed']:.2f} files/sec):")
                sizes = [
                    (50, "Small project"),
                    (500, "Medium web app"),
                    (5000, "Large enterprise app"),
                    (50000, "Very large monorepo")
                ]
                for size, name in sizes:
                    time_estimate = size / fast_result['speed']
                    print(f"  {name:25} ({size:5,} files): {time_estimate:6.2f}s")
            
            if hybrid_result:
                print(f"\nHYBRID MODE ({hybrid_result['speed']:.2f} files/sec):")
                for size, name in sizes:
                    time_estimate = size / hybrid_result['speed']
                    print(f"  {name:25} ({size:5,} files): {time_estimate:6.2f}s")
    
    print("\n" + "="*60)
    print("Done!")
    print("="*60)


if __name__ == "__main__":
    main()

