#!/usr/bin/env python3
"""
Comprehensive metrics testing for large codebase feasibility
Tests Parry performance across different codebase sizes
"""

import json
import time
import subprocess
import psutil
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any


def get_file_count(directory: Path) -> int:
    """Count Python files in directory"""
    return len(list(directory.rglob("*.py")))


def get_directory_size(directory: Path) -> int:
    """Get total size of directory in bytes"""
    total = 0
    for filepath in directory.rglob("*"):
        if filepath.is_file():
            total += filepath.stat().st_size
    return total


def measure_memory_usage() -> Dict[str, float]:
    """Get current memory usage in MB"""
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    return {
        "rss_mb": mem_info.rss / 1024 / 1024,  # Resident Set Size
        "vms_mb": mem_info.vms / 1024 / 1024,  # Virtual Memory Size
    }


def run_parry_scan(target: Path, mode: str, output_file: Path) -> Dict[str, Any]:
    """Run Parry scan and collect metrics"""
    print(f"\n{'='*70}")
    print(f"Running Parry {mode.upper()} mode on: {target}")
    print(f"{'='*70}")
    
    # Get initial memory
    mem_before = measure_memory_usage()
    
    # Start timer
    start_time = time.time()
    
    try:
        # Run scan
        result = subprocess.run(
            [
                "parry", "scan", str(target),
                "--mode", mode,
                "--format", "json",
                "--output", str(output_file)
            ],
            capture_output=True,
            text=True,
            timeout=1800  # 30 minute timeout for large codebases
        )
        
        elapsed_time = time.time() - start_time
        mem_after = measure_memory_usage()
        
        # Parse results
        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
                summary = data.get("summary", {})
                
                files_scanned = summary.get("files_scanned", 0)
                vulns_found = summary.get("vulnerabilities_found", 0)
                
                return {
                    "status": "success",
                    "mode": mode,
                    "target": str(target),
                    "duration_seconds": round(elapsed_time, 2),
                    "files_scanned": files_scanned,
                    "files_per_second": round(files_scanned / elapsed_time, 2) if elapsed_time > 0 else 0,
                    "vulnerabilities_found": vulns_found,
                    "by_severity": summary.get("by_severity", {}),
                    "by_cwe": summary.get("by_cwe", {}),
                    "memory_rss_mb": round(mem_after["rss_mb"] - mem_before["rss_mb"], 2),
                    "memory_vms_mb": round(mem_after["vms_mb"] - mem_before["vms_mb"], 2),
                    "exit_code": result.returncode,
                    "stderr": result.stderr[:500] if result.stderr else None
                }
        else:
            return {
                "status": "error",
                "mode": mode,
                "target": str(target),
                "duration_seconds": round(elapsed_time, 2),
                "error": "Output file not created",
                "stderr": result.stderr[:500] if result.stderr else None
            }
            
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "mode": mode,
            "target": str(target),
            "duration_seconds": 1800
        }
    except Exception as e:
        return {
            "status": "error",
            "mode": mode,
            "target": str(target),
            "error": str(e)
        }


def main():
    """Run comprehensive metrics testing"""
    
    base_dir = Path(__file__).parent.parent
    
    # Define test targets
    test_targets = [
        {
            "name": "Small (Examples)",
            "path": base_dir / "examples",
            "description": "Small test files for quick validation"
        },
        {
            "name": "Medium (Parry Source)",
            "path": base_dir / "parry",
            "description": "Parry's own source code (medium complexity)"
        },
        {
            "name": "Large (Full Repo)",
            "path": base_dir,
            "description": "Entire repository (includes venv, .git, etc - will be filtered)"
        }
    ]
    
    results = {
        "timestamp": datetime.now().isoformat(),
        "tests": []
    }
    
    print("="*70)
    print("PARRY LARGE CODEBASE FEASIBILITY TEST")
    print("="*70)
    print()
    
    for target in test_targets:
        target_path = target["path"]
        
        if not target_path.exists():
            print(f"⚠ Skipping {target['name']}: path does not exist")
            continue
        
        # Get codebase stats
        file_count = get_file_count(target_path)
        dir_size_mb = get_directory_size(target_path) / 1024 / 1024
        
        print(f"\n📊 {target['name']}:")
        print(f"   Files: {file_count} Python files")
        print(f"   Size: {dir_size_mb:.1f} MB")
        print(f"   Description: {target['description']}")
        
        test_result = {
            "name": target["name"],
            "path": str(target_path),
            "file_count": file_count,
            "size_mb": round(dir_size_mb, 2),
            "modes": {}
        }
        
        # Test Fast mode
        print(f"\n  🔍 Testing FAST mode...")
        fast_output = base_dir / f"benchmark_fast_{target['name'].lower().replace(' ', '_')}.json"
        fast_result = run_parry_scan(target_path, "fast", fast_output)
        test_result["modes"]["fast"] = fast_result
        
        if fast_result["status"] == "success":
            print(f"     ✓ Scanned {fast_result['files_scanned']} files in {fast_result['duration_seconds']}s")
            print(f"     ✓ Throughput: {fast_result['files_per_second']} files/sec")
            print(f"     ✓ Found {fast_result['vulnerabilities_found']} vulnerabilities")
            print(f"     ✓ Memory: +{fast_result['memory_rss_mb']} MB RSS")
        
        # Test Hybrid mode (only for small/medium to avoid long waits)
        if file_count < 1000:
            print(f"\n  🔍 Testing HYBRID mode...")
            hybrid_output = base_dir / f"benchmark_hybrid_{target['name'].lower().replace(' ', '_')}.json"
            hybrid_result = run_parry_scan(target_path, "hybrid", hybrid_output)
            test_result["modes"]["hybrid"] = hybrid_result
            
            if hybrid_result["status"] == "success":
                print(f"     ✓ Scanned {hybrid_result['files_scanned']} files in {hybrid_result['duration_seconds']}s")
                print(f"     ✓ Throughput: {hybrid_result['files_per_second']} files/sec")
                print(f"     ✓ Found {hybrid_result['vulnerabilities_found']} vulnerabilities")
                print(f"     ✓ Memory: +{hybrid_result['memory_rss_mb']} MB RSS")
                
                # Compare with Fast mode
                if fast_result["status"] == "success":
                    speedup = fast_result["duration_seconds"] / hybrid_result["duration_seconds"]
                    vuln_increase = hybrid_result["vulnerabilities_found"] - fast_result["vulnerabilities_found"]
                    print(f"     📈 vs Fast: {speedup:.2f}x slower, +{vuln_increase} vulnerabilities")
        else:
            print(f"\n  ⏭ Skipping HYBRID mode (too large: {file_count} files)")
            test_result["modes"]["hybrid"] = {"status": "skipped", "reason": "Too large for hybrid scan"}
        
        results["tests"].append(test_result)
        
        # Cleanup
        for f in [fast_output]:
            if f.exists():
                f.unlink()
    
    # Save results
    output_file = base_dir / "large_codebase_metrics.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    for test in results["tests"]:
        print(f"\n{test['name']} ({test['file_count']} files):")
        if "fast" in test["modes"] and test["modes"]["fast"]["status"] == "success":
            fast = test["modes"]["fast"]
            print(f"  Fast Mode:   {fast['files_per_second']} files/sec, {fast['duration_seconds']}s")
        
        if "hybrid" in test["modes"] and test["modes"]["hybrid"]["status"] == "success":
            hybrid = test["modes"]["hybrid"]
            print(f"  Hybrid Mode: {hybrid['files_per_second']} files/sec, {hybrid['duration_seconds']}s")
    
    print(f"\n✅ Detailed results saved to: {output_file}")
    print()
    
    # Feasibility assessment
    print("="*70)
    print("FEASIBILITY ASSESSMENT")
    print("="*70)
    
    # Find largest successful scan
    max_files = 0
    max_throughput = 0
    for test in results["tests"]:
        if "fast" in test["modes"] and test["modes"]["fast"]["status"] == "success":
            fast = test["modes"]["fast"]
            max_files = max(max_files, fast["files_scanned"])
            max_throughput = max(max_throughput, fast["files_per_second"])
    
    print(f"\n✅ Largest scan: {max_files} files")
    print(f"✅ Peak throughput: {max_throughput} files/sec")
    
    # Estimate for 10K, 50K, 100K file codebases
    if max_throughput > 0:
        for size in [10000, 50000, 100000]:
            estimated_time = size / max_throughput
            print(f"\n📊 Estimated scan time for {size:,} files:")
            print(f"   Fast Mode:   ~{estimated_time:.0f} seconds (~{estimated_time/60:.1f} minutes)")
            print(f"   Hybrid Mode: ~{estimated_time*10:.0f} seconds (~{estimated_time*10/60:.1f} minutes)")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    main()

