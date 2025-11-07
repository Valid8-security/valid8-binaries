#!/usr/bin/env python3
"""
Validate Parry Performance
"""
import sys
import time
import argparse
import psutil
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def validate_performance(target_path="parry", quick=False):
    """Validate Parry performance"""
    from parry.scanner import Scanner
    
    target = Path(target_path)
    if not target.exists():
        print(f"⚠️  Target path does not exist: {target_path}, using 'parry' directory")
        target = Path("parry")
        if not target.exists():
            print("❌ No valid target found")
            return False
    
    print("=" * 70)
    print("PERFORMANCE VALIDATION")
    print("=" * 70)
    
    # Get initial memory
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024  # MB
    
    print(f"\n📊 Memory before scan: {mem_before:.2f} MB")
    
    scanner = Scanner()
    start_time = time.time()
    
    try:
        results = scanner.scan(target)
        elapsed = time.time() - start_time
        
        # Get memory after
        mem_after = process.memory_info().rss / 1024 / 1024  # MB
        mem_used = mem_after - mem_before
        
        files_scanned = results.get('files_scanned', 0)
        vulnerabilities = results.get('vulnerabilities', [])
        
        print(f"\n📈 Performance Results:")
        print(f"   Files scanned: {files_scanned}")
        print(f"   Scan time: {elapsed:.2f}s")
        
        if files_scanned > 0:
            fps = files_scanned / elapsed
            print(f"   Files/sec: {fps:.2f}")
            
            # Targets
            target_fps = 50
            if fps >= target_fps:
                print(f"   ✅ Files/sec meets target ({target_fps}+)")
            else:
                print(f"   ⚠️  Files/sec below target ({target_fps}+)")
        
        print(f"   Memory used: {mem_used:.2f} MB")
        print(f"   Memory after: {mem_after:.2f} MB")
        
        # Memory targets
        target_mem = 2000  # 2GB
        if mem_after < target_mem:
            print(f"   ✅ Memory usage within target (<{target_mem}MB)")
        else:
            print(f"   ⚠️  Memory usage exceeds target (<{target_mem}MB)")
        
        print(f"   Vulnerabilities found: {len(vulnerabilities)}")
        
        print(f"\n✅ Performance validation completed!")
        return True
        
    except Exception as e:
        print(f"❌ Error during performance test: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate Parry performance")
    parser.add_argument("--target", default="parry", help="Target directory to scan")
    parser.add_argument("--quick", action="store_true", help="Quick performance check")
    args = parser.parse_args()
    
    success = validate_performance(args.target, args.quick)
    sys.exit(0 if success else 1)

