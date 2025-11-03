#!/usr/bin/env python3
# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Test parallel performance optimizations in Hybrid Mode
"""

import sys
import time
from pathlib import Path
from parry.ai_detector import AIDetector
from parry.llm import LLMClient

def test_parallel_processing():
    """Test that parallel processing improves speed"""
    
    print("Testing parallel processing optimizations...")
    print("=" * 60)
    
    # Create test codebase with multiple files
    test_dir = Path("test_parallel_temp")
    test_dir.mkdir(exist_ok=True)
    
    # Create 20 simple Python files
    test_files = []
    for i in range(20):
        test_file = test_dir / f"test_{i}.py"
        test_file.write_text(f"""
def vulnerable_function_{i}(user_input):
    # Vulnerable code
    import subprocess
    subprocess.call([user_input])  # Command injection
    return eval(user_input)  # Code injection
""")
        test_files.append(test_file)
    
    print(f"Created {len(test_files)} test files")
    
    # Initialize AI detector with optimizations
    ai_detector = AIDetector(max_workers=8)
    
    print(f"AI Detector workers: {ai_detector.max_workers}")
    print(f"LLM timeout: {ai_detector.llm.config.timeout}s")
    print(f"LLM max_tokens: {ai_detector.llm.config.max_tokens}")
    print(f"LLM temperature: {ai_detector.llm.config.temperature}")
    
    # Test parallel processing
    print("\nRunning parallel AI detection...")
    start_time = time.time()
    
    all_vulns = []
    for test_file in test_files:
        code = test_file.read_text()
        vulns = ai_detector.detect_vulnerabilities(
            code,
            str(test_file),
            'python'
        )
        all_vulns.extend(vulns)
    
    elapsed = time.time() - start_time
    
    print(f"\nResults:")
    print(f"  Files analyzed: {len(test_files)}")
    print(f"  Vulnerabilities found: {len(all_vulns)}")
    print(f"  Time elapsed: {elapsed:.2f}s")
    print(f"  Speed: {len(test_files)/elapsed:.2f} files/sec")
    
    # Cleanup
    import shutil
    shutil.rmtree(test_dir)
    
    print("\n✅ Parallel processing test completed!")
    return len(all_vulns) > 0  # Success if found any vulnerabilities


if __name__ == "__main__":
    try:
        success = test_parallel_processing()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

