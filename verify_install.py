#!/usr/bin/env python3
"""
Verification script for Parry installation
Run this after installation to verify everything works
"""

import sys
import subprocess
from pathlib import Path


def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60 + "\n")


def print_status(test_name, passed, message=""):
    """Print test status"""
    status = "✓ PASS" if passed else "✗ FAIL"
    color = "\033[92m" if passed else "\033[91m"
    reset = "\033[0m"
    print(f"{color}{status}{reset} - {test_name}")
    if message:
        print(f"      {message}")


def check_python():
    """Check Python version"""
    version = sys.version_info
    required = (3, 9)
    passed = version >= required
    message = f"Python {version.major}.{version.minor}.{version.micro}"
    print_status("Python Version", passed, message)
    return passed


def check_ollama():
    """Check if Ollama is installed and running"""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=5
        )
        passed = result.returncode == 0
        message = "Ollama is installed and running" if passed else "Ollama not responding"
        print_status("Ollama Service", passed, message)
        return passed
    except FileNotFoundError:
        print_status("Ollama Service", False, "Ollama not found - run: brew install ollama")
        return False
    except Exception as e:
        print_status("Ollama Service", False, str(e))
        return False


def check_model():
    """Check if CodeLlama model is available"""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            has_codellama = "codellama" in result.stdout.lower() or "codegemma" in result.stdout.lower()
            message = "Code model found" if has_codellama else "No code model - run: ollama pull codellama:7b-instruct"
            print_status("LLM Model", has_codellama, message)
            return has_codellama
        return False
    except Exception as e:
        print_status("LLM Model", False, str(e))
        return False


def check_parry():
    """Check if Parry is installed"""
    try:
        result = subprocess.run(
            ["parry", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        passed = result.returncode == 0
        message = "Parry CLI is installed" if passed else "Parry not found"
        print_status("Parry Installation", passed, message)
        return passed
    except FileNotFoundError:
        print_status("Parry Installation", False, "Parry not found - run: pip install -e .")
        return False
    except Exception as e:
        print_status("Parry Installation", False, str(e))
        return False


def check_example_files():
    """Check if example files exist"""
    examples_dir = Path("examples")
    if not examples_dir.exists():
        print_status("Example Files", False, "examples/ directory not found")
        return False
    
    required_files = ["vulnerable_code.py", "vulnerable_code.js"]
    missing = [f for f in required_files if not (examples_dir / f).exists()]
    
    passed = len(missing) == 0
    message = "All example files present" if passed else f"Missing: {', '.join(missing)}"
    print_status("Example Files", passed, message)
    return passed


def test_scan():
    """Test scanning functionality"""
    try:
        result = subprocess.run(
            ["parry", "scan", "examples/vulnerable_code.py", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode in [0, 1, 2]:  # 0=no vulns, 1=high, 2=critical
            import json
            try:
                data = json.loads(result.stdout)
                vuln_count = data.get("vulnerabilities_found", 0)
                passed = vuln_count > 0
                message = f"Found {vuln_count} vulnerabilities (expected 8-10)" if passed else "No vulnerabilities detected"
                print_status("Scan Functionality", passed, message)
                return passed
            except json.JSONDecodeError:
                print_status("Scan Functionality", False, "Invalid JSON output")
                return False
        else:
            print_status("Scan Functionality", False, f"Scan failed with code {result.returncode}")
            return False
    except subprocess.TimeoutExpired:
        print_status("Scan Functionality", False, "Scan timed out")
        return False
    except Exception as e:
        print_status("Scan Functionality", False, str(e))
        return False


def test_llm_connection():
    """Test LLM connectivity"""
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        passed = response.status_code == 200
        message = "Ollama API responding" if passed else "Ollama API not responding"
        print_status("LLM Connection", passed, message)
        return passed
    except ImportError:
        print_status("LLM Connection", False, "requests library not found")
        return False
    except Exception as e:
        print_status("LLM Connection", False, "Cannot connect to Ollama - run: ollama serve")
        return False


def main():
    """Run all verification tests"""
    print_header("Parry Installation Verification")
    
    print("Running system checks...\n")
    
    results = []
    
    # Basic checks
    results.append(("Python", check_python()))
    results.append(("Ollama", check_ollama()))
    results.append(("Model", check_model()))
    results.append(("Parry", check_parry()))
    results.append(("Examples", check_example_files()))
    
    # Functional tests
    print("\nRunning functional tests...\n")
    results.append(("LLM Connection", test_llm_connection()))
    results.append(("Scan Test", test_scan()))
    
    # Summary
    print_header("Verification Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"Tests Passed: {passed}/{total}\n")
    
    if passed == total:
        print("✅ All checks passed! Parry is ready to use.\n")
        print("Next steps:")
        print("  1. Read the quick start: cat QUICKSTART.md")
        print("  2. Scan your code: parry scan /path/to/your/project")
        print("  3. Generate patches: parry patch /path/to/file.py --interactive")
        return 0
    else:
        print("❌ Some checks failed. Please review the errors above.\n")
        print("Common fixes:")
        print("  - Install Ollama: brew install ollama")
        print("  - Start Ollama: ollama serve")
        print("  - Pull model: ollama pull codellama:7b-instruct")
        print("  - Install Parry: pip install -e .")
        print("\nFor detailed help, see SETUP.md")
        return 1


if __name__ == "__main__":
    sys.exit(main())


