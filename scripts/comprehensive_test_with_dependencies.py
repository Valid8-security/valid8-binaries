#!/usr/bin/env python3
"""
Comprehensive Test Script for Parry with SCA and Custom Rules
Tests Parry (Fast, Deep, Hybrid modes) with SCA and custom rules enabled
against Snyk, Semgrep, and Bandit using pre-existing benchmark data.
"""
import json
import subprocess
import time
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import defaultdict
import tempfile

def run_parry_mode(target: Path, mode: str, sca: bool = False, custom_rules: Optional[Path] = None) -> Dict[str, Any]:
    """Run Parry in a specific mode with optional SCA and custom rules"""
    output_file = Path(tempfile.gettempdir()) / f"parry_{mode}_{int(time.time())}.json"
    
    cmd = [
        "parry", "scan", str(target),
        "--mode", mode,
        "--format", "json",
        "--output", str(output_file)
    ]
    
    if sca:
        cmd.append("--sca")
    
    if custom_rules:
        cmd.append("--custom-rules")
        cmd.append(str(custom_rules))
    
    try:
        start_time = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )
        duration = time.time() - start_time
        
        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
            
            vulns = data.get("vulnerabilities", [])
            code_vulns = [v for v in vulns if v.get("category") not in ["dependency", "custom-rule"]]
            dep_vulns = [v for v in vulns if v.get("category") == "dependency"]
            custom_vulns = [v for v in vulns if v.get("category") == "custom-rule"]
            
            return {
                "tool": f"Parry {mode.capitalize()}",
                "status": "success",
                "duration_seconds": round(duration, 2),
                "files_scanned": data.get("files_scanned", 0),
                "vulnerabilities_found": len(vulns),
                "code_vulnerabilities": len(code_vulns),
                "dependency_vulnerabilities": len(dep_vulns),
                "custom_rule_violations": len(custom_vulns),
                "vulnerabilities_per_second": round(len(vulns) / duration, 2) if duration > 0 else 0,
                "files_per_second": round(data.get("files_scanned", 0) / duration, 2) if duration > 0 else 0,
                "severity_breakdown": _count_by_severity(vulns),
                "cwe_coverage": len(set(v.get("cwe", "") for v in vulns if v.get("cwe"))),
                "raw_output_file": str(output_file)
            }
        else:
            return {
                "tool": f"Parry {mode.capitalize()}",
                "status": "error",
                "error": "No output file generated",
                "duration_seconds": round(duration, 2)
            }
    
    except subprocess.TimeoutExpired:
        return {
            "tool": f"Parry {mode.capitalize()}",
            "status": "timeout",
            "duration_seconds": 600
        }
    except Exception as e:
        return {
            "tool": f"Parry {mode.capitalize()}",
            "status": "error",
            "error": str(e)
        }

def run_semgrep(target: Path, config: str) -> Dict[str, Any]:
    """Run Semgrep with a specific config"""
    output_file = Path(tempfile.gettempdir()) / f"semgrep_{config.replace('/', '_')}_{int(time.time())}.json"
    
    try:
        start_time = time.time()
        result = subprocess.run(
            ["semgrep", "--config", config, "--json", "-o", str(output_file), str(target)],
            capture_output=True,
            text=True,
            timeout=600
        )
        duration = time.time() - start_time
        
        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
            
            results = data.get("results", [])
            
            return {
                "tool": f"Semgrep ({config})",
                "status": "success",
                "duration_seconds": round(duration, 2),
                "files_scanned": len(set(r.get("path", "") for r in results)),
                "vulnerabilities_found": len(results),
                "vulnerabilities_per_second": round(len(results) / duration, 2) if duration > 0 else 0,
                "files_per_second": round(len(set(r.get("path", "") for r in results)) / duration, 2) if duration > 0 else 0,
                "severity_breakdown": _count_by_severity_semgrep(results),
                "raw_output_file": str(output_file)
            }
        else:
            return {
                "tool": f"Semgrep ({config})",
                "status": "error",
                "error": "No output file generated",
                "duration_seconds": round(duration, 2)
            }
    
    except subprocess.TimeoutExpired:
        return {
            "tool": f"Semgrep ({config})",
            "status": "timeout",
            "duration_seconds": 600
        }
    except FileNotFoundError:
        return {
            "tool": f"Semgrep ({config})",
            "status": "error",
            "error": "Semgrep not installed"
        }
    except Exception as e:
        return {
            "tool": f"Semgrep ({config})",
            "status": "error",
            "error": str(e)
        }

def run_bandit(target: Path) -> Dict[str, Any]:
    """Run Bandit security scanner"""
    output_file = Path(tempfile.gettempdir()) / f"bandit_{int(time.time())}.json"
    
    try:
        start_time = time.time()
        result = subprocess.run(
            ["bandit", "-r", str(target), "-f", "json", "-o", str(output_file)],
            capture_output=True,
            text=True,
            timeout=600
        )
        duration = time.time() - start_time
        
        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
            
            results = data.get("results", [])
            
            return {
                "tool": "Bandit",
                "status": "success",
                "duration_seconds": round(duration, 2),
                "files_scanned": len(set(r.get("filename", "") for r in results)),
                "vulnerabilities_found": len(results),
                "vulnerabilities_per_second": round(len(results) / duration, 2) if duration > 0 else 0,
                "severity_breakdown": _count_by_severity_bandit(results),
                "raw_output_file": str(output_file)
            }
        else:
            return {
                "tool": "Bandit",
                "status": "error",
                "error": "No output file generated",
                "duration_seconds": round(duration, 2)
            }
    
    except subprocess.TimeoutExpired:
        return {
            "tool": "Bandit",
            "status": "timeout",
            "duration_seconds": 600
        }
    except FileNotFoundError:
        return {
            "tool": "Bandit",
            "status": "error",
            "error": "Bandit not installed"
        }
    except Exception as e:
        return {
            "tool": "Bandit",
            "status": "error",
            "error": str(e)
        }

def _count_by_severity(vulns: List[Dict]) -> Dict[str, int]:
    """Count vulnerabilities by severity"""
    counts = defaultdict(int)
    for v in vulns:
        severity = v.get("severity", "low").lower()
        counts[severity] += 1
    return dict(counts)

def _count_by_severity_semgrep(results: List[Dict]) -> Dict[str, int]:
    """Count Semgrep results by severity"""
    counts = defaultdict(int)
    for r in results:
        severity = r.get("extra", {}).get("severity", "medium").lower()
        counts[severity] += 1
    return dict(counts)

def _count_by_severity_bandit(results: List[Dict]) -> Dict[str, int]:
    """Count Bandit results by severity"""
    counts = defaultdict(int)
    for r in results:
        severity = r.get("issue_severity", "low").lower()
        counts[severity] += 1
    return dict(counts)

def create_custom_rules_file() -> Path:
    """Create a sample custom rules file for testing"""
    rules_file = Path(tempfile.gettempdir()) / f"parry_custom_rules_{int(time.time())}.yaml"
    
    rules_content = """# Parry Custom Security Rules for Testing
rules:
  - id: test-eval-detection
    message: "Use of eval() is dangerous and should be avoided"
    severity: HIGH
    languages:
      - python
      - javascript
    patterns:
      - pattern: eval($EXPR)
    metadata:
      cwe: CWE-94
      category: code-quality
  
  - id: test-hardcoded-ip
    message: "Hardcoded IP address detected"
    severity: MEDIUM
    languages:
      - python
      - javascript
      - java
    pattern-either:
      - pattern: ip = "192.168..."
      - pattern: ip = "10.0..."
      - pattern: host = "127.0.0.1"
    metadata:
      cwe: CWE-547
"""
    
    rules_file.write_text(rules_content)
    return rules_file

def main():
    """Main test execution"""
    print("=" * 80)
    print("COMPREHENSIVE PARRY TEST WITH SCA & CUSTOM RULES")
    print("=" * 80)
    print()
    
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    test_target = repo_root / "examples"
    
    if not test_target.exists():
        print(f"Warning: Test target {test_target} not found, using current directory")
        test_target = Path(".")
    
    py_files = list(test_target.rglob("*.py"))
    print(f"Test Target: {test_target}")
    print(f"Python Files: {len(py_files)}")
    print()
    
    print("Creating custom rules file for testing...")
    custom_rules_file = create_custom_rules_file()
    print(f"✓ Custom rules created: {custom_rules_file}")
    print()
    
    results = {
        "timestamp": datetime.now().isoformat(),
        "test_target": str(test_target),
        "file_count": len(py_files),
        "note": "All metrics collected from actual tool runs on same codebase",
        "tools": []
    }
    
    # Test Parry modes
    print("Testing Parry Fast Mode...")
    results["tools"].append(run_parry_mode(test_target, "fast", sca=False))
    status = results["tools"][-1].get("status", "unknown")
    if status == "success":
        print(f"  ✓ Fast: {results['tools'][-1].get('vulnerabilities_found', 0)} vulns")
    else:
        print(f"  ✗ Fast: {status}")
    
    print("\nTesting Parry Fast Mode with SCA...")
    results["tools"].append(run_parry_mode(test_target, "fast", sca=True))
    if results["tools"][-1].get("status") == "success":
        r = results["tools"][-1]
        print(f"  ✓ Fast+SCA: {r.get('vulnerabilities_found', 0)} total ({r.get('code_vulnerabilities', 0)} code, {r.get('dependency_vulnerabilities', 0)} deps)")
    
    print("\nTesting Parry Fast Mode with Custom Rules...")
    results["tools"].append(run_parry_mode(test_target, "fast", sca=False, custom_rules=custom_rules_file))
    if results["tools"][-1].get("status") == "success":
        r = results["tools"][-1]
        print(f"  ✓ Fast+Custom: {r.get('vulnerabilities_found', 0)} total ({r.get('custom_rule_violations', 0)} custom)")
    
    print("\nTesting Parry Fast Mode with SCA and Custom Rules...")
    results["tools"].append(run_parry_mode(test_target, "fast", sca=True, custom_rules=custom_rules_file))
    if results["tools"][-1].get("status") == "success":
        r = results["tools"][-1]
        print(f"  ✓ Fast+SCA+Custom: {r.get('vulnerabilities_found', 0)} total")
    
    print("\nTesting Parry Hybrid Mode with SCA and Custom Rules...")
    results["tools"].append(run_parry_mode(test_target, "hybrid", sca=True, custom_rules=custom_rules_file))
    if results["tools"][-1].get("status") == "success":
        r = results["tools"][-1]
        print(f"  ✓ Hybrid+SCA+Custom: {r.get('vulnerabilities_found', 0)} total")
    
    # Test competitors
    print("\nTesting Semgrep (p/owasp-top-ten)...")
    results["tools"].append(run_semgrep(test_target, "p/owasp-top-ten"))
    if results["tools"][-1].get("status") == "success":
        print(f"  ✓ Semgrep OWASP: {results['tools'][-1].get('vulnerabilities_found', 0)} vulns")
    
    print("\nTesting Bandit...")
    results["tools"].append(run_bandit(test_target))
    if results["tools"][-1].get("status") == "success":
        print(f"  ✓ Bandit: {results['tools'][-1].get('vulnerabilities_found', 0)} vulns")
    
    # Save results
    output_file = repo_root / "comprehensive_test_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    successful = [t for t in results["tools"] if t.get("status") == "success"]
    
    if successful:
        print("\n✅ SUCCESSFUL TOOLS:")
        print("-" * 80)
        for tool in sorted(successful, key=lambda x: x.get("vulnerabilities_found", 0), reverse=True):
            name = tool.get("tool", "Unknown")
            vulns = tool.get("vulnerabilities_found", 0)
            duration = tool.get("duration_seconds", 0)
            
            breakdown = []
            if tool.get("code_vulnerabilities") is not None:
                breakdown.append(f"{tool.get('code_vulnerabilities')} code")
            if tool.get("dependency_vulnerabilities", 0) > 0:
                breakdown.append(f"{tool.get('dependency_vulnerabilities')} deps")
            if tool.get("custom_rule_violations", 0) > 0:
                breakdown.append(f"{tool.get('custom_rule_violations')} custom")
            
            breakdown_str = f" ({', '.join(breakdown)})" if breakdown else ""
            
            print(f"  {name:<45} {vulns:>4} vulns{breakdown_str:<25} {duration:>6.2f}s")
    
    print(f"\n✅ Complete results saved to: {output_file}")
    print("=" * 80)

if __name__ == "__main__":
    main()
