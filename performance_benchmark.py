#!/usr/bin/env python3
"""
Comprehensive Performance Benchmark for Valid8 Ultra-Precise Scanner

Tests precision, recall, speed, and F1-score across multiple codebases and languages.
Validates the 99.5% precision and 95% recall targets.

Usage:
    python performance_benchmark.py
    python performance_benchmark.py --comprehensive  # Full benchmark suite
"""

import sys
import os
import time
import json
import tempfile
import statistics
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add valid8 to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from valid8.scanner import Scanner
    from valid8.ultra_permissive_detector import UltraPermissivePatternDetector
    from valid8.ai_true_positive_validator import AITruePositiveValidator
except ImportError as e:
    print(f"❌ Failed to import Valid8 components: {e}")
    sys.exit(1)


@dataclass
class BenchmarkResult:
    """Result from a single benchmark test"""
    codebase_name: str
    language: str
    files_scanned: int
    vulnerabilities_found: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    scan_time_seconds: float
    files_per_second: float
    ai_validation_enabled: bool


@dataclass
class GroundTruth:
    """Ground truth data for a codebase"""
    sql_injections: List[Dict[str, Any]]
    xss_vulnerabilities: List[Dict[str, Any]]
    command_injections: List[Dict[str, Any]]
    deserialization_vulns: List[Dict[str, Any]]
    path_traversals: List[Dict[str, Any]]
    secrets_exposures: List[Dict[str, Any]]

    @property
    def total_vulnerabilities(self) -> int:
        """Total expected vulnerabilities"""
        return (len(self.sql_injections) + len(self.xss_vulnerabilities) +
                len(self.command_injections) + len(self.deserialization_vulns) +
                len(self.path_traversals) + len(self.secrets_exposures))


class PerformanceBenchmark:
    """
    Comprehensive performance benchmark for Valid8 scanner.

    Tests precision, recall, speed, and F1-score across multiple scenarios.
    """

    def __init__(self):
        self.scanner = Scanner()
        self.test_codebases = self._create_test_codebases()
        self.ground_truth = self._create_ground_truth()

    def run_full_benchmark(self) -> Dict[str, Any]:
        """Run comprehensive benchmark across all test scenarios"""
        print("🚀 VALID8 ULTRA-PRECISE SCANNER - COMPREHENSIVE BENCHMARK")
        print("=" * 70)

        results = []
        start_time = time.time()

        # Test each codebase
        for codebase_name, codebase_info in self.test_codebases.items():
            print(f"\\n🔬 Testing {codebase_name} ({codebase_info['language']})")
            print("-" * 50)

            result = self._benchmark_codebase(codebase_name, codebase_info)
            results.append(result)

            self._print_result_summary(result)

        # Calculate aggregate metrics
        total_time = time.time() - start_time
        aggregate_results = self._calculate_aggregate_metrics(results)

        print("\\n🏆 FINAL AGGREGATE RESULTS")
        print("=" * 50)
        print(f"📊 Codebases tested: {len(results)}")
        print(f"🌍 Languages covered: {len(set(r.language for r in results))}")
        print(f"📁 Total files scanned: {sum(r.files_scanned for r in results)}")
        print(f"⏱️  Total benchmark time: {total_time:.2f} seconds")
        print()
        print("🎯 PERFORMANCE METRICS:")
        print(f"   🎯 Precision: {aggregate_results['precision']:.3f} (Target: 0.995)")
        print(f"   🔍 Recall: {aggregate_results['recall']:.3f} (Target: 0.950)")
        print(f"   🏅 F1-Score: {aggregate_results['f1_score']:.3f} (Target: 0.970)")
        print(f"   🏃‍♂️ Avg Speed: {aggregate_results['avg_files_per_second']:.1f} files/sec")

        # Target validation
        self._validate_targets(aggregate_results)

        return {
            'timestamp': time.time(),
            'total_time': total_time,
            'results': [self._result_to_dict(r) for r in results],
            'aggregate': aggregate_results,
            'targets_achieved': self._check_targets_achieved(aggregate_results)
        }

    def _benchmark_codebase(self, name: str, info: Dict[str, Any]) -> BenchmarkResult:
        """Benchmark a single codebase"""
        codebase_path = info['path']
        language = info['language']
        ground_truth = self.ground_truth[name]

        # Run ultra-precise scan
        scan_start = time.time()
        scan_results = self.scanner.scan_ultra_precise(codebase_path)
        scan_time = time.time() - scan_start

        # Extract detected vulnerabilities
        detected_vulns = scan_results['vulnerabilities']

        # Calculate precision/recall against ground truth
        precision, recall, f1, tp, fp, fn = self._calculate_precision_recall(
            detected_vulns, ground_truth
        )

        return BenchmarkResult(
            codebase_name=name,
            language=language,
            files_scanned=scan_results['files_scanned'],
            vulnerabilities_found=len(detected_vulns),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            scan_time_seconds=scan_time,
            files_per_second=scan_results['files_scanned'] / scan_time if scan_time > 0 else 0,
            ai_validation_enabled=scan_results['ai_validation_enabled']
        )

    def _calculate_precision_recall(self, detected: List[Dict], ground_truth: GroundTruth) -> Tuple[float, float, float, int, int, int]:
        """Calculate precision, recall, and F1-score"""
        detected_cwes = set()
        for vuln in detected:
            # Extract CWE and file:line info for matching
            cwe = vuln.get('cwe', '')
            file_path = vuln.get('file_path', '')
            line = vuln.get('line_number', 0)
            key = f"{cwe}:{file_path}:{line}"
            detected_cwes.add(key)

        # Ground truth vulnerabilities
        expected_cwes = set()
        for vuln_list in [ground_truth.sql_injections, ground_truth.xss_vulnerabilities,
                         ground_truth.command_injections, ground_truth.deserialization_vulns,
                         ground_truth.path_traversals, ground_truth.secrets_exposures]:
            for vuln in vuln_list:
                cwe = vuln.get('cwe', '')
                file_path = vuln.get('file_path', '')
                line = vuln.get('line_number', 0)
                key = f"{cwe}:{file_path}:{line}"
                expected_cwes.add(key)

        # Calculate metrics
        true_positives = len(detected_cwes & expected_cwes)
        false_positives = len(detected_cwes - expected_cwes)
        false_negatives = len(expected_cwes - detected_cwes)

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 1.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 1.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return precision, recall, f1_score, true_positives, false_positives, false_negatives

    def _calculate_aggregate_metrics(self, results: List[BenchmarkResult]) -> Dict[str, float]:
        """Calculate aggregate metrics across all benchmarks"""
        if not results:
            return {}

        total_tp = sum(r.true_positives for r in results)
        total_fp = sum(r.false_positives for r in results)
        total_fn = sum(r.false_negatives for r in results)

        # Aggregate precision/recall
        agg_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
        agg_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
        agg_f1 = 2 * (agg_precision * agg_recall) / (agg_precision + agg_recall) if (agg_precision + agg_recall) > 0 else 0.0

        # Performance metrics
        avg_files_per_second = statistics.mean(r.files_per_second for r in results)
        total_scan_time = sum(r.scan_time_seconds for r in results)

        return {
            'precision': agg_precision,
            'recall': agg_recall,
            'f1_score': agg_f1,
            'total_true_positives': total_tp,
            'total_false_positives': total_fp,
            'total_false_negatives': total_fn,
            'avg_files_per_second': avg_files_per_second,
            'total_scan_time': total_scan_time,
            'codebases_tested': len(results)
        }

    def _validate_targets(self, aggregate: Dict[str, float]):
        """Validate against target metrics"""
        precision_target = 0.995
        recall_target = 0.950
        f1_target = 0.970

        print("\\n🎯 TARGET VALIDATION:")
        print("-" * 30)

        # Precision check
        if aggregate['precision'] >= precision_target:
            print(f"✅ PRECISION: {aggregate['precision']:.3f} ≥ {precision_target:.3f} ✓ TARGET ACHIEVED")
        else:
            print(f"❌ PRECISION: {aggregate['precision']:.3f} < {precision_target:.3f} ✗ TARGET MISSED")

        # Recall check
        if aggregate['recall'] >= recall_target:
            print(f"✅ RECALL: {aggregate['recall']:.3f} ≥ {recall_target:.3f} ✓ TARGET ACHIEVED")
        else:
            print(f"❌ RECALL: {aggregate['recall']:.3f} < {recall_target:.3f} ✗ TARGET MISSED")

        # F1 check
        if aggregate['f1_score'] >= f1_target:
            print(f"✅ F1-SCORE: {aggregate['f1_score']:.3f} ≥ {f1_target:.3f} ✓ TARGET ACHIEVED")
        else:
            print(f"❌ F1-SCORE: {aggregate['f1_score']:.3f} < {f1_target:.3f} ✗ TARGET MISSED")

    def _check_targets_achieved(self, aggregate: Dict[str, float]) -> bool:
        """Check if all targets are achieved"""
        return (aggregate['precision'] >= 0.995 and
                aggregate['recall'] >= 0.950 and
                aggregate['f1_score'] >= 0.970)

    def _print_result_summary(self, result: BenchmarkResult):
        """Print summary for a single benchmark result"""
        print(f"   📁 Files scanned: {result.files_scanned}")
        print(f"   ⏱️  Scan time: {result.scan_time_seconds:.2f}s")
        print(f"   🏃‍♂️ Speed: {result.files_per_second:.1f} files/sec")
        print(f"   🎯 Precision: {result.precision:.3f}")
        print(f"   🔍 Recall: {result.recall:.3f}")
        print(f"   🏅 F1-Score: {result.f1_score:.3f}")
        print(f"   ✅ True Positives: {result.true_positives}")
        print(f"   ❌ False Positives: {result.false_positives}")
        print(f"   ⚠️  False Negatives: {result.false_negatives}")

    def _result_to_dict(self, result: BenchmarkResult) -> Dict[str, Any]:
        """Convert BenchmarkResult to dictionary"""
        return {
            'codebase_name': result.codebase_name,
            'language': result.language,
            'files_scanned': result.files_scanned,
            'vulnerabilities_found': result.vulnerabilities_found,
            'true_positives': result.true_positives,
            'false_positives': result.false_positives,
            'false_negatives': result.false_negatives,
            'precision': result.precision,
            'recall': result.recall,
            'f1_score': result.f1_score,
            'scan_time_seconds': result.scan_time_seconds,
            'files_per_second': result.files_per_second,
            'ai_validation_enabled': result.ai_validation_enabled
        }

    def _create_test_codebases(self) -> Dict[str, Dict[str, Any]]:
        """Create test codebases with known vulnerabilities"""
        codebases = {}

        # Create temporary directory for test codebases
        temp_dir = Path(tempfile.mkdtemp())

        # Python test codebase
        python_dir = temp_dir / "python_test"
        python_dir.mkdir()
        self._create_python_test_files(python_dir)
        codebases['python_test'] = {
            'path': str(python_dir),
            'language': 'python'
        }

        # JavaScript test codebase
        js_dir = temp_dir / "javascript_test"
        js_dir.mkdir()
        self._create_javascript_test_files(js_dir)
        codebases['javascript_test'] = {
            'path': str(js_dir),
            'language': 'javascript'
        }

        # Mixed codebase
        mixed_dir = temp_dir / "mixed_test"
        mixed_dir.mkdir()
        self._create_mixed_test_files(mixed_dir)
        codebases['mixed_test'] = {
            'path': str(mixed_dir),
            'language': 'mixed'
        }

        # Store temp directory for cleanup
        self.temp_dir = temp_dir

        return codebases

    def _create_python_test_files(self, base_dir: Path):
        """Create Python test files with known vulnerabilities"""
        # SQL Injection vulnerability
        sql_file = base_dir / "sql_vuln.py"
        sql_file.write_text('''
import sqlite3

def vulnerable_sql(user_input):
    # CWE-89: SQL Injection - LINE 6
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"  # VULNERABLE
    cursor.execute(query)
    return cursor.fetchall()

def safe_sql(user_input):
    # This is safe
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
    return cursor.fetchall()
''')

        # XSS vulnerability
        xss_file = base_dir / "xss_vuln.py"
        xss_file.write_text('''
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # CWE-79: XSS - LINE 9
    return f"<h1>Results for: {query}</h1>"  # VULNERABLE

@app.route('/safe_search')
def safe_search():
    query = request.args.get('q', '')
    # This is safe
    from html import escape
    return f"<h1>Results for: {escape(query)}</h1>"
''')

        # Command injection
        cmd_file = base_dir / "cmd_vuln.py"
        cmd_file.write_text('''
import subprocess

def vulnerable_cmd(user_cmd):
    # CWE-78: Command Injection - LINE 5
    result = subprocess.run(user_cmd, shell=True)  # VULNERABLE
    return result.returncode

def safe_cmd(user_cmd):
    # This is safe
    import shlex
    result = subprocess.run(shlex.split(user_cmd))
    return result.returncode
''')

        # Secrets exposure
        secrets_file = base_dir / "secrets.py"
        secrets_file.write_text('''
# CWE-798: Secrets in code - LINE 3
API_KEY = "sk-1234567890abcdef"  # VULNERABLE

# Safe usage (would be from env)
# API_KEY = os.environ.get('API_KEY')
''')

    def _create_javascript_test_files(self, base_dir: Path):
        """Create JavaScript test files with known vulnerabilities"""
        # XSS vulnerability
        xss_file = base_dir / "xss.js"
        xss_file.write_text('''
// CWE-79: XSS - LINE 5
function vulnerableSearch(query) {
    const element = document.getElementById('results');
    element.innerHTML = `<h1>Results for: ${query}</h1>`; // VULNERABLE
}

function safeSearch(query) {
    const element = document.getElementById('results');
    element.textContent = `Results for: ${query}`; // SAFE
}
''')

        # Command injection (Node.js)
        cmd_file = base_dir / "cmd.js"
        cmd_file.write_text('''
const { exec } = require('child_process');

// CWE-78: Command Injection - LINE 5
function vulnerableExec(userCmd) {
    exec(userCmd, (error, stdout, stderr) => { // VULNERABLE
        console.log(stdout);
    });
}

function safeExec(userCmd) {
    const { spawn } = require('child_process');
    const child = spawn('sh', ['-c', userCmd]); // SAFER
}
''')

    def _create_mixed_test_files(self, base_dir: Path):
        """Create mixed language test files"""
        # Add more complex scenarios here
        complex_file = base_dir / "complex.py"
        complex_file.write_text('''
# Mixed vulnerabilities for testing
import os
import sqlite3

def complex_vuln(user_data):
    # Multiple issues
    query = f"SELECT * FROM table WHERE id = {user_data['id']}"  # SQLi
    os.system(user_data['cmd'])  # Command injection
    return eval(user_data['code'])  # Code injection
''')

    def _create_ground_truth(self) -> Dict[str, GroundTruth]:
        """Create ground truth data for all test codebases"""
        return {
            'python_test': GroundTruth(
                sql_injections=[{
                    'cwe': 'CWE-89',
                    'file_path': 'sql_vuln.py',
                    'line_number': 6,
                    'description': 'F-string SQL injection'
                }],
                xss_vulnerabilities=[{
                    'cwe': 'CWE-79',
                    'file_path': 'xss_vuln.py',
                    'line_number': 9,
                    'description': 'Unsanitized user input in HTML'
                }],
                command_injections=[{
                    'cwe': 'CWE-78',
                    'file_path': 'cmd_vuln.py',
                    'line_number': 5,
                    'description': 'shell=True in subprocess.run'
                }],
                deserialization_vulns=[],
                path_traversals=[],
                secrets_exposures=[{
                    'cwe': 'CWE-798',
                    'file_path': 'secrets.py',
                    'line_number': 3,
                    'description': 'Hardcoded API key'
                }]
            ),
            'javascript_test': GroundTruth(
                sql_injections=[],
                xss_vulnerabilities=[{
                    'cwe': 'CWE-79',
                    'file_path': 'xss.js',
                    'line_number': 5,
                    'description': 'innerHTML with template literal'
                }],
                command_injections=[{
                    'cwe': 'CWE-78',
                    'file_path': 'cmd.js',
                    'line_number': 5,
                    'description': 'exec() with user input'
                }],
                deserialization_vulns=[],
                path_traversals=[],
                secrets_exposures=[]
            ),
            'mixed_test': GroundTruth(
                sql_injections=[{
                    'cwe': 'CWE-89',
                    'file_path': 'complex.py',
                    'line_number': 8,
                    'description': 'F-string SQL injection in complex function'
                }],
                xss_vulnerabilities=[],
                command_injections=[{
                    'cwe': 'CWE-78',
                    'file_path': 'complex.py',
                    'line_number': 9,
                    'description': 'os.system with user data'
                }],
                deserialization_vulns=[],
                path_traversals=[],
                secrets_exposures=[]
            )
        }


def main():
    """Main benchmark execution"""
    import argparse

    parser = argparse.ArgumentParser(description='Valid8 Performance Benchmark')
    parser.add_argument('--comprehensive', action='store_true',
                       help='Run comprehensive benchmark suite')
    parser.add_argument('--output', type=str, default='benchmark_results.json',
                       help='Output file for results')

    args = parser.parse_args()

    try:
        benchmark = PerformanceBenchmark()

        if args.comprehensive:
            results = benchmark.run_full_benchmark()
        else:
            # Quick benchmark
            results = benchmark.run_full_benchmark()

        # Save results
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\\n📊 Results saved to {args.output}")

        # Check if targets achieved
        if results['targets_achieved']:
            print("\\n🎉 SUCCESS: All performance targets achieved!")
            print("   ✅ 99.5% Precision ✓")
            print("   ✅ 95% Recall ✓")
            print("   ✅ 97% F1-Score ✓")
            return 0
        else:
            print("\\n⚠️  PARTIAL: Some targets not fully achieved")
            print("   Additional optimization may be needed")
            return 1

    except Exception as e:
        print(f"❌ Benchmark failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
