#!/usr/bin/env python3
"""
Comprehensive Benchmark: Parry vs Snyk

Tests recall, precision, F1 score, false positive rate on known vulnerable code.
"""

import json
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
import sys

@dataclass
class BenchmarkMetrics:
    """Metrics for a single tool"""
    tool_name: str
    vulnerabilities_found: int
    true_positives: int
    false_positives: int
    false_negatives: int
    scan_time: float
    recall: float
    precision: float
    f1_score: float
    false_positive_rate: float
    unique_findings: int  # Findings only this tool detected

# Ground truth: Known vulnerabilities in test cases
GROUND_TRUTH = {
    'test_sqli.py': [
        {'cwe': 'CWE-89', 'line': 10, 'type': 'SQL Injection'},
        {'cwe': 'CWE-89', 'line': 15, 'type': 'SQL Injection'},
    ],
    'test_xss.py': [
        {'cwe': 'CWE-79', 'line': 8, 'type': 'XSS'},
        {'cwe': 'CWE-79', 'line': 12, 'type': 'XSS'},
    ],
    'test_auth.py': [
        {'cwe': 'CWE-285', 'line': 20, 'type': 'Broken Access Control'},
        {'cwe': 'CWE-306', 'line': 30, 'type': 'Missing Authentication'},
    ],
    'test_crypto.py': [
        {'cwe': 'CWE-327', 'line': 5, 'type': 'Weak Cryptography'},
        {'cwe': 'CWE-330', 'line': 12, 'type': 'Weak Randomness'},
    ],
    'test_idor.py': [
        {'cwe': 'CWE-639', 'line': 18, 'type': 'IDOR'},
    ],
    'test_race.py': [
        {'cwe': 'CWE-362', 'line': 25, 'type': 'Race Condition'},
    ],
    'test_session.py': [
        {'cwe': 'CWE-384', 'line': 15, 'type': 'Session Fixation'},
    ],
    'test_info_leak.py': [
        {'cwe': 'CWE-200', 'line': 22, 'type': 'Information Disclosure'},
    ],
}

def create_test_cases():
    """Create test files with known vulnerabilities"""
    test_dir = Path('./benchmark_test_cases')
    test_dir.mkdir(exist_ok=True)
    
    # SQL Injection
    (test_dir / 'test_sqli.py').write_text("""
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    
    # VULNERABLE: SQL Injection
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)  # Line 10
    
    # VULNERABLE: SQL Injection via f-string
    query2 = f"SELECT * FROM users WHERE name = '{user_id}'"
    cursor.execute(query2)  # Line 15
    
    return cursor.fetchall()
""")
    
    # XSS
    (test_dir / 'test_xss.py').write_text("""
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: XSS - unsanitized output
    return f"<h1>Search results for: {query}</h1>"  # Line 8

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # VULNERABLE: XSS in template
    return render_template_string(f"<h1>Hello {name}</h1>")  # Line 12
""")
    
    # Access Control
    (test_dir / 'test_auth.py').write_text("""
from flask import Flask, request, jsonify

app = Flask(__name__)

users = {'alice': {'role': 'user'}, 'bob': {'role': 'admin'}}

@app.route('/admin/delete_user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    # VULNERABLE: Missing authorization check
    # Anyone can delete users without checking if they're admin
    if user_id in users:
        del users[user_id]
        return jsonify({'success': True})  # Line 20
    return jsonify({'error': 'User not found'})

@app.route('/api/sensitive_data')
def get_sensitive_data():
    # VULNERABLE: Missing authentication
    # No check if user is logged in
    sensitive_data = {'ssn': '123-45-6789', 'credit_card': '4111-1111-1111-1111'}
    return jsonify(sensitive_data)  # Line 30
""")
    
    # Cryptography
    (test_dir / 'test_crypto.py').write_text("""
import hashlib
import random

def hash_password(password):
    # VULNERABLE: Weak hash (MD5)
    return hashlib.md5(password.encode()).hexdigest()  # Line 5

def generate_token():
    # VULNERABLE: Weak randomness for security token
    token = ""
    for i in range(32):
        token += str(random.randint(0, 9))  # Line 12
    return token
""")
    
    # IDOR
    (test_dir / 'test_idor.py').write_text("""
from flask import Flask, request, jsonify

app = Flask(__name__)

documents = {
    1: {'owner': 'alice', 'content': 'Alice private doc'},
    2: {'owner': 'bob', 'content': 'Bob private doc'},
}

@app.route('/document/<int:doc_id>')
def get_document(doc_id):
    current_user = request.args.get('user')
    
    # VULNERABLE: IDOR - no ownership check
    if doc_id in documents:
        return jsonify(documents[doc_id])  # Line 18
    return jsonify({'error': 'Not found'})
""")
    
    # Race Condition
    (test_dir / 'test_race.py').write_text("""
balance = 1000

def withdraw(amount):
    global balance
    
    # Check balance
    if balance >= amount:
        # VULNERABLE: Race condition (TOCTOU)
        # Another thread could withdraw between check and update
        import time
        time.sleep(0.01)  # Simulating processing
        balance -= amount  # Line 25
        return True
    return False
""")
    
    # Session Fixation
    (test_dir / 'test_session.py').write_text("""
from flask import Flask, session

app = Flask(__name__)
app.secret_key = 'dev'

@app.route('/login', methods=['POST'])
def login():
    # Authenticate user...
    user = {'id': 123, 'name': 'Alice'}
    
    # VULNERABLE: Session fixation - not regenerating session ID
    session['user'] = user  # Line 15
    return 'Logged in'
""")
    
    # Information Disclosure
    (test_dir / 'test_info_leak.py').write_text("""
from flask import Flask, jsonify
import traceback

app = Flask(__name__)
app.config['DEBUG'] = True  # VULNERABLE: Debug mode in production

@app.route('/api/process')
def process():
    try:
        result = some_complex_operation()
        return jsonify(result)
    except Exception as e:
        # VULNERABLE: Information disclosure via detailed error
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()})  # Line 22
""")
    
    print(f"✅ Created {len(GROUND_TRUTH)} test files in {test_dir}")
    return test_dir

def run_parry(test_dir: Path, mode: str = 'hybrid') -> Dict[str, Any]:
    """Run Parry scanner"""
    print(f"\n🔍 Running Parry ({mode} mode)...")
    output_file = Path(f'parry_{mode}_results.json')
    
    start = time.time()
    result = subprocess.run(
        ['parry', 'scan', str(test_dir), '--mode', mode, '--format', 'json', '--output', str(output_file)],
        capture_output=True,
        text=True
    )
    scan_time = time.time() - start
    
    if output_file.exists():
        with open(output_file) as f:
            data = json.load(f)
            return {'vulnerabilities': data.get('vulnerabilities', []), 'scan_time': scan_time}
    
    return {'vulnerabilities': [], 'scan_time': scan_time}

def run_snyk(test_dir: Path) -> Dict[str, Any]:
    """Run Snyk Code scanner"""
    print("\n🔍 Running Snyk Code...")
    
    start = time.time()
    try:
        result = subprocess.run(
            ['snyk', 'code', 'test', str(test_dir), '--json'],
            capture_output=True,
            text=True,
            timeout=300
        )
        scan_time = time.time() - start
        
        data = json.loads(result.stdout)
        vulnerabilities = []
        
        # Parse Snyk output
        if 'runs' in data and len(data['runs']) > 0:
            for run in data['runs']:
                for vuln in run.get('results', []):
                    vulnerabilities.append({
                        'file_path': vuln.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', ''),
                        'line_number': vuln.get('locations', [{}])[0].get('physicalLocation', {}).get('region', {}).get('startLine', 0),
                        'cwe': vuln.get('ruleId', ''),
                        'severity': vuln.get('level', 'unknown')
                    })
        
        return {'vulnerabilities': vulnerabilities, 'scan_time': scan_time}
    except subprocess.TimeoutExpired:
        return {'vulnerabilities': [], 'scan_time': 300}
    except Exception as e:
        print(f"⚠️  Snyk not available: {e}")
        return {'vulnerabilities': [], 'scan_time': 0}

def calculate_metrics(tool_name: str, findings: List[Dict], scan_time: float, other_findings: List[Dict] = None) -> BenchmarkMetrics:
    """Calculate comprehensive metrics"""
    
    # Calculate TP, FP, FN
    true_positives = 0
    false_positives = 0
    detected_vulns = set()
    
    for finding in findings:
        file_name = Path(finding.get('file_path', '')).name
        line = finding.get('line_number', 0)
        cwe = finding.get('cwe', '')
        
        # Check if this matches ground truth
        matched = False
        if file_name in GROUND_TRUTH:
            for gt_vuln in GROUND_TRUTH[file_name]:
                if abs(gt_vuln['line'] - line) <= 2:  # Allow 2 line tolerance
                    if cwe.replace('CWE-', '') == gt_vuln['cwe'].replace('CWE-', ''):
                        true_positives += 1
                        detected_vulns.add((file_name, gt_vuln['line'], gt_vuln['cwe']))
                        matched = True
                        break
        
        if not matched:
            false_positives += 1
    
    # Calculate false negatives
    total_vulns = sum(len(vulns) for vulns in GROUND_TRUTH.values())
    false_negatives = total_vulns - true_positives
    
    # Calculate metrics
    recall = true_positives / total_vulns if total_vulns > 0 else 0
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fp_rate = false_positives / (false_positives + true_positives) if (false_positives + true_positives) > 0 else 0
    
    # Calculate unique findings (only this tool detected)
    unique_findings = 0
    if other_findings is not None:
        other_detected = set()
        for finding in other_findings:
            file_name = Path(finding.get('file_path', '')).name
            line = finding.get('line_number', 0)
            other_detected.add((file_name, line))
        
        for finding in findings:
            file_name = Path(finding.get('file_path', '')).name
            line = finding.get('line_number', 0)
            if (file_name, line) not in other_detected:
                unique_findings += 1
    
    return BenchmarkMetrics(
        tool_name=tool_name,
        vulnerabilities_found=len(findings),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        scan_time=scan_time,
        recall=recall,
        precision=precision,
        f1_score=f1_score,
        false_positive_rate=fp_rate,
        unique_findings=unique_findings
    )

def print_results(parry_metrics: BenchmarkMetrics, snyk_metrics: BenchmarkMetrics = None):
    """Print comprehensive comparison"""
    
    print("\n" + "="*80)
    print(" BENCHMARK RESULTS: Parry vs Snyk")
    print("="*80)
    
    print(f"\n📊 GROUND TRUTH: {sum(len(v) for v in GROUND_TRUTH.values())} known vulnerabilities")
    
    # Parry Results
    print(f"\n🔒 PARRY ({parry_metrics.tool_name}):")
    print(f"  Vulnerabilities Found: {parry_metrics.vulnerabilities_found}")
    print(f"  True Positives: {parry_metrics.true_positives}")
    print(f"  False Positives: {parry_metrics.false_positives}")
    print(f"  False Negatives: {parry_metrics.false_negatives}")
    print(f"  ──────────────────────────────")
    print(f"  Recall: {parry_metrics.recall:.2%} ✅" if parry_metrics.recall >= 0.85 else f"  Recall: {parry_metrics.recall:.2%}")
    print(f"  Precision: {parry_metrics.precision:.2%} ✅" if parry_metrics.precision >= 0.90 else f"  Precision: {parry_metrics.precision:.2%}")
    print(f"  F1 Score: {parry_metrics.f1_score:.3f}")
    print(f"  False Positive Rate: {parry_metrics.false_positive_rate:.2%}")
    print(f"  Scan Time: {parry_metrics.scan_time:.2f}s")
    if parry_metrics.unique_findings > 0:
        print(f"  Unique Findings: {parry_metrics.unique_findings} (only Parry detected)")
    
    # Snyk Results
    if snyk_metrics:
        print(f"\n⚡ SNYK:")
        print(f"  Vulnerabilities Found: {snyk_metrics.vulnerabilities_found}")
        print(f"  True Positives: {snyk_metrics.true_positives}")
        print(f"  False Positives: {snyk_metrics.false_positives}")
        print(f"  False Negatives: {snyk_metrics.false_negatives}")
        print(f"  ──────────────────────────────")
        print(f"  Recall: {snyk_metrics.recall:.2%}")
        print(f"  Precision: {snyk_metrics.precision:.2%}")
        print(f"  F1 Score: {snyk_metrics.f1_score:.3f}")
        print(f"  False Positive Rate: {snyk_metrics.false_positive_rate:.2%}")
        print(f"  Scan Time: {snyk_metrics.scan_time:.2f}s")
        if snyk_metrics.unique_findings > 0:
            print(f"  Unique Findings: {snyk_metrics.unique_findings} (only Snyk detected)")
        
        # Comparison
        print(f"\n📈 COMPARISON:")
        print(f"  Recall: Parry {parry_metrics.recall:.2%} vs Snyk {snyk_metrics.recall:.2%} " +
              ("✅ Parry wins" if parry_metrics.recall > snyk_metrics.recall else "⚠️  Snyk wins"))
        print(f"  Precision: Parry {parry_metrics.precision:.2%} vs Snyk {snyk_metrics.precision:.2%} " +
              ("✅ Parry wins" if parry_metrics.precision > snyk_metrics.precision else "⚠️  Snyk wins"))
        print(f"  F1 Score: Parry {parry_metrics.f1_score:.3f} vs Snyk {snyk_metrics.f1_score:.3f} " +
              ("✅ Parry wins" if parry_metrics.f1_score > snyk_metrics.f1_score else "⚠️  Snyk wins"))
        print(f"  Speed: Parry {parry_metrics.scan_time:.2f}s vs Snyk {snyk_metrics.scan_time:.2f}s " +
              ("✅ Parry faster" if parry_metrics.scan_time < snyk_metrics.scan_time else "⚠️  Snyk faster"))
    
    print("\n" + "="*80)

def main():
    """Run comprehensive benchmark"""
    print("🚀 Starting Comprehensive Benchmark: Parry vs Snyk\n")
    
    # Create test cases
    test_dir = create_test_cases()
    
    # Run Parry
    parry_results = run_parry(test_dir, mode='hybrid')
    parry_metrics = calculate_metrics(
        'Parry Hybrid',
        parry_results['vulnerabilities'],
        parry_results['scan_time']
    )
    
    # Run Snyk
    snyk_results = run_snyk(test_dir)
    snyk_metrics = None
    if snyk_results['vulnerabilities']:
        snyk_metrics = calculate_metrics(
            'Snyk Code',
            snyk_results['vulnerabilities'],
            snyk_results['scan_time'],
            parry_results['vulnerabilities']
        )
        
        # Update Parry unique findings
        parry_metrics = calculate_metrics(
            'Parry Hybrid',
            parry_results['vulnerabilities'],
            parry_results['scan_time'],
            snyk_results['vulnerabilities']
        )
    
    # Print results
    print_results(parry_metrics, snyk_metrics)
    
    # Save results
    output_file = Path('benchmark_results.json')
    with open(output_file, 'w') as f:
        json.dump({
            'parry': asdict(parry_metrics),
            'snyk': asdict(snyk_metrics) if snyk_metrics else None,
            'ground_truth_count': sum(len(v) for v in GROUND_TRUTH.values())
        }, f, indent=2)
    
    print(f"\n💾 Results saved to {output_file}")

if __name__ == '__main__':
    main()

