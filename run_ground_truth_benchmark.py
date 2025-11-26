#!/usr/bin/env python3
"""
Ground Truth Benchmark for Valid8

Uses comprehensive test datasets with known vulnerabilities (ground truth)
to properly evaluate Valid8's performance with precision, recall, and F1 scores.
"""

import os
import json
import time
import statistics
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess
import sys
from typing import List, Dict, Any

# Setup detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('ground_truth_benchmark.log', mode='w')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class GroundTruthBenchmarkResult:
    """Result from ground truth benchmark"""
    dataset: str
    language: str
    total_files: int
    expected_vulnerabilities: int
    detected_vulnerabilities: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    scan_time_seconds: float
    files_per_second: float
    timestamp: str

def load_ground_truth(test_dir: Path) -> Dict[str, Any]:
    """Load ground truth data for test cases"""
    logger.info(f"🔍 Scanning for ground truth files in {test_dir}")
    ground_truth_files = list(test_dir.glob("**/ground_truth.json"))
    logger.info(f"📁 Found {len(ground_truth_files)} ground truth files")

    if not ground_truth_files:
        logger.warning(f"No ground_truth.json files found in {test_dir}")
        return {}

    # Load all ground truth files
    all_ground_truth = {}
    total_expected_vulns = 0

    for i, gt_file in enumerate(ground_truth_files, 1):
        logger.info(f"📖 Loading ground truth file {i}/{len(ground_truth_files)}: {gt_file}")
        try:
            with open(gt_file, 'r') as f:
                gt_data = json.load(f)
                dataset_key = f"{gt_file.parent.parent.name}/{gt_file.parent.name}"
                all_ground_truth[dataset_key] = gt_data

                vuln_count = gt_data.get('expected_vulnerabilities', 0)
                total_expected_vulns += vuln_count

                logger.info(f"✅ Loaded {dataset_key}: {gt_data.get('total_files', 0)} files, {vuln_count} expected vulnerabilities")

        except Exception as e:
            logger.error(f"❌ Error loading {gt_file}: {e}")

    logger.info(f"📊 Ground truth loading complete: {len(all_ground_truth)} datasets, {total_expected_vulns} total expected vulnerabilities")
    return all_ground_truth

def run_valid8_on_dataset(test_dir: Path, ground_truth: Dict[str, Any]) -> List[GroundTruthBenchmarkResult]:
    """Run Valid8 on test datasets and compare against ground truth"""
    results = []
    total_start_time = time.time()

    logger.info("🚀 Starting Valid8 ground truth benchmark...")
    logger.info(f"📊 Processing {len(ground_truth)} datasets")

    # Process each dataset
    for dataset_idx, (dataset_key, gt_data) in enumerate(ground_truth.items(), 1):
        dataset_start_time = time.time()
        logger.info(f"🔄 Dataset {dataset_idx}/{len(ground_truth)}: {dataset_key}")

        dataset_path = test_dir / dataset_key.replace('/', '/')
        if not dataset_path.exists():
            logger.warning(f"Dataset path not found: {dataset_path}")
            continue

        logger.info(f"📂 Dataset path: {dataset_path}")

        # Get test files
        test_files = []
        for ext in ['*.py', '*.js', '*.java', '*.ts', '*.kt']:
            files_found = list(dataset_path.glob(ext))
            test_files.extend(files_found)
            logger.debug(f"Found {len(files_found)} {ext} files")

        if not test_files:
            logger.warning(f"No test files found in {dataset_path}")
            continue

        logger.info(f"📄 Found {len(test_files)} test files to scan")
        expected_vulns = gt_data.get('vulnerabilities', [])
        logger.info(f"🎯 Ground truth: {len(expected_vulns)} expected vulnerabilities")

        # Run Valid8 on all files in this dataset
        all_detected_vulns = []
        successful_scans = 0
        failed_scans = 0

        logger.info("🔍 Starting Valid8 scans in hybrid mode (all features enabled)...")

        for file_idx, test_file in enumerate(test_files, 1):
            logger.info(f"📋 File {file_idx}/{len(test_files)}: {test_file.name}")

            try:
                # Run Valid8 in hybrid mode (uses all features)
                cmd = [
                    sys.executable, "-m", "valid8.cli",
                    "scan", str(test_file),
                    "--format", "json",
                    "--mode", "hybrid"  # Use all Valid8 features
                ]

                logger.debug(f"Running command: {' '.join(cmd)}")
                scan_start = time.time()

                result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(__file__), timeout=300)

                scan_time = time.time() - scan_start
                logger.debug(f"Scan completed in {scan_time:.2f} seconds")

                if result.returncode == 0:
                    try:
                        scan_data = json.loads(result.stdout)
                        detected_vulns = scan_data.get('vulnerabilities', [])
                        all_detected_vulns.extend(detected_vulns)
                        successful_scans += 1
                        logger.info(f"✅ {test_file.name}: Found {len(detected_vulns)} vulnerabilities")
                        logger.debug(f"   Vulnerabilities: {[v.get('cwe', 'unknown') for v in detected_vulns]}")
                    except json.JSONDecodeError as e:
                        failed_scans += 1
                        logger.error(f"❌ {test_file.name}: JSON parse error: {e}")
                        logger.debug(f"Raw output: {result.stdout[:500]}...")
                else:
                    failed_scans += 1
                    logger.error(f"❌ {test_file.name}: Scan failed (exit code {result.returncode})")
                    logger.debug(f"Stderr: {result.stderr[:500]}...")

            except subprocess.TimeoutExpired:
                failed_scans += 1
                logger.error(f"❌ {test_file.name}: Scan timed out (5 minutes)")
            except Exception as e:
                failed_scans += 1
                logger.error(f"❌ {test_file.name}: Scan error: {e}")

        dataset_time = time.time() - dataset_start_time
        logger.info(f"📊 Dataset {dataset_key} scan complete:")
        logger.info(f"   ⏱️  Total time: {dataset_time:.2f} seconds")
        logger.info(f"   📈 Files processed: {successful_scans} successful, {failed_scans} failed")
        logger.info(f"   🔍 Total vulnerabilities detected: {len(all_detected_vulns)}")

        # Compare against ground truth
        expected_vulns = gt_data.get('vulnerabilities', [])
        logger.info(f"🔍 Comparing {len(all_detected_vulns)} detected vs {len(expected_vulns)} expected vulnerabilities")

        true_positives = 0
        false_positives = 0

        logger.info("🔎 Analyzing detected vulnerabilities for matches...")
        # For each detected vulnerability, check if it matches ground truth
        for detected_idx, detected in enumerate(all_detected_vulns, 1):
            detected_file = detected.get('file_path', '').split('/')[-1]
            detected_line = detected.get('line_number')
            detected_cwe = detected.get('cwe', '')

            logger.debug(f"   Checking detection {detected_idx}: {detected_file}:{detected_line} CWE-{detected_cwe}")

            # Check if this matches any expected vulnerability
            match_found = False
            for expected in expected_vulns:
                line_diff = abs(expected['line'] - detected_line)
                cwe_match = expected['cwe'] in detected_cwe

                if (expected['file'] == detected_file and
                    line_diff <= 2 and  # Allow small line differences
                    cwe_match):
                    true_positives += 1
                    match_found = True
                    logger.debug(f"     ✅ TRUE POSITIVE: Matches {expected['file']}:{expected['line']} CWE-{expected['cwe']} (line diff: {line_diff})")
                    break

            if not match_found:
                false_positives += 1
                logger.debug(f"     ❌ FALSE POSITIVE: No match found for {detected_file}:{detected_line} CWE-{detected_cwe}")

        logger.info(f"📊 Detection analysis complete: {true_positives} true positives, {false_positives} false positives")

        # Calculate false negatives (expected but not found)
        logger.info("🔍 Checking for false negatives (expected vulnerabilities not found)...")
        false_negatives = 0
        for expected_idx, expected in enumerate(expected_vulns, 1):
            expected_file = expected['file']
            expected_line = expected['line']
            expected_cwe = expected['cwe']

            logger.debug(f"   Checking expected {expected_idx}: {expected_file}:{expected_line} CWE-{expected_cwe}")

            match_found = False
            for detected in all_detected_vulns:
                detected_file = detected.get('file_path', '').split('/')[-1]
                detected_line = detected.get('line_number')
                detected_cwe = detected.get('cwe', '')

                line_diff = abs(expected_line - detected_line)
                cwe_match = expected_cwe in detected_cwe

                if (expected_file == detected_file and
                    line_diff <= 2 and
                    cwe_match):
                    match_found = True
                    break

            if not match_found:
                false_negatives += 1
                logger.debug(f"     ❌ FALSE NEGATIVE: {expected_file}:{expected_line} CWE-{expected_cwe} not detected")
            else:
                logger.debug(f"     ✅ Expected vuln {expected_idx} was detected")

        logger.info(f"📊 False negative analysis complete: {false_negatives} missed vulnerabilities")

        # Calculate metrics
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        # Calculate metrics
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        # Create result
        result = GroundTruthBenchmarkResult(
            dataset=dataset_key,
            language=dataset_key.split('/')[0],
            total_files=len(test_files),
            expected_vulnerabilities=len(expected_vulns),
            detected_vulnerabilities=len(all_detected_vulns),
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            precision=round(precision, 3),
            recall=round(recall, 3),
            f1_score=round(f1_score, 3),
            scan_time_seconds=round(dataset_time, 2),
            files_per_second=round(len(test_files) / dataset_time, 2) if dataset_time > 0 else 0,
            timestamp=datetime.now().isoformat()
        )

        results.append(result)

        logger.info(f"📊 Dataset {dataset_key} final results:")
        logger.info(f"   📈 Performance: Precision={result.precision:.1%}, Recall={result.recall:.1%}, F1={result.f1_score:.1%}")
        logger.info(f"   ⏱️  Performance: {result.scan_time_seconds}s total ({result.files_per_second:.1f} files/sec)")
        logger.info(f"   🎯 Accuracy: TP={result.true_positives}, FP={result.false_positives}, FN={result.false_negatives}")
        logger.info(f"   📋 Coverage: {result.detected_vulnerabilities}/{result.expected_vulnerabilities} vulnerabilities detected")

    return results

def main():
    """Main benchmark runner"""
    logger.info("🚀 VALID8 GROUND TRUTH BENCHMARK SUITE STARTED")
    logger.info("Testing against datasets with known vulnerabilities")
    logger.info("=" * 60)

    start_time = time.time()

    # Use comprehensive test directory
    test_dir = Path("comprehensive_test")
    logger.info(f"📂 Using test directory: {test_dir.absolute()}")

    if not test_dir.exists():
        logger.error("comprehensive_test directory not found")
        logger.error("Please ensure test datasets are available")
        sys.exit(1)

    logger.info("📖 Loading ground truth data...")
    # Load ground truth data
    ground_truth = load_ground_truth(test_dir)

    if not ground_truth:
        logger.error("No ground truth data found")
        sys.exit(1)

    logger.info(f"📋 Benchmark setup complete:")
    logger.info(f"   • Datasets loaded: {len(ground_truth)}")
    total_expected = sum(gt.get('expected_vulnerabilities', 0) for gt in ground_truth.values())
    logger.info(f"   • Total expected vulnerabilities: {total_expected}")
    logger.info(f"   • Valid8 mode: hybrid (all features enabled)")

    # Run benchmark
    logger.info("🏁 Starting benchmark execution...")
    results = run_valid8_on_dataset(test_dir, ground_truth)

    total_time = time.time() - start_time
    logger.info(f"⏱️ Benchmark execution completed in {total_time:.2f} seconds")

    if not results:
        print("❌ No benchmark results generated")
        sys.exit(1)

    # Calculate overall statistics
    logger.info("📊 Calculating final benchmark statistics...")

    all_precision = [r.precision for r in results]
    all_recall = [r.recall for r in results]
    all_f1 = [r.f1_score for r in results]
    all_speed = [r.files_per_second for r in results]

    logger.info(f"📈 Performance metrics across {len(results)} datasets:")
    logger.info(f"   Precision range: {min(all_precision):.1%} - {max(all_precision):.1%}")
    logger.info(f"   Recall range: {min(all_recall):.1%} - {max(all_recall):.1%}")
    logger.info(f"   F1 range: {min(all_f1):.1%} - {max(all_f1):.1%}")
    logger.info(f"   Speed range: {min(all_speed):.1f} - {max(all_speed):.1f} files/sec")

    summary = {
        "valid8_overall_precision": round(statistics.mean(all_precision), 3),
        "valid8_overall_recall": round(statistics.mean(all_recall), 3),
        "valid8_overall_f1": round(statistics.mean(all_f1), 3),
        "valid8_overall_speed": round(statistics.mean(all_speed), 2),
        "datasets_tested": len(results),
        "total_files_scanned": sum(r.total_files for r in results),
        "total_expected_vulns": sum(r.expected_vulnerabilities for r in results),
        "total_detected_vulns": sum(r.detected_vulnerabilities for r in results),
        "methodology": "Ground truth comparison with hybrid mode scanning",
        "features_used": ["Pattern matching", "AI detection", "Taint analysis", "Semantic analysis", "Inter-procedural analysis"]
    }

    logger.info("📋 Final summary statistics:")
    logger.info(f"   Overall Precision: {summary['valid8_overall_precision']:.1%}")
    logger.info(f"   Overall Recall: {summary['valid8_overall_recall']:.1%}")
    logger.info(f"   Overall F1-Score: {summary['valid8_overall_f1']:.1%}")
    logger.info(f"   Overall Speed: {summary['valid8_overall_speed']:.1f} files/sec")
    logger.info(f"   Total Coverage: {summary['total_files_scanned']} files, {summary['total_expected_vulns']} vulnerabilities")

    # Save detailed results
    logger.info("💾 Preparing and saving benchmark results...")

    report_data = {
        "valid8_ground_truth_results": [asdict(r) for r in results],
        "competitor_data": [],  # We'll keep this for compatibility but focus on Valid8 metrics
        "summary": summary,
        "generated_at": datetime.now().isoformat(),
        "benchmark_type": "Ground Truth Validation",
        "valid8_features_tested": [
            "Multi-language support (Python, JavaScript, Java, TypeScript, Kotlin)",
            "Hybrid scanning mode (pattern + AI detection)",
            "Precise CWE identification",
            "Line-accurate vulnerability reporting",
            "False positive reduction",
            "Performance optimization"
        ]
    }

    logger.info("📝 Saving results to ground_truth_benchmark_results.json...")
    with open('ground_truth_benchmark_results.json', 'w') as f:
        json.dump(report_data, f, indent=2, default=str)

    logger.info("📊 GROUND TRUTH BENCHMARK RESULTS")
    logger.info("=" * 50)
    logger.info(".1%")
    logger.info(".1%")
    logger.info(".1%")
    logger.info(".2f")
    logger.info(f"📁 Datasets tested: {summary['datasets_tested']}")
    logger.info(f"📄 Files scanned: {summary['total_files_scanned']}")
    logger.info(f"🎯 Expected vulnerabilities: {summary['total_expected_vulns']}")
    logger.info(f"🔍 Detected vulnerabilities: {summary['total_detected_vulns']}")

    logger.info("✅ Ground truth benchmark completed successfully!")
    logger.info("📄 Results saved to: ground_truth_benchmark_results.json")
    logger.info("📋 Log file saved to: ground_truth_benchmark.log")

    # Update the main performance report with ground truth metrics
    try:
        with open('comprehensive_performance_report.json', 'r') as f:
            existing_report = json.load(f)

        existing_report['valid8_results'] = [
            {
                "benchmark_name": f"GroundTruth-{r.dataset.replace('/', '-')}",
                "dataset": "Real Ground Truth",
                "language": r.language,
                "total_files": r.total_files,
                "total_vulnerabilities": r.expected_vulnerabilities,
                "detected_vulnerabilities": r.detected_vulnerabilities,
                "true_positives": r.true_positives,
                "false_positives": r.false_positives,
                "false_negatives": r.false_negatives,
                "precision": r.precision,
                "recall": r.recall,
                "f1_score": r.f1_score,
                "scan_time_seconds": r.scan_time_seconds,
                "files_per_second": r.files_per_second,
                "timestamp": r.timestamp,
                "source": "Ground Truth Benchmark"
            }
            for r in results
        ]

        existing_report['summary'].update({
            "valid8_avg_precision": summary["valid8_overall_precision"],
            "valid8_avg_recall": summary["valid8_overall_recall"],
            "valid8_avg_f1": summary["valid8_overall_f1"],
            "valid8_avg_speed": summary["valid8_overall_speed"],
            "ground_truth_validated": True,
            "methodology": "Ground truth comparison with hybrid scanning"
        })

        with open('comprehensive_performance_report.json', 'w') as f:
            json.dump(existing_report, f, indent=2, default=str)

        print("📈 Updated comprehensive_performance_report.json with ground truth metrics")

    except Exception as e:
        print(f"⚠️ Could not update main report: {e}")

if __name__ == "__main__":
    main()
