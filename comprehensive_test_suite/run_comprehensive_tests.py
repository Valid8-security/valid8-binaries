#!/usr/bin/env python3
"""
Comprehensive test runner for Valid8 - measures speed, recall, precision, F1 score
"""

import json
import time
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any
import statistics

class ComprehensiveTester:
    def __init__(self):
        self.results = {}
        self.ground_truth = self.load_ground_truth()
        
    def load_ground_truth(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load the ground truth vulnerabilities for each test file"""
        ground_truth = {}
        
        # Define expected vulnerabilities for each file
        vuln_patterns = {
            'python': [
                {'cwe': 'CWE-78', 'line': 10},
                {'cwe': 'CWE-79', 'line': 20},
                {'cwe': 'CWE-89', 'line': 30},
                {'cwe': 'CWE-22', 'line': 40},
                {'cwe': 'CWE-502', 'line': 50}
            ],
            'javascript': [
                {'cwe': 'CWE-79', 'line': 10},
                {'cwe': 'CWE-89', 'line': 20},
                {'cwe': 'CWE-22', 'line': 30},
                {'cwe': 'CWE-79', 'line': 40},
                {'cwe': 'CWE-200', 'line': 50}
            ],
            'java': [
                {'cwe': 'CWE-89', 'line': 10},
                {'cwe': 'CWE-79', 'line': 20},
                {'cwe': 'CWE-22', 'line': 30},
                {'cwe': 'CWE-502', 'line': 40},
                {'cwe': 'CWE-798', 'line': 50}
            ],
            'go': [
                {'cwe': 'CWE-89', 'line': 10},
                {'cwe': 'CWE-79', 'line': 20},
                {'cwe': 'CWE-22', 'line': 30},
                {'cwe': 'CWE-502', 'line': 40},
                {'cwe': 'CWE-798', 'line': 50}
            ],
            'rust': [
                {'cwe': 'CWE-78', 'line': 10},
                {'cwe': 'CWE-79', 'line': 20},
                {'cwe': 'CWE-22', 'line': 30},
                {'cwe': 'CWE-200', 'line': 40},
                {'cwe': 'CWE-798', 'line': 50}
            ],
            'php': [
                {'cwe': 'CWE-89', 'line': 10},
                {'cwe': 'CWE-79', 'line': 20},
                {'cwe': 'CWE-22', 'line': 30},
                {'cwe': 'CWE-502', 'line': 40},
                {'cwe': 'CWE-798', 'line': 50}
            ],
            'cpp': [
                {'cwe': 'CWE-78', 'line': 10},
                {'cwe': 'CWE-79', 'line': 20},
                {'cwe': 'CWE-22', 'line': 30},
                {'cwe': 'CWE-119', 'line': 40},
                {'cwe': 'CWE-200', 'line': 50}
            ],
            'ruby': [
                {'cwe': 'CWE-89', 'line': 10},
                {'cwe': 'CWE-79', 'line': 20},
                {'cwe': 'CWE-22', 'line': 30},
                {'cwe': 'CWE-502', 'line': 40},
                {'cwe': 'CWE-798', 'line': 50}
            ]
        }
        
        sizes = ['small', 'medium', 'large', 'huge']
        for language in vuln_patterns:
            for size in sizes:
                # Adjust line numbers based on size
                multiplier = {'small': 1, 'medium': 10, 'large': 100, 'huge': 1000}[size]
                adjusted_vulns = []
                for vuln in vuln_patterns[language]:
                    adjusted_vuln = vuln.copy()
                    adjusted_vuln['line'] = vuln['line'] * multiplier
                    adjusted_vulns.append(adjusted_vuln)
                
                filename = f'test_{language}_{size}'
                ground_truth[f'{language}_{size}'] = adjusted_vulns
        
        return ground_truth
    
    def run_scan(self, target_path: str, mode: str = 'fast', **kwargs) -> Dict[str, Any]:
        """Run a single scan and return results"""
        cmd = [sys.executable, '-m', 'parry', 'scan', target_path, '--format', 'json', '--mode', mode]
        
        # Add additional options
        if kwargs.get('validate'):
            cmd.append('--validate')
        if kwargs.get('sca'):
            cmd.append('--sca')
        if kwargs.get('incremental'):
            cmd.append('--incremental')
        
        start_time = time.time()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            end_time = time.time()
            
            if result.returncode in [0, 2]:  # 0 = success, 2 = found vulnerabilities
                scan_data = json.loads(result.stdout)
                return {
                    'success': True,
                    'duration': end_time - start_time,
                    'results': scan_data
                }
            else:
                return {
                    'success': False,
                    'duration': end_time - start_time,
                    'error': result.stderr
                }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'duration': 300,
                'error': 'Timeout after 5 minutes'
            }
        except Exception as e:
            return {
                'success': False,
                'duration': time.time() - start_time,
                'error': str(e)
            }
    
    def calculate_metrics(self, detected_vulns: List[Dict], ground_truth_vulns: List[Dict]) -> Dict[str, float]:
        """Calculate precision, recall, and F1 score"""
        
        # Convert detected vulnerabilities to comparable format
        detected_set = set()
        for vuln in detected_vulns:
            # Create a signature based on CWE and approximate line number (±5 lines tolerance)
            cwe = vuln.get('cwe', '')
            line = vuln.get('line_number', 0)
            signature = f"{cwe}:{line // 10 * 10}"  # Round to nearest 10 for tolerance
            detected_set.add(signature)
        
        # Ground truth set
        ground_truth_set = set()
        for vuln in ground_truth_vulns:
            cwe = vuln.get('cwe', '')
            line = vuln.get('line', 0)
            signature = f"{cwe}:{line // 10 * 10}"  # Round to nearest 10 for tolerance
            ground_truth_set.add(signature)
        
        # Calculate metrics
        true_positives = len(detected_set & ground_truth_set)
        false_positives = len(detected_set - ground_truth_set)
        false_negatives = len(ground_truth_set - detected_set)
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'total_detected': len(detected_vulns),
            'total_ground_truth': len(ground_truth_vulns)
        }
    
    def run_comprehensive_tests(self):
        """Run all comprehensive tests"""
        
        languages = ['python', 'javascript', 'java', 'go', 'rust', 'php', 'cpp', 'ruby']
        sizes = ['small', 'medium', 'large', 'huge']
        modes = ['fast', 'hybrid']  # Skip 'deep' as it may be too slow
        
        features_to_test = [
            {'name': 'basic', 'options': {}},
            {'name': 'with_validation', 'options': {'validate': True}},
            {'name': 'with_sca', 'options': {'sca': True}},
            {'name': 'incremental', 'options': {'incremental': True}},
        ]
        
        total_tests = len(languages) * len(sizes) * len(modes) * len(features_to_test)
        completed_tests = 0
        
        print(f"Starting comprehensive testing: {total_tests} total tests")
        print("=" * 80)
        
        for language in languages:
            for size in sizes:
                test_key = f'{language}_{size}'
                target_path = f'comprehensive_test_suite/{size}/{language}'
                
                print(f"\n🔍 Testing {language} {size} codebase ({target_path})")
                print("-" * 60)
                
                if test_key not in self.results:
                    self.results[test_key] = {}
                
                for mode in modes:
                    if mode not in self.results[test_key]:
                        self.results[test_key][mode] = {}
                    
                    for feature in features_to_test:
                        feature_name = feature['name']
                        
                        print(f"  Running {mode} mode with {feature_name}...")
                        
                        # Run the scan
                        scan_result = self.run_scan(target_path, mode, **feature['options'])
                        
                        if scan_result['success']:
                            detected_vulns = scan_result['results'].get('vulnerabilities', [])
                            ground_truth = self.ground_truth.get(test_key, [])
                            
                            # Calculate metrics
                            metrics = self.calculate_metrics(detected_vulns, ground_truth)
                            
                            # Store results
                            self.results[test_key][mode][feature_name] = {
                                'duration': scan_result['duration'],
                                'metrics': metrics,
                                'detected_count': len(detected_vulns),
                                'files_scanned': scan_result['results'].get('summary', {}).get('files_scanned', 0)
                            }
                            
                            print(f"    ✅ Duration: {scan_result['duration']:.2f}s")
                            print(f"    📊 Precision: {metrics['precision']:.3f}")
                            print(f"    📊 Recall: {metrics['recall']:.3f}")
                            print(f"    📊 F1 Score: {metrics['f1_score']:.3f}")
                            print(f"    🎯 Detected: {len(detected_vulns)}/{len(ground_truth)} vulnerabilities")
                            
                        else:
                            print(f"    ❌ Failed: {scan_result.get('error', 'Unknown error')}")
                            self.results[test_key][mode][feature_name] = {
                                'duration': scan_result['duration'],
                                'error': scan_result.get('error', 'Unknown error')
                            }
                        
                        completed_tests += 1
                        progress = completed_tests / total_tests * 100
                        print(".1f"                        print()
        
        print("\n" + "=" * 80)
        print("🎉 COMPREHENSIVE TESTING COMPLETE!")
        print("=" * 80)
        
        self.save_results()
        self.generate_summary_report()
    
    def save_results(self):
        """Save detailed results to JSON file"""
        with open('comprehensive_test_suite/detailed_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        print("📁 Detailed results saved to comprehensive_test_suite/detailed_results.json")
    
    def generate_summary_report(self):
        """Generate a comprehensive summary report"""
        
        summary = {
            'overall_metrics': {},
            'by_language': {},
            'by_size': {},
            'by_mode': {},
            'performance_metrics': {}
        }
        
        # Collect all successful results
        all_durations = []
        all_precisions = []
        all_recalls = []
        all_f1_scores = []
        
        language_stats = {}
        size_stats = {}
        mode_stats = {}
        
        for test_key, test_results in self.results.items():
            language = test_key.split('_')[0]
            size = test_key.split('_')[1]
            
            if language not in language_stats:
                language_stats[language] = {'durations': [], 'precisions': [], 'recalls': [], 'f1_scores': []}
            if size not in size_stats:
                size_stats[size] = {'durations': [], 'precisions': [], 'recalls': [], 'f1_scores': []}
            
            for mode, mode_results in test_results.items():
                if mode not in mode_stats:
                    mode_stats[mode] = {'durations': [], 'precisions': [], 'recalls': [], 'f1_scores': []}
                
                for feature_name, feature_results in mode_results.items():
                    if 'metrics' in feature_results:
                        metrics = feature_results['metrics']
                        
                        # Overall stats
                        all_durations.append(feature_results['duration'])
                        all_precisions.append(metrics['precision'])
                        all_recalls.append(metrics['recall'])
                        all_f1_scores.append(metrics['f1_score'])
                        
                        # Language stats
                        language_stats[language]['durations'].append(feature_results['duration'])
                        language_stats[language]['precisions'].append(metrics['precision'])
                        language_stats[language]['recalls'].append(metrics['recall'])
                        language_stats[language]['f1_scores'].append(metrics['f1_score'])
                        
                        # Size stats
                        size_stats[size]['durations'].append(feature_results['duration'])
                        size_stats[size]['precisions'].append(metrics['precision'])
                        size_stats[size]['recalls'].append(metrics['recall'])
                        size_stats[size]['f1_scores'].append(metrics['f1_score'])
                        
                        # Mode stats
                        mode_stats[mode]['durations'].append(feature_results['duration'])
                        mode_stats[mode]['precisions'].append(metrics['precision'])
                        mode_stats[mode]['recalls'].append(metrics['recall'])
                        mode_stats[mode]['f1_scores'].append(metrics['f1_score'])
        
        # Calculate summary statistics
        summary['overall_metrics'] = {
            'average_speed_fps': statistics.mean(all_durations) if all_durations else 0,
            'average_precision': statistics.mean(all_precisions) if all_precisions else 0,
            'average_recall': statistics.mean(all_recalls) if all_recalls else 0,
            'average_f1_score': statistics.mean(all_f1_scores) if all_f1_scores else 0,
            'total_tests': len(all_durations),
            'successful_tests': len(all_durations)
        }
        
        # Language breakdown
        for lang, stats in language_stats.items():
            summary['by_language'][lang] = {
                'avg_precision': statistics.mean(stats['precisions']) if stats['precisions'] else 0,
                'avg_recall': statistics.mean(stats['recalls']) if stats['recalls'] else 0,
                'avg_f1_score': statistics.mean(stats['f1_scores']) if stats['f1_scores'] else 0,
                'avg_duration': statistics.mean(stats['durations']) if stats['durations'] else 0,
                'test_count': len(stats['durations'])
            }
        
        # Size breakdown
        for size, stats in size_stats.items():
            summary['by_size'][size] = {
                'avg_precision': statistics.mean(stats['precisions']) if stats['precisions'] else 0,
                'avg_recall': statistics.mean(stats['recalls']) if stats['recalls'] else 0,
                'avg_f1_score': statistics.mean(stats['f1_scores']) if stats['f1_scores'] else 0,
                'avg_duration': statistics.mean(stats['durations']) if stats['durations'] else 0,
                'test_count': len(stats['durations'])
            }
        
        # Mode breakdown
        for mode, stats in mode_stats.items():
            summary['by_mode'][mode] = {
                'avg_precision': statistics.mean(stats['precisions']) if stats['precisions'] else 0,
                'avg_recall': statistics.mean(stats['recalls']) if stats['recalls'] else 0,
                'avg_f1_score': statistics.mean(stats['f1_scores']) if stats['f1_scores'] else 0,
                'avg_duration': statistics.mean(stats['durations']) if stats['durations'] else 0,
                'test_count': len(stats['durations'])
            }
        
        # Performance metrics
        if all_durations:
            summary['performance_metrics'] = {
                'min_duration': min(all_durations),
                'max_duration': max(all_durations),
                'median_duration': statistics.median(all_durations),
                'p95_duration': statistics.quantiles(all_durations, n=20)[18] if len(all_durations) >= 20 else max(all_durations),
                'total_duration': sum(all_durations)
            }
        
        # Save summary
        with open('comprehensive_test_suite/summary_report.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Print summary report
        self.print_summary_report(summary)
    
    def print_summary_report(self, summary):
        """Print a formatted summary report"""
        
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE VALID8 PERFORMANCE SUMMARY")
        print("=" * 80)
        
        overall = summary['overall_metrics']
        print("
🎯 OVERALL PERFORMANCE:"        print(".3f"        print(".3f"        print(".3f"        print(".1f"        print(f"   Total Tests Run: {overall['total_tests']}")
        
        print("
📈 PERFORMANCE METRICS:"        perf = summary.get('performance_metrics', {})
        if perf:
            print(".3f"            print(".3f"            print(".3f"            print(".3f"            print(".3f"
        print("
🌐 BY PROGRAMMING LANGUAGE:"        for lang, stats in summary['by_language'].items():
            print("15"            print("15")
        
        print("
📏 BY CODEBASE SIZE:"        for size, stats in summary['by_size'].items():
            print("15"            print("15")
        
        print("
⚙️  BY SCANNING MODE:"        for mode, stats in summary['by_mode'].items():
            print("15"            print("15")
        
        print("
✅ VALIDATION COMPLETE"        print("   All metrics calculated from actual test runs"        print("   Results saved to comprehensive_test_suite/summary_report.json"
if __name__ == '__main__':
    tester = ComprehensiveTester()
    tester.run_comprehensive_tests()
