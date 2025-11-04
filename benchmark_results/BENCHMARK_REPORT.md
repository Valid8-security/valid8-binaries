# Comprehensive Benchmark Report

**Date:** 2025-11-03 21:03:40  
**Test Codebase:** 12 known vulnerabilities  
**Tools Tested:** Parry (Fast, Deep, Hybrid), Snyk, Semgrep

---

## Ground Truth

The test codebase contains **12 known vulnerabilities**:

| File | Line | CWE | Type | Severity |
|------|------|-----|------|----------|
| sql_injection.py | 6 | CWE-89 | SQL Injection | high |
| command_injection.py | 6 | CWE-78 | Command Injection | critical |
| command_injection.py | 10 | CWE-78 | Command Injection | critical |
| path_traversal.py | 4 | CWE-22 | Path Traversal | high |
| hardcoded_credentials.py | 3 | CWE-798 | Hardcoded Credentials | high |
| hardcoded_credentials.py | 4 | CWE-798 | Hardcoded Credentials | high |
| hardcoded_credentials.py | 5 | CWE-798 | Hardcoded Credentials | medium |
| hardcoded_credentials.py | 13 | CWE-798 | Hardcoded Credentials | high |
| weak_crypto.py | 6 | CWE-327 | Weak Cryptography | high |
| weak_crypto.py | 10 | CWE-327 | Weak Cryptography | medium |
| xss_vulnerability.js | 4 | CWE-79 | Cross-Site Scripting | high |
| xss_vulnerability.js | 9 | CWE-79 | Cross-Site Scripting | high |

---

## Scan Results

| Tool | Mode | Vulns Found | Time (s) | Speed (f/s) |
|------|------|-------------|----------|-------------|
| Parry (fast) | fast | 0 | 0.07 | 80.5 |
| Parry (hybrid) | hybrid | 0 | 0.07 | 81.8 |
| Snyk | N/A | 0 | 1.48 | 4.1 |
| Semgrep | N/A | 6 | 6.52 | 0.9 |

---

## Metrics Comparison

| Tool | Mode | TP | FP | FN | Recall | Precision | F1 Score |
|------|------|----|----|----|----|----|----|----|
| Parry (fast) | fast | 0 | 0 | 12 | 0.0% | 0.0% | 0.000 |
| Parry (hybrid) | hybrid | 0 | 0 | 12 | 0.0% | 0.0% | 0.000 |
| Snyk | N/A | 0 | 0 | 12 | 0.0% | 0.0% | 0.000 |
| Semgrep | N/A | 0 | 0 | 12 | 0.0% | 0.0% | 0.000 |

---

## Key Findings

### Best Recall
**Parry** (fast): **0.0%**

### Best Precision
**Parry** (fast): **0.0%**

### Best F1 Score
**Parry** (fast): **0.000**

### Fastest
**Parry** (hybrid): **81.8 files/sec**


---

## Detailed Analysis

### Parry (fast)

- **True Positives:** 0 / 12
- **False Positives:** 0
- **False Negatives:** 12
- **Recall:** 0.0% (found 0 of 12 vulnerabilities)
- **Precision:** 0.0% (0 false alarms)
- **F1 Score:** 0.000
- **Speed:** 80.5 files/sec

### Parry (hybrid)

- **True Positives:** 0 / 12
- **False Positives:** 0
- **False Negatives:** 12
- **Recall:** 0.0% (found 0 of 12 vulnerabilities)
- **Precision:** 0.0% (0 false alarms)
- **F1 Score:** 0.000
- **Speed:** 81.8 files/sec

### Snyk

- **True Positives:** 0 / 12
- **False Positives:** 0
- **False Negatives:** 12
- **Recall:** 0.0% (found 0 of 12 vulnerabilities)
- **Precision:** 0.0% (0 false alarms)
- **F1 Score:** 0.000
- **Speed:** 4.1 files/sec

### Semgrep

- **True Positives:** 0 / 12
- **False Positives:** 0
- **False Negatives:** 12
- **Recall:** 0.0% (found 0 of 12 vulnerabilities)
- **Precision:** 0.0% (0 false alarms)
- **F1 Score:** 0.000
- **Speed:** 0.9 files/sec

---

## Conclusion

Tested 4 tool configurations against 12 known vulnerabilities.

