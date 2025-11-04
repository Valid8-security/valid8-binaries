# Real-World Benchmark Results

**Date:** 2025-11-03 21:05:14  
**Test Target:** `examples/` directory (11 files)  
**Tools:** Parry (Fast/Hybrid), Snyk, Semgrep

---

## Results

| Tool | Mode | Vulnerabilities | Time (s) | Speed (files/s) |
|------|------|-----------------|----------|-----------------|
| Parry fast | fast | 0 | 0.08 | 132.0 |
| Parry hybrid | hybrid | 0 | 0.08 | 144.7 |
| Snyk | - | 0 | 1.64 | 6.7 |
| Semgrep | - | 52 | 3.97 | 2.8 |

---

## Key Findings

### Most Vulnerabilities Found
**Semgrep** (default): **52** vulnerabilities

### Fastest Scan
**Parry** (hybrid): **144.7** files/second

### Comparative Analysis

- Parry Fast is **19.7x faster** than Snyk
- Parry Hybrid found **-100.0%** more vulnerabilities than Semgrep

---

**Note:** This benchmark tests detection capability on real vulnerable code from Parry's test suite.
