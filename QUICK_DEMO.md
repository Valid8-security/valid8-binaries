# Quick Demo Guide - Show Parry in 60 Seconds

Want to demonstrate Parry's capabilities quickly? Here's how!

## One-Liner Demo

```bash
python scripts/demo_scan_with_fixes.py examples/vulnerable_code.py
```

**That's it!** This single command shows:
- ✅ 24 vulnerabilities detected
- ✅ Real-time AI-powered fixes
- ✅ Beautiful formatted output
- ✅ Before/after comparisons

---

## What You'll See

### 1. Instant Scan (0.01 seconds)
```
📋 Step 1: Scanning codebase...
✓ Scan complete in 0.01 seconds
✓ Files scanned: 1
✓ Vulnerabilities found: 24
```

### 2. Vulnerability Table
```
Critical: 7  High: 14  Medium: 3
Including:
- SQL Injection
- Command Injection
- Hardcoded Credentials
- Cross-Site Scripting
- And more...
```

### 3. AI-Powered Fixes
```
Original:
    result = os.system(f"ping -c 1 {host}")

Fixed:
result = subprocess.run(["ping", "-c", "1", host], check=True)
```

---

## Perfect For

✅ **Beta Launch Demos** - Show real capabilities  
✅ **Sales Calls** - Impress prospects  
✅ **Training** - Teach security best practices  
✅ **Conferences** - Live coding demos  
✅ **Recruiting** - Showcase product  

---

## Want More?

### Full Documentation
→ `scripts/DEMO_README.md` - Complete guide

### Benchmarks
→ `COMPREHENSIVE_BENCHMARK_RESULTS.md` - Performance data

### Setup
→ `SETUP_GUIDE.md` - Installation instructions

---

**Ready? Run it now!** 🚀

```bash
python scripts/demo_scan_with_fixes.py examples/vulnerable_code.py
```

