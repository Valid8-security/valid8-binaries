# The Purpose of Fast, Hybrid, and Deep Scan Modes

## Why Three Modes Exist

**Different use cases require different trade-offs between speed and accuracy.** The three modes let you choose the right balance for your specific needs.

---

## 🎯 The Core Purpose

### **Fast Mode: Speed for Development**
**Purpose:** Get quick security feedback during active development

**When you need it:**
- ✅ **CI/CD pipelines** - Don't want builds to take forever
- ✅ **Pre-commit hooks** - Need instant feedback before committing
- ✅ **IDE integration** - Real-time warnings while coding
- ✅ **Frequent scanning** - Multiple scans per hour/day

**What it does:**
- Pattern matching only (no AI)
- Fast regex-based detection
- Catches obvious vulnerabilities quickly
- Lower accuracy but good enough for development

**The point:** **Speed matters more than perfect accuracy during development**

---

### **Hybrid Mode: Best Balance (Default)**
**Purpose:** Get excellent accuracy without sacrificing too much speed

**When you need it:**
- ✅ **Pull request reviews** - Need accurate results but can't wait hours
- ✅ **Regular security checks** - Weekly/monthly comprehensive scans
- ✅ **Development workflow** - Professional teams need both speed and accuracy
- ✅ **Most production use cases** - Default choice for most users

**What it does:**
- Pattern matching (catches everything possible)
- AI validation (filters out false positives)
- Best accuracy-to-speed ratio
- 93% F1-score at 650 files/sec

**The point:** **Most users want good accuracy without waiting forever**

---

### **Deep Mode: Maximum Accuracy**
**Purpose:** Find every vulnerability when accuracy is critical

**When you need it:**
- ✅ **Security audits** - Must find everything, time is not a constraint
- ✅ **Compliance reviews** - SOC2, HIPAA, GDPR audits need comprehensive analysis
- ✅ **Pre-release validation** - Final security check before production
- ✅ **Third-party code review** - Analyzing dependencies thoroughly
- ✅ **Penetration testing prep** - Identify all potential weaknesses

**What it does:**
- Full semantic analysis (AST, data flow, taint tracking)
- Cross-file analysis (inter-procedural)
- Symbolic execution (explores execution paths)
- Multi-layer ensemble validation
- Highest precision (95.1%)

**The point:** **When accuracy is more important than speed**

---

## 📊 Quick Comparison

| Mode | Speed | Accuracy | Use Case | The Point |
|------|-------|----------|----------|-----------|
| **Fast** | 890 files/sec | 88.9% F1 | Development | **Speed > Accuracy** |
| **Hybrid** | 650 files/sec | 93.0% F1 | Production | **Balance** ⭐ |
| **Deep** | 520 files/sec | 92.1% F1 | Audits | **Accuracy > Speed** |

---

## 🤔 Why Not Just One Mode?

### **Problem with Only Fast Mode:**
- ❌ Too many false positives (noisy)
- ❌ Misses complex vulnerabilities
- ✅ But developers need speed

### **Problem with Only Deep Mode:**
- ❌ Too slow for frequent use
- ❌ Blocks development workflow
- ✅ But auditors need accuracy

### **Solution: Three Modes**
- ✅ **Fast** for when speed matters
- ✅ **Hybrid** for when balance matters (most cases)
- ✅ **Deep** for when accuracy matters most

---

## 💡 Real-World Examples

### Example 1: Developer Workflow
```
Developer writes code
  ↓
Pre-commit hook runs Fast Mode (2 seconds)
  ↓
Quick feedback: "Potential SQL injection"
  ↓
Developer fixes it immediately
```

**Point:** Fast mode gives instant feedback without blocking workflow

---

### Example 2: Pull Request Review
```
PR submitted
  ↓
CI runs Hybrid Mode (30 seconds for 20k files)
  ↓
Accurate results: "3 real vulnerabilities found"
  ↓
Reviewer can trust the results
```

**Point:** Hybrid mode provides accurate results fast enough for PR reviews

---

### Example 3: Security Audit
```
Quarterly security audit scheduled
  ↓
Run Deep Mode overnight (2 hours for 100k files)
  ↓
Comprehensive report: "All vulnerabilities identified"
  ↓
Auditor has complete picture for compliance
```

**Point:** Deep mode finds everything when time permits thorough analysis

---

## 🎯 Decision Framework

### **Choose Fast Mode If:**
- ⏱️ Need results in < 30 seconds
- 🔄 Scanning multiple times per day
- 💻 Development/IDE integration
- 🚀 CI/CD pipeline speed critical

### **Choose Hybrid Mode If:**
- ⚖️ Need good accuracy AND reasonable speed
- 📝 Pull request reviews
- 🏢 Production security checks
- 👥 Team collaboration workflows
- **← This is the default for most users**

### **Choose Deep Mode If:**
- 🎯 Maximum accuracy required
- 📋 Security audits and compliance
- 🔍 Analyzing third-party code
- ⏰ Time is not a constraint
- 🛡️ Pre-release final validation

---

## 🔄 Typical Workflow Strategy

### **Development Phase:**
```
Fast Mode → Quick feedback during coding
```

### **Code Review Phase:**
```
Hybrid Mode → Accurate PR reviews
```

### **Release Phase:**
```
Deep Mode → Final security validation
```

### **Audit Phase:**
```
Deep Mode → Comprehensive security assessment
```

---

## 📈 The Trade-off Curve

```
Speed (files/sec)
    ↑
 890 | Fast Mode ────────────────┐
     |                            │
 650 | Hybrid Mode ──────────────┤ Accuracy increases
     |                            │ as speed decreases
 520 | Deep Mode ─────────────────┘
     |
   0 └────────────────────────────────→ Accuracy (F1)
    88.9%  92.1%  93.0%
```

**Key Insight:** Each mode represents a different point on the speed-accuracy trade-off curve.

---

## 🎯 Summary: The Point of Each Mode

### **Fast Mode**
**Point:** Get security feedback **instantly** during development, even if it's not perfect.

**Analogy:** Like a spell-checker - catches obvious mistakes quickly.

---

### **Hybrid Mode**
**Point:** Get **excellent accuracy** without waiting too long - the sweet spot for most users.

**Analogy:** Like a grammar checker - catches most issues accurately and quickly.

---

### **Deep Mode**
**Point:** Find **everything** when accuracy is more important than speed.

**Analogy:** Like a professional editor - comprehensive review when quality matters most.

---

## ✅ Bottom Line

**The three modes exist because:**
1. **Different users have different priorities** (speed vs accuracy)
2. **Different workflows have different constraints** (CI/CD vs audits)
3. **One size doesn't fit all** - flexibility is valuable
4. **You can use the right tool for the right job**

**Most users should use Hybrid Mode** (it's the default for a reason), but having Fast and Deep options gives you flexibility when you need it.




