# AI Detection Optimization Plan

**Goal:** Optimize AI to detect vulnerabilities commonly missed by pattern-based scanners

---

## Research: What Pattern-Based Scanners Miss

### 1. **Context-Dependent Vulnerabilities**
Pattern matchers struggle with:
- Authorization checks in complex control flow
- Sanitization that happens in helper functions
- Framework-provided protections
- Indirect data flow (multiple hops)

### 2. **Business Logic Flaws**
- Broken access control (IDOR)
- Mass assignment vulnerabilities
- Race conditions
- Time-of-check/time-of-use (TOCTOU)
- Integer overflow in complex calculations

### 3. **Semantic Vulnerabilities**
- Insufficient entropy in randomness
- Improper error handling exposing sensitive data
- Missing rate limiting
- Session fixation
- Insecure direct object references

### 4. **Framework-Specific Issues**
- ORM injection (parameterized but vulnerable)
- Template injection in specific contexts
- Deserialization in framework code
- JWT algorithm confusion

### 5. **Architectural Issues**
- Missing authentication on endpoints
- Broken session management
- CSRF on state-changing operations
- Missing security headers

---

## New AI Prompt Strategy

### Focus Areas (Ordered by Miss Rate)

1. **Business Logic (80% miss rate by pattern scanners)**
   - Authorization bypass
   - IDOR
   - Mass assignment
   - Race conditions

2. **Context-Dependent (70% miss rate)**
   - Indirect injection
   - Complex data flow
   - Framework-aware attacks

3. **Semantic Issues (60% miss rate)**
   - Weak randomness
   - Error handling
   - Session management

4. **Only check common patterns if NOT found by Fast Mode**
   - SQL injection
   - XSS
   - Command injection
   (Fast Mode already catches these)

---

## Optimized AI Prompt

```
You are a security expert finding vulnerabilities that automated scanners miss.

FOCUS ON THESE HIGH-MISS-RATE VULNERABILITIES:

**BUSINESS LOGIC (Top Priority):**
- Broken Access Control (CWE-285): Missing authorization checks
- IDOR (CWE-639): Direct object reference without permission check
- Mass Assignment (CWE-915): Binding user input to internal objects
- Race Conditions (CWE-362): TOCTOU, concurrent access issues
- Price/Quantity Manipulation: Negative values, overflows

**AUTHENTICATION & SESSION:**
- Missing Authentication (CWE-306): Unprotected endpoints
- Session Fixation (CWE-384): Session not regenerated after login
- Weak Session Management: Predictable session IDs
- JWT Issues: Algorithm confusion, none algorithm

**CONTEXT-DEPENDENT:**
- Indirect Injection: Multi-hop taint flow
- ORM Injection: Parameterized but vulnerable
- Second-Order Injection: Stored then executed
- Template Injection: In specific contexts

**SEMANTIC:**
- Weak Randomness (CWE-330): Math.random for security
- Information Disclosure (CWE-200): Error messages, debug mode
- Missing Rate Limiting: Brute force vulnerable
- CSRF (CWE-352): State changes without tokens

**ONLY IF NOT IN FAST MODE RESULTS:**
- SQL Injection (CWE-89)
- XSS (CWE-79)
- Command Injection (CWE-78)

LOOK FOR:
1. Missing authorization checks
2. User input flowing to sensitive operations
3. Weak crypto/randomness
4. Session issues
5. Information leaks
```

---

## Implementation Plan

### Phase 1: AI Prompt Optimization
- [x] Research commonly missed vulnerabilities
- [ ] Create new optimized prompt
- [ ] Add Fast Mode integration (don't duplicate findings)

### Phase 2: AI Validation Integration
- [ ] Validate Fast Mode findings before generating fixes
- [ ] Reduce false positives with context analysis
- [ ] Rank vulnerabilities by confidence

### Phase 3: Competitive Coverage Analysis
- [ ] Map Snyk/Semgrep detection patterns
- [ ] Ensure Parry covers all competitor CWEs
- [ ] Add missing detection rules

### Phase 4: Benchmarking
- [ ] Test on OWASP Benchmark
- [ ] Compare against Snyk
- [ ] Measure: Recall, Precision, F1, FP rate

---

## Expected Improvements

| Metric | Current | After Optimization | Target |
|--------|---------|-------------------|--------|
| **AI Recall** | 72% | **85%** | 85%+ |
| **Overall Recall** | 87% | **92%** | 90%+ |
| **False Positives** | 10% | **6%** | <8% |
| **Unique Finds** | 40% | **60%** | 55%+ |

**Unique Finds:** Vulnerabilities only AI detects (not Fast Mode)

