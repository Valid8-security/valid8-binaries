# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Advanced Language-Specific Security Detectors

Deep detectors for modern languages with advanced features:
- Rust (unsafe blocks, memory safety)
- Swift (ARC issues, memory management)
- Kotlin (coroutine safety, null safety bypass)
- TypeScript (type assertion abuse, any types)
- Go (goroutine leaks, race conditions)
"""

import re
from typing import List
from dataclasses import dataclass


@dataclass
class AdvancedDetector:
    """Advanced language-specific detector"""
    name: str
    language: str
    cwe: str
    severity: str
    description: str
    pattern: re.Pattern
    fix_suggestion: str
    examples: List[str]


class RustSecurityDetectors:
    """Rust advanced security detectors"""
    
    DETECTORS = [
        # CWE-416: Use After Free in Unsafe Blocks
        AdvancedDetector(
            name="rust-unsafe-use-after-free",
            language="rust",
            cwe="CWE-416",
            severity="critical",
            description="Potential use-after-free in unsafe block with raw pointer dereference",
            pattern=re.compile(r'unsafe\s*{[^}]*\*\w+[^}]*drop\([^)]*\)[^}]*\*\w+', re.DOTALL),
            fix_suggestion="Avoid raw pointers; use Rust's ownership system or Rc/Arc for shared ownership",
            examples=[
                "unsafe { let x = *ptr; drop(ptr); let y = *ptr; }  // BAD",
                "let x = Rc::new(data); let y = Rc::clone(&x);  // GOOD"
            ]
        ),
        
        # CWE-119: Unchecked Slice Indexing
        AdvancedDetector(
            name="rust-unchecked-index",
            language="rust",
            cwe="CWE-119",
            severity="high",
            description="Using get_unchecked() bypasses bounds checking and can cause memory corruption",
            pattern=re.compile(r'\.get_unchecked\('),
            fix_suggestion="Use .get() with Option or bounds-checked indexing unless in hot path with proven safety",
            examples=[
                "let x = arr.get_unchecked(idx);  // BAD - no bounds check",
                "let x = arr.get(idx).unwrap_or(&default);  // GOOD"
            ]
        ),
        
        # CWE-662: Improper Synchronization (Data Race)
        AdvancedDetector(
            name="rust-data-race-unsafe",
            language="rust",
            cwe="CWE-662",
            severity="high",
            description="Unsafe block bypassing Send/Sync bounds can introduce data races",
            pattern=re.compile(r'unsafe\s+impl\s+(Send|Sync)\s+for'),
            fix_suggestion="Only implement Send/Sync if type is truly thread-safe; use Arc<Mutex<T>> for shared mutable state",
            examples=[
                "unsafe impl Send for MyType { }  // BAD - must verify thread safety",
                "struct Safe(Arc<Mutex<Data>>);  // GOOD - compiler-verified"
            ]
        ),
        
        # CWE-676: Use of Potentially Dangerous Function
        AdvancedDetector(
            name="rust-transmute-abuse",
            language="rust",
            cwe="CWE-676",
            severity="critical",
            description="std::mem::transmute can bypass type system and cause undefined behavior",
            pattern=re.compile(r'std::mem::transmute|mem::transmute'),
            fix_suggestion="Avoid transmute; use safe alternatives like From/Into traits or explicit conversions",
            examples=[
                "let x: u32 = unsafe { mem::transmute(f) };  // BAD",
                "let x: u32 = f.to_bits();  // GOOD - safe float to bits"
            ]
        ),
        
        # CWE-252: Unchecked Error Return Value
        AdvancedDetector(
            name="rust-unwrap-panic",
            language="rust",
            cwe="CWE-252",
            severity="medium",
            description="Using unwrap() or expect() can cause panic on None/Err values",
            pattern=re.compile(r'\.(unwrap|expect)\(\)'),
            fix_suggestion="Use pattern matching or ? operator for proper error handling",
            examples=[
                "let x = result.unwrap();  // BAD - can panic",
                "let x = result?;  // GOOD - propagate error"
            ]
        ),
    ]


class SwiftSecurityDetectors:
    """Swift advanced security detectors"""
    
    DETECTORS = [
        # CWE-416: Retain Cycle / Memory Leak
        AdvancedDetector(
            name="swift-retain-cycle",
            language="swift",
            cwe="CWE-401",
            severity="medium",
            description="Strong reference in closure can create retain cycle and memory leak",
            pattern=re.compile(r'\{[^}]*self\.\w+[^}]*\}(?!.*\[weak|unowned)', re.DOTALL),
            fix_suggestion="Use [weak self] or [unowned self] capture list in closures",
            examples=[
                "handler = { self.process() }  // BAD - retain cycle",
                "handler = { [weak self] in self?.process() }  // GOOD"
            ]
        ),
        
        # CWE-476: Force Unwrapping Optional
        AdvancedDetector(
            name="swift-force-unwrap",
            language="swift",
            cwe="CWE-476",
            severity="medium",
            description="Force unwrapping optional with ! can cause runtime crash if nil",
            pattern=re.compile(r'\w+!(?:\.\w+|\[)'),
            fix_suggestion="Use optional binding (if let) or nil coalescing (??) instead of force unwrap",
            examples=[
                "let x = dict[key]!  // BAD - crashes if key absent",
                "if let x = dict[key] { }  // GOOD"
            ]
        ),
        
        # CWE-484: Omitted Break Statement in Switch
        AdvancedDetector(
            name="swift-fallthrough-misuse",
            language="swift",
            cwe="CWE-484",
            severity="low",
            description="Explicit fallthrough in switch can lead to unintended execution",
            pattern=re.compile(r'case\s+\w+:[^:]*fallthrough'),
            fix_suggestion="Avoid fallthrough; use explicit conditions or combine cases with comma",
            examples=[
                "case .error: log(); fallthrough  // BAD",
                "case .error, .warning: log()  // GOOD"
            ]
        ),
        
        # CWE-798: Hardcoded Credentials
        AdvancedDetector(
            name="swift-hardcoded-key",
            language="swift",
            cwe="CWE-798",
            severity="critical",
            description="API key or password hardcoded in Swift source",
            pattern=re.compile(r'let\s+(apiKey|password|secret|token)\s*=\s*"[^"]{8,}"'),
            fix_suggestion="Load credentials from Keychain or environment variables",
            examples=[
                'let apiKey = "sk_live_abc123..."  // BAD',
                "let apiKey = ProcessInfo.processInfo.environment[\"API_KEY\"]  // GOOD"
            ]
        ),
        
        # CWE-327: Weak Encryption
        AdvancedDetector(
            name="swift-deprecated-crypto",
            language="swift",
            cwe="CWE-327",
            severity="high",
            description="Using deprecated or weak cryptographic algorithm",
            pattern=re.compile(r'CommonCrypto.*kCCAlgorithm(DES|RC2|RC4)'),
            fix_suggestion="Use AES-256-GCM from CryptoKit for encryption",
            examples=[
                "CCCrypt(kCCEncrypt, kCCAlgorithmDES, ...)  // BAD",
                "AES.GCM.seal(data, using: key)  // GOOD"
            ]
        ),
    ]


class KotlinSecurityDetectors:
    """Kotlin advanced security detectors"""
    
    DETECTORS = [
        # CWE-404: Coroutine Leak
        AdvancedDetector(
            name="kotlin-coroutine-leak",
            language="kotlin",
            cwe="CWE-404",
            severity="medium",
            description="GlobalScope.launch creates unstructured coroutines that can leak",
            pattern=re.compile(r'GlobalScope\.launch'),
            fix_suggestion="Use structured concurrency with CoroutineScope or viewModelScope/lifecycleScope",
            examples=[
                "GlobalScope.launch { work() }  // BAD - no cancellation",
                "viewModelScope.launch { work() }  // GOOD - tied to lifecycle"
            ]
        ),
        
        # CWE-476: Null Safety Bypass
        AdvancedDetector(
            name="kotlin-force-not-null",
            language="kotlin",
            cwe="CWE-476",
            severity="medium",
            description="Using !! operator bypasses null safety and can throw NullPointerException",
            pattern=re.compile(r'\w+!!'),
            fix_suggestion="Use safe calls (?.) or elvis operator (?:) instead of !!",
            examples=[
                "val x = user!!.name  // BAD - can throw NPE",
                "val x = user?.name ?: \"Unknown\"  // GOOD"
            ]
        ),
        
        # CWE-502: Unsafe Deserialization
        AdvancedDetector(
            name="kotlin-unsafe-serialization",
            language="kotlin",
            cwe="CWE-502",
            severity="critical",
            description="Using Java serialization in Kotlin can lead to RCE vulnerabilities",
            pattern=re.compile(r'ObjectInputStream|readObject\(\)'),
            fix_suggestion="Use kotlinx.serialization with JSON format for safe data exchange",
            examples=[
                "val obj = ObjectInputStream(input).readObject()  // BAD",
                "val obj = Json.decodeFromString<MyClass>(json)  // GOOD"
            ]
        ),
        
        # CWE-470: Unsafe Reflection
        AdvancedDetector(
            name="kotlin-reflection-abuse",
            language="kotlin",
            cwe="CWE-470",
            severity="high",
            description="Using reflection to access private members bypasses encapsulation",
            pattern=re.compile(r'\.javaClass\.getDeclaredField|isAccessible\s*=\s*true'),
            fix_suggestion="Respect access modifiers; refactor to use public APIs",
            examples=[
                "field.isAccessible = true  // BAD - violates encapsulation",
                "// Use proper public API or refactor design  // GOOD"
            ]
        ),
        
        # CWE-662: Race Condition in Shared State
        AdvancedDetector(
            name="kotlin-shared-mutable-state",
            language="kotlin",
            cwe="CWE-662",
            severity="high",
            description="Mutable shared state accessed from multiple coroutines without synchronization",
            pattern=re.compile(r'var\s+\w+\s*=\s*\w+.*launch.*\w+\s*(\+\+|\-\-|=)', re.DOTALL),
            fix_suggestion="Use Mutex, synchronized, or atomic operations for shared mutable state",
            examples=[
                "var counter = 0; launch { counter++ }  // BAD - race condition",
                "val counter = AtomicInteger(0); launch { counter.incrementAndGet() }  // GOOD"
            ]
        ),
    ]


class TypeScriptSecurityDetectors:
    """TypeScript advanced security detectors"""
    
    DETECTORS = [
        # CWE-843: Type Confusion via 'any'
        AdvancedDetector(
            name="typescript-any-abuse",
            language="typescript",
            cwe="CWE-843",
            severity="medium",
            description="Excessive use of 'any' type bypasses type safety",
            pattern=re.compile(r':\s*any(?:\[\])?(?!\s*//\s*TODO)'),
            fix_suggestion="Use specific types or 'unknown' with type guards instead of 'any'",
            examples=[
                "function process(data: any) { }  // BAD",
                "function process(data: unknown) { if (isValid(data)) { } }  // GOOD"
            ]
        ),
        
        # CWE-843: Dangerous Type Assertion
        AdvancedDetector(
            name="typescript-unsafe-assertion",
            language="typescript",
            cwe="CWE-843",
            severity="medium",
            description="Type assertion (as) without runtime validation can cause type confusion",
            pattern=re.compile(r'as\s+\w+(?!.*instanceof)'),
            fix_suggestion="Validate types at runtime before asserting, use type guards",
            examples=[
                "const user = data as User;  // BAD - no validation",
                "const user = isUser(data) ? data : null;  // GOOD"
            ]
        ),
        
        # CWE-79: XSS via dangerouslySetInnerHTML
        AdvancedDetector(
            name="typescript-react-xss",
            language="typescript",
            cwe="CWE-79",
            severity="critical",
            description="dangerouslySetInnerHTML with user input can introduce XSS",
            pattern=re.compile(r'dangerouslySetInnerHTML=\{\{__html:\s*\w+'),
            fix_suggestion="Sanitize HTML with DOMPurify before rendering or avoid innerHTML entirely",
            examples=[
                "<div dangerouslySetInnerHTML={{__html: userInput}} />  // BAD",
                "<div>{DOMPurify.sanitize(userInput)}</div>  // GOOD"
            ]
        ),
        
        # CWE-1321: Prototype Pollution
        AdvancedDetector(
            name="typescript-prototype-pollution",
            language="typescript",
            cwe="CWE-1321",
            severity="high",
            description="Deep merge or assign with user data can pollute Object prototype",
            pattern=re.compile(r'Object\.assign\([^,]+,\s*\w+(Data|Input|Params)'),
            fix_suggestion="Validate keys, use Object.create(null), or freeze prototypes",
            examples=[
                "Object.assign(config, userData);  // BAD",
                "const clean = Object.create(null); Object.assign(clean, validated);  // GOOD"
            ]
        ),
    ]


class GoSecurityDetectors:
    """Go advanced security detectors"""
    
    DETECTORS = [
        # CWE-404: Goroutine Leak
        AdvancedDetector(
            name="go-goroutine-leak",
            language="go",
            cwe="CWE-404",
            severity="medium",
            description="Goroutine without context or cancellation can leak",
            pattern=re.compile(r'go\s+func\([^)]*\)\s*{[^}]*(?!context\.)(?!<-done)', re.DOTALL),
            fix_suggestion="Use context.Context for cancellation or timeout control",
            examples=[
                "go func() { doWork() }()  // BAD - no cancellation",
                "go func(ctx context.Context) { <-ctx.Done() }(ctx)  // GOOD"
            ]
        ),
        
        # CWE-662: Race Condition
        AdvancedDetector(
            name="go-data-race",
            language="go",
            cwe="CWE-662",
            severity="high",
            description="Shared variable accessed without mutex protection",
            pattern=re.compile(r'var\s+\w+\s+\w+.*go\s+func\([^)]*\)\s*{[^}]*\w+\s*(\+\+|--|=)', re.DOTALL),
            fix_suggestion="Use sync.Mutex or sync/atomic for concurrent access",
            examples=[
                "var counter int; go func() { counter++ }()  // BAD - race",
                "var mu sync.Mutex; go func() { mu.Lock(); counter++; mu.Unlock() }()  // GOOD"
            ]
        ),
        
        # CWE-703: Unchecked Error
        AdvancedDetector(
            name="go-unchecked-error",
            language="go",
            cwe="CWE-703",
            severity="medium",
            description="Error return value ignored without check",
            pattern=re.compile(r'\w+\([^)]*\)\s*(?=\n|;|})(?!.*err)'),
            fix_suggestion="Always check error returns: if err != nil { return err }",
            examples=[
                "file.Close()  // BAD - error ignored",
                "if err := file.Close(); err != nil { log.Fatal(err) }  // GOOD"
            ]
        ),
    ]


def get_all_advanced_detectors():
    """Get all advanced language-specific detectors"""
    detectors = []
    detectors.extend(RustSecurityDetectors.DETECTORS)
    detectors.extend(SwiftSecurityDetectors.DETECTORS)
    detectors.extend(KotlinSecurityDetectors.DETECTORS)
    detectors.extend(TypeScriptSecurityDetectors.DETECTORS)
    detectors.extend(GoSecurityDetectors.DETECTORS)
    return detectors
