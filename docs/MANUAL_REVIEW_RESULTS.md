# Manual Code Review Results

## Review Methodology
- Read actual code files
- Examine full context around reported line
- Understand purpose and usage
- Determine if exploitable in production

---

## Review #1: CWE-327 - cryptography/_oid.py:128

**Finding:** `hashes.MD5()` instantiated in OID mapping

**Code Context:**
```python
_SIG_OIDS_TO_HASH: dict[ObjectIdentifier, hashes.HashAlgorithm | None] = {
    SignatureAlgorithmOID.RSA_WITH_MD5: hashes.MD5(),
    SignatureAlgorithmOID.RSA_WITH_SHA1: hashes.SHA1(),
    ...
}
```

**Analysis:** This is a cryptography library's internal OID-to-hash mapping. The MD5 instance is created for parsing/validating existing certificates that use MD5, not for creating new weak crypto. This is necessary for backward compatibility.

**Verdict:** ❌ **FALSE POSITIVE** - Library needs to support parsing MD5 for compatibility, not using it for new crypto.

---

## Review #2: CWE-78 - pydantic Rust bench code

**Finding:** Command injection in Rust benchmark

**Code Context:**
```rust
let input = py.eval(c"'a' * 25 + '99'", None, None).unwrap();
```

**Analysis:** This is Rust code, not Python. The `c"..."` is a Rust raw string literal, not a command. `py.eval` is calling Python from Rust in a benchmark. No user input, no command execution.

**Verdict:** ❌ **FALSE POSITIVE** - Pattern matching incorrectly flagged Rust code as command injection.

---

## Review #3: CWE-502 - Django redis cache:28

**Finding:** `pickle.loads(data)` from Redis cache

**Code Context:**
```python
def loads(self, data):
    try:
        return int(data)
    except ValueError:
        return pickle.loads(data)  # Line 28
```

**Analysis:** Django's Redis cache backend deserializes data from Redis using pickle. If an attacker can write to Redis (compromised Redis, cache poisoning, etc.), they can achieve RCE via pickle deserialization.

**Verdict:** ✅ **TRUE POSITIVE** - Real vulnerability if Redis is compromised or cache can be poisoned.

---

## Review #4: CWE-502 - Django locmem cache:73

**Finding:** `pickle.loads(pickled)` in local memory cache

**Code Context:**
```python
pickled = self._cache[key]
value = pickle.loads(pickled)  # Line 73
```

**Analysis:** Similar to Redis - local memory cache using pickle. If cache key can be controlled or cache can be poisoned, RCE is possible.

**Verdict:** ✅ **TRUE POSITIVE** - Real vulnerability if cache can be manipulated.

---

## Review #5: CWE-502 - Django locmem cache:43

**Finding:** `pickle.loads(pickled)` in get method

**Code Context:**
```python
pickled = self._cache[key]
self._cache.move_to_end(key, last=False)
return pickle.loads(pickled)  # Line 43
```

**Analysis:** Same as #4 - local memory cache pickle deserialization.

**Verdict:** ✅ **TRUE POSITIVE** - Same vulnerability as #4.

---

## Review #6: CWE-502 - Django db cache:96

**Finding:** `pickle.loads(base64.b64decode(value.encode()))` from database

**Code Context:**
```python
value = connection.ops.process_clob(value)
value = pickle.loads(base64.b64decode(value.encode()))  # Line 96
```

**Analysis:** Database cache backend deserializing from DB. If database is compromised or cache can be poisoned, RCE possible.

**Verdict:** ✅ **TRUE POSITIVE** - Real vulnerability if DB/cache can be manipulated.

---

## Review #7: CWE-502 - configparser tracemalloc:439

**Finding:** `pickle.load(fp)` loading snapshot

**Code Context:**
```python
@staticmethod
def load(filename):
    """Load a snapshot from a file."""
    with open(filename, "rb") as fp:
        return pickle.load(fp)  # Line 439
```

**Analysis:** This is Python's tracemalloc module loading a snapshot file. If an attacker can control the filename or file contents, RCE is possible. However, this is typically used for debugging/profiling, not in production web apps.

**Verdict:** ⚠️ **CONTEXT-DEPENDENT** - True positive if file can be controlled, but low risk in typical usage.

---

## Review #8: CWE-89 - Django SQLite:331

**Finding:** SQL injection in SQLite backend

**Code Context:** Need to check actual code...

**Analysis:** [To be reviewed]

**Verdict:** [Pending]

---

Continuing review...




