# Secure Beta Licensing System

## Current Security Issues

### Critical Vulnerabilities

**Issue 1: Local Beta License Installation**
```python
# Anyone can run this locally:
from parry.license import LicenseManager
LicenseManager.install_beta_license('fake@email.com')
# → Unlimited free access!
```

**Issue 2: No Usage Limits**
- No tracking of beta installs per email
- No limits on number of beta licenses
- No rate limiting
- Easy to abuse

**Issue 3: Lenient Enforcement**
- Expired licenses still work
- No checks against abuse
- No fraud detection

---

## Secure Solution Architecture

### Option 1: Online Beta Registration (Recommended)

**How it works:**
1. User requests beta via web form or email
2. Admin approves on backend
3. User receives unique beta token
4. Token validated online (or local with signature)
5. Usage tracked server-side

**Implementation:**
```python
# User requests beta
POST https://api.parry.dev/beta/request
{
  "email": "user@example.com",
  "feedback": "Would love to test Parry"
}

# Admin approves
POST https://api.parry.dev/beta/approve
{
  "email": "user@example.com",
  "admin_token": "admin_secret"
}

# User installs with token
parry license --install beta --token abc123def456

# Validation
GET https://api.parry.dev/beta/validate
{
  "token": "abc123def456",
  "machine_id": "PARRY-xxx"
}
# Returns: valid, expires, usage_count
```

**Pros:**
- ✅ Centralized control
- ✅ Usage tracking
- ✅ Rate limiting
- ✅ Fraud prevention
- ✅ Automatic expiration

**Cons:**
- ❌ Requires server infrastructure
- ❌ Cannot work offline
- ❌ Not ideal for early beta

---

### Option 2: Signed Beta Tokens (Recommended for Early Beta)

**How it works:**
1. Admin generates signed tokens for approved users
2. Tokens include expiration, email, usage limits
3. User installs token locally
4. Token verified with cryptographic signature
5. No server needed, but admin controls issuance

**Implementation:**
```python
# Admin generates token
from parry.crypto import sign_token

token = sign_token({
    'email': 'user@example.com',
    'expires': '2026-04-01',
    'max_installations': 1,
    'issued': '2025-01-01',
    'issued_by': 'admin@parry.dev'
})
# Returns: eyJ...J9.signature

# User installs
parry license --install beta --token eyJ...J9.signature

# Local validation (no server!)
verify_token(token)  # Checks signature
check_expiration(token)  # Checks date
check_machine_limit(token)  # Checks installations
```

**Pros:**
- ✅ Works offline
- ✅ Admin controls issuance
- ✅ No server needed
- ✅ Cryptographically secure
- ✅ Usage limits enforceable

**Cons:**
- ⚠️ Admin must manually generate tokens
- ⚠️ Signature verification needed
- ⚠️ More complex

**Best for:** Early beta, airgapped environments

---

### Option 3: Hybrid (Recommended Short-Term)

**How it works:**
1. Admin issues signed beta tokens manually
2. Users install with tokens
3. Tokens validated locally (signature)
4. Usage tracked locally
5. Optional: Report to server for analytics

**Phase 1 (Beta):** Signed tokens, local validation
**Phase 2 (Paid):** Online validation, cloud tracking

---

## Recommended Implementation

### Short-Term: Secure Token-Based Beta

**Step 1: Token Generation Tool (Admin)**
```python
# parry-admin create-beta-token --email user@example.com
```

**Step 2: Token Format**
```json
{
  "email": "user@example.com",
  "expires": "2026-04-01",
  "max_installations": 1,
  "issued": "2025-01-01",
  "issued_by": "admin@parry.dev",
  "version": "0.7.0"
}
```

**Step 3: Local Validation**
- Verify signature
- Check expiration
- Enforce usage limits
- Hardware binding (optional)

**Step 4: Usage Limits**
- Max 1 beta license per email
- Max 1 installation per token
- 60-day expiration enforced
- No infinite renewals

---

## Implementation Plan

### Phase 1: Cryptography (Now)

Add token signing/verification:
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
```

### Phase 2: Token Management (Now)

**Admin tools:**
- Generate tokens
- List issued tokens
- Revoke tokens
- Track usage

### Phase 3: Secure Installation (Now)

**Replace vulnerable install_beta_license() with:**
- Token-based installation only
- Signature verification
- Usage limit checks
- Expiration enforcement

### Phase 4: Online Validation (Later)

**Migration to server:**
- Online token validation
- Cloud-based usage tracking
- Automatic expiration
- Fraud detection

---

## Security Features to Add

### 1. Token-Based Installation ✅

**Remove:** `install_beta_license(email)` - too insecure

**Add:** `install_beta_license(token)` - requires valid token

### 2. Usage Limits ✅

- Max 1 beta per email address
- Max 1 installation per token
- Track installations per token
- Enforce hard limits

### 3. Expiration Enforcement ✅

**Replace lenient with:**
- Hard enforcement after expiration
- No grace period during beta
- Downgrade to Free tier

### 4. Fraud Detection ✅

- Detect duplicate emails
- Detect token reuse
- Track installation frequency
- Alert on suspicious patterns

### 5. Hardware Binding (Optional) ✅

**For beta:**
- Optional, not enforced
- Track machine IDs
- Detect multi-machine abuse

**For paid:**
- Enforced
- Lock to machine ID
- Request transfer if needed

---

## Code Changes Required

### 1. Remove Vulnerable Method

```python
# DELETE THIS:
def install_beta_license(email: str) -> bool:
    # Anyone can call this!
    license_data = {'email': email, 'tier': 'beta', ...}
    # ...
```

### 2. Add Secure Method

```python
# REPLACE WITH:
def install_beta_license(token: str) -> bool:
    # Verify token signature
    if not verify_token_signature(token):
        return False
    
    # Check expiration
    if token_expired(token):
        return False
    
    # Check usage limits
    if token_used_up(token):
        return False
    
    # Install license
    license_data = parse_token(token)
    # ...
```

### 3. Add Token Generation (Admin Tool)

```python
# parry-admin generate-beta-token
def generate_beta_token(email: str, days: int = 90) -> str:
    payload = {
        'email': email,
        'expires': calculate_expiration(days),
        'max_installations': 1,
        'issued': datetime.now().isoformat(),
        'version': LicenseConfig.VERSION
    }
    return sign_token(payload)
```

---

## Migration Strategy

### Existing Beta Users

**Problem:** Users already have local beta licenses

**Solution:**
1. Keep existing licenses valid
2. No new local installations without token
3. Tell existing users to request tokens for renewal
4. Grandfather existing users

### New Beta Users

**Flow:**
1. User requests beta via email/form
2. Admin generates token
3. Admin emails token to user
4. User installs: `parry license --install beta --token xxx`
5. System validates and installs

---

## Implementation Checklist

### Critical (Security)

- [ ] Remove vulnerable `install_beta_license(email)`
- [ ] Add token-based installation
- [ ] Implement signature verification
- [ ] Enforce usage limits
- [ ] Add expiration checks
- [ ] Track installations

### Important (Functionality)

- [ ] Admin token generator
- [ ] Admin token revoker
- [ ] Usage analytics
- [ ] Fraud detection
- [ ] Email notifications

### Optional (Future)

- [ ] Online validation
- [ ] Cloud dashboard
- [ ] Auto-approval logic
- [ ] Hardware binding enforcement

---

## Summary

**Current State:** ❌ Insecure - anyone can get free access

**Required Changes:**
1. ✅ Token-based beta licensing
2. ✅ Cryptographic signatures
3. ✅ Usage limit enforcement
4. ✅ Expiration enforcement
5. ✅ Admin-controlled issuance

**Implementation:** Cryptographic tokens, local validation, admin control

**Timeline:** Start now, complete before public launch

---

The system needs significant security hardening before launch!

