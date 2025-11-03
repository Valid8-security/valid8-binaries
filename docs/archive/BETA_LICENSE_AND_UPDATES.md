# Beta License Program & Update Distribution Strategy

## Executive Summary

This document details:
1. **Beta License Terms** - How long beta testers have premium features
2. **License Enforcement** - Technical implementation for controlling access
3. **Update Distribution** - How users get updates (including airgapped networks)
4. **Pricing Tiers** - Free, Pro, Enterprise licensing model

---

## Beta License Program

### License Duration Options

**Option 1: Time-Limited Beta (Recommended)**
- **Duration:** 60 days from signup date (optimized for revenue timeline)
- **Renewable:** Yes, with feedback submission
- **Enforcement:** Online validation + offline grace period
- **Benefits:** Sense of urgency, encourage engagement

**Option 2: Lifetime Beta Access**
- **Duration:** Forever (grandfather clause)
- **Condition:** Must provide monthly feedback
- **Enforcement:** Online validation (lenient)
- **Benefits:** Build community, reduce churn

**Option 3: Feature-Limited Beta**
- **Duration:** Unlimited time
- **Limitation:** Maximum 1 repo, 100 files/scan
- **Enforcement:** Local validation
- **Benefits:** Low maintenance, broad distribution

**Recommendation:** **Option 1 (60 days)** for momentum and revenue timeline, with **Option 2** as VIP for early adopters

---

## License Enforcement Architecture

### Technical Implementation

**Current License System:**
- Location: `parry/license.py`
- Features: Online validation, hardware binding, feature gating
- Offline grace: 7 days

**Beta License Format:**
```json
{
  "type": "BETA",
  "email": "user@example.com",
  "issued": "2025-01-01T00:00:00Z",
  "expires": "2025-04-01T00:00:00Z",
  "features": ["deep-mode", "ai-validation", "sca", "unlimited-files"],
  "machine_id": "PARRY-abc123...",
  "hardware_bound": true,
  "version": "0.7.0-beta"
}
```

### Enforcement Levels

#### Level 1: Honor System (Beta)
```python
# parry/cli.py
@main.command()
def scan(...):
    license_tier = "beta"  # Always allow during beta
    if mode == "deep" and license_tier == "free":
        console.print("Deep mode requires Pro license")
        console.print("Beta users get free access until [date]")
        return
```

**Pros:**
- Zero friction for users
- Fast iteration
- Good developer experience

**Cons:**
- Can't prevent abuse
- No data collection
- Harder to convert to paid

#### Level 2: Online Validation (Standard)
```python
# parry/license.py
def validate_beta_license(email: str) -> bool:
    """Validate beta license via server"""
    response = requests.post(
        "https://api.parry.dev/beta/validate",
        json={"email": email, "machine_id": get_machine_id()},
        timeout=5
    )
    return response.json().get("valid", False)
```

**Pros:**
- Real usage data
- Can disable bad actors
- Track engagement
- Easy to limit duration

**Cons:**
- Requires internet
- User privacy concerns
- Server costs

#### Level 3: Hardware-Bound (Enterprise)
```python
# parry/license.py - Already implemented
def validate_enterprise_license(license_key: str) -> bool:
    """Validate with hardware binding"""
    if not check_hardware_match(license_key):
        console.print("License not valid for this machine")
        return False
    return validate_online(license_key)
```

**Pros:**
- Prevents license sharing
- Strong control
- Enterprise-ready

**Cons:**
- Poor UX for legitimate users
- Support burden (VM detection)
- Privacy concerns

---

## Recommended Beta Enforcement Strategy

### Hybrid Approach

**For Beta (Free Users):**
```python
# parry/cli.py
def check_beta_access():
    """Check if user has beta access"""
    
    # 1. Check local cache first (fast, works offline)
    cached = check_beta_cache()
    if cached and cached["valid"]:
        return True
    
    # 2. Check license file
    license = load_license()
    if license and license.get("type") == "BETA":
        # Offline grace period: 7 days
        expires = datetime.fromisoformat(license["expires"])
        if datetime.now() < expires:
            return True
    
    # 3. Try online validation (optional)
    if is_online():
        try:
            validated = validate_online(license["email"])
            cache_result(validated)
            return validated
        except:
            pass
    
    # 4. Fallback: show message but allow
    console.print("[yellow]⚠️  Beta license expired. Continuing anyway.[/yellow]")
    console.print("[dim]Please renew at beta@parry.ai[/dim]")
    return True  # Lenient during beta
```

**Key Points:**
- ✅ 60-day expiration in license file
- ✅ 7-day offline grace period
- ✅ Online validation optional (privacy-first)
- ✅ Show reminder but don't block
- ✅ Collect telemetry to measure engagement

---

## Update Distribution Process

### Standard Updates (Internet-Connected)

**Method 1: PyPI (Recommended)**
```bash
# User updates
pip install --upgrade parry-scanner

# Your release process
python -m build
twine upload dist/*
```

**Pros:**
- Universal
- Automatic dependency management
- Version pinning available
- Works on all platforms

**Cons:**
- Requires internet
- Small delay (propagation)

**Method 2: GitHub Releases**
```bash
# User downloads manually
wget https://github.com/Parry-AI/parry-scanner/releases/download/v0.7.0/parry_scanner-0.7.0-py3-none-any.whl
pip install parry_scanner-0.7.0-py3-none-any.whl
```

**Pros:**
- Direct control
- Release notes bundled
- Deterministic downloads

**Cons:**
- Manual download
- No automatic updates

### Airgapped Network Updates

**Problem:** Users on airgapped networks can't use PyPI

**Solution: Offline Distribution Package**

#### Create Offline Package
```bash
# scripts/create_offline_package.sh
#!/bin/bash

VERSION="0.7.0"
OUTPUT_DIR="parry_offline_$VERSION"

mkdir -p $OUTPUT_DIR

# Download wheel and all dependencies
pip download -d $OUTPUT_DIR parry-scanner==$VERSION

# Include installation instructions
cat > $OUTPUT_DIR/INSTALL.txt << 'EOF'
PARRY OFFLINE INSTALLATION

1. Copy this folder to target machine (USB drive, network share)
2. Install from local directory:

   pip install --find-links ./ parry-scanner==0.7.0

3. Verify installation:

   parry --version

4. If dependency issues, install individual wheels:

   pip install ./parry_scanner-0.7.0-py3-none-any.whl
   pip install ./click-8.1.7-py3-none-any.whl
   # ... (all dependencies)
EOF

# Create checksums
cd $OUTPUT_DIR
sha256sum * > SHA256SUMS

# Package it
cd ..
tar -czf parry_offline_$VERSION.tar.gz $OUTPUT_DIR
```

#### Deployment Process

**Step 1: Create Offline Package**
```bash
# Run on connected machine
bash scripts/create_offline_package.sh

# Output:
# parry_offline_0.7.0/
#   ├── parry_scanner-0.7.0-py3-none-any.whl
#   ├── click-8.1.7-py3-none-any.whl
#   ├── rich-13.7.0-py3-none-any.whl
#   ├── ... (all deps)
#   ├── INSTALL.txt
#   └── SHA256SUMS
```

**Step 2: Transfer to Airgapped Network**
- USB drive
- Network air-gap transfer (one-way)
- Internal package repository
- Secure file transfer protocol

**Step 3: Install on Target Machine**
```bash
# On airgapped machine
cd parry_offline_0.7.0

# Verify integrity
sha256sum -c SHA256SUMS

# Install
pip install --find-links ./ parry-scanner==0.7.0

# Or install from tar
tar -xzf parry_offline_0.7.0.tar.gz
cd parry_offline_0.7.0
pip install --find-links ./ parry-scanner==0.7.0
```

#### Automated Offline Updates

**Create Internal Repository:**
```bash
# On internal network, mirror PyPI
# Setup: pypiserver or devpi

# Install pypiserver
pip install pypiserver

# Create offline repo
mkdir -p ~/offline_repo

# Download specific packages
pip download -d ~/offline_repo parry-scanner==0.7.0
pip download -d ~/offline_repo ollama

# Serve locally
pypi-server run ~/offline_repo -p 8080

# Clients install from local server
pip install --index-url http://internal-pypi:8080/simple parry-scanner
```

**Benefits:**
- One admin downloads/verifies
- All clients use internal repo
- Faster installs (LAN)
- Central audit trail

---

## Update Notification & Delivery

### Notify Users of Updates

**Method 1: Automatic Check (Recommended)**
```python
# parry/cli.py
def check_for_updates():
    """Check if newer version available"""
    if not is_online():
        return
    
    try:
        response = requests.get(
            'https://pypi.org/pypi/parry-scanner/json',
            timeout=2
        )
        latest_version = response.json()['info']['version']
        current_version = __version__
        
        if Version(latest_version) > Version(current_version):
            console.print("\n[yellow]📦 Update available: v{latest_version}[/yellow]")
            console.print("[dim]pip install --upgrade parry-scanner[/dim]\n")
            
            # Track update notifications
            analytics.track("update_notification_shown", {
                "current": current_version,
                "latest": latest_version
            })
    except:
        pass
```

**Method 2: Manual Check Command**
```bash
parry check-updates
# Output:
# ✓ You're on latest version (v0.7.0)
# or
# 📦 Update available: v0.7.1
# Run: pip install --upgrade parry-scanner
```

**Method 3: Email Notifications**
```python
# For beta users
def send_update_email(user_email, version):
    """Send update notification"""
    subject = f"Parry v{version} Released"
    body = f"""
    New features in v{version}:
    - Fixed CWE detection
    - Performance improvements
    - Bug fixes
    
    Update: pip install --upgrade parry-scanner
    
    Questions? Reply to this email.
    """
    send_email(user_email, subject, body)
```

### Changelog Distribution

**Include in Package:**
```bash
# Include CHANGELOG.md in sdist
# MANIFEST.in:
include CHANGELOG.md
include release_notes/

# Users can read
cat /path/to/venv/lib/python3.12/site-packages/parry/CHANGELOG.md
```

**Web-Based:**
```markdown
# https://parry.dev/changelog
# https://github.com/Parry-AI/parry-scanner/releases
```

---

## Pricing Tiers & Licensing

### Tier Definitions

#### Free Tier (Forever)
**Limitations:**
- Fast Mode only (pattern-based)
- Single repository
- Max 100 files per scan
- Community support
- JSON/Markdown output only

**Use Case:**
- Individual developers
- Personal projects
- Learning/education
- Small scripts

**Enforcement:**
```python
# parry/cli.py
@scan.command()
def scan(...):
    license = get_license_tier()
    
    if license == "free":
        # Check file limit
        file_count = count_files(path)
        if file_count > 100:
            console.print("[red]Free tier limited to 100 files[/red]")
            console.print("[yellow]Upgrade to Pro for unlimited: https://parry.dev/pricing[/yellow]")
            return
        
        # Force fast mode
        if mode == "deep":
            console.print("[yellow]Deep mode requires Pro license[/yellow]")
            mode = "fast"
```

#### Pro Tier ($29/month or $290/year)
**Features:**
- Deep + Hybrid modes (AI-powered)
- AI validation (reduce false positives)
- SCA scanning (dependency vulnerabilities)
- Secrets scanning
- Unlimited files/repos
- Email support
- Priority bug fixes
- Custom rules support
- Compliance reports

**Enforcement:**
```python
# Requires valid license key
def check_pro_features():
    license = validate_license()
    
    if not license or license["tier"] != "pro":
        console.print("[red]This feature requires Pro license[/red]")
        console.print("[yellow]Get Pro: https://parry.dev/pro[/yellow]")
        return False
    return True
```

#### Enterprise Tier ($99+/month per seat)
**Features:**
- All Pro features
- REST API access
- CI/CD integrations
- On-prem deployment
- SSO integration (SAML)
- Audit logs
- SLA guarantees
- Dedicated support
- Custom CWE rules
- Container/IaC scanning
- Compliance: SOC2, ISO 27001 reports

**Enforcement:**
```python
# Hardware-bound license
def check_enterprise_features():
    license = validate_license()
    
    if not license or license["tier"] != "enterprise":
        return False
    
    # Check hardware binding
    if not verify_machine_binding(license["machine_id"]):
        console.print("[red]License not valid for this machine[/red]")
        return False
    
    return True
```

---

## Beta-to-Paid Conversion

### Conversion Strategy

**Month 1-3: Beta (Free)**
- All features unlocked
- No credit card required
- Collect feedback
- Show value

**Month 4: Conversion**
- Email: "Beta ending, convert to Pro"
- Offer: 50% discount first year
- Alternative: Free tier still available

**Tactics:**
1. **Soft Reminder (Day 60):**
   ```
   "Your beta access ends in 30 days. 
   Want to continue using Deep Mode? 
   Get Pro at 50% off: https://..."
   ```

2. **Conversion Email (Day 75):**
   ```
   "Thank you for testing Parry!
   
   We'd love you to stay. Choose:
   
   [Button: Get Pro - 50% off]
   [Button: Continue with Free]
   [Button: Share Feedback]
   ```

3. **Grandfather Early Adopters:**
   ```
   "First 100 beta users get lifetime Pro access
   if they convert within 30 days"
   ```

---

## License Administration

### Managing Beta Access

**Automated Signup:**
```python
# Web form → API → License generation
def generate_beta_license(email: str) -> dict:
    """Generate beta license for user"""
    license = {
        "type": "BETA",
        "email": email,
        "issued": datetime.now().isoformat(),
        "expires": (datetime.now() + timedelta(days=90)).isoformat(),
        "features": ["deep-mode", "ai-validation", "unlimited-files"],
        "machine_id": "PARRY-NEW",  # Will be bound on first use
        "version": "0.7.0-beta"
    }
    
    # Store in database
    db.beta_licenses.insert(license)
    
    # Send email with license key
    send_license_email(email, license)
    
    return license
```

**License Revocation:**
```python
def revoke_license(email: str, reason: str):
    """Revoke beta access"""
    # Mark as revoked in database
    db.beta_licenses.update(
        {"email": email},
        {"revoked": True, "revoked_reason": reason}
    )
    
    # Next validation check will fail
    # User sees: "Beta access revoked: [reason]"
```

**Renewal Process:**
```python
def renew_beta_access(email: str) -> bool:
    """Renew expiring beta access"""
    # Check if user provided feedback
    feedback_count = db.feedback.count({"email": email})
    
    if feedback_count >= 3:  # Active beta user
        # Extend 90 more days
        extend_license(email, days=90)
        send_license_email(email, "renewed")
        return True
    
    # No feedback, no renewal
    return False
```

---

## Summary

### Beta License Model

**Recommended:**
- **Duration:** 60 days from signup
- **Enforcement:** Online validation + 7-day offline grace
- **Renewal:** Yes, with feedback submission
- **Conversion:** 50% discount, lifetime VIP for early adopters

### Update Distribution

**Internet-Connected:**
- Primary: `pip install --upgrade parry-scanner`
- Secondary: Manual download from GitHub releases

**Airgapped Networks:**
- Create offline package with all dependencies
- Internal PyPI mirror (pypiserver/devpi)
- Manual transfer (USB, network)

### Pricing Tiers

**Free:** Fast Mode, 100 files max, community support  
**Pro ($29/mo):** All features, unlimited, email support  
**Enterprise ($99+/mo):** On-prem, SSO, SLA, dedicated support

### Technical Implementation

**License Storage:**
- `~/.parry/license.json` (user's home directory)
- Hardware-bound for Enterprise
- Online validation with caching
- 7-day offline grace period

**Feature Gating:**
- Check license tier in CLI commands
- Show upgrade message for limited features
- Allow downgrade to Free if expired

**Security:**
- Tamper detection (already implemented)
- Hardware fingerprinting
- License revocation capability
- Audit logging (Enterprise)

---

## Next Steps

1. **Implement Beta License System**
   - Update `parry/license.py` for beta tier
   - Add email signup flow
   - Create license generation API

2. **Create Offline Package Script**
   - `scripts/create_offline_package.sh`
   - Include in CI/CD
   - Upload to GitHub releases

3. **Launch Beta Landing Page**
   - Signup form
   - License delivery via email
   - Status dashboard

4. **Setup Update Notifications**
   - Automatic version check
   - Email alerts for beta users
   - Changelog distribution

**Questions?** Review `parry/license.py` for implementation details.

