# Code Signing Cost Analysis & Options

## Summary: Cheapest Path to Verified Status

### Minimum Viable Solution: ~$99/year
- **macOS:** Apple Developer Program ($99/year) - REQUIRED for notarization
- **Windows:** Self-signed certificate (FREE) - Shows warning but works
- **Total:** $99/year

### Professional Solution: ~$300-500/year
- **macOS:** Apple Developer Program ($99/year)
- **Windows:** OV Code Signing Certificate ($200-300/year)
- **Total:** $300-400/year

### Enterprise Solution: ~$500-700/year
- **macOS:** Apple Developer Program ($99/year)
- **Windows:** EV Code Signing Certificate ($400-600/year)
- **Total:** $500-700/year

---

## macOS Code Signing

### Option 1: Apple Developer Program (REQUIRED for Notarization)
**Cost:** $99/year
**What you get:**
- Developer ID Application certificate
- Ability to notarize apps (required for distribution)
- No "unidentified developer" warnings after notarization
- Required for App Store distribution (if needed later)

**Process:**
1. Join Apple Developer Program ($99/year)
2. Create Developer ID Application certificate (free, included)
3. Sign: `codesign --sign "Developer ID Application: Your Name" --options runtime valid8-macos`
4. Notarize: `xcrun notarytool submit valid8-macos.zip --apple-id your@email.com --team-id TEAM_ID --password APP_SPECIFIC_PASSWORD`
5. Staple: `xcrun stapler staple valid8-macos`

**Timeline:** 1-2 days for Apple Developer approval

### Option 2: Self-Signed Certificate (NOT RECOMMENDED)
**Cost:** FREE
**Issues:**
- Still shows "unidentified developer" warning
- Cannot notarize
- Users must manually trust certificate
- Not suitable for distribution

**Verdict:** Not worth it - users still see warnings

---

## Windows Code Signing

### Option 1: Self-Signed Certificate (FREE - Cheapest)
**Cost:** FREE
**Pros:**
- No cost
- Can sign binaries
- Works for internal/testing

**Cons:**
- Shows "Unknown Publisher" warning
- Users must click "More info" → "Run anyway"
- Not trusted by default
- SmartScreen may still flag

**Process:**
```powershell
# Create self-signed certificate
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Valid8 Security" -CertStoreLocation Cert:\CurrentUser\My

# Sign binary
signtool sign /f certificate.pfx /p password valid8.exe
```

**Verdict:** Free but still shows warnings - not ideal for production

### Option 2: OV (Organization Validated) Certificate
**Cost:** $200-300/year
**Providers:**
- Sectigo: ~$200/year
- DigiCert: ~$300/year
- GlobalSign: ~$250/year

**What you get:**
- "Published by: Valid8 Security" (verified organization name)
- Reduces SmartScreen warnings
- Trusted by Windows
- No "Unknown Publisher" warning

**Process:**
1. Purchase OV certificate
2. Complete organization validation (1-3 days)
3. Sign: `signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com valid8.exe`

**Verdict:** Good balance of cost and trust

### Option 3: EV (Extended Validation) Certificate
**Cost:** $400-600/year
**Providers:**
- DigiCert: ~$500/year
- Sectigo: ~$400/year
- GlobalSign: ~$550/year

**What you get:**
- Immediate SmartScreen trust (no warnings)
- Highest level of trust
- "Published by: Valid8 Security" with verified status
- Hardware token required (USB key)

**Process:**
1. Purchase EV certificate
2. Complete extended validation (3-5 days)
3. Receive hardware token
4. Sign with token: `signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com valid8.exe`

**Verdict:** Best trust, but expensive

---

## Recommended Approach: Start Cheap, Scale Up

### Phase 1: Minimum Viable (Year 1)
**Cost:** $99/year
- Apple Developer Program for macOS
- Self-signed for Windows (with clear user instructions)
- **Total:** $99/year

**User Experience:**
- macOS: No warnings after notarization ✅
- Windows: Shows warning, but clear instructions provided

### Phase 2: Professional (Year 2+)
**Cost:** $300-400/year
- Apple Developer Program ($99/year)
- OV Code Signing Certificate ($200-300/year)
- **Total:** $300-400/year

**User Experience:**
- macOS: No warnings ✅
- Windows: Verified publisher, minimal warnings ✅

### Phase 3: Enterprise (If needed)
**Cost:** $500-700/year
- Apple Developer Program ($99/year)
- EV Code Signing Certificate ($400-600/year)
- **Total:** $500-700/year

**User Experience:**
- macOS: No warnings ✅
- Windows: No warnings, immediate trust ✅

---

## Implementation Steps (Cheapest Path)

### Step 1: Apple Developer Program ($99/year)
1. Go to: https://developer.apple.com/programs/
2. Sign up with Apple ID
3. Pay $99/year
4. Wait 1-2 days for approval
5. Create Developer ID Application certificate
6. Sign and notarize macOS binary

### Step 2: Windows Self-Signed (FREE)
1. Create self-signed certificate
2. Sign Windows binary
3. Provide clear user instructions
4. Plan to upgrade to OV certificate when budget allows

### Step 3: Automate in CI/CD
- Add signing to GitHub Actions workflows
- Store certificates securely (GitHub Secrets)
- Automate notarization

---

## Cost Comparison Table

| Solution | macOS | Windows | Total/Year | User Experience |
|----------|-------|---------|------------|-----------------|
| **Minimum** | $99 (Apple Dev) | FREE (Self-signed) | **$99** | macOS: ✅ No warnings<br>Windows: ⚠️ Warning |
| **Professional** | $99 (Apple Dev) | $200-300 (OV) | **$300-400** | macOS: ✅ No warnings<br>Windows: ✅ Verified |
| **Enterprise** | $99 (Apple Dev) | $400-600 (EV) | **$500-700** | macOS: ✅ No warnings<br>Windows: ✅ No warnings |

---

## Recommendation

**Start with Minimum Viable ($99/year):**
1. Get Apple Developer Program for macOS notarization
2. Use self-signed certificate for Windows initially
3. Provide clear user instructions for Windows
4. Upgrade to OV certificate when you have revenue/budget

**Why this works:**
- macOS users get seamless experience (no warnings)
- Windows users see one warning but have clear instructions
- Can upgrade Windows signing later without changing macOS setup
- Total cost: Only $99/year initially

---

## Next Steps

1. **Immediate:** Sign up for Apple Developer Program
2. **Week 1:** Set up macOS code signing and notarization
3. **Week 2:** Create self-signed Windows certificate
4. **Month 3-6:** Evaluate upgrading to OV certificate based on user feedback
