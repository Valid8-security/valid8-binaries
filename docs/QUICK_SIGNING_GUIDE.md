# Cheapest Code Signing Implementation Guide

## Quick Start: $99/year Solution

### Step 1: Apple Developer Program ($99/year)

**Sign up:**
1. Go to: https://developer.apple.com/programs/
2. Click "Enroll"
3. Sign in with Apple ID
4. Complete enrollment (1-2 days for approval)
5. Pay $99/year

**After approval:**
1. Go to: https://developer.apple.com/account/resources/certificates/list
2. Click "+" to create new certificate
3. Select "Developer ID Application"
4. Follow prompts to create certificate
5. Download certificate (.cer file)
6. Double-click to install in Keychain

**Sign and notarize:**
```bash
# Sign the binary
codesign --sign "Developer ID Application: Your Name (TEAM_ID)" \
  --options runtime \
  --timestamp \
  valid8-macos

# Verify signature
codesign -dv --verbose=4 valid8-macos

# Create zip for notarization
zip valid8-macos.zip valid8-macos

# Submit for notarization
xcrun notarytool submit valid8-macos.zip \
  --apple-id your@email.com \
  --team-id TEAM_ID \
  --password APP_SPECIFIC_PASSWORD \
  --wait

# Staple the notarization
xcrun stapler staple valid8-macos
```

### Step 2: Windows Self-Signed (FREE)

**Create certificate:**
```powershell
# In PowerShell (run as Administrator)
New-SelfSignedCertificate \
  -Type CodeSigningCert \
  -Subject "CN=Valid8 Security" \
  -KeyUsage DigitalSignature \
  -FriendlyName "Valid8 Code Signing" \
  -CertStoreLocation Cert:\CurrentUser\My \
  -NotAfter (Get-Date).AddYears(1)

# Export to PFX
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
$password = ConvertTo-SecureString -String "YourPassword" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "valid8-cert.pfx" -Password $password
```

**Sign binary:**
```powershell
# Sign the executable
signtool sign /f valid8-cert.pfx /p YourPassword /t http://timestamp.digicert.com valid8.exe

# Verify signature
signtool verify /pa valid8.exe
```

**Note:** Self-signed certificates will still show "Unknown Publisher" but the binary will be signed.

### Step 3: Update CI/CD (GitHub Actions)

**macOS signing:**
```yaml
- name: Sign macOS binary
  run: |
    codesign --sign "Developer ID Application: Your Name (TEAM_ID)" \
      --options runtime \
      --timestamp \
      dist/valid8-macos
    
    # Notarize
    xcrun notarytool submit dist/valid8-macos.zip \
      --apple-id ${{ secrets.APPLE_ID }} \
      --team-id ${{ secrets.APPLE_TEAM_ID }} \
      --password ${{ secrets.APPLE_APP_PASSWORD }} \
      --wait
    
    xcrun stapler staple dist/valid8-macos
```

**Windows signing:**
```yaml
- name: Sign Windows binary
  run: |
    signtool sign /f ${{ secrets.WINDOWS_CERT_PATH }} /p ${{ secrets.WINDOWS_CERT_PASSWORD }} /t http://timestamp.digicert.com dist/valid8.exe
```

---

## Total Cost: $99/year

**What you get:**
- ✅ macOS: No security warnings (after notarization)
- ⚠️ Windows: One-time warning (with instructions)
- ✅ Both binaries are signed
- ✅ Professional appearance

**When to upgrade Windows:**
- When you have $200-300/year budget
- When Windows user complaints increase
- When you want "Verified Publisher" status
