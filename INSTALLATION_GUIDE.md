# Valid8 Installation & Security Guide

## Quick Start

### macOS
1. Download `valid8-macos-arm64.zip`
2. Extract: `unzip valid8-macos-arm64.zip`
3. If blocked by Gatekeeper:
   - **Right-click** the `valid8` binary → **Open**
   - Or run: `xattr -cr valid8 && chmod +x valid8`
4. Run: `./valid8 --version`

### Windows
1. Download `valid8-windows-amd64.zip`
2. Extract the zip file
3. If blocked by Windows Defender:
   - Click **"More info"** on the warning
   - Click **"Run anyway"**
   - Or: Right-click `valid8.exe` → Properties → **Unblock** → OK
4. Run: `valid8.exe --version`

### Linux
1. Download `valid8-linux-amd64.zip`
2. Extract: `unzip valid8-linux-amd64.zip`
3. Make executable: `chmod +x valid8`
4. Run: `./valid8 --version`

## Why Security Warnings?

Valid8 binaries are **not code signed** (to avoid $99-400/year costs). This is common for open-source tools.

**macOS:** Gatekeeper blocks unsigned apps by default
**Windows:** SmartScreen flags unsigned executables

Both are **safe to bypass** for Valid8 - it's open-source and you can review the code.

## Verification

You can verify Valid8 is safe by:
1. Reviewing the source code: https://github.com/Valid8-security/parry-scanner
2. Building from source yourself
3. Checking the binary hash matches our releases

## Future Plans

We plan to add code signing in the future for a smoother experience.
