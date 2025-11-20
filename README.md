

## Security Warnings

### macOS
If you see "cannot be opened because it is from an unidentified developer":
1. **Right-click** the `valid8` binary → **Open**
2. Click **"Open"** in the security dialog
3. Or run: `xattr -cr valid8 && chmod +x valid8`

### Windows
If Windows Defender blocks the download:
1. Click **"More info"** on the warning
2. Click **"Run anyway"**
3. Or: Right-click → Properties → **Unblock** → OK

**Why?** Valid8 binaries are not code signed (to avoid $99-400/year costs). This is safe to bypass - Valid8 is proprietary.

