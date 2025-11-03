# Parry VS Code Extension

Real-time security vulnerability detection directly in VS Code with AI-powered fixes.

## Features

- 🔍 **Real-time Scanning**: Detect vulnerabilities as you type (debounced)
- 🐛 **Inline Diagnostics**: Squiggly underlines for security issues
- ⚡ **Quick Fixes**: One-click AI-generated fixes (Pro/Enterprise)
- 📊 **Security Panel**: Visual dashboard of vulnerabilities
- 🎯 **200+ Detectors**: Framework-specific, language-advanced, crypto, AI/ML, API security
- 🔐 **License Tiers**: Free (100 files, local), Pro (unlimited, hosted LLM), Enterprise (API access)

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Press `Ctrl+P` / `Cmd+P`
3. Run `ext install parry-dev.parry-security-scanner`

### From VSIX File

1. Download `.vsix` from releases
2. Open VS Code
3. Extensions → ... → Install from VSIX

### From Source

```bash
cd vscode-extension
npm install
npm run compile
# Press F5 to launch Extension Development Host
```

## Quick Start

1. **Install Extension**
2. **Open Project**: Open any code file
3. **Start Scanning**: Extension auto-scans on file open/save
4. **View Results**: Check Problems panel (`Ctrl+Shift+M`) or Security sidebar
5. **Apply Fixes**: Click lightbulb 💡 for quick fixes

## Usage

### Commands

- `Parry: Scan Current File` - Scan active file
- `Parry: Scan Entire Workspace` - Full workspace scan
- `Parry: Show Security Panel` - Open vulnerability dashboard
- `Parry: Ask LLM About This Code` - Direct LLM security analysis (Pro/Enterprise)
- `Parry: Clear All Diagnostics` - Clear warnings
- `Parry: Activate License` - Enter Pro/Enterprise key
- `Parry: Show License Information` - View current tier
- `Parry: Subscribe to Pro` - Open pricing page

### Keyboard Shortcuts

- `Ctrl+Shift+P` → "Parry: Scan File"
- `Ctrl+Shift+P` → "Parry: Ask LLM About This Code"
- Right-click in editor → "Parry: Scan File"
- Click shield icon in title bar

### Settings

```json
{
  "parry.enabled": true,
  "parry.realtimeScan": true,
  "parry.scanDelay": 2000,
  "parry.severity": "low",
  "parry.mode": "hybrid",
  "parry.excludePatterns": ["**/node_modules/**", "**/dist/**"],
  "parry.showInlineErrors": true,
  "parry.apiEndpoint": "https://api.parry.dev"
}
```

## License Tiers

| Feature | Free | Pro ($49/mo) | Enterprise ($299/mo) |
|---------|------|--------------|----------------------|
| Pattern Scanning | ✅ | ✅ | ✅ |
| Real-time Scanning | ✅ | ✅ | ✅ |
| File Limit | 100 | Unlimited | Unlimited |
| AI-Powered Fixes | ❌ | ✅ | ✅ |
| Hosted LLM | ❌ | ✅ | ✅ |
| Deep Mode | ❌ | ✅ | ✅ |
| API Access | ❌ | ❌ | ✅ |
| Priority Support | ❌ | ❌ | ✅ |

### Activate Pro/Enterprise

1. Subscribe at https://parry.dev/pricing
2. Receive license key via email
3. In VS Code: `Cmd+Shift+P` → "Parry: Activate License"
4. Enter key → Done!

Or via CLI:
```bash
parry activate <your-license-key>
```

## How It Works

1. **File Change Detection**: Watches for file edits with debouncing
2. **Smart Scanning**: 
   - Free: Pattern-based local scanning
   - Pro/Enterprise: Hosted AI analysis
3. **Diagnostic Publishing**: Creates VS Code diagnostics with severity
4. **Quick Fix Generation**: AI generates contextual fixes for Pro+ users
5. **Security Panel**: Real-time dashboard with click-to-navigate

## Supported Languages

Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, Rust, Swift, Kotlin, C++, C#, C

## Security Coverage

- **OWASP Top 10 2021**: A01-A10 covered
- **OWASP API Security Top 10 2023**: API1-API10 covered
- **OWASP LLM Top 10**: ML01-ML10 covered
- **CWE Coverage**: 150+ CWEs
- **Frameworks**: Spring, Django, Rails, Express, Laravel, ASP.NET
- **Cloud**: AWS, Azure, GCP metadata SSRF, IAM misconfigs
- **Container/K8s**: Privileged containers, secrets, network policies
- **Modern Crypto**: TLS 1.2+, RSA 2048+, no MD5/SHA1 for auth

## Development

### Build

```bash
npm install
npm run compile
```

### Watch Mode

```bash
npm run watch
```

### Test

```bash
npm test
```

### Package

```bash
npm run package  # Creates .vsix file
```

### Publish

```bash
vsce login parry-dev
vsce publish
```

## Troubleshooting

### "Parry scan failed" error
- Check internet connection (for Pro/Enterprise)
- Verify license key: `Parry: Show License Information`
- Check API endpoint in settings

### Real-time scanning not working
- Enable in settings: `"parry.realtimeScan": true`
- Check file not in exclude patterns
- Restart VS Code

### No AI fixes available
- Upgrade to Pro: `Parry: Subscribe to Pro`
- Verify license active: `Parry: Show License Information`

## Support

- **Documentation**: https://docs.parry.dev
- **Issues**: https://github.com/Parry-AI/parry-scanner/issues
- **Email**: support@parry.dev
- **Discord**: https://discord.gg/parry

## License

Copyright (C) Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra.

See LICENSE file for details.

## Changelog

### 1.0.0 (2025-11-03)

- Initial release
- Real-time vulnerability scanning
- Inline diagnostics with quick fixes
- Security panel dashboard
- Pro/Enterprise license support
- 200+ security detectors
- AI-powered fix generation
