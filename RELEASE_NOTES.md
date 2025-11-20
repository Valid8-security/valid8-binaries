# Valid8 Binaries Release

## Version 1.0.0

### macOS (ARM64)
- ✅ Binary available: `valid8-macos-arm64.zip` (18MB)
- Fully functional Valid8 scanner
- Universal binary for Apple Silicon

### Windows (AMD64)
- ⚠️ Binary needs to be built
- Use `build_secure_binary.py --platform windows` on Windows machine

### Linux (AMD64)
- ⚠️ Binary needs to be built
- Use `build_secure_binary.py --platform linux` on Linux machine

## Installation

1. Download the binary for your platform
2. Extract the ZIP file
3. Make executable (Linux/macOS): `chmod +x valid8`
4. Run: `./valid8 scan /path/to/code`

## Building Binaries

To build binaries for all platforms:

```bash
# macOS (on macOS)
python3 build_secure_binary.py --platform macos

# Windows (on Windows)
python3 build_secure_binary.py --platform windows

# Linux (on Linux)
python3 build_secure_binary.py --platform linux
```

Then zip the binaries:
```bash
zip valid8-macos-arm64.zip valid8-macos
zip valid8-windows-amd64.zip valid8-windows.exe
zip valid8-linux-amd64.zip valid8-linux
```
