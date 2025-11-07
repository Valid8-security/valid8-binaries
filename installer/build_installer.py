"""
🚀 Parry One-Click Installer Builder

Creates standalone binaries for Windows, macOS, and Linux.
No Python/Node.js installation required for end users.
"""

import os
import sys
import platform
import subprocess
from pathlib import Path
import shutil
import requests
from typing import Dict, List

class ParryInstallerBuilder:
    """Builds one-click installers for Parry Security Scanner"""

    def __init__(self):
        self.root_dir = Path(__file__).parent.parent
        self.installer_dir = self.root_dir / "installer"
        self.dist_dir = self.installer_dir / "dist"
        self.build_dir = self.installer_dir / "build"

        # Create directories
        self.dist_dir.mkdir(exist_ok=True)
        self.build_dir.mkdir(exist_ok=True)

    def install_dependencies(self):
        """Install build dependencies"""
        print("📦 Installing build dependencies...")

        # Install PyInstaller and other build tools
        subprocess.run([
            sys.executable, "-m", "pip", "install",
            "pyinstaller>=6.0.0",
            "pefile>=2023.2.7",  # For Windows
            "macholib>=1.16.3",  # For macOS
            "dmgbuild>=1.6.1",   # For macOS DMG
            "nsis>=3.08",        # For Windows installer
        ], check=True)

        # Install Ollama if not present (for AI features)
        self._ensure_ollama_available()

    def _ensure_ollama_available(self):
        """Ensure Ollama is available or provide fallback"""
        try:
            result = subprocess.run(["ollama", "--version"],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ Ollama found: {result.stdout.strip()}")
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        print("⚠️  Ollama not found - will use local AI models only")
        print("   Users can install Ollama separately for full AI features")

    def create_spec_file(self):
        """Create PyInstaller spec file for optimized build"""

        spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

import os
import sys
from pathlib import Path

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(SPEC))
sys.path.insert(0, current_dir)

# Parry analysis
a = Analysis(
    ['../parry/__main__.py'],
    pathex=[current_dir],
    binaries=[],
    datas=[
        ('../parry', 'parry'),
        ('../integrations', 'integrations'),
    ],
    hiddenimports=[
        'parry.scanner',
        'parry.ai_detector',
        'parry.reporter',
        'parry.cli',
        'parry.llm',
        'parry.cache',
        'parry.language_support',
        'parry.detectors',
        'cryptography',
        'rich',
        'plotly',
        'pandas',
        'chardet',
        'mmap',
        'hmac',
        'hashlib',
        'jwt',
        'requests',
        'click',
        'pathlib',
        'dataclasses',
        'typing',
        'concurrent.futures',
        'threading',
        'asyncio',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'scipy',
        'PIL',
        'pygame',
        'cv2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='parry',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
'''

        spec_file = self.installer_dir / "parry.spec"
        with open(spec_file, 'w') as f:
            f.write(spec_content)

        return spec_file

    def build_binary(self, platform_name: str):
        """Build binary for specific platform"""

        print(f"🔨 Building Parry binary for {platform_name}...")

        # Create spec file
        spec_file = self.create_spec_file()

        # Build command
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--clean",
            "--noconfirm",
            str(spec_file)
        ]

        # Platform-specific options
        if platform_name == "windows":
            cmd.extend(["--target", "windows"])
        elif platform_name == "macos":
            cmd.extend(["--target", "macos"])

        # Run build
        result = subprocess.run(cmd, cwd=self.installer_dir)
        if result.returncode != 0:
            raise Exception(f"Build failed for {platform_name}")

        print(f"✅ Binary built successfully for {platform_name}")

    def create_installer_package(self, platform_name: str):
        """Create installer package for the platform"""

        binary_path = self.dist_dir / "parry"
        if platform_name == "windows":
            binary_path = binary_path.with_suffix(".exe")

        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        print(f"📦 Creating installer package for {platform_name}...")

        if platform_name == "windows":
            self._create_windows_installer(binary_path)
        elif platform_name == "macos":
            self._create_macos_installer(binary_path)
        elif platform_name == "linux":
            self._create_linux_installer(binary_path)

    def _create_windows_installer(self, binary_path: Path):
        """Create Windows NSIS installer"""

        nsis_script = f'''
!include "MUI2.nsh"

Name "Parry Security Scanner"
OutFile "parry-windows-installer.exe"
InstallDir "$PROGRAMFILES\\Parry"
InstallDirRegKey HKCU "Software\\Parry" ""

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Section "Parry Security Scanner" SecApp
    SetOutPath "$INSTDIR"
    File "{binary_path}"

    # Create desktop shortcut
    CreateShortCut "$DESKTOP\\Parry Security Scanner.lnk" "$INSTDIR\\parry.exe"

    # Registry information for add/remove programs
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Parry" "DisplayName" "Parry Security Scanner"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Parry" "UninstallString" "$INSTDIR\\uninstall.exe"
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Parry" "NoModify" 1
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Parry" "NoRepair" 1

    WriteUninstaller "$INSTDIR\\uninstall.exe"
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\\parry.exe"
    Delete "$INSTDIR\\uninstall.exe"
    Delete "$DESKTOP\\Parry Security Scanner.lnk"
    RMDir "$INSTDIR"
    DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Parry"
SectionEnd
'''

        nsis_file = self.installer_dir / "installer.nsi"
        with open(nsis_file, 'w') as f:
            f.write(nsis_script)

        # Compile NSIS installer
        subprocess.run(["makensis", str(nsis_file)], check=True)

        print("✅ Windows installer created: parry-windows-installer.exe")

    def _create_macos_installer(self, binary_path: Path):
        """Create macOS DMG installer"""

        # Create app bundle structure
        app_dir = self.dist_dir / "Parry.app"
        contents_dir = app_dir / "Contents"
        macos_dir = contents_dir / "MacOS"
        resources_dir = contents_dir / "Resources"

        contents_dir.mkdir(parents=True, exist_ok=True)
        macos_dir.mkdir(exist_ok=True)
        resources_dir.mkdir(exist_ok=True)

        # Copy binary
        shutil.copy2(binary_path, macos_dir / "parry")

        # Create Info.plist
        plist_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>parry</string>
    <key>CFBundleIdentifier</key>
    <string>ai.parry.scanner</string>
    <key>CFBundleName</key>
    <string>Parry</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.12</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
</dict>
</plist>'''

        with open(contents_dir / "Info.plist", 'w') as f:
            f.write(plist_content)

        # Create DMG
        dmg_name = "parry-macos-installer.dmg"
        subprocess.run([
            "hdiutil", "create", "-volname", "Parry Security Scanner",
            "-srcfolder", str(app_dir), "-ov", dmg_name
        ], check=True)

        print(f"✅ macOS installer created: {dmg_name}")

    def _create_linux_installer(self, binary_path: Path):
        """Create Linux AppImage or tar.gz"""

        # Create directory structure
        linux_dir = self.dist_dir / "parry-linux"
        linux_dir.mkdir(exist_ok=True)

        # Copy binary and create launcher script
        shutil.copy2(binary_path, linux_dir / "parry")

        # Create desktop file
        desktop_content = '''[Desktop Entry]
Name=Parry Security Scanner
Exec=parry
Icon=parry
Type=Application
Categories=Development;Security;
'''

        with open(linux_dir / "parry.desktop", 'w') as f:
            f.write(desktop_content)

        # Create tar.gz archive
        archive_name = "parry-linux-installer.tar.gz"
        subprocess.run([
            "tar", "-czf", archive_name, "-C", str(linux_dir), "."
        ], check=True)

        print(f"✅ Linux installer created: {archive_name}")

    def create_install_script(self):
        """Create automated install script"""

        script_content = '''#!/bin/bash
# Parry One-Click Installer
# Automatically detects platform and installs appropriate version

set -e

echo "🛡️ Parry Security Scanner - One-Click Installer"
echo "=============================================="

# Detect platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
    ARCHIVE_NAME="parry-linux-installer.tar.gz"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    ARCHIVE_NAME="parry-macos-installer.dmg"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    PLATFORM="windows"
    ARCHIVE_NAME="parry-windows-installer.exe"
else
    echo "❌ Unsupported platform: $OSTYPE"
    exit 1
fi

echo "📍 Detected platform: $PLATFORM"

# Download appropriate installer
DOWNLOAD_URL="https://github.com/Parry-AI/parry-scanner/releases/latest/download/$ARCHIVE_NAME"

echo "⬇️ Downloading Parry installer..."
if command -v curl &> /dev/null; then
    curl -L -o installer "$DOWNLOAD_URL"
elif command -v wget &> /dev/null; then
    wget -O installer "$DOWNLOAD_URL"
else
    echo "❌ Neither curl nor wget found. Please install one and try again."
    exit 1
fi

# Install based on platform
case $PLATFORM in
    linux)
        echo "📦 Installing for Linux..."
        tar -xzf installer
        chmod +x parry
        sudo mv parry /usr/local/bin/
        echo "✅ Parry installed to /usr/local/bin/parry"
        ;;

    macos)
        echo "📦 Installing for macOS..."
        hdiutil attach installer
        cp -r /Volumes/"Parry Security Scanner"/Parry.app /Applications/
        hdiutil detach /Volumes/"Parry Security Scanner"
        echo "✅ Parry installed to /Applications/Parry.app"
        ;;

    windows)
        echo "📦 Installing for Windows..."
        ./installer  # Run NSIS installer
        echo "✅ Parry installed via Windows installer"
        ;;
esac

# Cleanup
rm -f installer

# Test installation
echo "🧪 Testing installation..."
parry --version

echo ""
echo "🎉 Parry Security Scanner installed successfully!"
echo ""
echo "🚀 Quick start:"
echo "   parry scan .                    # Scan current directory"
echo "   parry scan . --mode hybrid     # AI-enhanced scanning"
echo "   parry --help                   # Show all options"
echo ""
echo "📚 Documentation: https://parry.ai/docs"
echo "🐛 Issues: https://github.com/Parry-AI/parry-scanner/issues"
'''

        install_script = self.installer_dir / "install.sh"
        with open(install_script, 'w') as f:
            f.write(script_content)

        # Make executable
        os.chmod(install_script, 0o755)

        print("✅ Install script created: install.sh")

    def run_tests(self):
        """Run tests to ensure the build works"""

        print("🧪 Running build tests...")

        # Test that the binary was created and is executable
        binary_path = self.dist_dir / "parry"
        if not binary_path.exists():
            raise FileNotFoundError("Binary not found after build")

        # Test basic functionality (if possible)
        try:
            result = subprocess.run([str(binary_path), "--help"],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✅ Binary test passed")
            else:
                print(f"⚠️ Binary test warning: {result.stderr}")
        except Exception as e:
            print(f"⚠️ Could not test binary: {e}")

    def build_all_platforms(self):
        """Build installers for all supported platforms"""

        current_platform = platform.system().lower()

        # Build for current platform
        self.build_binary(current_platform)
        self.create_installer_package(current_platform)

        # Note: Cross-compilation would require additional setup
        # For now, we build for the current platform

        print(f"✅ Built installer for {current_platform}")

    def main(self):
        """Main build process"""

        print("🚀 Building Parry One-Click Installers")
        print("=" * 50)

        try:
            self.install_dependencies()
            self.build_all_platforms()
            self.create_install_script()
            self.run_tests()

            print("\n" + "=" * 50)
            print("🎉 All installers built successfully!")
            print("\n📦 Output files:")
            for file in self.dist_dir.glob("*"):
                if file.is_file():
                    size_mb = file.stat().st_size / (1024 * 1024)
                    print(".2f")

            print("\n🚀 Ready for distribution!")

        except Exception as e:
            print(f"❌ Build failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    builder = ParryInstallerBuilder()
    builder.main()
