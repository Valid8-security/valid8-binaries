#!/usr/bin/env python3
"""
Valid8 Binary Builder

Creates cross-platform executables for Valid8 scanner using PyInstaller.
Supports Windows, macOS, and Linux platforms.
"""

import os
import sys
import platform
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Optional

class BinaryBuilder:
    """Build cross-platform binaries for Valid8"""

    def __init__(self, source_dir: Path, output_dir: Path):
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def check_pyinstaller(self) -> bool:
        """Check if PyInstaller is installed"""
        try:
            import PyInstaller
            print("✅ PyInstaller found")
            return True
        except ImportError:
            print("❌ PyInstaller not found. Installing...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
                print("✅ PyInstaller installed")
                return True
            except subprocess.CalledProcessError:
                print("❌ Failed to install PyInstaller")
                return False

    def get_platform_info(self) -> Dict[str, str]:
        """Get current platform information"""
        system = platform.system().lower()
        machine = platform.machine().lower()

        # Normalize platform names
        if system == "darwin":
            system = "macos"
        elif system == "windows":
            system = "windows"
        else:
            system = "linux"

        # Normalize architecture
        if machine in ["x86_64", "amd64"]:
            arch = "x64"
        elif machine in ["arm64", "aarch64"]:
            arch = "arm64"
        else:
            arch = machine

        return {
            "system": system,
            "arch": arch,
            "full_name": f"{system}-{arch}"
        }

    def build_binary(self, platform_info: Dict[str, str]) -> Optional[Path]:
        """Build binary for the specified platform"""
        print(f"🏗️  Building Valid8 binary for {platform_info['full_name']}")

        # Build command for simple executable
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--clean",
            "--onefile",
            "--name", "valid8",
            "--distpath", str(self.output_dir),
            "--workpath", str(self.source_dir / "build"),
            "--hidden-import", "rich",
            "--hidden-import", "click",
            "--hidden-import", "valid8.scanner",
            "--hidden-import", "valid8.detectors",
            "--hidden-import", "valid8.license",
            "--hidden-import", "valid8.beta_token",
            "--exclude-module", "tkinter",
            "--exclude-module", "matplotlib",
            "valid8/cli.py"
        ]

        try:
            print(f"Running: {' '.join(cmd[:3])} ... (truncated)")
            result = subprocess.run(cmd, cwd=self.source_dir, capture_output=True, text=True)

            if result.returncode == 0:
                # Find the built binary
                binary_name = "valid8.exe" if platform_info["system"] == "windows" else "valid8"
                binary_path = self.output_dir / binary_name

                if binary_path.exists():
                    print(f"✅ Binary built successfully: {binary_path}")
                    return binary_path
                else:
                    print("❌ Binary not found in output directory")
                    print(f"Output directory contents: {list(self.output_dir.iterdir()) if self.output_dir.exists() else 'Directory does not exist'}")
                    return None
            else:
                print("❌ Build failed:")
                print("STDOUT:", result.stdout[-1000:])  # Last 1000 chars
                print("STDERR:", result.stderr[-1000:])
                return None

        except Exception as e:
            print(f"❌ Build error: {e}")
            return None

    def create_release_archive(self, binary_path: Path, platform_info: Dict[str, str]) -> Optional[Path]:
        """Create a release archive containing the binary"""
        archive_name = f"valid8-{platform_info['full_name']}.zip"
        archive_path = self.output_dir / archive_name

        try:
            # Create ZIP archive
            shutil.make_archive(
                str(archive_path.with_suffix('')),
                'zip',
                self.output_dir,
                binary_path.name
            )

            if archive_path.exists():
                print(f"✅ Release archive created: {archive_path}")
                return archive_path
            else:
                print("❌ Archive creation failed")
                return None

        except Exception as e:
            print(f"❌ Archive creation error: {e}")
            return None

def main():
    """Main entry point"""
    print("🔧 Valid8 Binary Builder")
    print("=" * 40)

    # Set up directories
    source_dir = Path(__file__).parent
    output_dir = source_dir / "dist" / "binaries"

    builder = BinaryBuilder(source_dir, output_dir)
    platform_info = builder.get_platform_info()
    
    print(f"📋 Current platform: {platform_info['full_name']}")

    if not builder.check_pyinstaller():
        sys.exit(1)

    # Build binary for current platform
    binary_path = builder.build_binary(platform_info)

    if binary_path:
        archive_path = builder.create_release_archive(binary_path, platform_info)
        if archive_path:
            print("
✅ Build completed successfully!"            print("📦 Generated archive:")
            print(f"   • {archive_path.name} ({archive_path.stat().st_size / (1024*1024):.1f} MB)")

            print(f"\n📂 Archive located in: {output_dir}")
            print("\n📋 Next steps:")
            print("   1. Test the binary on target platform")
            print("   2. Create GitHub release in Valid8-security/valid8-binaries")
            print("   3. Upload this archive as release asset")
            print("   4. Update download links in website")
        else:
            print("\n❌ Archive creation failed, but binary was built")
    else:
        print("\n❌ Build failed. Check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
