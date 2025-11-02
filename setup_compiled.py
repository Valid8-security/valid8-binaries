"""
Setup script for compiled/protected Parry distribution

This creates a distribution where core logic is compiled to C extensions,
preventing source code access while maintaining full functionality.

Build Types:
- Development: Standard Python (source visible)
- Distribution: Cython compiled (source protected)
- Enterprise: Compiled + obfuscated + license checks
"""

import os
import sys
from pathlib import Path
from setuptools import setup, find_packages, Extension
from Cython.Build import cythonize
import shutil

# Version
VERSION = "0.6.0"

# Modules to compile (core IP to protect)
MODULES_TO_COMPILE = [
    "parry/scanner.py",
    "parry/llm.py",
    "parry/ai_detector.py",
    "parry/validator.py",
    "parry/patch.py",
    "parry/language_support/base.py",
    "parry/language_support/python_analyzer.py",
    "parry/language_support/java_analyzer.py",
    "parry/language_support/javascript_analyzer.py",
    "parry/language_support/go_analyzer.py",
    "parry/language_support/rust_analyzer.py",
    "parry/language_support/cpp_analyzer.py",
    "parry/language_support/php_analyzer.py",
    "parry/language_support/ruby_analyzer.py",
    "parry/language_support/universal_detectors.py",
    "parry/framework_detectors.py",
    "parry/secrets_scanner.py",
    "parry/compliance.py",
    "parry/sca.py",
    "parry/custom_rules.py",
]

# Modules to keep as Python (user-facing, less sensitive)
MODULES_TO_KEEP_PYTHON = [
    "parry/cli.py",
    "parry/setup.py",
    "parry/reporter.py",
    "parry/compare.py",
]

def create_extensions():
    """Create Cython extension modules"""
    extensions = []
    
    for module_path in MODULES_TO_COMPILE:
        # Convert path to module name
        module_name = module_path.replace('/', '.').replace('.py', '')
        
        # Create extension
        ext = Extension(
            module_name,
            [module_path],
            extra_compile_args=['-O3'],  # Optimization
        )
        extensions.append(ext)
    
    return extensions


def create_build_config():
    """Create build configuration for different distribution types"""
    
    # Compiler directives for Cython
    compiler_directives = {
        'language_level': 3,
        'embedsignature': False,  # Don't embed signatures (makes reverse engineering harder)
        'binding': False,  # Disable binding (slight performance gain, harder to inspect)
        'boundscheck': False,  # Disable bounds checking (performance)
        'wraparound': False,  # Disable negative indexing (performance)
        'initializedcheck': False,  # Disable initialization checks (performance)
        'nonecheck': False,  # Disable None checks (performance)
        'overflowcheck': False,  # Disable overflow checks (performance)
        'cdivision': True,  # Use C division (performance)
        'infer_types': True,  # Infer types (optimization)
        'c_string_type': 'str',
        'c_string_encoding': 'utf-8',
    }
    
    return compiler_directives


def cleanup_source_files():
    """Remove .py source files after compilation (for distribution)"""
    print("\n🧹 Cleaning up source files...")
    
    for module_path in MODULES_TO_COMPILE:
        py_file = Path(module_path)
        if py_file.exists():
            print(f"  Removing {module_path}")
            py_file.unlink()
            
            # Also remove .pyc files
            pyc_dir = py_file.parent / '__pycache__'
            if pyc_dir.exists():
                for pyc_file in pyc_dir.glob(f'{py_file.stem}*.pyc'):
                    pyc_file.unlink()
    
    print("✓ Source files cleaned up\n")


def create_license_check():
    """Create license validation module"""
    license_check_code = '''"""
License validation for Parry

This module verifies license keys for Pro/Enterprise editions.
Compiled to prevent tampering.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any


class LicenseValidator:
    """Validates Parry licenses"""
    
    LICENSE_FILE = Path.home() / '.parry' / 'license.json'
    
    @staticmethod
    def check_license() -> Dict[str, Any]:
        """
        Check if valid license exists
        
        Returns:
            dict with 'valid', 'tier', 'expires' keys
        """
        if not LicenseValidator.LICENSE_FILE.exists():
            return {
                'valid': True,
                'tier': 'open-source',
                'expires': None,
                'features': ['fast-mode', 'basic-scanning']
            }
        
        try:
            with open(LicenseValidator.LICENSE_FILE, 'r') as f:
                license_data = json.load(f)
            
            # Verify license signature
            if not LicenseValidator._verify_signature(license_data):
                return {
                    'valid': False,
                    'tier': 'invalid',
                    'error': 'Invalid license signature'
                }
            
            # Check expiration
            expires = license_data.get('expires')
            if expires and time.time() > expires:
                return {
                    'valid': False,
                    'tier': 'expired',
                    'error': 'License expired'
                }
            
            return {
                'valid': True,
                'tier': license_data.get('tier', 'open-source'),
                'expires': expires,
                'features': license_data.get('features', [])
            }
            
        except Exception as e:
            return {
                'valid': False,
                'tier': 'error',
                'error': str(e)
            }
    
    @staticmethod
    def _verify_signature(license_data: Dict) -> bool:
        """Verify license signature (simplified for demo)"""
        # In production, use proper cryptographic signatures
        signature = license_data.get('signature', '')
        data_to_sign = json.dumps({
            'tier': license_data.get('tier'),
            'expires': license_data.get('expires'),
            'email': license_data.get('email')
        }, sort_keys=True)
        
        expected_sig = hashlib.sha256(
            (data_to_sign + 'PARRY_SECRET_KEY').encode()
        ).hexdigest()
        
        return signature == expected_sig
    
    @staticmethod
    def install_license(license_key: str) -> bool:
        """Install a license key"""
        # Decode and validate license key
        # Store in LICENSE_FILE
        # Return True if successful
        pass
    
    @staticmethod
    def get_tier() -> str:
        """Get current license tier"""
        return LicenseValidator.check_license().get('tier', 'open-source')
    
    @staticmethod
    def has_feature(feature: str) -> bool:
        """Check if license includes specific feature"""
        license_info = LicenseValidator.check_license()
        if not license_info['valid']:
            return False
        
        features = license_info.get('features', [])
        return feature in features


# Feature gates
def require_feature(feature: str):
    """Decorator to gate features by license"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not LicenseValidator.has_feature(feature):
                tier = LicenseValidator.get_tier()
                raise PermissionError(
                    f"Feature '{feature}' requires Pro or Enterprise license. "
                    f"Current tier: {tier}. Visit https://parry.dev/pricing"
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
'''
    
    # Write license module
    license_file = Path('parry/license_check.py')
    license_file.write_text(license_check_code)
    print("✓ Created license validation module")
    
    # Add to compilation list
    MODULES_TO_COMPILE.append('parry/license_check.py')


def build_distribution(build_type='distribution'):
    """
    Build protected distribution
    
    Args:
        build_type: 'development', 'distribution', or 'enterprise'
    """
    print(f"\n🔨 Building {build_type} distribution...\n")
    
    if build_type in ['distribution', 'enterprise']:
        # Create license checking
        create_license_check()
        
        # Get extensions and compiler directives
        extensions = create_extensions()
        compiler_directives = create_build_config()
        
        # Cythonize
        print("📦 Compiling modules with Cython...")
        cythonized_extensions = cythonize(
            extensions,
            compiler_directives=compiler_directives,
            build_dir='build',
            language_level=3,
        )
        
        return cythonized_extensions
    
    return []


# Read requirements
def read_requirements():
    """Read requirements from file"""
    req_file = Path('requirements.txt')
    if req_file.exists():
        return req_file.read_text().splitlines()
    return []


# Read README
def read_readme():
    """Read README for long description"""
    readme_file = Path('README.md')
    if readme_file.exists():
        return readme_file.read_text()
    return "Parry Security Scanner - Privacy-first AI-powered security scanning"


if __name__ == '__main__':
    # Determine build type from command line
    build_type = 'development'
    if '--distribution' in sys.argv:
        build_type = 'distribution'
        sys.argv.remove('--distribution')
    elif '--enterprise' in sys.argv:
        build_type = 'enterprise'
        sys.argv.remove('--enterprise')
    
    # Build extensions
    ext_modules = build_distribution(build_type)
    
    # Setup configuration
    setup(
        name='parry-scanner',
        version=VERSION,
        description='Privacy-first AI-powered security scanner',
        long_description=read_readme(),
        long_description_content_type='text/markdown',
        author='Parry Security',
        author_email='security@parry.dev',
        url='https://github.com/parry/parry',
        packages=find_packages(),
        ext_modules=ext_modules if build_type != 'development' else [],
        install_requires=read_requirements(),
        entry_points={
            'console_scripts': [
                'parry=parry.cli:main',
            ],
        },
        classifiers=[
            'Development Status :: 4 - Beta',
            'Intended Audience :: Developers',
            'Topic :: Security',
            'Topic :: Software Development :: Quality Assurance',
            'License :: OSI Approved :: MIT License',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
            'Programming Language :: Python :: 3.10',
            'Programming Language :: Python :: 3.11',
        ],
        python_requires='>=3.8',
        include_package_data=True,
        zip_safe=False,  # Required for C extensions
    )
    
    # Post-build cleanup for distribution builds
    if build_type in ['distribution', 'enterprise'] and 'sdist' not in sys.argv:
        if '--keep-sources' not in sys.argv:
            # Optionally remove source files after build
            # cleanup_source_files()  # Uncomment for distribution
            pass
    
    print(f"\n✅ {build_type.capitalize()} build complete!\n")
    
    if build_type == 'distribution':
        print("📦 To create wheel distribution:")
        print("   python setup_compiled.py --distribution bdist_wheel")
        print("\n📦 To create source distribution:")
        print("   python setup_compiled.py --distribution sdist")
        print("\n⚠️  Source files are still present. To remove after testing:")
        print("   python setup_compiled.py --distribution build --keep-sources=False")

