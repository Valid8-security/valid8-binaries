"""
Comprehensive License Management System

Features:
- Online license validation
- Hardware binding
- Feature gating
- Watermarking
- Tamper detection
- Offline grace period
"""

import hashlib
import json
import os
import platform
import socket
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
import sys

# Try to import requests, but don't fail if not available (for compiled version)
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class LicenseConfig:
    """Configuration for license system"""
    
    # Server configuration
    VALIDATION_SERVER = "https://api.valid8.dev/validate"
    SERVER_TIMEOUT = 10  # seconds
    
    # Cache configuration
    CACHE_DURATION = 3600  # 1 hour
    OFFLINE_GRACE_PERIOD = 7 * 24 * 3600  # 7 days
    
    # File paths
    LICENSE_FILE = Path.home() / '.parry' / 'license.json'
    CACHE_FILE = Path.home() / '.parry' / '.validation_cache'
    FINGERPRINT_FILE = Path.home() / '.parry' / '.machine_fingerprint'
    
    # Build information (set at build time)
    BUILD_ID = os.environ.get('PARRY_BUILD_ID', 'dev-build')
    VERSION = '0.6.0'
    
    # Feature definitions
    FREE_FEATURES = [
        'basic-scan',
        'fast-mode',
        'json-output',
        'html-output',
        'community-support',
        'scan-up-to-100-files',
        'standard-formats'
    ]
    
    # Beta tier has all Pro features unlocked
    BETA_FEATURES = [
        'deep-mode',
        'ai-detection',
        'ai-validation',
        'compliance-reports',
        'sca-scanning',
        'secrets-scanning',
        'email-support',
        'unlimited-files',
        'multi-language'
    ]
    
    PRO_FEATURES = BETA_FEATURES.copy()  # Same features as beta
    
    ENTERPRISE_FEATURES = [
        'rest-api',
        'priority-support',
        'custom-rules',
        'on-premise',
        'sso-integration',
        'audit-logs',
        'sla-guarantee',
        'advanced-compliance',
        'container-scanning',
        'iac-scanning'
    ]
    
    # Beta license configuration
    BETA_DURATION_DAYS = 60  # 60-day beta period (optimized for Winter Quarter revenue timeline)


class MachineFingerprint:
    """Generate and manage machine fingerprints for hardware binding"""
    
    @staticmethod
    def get() -> str:
        """Generate unique machine fingerprint"""
        # Try to load cached fingerprint
        if LicenseConfig.FINGERPRINT_FILE.exists():
            try:
                return LicenseConfig.FINGERPRINT_FILE.read_text().strip()
            except:
                pass
        
        # Generate new fingerprint
        fingerprint = MachineFingerprint._generate()
        
        # Cache it
        try:
            LicenseConfig.FINGERPRINT_FILE.parent.mkdir(parents=True, exist_ok=True)
            LicenseConfig.FINGERPRINT_FILE.write_text(fingerprint)
        except:
            pass
        
        return fingerprint
    
    @staticmethod
    def _generate() -> str:
        """Generate fingerprint from hardware components"""
        components = []
        
        # CPU information
        try:
            components.append(platform.processor() or "unknown-cpu")
            components.append(platform.machine())  # Architecture
        except:
            pass
        
        # Network MAC address
        try:
            mac = uuid.getnode()
            components.append(str(mac))
        except:
            pass
        
        # System information
        try:
            components.append(platform.system())  # OS
            components.append(platform.release())  # OS version
        except:
            pass
        
        # Hostname
        try:
            components.append(socket.gethostname())
        except:
            pass
        
        # Username
        try:
            components.append(os.getenv('USER') or os.getenv('USERNAME') or 'unknown-user')
        except:
            pass
        
        # Combine and hash
        combined = '|'.join(components)
        fingerprint = hashlib.sha256(combined.encode()).hexdigest()[:16]
        
        return f"PARRY-{fingerprint}"


class TamperDetector:
    """Detect if code is being tampered with or debugged"""
    
    @staticmethod
    def check_all() -> List[str]:
        """Run all tamper detection checks"""
        warnings = []
        
        # Check for debugger
        if TamperDetector._detect_debugger():
            warnings.append('debugger_detected')
        
        # Check for VM
        if TamperDetector._detect_vm():
            warnings.append('vm_detected')
        
        # Check for sandbox
        if TamperDetector._detect_sandbox():
            warnings.append('sandbox_detected')
        
        # Check for obfuscation/code modification
        if TamperDetector._check_binary_integrity():
            warnings.append('integrity_check_failed')
        
        return warnings
    
    @staticmethod
    def _detect_debugger() -> bool:
        """Detect if running under debugger"""
        # Python debugger check
        if sys.gettrace() is not None:
            return True
        
        # Attached debugger check (Unix)
        if os.path.exists('/proc/self/status'):
            try:
                with open('/proc/self/status', 'r') as f:
                    content = f.read()
                    # Check TracerPid field
                    for line in content.split('\n'):
                        if line.startswith('TracerPid:'):
                            pid = line.split()[1]
                            if pid != '0':
                                return True
            except:
                pass
        
        return False
    
    @staticmethod
    def _detect_vm() -> bool:
        """Detect if running in virtual machine"""
        # Check common VM indicators
        vm_indicators = [
            'VMware',
            'VirtualBox',
            'QEMU',
            'Parallels',
            'Hyper-V',
            'Xen'
        ]
        
        # Check system information
        try:
            system_info = platform.system().lower()
            if any(indicator.lower() in system_info for indicator in vm_indicators):
                return True
        except:
            pass
        
        # Check MAC address (virtual machines have specific prefixes)
        try:
            mac = uuid.getnode()
            mac_str = ':'.join([f'{(mac >> elements) & 0xff:02x}' 
                               for elements in range(40, -1, -8)])
            vm_mac_prefixes = ['00:05:69', '00:0c:29', '00:1c:14',  # VMware
                              '08:00:27',  # VirtualBox
                              '52:54:00']  # QEMU
            if any(mac_str.startswith(prefix) for prefix in vm_mac_prefixes):
                return True
        except:
            pass
        
        return False
    
    @staticmethod
    def _detect_sandbox() -> bool:
        """Detect if running in sandbox/environment"""
        # Check for sandbox indicators
        sandbox_paths = [
            '/home/sandbox',
            '/tmp/sandbox',
            '/sandbox'
        ]
        
        for path in sandbox_paths:
            if os.path.exists(path):
                return True
        
        return False
    
    @staticmethod
    def _check_binary_integrity() -> bool:
        """Check if binary has been modified"""
        # Basic check: ensure we're running from expected location
        # In compiled version, this would check .so file hash
        
        # For now, just check if running from development (not a concern)
        if LicenseConfig.BUILD_ID == 'dev-build':
            return False
        
        # In production build, could check embedded hash
        # This is a placeholder for actual integrity check
        
        return False


class OnlineValidator:
    """Validate licenses with online server"""
    
    @staticmethod
    def validate(license_key: str, machine_id: str) -> Dict[str, Any]:
        """
        Validate license with server
        
        Returns:
            dict with 'valid', 'tier', 'features', 'error' keys
        """
        if not HAS_REQUESTS:
            return {
                'valid': False,
                'error': 'Network support not available',
                'offline_allowed': True
            }
        
        try:
            # Prepare validation request
            request_data = {
                'license_key': license_key,
                'machine_id': machine_id,
                'build_id': LicenseConfig.BUILD_ID,
                'version': LicenseConfig.VERSION
            }
            
            # Call validation server
            response = requests.post(
                LicenseConfig.VALIDATION_SERVER,
                json=request_data,
                timeout=LicenseConfig.SERVER_TIMEOUT,
                headers={'User-Agent': f'Parry/{LicenseConfig.VERSION}'}
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'valid': result.get('valid', False),
                    'tier': result.get('tier', 'free'),
                    'features': result.get('features', []),
                    'expires': result.get('expires'),
                    'error': None
                }
            else:
                return {
                    'valid': False,
                    'error': f'Server error: {response.status_code}',
                    'offline_allowed': True
                }
                
        except requests.exceptions.Timeout:
            return {
                'valid': False,
                'error': 'Connection timeout',
                'offline_allowed': True
            }
        except requests.exceptions.ConnectionError:
            return {
                'valid': False,
                'error': 'Cannot reach server',
                'offline_allowed': True
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e),
                'offline_allowed': True
            }


class ValidationCache:
    """Cache validation results to reduce server calls"""
    
    @staticmethod
    def get() -> Optional[Dict[str, Any]]:
        """Get cached validation result"""
        if not LicenseConfig.CACHE_FILE.exists():
            return None
        
        try:
            data = json.loads(LicenseConfig.CACHE_FILE.read_text())
            # Check if cache is still valid (1 hour)
            timestamp = data.get('timestamp', 0)
            if time.time() - timestamp < LicenseConfig.CACHE_DURATION:
                return data
        except:
            pass
        
        return None
    
    @staticmethod
    def set(validation_result: Dict[str, Any]):
        """Cache validation result"""
        try:
            data = {
                **validation_result,
                'timestamp': int(time.time())
            }
            LicenseConfig.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            LicenseConfig.CACHE_FILE.write_text(json.dumps(data))
        except:
            pass
    
    @staticmethod
    def clear():
        """Clear cache"""
        try:
            if LicenseConfig.CACHE_FILE.exists():
                LicenseConfig.CACHE_FILE.unlink()
        except:
            pass
    
    @staticmethod
    def is_offline_period_valid() -> bool:
        """Check if offline grace period is still valid"""
        if not LicenseConfig.CACHE_FILE.exists():
            return False
        
        try:
            data = json.loads(LicenseConfig.CACHE_FILE.read_text())
            timestamp = data.get('timestamp', 0)
            # Allow 7 days offline
            return time.time() - timestamp < LicenseConfig.OFFLINE_GRACE_PERIOD
        except:
            return False


class LicenseManager:
    """Main license management interface"""
    
    @staticmethod
    def get_tier() -> str:
        """Get current license tier"""
        if not LicenseConfig.LICENSE_FILE.exists():
            return 'free'
        
        try:
            with open(LicenseConfig.LICENSE_FILE, 'r') as f:
                data = json.load(f)
            tier = data.get('tier', 'free')
            
            # Check if beta license has expired
            if tier == 'beta':
                expires_str = data.get('expires')
                if expires_str:
                    try:
                        from datetime import datetime
                        expires = datetime.fromisoformat(expires_str)
                        if datetime.now() > expires:
                            # Beta expired, show message but allow
                            print("[yellow]⚠️  Beta license expired. Continuing anyway.[/yellow]")
                            print("[dim]Visit https://valid8.dev to get Pro or continue with Free tier[/dim]")
                            # Return 'beta' anyway to be lenient
                            return 'beta'
                    except:
                        pass
            
            return tier
        except:
            return 'free'
    
    @staticmethod
    def has_feature(feature: str) -> bool:
        """
        Check if current license includes feature
        
        This is the main function to gate premium features.
        """
        # Check if tampering detected (log but don't block)
        tamper_warnings = TamperDetector.check_all()
        if tamper_warnings:
            # Log for analytics, but allow operation
            LicenseManager._log_event('tamper_detected', {
                'warnings': tamper_warnings,
                'build_id': LicenseConfig.BUILD_ID
            })
        
        # Get tier
        tier = LicenseManager.get_tier()
        
        # Free tier features
        if tier == 'free':
            return feature in LicenseConfig.FREE_FEATURES
        
        # Beta tier features (same as Pro, lenient enforcement)
        if tier == 'beta':
            return feature in LicenseConfig.BETA_FEATURES or feature in LicenseConfig.FREE_FEATURES
        
        # Premium features require validation
        if tier in ['pro', 'enterprise']:
            # Check cached validation
            cached = ValidationCache.get()
            if cached and cached.get('valid'):
                features = cached.get('features', [])
                return feature in features or LicenseManager._has_tier_feature(feature, tier)
            
            # Validate online
            if LicenseManager._validate_license():
                cached = ValidationCache.get()
                if cached and cached.get('valid'):
                    features = cached.get('features', [])
                    return feature in features or LicenseManager._has_tier_feature(feature, tier)
            
            # Check offline grace period
            if ValidationCache.is_offline_period_valid():
                cached = ValidationCache.get()
                if cached:
                    features = cached.get('features', [])
                    return feature in features or LicenseManager._has_tier_feature(feature, tier)
            
            return False
        
        return False
    
    @staticmethod
    def _validate_license() -> bool:
        """Validate license with server"""
        if not LicenseConfig.LICENSE_FILE.exists():
            return False
        
        try:
            with open(LicenseConfig.LICENSE_FILE, 'r') as f:
                license_data = json.load(f)
            
            license_key = license_data.get('key')
            if not license_key:
                return False
            
            machine_id = MachineFingerprint.get()
            result = OnlineValidator.validate(license_key, machine_id)
            
            # Cache result
            ValidationCache.set(result)
            
            return result.get('valid', False)
            
        except Exception:
            return False
    
    @staticmethod
    def _has_tier_feature(feature: str, tier: str) -> bool:
        """Check if feature is included in tier"""
        if tier == 'pro':
            return feature in LicenseConfig.PRO_FEATURES
        elif tier == 'enterprise':
            return feature in (LicenseConfig.PRO_FEATURES + LicenseConfig.ENTERPRISE_FEATURES)
        return False
    
    @staticmethod
    def get_features() -> List[str]:
        """Get list of available features"""
        tier = LicenseManager.get_tier()
        
        if tier == 'free':
            return LicenseConfig.FREE_FEATURES.copy()
        elif tier == 'beta':
            return LicenseConfig.BETA_FEATURES.copy()
        elif tier == 'pro':
            return LicenseConfig.PRO_FEATURES.copy()
        elif tier == 'enterprise':
            return (LicenseConfig.PRO_FEATURES + LicenseConfig.ENTERPRISE_FEATURES).copy()
        
        return []
    
    @staticmethod
    def get_license_info() -> Dict[str, Any]:
        """Get comprehensive license information"""
        tier = LicenseManager.get_tier()
        
        info = {
            'tier': tier,
            'features': LicenseManager.get_features(),
            'build_id': LicenseConfig.BUILD_ID,
            'machine_id': MachineFingerprint.get(),
            'validation_cached': ValidationCache.get() is not None
        }
        
        # Add cached validation info if available
        cached = ValidationCache.get()
        if cached:
            info['validation'] = cached
        
        return info
    
    @staticmethod
    def install_license(license_key: str, tier: str) -> bool:
        """
        Install a license key
        
        Args:
            license_key: License key string
            tier: License tier (beta/pro/enterprise)
        
        Returns:
            True if installation successful
        """
        try:
            # For beta licenses, no online validation needed
            if tier == 'beta':
                from datetime import datetime, timedelta
                license_data = {
                    'key': license_key,
                    'tier': 'beta',
                    'installed_at': datetime.now().isoformat(),
                    'expires': (datetime.now() + timedelta(days=LicenseConfig.BETA_DURATION_DAYS)).isoformat(),
                    'machine_id': MachineFingerprint.get(),
                    'hardware_bound': False
                }
            else:
                # For pro/enterprise, validate first
                machine_id = MachineFingerprint.get()
                result = OnlineValidator.validate(license_key, machine_id)
                
                if not result.get('valid'):
                    return False
                
                # Install license
                license_data = {
                    'key': license_key,
                    'tier': tier,
                    'installed_at': int(time.time()),
                    'machine_id': machine_id
                }
            
            LicenseConfig.LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
            LicenseConfig.LICENSE_FILE.write_text(json.dumps(license_data, indent=2))
            
            # Cache validation result (skip for beta)
            if tier != 'beta':
                ValidationCache.set(result)
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def install_beta_license(email: str, token: Optional[str] = None) -> bool:
        """
        Install a beta license (DEPRECATED: use install_beta_license_with_token instead)
        
        For backward compatibility, if no token provided, creates local-only license.
        This method is insecure and should not be used for production.
        
        Args:
            email: User email for identification
            token: Optional beta token (for secure installation)
        
        Returns:
            True if installation successful
        """
        # If token provided, use secure installation
        if token:
            return LicenseManager.install_beta_license_with_token(token)
        
        # Otherwise, use insecure local method (deprecated)
        try:
            from datetime import datetime, timedelta
            
            license_data = {
                'type': 'BETA',
                'email': email,
                'tier': 'beta',
                'issued': datetime.now().isoformat(),
                'expires': (datetime.now() + timedelta(days=LicenseConfig.BETA_DURATION_DAYS)).isoformat(),
                'features': LicenseConfig.BETA_FEATURES,
                'machine_id': MachineFingerprint.get(),
                'hardware_bound': False,
                'version': LicenseConfig.VERSION,
                'insecure': True  # Mark as insecure
            }
            
            LicenseConfig.LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
            LicenseConfig.LICENSE_FILE.write_text(json.dumps(license_data, indent=2))
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def install_beta_license_with_token(token: str) -> bool:
        """
        Install a beta license using a secure token.
        
        Args:
            token: Signed beta token from admin
        
        Returns:
            True if installation successful
        """
        try:
            from valid8.beta_token import BetaTokenManager
            
            # Get machine ID
            machine_id = MachineFingerprint.get()
            
            # Validate token
            valid, payload, error = BetaTokenManager.validate_token(token, machine_id)
            
            if not valid:
                # Log error but don't expose details
                LicenseManager._log_event('beta_install_failed', {'error': error})
                return False
            
            # Record installation
            BetaTokenManager._record_installation(token, machine_id, payload['email'])
            
            # Create license data
            license_data = {
                'type': 'BETA',
                'email': payload['email'],
                'tier': 'beta',
                'issued': payload['issued'],
                'expires': payload['expires'],
                'features': LicenseConfig.BETA_FEATURES,
                'machine_id': machine_id,
                'hardware_bound': False,
                'version': LicenseConfig.VERSION,
                'secure': True  # Mark as secure token-based
            }
            
            LicenseConfig.LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
            LicenseConfig.LICENSE_FILE.write_text(json.dumps(license_data, indent=2))
            
            # Log successful installation
            LicenseManager._log_event('beta_installed', {'email': payload['email']})
            
            return True
            
        except ImportError:
            # Fall back if beta_token not available
            return False
        except Exception:
            return False
    
    @staticmethod
    def revoke_license():
        """Revoke current license"""
        try:
            if LicenseConfig.LICENSE_FILE.exists():
                LicenseConfig.LICENSE_FILE.unlink()
            ValidationCache.clear()
        except:
            pass
    
    @staticmethod
    def _log_event(event_name: str, data: Dict[str, Any]):
        """Log security events for analytics"""
        # In production, send to analytics server
        # For now, just print to console in debug mode
        if os.environ.get('PARRY_DEBUG'):
            print(f"[License Event] {event_name}: {data}")


# Convenience functions for use throughout codebase
def has_feature(feature: str) -> bool:
    """Check if feature is available"""
    return LicenseManager.has_feature(feature)


def get_tier() -> str:
    """Get current license tier"""
    return LicenseManager.get_tier()


def require_feature(feature: str):
    """
    Decorator to gate features by license
    
    Usage:
        @require_feature('deep-mode')
        def ai_detection():
            # Only runs if deep-mode feature is available
            pass
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            if not LicenseManager.has_feature(feature):
                tier = LicenseManager.get_tier()
                raise PermissionError(
                    f"Feature '{feature}' requires Pro or Enterprise license. "
                    f"Current tier: {tier}.\n"
                    f"Visit https://valid8.dev/pricing to upgrade."
                )
            return func(*args, **kwargs)
        
        # Preserve function metadata
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        
        return wrapper
    
    return decorator


# Watermarking utility
def get_build_id() -> str:
    """Get unique build ID for watermarking"""
    return LicenseConfig.BUILD_ID


def get_machine_id() -> str:
    """Get machine fingerprint"""
    return MachineFingerprint.get()

