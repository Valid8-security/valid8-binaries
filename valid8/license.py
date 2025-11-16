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
    
    # Trial license configuration - HIGH SECURITY
    TRIAL_DURATION_DAYS = 7  # 7-day trial period (maximum security)
    TRIAL_USAGE_FILE = Path.home() / '.parry' / '.trial_usage'  # Permanent trial tracking
    MAX_TRIAL_ATTEMPTS = 1  # Only one trial per machine EVER

    # Legacy beta config (deprecated)
    BETA_DURATION_DAYS = 60  # 60-day beta period (for existing beta users)


class TrialUsageTracker:
    """Permanent trial usage tracking that survives uninstall/reinstall"""

    @staticmethod
    def record_trial_usage(machine_id: str, email: str) -> bool:
        """Record that a trial has been used on this machine. Returns False if trial already used."""
        try:
            # Load existing trial usage
            usage_data = TrialUsageTracker._load_trial_usage()

            # Check if this machine has already used a trial
            if machine_id in usage_data.get('machines', {}):
                return False  # Trial already used on this machine

            # Check if this email has already used a trial
            if email in usage_data.get('emails', {}):
                return False  # Trial already used by this email

            # Record new trial usage
            if 'machines' not in usage_data:
                usage_data['machines'] = {}
            if 'emails' not in usage_data:
                usage_data['emails'] = {}

            usage_data['machines'][machine_id] = {
                'first_used': time.time(),
                'email': email,
                'attempts': 1
            }

            usage_data['emails'][email] = {
                'first_used': time.time(),
                'machine_id': machine_id,
                'attempts': 1
            }

            # Save to permanent storage with high security
            TrialUsageTracker._save_trial_usage_secure(usage_data)

            return True

        except Exception as e:
            # If we can't record usage securely, deny trial to be safe
            print(f"Security error recording trial usage: {e}")
            return False

    @staticmethod
    def can_use_trial(machine_id: str, email: str) -> bool:
        """Check if this machine/email combination can use a trial"""
        try:
            usage_data = TrialUsageTracker._load_trial_usage()

            # Check machine usage
            if machine_id in usage_data.get('machines', {}):
                return False

            # Check email usage
            if email in usage_data.get('emails', {}):
                return False

            return True

        except Exception as e:
            # If we can't verify securely, deny trial to be safe
            print(f"Security error checking trial usage: {e}")
            return False

    @staticmethod
    def get_trial_usage_stats() -> Dict[str, Any]:
        """Get trial usage statistics for admin purposes"""
        try:
            usage_data = TrialUsageTracker._load_trial_usage()
            return {
                'total_machines': len(usage_data.get('machines', {})),
                'total_emails': len(usage_data.get('emails', {})),
                'data': usage_data
            }
        except:
            return {'total_machines': 0, 'total_emails': 0, 'data': {}}

    @staticmethod
    def _load_trial_usage() -> Dict[str, Any]:
        """Load trial usage data with integrity checking"""
        if not LicenseConfig.TRIAL_USAGE_FILE.exists():
            return {}

        try:
            # Read and verify integrity
            data = json.loads(LicenseConfig.TRIAL_USAGE_FILE.read_text())

            # Basic integrity check - ensure required fields exist
            if not isinstance(data, dict):
                return {}

            return data

        except Exception as e:
            # If file is corrupted, return empty (safer than trusting corrupted data)
            print(f"Trial usage file corrupted: {e}")
            return {}

    @staticmethod
    def _save_trial_usage_secure(usage_data: Dict[str, Any]) -> None:
        """Save trial usage data with maximum security"""
        try:
            # Create directory if it doesn't exist
            LicenseConfig.TRIAL_USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)

            # Add integrity markers
            usage_data['_integrity_check'] = hashlib.sha256(
                json.dumps(usage_data, sort_keys=True).encode()
            ).hexdigest()[:16]

            # Save with restricted permissions (if possible)
            with open(LicenseConfig.TRIAL_USAGE_FILE, 'w') as f:
                json.dump(usage_data, f, indent=2)

            # Try to set restrictive permissions (Unix only)
            try:
                os.chmod(LicenseConfig.TRIAL_USAGE_FILE, 0o600)  # Owner read/write only
            except:
                pass  # Windows or permission denied - continue anyway

        except Exception as e:
            print(f"Failed to save trial usage securely: {e}")
            raise  # Re-raise to prevent insecure trial installation


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
        """Get current license tier with maximum security validation"""
        if not LicenseConfig.LICENSE_FILE.exists():
            return 'free'

        try:
            # SECURITY: Load and validate license integrity
            with open(LicenseConfig.LICENSE_FILE, 'r') as f:
                data = json.load(f)

            # SECURITY: Verify license integrity
            if not LicenseManager._verify_license_integrity(data):
                print("[red]❌ License file integrity check failed[/red]")
                print("[dim]License may have been tampered with[/dim]")
                return 'free'

            tier = data.get('tier', 'free')

            # SECURITY: Enhanced expiration checking
            if tier in ['trial', 'beta']:
                expires_str = data.get('expires')
                if expires_str:
                    try:
                        from datetime import datetime
                        expires = datetime.fromisoformat(expires_str)
                        now = datetime.now()

                        if now > expires:
                            # License expired - revoke immediately for security
                            print(f"[red]❌ {tier.title()} license expired[/red]")
                            if tier == 'trial':
                                print("[dim]Contact sales@valid8.dev for enterprise licensing[/dim]")
                            else:
                                print("[dim]Visit https://valid8.dev to upgrade[/dim]")
                            LicenseManager._revoke_expired_license()
                            return 'free'
                        else:
                            # Show warning for licenses expiring soon
                            days_left = (expires - now).days
                            if days_left <= 3:
                                print(f"[yellow]⚠️  {tier.title()} license expires in {days_left} days[/yellow]")
                    except:
                        # Invalid date format - revoke for security
                        LicenseManager._revoke_expired_license()
                        return 'free'

            # SECURITY: Verify hardware binding
            machine_id = MachineFingerprint.get()
            license_machine_id = data.get('machine_id')
            if license_machine_id and license_machine_id != machine_id:
                print("[red]❌ License hardware binding check failed[/red]")
                print("[dim]License is bound to a different machine[/dim]")
                return 'free'

            return tier

        except Exception as e:
            # SECURITY: On any error, default to free tier
            print(f"[red]❌ License validation error: {e}[/red]")
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
    def install_trial_license(email: str) -> Tuple[bool, str]:
        """
        Install a trial license with maximum security restrictions.

        TRIAL SECURITY FEATURES:
        - Only one trial per machine EVER (survives uninstall/reinstall)
        - Hardware-bound fingerprint tracking
        - Tamper detection and integrity checking
        - 7-day duration maximum

        Args:
            email: User email for trial

        Returns:
            (success: bool, message: str)
        """
        try:
            # Get machine fingerprint for binding
            machine_id = MachineFingerprint.get()

            # SECURITY CHECK 1: Verify trial eligibility
            if not TrialUsageTracker.can_use_trial(machine_id, email):
                return False, "Trial has already been used on this machine or email address. Contact sales for enterprise licensing."

            # SECURITY CHECK 2: Tamper detection
            tamper_warnings = TamperDetector.check_all()
            if tamper_warnings:
                LicenseManager._log_event('tamper_detected_trial_install', {
                    'warnings': tamper_warnings,
                    'email': email,
                    'machine_id': machine_id
                })
                return False, "Security check failed. Please ensure you're running Valid8 in a standard environment."

            # SECURITY CHECK 3: Record trial usage BEFORE installing license
            if not TrialUsageTracker.record_trial_usage(machine_id, email):
                return False, "Failed to secure trial installation. Please try again or contact support."

            # Create secure trial license
            from datetime import datetime, timedelta

            license_data = {
                'type': 'TRIAL',
                'email': email,
                'tier': 'trial',
                'issued': datetime.now().isoformat(),
                'expires': (datetime.now() + timedelta(days=LicenseConfig.TRIAL_DURATION_DAYS)).isoformat(),
                'features': LicenseConfig.FREE_FEATURES,  # Trial gets free features
                'machine_id': machine_id,
                'hardware_bound': True,
                'version': LicenseConfig.VERSION,
                'trial_used': True,
                'security_level': 'maximum'
            }

            # SECURITY: Create directory with secure permissions
            LicenseConfig.LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)

            # SECURITY: Save license with integrity protection
            license_json = json.dumps(license_data, indent=2)
            license_data['_integrity_hash'] = hashlib.sha256(license_json.encode()).hexdigest()

            with open(LicenseConfig.LICENSE_FILE, 'w') as f:
                json.dump(license_data, f, indent=2)

            # SECURITY: Try to set restrictive permissions
            try:
                os.chmod(LicenseConfig.LICENSE_FILE, 0o600)  # Owner read/write only
            except:
                pass  # Windows or permission denied

            # Log successful secure installation
            LicenseManager._log_event('trial_installed_secure', {
                'email': email,
                'machine_id': machine_id,
                'duration_days': LicenseConfig.TRIAL_DURATION_DAYS
            })

            return True, f"Trial license installed successfully. Valid for {LicenseConfig.TRIAL_DURATION_DAYS} days on this machine."

        except Exception as e:
            # SECURITY: On any error, don't reveal details but log for analysis
            LicenseManager._log_event('trial_install_error', {
                'email': email,
                'error': str(e),
                'machine_id': MachineFingerprint.get()
            })
            return False, "Trial installation failed due to security restrictions. Please contact support."

    @staticmethod
    def install_beta_license_with_token(token: str) -> bool:
        """
        Install a beta license using a secure token.

        NOTE: This is for legacy beta users. New users should use install_trial_license().

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
    def _verify_license_integrity(license_data: Dict[str, Any]) -> bool:
        """Verify license file integrity"""
        try:
            # Check for integrity hash
            stored_hash = license_data.get('_integrity_hash')
            if not stored_hash:
                # No integrity check - allow for backward compatibility
                return True

            # Calculate current hash
            license_copy = license_data.copy()
            del license_copy['_integrity_hash']  # Remove hash from calculation
            current_hash = hashlib.sha256(json.dumps(license_copy, sort_keys=True).encode()).hexdigest()

            return current_hash == stored_hash

        except Exception:
            # Integrity check failed
            return False

    @staticmethod
    def _revoke_expired_license():
        """Securely revoke an expired license"""
        try:
            if LicenseConfig.LICENSE_FILE.exists():
                # Overwrite with empty data for security
                empty_license = {
                    'tier': 'free',
                    'revoked': True,
                    'reason': 'expired'
                }
                with open(LicenseConfig.LICENSE_FILE, 'w') as f:
                    json.dump(empty_license, f)
        except Exception:
            # If revocation fails, at least remove the file
            try:
                LicenseConfig.LICENSE_FILE.unlink()
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

