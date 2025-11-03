"""
Secure Beta Token Management System

Implements token-based beta licensing with:
- Cryptographic signatures
- Usage limit enforcement
- Expiration checks
- Admin-controlled issuance
"""

import os
import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, Tuple


class BetaTokenConfig:
    """Configuration for beta tokens"""
    
    # Token expiration
    DEFAULT_BETA_DURATION_DAYS = 60  # 60-day beta period (optimized for revenue timeline)
    
    # Usage limits
    MAX_INSTALLATIONS_PER_TOKEN = 1
    MAX_BETA_LICENSES_PER_EMAIL = 1
    
    # Admin secret (should be stored securely in production)
    ADMIN_SECRET = os.environ.get('PARRY_ADMIN_SECRET', 'dev-secret-change-in-production')
    
    # Token storage
    TOKEN_FILE = Path.home() / '.parry' / 'beta_tokens.json'
    INSTALLATIONS_FILE = Path.home() / '.parry' / 'beta_installations.json'


class BetaTokenManager:
    """Manage beta token generation and validation"""
    
    @staticmethod
    def generate_token(
        email: str,
        days: int = BetaTokenConfig.DEFAULT_BETA_DURATION_DAYS,
        max_installations: int = BetaTokenConfig.MAX_INSTALLATIONS_PER_TOKEN,
        issued_by: str = 'admin'
    ) -> str:
        """
        Generate a signed beta token.
        
        Args:
            email: User email
            days: License duration in days
            max_installations: Maximum installations allowed
            issued_by: Admin identifier
        
        Returns:
            Signed token string
        
        Token Format:
            base64(payload) + '.' + signature
        """
        # Create token payload
        payload = {
            'email': email,
            'issued': datetime.now().isoformat(),
            'expires': (datetime.now() + timedelta(days=days)).isoformat(),
            'max_installations': max_installations,
            'issued_by': issued_by,
            'version': '0.7.0',
            'salt': os.urandom(16).hex()  # Prevent token reuse
        }
        
        # Encode payload
        payload_json = json.dumps(payload, sort_keys=True)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()
        
        # Generate signature
        signature = BetaTokenManager._sign(payload_b64)
        
        # Return token
        token = f"{payload_b64}.{signature}"
        
        # Store token for tracking
        BetaTokenManager._store_token(email, token, payload)
        
        return token
    
    @staticmethod
    def validate_token(token: str, machine_id: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validate a beta token.
        
        Args:
            token: Token string
            machine_id: Machine fingerprint
        
        Returns:
            (is_valid, payload_dict, error_message)
        """
        try:
            # Parse token
            if '.' not in token:
                return False, None, "Invalid token format"
            
            payload_b64, signature = token.rsplit('.', 1)
            
            # Verify signature
            if not BetaTokenManager._verify_signature(payload_b64, signature):
                return False, None, "Invalid token signature"
            
            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
            payload = json.loads(payload_json)
            
            # Check expiration
            expires = datetime.fromisoformat(payload.get('expires', ''))
            if datetime.now() > expires:
                return False, None, "Token expired"
            
            # Check installation limit
            if not BetaTokenManager._check_installation_limit(token, machine_id):
                return False, None, "Token installation limit reached"
            
            return True, payload, None
            
        except Exception as e:
            return False, None, f"Token validation error: {e}"
    
    @staticmethod
    def _sign(data: str) -> str:
        """Generate HMAC signature for data"""
        return hmac.new(
            BetaTokenConfig.ADMIN_SECRET.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    @staticmethod
    def _verify_signature(data: str, signature: str) -> bool:
        """Verify HMAC signature"""
        expected_signature = BetaTokenManager._sign(data)
        return hmac.compare_digest(expected_signature, signature)
    
    @staticmethod
    def _check_installation_limit(token: str, machine_id: str) -> bool:
        """Check if token installation limit reached"""
        try:
            # Load installations tracking
            if not BetaTokenConfig.INSTALLATIONS_FILE.exists():
                return True  # No previous installations
            
            with open(BetaTokenConfig.INSTALLATIONS_FILE, 'r') as f:
                installations = json.load(f)
            
            # Check this token's installations
            token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
            token_installs = installations.get(token_hash, [])
            
            # If already installed on this machine, allow
            if machine_id in token_installs:
                return True
            
            # Check limit
            if len(token_installs) >= BetaTokenConfig.MAX_INSTALLATIONS_PER_TOKEN:
                return False
            
            return True
            
        except Exception:
            return True  # Allow on error
    
    @staticmethod
    def _record_installation(token: str, machine_id: str, email: str):
        """Record a successful installation"""
        try:
            # Load or create installations dict
            if BetaTokenConfig.INSTALLATIONS_FILE.exists():
                with open(BetaTokenConfig.INSTALLATIONS_FILE, 'r') as f:
                    installations = json.load(f)
            else:
                installations = {}
            
            # Add installation
            token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
            if token_hash not in installations:
                installations[token_hash] = []
            
            if machine_id not in installations[token_hash]:
                installations[token_hash].append(machine_id)
            
            # Save
            BetaTokenConfig.INSTALLATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(BetaTokenConfig.INSTALLATIONS_FILE, 'w') as f:
                json.dump(installations, f, indent=2)
            
        except Exception:
            pass  # Non-critical
    
    @staticmethod
    def _store_token(email: str, token: str, payload: Dict[str, Any]):
        """Store token for tracking"""
        try:
            # Load or create tokens dict
            if BetaTokenConfig.TOKEN_FILE.exists():
                with open(BetaTokenConfig.TOKEN_FILE, 'r') as f:
                    tokens = json.load(f)
            else:
                tokens = {}
            
            # Store token
            token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
            tokens[token_hash] = {
                'email': email,
                'issued': payload.get('issued'),
                'expires': payload.get('expires'),
                'issued_by': payload.get('issued_by')
            }
            
            # Save
            BetaTokenConfig.TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(BetaTokenConfig.TOKEN_FILE, 'w') as f:
                json.dump(tokens, f, indent=2)
            
        except Exception:
            pass  # Non-critical
    
    @staticmethod
    def list_issued_tokens() -> Dict[str, Any]:
        """List all issued tokens"""
        if not BetaTokenConfig.TOKEN_FILE.exists():
            return {}
        
        try:
            with open(BetaTokenConfig.TOKEN_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
