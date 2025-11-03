# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Stripe Payment Integration for Parry Security Scanner

Handles subscription payments for:
- CLI tool (uses local Ollama - Free tier available)
- IDE extensions (uses hosted LLM - Requires Pro/Enterprise)
- GitHub Actions (uses hosted LLM - Requires Pro/Enterprise)

Pricing Tiers:
- Free: CLI with local Ollama, basic detectors, 100 files limit
- Pro ($49/month): Hosted LLM, all detectors, unlimited files, IDE + GitHub Actions
- Enterprise ($299/month): Everything + API access, SSO, priority support

License Enforcement:
- CLI: Enforces file limits, detector access
- IDE: Requires Pro+ subscription, shut off if expired
- GitHub Actions: Requires Pro+ subscription with org billing
"""

import os
import json
import time
import hashlib
import hmac
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False
    # Fallback to requests if stripe not installed
    import requests


@dataclass
class SubscriptionTier:
    """Subscription tier definition"""
    name: str
    price_monthly: int  # USD cents
    price_yearly: int  # USD cents
    features: list
    file_limit: Optional[int] = None
    llm_mode: str = 'local'  # 'local' or 'hosted'


class PaymentConfig:
    """Configuration for payment system"""
    
    # Stripe configuration (load from environment in production)
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_...')
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', 'pk_test_...')
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', 'whsec_...')
    
    # API endpoints
    LICENSE_SERVER = os.environ.get('PARRY_LICENSE_SERVER', 'https://api.parry.dev')
    STRIPE_API_URL = 'https://api.stripe.com/v1'
    
    # Subscription tiers
    TIERS = {
        'free': SubscriptionTier(
            name='Free',
            price_monthly=0,
            price_yearly=0,
            features=[
                'CLI tool with local Ollama',
                'Basic security detectors (30+)',
                'Fast mode scanning',
                'JSON/Text output'
            ],
            file_limit=100,
            llm_mode='local'
        ),
        'pro': SubscriptionTier(
            name='Pro',
            price_monthly=4900,  # $49.00
            price_yearly=49900,  # $499.00 (save $89)
            features=[
                'Everything in Free',
                'Hosted LLM (no Ollama setup needed)',
                'AI-powered validation',
                'IDE extensions (VS Code, JetBrains)',
                'GitHub Actions integration',
                'All security detectors (150+)',
                'Deep + Hybrid modes',
                'Compliance reports',
                'Email support'
            ],
            file_limit=None,  # Unlimited
            llm_mode='hosted'
        ),
        'enterprise': SubscriptionTier(
            name='Enterprise',
            price_monthly=29900,  # $299.00
            price_yearly=299900,  # $2,999.00 (save $590)
            features=[
                'Everything in Pro',
                'REST API access',
                'Custom security rules',
                'SSO integration',
                'On-premise deployment',
                'Container + IaC scanning',
                'Priority support (SLA)',
                'Advanced compliance (SOC2, HIPAA)',
                'Audit logs',
                'Unlimited organizations'
            ],
            file_limit=None,
            llm_mode='hosted'
        )
    }
    
    # Product IDs (set after creating Stripe products)
    STRIPE_PRODUCTS = {
        'pro_monthly': os.environ.get('STRIPE_PRODUCT_PRO_MONTHLY', 'prod_...'),
        'pro_yearly': os.environ.get('STRIPE_PRODUCT_PRO_YEARLY', 'prod_...'),
        'enterprise_monthly': os.environ.get('STRIPE_PRODUCT_ENT_MONTHLY', 'prod_...'),
        'enterprise_yearly': os.environ.get('STRIPE_PRODUCT_ENT_YEARLY', 'prod_...')
    }


class StripePaymentManager:
    """Manage Stripe payments and subscriptions"""
    
    def __init__(self):
        self.api_key = PaymentConfig.STRIPE_SECRET_KEY
        
        if STRIPE_AVAILABLE:
            stripe.api_key = self.api_key
        else:
            # Fallback to raw requests
            self.headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
    
    def create_checkout_session(
        self,
        tier: str,
        billing_cycle: str,
        customer_email: str,
        success_url: str,
        cancel_url: str,
        metadata: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Create Stripe checkout session for subscription
        
        Args:
            tier: 'pro' or 'enterprise'
            billing_cycle: 'monthly' or 'yearly'
            customer_email: Customer email
            success_url: Redirect URL on success
            cancel_url: Redirect URL on cancel
            metadata: Additional metadata (CLI version, machine ID, etc.)
        
        Returns:
            Checkout session with URL
        """
        product_key = f'{tier}_{billing_cycle}'
        price_id = PaymentConfig.STRIPE_PRODUCTS.get(product_key)
        
        if not price_id:
            raise ValueError(f"Invalid tier/billing cycle: {tier}/{billing_cycle}")
        
        if STRIPE_AVAILABLE:
            # Use official Stripe SDK
            try:
                session = stripe.checkout.Session.create(
                    mode='subscription',
                    customer_email=customer_email,
                    line_items=[{
                        'price': price_id,
                        'quantity': 1
                    }],
                    success_url=success_url,
                    cancel_url=cancel_url,
                    allow_promotion_codes=True,
                    billing_address_collection='required',
                    metadata=metadata or {}
                )
                return session
            except stripe.error.StripeError as e:
                raise ValueError(f"Stripe error: {e.user_message}")
        else:
            # Fallback to raw requests
            data = {
                'mode': 'subscription',
                'customer_email': customer_email,
                'line_items[0][price]': price_id,
                'line_items[0][quantity]': '1',
                'success_url': success_url,
                'cancel_url': cancel_url,
                'allow_promotion_codes': 'true',
                'billing_address_collection': 'required'
            }
            
            # Add metadata
            if metadata:
                for key, value in metadata.items():
                    data[f'metadata[{key}]'] = value
            
            response = requests.post(
                f'{PaymentConfig.STRIPE_API_URL}/checkout/sessions',
                headers=self.headers,
                data=data
            )
            
            response.raise_for_status()
            return response.json()
    
    def verify_subscription(self, customer_email: str) -> Dict[str, Any]:
        """
        Verify active subscription for customer
        
        Returns:
            {
                'active': bool,
                'tier': 'free'|'pro'|'enterprise',
                'expires': timestamp,
                'status': 'active'|'canceled'|'past_due'|'none'
            }
        """
        if STRIPE_AVAILABLE:
            try:
                # Search for customer by email
                customers = stripe.Customer.list(email=customer_email, limit=1)
                
                if not customers.data:
                    return {'active': False, 'tier': 'free', 'expires': None, 'status': 'none'}
                
                customer = customers.data[0]
                
                # Get active subscriptions
                subscriptions = stripe.Subscription.list(
                    customer=customer.id,
                    status='active',
                    limit=1
                )
                
                if not subscriptions.data:
                    return {'active': False, 'tier': 'free', 'expires': None, 'status': 'none'}
                
                subscription = subscriptions.data[0]
                tier = self._get_tier_from_subscription_object(subscription)
                
                return {
                    'active': subscription.status == 'active',
                    'tier': tier,
                    'expires': subscription.current_period_end,
                    'status': subscription.status,
                    'cancel_at_period_end': subscription.cancel_at_period_end
                }
            except stripe.error.StripeError as e:
                print(f"Stripe error: {e.user_message}")
                return {'active': False, 'tier': 'free', 'expires': None, 'status': 'none'}
        else:
            # Fallback to raw requests
            response = requests.get(
                f'{PaymentConfig.STRIPE_API_URL}/customers',
                headers=self.headers,
                params={'email': customer_email, 'limit': 1}
            )
            
            response.raise_for_status()
            customers = response.json()['data']
            
            if not customers:
                return {'active': False, 'tier': 'free', 'expires': None, 'status': 'none'}
            
            customer_id = customers[0]['id']
            
            # Get subscriptions
            response = requests.get(
                f'{PaymentConfig.STRIPE_API_URL}/subscriptions',
                headers=self.headers,
                params={'customer': customer_id, 'status': 'active', 'limit': 1}
            )
            
            response.raise_for_status()
            subscriptions = response.json()['data']
            
            if not subscriptions:
                return {'active': False, 'tier': 'free', 'expires': None, 'status': 'none'}
            
            subscription = subscriptions[0]
            tier = self._get_tier_from_subscription(subscription)
            
            return {
                'active': subscription['status'] == 'active',
                'tier': tier,
                'expires': subscription['current_period_end'],
                'status': subscription['status'],
                'cancel_at_period_end': subscription['cancel_at_period_end']
            }
    
    def _get_tier_from_subscription(self, subscription: Dict) -> str:
        """Extract tier from subscription items (dict version)"""
        for item in subscription['items']['data']:
            product_id = item['price']['product']
            
            # Match against known products
            for key, stripe_product_id in PaymentConfig.STRIPE_PRODUCTS.items():
                if product_id == stripe_product_id:
                    if 'pro' in key:
                        return 'pro'
                    elif 'enterprise' in key:
                        return 'enterprise'
        
        return 'free'
    
    def _get_tier_from_subscription_object(self, subscription) -> str:
        """Extract tier from subscription items (Stripe object version)"""
        for item in subscription['items']['data']:
            product_id = item.price.product
            
            # Match against known products
            for key, stripe_product_id in PaymentConfig.STRIPE_PRODUCTS.items():
                if product_id == stripe_product_id:
                    if 'pro' in key:
                        return 'pro'
                    elif 'enterprise' in key:
                        return 'enterprise'
        
        return 'free'
    
    def handle_webhook(self, payload: bytes, signature: str) -> Dict[str, Any]:
        """
        Handle Stripe webhook events
        
        Events handled:
        - checkout.session.completed: New subscription
        - customer.subscription.updated: Subscription change
        - customer.subscription.deleted: Cancellation
        - invoice.payment_failed: Payment failure
        """
        if not STRIPE_AVAILABLE:
            raise RuntimeError("Stripe SDK required for webhook handling. Run: pip install stripe")
        
        try:
            event = stripe.Webhook.construct_event(
                payload, signature, PaymentConfig.STRIPE_WEBHOOK_SECRET
            )
        except stripe.error.SignatureVerificationError as e:
            raise ValueError(f"Webhook signature verification failed: {e}")
        except Exception as e:
            raise ValueError(f"Webhook error: {e}")
        
        event_type = event['type']
        data = event['data']['object']
        
        if event_type == 'checkout.session.completed':
            return self._handle_checkout_completed(data)
        elif event_type == 'customer.subscription.updated':
            return self._handle_subscription_updated(data)
        elif event_type == 'customer.subscription.deleted':
            return self._handle_subscription_deleted(data)
        elif event_type == 'invoice.payment_failed':
            return self._handle_payment_failed(data)
        
        return {'status': 'ignored', 'type': event_type}
    
    def _handle_checkout_completed(self, session: Dict) -> Dict:
        """Handle successful checkout"""
        customer_email = session['customer_email']
        subscription_id = session.get('subscription')
        
        # Generate license key
        license_manager = LicenseManager()
        tier = self._get_tier_from_session(session)
        license_key = license_manager.generate_license_key(customer_email, tier, subscription_id)
        
        # Send welcome email with license key
        self._send_license_email(customer_email, license_key, tier)
        
        return {
            'status': 'success',
            'action': 'license_issued',
            'email': customer_email,
            'tier': tier
        }
    
    def _handle_subscription_updated(self, subscription: Dict) -> Dict:
        """Handle subscription changes"""
        # Update license if tier changed or subscription canceled
        return {'status': 'updated', 'subscription_id': subscription['id']}
    
    def _handle_subscription_deleted(self, subscription: Dict) -> Dict:
        """Handle subscription cancellation"""
        # Revoke license
        customer = subscription['customer']
        # Get customer email and revoke license
        return {'status': 'revoked', 'subscription_id': subscription['id']}
    
    def _handle_payment_failed(self, invoice: Dict) -> Dict:
        """Handle failed payment"""
        # Send notification to customer
        # Grace period before revoking access
        return {'status': 'payment_failed', 'invoice_id': invoice['id']}
    
    def _send_license_email(self, email: str, license_key: str, tier: str):
        """Send license key to customer"""
        # Implementation would use SendGrid, AWS SES, etc.
        pass
    
    def _get_tier_from_session(self, session: Dict) -> str:
        """Get tier from checkout session"""
        # Extract from line items
        line_items = session.get('line_items', {}).get('data', [])
        if not line_items:
            return 'free'
        
        # Get price ID from first line item
        price_id = line_items[0].get('price', {}).get('id', '')
        
        # Map price ID to tier
        if 'pro' in price_id.lower():
            return 'pro'
        elif 'enterprise' in price_id.lower():
            return 'enterprise'
        
        return 'free'


class LicenseManager:
    """Manage license keys and validation"""
    
    LICENSE_FILE = Path.home() / '.parry' / 'license.json'
    
    def generate_license_key(self, email: str, tier: str, subscription_id: str) -> str:
        """Generate cryptographically signed license key"""
        data = {
            'email': email,
            'tier': tier,
            'subscription_id': subscription_id,
            'issued': datetime.now().isoformat()
        }
        
        # Create signature
        data_str = json.dumps(data, sort_keys=True)
        secret = os.environ.get('PARRY_LICENSE_SECRET', 'dev-secret')
        signature = hmac.new(
            secret.encode(),
            data_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Encode as license key
        license_data = {**data, 'signature': signature}
        license_json = json.dumps(license_data)
        license_key = license_json.encode().hex()
        
        return license_key
    
    def install_license(self, license_key: str) -> bool:
        """Install and validate license key"""
        try:
            # Decode license
            license_json = bytes.fromhex(license_key).decode()
            license_data = json.load(license_json)
            
            # Verify signature
            signature = license_data.pop('signature')
            data_str = json.dumps(license_data, sort_keys=True)
            secret = os.environ.get('PARRY_LICENSE_SECRET', 'dev-secret')
            expected_sig = hmac.new(
                secret.encode(),
                data_str.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if signature != expected_sig:
                return False
            
            # Verify subscription is active
            payment_manager = StripePaymentManager()
            subscription_status = payment_manager.verify_subscription(license_data['email'])
            
            if not subscription_status['active']:
                return False
            
            # Save license
            self.LICENSE_FILE.parent.mkdir(exist_ok=True)
            license_data['verified_at'] = datetime.now().isoformat()
            license_data['expires'] = subscription_status['expires']
            
            with open(self.LICENSE_FILE, 'w') as f:
                json.dump(license_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"License installation failed: {e}")
            return False
    
    def validate_license(self) -> Dict[str, Any]:
        """
        Validate current license and check subscription status
        
        Returns:
            {
                'valid': bool,
                'tier': str,
                'features': list,
                'file_limit': int or None,
                'llm_mode': 'local' or 'hosted'
            }
        """
        if not self.LICENSE_FILE.exists():
            # No license, return free tier
            tier = PaymentConfig.TIERS['free']
            return {
                'valid': True,
                'tier': 'free',
                'features': tier.features,
                'file_limit': tier.file_limit,
                'llm_mode': tier.llm_mode
            }
        
        try:
            with open(self.LICENSE_FILE) as f:
                license_data = json.load(f)
            
            # Check expiration
            expires = license_data.get('expires')
            if expires and time.time() > expires:
                # License expired, check subscription status
                payment_manager = StripePaymentManager()
                subscription_status = payment_manager.verify_subscription(license_data['email'])
                
                if subscription_status['active']:
                    # Update expiration
                    license_data['expires'] = subscription_status['expires']
                    with open(self.LICENSE_FILE, 'w') as f:
                        json.dump(license_data, f, indent=2)
                else:
                    # Subscription canceled, revert to free
                    tier = PaymentConfig.TIERS['free']
                    return {
                        'valid': False,
                        'tier': 'free',
                        'features': tier.features,
                        'file_limit': tier.file_limit,
                        'llm_mode': tier.llm_mode,
                        'error': 'Subscription expired or canceled'
                    }
            
            # Valid license
            tier_name = license_data.get('tier', 'free')
            tier = PaymentConfig.TIERS[tier_name]
            
            return {
                'valid': True,
                'tier': tier_name,
                'features': tier.features,
                'file_limit': tier.file_limit,
                'llm_mode': tier.llm_mode,
                'expires': expires
            }
            
        except Exception as e:
            # Error reading license, fallback to free
            tier = PaymentConfig.TIERS['free']
            return {
                'valid': False,
                'tier': 'free',
                'features': tier.features,
                'file_limit': tier.file_limit,
                'llm_mode': tier.llm_mode,
                'error': str(e)
            }
    
    def enforce_file_limit(self, file_count: int) -> bool:
        """Check if file count exceeds license limit"""
        license_info = self.validate_license()
        file_limit = license_info.get('file_limit')
        
        if file_limit is None:
            return True  # Unlimited
        
        return file_count <= file_limit
    
    def can_use_hosted_llm(self) -> bool:
        """Check if license allows hosted LLM (required for IDE/GitHub Actions)"""
        license_info = self.validate_license()
        return license_info['llm_mode'] == 'hosted'


# Example usage
if __name__ == '__main__':
    # Example: Generate checkout URL for Pro monthly subscription
    payment_manager = StripePaymentManager()
    
    session = payment_manager.create_checkout_session(
        tier='pro',
        billing_cycle='monthly',
        customer_email='user@example.com',
        success_url='https://parry.dev/success',
        cancel_url='https://parry.dev/cancel',
        metadata={'cli_version': '3.0.0', 'platform': 'macOS'}
    )
    
    print(f"Checkout URL: {session['url']}")
    
    # Example: Validate license
    license_manager = LicenseManager()
    license_info = license_manager.validate_license()
    
    print(f"License Tier: {license_info['tier']}")
    print(f"LLM Mode: {license_info['llm_mode']}")
    print(f"File Limit: {license_info['file_limit']}")
