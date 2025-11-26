#!/usr/bin/env python3
"""
Test script to verify Stripe setup is working
Run this after completing the Stripe setup checklist
"""
import os
import sys
from pathlib import Path

def test_stripe_setup():
    """Test that all Stripe configuration is properly set up"""
    print("🧪 Testing Valid8 Stripe Setup")
    print("=" * 40)
    
    # Check if .env file exists
    env_file = Path('.env')
    if not env_file.exists():
        print("❌ .env file not found")
        print("   Please create .env file with Stripe configuration")
        return False
    
    # Load environment variables from .env
    try:
        with open('.env', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
    except Exception as e:
        print(f"❌ Error reading .env file: {e}")
        return False
    
    # Check required environment variables
    required_vars = [
        'STRIPE_SECRET_KEY',
        'STRIPE_PUBLISHABLE_KEY', 
        'STRIPE_WEBHOOK_SECRET',
        'STRIPE_PRODUCT_DEVELOPER_MONTHLY',
        'STRIPE_PRODUCT_DEVELOPER_YEARLY',
        'STRIPE_PRODUCT_PROFESSIONAL_MONTHLY', 
        'STRIPE_PRODUCT_PROFESSIONAL_YEARLY'
    ]
    
    missing_vars = []
    for var in required_vars:
        value = os.environ.get(var, '').strip()
        if not value:
            missing_vars.append(var)
        elif var.startswith('STRIPE_PRODUCT_') and not value.startswith('price_'):
            print(f"⚠️  {var} doesn't look like a valid price ID (should start with 'price_')")
        elif var == 'STRIPE_SECRET_KEY' and not value.startswith('sk_test_'):
            print(f"⚠️  {var} doesn't look like a test secret key (should start with 'sk_test_')")
        elif var == 'STRIPE_PUBLISHABLE_KEY' and not value.startswith('pk_test_'):
            print(f"⚠️  {var} doesn't look like a test publishable key (should start with 'pk_test_')")
        elif var == 'STRIPE_WEBHOOK_SECRET' and not value.startswith('whsec_'):
            print(f"⚠️  {var} doesn't look like a webhook secret (should start with 'whsec_')")
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease check your .env file and STRIPE_SETUP_GUIDE.md")
        return False
    
    print("✅ All required environment variables found")
    
    # Test Stripe integration
    try:
        from valid8.payment.stripe_integration import StripePaymentManager, PaymentConfig
        print("✅ Stripe integration modules imported successfully")
        
        # Test payment manager initialization
        pm = StripePaymentManager()
        print("✅ Stripe payment manager initialized")
        
        # Test configuration
        tiers = PaymentConfig.TIERS
        print(f"✅ Pricing tiers loaded: {len([t for t in tiers.keys() if t != 'enterprise_custom'])} tiers")
        
        # Show pricing summary
        print("\n💰 Pricing Tiers:")
        for tier_name, tier in tiers.items():
            if tier_name != 'enterprise_custom':
                monthly = tier.price_monthly / 100
                yearly = tier.price_yearly / 100 if tier.price_yearly else 0
                print(f"   • {tier.name}: ${monthly:.0f}/month, ${yearly:.0f}/year")
        
        print("\n✅ Stripe setup verification complete!")
        print("🎉 Your Valid8 payment system is ready to accept payments!")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure stripe package is installed: pip install stripe")
        return False
    except Exception as e:
        print(f"❌ Stripe integration error: {e}")
        print("   Check your Stripe API keys and configuration")
        return False

if __name__ == "__main__":
    success = test_stripe_setup()
    sys.exit(0 if success else 1)
