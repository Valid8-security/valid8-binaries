#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Beta license signup script for testing
"""

from parry.license import LicenseManager
import sys

def main():
    print("🎉 Parry Beta License Signup")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        email = input("Enter your email: ")
    else:
        email = sys.argv[1]
    
    print(f"\nInstalling beta license for {email}...")
    
    if LicenseManager.install_beta_license(email):
        print("\n✅ Beta license installed successfully!")
        print("\nAccess granted to:")
        print("  • Deep mode (AI-powered scanning)")
        print("  • Hybrid mode (90% recall)")
        print("  • AI validation (reduce false positives)")
        print("  • Compliance reports")
        print("  • SCA scanning")
        print("  • Secrets scanning")
        print("  • All languages supported")
        print("  • Unlimited files/repos")
        
        print("\n📅 Beta Duration: 90 days")
        print("\n🚀 Get started:")
        print("  parry scan . --mode hybrid")
        print("\n📝 License info:")
        print("  parry license")
        print("\n💬 Questions? Email: beta@parry.ai")
        print("\nThank you for beta testing Parry!")
        
        return 0
    else:
        print("\n❌ Failed to install beta license")
        print("Please check your email address and try again.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

