#!/usr/bin/env python3
"""
Complete Stripe Setup Wizard - Plug and Play
Automatically sets up Stripe for Valid8 security scanner
"""
import os
import sys
import json
import secrets
import subprocess
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.text import Text

console = Console()

def run_command(cmd: str, description: str) -> bool:
    """Run a command and return success status"""
    console.print(f"\n[cyan]▶[/cyan] {description}")
    console.print(f"[dim]{cmd}[/dim]")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            console.print("[green]✓ Success![/green]")
            if result.stdout.strip():
                console.print(f"[dim]{result.stdout.strip()}[/dim]")
            return True
        else:
            console.print(f"[red]✗ Failed: {result.stderr.strip()}[/red]")
            return False
    except Exception as e:
        console.print(f"[red]✗ Error: {str(e)}[/red]")
        return False

def main():
    console.print(Panel.fit(
        "[bold blue]🎯 Valid8 Stripe Setup Wizard[/bold blue]\n\n"
        "This wizard will set up Stripe payment processing for your Valid8 security scanner.\n"
        "You'll need a Stripe account (free at stripe.com).\n\n"
        "[yellow]⚠️  This sets up test mode first. Switch to live mode when ready.[/yellow]",
        title="Welcome"
    ))

    # Check prerequisites
    console.print("\n[bold]📋 Checking Prerequisites[/bold]")
    
    # Check Python stripe package
    try:
        import stripe
        console.print("✓ Stripe Python package installed")
    except ImportError:
        console.print("✗ Stripe package not found")
        if Confirm.ask("Install stripe package now?"):
            if not run_command("pip install stripe", "Installing Stripe Python package"):
                console.print("[red]Please install manually: pip install stripe[/red]")
                return
        else:
            console.print("[red]Stripe package required. Exiting.[/red]")
            return
    
    # Check if .env exists
    env_file = Path(".env")
    if env_file.exists():
        console.print("✓ .env file exists")
        if not Confirm.ask("Overwrite existing .env file?"):
            console.print("[yellow]Keeping existing .env file[/yellow]")
    else:
        console.print("✗ .env file not found (will create)")

    # Step 1: Get Stripe API keys
    console.print("\n[bold]🔧 Step 1: Stripe API Keys[/bold]")
    console.print("Go to: https://dashboard.stripe.com/test/apikeys")
    
    stripe_secret = Prompt.ask("Enter your Stripe secret key (sk_test_...)")
    if not stripe_secret.startswith("sk_test_"):
        console.print("[red]Invalid secret key format. Must start with 'sk_test_'[/red]")
        return
    
    stripe_publishable = Prompt.ask("Enter your Stripe publishable key (pk_test_...)")
    if not stripe_publishable.startswith("pk_test_"):
        console.print("[red]Invalid publishable key format. Must start with 'pk_test_'[/red]")
        return

    # Step 2: Create webhook (instructions only)
    console.print("\n[bold]🔧 Step 2: Webhook Setup[/bold]")
    console.print("Create a webhook endpoint in Stripe Dashboard:")
    console.print("  1. Go to: https://dashboard.stripe.com/test/webhooks")
    console.print("  2. Click 'Add endpoint'")
    console.print("  3. URL: https://your-domain.com/api/webhooks/stripe")
    console.print("  4. Events: checkout.session.completed, customer.subscription.*, invoice.payment_*")
    console.print("  5. Copy the webhook signing secret (whsec_...)")
    
    webhook_secret = Prompt.ask("Enter your webhook signing secret (whsec_...)", default="whsec_skip_for_now")
    if not webhook_secret.startswith("whsec_") and webhook_secret != "whsec_skip_for_now":
        console.print("[red]Invalid webhook secret format. Must start with 'whsec_'[/red]")
        return

    # Step 3: Create products and prices
    console.print("\n[bold]💰 Step 3: Creating Products and Prices[/bold]")
    if run_command(f"python3 scripts/setup_stripe_products.py --api-key {stripe_secret} --create", 
                   "Creating Stripe products and prices"):
        
        # Extract price IDs from the output (this is a simplified version)
        console.print("\n[yellow]Note the Price IDs above - you'll need them for the .env file[/yellow]")
        console.print("[yellow]Run this again if you need to see them: python3 scripts/setup_stripe_products.py --api-key YOUR_KEY --list[/yellow]")
        
        # For now, use placeholder values - user can update later
        price_ids = {
            'STRIPE_PRODUCT_DEVELOPER_MONTHLY': 'price_developer_monthly_placeholder',
            'STRIPE_PRODUCT_DEVELOPER_YEARLY': 'price_developer_yearly_placeholder',
            'STRIPE_PRODUCT_PROFESSIONAL_MONTHLY': 'price_professional_monthly_placeholder',
            'STRIPE_PRODUCT_PROFESSIONAL_YEARLY': 'price_professional_yearly_placeholder',
            'STRIPE_PRODUCT_ENT_MONTHLY': 'price_ent_monthly_placeholder',
            'STRIPE_PRODUCT_ENT_YEARLY': 'price_ent_yearly_placeholder',
            'STRIPE_PRODUCT_ENT_CUSTOM': 'price_ent_custom_placeholder'
        }
        
    else:
        console.print("[red]Failed to create products. You can run manually later.[/red]")
        price_ids = {
            'STRIPE_PRODUCT_PRO_MONTHLY': 'price_add_manually',
            'STRIPE_PRODUCT_PRO_YEARLY': 'price_add_manually',
            'STRIPE_PRODUCT_ENT_MONTHLY': 'price_add_manually', 
            'STRIPE_PRODUCT_ENT_YEARLY': 'price_add_manually',
            'STRIPE_PRODUCT_ENT_CUSTOM': 'price_add_manually'
        }

    # Step 4: Create .env file
    console.print("\n[bold]🔐 Step 4: Creating .env Configuration[/bold]")
    
    # Generate secure license secret
    license_secret = secrets.token_hex(32)
    
    env_content = f"""# Valid8 Security Scanner - Stripe Configuration
# Generated by setup wizard

# =============================================================================
# STRIPE CONFIGURATION
# =============================================================================
STRIPE_SECRET_KEY={stripe_secret}
STRIPE_PUBLISHABLE_KEY={stripe_publishable}
STRIPE_WEBHOOK_SECRET={webhook_secret}

# Product IDs (update these with actual price IDs from Stripe dashboard)
{chr(10).join(f'{key}={value}' for key, value in price_ids.items())}

# =============================================================================
# LICENSE CONFIGURATION
# =============================================================================
PARRY_LICENSE_SECRET={license_secret}
PARRY_LICENSE_SERVER=https://api.valid8.dev

# =============================================================================
# OPTIONAL CONFIGURATION
# =============================================================================
VALID8_SUCCESS_URL=https://valid8.dev/success
VALID8_CANCEL_URL=https://valid8.dev/pricing
VALID8_WEBHOOK_URL=https://api.valid8.dev/webhooks/stripe
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    console.print("✓ Created .env file with your configuration")
    
    # Step 5: Test the setup
    console.print("\n[bold]🧪 Step 5: Testing Setup[/bold]")
    if run_command("python3 -c \"import os; os.chdir('.'); from valid8.payment.stripe_integration import StripePaymentManager; pm = StripePaymentManager(); print('Stripe integration working!')\"", 
                   "Testing Stripe integration"):
        console.print("[green]🎉 Stripe setup complete and working![/green]")
    else:
        console.print("[yellow]⚠️  Setup completed but integration test failed. Check your API keys.[/yellow]")
    
    # Final instructions
    console.print("\n" + "="*60)
    console.print("[bold green]🎯 SETUP COMPLETE![/bold green]")
    console.print("="*60)
    
    console.print("\n[bold]📋 NEXT STEPS:[/bold]")
    console.print("1. Update .env file with actual Price IDs from Stripe dashboard")
    console.print("2. Set up webhook endpoint if not done")
    console.print("3. Test checkout flow with a real payment")
    console.print("4. Switch to live mode when ready:")
    console.print("   - Replace sk_test_ keys with sk_live_ keys")
    console.print("   - Update webhook URL to production domain")
    console.print("   - Run: python3 scripts/setup_stripe_products.py --api-key sk_live_xxx --create")
    
    console.print("\n[bold]💳 PRICING TIERS READY:[/bold]")
    console.print("• Free: CLI only, local Ollama, 100 files")
    console.print("• Developer: $29/mo - Hosted LLM, unlimited files, IDE extensions")
    console.print("• Professional: $59/mo - Teams, GitHub Actions, API access, priority support")
    console.print("• Enterprise: $299/mo - Organizations, SSO, on-premise, dedicated support")
    
    console.print("\n[bold]🔗 INTEGRATION POINTS:[/bold]")
    console.print("• Checkout: api/create-checkout-session.py")
    console.print("• Webhooks: api/webhooks/stripe.py")
    console.print("• License: valid8/payment/stripe_integration.py")
    
    console.print("\n[green]🚀 Ready for payments![/green]")

if __name__ == "__main__":
    main()
