#!/usr/bin/env python3
# Copyright (c) 2025 Parry Security Labs
# SPDX-License-Identifier: MIT

"""
Setup Stripe Products and Prices

This script creates the necessary products and prices in Stripe.
Run once during initial setup or when pricing changes.

Usage:
    python scripts/setup_stripe_products.py --api-key sk_test_xxxxx
"""

import stripe
import click
import sys
from rich.console import Console
from rich.table import Table

console = Console()

PRODUCTS = {
    'developer_monthly': {
        'name': 'Valid8 Developer - Monthly',
        'description': 'Individual developer tier with hosted LLM, unlimited files, IDE extensions',
        'price': 2900,  # $29.00 in cents
        'interval': 'month'
    },
    'developer_yearly': {
        'name': 'Valid8 Developer - Yearly',
        'description': 'Individual developer tier with hosted LLM, unlimited files, IDE extensions (Save 17%)',
        'price': 24900,  # $249.00 in cents (save $129/year)
        'interval': 'year'
    },
    'professional_monthly': {
        'name': 'Valid8 Professional - Monthly',
        'description': 'Team tier with GitHub Actions, API access, advanced compliance, priority support',
        'price': 5900,  # $59.00 in cents
        'interval': 'month'
    },
    'professional_yearly': {
        'name': 'Valid8 Professional - Yearly',
        'description': 'Team tier with GitHub Actions, API access, advanced compliance, priority support (Save 25%)',
        'price': 54900,  # $549.00 in cents (save $249/year)
        'interval': 'year'
    },
    'enterprise_monthly': {
        'name': 'Valid8 Enterprise - Monthly',
        'description': 'Organization tier with SSO, on-premise deployment, unlimited API, dedicated support',
        'price': 29900,  # $299.00 in cents
        'interval': 'month'
    },
    'enterprise_yearly': {
        'name': 'Valid8 Enterprise - Yearly',
        'description': 'Organization tier with SSO, on-premise deployment, unlimited API, dedicated support (Save 25%)',
        'price': 269100,  # $2,691.00 in cents (save $3,588/year)
        'interval': 'year'
    }
}


def create_products_and_prices(api_key: str, test_mode: bool = True) -> dict:
    """
    Create Stripe products and prices
    
    Args:
        api_key: Stripe API key (test or live)
        test_mode: Whether using test mode (affects display only)
    
    Returns:
        Dictionary mapping product keys to price IDs
    """
    stripe.api_key = api_key
    
    price_ids = {}
    
    console.print(f"\n[bold cyan]Creating Stripe Products ({['LIVE', 'TEST'][test_mode]} mode)[/bold cyan]\n")
    
    for key, product_info in PRODUCTS.items():
        try:
            # Create product
            console.print(f"Creating product: [bold]{product_info['name']}[/bold]")
            
            product = stripe.Product.create(
                name=product_info['name'],
                description=product_info['description'],
                metadata={
                    'parry_tier': 'pro' if 'pro' in key else 'enterprise',
                    'billing_cycle': product_info['interval']
                }
            )
            
            console.print(f"  Product ID: {product.id}")
            
            # Create price
            price = stripe.Price.create(
                product=product.id,
                unit_amount=product_info['price'],
                currency='usd',
                recurring={
                    'interval': product_info['interval']
                },
                metadata={
                    'parry_key': key
                }
            )
            
            console.print(f"  Price ID: [green]{price.id}[/green]")
            console.print(f"  Amount: ${product_info['price'] / 100:.2f} per {product_info['interval']}\n")
            
            price_ids[key] = price.id
            
        except stripe.error.StripeError as e:
            console.print(f"[red]Error creating {key}: {e.user_message}[/red]\n")
            continue
    
    # Display summary table
    table = Table(title="Stripe Products Created", show_header=True, header_style="bold magenta")
    table.add_column("Product Key", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Price ID", style="green")
    table.add_column("Amount", justify="right", style="yellow")
    
    for key, price_id in price_ids.items():
        product_info = PRODUCTS[key]
        table.add_row(
            key,
            product_info['name'],
            price_id,
            f"${product_info['price'] / 100:.2f}/{product_info['interval']}"
        )
    
    console.print("\n")
    console.print(table)
    console.print("\n")
    
    # Show environment variable exports
    console.print("[bold yellow]Add these to your .env file:[/bold yellow]\n")
    for key, price_id in price_ids.items():
        env_key = f"STRIPE_PRICE_{key.upper()}"
        console.print(f"{env_key}={price_id}")
    
    console.print("\n[bold yellow]Or update PaymentConfig in parry/payment/stripe_integration.py:[/bold yellow]\n")
    console.print("STRIPE_PRODUCTS = {")
    for key, price_id in price_ids.items():
        console.print(f"    '{key}': '{price_id}',")
    console.print("}")
    
    return price_ids


def list_existing_products(api_key: str):
    """List existing products and prices"""
    stripe.api_key = api_key
    
    console.print("\n[bold cyan]Existing Stripe Products[/bold cyan]\n")
    
    products = stripe.Product.list(limit=100)
    
    if not products.data:
        console.print("[yellow]No products found[/yellow]")
        return
    
    for product in products.data:
        console.print(f"[bold]{product.name}[/bold]")
        console.print(f"  Product ID: {product.id}")
        console.print(f"  Description: {product.description}")
        
        # Get prices for this product
        prices = stripe.Price.list(product=product.id)
        
        for price in prices.data:
            console.print(f"  Price ID: [green]{price.id}[/green]")
            console.print(f"  Amount: ${price.unit_amount / 100:.2f} per {price.recurring['interval']}")
        
        console.print()


@click.command()
@click.option('--api-key', required=True, help='Stripe API key (sk_test_xxx or sk_live_xxx)')
@click.option('--create', is_flag=True, help='Create products and prices')
@click.option('--list', 'list_only', is_flag=True, help='List existing products')
def main(api_key: str, create: bool, list_only: bool):
    """Setup Stripe products and prices for Parry Scanner"""
    
    if not api_key.startswith('sk_'):
        console.print("[red]Error: Invalid API key format. Must start with 'sk_test_' or 'sk_live_'[/red]")
        sys.exit(1)
    
    test_mode = api_key.startswith('sk_test_')
    
    if test_mode:
        console.print("[yellow]⚠️  Using TEST mode - no real charges will occur[/yellow]")
    else:
        console.print("[red]⚠️  Using LIVE mode - real charges will occur![/red]")
        if not click.confirm('Are you sure you want to proceed?'):
            sys.exit(0)
    
    if list_only:
        list_existing_products(api_key)
    elif create:
        price_ids = create_products_and_prices(api_key, test_mode)
        
        if len(price_ids) == len(PRODUCTS):
            console.print("[bold green]✓ All products created successfully![/bold green]")
        else:
            console.print(f"[yellow]⚠️  Created {len(price_ids)}/{len(PRODUCTS)} products[/yellow]")
    else:
        console.print("[yellow]Please specify --create or --list[/yellow]")
        console.print("\nExamples:")
        console.print("  python scripts/setup_stripe_products.py --api-key sk_test_xxx --create")
        console.print("  python scripts/setup_stripe_products.py --api-key sk_test_xxx --list")


if __name__ == '__main__':
    main()
