#!/bin/bash

# Valid8 Stripe Setup Script
# This script helps you set up Stripe integration securely

set -e

echo "🚀 Valid8 Stripe Setup"
echo "======================"
echo ""

# Check if .env exists
if [ -f ".env" ]; then
    echo "⚠️  .env file already exists. This script will help you update it."
    echo "   Make sure not to commit .env to version control!"
    echo ""
fi

# Create .env if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file from template..."
    cp env.example .env
    echo "✅ Created .env file"
    echo ""
fi

echo "📋 Stripe Setup Instructions:"
echo "=============================="
echo ""
echo "1. 🌐 Go to https://dashboard.stripe.com"
echo "2. 📊 Sign up or log in to your Stripe account"
echo "3. 🔑 Go to Developers → API keys"
echo "4. 📋 Copy your Publishable key (starts with pk_test_)"
echo ""
echo "5. 🛒 Create Products in Stripe:"
echo "   - Go to Products in your dashboard"
echo "   - Create: 'Valid8 Starter' - $15/month"
echo "   - Create: 'Valid8 Professional' - $12/month"
echo "   - Create: 'Valid8 Business' - $10/month"
echo ""
echo "6. 💰 Copy the Price IDs from each product"
echo ""

# Interactive setup
read -p "Do you have your Stripe keys ready? (y/n): " ready

if [[ $ready =~ ^[Yy]$ ]]; then
    echo ""
    echo "🔐 Enter your Stripe credentials:"
    echo "(These will be stored securely in your local .env file)"
    echo ""

    read -p "Stripe Publishable Key (pk_test_...): " stripe_key
    read -p "Starter Plan Price ID: " starter_price
    read -p "Professional Plan Price ID: " pro_price
    read -p "Business Plan Price ID: " business_price

    # Update .env file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|VITE_STRIPE_PUBLISHABLE_KEY=.*|VITE_STRIPE_PUBLISHABLE_KEY=$stripe_key|" .env
        sed -i '' "s|VITE_STRIPE_STARTER_PRICE_ID=.*|VITE_STRIPE_STARTER_PRICE_ID=$starter_price|" .env
        sed -i '' "s|VITE_STRIPE_PROFESSIONAL_PRICE_ID=.*|VITE_STRIPE_PROFESSIONAL_PRICE_ID=$pro_price|" .env
        sed -i '' "s|VITE_STRIPE_BUSINESS_PRICE_ID=.*|VITE_STRIPE_BUSINESS_PRICE_ID=$business_price|" .env
    else
        # Linux
        sed -i "s|VITE_STRIPE_PUBLISHABLE_KEY=.*|VITE_STRIPE_PUBLISHABLE_KEY=$stripe_key|" .env
        sed -i "s|VITE_STRIPE_STARTER_PRICE_ID=.*|VITE_STRIPE_STARTER_PRICE_ID=$starter_price|" .env
        sed -i "s|VITE_STRIPE_PROFESSIONAL_PRICE_ID=.*|VITE_STRIPE_PROFESSIONAL_PRICE_ID=$pro_price|" .env
        sed -i "s|VITE_STRIPE_BUSINESS_PRICE_ID=.*|VITE_STRIPE_BUSINESS_PRICE_ID=$business_price|" .env
    fi

    echo ""
    echo "✅ Stripe configuration updated!"
    echo ""
    echo "🧪 Testing configuration..."
    npm run build

    if [ $? -eq 0 ]; then
        echo ""
        echo "🎉 Setup complete! Your Valid8 website is ready."
        echo ""
        echo "🚀 Next steps:"
        echo "   1. Test locally: npm run dev"
        echo "   2. Deploy to production"
        echo "   3. Set environment variables in your hosting platform"
        echo ""
    else
        echo ""
        echo "❌ Build failed. Please check your configuration."
        exit 1
    fi
else
    echo ""
    echo "📚 Setup instructions saved to README.md"
    echo "   Run this script again when you have your Stripe keys ready."
    echo ""
    echo "🔗 Quick links:"
    echo "   - Stripe Dashboard: https://dashboard.stripe.com"
    echo "   - Valid8 README: See README.md for detailed instructions"
    echo ""
fi
