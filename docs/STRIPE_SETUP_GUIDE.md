# Stripe Setup Guide for Valid8

**Date:** 2025-01-27  
**Product:** Valid8 Security Scanner  
**Domain:** valid8code.ai

---

## Overview

This guide walks you through setting up Stripe payment processing for Valid8, including:
- Creating Stripe account
- Setting up products and prices
- Configuring webhooks
- Integrating with your application
- Testing payments

---

## Step 1: Create Stripe Account

### 1.1 Sign Up

1. **Go to Stripe:**
   - Visit: https://stripe.com
   - Click: **Sign up**

2. **Create Account:**
   - Use your business email
   - Choose: **Business** account type
   - Complete registration

3. **Verify Email:**
   - Check email for verification link
   - Click to verify

### 1.2 Complete Business Information

1. **Dashboard → Settings → Business settings**
2. **Fill in:**
   - Business name: Valid8 Security
   - Business type: Software/SaaS
   - Website: https://valid8code.ai
   - Business address
   - Tax information (if applicable)

3. **Save** all information

---

## Step 2: Get API Keys

### 2.1 Test Mode Keys (For Development)

1. **Dashboard → Developers → API keys**
2. **Test mode toggle:** Should be ON (default)
3. **Copy keys:**
   - **Publishable key:** `pk_test_...` (starts with pk_test_)
   - **Secret key:** `sk_test_...` (starts with sk_test_)
   - Click **Reveal** to see secret key

### 2.2 Live Mode Keys (For Production)

1. **Toggle:** Switch to **Live mode** (top right)
2. **Copy keys:**
   - **Publishable key:** `pk_live_...` (starts with pk_live_)
   - **Secret key:** `sk_live_...` (starts with sk_live_)

⚠️ **Important:** Never commit live keys to git!

---

## Step 3: Create Products and Prices

### 3.1 Using Stripe Dashboard (Manual)

1. **Dashboard → Products → Add product**

2. **Create Pro Monthly:**
   - Name: `Valid8 Pro - Monthly`
   - Description: `Professional security scanning with hosted LLM`
   - Pricing: `$29.00 USD`
   - Billing: `Recurring monthly`
   - Click: **Save product**
   - **Copy Product ID:** `prod_...`
   - **Copy Price ID:** `price_...`

3. **Create Pro Yearly:**
   - Name: `Valid8 Pro - Yearly`
   - Description: `Professional security scanning (annual)`
   - Pricing: `$249.00 USD`
   - Billing: `Recurring yearly`
   - Click: **Save product**
   - **Copy Product ID and Price ID**

4. **Create Enterprise Monthly:**
   - Name: `Valid8 Enterprise - Monthly`
   - Description: `Enterprise security scanning with advanced features`
   - Pricing: `$99.00 USD`
   - Billing: `Recurring monthly`
   - Click: **Save product**
   - **Copy Product ID and Price ID**

5. **Create Enterprise Yearly:**
   - Name: `Valid8 Enterprise - Yearly`
   - Description: `Enterprise security scanning (annual)`
   - Pricing: `$990.00 USD` (or custom)
   - Billing: `Recurring yearly`
   - Click: **Save product**
   - **Copy Product ID and Price ID**

### 3.2 Using Setup Script (Automated)

We have a setup script that creates all products automatically:

```bash
cd /Users/sathvikkurapati/Downloads/valid8-local
python3 scripts/setup_stripe_products.py --api-key sk_test_xxxxx
```

This will:
- Create all products
- Create all prices
- Display Product IDs and Price IDs
- Save configuration

---

## Step 4: Configure Environment Variables

### 4.1 For Local Development

Create `.env` file (add to `.gitignore`):

```bash
# Stripe Test Keys
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Stripe Product IDs (from Step 3)
STRIPE_PRODUCT_PRO_MONTHLY=prod_...
STRIPE_PRODUCT_PRO_YEARLY=prod_...
STRIPE_PRODUCT_ENT_MONTHLY=prod_...
STRIPE_PRODUCT_ENT_YEARLY=prod_...
```

### 4.2 For Vercel Deployment

1. **Vercel Dashboard → Project → Settings → Environment Variables**
2. **Add each variable:**
   - `STRIPE_SECRET_KEY` → Your live secret key
   - `STRIPE_PUBLISHABLE_KEY` → Your live publishable key
   - `STRIPE_WEBHOOK_SECRET` → Your webhook secret (from Step 5)
   - `STRIPE_PRODUCT_PRO_MONTHLY` → Product ID
   - `STRIPE_PRODUCT_PRO_YEARLY` → Product ID
   - `STRIPE_PRODUCT_ENT_MONTHLY` → Product ID
   - `STRIPE_PRODUCT_ENT_YEARLY` → Product ID

3. **Select Environment:** Production (and Preview if needed)
4. **Save** all variables

---

## Step 5: Set Up Webhooks

### 5.1 Create Webhook Endpoint

1. **Stripe Dashboard → Developers → Webhooks**
2. **Click:** Add endpoint
3. **Endpoint URL:** 
   ```
   https://valid8code.ai/api/webhooks/stripe
   ```
4. **Description:** Valid8 payment webhooks
5. **Events to send:** Select:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
6. **Click:** Add endpoint

### 5.2 Get Webhook Secret

1. **After creating endpoint:** Click on it
2. **Signing secret:** Click **Reveal**
3. **Copy secret:** `whsec_...`
4. **Add to environment variables** (Step 4)

### 5.3 Test Webhook Locally (Optional)

Use Stripe CLI for local testing:

```bash
# Install Stripe CLI
brew install stripe/stripe-cli/stripe

# Login
stripe login

# Forward webhooks to local server
stripe listen --forward-to localhost:3000/api/webhooks/stripe
```

---

## Step 6: Integration Files

### 6.1 Webhook Handler

Created: `api/webhooks/stripe.py`

This handles all Stripe webhook events:
- Checkout completion
- Subscription creation/updates/deletion
- Payment success/failure

### 6.2 Checkout Session API

Created: `api/create-checkout-session.py`

This creates Stripe Checkout sessions when users click "Subscribe" on your pricing page.

### 6.3 Vercel Configuration

Updated: `vercel.json`

Added routes for:
- `/api/webhooks/stripe` → Webhook handler
- `/api/create-checkout-session` → Checkout creation

---

## Step 7: Frontend Integration

### 7.1 Install Stripe.js

```bash
cd valid8-ui-prototype
npm install @stripe/stripe-js @stripe/react-stripe-js
```

### 7.2 Update PricingSection.tsx

Add Stripe Checkout integration:

```typescript
import { loadStripe } from '@stripe/stripe-js';

const stripePromise = loadStripe(process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY!);

const handleCheckout = async (priceId: string) => {
  const stripe = await stripePromise;
  
  // Call your API to create checkout session
  const response = await fetch('/api/create-checkout-session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      priceId: priceId,
      successUrl: window.location.origin + '/success',
      cancelUrl: window.location.origin + '/pricing'
    })
  });
  
  const { sessionId } = await response.json();
  
  // Redirect to Stripe Checkout
  const result = await stripe?.redirectToCheckout({ sessionId });
  
  if (result?.error) {
    console.error(result.error);
  }
};
```

### 7.3 Environment Variables for Frontend

Add to `.env` (or Vercel environment variables):

```
REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_test_... or pk_live_...
```

---

## Step 8: Testing

### 8.1 Test Mode

1. **Use test keys** (pk_test_ and sk_test_)
2. **Test cards:**
   - Success: `4242 4242 4242 4242`
   - Decline: `4000 0000 0000 0002`
   - 3D Secure: `4000 0025 0000 3155`
   - Expiry: Any future date
   - CVC: Any 3 digits

3. **Test webhooks:**
   - Use Stripe CLI: `stripe listen --forward-to localhost:3000/api/webhooks/stripe`
   - Or use Stripe Dashboard → Webhooks → Send test webhook

### 8.2 Go Live

1. **Complete business verification** in Stripe Dashboard
2. **Switch to live mode**
3. **Update environment variables** with live keys
4. **Test with real card** (small amount)
5. **Monitor** Stripe Dashboard for transactions

---

## Step 9: Pricing Configuration

### Current Pricing Tiers

**Free Tier:**
- Price: $0
- Features: Basic scanning, 100 files/month

**Pro:**
- Monthly: $29/month
- Yearly: $249/year (save $99)
- Features: Unlimited scans, hosted LLM, IDE extensions

**Enterprise:**
- Monthly: $99/month
- Yearly: $990/year (or custom)
- Features: Everything + SSO, API, priority support

### Update Pricing

Edit `valid8/payment/stripe_integration.py`:
- Update `PaymentConfig.TIERS` with your pricing
- Update `STRIPE_PRODUCTS` with your Product IDs

---

## Step 10: Security Best Practices

### 10.1 Never Commit Keys

- ✅ Use environment variables
- ✅ Add `.env` to `.gitignore`
- ✅ Use Vercel environment variables for production

### 10.2 Webhook Security

- ✅ Always verify webhook signatures
- ✅ Use HTTPS for webhook endpoints
- ✅ Store webhook secret securely

### 10.3 API Security

- ✅ Validate all user input
- ✅ Use Stripe's official libraries
- ✅ Implement rate limiting
- ✅ Log all payment events

---

## Quick Reference

### Stripe Dashboard Links

- **Dashboard:** https://dashboard.stripe.com
- **API Keys:** https://dashboard.stripe.com/apikeys
- **Products:** https://dashboard.stripe.com/products
- **Webhooks:** https://dashboard.stripe.com/webhooks
- **Customers:** https://dashboard.stripe.com/customers
- **Subscriptions:** https://dashboard.stripe.com/subscriptions

### Environment Variables Needed

```bash
STRIPE_SECRET_KEY=sk_live_... or sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_live_... or pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRODUCT_PRO_MONTHLY=prod_...
STRIPE_PRODUCT_PRO_YEARLY=prod_...
STRIPE_PRODUCT_ENT_MONTHLY=prod_...
STRIPE_PRODUCT_ENT_YEARLY=prod_...
```

### Test Cards

- **Success:** 4242 4242 4242 4242
- **Decline:** 4000 0000 0000 0002
- **3D Secure:** 4000 0025 0000 3155
- **Expiry:** Any future date (e.g., 12/25)
- **CVC:** Any 3 digits (e.g., 123)

---

## Troubleshooting

### Common Issues

1. **"Invalid API Key"**
   - Check you're using correct key (test vs live)
   - Verify key is in environment variables
   - Check for typos or extra spaces

2. **"Webhook signature verification failed"**
   - Verify webhook secret is correct
   - Check webhook endpoint URL matches
   - Ensure using raw request body (not parsed)

3. **"Product not found"**
   - Verify Product IDs in environment variables
   - Check products exist in Stripe Dashboard
   - Ensure using correct mode (test vs live)

---

## Next Steps

1. ✅ Create Stripe account
2. ✅ Get API keys
3. ✅ Create products and prices
4. ✅ Set up webhooks
5. ✅ Configure environment variables
6. ✅ Test checkout flow
7. ✅ Deploy to production
8. ✅ Go live!

---

**Support:**
- Stripe Docs: https://stripe.com/docs
- Stripe Support: https://support.stripe.com
- Valid8 Payment Code: `valid8/payment/stripe_integration.py`


