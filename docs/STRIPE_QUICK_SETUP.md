# Stripe Setup - Quick Start Guide

## Step 1: Create Stripe Account (5 minutes)

1. **Go to Stripe**: https://stripe.com
2. **Sign Up** with your business email
3. **Complete Business Information**:
   - Business name: Valid8 Security
   - Business type: Software/SaaS
   - Website: https://valid8code.ai
   - Business address

## Step 2: Get API Keys (2 minutes)

1. **Dashboard** → **Developers** → **API keys**
2. **Test Mode** (for development):
   - Copy **Publishable key**: `pk_test_...`
   - Copy **Secret key**: `sk_test_...` (click Reveal)

3. **Live Mode** (for production):
   - Toggle to **Live mode** (top right)
   - Copy **Publishable key**: `pk_live_...`
   - Copy **Secret key**: `sk_live_...`

⚠️ **Never commit keys to git!**

## Step 3: Create Products (5 minutes)

### Option A: Using Stripe Dashboard (Manual)

1. **Dashboard** → **Products** → **Add product**

2. **Create Pro Monthly**:
   - Name: `Valid8 Pro - Monthly`
   - Description: `Professional security scanning with hosted LLM`
   - Price: `$29.00 USD`
   - Billing: `Recurring monthly`
   - Click **Save**
   - **Copy Price ID**: `price_...`

3. **Create Pro Yearly**:
   - Name: `Valid8 Pro - Yearly`
   - Price: `$249.00 USD`
   - Billing: `Recurring yearly`
   - **Copy Price ID**

4. **Create Enterprise Monthly**:
   - Name: `Valid8 Enterprise - Monthly`
   - Price: `$99.00 USD`
   - Billing: `Recurring monthly`
   - **Copy Price ID**

5. **Create Enterprise Yearly**:
   - Name: `Valid8 Enterprise - Yearly`
   - Price: `$990.00 USD`
   - Billing: `Recurring yearly`
   - **Copy Price ID**

### Option B: Using Setup Script (Automated)

```bash
cd /Users/sathvikkurapati/Downloads/valid8-local
python3 scripts/setup_stripe_products.py --api-key sk_test_xxxxx
```

This creates all products automatically.

## Step 4: Set Up Webhook (3 minutes)

1. **Dashboard** → **Developers** → **Webhooks**
2. **Add endpoint**
3. **Endpoint URL**: 
   ```
   https://valid8code.ai/api/webhooks/stripe
   ```
4. **Description**: Valid8 payment webhooks
5. **Events to send**:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
6. **Add endpoint**
7. **Copy Signing secret**: `whsec_...` (click Reveal)

## Step 5: Add Environment Variables to Vercel (5 minutes)

1. **Vercel Dashboard** → Your Project → **Settings** → **Environment Variables**

2. **Add each variable** (use **LIVE** keys for production):

   ```
   STRIPE_SECRET_KEY=sk_live_...
   STRIPE_PUBLISHABLE_KEY=pk_live_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   STRIPE_PRICE_PRO_MONTHLY=price_...
   STRIPE_PRICE_PRO_YEARLY=price_...
   STRIPE_PRICE_ENT_MONTHLY=price_...
   STRIPE_PRICE_ENT_YEARLY=price_...
   ```

3. **Select Environment**: Production (and Preview if needed)
4. **Save** all variables

## Step 6: Update Frontend (2 minutes)

Add Stripe publishable key to frontend:

1. **Vercel Environment Variables**:
   ```
   REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_live_...
   ```

2. **Or update frontend code** to read from environment:
   ```typescript
   const stripePromise = loadStripe(
     process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY || 'pk_test_...'
   );
   ```

## Step 7: Test (5 minutes)

### Test Mode

1. Use **test keys** (`pk_test_` and `sk_test_`)
2. **Test cards**:
   - Success: `4242 4242 4242 4242`
   - Decline: `4000 0000 0000 0002`
   - 3D Secure: `4000 0025 0000 3155`
   - Expiry: Any future date (e.g., `12/25`)
   - CVC: Any 3 digits (e.g., `123`)

3. **Test checkout**:
   ```bash
   curl -X POST https://valid8code.ai/api/create-checkout-session \
     -H "Content-Type: application/json" \
     -d '{"priceId": "price_test_xxxxx"}'
   ```

### Go Live

1. Complete **business verification** in Stripe
2. Switch to **live mode**
3. Update environment variables with **live keys**
4. Test with real card (small amount)
5. Monitor Stripe Dashboard

## Quick Reference

### Stripe Dashboard Links
- **Dashboard**: https://dashboard.stripe.com
- **API Keys**: https://dashboard.stripe.com/apikeys
- **Products**: https://dashboard.stripe.com/products
- **Webhooks**: https://dashboard.stripe.com/webhooks

### Environment Variables Needed
```bash
STRIPE_SECRET_KEY=sk_live_... or sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_live_... or pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO_MONTHLY=price_...
STRIPE_PRICE_PRO_YEARLY=price_...
STRIPE_PRICE_ENT_MONTHLY=price_...
STRIPE_PRICE_ENT_YEARLY=price_...
```

### Test Cards
- **Success**: `4242 4242 4242 4242`
- **Decline**: `4000 0000 0000 0002`
- **3D Secure**: `4000 0025 0000 3155`

## Current Pricing

- **Pro Monthly**: $29/month
- **Pro Yearly**: $249/year (save $99)
- **Enterprise Monthly**: $99/month
- **Enterprise Yearly**: $990/year

## Troubleshooting

### "Invalid API Key"
- Check you're using correct key (test vs live)
- Verify key is in Vercel environment variables
- Check for typos or extra spaces

### "Webhook signature verification failed"
- Verify webhook secret is correct
- Check webhook endpoint URL matches
- Ensure using raw request body

### "Product not found"
- Verify Price IDs in environment variables
- Check products exist in Stripe Dashboard
- Ensure using correct mode (test vs live)

## Support

- **Stripe Docs**: https://stripe.com/docs
- **Stripe Support**: https://support.stripe.com
- **Valid8 Payment Code**: `api/create-checkout-session.py`
