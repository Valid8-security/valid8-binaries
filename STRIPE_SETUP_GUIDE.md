# 🎯 Valid8 Stripe Setup Guide - What You Need to Do on Stripe

## 📋 Overview
This guide tells you **exactly** what to set up in your Stripe dashboard and what information to copy. We'll create 3 pricing tiers: Free, Developer ($29/mo), and Professional ($59/mo).

---

## 🔑 STEP 1: Get Your Stripe API Keys

### What to do in Stripe:
1. Go to [Stripe Dashboard](https://dashboard.stripe.com/test/apikeys)
2. You'll see two keys - copy both:

### Information you need to copy:
```
STRIPE_SECRET_KEY = sk_test_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PUBLISHABLE_KEY = pk_test_XXXXXXXXXXXXXXXXXXXXX
```

**Important:** Use **test mode** for now (URLs start with `test`). Switch to live later.

---

## 💰 STEP 2: Create Products and Prices in Stripe

### What to do in Stripe:
1. Go to [Products](https://dashboard.stripe.com/test/products) in your dashboard
2. Click "Create product" for each tier below

### Create These 5 Products:

#### Product 1: Valid8 Developer Monthly
```
Name: Valid8 Developer Monthly
Description: Individual developer tier with hosted LLM, unlimited files, IDE extensions
Pricing: 
  - Price: $29.00
  - Billing: Monthly
  - Currency: USD
```

#### Product 2: Valid8 Developer Yearly  
```
Name: Valid8 Developer Yearly
Description: Individual developer tier with hosted LLM, unlimited files, IDE extensions (Save 17%)
Pricing:
  - Price: $249.00
  - Billing: Yearly
  - Currency: USD
```

#### Product 3: Valid8 Professional Monthly
```
Name: Valid8 Professional Monthly
Description: Team tier with GitHub Actions, API access, advanced compliance, priority support
Pricing:
  - Price: $59.00
  - Billing: Monthly
  - Currency: USD
```

#### Product 4: Valid8 Professional Yearly
```
Name: Valid8 Professional Yearly
Description: Team tier with GitHub Actions, API access, advanced compliance, priority support (Save 25%)
Pricing:
  - Price: $549.00
  - Billing: Yearly
  - Currency: USD
```

#### Product 5: Valid8 Free (Optional - for reference)
```
Name: Valid8 Free
Description: CLI tool with local Ollama, basic detectors, 100 files
Pricing:
  - Price: $0.00
  - Billing: One-time (or leave blank)
```

### Information you need to copy after creating products:
After creating each product, click on it and copy the **Price ID** from the pricing section:

```
STRIPE_PRODUCT_DEVELOPER_MONTHLY = price_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PRODUCT_DEVELOPER_YEARLY = price_XXXXXXXXXXXXXXXXXXXXX  
STRIPE_PRODUCT_PROFESSIONAL_MONTHLY = price_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PRODUCT_PROFESSIONAL_YEARLY = price_XXXXXXXXXXXXXXXXXXXXX
```

**Where to find Price IDs:**
1. Click on the product name in Products list
2. Scroll down to "Pricing" section
3. Click on the price amount
4. Copy the ID that starts with `price_`

---

## 🌐 STEP 3: Set Up Webhook Endpoint

### What to do in Stripe:
1. Go to [Webhooks](https://dashboard.stripe.com/test/webhooks)
2. Click "Add endpoint"
3. Fill in these details:

```
Endpoint URL: https://your-domain.com/api/webhooks/stripe
Description: Valid8 subscription webhooks
Events to send:
  ✓ checkout.session.completed
  ✓ customer.subscription.created
  ✓ customer.subscription.updated  
  ✓ customer.subscription.deleted
  ✓ invoice.payment_succeeded
  ✓ invoice.payment_failed
```

### Information you need to copy:
After creating the webhook, copy the **Signing secret**:

```
STRIPE_WEBHOOK_SECRET = whsec_XXXXXXXXXXXXXXXXXXXXX
```

**Where to find the signing secret:**
- After creating the webhook, click the "reveal" button next to "Signing secret"
- Copy the entire secret (starts with `whsec_`)

---

## 🔐 STEP 4: Create Your .env File

### What to do locally:
Create a file named `.env` in your project root with this content:

```bash
# Stripe Configuration
STRIPE_SECRET_KEY=sk_test_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PUBLISHABLE_KEY=pk_test_XXXXXXXXXXXXXXXXXXXXX
STRIPE_WEBHOOK_SECRET=whsec_XXXXXXXXXXXXXXXXXXXXX

# Product IDs from Step 2
STRIPE_PRODUCT_DEVELOPER_MONTHLY=price_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PRODUCT_DEVELOPER_YEARLY=price_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PRODUCT_PROFESSIONAL_MONTHLY=price_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PRODUCT_PROFESSIONAL_YEARLY=price_XXXXXXXXXXXXXXXXXXXXX

# License Configuration
PARRY_LICENSE_SECRET=your_secure_random_secret_here_32_chars_minimum
PARRY_LICENSE_SERVER=https://api.valid8.dev

# Web URLs (update with your domain)
VALID8_SUCCESS_URL=https://your-domain.com/success
VALID8_CANCEL_URL=https://your-domain.com/pricing
```

### What information you need to provide:
Replace all the `XXXXXXXXXXXXXXXXXXXXX` placeholders with the actual values you copied from Stripe.

---

## 🧪 STEP 5: Test Your Setup

### Run these commands to verify:

```bash
# Test Stripe integration
python3 -c "from valid8.payment.stripe_integration import StripePaymentManager; pm = StripePaymentManager(); print('✅ Stripe connected!')"

# Test checkout session creation
python3 -c "
from valid8.payment.stripe_integration import StripePaymentManager
pm = StripePaymentManager()
session = pm.create_checkout_session(
    tier='developer',
    billing_cycle='monthly', 
    customer_email='test@example.com',
    success_url='https://your-domain.com/success',
    cancel_url='https://your-domain.com/pricing'
)
print('✅ Checkout URL:', session['url'])
"
```

---

## 📋 SUMMARY: What You Need From Stripe

Here's a checklist of everything you need to copy from your Stripe dashboard:

### ✅ Required Information:
- [ ] **STRIPE_SECRET_KEY** (from API keys page)
- [ ] **STRIPE_PUBLISHABLE_KEY** (from API keys page)  
- [ ] **STRIPE_WEBHOOK_SECRET** (from webhook settings)
- [ ] **STRIPE_PRODUCT_DEVELOPER_MONTHLY** (price ID)
- [ ] **STRIPE_PRODUCT_DEVELOPER_YEARLY** (price ID)
- [ ] **STRIPE_PRODUCT_PROFESSIONAL_MONTHLY** (price ID)
- [ ] **STRIPE_PRODUCT_PROFESSIONAL_YEARLY** (price ID)

### 🎯 Stripe Dashboard Actions:
1. [ ] Get API keys from https://dashboard.stripe.com/test/apikeys
2. [ ] Create 4 products with pricing at https://dashboard.stripe.com/test/products
3. [ ] Set up webhook at https://dashboard.stripe.com/test/webhooks
4. [ ] Copy all the IDs and secrets listed above

### 📁 Files to Create/Update:
- [ ] `.env` file with all the configuration above
- [ ] Update your domain in the success/cancel URLs

---

## 🚀 Going Live (Later)

When ready for real payments:

1. **Switch to live mode:**
   - Get live API keys (start with `sk_live_` and `pk_live_`)
   - Recreate products in live mode
   - Update webhook URL to your production domain

2. **Update your .env file:**
   ```bash
   STRIPE_SECRET_KEY=sk_live_XXXXXXXXXXXXXXXXXXXXX
   STRIPE_PUBLISHABLE_KEY=pk_live_XXXXXXXXXXXXXXXXXXXXX
   ```

3. **Test with live mode** (use small amounts first!)

---

## 🔧 Troubleshooting

**"Invalid API key" error:**
- Make sure you're using test keys (start with `sk_test_`)
- Check for typos in your .env file

**"Product not found" error:**  
- Verify the price IDs are correct (start with `price_`)
- Make sure products are created in test mode

**Webhook not working:**
- Check the endpoint URL is accessible
- Verify the webhook secret is correct
- Make sure all required events are selected

**Need help?** Check the Stripe dashboard for detailed error messages in the Events section.

---

## 📞 That's It!

Once you have those 7 pieces of information from Stripe and create the `.env` file, your payment system is ready! The rest is handled automatically by the Valid8 integration.

**Questions?** The setup is designed to be copy-paste simple. Just follow the steps above in order.
