# 📋 Valid8 Stripe Setup Checklist

## 🎯 WHAT YOU NEED FROM STRIPE (7 Items)

### 1. API Keys (2 items)
- [ ] `STRIPE_SECRET_KEY` = `sk_test_...` 
- [ ] `STRIPE_PUBLISHABLE_KEY` = `pk_test_...`

**Where:** https://dashboard.stripe.com/test/apikeys

### 2. Product Price IDs (4 items)  
- [ ] `STRIPE_PRODUCT_DEVELOPER_MONTHLY` = `price_...`
- [ ] `STRIPE_PRODUCT_DEVELOPER_YEARLY` = `price_...`  
- [ ] `STRIPE_PRODUCT_PROFESSIONAL_MONTHLY` = `price_...`
- [ ] `STRIPE_PRODUCT_PROFESSIONAL_YEARLY` = `price_...`

**Where:** https://dashboard.stripe.com/test/products (click product → pricing → copy price ID)

### 3. Webhook Secret (1 item)
- [ ] `STRIPE_WEBHOOK_SECRET` = `whsec_...`

**Where:** https://dashboard.stripe.com/test/webhooks (after creating webhook endpoint)

---

## 🛠️ STRIPE DASHBOARD ACTIONS

### Step 1: Create Products
Go to https://dashboard.stripe.com/test/products and create:

1. **Valid8 Developer Monthly** - $29/month
2. **Valid8 Developer Yearly** - $249/year  
3. **Valid8 Professional Monthly** - $59/month
4. **Valid8 Professional Yearly** - $549/year

### Step 2: Create Webhook  
Go to https://dashboard.stripe.com/test/webhooks and add:

```
URL: https://your-domain.com/api/webhooks/stripe
Events: checkout.session.completed, customer.subscription.*, invoice.payment_*
```

### Step 3: Copy Information
Copy the 7 values above into your `.env` file.

---

## 📄 .ENV FILE TEMPLATE

```bash
# Stripe Configuration  
STRIPE_SECRET_KEY=sk_test_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PUBLISHABLE_KEY=pk_test_XXXXXXXXXXXXXXXXXXXXX
STRIPE_WEBHOOK_SECRET=whsec_XXXXXXXXXXXXXXXXXXXXX

# Product Price IDs
STRIPE_PRODUCT_DEVELOPER_MONTHLY=price_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PRODUCT_DEVELOPER_YEARLY=price_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PRODUCT_PROFESSIONAL_MONTHLY=price_XXXXXXXXXXXXXXXXXXXXX
STRIPE_PRODUCT_PROFESSIONAL_YEARLY=price_XXXXXXXXXXXXXXXXXXXXX

# Other config
PARRY_LICENSE_SECRET=your_secure_random_secret_here_32_chars_minimum
PARRY_LICENSE_SERVER=https://api.valid8.dev
VALID8_SUCCESS_URL=https://your-domain.com/success
VALID8_CANCEL_URL=https://your-domain.com/pricing
```

---

## ✅ VERIFICATION

After setup, test with:
```bash
python3 -c "from valid8.payment.stripe_integration import StripePaymentManager; pm = StripePaymentManager(); print('✅ Connected!')"
```

**If you get errors, double-check the 7 values above are correct.**

---
**That's all you need! Just 7 pieces of information from Stripe dashboard.**
