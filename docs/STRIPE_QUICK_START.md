# Stripe Quick Start for Valid8

## 🚀 5-Minute Setup

### 1. Get API Keys
- Go to: https://dashboard.stripe.com/apikeys
- Copy **Test** keys (for development):
  - `pk_test_...` (Publishable)
  - `sk_test_...` (Secret)

### 2. Create Products
Run the setup script:
```bash
python3 scripts/setup_stripe_products.py --api-key sk_test_xxxxx
```

Or create manually in Stripe Dashboard → Products

### 3. Set Environment Variables

**Local (.env):**
```bash
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

**Vercel (Dashboard → Settings → Environment Variables):**
- Add all variables above
- Use **live** keys for production

### 4. Set Up Webhook
1. Stripe Dashboard → Webhooks → Add endpoint
2. URL: `https://valid8code.ai/api/webhooks/stripe`
3. Events: `checkout.session.completed`, `customer.subscription.*`, `invoice.payment_*`
4. Copy webhook secret → Add to environment variables

### 5. Test
Use test card: `4242 4242 4242 4242`

---

## Files Created

✅ `api/webhooks/stripe.py` - Webhook handler  
✅ `api/create-checkout-session.py` - Checkout API  
✅ `vercel.json` - Updated with Stripe routes  
✅ `.env.example` - Environment variable template  
✅ `STRIPE_SETUP_GUIDE.md` - Complete guide

---

## Next Steps

1. Read `STRIPE_SETUP_GUIDE.md` for detailed instructions
2. Integrate frontend (see guide Step 7)
3. Test with test cards
4. Deploy to production

---

## Test Cards

- **Success:** 4242 4242 4242 4242
- **Decline:** 4000 0000 0000 0002
- **3D Secure:** 4000 0025 0000 3155
- **Expiry:** 12/25
- **CVC:** 123
