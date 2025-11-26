# 🎯 Valid8 Security Scanner - New Pricing Tiers Setup Guide

## 📋 Overview

Updated pricing strategy with competitive $29/month and $59/month tiers designed for individual developers and professional teams.

## 💰 New Pricing Tiers

### 🆓 **Free Tier** - $0/month
**Value Proposition:** Get started with powerful security scanning
- CLI tool with local Ollama
- Basic security detectors (30+)
- Fast mode scanning
- JSON/Text output
- Community support
- **File limit:** 100 files

---

### 👨‍💻 **Developer Tier** - $29/month ($249/year - Save 17%)
**Value Proposition:** Perfect for individual developers who need professional-grade security tools

**🚀 Key Benefits:**
- Everything in Free
- **Hosted LLM** (GPT-4, Claude, Gemini) for AI-powered analysis
- **AI-powered false positive reduction** (94.5% precision)
- **IDE extensions** (VS Code, JetBrains) for seamless integration
- **All security detectors** (150+ vulnerability types)
- **Deep + Hybrid scanning modes** for comprehensive analysis
- **Basic compliance reports**
- **Email support**
- **Unlimited files** - no more restrictions
- **Priority scanning queue**

**Perfect For:**
- Individual developers
- Freelancers
- Small development teams
- Open-source contributors
- Security enthusiasts

---

### 👥 **Professional Tier** - $59/month ($549/year - Save 25%)
**Value Proposition:** Complete solution for professional teams and organizations

**🚀 Key Benefits:**
- Everything in Developer
- **GitHub Actions integration** for CI/CD security
- **Team collaboration** (up to 5 seats)
- **Advanced REST API** (10,000 scans/month)
- **Custom security rules & policies**
- **Container & IaC scanning**
- **Priority support** (24-hour SLA)
- **Advanced compliance** (SOC2, GDPR)
- **Audit logs & team reports**
- **Multi-organization support**
- **Advanced integrations**
- **Team management dashboard**

**Perfect For:**
- Development teams
- Small to medium businesses
- Security teams
- DevOps organizations
- Compliance-focused companies

---

### 🏢 **Enterprise Tier** - $299/month ($2,691/year - Save 25%)
**Value Proposition:** Enterprise-grade security for large organizations

**🚀 Key Benefits:**
- Everything in Professional
- **Unlimited API scans**
- **SSO integration** (SAML, OAuth, Okta)
- **On-premise & air-gapped deployment**
- **Supply chain security analysis**
- **Federated learning capabilities**
- **Dedicated support** (4-hour SLA)
- **Advanced compliance** (SOC2, HIPAA, GDPR, ISO27001)
- **White-label options**
- **Unlimited organizations & seats**
- **Custom integrations**
- **Dedicated success manager**
- **Annual contract terms**

**Perfect For:**
- Large enterprises
- Financial institutions
- Healthcare organizations
- Government agencies
- Highly regulated industries

## 🛠️ Setup Instructions

### Method 1: Automated Setup Wizard (Recommended)

```bash
# Run the interactive setup wizard
python3 scripts/setup_stripe_complete.py
```

The wizard will guide you through:
1. Stripe API key configuration
2. Webhook setup
3. Product creation
4. Environment configuration

### Method 2: Manual Setup

#### Step 1: Get Stripe API Keys
1. Go to [Stripe Dashboard](https://dashboard.stripe.com/test/apikeys)
2. Copy your **Secret key** (starts with `sk_test_`)
3. Copy your **Publishable key** (starts with `pk_test_`)

#### Step 2: Create Products
```bash
# Create all products and prices
python3 scripts/setup_stripe_products.py --api-key sk_test_xxxxx --create
```

This creates:
- **Developer Monthly:** $29/month
- **Developer Yearly:** $249/year (17% savings)
- **Professional Monthly:** $59/month
- **Professional Yearly:** $549/year (25% savings)
- **Enterprise Monthly:** $299/month
- **Enterprise Yearly:** $2,691/year (25% savings)

#### Step 3: Configure Environment
Copy `.env.template.new` to `.env` and fill in:

```bash
# Stripe Configuration
STRIPE_SECRET_KEY=sk_test_your_key_here
STRIPE_PUBLISHABLE_KEY=pk_test_your_key_here
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret_here

# Product IDs (from step 2 output)
STRIPE_PRODUCT_DEVELOPER_MONTHLY=price_xxxxx
STRIPE_PRODUCT_DEVELOPER_YEARLY=price_xxxxx
STRIPE_PRODUCT_PROFESSIONAL_MONTHLY=price_xxxxx
STRIPE_PRODUCT_PROFESSIONAL_YEARLY=price_xxxxx
STRIPE_PRODUCT_ENT_MONTHLY=price_xxxxx
STRIPE_PRODUCT_ENT_YEARLY=price_xxxxx

# License Configuration
PARRY_LICENSE_SECRET=your_secure_random_secret_here
```

#### Step 4: Set Up Webhooks
1. Go to [Stripe Webhooks](https://dashboard.stripe.com/test/webhooks)
2. Add endpoint: `https://your-domain.com/api/webhooks/stripe`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.*`
   - `invoice.payment_*`

### Method 3: Live Mode Setup
When ready for production:
```bash
# Switch to live keys
export STRIPE_SECRET_KEY=sk_live_xxxxx
export STRIPE_PUBLISHABLE_KEY=pk_live_xxxxx

# Recreate products for live mode
python3 scripts/setup_stripe_products.py --api-key sk_live_xxxxx --create

# Update webhook URL to production domain
```

## 🧪 Testing Setup

```bash
# Test integration
python3 -c "from valid8.payment.stripe_integration import StripePaymentManager; pm = StripePaymentManager(); print('✅ Working!')"

# Test license management
python3 -c "from valid8.payment.stripe_integration import LicenseManager; lm = LicenseManager(); print('License system ready')"
```

## 🔗 Integration Examples

### Create Checkout Session
```python
from valid8.payment.stripe_integration import StripePaymentManager

pm = StripePaymentManager()
session = pm.create_checkout_session(
    tier='developer',  # or 'professional', 'enterprise'
    billing_cycle='monthly',  # or 'yearly'
    customer_email='user@example.com',
    success_url='https://valid8.dev/success',
    cancel_url='https://valid8.dev/pricing'
)

print(f"Checkout URL: {session['url']}")
```

### API Checkout (POST)
```json
{
  "priceId": "price_developer_monthly_xxxxx",
  "tier": "developer",
  "successUrl": "https://valid8.dev/success",
  "cancelUrl": "https://valid8.dev/pricing"
}
```

## 📊 Pricing Strategy Rationale

### Why $29/month for Developer?
- **Market Research:** Competitive with GitHub Copilot ($10-39/month), ESLint premium tools
- **Value Perception:** Clear upgrade from free with significant AI capabilities
- **Conversion Funnel:** Low barrier for individual developers to upgrade
- **LTV Focus:** Builds loyalty for future Professional upgrades

### Why $59/month for Professional?
- **Team Value:** 5 seats = $11.80/user/month (competitive with enterprise tools)
- **Feature Depth:** GitHub Actions, API access, compliance features
- **Enterprise Bridge:** Smooth transition path to Enterprise tier
- **Profit Margin:** Healthy margins while remaining accessible

### Why $299/month for Enterprise?
- **Market Standard:** Competitive with enterprise security tools (Snyk, Veracode)
- **Feature Rich:** Comprehensive enterprise features justify premium pricing
- **Support Model:** Dedicated success managers and custom integrations
- **Volume Discounts:** Per-seat pricing scales with organization size

## 🎯 Value Proposition Summary

| Tier | Price | Target User | Key Value | Conversion Path |
|------|-------|-------------|-----------|----------------|
| Free | $0 | Developers | Try before buy | → Developer |
| Developer | $29 | Individuals | AI-powered security | → Professional |
| Professional | $59 | Teams | Team collaboration + CI/CD | → Enterprise |
| Enterprise | $299 | Organizations | Enterprise-grade security | Custom contracts |

## 🚀 Next Steps

1. **Run setup wizard:** `python3 scripts/setup_stripe_complete.py`
2. **Test checkout flow** with test payments
3. **Update website** with new pricing
4. **Create marketing materials** highlighting value propositions
5. **Monitor conversion rates** and optimize pricing if needed

## 📞 Support

- **Setup Issues:** Check Stripe dashboard for product/price IDs
- **Integration Help:** Review `valid8/payment/stripe_integration.py`
- **Webhook Debugging:** Check `api/webhooks/stripe.py` logs

---

**Ready to start accepting payments with the new competitive pricing tiers! 🚀**
