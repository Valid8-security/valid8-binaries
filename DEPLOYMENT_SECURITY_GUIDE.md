# 🔒 Valid8 Deployment & Security Guide

## Overview

This guide covers secure deployment of Valid8's web interface with proper Stripe integration and environment variable management.

## 🛡️ Security Principles

### 1. Never Commit Secrets
- **Environment variables** containing API keys are never committed to git
- **`.env` files** are automatically ignored via `.gitignore`
- **Placeholder values** are provided in `env.example` for safe development

### 2. Secure Key Management
- **Stripe Publishable Keys**: Safe to expose in frontend (pk_test_/pk_live_)
- **Stripe Secret Keys**: Never exposed to frontend, only used server-side
- **Environment Separation**: Test vs Production keys clearly separated

### 3. Validation & Monitoring
- **Configuration validation** on app startup
- **Error boundaries** for crash monitoring
- **Analytics tracking** for user behavior monitoring

---

## 🚀 Deployment Steps

### Phase 1: Local Development Setup

#### 1. Clone and Install
```bash
git clone <repository>
cd valid8-ui-prototype
npm install
```

#### 2. Environment Configuration
```bash
# Copy the secure template
cp env.example .env

# Edit .env with your values (NEVER COMMIT THIS FILE)
nano .env
```

#### 3. Stripe Setup
```bash
# Run the secure setup script
./setup-stripe.sh
```

This script will:
- Guide you through Stripe account creation
- Help you create products and prices
- Securely store credentials in .env
- Validate the configuration

### Phase 2: Stripe Account Configuration

#### Create Stripe Account
1. Go to [stripe.com](https://stripe.com) and create account
2. Complete business verification
3. Enable test mode for development

#### Create Products & Prices
```bash
# In Stripe Dashboard → Products

# Create Valid8 Starter
Name: "Valid8 Starter"
Price: $15/month
Description: "Perfect for individual developers"

# Create Valid8 Professional
Name: "Valid8 Professional"
Price: $12/month
Description: "For growing development teams"

# Create Valid8 Business
Name: "Valid8 Business"
Price: $10/month
Description: "Enterprise-grade security"
```

#### Get API Keys
```bash
# In Stripe Dashboard → Developers → API keys

# Copy Publishable key (safe for frontend)
VITE_STRIPE_PUBLISHABLE_KEY=pk_test_...

# Note: Secret keys are for server-side only
# Never put secret keys in frontend .env
```

### Phase 3: Testing & Validation

#### Local Testing
```bash
# Test with Stripe test cards
npm run dev

# Test cards:
# Success: 4242 4242 4242 4242
# Declined: 4000 0000 0000 0002
```

#### Configuration Validation
```bash
# Check console for configuration warnings
# App will show warnings if Stripe isn't configured
```

### Phase 4: Production Deployment

#### Choose Hosting Platform
**Recommended Options:**

1. **Vercel** (Easiest)
   ```bash
   npm i -g vercel
   vercel --prod
   ```

2. **Netlify** (Good performance)
   ```bash
   npm i -g netlify-cli
   netlify deploy --prod
   ```

3. **AWS S3 + CloudFront** (Scalable)
   ```bash
   aws s3 sync dist/ s3://your-bucket
   ```

#### Set Production Environment Variables

**Vercel:**
```bash
vercel env add VITE_STRIPE_PUBLISHABLE_KEY
vercel env add VITE_STRIPE_STARTER_PRICE_ID
# ... add all required variables
```

**Netlify:**
```bash
netlify env:set VITE_STRIPE_PUBLISHABLE_KEY your_key
netlify env:set VITE_STRIPE_STARTER_PRICE_ID price_xxx
# ... set all variables
```

**AWS (via Console):**
- Go to Lambda@Edge or CloudFront Functions
- Set environment variables in function configuration

---

## 🔐 Security Checklist

### Pre-Deployment
- [ ] `.env` file is not committed to git
- [ ] All secrets use environment variables
- [ ] Stripe keys are properly formatted
- [ ] HTTPS is enabled on production domain
- [ ] Domain (valid8.dev) is properly configured

### Post-Deployment
- [ ] Stripe webhooks are configured (if using server-side processing)
- [ ] SSL certificate is valid
- [ ] Environment variables are set in production
- [ ] Error monitoring is working
- [ ] Analytics are tracking properly

---

## 🚨 Security Best Practices

### API Key Security
```javascript
// ✅ GOOD: Environment variables
const stripeKey = import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY;

// ❌ BAD: Hardcoded keys
const stripeKey = "pk_test_123456789";
```

### Environment Separation
```bash
# .env (Development/Test)
VITE_STRIPE_PUBLISHABLE_KEY=pk_test_...

# Production Environment Variables
VITE_STRIPE_PUBLISHABLE_KEY=pk_live_...
```

### Monitoring & Alerts
- Set up Stripe alerts for failed payments
- Monitor for unusual API usage
- Enable Stripe radar for fraud detection
- Set up error tracking (Sentry, etc.)

---

## 🧪 Testing Stripe Integration

### Test Cards
```bash
# Success scenarios
4242 4242 4242 4242  # Succeeds
5555 5555 5555 4444  # Succeeds with authentication

# Failure scenarios
4000 0000 0000 0002  # Declined
4000 0000 0000 0069  # Expired card
4000 0000 0000 0127  # Incorrect CVC
```

### Webhook Testing
```bash
# Use Stripe CLI for webhook testing
stripe listen --forward-to localhost:3000/webhook
```

---

## 📊 Monitoring & Analytics

### Required Tracking
- Payment conversion rates
- Trial signup success
- User engagement metrics
- Error rates and types

### Optional Enhancements
- Google Analytics 4 setup
- Hotjar for user behavior
- Sentry for error tracking
- Stripe Sigma for revenue analytics

---

## 🚨 Emergency Procedures

### If Stripe Keys are Compromised
1. **Immediately disable** compromised keys in Stripe Dashboard
2. **Generate new keys**
3. **Update environment variables** in all environments
4. **Redeploy application**
5. **Monitor for suspicious activity**

### If Environment Variables Leak
1. **Rotate all secrets** immediately
2. **Check git history** for any committed secrets
3. **Update all deployment environments**
4. **Enable additional security monitoring**

---

## 📞 Support & Resources

### Stripe Resources
- [Stripe Documentation](https://stripe.com/docs)
- [Stripe Testing](https://stripe.com/docs/testing)
- [Stripe Security](https://stripe.com/docs/security)

### Deployment Resources
- [Vercel Docs](https://vercel.com/docs)
- [Netlify Docs](https://docs.netlify.com)
- [AWS CloudFront](https://aws.amazon.com/cloudfront/)

### Security Resources
- [OWASP Environment Variables](https://owasp.org/www-community/vulnerabilities/Information_Disclosure_Through_Environment_Variables)
- [12 Factor App Config](https://12factor.net/config)

---

## ✅ Final Checklist

### Security
- [ ] No secrets committed to git
- [ ] Environment variables properly configured
- [ ] HTTPS enabled
- [ ] Stripe keys validated

### Functionality
- [ ] Payments process correctly
- [ ] Trial signup works
- [ ] Error handling functional
- [ ] Analytics tracking

### Performance
- [ ] Page loads under 3 seconds
- [ ] Mobile responsive
- [ ] No console errors
- [ ] SEO optimized

**Ready to deploy? Run `./setup-stripe.sh` and follow the prompts!** 🚀
