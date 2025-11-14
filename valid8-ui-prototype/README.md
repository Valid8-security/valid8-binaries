# Valid8 Web Interface

A modern React application for the Valid8 security scanner platform.

## 🚀 Features

- **Free Trial**: 7-day trial with 100 file scans
- **Secure Payments**: Stripe integration for subscriptions
- **Professional UI**: Clean, enterprise-ready design
- **Analytics**: Built-in event tracking
- **Error Handling**: Comprehensive error boundaries

## 🛠️ Setup

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
npm install
```

### Environment Configuration

1. Copy the environment template:
```bash
cp env.example .env
```

2. Configure your environment variables in `.env`:

```bash
# Stripe Configuration (Required for payments)
VITE_STRIPE_PUBLISHABLE_KEY=pk_test_YOUR_ACTUAL_STRIPE_KEY
VITE_STRIPE_STARTER_PRICE_ID=price_YOUR_STARTER_PRICE_ID
VITE_STRIPE_PROFESSIONAL_PRICE_ID=price_YOUR_PROFESSIONAL_PRICE_ID
VITE_STRIPE_BUSINESS_PRICE_ID=price_YOUR_BUSINESS_PRICE_ID

# Application Configuration
VITE_APP_NAME=Valid8
VITE_APP_URL=https://valid8.dev

# Analytics (Optional)
VITE_GOOGLE_ANALYTICS_ID=GA_MEASUREMENT_ID

# Support Configuration
VITE_SUPPORT_EMAIL=support@valid8.dev
VITE_SALES_EMAIL=sales@valid8.dev
```

### Stripe Setup

1. **Create a Stripe account** at [stripe.com](https://stripe.com)

2. **Get your API keys** from the Stripe Dashboard:
   - Go to Developers → API keys
   - Copy your **Publishable key** (starts with `pk_test_` for testing)

3. **Create products and prices**:
   - Go to Products in your Stripe Dashboard
   - Create products for each tier (Starter, Professional, Business)
   - Add recurring prices (monthly billing)

4. **Update your `.env` file** with the actual price IDs

### Development

```bash
npm run dev
```

### Build for Production

```bash
npm run build
```

## 🔒 Security

### Environment Variables

**Never commit your `.env` file to version control.** It contains sensitive API keys.

The `.env` file is automatically ignored by `.gitignore`, and the `env.example` file provides a safe template.

### Stripe Security

- API keys are environment-specific (test vs live)
- Publishable keys are safe to expose in frontend code
- Secret keys are never exposed to the frontend
- All payment processing happens securely through Stripe

## 📊 Analytics

The app includes built-in analytics tracking:

- Trial signups
- Pricing page views
- Checkout attempts
- Error events

For production, configure Google Analytics by setting `VITE_GOOGLE_ANALYTICS_ID`.

## 🚀 Deployment

### Recommended Hosting

- **Vercel**: Automatic deployments, great for React apps
- **Netlify**: Easy CI/CD, good performance
- **AWS S3 + CloudFront**: Scalable, cost-effective

### Environment Variables in Production

Set your environment variables in your hosting platform:

**Vercel:**
```bash
vercel env add VITE_STRIPE_PUBLISHABLE_KEY
```

**Netlify:**
```bash
netlify env:set VITE_STRIPE_PUBLISHABLE_KEY your_key_here
```

## 🧪 Testing

### Payment Testing

Use Stripe's test card numbers:
- Success: `4242 4242 4242 4242`
- Declined: `4000 0000 0000 0002`
- Requires authentication: `4000 0025 0000 3155`

### Trial Testing

The free trial uses a simple installation command that doesn't require server-side processing.

## 📞 Support

- **General Support**: support@valid8.dev
- **Sales Inquiries**: sales@valid8.dev
- **Technical Issues**: GitHub Issues

## 📝 License

This project is part of the Valid8 security platform.
