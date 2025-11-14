// Secure configuration utility for environment variables
// Validates required settings and provides safe defaults

interface AppConfig {
  // Stripe Configuration
  stripe: {
    publishableKey: string;
    priceIds: {
      starter: string;
      professional: string;
      business: string;
    };
  };

  // Application Settings
  app: {
    name: string;
    url: string;
  };

  // Analytics (Optional)
  analytics?: {
    googleAnalyticsId?: string;
  };

  // Support
  support: {
    email: string;
    salesEmail: string;
  };

  // Feature Flags
  features: {
    paymentsEnabled: boolean;
    analyticsEnabled: boolean;
  };
}

function getEnvVar(key: string, defaultValue?: string): string {
  const value = import.meta.env[key];
  if (!value && !defaultValue) {
    console.warn(`Environment variable ${key} is not set`);
    return '';
  }
  return value || defaultValue || '';
}

function validateStripeConfig(): boolean {
  const publishableKey = getEnvVar('VITE_STRIPE_PUBLISHABLE_KEY');
  if (!publishableKey) {
    console.warn('Stripe publishable key not configured - payments will be disabled');
    return false;
  }

  // Basic validation of Stripe key format
  if (!publishableKey.startsWith('pk_test_') && !publishableKey.startsWith('pk_live_')) {
    console.warn('Invalid Stripe publishable key format');
    return false;
  }

  return true;
}

export const config: AppConfig = {
  stripe: {
    publishableKey: getEnvVar('VITE_STRIPE_PUBLISHABLE_KEY', ''),
    priceIds: {
      starter: getEnvVar('VITE_STRIPE_STARTER_PRICE_ID', 'price_starter_plan'),
      professional: getEnvVar('VITE_STRIPE_PROFESSIONAL_PRICE_ID', 'price_professional_plan'),
      business: getEnvVar('VITE_STRIPE_BUSINESS_PRICE_ID', 'price_business_plan'),
    },
  },

  app: {
    name: getEnvVar('VITE_APP_NAME', 'Valid8'),
    url: getEnvVar('VITE_APP_URL', 'https://valid8.dev'),
  },

  analytics: {
    googleAnalyticsId: getEnvVar('VITE_GOOGLE_ANALYTICS_ID'),
  },

  support: {
    email: getEnvVar('VITE_SUPPORT_EMAIL', 'support@valid8.dev'),
    salesEmail: getEnvVar('VITE_SALES_EMAIL', 'sales@valid8.dev'),
  },

  features: {
    paymentsEnabled: validateStripeConfig(),
    analyticsEnabled: !!getEnvVar('VITE_GOOGLE_ANALYTICS_ID'),
  },
};

// Validation function to check configuration on app start
export function validateConfiguration(): { isValid: boolean; warnings: string[] } {
  const warnings: string[] = [];

  // Check Stripe configuration
  if (!config.features.paymentsEnabled) {
    warnings.push('Stripe payment processing is not configured - users will see payment disabled messages');
  }

  // Check required environment variables
  const requiredVars = ['VITE_APP_NAME', 'VITE_APP_URL'];
  for (const varName of requiredVars) {
    if (!getEnvVar(varName)) {
      warnings.push(`Required environment variable ${varName} is not set`);
    }
  }

  // Check for development vs production warnings
  if (config.stripe.publishableKey?.startsWith('pk_test_') && import.meta.env.PROD) {
    warnings.push('Using test Stripe keys in production environment');
  }

  return {
    isValid: warnings.length === 0,
    warnings,
  };
}

// Export for use in components
export default config;
