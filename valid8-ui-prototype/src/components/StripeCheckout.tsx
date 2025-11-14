import React, { useState } from 'react';
import { loadStripe } from '@stripe/stripe-js';
import { Button } from 'lucide-react';
import { useAnalytics } from '../hooks/useAnalytics';
import { config } from '../utils/config';

// Initialize Stripe with secure configuration
const stripePromise = config.features.paymentsEnabled
  ? loadStripe(config.stripe.publishableKey)
  : null;

interface StripeCheckoutProps {
  priceId: string;
  tierName: string;
  amount: number;
}

const StripeCheckout: React.FC<StripeCheckoutProps> = ({ priceId, tierName, amount }) => {
  const [loading, setLoading] = useState(false);
  const { trackCheckoutStart } = useAnalytics();

  const handleCheckout = async () => {
    // Track checkout start
    trackCheckoutStart(tierName, amount);

    setLoading(true);

    try {
      // Check if payments are enabled
      if (!config.features.paymentsEnabled) {
        alert(`Payment processing is not configured yet. Please contact ${config.support.email} for assistance.`);
        setLoading(false);
        return;
      }

      if (!stripePromise) {
        alert('Payment system is temporarily unavailable. Please try again later or contact support.');
        setLoading(false);
        return;
      }

      const stripe = await stripePromise;

      if (!stripe) {
        alert('Payment system is temporarily unavailable. Please try again later or contact support.');
        setLoading(false);
        return;
      }

      // Create checkout session (this would typically be done server-side)
      const response = await fetch('/api/create-checkout-session', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          priceId,
          tierName,
          successUrl: `${window.location.origin}/success?tier=${tierName}`,
          cancelUrl: `${window.location.origin}/cancel`,
        }),
      });

      if (!response.ok) {
        // For demo purposes, simulate checkout
        alert(`Demo: Would redirect to Stripe checkout for ${tierName} plan ($${amount}/month)`);
        setLoading(false);
        return;
      }

      const session = await response.json();

      // Redirect to Stripe Checkout
      const result = await stripe.redirectToCheckout({
        sessionId: session.id,
      });

      if (result.error) {
        alert(result.error.message);
      }
    } catch (error) {
      console.error('Checkout error:', error);
      alert('Demo: Checkout would process payment for ' + tierName + ' plan');
    }

    setLoading(false);
  };

  return (
    <button
      onClick={handleCheckout}
      disabled={loading}
      className="w-full py-3 px-4 rounded-lg font-semibold transition-colors flex items-center justify-center bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
    >
      {loading ? 'Processing...' : `Subscribe to ${tierName}`}
    </button>
  );
};

export default StripeCheckout;
