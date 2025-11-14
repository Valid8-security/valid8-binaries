// Simple analytics hook for tracking user interactions
// Replace with Google Analytics or other analytics service

interface AnalyticsEvent {
  event: string;
  category?: string;
  label?: string;
  value?: number;
}

export const useAnalytics = () => {
  const trackEvent = (eventData: AnalyticsEvent) => {
    // In production, send to Google Analytics, Mixpanel, etc.
    if (process.env.NODE_ENV === 'production') {
      console.log('Analytics Event:', eventData);

      // Example Google Analytics implementation:
      // if (window.gtag) {
      //   window.gtag('event', eventData.event, {
      //     event_category: eventData.category,
      //     event_label: eventData.label,
      //     value: eventData.value
      //   });
      // }
    }
  };

  const trackTrialSignup = () => {
    trackEvent({
      event: 'trial_signup',
      category: 'engagement',
      label: 'free_trial'
    });
  };

  const trackPricingView = (tier: string) => {
    trackEvent({
      event: 'pricing_view',
      category: 'engagement',
      label: tier
    });
  };

  const trackCheckoutStart = (tier: string, amount: number) => {
    trackEvent({
      event: 'begin_checkout',
      category: 'ecommerce',
      label: tier,
      value: amount
    });
  };

  return {
    trackEvent,
    trackTrialSignup,
    trackPricingView,
    trackCheckoutStart
  };
};
