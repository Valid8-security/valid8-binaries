import React, { useState } from 'react';
import { Check, Star, Download } from 'lucide-react';
import DownloadModal from './DownloadModal';

const PricingSection = () => {
  const [isDownloadModalOpen, setIsDownloadModalOpen] = useState(false);

  const pricingTiers = [
    {
      name: "Free Trial",
      price: 0,
      originalPrice: null,
      scansPerUser: "100 scans/month",
      seats: "1 seat",
      description: "Automatic 7-day free trial",
      features: [
        "100 scans per month",
        "All languages supported",
        "AI-powered analysis",
        "Basic fix suggestions",
        "Community support"
      ],
      popular: false,
      cta: "Start Free Trial"
    },
    {
      name: "Starter",
      price: 15,
      originalPrice: null,
      scansPerUser: "200 scans/user",
      seats: "1-10 seats",
      description: "Ideal for small teams",
      features: [
        "200 scans per user/month",
        "All languages supported",
        "Email support",
        "Advanced AI analysis",
        "Basic fix suggestions"
      ],
      popular: false,
      cta: "Start Free Trial"
    },
    {
      name: "Professional",
      price: 12,
      originalPrice: 15,
      scansPerUser: "300 scans/user",
      seats: "11-50 seats",
      description: "For growing development teams",
      features: [
        "300 scans per user/month",
        "Volume discount pricing",
        "Priority email support",
        "Advanced AI fix suggestions",
        "CI/CD integration",
        "Basic reporting"
      ],
      popular: true,
      cta: "Start Free Trial"
    },
    {
      name: "Business",
      price: 10,
      originalPrice: 15,
      scansPerUser: "500 scans/user",
      seats: "51-200 seats",
      description: "Enterprise-grade security",
      features: [
        "500 scans per user/month",
        "Maximum volume discount",
        "Dedicated support",
        "Advanced reporting & analytics",
        "Custom integrations",
        "Compliance reporting"
      ],
      popular: false,
      cta: "Contact Sales"
    },
    {
      name: "Enterprise",
      price: 8,
      originalPrice: 15,
      scansPerUser: "Unlimited scans/user",
      seats: "200+ seats",
      description: "Unlimited security automation",
      features: [
        "Unlimited scans per user",
        "Ultimate volume discount",
        "White-label options",
        "Custom development",
        "Strategic partnership",
        "24/7 premium support"
      ],
      popular: false,
      cta: "Contact Sales"
    }
  ];

  return (
    <section id="pricing" className="py-20 bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
            Choose Your Plan
          </h2>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Seat-based pricing that scales with your team. Volume discounts automatically apply as you grow.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-8 max-w-6xl mx-auto">
          {pricingTiers.map((tier, index) => (
            <div
              key={index}
              className={`bg-white rounded-lg shadow-lg overflow-hidden relative ${
                tier.popular ? 'ring-2 ring-blue-500 scale-105' : ''
              }`}
            >
              {tier.popular && (
                <div className="bg-blue-500 text-white text-center py-2">
                  <div className="flex items-center justify-center">
                    <Star className="h-4 w-4 mr-1" />
                    Most Popular
                  </div>
                </div>
              )}

              <div className="p-6">
                <h3 className="text-xl font-bold text-gray-900 mb-2">{tier.name}</h3>
                <p className="text-gray-600 mb-4">{tier.description}</p>

                <div className="mb-4">
                  {tier.price === 0 ? (
                    <div className="text-3xl font-bold text-gray-900">FREE</div>
                  ) : (
                    <div className="flex items-baseline">
                      <span className="text-3xl font-bold text-gray-900">${tier.price}</span>
                      <span className="text-gray-600 ml-1">/user/month</span>
                      {tier.originalPrice && (
                        <span className="text-gray-400 line-through ml-2">${tier.originalPrice}</span>
                      )}
                    </div>
                  )}
                </div>

                <div className="text-sm text-gray-600 mb-4">
                  <div>{tier.scansPerUser}</div>
                  <div>{tier.seats}</div>
                </div>

                <ul className="space-y-2 mb-6">
                  {tier.features.map((feature, featureIndex) => (
                    <li key={featureIndex} className="flex items-center text-sm">
                      <Check className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>

                <button
                  onClick={() => {
                    if (tier.price === 0 || tier.name === 'Free Trial' || tier.name === 'Starter') {
                      setIsDownloadModalOpen(true);
                    }
                  }}
                  className={`w-full py-3 px-4 rounded-lg font-semibold transition-colors flex items-center justify-center ${
                    tier.price === 0 || tier.name === 'Free Trial'
                      ? 'bg-green-600 text-white hover:bg-green-700'
                      : tier.popular
                      ? 'bg-blue-600 text-white hover:bg-blue-700'
                      : 'bg-gray-800 text-white hover:bg-gray-900'
                  }`}
                >
                  {(tier.price === 0 || tier.name === 'Free Trial' || tier.name === 'Starter') && <Download className="mr-2 h-4 w-4" />}
                  {tier.cta}
                </button>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-16 text-center">
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-6 max-w-4xl mx-auto">
            <h3 className="text-lg font-semibold text-blue-900 mb-2">
              Volume Discounts Apply Automatically
            </h3>
            <p className="text-blue-800">
              Start with any number of seats. As your team grows, you'll automatically qualify for
              volume discounts. No need to change plans or renegotiate contracts.
            </p>
          </div>
        </div>

        <div className="mt-12 text-center">
          <p className="text-gray-600 mb-4">
            All plans include 14-day free trial. No credit card required.
          </p>
          <p className="text-sm text-gray-500">
            Questions about pricing? <a href="mailto:sales@valid8.com" className="text-blue-600 hover:underline">Contact our sales team</a>
          </p>
        </div>
      </div>

      <DownloadModal
        isOpen={isDownloadModalOpen}
        onClose={() => setIsDownloadModalOpen(false)}
      />
    </section>
  );
};

export default PricingSection;
