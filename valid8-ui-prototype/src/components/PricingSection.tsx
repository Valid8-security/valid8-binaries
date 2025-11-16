import { useState } from 'react';
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
      name: "Pro",
      price: 29,
      originalPrice: null,
      scansPerUser: "Unlimited scans",
      seats: "5 seats included",
      description: "Professional security scanning",
      features: [
        "Unlimited file scanning",
        "Hosted LLM (GPT-4, Claude, Gemini)",
        "AI-powered validation",
        "IDE extensions (VS Code, JetBrains)",
        "GitHub Actions integration",
        "150+ security detectors",
        "Team collaboration (5 seats)",
        "Basic API access (1000 scans/month)",
        "Email support"
      ],
      popular: true,
      cta: "Start Free Trial"
    },
    {
      name: "Enterprise",
      price: 99,
      originalPrice: null,
      scansPerUser: "Unlimited scans",
      seats: "Per seat pricing",
      description: "Advanced enterprise security",
      features: [
        "Everything in Pro",
        "Advanced REST API (unlimited scans)",
        "Custom security rules & policies",
        "SSO integration (SAML, OAuth)",
        "On-premise & air-gapped deployment",
        "Container & IaC scanning",
        "Supply chain security analysis",
        "Federated learning capabilities",
        "Priority support (4-hour SLA)",
        "Advanced compliance (SOC2, HIPAA, GDPR)",
        "Audit logs & compliance reports",
        "Unlimited organizations & seats",
        "Dedicated success manager"
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
            Enterprise-Grade Security Scanning
          </h2>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            From individual developers to Fortune 500 enterprises. Competitive pricing with advanced features for every team size.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-5xl mx-auto">
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
                    if (tier.name === 'Free Trial' || tier.name === 'Pro') {
                      window.location.href = '/signup';
                    } else if (tier.name === 'Enterprise') {
                      window.location.href = '/enterprise-signup';
                    }
                  }}
                  className={`w-full py-3 px-4 rounded-lg font-semibold transition-colors flex items-center justify-center ${
                    tier.name === 'Free Trial'
                      ? 'bg-green-600 text-white hover:bg-green-700'
                      : tier.name === 'Pro'
                      ? 'bg-blue-600 text-white hover:bg-blue-700'
                      : tier.name === 'Enterprise'
                      ? 'bg-purple-600 text-white hover:bg-purple-700'
                      : 'bg-gray-800 text-white hover:bg-gray-900'
                  }`}
                >
                  {(tier.name === 'Free Trial' || tier.name === 'Pro') && <Download className="mr-2 h-4 w-4" />}
                  {tier.cta}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Enterprise Features Highlight */}
        <div className="mt-16 text-center">
          <div className="bg-gradient-to-r from-blue-50 to-purple-50 border border-blue-200 rounded-lg p-8 max-w-5xl mx-auto">
            <h3 className="text-2xl font-bold text-gray-900 mb-4">
              Enterprise-Ready Security Platform
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
              <div className="text-center">
                <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Check className="h-6 w-6 text-blue-600" />
                </div>
                <h4 className="font-semibold text-gray-900 mb-2">On-Premise Ready</h4>
                <p className="text-gray-600 text-sm">Deploy in air-gapped environments with full data control</p>
              </div>
              <div className="text-center">
                <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Check className="h-6 w-6 text-purple-600" />
                </div>
                <h4 className="font-semibold text-gray-900 mb-2">Compliance Certified</h4>
                <p className="text-gray-600 text-sm">SOC2, HIPAA, GDPR compliant with audit logs</p>
              </div>
              <div className="text-center">
                <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Check className="h-6 w-6 text-green-600" />
                </div>
                <h4 className="font-semibold text-gray-900 mb-2">24/7 Enterprise Support</h4>
                <p className="text-gray-600 text-sm">Dedicated success manager and priority SLA</p>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-12 text-center">
          <p className="text-gray-600 mb-4">
            All plans include 7-day free trial. Enterprise plans available with custom contracts.
          </p>
          <p className="text-sm text-gray-500">
            Questions about enterprise pricing? <a href="mailto:sales@valid8.dev" className="text-blue-600 hover:underline">Contact our enterprise sales team</a>
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
