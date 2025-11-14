import React, { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

const FAQPage: React.FC = () => {
  const [openItems, setOpenItems] = useState<Set<number>>(new Set());

  const toggleItem = (index: number) => {
    const newOpenItems = new Set(openItems);
    if (newOpenItems.has(index)) {
      newOpenItems.delete(index);
    } else {
      newOpenItems.add(index);
    }
    setOpenItems(newOpenItems);
  };

  const faqs = [
    {
      question: "What makes Valid8 different from other security scanners?",
      answer: "Valid8 uniquely combines AI-powered detection with automated fix generation. While most tools only identify vulnerabilities, Valid8 provides actionable code patches that you can apply with one click. Additionally, all scanning happens locally on your machine, ensuring your code never leaves your environment."
    },
    {
      question: "How does the free trial work?",
      answer: "Our 7-day free trial gives you full access to Valid8's core features. You can scan up to 100 files and experience our AI-powered detection and automated fixes. No credit card required. At the end of the trial, you can upgrade to a paid plan or continue with limited free usage."
    },
    {
      question: "Which programming languages does Valid8 support?",
      answer: "Valid8 supports 8 major programming languages: Python, Java, JavaScript, TypeScript, Go, Rust, PHP, and C++. We're continuously adding support for additional languages based on user demand."
    },
    {
      question: "How does Valid8 ensure my code stays private?",
      answer: "Valid8 performs all scanning and analysis locally on your machine. Your source code never gets transmitted to external servers. We use advanced AI models that run entirely on your infrastructure, ensuring complete data privacy and compliance with regulations like GDPR and SOC2."
    },
    {
      question: "What are the volume discounts?",
      answer: "Our pricing automatically adjusts based on team size: 1-10 seats ($15/user), 11-50 seats ($12/user), 51-200 seats ($10/user), and 200+ seats ($8/user). Discounts apply automatically as your team grows - no need to change plans or renegotiate."
    },
    {
      question: "Can Valid8 integrate with my CI/CD pipeline?",
      answer: "Yes! Valid8 integrates with popular CI/CD platforms including GitHub Actions, GitLab CI, Jenkins, CircleCI, and Azure DevOps. You can add security scanning to your existing pipelines with just a few lines of configuration."
    },
    {
      question: "How accurate is Valid8's vulnerability detection?",
      answer: "Valid8 achieves 92.3% recall (ability to find real vulnerabilities) and 100% precision (no false positives) on industry-standard benchmarks. Our AI models are trained on millions of code samples and continuously updated to catch new vulnerability patterns."
    },
    {
      question: "What happens if I find a vulnerability that Valid8 misses?",
      answer: "While we strive for comprehensive coverage, no automated tool can catch 100% of vulnerabilities. Valid8 is designed to complement, not replace, manual code reviews and penetration testing. If you discover a missed vulnerability, please report it to our team so we can improve our detection capabilities."
    },
    {
      question: "Can I use Valid8 for open source projects?",
      answer: "Absolutely! Valid8 includes a generous free tier that's perfect for open source projects. Many open source maintainers use Valid8 to ensure code quality and security before releases."
    },
    {
      question: "How do I get support if I run into issues?",
      answer: "We offer multiple support channels: email support for all users, priority support for paid plans, and enterprise-level support for larger organizations. You can also check our documentation and community forums for self-service support."
    },
    {
      question: "Is there a limit to how many files I can scan?",
      answer: "Free trial users can scan up to 100 files. Paid plans have tiered limits: Starter (200 files/user/month), Professional (300 files/user/month), Business (500 files/user/month), and Enterprise (unlimited). Contact us for custom enterprise limits."
    },
    {
      question: "How often should I run security scans?",
      answer: "We recommend running scans at key points in your development process: before commits, during CI/CD builds, before releases, and as part of regular security audits. The frequency depends on your development velocity and risk tolerance."
    },
    {
      question: "Can Valid8 scan container images or infrastructure code?",
      answer: "Currently, Valid8 focuses on application code scanning. However, we're actively developing support for infrastructure as code (Terraform, CloudFormation) and container scanning. Enterprise customers can request early access to these features."
    },
    {
      question: "What compliance standards does Valid8 support?",
      answer: "Valid8 helps you meet various compliance requirements through comprehensive reporting. Our tools support SOC2, HIPAA, PCI-DSS, and GDPR compliance with detailed audit trails and compliance-specific reporting features."
    },
    {
      question: "How do I cancel my subscription?",
      answer: "You can cancel your subscription at any time through your account dashboard or by contacting support. You'll continue to have access to paid features until the end of your current billing period. No cancellation fees apply."
    }
  ];

  return (
    <div className="min-h-screen bg-gray-50 py-16">
      <div className="max-w-4xl mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Frequently Asked Questions
          </h1>
          <p className="text-xl text-gray-600">
            Everything you need to know about Valid8
          </p>
        </div>

        {/* FAQ Items */}
        <div className="space-y-4">
          {faqs.map((faq, index) => (
            <div key={index} className="bg-white rounded-lg shadow-sm border">
              <button
                onClick={() => toggleItem(index)}
                className="w-full px-6 py-4 text-left flex items-center justify-between hover:bg-gray-50"
              >
                <span className="text-lg font-medium text-gray-900">
                  {faq.question}
                </span>
                {openItems.has(index) ? (
                  <ChevronUp className="w-5 h-5 text-gray-500" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-gray-500" />
                )}
              </button>

              {openItems.has(index) && (
                <div className="px-6 pb-4">
                  <div className="border-t border-gray-200 pt-4">
                    <p className="text-gray-700 leading-relaxed">
                      {faq.answer}
                    </p>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Still Need Help */}
        <div className="mt-12 bg-blue-50 border border-blue-200 rounded-lg p-8 text-center">
          <h2 className="text-2xl font-semibold text-blue-900 mb-4">
            Still Have Questions?
          </h2>
          <p className="text-blue-800 mb-6">
            Can't find what you're looking for? Our team is here to help.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a
              href="mailto:support@valid8.dev"
              className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700"
            >
              Contact Support
            </a>
            <a
              href="mailto:sales@valid8.dev"
              className="bg-white text-blue-600 border border-blue-600 px-6 py-3 rounded-lg hover:bg-blue-50"
            >
              Sales Inquiry
            </a>
          </div>
        </div>

        {/* Related Links */}
        <div className="mt-8 text-center">
          <p className="text-gray-600 mb-4">Explore more resources:</p>
          <div className="flex flex-wrap justify-center gap-4">
            <a href="/docs" className="text-blue-600 hover:text-blue-800">
              Documentation
            </a>
            <span className="text-gray-400">•</span>
            <a href="/features" className="text-blue-600 hover:text-blue-800">
              Features
            </a>
            <span className="text-gray-400">•</span>
            <a href="/pricing" className="text-blue-600 hover:text-blue-800">
              Pricing
            </a>
            <span className="text-gray-400">•</span>
            <a href="/contact" className="text-blue-600 hover:text-blue-800">
              Contact Us
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FAQPage;
