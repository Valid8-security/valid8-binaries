import React from 'react';

const TermsOfService: React.FC = () => {
  return (
    <div className="max-w-4xl mx-auto px-4 py-16">
      <h1 className="text-3xl font-bold text-gray-900 mb-8">Terms of Service</h1>

      <div className="prose prose-lg max-w-none">
        <p className="text-gray-600 mb-6">
          <strong>Last updated:</strong> {new Date().toLocaleDateString()}
        </p>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">1. Agreement to Terms</h2>
          <p className="text-gray-700 mb-4">
            By accessing or using Valid8, you agree to be bound by these Terms of Service. If you disagree with any part of these terms, you may not access the service.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">2. Description of Service</h2>
          <p className="text-gray-700 mb-4">
            Valid8 is an AI-powered static application security testing (SAST) tool that automatically finds and fixes vulnerabilities in source code. The service includes:
          </p>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li>Automated vulnerability scanning</li>
            <li>AI-powered fix suggestions</li>
            <li>Multi-language support</li>
            <li>Integration capabilities</li>
          </ul>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">3. Free Trial</h2>
          <p className="text-gray-700 mb-4">
            We offer a 7-day free trial with limited functionality (100 scans). During the trial period, you may upgrade to a paid plan at any time. If you do not upgrade, access to premium features will be restricted after the trial expires.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">4. Billing and Payment</h2>
          <p className="text-gray-700 mb-4">
            Paid plans are billed monthly or annually in advance. All fees are non-refundable except as required by law. We use Stripe for secure payment processing.
          </p>
          <p className="text-gray-700 mb-4">
            <strong>Volume Discounts:</strong> Automatic discounts apply based on team size:
          </p>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li>1-10 seats: $15/user/month</li>
            <li>11-50 seats: $12/user/month</li>
            <li>51-200 seats: $10/user/month</li>
            <li>200+ seats: $8/user/month</li>
          </ul>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">5. License and Usage</h2>
          <p className="text-gray-700 mb-4">
            Each user receives an individual license bound to their machine. Licenses are non-transferable and may not be shared between users or devices.
          </p>
          <p className="text-gray-700 mb-4">
            You may not:
          </p>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li>Reverse engineer or decompile the software</li>
            <li>Use the service for illegal activities</li>
            <li>Share login credentials or licenses</li>
            <li>Exceed fair usage limits</li>
          </ul>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">6. Data Privacy</h2>
          <p className="text-gray-700 mb-4">
            We take your privacy seriously. All code analysis happens locally on your machine. We do not store or transmit your source code. See our Privacy Policy for complete details.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">7. Termination</h2>
          <p className="text-gray-700 mb-4">
            Either party may terminate this agreement at any time. Upon termination, your access to premium features will cease, but you may continue using free features.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">8. Disclaimer</h2>
          <p className="text-gray-700 mb-4">
            Valid8 is provided "as is" without warranties of any kind. While we strive for accuracy, automated security scanning cannot guarantee the detection of all vulnerabilities. Users should not rely solely on automated tools for security assessment.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">9. Limitation of Liability</h2>
          <p className="text-gray-700 mb-4">
            Valid8's liability is limited to the amount paid for the service in the 12 months preceding the claim. We are not liable for any indirect, incidental, or consequential damages.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">10. Contact Information</h2>
          <p className="text-gray-700 mb-4">
            For questions about these terms, contact us at:
          </p>
          <ul className="list-disc pl-6 text-gray-700">
            <li>Email: legal@valid8.dev</li>
            <li>Support: support@valid8.dev</li>
          </ul>
        </section>
      </div>
    </div>
  );
};

export default TermsOfService;
