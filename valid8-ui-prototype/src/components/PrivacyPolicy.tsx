import React from 'react';

const PrivacyPolicy: React.FC = () => {
  return (
    <div className="max-w-4xl mx-auto px-4 py-16">
      <h1 className="text-3xl font-bold text-gray-900 mb-8">Privacy Policy</h1>

      <div className="prose prose-lg max-w-none">
        <p className="text-gray-600 mb-6">
          <strong>Last updated:</strong> {new Date().toLocaleDateString()}
        </p>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">1. Our Commitment to Privacy</h2>
          <p className="text-gray-700 mb-4">
            At Valid8, we take your privacy seriously. Our core principle is that your code stays yours. We designed Valid8 to perform all security analysis locally on your machine, ensuring your source code never leaves your environment.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">2. Data We Don't Collect</h2>
          <p className="text-gray-700 mb-4">
            Valid8 is fundamentally different from cloud-based security tools:
          </p>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li><strong>No source code storage:</strong> Your code never leaves your machine</li>
            <li><strong>No file uploads:</strong> All analysis happens locally</li>
            <li><strong>No cloud processing:</strong> Everything runs on your hardware</li>
            <li><strong>No data transmission:</strong> Results stay on your device</li>
          </ul>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">3. Data We Do Collect</h2>
          <p className="text-gray-700 mb-4">
            We only collect minimal data necessary for service operation:
          </p>

          <h3 className="text-xl font-medium text-gray-900 mb-3">Required for Licensing:</h3>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li>Machine fingerprint (hardware ID for license binding)</li>
            <li>License activation status</li>
            <li>License tier and expiration</li>
          </ul>

          <h3 className="text-xl font-medium text-gray-900 mb-3">Optional Analytics (With Consent):</h3>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li>Usage statistics (anonymized)</li>
            <li>Error reports (for debugging)</li>
            <li>Feature usage patterns</li>
          </ul>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">4. How We Use Data</h2>
          <p className="text-gray-700 mb-4">
            We use collected data solely for:
          </p>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li><strong>License validation:</strong> Ensuring legitimate usage</li>
            <li><strong>Service improvement:</strong> Understanding how features are used</li>
            <li><strong>Support:</strong> Helping users with issues</li>
            <li><strong>Analytics:</strong> Measuring product success (aggregated only)</li>
          </ul>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">5. Data Storage and Security</h2>
          <p className="text-gray-700 mb-4">
            All data is stored securely:
          </p>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li><strong>Local storage only:</strong> License data stored in ~/.valid8/</li>
            <li><strong>Encrypted:</strong> Sensitive data is encrypted at rest</li>
            <li><strong>No third-party sharing:</strong> We don't sell or share your data</li>
            <li><strong>Minimal retention:</strong> Data kept only as long as necessary</li>
          </ul>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">6. Payment Information</h2>
          <p className="text-gray-700 mb-4">
            Payment processing is handled by Stripe, our PCI-compliant payment processor. We do not store credit card information. Stripe's privacy policy applies to payment data.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">7. Third-Party Services</h2>
          <p className="text-gray-700 mb-4">
            Valid8 integrates with optional third-party services:
          </p>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li><strong>Stripe:</strong> Payment processing (see their privacy policy)</li>
            <li><strong>GitHub:</strong> Optional integration for CI/CD</li>
            <li><strong>Analytics:</strong> Optional usage tracking (Google Analytics)</li>
          </ul>
          <p className="text-gray-700 mb-4">
            All third-party integrations are optional and require explicit user consent.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">8. Your Rights</h2>
          <p className="text-gray-700 mb-4">
            Under applicable privacy laws, you have the right to:
          </p>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li><strong>Access:</strong> Request what data we have about you</li>
            <li><strong>Deletion:</strong> Request removal of your data</li>
            <li><strong>Portability:</strong> Export your data in standard format</li>
            <li><strong>Opt-out:</strong> Disable analytics and optional data collection</li>
          </ul>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">9. Data Retention</h2>
          <p className="text-gray-700 mb-4">
            We retain data only as long as necessary:
          </p>
          <ul className="list-disc pl-6 text-gray-700 mb-4">
            <li><strong>License data:</strong> Kept during active subscription + 7 years for tax purposes</li>
            <li><strong>Analytics:</strong> Aggregated and anonymized, retained indefinitely</li>
            <li><strong>Support data:</strong> Deleted after issue resolution</li>
          </ul>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">10. International Data Transfers</h2>
          <p className="text-gray-700 mb-4">
            Since all processing happens locally on your device, there are no international data transfers of your code or sensitive information. License validation may involve minimal data transfer to our servers.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">11. Changes to This Policy</h2>
          <p className="text-gray-700 mb-4">
            We will notify users of material changes to this privacy policy via email or in-app notifications. Continued use of Valid8 constitutes acceptance of the updated policy.
          </p>
        </section>

        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">12. Contact Us</h2>
          <p className="text-gray-700 mb-4">
            For privacy-related questions or requests:
          </p>
          <ul className="list-disc pl-6 text-gray-700">
            <li>Email: privacy@valid8.dev</li>
            <li>Support: support@valid8.dev</li>
            <li>Mailing: Valid8 Security, Seattle, WA</li>
          </ul>
        </section>

        <div className="mt-12 p-6 bg-blue-50 border border-blue-200 rounded-lg">
          <h3 className="text-lg font-semibold text-blue-900 mb-3">🔒 Our Privacy Promise</h3>
          <p className="text-blue-800">
            Unlike cloud-based security tools, Valid8 never sees or stores your source code. Your intellectual property stays completely private and secure on your own infrastructure.
          </p>
        </div>
      </div>
    </div>
  );
};

export default PrivacyPolicy;
