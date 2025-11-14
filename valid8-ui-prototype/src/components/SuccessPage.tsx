import React, { useEffect, useState } from 'react';
import { CheckCircle, Download, Mail, ArrowRight } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

const SuccessPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [licenseKey, setLicenseKey] = useState<string>('');
  const [emailSent, setEmailSent] = useState(false);

  const sessionId = searchParams.get('session_id');
  const tier = searchParams.get('tier') || 'subscription';

  useEffect(() => {
    // In a real implementation, this would:
    // 1. Verify the Stripe session
    // 2. Create user account
    // 3. Generate and store license key
    // 4. Send welcome email

    // For demo purposes, generate a mock license key
    const mockLicenseKey = `VALID8-${tier.toUpperCase()}-${Math.random().toString(36).substring(2, 15).toUpperCase()}`;
    setLicenseKey(mockLicenseKey);

    // Simulate email sending
    setTimeout(() => {
      setEmailSent(true);
    }, 2000);
  }, [tier]);

  const handleCopyLicense = () => {
    navigator.clipboard.writeText(licenseKey);
    alert('License key copied to clipboard!');
  };

  const handleDownloadCli = () => {
    // In real implementation, this would trigger CLI download
    alert('CLI download would start here. For now, use: pip install valid8-scanner');
  };

  return (
    <div className="min-h-screen bg-gray-50 py-16">
      <div className="max-w-4xl mx-auto px-4">
        {/* Success Header */}
        <div className="text-center mb-12">
          <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-6">
            <CheckCircle className="w-12 h-12 text-green-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-4">
            Welcome to Valid8! 🎉
          </h1>
          <p className="text-xl text-gray-600">
            Your {tier} subscription is now active. Here's everything you need to get started.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-8 mb-12">
          {/* License Key Section */}
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
              <Download className="w-5 h-5 mr-2 text-blue-600" />
              Your License Key
            </h2>
            <p className="text-gray-600 mb-4">
              Save this license key securely. You'll need it to activate Valid8 on your systems.
            </p>
            <div className="bg-gray-50 rounded-lg p-4 font-mono text-sm mb-4">
              {licenseKey || 'Generating license key...'}
            </div>
            <button
              onClick={handleCopyLicense}
              disabled={!licenseKey}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              Copy License Key
            </button>
          </div>

          {/* Email Confirmation */}
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
              <Mail className="w-5 h-5 mr-2 text-green-600" />
              Confirmation Email
            </h2>
            <p className="text-gray-600 mb-4">
              We've sent a confirmation email with your license details, installation guide, and next steps.
            </p>
            <div className="flex items-center text-sm text-gray-600">
              {emailSent ? (
                <>
                  <CheckCircle className="w-4 h-4 text-green-600 mr-2" />
                  Email sent successfully!
                </>
              ) : (
                <>
                  <div className="w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mr-2"></div>
                  Sending confirmation email...
                </>
              )}
            </div>
          </div>
        </div>

        {/* Installation Steps */}
        <div className="bg-white rounded-lg shadow-sm border p-8 mb-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-6">
            🚀 Get Started in 3 Steps
          </h2>

          <div className="space-y-6">
            <div className="flex items-start">
              <div className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-semibold mr-4 flex-shrink-0">
                1
              </div>
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-2">Install Valid8 CLI</h3>
                <p className="text-gray-600 mb-3">
                  Download and install the Valid8 command-line scanner on your development machine.
                </p>
                <button
                  onClick={handleDownloadCli}
                  className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 inline-flex items-center"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download CLI
                </button>
              </div>
            </div>

            <div className="flex items-start">
              <div className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-semibold mr-4 flex-shrink-0">
                2
              </div>
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-2">Activate Your License</h3>
                <p className="text-gray-600 mb-3">
                  Use your license key to activate Valid8 and unlock all premium features.
                </p>
                <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm">
                  valid8 activate {licenseKey || 'YOUR_LICENSE_KEY'}
                </div>
              </div>
            </div>

            <div className="flex items-start">
              <div className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-semibold mr-4 flex-shrink-0">
                3
              </div>
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-2">Scan Your First Project</h3>
                <p className="text-gray-600 mb-3">
                  Run your first security scan and see Valid8 in action.
                </p>
                <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm">
                  valid8 scan /path/to/your/project
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Resources Section */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-8 mb-8">
          <h2 className="text-2xl font-semibold text-blue-900 mb-6">
            📚 Resources & Next Steps
          </h2>

          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-lg font-medium text-blue-900 mb-3">Documentation</h3>
              <ul className="space-y-2 text-blue-800">
                <li><a href="#" className="hover:underline">Quick Start Guide</a></li>
                <li><a href="#" className="hover:underline">CLI Reference</a></li>
                <li><a href="#" className="hover:underline">Integration Guides</a></li>
              </ul>
            </div>

            <div>
              <h3 className="text-lg font-medium text-blue-900 mb-3">Support</h3>
              <ul className="space-y-2 text-blue-800">
                <li><a href="mailto:support@valid8.dev" className="hover:underline">Email Support</a></li>
                <li><a href="#" className="hover:underline">Community Forum</a></li>
                <li><a href="#" className="hover:underline">Video Tutorials</a></li>
              </ul>
            </div>
          </div>
        </div>

        {/* CTA */}
        <div className="text-center">
          <p className="text-gray-600 mb-4">
            Questions? We're here to help you succeed with Valid8.
          </p>
          <div className="space-x-4">
            <a
              href="mailto:support@valid8.dev"
              className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 inline-flex items-center"
            >
              Get Support
              <ArrowRight className="w-4 h-4 ml-2" />
            </a>
            <a
              href="/docs"
              className="bg-white text-blue-600 border border-blue-600 px-6 py-3 rounded-lg hover:bg-blue-50"
            >
              View Documentation
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SuccessPage;
