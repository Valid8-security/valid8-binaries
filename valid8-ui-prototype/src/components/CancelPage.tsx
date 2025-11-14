import React from 'react';
import { XCircle, RefreshCw, MessageCircle, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

const CancelPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50 py-16">
      <div className="max-w-2xl mx-auto px-4 text-center">
        {/* Error Header */}
        <div className="w-20 h-20 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-6">
          <XCircle className="w-12 h-12 text-red-600" />
        </div>

        <h1 className="text-3xl font-bold text-gray-900 mb-4">
          Payment Cancelled
        </h1>

        <p className="text-xl text-gray-600 mb-8">
          No worries! Your payment was cancelled and you haven't been charged.
          You can try again anytime or start with our free trial.
        </p>

        {/* Options */}
        <div className="space-y-4 mb-12">
          <Link
            to="/"
            className="block w-full bg-blue-600 text-white px-6 py-4 rounded-lg hover:bg-blue-700 text-lg font-medium inline-flex items-center justify-center"
          >
            <RefreshCw className="w-5 h-5 mr-3" />
            Try Payment Again
          </Link>

          <Link
            to="/"
            onClick={(e) => {
              // Scroll to download section
              setTimeout(() => {
                document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' });
              }, 100);
            }}
            className="block w-full bg-green-600 text-white px-6 py-4 rounded-lg hover:bg-green-700 text-lg font-medium inline-flex items-center justify-center"
          >
            Start Free Trial Instead
          </Link>
        </div>

        {/* Help Section */}
        <div className="bg-white rounded-lg shadow-sm border p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center justify-center">
            <MessageCircle className="w-5 h-5 mr-2 text-blue-600" />
            Need Help?
          </h2>

          <p className="text-gray-600 mb-6">
            If you encountered any issues during checkout or have questions about pricing,
            our team is here to help.
          </p>

          <div className="space-y-3">
            <a
              href="mailto:support@valid8.dev?subject=Payment%20Help"
              className="block w-full bg-blue-50 text-blue-700 px-4 py-3 rounded-lg hover:bg-blue-100 text-center"
            >
              Contact Support
            </a>

            <a
              href="mailto:sales@valid8.dev?subject=Pricing%20Questions"
              className="block w-full bg-gray-50 text-gray-700 px-4 py-3 rounded-lg hover:bg-gray-100 text-center"
            >
              Sales Inquiry
            </a>
          </div>

          <div className="mt-6 pt-6 border-t border-gray-200">
            <p className="text-sm text-gray-500">
              Common issues: Try a different payment method, check your card details,
              or ensure your bank allows international transactions.
            </p>
          </div>
        </div>

        {/* Back to Home */}
        <div className="mt-8">
          <Link
            to="/"
            className="text-blue-600 hover:text-blue-800 inline-flex items-center"
          >
            <ArrowRight className="w-4 h-4 mr-2 transform rotate-180" />
            Back to Valid8
          </Link>
        </div>
      </div>
    </div>
  );
};

export default CancelPage;
