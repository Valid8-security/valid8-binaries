import React, { useState } from 'react';
import { CheckCircle, Download, Zap, Users, BookOpen, MessageCircle, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

const TrialSuccessPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [emailSubmitted, setEmailSubmitted] = useState(false);

  const handleEmailSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // In real implementation, this would send email to backend
    setEmailSubmitted(true);
    // Simulate API call
    setTimeout(() => {
      alert('Welcome email sent! Check your inbox for next steps.');
    }, 1000);
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
          <p className="text-xl text-gray-600 mb-6">
            Your 7-day free trial is now active. Here's how to make the most of it.
          </p>

          {/* Trial Status */}
          <div className="bg-green-50 border border-green-200 rounded-lg p-4 inline-block">
            <div className="flex items-center text-green-800">
              <Zap className="w-5 h-5 mr-2" />
              <span className="font-medium">Trial Active: 7 days remaining</span>
            </div>
          </div>
        </div>

        {/* Email Capture */}
        {!emailSubmitted && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-6 mb-8">
            <h2 className="text-xl font-semibold text-blue-900 mb-3">
              📧 Stay Updated
            </h2>
            <p className="text-blue-800 mb-4">
              Get tips, tutorials, and trial extension offers delivered to your inbox.
            </p>
            <form onSubmit={handleEmailSubmit} className="flex gap-3 max-w-md mx-auto">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="your.email@company.com"
                className="flex-1 px-4 py-2 border border-blue-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                required
              />
              <button
                type="submit"
                className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700"
              >
                Subscribe
              </button>
            </form>
          </div>
        )}

        {emailSubmitted && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-6 mb-8">
            <div className="flex items-center text-green-800">
              <CheckCircle className="w-5 h-5 mr-2" />
              <span>Thanks! Welcome emails are on the way.</span>
            </div>
          </div>
        )}

        {/* Quick Start Guide */}
        <div className="grid md:grid-cols-2 gap-8 mb-12">
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
              <Download className="w-5 h-5 mr-2 text-blue-600" />
              Quick Start (2 minutes)
            </h2>
            <div className="space-y-4">
              <div className="flex items-start">
                <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm font-semibold mr-3 flex-shrink-0 mt-0.5">
                  1
                </div>
                <div>
                  <p className="font-medium text-gray-900">Verify Installation</p>
                  <p className="text-gray-600 text-sm">Run: <code className="bg-gray-100 px-1 py-0.5 rounded text-xs">valid8 --version</code></p>
                </div>
              </div>

              <div className="flex items-start">
                <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm font-semibold mr-3 flex-shrink-0 mt-0.5">
                  2
                </div>
                <div>
                  <p className="font-medium text-gray-900">Scan Your First Project</p>
                  <p className="text-gray-600 text-sm">Run: <code className="bg-gray-100 px-1 py-0.5 rounded text-xs">valid8 scan ./my-project</code></p>
                </div>
              </div>

              <div className="flex items-start">
                <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm font-semibold mr-3 flex-shrink-0 mt-0.5">
                  3
                </div>
                <div>
                  <p className="font-medium text-gray-900">View Results</p>
                  <p className="text-gray-600 text-sm">Check the generated HTML/JSON reports</p>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm border p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
              <Users className="w-5 h-5 mr-2 text-green-600" />
              Maximize Your Trial
            </h2>
            <ul className="space-y-3 text-gray-700">
              <li className="flex items-start">
                <CheckCircle className="w-4 h-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                <span className="text-sm">Scan multiple projects to see comprehensive results</span>
              </li>
              <li className="flex items-start">
                <CheckCircle className="w-4 h-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                <span className="text-sm">Try different output formats (HTML, JSON, CLI)</span>
              </li>
              <li className="flex items-start">
                <CheckCircle className="w-4 h-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                <span className="text-sm">Test various project sizes and languages</span>
              </li>
              <li className="flex items-start">
                <CheckCircle className="w-4 h-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                <span className="text-sm">Compare results with your current security tools</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Trial Limits & Upgrade */}
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6 mb-8">
          <h2 className="text-xl font-semibold text-yellow-900 mb-4">
            ⚡ Trial Limits
          </h2>
          <div className="grid md:grid-cols-3 gap-4 mb-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-900">100</div>
              <div className="text-sm text-yellow-800">Files per scan</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-900">7</div>
              <div className="text-sm text-yellow-800">Days active</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-900">∞</div>
              <div className="text-sm text-yellow-800">Support access</div>
            </div>
          </div>

          <div className="text-center">
            <p className="text-yellow-800 mb-4">
              Ready to unlock unlimited scans and advanced features?
            </p>
            <Link
              to="/"
              onClick={(e) => {
                setTimeout(() => {
                  document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }}
              className="bg-yellow-600 text-white px-6 py-3 rounded-lg hover:bg-yellow-700 inline-flex items-center"
            >
              Upgrade Now
              <ArrowRight className="w-4 h-4 ml-2" />
            </Link>
          </div>
        </div>

        {/* Resources */}
        <div className="bg-white rounded-lg shadow-sm border p-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-6 flex items-center">
            <BookOpen className="w-6 h-6 mr-3 text-blue-600" />
            Resources & Support
          </h2>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="text-center">
              <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-3">
                <BookOpen className="w-6 h-6 text-blue-600" />
              </div>
              <h3 className="font-medium text-gray-900 mb-2">Documentation</h3>
              <p className="text-sm text-gray-600 mb-3">
                Complete guides and API reference
              </p>
              <a href="#" className="text-blue-600 hover:text-blue-800 text-sm">
                View Docs →
              </a>
            </div>

            <div className="text-center">
              <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mx-auto mb-3">
                <MessageCircle className="w-6 h-6 text-green-600" />
              </div>
              <h3 className="font-medium text-gray-900 mb-2">Community</h3>
              <p className="text-sm text-gray-600 mb-3">
                Connect with other Valid8 users
              </p>
              <a href="#" className="text-blue-600 hover:text-blue-800 text-sm">
                Join Forum →
              </a>
            </div>

            <div className="text-center">
              <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mx-auto mb-3">
                <Users className="w-6 h-6 text-purple-600" />
              </div>
              <h3 className="font-medium text-gray-900 mb-2">Team Features</h3>
              <p className="text-sm text-gray-600 mb-3">
                Learn about team plans
              </p>
              <Link to="/" onClick={(e) => {
                setTimeout(() => {
                  document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }} className="text-blue-600 hover:text-blue-800 text-sm">
                View Pricing →
              </Link>
            </div>

            <div className="text-center">
              <div className="w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center mx-auto mb-3">
                <MessageCircle className="w-6 h-6 text-orange-600" />
              </div>
              <h3 className="font-medium text-gray-900 mb-2">Support</h3>
              <p className="text-sm text-gray-600 mb-3">
                Get help from our team
              </p>
              <a href="mailto:support@valid8.dev" className="text-blue-600 hover:text-blue-800 text-sm">
                Contact Us →
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TrialSuccessPage;
