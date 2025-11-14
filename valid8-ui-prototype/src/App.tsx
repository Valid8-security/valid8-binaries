import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navigation from './components/Navigation';
import HeroSection from './components/HeroSection';
import PricingSection from './components/PricingSection';
import TermsOfService from './components/TermsOfService';
import PrivacyPolicy from './components/PrivacyPolicy';
import SuccessPage from './components/SuccessPage';
import CancelPage from './components/CancelPage';
import TrialSuccessPage from './components/TrialSuccessPage';
import AboutPage from './components/AboutPage';
import FeaturesPage from './components/FeaturesPage';
import FAQPage from './components/FAQPage';
import ContactPage from './components/ContactPage';
import DownloadModal from './components/DownloadModal';
import ErrorBoundary from './components/ErrorBoundary';
import { validateConfiguration } from './utils/config';

function HomePage() {
  const [isDownloadModalOpen, setIsDownloadModalOpen] = useState(false);

  return (
    <>
      <HeroSection onDownloadClick={() => setIsDownloadModalOpen(true)} />
      <PricingSection />
      <DownloadModal
        isOpen={isDownloadModalOpen}
        onClose={() => setIsDownloadModalOpen(false)}
      />
    </>
  );
}

function App() {
  useEffect(() => {
    // Validate configuration on app startup
    const { isValid, warnings } = validateConfiguration();

    if (!isValid && warnings.length > 0) {
      console.warn('Configuration warnings:', warnings);

      // In development, show warnings in console
      if (import.meta.env.DEV) {
        console.group('🚨 Configuration Issues');
        warnings.forEach(warning => console.warn('⚠️', warning));
        console.groupEnd();
      }
    }
  }, []);

  return (
    <ErrorBoundary>
      <Router>
        <div className="min-h-screen bg-gray-50">
          <Navigation />
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/about" element={<AboutPage />} />
            <Route path="/features" element={<FeaturesPage />} />
            <Route path="/faq" element={<FAQPage />} />
            <Route path="/contact" element={<ContactPage />} />
            <Route path="/terms" element={<TermsOfService />} />
            <Route path="/privacy" element={<PrivacyPolicy />} />
            <Route path="/success" element={<SuccessPage />} />
            <Route path="/cancel" element={<CancelPage />} />
            <Route path="/trial-success" element={<TrialSuccessPage />} />
          </Routes>

          {/* Footer */}
          <footer className="bg-white border-t border-gray-200 mt-20">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
              <div className="grid md:grid-cols-4 gap-8 mb-8">
                {/* Company */}
                <div>
                  <div className="flex items-center mb-4">
                    <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center mr-2">
                      <span className="text-white font-bold text-sm">V8</span>
                    </div>
                    <span className="text-lg font-bold text-gray-900">Valid8</span>
                  </div>
                  <p className="text-gray-600 text-sm mb-4">
                    Enterprise-grade security scanning with AI-powered fixes.
                    Built for modern development teams.
                  </p>
                  <div className="flex space-x-4">
                    <a href="#" className="text-gray-400 hover:text-gray-600">
                      <span className="sr-only">Twitter</span>
                      <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
                      </svg>
                    </a>
                    <a href="#" className="text-gray-400 hover:text-gray-600">
                      <span className="sr-only">GitHub</span>
                      <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                        <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd"/>
                      </svg>
                    </a>
                  </div>
                </div>

                {/* Product */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 uppercase tracking-wider mb-4">
                    Product
                  </h3>
                  <ul className="space-y-2">
                    <li><a href="/features" className="text-gray-600 hover:text-gray-900 text-sm">Features</a></li>
                    <li><a href="/#pricing" className="text-gray-600 hover:text-gray-900 text-sm">Pricing</a></li>
                    <li><a href="/docs" className="text-gray-600 hover:text-gray-900 text-sm">Documentation</a></li>
                    <li><a href="/faq" className="text-gray-600 hover:text-gray-900 text-sm">FAQ</a></li>
                  </ul>
                </div>

                {/* Company */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 uppercase tracking-wider mb-4">
                    Company
                  </h3>
                  <ul className="space-y-2">
                    <li><a href="/about" className="text-gray-600 hover:text-gray-900 text-sm">About</a></li>
                    <li><a href="/contact" className="text-gray-600 hover:text-gray-900 text-sm">Contact</a></li>
                    <li><a href="mailto:careers@valid8.dev" className="text-gray-600 hover:text-gray-900 text-sm">Careers</a></li>
                    <li><a href="/blog" className="text-gray-600 hover:text-gray-900 text-sm">Blog</a></li>
                  </ul>
                </div>

                {/* Support */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 uppercase tracking-wider mb-4">
                    Support
                  </h3>
                  <ul className="space-y-2">
                    <li><a href={`mailto:${import.meta.env.VITE_SUPPORT_EMAIL || 'support@valid8.dev'}`} className="text-gray-600 hover:text-gray-900 text-sm">Help Center</a></li>
                    <li><a href="/contact" className="text-gray-600 hover:text-gray-900 text-sm">Contact Us</a></li>
                    <li><a href="/privacy" className="text-gray-600 hover:text-gray-900 text-sm">Privacy</a></li>
                    <li><a href="/terms" className="text-gray-600 hover:text-gray-900 text-sm">Terms</a></li>
                  </ul>
                </div>
              </div>

              <div className="border-t border-gray-200 pt-8">
                <div className="flex flex-col md:flex-row justify-between items-center">
                  <p className="text-gray-600 text-sm">
                    &copy; 2024 Valid8 Security. All rights reserved.
                  </p>
                  <div className="mt-4 md:mt-0 flex space-x-6">
                    <a href="/privacy" className="text-gray-600 hover:text-gray-900 text-sm">
                      Privacy Policy
                    </a>
                    <a href="/terms" className="text-gray-600 hover:text-gray-900 text-sm">
                      Terms of Service
                    </a>
                    <a href={`mailto:${import.meta.env.VITE_SUPPORT_EMAIL || 'support@valid8.dev'}`} className="text-gray-600 hover:text-gray-900 text-sm">
                      Support
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </footer>
        </div>
      </Router>
    </ErrorBoundary>
  );
}

export default App;
