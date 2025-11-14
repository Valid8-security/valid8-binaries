import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const Navigation: React.FC = () => {
  const location = useLocation();

  return (
    <nav className="bg-white shadow-sm border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <Link to="/" className="flex items-center">
              <div className="flex items-center space-x-2">
                <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                  <span className="text-white font-bold text-sm">V8</span>
                </div>
                <span className="text-xl font-bold text-gray-900">Valid8</span>
              </div>
            </Link>
          </div>

          <div className="flex items-center space-x-6">
            <Link
              to="/"
              className={`text-sm font-medium ${
                location.pathname === '/'
                  ? 'text-blue-600'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Home
            </Link>
            <Link
              to="/features"
              className={`text-sm font-medium ${
                location.pathname === '/features'
                  ? 'text-blue-600'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Features
            </Link>
            <Link
              to="/about"
              className={`text-sm font-medium ${
                location.pathname === '/about'
                  ? 'text-blue-600'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              About
            </Link>
            <a
              href="#pricing"
              className="text-sm font-medium text-gray-600 hover:text-gray-900"
              onClick={(e) => {
                if (location.pathname === '/') {
                  e.preventDefault();
                  document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' });
                } else {
                  // Navigate to home and scroll
                  window.location.href = '/#pricing';
                }
              }}
            >
              Pricing
            </a>
            <Link
              to="/faq"
              className={`text-sm font-medium ${
                location.pathname === '/faq'
                  ? 'text-blue-600'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              FAQ
            </Link>
            <Link
              to="/contact"
              className={`text-sm font-medium ${
                location.pathname === '/contact'
                  ? 'text-blue-600'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Contact
            </Link>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
