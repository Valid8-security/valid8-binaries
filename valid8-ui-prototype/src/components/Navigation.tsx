import React from 'react';
import { Shield } from 'lucide-react';

const Navigation = () => {
  return (
    <nav className="bg-white shadow-sm border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center">
            <Shield className="h-8 w-8 text-blue-600" />
            <span className="ml-2 text-xl font-bold text-gray-900">Valid8</span>
          </div>
          <div className="hidden md:flex items-center space-x-8">
            <a href="#features" className="text-gray-600 hover:text-blue-600 transition-colors">Features</a>
            <a href="#pricing" className="text-gray-600 hover:text-blue-600 transition-colors">Pricing</a>
            <a href="https://github.com/Valid8-security/parry-scanner" className="text-gray-600 hover:text-blue-600 transition-colors">GitHub</a>
            <a href="https://github.com/Valid8-security/parry-scanner/blob/main/README.md" className="text-gray-600 hover:text-blue-600 transition-colors">Docs</a>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
