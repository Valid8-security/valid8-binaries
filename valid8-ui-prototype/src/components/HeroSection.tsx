import React, { useState } from 'react';
import { Shield, Zap, Brain, CheckCircle, Download } from 'lucide-react';
import DownloadModal from './DownloadModal';

const HeroSection = () => {
  const [isDownloadModalOpen, setIsDownloadModalOpen] = useState(false);

  return (
    <section className="py-20 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="text-center">
          <div className="flex justify-center mb-8">
            <div className="bg-blue-100 p-4 rounded-full">
              <Shield className="h-16 w-16 text-blue-600" />
            </div>
          </div>

          <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
            AI-Powered SAST with
            <span className="text-blue-600"> 95%+ Accuracy</span>
          </h1>

          <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
            Revolutionary static application security testing that combines unmatched accuracy
            with AI-powered fix suggestions. Local processing, enterprise-grade security.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <button
              onClick={() => setIsDownloadModalOpen(true)}
              className="bg-blue-600 text-white px-8 py-3 rounded-lg text-lg font-semibold hover:bg-blue-700 transition-colors flex items-center justify-center"
            >
              <Download className="mr-2 h-5 w-5" />
              Start Free Trial
            </button>
            <button className="border-2 border-blue-600 text-blue-600 px-8 py-3 rounded-lg text-lg font-semibold hover:bg-blue-50 transition-colors">
              Watch Demo
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="bg-white p-6 rounded-lg shadow-lg">
              <div className="flex items-center justify-center mb-4">
                <Brain className="h-8 w-8 text-purple-600" />
              </div>
              <h3 className="text-lg font-semibold mb-2">95.8% F1-Score</h3>
              <p className="text-gray-600">Industry-leading accuracy with statistical validation</p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-lg">
              <div className="flex items-center justify-center mb-4">
                <Zap className="h-8 w-8 text-green-600" />
              </div>
              <h3 className="text-lg font-semibold mb-2">AI Fix Suggestions</h3>
              <p className="text-gray-600">Automated remediation reduces developer time by 90%</p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-lg">
              <div className="flex items-center justify-center mb-4">
                <Shield className="h-8 w-8 text-blue-600" />
              </div>
              <h3 className="text-lg font-semibold mb-2">100% Local</h3>
              <p className="text-gray-600">Privacy-first with no external data transmission</p>
            </div>
          </div>
        </div>
      </div>

      <DownloadModal
        isOpen={isDownloadModalOpen}
        onClose={() => setIsDownloadModalOpen(false)}
      />
    </section>
  );
};

export default HeroSection;
