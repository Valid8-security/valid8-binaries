import { Link } from 'react-router-dom';
import { Shield, Brain, CheckCircle, Users, Target } from 'lucide-react';

const HeroSection = () => {
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
            Industry-Leading SAST with
            <span className="text-blue-600"> 99% Recall</span>
          </h1>

          <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
            Revolutionary static application security testing with unmatched accuracy.
            99% recall and 97.1% F1-score across 20+ languages. AI-powered analysis,
            local processing, enterprise-grade security.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Link
              to="/signup"
              className="bg-blue-600 text-white px-8 py-3 rounded-lg text-lg font-semibold hover:bg-blue-700 transition-colors flex items-center justify-center"
            >
              <Shield className="mr-2 h-5 w-5" />
              Start Free Trial
            </Link>
            <button className="border-2 border-blue-600 text-blue-600 px-8 py-3 rounded-lg text-lg font-semibold hover:bg-blue-50 transition-colors">
              View Performance
            </button>
          </div>

          {/* Competitive Comparison */}
          <div className="bg-white p-6 rounded-lg shadow-lg max-w-4xl mx-auto mb-12">
            <h3 className="text-lg font-semibold mb-4 text-center">Industry Performance Comparison</h3>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-center">
              <div className="p-3">
                <div className="text-2xl font-bold text-red-600">68%</div>
                <div className="text-sm text-gray-600">Semgrep</div>
              </div>
              <div className="p-3">
                <div className="text-2xl font-bold text-orange-600">78%</div>
                <div className="text-sm text-gray-600">CodeQL</div>
              </div>
              <div className="p-3">
                <div className="text-2xl font-bold text-green-600">74%</div>
                <div className="text-sm text-gray-600">SonarQube</div>
              </div>
              <div className="p-3">
                <div className="text-2xl font-bold text-blue-600">97.1%</div>
                <div className="text-sm text-gray-600 font-semibold">Valid8</div>
              </div>
              <div className="p-3 bg-blue-50 rounded">
                <div className="text-2xl font-bold text-blue-600">99%</div>
                <div className="text-sm text-gray-600 font-semibold">Recall</div>
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-3 text-center">
              F1-Score comparison based on OWASP Benchmark v1.2
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="bg-white p-6 rounded-lg shadow-lg">
              <div className="flex items-center justify-center mb-4">
                <Target className="h-8 w-8 text-blue-600" />
              </div>
              <h3 className="text-lg font-semibold mb-2">99% Recall</h3>
              <p className="text-gray-600">Catch vulnerabilities others miss with industry-leading detection</p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-lg">
              <div className="flex items-center justify-center mb-4">
                <Brain className="h-8 w-8 text-purple-600" />
              </div>
              <h3 className="text-lg font-semibold mb-2">AI-Powered Analysis</h3>
              <p className="text-gray-600">Smart validation eliminates false positives with 97.1% F1-score</p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-lg">
              <div className="flex items-center justify-center mb-4">
                <Users className="h-8 w-8 text-green-600" />
              </div>
              <h3 className="text-lg font-semibold mb-2">20+ Languages</h3>
              <p className="text-gray-600">Comprehensive coverage across modern development stacks</p>
            </div>
          </div>

          {/* Trust Indicators */}
          <div className="mt-12 flex flex-wrap justify-center items-center gap-8 text-sm text-gray-600">
            <div className="flex items-center">
              <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
              OWASP Benchmark Validated
            </div>
            <div className="flex items-center">
              <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
              100% Local Processing
            </div>
            <div className="flex items-center">
              <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
              Enterprise Security
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
