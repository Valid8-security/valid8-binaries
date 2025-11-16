import { Brain, Shield, Zap, CheckCircle, Target, Lock } from 'lucide-react';

const FeaturesSection = () => {
  const features = [
    {
      icon: <Brain className="h-8 w-8 text-purple-600" />,
      title: "AI-Powered Analysis",
      description: "Advanced machine learning algorithms detect complex vulnerabilities that traditional tools miss, with contextual understanding of code patterns."
    },
    {
      icon: <Shield className="h-8 w-8 text-blue-600" />,
      title: "95.8% F1-Score Accuracy",
      description: "Industry-leading accuracy validated through extensive benchmarking against OWASP test suites and real-world codebases."
    },
    {
      icon: <Zap className="h-8 w-8 text-green-600" />,
      title: "AI Fix Suggestions",
      description: "Automated remediation recommendations that reduce developer time by 90% with contextually appropriate security fixes."
    },
    {
      icon: <Lock className="h-8 w-8 text-red-600" />,
      title: "100% Local Processing",
      description: "Privacy-first architecture ensures your code never leaves your environment. No external data transmission or cloud dependencies."
    },
    {
      icon: <Target className="h-8 w-8 text-orange-600" />,
      title: "Multi-Language Support",
      description: "Comprehensive support for Python, JavaScript, Java, Go, TypeScript, and more with language-specific security analysis."
    },
    {
      icon: <CheckCircle className="h-8 w-8 text-teal-600" />,
      title: "Enterprise-Grade Security",
      description: "Hardware-bound licensing, tamper detection, and cryptographic verification ensure secure deployment in enterprise environments."
    }
  ];

  return (
    <section id="features" className="py-20 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
            Revolutionary AI-Powered Security
          </h2>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Valid8 combines cutting-edge AI with comprehensive security analysis to deliver
            unmatched accuracy and actionable insights for modern development teams.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <div key={index} className="bg-gray-50 p-8 rounded-lg hover:shadow-lg transition-shadow">
              <div className="flex items-center justify-center mb-4">
                {feature.icon}
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-3 text-center">
                {feature.title}
              </h3>
              <p className="text-gray-600 text-center leading-relaxed">
                {feature.description}
              </p>
            </div>
          ))}
        </div>

        <div className="mt-16 text-center">
          <div className="bg-gradient-to-r from-blue-50 to-purple-50 border border-blue-200 rounded-lg p-8 max-w-4xl mx-auto">
            <h3 className="text-2xl font-bold text-gray-900 mb-4">
              Validated Performance
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="text-3xl font-bold text-blue-600 mb-2">95.8%</div>
                <div className="text-gray-600">F1-Score Accuracy</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-green-600 mb-2">90%</div>
                <div className="text-gray-600">Time Saved on Fixes</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-purple-600 mb-2">100%</div>
                <div className="text-gray-600">Local Processing</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
