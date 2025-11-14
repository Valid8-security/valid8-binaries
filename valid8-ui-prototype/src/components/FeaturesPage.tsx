import React from 'react';
import { Shield, Zap, Brain, Code, Cloud, Users, CheckCircle, ArrowRight, Play } from 'lucide-react';

const FeaturesPage: React.FC = () => {
  const coreFeatures = [
    {
      icon: Brain,
      title: "AI-Powered Detection",
      description: "Advanced machine learning algorithms identify vulnerabilities with 92.3% recall and 100% precision.",
      details: [
        "Context-aware vulnerability detection",
        "False positive elimination",
        "Multi-language support (Python, Java, JavaScript, Go, etc.)",
        "OWASP Top 10 coverage"
      ]
    },
    {
      icon: Zap,
      title: "Automated Fixes",
      description: "Don't just find problems—solve them instantly with AI-generated code patches.",
      details: [
        "One-click vulnerability remediation",
        "Multiple fix options for different scenarios",
        "Safe code transformation",
        "Integration with existing workflows"
      ]
    },
    {
      icon: Shield,
      title: "Privacy-First Architecture",
      description: "All scanning happens locally on your infrastructure. Your code never leaves your environment.",
      details: [
        "100% local processing",
        "No cloud dependencies",
        "Enterprise security compliance",
        "GDPR and SOC2 ready"
      ]
    }
  ];

  const additionalFeatures = [
    {
      icon: Code,
      title: "Multi-Language Support",
      languages: ["Python", "Java", "JavaScript", "TypeScript", "Go", "Rust", "PHP", "C++"],
      description: "Comprehensive support for modern development stacks"
    },
    {
      icon: Cloud,
      title: "CI/CD Integration",
      integrations: ["GitHub Actions", "GitLab CI", "Jenkins", "CircleCI", "Azure DevOps"],
      description: "Seamlessly integrate security into your development pipeline"
    },
    {
      icon: Users,
      title: "Team Collaboration",
      features: ["Shared security policies", "Team dashboards", "Audit trails", "Compliance reporting"],
      description: "Scale security practices across your entire organization"
    }
  ];

  const stats = [
    { number: "92.3%", label: "Detection Accuracy", description: "Industry-leading recall rate" },
    { number: "75.6", label: "Files/Second", description: "Lightning-fast scanning speed" },
    { number: "900+", label: "Vulnerabilities", description: "CWE coverage" },
    { number: "8", label: "Languages", description: "Supported programming languages" }
  ];

  const useCases = [
    {
      title: "Rapid Development Teams",
      description: "Keep development velocity high while maintaining security standards",
      benefits: ["Automated security checks", "Zero false positives", "Instant fix generation"]
    },
    {
      title: "Enterprise Compliance",
      description: "Meet regulatory requirements with comprehensive security reporting",
      benefits: ["Audit-ready reports", "Compliance dashboards", "Multi-framework support"]
    },
    {
      title: "Open Source Projects",
      description: "Ensure code quality and security for community-driven development",
      benefits: ["Free tier available", "CI/CD integration", "Community support"]
    }
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Hero Section */}
      <div className="bg-gradient-to-br from-blue-600 to-blue-800 text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
          <div className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold mb-6">
              Enterprise-Grade Security
              <span className="block text-blue-200">Made Simple</span>
            </h1>
            <p className="text-xl text-blue-100 max-w-3xl mx-auto mb-8">
              Valid8 combines the power of AI with local processing to deliver
              unparalleled security automation that scales with your team.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <a
                href="/"
                onClick={(e) => {
                  setTimeout(() => {
                    document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' });
                  }, 100);
                }}
                className="bg-white text-blue-600 px-8 py-3 rounded-lg hover:bg-blue-50 font-semibold"
              >
                Start Free Trial
              </a>
              <button className="border-2 border-white text-white px-8 py-3 rounded-lg hover:bg-white hover:text-blue-600 font-semibold flex items-center justify-center">
                <Play className="w-4 h-4 mr-2" />
                Watch Demo
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Section */}
      <section className="py-16 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <div key={index} className="text-center">
                <div className="text-4xl md:text-5xl font-bold text-blue-600 mb-2">
                  {stat.number}
                </div>
                <div className="text-xl font-semibold text-gray-900 mb-1">
                  {stat.label}
                </div>
                <div className="text-gray-600">
                  {stat.description}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Core Features */}
      <section className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Core Features
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Everything you need for comprehensive application security
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {coreFeatures.map((feature, index) => (
              <div key={index} className="bg-white p-8 rounded-lg shadow-sm">
                <div className="w-16 h-16 bg-blue-100 rounded-lg flex items-center justify-center mb-6">
                  <feature.icon className="w-8 h-8 text-blue-600" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-4">
                  {feature.title}
                </h3>
                <p className="text-gray-600 mb-6">
                  {feature.description}
                </p>
                <ul className="space-y-2">
                  {feature.details.map((detail, detailIndex) => (
                    <li key={detailIndex} className="flex items-center text-sm text-gray-600">
                      <CheckCircle className="w-4 h-4 text-green-500 mr-2 flex-shrink-0" />
                      {detail}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Additional Features */}
      <section className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Built for Modern Development
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Integrates seamlessly with your existing tools and workflows
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {additionalFeatures.map((feature, index) => (
              <div key={index} className="text-center">
                <div className="w-16 h-16 bg-green-100 rounded-lg flex items-center justify-center mx-auto mb-6">
                  <feature.icon className="w-8 h-8 text-green-600" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-4">
                  {feature.title}
                </h3>
                <p className="text-gray-600 mb-6">
                  {feature.description}
                </p>
                <div className="flex flex-wrap justify-center gap-2">
                  {feature.languages?.map((lang, langIndex) => (
                    <span key={langIndex} className="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-sm">
                      {lang}
                    </span>
                  ))}
                  {feature.integrations?.map((integration, intIndex) => (
                    <span key={intIndex} className="bg-purple-100 text-purple-800 px-3 py-1 rounded-full text-sm">
                      {integration}
                    </span>
                  ))}
                  {feature.features?.map((feat, featIndex) => (
                    <span key={featIndex} className="bg-green-100 text-green-800 px-3 py-1 rounded-full text-sm">
                      {feat}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Use Cases */}
      <section className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Perfect For Every Team
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              From startups to enterprises, Valid8 adapts to your security needs
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {useCases.map((useCase, index) => (
              <div key={index} className="bg-white p-8 rounded-lg shadow-sm">
                <h3 className="text-xl font-semibold text-gray-900 mb-4">
                  {useCase.title}
                </h3>
                <p className="text-gray-600 mb-6">
                  {useCase.description}
                </p>
                <ul className="space-y-2">
                  {useCase.benefits.map((benefit, benefitIndex) => (
                    <li key={benefitIndex} className="flex items-center text-sm text-gray-600">
                      <CheckCircle className="w-4 h-4 text-green-500 mr-2 flex-shrink-0" />
                      {benefit}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 bg-blue-600">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
            Ready to Secure Your Code?
          </h2>
          <p className="text-xl text-blue-100 mb-8">
            Join thousands of developers who trust Valid8 to keep their applications secure.
            Start your free trial today.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a
              href="/"
              onClick={(e) => {
                setTimeout(() => {
                  document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }}
              className="bg-white text-blue-600 px-8 py-3 rounded-lg hover:bg-blue-50 font-semibold"
            >
              Start Free Trial
            </a>
            <a
              href="/contact"
              className="border-2 border-white text-white px-8 py-3 rounded-lg hover:bg-white hover:text-blue-600 font-semibold"
            >
              Contact Sales
            </a>
          </div>
        </div>
      </section>
    </div>
  );
};

export default FeaturesPage;
