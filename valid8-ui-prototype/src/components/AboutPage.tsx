import React from 'react';
import { Shield, Users, Zap, Award, Target, Heart } from 'lucide-react';

const AboutPage: React.FC = () => {
  const values = [
    {
      icon: Shield,
      title: "Security First",
      description: "We believe security should never be an afterthought. Valid8 makes security automation accessible to every developer."
    },
    {
      icon: Users,
      title: "Developer-Centric",
      description: "Built by developers, for developers. We understand the challenges of modern software development and deliver practical solutions."
    },
    {
      icon: Zap,
      title: "Innovation Driven",
      description: "We leverage cutting-edge AI to solve real-world security problems, making advanced security tools accessible to teams of all sizes."
    }
  ];

  const team = [
    {
      name: "Alex Chen",
      role: "CEO & Co-Founder",
      bio: "Former security engineer at Amazon. Passionate about making security accessible.",
      image: "/api/placeholder/150/150"
    },
    {
      name: "Sarah Johnson",
      role: "CTO & Co-Founder",
      bio: "AI researcher with 8+ years in machine learning. UW Computer Science graduate.",
      image: "/api/placeholder/150/150"
    },
    {
      name: "Marcus Rodriguez",
      role: "Head of Engineering",
      bio: "Full-stack engineer with expertise in scalable security systems.",
      image: "/api/placeholder/150/150"
    }
  ];

  const milestones = [
    { year: "2023", event: "Founded Valid8 with mission to democratize security" },
    { year: "2024", event: "Launched AI-powered vulnerability detection" },
    { year: "2024", event: "Reached 10,000+ scans across beta users" },
    { year: "2024", event: "Public launch with enterprise-grade security" }
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Hero Section */}
      <div className="bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
          <div className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
              Building the Future of
              <span className="text-blue-600 block">Secure Software</span>
            </h1>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto mb-8">
              We're on a mission to make application security accessible to every developer.
              Through AI-powered automation, we're eliminating security bottlenecks and
              enabling teams to build secure software faster than ever before.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <a
                href="/"
                onClick={(e) => {
                  setTimeout(() => {
                    document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' });
                  }, 100);
                }}
                className="bg-blue-600 text-white px-8 py-3 rounded-lg hover:bg-blue-700 font-semibold"
              >
                Start Free Trial
              </a>
              <a
                href="#story"
                className="bg-white text-blue-600 border border-blue-600 px-8 py-3 rounded-lg hover:bg-blue-50 font-semibold"
              >
                Our Story
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Our Story Section */}
      <section id="story" className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Our Story
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              From classroom frustration to industry innovation
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <h3 className="text-2xl font-semibold text-gray-900 mb-6">
                Born from Real-World Problems
              </h3>
              <p className="text-gray-700 mb-6">
                Valid8 started as a class project at the University of Washington. Our founders,
                working on real software projects, kept running into the same frustrating problem:
                security was always treated as an afterthought, causing endless delays and
                manual work that slowed down development.
              </p>
              <p className="text-gray-700 mb-6">
                We realized that existing security tools were either too complex for small teams
                or too expensive for growing companies. There had to be a better way to make
                security automation accessible to everyone.
              </p>
              <p className="text-gray-700">
                That's when we started building Valid8 – an AI-powered security scanner that
                doesn't just find vulnerabilities, but actually fixes them automatically.
              </p>
            </div>

            <div className="bg-gray-50 p-8 rounded-lg">
              <div className="space-y-4">
                {milestones.map((milestone, index) => (
                  <div key={index} className="flex items-start">
                    <div className="w-3 h-3 bg-blue-600 rounded-full mt-2 mr-4 flex-shrink-0"></div>
                    <div>
                      <div className="font-semibold text-gray-900">{milestone.year}</div>
                      <div className="text-gray-600">{milestone.event}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Our Values */}
      <section className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Our Values
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              The principles that guide everything we do
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {values.map((value, index) => (
              <div key={index} className="bg-white p-8 rounded-lg shadow-sm text-center">
                <div className="w-16 h-16 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-6">
                  <value.icon className="w-8 h-8 text-blue-600" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-4">{value.title}</h3>
                <p className="text-gray-600">{value.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Team Section */}
      <section className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Meet Our Team
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Experts in security, AI, and developer experience
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {team.map((member, index) => (
              <div key={index} className="text-center">
                <div className="w-32 h-32 bg-gray-200 rounded-full mx-auto mb-6 flex items-center justify-center">
                  <Users className="w-16 h-16 text-gray-400" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">{member.name}</h3>
                <p className="text-blue-600 font-medium mb-4">{member.role}</p>
                <p className="text-gray-600">{member.bio}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Mission Section */}
      <section className="py-24 bg-blue-600">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
            Our Mission
          </h2>
          <p className="text-xl text-blue-100 mb-8">
            To make application security as fundamental to software development
            as testing and version control. We believe every developer should have
            access to enterprise-grade security tools, regardless of company size.
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
              Start Building Securely
            </a>
            <a
              href="mailto:careers@valid8.dev"
              className="border-2 border-white text-white px-8 py-3 rounded-lg hover:bg-white hover:text-blue-600 font-semibold"
            >
              Join Our Team
            </a>
          </div>
        </div>
      </section>
    </div>
  );
};

export default AboutPage;
