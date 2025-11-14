import React, { useState } from 'react';
import { Mail, Phone, MapPin, Clock, Send, MessageCircle, Users, Building } from 'lucide-react';

const ContactPage: React.FC = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    company: '',
    inquiryType: '',
    message: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    // Simulate form submission
    await new Promise(resolve => setTimeout(resolve, 2000));

    setIsSubmitting(false);
    setSubmitted(true);

    // Reset form after 3 seconds
    setTimeout(() => {
      setSubmitted(false);
      setFormData({
        name: '',
        email: '',
        company: '',
        inquiryType: '',
        message: ''
      });
    }, 3000);
  };

  const contactMethods = [
    {
      icon: Mail,
      title: "Email Support",
      description: "General inquiries and technical support",
      contact: "support@valid8.dev",
      availability: "24/7 via email"
    },
    {
      icon: Users,
      title: "Sales Inquiries",
      description: "Enterprise solutions and custom pricing",
      contact: "sales@valid8.dev",
      availability: "Mon-Fri, 9AM-5PM PST"
    },
    {
      icon: Building,
      title: "Partnerships",
      description: "Integration partnerships and collaborations",
      contact: "partners@valid8.dev",
      availability: "By appointment"
    }
  ];

  const officeInfo = [
    {
      icon: MapPin,
      label: "Address",
      value: "University of Washington\nSeattle, WA 98195"
    },
    {
      icon: Phone,
      label: "Phone",
      value: "+1 (555) 123-VALID8"
    },
    {
      icon: Clock,
      label: "Business Hours",
      value: "Mon-Fri: 9AM-5PM PST"
    }
  ];

  return (
    <div className="min-h-screen bg-gray-50 py-16">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Get in Touch
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Have questions about Valid8? Need help with your security scanning?
            We'd love to hear from you.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-12">
          {/* Contact Form */}
          <div className="bg-white rounded-lg shadow-sm border p-8">
            <h2 className="text-2xl font-semibold text-gray-900 mb-6">
              Send us a Message
            </h2>

            {submitted ? (
              <div className="text-center py-12">
                <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Send className="w-8 h-8 text-green-600" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  Message Sent!
                </h3>
                <p className="text-gray-600">
                  Thanks for reaching out. We'll get back to you within 24 hours.
                </p>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-2">
                      Full Name *
                    </label>
                    <input
                      type="text"
                      id="name"
                      name="name"
                      value={formData.name}
                      onChange={handleInputChange}
                      required
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="Your full name"
                    />
                  </div>

                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                      Email Address *
                    </label>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      value={formData.email}
                      onChange={handleInputChange}
                      required
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="your.email@company.com"
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="company" className="block text-sm font-medium text-gray-700 mb-2">
                    Company
                  </label>
                  <input
                    type="text"
                    id="company"
                    name="company"
                    value={formData.company}
                    onChange={handleInputChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="Your company name"
                  />
                </div>

                <div>
                  <label htmlFor="inquiryType" className="block text-sm font-medium text-gray-700 mb-2">
                    How can we help? *
                  </label>
                  <select
                    id="inquiryType"
                    name="inquiryType"
                    value={formData.inquiryType}
                    onChange={handleInputChange}
                    required
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="">Select an option</option>
                    <option value="support">Technical Support</option>
                    <option value="sales">Sales Inquiry</option>
                    <option value="partnership">Partnership Opportunity</option>
                    <option value="demo">Request a Demo</option>
                    <option value="feedback">Product Feedback</option>
                    <option value="other">Other</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="message" className="block text-sm font-medium text-gray-700 mb-2">
                    Message *
                  </label>
                  <textarea
                    id="message"
                    name="message"
                    value={formData.message}
                    onChange={handleInputChange}
                    required
                    rows={5}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-vertical"
                    placeholder="Tell us how we can help you..."
                  />
                </div>

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center font-semibold"
                >
                  {isSubmitting ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                      Sending...
                    </>
                  ) : (
                    <>
                      <Send className="w-4 h-4 mr-2" />
                      Send Message
                    </>
                  )}
                </button>
              </form>
            )}
          </div>

          {/* Contact Information */}
          <div className="space-y-8">
            {/* Contact Methods */}
            <div>
              <h2 className="text-2xl font-semibold text-gray-900 mb-6">
                Contact Methods
              </h2>
              <div className="space-y-4">
                {contactMethods.map((method, index) => (
                  <div key={index} className="bg-gray-50 p-6 rounded-lg">
                    <div className="flex items-start">
                      <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center mr-4">
                        <method.icon className="w-5 h-5 text-blue-600" />
                      </div>
                      <div className="flex-1">
                        <h3 className="font-semibold text-gray-900 mb-1">
                          {method.title}
                        </h3>
                        <p className="text-gray-600 mb-2">
                          {method.description}
                        </p>
                        <a
                          href={`mailto:${method.contact}`}
                          className="text-blue-600 hover:text-blue-800 font-medium"
                        >
                          {method.contact}
                        </a>
                        <p className="text-sm text-gray-500 mt-1">
                          {method.availability}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Office Information */}
            <div>
              <h2 className="text-2xl font-semibold text-gray-900 mb-6">
                Office Information
              </h2>
              <div className="bg-gray-50 p-6 rounded-lg">
                <div className="space-y-4">
                  {officeInfo.map((info, index) => (
                    <div key={index} className="flex items-start">
                      <info.icon className="w-5 h-5 text-gray-400 mr-3 mt-0.5" />
                      <div>
                        <div className="font-medium text-gray-900">
                          {info.label}
                        </div>
                        <div className="text-gray-600 whitespace-pre-line">
                          {info.value}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Response Time */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
              <div className="flex items-start">
                <MessageCircle className="w-6 h-6 text-blue-600 mr-3 mt-0.5" />
                <div>
                  <h3 className="font-semibold text-blue-900 mb-2">
                    Response Times
                  </h3>
                  <ul className="text-blue-800 space-y-1">
                    <li>• Support inquiries: Within 24 hours</li>
                    <li>• Sales inquiries: Within 4 hours (business days)</li>
                    <li>• Partnership requests: Within 48 hours</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Additional Help */}
        <div className="mt-16 text-center">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">
            Need Immediate Help?
          </h2>
          <p className="text-gray-600 mb-6 max-w-2xl mx-auto">
            Check out our comprehensive documentation or browse our knowledge base
            for quick answers to common questions.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a
              href="/docs"
              className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700"
            >
              View Documentation
            </a>
            <a
              href="/faq"
              className="bg-white text-blue-600 border border-blue-600 px-6 py-3 rounded-lg hover:bg-blue-50"
            >
              Browse FAQ
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ContactPage;
