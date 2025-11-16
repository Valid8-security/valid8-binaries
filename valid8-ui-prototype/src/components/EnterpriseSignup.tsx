import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Building2, ArrowLeft, CheckCircle } from 'lucide-react';

const EnterpriseSignup = () => {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState<{
    organizationName: string;
    organizationDomain: string;
    adminName: string;
    adminEmail: string;
    adminPassword: string;
    confirmPassword: string;
    seats: number;
    planType: string;
  }>({
    organizationName: '',
    organizationDomain: '',
    adminName: '',
    adminEmail: '',
    adminPassword: '',
    confirmPassword: '',
    seats: 10,
    planType: 'enterprise'
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: name === 'seats' ? parseInt(value) : value
    }));
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[name];
        return newErrors;
      });
    }
  };

  const validateStep1 = () => {
    const newErrors: any = {};

    if (!formData.organizationName.trim()) {
      newErrors.organizationName = 'Organization name is required';
    }
    if (!formData.organizationDomain.trim()) {
      newErrors.organizationDomain = 'Domain is required';
    } else if (!formData.organizationDomain.includes('.')) {
      newErrors.organizationDomain = 'Please enter a valid domain';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const validateStep2 = () => {
    const newErrors: any = {};

    if (!formData.adminName.trim()) {
      newErrors.adminName = 'Full name is required';
    }
    if (!formData.adminEmail.trim()) {
      newErrors.adminEmail = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.adminEmail)) {
      newErrors.adminEmail = 'Please enter a valid email';
    }
    if (!formData.adminPassword) {
      newErrors.adminPassword = 'Password is required';
    } else if (formData.adminPassword.length < 8) {
      newErrors.adminPassword = 'Password must be at least 8 characters';
    }
    if (formData.adminPassword !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleStep1Next = () => {
    if (validateStep1()) {
      setStep(2);
    }
  };

  const handleStep2Back = () => {
    setStep(1);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateStep2()) {
      return;
    }

    setLoading(true);

    try {
      // Simulate enterprise organization creation
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Create enterprise organization data
      const enterpriseData = {
        organization_name: formData.organizationName,
        organization_domain: formData.organizationDomain,
        name: formData.adminName,
        email: formData.adminEmail,
        subscription: 'enterprise_trial',
        seats_allocated: formData.seats,
        machine_id: `ent-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        machine_bound: true,
        scans_remaining: 10000, // Higher limit for enterprise trial
        trial_expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
        created_at: new Date().toISOString()
      };

      localStorage.setItem('valid8_user', JSON.stringify(enterpriseData));
      localStorage.setItem('valid8_license', `VALID8-ENT-${Date.now().toString(36).toUpperCase()}`);

      setStep(3); // Success step
    } catch (error) {
      console.error('Enterprise signup error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleContinueToDashboard = () => {
    navigate('/enterprise');
  };

  if (step === 3) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <div className="mx-auto w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mb-4">
              <CheckCircle className="w-8 h-8 text-green-600" />
            </div>
            <h2 className="text-3xl font-bold text-gray-900 mb-2">
              Enterprise Account Created!
            </h2>
            <p className="text-gray-600 mb-8">
              Your enterprise organization has been set up successfully. You now have access to advanced security features and team management.
            </p>

            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-8">
              <h3 className="font-medium text-blue-900 mb-2">Your Enterprise Trial Includes:</h3>
              <ul className="text-sm text-blue-800 space-y-1">
                <li>• 30-day enterprise trial</li>
                <li>• {formData.seats} team seats allocated</li>
                <li>• Unlimited API access</li>
                <li>• Priority support</li>
                <li>• Advanced compliance features</li>
              </ul>
            </div>

            <button
              onClick={handleContinueToDashboard}
              className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg font-semibold hover:bg-blue-700 transition-colors"
            >
              Go to Enterprise Dashboard
            </button>

            <p className="text-sm text-gray-500 mt-4">
              Need help getting started? <a href="mailto:enterprise@valid8.dev" className="text-blue-600 hover:underline">Contact enterprise support</a>
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-md mx-auto py-12 px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center text-blue-600 hover:text-blue-500 mb-4">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to home
          </Link>
          <div className="flex justify-center mb-4">
            <div className="bg-blue-100 p-3 rounded-full">
              <Building2 className="h-8 w-8 text-blue-600" />
            </div>
          </div>
          <h2 className="text-3xl font-bold text-gray-900">
            Enterprise Setup
          </h2>
          <p className="text-gray-600 mt-2">
            Set up your enterprise organization with advanced security features
          </p>
        </div>

        <div className="bg-white shadow rounded-lg p-6">
          {/* Progress Indicator */}
          <div className="flex items-center justify-center mb-8">
            <div className="flex items-center">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                step >= 1 ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-600'
              }`}>
                1
              </div>
              <div className={`w-16 h-0.5 ${step >= 2 ? 'bg-blue-600' : 'bg-gray-200'}`}></div>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                step >= 2 ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-600'
              }`}>
                2
              </div>
            </div>
          </div>

          {step === 1 && (
            <form onSubmit={(e) => { e.preventDefault(); handleStep1Next(); }}>
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Organization Name
                  </label>
                  <input
                    type="text"
                    name="organizationName"
                    value={formData.organizationName}
                    onChange={handleInputChange}
                    className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      errors.organizationName ? 'border-red-300' : 'border-gray-300'
                    }`}
                    placeholder="Acme Corporation"
                  />
                  {errors.organizationName && (
                    <p className="mt-1 text-sm text-red-600">{errors.organizationName}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Organization Domain
                  </label>
                  <input
                    type="text"
                    name="organizationDomain"
                    value={formData.organizationDomain}
                    onChange={handleInputChange}
                    className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      errors.organizationDomain ? 'border-red-300' : 'border-gray-300'
                    }`}
                    placeholder="acme.com"
                  />
                  {errors.organizationDomain && (
                    <p className="mt-1 text-sm text-red-600">{errors.organizationDomain}</p>
                  )}
                  <p className="mt-1 text-sm text-gray-500">
                    Used for domain verification and team invites
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Number of Seats
                  </label>
                  <select
                    name="seats"
                    value={formData.seats}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value={10}>10 seats (Minimum)</option>
                    <option value={25}>25 seats</option>
                    <option value={50}>50 seats</option>
                    <option value={100}>100 seats</option>
                    <option value={250}>250 seats</option>
                    <option value={500}>500+ seats (Contact sales)</option>
                  </select>
                  <p className="mt-1 text-sm text-gray-500">
                    You can add more seats later. Enterprise pricing: $99/seat/month
                  </p>
                </div>

                <button
                  type="submit"
                  className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg font-semibold hover:bg-blue-700 transition-colors"
                >
                  Continue to Account Setup
                </button>
              </div>
            </form>
          )}

          {step === 2 && (
            <form onSubmit={handleSubmit}>
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Full Name
                  </label>
                  <input
                    type="text"
                    name="adminName"
                    value={formData.adminName}
                    onChange={handleInputChange}
                    className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      errors.adminName ? 'border-red-300' : 'border-gray-300'
                    }`}
                    placeholder="John Doe"
                  />
                  {errors.adminName && (
                    <p className="mt-1 text-sm text-red-600">{errors.adminName}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Email Address
                  </label>
                  <input
                    type="email"
                    name="adminEmail"
                    value={formData.adminEmail}
                    onChange={handleInputChange}
                    className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      errors.adminEmail ? 'border-red-300' : 'border-gray-300'
                    }`}
                    placeholder="john@acme.com"
                  />
                  {errors.adminEmail && (
                    <p className="mt-1 text-sm text-red-600">{errors.adminEmail}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Password
                  </label>
                  <input
                    type="password"
                    name="adminPassword"
                    value={formData.adminPassword}
                    onChange={handleInputChange}
                    className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      errors.adminPassword ? 'border-red-300' : 'border-gray-300'
                    }`}
                    placeholder="••••••••"
                  />
                  {errors.adminPassword && (
                    <p className="mt-1 text-sm text-red-600">{errors.adminPassword}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Confirm Password
                  </label>
                  <input
                    type="password"
                    name="confirmPassword"
                    value={formData.confirmPassword}
                    onChange={handleInputChange}
                    className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      errors.confirmPassword ? 'border-red-300' : 'border-gray-300'
                    }`}
                    placeholder="••••••••"
                  />
                  {errors.confirmPassword && (
                    <p className="mt-1 text-sm text-red-600">{errors.confirmPassword}</p>
                  )}
                </div>

                <div className="flex space-x-4">
                  <button
                    type="button"
                    onClick={handleStep2Back}
                    className="flex-1 bg-gray-100 text-gray-700 py-3 px-4 rounded-lg font-semibold hover:bg-gray-200 transition-colors"
                  >
                    Back
                  </button>
                  <button
                    type="submit"
                    disabled={loading}
                    className="flex-1 bg-blue-600 text-white py-3 px-4 rounded-lg font-semibold hover:bg-blue-700 transition-colors disabled:opacity-50"
                  >
                    {loading ? 'Creating Enterprise Account...' : 'Create Enterprise Account'}
                  </button>
                </div>
              </div>
            </form>
          )}
        </div>

        <div className="mt-8 text-center">
          <p className="text-sm text-gray-500">
            Already have an enterprise account?{' '}
            <Link to="/login" className="text-blue-600 hover:underline">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default EnterpriseSignup;
