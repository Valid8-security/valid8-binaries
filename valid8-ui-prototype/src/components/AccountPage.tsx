import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  User,
  Mail,
  Key,
  Monitor,
  AlertTriangle,
  CheckCircle,
  Settings,
  Download
} from 'lucide-react';

const AccountPage = () => {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const handleDownload = () => {
    const baseUrl = "https://github.com/Valid8-security/parry-scanner/releases/latest/download";
    const platform = navigator.userAgent.toLowerCase().includes("win") ? "windows" : navigator.userAgent.toLowerCase().includes("mac") ? "macos" : "linux";
    const url = platform === "macos" ? `${baseUrl}/valid8-macos-arm64.zip` : platform === "windows" ? `${baseUrl}/valid8-windows-amd64.zip` : `${baseUrl}/valid8-linux-amd64.zip`;
    window.open(url, "_blank");
  };

  const navigate = useNavigate();

  useEffect(() => {
    const userData = localStorage.getItem('valid8_user');
    if (!userData) {
      navigate('/login');
      return;
    }
    setUser(JSON.parse(userData));
  }, [navigate]);

  const getSubscriptionStatus = () => {
    if (!user) return { status: 'unknown', color: 'gray' };

    if (user.subscription === 'free_trial') {
      const trialEnd = new Date(user.trial_expires);
      const now = new Date();
      const daysLeft = Math.ceil((trialEnd.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

      if (daysLeft <= 0) {
        return { status: 'expired', color: 'red', message: 'Trial expired' };
      } else if (daysLeft <= 3) {
        return { status: 'expiring', color: 'yellow', message: `${daysLeft} days left` };
      } else {
        return { status: 'active', color: 'green', message: `${daysLeft} days left` };
      }
    }

    return { status: 'active', color: 'green', message: 'Active' };
  };

  const handleUpgrade = () => {
    // Simulate subscription upgrade
    setLoading(true);
    setTimeout(() => {
      const updatedUser = { ...user, subscription: 'pro', scans_remaining: 1000 };
      localStorage.setItem('valid8_user', JSON.stringify(updatedUser));
      setUser(updatedUser);
      setLoading(false);
      alert('Successfully upgraded to Pro plan!');
    }, 2000);
  };

  const handleLogout = () => {
    localStorage.removeItem('valid8_user');
    localStorage.removeItem('valid8_license');
    navigate('/');
  };

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading account...</p>
        </div>
      </div>
    );
  }

  const subscriptionStatus = getSubscriptionStatus();

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Account Settings</h1>
                <p className="text-sm text-gray-600">Manage your Valid8 account and subscription</p>
              </div>
            </div>
            <button
              onClick={() => navigate('/dashboard')}
              className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
            >
              Back to Dashboard
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Account Information */}
          <div className="lg:col-span-2 space-y-8">
            {/* Profile Information */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Profile Information</h3>
              </div>
              <div className="p-6 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Full Name</label>
                    <div className="mt-1 flex items-center">
                      <User className="h-5 w-5 text-gray-400 mr-2" />
                      <span className="text-gray-900">{user.name || 'Not provided'}</span>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Email Address</label>
                    <div className="mt-1 flex items-center">
                      <Mail className="h-5 w-5 text-gray-400 mr-2" />
                      <span className="text-gray-900">{user.email}</span>
                    </div>
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Account Created</label>
                  <span className="text-gray-600 text-sm">
                    {new Date(user.created_at || Date.now()).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </div>

            {/* License Information */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">License Information</h3>
              </div>
              <div className="p-6 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">License Key</label>
                    <div className="mt-1 flex items-center">
                      <Key className="h-5 w-5 text-gray-400 mr-2" />
                      <span className="font-mono text-sm text-gray-900 bg-gray-100 px-2 py-1 rounded">
                        {user.license_key || 'Not generated'}
                      </span>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Machine ID</label>
                    <div className="mt-1 flex items-center">
                      <Monitor className="h-5 w-5 text-gray-400 mr-2" />
                      <span className="font-mono text-xs text-gray-600 bg-gray-100 px-2 py-1 rounded">
                        {user.machine_id ? user.machine_id.substring(0, 20) + '...' : 'Not bound'}
                      </span>
                    </div>
                  </div>
                </div>

                {user.machine_bound && (
                  <div className="flex items-center p-4 bg-green-50 rounded-md">
                    <CheckCircle className="h-5 w-5 text-green-400 mr-2" />
                    <span className="text-sm text-green-700">License is bound to this machine</span>
                  </div>
                )}
              </div>
            </div>

            {/* Scan History */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Scan History</h3>
              </div>
              <div className="p-6">
                <div className="text-center py-8">
                  <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-600">No scans performed yet</p>
                  <p className="text-sm text-gray-500 mt-1">Your scan history will appear here</p>
                </div>
              </div>
            </div>
          </div>

          {/* Subscription & Actions */}
          <div className="space-y-8">
            {/* Current Subscription */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Current Subscription</h3>
              </div>
              <div className="p-6">
                <div className={`rounded-lg p-4 mb-4 ${
                  subscriptionStatus.color === 'green' ? 'bg-green-50 border-green-200' :
                  subscriptionStatus.color === 'yellow' ? 'bg-yellow-50 border-yellow-200' :
                  'bg-red-50 border-red-200'
                } border`}>
                  <div className="flex items-center">
                    <div className={`flex-shrink-0 ${
                      subscriptionStatus.color === 'green' ? 'text-green-400' :
                      subscriptionStatus.color === 'yellow' ? 'text-yellow-400' :
                      'text-red-400'
                    }`}>
                      {subscriptionStatus.color === 'green' ? (
                        <CheckCircle className="h-6 w-6" />
                      ) : (
                        <AlertTriangle className="h-6 w-6" />
                      )}
                    </div>
                    <div className="ml-3">
                      <h4 className={`text-sm font-medium ${
                        subscriptionStatus.color === 'green' ? 'text-green-800' :
                        subscriptionStatus.color === 'yellow' ? 'text-yellow-800' :
                        'text-red-800'
                      }`}>
                        {user.subscription === 'free_trial' ? 'Free Trial' : 'Pro Plan'}
                      </h4>
                      <p className={`text-sm ${
                        subscriptionStatus.color === 'green' ? 'text-green-700' :
                        subscriptionStatus.color === 'yellow' ? 'text-yellow-700' :
                        'text-red-700'
                      }`}>
                        {subscriptionStatus.message}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Scans remaining</span>
                    <span className="font-medium">{user.scans_remaining}</span>
                  </div>

                  {user.subscription === 'free_trial' && (
                    <div className="pt-4 border-t">
                      <button
                        onClick={handleUpgrade}
                        disabled={loading}
                        className="w-full flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                      >
                        {loading ? 'Upgrading...' : 'Upgrade to Pro'}
                      </button>
                      <p className="text-xs text-gray-500 mt-2 text-center">
                        Unlimited scans • Priority support • Advanced features
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Quick Actions</h3>
              </div>
              <div className="p-6 space-y-3">
                <button onClick={handleDownload} className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center">
                    <Download className="h-4 w-4 mr-2" />
                    Download Scanner
                  </button>

                <button className="w-full flex items-center justify-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                  <Settings className="h-4 w-4 mr-2" />
                  Update Profile
                </button>

                <button
                  onClick={handleLogout}
                  className="w-full flex items-center justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700"
                >
                  Sign Out
                </button>
              </div>
            </div>

            {/* Support */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Support</h3>
              </div>
              <div className="p-6 space-y-3">
                <a href="https://github.com/Valid8-security/parry-scanner/blob/main/README.md" target="_blank" rel="noopener noreferrer" className="block text-sm text-blue-600 hover:text-blue-500">
                  📚 Documentation
                </a>
                <a href="https://github.com/Valid8-security/parry-scanner/discussions" target="_blank" rel="noopener noreferrer" className="block text-sm text-blue-600 hover:text-blue-500">
                  💬 Community Forum
                </a>
                <a href="mailto:support@valid8code.ai" className="block text-sm text-blue-600 hover:text-blue-500">
                  📧 Contact Support
                </a>
                <a href="https://github.com/Valid8-security/parry-scanner/issues" target="_blank" rel="noopener noreferrer" className="block text-sm text-blue-600 hover:text-blue-500">
                  🐛 Report Issue
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AccountPage;
