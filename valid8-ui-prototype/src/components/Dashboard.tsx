import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Shield,
  Download,
  BarChart3,
  Settings,
  CheckCircle,
  AlertTriangle,
  Target,
  Zap
} from 'lucide-react';

const Dashboard = () => {
  const [user, setUser] = useState<any>(null);
  const [scans, setScans] = useState<any[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    const userData = localStorage.getItem('valid8_user');
    if (!userData) {
      navigate('/login');
      return;
    }

    const parsedUser = JSON.parse(userData);
    setUser(parsedUser);

    setScans([
      {
        id: 'scan-001',
        date: '2024-11-16',
        target: '/home/user/project',
        vulnerabilities: 3,
        status: 'completed',
        duration: '2.3s'
      },
      {
        id: 'scan-002',
        date: '2024-11-15',
        target: '/home/user/api',
        vulnerabilities: 0,
        status: 'completed',
        duration: '1.8s'
      },
      {
        id: 'scan-003',
        date: '2024-11-14',
        target: '/home/user/frontend',
        vulnerabilities: 1,
        status: 'completed',
        duration: '3.1s'
      }
    ]);
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem('valid8_user');
    localStorage.removeItem('valid8_license');
    navigate('/');
  };

  const getDownloadUrl = (platform: string) => {
    const baseUrl = 'https://github.com/Valid8-security/valid8-binaries/releases/latest/download';
    if (platform === 'macos') {
      return `${baseUrl}/valid8-macos-arm64.zip`;
    } else if (platform === 'windows') {
      return `${baseUrl}/valid8-windows-amd64.zip`;
    }
    return `${baseUrl}/valid8-linux-amd64.zip`;
  };

  const handleDownload = (platform: string) => {
    const url = getDownloadUrl(platform);
    window.open(url, '_blank');
  };

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

  const subscriptionStatus = getSubscriptionStatus();

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Valid8 Dashboard</h1>
                <p className="text-sm text-gray-600">Welcome back, {user.name || user.email}</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Link
                to="/account"
                className="flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              >
                <Settings className="h-4 w-4 mr-2" />
                Account
              </Link>
              <button
                onClick={handleLogout}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <div className={`rounded-lg p-6 ${
            subscriptionStatus.color === 'green' ? 'bg-green-50 border-green-200' :
            subscriptionStatus.color === 'yellow' ? 'bg-yellow-50 border-yellow-200' :
            'bg-red-50 border-red-200'
          } border`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className={`flex-shrink-0 ${
                  subscriptionStatus.color === 'green' ? 'text-green-400' :
                  subscriptionStatus.color === 'yellow' ? 'text-yellow-400' :
                  'text-red-400'
                }`}>
                  {subscriptionStatus.color === 'green' ? (
                    <CheckCircle className="h-8 w-8" />
                  ) : (
                    <AlertTriangle className="h-8 w-8" />
                  )}
                </div>
                <div className="ml-3">
                  <h3 className={`text-lg font-medium ${
                    subscriptionStatus.color === 'green' ? 'text-green-800' :
                    subscriptionStatus.color === 'yellow' ? 'text-yellow-800' :
                    'text-red-800'
                  }`}>
                    {user.subscription === 'free_trial' ? 'Free Trial' : 'Subscription'} {subscriptionStatus.status === 'active' ? 'Active' : subscriptionStatus.status}
                  </h3>
                  <p className={`text-sm ${
                    subscriptionStatus.color === 'green' ? 'text-green-700' :
                    subscriptionStatus.color === 'yellow' ? 'text-yellow-700' :
                    'text-red-700'
                  }`}>
                    {subscriptionStatus.message}
                  </p>
                </div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold text-gray-900">{user.scans_remaining || 'Unlimited'}</div>
                <div className="text-sm text-gray-600">scans remaining</div>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Target className="h-6 w-6 text-blue-600" />
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Total Scans</dt>
                    <dd className="text-lg font-medium text-gray-900">{scans.length}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Shield className="h-6 w-6 text-green-600" />
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Vulnerabilities Found</dt>
                    <dd className="text-lg font-medium text-gray-900">
                      {scans.reduce((sum, scan) => sum + scan.vulnerabilities, 0)}
                    </dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Zap className="h-6 w-6 text-yellow-600" />
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Avg Scan Time</dt>
                    <dd className="text-lg font-medium text-gray-900">2.4s</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <BarChart3 className="h-6 w-6 text-purple-600" />
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Detection Rate</dt>
                    <dd className="text-lg font-medium text-gray-900">99%</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-white shadow rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">Download Valid8 Scanner</h3>
              <p className="text-sm text-gray-600 mt-1">License-bound installation for your machine</p>
            </div>
            <div className="p-6 space-y-4">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium text-blue-900">License Active</h4>
                    <p className="text-sm text-blue-700">
                      Bound to machine: {user.machine_id ? user.machine_id.substring(0, 16) + '...' : 'Unknown'}
                    </p>
                  </div>
                  <CheckCircle className="h-6 w-6 text-blue-600" />
                </div>
              </div>

              <div className="space-y-3">
                <h4 className="font-medium text-gray-900">Choose Your Platform</h4>
                <div className="grid grid-cols-1 gap-3">
                  <div className="border border-gray-200 rounded-lg p-4 hover:border-blue-300 transition-colors">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center">
                        <div className="w-10 h-10 bg-gray-100 rounded-lg mr-3 flex items-center justify-center">🪟</div>
                        <div>
                          <span className="font-medium">Windows</span>
                          <span className="text-sm text-gray-500 ml-2">.exe installer</span>
                        </div>
                      </div>
                      <span className="text-sm text-gray-500">~50MB</span>
                    </div>
                    <button 
                      onClick={() => handleDownload('windows')}
                      className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download for Windows
                    </button>
                  </div>

                  <div className="border border-gray-200 rounded-lg p-4 hover:border-blue-300 transition-colors">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center">
                        <div className="w-10 h-10 bg-gray-100 rounded-lg mr-3 flex items-center justify-center">🍎</div>
                        <div>
                          <span className="font-medium">macOS</span>
                          <span className="text-sm text-gray-500 ml-2">Universal binary</span>
                        </div>
                      </div>
                      <span className="text-sm text-gray-500">~45MB</span>
                    </div>
                    <button 
                      onClick={() => handleDownload('macos')}
                      className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download for macOS
                    </button>
                  </div>

                  <div className="border border-gray-200 rounded-lg p-4 hover:border-blue-300 transition-colors">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center">
                        <div className="w-10 h-10 bg-gray-100 rounded-lg mr-3 flex items-center justify-center">🐧</div>
                        <div>
                          <span className="font-medium">Linux</span>
                          <span className="text-sm text-gray-500 ml-2">AppImage</span>
                        </div>
                      </div>
                      <span className="text-sm text-gray-500">~55MB</span>
                    </div>
                    <button 
                      onClick={() => handleDownload('linux')}
                      className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download for Linux
                    </button>
                  </div>
                </div>
              </div>

              <div className="border-t pt-4">
                <h4 className="font-medium text-gray-900 mb-2">Quick Setup</h4>
                <div className="bg-gray-50 p-3 rounded-lg">
                  <ol className="text-sm text-gray-700 space-y-1">
                    <li>1. Download the installer for your platform</li>
                    <li>2. Run the installer (no admin rights required)</li>
                    <li>3. Your license is automatically activated</li>
                    <li>4. Start scanning: <code className="bg-gray-200 px-1 rounded text-xs">valid8 scan /path/to/code</code></li>
                  </ol>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white shadow rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">Recent Scans</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {scans.map((scan) => (
                <div key={scan.id} className="px-6 py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate">
                        {scan.target}
                      </p>
                      <p className="text-sm text-gray-500">
                        {scan.date} • {scan.duration}
                      </p>
                    </div>
                    <div className="flex items-center">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        scan.vulnerabilities === 0
                          ? 'bg-green-100 text-green-800'
                          : 'bg-red-100 text-red-800'
                      }`}>
                        {scan.vulnerabilities} vulnerabilities
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-8 bg-white shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Performance Metrics</h3>
            <p className="text-sm text-gray-600 mt-1">Based on OWASP Benchmark v1.2</p>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="text-3xl font-bold text-blue-600">99.0%</div>
                <div className="text-sm text-gray-600">Recall</div>
                <div className="text-xs text-gray-500 mt-1">Industry Leading</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-green-600">95.2%</div>
                <div className="text-sm text-gray-600">Precision</div>
                <div className="text-xs text-gray-500 mt-1">High Accuracy</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-purple-600">97.1%</div>
                <div className="text-sm text-gray-600">F1-Score</div>
                <div className="text-xs text-gray-500 mt-1">Best in Class</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
