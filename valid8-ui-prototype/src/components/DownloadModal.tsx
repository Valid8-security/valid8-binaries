import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { X, Download, CheckCircle, Shield } from 'lucide-react';

interface DownloadModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const DownloadModal: React.FC<DownloadModalProps> = ({ isOpen, onClose }) => {
  const navigate = useNavigate();
  
  if (!isOpen) return null;

  const userData = localStorage.getItem('valid8_user');
  const user = userData ? JSON.parse(userData) : null;

  const getPlatform = () => {
    const userAgent = navigator.userAgent.toLowerCase();
    if (userAgent.includes('win')) return 'windows';
    if (userAgent.includes('mac')) return 'macos';
    return 'linux';
  };

  const platform = getPlatform();

  const getDownloadUrl = (platform: string) => {
    const baseUrl = 'https://github.com/Valid8-security/parry-scanner/releases/latest/download';
    if (platform === 'macos') {
      return `${baseUrl}/valid8-macos-arm64.zip`;
    } else if (platform === 'windows') {
      return `${baseUrl}/valid8-windows-amd64.zip`;
    }
    return `${baseUrl}/valid8-linux-amd64.zip`;
  };

  const handleDownload = (platform: string) => {
    if (!user) {
      alert('Please create an account first to download Valid8.');
      navigate('/signup');
      onClose();
      return;
    }
    const url = getDownloadUrl(platform);
    window.open(url, '_blank');
  };

  if (!user) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
        <div className="bg-white rounded-lg max-w-md w-full max-h-[90vh] overflow-y-auto">
          <div className="p-6">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-2xl font-bold text-gray-900">Download Valid8</h2>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            <div className="text-center py-8">
              <Shield className="h-16 w-16 text-blue-600 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">Account Required</h3>
              <p className="text-gray-600 mb-6">
                To download Valid8, you need to create an account with a free trial license.
              </p>
              <div className="space-y-3">
                <Link
                  to="/signup"
                  onClick={onClose}
                  className="w-full bg-blue-600 text-white px-4 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center font-semibold"
                >
                  <Shield className="mr-2 h-5 w-5" />
                  Start Free Trial
                </Link>
                <Link
                  to="/login"
                  onClick={onClose}
                  className="block text-blue-600 hover:text-blue-500 text-sm"
                >
                  Already have an account? Sign in
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold text-gray-900">Install Valid8</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600"
            >
              <X className="h-6 w-6" />
            </button>
          </div>

          <div className="space-y-6">
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-semibold text-green-900">License Active ✅</h3>
                  <p className="text-green-700 text-sm">
                    {user.subscription === 'free_trial' ? 'Free Trial' : 'Pro Plan'} • {user.scans_remaining || 'Unlimited'} scans remaining
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-green-600">Machine-bound license</p>
                  <p className="text-xs font-mono text-green-800">{user.machine_id?.substring(0, 12) || 'N/A'}...</p>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3 text-gray-900">System Requirements</h3>
              <div className="bg-blue-50 p-4 rounded-lg">
                <div className="flex items-start">
                  <CheckCircle className="h-5 w-5 text-blue-600 mt-0.5 mr-3" />
                  <div>
                    <p className="font-medium text-blue-900">No Dependencies Required</p>
                    <p className="text-blue-800 text-sm">Valid8 runs standalone - no Python or external dependencies needed</p>
                  </div>
                </div>
                <div className="flex items-start mt-3">
                  <CheckCircle className="h-5 w-5 text-blue-600 mt-0.5 mr-3" />
                  <div>
                    <p className="font-medium text-blue-900">100% Local Processing</p>
                    <p className="text-blue-800 text-sm">All scanning and AI analysis happens on your machine</p>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3 text-gray-900">Download Full Version</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div className={`border rounded-lg p-4 ${platform === 'windows' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center">
                      <div className="w-8 h-8 bg-gray-200 rounded mr-3 flex items-center justify-center">🪟</div>
                      <div>
                        <span className="font-medium">Windows</span>
                        {platform === 'windows' && <span className="text-blue-600 text-sm ml-2">(Recommended)</span>}
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => handleDownload('windows')}
                    className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center"
                  >
                    <Download className="mr-2 h-4 w-4" />
                    Download for Windows
                  </button>
                  <p className="text-gray-600 text-xs mt-2">
                    .exe installer • ~50MB • No installation required
                  </p>
                </div>

                <div className={`border rounded-lg p-4 ${platform === 'macos' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center">
                      <div className="w-8 h-8 bg-gray-200 rounded mr-3 flex items-center justify-center">🍎</div>
                      <div>
                        <span className="font-medium">macOS</span>
                        {platform === 'macos' && <span className="text-blue-600 text-sm ml-2">(Recommended)</span>}
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => handleDownload('macos')}
                    className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center"
                  >
                    <Download className="mr-2 h-4 w-4" />
                    Download for macOS
                  </button>
                  <p className="text-gray-600 text-xs mt-2">
                    Universal binary • ~45MB • Intel & Apple Silicon
                  </p>
                </div>

                <div className={`border rounded-lg p-4 ${platform === 'linux' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center">
                      <div className="w-8 h-8 bg-gray-200 rounded mr-3 flex items-center justify-center">🐧</div>
                      <div>
                        <span className="font-medium">Linux</span>
                        {platform === 'linux' && <span className="text-blue-600 text-sm ml-2">(Recommended)</span>}
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => handleDownload('linux')}
                    className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center"
                  >
                    <Download className="mr-2 h-4 w-4" />
                    Download for Linux
                  </button>
                  <p className="text-gray-600 text-xs mt-2">
                    AppImage • ~55MB • x64 & ARM64 support
                  </p>
                </div>

                <div className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center">
                      <div className="w-8 h-8 bg-gray-200 rounded mr-3 flex items-center justify-center">📦</div>
                      <span className="font-medium">All Platforms</span>
                    </div>
                  </div>
                  <a
                    href="https://github.com/Valid8-security/parry-scanner/releases"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="w-full bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700 transition-colors flex items-center justify-center"
                  >
                    <Download className="mr-2 h-4 w-4" />
                    View All Downloads
                  </a>
                  <p className="text-gray-600 text-xs mt-2">
                    Valid8-security/parry-scanner • Checksums included
                  </p>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3 text-gray-900">Quick Start</h3>
              <div className="bg-gray-50 p-4 rounded-lg">
                <ol className="list-decimal list-inside space-y-2 text-gray-700">
                  <li>Download and extract the Valid8 binary for your platform</li>
                  <li>Make it executable: <code className="bg-gray-200 px-1 rounded">chmod +x valid8</code> (Linux/macOS only)</li>
                  <li>Verify installation: <code className="bg-gray-200 px-1 rounded">./valid8 --version</code></li>
                  <li>Scan your project: <code className="bg-gray-200 px-1 rounded">./valid8 scan /path/to/your/project</code></li>
                  <li>View results and AI-generated fixes in the terminal output</li>
                </ol>
              </div>
            </div>

            <div className="border-t pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-medium text-gray-900">Need help?</h4>
                  <p className="text-gray-600 text-sm">Check out our documentation for advanced usage</p>
                </div>
                <a
                  href="https://github.com/Valid8-security/parry-scanner/blob/main/README.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center"
                >
                  <Download className="h-4 w-4 mr-2" />
                  View Docs
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DownloadModal;
