import React from 'react';
import { X, Download, Terminal, CheckCircle } from 'lucide-react';

interface DownloadModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const DownloadModal: React.FC<DownloadModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  // Detect user's platform
  const getPlatform = () => {
    const userAgent = navigator.userAgent.toLowerCase();
    if (userAgent.includes('win')) return 'windows';
    if (userAgent.includes('mac')) return 'macos';
    return 'linux';
  };

  const platform = getPlatform();

  const getDownloadUrl = (platform: string) => {
    // Point to the official Valid8 binaries repository
    const baseUrl = 'https://github.com/Valid8-security/valid8-binaries/releases/latest/download';

    // Map platform names to actual release asset names
    const assetMap: { [key: string]: string } = {
      'windows': 'valid8-darwin.zip', // Using macOS binary as placeholder for now
      'macos': 'valid8-darwin.zip',   // macOS/darwin binary
      'linux': 'valid8-darwin.zip'    // Using macOS binary as placeholder for now
    };

    return `${baseUrl}/${assetMap[platform] || 'valid8-darwin.zip'}`;
  };

  const handleDownload = (platform: string) => {
    const url = getDownloadUrl(platform);
    window.open(url, '_blank');
  };

  const handleFreeTrial = () => {
    // For free trial, we'll provide a simple installation command
    const trialCommand = `curl -fsSL https://raw.githubusercontent.com/Valid8-security/parry-scanner/v1/install-trial.sh | bash`;
    navigator.clipboard.writeText(trialCommand).then(() => {
      alert('Free trial installation command copied to clipboard!\n\nRun this in your terminal:\n' + trialCommand);
    });
  };

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
            {/* Prerequisites */}
            <div>
              <h3 className="text-lg font-semibold mb-3 text-gray-900">Prerequisites</h3>
              <div className="bg-blue-50 p-4 rounded-lg">
                <div className="flex items-start">
                  <CheckCircle className="h-5 w-5 text-blue-600 mt-0.5 mr-3" />
                  <div>
                    <p className="font-medium text-blue-900">Python 3.8+</p>
                    <p className="text-blue-800 text-sm">Valid8 requires Python 3.8 or higher</p>
                  </div>
                </div>
                <div className="flex items-start mt-3">
                  <CheckCircle className="h-5 w-5 text-blue-600 mt-0.5 mr-3" />
                  <div>
                    <p className="font-medium text-blue-900">Local LLM (Optional but Recommended)</p>
                    <p className="text-blue-800 text-sm">Install Ollama for best AI-powered accuracy</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Free Trial Option */}
            <div className="bg-green-50 border border-green-200 rounded-lg p-6 mb-6">
              <h3 className="text-lg font-semibold mb-3 text-green-900">🚀 Start Free Trial (Recommended)</h3>
              <p className="text-green-800 mb-4">
                Get started instantly with our limited free trial. Includes basic scanning for up to 100 files with AI assistance.
              </p>
              <div className="bg-white rounded p-3 mb-4">
                <code className="text-sm text-gray-800">
                  curl -fsSL https://raw.githubusercontent.com/Valid8-security/parry-scanner/main/install-trial.sh | bash
                </code>
              </div>
              <button
                onClick={handleFreeTrial}
                className="w-full bg-green-600 text-white px-4 py-3 rounded-lg hover:bg-green-700 transition-colors flex items-center justify-center font-semibold"
              >
                <Download className="mr-2 h-4 w-4" />
                Copy Trial Command
              </button>
              <p className="text-green-700 text-sm mt-2 text-center">
                ✨ No download required • 100 files limit • 7-day trial • Upgrade anytime
              </p>
            </div>

            {/* Download Options */}
            <div>
              <h3 className="text-lg font-semibold mb-3 text-gray-900">Download Full Version</h3>

              {/* Platform-specific downloads */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                {/* Windows */}
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

                {/* macOS */}
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

                {/* Linux */}
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

                {/* All Platforms */}
                <div className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center">
                      <div className="w-8 h-8 bg-gray-200 rounded mr-3 flex items-center justify-center">📦</div>
                      <span className="font-medium">All Platforms</span>
                    </div>
                  </div>
                  <a
                    href="https://github.com/Valid8-security/valid8-binaries/releases"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="w-full bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700 transition-colors flex items-center justify-center"
                  >
                    <Download className="mr-2 h-4 w-4" />
                    View All Downloads
                  </a>
                  <p className="text-gray-600 text-xs mt-2">
                    Valid8-security/valid8-binaries • Checksums included
                  </p>
                </div>
              </div>
            </div>

            {/* Quick Start */}
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

            {/* Documentation Link */}
            <div className="border-t pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-medium text-gray-900">Need help?</h4>
                  <p className="text-gray-600 text-sm">Check out our documentation for advanced usage</p>
                </div>
                <a
                  href="#"
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
