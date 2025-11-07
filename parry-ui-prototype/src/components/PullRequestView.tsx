import React from 'react';
import { GitPullRequest, CheckCircle, AlertTriangle, MessageSquare, Eye } from 'lucide-react';

const PullRequestView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Pull Request Review</h1>
          <p className="text-blue-100">Automated security analysis for code changes</p>
        </div>
      </div>

      <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
        <div className="flex items-center space-x-3 mb-6">
          <GitPullRequest className="w-8 h-8 text-green-400" />
          <div>
            <h2 className="text-xl font-semibold text-white">feat: Implement user authentication system</h2>
            <p className="text-blue-100">Add secure login, registration, and session management</p>
          </div>
          <span className="px-3 py-1 bg-green-500/20 text-green-300 rounded-full text-sm">
            Ready for Review
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <div className="text-center">
            <div className="text-2xl font-bold text-green-400 mb-1">2</div>
            <div className="text-white text-sm">Files Changed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-400 mb-1">47</div>
            <div className="text-white text-sm">Lines Added</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400 mb-1">3</div>
            <div className="text-white text-sm">Security Issues</div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5" />
              <div className="flex-1">
                <h4 className="text-white font-medium">SQL Injection in Login Handler</h4>
                <p className="text-blue-100 text-sm mb-2">src/auth/login.js:23</p>
                <p className="text-blue-100 text-sm">Direct string concatenation in SQL query allows injection attacks.</p>
                <div className="mt-3 flex space-x-2">
                  <button className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700">
                    Block Merge
                  </button>
                  <button className="bg-white/10 text-white px-3 py-1 rounded text-sm hover:bg-white/20">
                    Add Comment
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-5 h-5 text-yellow-400 mt-0.5" />
              <div className="flex-1">
                <h4 className="text-white font-medium">Weak Password Hashing</h4>
                <p className="text-blue-100 text-sm mb-2">src/auth/crypto.js:45</p>
                <p className="text-blue-100 text-sm">Using MD5 for password hashing is cryptographically weak.</p>
                <div className="mt-3 flex space-x-2">
                  <button className="bg-white/10 text-white px-3 py-1 rounded text-sm hover:bg-white/20">
                    Request Changes
                  </button>
                  <button className="bg-white/10 text-white px-3 py-1 rounded text-sm hover:bg-white/20">
                    Approve
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PullRequestView;
