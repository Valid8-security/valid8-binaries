import React from 'react';
import { Monitor, Zap, Code, AlertTriangle, CheckCircle } from 'lucide-react';

const IDEPlugin: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">IDE Integration</h1>
        <p className="text-blue-100">Real-time security scanning in your development environment</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Monitor className="w-6 h-6 text-blue-400" />
            <h3 className="text-xl font-semibold text-white">VS Code Extension</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-white">Inline Diagnostics</span>
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-white">Quick Fix Suggestions</span>
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-white">Security Code Lens</span>
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-white">File Watcher</span>
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Monitor className="w-6 h-6 text-purple-400" />
            <h3 className="text-xl font-semibold text-white">IntelliJ Plugin</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-white">IDE Integration</span>
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-white">Code Inspections</span>
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-white">Intentions & Quick Fixes</span>
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-white">Project Analysis</span>
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
            </div>
          </div>
          <p className="text-blue-100 text-sm mt-3">Coming Soon - Beta testing planned</p>
        </div>
      </div>

      <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
        <h3 className="text-xl font-semibold text-white mb-4">Live Demo</h3>
        <div className="bg-black/30 rounded-lg p-4 font-mono text-sm">
          <div className="text-green-300 mb-2">// Example: SQL Injection detected in VS Code</div>
          <div className="text-gray-100">
            app.get('/user/:id', (req, res) =&gt; {'{'}
          </div>
          <div className="text-gray-100 bg-red-500/20 border-l-4 border-red-500 pl-2">
            {'  '}const query = `SELECT * FROM users WHERE id = '${'{'}req.params.id{'}'}'`; // 🔴 SQL Injection
          </div>
          <div className="text-gray-100">
            {'  '}db.query(query, (err, result) =&gt; {'{'}...{'}'});
          </div>
          <div className="text-gray-100">
            {'}'});
          </div>
        </div>
        <div className="mt-4 flex space-x-2">
          <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">
            Apply Fix
          </button>
          <button className="bg-white/10 text-white px-4 py-2 rounded-lg hover:bg-white/20">
            Learn More
          </button>
        </div>
      </div>
    </div>
  );
};

export default IDEPlugin;
