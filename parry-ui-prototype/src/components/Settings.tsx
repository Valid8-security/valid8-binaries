import React from 'react';
import { Settings as SettingsIcon, Shield, Bell, Database, Zap } from 'lucide-react';

const Settings: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
        <p className="text-blue-100">Configure Parry security scanning and integrations</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Shield className="w-6 h-6 text-blue-400" />
            <h3 className="text-xl font-semibold text-white">Scan Configuration</h3>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-white text-sm mb-2">Scan Mode</label>
              <select className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white">
                <option>Fast (Pattern-based)</option>
                <option>Hybrid (AI-enhanced)</option>
                <option>Deep (Comprehensive)</option>
              </select>
            </div>
            <div>
              <label className="block text-white text-sm mb-2">Severity Threshold</label>
              <select className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white">
                <option>Critical & High</option>
                <option>All Severities</option>
                <option>High & Above</option>
              </select>
            </div>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Bell className="w-6 h-6 text-green-400" />
            <h3 className="text-xl font-semibold text-white">Notifications</h3>
          </div>
          <div className="space-y-3">
            <label className="flex items-center space-x-3">
              <input type="checkbox" defaultChecked className="rounded" />
              <span className="text-white">Critical vulnerabilities</span>
            </label>
            <label className="flex items-center space-x-3">
              <input type="checkbox" defaultChecked className="rounded" />
              <span className="text-white">Weekly security reports</span>
            </label>
            <label className="flex items-center space-x-3">
              <input type="checkbox" className="rounded" />
              <span className="text-white">CI/CD pipeline failures</span>
            </label>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Database className="w-6 h-6 text-purple-400" />
            <h3 className="text-xl font-semibold text-white">Integrations</h3>
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-white">GitHub Actions</span>
              <span className="text-green-400">Connected</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-white">Slack</span>
              <button className="text-blue-400 text-sm">Connect</button>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-white">Jira</span>
              <button className="text-blue-400 text-sm">Connect</button>
            </div>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Zap className="w-6 h-6 text-yellow-400" />
            <h3 className="text-xl font-semibold text-white">Performance</h3>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-white text-sm mb-2">Max Workers</label>
              <input
                type="number"
                defaultValue="4"
                className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-white text-sm mb-2">Cache Size (MB)</label>
              <input
                type="number"
                defaultValue="100"
                className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
