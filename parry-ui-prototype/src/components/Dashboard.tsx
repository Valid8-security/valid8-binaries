import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, TrendingUp, Activity, Users } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

interface VulnerabilityData {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  file: string;
  line: number;
  cwe: string;
  status: 'open' | 'fixed' | 'acknowledged';
}

interface ScanResult {
  totalFiles: number;
  vulnerabilities: VulnerabilityData[];
  scanTime: number;
  timestamp: string;
}

const Dashboard: React.FC = () => {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  // Mock data for demonstration
  const mockData: ScanResult = {
    totalFiles: 1247,
    vulnerabilities: [
      { id: '1', severity: 'critical', title: 'SQL Injection', file: 'user.py', line: 45, cwe: 'CWE-89', status: 'open' },
      { id: '2', severity: 'high', title: 'XSS Vulnerability', file: 'login.js', line: 23, cwe: 'CWE-79', status: 'open' },
      { id: '3', severity: 'medium', title: 'Weak Cryptography', file: 'crypto.py', line: 12, cwe: 'CWE-327', status: 'acknowledged' },
      { id: '4', severity: 'low', title: 'Information Disclosure', file: 'config.js', line: 78, cwe: 'CWE-209', status: 'fixed' },
    ],
    scanTime: 45.2,
    timestamp: new Date().toISOString()
  };

  const trendData = [
    { date: '2024-01-01', vulnerabilities: 45, fixed: 32 },
    { date: '2024-01-08', vulnerabilities: 38, fixed: 28 },
    { date: '2024-01-15', vulnerabilities: 42, fixed: 35 },
    { date: '2024-01-22', vulnerabilities: 35, fixed: 30 },
    { date: '2024-01-29', vulnerabilities: 28, fixed: 25 },
  ];

  const severityData = [
    { name: 'Critical', value: 2, color: '#dc3545' },
    { name: 'High', value: 8, color: '#fd7e14' },
    { name: 'Medium', value: 15, color: '#ffc107' },
    { name: 'Low', value: 12, color: '#28a745' },
  ];

  useEffect(() => {
    // Simulate loading scan results
    setTimeout(() => {
      setScanResult(mockData);
    }, 1000);
  }, []);

  const handleScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      setScanResult(mockData);
      setIsScanning(false);
    }, 3000);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="w-4 h-4" />;
      case 'high': return <AlertTriangle className="w-4 h-4" />;
      case 'medium': return <Shield className="w-4 h-4" />;
      case 'low': return <CheckCircle className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Dashboard</h1>
          <p className="text-blue-100">Real-time vulnerability monitoring and analysis</p>
        </div>
        <button
          onClick={handleScan}
          disabled={isScanning}
          className="bg-white text-blue-600 px-6 py-3 rounded-lg font-semibold hover:bg-blue-50 transition-colors disabled:opacity-50"
        >
          {isScanning ? 'Scanning...' : '🔍 Run Security Scan'}
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Total Files</p>
              <p className="text-2xl font-bold text-white">{scanResult?.totalFiles || 0}</p>
            </div>
            <Activity className="w-8 h-8 text-blue-300" />
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Vulnerabilities</p>
              <p className="text-2xl font-bold text-white">{scanResult?.vulnerabilities.length || 0}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-300" />
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Scan Time</p>
              <p className="text-2xl font-bold text-white">{scanResult ? `${scanResult.scanTime}s` : '0s'}</p>
            </div>
            <TrendingUp className="w-8 h-8 text-green-300" />
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Risk Score</p>
              <p className="text-2xl font-bold text-white">Medium</p>
            </div>
            <Users className="w-8 h-8 text-purple-300" />
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Trend Chart */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <h3 className="text-xl font-semibold text-white mb-4">Security Trends</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#ffffff20" />
              <XAxis dataKey="date" stroke="#ffffff80" />
              <YAxis stroke="#ffffff80" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1f2937',
                  border: '1px solid #ffffff20',
                  borderRadius: '8px'
                }}
              />
              <Line type="monotone" dataKey="vulnerabilities" stroke="#ef4444" strokeWidth={2} />
              <Line type="monotone" dataKey="fixed" stroke="#10b981" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <h3 className="text-xl font-semibold text-white mb-4">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={120}
                paddingAngle={5}
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Vulnerabilities Table */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20">
        <div className="p-6 border-b border-white/20">
          <h3 className="text-xl font-semibold text-white">Recent Vulnerabilities</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-white/5">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-blue-100 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-blue-100 uppercase tracking-wider">Title</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-blue-100 uppercase tracking-wider">File</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-blue-100 uppercase tracking-wider">CWE</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-blue-100 uppercase tracking-wider">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/10">
              {scanResult?.vulnerabilities.map((vuln) => (
                <tr key={vuln.id} className="hover:bg-white/5">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                      {getSeverityIcon(vuln.severity)}
                      <span className="ml-1 capitalize">{vuln.severity}</span>
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-white">{vuln.title}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-blue-100">
                    {vuln.file}:{vuln.line}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-blue-100">{vuln.cwe}</td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                      vuln.status === 'open' ? 'bg-red-100 text-red-800' :
                      vuln.status === 'fixed' ? 'bg-green-100 text-green-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {vuln.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
