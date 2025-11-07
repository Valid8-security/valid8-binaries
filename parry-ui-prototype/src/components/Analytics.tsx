import React from 'react';
import { BarChart3, TrendingUp, Calendar, Download, Filter } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';

const Analytics: React.FC = () => {
  const monthlyData = [
    { month: 'Jan', vulnerabilities: 45, fixed: 32, compliance: 78 },
    { month: 'Feb', vulnerabilities: 38, fixed: 28, compliance: 82 },
    { month: 'Mar', vulnerabilities: 42, fixed: 35, compliance: 85 },
    { month: 'Apr', vulnerabilities: 35, fixed: 30, compliance: 88 },
    { month: 'May', vulnerabilities: 28, fixed: 25, compliance: 92 },
    { month: 'Jun', vulnerabilities: 22, fixed: 20, compliance: 95 },
  ];

  const severityBreakdown = [
    { category: 'Injection', count: 12, percentage: 30 },
    { category: 'XSS', count: 8, percentage: 20 },
    { category: 'Crypto', count: 6, percentage: 15 },
    { category: 'Auth', count: 5, percentage: 12.5 },
    { category: 'Other', count: 9, percentage: 22.5 },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Analytics</h1>
          <p className="text-blue-100">Comprehensive security metrics and compliance reporting</p>
        </div>
        <div className="flex space-x-3">
          <button className="bg-white/10 text-white px-4 py-2 rounded-lg hover:bg-white/20 transition-colors flex items-center space-x-2">
            <Filter className="w-4 h-4" />
            <span>Filter</span>
          </button>
          <button className="bg-white/10 text-white px-4 py-2 rounded-lg hover:bg-white/20 transition-colors flex items-center space-x-2">
            <Calendar className="w-4 h-4" />
            <span>Date Range</span>
          </button>
          <button className="bg-white text-blue-600 px-4 py-2 rounded-lg hover:bg-blue-50 transition-colors flex items-center space-x-2">
            <Download className="w-4 h-4" />
            <span>Export Report</span>
          </button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Total Vulnerabilities</p>
              <p className="text-3xl font-bold text-white">187</p>
              <p className="text-green-300 text-sm">↓ 12% from last month</p>
            </div>
            <BarChart3 className="w-8 h-8 text-blue-300" />
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Fixed This Month</p>
              <p className="text-3xl font-bold text-white">47</p>
              <p className="text-green-300 text-sm">↑ 8% from last month</p>
            </div>
            <TrendingUp className="w-8 h-8 text-green-300" />
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Compliance Score</p>
              <p className="text-3xl font-bold text-white">92%</p>
              <p className="text-green-300 text-sm">↑ 3% from last month</p>
            </div>
            <BarChart3 className="w-8 h-8 text-purple-300" />
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Critical Issues</p>
              <p className="text-3xl font-bold text-white">3</p>
              <p className="text-red-300 text-sm">Requires immediate attention</p>
            </div>
            <BarChart3 className="w-8 h-8 text-red-300" />
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Monthly Trends */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <h3 className="text-xl font-semibold text-white mb-4">Monthly Security Trends</h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={monthlyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#ffffff20" />
              <XAxis dataKey="month" stroke="#ffffff80" />
              <YAxis stroke="#ffffff80" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1f2937',
                  border: '1px solid #ffffff20',
                  borderRadius: '8px'
                }}
              />
              <Area type="monotone" dataKey="vulnerabilities" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
              <Area type="monotone" dataKey="fixed" stackId="2" stroke="#10b981" fill="#10b981" fillOpacity={0.6} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Vulnerability Categories */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
          <h3 className="text-xl font-semibold text-white mb-4">Vulnerability Categories</h3>
          <div className="space-y-4">
            {severityBreakdown.map((item, index) => (
              <div key={index} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-3 h-3 rounded-full bg-blue-400"></div>
                  <span className="text-white">{item.category}</span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-24 bg-white/20 rounded-full h-2">
                    <div
                      className="bg-blue-400 h-2 rounded-full"
                      style={{ width: `${item.percentage}%` }}
                    ></div>
                  </div>
                  <span className="text-blue-100 text-sm w-12">{item.count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Compliance Report */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20">
        <div className="p-6 border-b border-white/20">
          <h3 className="text-xl font-semibold text-white">Compliance Report</h3>
          <p className="text-blue-100 mt-1">Security standards compliance status</p>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="text-3xl font-bold text-green-400 mb-2">95%</div>
              <div className="text-white font-medium">OWASP Top 10</div>
              <div className="text-blue-100 text-sm">Compliance Score</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-green-400 mb-2">92%</div>
              <div className="text-white font-medium">MITRE CWE</div>
              <div className="text-blue-100 text-sm">Coverage Score</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-yellow-400 mb-2">87%</div>
              <div className="text-white font-medium">Industry Average</div>
              <div className="text-blue-100 text-sm">Benchmark</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;
