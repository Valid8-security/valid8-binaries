import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Building2,
  Users,
  Shield,
  BarChart3,
  Settings,
  Plus,
  Trash2,
  CheckCircle,
  Activity,
  Download,
  Key,
  Crown
} from 'lucide-react';

interface Organization {
  id: string;
  name: string;
  domain: string;
  subscription_tier: string;
  seats_allocated: number;
  seats_used: number;
  monthly_scan_limit: number | null;
  scans_used_this_month: number;
  api_rate_limit: number;
  support_level: string;
  created_at: string;
}

interface Seat {
  id: string;
  user_email: string;
  user_name: string;
  role: string;
  assigned_at: string;
  last_active: string | null;
  license_key: string;
}

interface UsageStats {
  total_scans: number;
  total_api_calls: number;
  average_scans_per_month: number;
  active_users: number;
}

const EnterpriseDashboard = () => {
  const handleDownload = () => {
    const baseUrl = "https://github.com/Valid8-security/valid8-binaries/releases/latest/download";
    const platform = navigator.userAgent.toLowerCase().includes("win") ? "windows" : navigator.userAgent.toLowerCase().includes("mac") ? "macos" : "linux";
    const url = platform === "macos" ? `${baseUrl}/valid8-macos-arm64.zip` : platform === "windows" ? `${baseUrl}/valid8-windows-amd64.zip` : `${baseUrl}/valid8-linux-amd64.zip`;
    window.open(url, "_blank");
  };
  const navigate = useNavigate();
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [seats, setSeats] = useState<Seat[]>([]);
  const [usageStats, setUsageStats] = useState<UsageStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [showAddSeatModal, setShowAddSeatModal] = useState(false);
  const [newSeatEmail, setNewSeatEmail] = useState('');
  const [newSeatName, setNewSeatName] = useState('');

  useEffect(() => {
    loadEnterpriseData();
  }, []);

  const loadEnterpriseData = async () => {
    try {
      // Check if user has enterprise organization
      const userData = localStorage.getItem('valid8_user');
      if (!userData) {
        navigate('/login');
        return;
      }

      const user = JSON.parse(userData);

      // For demo purposes, create mock enterprise data
      // In production, this would call the enterprise API
      const mockOrg: Organization = {
        id: 'org-123',
        name: user.organization_name || 'Acme Corp',
        domain: user.organization_domain || 'acme.com',
        subscription_tier: user.subscription || 'enterprise',
        seats_allocated: 50,
        seats_used: 23,
        monthly_scan_limit: null,
        scans_used_this_month: 15420,
        api_rate_limit: 10000,
        support_level: 'priority',
        created_at: '2024-01-15T00:00:00Z'
      };

      const mockSeats: Seat[] = [
        {
          id: 'seat-1',
          user_email: user.email,
          user_name: user.name,
          role: 'admin',
          assigned_at: '2024-01-15T00:00:00Z',
          last_active: '2024-11-16T10:30:00Z',
          license_key: 'VALID8-ENT-A1B2C3D4...'
        },
        {
          id: 'seat-2',
          user_email: 'developer@acme.com',
          user_name: 'John Developer',
          role: 'developer',
          assigned_at: '2024-01-20T00:00:00Z',
          last_active: '2024-11-15T16:45:00Z',
          license_key: 'VALID8-ENT-E5F6G7H8...'
        }
      ];

      const mockUsage: UsageStats = {
        total_scans: 45680,
        total_api_calls: 12340,
        average_scans_per_month: 15227,
        active_users: 23
      };

      setOrganization(mockOrg);
      setSeats(mockSeats);
      setUsageStats(mockUsage);
    } catch (error) {
      console.error('Error loading enterprise data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddSeat = async () => {
    if (!newSeatEmail || !newSeatName) return;

    try {
      // In production, call enterprise API
      const newSeat: Seat = {
        id: `seat-${Date.now()}`,
        user_email: newSeatEmail,
        user_name: newSeatName,
        role: 'developer',
        assigned_at: new Date().toISOString(),
        last_active: null,
        license_key: `VALID8-ENT-${Math.random().toString(36).substr(2, 9).toUpperCase()}...`
      };

      setSeats([...seats, newSeat]);
      setNewSeatEmail('');
      setNewSeatName('');
      setShowAddSeatModal(false);
    } catch (error) {
      console.error('Error adding seat:', error);
    }
  };

  const handleRemoveSeat = async (seatId: string, email: string) => {
    if (!confirm(`Remove seat for ${email}?`)) return;

    try {
      // In production, call enterprise API
      setSeats(seats.filter(seat => seat.id !== seatId));
    } catch (error) {
      console.error('Error removing seat:', error);
    }
  };

  const getTierBadgeColor = (tier: string) => {
    switch (tier) {
      case 'enterprise': return 'bg-purple-100 text-purple-800';
      case 'pro': return 'bg-blue-100 text-blue-800';
      case 'free': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'admin': return 'bg-red-100 text-red-800';
      case 'auditor': return 'bg-orange-100 text-orange-800';
      case 'developer': return 'bg-blue-100 text-blue-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <Building2 className="h-12 w-12 text-blue-600 mx-auto mb-4 animate-pulse" />
          <p className="text-gray-600">Loading enterprise dashboard...</p>
        </div>
      </div>
    );
  }

  if (!organization) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center max-w-md">
          <Crown className="h-16 w-16 text-gray-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Enterprise Access Required</h2>
          <p className="text-gray-600 mb-6">
            Upgrade to Enterprise to access organization management features.
          </p>
          <Link
            to="/pricing"
            className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors"
          >
            View Enterprise Pricing
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="py-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-bold text-gray-900 flex items-center">
                  <Building2 className="h-8 w-8 text-blue-600 mr-3" />
                  {organization.name} - Enterprise Dashboard
                </h1>
                <p className="text-gray-600 mt-1">
                  Manage your organization's security scanning and team access
                </p>
              </div>
              <div className="flex items-center space-x-3">
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${getTierBadgeColor(organization.subscription_tier)}`}>
                  {organization.subscription_tier.charAt(0).toUpperCase() + organization.subscription_tier.slice(1)} Plan
                </span>
                <Link
                  to="/account"
                  className="bg-gray-100 text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-200 transition-colors flex items-center"
                >
                  <Settings className="h-4 w-4 mr-2" />
                  Settings
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-white p-6 rounded-lg shadow">
            <div className="flex items-center">
              <Users className="h-8 w-8 text-blue-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Seats Used</p>
                <p className="text-2xl font-bold text-gray-900">
                  {organization.seats_used}/{organization.seats_allocated}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-green-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Scans This Month</p>
                <p className="text-2xl font-bold text-gray-900">
                  {organization.scans_used_this_month.toLocaleString()}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <div className="flex items-center">
              <Activity className="h-8 w-8 text-purple-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">API Calls</p>
                <p className="text-2xl font-bold text-gray-900">
                  {usageStats?.total_api_calls.toLocaleString() || '0'}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <div className="flex items-center">
              <BarChart3 className="h-8 w-8 text-orange-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Active Users</p>
                <p className="text-2xl font-bold text-gray-900">
                  {usageStats?.active_users || 0}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Team Management */}
          <div className="bg-white shadow rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium text-gray-900">Team Members</h3>
                <button
                  onClick={() => setShowAddSeatModal(true)}
                  className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center text-sm"
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Add Member
                </button>
              </div>
            </div>
            <div className="p-6">
              <div className="space-y-4">
                {seats.map((seat) => (
                  <div key={seat.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                    <div className="flex items-center">
                      <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                        <Users className="h-5 w-5 text-blue-600" />
                      </div>
                      <div className="ml-4">
                        <p className="font-medium text-gray-900">{seat.user_name}</p>
                        <p className="text-sm text-gray-600">{seat.user_email}</p>
                        <div className="flex items-center mt-1">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRoleBadgeColor(seat.role)}`}>
                            {seat.role}
                          </span>
                          {seat.last_active && (
                            <span className="text-xs text-gray-500 ml-2">
                              Last active: {new Date(seat.last_active).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <button className="text-gray-400 hover:text-blue-600 transition-colors">
                        <Key className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleRemoveSeat(seat.id, seat.user_email)}
                        className="text-gray-400 hover:text-red-600 transition-colors"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Usage & Limits */}
          <div className="bg-white shadow rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">Usage & Limits</h3>
            </div>
            <div className="p-6">
              <div className="space-y-6">
                {/* Seats Usage */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">Seats Used</span>
                    <span className="text-sm text-gray-600">
                      {organization.seats_used}/{organization.seats_allocated}
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-blue-600 h-2 rounded-full"
                      style={{ width: `${(organization.seats_used / organization.seats_allocated) * 100}%` }}
                    ></div>
                  </div>
                </div>

                {/* Scan Usage */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">Monthly Scans</span>
                    <span className="text-sm text-gray-600">
                      {organization.scans_used_this_month.toLocaleString()}
                      {organization.monthly_scan_limit ? `/${organization.monthly_scan_limit.toLocaleString()}` : ' (Unlimited)'}
                    </span>
                  </div>
                  {organization.monthly_scan_limit && (
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${
                          organization.scans_used_this_month / organization.monthly_scan_limit > 0.9
                            ? 'bg-red-600'
                            : organization.scans_used_this_month / organization.monthly_scan_limit > 0.7
                            ? 'bg-yellow-600'
                            : 'bg-green-600'
                        }`}
                        style={{ width: `${(organization.scans_used_this_month / organization.monthly_scan_limit) * 100}%` }}
                      ></div>
                    </div>
                  )}
                </div>

                {/* API Usage */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">API Rate Limit</span>
                    <span className="text-sm text-gray-600">
                      {organization.api_rate_limit.toLocaleString()}/hour
                    </span>
                  </div>
                  <div className="flex items-center text-sm text-gray-600">
                    <CheckCircle className="h-4 w-4 text-green-600 mr-1" />
                    Within limits
                  </div>
                </div>

                {/* Enterprise Features */}
                <div className="border-t pt-4">
                  <h4 className="font-medium text-gray-900 mb-3">Enterprise Features</h4>
                  <div className="space-y-2">
                    <div className="flex items-center text-sm">
                      <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
                      Advanced REST API
                    </div>
                    <div className="flex items-center text-sm">
                      <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
                      Custom Security Rules
                    </div>
                    <div className="flex items-center text-sm">
                      <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
                      Federated Learning
                    </div>
                    <div className="flex items-center text-sm">
                      <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
                      Priority Support ({organization.support_level})
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="mt-8 bg-white shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Quick Actions</h3>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <button onClick={handleDownload} className="flex items-center justify-center px-4 py-3 border border-gray-300 rounded-lg text-gray-700 bg-white hover:bg-gray-50 transition-colors">
                <Download className="h-5 w-5 mr-2" />
                Download Enterprise Scanner
              </button>
              <button className="flex items-center justify-center px-4 py-3 border border-gray-300 rounded-lg text-gray-700 bg-white hover:bg-gray-50 transition-colors">
                <BarChart3 className="h-5 w-5 mr-2" />
                View Compliance Reports
              </button>
              <button className="flex items-center justify-center px-4 py-3 border border-gray-300 rounded-lg text-gray-700 bg-white hover:bg-gray-50 transition-colors">
                <Settings className="h-5 w-5 mr-2" />
                Configure SSO
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Add Seat Modal */}
      {showAddSeatModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg max-w-md w-full">
            <div className="p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Add Team Member</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Full Name
                  </label>
                  <input
                    type="text"
                    value={newSeatName}
                    onChange={(e) => setNewSeatName(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="John Doe"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Email Address
                  </label>
                  <input
                    type="email"
                    value={newSeatEmail}
                    onChange={(e) => setNewSeatEmail(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="john@company.com"
                  />
                </div>
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setShowAddSeatModal(false)}
                  className="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAddSeat}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Add Member
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EnterpriseDashboard;
