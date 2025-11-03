import { TrendingDown, TrendingUp, Shield, Bug, Clock, Download, FileText } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";

export function Analytics() {
  const vulnerabilityTrendData = [
    { month: "Jul", detected: 45, fixed: 38, remaining: 7 },
    { month: "Aug", detected: 52, fixed: 48, remaining: 11 },
    { month: "Sep", detected: 38, fixed: 40, remaining: 9 },
    { month: "Oct", detected: 28, fixed: 32, remaining: 5 },
  ];

  const vulnerabilityTypeData = [
    { name: "SQL Injection", value: 12, color: "#ef4444" },
    { name: "XSS", value: 8, color: "#f97316" },
    { name: "Hardcoded Secrets", value: 5, color: "#eab308" },
    { name: "Insecure Dependencies", value: 3, color: "#22c55e" },
  ];

  const severityDistribution = [
    { severity: "Critical", count: 5, color: "#ef4444" },
    { severity: "High", count: 8, color: "#f97316" },
    { severity: "Medium", count: 10, color: "#eab308" },
    { severity: "Low", count: 5, color: "#22c55e" },
  ];

  const teamPerformance = [
    { name: "Backend Team", fixed: 24, pending: 5, avgTime: "2.3h" },
    { name: "Frontend Team", fixed: 18, pending: 3, avgTime: "1.8h" },
    { name: "Mobile Team", fixed: 12, pending: 2, avgTime: "3.1h" },
    { name: "DevOps Team", fixed: 8, pending: 1, avgTime: "1.5h" },
  ];

  const mttrData = [
    { week: "Week 1", hours: 4.2 },
    { week: "Week 2", hours: 3.8 },
    { week: "Week 3", hours: 3.2 },
    { week: "Week 4", hours: 2.3 },
  ];

  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="container mx-auto max-w-7xl">
        {/* Header */}
        <div className="mb-8 flex items-start justify-between">
          <div>
            <h1 className="text-slate-50 mb-2">Analytics & Reports</h1>
            <p className="text-slate-400">Security trends, metrics, and team performance</p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" className="border-slate-700 text-slate-300">
              <Download className="w-4 h-4 mr-2" />
              Export PDF
            </Button>
            <Button variant="outline" className="border-slate-700 text-slate-300">
              <FileText className="w-4 h-4 mr-2" />
              Generate Report
            </Button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-slate-300">Total Vulnerabilities</CardTitle>
              <Bug className="w-5 h-5 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-slate-50 mb-2">28</div>
              <div className="flex items-center gap-2 text-slate-400">
                <TrendingDown className="w-4 h-4 text-green-500" />
                <span>12% decrease</span>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-slate-300">Fixed This Month</CardTitle>
              <Shield className="w-5 h-5 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-slate-50 mb-2">47</div>
              <div className="flex items-center gap-2 text-slate-400">
                <TrendingUp className="w-4 h-4 text-green-500" />
                <span>23% increase</span>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-slate-300">Avg. Resolution Time</CardTitle>
              <Clock className="w-5 h-5 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-slate-50 mb-2">2.3 hrs</div>
              <div className="flex items-center gap-2 text-slate-400">
                <TrendingDown className="w-4 h-4 text-green-500" />
                <span>45% improvement</span>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-slate-300">Security Score</CardTitle>
              <Shield className="w-5 h-5 text-cyan-500" />
            </CardHeader>
            <CardContent>
              <div className="text-slate-50 mb-2">82/100</div>
              <p className="text-slate-400">Excellent</p>
            </CardContent>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs defaultValue="trends" className="space-y-6">
          <TabsList className="bg-slate-900 border border-slate-800">
            <TabsTrigger value="trends">Trends</TabsTrigger>
            <TabsTrigger value="breakdown">Breakdown</TabsTrigger>
            <TabsTrigger value="team">Team Performance</TabsTrigger>
            <TabsTrigger value="compliance">Compliance</TabsTrigger>
          </TabsList>

          {/* Trends Tab */}
          <TabsContent value="trends" className="space-y-6">
            <div className="grid lg:grid-cols-2 gap-6">
              {/* Vulnerability Trend */}
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-slate-50">Vulnerability Trend</CardTitle>
                  <CardDescription className="text-slate-400">
                    Monthly detection and fix rate
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={vulnerabilityTrendData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="month" stroke="#94a3b8" />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1e293b', 
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          color: '#e2e8f0'
                        }} 
                      />
                      <Legend />
                      <Line type="monotone" dataKey="detected" stroke="#ef4444" strokeWidth={2} name="Detected" />
                      <Line type="monotone" dataKey="fixed" stroke="#22c55e" strokeWidth={2} name="Fixed" />
                      <Line type="monotone" dataKey="remaining" stroke="#eab308" strokeWidth={2} name="Remaining" />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              {/* Mean Time to Resolve */}
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-slate-50">Mean Time to Resolve (MTTR)</CardTitle>
                  <CardDescription className="text-slate-400">
                    Average time to fix vulnerabilities
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={mttrData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="week" stroke="#94a3b8" />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1e293b', 
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          color: '#e2e8f0'
                        }} 
                      />
                      <Bar dataKey="hours" fill="#3b82f6" radius={[8, 8, 0, 0]} name="Hours" />
                    </BarChart>
                  </ResponsiveContainer>
                  <div className="mt-4 p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <p className="text-slate-400">
                      <span className="text-green-400">↓ 45%</span> improvement over the last month
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Breakdown Tab */}
          <TabsContent value="breakdown" className="space-y-6">
            <div className="grid lg:grid-cols-2 gap-6">
              {/* Vulnerability Types */}
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-slate-50">Vulnerability Types</CardTitle>
                  <CardDescription className="text-slate-400">
                    Distribution by category
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={vulnerabilityTypeData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        outerRadius={100}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {vulnerabilityTypeData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1e293b', 
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          color: '#e2e8f0'
                        }} 
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="mt-4 space-y-2">
                    {vulnerabilityTypeData.map((item, index) => (
                      <div key={index} className="flex items-center justify-between p-2 rounded bg-slate-950">
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                          <span className="text-slate-300">{item.name}</span>
                        </div>
                        <span className="text-slate-400">{item.value}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Severity Distribution */}
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-slate-50">Severity Distribution</CardTitle>
                  <CardDescription className="text-slate-400">
                    Active vulnerabilities by severity
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={severityDistribution} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis type="number" stroke="#94a3b8" />
                      <YAxis dataKey="severity" type="category" stroke="#94a3b8" />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1e293b', 
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          color: '#e2e8f0'
                        }} 
                      />
                      <Bar dataKey="count" radius={[0, 8, 8, 0]}>
                        {severityDistribution.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                  <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                    <p className="text-red-400">
                      5 critical vulnerabilities require immediate attention
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Team Performance Tab */}
          <TabsContent value="team" className="space-y-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Team Performance Metrics</CardTitle>
                <CardDescription className="text-slate-400">
                  Resolution statistics by team
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {teamPerformance.map((team, index) => (
                    <div key={index} className="p-4 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-slate-50">{team.name}</span>
                        <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30" variant="outline">
                          Avg: {team.avgTime}
                        </Badge>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <div className="text-slate-400 mb-1">Fixed</div>
                          <div className="text-green-400">{team.fixed}</div>
                        </div>
                        <div>
                          <div className="text-slate-400 mb-1">Pending</div>
                          <div className="text-yellow-400">{team.pending}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Compliance Tab */}
          <TabsContent value="compliance" className="space-y-6">
            <div className="grid lg:grid-cols-2 gap-6">
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-slate-50">Compliance Status</CardTitle>
                  <CardDescription className="text-slate-400">
                    Current compliance with security standards
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div>
                      <div className="text-slate-300 mb-1">OWASP Top 10</div>
                      <div className="text-slate-400">2024 Standards</div>
                    </div>
                    <Badge className="bg-green-500/20 text-green-400 border-green-500/30" variant="outline">
                      Compliant
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div>
                      <div className="text-slate-300 mb-1">CWE Top 25</div>
                      <div className="text-slate-400">Most Dangerous Weaknesses</div>
                    </div>
                    <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30" variant="outline">
                      Partial
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div>
                      <div className="text-slate-300 mb-1">PCI DSS</div>
                      <div className="text-slate-400">Payment Card Industry</div>
                    </div>
                    <Badge className="bg-green-500/20 text-green-400 border-green-500/30" variant="outline">
                      Compliant
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div>
                      <div className="text-slate-300 mb-1">SOC 2</div>
                      <div className="text-slate-400">Security Controls</div>
                    </div>
                    <Badge className="bg-green-500/20 text-green-400 border-green-500/30" variant="outline">
                      Compliant
                    </Badge>
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-slate-50">Recent Compliance Reports</CardTitle>
                  <CardDescription className="text-slate-400">
                    Generated compliance documentation
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
                    <div className="flex items-center gap-3">
                      <FileText className="w-5 h-5 text-blue-400" />
                      <div>
                        <div className="text-slate-300">Q4 2024 Security Report</div>
                        <div className="text-slate-400">Generated Oct 20, 2025</div>
                      </div>
                    </div>
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                      <Download className="w-4 h-4" />
                    </Button>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
                    <div className="flex items-center gap-3">
                      <FileText className="w-5 h-5 text-blue-400" />
                      <div>
                        <div className="text-slate-300">OWASP Compliance Audit</div>
                        <div className="text-slate-400">Generated Oct 15, 2025</div>
                      </div>
                    </div>
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                      <Download className="w-4 h-4" />
                    </Button>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
                    <div className="flex items-center gap-3">
                      <FileText className="w-5 h-5 text-blue-400" />
                      <div>
                        <div className="text-slate-300">Monthly Security Summary</div>
                        <div className="text-slate-400">Generated Oct 1, 2025</div>
                      </div>
                    </div>
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                      <Download className="w-4 h-4" />
                    </Button>
                  </div>

                  <Button className="w-full bg-blue-600 hover:bg-blue-700 mt-4">
                    Generate New Report
                  </Button>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
