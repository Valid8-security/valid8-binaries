import { Shield, AlertTriangle, CheckCircle2, TrendingDown, Clock, GitBranch, Bug, Zap } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Progress } from "./ui/progress";

interface DashboardProps {
  onViewDetails: () => void;
}

export function Dashboard({ onViewDetails }: DashboardProps) {
  const repositories = [
    { name: "frontend-app", status: "healthy", score: 95, vulnerabilities: 2, branch: "main" },
    { name: "backend-api", status: "warning", score: 78, vulnerabilities: 8, branch: "develop" },
    { name: "mobile-ios", status: "healthy", score: 92, vulnerabilities: 3, branch: "main" },
    { name: "analytics-service", status: "critical", score: 64, vulnerabilities: 15, branch: "main" },
  ];

  const recentScans = [
    { 
      id: 1,
      repo: "backend-api", 
      severity: "critical", 
      type: "SQL Injection", 
      file: "api/users/controller.js",
      time: "2 minutes ago",
      status: "pending"
    },
    { 
      id: 2,
      repo: "frontend-app", 
      severity: "high", 
      type: "XSS Vulnerability", 
      file: "components/UserInput.tsx",
      time: "15 minutes ago",
      status: "pending"
    },
    { 
      id: 3,
      repo: "backend-api", 
      severity: "critical", 
      type: "Hardcoded Secret", 
      file: "config/database.js",
      time: "1 hour ago",
      status: "fixed"
    },
    { 
      id: 4,
      repo: "backend-api", 
      severity: "critical", 
      type: "Command Injection", 
      file: "utils/shell-executor.js",
      time: "2 hours ago",
      status: "pending"
    },
    { 
      id: 5,
      repo: "mobile-ios", 
      severity: "high", 
      type: "Path Traversal", 
      file: "FileManager.swift",
      time: "3 hours ago",
      status: "dismissed"
    },
    { 
      id: 6,
      repo: "frontend-app", 
      severity: "medium", 
      type: "Weak Cryptography", 
      file: "utils/encryption.js",
      time: "4 hours ago",
      status: "pending"
    },
    { 
      id: 7,
      repo: "mobile-ios", 
      severity: "low", 
      type: "Insecure Random", 
      file: "utils/TokenGenerator.swift",
      time: "5 hours ago",
      status: "dismissed"
    },
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500/10 text-red-500 border-red-500/20";
      case "high": return "bg-orange-500/10 text-orange-500 border-orange-500/20";
      case "medium": return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
      case "low": return "bg-green-500/10 text-green-500 border-green-500/20";
      default: return "bg-slate-500/10 text-slate-500 border-slate-500/20";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "healthy": return "text-green-500";
      case "warning": return "text-yellow-500";
      case "critical": return "text-red-500";
      default: return "text-slate-500";
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="container mx-auto max-w-7xl">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-slate-50 mb-2">Security Dashboard</h1>
          <p className="text-slate-400">Monitor your repositories and manage vulnerabilities</p>
        </div>

        {/* Metrics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-slate-300">Overall Security Score</CardTitle>
              <Shield className="w-5 h-5 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-slate-50 mb-2">82/100</div>
              <Progress value={82} className="h-2 mb-2" />
              <p className="text-slate-400">Good security posture</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-slate-300">Active Vulnerabilities</CardTitle>
              <AlertTriangle className="w-5 h-5 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-slate-50 mb-2">28</div>
              <div className="flex items-center gap-2 text-slate-400">
                <TrendingDown className="w-4 h-4 text-green-500" />
                <span>12% from last week</span>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-slate-300">Auto-Fixed This Week</CardTitle>
              <CheckCircle2 className="w-5 h-5 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-slate-50 mb-2">47</div>
              <p className="text-slate-400">AI-generated fixes applied</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-slate-300">Time Saved</CardTitle>
              <Clock className="w-5 h-5 text-cyan-500" />
            </CardHeader>
            <CardContent>
              <div className="text-slate-50 mb-2">23.5 hrs</div>
              <p className="text-slate-400">Estimated developer time</p>
            </CardContent>
          </Card>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Recent Scans */}
          <div className="lg:col-span-2">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Recent Vulnerability Scans</CardTitle>
                <CardDescription className="text-slate-400">Latest security findings from your repositories</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {recentScans.map((scan) => (
                    <div 
                      key={scan.id} 
                      className="flex items-start gap-4 p-4 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
                      onClick={onViewDetails}
                    >
                      <div className="flex-shrink-0">
                        {scan.status === "pending" ? (
                          <AlertTriangle className={`w-5 h-5 ${scan.severity === "critical" ? "text-red-500" : scan.severity === "high" ? "text-orange-500" : "text-yellow-500"}`} />
                        ) : scan.status === "fixed" ? (
                          <CheckCircle2 className="w-5 h-5 text-green-500" />
                        ) : (
                          <Bug className="w-5 h-5 text-slate-500" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge className={getSeverityColor(scan.severity)} variant="outline">
                            {scan.severity.toUpperCase()}
                          </Badge>
                          <span className="text-slate-50">{scan.type}</span>
                        </div>
                        <p className="text-slate-400 mb-1">
                          {scan.repo} • {scan.file}
                        </p>
                        <p className="text-slate-500">{scan.time}</p>
                      </div>
                      {scan.status === "pending" && (
                        <Button size="sm" variant="outline" className="border-blue-500/30 text-blue-400 hover:bg-blue-500/10">
                          Review
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* AI Insights */}
          <div>
            <Card className="bg-gradient-to-br from-blue-950 to-slate-900 border-blue-500/30 mb-6">
              <CardHeader>
                <div className="flex items-center gap-2 mb-2">
                  <Zap className="w-5 h-5 text-blue-400" />
                  <CardTitle className="text-slate-50">AI Insights</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 bg-slate-900/50 rounded-lg border border-slate-800">
                  <p className="text-slate-300 mb-2">
                    Your backend-api has 3 similar SQL injection patterns. Consider applying batch fix.
                  </p>
                  <Button size="sm" variant="outline" className="border-blue-500/50 text-blue-400 hover:bg-blue-500/10 hover:border-blue-500">
                    Apply Batch Fix
                  </Button>
                </div>
                <div className="p-3 bg-slate-900/50 rounded-lg border border-slate-800">
                  <p className="text-slate-300 mb-2">
                    Detected outdated dependencies in 2 repos with known vulnerabilities.
                  </p>
                  <Button size="sm" variant="outline" className="border-yellow-500/50 text-yellow-400 hover:bg-yellow-500/10 hover:border-yellow-500">
                    View Details
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <Button variant="outline" className="w-full justify-start border-slate-700 text-slate-200 hover:bg-slate-800 hover:text-white">
                  <Bug className="w-4 h-4 mr-2" />
                  Run Manual Scan
                </Button>
                <Button variant="outline" className="w-full justify-start border-slate-700 text-slate-200 hover:bg-slate-800 hover:text-white">
                  <GitBranch className="w-4 h-4 mr-2" />
                  Add Repository
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Repositories List */}
        <Card className="bg-slate-900 border-slate-800 mt-6">
          <CardHeader>
            <CardTitle className="text-slate-50">Monitored Repositories</CardTitle>
            <CardDescription className="text-slate-400">Security status of your connected repositories</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {repositories.map((repo, index) => (
                <div key={index} className="flex items-center justify-between p-4 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
                  <div className="flex items-center gap-4">
                    <Shield className={`w-5 h-5 ${getStatusColor(repo.status)}`} />
                    <div>
                      <div className="text-slate-50 mb-1">{repo.name}</div>
                      <div className="flex items-center gap-2 text-slate-400">
                        <GitBranch className="w-3 h-3" />
                        <span>{repo.branch}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-6">
                    <div className="text-right">
                      <div className="text-slate-50 mb-1">Score: {repo.score}</div>
                      <div className="text-slate-400">{repo.vulnerabilities} issues</div>
                    </div>
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-200 hover:bg-slate-800 hover:text-white" onClick={onViewDetails}>
                      View Details
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}