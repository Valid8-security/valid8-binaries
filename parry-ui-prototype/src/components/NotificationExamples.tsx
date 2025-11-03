import { Slack, Mail, MessageSquare, AlertTriangle, CheckCircle2, Shield } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Separator } from "./ui/separator";

export function NotificationExamples() {
  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="container mx-auto max-w-7xl">
        <div className="mb-8">
          <h1 className="text-slate-50 mb-2">Notification Examples</h1>
          <p className="text-slate-400">How Parry alerts your team across different channels</p>
        </div>

        <div className="grid lg:grid-cols-2 gap-6">
          {/* Slack Notifications */}
          <div className="space-y-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 bg-purple-500/20 rounded flex items-center justify-center">
                    <Slack className="w-5 h-5 text-purple-400" />
                  </div>
                  <CardTitle className="text-slate-50">Slack Integration</CardTitle>
                </div>
                <CardDescription className="text-slate-400">
                  Real-time alerts in your team channels
                </CardDescription>
              </CardHeader>
            </Card>

            {/* Critical Vulnerability Alert */}
            <Card className="bg-slate-900 border-slate-800 border-l-4 border-l-red-500">
              <CardContent className="pt-6">
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 bg-blue-600 rounded flex items-center justify-center flex-shrink-0">
                    <Shield className="w-6 h-6 text-white" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-slate-50">Parry Security</span>
                      <Badge className="bg-slate-800 text-slate-400" variant="outline">
                        APP
                      </Badge>
                      <span className="text-slate-500">2:34 PM</span>
                    </div>
                    
                    <div className="bg-slate-950 border border-red-500/30 rounded-lg p-4 mb-3">
                      <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className="w-5 h-5 text-red-500" />
                        <span className="text-slate-50">🔴 Critical Security Issue Detected</span>
                      </div>
                      <p className="text-slate-300 mb-3">
                        <span className="text-red-400">SQL Injection</span> vulnerability found in <span className="text-blue-400">backend-api</span>
                      </p>
                      <div className="space-y-2 text-slate-400">
                        <div><span className="text-slate-500">File:</span> api/users/controller.js:47</div>
                        <div><span className="text-slate-500">Branch:</span> feature/auth</div>
                        <div><span className="text-slate-500">PR:</span> #247</div>
                        <div><span className="text-slate-500">AI Confidence:</span> <span className="text-green-400">98%</span></div>
                      </div>
                      <Separator className="bg-slate-800 my-3" />
                      <div className="flex gap-2">
                        <button className="px-3 py-1 bg-green-600 text-white rounded hover:bg-green-700 transition-colors">
                          Apply Fix
                        </button>
                        <button className="px-3 py-1 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 transition-colors">
                          Review
                        </button>
                        <button className="px-3 py-1 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 transition-colors">
                          Dismiss
                        </button>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 text-slate-500">
                      <button className="flex items-center gap-1 hover:text-slate-400">
                        <MessageSquare className="w-4 h-4" />
                        <span>Reply</span>
                      </button>
                      <button className="hover:text-slate-400">Share message</button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Scan Complete Notification */}
            <Card className="bg-slate-900 border-slate-800 border-l-4 border-l-green-500">
              <CardContent className="pt-6">
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 bg-blue-600 rounded flex items-center justify-center flex-shrink-0">
                    <Shield className="w-6 h-6 text-white" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-slate-50">Parry Security</span>
                      <Badge className="bg-slate-800 text-slate-400" variant="outline">
                        APP
                      </Badge>
                      <span className="text-slate-500">1:15 PM</span>
                    </div>
                    
                    <div className="bg-slate-950 border border-green-500/30 rounded-lg p-4 mb-3">
                      <div className="flex items-center gap-2 mb-2">
                        <CheckCircle2 className="w-5 h-5 text-green-500" />
                        <span className="text-slate-50">✅ Security Scan Complete</span>
                      </div>
                      <p className="text-slate-300 mb-3">
                        Scan completed for <span className="text-blue-400">frontend-app</span> • main branch
                      </p>
                      <div className="grid grid-cols-3 gap-3 mb-3">
                        <div className="bg-slate-900 rounded p-2 text-center">
                          <div className="text-green-400">0</div>
                          <div className="text-slate-500">Critical</div>
                        </div>
                        <div className="bg-slate-900 rounded p-2 text-center">
                          <div className="text-yellow-400">2</div>
                          <div className="text-slate-500">Medium</div>
                        </div>
                        <div className="bg-slate-900 rounded p-2 text-center">
                          <div className="text-blue-400">95</div>
                          <div className="text-slate-500">Score</div>
                        </div>
                      </div>
                      <button className="px-3 py-1 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 transition-colors w-full">
                        View Full Report
                      </button>
                    </div>

                    <div className="flex items-center gap-4 text-slate-500">
                      <button className="flex items-center gap-1 hover:text-slate-400">
                        <MessageSquare className="w-4 h-4" />
                        <span>Reply</span>
                      </button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Weekly Summary */}
            <Card className="bg-slate-900 border-slate-800 border-l-4 border-l-blue-500">
              <CardContent className="pt-6">
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 bg-blue-600 rounded flex items-center justify-center flex-shrink-0">
                    <Shield className="w-6 h-6 text-white" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-slate-50">Parry Security</span>
                      <Badge className="bg-slate-800 text-slate-400" variant="outline">
                        APP
                      </Badge>
                      <span className="text-slate-500">Mon 9:00 AM</span>
                    </div>
                    
                    <div className="bg-slate-950 border border-blue-500/30 rounded-lg p-4 mb-3">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="text-slate-50">📊 Weekly Security Summary</span>
                      </div>
                      <div className="space-y-3 text-slate-300">
                        <div className="flex items-center justify-between">
                          <span>Vulnerabilities Fixed</span>
                          <span className="text-green-400">47</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>AI Fixes Applied</span>
                          <span className="text-blue-400">38</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>Time Saved</span>
                          <span className="text-cyan-400">23.5 hrs</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>Security Score</span>
                          <span className="text-green-400">↑ +8 points</span>
                        </div>
                      </div>
                      <Separator className="bg-slate-800 my-3" />
                      <button className="px-3 py-1 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 transition-colors w-full">
                        View Detailed Analytics
                      </button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Email Notifications */}
          <div className="space-y-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 bg-blue-500/20 rounded flex items-center justify-center">
                    <Mail className="w-5 h-5 text-blue-400" />
                  </div>
                  <CardTitle className="text-slate-50">Email Notifications</CardTitle>
                </div>
                <CardDescription className="text-slate-400">
                  Detailed reports delivered to your inbox
                </CardDescription>
              </CardHeader>
            </Card>

            {/* Critical Alert Email */}
            <Card className="bg-slate-900 border-slate-800">
              <CardContent className="pt-6">
                <div className="bg-white rounded-lg overflow-hidden">
                  {/* Email Header */}
                  <div className="bg-slate-900 text-white p-4">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="w-10 h-10 bg-blue-600 rounded flex items-center justify-center">
                        <Shield className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="font-semibold">Parry Security Scanner</div>
                        <div className="text-slate-400">security@parry.dev</div>
                      </div>
                    </div>
                  </div>

                  {/* Email Body */}
                  <div className="p-6 bg-white text-slate-900">
                    <h2 className="text-xl mb-2">🔴 Critical Security Alert</h2>
                    <p className="text-slate-600 mb-4">A critical vulnerability was detected in your repository</p>

                    <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
                      <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className="w-5 h-5 text-red-600" />
                        <span className="font-semibold text-red-900">SQL Injection</span>
                        <Badge className="bg-red-200 text-red-900">CRITICAL</Badge>
                      </div>
                      <p className="text-slate-700 mb-3">
                        Unsanitized user input in database query detected in backend-api
                      </p>
                      <div className="space-y-1 text-sm text-slate-600">
                        <div><strong>File:</strong> api/users/controller.js:47</div>
                        <div><strong>Repository:</strong> backend-api</div>
                        <div><strong>Branch:</strong> feature/auth</div>
                        <div><strong>Pull Request:</strong> #247</div>
                      </div>
                    </div>

                    <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-4">
                      <div className="flex items-center gap-2 mb-2">
                        <CheckCircle2 className="w-5 h-5 text-green-600" />
                        <span className="font-semibold text-green-900">AI Fix Available</span>
                        <Badge className="bg-green-200 text-green-900">98% Confidence</Badge>
                      </div>
                      <p className="text-slate-700 mb-2">
                        Parry has generated a secure fix using parameterized queries
                      </p>
                    </div>

                    <div className="flex gap-3">
                      <button className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">
                        Apply Fix in Dashboard
                      </button>
                      <button className="px-4 py-2 bg-slate-200 text-slate-700 rounded hover:bg-slate-300">
                        View Details
                      </button>
                    </div>
                  </div>

                  {/* Email Footer */}
                  <div className="bg-slate-100 p-4 text-center text-slate-600 border-t">
                    <p className="text-sm">
                      You're receiving this because critical vulnerabilities require immediate attention.
                    </p>
                    <p className="text-sm mt-2">
                      <a href="#" className="text-blue-600 hover:underline">Manage notification settings</a>
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Weekly Report Email */}
            <Card className="bg-slate-900 border-slate-800">
              <CardContent className="pt-6">
                <div className="bg-white rounded-lg overflow-hidden">
                  {/* Email Header */}
                  <div className="bg-slate-900 text-white p-4">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="w-10 h-10 bg-blue-600 rounded flex items-center justify-center">
                        <Shield className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="font-semibold">Parry Security Scanner</div>
                        <div className="text-slate-400">reports@parry.dev</div>
                      </div>
                    </div>
                  </div>

                  {/* Email Body */}
                  <div className="p-6 bg-white text-slate-900">
                    <h2 className="text-xl mb-2">📊 Your Weekly Security Report</h2>
                    <p className="text-slate-600 mb-4">Oct 14-20, 2025</p>

                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-center">
                        <div className="text-2xl text-green-600 mb-1">47</div>
                        <div className="text-sm text-slate-700">Vulnerabilities Fixed</div>
                      </div>
                      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-center">
                        <div className="text-2xl text-blue-600 mb-1">82</div>
                        <div className="text-sm text-slate-700">Security Score</div>
                      </div>
                      <div className="bg-cyan-50 border border-cyan-200 rounded-lg p-3 text-center">
                        <div className="text-2xl text-cyan-600 mb-1">23.5h</div>
                        <div className="text-sm text-slate-700">Time Saved</div>
                      </div>
                      <div className="bg-purple-50 border border-purple-200 rounded-lg p-3 text-center">
                        <div className="text-2xl text-purple-600 mb-1">38</div>
                        <div className="text-sm text-slate-700">AI Fixes Applied</div>
                      </div>
                    </div>

                    <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 mb-4">
                      <h3 className="font-semibold mb-2">Top Issues This Week</h3>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span>SQL Injection</span>
                          <span className="text-red-600">5 found, 4 fixed</span>
                        </div>
                        <div className="flex justify-between">
                          <span>XSS Vulnerabilities</span>
                          <span className="text-orange-600">3 found, 3 fixed</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Hardcoded Secrets</span>
                          <span className="text-yellow-600">2 found, 2 fixed</span>
                        </div>
                      </div>
                    </div>

                    <button className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 w-full">
                      View Full Analytics Dashboard
                    </button>
                  </div>

                  {/* Email Footer */}
                  <div className="bg-slate-100 p-4 text-center text-slate-600 border-t">
                    <p className="text-sm">
                      Weekly reports are sent every Monday at 9:00 AM.
                    </p>
                    <p className="text-sm mt-2">
                      <a href="#" className="text-blue-600 hover:underline">Manage notification settings</a>
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
