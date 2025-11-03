import { Shield, AlertTriangle, CheckCircle2, X, Settings as SettingsIcon, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

export function IDEPlugin() {
  const vulnerabilities = [
    {
      file: "api/users/controller.js",
      line: 47,
      severity: "critical",
      type: "SQL Injection",
      message: "Unsanitized user input in database query"
    },
    {
      file: "components/UserForm.tsx",
      line: 23,
      severity: "high",
      type: "XSS Vulnerability",
      message: "Dangerous HTML rendering without sanitization"
    }
  ];

  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="container mx-auto max-w-7xl">
        <div className="mb-8">
          <h1 className="text-slate-50 mb-2">IDE Plugin Interface</h1>
          <p className="text-slate-400">VS Code extension for real-time security scanning</p>
        </div>

        <div className="grid lg:grid-cols-2 gap-6">
          {/* VS Code Window Mockup */}
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-slate-50">Visual Studio Code Extension</CardTitle>
            </CardHeader>
            <CardContent>
              {/* VS Code Title Bar */}
              <div className="bg-slate-950 rounded-t-lg border border-slate-800">
                <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500" />
                    <div className="w-3 h-3 rounded-full bg-green-500" />
                  </div>
                  <span className="text-slate-400">backend-api - api/users/controller.js</span>
                  <div className="w-16" />
                </div>

                {/* VS Code Sidebar */}
                <div className="flex">
                  {/* File Explorer */}
                  <div className="w-48 border-r border-slate-800 p-3 bg-slate-900/50">
                    <div className="text-slate-400 mb-2">EXPLORER</div>
                    <div className="space-y-1 text-slate-400">
                      <div className="text-slate-500">📁 api</div>
                      <div className="pl-3 text-slate-500">📁 users</div>
                      <div className="pl-6 text-slate-300 bg-slate-800 px-2 py-1 rounded">
                        controller.js
                      </div>
                      <div className="text-slate-500">📁 components</div>
                      <div className="text-slate-500">📁 config</div>
                    </div>
                  </div>

                  {/* Code Editor */}
                  <div className="flex-1">
                    <div className="bg-slate-950 p-4 font-mono">
                      <div className="space-y-1">
                        <div className="flex">
                          <span className="text-slate-600 w-8 text-right mr-4">45</span>
                          <span className="text-purple-400">async function</span>
                          <span className="text-blue-400"> getUserById</span>
                          <span className="text-slate-300">(req, res) {'{'}</span>
                        </div>
                        <div className="flex">
                          <span className="text-slate-600 w-8 text-right mr-4">46</span>
                          <span className="text-slate-300 pl-4">
                            <span className="text-purple-400">const</span> userId = req.params.id;
                          </span>
                        </div>
                        <div className="flex">
                          <span className="text-slate-600 w-8 text-right mr-4">47</span>
                          <span className="text-slate-300 pl-4" />
                        </div>
                        <div className="flex bg-red-500/10 border-l-2 border-red-500">
                          <span className="text-slate-600 w-8 text-right mr-4">48</span>
                          <span className="text-slate-300 pl-4">
                            <span className="text-purple-400">const</span> query = 
                            <span className="text-green-400"> "SELECT * FROM users WHERE id = '" </span>
                            + userId + 
                            <span className="text-green-400">"'"</span>;
                          </span>
                        </div>
                        <div className="flex">
                          <span className="text-slate-600 w-8 text-right mr-4">49</span>
                          <span className="text-slate-300 pl-4" />
                        </div>
                        <div className="flex">
                          <span className="text-slate-600 w-8 text-right mr-4">50</span>
                          <span className="text-slate-300 pl-4">
                            <span className="text-purple-400">const</span> result = 
                            <span className="text-purple-400"> await</span> db.execute(query);
                          </span>
                        </div>
                        <div className="flex">
                          <span className="text-slate-600 w-8 text-right mr-4">51</span>
                          <span className="text-slate-300 pl-4">res.json(result);</span>
                        </div>
                        <div className="flex">
                          <span className="text-slate-600 w-8 text-right mr-4">52</span>
                          <span className="text-slate-300">{'}'}</span>
                        </div>
                      </div>

                      {/* Inline Error Squiggle */}
                      <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded">
                        <div className="flex items-start gap-3">
                          <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <Badge className="bg-red-500/20 text-red-400 border-red-500/30" variant="outline">
                                CRITICAL
                              </Badge>
                              <span className="text-slate-300">SQL Injection</span>
                            </div>
                            <p className="text-slate-400 mb-3">
                              Unsanitized user input in database query. Use parameterized queries instead.
                            </p>
                            <div className="flex gap-2">
                              <Button size="sm" className="bg-green-600 hover:bg-green-700">
                                Apply Fix
                              </Button>
                              <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                                Show Details
                              </Button>
                              <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                                <X className="w-4 h-4" />
                              </Button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* VS Code Bottom Bar */}
                <div className="flex items-center justify-between px-4 py-2 bg-blue-600 text-white border-t border-slate-800">
                  <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      <span>Parry</span>
                    </div>
                    <span>Scanning...</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span>2 vulnerabilities found</span>
                    <SettingsIcon className="w-4 h-4 cursor-pointer" />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Parry Sidebar Panel */}
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-slate-50 flex items-center gap-2">
                  <Shield className="w-5 h-5 text-blue-500" />
                  Parry Security
                </CardTitle>
                <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Scan Now
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {/* Security Status */}
              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 mb-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-slate-300">Security Score</span>
                  <span className="text-slate-50">78/100</span>
                </div>
                <div className="flex items-center gap-2 text-slate-400">
                  <AlertTriangle className="w-4 h-4 text-yellow-500" />
                  <span>2 issues need attention</span>
                </div>
              </div>

              {/* Issues List */}
              <div className="space-y-3">
                <div className="text-slate-400 mb-2">PROBLEMS (2)</div>
                {vulnerabilities.map((vuln, index) => (
                  <div 
                    key={index}
                    className="p-3 bg-slate-950 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
                  >
                    <div className="flex items-start gap-2 mb-2">
                      <AlertTriangle className={`w-4 h-4 flex-shrink-0 mt-0.5 ${vuln.severity === 'critical' ? 'text-red-500' : 'text-orange-500'}`} />
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge 
                            className={`${vuln.severity === 'critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 'bg-orange-500/10 text-orange-500 border-orange-500/20'}`}
                            variant="outline"
                          >
                            {vuln.severity.toUpperCase()}
                          </Badge>
                        </div>
                        <div className="text-slate-300 mb-1">{vuln.type}</div>
                        <div className="text-slate-400 mb-2">{vuln.message}</div>
                        <div className="text-slate-500">
                          {vuln.file}:{vuln.line}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Quick Actions */}
              <div className="mt-6 space-y-2">
                <Button variant="outline" className="w-full justify-start border-slate-700 text-slate-300">
                  <CheckCircle2 className="w-4 h-4 mr-2" />
                  Apply All Fixes
                </Button>
                <Button variant="outline" className="w-full justify-start border-slate-700 text-slate-300">
                  <SettingsIcon className="w-4 h-4 mr-2" />
                  Configure Rules
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Features */}
        <div className="grid md:grid-cols-3 gap-6 mt-6">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-slate-50">Real-Time Scanning</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-slate-400">
                Vulnerabilities are detected as you type, with inline warnings and suggestions directly in your editor.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-slate-50">One-Click Fixes</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-slate-400">
                AI-generated fixes can be applied with a single click, saving time and reducing manual code changes.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-slate-50">Works Offline</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-slate-400">
                Basic scanning works offline. Connect to Parry cloud for AI-powered fixes and advanced features.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
