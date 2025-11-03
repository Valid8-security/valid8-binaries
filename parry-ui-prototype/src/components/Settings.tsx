import { Github, Bell, Users, Shield, Slack, Mail, Webhook, Key } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Switch } from "./ui/switch";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Separator } from "./ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { Badge } from "./ui/badge";

export function Settings() {
  const connectedRepos = [
    { name: "frontend-app", branch: "main", autoScan: true, autoFix: true },
    { name: "backend-api", branch: "develop", autoScan: true, autoFix: false },
    { name: "mobile-ios", branch: "main", autoScan: true, autoFix: true },
  ];

  const teamMembers = [
    { name: "John Doe", email: "john@example.com", role: "Admin", status: "active" },
    { name: "Jane Smith", email: "jane@example.com", role: "Developer", status: "active" },
    { name: "Mike Johnson", email: "mike@example.com", role: "Developer", status: "active" },
  ];

  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="container mx-auto max-w-5xl">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-slate-50 mb-2">Settings</h1>
          <p className="text-slate-400">Manage your security scanner configuration and integrations</p>
        </div>

        {/* Tabs */}
        <Tabs defaultValue="repositories" className="space-y-6">
          <TabsList className="bg-slate-900 border border-slate-800">
            <TabsTrigger value="repositories">
              <Github className="w-4 h-4 mr-2" />
              Repositories
            </TabsTrigger>
            <TabsTrigger value="notifications">
              <Bell className="w-4 h-4 mr-2" />
              Notifications
            </TabsTrigger>
            <TabsTrigger value="team">
              <Users className="w-4 h-4 mr-2" />
              Team
            </TabsTrigger>
            <TabsTrigger value="security">
              <Shield className="w-4 h-4 mr-2" />
              Security Rules
            </TabsTrigger>
            <TabsTrigger value="integrations">
              <Webhook className="w-4 h-4 mr-2" />
              Integrations
            </TabsTrigger>
          </TabsList>

          {/* Repositories Tab */}
          <TabsContent value="repositories" className="space-y-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-slate-50">Connected Repositories</CardTitle>
                    <CardDescription className="text-slate-400">
                      Manage repositories being monitored by Parry
                    </CardDescription>
                  </div>
                  <Button className="bg-blue-600 hover:bg-blue-700">
                    <Github className="w-4 h-4 mr-2" />
                    Add Repository
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {connectedRepos.map((repo, index) => (
                    <div key={index} className="p-4 rounded-lg border border-slate-800">
                      <div className="flex items-start justify-between mb-4">
                        <div>
                          <div className="text-slate-50 mb-1">{repo.name}</div>
                          <div className="text-slate-400">Branch: {repo.branch}</div>
                        </div>
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30" variant="outline">
                          Active
                        </Badge>
                      </div>

                      <Separator className="bg-slate-800 my-4" />

                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="text-slate-300 mb-1">Auto Scan on Push</div>
                            <div className="text-slate-400">Automatically scan code on every push</div>
                          </div>
                          <Switch checked={repo.autoScan} />
                        </div>

                        <div className="flex items-center justify-between">
                          <div>
                            <div className="text-slate-300 mb-1">Auto-Fix Enabled</div>
                            <div className="text-slate-400">Automatically create PRs for fixes</div>
                          </div>
                          <Switch checked={repo.autoFix} />
                        </div>
                      </div>

                      <div className="flex gap-2 mt-4">
                        <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                          Configure
                        </Button>
                        <Button size="sm" variant="outline" className="border-red-500/30 text-red-400">
                          Remove
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Scan Frequency</CardTitle>
                <CardDescription className="text-slate-400">
                  Configure how often scans run
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label className="text-slate-300">Schedule Type</Label>
                  <Select defaultValue="push">
                    <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-300 mt-2">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-800">
                      <SelectItem value="push">On every push</SelectItem>
                      <SelectItem value="daily">Daily</SelectItem>
                      <SelectItem value="weekly">Weekly</SelectItem>
                      <SelectItem value="manual">Manual only</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div>
                    <div className="text-slate-300 mb-1">Deep Scan Mode</div>
                    <div className="text-slate-400">More thorough but slower scanning</div>
                  </div>
                  <Switch />
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Notifications Tab */}
          <TabsContent value="notifications" className="space-y-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Email Notifications</CardTitle>
                <CardDescription className="text-slate-400">
                  Choose when to receive email alerts
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="flex items-center gap-3">
                    <Mail className="w-5 h-5 text-blue-400" />
                    <div>
                      <div className="text-slate-300">Critical Vulnerabilities</div>
                      <div className="text-slate-400">Get notified immediately</div>
                    </div>
                  </div>
                  <Switch defaultChecked />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="flex items-center gap-3">
                    <Mail className="w-5 h-5 text-blue-400" />
                    <div>
                      <div className="text-slate-300">Weekly Summary</div>
                      <div className="text-slate-400">Receive weekly reports</div>
                    </div>
                  </div>
                  <Switch defaultChecked />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="flex items-center gap-3">
                    <Mail className="w-5 h-5 text-blue-400" />
                    <div>
                      <div className="text-slate-300">Auto-Fix Applied</div>
                      <div className="text-slate-400">When fixes are automatically applied</div>
                    </div>
                  </div>
                  <Switch />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="flex items-center gap-3">
                    <Mail className="w-5 h-5 text-blue-400" />
                    <div>
                      <div className="text-slate-300">Scan Completed</div>
                      <div className="text-slate-400">When scans finish</div>
                    </div>
                  </div>
                  <Switch />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Notification Channels</CardTitle>
                <CardDescription className="text-slate-400">
                  Configure where notifications are sent
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <Label className="text-slate-300">Email Address</Label>
                  <Input 
                    type="email"
                    defaultValue="john@example.com"
                    className="bg-slate-950 border-slate-800 text-slate-300 mt-2"
                  />
                </div>
                <div>
                  <Label className="text-slate-300">Severity Threshold</Label>
                  <Select defaultValue="medium">
                    <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-300 mt-2">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-800">
                      <SelectItem value="critical">Critical only</SelectItem>
                      <SelectItem value="high">High and above</SelectItem>
                      <SelectItem value="medium">Medium and above</SelectItem>
                      <SelectItem value="all">All severities</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Team Tab */}
          <TabsContent value="team" className="space-y-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-slate-50">Team Members</CardTitle>
                    <CardDescription className="text-slate-400">
                      Manage team access and permissions
                    </CardDescription>
                  </div>
                  <Button className="bg-blue-600 hover:bg-blue-700">
                    <Users className="w-4 h-4 mr-2" />
                    Invite Member
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {teamMembers.map((member, index) => (
                    <div key={index} className="flex items-center justify-between p-3 rounded-lg border border-slate-800">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-blue-600 flex items-center justify-center text-white">
                          {member.name.split(' ').map(n => n[0]).join('')}
                        </div>
                        <div>
                          <div className="text-slate-300">{member.name}</div>
                          <div className="text-slate-400">{member.email}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge className="bg-slate-800 text-slate-300" variant="outline">
                          {member.role}
                        </Badge>
                        <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                          Edit
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Security Rules Tab */}
          <TabsContent value="security" className="space-y-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Security Rule Sets</CardTitle>
                <CardDescription className="text-slate-400">
                  Configure which security rules to apply
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div>
                    <div className="text-slate-300 mb-1">OWASP Top 10</div>
                    <div className="text-slate-400">Standard web application risks</div>
                  </div>
                  <Switch defaultChecked />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div>
                    <div className="text-slate-300 mb-1">CWE Top 25</div>
                    <div className="text-slate-400">Most dangerous software weaknesses</div>
                  </div>
                  <Switch defaultChecked />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div>
                    <div className="text-slate-300 mb-1">Dependency Vulnerabilities</div>
                    <div className="text-slate-400">Check for known CVEs in packages</div>
                  </div>
                  <Switch defaultChecked />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div>
                    <div className="text-slate-300 mb-1">Secret Detection</div>
                    <div className="text-slate-400">Detect hardcoded credentials</div>
                  </div>
                  <Switch defaultChecked />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div>
                    <div className="text-slate-300 mb-1">Custom Rules</div>
                    <div className="text-slate-400">Your organization-specific rules</div>
                  </div>
                  <Switch />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Severity Thresholds</CardTitle>
                <CardDescription className="text-slate-400">
                  Define minimum severity to trigger actions
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label className="text-slate-300">Block Pull Requests</Label>
                  <Select defaultValue="critical">
                    <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-300 mt-2">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-800">
                      <SelectItem value="critical">Critical only</SelectItem>
                      <SelectItem value="high">High and above</SelectItem>
                      <SelectItem value="medium">Medium and above</SelectItem>
                      <SelectItem value="never">Never block</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label className="text-slate-300">Auto-Fix Threshold</Label>
                  <Select defaultValue="high">
                    <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-300 mt-2">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-800">
                      <SelectItem value="critical">Critical only</SelectItem>
                      <SelectItem value="high">High and above</SelectItem>
                      <SelectItem value="medium">Medium and above</SelectItem>
                      <SelectItem value="all">All severities</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Integrations Tab */}
          <TabsContent value="integrations" className="space-y-6">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Available Integrations</CardTitle>
                <CardDescription className="text-slate-400">
                  Connect Parry with your development tools
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between p-4 rounded-lg border border-slate-800">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
                      <Slack className="w-5 h-5 text-purple-400" />
                    </div>
                    <div>
                      <div className="text-slate-300 mb-1">Slack</div>
                      <div className="text-slate-400">Get notifications in Slack channels</div>
                    </div>
                  </div>
                  <Button variant="outline" className="border-green-500/30 text-green-400">
                    Connected
                  </Button>
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg border border-slate-800">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
                      <Github className="w-5 h-5 text-blue-400" />
                    </div>
                    <div>
                      <div className="text-slate-300 mb-1">GitHub</div>
                      <div className="text-slate-400">Required for repository access</div>
                    </div>
                  </div>
                  <Button variant="outline" className="border-green-500/30 text-green-400">
                    Connected
                  </Button>
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg border border-slate-800">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-cyan-500/20 rounded-lg flex items-center justify-center">
                      <Webhook className="w-5 h-5 text-cyan-400" />
                    </div>
                    <div>
                      <div className="text-slate-300 mb-1">Webhooks</div>
                      <div className="text-slate-400">Send events to custom endpoints</div>
                    </div>
                  </div>
                  <Button className="bg-blue-600 hover:bg-blue-700">
                    Configure
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">API Access</CardTitle>
                <CardDescription className="text-slate-400">
                  Manage API keys for programmatic access
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Key className="w-4 h-4 text-slate-400" />
                      <span className="text-slate-300">Production API Key</span>
                    </div>
                    <Badge className="bg-green-500/20 text-green-400 border-green-500/30" variant="outline">
                      Active
                    </Badge>
                  </div>
                  <code className="text-slate-400">parry_prod_••••••••••••</code>
                </div>

                <Button className="w-full bg-blue-600 hover:bg-blue-700">
                  Generate New API Key
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
