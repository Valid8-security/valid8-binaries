import { GitPullRequest, AlertTriangle, CheckCircle2, MessageSquare, FileCode, Clock, Bot } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Separator } from "./ui/separator";
import { Avatar, AvatarFallback } from "./ui/avatar";

export function PullRequestView() {
  const prChecks = [
    { name: "Parry Security Scan", status: "failed", time: "32s", vulnerabilities: 3 },
    { name: "Tests", status: "passed", time: "2m 15s" },
    { name: "Build", status: "passed", time: "1m 45s" },
    { name: "Lint", status: "passed", time: "18s" },
  ];

  const vulnerabilityComments = [
    {
      file: "api/users/controller.js",
      line: 47,
      severity: "critical",
      type: "SQL Injection",
      author: "parry-bot",
      time: "2 minutes ago",
      code: `const query = "SELECT * FROM users WHERE id = '" + userId + "'";`,
      message: "🔴 Critical: SQL Injection vulnerability detected",
      suggestion: `const query = "SELECT * FROM users WHERE id = ?";
const result = await db.execute(query, [userId]);`,
      confidence: 98
    },
    {
      file: "components/UserForm.tsx",
      line: 23,
      severity: "high",
      type: "XSS Vulnerability",
      author: "parry-bot",
      time: "2 minutes ago",
      code: `<div dangerouslySetInnerHTML={{__html: userInput}} />`,
      message: "🟠 High: Cross-Site Scripting (XSS) vulnerability detected",
      suggestion: `import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />`,
      confidence: 95
    },
    {
      file: "config/database.js",
      line: 12,
      severity: "critical",
      type: "Hardcoded Secret",
      author: "parry-bot",
      time: "2 minutes ago",
      code: `const password = "MySecretPassword123";`,
      message: "🔴 Critical: Hardcoded credentials detected",
      suggestion: `const password = process.env.DB_PASSWORD;`,
      confidence: 100
    }
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "text-red-500";
      case "high": return "text-orange-500";
      case "medium": return "text-yellow-500";
      case "low": return "text-green-500";
      default: return "text-slate-500";
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500/10 text-red-500 border-red-500/20";
      case "high": return "bg-orange-500/10 text-orange-500 border-orange-500/20";
      case "medium": return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
      case "low": return "bg-green-500/10 text-green-500 border-green-500/20";
      default: return "bg-slate-500/10 text-slate-500 border-slate-500/20";
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="container mx-auto max-w-6xl">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-2 text-slate-400 mb-4">
            <span>backend-api</span>
            <span>/</span>
            <span>Pull Requests</span>
            <span>/</span>
            <span className="text-slate-50">#247</span>
          </div>
          <div className="flex items-start justify-between mb-6">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <GitPullRequest className="w-6 h-6 text-green-500" />
                <h1 className="text-slate-50">Add user authentication endpoint</h1>
                <Badge className="bg-green-500/20 text-green-400 border-green-500/30" variant="outline">
                  Open
                </Badge>
              </div>
              <p className="text-slate-400">
                john-doe wants to merge 3 commits into main from feature/auth
              </p>
            </div>
          </div>
        </div>

        {/* PR Status Checks */}
        <Card className="bg-slate-900 border-slate-800 mb-6">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-slate-50">Checks</CardTitle>
              <Badge className="bg-red-500/20 text-red-400 border-red-500/30" variant="outline">
                Some checks failed
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {prChecks.map((check, index) => (
                <div key={index} className="flex items-center justify-between p-3 rounded-lg border border-slate-800">
                  <div className="flex items-center gap-3">
                    {check.status === "failed" ? (
                      <AlertTriangle className="w-5 h-5 text-red-500" />
                    ) : (
                      <CheckCircle2 className="w-5 h-5 text-green-500" />
                    )}
                    <div>
                      <div className="text-slate-300">{check.name}</div>
                      {check.vulnerabilities && (
                        <div className="text-red-400">
                          {check.vulnerabilities} security {check.vulnerabilities === 1 ? 'issue' : 'issues'} found
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-slate-400">{check.time}</span>
                    {check.status === "failed" && (
                      <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                        Details
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Parry Bot Summary */}
        <Card className="bg-gradient-to-br from-blue-950 to-slate-900 border-blue-500/30 mb-6">
          <CardHeader>
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center flex-shrink-0">
                <Bot className="w-6 h-6 text-white" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-slate-50">parry-bot</span>
                  <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30" variant="outline">
                    AI
                  </Badge>
                  <span className="text-slate-400">commented 2 minutes ago</span>
                </div>
                <div className="text-slate-300 mb-4">
                  🛡️ Parry Security Scan detected <span className="text-red-400">3 security vulnerabilities</span> in this pull request.
                </div>
                <div className="grid grid-cols-3 gap-4 p-4 bg-slate-900/50 rounded-lg border border-slate-800">
                  <div>
                    <div className="text-red-400 mb-1">2 Critical</div>
                    <div className="text-slate-400">Require immediate attention</div>
                  </div>
                  <div>
                    <div className="text-orange-400 mb-1">1 High</div>
                    <div className="text-slate-400">Should be fixed soon</div>
                  </div>
                  <div>
                    <div className="text-green-400 mb-1">97% Confidence</div>
                    <div className="text-slate-400">AI fix suggestions ready</div>
                  </div>
                </div>
                <div className="mt-4 flex gap-2">
                  <Button size="sm" className="bg-green-600 hover:bg-green-700">
                    <CheckCircle2 className="w-4 h-4 mr-2" />
                    Apply All Fixes
                  </Button>
                  <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                    Review Each Fix
                  </Button>
                </div>
              </div>
            </div>
          </CardHeader>
        </Card>

        {/* Inline Comments on Code */}
        <div className="space-y-6">
          <h2 className="text-slate-50">File Changes with Security Issues</h2>
          
          {vulnerabilityComments.map((comment, index) => (
            <Card key={index} className="bg-slate-900 border-slate-800">
              <CardHeader>
                <div className="flex items-center gap-2 mb-2">
                  <FileCode className="w-4 h-4 text-slate-400" />
                  <span className="text-slate-300">{comment.file}</span>
                  <span className="text-slate-500">Line {comment.line}</span>
                </div>
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono">
                  <div className="flex">
                    <span className="text-slate-600 px-3 select-none">{comment.line}</span>
                    <pre className="text-slate-300 flex-1">
                      <code>{comment.code}</code>
                    </pre>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="border-l-4 border-blue-500 pl-4">
                  <div className="flex items-start gap-3 mb-4">
                    <Avatar className="w-8 h-8 bg-blue-600">
                      <AvatarFallback className="bg-blue-600 text-white">
                        <Bot className="w-4 h-4" />
                      </AvatarFallback>
                    </Avatar>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-slate-300">parry-bot</span>
                        <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30" variant="outline">
                          AI
                        </Badge>
                        <span className="text-slate-400">{comment.time}</span>
                      </div>
                      <div className="mb-3">
                        <Badge className={getSeverityBadge(comment.severity)} variant="outline">
                          {comment.severity.toUpperCase()}
                        </Badge>
                        <span className="text-slate-300 ml-2">{comment.type}</span>
                      </div>
                      <p className="text-slate-300 mb-4">{comment.message}</p>
                      
                      <div className="bg-slate-950 p-4 rounded-lg border border-green-500/30 mb-4">
                        <div className="flex items-center gap-2 mb-2">
                          <CheckCircle2 className="w-4 h-4 text-green-500" />
                          <span className="text-slate-300">Suggested Fix</span>
                          <Badge className="bg-green-500/20 text-green-400 border-green-500/30" variant="outline">
                            {comment.confidence}% Confidence
                          </Badge>
                        </div>
                        <pre className="text-slate-300 font-mono text-sm">
                          <code>{comment.suggestion}</code>
                        </pre>
                      </div>

                      <div className="flex gap-2">
                        <Button size="sm" className="bg-green-600 hover:bg-green-700">
                          Apply This Fix
                        </Button>
                        <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                          <MessageSquare className="w-4 h-4 mr-2" />
                          Reply
                        </Button>
                        <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                          Dismiss
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Merge Status */}
        <Card className="bg-slate-900 border-slate-800 mt-6">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="w-5 h-5 text-red-500" />
              <div>
                <div className="text-slate-50 mb-1">This pull request has security issues that need to be resolved</div>
                <div className="text-slate-400">3 critical/high severity vulnerabilities must be fixed before merging</div>
              </div>
            </div>
            <Button disabled className="w-full" variant="outline">
              <AlertTriangle className="w-4 h-4 mr-2" />
              Merge Blocked by Security Issues
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
