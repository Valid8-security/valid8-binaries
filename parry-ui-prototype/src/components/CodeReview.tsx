import { useState } from "react";
import { CheckCircle2, XCircle, MessageSquare, ThumbsUp, ThumbsDown, GitPullRequest, Copy, Download } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Textarea } from "./ui/textarea";
import { Separator } from "./ui/separator";
import { toast } from "sonner@2.0.3";

export function CodeReview() {
  const [feedback, setFeedback] = useState("");
  const [isApplying, setIsApplying] = useState(false);

  const handleApplyFix = () => {
    setIsApplying(true);
    setTimeout(() => {
      setIsApplying(false);
      toast.success("Fix applied successfully! Creating pull request...");
    }, 2000);
  };

  const handleCopyCode = () => {
    toast.success("Code copied to clipboard");
  };

  const vulnerableLines = [
    { num: 45, code: "async function getUserById(req, res) {", highlight: false },
    { num: 46, code: "  const userId = req.params.id;", highlight: false },
    { num: 47, code: "  ", highlight: false },
    { num: 48, code: "  // Vulnerable code - direct string concatenation", highlight: true, type: "remove" },
    { num: 49, code: "  const query = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";", highlight: true, type: "remove" },
    { num: 50, code: "  ", highlight: false },
    { num: 51, code: "  const result = await db.execute(query);", highlight: false },
    { num: 52, code: "  res.json(result);", highlight: false },
    { num: 53, code: "}", highlight: false },
  ];

  const fixedLines = [
    { num: 45, code: "async function getUserById(req, res) {", highlight: false },
    { num: 46, code: "  const userId = req.params.id;", highlight: false },
    { num: 47, code: "  ", highlight: false },
    { num: 48, code: "  // Fixed code - using parameterized query", highlight: true, type: "add" },
    { num: 49, code: "  const query = \"SELECT * FROM users WHERE id = ?\";", highlight: true, type: "add" },
    { num: 50, code: "  ", highlight: false },
    { num: 51, code: "  const result = await db.execute(query, [userId]);", highlight: true, type: "modify" },
    { num: 52, code: "  res.json(result);", highlight: false },
    { num: 53, code: "}", highlight: false },
  ];

  const getLineStyle = (type?: string) => {
    if (type === "remove") return "bg-red-500/10 border-l-2 border-red-500";
    if (type === "add") return "bg-green-500/10 border-l-2 border-green-500";
    if (type === "modify") return "bg-blue-500/10 border-l-2 border-blue-500";
    return "";
  };

  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="container mx-auto max-w-7xl">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-2 text-slate-400 mb-4">
            <span>Dashboard</span>
            <span>/</span>
            <span>Vulnerabilities</span>
            <span>/</span>
            <span className="text-slate-50">Code Review</span>
          </div>
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <Badge className="bg-red-500/10 text-red-500 border-red-500/20" variant="outline">
                  CRITICAL
                </Badge>
                <h1 className="text-slate-50">SQL Injection - api/users/controller.js:47</h1>
              </div>
              <p className="text-slate-400">
                Review AI-generated fix and apply changes
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" className="border-slate-700 text-slate-300">
                <XCircle className="w-4 h-4 mr-2" />
                Reject
              </Button>
              <Button 
                onClick={handleApplyFix} 
                disabled={isApplying}
                className="bg-green-600 hover:bg-green-700"
              >
                <CheckCircle2 className="w-4 h-4 mr-2" />
                {isApplying ? "Applying..." : "Apply & Create PR"}
              </Button>
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Code Comparison */}
          <div className="lg:col-span-2 space-y-6">
            {/* Split View */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-slate-50">Code Comparison</CardTitle>
                  <div className="flex items-center gap-2">
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-300" onClick={handleCopyCode}>
                      <Copy className="w-4 h-4 mr-2" />
                      Copy
                    </Button>
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-300">
                      <Download className="w-4 h-4 mr-2" />
                      Export
                    </Button>
                  </div>
                </div>
                <CardDescription className="text-slate-400">
                  Side-by-side comparison of vulnerable and fixed code
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4">
                  {/* Vulnerable Code */}
                  <div>
                    <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800">
                      <XCircle className="w-4 h-4 text-red-500" />
                      <span className="text-slate-300">Vulnerable Code</span>
                      <Badge className="bg-red-500/10 text-red-500 border-red-500/20" variant="outline">
                        Before
                      </Badge>
                    </div>
                    <div className="bg-slate-950 rounded-lg overflow-hidden font-mono">
                      {vulnerableLines.map((line) => (
                        <div 
                          key={line.num} 
                          className={`flex ${line.highlight ? getLineStyle(line.type) : ""}`}
                        >
                          <span className="text-slate-600 px-3 py-1 select-none w-12 text-right flex-shrink-0">
                            {line.num}
                          </span>
                          <pre className="text-slate-300 px-3 py-1 flex-1 overflow-x-auto">
                            <code>{line.code}</code>
                          </pre>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Fixed Code */}
                  <div>
                    <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800">
                      <CheckCircle2 className="w-4 h-4 text-green-500" />
                      <span className="text-slate-300">Fixed Code</span>
                      <Badge className="bg-green-500/10 text-green-500 border-green-500/20" variant="outline">
                        After
                      </Badge>
                    </div>
                    <div className="bg-slate-950 rounded-lg overflow-hidden font-mono">
                      {fixedLines.map((line) => (
                        <div 
                          key={line.num} 
                          className={`flex ${line.highlight ? getLineStyle(line.type) : ""}`}
                        >
                          <span className="text-slate-600 px-3 py-1 select-none w-12 text-right flex-shrink-0">
                            {line.num}
                          </span>
                          <pre className="text-slate-300 px-3 py-1 flex-1 overflow-x-auto">
                            <code>{line.code}</code>
                          </pre>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Legend */}
                <div className="flex items-center gap-6 mt-4 pt-4 border-t border-slate-800">
                  <div className="flex items-center gap-2 text-slate-400">
                    <div className="w-3 h-3 bg-red-500/20 border-l-2 border-red-500" />
                    <span>Removed</span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <div className="w-3 h-3 bg-green-500/20 border-l-2 border-green-500" />
                    <span>Added</span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <div className="w-3 h-3 bg-blue-500/20 border-l-2 border-blue-500" />
                    <span>Modified</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* AI Explanation */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Fix Explanation</CardTitle>
                <CardDescription className="text-slate-400">
                  Why this fix resolves the vulnerability
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <h4 className="text-slate-300 mb-2">Problem</h4>
                  <p className="text-slate-400">
                    The original code directly concatenates user input (`userId`) into the SQL query string. 
                    This allows attackers to inject malicious SQL code by providing crafted input values.
                  </p>
                </div>

                <Separator className="bg-slate-800" />

                <div>
                  <h4 className="text-slate-300 mb-2">Solution</h4>
                  <p className="text-slate-400">
                    The fix uses parameterized queries (prepared statements) with placeholders (`?`). 
                    The user input is passed separately as an array parameter, ensuring proper escaping and type validation.
                  </p>
                </div>

                <Separator className="bg-slate-800" />

                <div>
                  <h4 className="text-slate-300 mb-2">Benefits</h4>
                  <ul className="list-disc list-inside space-y-1 text-slate-400">
                    <li>Prevents SQL injection attacks completely</li>
                    <li>Better performance through query plan caching</li>
                    <li>Automatic type checking and validation</li>
                    <li>Industry standard security practice</li>
                  </ul>
                </div>

                <Separator className="bg-slate-800" />

                <div>
                  <h4 className="text-slate-300 mb-2">Testing Recommendation</h4>
                  <p className="text-slate-400 mb-2">
                    After applying this fix, test with the following inputs to verify security:
                  </p>
                  <ul className="list-disc list-inside space-y-1 text-slate-400">
                    <li>Normal user IDs (e.g., "123")</li>
                    <li>SQL injection attempts (e.g., "1' OR '1'='1")</li>
                    <li>Special characters and edge cases</li>
                  </ul>
                </div>
              </CardContent>
            </Card>

            {/* Feedback */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50 flex items-center gap-2">
                  <MessageSquare className="w-5 h-5" />
                  Provide Feedback
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Help improve AI suggestions by rating this fix
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="outline" className="border-green-500/30 text-green-400 hover:bg-green-500/10">
                    <ThumbsUp className="w-4 h-4 mr-2" />
                    Helpful
                  </Button>
                  <Button size="sm" variant="outline" className="border-red-500/30 text-red-400 hover:bg-red-500/10">
                    <ThumbsDown className="w-4 h-4 mr-2" />
                    Not Helpful
                  </Button>
                </div>
                
                <Textarea 
                  placeholder="Add comments or suggestions (optional)..."
                  value={feedback}
                  onChange={(e) => setFeedback(e.target.value)}
                  className="bg-slate-950 border-slate-800 text-slate-300"
                  rows={3}
                />
                
                <Button variant="outline" className="border-slate-700 text-slate-300">
                  Submit Feedback
                </Button>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Fix Confidence */}
            <Card className="bg-gradient-to-br from-green-950 to-slate-900 border-green-500/30">
              <CardHeader>
                <CardTitle className="text-slate-50">AI Confidence Score</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-center mb-4">
                  <div className="text-green-400">98%</div>
                  <p className="text-slate-400">High Confidence</p>
                </div>
                <div className="space-y-2 text-slate-300">
                  <div className="flex items-center justify-between">
                    <span>Syntax Accuracy</span>
                    <span className="text-green-400">100%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Security Best Practice</span>
                    <span className="text-green-400">100%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Context Awareness</span>
                    <span className="text-green-400">95%</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* PR Preview */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50 flex items-center gap-2">
                  <GitPullRequest className="w-5 h-5" />
                  Pull Request Preview
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <label className="text-slate-400 mb-1 block">Title</label>
                  <div className="text-slate-300 p-2 bg-slate-950 rounded border border-slate-800">
                    Fix SQL Injection in getUserById
                  </div>
                </div>
                <div>
                  <label className="text-slate-400 mb-1 block">Branch</label>
                  <div className="text-slate-300 p-2 bg-slate-950 rounded border border-slate-800">
                    parry/fix-sql-injection-VUL-2024-001
                  </div>
                </div>
                <div>
                  <label className="text-slate-400 mb-1 block">Files Changed</label>
                  <div className="text-slate-300 p-2 bg-slate-950 rounded border border-slate-800">
                    1 file • +2 -2 lines
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50">Testing</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <Button variant="outline" className="w-full justify-start border-slate-700 text-slate-300 hover:bg-slate-800">
                  Run Security Tests
                </Button>
                <Button variant="outline" className="w-full justify-start border-slate-700 text-slate-300 hover:bg-slate-800">
                  Run Unit Tests
                </Button>
                <Button variant="outline" className="w-full justify-start border-slate-700 text-slate-300 hover:bg-slate-800">
                  Preview in Sandbox
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
