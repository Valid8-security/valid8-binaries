import {
  Shield,
  Zap,
  Lock,
  Github,
  CheckCircle2,
  ArrowRight,
  Star,
  AlertTriangle,
  Clock,
} from "lucide-react";
import { Button } from "./ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "./ui/card";
import { Badge } from "./ui/badge";
import { Progress } from "./ui/progress";
import { ImageWithFallback } from "./figma/ImageWithFallback";
import { DisclaimerBanner } from "./DisclaimerBanner";
import { Bot, GitPullRequest } from "lucide-react";

interface LandingPageProps {
  onGetStarted: () => void;
}

export function LandingPage({
  onGetStarted,
}: LandingPageProps) {
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const features = [
    {
      icon: Zap,
      title: "Real-Time Detection",
      description:
        "Catch vulnerabilities as you code with AI-powered scanning integrated directly into your workflow.",
    },
    {
      icon: Shield,
      title: "Auto-Fix Suggestions",
      description:
        "Get instant, intelligent fix recommendations with confidence scores and detailed explanations.",
    },
    {
      icon: Lock,
      title: "GitHub Actions Integration",
      description:
        "Seamlessly integrates with your CI/CD pipeline for automated security checks on every commit.",
    },
    {
      icon: Github,
      title: "Multi-Language Support",
      description:
        "Supports JavaScript, Python, Java, Go, and more with language-specific security rules.",
    },
  ];

  const pricingTiers = [
    {
      name: "Free",
      price: "0",
      description: "Perfect for individual developers",
      features: [
        "Up to 5 repositories",
        "Basic vulnerability detection",
        "Community support",
        "Weekly scans",
      ],
      cta: "Start Free",
    },
    {
      name: "Pro",
      price: "49",
      description: "For professional developers",
      features: [
        "Unlimited repositories",
        "AI-powered auto-fix",
        "Real-time scanning",
        "Priority support",
        "Custom rules",
        "Slack integration",
      ],
      cta: "Start Free Trial",
      popular: true,
    },
    {
      name: "Business",
      price: "149",
      description: "For teams and enterprises",
      features: [
        "Everything in Pro",
        "Team management",
        "Advanced analytics",
        "Compliance reporting",
        "SLA guarantee",
        "Dedicated support",
      ],
      cta: "Contact Sales",
    },
  ];

  const testimonials = [
    {
      name: "Sarah Chen",
      role: "Lead Developer at TechCorp",
      content:
        "Parry has saved us countless hours. It's like having a security expert reviewing every line of code.",
      avatar:
        "https://images.unsplash.com/photo-1425421669292-0c3da3b8f529?w=100&h=100&fit=crop",
    },
    {
      name: "Michael Rodriguez",
      role: "CTO at StartupXYZ",
      content:
        "The AI-generated fixes are incredibly accurate. We've reduced our vulnerability count by 80% in just 3 months.",
      avatar:
        "https://images.unsplash.com/photo-1425421669292-0c3da3b8f529?w=100&h=100&fit=crop",
    },
    {
      name: "Emily Thompson",
      role: "Security Engineer at DevSecure",
      content:
        "Finally, a security tool that developers actually enjoy using. The integration with our workflow is seamless.",
      avatar:
        "https://images.unsplash.com/photo-1425421669292-0c3da3b8f529?w=100&h=100&fit=crop",
    },
  ];

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Navigation */}
      <nav className="border-b border-slate-800 bg-slate-900/50 backdrop-blur">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <span className="text-white">
                Parry Security Scanner
              </span>
            </div>

            <div className="flex items-center gap-4">
              <Button
                variant="ghost"
                onClick={() => scrollToSection('features')}
                className="text-slate-300 hover:text-white"
              >
                Documentation
              </Button>
              <Button
                variant="ghost"
                onClick={() => scrollToSection('pricing')}
                className="text-slate-300 hover:text-white"
              >
                Pricing
              </Button>
              <Button onClick={onGetStarted}>
                Get Started
              </Button>
            </div>
          </div>
        </div>
      </nav>
      <DisclaimerBanner />

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-blue-500/10 via-transparent to-cyan-500/10" />
        <div className="container mx-auto px-4 py-24 relative">
          <div className="max-w-4xl mx-auto text-center">
            <Badge className="mb-6 bg-blue-500/20 text-blue-300 border-blue-500/30">
              The Spell-Check for Security Bugs
            </Badge>
            <h1 className="text-slate-50 mb-6">
              AI-Powered Security Scanning for Modern
              Development
            </h1>
            <p className="text-slate-400 text-xl mb-8 max-w-2xl mx-auto">
              Detect and fix vulnerabilities in real-time with
              AI-powered scanning that integrates seamlessly
              into your GitHub Actions workflow.
            </p>
            <div className="flex items-center justify-center gap-4 mb-12">
              <Button
                size="lg"
                onClick={onGetStarted}
                className="bg-blue-600 hover:bg-blue-700"
              >
                Start Free Trial
                <ArrowRight className="ml-2 w-4 h-4" />
              </Button>
              <Button
                size="lg"
                variant="outline"
                className="border-slate-600 text-slate-200 hover:bg-slate-800 hover:text-white hover:border-slate-500"
              >
                <Github className="mr-2 w-4 h-4" />
                View on GitHub
              </Button>
            </div>

            <div className="flex items-center justify-center gap-8 text-slate-400">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-green-500" />
                <span>Free 14-day trial</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-green-500" />
                <span>No credit card required</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-green-500" />
                <span>Cancel anytime</span>
              </div>
            </div>
          </div>

          {/* Hero Image/Dashboard Preview */}
          <div className="mt-16 max-w-6xl mx-auto relative h-[580px]">
            {/* VSCode IDE Screen - Background */}
            <div className="absolute top-0 left-0 w-[55%] z-10 transform rotate-[-2deg]">
              <div className="relative rounded-xl border border-slate-800 overflow-hidden bg-[#1e1e1e] backdrop-blur shadow-2xl">
                {/* VSCode Title Bar */}
                <div className="h-8 bg-[#323233] border-b border-[#2d2d30] flex items-center px-4 gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500" />
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                  <span className="ml-2 text-slate-400 text-xs">auth.js - MyProject</span>
                </div>
                
                <div className="flex">
                  {/* VSCode Sidebar */}
                  <div className="w-12 bg-[#333333] border-r border-[#2d2d30] flex flex-col items-center py-3 gap-4">
                    <div className="w-6 h-6 text-slate-400">
                      <svg viewBox="0 0 24 24" fill="currentColor">
                        <path d="M3 3h7v7H3V3m0 11h7v7H3v-7m11-11h7v7h-7V3m0 11h7v7h-7v-7z"/>
                      </svg>
                    </div>
                    <div className="w-6 h-6 text-blue-400">
                      <svg viewBox="0 0 24 24" fill="currentColor">
                        <path d="M13 9h5.5L13 3.5V9M6 2h8l6 6v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4c0-1.11.89-2 2-2m9 16v-2h-2v2h2m-6 0v-2H7v2h2z"/>
                      </svg>
                    </div>
                  </div>
                  
                  {/* File Explorer */}
                  <div className="w-48 bg-[#252526] border-r border-[#2d2d30] p-2 text-xs">
                    <div className="text-slate-400 mb-2 uppercase text-[10px]">Explorer</div>
                    <div className="space-y-1">
                      <div className="text-slate-400">📁 src</div>
                      <div className="pl-3 space-y-1">
                        <div className="text-slate-300 bg-[#37373d] px-1">📄 auth.js</div>
                        <div className="text-slate-400">📄 db.js</div>
                        <div className="text-slate-400">📄 index.js</div>
                      </div>
                    </div>
                  </div>
                  
                  {/* Code Editor */}
                  <div className="flex-1">
                    {/* Tab Bar */}
                    <div className="h-9 bg-[#2d2d2d] border-b border-[#2d2d30] flex items-center px-2">
                      <div className="bg-[#1e1e1e] border-t-2 border-blue-500 px-3 py-1 text-slate-300 text-xs flex items-center gap-2">
                        <span>auth.js</span>
                        <span className="text-slate-500">×</span>
                      </div>
                    </div>
                    
                    {/* Code Area */}
                    <div className="p-4 font-mono text-[11px] leading-relaxed">
                      <div className="space-y-1">
                        <div><span className="text-slate-500 select-none mr-4">1</span><span className="text-[#C586C0]">const</span> <span className="text-[#9CDCFE]">express</span> <span className="text-slate-400">=</span> <span className="text-[#DCDCAA]">require</span><span className="text-slate-400">(</span><span className="text-[#CE9178]">'express'</span><span className="text-slate-400">);</span></div>
                        <div><span className="text-slate-500 select-none mr-4">2</span><span className="text-[#C586C0]">const</span> <span className="text-[#9CDCFE]">db</span> <span className="text-slate-400">=</span> <span className="text-[#DCDCAA]">require</span><span className="text-slate-400">(</span><span className="text-[#CE9178]">'./db'</span><span className="text-slate-400">);</span></div>
                        <div><span className="text-slate-500 select-none mr-4">3</span></div>
                        <div><span className="text-slate-500 select-none mr-4">4</span><span className="text-[#9CDCFE]">app</span><span className="text-slate-400">.</span><span className="text-[#DCDCAA]">post</span><span className="text-slate-400">(</span><span className="text-[#CE9178]">'/login'</span><span className="text-slate-400">,</span> <span className="text-[#C586C0]">async</span> <span className="text-slate-400">(</span><span className="text-[#9CDCFE]">req</span><span className="text-slate-400">,</span> <span className="text-[#9CDCFE]">res</span><span className="text-slate-400">)</span> <span className="text-[#C586C0]">=&gt;</span> <span className="text-slate-400">{"{"}</span></div>
                        <div><span className="text-slate-500 select-none mr-4">5</span><span className="ml-4"><span className="text-[#C586C0]">const</span> <span className="text-slate-400">{"{"}</span> <span className="text-[#9CDCFE]">username</span><span className="text-slate-400">,</span> <span className="text-[#9CDCFE]">password</span> <span className="text-slate-400">{"}"}</span> <span className="text-slate-400">=</span> <span className="text-[#9CDCFE]">req</span><span className="text-slate-400">.</span><span className="text-[#9CDCFE]">body</span><span className="text-slate-400">;</span></span></div>
                        <div><span className="text-slate-500 select-none mr-4">6</span></div>
                        
                        {/* Highlighted vulnerable line with squiggly underline */}
                        <div className="relative bg-yellow-500/10 border-l-2 border-yellow-500">
                          <span className="text-slate-500 select-none mr-4">7</span>
                          <span className="ml-4">
                            <span className="text-[#C586C0]">const</span> <span className="text-[#9CDCFE]">query</span> <span className="text-slate-400">=</span> <span className="text-[#CE9178]">`SELECT * FROM users WHERE username='</span>
                            <span className="text-[#CE9178] relative">
                              ${"{username}"}
                              <span className="absolute bottom-0 left-0 right-0 h-[2px] border-b-2 border-yellow-500 border-dotted"></span>
                            </span>
                            <span className="text-[#CE9178]">'`</span><span className="text-slate-400">;</span>
                          </span>
                          
                          {/* VSCode Tooltip with fix suggestion */}
                          <div className="absolute left-full ml-4 top-0 w-80 bg-[#2d2d30] border border-[#454545] rounded-md shadow-2xl overflow-hidden z-20">
                            <div className="bg-[#3c3c3c] px-3 py-2 border-b border-[#454545] flex items-center gap-2">
                              <Shield className="w-4 h-4 text-yellow-500" />
                              <span className="text-yellow-500 text-xs font-semibold">Security Vulnerability Detected</span>
                            </div>
                            <div className="p-3">
                              <div className="flex items-start gap-2 mb-3">
                                <div className="flex-1">
                                  <div className="text-slate-200 text-xs mb-1">SQL Injection</div>
                                  <div className="text-slate-400 text-[10px]">High Severity • Parry Security</div>
                                </div>
                              </div>
                              <div className="text-slate-300 text-[11px] leading-relaxed mb-3">
                                User input is directly concatenated into SQL query. This allows attackers to inject malicious SQL code.
                              </div>
                              <div className="text-slate-400 text-[10px] mb-2">Suggested fix:</div>
                              <div className="bg-[#1e1e1e] rounded p-2 text-[10px] font-mono mb-3 space-y-1">
                                <div className="text-green-400">+ const query = 'SELECT * FROM users WHERE username = ?';</div>
                                <div className="text-green-400">+ const result = await db.query(query, [username]);</div>
                              </div>
                              <Button size="sm" className="w-full bg-blue-600 hover:bg-blue-700 text-[11px] h-6">
                                Quick Fix
                              </Button>
                            </div>
                          </div>
                        </div>
                        
                        <div><span className="text-slate-500 select-none mr-4">8</span><span className="ml-4"><span className="text-[#C586C0]">const</span> <span className="text-[#9CDCFE]">result</span> <span className="text-slate-400">=</span> <span className="text-[#C586C0]">await</span> <span className="text-[#9CDCFE]">db</span><span className="text-slate-400">.</span><span className="text-[#DCDCAA]">query</span><span className="text-slate-400">(</span><span className="text-[#9CDCFE]">query</span><span className="text-slate-400">);</span></span></div>
                        <div><span className="text-slate-500 select-none mr-4">9</span><span className="ml-4"><span className="text-[#C586C0]">return</span> <span className="text-[#9CDCFE]">res</span><span className="text-slate-400">.</span><span className="text-[#DCDCAA]">json</span><span className="text-slate-400">(</span><span className="text-[#9CDCFE]">result</span><span className="text-slate-400">);</span></span></div>
                        <div><span className="text-slate-500 select-none mr-4">10</span><span className="text-slate-400">{"}"});</span></div>
                      </div>
                    </div>
                    
                    {/* VSCode Bottom Panel - Problems Tab */}
                    <div className="border-t border-[#2d2d30] bg-[#1e1e1e]">
                      <div className="h-6 bg-[#252526] flex items-center px-2 gap-4 text-[11px]">
                        <div className="text-slate-200 flex items-center gap-1 border-b border-blue-500 pb-1">
                          <AlertTriangle className="w-3 h-3" />
                          <span>Problems</span>
                          <span className="bg-slate-700 px-1 rounded text-[9px]">1</span>
                        </div>
                        <div className="text-slate-400">Output</div>
                        <div className="text-slate-400">Terminal</div>
                        <div className="text-slate-400">Debug Console</div>
                      </div>
                      <div className="p-2 space-y-1">
                        <div className="flex items-start gap-2 text-[10px] hover:bg-[#2d2d30] p-1 rounded">
                          <AlertTriangle className="w-3 h-3 text-yellow-500 flex-shrink-0 mt-0.5" />
                          <div className="flex-1">
                            <div className="text-slate-200">SQL Injection vulnerability detected</div>
                            <div className="text-slate-400">auth.js [7, 16] - Parry Security</div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Dashboard Screen - Foreground */}
            <div className="absolute bottom-16 right-0 w-[60%] z-20 transform rotate-[1deg]">
              <div className="relative rounded-xl border border-slate-800 overflow-hidden bg-slate-950 backdrop-blur shadow-2xl max-h-[490px]">
                <div className="h-8 bg-slate-900 border-b border-slate-800 flex items-center px-4 gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500" />
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                  <span className="ml-2 text-slate-400 text-sm">github.com - Pull Request #247</span>
                </div>
                <div className="p-3 overflow-hidden" style={{ transform: 'scale(0.7)', transformOrigin: 'top left', width: '143%' }}>
                  {/* GitHub PR Interface */}
                  <div className="space-y-3">
                    {/* PR Header */}
                    <div className="flex items-start gap-2 mb-3">
                      <GitPullRequest className="w-5 h-5 text-green-500 mt-1" />
                      <div>
                        <div className="text-slate-50 text-lg mb-1">Add user authentication endpoint</div>
                        <div className="text-slate-400 text-xs">john-doe wants to merge 3 commits into main</div>
                      </div>
                    </div>

                    {/* Checks Section */}
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-3">
                        <div className="text-slate-50 text-sm">Checks</div>
                        <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-[10px]">
                          Some checks failed
                        </Badge>
                      </div>
                      <div className="space-y-2">
                        <div className="flex items-center justify-between p-2 rounded border border-slate-800 bg-red-500/5">
                          <div className="flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-red-500" />
                            <div>
                              <div className="text-slate-300 text-xs">Parry Security Scan</div>
                              <div className="text-red-400 text-[10px]">1 security issue found</div>
                            </div>
                          </div>
                          <div className="text-slate-400 text-[10px]">32s</div>
                        </div>
                        <div className="flex items-center justify-between p-2 rounded border border-slate-800">
                          <div className="flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-green-500" />
                            <div className="text-slate-300 text-xs">Tests</div>
                          </div>
                          <div className="text-slate-400 text-[10px]">2m 15s</div>
                        </div>
                      </div>
                    </div>

                    {/* Parry Bot Comment */}
                    <div className="bg-gradient-to-br from-blue-950 to-slate-900 border border-blue-500/30 rounded-lg p-3">
                      <div className="flex items-start gap-2">
                        <div className="w-7 h-7 bg-blue-600 rounded-full flex items-center justify-center flex-shrink-0">
                          <Bot className="w-4 h-4 text-white" />
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-slate-50 text-sm">parry-bot</span>
                            <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30 text-[9px] px-1 py-0">
                              AI
                            </Badge>
                            <span className="text-slate-400 text-[10px]">commented 2 min ago</span>
                          </div>
                          <div className="text-slate-300 text-xs mb-3">
                            🛡️ Parry Security Scan detected <span className="text-red-400">1 critical vulnerability</span> in this pull request.
                          </div>
                          
                          {/* Vulnerability Details */}
                          <div className="bg-slate-900/50 border border-slate-800 rounded p-2 mb-3">
                            <div className="flex items-center gap-2 mb-2">
                              <Badge className="bg-red-500/10 text-red-500 border-red-500/20 text-[9px] px-1 py-0">
                                CRITICAL
                              </Badge>
                              <span className="text-slate-300 text-xs">SQL Injection</span>
                            </div>
                            <div className="text-slate-400 text-[10px] mb-2">
                              📄 auth.js line 7
                            </div>
                            <div className="bg-slate-950 border border-slate-800 rounded p-2 mb-2">
                              <div className="font-mono text-[9px] text-slate-300 mb-1">
                                const query = `SELECT * FROM users WHERE username='${"{username}"}'`;
                              </div>
                            </div>
                            <div className="text-slate-300 text-[10px] mb-2">
                              User input is directly concatenated into SQL query.
                            </div>
                            <div className="bg-slate-950 border border-green-500/30 rounded p-2 mb-2">
                              <div className="flex items-center gap-1 mb-1">
                                <CheckCircle2 className="w-3 h-3 text-green-500" />
                                <span className="text-slate-300 text-[9px]">Suggested Fix</span>
                                <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-[8px] px-1 py-0">
                                  98% Confidence
                                </Badge>
                              </div>
                              <div className="font-mono text-[9px] text-green-400">
                                const query = 'SELECT * FROM users WHERE username = ?';<br />
                                const result = await db.query(query, [username]);
                              </div>
                            </div>
                            <div className="flex gap-1">
                              <Button size="sm" className="bg-green-600 hover:bg-green-700 text-[10px] h-5 px-2">
                                Apply Fix
                              </Button>
                              <Button size="sm" variant="outline" className="border-slate-700 text-slate-300 text-[10px] h-5 px-2">
                                Dismiss
                              </Button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Merge Status */}
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
                      <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className="w-4 h-4 text-red-500" />
                        <div className="text-slate-300 text-xs">This pull request has security issues</div>
                      </div>
                      <Button disabled className="w-full h-6 text-[10px] opacity-50" variant="outline">
                        Merge Blocked by Security Issues
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-24 bg-slate-900/50" id="features">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-slate-50 mb-4">
              Everything You Need for Secure Development
            </h2>
            <p className="text-slate-400 text-xl max-w-2xl mx-auto">
              Comprehensive security scanning with intelligent
              automation
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <Card
                  key={index}
                  className="bg-slate-900 border-slate-800"
                >
                  <CardHeader>
                    <div className="w-12 h-12 bg-blue-500/10 rounded-lg flex items-center justify-center mb-4">
                      <Icon className="w-6 h-6 text-blue-500" />
                    </div>
                    <CardTitle className="text-slate-50">
                      {feature.title}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-slate-400">
                      {feature.description}
                    </p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      {/* Comprehensive Security Coverage Section */}
      <section className="py-24">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <Badge className="mb-4 bg-green-500/20 text-green-300 border-green-500/30">
              79+ Vulnerability Classes Detected
            </Badge>
            <h2 className="text-slate-50 mb-4">
              Comprehensive Security Coverage
            </h2>
            <p className="text-slate-400 text-xl max-w-2xl mx-auto">
              Complete OWASP Top 10 2021 coverage with framework-specific and language-specific security patterns
            </p>
          </div>

          {/* Stats Grid */}
          <div className="grid md:grid-cols-4 gap-6 mb-12 max-w-5xl mx-auto">
            <Card className="bg-slate-900 border-slate-800 text-center">
              <CardHeader>
                <div className="text-4xl text-blue-500 mb-2">79+</div>
                <CardTitle className="text-slate-50">Vulnerability Classes</CardTitle>
              </CardHeader>
            </Card>
            <Card className="bg-slate-900 border-slate-800 text-center">
              <CardHeader>
                <div className="text-4xl text-green-500 mb-2">50+</div>
                <CardTitle className="text-slate-50">CWE Identifiers</CardTitle>
              </CardHeader>
            </Card>
            <Card className="bg-slate-900 border-slate-800 text-center">
              <CardHeader>
                <div className="text-4xl text-cyan-500 mb-2">10/10</div>
                <CardTitle className="text-slate-50">OWASP Coverage</CardTitle>
              </CardHeader>
            </Card>
            <Card className="bg-slate-900 border-slate-800 text-center">
              <CardHeader>
                <div className="text-4xl text-purple-500 mb-2">12+</div>
                <CardTitle className="text-slate-50">Languages</CardTitle>
              </CardHeader>
            </Card>
          </div>

          {/* Vulnerability Categories */}
          <div className="grid md:grid-cols-2 gap-6 max-w-6xl mx-auto mb-12">
            {/* Core Web Security */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50 flex items-center gap-2">
                  <Shield className="w-5 h-5 text-red-500" />
                  Core Web Security (10 patterns)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>SQL Injection (CWE-89)</span>
                    <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Critical</Badge>
                  </div>
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>Cross-Site Scripting (XSS)</span>
                    <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">High</Badge>
                  </div>
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>Command Injection</span>
                    <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Critical</Badge>
                  </div>
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>Path Traversal</span>
                    <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">High</Badge>
                  </div>
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>Hardcoded Secrets</span>
                    <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Critical</Badge>
                  </div>
                  <div className="text-slate-500 pt-2">+ 5 more patterns</div>
                </div>
              </CardContent>
            </Card>

            {/* Advanced Security Patterns */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-500" />
                  Advanced Patterns (10 patterns)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>Prototype Pollution</span>
                    <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Critical</Badge>
                  </div>
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>JWT Security Issues</span>
                    <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Critical</Badge>
                  </div>
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>GraphQL Security Issues</span>
                    <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">High</Badge>
                  </div>
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>XML External Entity (XXE)</span>
                    <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Critical</Badge>
                  </div>
                  <div className="flex items-center justify-between text-slate-300 hover:text-white transition-colors">
                    <span>NoSQL Injection</span>
                    <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Critical</Badge>
                  </div>
                  <div className="text-slate-500 pt-2">+ 5 more patterns</div>
                </div>
              </CardContent>
            </Card>

            {/* Framework-Specific */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50 flex items-center gap-2">
                  <Lock className="w-5 h-5 text-blue-500" />
                  Framework-Specific (26 patterns)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div>
                    <div className="text-slate-300 mb-2">Spring Framework (8 patterns)</div>
                    <div className="text-xs text-slate-400 space-y-1">
                      <div>• Spring SQL Injection • CORS Issues</div>
                      <div>• Security Disabled • CSRF Disabled</div>
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-300 mb-2">Django Framework (9 patterns)</div>
                    <div className="text-xs text-slate-400 space-y-1">
                      <div>• Django SSTI • Debug Enabled</div>
                      <div>• CSRF Exempt • mark_safe XSS</div>
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-300 mb-2">Ruby on Rails (9 patterns)</div>
                    <div className="text-xs text-slate-400 space-y-1">
                      <div>• Mass Assignment • Open Redirect</div>
                      <div>• Insecure Deserialization</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Language-Specific */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50 flex items-center gap-2">
                  <Github className="w-5 h-5 text-purple-500" />
                  Language-Specific (32 patterns)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div>
                    <div className="text-slate-300 mb-2">Rust Security (10 patterns)</div>
                    <div className="text-xs text-slate-400 space-y-1">
                      <div>• Unsafe Blocks • Unchecked Arithmetic</div>
                      <div>• Unsafe unwrap() • Poor expect()</div>
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-300 mb-2">Swift/iOS (11 patterns)</div>
                    <div className="text-xs text-slate-400 space-y-1">
                      <div>• Forced Unwrapping • Insecure HTTP</div>
                      <div>• Disabled SSL • Weak Cryptography</div>
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-300 mb-2">Kotlin/Android (11 patterns)</div>
                    <div className="text-xs text-slate-400 space-y-1">
                      <div>• Exported Components • Debuggable</div>
                      <div>• WebView JavaScript • Unvalidated Intents</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Security & Privacy Guarantees */}
          <Card className="bg-gradient-to-br from-green-950 to-slate-900 border-green-500/30 max-w-4xl mx-auto">
            <CardHeader>
              <CardTitle className="text-slate-50 flex items-center gap-2">
                <Lock className="w-5 h-5 text-green-500" />
                Security & Privacy Guarantees
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid md:grid-cols-2 gap-4 text-slate-300">
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="mb-1">Your Code is Secure</div>
                    <div className="text-sm text-slate-400">Code is only processed for vulnerability scanning and never stored or shared</div>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="mb-1">Custom Security Rules</div>
                    <div className="text-sm text-slate-400">Add your own company-specific security guidelines and compliance rules</div>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="mb-1">AI-Enhanced Detection</div>
                    <div className="text-sm text-slate-400">AI discovers additional vulnerability classes beyond predefined patterns</div>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="mb-1">OWASP & CWE Mapped</div>
                    <div className="text-sm text-slate-400">Every vulnerability includes OWASP references, CWE IDs, and remediation guidance</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* How It Works - GitHub Actions */}
      <section className="py-24">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-slate-50 mb-4">
              Seamless GitHub Actions Integration
            </h2>
            <p className="text-slate-400 text-xl max-w-2xl mx-auto">
              Add one simple workflow file and start scanning
              automatically
            </p>
          </div>

          <div className="max-w-4xl mx-auto">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-50 flex items-center gap-2">
                  <Github className="w-5 h-5" />
                  .github/workflows/parry-scan.yml
                </CardTitle>
              </CardHeader>
              <CardContent>
                <pre className="text-slate-300 bg-slate-950 p-4 rounded-lg overflow-x-auto">
                  {`name: Parry Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: parry-security/scan-action@v1
        with:
          api-key: \${{ secrets.PARRY_API_KEY }}
          auto-fix: true
          severity-threshold: medium`}
                </pre>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section className="py-24 bg-slate-900/50" id="pricing">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-slate-50 mb-4">
              Simple, Transparent Pricing
            </h2>
            <p className="text-slate-400 text-xl max-w-2xl mx-auto">
              Choose the plan that fits your needs
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            {pricingTiers.map((tier, index) => (
              <Card
                key={index}
                className={`relative ${tier.popular ? "bg-gradient-to-b from-blue-950 to-slate-900 border-blue-500" : "bg-slate-900 border-slate-800"}`}
              >
                {tier.popular && (
                  <div className="absolute -top-4 left-0 right-0 flex justify-center">
                    <Badge className="bg-blue-600 text-white">
                      Most Popular
                    </Badge>
                  </div>
                )}
                <CardHeader>
                  <CardTitle className="text-slate-50">
                    {tier.name}
                  </CardTitle>
                  <CardDescription className="text-slate-400">
                    {tier.description}
                  </CardDescription>
                  <div className="mt-4">
                    <span className="text-slate-50">
                      ${tier.price}
                    </span>
                    <span className="text-slate-400">
                      /month
                    </span>
                  </div>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-3">
                    {tier.features.map((feature, fIndex) => (
                      <li
                        key={fIndex}
                        className="flex items-start gap-2 text-slate-300"
                      >
                        <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
                <CardFooter>
                  <Button
                    className="w-full"
                    variant={
                      tier.popular ? "default" : "outline"
                    }
                    onClick={onGetStarted}
                  >
                    {tier.cta}
                  </Button>
                </CardFooter>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Testimonials */}
      <section className="py-24">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-slate-50 mb-4">
              Trusted by Developers Worldwide
            </h2>
            <p className="text-slate-400 text-xl max-w-2xl mx-auto">
              See what developers are saying about Parry
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            {testimonials.map((testimonial, index) => (
              <Card
                key={index}
                className="bg-slate-900 border-slate-800"
              >
                <CardHeader>
                  <div className="flex gap-1 mb-4">
                    {[...Array(5)].map((_, i) => (
                      <Star
                        key={i}
                        className="w-4 h-4 fill-yellow-500 text-yellow-500"
                      />
                    ))}
                  </div>
                  <p className="text-slate-300">
                    {testimonial.content}
                  </p>
                </CardHeader>
                <CardFooter className="flex items-center gap-3">
                  <ImageWithFallback
                    src={testimonial.avatar}
                    alt={testimonial.name}
                    className="w-10 h-10 rounded-full"
                  />
                  <div>
                    <div className="text-slate-50">
                      {testimonial.name}
                    </div>
                    <div className="text-slate-400">
                      {testimonial.role}
                    </div>
                  </div>
                </CardFooter>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 bg-gradient-to-r from-blue-950 to-cyan-950 border-t border-slate-800">
        <div className="container mx-auto px-4 text-center">
          <h2 className="text-slate-50 mb-6">
            Ready to Secure Your Code?
          </h2>
          <p className="text-slate-300 text-xl mb-8 max-w-2xl mx-auto">
            Join thousands of developers using Parry to build
            more secure applications
          </p>
          <Button
            size="lg"
            onClick={onGetStarted}
            className="bg-white text-slate-900 hover:bg-slate-100"
          >
            Start Free Trial
            <ArrowRight className="ml-2 w-4 h-4" />
          </Button>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-slate-800">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <span className="text-white">
                Parry Security Scanner
              </span>
            </div>
            <p className="text-slate-400">
              © 2025 Parry Security. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}