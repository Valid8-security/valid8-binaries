import React, { useState } from 'react';
import { Code, AlertTriangle, CheckCircle, Eye, MessageSquare, GitPullRequest } from 'lucide-react';

interface CodeSnippet {
  line: number;
  content: string;
  vulnerability?: {
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    cwe: string;
    description: string;
  };
}

const CodeReview: React.FC = () => {
  const [selectedLine, setSelectedLine] = useState<number | null>(null);

  const codeSnippets: CodeSnippet[] = [
    { line: 1, content: 'import express from \'express\';' },
    { line: 2, content: 'import { query } from \'../db\';' },
    { line: 3, content: '' },
    { line: 4, content: 'const app = express();' },
    { line: 5, content: '' },
    { line: 6, content: 'app.get(\'/user/:id\', async (req, res) => {' },
    { line: 7, content: '  const userId = req.params.id;' },
    { line: 8, content: '  // SQL Injection vulnerability' },
    { line: 9, content: '  const result = await query(`SELECT * FROM users WHERE id = \'${userId}\'`);',
      vulnerability: {
        severity: 'critical',
        title: 'SQL Injection',
        cwe: 'CWE-89',
        description: 'User input is directly concatenated into SQL query, allowing SQL injection attacks.'
      }
    },
    { line: 10, content: '  res.json(result);' },
    { line: 11, content: '});' },
    { line: 12, content: '' },
    { line: 13, content: 'app.listen(3000, () => {' },
    { line: 14, content: '  console.log(\'Server running on port 3000\');' },
    { line: 15, content: '});' },
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'border-red-500 bg-red-500/10';
      case 'high': return 'border-orange-500 bg-orange-500/10';
      case 'medium': return 'border-yellow-500 bg-yellow-500/10';
      case 'low': return 'border-green-500 bg-green-500/10';
      default: return 'border-gray-500 bg-gray-500/10';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high': return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'medium': return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      case 'low': return <CheckCircle className="w-4 h-4 text-green-400" />;
      default: return <AlertTriangle className="w-4 h-4 text-gray-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Code Review</h1>
          <p className="text-blue-100">Interactive vulnerability detection and fix suggestions</p>
        </div>
        <div className="flex space-x-3">
          <button className="bg-white/10 text-white px-4 py-2 rounded-lg hover:bg-white/20 transition-colors flex items-center space-x-2">
            <GitPullRequest className="w-4 h-4" />
            <span>View PR</span>
          </button>
          <button className="bg-white text-blue-600 px-4 py-2 rounded-lg hover:bg-blue-50 transition-colors flex items-center space-x-2">
            <MessageSquare className="w-4 h-4" />
            <span>Add Comment</span>
          </button>
        </div>
      </div>

      {/* Code Viewer */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 overflow-hidden">
        <div className="p-4 border-b border-white/20 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Code className="w-5 h-5 text-blue-300" />
            <span className="text-white font-medium">server.js</span>
            <span className="text-blue-100 text-sm">JavaScript</span>
          </div>
          <div className="flex items-center space-x-4 text-sm text-blue-100">
            <span>2 vulnerabilities found</span>
            <span className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-red-400 rounded-full"></div>
              <span>1 critical</span>
            </span>
            <span className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
              <span>1 medium</span>
            </span>
          </div>
        </div>

        {/* Code Content */}
        <div className="relative">
          <pre className="text-sm leading-6 overflow-x-auto p-4">
            <code>
              {codeSnippets.map((snippet) => (
                <div
                  key={snippet.line}
                  className={`flex hover:bg-white/5 cursor-pointer transition-colors ${
                    snippet.vulnerability ? getSeverityColor(snippet.vulnerability.severity) : ''
                  } ${selectedLine === snippet.line ? 'bg-white/10' : ''}`}
                  onClick={() => setSelectedLine(snippet.line)}
                >
                  <div className="w-12 text-right pr-4 text-blue-100 select-none border-r border-white/10">
                    {snippet.line}
                  </div>
                  <div className="flex-1 pl-4 relative">
                    <span className="text-gray-100">{snippet.content}</span>
                    {snippet.vulnerability && (
                      <div className="absolute left-0 top-0 bottom-0 w-1 bg-red-500"></div>
                    )}
                  </div>
                  {snippet.vulnerability && (
                    <div className="pr-4 flex items-center">
                      {getSeverityIcon(snippet.vulnerability.severity)}
                    </div>
                  )}
                </div>
              ))}
            </code>
          </pre>
        </div>
      </div>

      {/* Vulnerability Details */}
      {selectedLine && codeSnippets.find(s => s.line === selectedLine)?.vulnerability && (
        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
          <div className="flex items-start space-x-4">
            <AlertTriangle className="w-6 h-6 text-red-400 mt-1" />
            <div className="flex-1">
              <div className="flex items-center space-x-3 mb-3">
                <h3 className="text-xl font-semibold text-white">
                  {codeSnippets.find(s => s.line === selectedLine)?.vulnerability?.title}
                </h3>
                <span className="px-3 py-1 bg-red-500/20 text-red-300 rounded-full text-sm font-medium">
                  {codeSnippets.find(s => s.line === selectedLine)?.vulnerability?.severity.toUpperCase()}
                </span>
                <span className="text-blue-100 text-sm">
                  {codeSnippets.find(s => s.line === selectedLine)?.vulnerability?.cwe}
                </span>
              </div>

              <p className="text-blue-100 mb-4">
                {codeSnippets.find(s => s.line === selectedLine)?.vulnerability?.description}
              </p>

              {/* Fix Suggestion */}
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4 mb-4">
                <h4 className="text-white font-medium mb-2">💡 Suggested Fix</h4>
                <pre className="bg-black/30 rounded p-3 text-sm overflow-x-auto">
                  <code className="text-green-300">
{`// Use parameterized queries to prevent SQL injection
const result = await query('SELECT * FROM users WHERE id = ?', [userId]);

// Or use an ORM with built-in protection
const result = await User.findById(userId);`}
                  </code>
                </pre>
              </div>

              {/* Actions */}
              <div className="flex space-x-3">
                <button className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors flex items-center space-x-2">
                  <CheckCircle className="w-4 h-4" />
                  <span>Accept Fix</span>
                </button>
                <button className="bg-white/10 text-white px-4 py-2 rounded-lg hover:bg-white/20 transition-colors flex items-center space-x-2">
                  <Eye className="w-4 h-4" />
                  <span>Mark as Reviewed</span>
                </button>
                <button className="bg-white/10 text-white px-4 py-2 rounded-lg hover:bg-white/20 transition-colors flex items-center space-x-2">
                  <MessageSquare className="w-4 h-4" />
                  <span>Add Comment</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Review Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20 text-center">
          <div className="text-3xl font-bold text-green-400 mb-2">2</div>
          <div className="text-white font-medium">Files Reviewed</div>
          <div className="text-blue-100 text-sm">Out of 15 total</div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20 text-center">
          <div className="text-3xl font-bold text-red-400 mb-2">2</div>
          <div className="text-white font-medium">Vulnerabilities Found</div>
          <div className="text-blue-100 text-sm">Requires attention</div>
        </div>

        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20 text-center">
          <div className="text-3xl font-bold text-blue-400 mb-2">13%</div>
          <div className="text-white font-medium">Review Progress</div>
          <div className="text-blue-100 text-sm">Estimated 2 hours remaining</div>
        </div>
      </div>
    </div>
  );
};

export default CodeReview;
