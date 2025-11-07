import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Analytics from './components/Analytics';
import CodeReview from './components/CodeReview';
import VulnerabilityDetails from './components/VulnerabilityDetails';
import PullRequestView from './components/PullRequestView';
import Settings from './components/Settings';
import IDEPlugin from './components/IDEPlugin';
import Navigation from './components/Navigation';
import './styles/globals.css';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gradient-to-br from-blue-500 via-purple-600 to-blue-800">
        <Navigation />
        <main className="container mx-auto px-4 py-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/code-review" element={<CodeReview />} />
            <Route path="/vulnerabilities/:id" element={<VulnerabilityDetails />} />
            <Route path="/pull-requests/:id" element={<PullRequestView />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/ide-plugin" element={<IDEPlugin />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
