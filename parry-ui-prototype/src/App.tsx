import { useState } from "react";
import { LandingPage } from "./components/LandingPage";
import { Dashboard } from "./components/Dashboard";
import { VulnerabilityDetails } from "./components/VulnerabilityDetails";
import { CodeReview } from "./components/CodeReview";
import { Settings } from "./components/Settings";
import { Analytics } from "./components/Analytics";
import { PullRequestView } from "./components/PullRequestView";
import { IDEPlugin } from "./components/IDEPlugin";
import { NotificationExamples } from "./components/NotificationExamples";
import { Navigation } from "./components/Navigation";

type View = "landing" | "dashboard" | "vulnerabilities" | "code-review" | "settings" | "analytics" | "pull-request" | "ide-plugin" | "notifications";

export default function App() {
  const [currentView, setCurrentView] = useState<View>("landing");
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const handleLogin = () => {
    setIsLoggedIn(true);
    setCurrentView("dashboard");
  };

  const renderView = () => {
    if (currentView === "landing") {
      return <LandingPage onGetStarted={handleLogin} />;
    }

    return (
      <div className="min-h-screen bg-slate-950">
        <Navigation currentView={currentView} onNavigate={setCurrentView} />
        <main className="pt-16">
          {currentView === "dashboard" && <Dashboard onViewDetails={() => setCurrentView("vulnerabilities")} />}
          {currentView === "vulnerabilities" && <VulnerabilityDetails onReviewCode={() => setCurrentView("code-review")} />}
          {currentView === "code-review" && <CodeReview />}
          {currentView === "pull-request" && <PullRequestView />}
          {currentView === "ide-plugin" && <IDEPlugin />}
          {currentView === "notifications" && <NotificationExamples />}
          {currentView === "settings" && <Settings />}
          {currentView === "analytics" && <Analytics />}
        </main>
      </div>
    );
  };

  return renderView();
}