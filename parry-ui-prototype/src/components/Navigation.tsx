import { Shield, LayoutDashboard, AlertTriangle, Code, Settings, BarChart3, GitPullRequest, Laptop, Bell } from "lucide-react";
import { Button } from "./ui/button";
import { Avatar, AvatarFallback } from "./ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";

type View = "landing" | "dashboard" | "vulnerabilities" | "code-review" | "settings" | "analytics" | "pull-request" | "ide-plugin" | "notifications";

interface NavigationProps {
  currentView: View;
  onNavigate: (view: View) => void;
}

export function Navigation({ currentView, onNavigate }: NavigationProps) {
  const mainNavItems = [
    { id: "dashboard" as View, label: "Dashboard", icon: LayoutDashboard },
    { id: "vulnerabilities" as View, label: "Vulnerabilities", icon: AlertTriangle },
    { id: "pull-request" as View, label: "Pull Requests", icon: GitPullRequest },
    { id: "code-review" as View, label: "Code Review", icon: Code },
    { id: "analytics" as View, label: "Analytics", icon: BarChart3 },
  ];

  const moreNavItems = [
    { id: "ide-plugin" as View, label: "IDE Plugin", icon: Laptop },
    { id: "notifications" as View, label: "Notifications", icon: Bell },
    { id: "settings" as View, label: "Settings", icon: Settings },
  ];

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-slate-800 bg-slate-900/95 backdrop-blur">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-8">
            <button 
              onClick={() => onNavigate("landing")}
              className="flex items-center gap-2 hover:opacity-80 transition-opacity cursor-pointer"
            >
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <span className="text-white">Parry Security Scanner</span>
            </button>
            
            <div className="hidden md:flex items-center gap-1">
              {mainNavItems.map((item) => {
                const Icon = item.icon;
                return (
                  <Button
                    key={item.id}
                    variant={currentView === item.id ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => onNavigate(item.id)}
                    className={currentView === item.id ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white"}
                  >
                    <Icon className="w-4 h-4 mr-2" />
                    {item.label}
                  </Button>
                );
              })}
              
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className={["ide-plugin", "notifications", "settings"].includes(currentView) ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white"}
                  >
                    More
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent className="bg-slate-900 border-slate-800">
                  {moreNavItems.map((item) => {
                    const Icon = item.icon;
                    return (
                      <DropdownMenuItem
                        key={item.id}
                        onClick={() => onNavigate(item.id)}
                        className="text-slate-300 hover:text-white hover:bg-slate-800 cursor-pointer"
                      >
                        <Icon className="w-4 h-4 mr-2" />
                        {item.label}
                      </DropdownMenuItem>
                    );
                  })}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <Avatar className="w-8 h-8">
              <AvatarFallback className="bg-blue-600 text-white">JD</AvatarFallback>
            </Avatar>
          </div>
        </div>
      </div>
    </nav>
  );
}