import { AlertTriangle, X } from "lucide-react";
import { useState } from "react";
import { Alert } from "./ui/alert";
import { Button } from "./ui/button";

export function DisclaimerBanner() {
  const [isVisible, setIsVisible] = useState(true);

  if (!isVisible) return null;

  return (
    <Alert className="rounded-none border-x-0 border-t-0 border-b border-yellow-500/30 bg-yellow-500/10 block">
      <div className="container mx-auto px-4">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
          <div className="flex-1 text-yellow-200">
            <span className="font-semibold">Prototype Notice:</span> This is a design prototype for demonstration purposes only. 
            All testimonials, user data, security metrics, and financial numbers shown are fictional and for illustrative purposes. 
            Parry Security Scanner is a concept project developed as part of a University of Washington business course.
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsVisible(false)}
            className="flex-shrink-0 text-yellow-200 hover:text-yellow-100 hover:bg-yellow-500/20 -mt-1"
          >
            <X className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </Alert>
  );
}