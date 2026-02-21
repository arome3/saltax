"use client";

import { Component, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback ?? (
          <Card className="border-reject/30">
            <CardContent className="flex flex-col items-center gap-3 py-8">
              <AlertTriangle className="h-8 w-8 text-reject" />
              <p className="text-sm text-muted-foreground">
                Something went wrong loading this section.
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => this.setState({ hasError: false })}
              >
                <RefreshCw className="mr-2 h-3 w-3" />
                Retry
              </Button>
            </CardContent>
          </Card>
        )
      );
    }
    return this.props.children;
  }
}
