import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, AlertCircle, Info, ChevronDown } from "lucide-react";
import type { Severity } from "@/types";

const severityConfig: Record<
  Severity,
  { className: string; icon: typeof AlertTriangle }
> = {
  CRITICAL: {
    className: "bg-reject/15 text-reject border-reject/30",
    icon: AlertTriangle,
  },
  HIGH: {
    className: "bg-high/15 text-high border-high/30",
    icon: AlertCircle,
  },
  MEDIUM: {
    className: "bg-pending/15 text-pending border-pending/30",
    icon: AlertCircle,
  },
  LOW: {
    className: "bg-info/15 text-info border-info/30",
    icon: ChevronDown,
  },
  INFO: {
    className: "bg-muted text-muted-foreground border-border",
    icon: Info,
  },
};

interface SeverityBadgeProps {
  severity: Severity;
  size?: "sm" | "md";
}

export function SeverityBadge({ severity, size = "md" }: SeverityBadgeProps) {
  const config = severityConfig[severity];
  const Icon = config.icon;

  return (
    <Badge
      variant="outline"
      className={cn(
        config.className,
        size === "sm" ? "text-xs px-1.5 py-0 gap-0.5" : "text-xs px-2 py-0.5 gap-1",
      )}
    >
      <Icon className={cn(size === "sm" ? "h-3 w-3" : "h-3.5 w-3.5")} aria-hidden="true" />
      {severity}
    </Badge>
  );
}
