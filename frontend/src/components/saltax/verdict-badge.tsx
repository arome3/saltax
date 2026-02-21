import { Check, X, Minus } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import type { VerdictDecision } from "@/types";

const verdictConfig: Record<
  VerdictDecision,
  { label: string; className: string; icon: typeof Check }
> = {
  APPROVE: {
    label: "Approved",
    className: "bg-approve/15 text-approve border-approve/30 hover:bg-approve/20",
    icon: Check,
  },
  REJECT: {
    label: "Rejected",
    className: "bg-reject/15 text-reject border-reject/30 hover:bg-reject/20",
    icon: X,
  },
  REQUEST_CHANGES: {
    label: "Changes",
    className: "bg-pending/15 text-pending border-pending/30 hover:bg-pending/20",
    icon: Minus,
  },
  UNKNOWN: {
    label: "Unknown",
    className: "bg-muted text-muted-foreground border-border",
    icon: Minus,
  },
};

interface VerdictBadgeProps {
  verdict: VerdictDecision;
  size?: "sm" | "md" | "lg";
}

export function VerdictBadge({ verdict, size = "md" }: VerdictBadgeProps) {
  const config = verdictConfig[verdict];
  const Icon = config.icon;
  const sizeClasses = {
    sm: "text-xs px-1.5 py-0 gap-0.5",
    md: "text-xs px-2 py-0.5 gap-1",
    lg: "text-sm px-2.5 py-1 gap-1.5",
  };

  return (
    <Badge
      variant="outline"
      className={cn(sizeClasses[size], config.className)}
    >
      <Icon
        className={cn(
          size === "sm" ? "h-3 w-3" : size === "lg" ? "h-4 w-4" : "h-3.5 w-3.5",
        )}
        aria-hidden="true"
      />
      <span>{config.label}</span>
    </Badge>
  );
}
