import { cn } from "@/lib/utils";
import type { AgentHealthStatus } from "@/types";

const statusConfig: Record<
  AgentHealthStatus,
  { label: string; dotClass: string; textClass: string }
> = {
  operational: {
    label: "Operational",
    dotClass: "bg-approve animate-pulse",
    textClass: "text-approve",
  },
  degraded: {
    label: "Degraded",
    dotClass: "bg-pending",
    textClass: "text-pending",
  },
  halted: {
    label: "Halted",
    dotClass: "bg-reject",
    textClass: "text-reject",
  },
  unknown: {
    label: "Unknown",
    dotClass: "bg-muted-foreground",
    textClass: "text-muted-foreground",
  },
};

interface StatusPillProps {
  status: AgentHealthStatus;
}

export function StatusPill({ status }: StatusPillProps) {
  const config = statusConfig[status];
  return (
    <div
      className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5"
      role="status"
      aria-label={`Agent status: ${config.label}`}
    >
      <span
        className={cn("h-2 w-2 rounded-full", config.dotClass)}
        aria-hidden="true"
      />
      <span className={cn("text-xs font-medium", config.textClass)}>
        {config.label}
      </span>
    </div>
  );
}
