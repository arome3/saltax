import {
  GitPullRequest,
  Shield,
  Fingerprint,
  AlertTriangle,
  Coins,
  ScrollText,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatRelativeTime } from "@/lib/utils";
import type { LogEvent } from "@/types";

const levelConfig: Record<string, { icon: typeof ScrollText; color: string }> = {
  INFO: { icon: ScrollText, color: "text-info" },
  WARNING: { icon: AlertTriangle, color: "text-pending" },
  ERROR: { icon: AlertTriangle, color: "text-reject" },
  CRITICAL: { icon: AlertTriangle, color: "text-reject" },
  DEBUG: { icon: ScrollText, color: "text-muted-foreground" },
};

function getEventIcon(event: LogEvent) {
  if (event.stage) return GitPullRequest;
  if (event.component === "patrol") return Shield;
  if (event.message.includes("attestation")) return Fingerprint;
  if (event.message.includes("bounty") || event.message.includes("payout")) return Coins;
  return levelConfig[event.level]?.icon ?? ScrollText;
}

interface ActivityFeedItemProps {
  event: LogEvent;
}

export function ActivityFeedItem({ event }: ActivityFeedItemProps) {
  const config = levelConfig[event.level] ?? levelConfig.INFO;
  const Icon = getEventIcon(event);

  return (
    <div className="flex items-start gap-2.5 py-1.5">
      <Icon
        className={cn("h-4 w-4 mt-0.5 shrink-0", config.color)}
        aria-hidden="true"
      />
      <div className="min-w-0 flex-1">
        <p className="text-xs leading-relaxed truncate">{event.message}</p>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-[10px] text-muted-foreground">
            {formatRelativeTime(event.timestamp)}
          </span>
          {event.repo && (
            <span className="text-[10px] text-muted-foreground font-mono truncate">
              {event.repo}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
