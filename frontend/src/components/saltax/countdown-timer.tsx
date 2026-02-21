"use client";

import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

interface CountdownTimerProps {
  closesAt: string;
  onExpire?: () => void;
}

function formatCountdown(ms: number): string {
  if (ms <= 0) return "Expired";
  const totalSeconds = Math.floor(ms / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

export function CountdownTimer({ closesAt, onExpire }: CountdownTimerProps) {
  const [remaining, setRemaining] = useState(() => {
    return new Date(closesAt).getTime() - Date.now();
  });

  useEffect(() => {
    const interval = setInterval(() => {
      const ms = new Date(closesAt).getTime() - Date.now();
      setRemaining(ms);
      if (ms <= 0) {
        clearInterval(interval);
        onExpire?.();
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [closesAt, onExpire]);

  const isUrgent = remaining > 0 && remaining < 3600_000; // < 1h

  return (
    <span
      className={cn(
        "font-mono text-sm tabular-nums",
        remaining <= 0
          ? "text-muted-foreground"
          : isUrgent
            ? "text-reject font-medium"
            : "text-foreground",
      )}
      aria-label={`Time remaining: ${formatCountdown(remaining)}`}
    >
      {formatCountdown(remaining)}
    </span>
  );
}
