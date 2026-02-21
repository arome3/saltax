"use client";

import { useCallback, useEffect, useRef, useState, useMemo } from "react";
import { useWebSocket } from "@/lib/websocket";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import {
  Search,
  Pause,
  Play,
  Trash2,
  ScrollText,
  Wifi,
  WifiOff,
} from "lucide-react";
import type { LogEvent } from "@/types";

// ── Constants ───────────────────────────────────────────────────────────────

const VISIBLE_LIMIT = 500;

type LogLevel = "INFO" | "WARNING" | "ERROR";

const LEVEL_FILTERS: { value: LogLevel | "ALL"; label: string; color: string }[] = [
  { value: "ALL", label: "All", color: "bg-muted text-muted-foreground" },
  { value: "INFO", label: "Info", color: "bg-info/15 text-info" },
  { value: "WARNING", label: "Warning", color: "bg-pending/15 text-pending" },
  { value: "ERROR", label: "Error", color: "bg-reject/15 text-reject" },
];

const LEVEL_BORDER_COLORS: Record<string, string> = {
  DEBUG: "border-l-muted-foreground/40",
  INFO: "border-l-info",
  WARNING: "border-l-pending",
  ERROR: "border-l-reject",
  CRITICAL: "border-l-reject",
};

const LEVEL_TEXT_COLORS: Record<string, string> = {
  DEBUG: "text-muted-foreground",
  INFO: "text-info",
  WARNING: "text-pending",
  ERROR: "text-reject",
  CRITICAL: "text-reject",
};

// ── Log entry component ─────────────────────────────────────────────────────

function LogEntry({ event }: { event: LogEvent }) {
  const borderColor = LEVEL_BORDER_COLORS[event.level] ?? LEVEL_BORDER_COLORS.DEBUG;
  const textColor = LEVEL_TEXT_COLORS[event.level] ?? LEVEL_TEXT_COLORS.DEBUG;

  const timestamp = new Date(event.timestamp).toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div className={cn("border-l-2 pl-3 py-1.5", borderColor)}>
      <div className="flex items-center gap-2 flex-wrap">
        <span className={cn("text-[10px] font-bold uppercase tracking-wider", textColor)}>
          {event.level}
        </span>
        <span className="text-[10px] text-muted-foreground font-mono">
          {timestamp}
        </span>
        {event.repo && (
          <span className="text-[10px] text-muted-foreground font-mono truncate max-w-[180px]">
            {event.repo}
          </span>
        )}
      </div>
      <p className="text-xs leading-relaxed mt-0.5">{event.message}</p>
    </div>
  );
}

// ── Empty state ─────────────────────────────────────────────────────────────

function EmptyLogs() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <ScrollText className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">No log events yet</p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Logs will stream in real-time as the agent operates
        </p>
      </CardContent>
    </Card>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function SystemLogsPage() {
  const { events, connected, paused, setPaused, clearEvents } = useWebSocket();

  const [levelFilter, setLevelFilter] = useState<LogLevel | "ALL">("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);

  const scrollRef = useRef<HTMLDivElement>(null);

  // Filter and limit events
  const filteredEvents = useMemo(() => {
    let filtered = events;

    if (levelFilter !== "ALL") {
      filtered = filtered.filter((e) => e.level === levelFilter);
    }

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (e) =>
          e.message.toLowerCase().includes(query) ||
          (e.repo && e.repo.toLowerCase().includes(query)) ||
          (e.component && e.component.toLowerCase().includes(query)),
      );
    }

    return filtered.slice(0, VISIBLE_LIMIT);
  }, [events, levelFilter, searchQuery]);

  // Auto-scroll when new events arrive
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [filteredEvents.length, autoScroll]);

  const handleTogglePause = useCallback(() => {
    setPaused(!paused);
  }, [paused, setPaused]);

  const handleToggleAutoScroll = useCallback(() => {
    setAutoScroll((prev) => !prev);
  }, []);

  const handleClear = useCallback(() => {
    clearEvents();
  }, [clearEvents]);

  return (
    <div className="space-y-4">
      {/* ── Controls bar ─────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          {/* Level filter pills */}
          {LEVEL_FILTERS.map((filter) => (
            <button
              key={filter.value}
              type="button"
              onClick={() => setLevelFilter(filter.value)}
              className={cn(
                "rounded-full px-3 py-1 text-xs font-medium transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                levelFilter === filter.value
                  ? filter.color
                  : "bg-transparent text-muted-foreground hover:bg-accent",
              )}
            >
              {filter.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          {/* Connection indicator */}
          <div className="flex items-center gap-1.5 mr-2">
            {connected ? (
              <Wifi className="h-3.5 w-3.5 text-approve" />
            ) : (
              <WifiOff className="h-3.5 w-3.5 text-reject" />
            )}
            <span className="text-[10px] text-muted-foreground">
              {connected ? "Live" : "Disconnected"}
            </span>
          </div>

          {/* Pause/Resume */}
          <Button
            variant="outline"
            size="sm"
            onClick={handleTogglePause}
            className={cn(paused && "border-pending text-pending")}
          >
            {paused ? (
              <>
                <Play className="h-3.5 w-3.5" />
                Resume
              </>
            ) : (
              <>
                <Pause className="h-3.5 w-3.5" />
                Pause
              </>
            )}
          </Button>

          {/* Auto-scroll toggle */}
          <Button
            variant={autoScroll ? "default" : "outline"}
            size="sm"
            onClick={handleToggleAutoScroll}
          >
            Auto-scroll {autoScroll ? "On" : "Off"}
          </Button>

          {/* Clear */}
          <Button variant="outline" size="sm" onClick={handleClear}>
            <Trash2 className="h-3.5 w-3.5" />
            Clear
          </Button>
        </div>
      </div>

      {/* ── Search ───────────────────────────────────────────────────────── */}
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search logs..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-8"
        />
      </div>

      {/* ── Log stream ───────────────────────────────────────────────────── */}
      {filteredEvents.length === 0 ? (
        <EmptyLogs />
      ) : (
        <Card>
          <CardContent className="p-0">
            <ScrollArea className="h-[600px]" ref={scrollRef}>
              <div className="p-4 space-y-0.5">
                {filteredEvents.map((event, idx) => (
                  <LogEntry
                    key={`${event.timestamp}-${idx}`}
                    event={event}
                  />
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      {/* ── Footer info ──────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
        <span>
          Showing {filteredEvents.length} of {events.length} events
          {filteredEvents.length >= VISIBLE_LIMIT && (
            <span> (capped at {VISIBLE_LIMIT})</span>
          )}
        </span>
        {paused && (
          <span className="text-pending font-medium">
            Stream paused -- new events will be buffered
          </span>
        )}
      </div>
    </div>
  );
}
