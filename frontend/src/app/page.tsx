"use client";

import { useCallback } from "react";
import {
  useAgentStatus,
  useIntelligenceStats,
  useBounties,
  usePipelineList,
} from "@/lib/api";
import { useWebSocket } from "@/lib/websocket";
import { MetricCard } from "@/components/saltax/metric-card";
import { ActivityFeedItem } from "@/components/saltax/activity-feed-item";
import { StatusPill } from "@/components/saltax/status-pill";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { formatWei, formatDuration, truncateHash } from "@/lib/utils";
import {
  GitPullRequest,
  ShieldCheck,
  Brain,
  Bug,
  Wallet,
  Activity,
  RefreshCw,
  Rocket,
} from "lucide-react";
import type { AgentHealthStatus } from "@/types";

// ── Helpers ──────────────────────────────────────────────────────────────────

function deriveHealthStatus(uptime: number | undefined): AgentHealthStatus {
  if (uptime === undefined) return "unknown";
  if (uptime > 0) return "operational";
  return "halted";
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

// ── Skeleton state ───────────────────────────────────────────────────────────

function MetricCardsSkeleton() {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
      {Array.from({ length: 5 }).map((_, i) => (
        <Card key={i}>
          <CardContent className="p-4">
            <Skeleton className="h-4 w-24 mb-3" />
            <Skeleton className="h-8 w-20" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function HeroSkeleton() {
  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-12 w-12 rounded-full" />
          <div className="space-y-2">
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-64" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Error state ──────────────────────────────────────────────────────────────

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-4 py-16">
        <div className="rounded-full bg-reject/10 p-3">
          <RefreshCw className="h-6 w-6 text-reject" />
        </div>
        <div className="text-center">
          <p className="text-sm font-medium">Failed to load dashboard data</p>
          <p className="text-xs text-muted-foreground mt-1">
            Check your connection and try again
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </Button>
      </CardContent>
    </Card>
  );
}

// ── Empty state ──────────────────────────────────────────────────────────────

function WelcomeState() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-4 py-20">
        <div className="rounded-full bg-primary/10 p-4">
          <Rocket className="h-8 w-8 text-primary" />
        </div>
        <div className="text-center max-w-sm">
          <h2 className="text-lg font-semibold">Welcome to SaltaX</h2>
          <p className="text-sm text-muted-foreground mt-2">
            Your sovereign AI code review agent is ready. Submit a PR to a
            monitored repository to begin autonomous code auditing.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main dashboard ───────────────────────────────────────────────────────────

export default function OverviewDashboard() {
  const status = useAgentStatus();
  const intelligence = useIntelligenceStats();
  const bounties = useBounties();
  const pipeline = usePipelineList({ limit: 7 });
  const { events, connected } = useWebSocket();

  const isLoading =
    status.isLoading ||
    intelligence.isLoading ||
    bounties.isLoading ||
    pipeline.isLoading;

  const isError =
    status.isError &&
    intelligence.isError &&
    bounties.isError &&
    pipeline.isError;

  const handleRetry = useCallback(() => {
    status.refetch();
    intelligence.refetch();
    bounties.refetch();
    pipeline.refetch();
  }, [status, intelligence, bounties, pipeline]);

  // Empty state: agent status loaded but no PRs reviewed yet
  const isEmpty =
    !isLoading &&
    !isError &&
    status.data &&
    status.data.reputation.total_prs_reviewed === 0 &&
    (!pipeline.data || pipeline.data.items.length === 0);

  if (isError) {
    return <ErrorState onRetry={handleRetry} />;
  }

  if (isEmpty) {
    return <WelcomeState />;
  }

  const agent = status.data?.agent;
  const reputation = status.data?.reputation;
  const treasury = status.data?.treasury;
  const totalPatterns = intelligence.data?.total_patterns ?? 0;
  const balanceWei = treasury?.balance_wei ?? 0;

  return (
    <div className="space-y-6">
      {/* ── Hero section ───────────────────────────────────────────────── */}
      {isLoading ? (
        <HeroSkeleton />
      ) : (
        <Card>
          <CardContent className="p-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
                  <ShieldCheck className="h-6 w-6 text-primary" />
                </div>
                <div>
                  <div className="flex items-center gap-3">
                    <h1 className="text-xl font-bold tracking-tight">
                      {agent?.name ?? "SaltaX Agent"}
                    </h1>
                    <StatusPill
                      status={deriveHealthStatus(agent?.uptime_seconds)}
                    />
                  </div>
                  <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
                    {agent?.wallet_address && (
                      <span className="font-mono">
                        {truncateHash(agent.wallet_address)}
                      </span>
                    )}
                    {agent?.uptime_seconds !== undefined && (
                      <>
                        <span aria-hidden="true">|</span>
                        <span>Uptime: {formatUptime(agent.uptime_seconds)}</span>
                      </>
                    )}
                    {agent?.version && (
                      <>
                        <span aria-hidden="true">|</span>
                        <span>v{agent.version}</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div
                  className={`h-2 w-2 rounded-full ${connected ? "bg-approve animate-pulse" : "bg-reject"}`}
                  aria-hidden="true"
                />
                <span className="text-xs text-muted-foreground">
                  {connected ? "Live" : "Disconnected"}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Metric cards ───────────────────────────────────────────────── */}
      {isLoading ? (
        <MetricCardsSkeleton />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <MetricCard
            label="Total PRs"
            value={reputation?.total_prs_reviewed ?? 0}
            icon={GitPullRequest}
          />
          <MetricCard
            label="Approval Rate"
            value={
              reputation?.approval_rate !== undefined
                ? `${(reputation.approval_rate * 100).toFixed(1)}%`
                : "--"
            }
            icon={ShieldCheck}
          />
          <MetricCard
            label="Patterns"
            value={totalPatterns}
            icon={Brain}
          />
          <MetricCard
            label="Vulns Caught"
            value={reputation?.vulnerabilities_caught ?? 0}
            icon={Bug}
          />
          <MetricCard
            label="Balance"
            value={formatWei(balanceWei)}
            icon={Wallet}
          />
        </div>
      )}

      {/* ── Activity feed ──────────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Live Activity
            {events.length > 0 && (
              <span className="ml-auto text-xs font-normal text-muted-foreground">
                {events.length} event{events.length !== 1 ? "s" : ""}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {events.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Activity className="h-8 w-8 text-muted-foreground/40 mb-2" />
              <p className="text-xs text-muted-foreground">
                Waiting for activity...
              </p>
            </div>
          ) : (
            <ScrollArea className="h-[320px]">
              <div className="space-y-0.5 pr-4">
                {events.slice(0, 50).map((event, idx) => (
                  <ActivityFeedItem
                    key={`${event.timestamp}-${idx}`}
                    event={event}
                  />
                ))}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
