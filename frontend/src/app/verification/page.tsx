"use client";

import { useCallback } from "react";
import { useVerificationWindows } from "@/lib/api";
import { VerdictBadge } from "@/components/saltax/verdict-badge";
import { CountdownTimer } from "@/components/saltax/countdown-timer";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatWei, formatRelativeTime } from "@/lib/utils";
import {
  Clock,
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  Timer,
} from "lucide-react";
import type { VerificationWindow, WindowStatus } from "@/types";

// ── Status badge config ──────────────────────────────────────────────────────

const statusStyles: Record<WindowStatus, string> = {
  open: "bg-approve/15 text-approve border-approve/30",
  challenged: "bg-pending/15 text-pending border-pending/30",
  executed: "bg-muted text-muted-foreground border-border",
  expired: "bg-reject/15 text-reject border-reject/30",
};

function WindowStatusBadge({ status }: { status: WindowStatus }) {
  return (
    <Badge
      variant="outline"
      className={`text-xs px-2 py-0.5 capitalize ${statusStyles[status]}`}
    >
      {status}
    </Badge>
  );
}

// ── Active window card ───────────────────────────────────────────────────────

function ActiveWindowCard({ window: w }: { window: VerificationWindow }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-medium">
                PR#{w.pr_number}
              </span>
              <WindowStatusBadge status={w.status} />
              {w.is_self_modification && (
                <Badge
                  variant="outline"
                  className="bg-selfmod/15 text-selfmod border-selfmod/30 gap-1 text-xs px-1.5 py-0"
                >
                  <ShieldAlert className="h-3 w-3" />
                  Self-Mod
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground font-mono mt-1 truncate">
              {w.repo}
            </p>
          </div>
          <div className="text-right shrink-0">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Closes in
            </p>
            <CountdownTimer closesAt={w.closes_at} />
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Bounty
            </p>
            <p className="font-mono text-xs font-medium mt-0.5">
              {formatWei(w.bounty_amount_wei)}
            </p>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Stake
            </p>
            <p className="font-mono text-xs font-medium mt-0.5">
              {formatWei(w.stake_amount_wei)}
            </p>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Window
            </p>
            <p className="text-xs font-medium mt-0.5">
              {w.window_hours}h
            </p>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Opened
            </p>
            <p className="text-xs font-medium mt-0.5">
              {formatRelativeTime(w.opens_at)}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Skeleton state ───────────────────────────────────────────────────────────

function WindowCardsSkeleton() {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {Array.from({ length: 4 }).map((_, i) => (
        <Card key={i}>
          <CardContent className="p-4 space-y-3">
            <div className="flex items-center justify-between">
              <Skeleton className="h-5 w-24" />
              <Skeleton className="h-5 w-16" />
            </div>
            <Skeleton className="h-3 w-40" />
            <div className="grid grid-cols-4 gap-3 pt-2">
              {Array.from({ length: 4 }).map((_, j) => (
                <Skeleton key={j} className="h-8 w-full" />
              ))}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function ResolvedTableSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 5 }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
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
          <p className="text-sm font-medium">
            Failed to load verification windows
          </p>
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

function EmptyWindows() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <ShieldCheck className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">
          No verification windows
        </p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Verification windows will appear after the agent reviews PRs
        </p>
      </CardContent>
    </Card>
  );
}

// ── Main Verification Page ───────────────────────────────────────────────────

export default function VerificationPage() {
  const { data, isLoading, isError, refetch } = useVerificationWindows();

  const handleRetry = useCallback(() => {
    refetch();
  }, [refetch]);

  if (isError) {
    return <ErrorState onRetry={handleRetry} />;
  }

  const windows = data?.windows ?? [];

  // Partition into active (open/challenged) and resolved (executed/expired)
  const activeWindows = windows.filter(
    (w) => w.status === "open" || w.status === "challenged",
  );
  const resolvedWindows = windows.filter(
    (w) => w.status === "executed" || w.status === "expired",
  );

  if (!isLoading && windows.length === 0) {
    return <EmptyWindows />;
  }

  return (
    <div className="space-y-6">
      {/* ── Active Windows ──────────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Timer className="h-4 w-4" />
          Active Windows
          {activeWindows.length > 0 && (
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {activeWindows.length} active
            </span>
          )}
        </h2>

        {isLoading ? (
          <WindowCardsSkeleton />
        ) : activeWindows.length === 0 ? (
          <Card>
            <CardContent className="flex items-center justify-center py-10">
              <p className="text-xs text-muted-foreground">
                No active verification windows
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {activeWindows.map((w) => (
              <ActiveWindowCard key={w.id} window={w} />
            ))}
          </div>
        )}
      </section>

      {/* ── Recently Resolved ───────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Clock className="h-4 w-4" />
          Recently Resolved
          {resolvedWindows.length > 0 && (
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {resolvedWindows.length} resolved
            </span>
          )}
        </h2>

        {isLoading ? (
          <ResolvedTableSkeleton />
        ) : resolvedWindows.length === 0 ? (
          <Card>
            <CardContent className="flex items-center justify-center py-10">
              <p className="text-xs text-muted-foreground">
                No resolved windows yet
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">PR#</TableHead>
                  <TableHead>Repo</TableHead>
                  <TableHead className="w-[100px]">Status</TableHead>
                  <TableHead className="w-[120px]">Bounty</TableHead>
                  <TableHead className="w-[120px]">Stake</TableHead>
                  <TableHead className="w-[100px]">Resolved</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {resolvedWindows.map((w) => (
                  <TableRow key={w.id}>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-sm">
                          #{w.pr_number}
                        </span>
                        {w.is_self_modification && (
                          <ShieldAlert className="h-3 w-3 text-selfmod" />
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground font-mono truncate max-w-[200px] block">
                        {w.repo}
                      </span>
                    </TableCell>
                    <TableCell>
                      <WindowStatusBadge status={w.status} />
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">
                        {formatWei(w.bounty_amount_wei)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">
                        {formatWei(w.stake_amount_wei)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {formatRelativeTime(w.updated_at)}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>
    </div>
  );
}
