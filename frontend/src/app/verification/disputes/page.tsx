"use client";

import { useCallback } from "react";
import { useVerificationWindows } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatWei, formatRelativeTime, truncateHash } from "@/lib/utils";
import {
  Swords,
  RefreshCw,
  AlertTriangle,
  Clock,
  ShieldAlert,
} from "lucide-react";
import type { VerificationWindow, WindowStatus } from "@/types";

// ── Status badge ─────────────────────────────────────────────────────────────

const disputeStatusStyles: Record<string, string> = {
  challenged: "bg-pending/15 text-pending border-pending/30",
  executed: "bg-approve/15 text-approve border-approve/30",
  expired: "bg-reject/15 text-reject border-reject/30",
  open: "bg-muted text-muted-foreground border-border",
};

function DisputeStatusBadge({ status }: { status: WindowStatus }) {
  const style = disputeStatusStyles[status] ?? disputeStatusStyles.open;
  return (
    <Badge
      variant="outline"
      className={`text-xs px-2 py-0.5 capitalize ${style}`}
    >
      {status}
    </Badge>
  );
}

// ── Dispute type badge ───────────────────────────────────────────────────────

function DisputeTypeBadge({ type }: { type?: string }) {
  if (!type) return null;
  const isComputation = type === "COMPUTATION";
  return (
    <Badge
      variant="outline"
      className={`text-[10px] px-1.5 py-0 gap-0.5 ${
        isComputation
          ? "bg-info/15 text-info border-info/30"
          : "bg-pending/15 text-pending border-pending/30"
      }`}
    >
      {type === "COMPUTATION" ? "Computation" : "Subjective"}
    </Badge>
  );
}

function ClaimTypeBadge({ type }: { type?: string }) {
  if (!type) return null;
  return (
    <Badge
      variant="outline"
      className="text-[10px] px-1.5 py-0 bg-muted text-muted-foreground border-border"
    >
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Active dispute card ──────────────────────────────────────────────────────

function ActiveDisputeCard({ window: w }: { window: VerificationWindow }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-medium">
                PR#{w.pr_number}
              </span>
              <DisputeStatusBadge status={w.status} />
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
              Challenged
            </p>
            <p className="text-xs font-medium mt-0.5">
              {formatRelativeTime(w.updated_at)}
            </p>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
          {w.challenger_address && (
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
                Challenger
              </p>
              <p className="font-mono text-xs font-medium mt-0.5">
                {truncateHash(w.challenger_address)}
              </p>
            </div>
          )}
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
        </div>

        {w.resolution && (
          <div className="mt-3 rounded-md bg-muted/50 px-3 py-2">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
              Resolution
            </p>
            <p className="text-xs">{w.resolution}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── Skeleton state ───────────────────────────────────────────────────────────

function DisputeCardsSkeleton() {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {Array.from({ length: 3 }).map((_, i) => (
        <Card key={i}>
          <CardContent className="p-4 space-y-3">
            <div className="flex items-center justify-between">
              <Skeleton className="h-5 w-24" />
              <Skeleton className="h-5 w-20" />
            </div>
            <Skeleton className="h-3 w-40" />
            <div className="grid grid-cols-3 gap-3 pt-2">
              {Array.from({ length: 3 }).map((_, j) => (
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
      {Array.from({ length: 4 }).map((_, i) => (
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
          <p className="text-sm font-medium">Failed to load dispute data</p>
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

function EmptyDisputes() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <Swords className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">No disputes</p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Challenged verification windows will appear here
        </p>
      </CardContent>
    </Card>
  );
}

// ── Main Dispute Resolution Page ─────────────────────────────────────────────

export default function DisputeResolutionPage() {
  const { data, isLoading, isError, refetch } =
    useVerificationWindows("challenged");

  const handleRetry = useCallback(() => {
    refetch();
  }, [refetch]);

  if (isError) {
    return <ErrorState onRetry={handleRetry} />;
  }

  const windows = data?.windows ?? [];

  // The "challenged" query returns windows currently challenged.
  // We also split by whether they have a resolution or not, to show
  // active disputes vs resolved disputes.
  const activeDisputes = windows.filter((w) => !w.resolution);
  const resolvedDisputes = windows.filter((w) => !!w.resolution);

  if (!isLoading && windows.length === 0) {
    return <EmptyDisputes />;
  }

  return (
    <div className="space-y-6">
      {/* ── Active Disputes ─────────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <AlertTriangle className="h-4 w-4 text-pending" />
          Active Disputes
          {activeDisputes.length > 0 && (
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {activeDisputes.length} pending
            </span>
          )}
        </h2>

        {isLoading ? (
          <DisputeCardsSkeleton />
        ) : activeDisputes.length === 0 ? (
          <Card>
            <CardContent className="flex items-center justify-center py-10">
              <p className="text-xs text-muted-foreground">
                No active disputes
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {activeDisputes.map((w) => (
              <ActiveDisputeCard key={w.id} window={w} />
            ))}
          </div>
        )}
      </section>

      {/* ── Resolved Disputes ───────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Clock className="h-4 w-4" />
          Resolved Disputes
          {resolvedDisputes.length > 0 && (
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {resolvedDisputes.length} resolved
            </span>
          )}
        </h2>

        {isLoading ? (
          <ResolvedTableSkeleton />
        ) : resolvedDisputes.length === 0 ? (
          <Card>
            <CardContent className="flex items-center justify-center py-10">
              <p className="text-xs text-muted-foreground">
                No resolved disputes yet
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
                  <TableHead className="w-[120px]">Challenger</TableHead>
                  <TableHead className="w-[120px]">Stake</TableHead>
                  <TableHead className="w-[120px]">Resolution</TableHead>
                  <TableHead className="w-[100px]">Resolved</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {resolvedDisputes.map((w) => (
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
                      <span className="text-xs text-muted-foreground font-mono truncate max-w-[180px] block">
                        {w.repo}
                      </span>
                    </TableCell>
                    <TableCell>
                      <DisputeStatusBadge status={w.status} />
                    </TableCell>
                    <TableCell>
                      {w.challenger_address ? (
                        <span className="font-mono text-xs">
                          {truncateHash(w.challenger_address)}
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          --
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">
                        {formatWei(w.stake_amount_wei)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs truncate max-w-[100px] block">
                        {w.resolution ?? "--"}
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
