"use client";

import { useCallback, useState } from "react";
import { useContributors } from "@/lib/api";
import { StakingCalculator } from "@/components/saltax/staking-calculator";
import { ScoreBar } from "@/components/saltax/score-bar";
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
import { formatRelativeTime } from "@/lib/utils";
import {
  Trophy,
  Users,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
} from "lucide-react";
import type { Contributor } from "@/types";

// ── Constants ───────────────────────────────────────────────────────────────

const PAGE_SIZE = 20;

// ── Skeleton state ──────────────────────────────────────────────────────────

function LeaderboardSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 8 }).map((_, i) => (
        <Skeleton key={i} className="h-14 w-full" />
      ))}
    </div>
  );
}

// ── Error state ─────────────────────────────────────────────────────────────

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-4 py-16">
        <div className="rounded-full bg-reject/10 p-3">
          <RefreshCw className="h-6 w-6 text-reject" />
        </div>
        <div className="text-center">
          <p className="text-sm font-medium">
            Failed to load contributor data
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

// ── Empty state ─────────────────────────────────────────────────────────────

function EmptyContributors() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <Users className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">No contributors yet</p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Contributors appear as they submit PRs to monitored repositories
        </p>
      </CardContent>
    </Card>
  );
}

// ── Rank badge ──────────────────────────────────────────────────────────────

function RankBadge({ rank }: { rank: number }) {
  if (rank === 1) {
    return (
      <span className="inline-flex items-center justify-center h-6 w-6 rounded-full bg-yellow-500/15 text-yellow-500 text-xs font-bold">
        1
      </span>
    );
  }
  if (rank === 2) {
    return (
      <span className="inline-flex items-center justify-center h-6 w-6 rounded-full bg-slate-400/15 text-slate-400 text-xs font-bold">
        2
      </span>
    );
  }
  if (rank === 3) {
    return (
      <span className="inline-flex items-center justify-center h-6 w-6 rounded-full bg-amber-700/15 text-amber-700 text-xs font-bold">
        3
      </span>
    );
  }
  return (
    <span className="inline-flex items-center justify-center h-6 w-6 text-xs text-muted-foreground font-mono">
      {rank}
    </span>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function StakingContributorsPage() {
  const [page, setPage] = useState(1);

  const { data, isLoading, isError, refetch } = useContributors({
    page,
    limit: PAGE_SIZE,
  });

  const handleRetry = useCallback(() => {
    refetch();
  }, [refetch]);

  if (isError) {
    return <ErrorState onRetry={handleRetry} />;
  }

  const contributors = data?.items ?? [];
  const totalCount = data?.count ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  return (
    <div className="space-y-6">
      {/* ── Staking calculator ────────────────────────────────────────────── */}
      <StakingCalculator />

      {/* ── Leaderboard ──────────────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Trophy className="h-4 w-4" />
          Contributor Leaderboard
          {totalCount > 0 && (
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {totalCount} contributor{totalCount !== 1 ? "s" : ""}
            </span>
          )}
        </h2>

        {isLoading ? (
          <LeaderboardSkeleton />
        ) : contributors.length === 0 ? (
          <EmptyContributors />
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[60px] text-center">#</TableHead>
                  <TableHead>GitHub Login</TableHead>
                  <TableHead className="w-[80px] text-center">Total</TableHead>
                  <TableHead className="w-[80px] text-center">Approved</TableHead>
                  <TableHead className="w-[80px] text-center">Rejected</TableHead>
                  <TableHead className="w-[160px]">Reputation</TableHead>
                  <TableHead className="w-[100px]">First Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {contributors.map((contributor, idx) => {
                  const rank = (page - 1) * PAGE_SIZE + idx + 1;
                  return (
                    <TableRow key={contributor.id}>
                      <TableCell className="text-center">
                        <RankBadge rank={rank} />
                      </TableCell>
                      <TableCell>
                        <span className="font-medium text-sm">
                          {contributor.github_login}
                        </span>
                      </TableCell>
                      <TableCell className="text-center">
                        <span className="font-mono text-sm">
                          {contributor.total_submissions}
                        </span>
                      </TableCell>
                      <TableCell className="text-center">
                        <span className="font-mono text-sm text-approve">
                          {contributor.approved_submissions}
                        </span>
                      </TableCell>
                      <TableCell className="text-center">
                        <span className="font-mono text-sm text-reject">
                          {contributor.rejected_submissions}
                        </span>
                      </TableCell>
                      <TableCell>
                        <ScoreBar
                          score={contributor.reputation_score}
                          label={contributor.reputation_score.toFixed(2)}
                        />
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground">
                          {formatRelativeTime(contributor.first_seen)}
                        </span>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      {/* ── Pagination ───────────────────────────────────────────────────── */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Page {page} of {totalPages}
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon-sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              aria-label="Previous page"
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon-sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              aria-label="Next page"
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
