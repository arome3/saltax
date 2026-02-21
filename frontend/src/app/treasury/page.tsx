"use client";

import { useCallback, useState } from "react";
import dynamic from "next/dynamic";
import { useAgentStatus, useTransactions } from "@/lib/api";
import { TransactionRow } from "@/components/saltax/transaction-row";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { formatWei } from "@/lib/utils";
import {
  Wallet,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  PiggyBank,
  ReceiptText,
} from "lucide-react";
import type { Transaction } from "@/types";

// ── Recharts (SSR-safe dynamic imports) ──────────────────────────────────────

const RechartsContainer = dynamic(
  () => import("recharts").then((m) => {
    const { ResponsiveContainer } = m;
    return { default: ResponsiveContainer };
  }),
  { ssr: false },
);

const RechartsPieChart = dynamic(
  () => import("recharts").then((m) => {
    const { PieChart } = m;
    return { default: PieChart };
  }),
  { ssr: false },
);

const RechartsPie = dynamic(
  () => import("recharts").then((m) => {
    const { Pie } = m;
    return { default: Pie };
  }),
  { ssr: false },
);

const RechartsCell = dynamic(
  () => import("recharts").then((m) => {
    const { Cell } = m;
    return { default: Cell };
  }),
  { ssr: false },
);

const RechartsTooltip = dynamic(
  () => import("recharts").then((m) => {
    const { Tooltip } = m;
    return { default: Tooltip };
  }),
  { ssr: false },
);

const RechartsLegend = dynamic(
  () => import("recharts").then((m) => {
    const { Legend } = m;
    return { default: Legend };
  }),
  { ssr: false },
);

// ── Constants ────────────────────────────────────────────────────────────────

const PAGE_SIZE = 25;

const BUDGET_DATA = [
  { name: "Bounty", value: 65, color: "hsl(142, 76%, 36%)" },
  { name: "Reserve", value: 20, color: "hsl(221, 83%, 53%)" },
  { name: "Compute", value: 10, color: "hsl(38, 92%, 50%)" },
  { name: "Community", value: 5, color: "hsl(280, 67%, 52%)" },
];

// ── Budget Donut Chart ───────────────────────────────────────────────────────

function BudgetDonut() {
  const [mounted, setMounted] = useState(false);

  // Ensure we only render chart after hydration
  if (typeof window !== "undefined" && !mounted) {
    // Use a microtask to avoid setState during render
    Promise.resolve().then(() => setMounted(true));
  }

  if (!mounted) {
    return (
      <div className="flex items-center justify-center h-[220px]">
        <Skeleton className="h-[180px] w-[180px] rounded-full" />
      </div>
    );
  }

  return (
    <div className="h-[220px] w-full">
      <RechartsContainer width="100%" height="100%">
        <RechartsPieChart>
          <RechartsPie
            data={BUDGET_DATA}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={80}
            paddingAngle={3}
            dataKey="value"
            stroke="none"
          >
            {BUDGET_DATA.map((entry) => (
              <RechartsCell key={entry.name} fill={entry.color} />
            ))}
          </RechartsPie>
          <RechartsTooltip
            contentStyle={{
              backgroundColor: "hsl(var(--card))",
              border: "1px solid hsl(var(--border))",
              borderRadius: "0.5rem",
              fontSize: "0.75rem",
            }}
            formatter={(value) => [`${value}%`, ""]}
          />
          <RechartsLegend
            verticalAlign="bottom"
            iconType="circle"
            iconSize={8}
            formatter={(value: string) => (
              <span className="text-xs text-muted-foreground">{value}</span>
            )}
          />
        </RechartsPieChart>
      </RechartsContainer>
    </div>
  );
}

// ── Skeleton state ───────────────────────────────────────────────────────────

function HeroSkeleton() {
  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-14 w-14 rounded-full" />
          <div className="space-y-2">
            <Skeleton className="h-4 w-28" />
            <Skeleton className="h-10 w-48" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function TransactionsSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-14 w-full" />
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
          <p className="text-sm font-medium">Failed to load treasury data</p>
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

function EmptyTransactions() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <ReceiptText className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">No transactions yet</p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Treasury activity will appear here once the agent starts processing
        </p>
      </CardContent>
    </Card>
  );
}

// ── Main Treasury Dashboard ──────────────────────────────────────────────────

export default function TreasuryDashboard() {
  const [page, setPage] = useState(1);

  const status = useAgentStatus();
  const transactions = useTransactions({ page, limit: PAGE_SIZE });

  const isLoading = status.isLoading || transactions.isLoading;
  const isError = status.isError && transactions.isError;

  const handleRetry = useCallback(() => {
    status.refetch();
    transactions.refetch();
  }, [status, transactions]);

  if (isError) {
    return <ErrorState onRetry={handleRetry} />;
  }

  const treasury = status.data?.treasury;
  const balanceWei = treasury?.balance_wei ?? 0;
  const reserveWei = treasury?.reserve_wei ?? 0;
  const bountyWei = treasury?.bounty_wei ?? 0;

  const txItems: Transaction[] = transactions.data?.items ?? [];
  const totalCount = transactions.data?.count ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  const handlePrevPage = () => setPage((p) => Math.max(1, p - 1));
  const handleNextPage = () => setPage((p) => Math.min(totalPages, p + 1));

  return (
    <div className="space-y-6">
      {/* ── Balance Hero ───────────────────────────────────────────────── */}
      {status.isLoading ? (
        <HeroSkeleton />
      ) : (
        <Card>
          <CardContent className="p-6">
            <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-4">
                <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/10">
                  <Wallet className="h-7 w-7 text-primary" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">
                    Treasury Balance
                  </p>
                  <p className="text-3xl font-bold font-mono tracking-tight">
                    {formatWei(balanceWei)}
                  </p>
                </div>
              </div>
              <div className="flex gap-6 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground">Reserve</p>
                  <p className="font-mono font-medium">
                    {formatWei(reserveWei)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Bounty Pool</p>
                  <p className="font-mono font-medium">
                    {formatWei(bountyWei)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Available</p>
                  <p className="font-mono font-medium">
                    {treasury?.available ? (
                      <span className="text-approve">Active</span>
                    ) : (
                      <span className="text-reject">Inactive</span>
                    )}
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Budget Allocation Donut ────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <PiggyBank className="h-4 w-4" />
            Budget Allocation
          </CardTitle>
        </CardHeader>
        <CardContent>
          <BudgetDonut />
        </CardContent>
      </Card>

      {/* ── Transaction History ─────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <ReceiptText className="h-4 w-4" />
            Transactions
            {totalCount > 0 && (
              <span className="ml-auto text-xs font-normal text-muted-foreground">
                {totalCount} total
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {transactions.isLoading ? (
            <TransactionsSkeleton />
          ) : txItems.length === 0 ? (
            <EmptyTransactions />
          ) : (
            <div className="space-y-0.5">
              {txItems.map((tx) => (
                <TransactionRow key={tx.id} tx={tx} showPrLink />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Pagination ─────────────────────────────────────────────────── */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Page {page} of {totalPages}
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon-sm"
              onClick={handlePrevPage}
              disabled={page <= 1}
              aria-label="Previous page"
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon-sm"
              onClick={handleNextPage}
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
