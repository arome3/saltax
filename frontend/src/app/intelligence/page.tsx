"use client";

import { useCallback, useState } from "react";
import dynamic from "next/dynamic";
import { useIntelligenceStats } from "@/lib/api";
import { MetricCard } from "@/components/saltax/metric-card";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Brain,
  BarChart3,
  ShieldAlert,
  GitFork,
  RefreshCw,
  Layers,
  Target,
} from "lucide-react";

// ── Recharts (SSR-safe dynamic imports) ──────────────────────────────────────

const RechartsContainer = dynamic(
  () => import("recharts").then((m) => ({ default: m.ResponsiveContainer })),
  { ssr: false },
);

const RechartsBarChart = dynamic(
  () => import("recharts").then((m) => ({ default: m.BarChart })),
  { ssr: false },
);

const RechartsBar = dynamic(
  () => import("recharts").then((m) => ({ default: m.Bar })),
  { ssr: false },
);

const RechartsXAxis = dynamic(
  () => import("recharts").then((m) => ({ default: m.XAxis })),
  { ssr: false },
);

const RechartsYAxis = dynamic(
  () => import("recharts").then((m) => ({ default: m.YAxis })),
  { ssr: false },
);

const RechartsTooltip = dynamic(
  () => import("recharts").then((m) => ({ default: m.Tooltip })),
  { ssr: false },
);

// ── Chart component ─────────────────────────────────────────────────────────

function HorizontalBarChart({
  data,
  color,
}: {
  data: { name: string; value: number }[];
  color: string;
}) {
  const [mounted, setMounted] = useState(false);

  if (typeof window !== "undefined" && !mounted) {
    Promise.resolve().then(() => setMounted(true));
  }

  if (!mounted) {
    return (
      <div className="flex items-center justify-center h-[200px]">
        <Skeleton className="h-[160px] w-full" />
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-[200px] text-xs text-muted-foreground">
        No data available
      </div>
    );
  }

  return (
    <div className="h-[240px] w-full">
      <RechartsContainer width="100%" height="100%">
        <RechartsBarChart
          data={data}
          layout="vertical"
          margin={{ top: 0, right: 20, bottom: 0, left: 80 }}
        >
          <RechartsXAxis type="number" hide />
          <RechartsYAxis
            dataKey="name"
            type="category"
            width={80}
            tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
          />
          <RechartsTooltip
            contentStyle={{
              backgroundColor: "hsl(var(--card))",
              border: "1px solid hsl(var(--border))",
              borderRadius: "0.5rem",
              fontSize: "0.75rem",
            }}
          />
          <RechartsBar
            dataKey="value"
            fill={color}
            radius={[0, 4, 4, 0]}
          />
        </RechartsBarChart>
      </RechartsContainer>
    </div>
  );
}

// ── Skeleton state ──────────────────────────────────────────────────────────

function MetricCardsSkeleton() {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {Array.from({ length: 4 }).map((_, i) => (
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

function ChartSkeleton() {
  return (
    <Card>
      <CardContent className="p-6 space-y-3">
        <Skeleton className="h-5 w-40" />
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-6 w-full" />
        ))}
      </CardContent>
    </Card>
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
          <p className="text-sm font-medium">Failed to load intelligence data</p>
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

function EmptyIntelligence() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <Brain className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">
          No intelligence patterns yet
        </p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Patterns will accumulate as the agent reviews code
        </p>
      </CardContent>
    </Card>
  );
}

// ── Top repos list ──────────────────────────────────────────────────────────

function TopReposList({ repos }: { repos: Record<string, number> }) {
  const entries = Object.entries(repos)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10);

  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center py-8 text-xs text-muted-foreground">
        No contributing repositories
      </div>
    );
  }

  const maxValue = entries[0]?.[1] ?? 1;

  return (
    <div className="space-y-2">
      {entries.map(([repo, count]) => (
        <div key={repo} className="space-y-1">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground font-mono truncate max-w-[200px]">
              {repo}
            </span>
            <span className="font-mono font-medium">{count}</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
            <div
              className="h-full rounded-full bg-primary transition-all duration-300"
              style={{ width: `${(count / maxValue) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function IntelligenceStatsPage() {
  const { data, isLoading, isError, refetch } = useIntelligenceStats();

  const handleRetry = useCallback(() => {
    refetch();
  }, [refetch]);

  if (isError) {
    return <ErrorState onRetry={handleRetry} />;
  }

  if (!isLoading && data && data.total_patterns === 0) {
    return <EmptyIntelligence />;
  }

  // Transform data for charts
  const categoryData = data
    ? Object.entries(data.category_distribution)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value)
    : [];

  const severityData = data
    ? Object.entries(data.severity_distribution)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value)
    : [];

  const uniqueCategories = categoryData.length;

  return (
    <div className="space-y-6">
      {/* ── Metric cards ─────────────────────────────────────────────────── */}
      {isLoading ? (
        <MetricCardsSkeleton />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <MetricCard
            label="Total Patterns"
            value={data?.total_patterns ?? 0}
            icon={Brain}
          />
          <MetricCard
            label="Avg FP Rate"
            value={
              data?.avg_false_positive_rate !== undefined
                ? `${(data.avg_false_positive_rate * 100).toFixed(1)}%`
                : "--"
            }
            icon={Target}
          />
          <MetricCard
            label="Patterns (7d)"
            value={data?.patterns_last_7_days ?? 0}
            icon={Layers}
          />
          <MetricCard
            label="Categories"
            value={uniqueCategories}
            icon={BarChart3}
          />
        </div>
      )}

      {/* ── Charts row ───────────────────────────────────────────────────── */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Category distribution */}
        {isLoading ? (
          <ChartSkeleton />
        ) : (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <BarChart3 className="h-4 w-4" />
                Category Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              <HorizontalBarChart
                data={categoryData}
                color="hsl(221, 83%, 53%)"
              />
            </CardContent>
          </Card>
        )}

        {/* Severity distribution */}
        {isLoading ? (
          <ChartSkeleton />
        ) : (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <ShieldAlert className="h-4 w-4" />
                Severity Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              <HorizontalBarChart
                data={severityData}
                color="hsl(0, 84%, 60%)"
              />
            </CardContent>
          </Card>
        )}
      </div>

      {/* ── Top repos ────────────────────────────────────────────────────── */}
      {isLoading ? (
        <ChartSkeleton />
      ) : (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <GitFork className="h-4 w-4" />
              Top Contributing Repos
              {data?.top_contributing_repos && (
                <span className="ml-auto text-xs font-normal text-muted-foreground">
                  {Object.keys(data.top_contributing_repos).length} repos
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <TopReposList repos={data?.top_contributing_repos ?? {}} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
