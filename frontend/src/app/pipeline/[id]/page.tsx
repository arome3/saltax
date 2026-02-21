"use client";

import { use } from "react";
import Link from "next/link";
import { usePipelineRecord, useAttestation } from "@/lib/api";
import { VerdictBadge } from "@/components/saltax/verdict-badge";
import { ScoreBar } from "@/components/saltax/score-bar";
import { AttestationCard } from "@/components/saltax/attestation-card";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { formatRelativeTime } from "@/lib/utils";
import {
  ArrowLeft,
  GitPullRequest,
  User,
  Clock,
  ShieldAlert,
  RefreshCw,
} from "lucide-react";

// ── Constants ────────────────────────────────────────────────────────────────

const THRESHOLD_STANDARD = 0.75;
const THRESHOLD_SELF_MOD = 0.9;

// ── Readable score labels ────────────────────────────────────────────────────

const SCORE_LABELS: Record<string, string> = {
  security: "Security",
  quality: "Quality",
  complexity: "Complexity",
  test_coverage: "Test Coverage",
  documentation: "Documentation",
  maintainability: "Maintainability",
  performance: "Performance",
  style: "Style",
};

function scoreLabel(key: string): string {
  return SCORE_LABELS[key] ?? key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ── Skeleton state ───────────────────────────────────────────────────────────

function DetailSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Skeleton className="h-9 w-9" />
        <Skeleton className="h-7 w-64" />
      </div>
      <Card>
        <CardContent className="p-6 space-y-4">
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-4 w-72" />
          <div className="grid grid-cols-2 gap-4 pt-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="p-6 space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-4 w-full" />
          ))}
        </CardContent>
      </Card>
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
        <p className="text-sm font-medium">Failed to load pipeline record</p>
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </Button>
      </CardContent>
    </Card>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function PipelineDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);

  const {
    data: record,
    isLoading: recordLoading,
    isError: recordError,
    refetch: refetchRecord,
  } = usePipelineRecord(id);

  const {
    data: attestation,
    isLoading: attestationLoading,
  } = useAttestation(record?.attestation_id ?? "");

  if (recordLoading) {
    return <DetailSkeleton />;
  }

  if (recordError || !record) {
    return <ErrorState onRetry={refetchRecord} />;
  }

  const isSelfMod = record.is_self_modification;
  const threshold = isSelfMod ? THRESHOLD_SELF_MOD : THRESHOLD_STANDARD;
  const breakdownEntries = Object.entries(record.score_breakdown);

  return (
    <div className="space-y-6">
      {/* ── Back button + header ──────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon-sm" asChild>
          <Link href="/pipeline" aria-label="Back to pipeline">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-tight font-mono">
              {record.pr_id}
            </h1>
            {isSelfMod && (
              <Badge
                variant="outline"
                className="bg-selfmod/15 text-selfmod border-selfmod/30 gap-1"
              >
                <ShieldAlert className="h-3 w-3" />
                Self-Mod
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-3 mt-0.5 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1 font-mono">
              <GitPullRequest className="h-3 w-3" />
              {record.repo}
            </span>
            <span className="inline-flex items-center gap-1">
              <User className="h-3 w-3" />
              {record.pr_author}
            </span>
            <span className="inline-flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {formatRelativeTime(record.created_at)}
            </span>
          </div>
        </div>
      </div>

      {/* ── Verdict + composite score ─────────────────────────────────── */}
      <Card>
        <CardContent className="p-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-4">
              <VerdictBadge verdict={record.verdict} size="lg" />
              <div>
                <p className="text-sm text-muted-foreground">Composite Score</p>
                <p className="text-2xl font-bold font-mono tracking-tight">
                  {record.composite_score.toFixed(3)}
                </p>
              </div>
            </div>
            <div className="text-right text-xs text-muted-foreground">
              <p>
                Threshold:{" "}
                <span className="font-mono font-medium text-foreground">
                  {threshold.toFixed(2)}
                </span>
              </p>
              <p>
                Findings:{" "}
                <span className="font-mono font-medium text-foreground">
                  {record.findings_count}
                </span>
              </p>
            </div>
          </div>
          <div className="mt-4">
            <ScoreBar
              score={record.composite_score}
              threshold={threshold}
              label="Composite"
              selfMod={isSelfMod}
            />
          </div>
        </CardContent>
      </Card>

      {/* ── Score breakdown ────────────────────────────────────────────── */}
      {breakdownEntries.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Score Breakdown</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {breakdownEntries.map(([key, value]) => (
              <ScoreBar
                key={key}
                score={value}
                threshold={threshold}
                label={scoreLabel(key)}
                selfMod={isSelfMod}
              />
            ))}
          </CardContent>
        </Card>
      )}

      {/* ── Attestation proof ─────────────────────────────────────────── */}
      {record.attestation_id && (
        <div>
          {attestationLoading ? (
            <Card>
              <CardContent className="p-6 space-y-3">
                <Skeleton className="h-5 w-40" />
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-4 w-full" />
                ))}
              </CardContent>
            </Card>
          ) : attestation ? (
            <AttestationCard proof={attestation} />
          ) : (
            <Card>
              <CardContent className="flex items-center justify-center py-8">
                <p className="text-xs text-muted-foreground">
                  Attestation data unavailable
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
