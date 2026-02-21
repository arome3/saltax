"use client";

import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { usePipelineList } from "@/lib/api";
import { VerdictBadge } from "@/components/saltax/verdict-badge";
import { ScoreBar } from "@/components/saltax/score-bar";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
  Search,
  ChevronLeft,
  ChevronRight,
  Fingerprint,
  ShieldAlert,
  Swords,
  RefreshCw,
} from "lucide-react";
import type { VerdictDecision, PipelineRecord } from "@/types";

// ── Constants ────────────────────────────────────────────────────────────────

const VERDICT_OPTIONS: { value: string; label: string }[] = [
  { value: "all", label: "All Verdicts" },
  { value: "APPROVE", label: "Approved" },
  { value: "REQUEST_CHANGES", label: "Changes Requested" },
  { value: "REJECT", label: "Rejected" },
  { value: "UNKNOWN", label: "Unknown" },
];

const PAGE_SIZE = 20;

// ── Helpers ──────────────────────────────────────────────────────────────────

function PRIndicators({ record }: { record: PipelineRecord }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      {record.is_self_modification && (
        <span
          className="text-selfmod"
          title="Self-modification PR"
          aria-label="Self-modification PR"
        >
          <ShieldAlert className="h-3.5 w-3.5" />
        </span>
      )}
      {record.findings_count > 0 && (
        <span
          className="text-pending"
          title={`${record.findings_count} finding${record.findings_count !== 1 ? "s" : ""}`}
          aria-label={`${record.findings_count} findings`}
        >
          <Swords className="h-3.5 w-3.5" />
        </span>
      )}
    </span>
  );
}

function AttestationIcon({ attestationId }: { attestationId?: string }) {
  if (!attestationId) return <span className="text-muted-foreground">--</span>;
  return (
    <span
      className="text-approve"
      title={attestationId}
      aria-label="Attested"
    >
      <Fingerprint className="h-4 w-4" />
    </span>
  );
}

// ── Skeleton state ───────────────────────────────────────────────────────────

function TableSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 8 }).map((_, i) => (
        <Skeleton key={i} className="h-12 w-full" />
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
        <p className="text-sm font-medium">Failed to load pipeline data</p>
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </Button>
      </CardContent>
    </Card>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function PipelineFeedPage() {
  return (
    <Suspense fallback={<PipelineFeedSkeleton />}>
      <PipelineFeedContent />
    </Suspense>
  );
}

function PipelineFeedSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-10 w-full" />
      <div className="space-y-2">
        {Array.from({ length: 10 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    </div>
  );
}

function PipelineFeedContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Read URL state
  const repoParam = searchParams.get("repo") ?? "";
  const verdictParam = searchParams.get("verdict") ?? "all";
  const pageParam = parseInt(searchParams.get("page") ?? "1", 10);

  // Local filter inputs (synced to URL on submit)
  const [repoInput, setRepoInput] = useState(repoParam);
  const [verdict, setVerdict] = useState(verdictParam);
  const [page, setPage] = useState(pageParam);

  // Keyboard navigation state
  const [focusedRow, setFocusedRow] = useState(-1);
  const tableRef = useRef<HTMLTableSectionElement>(null);

  // Build query params
  const queryParams = {
    page,
    limit: PAGE_SIZE,
    ...(repoParam ? { repo: repoParam } : {}),
    ...(verdictParam !== "all"
      ? { verdict: verdictParam as VerdictDecision }
      : {}),
  };

  const { data, isLoading, isError, refetch } = usePipelineList(queryParams);
  const items = data?.items ?? [];
  const totalCount = data?.count ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  // Sync URL when filters change
  const pushUrl = useCallback(
    (overrides: { repo?: string; verdict?: string; page?: number }) => {
      const params = new URLSearchParams();
      const nextRepo = overrides.repo ?? repoParam;
      const nextVerdict = overrides.verdict ?? verdictParam;
      const nextPage = overrides.page ?? page;

      if (nextRepo) params.set("repo", nextRepo);
      if (nextVerdict && nextVerdict !== "all")
        params.set("verdict", nextVerdict);
      if (nextPage > 1) params.set("page", String(nextPage));

      const qs = params.toString();
      router.push(qs ? `/pipeline?${qs}` : "/pipeline");
    },
    [repoParam, verdictParam, page, router],
  );

  // Handle search form submit
  const handleSearch = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      setPage(1);
      pushUrl({ repo: repoInput, verdict, page: 1 });
    },
    [repoInput, verdict, pushUrl],
  );

  // Handle verdict change
  const handleVerdictChange = useCallback(
    (value: string) => {
      setVerdict(value);
      setPage(1);
      pushUrl({ verdict: value, page: 1 });
    },
    [pushUrl],
  );

  // Pagination handlers
  const handlePrevPage = useCallback(() => {
    const prev = Math.max(1, page - 1);
    setPage(prev);
    pushUrl({ page: prev });
  }, [page, pushUrl]);

  const handleNextPage = useCallback(() => {
    const next = Math.min(totalPages, page + 1);
    setPage(next);
    pushUrl({ page: next });
  }, [page, totalPages, pushUrl]);

  // j/k keyboard navigation
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      // Skip if focused in an input or select
      const target = e.target as HTMLElement;
      if (
        target.tagName === "INPUT" ||
        target.tagName === "SELECT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable
      ) {
        return;
      }

      if (e.key === "j") {
        e.preventDefault();
        setFocusedRow((prev) => Math.min(prev + 1, items.length - 1));
      } else if (e.key === "k") {
        e.preventDefault();
        setFocusedRow((prev) => Math.max(prev - 1, 0));
      } else if (e.key === "Enter" && focusedRow >= 0 && focusedRow < items.length) {
        e.preventDefault();
        router.push(`/pipeline/${items[focusedRow].id}`);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [items, focusedRow, router]);

  // Reset focused row when items change
  useEffect(() => {
    setFocusedRow(-1);
  }, [items]);

  if (isError) {
    return <ErrorState onRetry={refetch} />;
  }

  return (
    <div className="space-y-4">
      {/* ── Filter bar ─────────────────────────────────────────────────── */}
      <form
        onSubmit={handleSearch}
        className="flex flex-col gap-3 sm:flex-row sm:items-center"
      >
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Filter by repository..."
            value={repoInput}
            onChange={(e) => setRepoInput(e.target.value)}
            className="pl-8"
          />
        </div>
        <Select value={verdict} onValueChange={handleVerdictChange}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All Verdicts" />
          </SelectTrigger>
          <SelectContent>
            {VERDICT_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button type="submit" variant="outline" size="sm">
          <Search className="h-3.5 w-3.5" />
          Search
        </Button>
      </form>

      {/* ── Table ──────────────────────────────────────────────────────── */}
      {isLoading ? (
        <TableSkeleton />
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <p className="text-sm text-muted-foreground">
              No pipeline records found
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[140px]">PR#</TableHead>
                <TableHead>Repo</TableHead>
                <TableHead className="w-[120px]">Verdict</TableHead>
                <TableHead className="w-[180px]">Score</TableHead>
                <TableHead className="w-[100px]">Time</TableHead>
                <TableHead className="w-[60px] text-center">Proof</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody ref={tableRef}>
              {items.map((record, idx) => (
                <TableRow
                  key={record.id}
                  data-state={focusedRow === idx ? "selected" : undefined}
                  className="cursor-pointer"
                >
                  <TableCell>
                    <Link
                      href={`/pipeline/${record.id}`}
                      className="flex items-center gap-2 font-mono text-sm hover:underline"
                    >
                      {record.pr_id}
                      <PRIndicators record={record} />
                    </Link>
                  </TableCell>
                  <TableCell>
                    <span className="text-xs text-muted-foreground font-mono truncate max-w-[200px] block">
                      {record.repo}
                    </span>
                  </TableCell>
                  <TableCell>
                    <VerdictBadge verdict={record.verdict} size="sm" />
                  </TableCell>
                  <TableCell>
                    <ScoreBar
                      score={record.composite_score}
                      threshold={record.is_self_modification ? 0.9 : 0.75}
                      selfMod={record.is_self_modification}
                    />
                  </TableCell>
                  <TableCell>
                    <span className="text-xs text-muted-foreground">
                      {formatRelativeTime(record.created_at)}
                    </span>
                  </TableCell>
                  <TableCell className="text-center">
                    <AttestationIcon attestationId={record.attestation_id} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* ── Pagination ─────────────────────────────────────────────────── */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            {totalCount} record{totalCount !== 1 ? "s" : ""} | Page {page} of{" "}
            {totalPages}
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

      {/* ── Keyboard hint ──────────────────────────────────────────────── */}
      <p className="text-[10px] text-muted-foreground/50 text-center">
        <kbd className="rounded border border-border px-1 py-0.5 text-[10px] font-mono">
          j
        </kbd>
        /
        <kbd className="rounded border border-border px-1 py-0.5 text-[10px] font-mono">
          k
        </kbd>{" "}
        to navigate,{" "}
        <kbd className="rounded border border-border px-1 py-0.5 text-[10px] font-mono">
          Enter
        </kbd>{" "}
        to open
      </p>
    </div>
  );
}
