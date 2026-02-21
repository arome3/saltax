"use client";

import { useCallback, useState } from "react";
import { useAttestationSearch, useAttestation } from "@/lib/api";
import { AttestationCard } from "@/components/saltax/attestation-card";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { formatRelativeTime, truncateHash } from "@/lib/utils";
import {
  Search,
  Fingerprint,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  FileSearch,
} from "lucide-react";
import type { AttestationProof } from "@/types";

// ── Constants ───────────────────────────────────────────────────────────────

const ACTION_TYPE_FILTERS = [
  { value: "", label: "All" },
  { value: "pipeline", label: "Pipeline" },
  { value: "patrol", label: "Patrol" },
  { value: "audit", label: "Audit" },
] as const;

const PAGE_SIZE = 20;

// ── Skeleton state ──────────────────────────────────────────────────────────

function ResultsSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <Card key={i}>
          <CardContent className="p-3">
            <Skeleton className="h-4 w-48 mb-2" />
            <Skeleton className="h-3 w-32" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function DetailSkeleton() {
  return (
    <Card>
      <CardContent className="p-6 space-y-3">
        <Skeleton className="h-5 w-40" />
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-4 w-full" />
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
          <p className="text-sm font-medium">
            Failed to load attestation data
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

function EmptyResults() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <FileSearch className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">
          No attestation records found
        </p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Attestations are created when the agent completes pipeline or patrol actions
        </p>
      </CardContent>
    </Card>
  );
}

// ── Result list item ────────────────────────────────────────────────────────

function AttestationListItem({
  proof,
  isActive,
  onClick,
}: {
  proof: AttestationProof;
  isActive: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "w-full text-left rounded-md border p-3 transition-colors",
        "hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        isActive && "bg-accent border-primary/40",
      )}
    >
      <div className="flex items-center gap-2">
        <Fingerprint className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        <span className="font-mono text-xs truncate">
          {truncateHash(proof.attestation_id, 10)}
        </span>
      </div>
      <div className="flex items-center gap-2 mt-1.5">
        <span className="text-[10px] text-muted-foreground">
          {formatRelativeTime(proof.created_at)}
        </span>
        {proof.signature_status && (
          <Badge
            variant="outline"
            className={cn(
              "text-[10px] px-1 py-0",
              proof.signature_status === "valid"
                ? "text-approve border-approve/30"
                : proof.signature_status === "invalid"
                  ? "text-reject border-reject/30"
                  : "text-muted-foreground border-border",
            )}
          >
            {proof.signature_status}
          </Badge>
        )}
      </div>
    </button>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function AttestationExplorerPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [activeQuery, setActiveQuery] = useState("");
  const [actionType, setActionType] = useState("");
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState("");

  const searchParams = {
    ...(activeQuery ? { q: activeQuery } : {}),
    ...(actionType ? { action_type: actionType } : {}),
    page,
    limit: PAGE_SIZE,
  };

  const {
    data: searchData,
    isLoading: searchLoading,
    isError: searchError,
    refetch: refetchSearch,
  } = useAttestationSearch(searchParams);

  const {
    data: detailData,
    isLoading: detailLoading,
  } = useAttestation(selectedId);

  const items = searchData?.items ?? [];
  const totalCount = searchData?.count ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  const handleSearch = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      setActiveQuery(searchQuery.trim());
      setPage(1);
    },
    [searchQuery],
  );

  const handleFilterChange = useCallback((type: string) => {
    setActionType(type);
    setPage(1);
  }, []);

  const handleRetry = useCallback(() => {
    refetchSearch();
  }, [refetchSearch]);

  if (searchError) {
    return <ErrorState onRetry={handleRetry} />;
  }

  return (
    <div className="space-y-4">
      {/* ── Search bar ───────────────────────────────────────────────────── */}
      <form
        onSubmit={handleSearch}
        className="flex flex-col gap-3 sm:flex-row sm:items-center"
      >
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search attestation ID, hash, signer..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8"
          />
        </div>
        <Button type="submit" variant="outline" size="sm">
          <Search className="h-3.5 w-3.5" />
          Search
        </Button>
      </form>

      {/* ── Filter tabs ──────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2">
        {ACTION_TYPE_FILTERS.map((filter) => (
          <button
            key={filter.value}
            type="button"
            onClick={() => handleFilterChange(filter.value)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
              "hover:bg-accent hover:text-accent-foreground",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              actionType === filter.value && "bg-accent text-accent-foreground",
            )}
          >
            {filter.label}
          </button>
        ))}
      </div>

      {/* ── Results + Detail panel ────────────────────────────────────────── */}
      <div className="grid gap-4 md:grid-cols-5">
        {/* Results list */}
        <div className="md:col-span-2">
          {searchLoading ? (
            <ResultsSkeleton />
          ) : items.length === 0 ? (
            <EmptyResults />
          ) : (
            <ScrollArea className="h-[520px]">
              <div className="space-y-2 pr-4">
                {items.map((proof) => (
                  <AttestationListItem
                    key={proof.attestation_id}
                    proof={proof}
                    isActive={selectedId === proof.attestation_id}
                    onClick={() => setSelectedId(proof.attestation_id)}
                  />
                ))}
              </div>
            </ScrollArea>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-3">
              <p className="text-xs text-muted-foreground">
                {totalCount} result{totalCount !== 1 ? "s" : ""} | Page {page}{" "}
                of {totalPages}
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

        {/* Detail panel */}
        <div className="md:col-span-3">
          {selectedId ? (
            detailLoading ? (
              <DetailSkeleton />
            ) : detailData ? (
              <AttestationCard proof={detailData} />
            ) : (
              <Card>
                <CardContent className="flex items-center justify-center py-16">
                  <p className="text-xs text-muted-foreground">
                    Attestation data unavailable
                  </p>
                </CardContent>
              </Card>
            )
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-20">
                <ShieldCheck className="h-8 w-8 text-muted-foreground/40 mb-3" />
                <p className="text-sm text-muted-foreground">
                  Select an attestation to view details
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
