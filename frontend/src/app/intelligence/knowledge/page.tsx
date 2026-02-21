"use client";

import { useCallback, useState } from "react";
import { useCodebaseKnowledge } from "@/lib/api";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { formatRelativeTime } from "@/lib/utils";
import {
  Search,
  FileCode,
  Brain,
  RefreshCw,
  FolderSearch,
} from "lucide-react";
import type { CodebaseKnowledge } from "@/types";

// ── Skeleton state ──────────────────────────────────────────────────────────

function KnowledgeSkeleton() {
  return (
    <div className="space-y-3">
      {Array.from({ length: 4 }).map((_, i) => (
        <Card key={i}>
          <CardContent className="p-4 space-y-2">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-3/4" />
          </CardContent>
        </Card>
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
          <p className="text-sm font-medium">Failed to load knowledge data</p>
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

function EmptyKnowledge({ hasRepo }: { hasRepo: boolean }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        {hasRepo ? (
          <>
            <FolderSearch className="h-8 w-8 text-muted-foreground/40 mb-3" />
            <p className="text-sm text-muted-foreground">
              No knowledge entries for this repository
            </p>
            <p className="text-xs text-muted-foreground/70 mt-1">
              Knowledge is built as the agent reviews code in this repo
            </p>
          </>
        ) : (
          <>
            <Brain className="h-8 w-8 text-muted-foreground/40 mb-3" />
            <p className="text-sm text-muted-foreground">
              Enter a repository name to explore
            </p>
            <p className="text-xs text-muted-foreground/70 mt-1">
              e.g. owner/repository
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ── Knowledge entry card ────────────────────────────────────────────────────

function KnowledgeEntryCard({ entry }: { entry: CodebaseKnowledge }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <FileCode className="h-4 w-4 shrink-0" />
          <span className="font-mono truncate">{entry.file_path}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-xs leading-relaxed whitespace-pre-wrap">
          {entry.knowledge}
        </p>
        <p className="text-[10px] text-muted-foreground mt-3">
          Updated {formatRelativeTime(entry.updated_at)}
        </p>
      </CardContent>
    </Card>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function CodebaseKnowledgePage() {
  const [repoInput, setRepoInput] = useState("");
  const [activeRepo, setActiveRepo] = useState("");

  const { data, isLoading, isError, refetch } = useCodebaseKnowledge(activeRepo);

  const handleSearch = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      setActiveRepo(repoInput.trim());
    },
    [repoInput],
  );

  const handleRetry = useCallback(() => {
    refetch();
  }, [refetch]);

  const knowledgeItems = data?.items ?? [];

  return (
    <div className="space-y-6">
      {/* ── Repo selector ────────────────────────────────────────────────── */}
      <form
        onSubmit={handleSearch}
        className="flex flex-col gap-3 sm:flex-row sm:items-center"
      >
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Enter repository (e.g. owner/repo)..."
            value={repoInput}
            onChange={(e) => setRepoInput(e.target.value)}
            className="pl-8"
          />
        </div>
        <Button type="submit" variant="outline" size="sm">
          <Search className="h-3.5 w-3.5" />
          Explore
        </Button>
      </form>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      {isError ? (
        <ErrorState onRetry={handleRetry} />
      ) : isLoading ? (
        <KnowledgeSkeleton />
      ) : !activeRepo || knowledgeItems.length === 0 ? (
        <EmptyKnowledge hasRepo={!!activeRepo} />
      ) : (
        <section>
          <h2 className="text-sm font-semibold flex items-center gap-2 mb-4">
            <Brain className="h-4 w-4" />
            File Knowledge
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {knowledgeItems.length} entries
            </span>
          </h2>
          <ScrollArea className="h-[600px]">
            <div className="space-y-3 pr-4">
              {knowledgeItems.map((entry) => (
                <KnowledgeEntryCard key={entry.id} entry={entry} />
              ))}
            </div>
          </ScrollArea>
        </section>
      )}
    </div>
  );
}
