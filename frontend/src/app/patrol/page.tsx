"use client";

import { useCallback } from "react";
import {
  usePatrolHistory,
  useVulnerabilities,
  usePatrolPatches,
} from "@/lib/api";
import { SeverityBadge } from "@/components/saltax/severity-badge";
import { MetricCard } from "@/components/saltax/metric-card";
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
import { ScrollArea } from "@/components/ui/scroll-area";
import { formatRelativeTime } from "@/lib/utils";
import {
  Shield,
  Bug,
  Wrench,
  RefreshCw,
  ScanLine,
  PackageOpen,
  ExternalLink,
} from "lucide-react";
import type { Vulnerability, PatrolPatch } from "@/types";

// ── Patch status badge ──────────────────────────────────────────────────────

const patchStatusStyles: Record<string, string> = {
  merged: "bg-approve/15 text-approve border-approve/30",
  open: "bg-info/15 text-info border-info/30",
  pending: "bg-pending/15 text-pending border-pending/30",
  closed: "bg-muted text-muted-foreground border-border",
  failed: "bg-reject/15 text-reject border-reject/30",
};

function PatchStatusBadge({ status }: { status: string }) {
  const style = patchStatusStyles[status.toLowerCase()] ?? patchStatusStyles.pending;
  return (
    <Badge
      variant="outline"
      className={`text-xs px-2 py-0.5 capitalize ${style}`}
    >
      {status}
    </Badge>
  );
}

// ── Skeleton states ─────────────────────────────────────────────────────────

function MetricCardsSkeleton() {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      {Array.from({ length: 3 }).map((_, i) => (
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

function VulnFeedSkeleton() {
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {Array.from({ length: 4 }).map((_, i) => (
        <Card key={i}>
          <CardContent className="p-4 space-y-3">
            <div className="flex items-center justify-between">
              <Skeleton className="h-5 w-24" />
              <Skeleton className="h-5 w-16" />
            </div>
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-40" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function PatchTableSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 5 }).map((_, i) => (
        <Skeleton key={i} className="h-12 w-full" />
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
          <p className="text-sm font-medium">Failed to load patrol data</p>
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

// ── Empty states ────────────────────────────────────────────────────────────

function EmptyVulnerabilities() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-12">
        <Shield className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">No vulnerabilities found</p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Patrol scans will detect vulnerabilities in monitored repositories
        </p>
      </CardContent>
    </Card>
  );
}

function EmptyPatches() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-12">
        <Wrench className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">No patches generated</p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Auto-generated patches will appear here when vulnerabilities are found
        </p>
      </CardContent>
    </Card>
  );
}

// ── Vulnerability card ──────────────────────────────────────────────────────

function VulnCard({ vuln }: { vuln: Vulnerability }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-medium">
                {vuln.package_name}
              </span>
              <SeverityBadge severity={vuln.severity} size="sm" />
            </div>
            {vuln.cve_id && (
              <div className="flex items-center gap-1 mt-1">
                <span className="text-xs font-mono text-muted-foreground">
                  {vuln.cve_id}
                </span>
                {vuln.advisory_url && (
                  <a
                    href={vuln.advisory_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-muted-foreground hover:text-foreground"
                    aria-label={`Advisory for ${vuln.cve_id}`}
                  >
                    <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>
            )}
          </div>
          <Badge
            variant="outline"
            className="text-[10px] px-1.5 py-0 capitalize shrink-0"
          >
            {vuln.language}
          </Badge>
        </div>

        <div className="mt-3 grid grid-cols-2 gap-3 text-xs">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Affected Range
            </p>
            <p className="font-mono mt-0.5">{vuln.affected_range}</p>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
              Fix Version
            </p>
            <p className="font-mono mt-0.5">
              {vuln.fixed_version ?? (
                <span className="text-muted-foreground">No fix available</span>
              )}
            </p>
          </div>
        </div>

        <div className="mt-3 flex items-center justify-between text-[10px] text-muted-foreground">
          <span className="font-mono truncate max-w-[200px]">{vuln.repo}</span>
          <span>{formatRelativeTime(vuln.first_detected)}</span>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function PatrolDashboard() {
  const history = usePatrolHistory();
  const vulns = useVulnerabilities();
  const patches = usePatrolPatches();

  const isLoading = history.isLoading || vulns.isLoading || patches.isLoading;
  const isError = history.isError && vulns.isError && patches.isError;

  const handleRetry = useCallback(() => {
    history.refetch();
    vulns.refetch();
    patches.refetch();
  }, [history, vulns, patches]);

  if (isError) {
    return <ErrorState onRetry={handleRetry} />;
  }

  // Aggregate stats from patrol history
  const historyItems = history.data?.items ?? [];
  const totalScans = historyItems.length;
  const vulnItems = vulns.data?.items ?? [];
  const vulnsFound = vulnItems.length;
  const patchItems = patches.data?.items ?? [];
  const patchesGenerated = patchItems.length;

  return (
    <div className="space-y-6">
      {/* ── Stats cards ──────────────────────────────────────────────────── */}
      {isLoading ? (
        <MetricCardsSkeleton />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <MetricCard
            label="Total Scans"
            value={totalScans}
            icon={ScanLine}
          />
          <MetricCard
            label="Vulns Found"
            value={vulnsFound}
            icon={Bug}
          />
          <MetricCard
            label="Patches Generated"
            value={patchesGenerated}
            icon={Wrench}
          />
        </div>
      )}

      {/* ── Vulnerability feed ───────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Bug className="h-4 w-4" />
          Vulnerabilities
          {vulnItems.length > 0 && (
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {vulnItems.length} found
            </span>
          )}
        </h2>

        {vulns.isLoading ? (
          <VulnFeedSkeleton />
        ) : vulnItems.length === 0 ? (
          <EmptyVulnerabilities />
        ) : (
          <ScrollArea className="h-[420px]">
            <div className="grid gap-3 md:grid-cols-2 pr-4">
              {vulnItems.map((vuln) => (
                <VulnCard key={vuln.id} vuln={vuln} />
              ))}
            </div>
          </ScrollArea>
        )}
      </section>

      {/* ── Patch tracker table ──────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <PackageOpen className="h-4 w-4" />
          Patch Tracker
          {patchItems.length > 0 && (
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {patchItems.length} patches
            </span>
          )}
        </h2>

        {patches.isLoading ? (
          <PatchTableSkeleton />
        ) : patchItems.length === 0 ? (
          <EmptyPatches />
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">PR#</TableHead>
                  <TableHead>Package</TableHead>
                  <TableHead className="w-[180px]">Version Change</TableHead>
                  <TableHead className="w-[100px]">Status</TableHead>
                  <TableHead className="w-[100px]">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {patchItems.map((patch) => (
                  <TableRow key={patch.id}>
                    <TableCell>
                      <span className="font-mono text-sm">
                        {patch.pr_number ? `#${patch.pr_number}` : "--"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div>
                        <span className="text-sm font-medium">
                          {patch.package_name}
                        </span>
                        {patch.cve_id && (
                          <span className="ml-2 text-xs text-muted-foreground font-mono">
                            {patch.cve_id}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">
                        <span className="text-reject">{patch.old_version}</span>
                        <span className="text-muted-foreground mx-1">{"->"}</span>
                        <span className="text-approve">{patch.new_version}</span>
                      </span>
                    </TableCell>
                    <TableCell>
                      <PatchStatusBadge status={patch.status} />
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {formatRelativeTime(patch.created_at)}
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
