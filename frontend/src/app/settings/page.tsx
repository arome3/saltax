"use client";

import { useCallback } from "react";
import { useAgentStatus, useIdentity, useVisionDocuments } from "@/lib/api";
import { StatusPill } from "@/components/saltax/status-pill";
import { CopyButton } from "@/components/saltax/copy-button";
import { ScoreBar } from "@/components/saltax/score-bar";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { truncateHash, formatRelativeTime } from "@/lib/utils";
import {
  Wallet,
  Fingerprint,
  ShieldCheck,
  Clock,
  FileText,
  Settings2,
  RefreshCw,
  Eye,
} from "lucide-react";
import type { AgentHealthStatus, VisionDocument } from "@/types";

// ── Helpers ─────────────────────────────────────────────────────────────────

function deriveHealthStatus(uptime: number | undefined): AgentHealthStatus {
  if (uptime === undefined) return "unknown";
  if (uptime > 0) return "operational";
  return "halted";
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

// ── Skeleton states ─────────────────────────────────────────────────────────

function IdentityCardSkeleton() {
  return (
    <Card>
      <CardContent className="p-6 space-y-4">
        <Skeleton className="h-6 w-48" />
        <div className="grid grid-cols-2 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function VisionListSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 3 }).map((_, i) => (
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
          <p className="text-sm font-medium">Failed to load settings</p>
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

// ── Empty vision docs ───────────────────────────────────────────────────────

function EmptyVisionDocs() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-12">
        <Eye className="h-8 w-8 text-muted-foreground/40 mb-3" />
        <p className="text-sm text-muted-foreground">No vision documents</p>
        <p className="text-xs text-muted-foreground/70 mt-1">
          Vision documents guide the agent&apos;s behavior per repository
        </p>
      </CardContent>
    </Card>
  );
}

// ── Identity field row ──────────────────────────────────────────────────────

function IdentityField({
  label,
  value,
  mono,
  copyable,
}: {
  label: string;
  value: string;
  mono?: boolean;
  copyable?: boolean;
}) {
  return (
    <div>
      <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
        {label}
      </p>
      <div className="flex items-center gap-1 mt-0.5">
        <span
          className={`text-xs font-medium ${mono ? "font-mono" : ""} truncate`}
        >
          {value}
        </span>
        {copyable && <CopyButton value={value} />}
      </div>
    </div>
  );
}

// ── Vision document row ─────────────────────────────────────────────────────

function VisionDocRow({ doc }: { doc: VisionDocument }) {
  return (
    <div className="flex items-center justify-between py-3 px-4 border-b last:border-b-0">
      <div className="flex items-center gap-3 min-w-0">
        <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className="text-[10px] px-1.5 py-0 capitalize"
            >
              {doc.doc_type}
            </Badge>
            <span className="text-xs font-mono text-muted-foreground truncate max-w-[200px]">
              {doc.repo}
            </span>
          </div>
        </div>
      </div>
      <span className="text-xs text-muted-foreground shrink-0 ml-4">
        {formatRelativeTime(doc.updated_at)}
      </span>
    </div>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const status = useAgentStatus();
  const identity = useIdentity();
  const vision = useVisionDocuments();

  const isLoading = status.isLoading || identity.isLoading || vision.isLoading;
  const isError = status.isError && identity.isError && vision.isError;

  const handleRetry = useCallback(() => {
    status.refetch();
    identity.refetch();
    vision.refetch();
  }, [status, identity, vision]);

  if (isError) {
    return <ErrorState onRetry={handleRetry} />;
  }

  const agent = status.data?.agent;
  const idData = identity.data?.identity;
  const localMetrics = identity.data?.local_metrics;
  const visionDocs = vision.data?.items ?? [];

  return (
    <div className="space-y-6">
      {/* ── Agent identity card ──────────────────────────────────────────── */}
      {status.isLoading || identity.isLoading ? (
        <IdentityCardSkeleton />
      ) : (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <Fingerprint className="h-4 w-4" />
                Agent Identity
              </CardTitle>
              {agent && (
                <StatusPill
                  status={deriveHealthStatus(agent.uptime_seconds)}
                />
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Identity fields */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {agent?.wallet_address && (
                <IdentityField
                  label="Wallet Address"
                  value={agent.wallet_address}
                  mono
                  copyable
                />
              )}
              {agent?.erc8004_id && (
                <IdentityField
                  label="ERC-8004 ID"
                  value={agent.erc8004_id}
                  mono
                  copyable
                />
              )}
              {idData?.agent_id && (
                <IdentityField
                  label="Agent ID"
                  value={idData.agent_id}
                  mono
                  copyable
                />
              )}
              {idData?.chain_id !== undefined && (
                <IdentityField
                  label="Chain ID"
                  value={String(idData.chain_id)}
                  mono
                />
              )}
              {agent?.name && (
                <IdentityField label="Name" value={agent.name} />
              )}
              {agent?.version && (
                <IdentityField
                  label="Version"
                  value={`v${agent.version}`}
                  mono
                />
              )}
            </div>

            {/* Metrics row */}
            <div className="border-t pt-4">
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider flex items-center gap-1">
                    <ShieldCheck className="h-3 w-3" />
                    Trust Score
                  </p>
                  <div className="mt-1">
                    {localMetrics?.approval_rate !== undefined ? (
                      <ScoreBar
                        score={localMetrics.approval_rate}
                        label={`${(localMetrics.approval_rate * 100).toFixed(1)}%`}
                      />
                    ) : (
                      <span className="text-xs text-muted-foreground">--</span>
                    )}
                  </div>
                </div>
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    Uptime
                  </p>
                  <p className="text-sm font-mono font-medium mt-1">
                    {agent?.uptime_seconds !== undefined
                      ? formatUptime(agent.uptime_seconds)
                      : "--"}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
                    PRs Reviewed
                  </p>
                  <p className="text-sm font-mono font-medium mt-1">
                    {localMetrics?.total_prs_reviewed ?? "--"}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
                    Vulns Caught
                  </p>
                  <p className="text-sm font-mono font-medium mt-1">
                    {localMetrics?.vulnerabilities_caught ?? "--"}
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Vision documents ─────────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Eye className="h-4 w-4" />
          Vision Documents
          {visionDocs.length > 0 && (
            <span className="ml-auto text-xs font-normal text-muted-foreground">
              {visionDocs.length} document{visionDocs.length !== 1 ? "s" : ""}
            </span>
          )}
        </h2>

        {vision.isLoading ? (
          <VisionListSkeleton />
        ) : visionDocs.length === 0 ? (
          <EmptyVisionDocs />
        ) : (
          <Card>
            <CardContent className="p-0">
              {visionDocs.map((doc) => (
                <VisionDocRow key={doc.id} doc={doc} />
              ))}
            </CardContent>
          </Card>
        )}
      </section>

      {/* ── Config info panel ────────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Settings2 className="h-4 w-4" />
            Configuration
          </CardTitle>
        </CardHeader>
        <CardContent>
          {status.isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-4 w-full" />
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {agent?.wallet_address && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground flex items-center gap-1">
                    <Wallet className="h-3 w-3" />
                    Treasury Wallet
                  </span>
                  <div className="flex items-center gap-1">
                    <span className="font-mono">
                      {truncateHash(agent.wallet_address)}
                    </span>
                    <CopyButton value={agent.wallet_address} />
                  </div>
                </div>
              )}
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Intelligence DB</span>
                <span className="font-medium">
                  {status.data?.intelligence.db_initialized ? (
                    <span className="text-approve">Initialized</span>
                  ) : (
                    <span className="text-reject">Not Initialized</span>
                  )}
                </span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Treasury Status</span>
                <span className="font-medium">
                  {status.data?.treasury.available ? (
                    <span className="text-approve">Active</span>
                  ) : (
                    <span className="text-reject">Inactive</span>
                  )}
                </span>
              </div>
              {idData?.registered_at && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Registered</span>
                  <span>{formatRelativeTime(idData.registered_at)}</span>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
