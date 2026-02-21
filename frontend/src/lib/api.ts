"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { qs } from "./utils";
import type {
  AgentStatus,
  PaginatedResponse,
  PipelineRecord,
  PipelineListParams,
  Contributor,
  VerificationWindow,
  Dispute,
  AttestationProof,
  PatrolHistory,
  Vulnerability,
  PatrolPatch,
  Transaction,
  IntelligenceStats,
  CodebaseKnowledge,
  Bounty,
  AgentIdentity,
  VisionDocument,
  HealthStatus,
  PaginationParams,
} from "@/types";

// ── Base fetcher ────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public status: number,
    public body: unknown,
  ) {
    super(`API error ${status}`);
    this.name = "ApiError";
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init);
  if (!res.ok) {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = await res.text();
    }
    throw new ApiError(res.status, body);
  }
  return res.json() as Promise<T>;
}

// ── Status & Health ─────────────────────────────────────────────────────────

export function useAgentStatus() {
  return useQuery({
    queryKey: ["agent", "status"],
    queryFn: () => apiFetch<AgentStatus>("/api/v1/status"),
    refetchInterval: 30_000,
    retry: 3,
  });
}

export function useHealthStatus() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => apiFetch<HealthStatus>("/api/v1/health"),
    refetchInterval: 60_000,
  });
}

// ── Pipeline ────────────────────────────────────────────────────────────────

export function usePipelineList(params: PipelineListParams) {
  return useQuery({
    queryKey: ["pipeline", "list", params],
    queryFn: () =>
      apiFetch<PaginatedResponse<PipelineRecord>>(
        `/api/v1/pipeline?${qs(params)}`,
      ),
    refetchInterval: 30_000,
  });
}

export function usePipelineRecord(id: string) {
  return useQuery({
    queryKey: ["pipeline", "record", id],
    queryFn: () => apiFetch<PipelineRecord>(`/api/v1/pipeline/${id}`),
    enabled: !!id,
  });
}

// ── Contributors ────────────────────────────────────────────────────────────

export function useContributors(params: PaginationParams = {}) {
  return useQuery({
    queryKey: ["contributors", "list", params],
    queryFn: () =>
      apiFetch<PaginatedResponse<Contributor>>(
        `/api/v1/contributors?${qs(params)}`,
      ),
    refetchInterval: 60_000,
  });
}

export function useContributor(id: string) {
  return useQuery({
    queryKey: ["contributors", "detail", id],
    queryFn: () => apiFetch<Contributor>(`/api/v1/contributors/${id}`),
    enabled: !!id,
  });
}

// ── Verification & Disputes ─────────────────────────────────────────────────

export function useVerificationWindows(status?: string) {
  const params = status ? { status } : {};
  return useQuery({
    queryKey: ["verification", "windows", params],
    queryFn: () =>
      apiFetch<{ windows: VerificationWindow[]; count: number }>(
        `/api/v1/verification/windows?${qs(params)}`,
      ),
    refetchInterval: 30_000,
  });
}

export function useVerificationWindow(id: string) {
  return useQuery({
    queryKey: ["verification", "window", id],
    queryFn: () =>
      apiFetch<VerificationWindow>(`/api/v1/verification/windows/${id}`),
    enabled: !!id,
  });
}

export function useDisputesForWindow(windowId: string) {
  return useQuery({
    queryKey: ["disputes", "window", windowId],
    queryFn: () =>
      apiFetch<{ disputes: Dispute[]; count: number }>(
        `/api/v1/disputes/window/${windowId}`,
      ),
    enabled: !!windowId,
  });
}

export function useFileChallenge() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      window_id: string;
      rationale: string;
      evidence_hash?: string;
    }) =>
      apiFetch<{ success: boolean; challenge_id: string }>(
        "/api/v1/challenges",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["verification"] });
    },
  });
}

// ── Attestation ─────────────────────────────────────────────────────────────

export function useAttestationSearch(params: {
  q?: string;
  action_type?: string;
  page?: number;
  limit?: number;
}) {
  return useQuery({
    queryKey: ["attestation", "search", params],
    queryFn: () =>
      apiFetch<PaginatedResponse<AttestationProof>>(
        `/api/v1/attestation?${qs(params)}`,
      ),
  });
}

export function useAttestation(actionId: string) {
  return useQuery({
    queryKey: ["attestation", "detail", actionId],
    queryFn: () =>
      apiFetch<AttestationProof & { signature_status: string }>(
        `/api/v1/attestation/${actionId}`,
      ),
    enabled: !!actionId,
  });
}

// ── Patrol ──────────────────────────────────────────────────────────────────

export function usePatrolHistory(params: { repo?: string } & PaginationParams = {}) {
  return useQuery({
    queryKey: ["patrol", "history", params],
    queryFn: () =>
      apiFetch<{ items: PatrolHistory[]; page: number; limit: number }>(
        `/api/v1/patrol/history?${qs(params)}`,
      ),
    refetchInterval: 60_000,
  });
}

export function useVulnerabilities(
  params: { repo?: string; status?: string; severity?: string } & PaginationParams = {},
) {
  return useQuery({
    queryKey: ["patrol", "vulnerabilities", params],
    queryFn: () =>
      apiFetch<{ items: Vulnerability[]; page: number; limit: number }>(
        `/api/v1/patrol/vulnerabilities?${qs(params)}`,
      ),
  });
}

export function usePatrolPatches(
  params: { repo?: string; status?: string } & PaginationParams = {},
) {
  return useQuery({
    queryKey: ["patrol", "patches", params],
    queryFn: () =>
      apiFetch<{ items: PatrolPatch[]; page: number; limit: number }>(
        `/api/v1/patrol/patches?${qs(params)}`,
      ),
  });
}

// ── Treasury ────────────────────────────────────────────────────────────────

export function useTransactions(params: PaginationParams = {}) {
  return useQuery({
    queryKey: ["treasury", "transactions", params],
    queryFn: () =>
      apiFetch<PaginatedResponse<Transaction>>(
        `/api/v1/treasury/transactions?${qs(params)}`,
      ),
    refetchInterval: 60_000,
  });
}

// ── Intelligence ────────────────────────────────────────────────────────────

export function useIntelligenceStats() {
  return useQuery({
    queryKey: ["intelligence", "stats"],
    queryFn: () => apiFetch<IntelligenceStats>("/api/v1/intelligence/stats"),
    refetchInterval: 60_000,
  });
}

export function useCodebaseKnowledge(repo: string) {
  return useQuery({
    queryKey: ["intelligence", "knowledge", repo],
    queryFn: () =>
      apiFetch<{ items: CodebaseKnowledge[]; count: number }>(
        `/api/v1/intelligence/knowledge?${qs({ repo })}`,
      ),
    enabled: !!repo,
  });
}

// ── Bounties ────────────────────────────────────────────────────────────────

export function useBounties() {
  return useQuery({
    queryKey: ["bounties"],
    queryFn: () =>
      apiFetch<{ bounties: Bounty[]; count: number }>("/api/v1/bounties"),
    refetchInterval: 60_000,
  });
}

// ── Identity ────────────────────────────────────────────────────────────────

export function useIdentity() {
  return useQuery({
    queryKey: ["identity"],
    queryFn: () => apiFetch<AgentIdentity>("/api/v1/identity"),
  });
}

// ── Vision ──────────────────────────────────────────────────────────────────

export function useVisionDocuments() {
  return useQuery({
    queryKey: ["vision", "list"],
    queryFn: () =>
      apiFetch<{ items: VisionDocument[]; count: number }>("/api/v1/vision"),
  });
}

export function useSubmitVision() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      repo: string;
      content: string;
      doc_type?: string;
      title?: string;
    }) =>
      apiFetch<{ status: string }>("/api/v1/vision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vision"] });
    },
  });
}

// ── Audit ────────────────────────────────────────────────────────────────────

export function useSubmitAudit() {
  return useMutation({
    mutationFn: (body: {
      repository_url: string;
      commit_sha: string;
      scope: string;
    }) =>
      apiFetch<{ audit_id: string }>("/api/v1/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
  });
}
