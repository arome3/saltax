import { http, HttpResponse } from "msw";
import type {
  AgentStatus,
  PipelineRecord,
  Contributor,
  VerificationWindow,
  IntelligenceStats,
  AttestationProof,
  Transaction,
  Bounty,
  AgentIdentity,
} from "@/types";

// ── Fixtures ────────────────────────────────────────────────────────────────

export const mockAgentStatus: AgentStatus = {
  agent: {
    name: "SaltaX",
    version: "1.0.0",
    wallet_address: "0x1234567890abcdef1234567890abcdef12345678",
    erc8004_id: "erc8004-001",
    uptime_seconds: 86400,
  },
  treasury: {
    balance_wei: 5000000000000000000,
    reserve_wei: 1000000000000000000,
    bounty_wei: 500000000000000000,
    available: true,
  },
  reputation: {
    total_prs_reviewed: 150,
    approval_rate: 0.87,
    vulnerabilities_caught: 12,
    uptime_seconds: 86400,
  },
  intelligence: {
    total_patterns: 450,
    db_initialized: true,
  },
};

export const mockPipelineRecord: PipelineRecord = {
  id: "pipe-001",
  pr_id: "owner/repo#42",
  repo: "owner/repo",
  pr_author: "contributor1",
  verdict: "APPROVE",
  composite_score: 0.87,
  findings_count: 2,
  score_breakdown: { static_analysis: 0.85, ai_quality: 0.90, test_coverage: 0.88 },
  is_self_modification: false,
  threshold_used: 0.75,
  attestation_id: "attest-001",
  created_at: new Date().toISOString(),
};

export const mockContributor: Contributor = {
  id: "contrib-001",
  github_login: "alice",
  wallet_address: "0xabcdef1234567890abcdef1234567890abcdef12",
  total_submissions: 20,
  approved_submissions: 18,
  rejected_submissions: 2,
  reputation_score: 0.9,
  first_seen: "2025-01-01T00:00:00Z",
  last_active: new Date().toISOString(),
};

export const mockVerificationWindow: VerificationWindow = {
  id: "win-001",
  pr_id: "owner/repo#42",
  repo: "owner/repo",
  pr_number: 42,
  status: "open",
  bounty_amount_wei: "100000000000000000",
  stake_amount_wei: "50000000000000000",
  window_hours: 24,
  opens_at: new Date().toISOString(),
  closes_at: new Date(Date.now() + 86400000).toISOString(),
  is_self_modification: false,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

export const mockIntelStats: IntelligenceStats = {
  total_patterns: 450,
  category_distribution: { security: 120, quality: 200, performance: 130 },
  severity_distribution: { CRITICAL: 5, HIGH: 25, MEDIUM: 80, LOW: 200, INFO: 140 },
  avg_false_positive_rate: 0.03,
  patterns_last_7_days: 35,
  top_contributing_repos: { "owner/repo": 80, "org/lib": 45 },
};

export const mockAttestation: AttestationProof = {
  attestation_id: "attest-001",
  docker_image_digest: "sha256:abc123def456",
  tee_platform_id: "sgx-v3",
  pipeline_input_hash: "0xinput123",
  pipeline_output_hash: "0xoutput456",
  ai_seed: "seed-789",
  ai_output_hash: "0xai789",
  ai_system_fingerprint: "fp-001",
  signature: "0xsig123",
  signer_address: "0x1234567890abcdef1234567890abcdef12345678",
  created_at: new Date().toISOString(),
  previous_attestation_id: null,
  signature_status: "valid",
};

export const mockTransaction: Transaction = {
  id: "tx-001",
  tx_hash: "0xtxhash123456789abcdef",
  tx_type: "BOUNTY_OUT",
  amount_wei: 100000000000000000,
  currency: "ETH",
  counterparty: "0xabcdef",
  pr_id: "owner/repo#42",
  timestamp: new Date().toISOString(),
};

export const mockBounty: Bounty = {
  id: "bounty-001",
  repo: "owner/repo",
  issue_number: 10,
  label: "bounty-md",
  amount_eth: 0.1,
  status: "open",
  created_at: new Date().toISOString(),
};

export const mockIdentity: AgentIdentity = {
  identity: {
    agent_id: "saltax-001",
    chain_id: 8453,
    wallet_address: "0x1234567890abcdef1234567890abcdef12345678",
    name: "SaltaX",
    description: "Sovereign AI code reviewer",
    registered_at: "2025-01-01T00:00:00Z",
  },
  local_metrics: {
    total_prs_reviewed: 150,
    approval_rate: 0.87,
    vulnerabilities_caught: 12,
    uptime_seconds: 86400,
  },
};

// ── Handlers ────────────────────────────────────────────────────────────────

export const handlers = [
  http.get("/api/v1/status", () => {
    return HttpResponse.json(mockAgentStatus);
  }),

  http.get("/api/v1/health", () => {
    return HttpResponse.json({
      status: "ok",
      components: { db: { status: "ok", latency_ms: 1 } },
      cached: false,
    });
  }),

  http.get("/api/v1/pipeline", ({ request }) => {
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get("page") ?? "1");
    const limit = parseInt(url.searchParams.get("limit") ?? "20");
    return HttpResponse.json({
      items: [mockPipelineRecord],
      count: 1,
      page,
      limit,
    });
  }),

  http.get("/api/v1/pipeline/:id", () => {
    return HttpResponse.json(mockPipelineRecord);
  }),

  http.get("/api/v1/contributors", () => {
    return HttpResponse.json({
      items: [mockContributor],
      count: 1,
      page: 1,
      limit: 25,
    });
  }),

  http.get("/api/v1/contributors/:id", () => {
    return HttpResponse.json(mockContributor);
  }),

  http.get("/api/v1/verification/windows", () => {
    return HttpResponse.json({
      windows: [mockVerificationWindow],
      count: 1,
    });
  }),

  http.get("/api/v1/verification/windows/:id", () => {
    return HttpResponse.json(mockVerificationWindow);
  }),

  http.get("/api/v1/disputes/window/:id", () => {
    return HttpResponse.json({ disputes: [], count: 0 });
  }),

  http.get("/api/v1/intelligence/stats", () => {
    return HttpResponse.json(mockIntelStats);
  }),

  http.get("/api/v1/intelligence/knowledge", () => {
    return HttpResponse.json({ items: [], count: 0 });
  }),

  http.get("/api/v1/attestation", () => {
    return HttpResponse.json({
      items: [mockAttestation],
      count: 1,
      page: 1,
      limit: 25,
    });
  }),

  http.get("/api/v1/attestation/:actionId", () => {
    return HttpResponse.json({ ...mockAttestation, signature_status: "valid" });
  }),

  http.get("/api/v1/patrol/history", () => {
    return HttpResponse.json({ items: [], page: 1, limit: 25 });
  }),

  http.get("/api/v1/patrol/vulnerabilities", () => {
    return HttpResponse.json({ items: [], page: 1, limit: 25 });
  }),

  http.get("/api/v1/patrol/patches", () => {
    return HttpResponse.json({ items: [], page: 1, limit: 25 });
  }),

  http.get("/api/v1/treasury/transactions", () => {
    return HttpResponse.json({
      items: [mockTransaction],
      count: 1,
      page: 1,
      limit: 25,
    });
  }),

  http.get("/api/v1/bounties", () => {
    return HttpResponse.json({
      bounties: [mockBounty],
      count: 1,
    });
  }),

  http.get("/api/v1/identity", () => {
    return HttpResponse.json(mockIdentity);
  }),

  http.get("/api/v1/vision", () => {
    return HttpResponse.json({ items: [], count: 0 });
  }),

  http.post("/api/v1/vision", () => {
    return HttpResponse.json({ status: "accepted" });
  }),

  http.post("/api/v1/audit", () => {
    return HttpResponse.json({ audit_id: "audit-001" });
  }),

  http.post("/api/v1/challenges", () => {
    return HttpResponse.json({ success: true, challenge_id: "chal-001" });
  }),
];
