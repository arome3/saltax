// ── Agent & System ──────────────────────────────────────────────────────────

export interface AgentStatus {
  agent: {
    name: string;
    version: string;
    wallet_address: string;
    erc8004_id: string;
    uptime_seconds: number;
  };
  treasury: {
    balance_wei: number;
    reserve_wei: number;
    bounty_wei: number;
    available: boolean;
  };
  reputation: {
    total_prs_reviewed: number;
    approval_rate: number;
    vulnerabilities_caught: number;
    uptime_seconds: number;
  };
  intelligence: {
    total_patterns: number;
    db_initialized: boolean;
  };
}

export interface HealthStatus {
  status: "ok" | "degraded";
  components: Record<
    string,
    { status: string; latency_ms: number; detail?: string }
  >;
  cached: boolean;
  budget_utilisation?: number;
}

// ── Pagination ──────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  items: T[];
  count: number;
  page: number;
  limit: number;
}

export interface PaginationParams {
  page?: number;
  limit?: number;
}

// ── Pipeline ────────────────────────────────────────────────────────────────

export type VerdictDecision = "APPROVE" | "REQUEST_CHANGES" | "REJECT" | "UNKNOWN";

export interface PipelineRecord {
  id: string;
  pr_id: string;
  repo: string;
  pr_author: string;
  verdict: VerdictDecision;
  composite_score: number;
  findings_count: number;
  score_breakdown: Record<string, number>;
  is_self_modification: boolean;
  threshold_used: number | null;
  attestation_id?: string;
  created_at: string;
}

export interface PipelineListParams extends PaginationParams {
  repo?: string;
  verdict?: VerdictDecision;
}

// ── Contributors ────────────────────────────────────────────────────────────

export interface Contributor {
  id: string;
  github_login: string;
  wallet_address: string;
  total_submissions: number;
  approved_submissions: number;
  rejected_submissions: number;
  reputation_score: number;
  first_seen: string;
  last_active: string;
}

// ── Verification ────────────────────────────────────────────────────────────

export type WindowStatus = "open" | "challenged" | "executed" | "expired";

export interface VerificationWindow {
  id: string;
  pr_id: string;
  repo: string;
  pr_number: number;
  status: WindowStatus;
  bounty_amount_wei: string;
  stake_amount_wei: string;
  window_hours: number;
  opens_at: string;
  closes_at: string;
  challenge_id?: string;
  challenger_address?: string;
  resolution?: string;
  is_self_modification: boolean;
  created_at: string;
  updated_at: string;
}

export type DisputeStatus =
  | "PENDING"
  | "SUBMITTED"
  | "RESOLVED"
  | "TIMED_OUT"
  | "MANUAL_REVIEW"
  | "FAILED";

export interface Dispute {
  dispute_id: string;
  challenge_id: string;
  window_id: string;
  dispute_type: "COMPUTATION" | "SUBJECTIVE";
  claim_type: "AI_OUTPUT_INCORRECT" | "SCORING_UNFAIR";
  status: DisputeStatus;
  provider_case_id?: string;
  provider_verdict?: string;
  challenger_address: string;
  challenger_stake_wei: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
}

// ── Attestation ─────────────────────────────────────────────────────────────

export interface AttestationProof {
  attestation_id: string;
  docker_image_digest: string;
  tee_platform_id: string;
  pipeline_input_hash: string;
  pipeline_output_hash: string;
  ai_seed: string | null;
  ai_output_hash: string | null;
  ai_system_fingerprint: string | null;
  signature: string;
  signer_address: string;
  created_at: string;
  previous_attestation_id: string | null;
  signature_status?: "valid" | "invalid" | "unsigned" | "unverifiable";
}

// ── Patrol ──────────────────────────────────────────────────────────────────

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface PatrolHistory {
  id: string;
  repo: string;
  timestamp: string;
  dependency_findings_count: number;
  code_findings_count: number;
  patches_generated: number;
  issues_created: number;
  bounties_assigned_wei: string;
  attestation_id?: string;
  duration_ms?: number;
}

export interface Vulnerability {
  id: string;
  cve_id?: string;
  package_name: string;
  language: string;
  severity: Severity;
  affected_range: string;
  fixed_version?: string;
  advisory_url?: string;
  repo: string;
  status: string;
  first_detected: string;
  last_checked: string;
  bounty_issue_number?: number;
}

export interface PatrolPatch {
  id: string;
  repo: string;
  pr_number?: number;
  cve_id?: string;
  package_name: string;
  old_version: string;
  new_version: string;
  status: string;
  created_at: string;
  merged_at?: string;
  attestation_id?: string;
}

// ── Treasury ────────────────────────────────────────────────────────────────

export interface Transaction {
  id: string;
  tx_hash?: string;
  tx_type: string;
  amount_wei: number;
  currency: string;
  counterparty: string;
  pr_id?: string;
  audit_id?: string;
  bounty_id?: string;
  attestation_id?: string;
  timestamp: string;
}

// ── Intelligence ────────────────────────────────────────────────────────────

export interface IntelligenceStats {
  total_patterns: number;
  category_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  avg_false_positive_rate: number;
  patterns_last_7_days: number;
  top_contributing_repos: Record<string, number>;
}

export interface CodebaseKnowledge {
  id: string;
  repo: string;
  file_path: string;
  knowledge: string;
  updated_at: string;
}

// ── Bounties ────────────────────────────────────────────────────────────────

export interface Bounty {
  id: string;
  repo: string;
  issue_number: number;
  label: string;
  amount_eth: number;
  status: string;
  created_at: string;
  claimed_by?: string;
  source?: string;
}

// ── Identity ────────────────────────────────────────────────────────────────

export interface AgentIdentity {
  identity: {
    agent_id: string;
    chain_id: number;
    wallet_address: string;
    name: string;
    description: string;
    registered_at: string;
  };
  local_metrics: {
    total_prs_reviewed: number;
    approval_rate: number;
    vulnerabilities_caught: number;
    uptime_seconds: number;
  };
  on_chain_reputation?: Record<string, unknown>;
}

// ── Vision ──────────────────────────────────────────────────────────────────

export interface VisionDocument {
  id: string;
  repo: string;
  doc_type: string;
  updated_at: string;
}

// ── WebSocket Events ────────────────────────────────────────────────────────

export interface LogEvent {
  timestamp: string;
  level: "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL";
  logger: string;
  message: string;
  repo?: string;
  pr_id?: string;
  pr_number?: number;
  action?: string;
  stage?: string;
  duration_ms?: number;
  component?: string;
  status?: string;
}

// ── Enums / Unions ──────────────────────────────────────────────────────────

export type AgentHealthStatus = "operational" | "degraded" | "halted" | "unknown";

export type AuditScope = "security_only" | "quality_only" | "full";

export type TransactionType =
  | "SPONSORSHIP_IN"
  | "AUDIT_FEE_IN"
  | "STAKE_PENALTY_IN"
  | "BOUNTY_OUT"
  | "COMPUTE_FEE_OUT"
  | "COMMUNITY_GRANT_OUT"
  | "STAKE_RETURN_OUT"
  | "STAKE_BONUS_OUT"
  | "payout"
  | "audit_fee_usdc";
