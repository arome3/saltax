-- SaltaX Intelligence Database — PostgreSQL Schema
-- Idempotent: safe to re-run on an existing database.
-- 22 tables (21 IntelligenceDB + seen_tx_hashes).

-- ── Schema version tracking ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS schema_version (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    version     INTEGER NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

-- ── Vulnerability patterns ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vulnerability_patterns (
    id                       TEXT PRIMARY KEY,
    rule_id                  TEXT NOT NULL,
    severity                 TEXT NOT NULL DEFAULT 'MEDIUM',
    category                 TEXT NOT NULL DEFAULT 'uncategorized',
    normalized_pattern       TEXT NOT NULL,
    pattern_signature        TEXT NOT NULL UNIQUE,
    confidence               REAL NOT NULL DEFAULT 0.5,
    times_seen               INTEGER NOT NULL DEFAULT 1,
    first_seen               TEXT NOT NULL,
    last_seen                TEXT NOT NULL,
    source_stage             TEXT NOT NULL DEFAULT 'unknown',
    confirmed_true_positive  INTEGER NOT NULL DEFAULT 0,
    confirmed_false_positive INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_vp_signature ON vulnerability_patterns(pattern_signature);
CREATE INDEX IF NOT EXISTS idx_vp_rule_id ON vulnerability_patterns(rule_id);
CREATE INDEX IF NOT EXISTS idx_vp_category ON vulnerability_patterns(category);
CREATE INDEX IF NOT EXISTS idx_vp_severity ON vulnerability_patterns(severity);

-- ── Contributor profiles ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS contributor_profiles (
    id                   TEXT PRIMARY KEY,
    github_login         TEXT NOT NULL DEFAULT '',
    wallet_address       TEXT NOT NULL DEFAULT '',
    total_submissions    INTEGER NOT NULL DEFAULT 0,
    approved_submissions INTEGER NOT NULL DEFAULT 0,
    rejected_submissions INTEGER NOT NULL DEFAULT 0,
    reputation_score     REAL NOT NULL DEFAULT 0.5,
    first_seen           TEXT NOT NULL,
    last_active          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cp_github ON contributor_profiles(github_login);
CREATE INDEX IF NOT EXISTS idx_cp_wallet ON contributor_profiles(wallet_address);

-- ── Codebase knowledge ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codebase_knowledge (
    id          TEXT PRIMARY KEY,
    repo        TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    knowledge   TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- ── Pipeline history ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS pipeline_history (
    id              TEXT PRIMARY KEY,
    pr_id           TEXT NOT NULL,
    repo            TEXT NOT NULL,
    pr_author       TEXT DEFAULT '',
    verdict         TEXT NOT NULL,
    composite_score REAL,
    findings_count  INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ph_repo ON pipeline_history(repo);
CREATE INDEX IF NOT EXISTS idx_ph_pr_author ON pipeline_history(pr_author);
CREATE INDEX IF NOT EXISTS idx_ph_created ON pipeline_history(created_at);

-- ── Attestation store ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS attestation_store (
    attestation_id          TEXT PRIMARY KEY,
    pr_id                   TEXT NOT NULL,
    repo                    TEXT NOT NULL,
    pipeline_input_hash     TEXT NOT NULL,
    pipeline_output_hash    TEXT NOT NULL,
    signature               TEXT NOT NULL DEFAULT '',
    docker_image_digest     TEXT NOT NULL DEFAULT '',
    tee_platform_id         TEXT NOT NULL DEFAULT '',
    previous_attestation_id TEXT,
    ai_seed                 BIGINT,
    ai_output_hash          TEXT,
    ai_system_fingerprint   TEXT,
    signer_address          TEXT NOT NULL DEFAULT '',
    created_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_as_pr ON attestation_store(pr_id);
CREATE INDEX IF NOT EXISTS idx_as_created ON attestation_store(created_at);

-- ── Active bounties ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS active_bounties (
    id           TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    label        TEXT NOT NULL,
    amount_eth   REAL NOT NULL DEFAULT 0.0,
    status       TEXT NOT NULL DEFAULT 'open',
    created_at   TEXT NOT NULL,
    claimed_by   TEXT,
    source       TEXT DEFAULT 'pipeline'
);

CREATE INDEX IF NOT EXISTS idx_ab_repo ON active_bounties(repo);
CREATE INDEX IF NOT EXISTS idx_ab_status ON active_bounties(status);

-- ── Verification windows ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS verification_windows (
    id                   TEXT PRIMARY KEY,
    pr_id                TEXT NOT NULL,
    repo                 TEXT NOT NULL,
    pr_number            INTEGER NOT NULL,
    installation_id      INTEGER NOT NULL,
    attestation_id       TEXT NOT NULL,
    verdict_json         JSONB NOT NULL DEFAULT '{}',
    attestation_json     JSONB NOT NULL DEFAULT '{}',
    contributor_address  TEXT,
    bounty_amount_wei    TEXT DEFAULT '0',
    stake_amount_wei     TEXT DEFAULT '0',
    window_hours         INTEGER NOT NULL,
    opens_at             TEXT NOT NULL,
    closes_at            TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'open',
    challenge_id         TEXT,
    challenger_address   TEXT,
    challenger_stake_wei TEXT,
    challenge_rationale  TEXT,
    resolution           TEXT,
    contributor_stake_id TEXT,
    challenger_stake_id  TEXT,
    is_self_modification BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vw_status ON verification_windows(status);
CREATE INDEX IF NOT EXISTS idx_vw_closes_at ON verification_windows(closes_at);
CREATE INDEX IF NOT EXISTS idx_vw_verdict_gin ON verification_windows USING GIN (verdict_json);

-- ── PR embeddings ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS pr_embeddings (
    id              TEXT PRIMARY KEY,
    pr_id           TEXT NOT NULL,
    repo            TEXT NOT NULL,
    pr_number       INTEGER,
    commit_sha      TEXT NOT NULL,
    embedding       BYTEA NOT NULL,
    embedding_model TEXT NOT NULL DEFAULT '',
    issue_number    INTEGER,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pe_repo ON pr_embeddings(repo);
CREATE INDEX IF NOT EXISTS idx_pe_repo_created ON pr_embeddings(repo, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pe_repo_issue ON pr_embeddings(repo, issue_number);

-- ── Vision documents ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vision_documents (
    id           TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    doc_type     TEXT NOT NULL DEFAULT 'vision',
    content      TEXT NOT NULL,
    embedding    BYTEA,
    updated_at   TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vd_repo_doctype
    ON vision_documents(repo, doc_type);
CREATE INDEX IF NOT EXISTS idx_vd_repo ON vision_documents(repo);

-- ── Vision score history ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vision_score_history (
    id               TEXT PRIMARY KEY,
    repo             TEXT NOT NULL,
    pr_id            TEXT NOT NULL,
    pr_number        INTEGER NOT NULL DEFAULT 0,
    vision_score     INTEGER NOT NULL,
    ai_confidence    REAL NOT NULL,
    goal_scores_json JSONB,
    created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vsh_repo_created
    ON vision_score_history(repo, created_at DESC);

-- ── Agent identity cache ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agent_identity_cache (
    wallet_address  TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    chain_id        INTEGER NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    registered_at   TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ── Dispute records ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS dispute_records (
    dispute_id           TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL,
    window_id            TEXT NOT NULL,
    dispute_type         TEXT NOT NULL,
    claim_type           TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending',
    provider_case_id     TEXT,
    provider_verdict     TEXT,
    attestation_json     TEXT,
    challenger_address   TEXT NOT NULL,
    challenger_stake_wei TEXT NOT NULL DEFAULT '0',
    contributor_stake_id TEXT,
    challenger_stake_id  TEXT,
    submission_attempts  INTEGER NOT NULL DEFAULT 0,
    staking_applied      INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    resolved_at          TEXT
);

CREATE INDEX IF NOT EXISTS idx_dr_status ON dispute_records(status);
CREATE INDEX IF NOT EXISTS idx_dr_window ON dispute_records(window_id);

-- ── Ranking updates ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ranking_updates (
    id           TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    updated_at   TEXT NOT NULL,
    ranking_json JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_ru_repo_issue ON ranking_updates(repo, issue_number);

-- ── Issue embeddings ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS issue_embeddings (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    title TEXT NOT NULL,
    embedding BYTEA NOT NULL,
    labels JSONB,
    status TEXT DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(repo, issue_number)
);

CREATE INDEX IF NOT EXISTS idx_ie_repo ON issue_embeddings(repo);
CREATE INDEX IF NOT EXISTS idx_ie_status ON issue_embeddings(status);

-- ── Backfill progress ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS backfill_progress (
    id         TEXT PRIMARY KEY,
    repo       TEXT NOT NULL,
    mode       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'running',
    last_page  INTEGER NOT NULL DEFAULT 0,
    processed  INTEGER NOT NULL DEFAULT 0,
    failed     INTEGER NOT NULL DEFAULT 0,
    skipped    INTEGER NOT NULL DEFAULT 0,
    error_msg  TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(repo, mode)
);

CREATE INDEX IF NOT EXISTS idx_bp_repo_mode ON backfill_progress(repo, mode);

-- ── Patrol history ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS patrol_history (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    dependency_findings_count INTEGER DEFAULT 0,
    code_findings_count INTEGER DEFAULT 0,
    patches_generated INTEGER DEFAULT 0,
    issues_created INTEGER DEFAULT 0,
    bounties_assigned_wei TEXT DEFAULT '0',
    attestation_id TEXT,
    duration_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_patrol_history_repo ON patrol_history(repo);
CREATE INDEX IF NOT EXISTS idx_patrol_history_timestamp ON patrol_history(timestamp);

-- ── Known vulnerabilities ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS known_vulnerabilities (
    id TEXT PRIMARY KEY,
    cve_id TEXT,
    dedup_key TEXT NOT NULL,
    package_name TEXT NOT NULL,
    language TEXT NOT NULL,
    severity TEXT NOT NULL,
    affected_range TEXT NOT NULL,
    fixed_version TEXT,
    advisory_url TEXT,
    repo TEXT NOT NULL,
    first_detected TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_checked TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'open',
    bounty_issue_number INTEGER,
    UNIQUE(repo, dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_known_vuln_package ON known_vulnerabilities(package_name, language);
CREATE INDEX IF NOT EXISTS idx_known_vuln_cve ON known_vulnerabilities(cve_id);

-- ── Patrol finding signatures ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS patrol_finding_signatures (
    id SERIAL PRIMARY KEY,
    repo TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    bounty_issue_number INTEGER,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repo, rule_id, file_path, line_start)
);

CREATE INDEX IF NOT EXISTS idx_pfs_repo ON patrol_finding_signatures(repo);

-- ── Patrol patches ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS patrol_patches (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    pr_number INTEGER,
    cve_id TEXT,
    package_name TEXT NOT NULL,
    old_version TEXT NOT NULL,
    new_version TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    merged_at TEXT,
    attestation_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_patrol_patches_repo ON patrol_patches(repo);
CREATE INDEX IF NOT EXISTS idx_patrol_patches_status ON patrol_patches(status);

-- ── Treasury transactions ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS treasury_transactions (
    id              TEXT PRIMARY KEY,
    tx_hash         TEXT,
    tx_type         TEXT NOT NULL,
    amount_wei      BIGINT NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'ETH',
    counterparty    TEXT NOT NULL DEFAULT '',
    pr_id           TEXT,
    audit_id        TEXT,
    bounty_id       TEXT,
    attestation_id  TEXT,
    timestamp       TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tt_timestamp ON treasury_transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_tt_tx_type ON treasury_transactions(tx_type);

-- ── Seen transaction hashes (replay protection) ─────────────────────────────

CREATE TABLE IF NOT EXISTS seen_tx_hashes (
    tx_hash     TEXT PRIMARY KEY,
    audit_id    TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
