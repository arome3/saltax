# SaltaX

**The Sovereign Code Organism**

A self-sustaining, ownerless AI agent that autonomously maintains open-source repositories, audits code for vulnerabilities, pays contributors, builds private intelligence, and evolves its own codebase — all running inside a TEE with zero human control.

---

## What Is SaltaX?

SaltaX is a **sovereign AI agent** — an ownerless, self-sustaining digital entity that autonomously maintains open-source software repositories. It is not a tool operated by a human. It is an independent organism that:

- **Owns a treasury** — an autonomous wallet controlled by no human
- **Earns revenue** — from sponsorships, paid audits (via x402), and stake penalties
- **Pays contributors** — instant, guaranteed bounty payments for verified work
- **Builds private intelligence** — a vulnerability knowledge base with feedback-driven confidence calibration that appreciates over time
- **Proactively patrols** — scans dependencies for CVEs, re-audits codebases, issues bounties for discovered vulnerabilities
- **Evolves itself** — merges PRs into its own source code through the same review pipeline it applies to external code

SaltaX runs entirely inside an **Intel TDX Trusted Execution Environment** on EigenCompute, providing hardware-enforced guarantees that its code is tamper-proof, its private intelligence database is inaccessible to any human (including its deployer), and its decisions are cryptographically attested.

It is the first open-source maintainer that cannot be bribed, burned out, or compromised.

## Architecture

```
                    EXTERNAL WORLD
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │  GitHub   │    │ External │    │ Sponsors │    │ Next.js  │
    │  Repos    │    │  Clients │    │ & Donors │    │Dashboard │
    └────┬──────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘
         │ Webhooks       │ x402          │ ETH/USDC      │ REST+WS
    ═════╪════════════════╪═══════════════╪═══════════════╪════════
    ║    ▼                ▼               ▼               ▼      ║
    ║  ┌──────────────────────────────────────────────────────┐  ║
    ║  │         INGRESS CONTROLLER                           │  ║
    ║  │   (HMAC verification, x402 gate, rate limiting,      │  ║
    ║  │    dedup, prompt injection detection)                 │  ║
    ║  └───────────────┬──────────────────────────────────────┘  ║
    ║                  │                                         ║
    ║  ┌───────────────▼──────────────────────────────────────┐  ║
    ║  │          TRIAGE LAYER                                │  ║
    ║  │  PR Dedup │ Issue Dedup │ Ranking │ Vision │ Advisory│  ║
    ║  └───────────────┬──────────────────────────────────────┘  ║
    ║                  │                                         ║
    ║  ┌───────────────▼──────────────────────────────────────┐  ║
    ║  │        ASYNC PIPELINE ENGINE                         │  ║
    ║  │  ┌────────────┐  ┌───────────┐  ┌──────┐            │  ║
    ║  │  │  Static    │─▶│    AI     │─▶│ Test │            │  ║
    ║  │  │  Scanner   │  │ Analyzer  │  │ Exec │            │  ║
    ║  │  │ (Semgrep)  │  │(EigenAI)  │  │      │            │  ║
    ║  │  └────────────┘  └─────┬─────┘  └──────┘            │  ║
    ║  │              ┌─────────▼────────┐                    │  ║
    ║  │              │ Decision Engine  │                    │  ║
    ║  │              └──────────────────┘                    │  ║
    ║  └───────────────┬──────────────────────────────────────┘  ║
    ║                  │                                         ║
    ║  ┌───────────────▼──────────────────────────────────────┐  ║
    ║  │       PRIVATE INTELLIGENCE DB                        │  ║
    ║  │    (Supabase PostgreSQL, schema v17, 23 tables)      │  ║
    ║  │  Vuln Patterns │ PR Embeds │ Issue Embeds │ Vision   │  ║
    ║  │  Contributors  │ Attestations │ Bounties │ Windows   │  ║
    ║  └───────────────┬──────────────────────────────────────┘  ║
    ║                  │                                         ║
    ║  ┌───────────────▼──────────────────────────────────────┐  ║
    ║  │         SOVEREIGNTY LAYER                            │  ║
    ║  │  Treasury │ ERC-8004  │ Optimistic    │ Attestation  │  ║
    ║  │  Manager  │ Identity  │ Verification  │ Chain        │  ║
    ║  └───────────────┬──────────────────────────────────────┘  ║
    ║                  │                                         ║
    ║  ┌───────────────▼──────────────────────────────────────┐  ║
    ║  │         ON-CHAIN CONTRACTS (Base)                    │  ║
    ║  │  SaltaXTreasury.sol │ SaltaXStaking.sol              │  ║
    ║  │  (ReentrancyGuard, Ownable2Step, Pausable)           │  ║
    ║  └──────────────────────────────────────────────────────┘  ║
    ║                                                            ║
    ║       TEE ENCLAVE (Intel TDX via EigenCompute)             ║
    ═════════════════════════════════════════════════════════════
```

## EigenCloud Primitives

SaltaX uses every major EigenCloud primitive — each is architecturally load-bearing:

| Primitive | How SaltaX Uses It |
|---|---|
| **EigenCompute** | TEE runtime (Intel TDX). KMS-sealed secrets (wallet, intelligence DB, webhook secret). Attestation metadata API at `169.254.169.254`. Single Docker container — one TEE boundary. |
| **EigenAI (Determinal)** | Deterministic inference with seed pinning (`int(commit_sha[:8], 16) % 2**32`). Grant-based wallet authentication — no API keys, the agent's wallet identity IS its credential. `system_fingerprint` capture for verification feasibility. |
| **ERC-8004 / Agent0** | On-chain identity registration via TypeScript bridge subprocess. Reputation anchoring. Upgrade history logging. Crash detection with automatic restart. |
| **x402** | HTTP-native USDC payment protocol for paid audit services. Facilitator integration with replay protection via durable `TxHashStore`. |
| **EigenVerify** | Computational dispute resolution. Replays deterministic AI inference with the same seed to verify challenged verdicts. Integrated via `EigenVerifyClient` in the dispute router. |

## How the Pipeline Works

When a pull request is submitted to a SaltaX-managed repository:

```
PR Submitted ──▶ Webhook Received ──▶ HMAC Verified ──▶ Triage ──▶ Pipeline
                                                           │
          ┌────────────────────────────────────────────────┘
          │  Dedup check, issue linking, vision alignment, custom rules loading
          │
    ┌─────▼─────────┐    ┌──────────────┐    ┌──────────────┐
    │ Stage 1:      │    │ Stage 2:     │    │ Stage 3:     │
    │ Static Scan   │───▶│ AI Analysis  │───▶│ Test Runner  │
    │ (Semgrep)     │    │ (EigenAI)    │    │ (Sandboxed)  │
    │               │    │              │    │              │
    │ OWASP, supply │    │ Quality 1-10 │    │ Exit code,   │
    │ chain, secrets│    │ Risk 1-10    │    │ coverage,    │
    │ Path-scoped   │    │ Seed-pinned  │    │ stdout/err   │
    │ custom rules  │    │ Custom rules │    │              │
    └───────────────┘    └──────────────┘    └──────────────┘
          │                    │                    │
          │    Short-circuit   │                    │
          │    on CRITICAL     │                    │
          │    findings        │                    │
          ▼                    ▼                    ▼
    ┌────────────────────────────────────────────────────┐
    │              Stage 4: Decision Engine              │
    │                                                    │
    │  Score = 0.25 * static_clear                       │
    │        + 0.25 * ai_quality                         │
    │        + 0.25 * ai_security                        │
    │        + 0.25 * tests_pass                         │
    │                                                    │
    │  >= 0.75 → APPROVE    (optimistic window opens)    │
    │  >= 0.50 → REQUEST_CHANGES                         │
    │  <  0.50 → REJECT                                  │
    │                                                    │
    │  Self-modification detected → threshold = 0.90     │
    └────────────────────────────────────────────────────┘
```

If approved, the PR enters a **24-hour optimistic verification window** (72 hours for self-modifications). Anyone can challenge by staking tokens. Unchallenged PRs auto-merge and trigger bounty payout. Challenged PRs route to EigenVerify (computation disputes) or MoltCourt (subjective disputes).

## Cryptographic Verifiability

Most AI systems are black boxes. SaltaX is a **glass box** — every decision it makes can be independently verified by anyone, after the fact, without trusting the agent.

This is possible because of two design choices that reinforce each other:

**Deterministic AI inference.** Every EigenAI call is seed-pinned: `int(commit_sha[:8], 16) % 2**32`. The same commit always produces the same seed, which produces the same AI output, which produces the same verdict. This isn't approximate — it's bit-exact. A challenger can re-execute the same inference with the same seed on EigenVerify and compare the output byte-for-byte.

**5-component attestation binding.** After every pipeline run, SaltaX signs an EIP-191 attestation proof that binds five components into a single cryptographic statement:

| Component | What it proves |
|---|---|
| `docker_image_digest` | This exact code was running (probed from `/proc/self/cgroup`) |
| `tee_platform_id` | It was running inside this specific TEE (from `169.254.169.254` metadata API) |
| `pipeline_input_hash` | It analyzed this exact diff (SHA-256 of repo + commit SHA + diff) |
| `pipeline_output_hash` | It produced this exact verdict (SHA-256 of findings + analysis + verdict) |
| `ai_seed` + `ai_system_fingerprint` | The AI inference used this seed and ran on this model checkpoint |

The attestation payload uses canonical JSON (sorted keys, no whitespace) with domain separation (`"v": "saltax-attestation-v1"`) and cross-chain replay prevention (`chain_prefix`). Each proof stores `previous_attestation_id`, forming a hash chain where every proof links to its predecessor.

**What this means in practice:** Any third party can take a SaltaX attestation, verify the EIP-191 signature against the agent's known wallet address, and confirm that this specific Docker image, on this specific TEE, analyzed this specific diff, with this specific AI seed, and produced this specific verdict. If they doubt the verdict, they can replay the AI call with the same seed and get the same output. The agent cannot lie about what it saw, what it ran, or what it concluded.

## Layered Safety Architecture

SaltaX doesn't rely on a single security mechanism. It uses **five layers**, where each layer is a safety net for the one above it. A failure at any layer is caught by the layer below.

```
Layer 1: PIPELINE INTEGRITY
│  HMAC-SHA256 webhook verification, SSRF prevention (clone URLs restricted
│  to https://github.com), prompt injection detection, token scrubbing,
│  input validation (branches, SHAs, diff sizes), rate limiting (60 rpm
│  global, 10 rpm audits), per-installation circuit breaker, webhook
│  deduplication, x402 replay protection via durable TxHashStore
│
▼
Layer 2: CRYPTOGRAPHIC ATTESTATION
│  Every verdict is signed and chained. Tampered outputs are detectable
│  by anyone who checks the proof. See "Cryptographic Verifiability" above.
│
▼
Layer 3: OPTIMISTIC VERIFICATION WINDOW
│  No approved PR is merged immediately. A 24-hour window (72h for
│  self-modifications) gives anyone the opportunity to challenge.
│  Challenge requires staking ≥ the bounty value — skin in the game.
│
▼
Layer 4: DISPUTE RESOLUTION
│  Challenges route to two paths based on dispute type:
│
│  ┌─────────────────────┐     ┌─────────────────────┐
│  │ EIGENVERIFY          │     │ MOLTCOURT            │
│  │ Computation disputes │     │ Subjective disputes  │
│  │ Re-execute with same │     │ Structured debate +  │
│  │ seed → bit-exact     │     │ AI jury              │
│  │ comparison           │     │                      │
│  └─────────────────────┘     └─────────────────────┘
│
▼
Layer 5: TEE GUARANTEES + ON-CHAIN ENFORCEMENT
   Code integrity — the attested Docker image is exactly what's running.
   Memory isolation — no external process can read TEE memory.
   Sealed secrets — wallet keys and intelligence DB inaccessible to host.
   Remote attestation — any party can verify the above.
   On-chain policy — Solidity contracts mirror Python policy engine
   (treasury + staking). The smart contract is the final guard even if
   the Python code is compromised.
```

On crash recovery, `recover_pending_windows()` reverts `executing` → `open` and `resolving` → `challenged`. No verification window is ever silently dropped.

## Self-Improving Intelligence

SaltaX is not a static program. It is a **closed-loop organism** that gets smarter with every cycle:

```
       ┌──── EARN ◀──── ATTRACT ◀──── SPEND ◀────┐
       │                                           │
       ▼                                           │
   Treasury grows ──▶ Post bounties ──▶ Contributors submit PRs
                                              │
                                              ▼
                                     Pipeline reviews PR
                                              │
                                              ▼
                                     LEARN: Extract vulnerability
                                     patterns, store embeddings,
                                     update contributor profiles,
                                     grow codebase knowledge graph
                                              │
                                              └──▶ Intelligence DB grows
                                                         │
                                                         ▼
                                                   Better reviews,
                                                   smarter patrol,
                                                   higher-value bounties
                                                         │
                                                         └──────────────┐
                                                                        ▼
                                                                   EARN ─┘
```

**The intelligence database** (23 tables, schema v17) runs on Supabase PostgreSQL with psycopg3 async connection pooling. It stores vulnerability patterns, PR embeddings, issue embeddings, contributor profiles, attestation history, bounty records, codebase knowledge graphs, and vision alignment data. Access is restricted to the TEE container via Supavisor session-mode pooling.

**Confidence calibration** turns human feedback into accuracy. GitHub emoji reactions on review comments (thumbs up = true positive, thumbs down = false positive) feed back into vulnerability pattern counters. Rules exceeding an 80% false-positive rate with sufficient signal are automatically suppressed. The system gets more accurate without retraining.

**Codebase graph indexing** maps multi-language dependency structures (Python, JS/TS, Go, Rust) into an import graph with PageRank centrality scoring. High-centrality files receive more scrutiny during review — a bug in `core/auth.py` that 40 modules import is riskier than a bug in `scripts/cleanup.py`.

**Patrol is the proactive arm.** SaltaX doesn't wait for PRs. On a configurable schedule, it scans managed repositories for dependency vulnerabilities (via OSV.dev), re-audits codebases with Semgrep, and automatically issues severity-calibrated bounties for discovered vulnerabilities. Every patrol cycle adds to the intelligence database, making the next cycle more informed.

**Self-evolution** closes the loop. SaltaX can merge PRs that modify its own source code — through the same pipeline, with an elevated 0.90 approval threshold, a 72-hour verification window, `py_compile` health checks on 5 critical modules, and KMS-backed rollback if the health check fails. The organism upgrades itself.

## Custom Review Rules

Repository owners can define project-specific rules in `.saltax/rules.md`:

```markdown
## Scan Configuration
**Scan_include:** src/**/*.py, lib/**/*.py
**Scan_exclude:** vendor/**, generated/**

## No raw SQL in API routes
**Severity:** HIGH
**Scope:** src/api/**/*.py, !src/api/tests/**
**Description:** Use parameterized queries only. No f-strings in SQL.

## Require error handling in handlers
**Severity:** MEDIUM
**Scope:** src/handlers/**/*.py
**Description:** All handler functions must wrap async calls in try/except.
```

Rules support include/exclude glob patterns (`!` prefix for excludes, `**` for recursive matching). The scoping engine uses `PurePosixPath.full_match()` which correctly treats `*` as single-component (unlike `fnmatch` which crosses `/` boundaries).

In the AI prompt, each rule shows exactly which changed files it applies to — not raw globs, but the resolved file list. `Scan_include`/`Scan_exclude` pass through to Semgrep's `--include`/`--exclude` CLI flags. Post-scan, findings are filtered to only files modified in the PR.

## Economic Design

SaltaX's economic model is designed around three principles: **asymmetric staking** (challengers risk real capital, preventing frivolous disputes), **severity-calibrated patrol bounties** (critical vulnerabilities pay more, attracting effort where it matters most), and **dual Python + Solidity enforcement** (fiscal policy is enforced in both the agent's runtime and on-chain contracts — even if the Python code is compromised, the Solidity contracts hold the line).

### Revenue Streams

| Source | Mechanism |
|---|---|
| **Sponsorships** | GitHub Sponsors, direct ETH/USDC transfers to the treasury wallet |
| **x402 Audit Fees** | External clients pay USDC for attested security analysis |
| **Stake Penalties** | Slashed stakes from contributors whose PRs are overturned on challenge |

### Treasury Allocation

| Category | % | Description |
|---|---|---|
| Bounty Payouts | 65% | Direct payment to verified contributors |
| Reserve Fund | 20% | Minimum balance for operational continuity |
| EigenCompute Fees | 10% | Infrastructure costs (TEE runtime, AI inference) |
| Community Grants | 5% | Documentation bounties, ecosystem development |

Enforced in **both** Python (`TreasuryPolicy`) and Solidity (`SaltaXTreasury.sol`) — the smart contract is the final guard even if the Python code is compromised.

### Bounty Tiers

| Label | Payout (ETH) |
|---|---|
| `bounty-xs` | 0.01 |
| `bounty-sm` | 0.05 |
| `bounty-md` | 0.10 |
| `bounty-lg` | 0.25 |
| `bounty-xl` | 0.50 |

Patrol-discovered vulnerabilities are automatically mapped to bounty tiers by severity: CRITICAL → `bounty-xl`, HIGH → `bounty-lg`, MEDIUM → `bounty-md`, LOW → `bounty-sm`. This creates a market signal — the agent spends more to fix what matters more.

### Staking Economics

Integer-only basis-point arithmetic (no floating point):

| Scenario | Contributor Outcome |
|---|---|
| PR approved, no challenge | Bounty + stake returned + 10% bonus |
| PR approved, challenged, upheld | Bounty + stake returned + 20% bonus |
| PR approved, challenged, overturned | Stake slashed 50%, no bounty |
| PR rejected by pipeline | Stake returned in full (no penalty) |

The 20% upheld bonus (vs. 10% unchallenged) deliberately rewards contributors who survive scrutiny. The 50% slash on overturned decisions makes low-quality submissions expensive. The asymmetry is intentional — it selects for confidence and quality.

## Smart Contracts

Solidity contracts deployed to **Base** enforce fiscal policy on-chain, mirroring the Python policy engine for defense in depth:

**`SaltaXTreasury.sol`** — On-chain treasury with three policy checks on every payout:
1. `amount <= maxSinglePayoutWei`
2. `(balance - amount) >= (balance * reserveRatioBps / 10000)`
3. `amount <= (balance * bountyBudgetBps / 10000)`

**`SaltaXStaking.sol`** — Full staking lifecycle: `depositStake`, `releaseStake`, `slashStake`, `refundStake`. `ReentrancyGuard` on all value transfers. `Ownable2Step` for safe ownership. `Pausable` for emergency circuit breaker.

Built with Foundry. Tests in `contracts/test/`.

## Mission Control Dashboard

SaltaX includes a full **Next.js dashboard** (8,500 lines of TypeScript) providing real-time mission control:

| Route | Page | What It Shows |
|-------|------|---------------|
| `/` | Overview | Agent status hero, metric cards, 7-day sparkline, live activity feed |
| `/pipeline` | Pipeline Feed | Searchable/filterable table of all PR reviews with verdict badges |
| `/pipeline/[id]` | Pipeline Detail | Score breakdown bars, threshold line, attestation proof card |
| `/treasury` | Treasury | Balance hero, budget allocation donut, paginated transaction history |
| `/verification` | Verification Windows | Active windows with countdown timers, recently resolved table |
| `/verification/disputes` | Disputes | Active and resolved challenge disputes |
| `/patrol` | Patrol | Vulnerability feed with severity badges, patch PR tracker |
| `/intelligence` | Intelligence Stats | Pattern growth charts, category/severity distributions |
| `/intelligence/knowledge` | Codebase Knowledge | Per-repo file explorer with risk heatmap |
| `/attestation` | Attestation Explorer | Search/filter proofs, signature chain timeline, full proof detail |
| `/staking` | Staking & Contributors | Staking calculator with 4 outcome scenarios, contributor leaderboard |
| `/audit` | Paid Audit | Repository URL + scope selector form, payment summary |
| `/logs` | System Logs | Real-time WebSocket log stream with level filters, auto-scroll |
| `/settings` | Settings | Agent identity card, trust score, vision documents, config status |

Built with shadcn/ui, Tailwind CSS, and wagmi for wallet integration. Dark theme optimized for screen recording. `Cmd+K` command palette for navigation. Connects to the Python backend via REST API and WebSocket (live log streaming).

## Core Capabilities

| Capability | Description |
|---|---|
| **Autonomous PR Review** | Multi-stage pipeline: static scan + AI analysis + test execution + weighted verdict |
| **Deterministic AI Inference** | Seed-pinned EigenAI calls produce bit-exact reproducible outputs for independent verification |
| **Grant-Based Wallet Auth** | No API keys — EigenAI authentication via wallet signature on a challenge message (EIP-191) |
| **Private Intelligence DB** | Supabase PostgreSQL (23 tables, schema v17) with psycopg3 async pooling, storing vulnerability patterns, contributor profiles, embeddings, treasury transactions, and codebase knowledge |
| **Chained Attestation Proofs** | Domain-separated canonical JSON signed via EIP-191. Each proof links to its predecessor via `previous_attestation_id`. Captures Docker digest, TEE platform ID, I/O hashes, AI seed, system fingerprint. |
| **Paid Audit Service** | x402-gated endpoint — external repos pay USDC for attested security analysis |
| **Optimistic Verification** | 24h challenge window with dual-path dispute resolution (EigenVerify + MoltCourt) |
| **Contributor Staking** | Optional stake with bonuses for verified work, slashing for overturned decisions |
| **Self-Merge Protocol** | SaltaX can merge PRs that modify its own source code (elevated 0.90 threshold, 72h window, KMS-backed rollback, `py_compile` health check on 5 critical modules) |
| **PR Deduplication** | Cosine-similarity detection of duplicate submissions across competing PRs (threshold 0.85) |
| **Issue Deduplication** | Template-aware preprocessing strips boilerplate, embeds issues, flags near-duplicates at 0.90 threshold |
| **Competitive Ranking** | Live ranking of competing PRs per issue, with labels and recommendation comments |
| **Vision Alignment** | Score PRs against a project's `vision.yaml` for roadmap/architectural fit (up to 30% weight) |
| **Autonomous Patrol** | Scheduled dependency vulnerability scanning (OSV.dev), codebase re-audits (Semgrep), bounty issuance for discovered vulnerabilities |
| **Custom Review Rules** | Repository owners define rules in `.saltax/rules.md` with severity, scope patterns, and descriptions — injected into AI analysis with per-file applicability |
| **Path-Scoped Rules** | Include/exclude glob patterns (`!tests/**`) with `PurePosixPath.full_match()`, Semgrep `--include`/`--exclude` flags, and post-scan filtering to changed files only |
| **PR Summary Comments** | Visual verdict summaries with mermaid score waterfall charts, module dependency diagrams, file risk heatmaps, and attestation links — posted as a single comment that updates in-place on re-runs |
| **Confidence Calibration** | Feedback-driven confidence scoring — GitHub emoji reactions (thumbs up/down) feed back into pattern accuracy, auto-suppressing rules that exceed 80% false-positive rate. Anti-gaming: 24h reaction window, 5-reaction/user/PR cap, `UNIQUE(pr_id, rule_id, github_user)` dedup |
| **Codebase Graph Indexing** | Multi-language dependency graph (Python, JS/TS, Go, Rust) with PageRank centrality scoring, stored in the intelligence DB for context-aware risk analysis |
| **Backfill Engine** | Resumable batch processing of existing PRs/issues with rate-limit-aware pagination — bootstrap intelligence from historical data without re-triggering webhooks |
| **Vector Similarity Index** | In-process HNSW index for sub-linear cosine similarity search across PR and issue embeddings, with auto-enable heuristic (activates when embedding count exceeds linear-scan threshold) |
| **Advisory Mode** | Human-in-the-loop mode: recommends actions via comments/labels without auto-merging |
| **On-Chain Treasury** | Solidity contracts enforce fiscal policy (reserve ratio, bounty cap, max payout) mirroring Python policy engine — defense in depth |

## Tech Stack

| Layer | Technology |
|---|---|
| **Core Runtime** | Python 3.11+ (asyncio, tested up to 3.14) |
| **HTTP Server** | FastAPI + Uvicorn |
| **GitHub Integration** | TypeScript proxy (Node 22, Octokit) + Python client (httpx, PyJWT) |
| **AI Inference** | EigenAI (OpenAI-compatible API, deterministic seed pinning, grant-based wallet auth) |
| **Static Analysis** | Semgrep (security-audit, OWASP, supply-chain rulesets) |
| **Intelligence DB** | Supabase PostgreSQL (psycopg3, AsyncConnectionPool, Supavisor session mode) |
| **Blockchain** | web3.py (Base for treasury/staking, Ethereum Sepolia for identity) |
| **Smart Contracts** | Solidity (Foundry), deployed to Base |
| **Identity** | ERC-8004 via Agent0 SDK (Node.js bridge) |
| **Payments** | x402 protocol (HTTP-native stablecoin micropayments) |
| **Dashboard** | Next.js 16, TypeScript, shadcn/ui, Tailwind CSS, wagmi |
| **WebSocket** | Live log streaming from backend to dashboard |
| **Containerization** | Docker (multi-stage: Node 22 + Python 3.11-slim production image) |
| **TEE** | Intel TDX on EigenCompute |
| **Testing** | pytest + pytest-asyncio + respx (Python), Vitest + Playwright (frontend) |
| **Linting** | Ruff (E, F, I, N, W, UP, B, SIM, TCH rules) |

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 22+ (for the TypeScript GitHub proxy and dashboard)
- Docker (for production deployment)
- Git
- Semgrep CLI (optional for local static scanning — `pip install semgrep`)

### Installation

```bash
# Clone the repository
git clone https://github.com/arome3/saltax.git
cd saltax

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install with all dependencies
pip install -e ".[prod,test,dev]"

# Install the TypeScript proxy dependencies
cd github-proxy && npm ci && cd ..

# Install the dashboard dependencies
cd frontend && npm install && cd ..
```

### Configuration

SaltaX uses a **three-tier configuration system**:

| Tier | Source | Mutability |
|---|---|---|
| **Tier 1** | Docker image parameters | Immutable |
| **Tier 2** | `saltax.config.yaml` | Self-modifiable (via PR pipeline) |
| **Tier 3** | `.env` environment variables | Runtime secrets |

**1. Set up environment variables:**

```bash
cp .env.example .env
# Edit .env with your actual values
```

Required environment variables (prefix `SALTAX_`):

| Variable | Description |
|---|---|
| `SALTAX_GITHUB_APP_ID` | GitHub App ID (string) |
| `SALTAX_GITHUB_APP_PRIVATE_KEY` | PEM-encoded RSA private key for the GitHub App (raw PEM or base64-encoded) |
| `SALTAX_GITHUB_WEBHOOK_SECRET` | Webhook secret for HMAC signature verification |
| `SALTAX_EIGENCLOUD_KMS_ENDPOINT` | EigenCloud KMS endpoint for secret sealing |
| `SALTAX_EIGENAI_WALLET_PRIVATE_KEY` | Wallet private key for Determinal grant auth (KMS-sealed in production) |
| `SALTAX_EIGENAI_WALLET_ADDRESS` | Wallet address for grant auth |

Optional variables with defaults:

| Variable | Default | Description |
|---|---|---|
| `SALTAX_EIGENAI_GRANT_API_URL` | `https://determinal-api.eigenarcade.com` | Determinal grant API endpoint |
| `SALTAX_EIGENAI_API_URL` | `https://eigenai.eigencloud.xyz/v1` | EigenAI endpoint (embeddings) |
| `SALTAX_RPC_URL` | `https://mainnet.base.org` | Base chain RPC |
| `SALTAX_CHAIN_ID` | `8453` | Base chain ID |
| `SALTAX_IDENTITY_RPC_URL` | `https://ethereum-sepolia-rpc.publicnode.com` | Ethereum RPC for ERC-8004 |
| `SALTAX_IDENTITY_CHAIN_ID` | `11155111` | Sepolia chain ID |
| `SALTAX_LOG_LEVEL` | `INFO` | Logging level |
| `SALTAX_HOST` | `0.0.0.0` | Server bind address |
| `SALTAX_PORT` | `8080` | Server port |

**2. Review `saltax.config.yaml`** for pipeline thresholds, bounty tiers, treasury allocations, triage settings, and staking economics.

### Running

**Local development:**
```bash
# Via the console script
saltax

# Or directly
python -m src.main
```

**Dashboard:**
```bash
cd frontend && npm run dev
# Opens at http://localhost:3000
```

**Docker:**
```bash
# Build
docker build -t saltax .

# Run
docker run -p 8080:8080 --env-file .env saltax
```

**Docker Compose (development):**
```bash
docker-compose up
```

### Bootstrap Sequence

SaltaX initializes through a 5-phase ordered sequence:

1. **Configuration** — load `saltax.config.yaml` + `.env`, cross-validate 11 constraint rules
2. **Cryptographic Identity** — KMS initialization, wallet generation (3-path priority: mnemonic → KMS unseal → fresh keypair), ERC-8004 identity registration
3. **State Recovery** — connect to the intelligence database (Supabase PostgreSQL, schema v17, 23 tables)
4. **Build Connections** — wire the analysis pipeline, GitHub client, verification scheduler, patrol scheduler, dispute router, treasury manager
5. **Start Services** — launch FastAPI server, verification scheduler, TypeScript proxy (with crash detection), patrol scheduler

If any phase fails, resources are torn down in reverse order and the process exits. A 30-second global timeout guards against any step hanging.

## API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/webhook/github` | POST | GitHub HMAC signature | Receive PR and issue webhook events |
| `/api/v1/health` | GET | None | Per-component health check (database, GitHub, wallet latency) |
| `/api/v1/status` | GET | None | Agent health, wallet, reputation, intelligence stats |
| `/api/v1/pipeline` | GET | None | Pipeline history — all PR reviews with scores and verdicts |
| `/api/v1/pipeline/{id}` | GET | None | Individual pipeline run detail with score breakdown |
| `/api/v1/audit` | POST | x402 payment | Submit a codebase for paid security audit |
| `/api/v1/attestation/{action_id}` | GET | None | Retrieve cryptographic attestation proof |
| `/api/v1/bounties` | GET | None | List active bounties across managed repos |
| `/api/v1/treasury` | GET | None | Treasury balance, allocations, transaction history |
| `/api/v1/contributors` | GET | None | Contributor profiles, reputation scores, submission history |
| `/api/v1/intelligence/stats` | GET | None | Anonymized pattern statistics (no raw data) |
| `/api/v1/patrol` | GET | None | Patrol scan results, vulnerability feed |
| `/api/v1/codebase` | GET | None | Codebase knowledge graph and file-level risk data |
| `/api/v1/identity` | GET | None | Agent on-chain identity and ERC-8004 status |
| `/api/v1/challenge` | POST | Staking | File a dispute challenge against a verification window |
| `/api/v1/dispute/{id}` | GET | None | Dispute resolution status and history |
| `/api/v1/vision` | POST | API key | Upload a vision document for alignment scoring |
| `/ws/logs` | WebSocket | None | Real-time structured log streaming |

### Paid Audit Pricing

| Scope | Price (USDC) | Pipeline Stages Used |
|---|---|---|
| `security-only` | 5 | Static Scanner + AI Analyzer (security) |
| `quality-only` | 3 | AI Analyzer (quality) + Test Executor |
| `full` | 10 | All four stages |

## Project Structure

```
saltaX/
├── src/                                 # Python backend (25,000 lines)
│   ├── main.py                          # 5-phase bootstrap, signal handling, graceful shutdown
│   ├── config.py                        # SaltaXConfig (YAML) + EnvConfig (pydantic-settings)
│   ├── security/                        # URL validation, token scrubbing, prompt injection detection
│   ├── api/
│   │   ├── app.py                       # FastAPI factory, middleware, exception handlers
│   │   ├── handlers.py                  # Background event handlers (PR pipeline, bounty detection)
│   │   ├── deps.py                      # FastAPI dependency injection helpers
│   │   ├── models.py                    # API request/response models
│   │   ├── middleware/                   # HMAC, x402, rate limiter, dedup, tx_store
│   │   └── routes/                      # 18 route modules (webhook, pipeline, treasury, patrol, etc.)
│   ├── pipeline/
│   │   ├── runner.py                    # Pipeline orchestrator
│   │   ├── state.py                     # PipelineState dataclass
│   │   ├── prompts.py                   # AI Analyzer prompt templates
│   │   └── stages/                      # static_scanner, ai_analyzer, test_executor, decision_engine
│   ├── models/                          # Domain models (enums, pipeline, github, treasury, staking, etc.)
│   ├── github/                          # Async GitHub App client (JWT auth, circuit breaker)
│   ├── intelligence/                    # IntelligenceDB, KMS sealing, pattern extraction, vector index
│   ├── treasury/                        # WalletManager, TreasuryPolicy, TreasuryManager
│   ├── identity/                        # ERC-8004 registration, reputation, bridge client
│   ├── verification/                    # Optimistic verification scheduler, window state machine
│   ├── selfmerge/                       # Self-modification detection, health check, KMS rollback
│   ├── attestation/                     # TEE attestation engine, store, verifier
│   ├── rules/                           # Custom review rules: loader, models, scoping engine, prompt formatter
│   ├── feedback/                        # Confidence calibration from GitHub emoji reactions
│   ├── indexing/                        # Multi-language dependency graph indexing with PageRank
│   ├── triage/                          # PR dedup, issue dedup, ranking, vision alignment, advisory
│   ├── patrol/                          # Dependency audit, codebase scan, bounty issuer, OSV client
│   ├── staking/                         # Contract interaction, economics, resolver
│   ├── disputes/                        # EigenVerify client, MoltCourt client, dispute router
│   ├── observability/                   # Structured logging, health checks, metrics
│   ├── backfill/                        # Historical data backfill engine
│   └── cli/                             # CLI tools (backfill)
├── frontend/                            # Next.js 16 dashboard (8,500 lines TypeScript)
│   ├── src/app/                         # 14 pages (App Router)
│   ├── src/components/
│   │   ├── ui/                          # 21 shadcn/ui base components
│   │   ├── layout/                      # Sidebar, topbar, command palette
│   │   └── saltax/                      # 14 domain components (pipeline stepper, attestation card, etc.)
│   ├── src/lib/                         # API client, WebSocket, wagmi config
│   ├── __tests__/                       # 28 component + view tests (Vitest)
│   └── e2e/                             # End-to-end tests (Playwright)
├── contracts/                           # Solidity smart contracts (Foundry)
│   ├── contracts/
│   │   ├── SaltaXTreasury.sol           # On-chain treasury with fiscal policy enforcement
│   │   ├── SaltaXStaking.sol            # Staking lifecycle (deposit, release, slash, refund)
│   │   └── interfaces/                  # ISaltaXIdentity
│   ├── script/Deploy.s.sol             # Forge deployment script
│   ├── test/                            # Staking.t.sol, Treasury.t.sol
│   └── foundry.toml                     # Foundry configuration
├── github-proxy/                        # TypeScript webhook proxy (Node 22, Octokit)
├── tests/                               # Python test suite
│   ├── conftest.py                      # Shared fixtures (VALID_YAML, REQUIRED_ENV_VARS, etc.)
│   ├── unit/                            # 44 unit test files
│   ├── integration/                     # End-to-end webhook flow, pipeline, attestation chain tests
│   ├── e2e/                             # Full pipeline end-to-end tests
│   └── fixtures/                        # Mock responses, sample diffs
├── scripts/
│   ├── deploy.sh                        # EigenCompute deployment
│   └── kms-init.sh                      # KMS secret sealing
├── saltax.config.yaml                   # Pipeline, treasury, bounties, triage, staking config
├── pyproject.toml                       # Build system, dependencies, tool config
├── Dockerfile                           # Multi-stage build (Node 22 + Python 3.11-slim)
├── docker-compose.yml                   # Development compose file
└── .env.example                         # Environment variable template
```

## Concurrency Model

SaltaX handles concurrent webhooks, scheduled verification, dispute polling, and patrol scans:

| Lock / Mechanism | Purpose |
|---|---|
| `WalletManager._tx_lock` | Serializes all on-chain transactions to prevent nonce interleaving |
| `AsyncConnectionPool` (psycopg3) | Connection pooling (min=2, max=10) with PostgreSQL MVCC — no application-level write lock needed |
| `_analysis_semaphore` | Limits concurrent AI analyses to 5 (prevents OOM) |
| Verification scheduler | Event-driven loop with `asyncio.Event` for clean shutdown |
| TS proxy monitor | `asyncio.Task` with 5-second polling, restart-on-crash (up to 3 retries) |

Every service has an `async close()` method. Teardown happens in reverse initialization order. `CancelledError` is `BaseException` — caught explicitly where needed, never swallowed by `except Exception`.

## Testing

```bash
# Run all tests
uv run python -m pytest

# Run with coverage
uv run python -m pytest --cov=src --cov-report=term-missing

# Run only unit tests
uv run python -m pytest tests/unit/

# Run only integration tests
uv run python -m pytest tests/integration/

# Run frontend tests
cd frontend && npm test

# Run contract tests
cd contracts && forge test
```

Tests use `asyncio_mode = "auto"` — no `@pytest.mark.asyncio` decorators needed. External services (GitHub API, EigenAI) are mocked via `respx` and `unittest.mock`.

## Roadmap

| Phase | Focus | Status |
|---|---|---|
| **Core** | 4-stage pipeline, attestation, treasury, self-merge, staking, patrol, triage, dashboard | Shipped |
| **Phase 2** | Multi-language support (Rust, Solidity, Go) | Planned |
| **Phase 2.5** | EigenDA attestation storage (durable proof archival) | Planned |
| **Phase 3** | Multi-agent federation (TEE-to-TEE intelligence sharing) | Planned |
| **Phase 4** | Yield generation (conservative DeFi on treasury reserves) | Planned |
| **Phase 5** | EigenVerify/MoltCourt deep integration (expert witness role) | Planned |

## Contributing

SaltaX reviews its own PRs. To contribute:

1. Check the open issues for bounty labels (`bounty-xs` through `bounty-xl`)
2. Submit a PR against a bountied issue
3. SaltaX runs the full pipeline and posts an attested verdict
4. If approved, your PR enters the optimistic verification window
5. After the window closes without challenge, your bounty is paid automatically

Optionally stake tokens alongside your PR for bonus payouts (10-20% on top of the bounty).

---

*SaltaX is not a tool. It is an institution. It runs on math, not trust.*
