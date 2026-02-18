# SaltaX

**The Sovereign Code Organism**

A self-sustaining, ownerless AI agent that autonomously maintains open-source repositories, audits code for vulnerabilities, pays contributors, sells intelligence, and evolves its own codebase — all running inside a TEE with zero human control.

---

**Author:** Arome Onoja / NatQuest Limited
**License:** MIT
**Platform:** [EigenCloud](https://eigencloud.xyz) (EigenCompute + EigenAI)

---

## What Is SaltaX?

SaltaX is a **sovereign AI agent** — an ownerless, self-sustaining digital entity that autonomously maintains open-source software repositories. It is not a tool operated by a human. It is an independent organism that:

- **Owns a treasury** — an autonomous wallet controlled by no human
- **Earns revenue** — from sponsorships, paid audits (via x402), and stake penalties
- **Pays contributors** — instant, guaranteed bounty payments for verified work
- **Builds private intelligence** — a TEE-sealed vulnerability knowledge base that appreciates over time
- **Evolves itself** — merges PRs into its own configuration through the same review pipeline it applies to external code

SaltaX runs entirely inside an **Intel TDX Trusted Execution Environment** on EigenCompute, providing hardware-enforced guarantees that its code is tamper-proof, its private intelligence database is inaccessible to any human (including its deployer), and its decisions are cryptographically attested.

It is the first open-source maintainer that cannot be bribed, burned out, or compromised.

## Architecture

```
                    EXTERNAL WORLD
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │  GitHub   │    │ External │    │ Sponsors │
    │  Repos    │    │  Clients │    │ & Donors │
    └────┬──────┘    └────┬─────┘    └────┬─────┘
         │ Webhooks       │ x402          │ ETH/USDC
    ═════╪════════════════╪═══════════════╪══════════════
    ║    ▼                ▼               ▼             ║
    ║  ┌──────────────────────────────────────────┐     ║
    ║  │         INGRESS CONTROLLER               │     ║
    ║  │   (webhook validation, x402 gate,        │     ║
    ║  │    rate limiting, signature check)        │     ║
    ║  └───────────────┬──────────────────────────┘     ║
    ║                  │                                ║
    ║  ┌───────────────▼──────────────────────────┐     ║
    ║  │        ASYNC PIPELINE ENGINE             │     ║
    ║  │  ┌────────────┐  ┌───────────┐  ┌──────┐│     ║
    ║  │  │  Static    │─▶│    AI     │─▶│ Test ││     ║
    ║  │  │  Scanner   │  │ Analyzer  │  │ Exec ││     ║
    ║  │  │ (Semgrep)  │  │(EigenAI)  │  │      ││     ║
    ║  │  └────────────┘  └─────┬─────┘  └──────┘│     ║
    ║  │              ┌─────────▼────────┐        │     ║
    ║  │              │ Decision Engine  │        │     ║
    ║  │              └──────────────────┘        │     ║
    ║  └───────────────┬──────────────────────────┘     ║
    ║                  │                                ║
    ║  ┌───────────────▼──────────────────────────┐     ║
    ║  │       PRIVATE INTELLIGENCE DB            │     ║
    ║  │    (TEE-sealed, hardware-encrypted)       │     ║
    ║  │  Vuln Patterns │ PR Embeds │ Vision Docs  │     ║
    ║  └───────────────┬──────────────────────────┘     ║
    ║                  │                                ║
    ║  ┌───────────────▼──────────────────────────┐     ║
    ║  │         SOVEREIGNTY LAYER                │     ║
    ║  │  Treasury │ ERC-8004  │ Optimistic       │     ║
    ║  │  Manager  │ Identity  │ Verification     │     ║
    ║  └──────────────────────────────────────────┘     ║
    ║                                                   ║
    ║       TEE ENCLAVE (Intel TDX via EigenCompute)    ║
    ════════════════════════════════════════════════════
```

## Core Capabilities

| Capability | Description |
|---|---|
| **Autonomous PR Review** | Multi-stage pipeline: static scan + AI analysis + test execution + weighted verdict |
| **Deterministic AI Inference** | Seed-pinned EigenAI calls produce bit-exact reproducible outputs for independent verification |
| **Private Intelligence DB** | TEE-sealed SQLite storing vulnerability patterns, contributor profiles, and codebase knowledge |
| **Paid Audit Service** | x402-gated endpoint — external repos pay stablecoins for attested security analysis |
| **Optimistic Verification** | 24h challenge window with dual-path dispute resolution (EigenVerify + MoltCourt) |
| **Contributor Staking** | Optional stake with bonuses for verified work, slashing for overturned decisions |
| **Self-Merge Protocol** | SaltaX can merge PRs that modify its own config (elevated 0.90 threshold, 72h window) |
| **PR Deduplication** | Cosine-similarity detection of duplicate submissions across competing PRs |
| **Competitive Ranking** | Live ranking of competing PRs per issue, with labels and recommendation comments |
| **Vision Alignment** | Score PRs against a project's `VISION.md` for roadmap/architectural fit |
| **Advisory Mode** | Human-in-the-loop mode: recommends actions via comments/labels without auto-merging |
| **TEE Attestation** | Every action produces a cryptographic proof linking Docker image + TEE + inputs + outputs |

## How the Pipeline Works

When a pull request is submitted to a SaltaX-managed repository:

```
PR Submitted ──▶ Webhook Received ──▶ HMAC Verified ──▶ Pipeline Starts
                                                              │
          ┌───────────────────────────────────────────────────┘
          │
    ┌─────▼─────────┐    ┌──────────────┐    ┌──────────────┐
    │ Stage 1:      │    │ Stage 2:     │    │ Stage 3:     │
    │ Static Scan   │───▶│ AI Analysis  │───▶│ Test Runner  │
    │ (Semgrep)     │    │ (EigenAI)    │    │ (Sandboxed)  │
    │               │    │              │    │              │
    │ OWASP, supply │    │ Quality 1-10 │    │ Exit code,   │
    │ chain, secrets│    │ Risk 1-10    │    │ coverage,    │
    │               │    │ Arch fit     │    │ stdout/err   │
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
    └────────────────────────────────────────────────────┘
```

If approved, the PR enters a **24-hour optimistic verification window**. Anyone can challenge by staking tokens. Unchallenged PRs auto-merge and trigger bounty payout. Challenged PRs route to EigenVerify (computation disputes) or MoltCourt (subjective disputes).

## Tech Stack

| Layer | Technology |
|---|---|
| **Core Runtime** | Python 3.11+ (asyncio) |
| **HTTP Server** | FastAPI + Uvicorn |
| **GitHub Integration** | TypeScript proxy (Node 22, Octokit) + Python client (httpx, PyJWT) |
| **AI Inference** | EigenAI (OpenAI-compatible API, `gpt-oss-120b-f16`) |
| **Static Analysis** | Semgrep (security-audit, OWASP, supply-chain rulesets) |
| **Intelligence DB** | SQLite (TEE-sealed via EigenCloud KMS) |
| **Blockchain** | web3.py (Base for treasury, Ethereum Sepolia for identity) |
| **Identity** | ERC-8004 via Agent0 SDK (Node.js bridge) |
| **Payments** | x402 protocol (HTTP-native stablecoin micropayments) |
| **Containerization** | Docker (multi-stage: Node 22 + Python 3.11-slim) |
| **TEE** | Intel TDX on EigenCompute |
| **Testing** | pytest + pytest-asyncio + respx |
| **Linting** | Ruff (E, F, I, N, W, UP, B, SIM, TCH rules) |

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 22+ (for the TypeScript GitHub proxy)
- Docker (for production deployment)
- Git
- Semgrep CLI (optional for local static scanning — `pip install semgrep`)

### Installation

```bash
# Clone the repository
git clone https://github.com/AroOnoja/saltaX.git
cd saltaX

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install with all dependencies
pip install -e ".[prod,test,dev]"

# Install the TypeScript proxy dependencies
cd github-proxy && npm ci && cd ..
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
| `SALTAX_EIGENAI_API_KEY` | EigenAI API key for LLM inference |
| `SALTAX_GITHUB_APP_ID` | GitHub App ID (string) |
| `SALTAX_GITHUB_APP_PRIVATE_KEY` | PEM-encoded RSA private key for the GitHub App |
| `SALTAX_GITHUB_WEBHOOK_SECRET` | Webhook secret for HMAC signature verification |
| `SALTAX_EIGENCLOUD_KMS_ENDPOINT` | EigenCloud KMS endpoint for secret sealing |

Optional variables with defaults:

| Variable | Default | Description |
|---|---|---|
| `SALTAX_EIGENAI_API_URL` | `https://eigenai.eigencloud.xyz/v1` | EigenAI endpoint |
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

1. **Configuration** — load `saltax.config.yaml` + `.env`, cross-validate
2. **Cryptographic Identity** — KMS initialization, wallet generation, ERC-8004 identity registration
3. **State Recovery** — open and unseal the intelligence database
4. **Build Connections** — wire the analysis pipeline, GitHub client, verification scheduler
5. **Start Services** — launch FastAPI server, verification scheduler, TypeScript proxy

If any phase fails, resources are torn down in reverse order and the process exits.

## API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/webhook/github` | POST | GitHub HMAC signature | Receive PR and issue webhook events |
| `/api/v1/status` | GET | None | Agent health, wallet, reputation, intelligence stats |
| `/api/v1/audit` | POST | x402 payment | Submit a codebase for paid security audit |
| `/api/v1/attestation/{action_id}` | GET | None | Retrieve cryptographic attestation proof |
| `/api/v1/bounties` | GET | None | List active bounties across managed repos |
| `/api/v1/intelligence/stats` | GET | None | Anonymized pattern statistics (no raw data) |
| `/api/v1/vision` | POST | API key | Upload a vision document for alignment scoring |
| `/healthz` | GET | None | Liveness probe (checks intel_db, scheduler, wallet) |

### Paid Audit Pricing

| Scope | Price (USDC) | Pipeline Stages Used |
|---|---|---|
| `security-only` | 5 | Static Scanner + AI Analyzer (security) |
| `quality-only` | 3 | AI Analyzer (quality) + Test Executor |
| `full` | 10 | All four stages |

## Project Structure

```
saltaX/
├── src/
│   ├── main.py                       # 5-phase bootstrap, signal handling, graceful shutdown
│   ├── config.py                     # SaltaXConfig (YAML) + EnvConfig (pydantic-settings)
│   ├── security.py                   # URL validation, token scrubbing, prompt injection detection
│   ├── api/
│   │   ├── app.py                    # FastAPI factory, middleware, exception handlers
│   │   ├── handlers.py               # Background event handlers (PR pipeline, bounty detection)
│   │   ├── deps.py                   # FastAPI dependency injection helpers
│   │   ├── models.py                 # API request/response models
│   │   ├── middleware/
│   │   │   ├── github_signature.py   # HMAC-SHA256 webhook signature verification
│   │   │   ├── x402.py               # x402 payment verification middleware
│   │   │   ├── rate_limiter.py       # Per-endpoint rate limiting
│   │   │   └── dedup.py              # Webhook delivery deduplication
│   │   └── routes/
│   │       ├── webhook.py            # GitHub webhook ingress
│   │       ├── status.py             # Agent status endpoint
│   │       ├── audit.py              # Paid audit service
│   │       ├── attestation.py        # Attestation proof retrieval
│   │       ├── bounties.py           # Active bounty listing
│   │       ├── intelligence.py       # Anonymized intelligence stats
│   │       └── vision.py             # Vision document upload
│   ├── pipeline/
│   │   ├── runner.py                 # Pipeline orchestrator
│   │   ├── state.py                  # PipelineState dataclass
│   │   ├── prompts.py                # AI Analyzer prompt templates
│   │   └── stages/
│   │       ├── static_scanner.py     # Stage 1: Semgrep integration
│   │       └── ai_analyzer.py        # Stage 2: EigenAI with deterministic seed
│   ├── models/
│   │   ├── enums.py                  # Severity, Decision, AuditScope, StakeStatus, etc.
│   │   ├── pipeline.py               # Finding, AIAnalysisResult, TestResult, Verdict
│   │   ├── github.py                 # GitHub domain models
│   │   ├── treasury.py               # Treasury transaction models
│   │   ├── identity.py               # ERC-8004 identity models
│   │   ├── staking.py                # Contributor staking models
│   │   ├── audit.py                  # Audit request/response models
│   │   └── attestation.py            # Attestation proof models
│   ├── github/
│   │   ├── client.py                 # Async GitHub App client (JWT auth, circuit breaker)
│   │   ├── comments.py               # PR comment formatting
│   │   ├── checks.py                 # GitHub Check Runs API
│   │   ├── merge.py                  # Merge operations
│   │   └── exceptions.py             # GitHubError hierarchy
│   ├── intelligence/
│   │   ├── database.py               # IntelligenceDB (SQLite, KMS-sealed)
│   │   └── sealing.py                # KMSSealManager for TEE-sealed storage
│   ├── treasury/
│   │   └── wallet.py                 # WalletManager (web3.py, KMS-derived keys)
│   ├── identity/
│   │   └── registration.py           # ERC-8004 identity via Agent0 SDK bridge
│   ├── verification/
│   │   └── scheduler.py              # Optimistic verification window scheduler
│   ├── selfmerge/                    # Self-modification detection and elevated thresholds
│   ├── staking/                      # Contributor staking contract interaction
│   ├── attestation/                  # TEE attestation generation and verification
│   └── triage/                       # Dedup, ranking, vision alignment, advisory mode
├── tests/
│   ├── conftest.py                   # Shared fixtures (VALID_YAML, REQUIRED_ENV_VARS, etc.)
│   ├── unit/                         # Unit tests (config, client, scanner, analyzer, etc.)
│   └── integration/                  # End-to-end webhook flow tests
├── github-proxy/                     # TypeScript webhook proxy (Node 22, Octokit)
├── rules/                            # Custom Semgrep rulesets
├── saltax.config.yaml                # Pipeline, treasury, bounties, triage config
├── pyproject.toml                    # Build system, dependencies, tool config
├── Dockerfile                        # Multi-stage build (Node 22 + Python 3.11-slim)
├── docker-compose.yml                # Development compose file
└── .env.example                      # Environment variable template
```

## Economic Model

### Revenue Streams

| Source | Mechanism |
|---|---|
| **Sponsorships** | GitHub Sponsors, direct ETH/USDC transfers to the treasury wallet |
| **x402 Audit Fees** | External clients pay stablecoins for attested security analysis |
| **Stake Penalties** | Slashed stakes from contributors whose PRs are overturned on challenge |

### Treasury Allocation

| Category | % | Description |
|---|---|---|
| Bounty Payouts | 65% | Direct payment to verified contributors |
| Reserve Fund | 20% | Minimum balance for operational continuity |
| EigenCompute Fees | 10% | Infrastructure costs (TEE runtime, AI inference) |
| Community Grants | 5% | Future: documentation bounties, issue creation |

### Bounty Tiers

| Label | Payout (ETH) |
|---|---|
| `bounty-xs` | 0.01 |
| `bounty-sm` | 0.05 |
| `bounty-md` | 0.10 |
| `bounty-lg` | 0.25 |
| `bounty-xl` | 0.50 |

### Staking Economics

| Scenario | Contributor Outcome |
|---|---|
| PR approved, no challenge | Bounty + stake returned + 10% bonus |
| PR approved, challenged, upheld | Bounty + stake returned + 20% bonus |
| PR approved, challenged, overturned | Stake slashed 50%, no bounty |
| PR rejected by pipeline | Stake returned in full (no penalty) |

## Dispute Resolution

SaltaX uses **optimistic verification** — decisions are assumed valid unless challenged within a time window.

```
SaltaX approves PR
        │
        ▼
  OPTIMISTIC WINDOW
  (24h standard / 72h self-mod)
        │
   ┌────┴─────┐
   │          │
No challenge  Challenge filed (must stake >= bounty value)
   │          │
   ▼          ▼
AUTO-EXECUTE  CLASSIFY DISPUTE
(merge+pay)        │
              ┌────┴────────┐
              │             │
         Computation    Subjective
         dispute        dispute
              │             │
              ▼             ▼
        EIGENVERIFY     MOLTCOURT
       (re-execute +   (structured
        validator       debate +
        consensus)      AI jury)
```

**EigenVerify** handles objective, computation-based disputes. Because SaltaX uses seed-pinned deterministic inference, the AI analysis stage produces bit-exact identical output on re-execution.

**MoltCourt** handles subjective disputes (e.g., "the code quality score should have been higher") through structured multi-round debate with an AI jury.

## Security Model

### TEE Guarantees

- **Code integrity** — the attested Docker image is exactly what's running
- **Memory isolation** — no external process can read TEE memory
- **Sealed secrets** — wallet keys and intelligence DB are inaccessible to the host
- **Remote attestation** — any party can verify the above

### Defense-in-Depth

- **HMAC-SHA256** verification on all GitHub webhooks
- **SSRF prevention** — clone URLs restricted to `https://github.com` only
- **Prompt injection detection** — regex-based scanning with XML tag neutralization
- **Token scrubbing** — GitHub PATs and installation tokens redacted from all logs
- **Input validation** — branch names, commit SHAs, and diff sizes validated before processing
- **Rate limiting** — per-endpoint rate limits (60 rpm global, 10 rpm for audits)
- **Circuit breaker** — per-installation GitHub API circuit breaker with exponential backoff
- **Non-root container** — defense-in-depth alongside TEE isolation

### Attestation Chain

Every action produces a cryptographic proof:
```
[Docker Image Digest] → [TEE Platform Identity] → [Action] → [Inputs] → [Outputs]
```

## Sovereignty Lifecycle

| Property | Implementation |
|---|---|
| **Owns assets** | Autonomous wallet (ETH/USDC) + TEE-sealed intelligence DB |
| **Earns income** | Sponsorships + x402 audit fees + stake penalties |
| **Spends** | Bounty payouts + EigenCompute fees + community grants |
| **Upgrades itself** | Self-merge protocol: PRs targeting SaltaX's own config |
| **Enforces property rights** | TEE seals the intelligence DB; wallet key exists only in TEE memory |
| **Operates autonomously** | No human in the loop; disputes are the only external touchpoint |

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/
```

Tests use `asyncio_mode = "auto"` — no `@pytest.mark.asyncio` decorators needed. External services (GitHub API, EigenAI) are mocked via `respx` and `unittest.mock`.

## Roadmap

| Phase | Timeline | Focus |
|---|---|---|
| **Phase 2** | Month 2-3 | Multi-language support (Python, Rust, Solidity, Go) |
| **Phase 2.5** | Month 2-3 | EigenDA attestation storage (durable proof archival) |
| **Phase 3** | Month 3-6 | Multi-agent federation (TEE-to-TEE intelligence sharing) |
| **Phase 4** | Month 6+ | Yield generation (conservative DeFi on treasury reserves) |
| **Phase 5** | Month 6+ | Autonomous issue creation (self-commissioned improvements) |
| **Phase 6** | Month 9+ | EigenVerify/MoltCourt deep integration (expert witness role) |

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
