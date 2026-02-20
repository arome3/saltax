"""CLI entry point for the backfill engine.

Usage::

    saltax-backfill --repo owner/repo --mode embedding_only
    saltax-backfill --repo owner/repo --mode full --concurrency 5
    saltax-backfill --repo owner/repo --mode issues_only --no-resume
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import click

from src.backfill.engine import BackfillEngine, BackfillMode
from src.config import EnvConfig, SaltaXConfig

logger = logging.getLogger(__name__)


def _setup_logging(level: str) -> None:
    """Configure structured JSON logging for CLI output."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


async def _run_backfill(
    repo: str,
    mode: BackfillMode,
    config_path: str,
    concurrency: int,
    no_resume: bool,
) -> dict[str, int]:
    """Bootstrap services and run the backfill engine."""
    # Load config
    config = SaltaXConfig.load(config_path)
    env = EnvConfig(_env_file=".env")  # type: ignore[call-arg]

    _setup_logging(env.log_level)

    # Import heavy dependencies only after config is loaded
    from src.github.client import GitHubClient  # noqa: PLC0415
    from src.intelligence.database import IntelligenceDB  # noqa: PLC0415
    from src.intelligence.sealing import KMSSealManager  # noqa: PLC0415

    # Bootstrap core services
    kms = KMSSealManager(env.eigencloud_kms_endpoint)
    intel_db = IntelligenceDB(kms)
    github_client = GitHubClient(
        app_id=env.github_app_id,
        private_key=env.github_app_private_key,
    )

    # Full mode needs the pipeline runner and attestation engine
    pipeline_runner = None
    attestation_engine = None
    if mode == BackfillMode.FULL:
        from src.attestation.engine import AttestationEngine  # noqa: PLC0415
        from src.pipeline.runner import run_pipeline  # noqa: PLC0415

        attestation_engine = AttestationEngine(config=config, env=env, intel_db=intel_db)
        pipeline_runner = run_pipeline

    try:
        await intel_db.initialize()

        # Clear prior progress if --no-resume
        if no_resume:
            logger.info("--no-resume: prior progress will be ignored")
            # Save a fresh "running" record at page 0 to reset
            if mode == BackfillMode.FULL:
                for sub_mode in ("full:pr", "full:issue"):
                    await intel_db.save_backfill_progress(
                        repo=repo, mode=sub_mode, status="completed",
                        last_page=0, processed=0, failed=0, skipped=0,
                    )
            else:
                await intel_db.save_backfill_progress(
                    repo=repo, mode=mode.value, status="completed",
                    last_page=0, processed=0, failed=0, skipped=0,
                )

        engine = BackfillEngine(
            config=config,
            env=env,
            intel_db=intel_db,
            github_client=github_client,
            repo=repo,
            mode=mode,
            pipeline_runner=pipeline_runner,
            attestation_engine=attestation_engine,
            concurrency=concurrency,
        )

        # Signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, engine.stop)

        results = await engine.run()
        return results

    finally:
        await intel_db.seal(kms)
        await github_client.close()


@click.command("backfill")
@click.option("--repo", required=True, help="Repository full name (owner/repo)")
@click.option(
    "--mode",
    type=click.Choice(["embedding_only", "full", "issues_only"], case_sensitive=False),
    default=None,
    help="Backfill mode (default: from config)",
)
@click.option("--concurrency", type=int, default=None, help="Max concurrent items per page")
@click.option("--no-resume", is_flag=True, default=False, help="Ignore prior progress, start fresh")
@click.option("--config", "config_path", default="saltax.config.yaml", help="Config file path")
def main(
    repo: str,
    mode: str | None,
    concurrency: int | None,
    no_resume: bool,
    config_path: str,
) -> None:
    """Run the SaltaX backfill engine for a repository."""
    # Resolve defaults from config if not provided
    config = SaltaXConfig.load(config_path)

    if mode is None:
        mode = config.backfill.default_mode
    backfill_mode = BackfillMode(mode)

    if concurrency is None:
        concurrency = config.backfill.concurrency

    click.echo(f"Starting backfill: repo={repo} mode={backfill_mode} concurrency={concurrency}")

    results = asyncio.run(
        _run_backfill(repo, backfill_mode, config_path, concurrency, no_resume),
    )

    click.echo(
        f"Backfill complete: "
        f"processed={results['processed']} "
        f"skipped={results['skipped']} "
        f"failed={results['failed']}"
    )
    sys.exit(1 if results["failed"] > 0 else 0)


if __name__ == "__main__":
    main()
