"""Tests for handler helper logic: wallet lookups and bounty computation."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from src.intelligence.database import IntelligenceDB

_ = pytest  # ensure pytest is used (fixture injection)


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
async def intel_db(tmp_path, monkeypatch):
    """Provide a fresh IntelligenceDB with schema v3."""
    monkeypatch.setattr("src.intelligence.database.DB_PATH", tmp_path / "test.db")
    kms = AsyncMock()
    kms.unseal = AsyncMock(side_effect=Exception("no sealed data"))
    db = IntelligenceDB(kms=kms)
    await db.initialize()
    yield db
    await db.close()


async def _insert_contributor(
    intel_db: IntelligenceDB,
    github_login: str,
    wallet_address: str = "",
) -> None:
    """Insert a contributor profile directly."""
    db = intel_db._require_db()
    now = datetime.now(UTC).isoformat()
    cp_id = hashlib.sha256(github_login.encode()).hexdigest()[:16]
    async with intel_db._write_lock:
        await db.execute(
            "INSERT INTO contributor_profiles "
            "(id, github_login, wallet_address, total_submissions, "
            "approved_submissions, rejected_submissions, first_seen, last_active) "
            "VALUES (?, ?, ?, 1, 1, 0, ?, ?)",
            (cp_id, github_login, wallet_address, now, now),
        )
        await db.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# A. get_contributor_wallet
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetContributorWallet:
    """Test IntelligenceDB.get_contributor_wallet()."""

    async def test_wallet_exists(self, intel_db) -> None:
        """Returns wallet address when profile exists with a wallet."""
        await _insert_contributor(intel_db, "alice", "0xAliceWallet")
        wallet = await intel_db.get_contributor_wallet("alice")
        assert wallet == "0xAliceWallet"

    async def test_no_profile(self, intel_db) -> None:
        """Returns None when no contributor profile exists."""
        wallet = await intel_db.get_contributor_wallet("unknown")
        assert wallet is None

    async def test_empty_wallet(self, intel_db) -> None:
        """Returns None when wallet_address is empty string."""
        await _insert_contributor(intel_db, "bob", "")
        wallet = await intel_db.get_contributor_wallet("bob")
        assert wallet is None


# ═══════════════════════════════════════════════════════════════════════════════
# B. Bounty computation from PR labels
# ═══════════════════════════════════════════════════════════════════════════════


class TestBountyFromLabels:
    """Test bounty amount computation from PR label matching.

    The logic lives in handle_pr_event() — tested here as a unit by
    replicating the label-matching algorithm.
    """

    def _compute_bounty(
        self, labels: list[str], bounty_labels: dict[str, float],
    ) -> int | None:
        """Replicate the handler's label-to-bounty logic."""
        for label in labels:
            if label.startswith("bounty-"):
                eth_amount = bounty_labels.get(label)
                if eth_amount is not None:
                    return int(eth_amount * 10**18)
        return None

    def test_bounty_sm(self) -> None:
        """bounty-sm label → 0.05 ETH in wei."""
        labels = {"bounty-sm": 0.05, "bounty-md": 0.10}
        result = self._compute_bounty(["bounty-sm"], labels)
        assert result == 50000000000000000  # 0.05 * 10^18

    def test_no_bounty_label(self) -> None:
        """No bounty label → None."""
        labels = {"bounty-sm": 0.05}
        result = self._compute_bounty(["enhancement", "bug"], labels)
        assert result is None

    def test_unknown_bounty_label(self) -> None:
        """Unknown bounty-xxx label → None."""
        labels = {"bounty-sm": 0.05}
        result = self._compute_bounty(["bounty-unknown"], labels)
        assert result is None

    def test_first_matching_label_wins(self) -> None:
        """When multiple bounty labels exist, first match wins."""
        labels = {"bounty-sm": 0.05, "bounty-md": 0.10}
        result = self._compute_bounty(["bounty-md", "bounty-sm"], labels)
        assert result == 100000000000000000  # 0.10 * 10^18 (bounty-md first)
