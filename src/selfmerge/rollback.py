"""KMS-backed configuration rollback for self-merge safety.

Backup and restore are serialised by :data:`_self_merge_lock` — the caller
must acquire it before calling any :class:`ConfigRollback` method.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.intelligence.sealing import KMSSealManager

logger = logging.getLogger(__name__)

BACKUP_DIR = Path("/tmp/saltax_config_backups")

_self_merge_lock = asyncio.Lock()

# KMS key under which the backup index is stored.
_INDEX_KEY = "saltax:config_backup_index"


class ConfigRollback:
    """Create, list, and restore KMS-sealed configuration backups."""

    def __init__(
        self,
        kms: KMSSealManager,
        backup_dir: Path = BACKUP_DIR,
    ) -> None:
        self._kms = kms
        self._backup_dir = backup_dir
        self._closed = False

    async def initialize(self) -> None:
        """Prepare the backup directory.  Safe to call more than once."""
        self._backup_dir.mkdir(parents=True, exist_ok=True)

    # ── create ────────────────────────────────────────────────────────────

    async def create_backup(
        self,
        files_to_backup: list[str],
        backup_name: str,
    ) -> str:
        """Read *files_to_backup*, seal the bundle in KMS, return *backup_name*.

        Raises :class:`RuntimeError` if any source file is missing or KMS
        fails.  Temp files are cleaned up in all failure paths.
        """
        self._require_open()

        # Read all files — fail fast on missing
        file_contents: dict[str, str] = {}
        for fpath in files_to_backup:
            p = Path(fpath)
            if not p.is_file():
                raise RuntimeError(f"Cannot backup: file not found: {fpath}")
            file_contents[fpath] = p.read_text()

        bundle = json.dumps({
            "backup_name": backup_name,
            "timestamp": datetime.now(UTC).isoformat(),
            "files": file_contents,
        }).encode()

        kms_key = f"saltax:config_backup:{backup_name}"

        # Seal to KMS + write local .sealed indicator
        fd: int | None = None
        tmp_path: str | None = None
        try:
            await self._kms.seal(kms_key, bundle)

            fd, tmp_path = tempfile.mkstemp(
                dir=str(self._backup_dir),
                suffix=".tmp",
            )
            os.write(fd, b"sealed")
            os.close(fd)
            fd = None  # closed — don't close again in finally

            sealed_path = self._backup_dir / f"{backup_name}.sealed"
            os.replace(tmp_path, str(sealed_path))
            tmp_path = None  # replaced — don't unlink in finally

        except Exception:
            raise
        finally:
            if fd is not None:
                os.close(fd)
            if tmp_path is not None:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)

        # Update the index in KMS (best-effort — the backup itself is already
        # safely sealed and recoverable by key name even if indexing fails).
        try:
            await self._update_index(backup_name, list(file_contents.keys()))
        except Exception:
            logger.warning(
                "Backup sealed successfully but index update failed — "
                "backup is still recoverable by name",
                extra={"backup_name": backup_name},
                exc_info=True,
            )

        logger.info("Config backup created", extra={"backup_name": backup_name})
        return backup_name

    # ── restore ───────────────────────────────────────────────────────────

    async def restore_backup(self, backup_name: str) -> list[str]:
        """Unseal *backup_name* from KMS and atomically restore each file.

        Returns the list of restored file paths.

        Raises :class:`RuntimeError` if the backup does not exist in KMS or
        unseal fails.  On file-write failure mid-restore, temp files are
        cleaned but the caller should treat the system as degraded.
        """
        self._require_open()

        kms_key = f"saltax:config_backup:{backup_name}"
        try:
            plaintext = await self._kms.unseal(kms_key)
        except Exception as exc:
            logger.critical(
                "KMS unseal failed during restore",
                extra={"backup_name": backup_name},
            )
            raise RuntimeError(
                f"Cannot restore backup '{backup_name}': KMS unseal failed"
            ) from exc

        try:
            bundle = json.loads(plaintext)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(
                f"Corrupt backup bundle for '{backup_name}'"
            ) from exc

        files: dict[str, str] = bundle.get("files", {})
        if not files:
            raise RuntimeError(f"Backup '{backup_name}' contains no files")

        restored: list[str] = []
        for fpath, content in files.items():
            fd: int | None = None
            tmp_path: str | None = None
            try:
                target = Path(fpath)
                target.parent.mkdir(parents=True, exist_ok=True)

                fd, tmp_path = tempfile.mkstemp(
                    dir=str(target.parent),
                    suffix=".tmp",
                )
                os.write(fd, content.encode())
                os.close(fd)
                fd = None

                os.replace(tmp_path, fpath)
                tmp_path = None
                restored.append(fpath)
            finally:
                if fd is not None:
                    os.close(fd)
                if tmp_path is not None:
                    with contextlib.suppress(OSError):
                        os.unlink(tmp_path)

        logger.info(
            "Config backup restored",
            extra={"backup_name": backup_name, "restored_files": restored},
        )
        return restored

    # ── list ──────────────────────────────────────────────────────────────

    async def list_backups(self) -> list[dict[str, Any]]:
        """Return the backup index from KMS.  Empty list if no index exists.

        Logs a warning on KMS errors so operators can distinguish "no backups"
        from "KMS unreachable".
        """
        self._require_open()

        try:
            raw = await self._kms.unseal(_INDEX_KEY)
            index = json.loads(raw)
            return index.get("backups", [])
        except Exception:
            logger.warning(
                "Could not retrieve backup index from KMS "
                "(may be first run or KMS unreachable)",
                exc_info=True,
            )
            return []

    # ── close ─────────────────────────────────────────────────────────────

    async def close(self) -> None:
        """Mark this rollback instance as closed."""
        self._closed = True

    # ── internals ─────────────────────────────────────────────────────────

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("ConfigRollback is closed")

    async def _update_index(
        self,
        backup_name: str,
        files: list[str],
    ) -> None:
        """Append an entry to the sealed JSON index in KMS."""
        existing = await self.list_backups()
        existing.append({
            "backup_name": backup_name,
            "timestamp": datetime.now(UTC).isoformat(),
            "files": files,
        })
        payload = json.dumps({"backups": existing}).encode()
        await self._kms.seal(_INDEX_KEY, payload)
