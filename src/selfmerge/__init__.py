"""Self-merge protocol — sovereignty boundary for SaltaX self-modification."""

from src.selfmerge.detector import (
    SELF_MODIFICATION_PATHS,
    extract_modified_files,
    is_self_modification,
)
from src.selfmerge.health_check import HealthResult, run_health_check
from src.selfmerge.rollback import BACKUP_DIR, ConfigRollback, _self_merge_lock
from src.selfmerge.upgrade_logger import UpgradeEvent, log_upgrade_event

__all__ = [
    "BACKUP_DIR",
    "ConfigRollback",
    "HealthResult",
    "SELF_MODIFICATION_PATHS",
    "UpgradeEvent",
    "_self_merge_lock",
    "extract_modified_files",
    "is_self_modification",
    "log_upgrade_event",
    "run_health_check",
]
