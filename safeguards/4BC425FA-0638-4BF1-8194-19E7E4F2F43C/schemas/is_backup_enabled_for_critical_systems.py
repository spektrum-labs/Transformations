"""Schema for is_backup_enabled_for_critical_systems transformation input."""

from typing import Optional
from pydantic import Field

from .isbackupenabled import (
    IsBackupEnabledInput,
    DBBackups,
    DBManualSnapshots,
)


class IsBackupEnabledForCriticalSystemsInput(IsBackupEnabledInput):
    """
    Expected input schema for the is_backup_enabled_for_critical_systems transformation.

    This schema shares a similar structure to IsBackupEnabledInput but only uses
    dbBackups and dbManualSnapshots (not volumeSnapshots).
    """

    dbBackups: Optional[DBBackups] = Field(
        default=None,
        description="RDS automated backups from DescribeDBInstanceAutomatedBackups"
    )
    dbManualSnapshots: Optional[DBManualSnapshots] = Field(
        default=None,
        description="RDS manual snapshots from DescribeDBSnapshots"
    )
