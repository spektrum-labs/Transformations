"""Schema for is_backup_encrypted transformation input."""

from typing import Optional
from pydantic import Field

from .isbackupenabled import (
    IsBackupEnabledInput,
    DBBackups,
    DBManualSnapshots,
    VolumeSnapshots,
)


class IsBackupEncryptedInput(IsBackupEnabledInput):
    """
    Expected input schema for the is_backup_encrypted transformation.

    This schema shares the same structure as IsBackupEnabledInput since both
    transformations process the same AWS backup data (dbBackups, dbManualSnapshots,
    volumeSnapshots).

    The transformation checks the 'Encrypted' field on each backup/snapshot record.
    """

    dbBackups: Optional[DBBackups] = Field(
        default=None,
        description="RDS automated backups - checks Encrypted field"
    )
    dbManualSnapshots: Optional[DBManualSnapshots] = Field(
        default=None,
        description="RDS manual snapshots - checks Encrypted field"
    )
    volumeSnapshots: Optional[VolumeSnapshots] = Field(
        default=None,
        description="EBS volume snapshots - checks encrypted field"
    )
