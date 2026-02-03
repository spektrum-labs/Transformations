"""Schema for is_backup_immutable transformation input."""

from typing import Optional
from pydantic import BaseModel, Field


class BackupVaultLockConfiguration(BaseModel):
    """Configuration for AWS Backup Vault Lock."""
    MinRetentionDays: Optional[int] = None
    MaxRetentionDays: Optional[int] = None
    ChangeableForDays: Optional[int] = None
    LockState: Optional[str] = Field(
        default=None,
        description="Lock state: 'LOCKED' or 'UNLOCKED'"
    )
    LockDate: Optional[int] = Field(
        default=None,
        description="Unix timestamp in milliseconds when the vault was locked"
    )

    class Config:
        extra = "allow"


class IsBackupImmutableInput(BaseModel):
    """
    Expected input schema for the is_backup_immutable transformation.

    This schema validates the GetBackupVaultLockConfiguration API response
    that checks if backup vault lock is active (immutable).
    """

    BackupVaultName: Optional[str] = Field(
        default=None,
        description="Name of the backup vault"
    )
    BackupVaultLockConfiguration: Optional[BackupVaultLockConfiguration] = Field(
        default=None,
        description="Lock configuration containing LockState"
    )

    class Config:
        extra = "allow"
