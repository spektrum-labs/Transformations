"""Schema for is_backup_enabled_for_critical_systems transformation input."""

from pydantic import BaseModel


class IsBackupEnabledForCriticalSystemsInput(BaseModel):
    """
    Expected input schema for the is_backup_enabled_for_critical_systems transformation.
    """

    class Config:
        extra = "allow"
