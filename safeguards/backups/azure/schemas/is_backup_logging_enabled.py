"""Schema for is_backup_logging_enabled transformation input."""

from pydantic import BaseModel


class IsBackupLoggingEnabledInput(BaseModel):
    """
    Expected input schema for the is_backup_logging_enabled transformation.
    """

    class Config:
        extra = "allow"
