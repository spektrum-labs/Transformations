"""Schema for is_backup_immutable transformation input."""

from pydantic import BaseModel


class IsBackupImmutableInput(BaseModel):
    """
    Expected input schema for the is_backup_immutable transformation.
    """

    class Config:
        extra = "allow"
