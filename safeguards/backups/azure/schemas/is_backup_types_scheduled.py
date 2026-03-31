"""Schema for is_backup_types_scheduled transformation input."""

from pydantic import BaseModel


class IsBackupTypesScheduledInput(BaseModel):
    """
    Expected input schema for the is_backup_types_scheduled transformation.
    """

    class Config:
        extra = "allow"
