"""Schema for is_backup_tested transformation input."""

from pydantic import BaseModel


class IsBackupTestedInput(BaseModel):
    """
    Expected input schema for the is_backup_tested transformation.
    """

    class Config:
        extra = "allow"
