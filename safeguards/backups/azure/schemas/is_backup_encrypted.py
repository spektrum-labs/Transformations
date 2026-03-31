"""Schema for is_backup_encrypted transformation input."""

from pydantic import BaseModel


class IsBackupEncryptedInput(BaseModel):
    """
    Expected input schema for the is_backup_encrypted transformation.
    """

    class Config:
        extra = "allow"
