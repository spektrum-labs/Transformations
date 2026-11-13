from pydantic import BaseModel


class IsBackupEnabledInput(BaseModel):
    """Input schema for the isBackupEnabled transformation."""

    class Config:
        extra = "allow"
