from pydantic import BaseModel


class IsMinimumRetentionLockConfiguredInput(BaseModel):
    """Input schema for the isMinimumRetentionLockConfigured transformation."""

    class Config:
        extra = "allow"
