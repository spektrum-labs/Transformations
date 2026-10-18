from pydantic import BaseModel


class IsHybridBackupDestinationConfiguredInput(BaseModel):
    """Input schema for the isHybridBackupDestinationConfigured transformation."""

    class Config:
        extra = "allow"
