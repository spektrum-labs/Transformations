from pydantic import BaseModel


class IsCrossAccountBackupEnabledInput(BaseModel):
    """Input schema for the isCrossAccountBackupEnabled transformation."""

    class Config:
        extra = "allow"
