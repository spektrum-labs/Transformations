from pydantic import BaseModel

class IsMissedScheduledBackupAutoResumeEnabledInput(BaseModel):
    """Input schema for the isMissedScheduledBackupAutoResumeEnabled transformation."""
    class Config:
        extra = "allow"
