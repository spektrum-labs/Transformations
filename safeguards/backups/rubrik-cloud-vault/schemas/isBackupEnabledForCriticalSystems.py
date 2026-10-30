from pydantic import BaseModel


class IsBackupEnabledForCriticalSystemsInput(BaseModel):
    """Input schema for the isBackupEnabledForCriticalSystems transformation."""

    class Config:
        extra = "allow"
