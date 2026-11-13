from pydantic import BaseModel


class IsBackupTypesScheduledInput(BaseModel):
    """Input schema for the isBackupTypesScheduled transformation."""

    class Config:
        extra = "allow"
