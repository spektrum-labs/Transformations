from pydantic import BaseModel


class IsForeverIncrementalBackupEnabledInput(BaseModel):
    """Input schema for the isForeverIncrementalBackupEnabled transformation."""

    class Config:
        extra = "allow"
