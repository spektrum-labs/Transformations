from pydantic import BaseModel


class IsCloudBackupConfiguredInput(BaseModel):
    """Input schema for the isCloudBackupConfigured transformation."""

    class Config:
        extra = "allow"
