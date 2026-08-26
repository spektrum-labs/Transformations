from pydantic import BaseModel


class IsEncryptionEnabledInput(BaseModel):
    """Input schema for the isEncryptionEnabled transformation (getVolumes response)."""

    class Config:
        extra = "allow"
