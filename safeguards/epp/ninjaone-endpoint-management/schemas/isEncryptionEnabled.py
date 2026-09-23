from pydantic import BaseModel


class IsEncryptionEnabledInput(BaseModel):
    """Input schema for the isEncryptionEnabled transformation."""

    class Config:
        extra = "allow"
