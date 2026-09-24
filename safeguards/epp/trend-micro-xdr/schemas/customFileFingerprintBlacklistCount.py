from pydantic import BaseModel


class CustomFileFingerprintBlacklistCountInput(BaseModel):
    """Input schema for the customFileFingerprintBlacklistCount transformation."""

    class Config:
        extra = "allow"
