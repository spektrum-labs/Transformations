from pydantic import BaseModel


class IsScannerFeedEarlyWarningEnabledInput(BaseModel):
    """Input schema for the isScannerFeedEarlyWarningEnabled transformation."""

    class Config:
        extra = "allow"
