from pydantic import BaseModel


class IsBillableAssetTrackingEnabledInput(BaseModel):
    """Input schema for the isBillableAssetTrackingEnabled transformation."""

    class Config:
        extra = "allow"
