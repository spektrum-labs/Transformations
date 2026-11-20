from pydantic import BaseModel


class IsContinuousDiscoveryEnabledInput(BaseModel):
    """Input schema for the isContinuousDiscoveryEnabled transformation."""

    class Config:
        extra = "allow"
