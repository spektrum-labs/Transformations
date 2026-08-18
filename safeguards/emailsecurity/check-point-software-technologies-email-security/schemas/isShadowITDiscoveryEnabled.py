from pydantic import BaseModel


class IsShadowITDiscoveryEnabledInput(BaseModel):
    """Input schema for the isShadowITDiscoveryEnabled transformation."""

    class Config:
        extra = "allow"
