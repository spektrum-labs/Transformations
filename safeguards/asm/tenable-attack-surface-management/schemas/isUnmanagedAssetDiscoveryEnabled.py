from pydantic import BaseModel


class IsUnmanagedAssetDiscoveryEnabledInput(BaseModel):
    """Input schema for the isUnmanagedAssetDiscoveryEnabled transformation."""

    class Config:
        extra = "allow"
