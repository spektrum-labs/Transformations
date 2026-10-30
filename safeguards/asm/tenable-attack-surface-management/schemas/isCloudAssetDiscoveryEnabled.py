from pydantic import BaseModel


class IsCloudAssetDiscoveryEnabledInput(BaseModel):
    """Input schema for the isCloudAssetDiscoveryEnabled transformation."""

    class Config:
        extra = "allow"
