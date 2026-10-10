from pydantic import BaseModel


class IsShadowITAssetTaggingEnabledInput(BaseModel):
    """Input schema for the isShadowITAssetTaggingEnabled transformation."""

    class Config:
        extra = "allow"
