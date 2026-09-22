from pydantic import BaseModel


class IsInfiniteCloudRetentionEnabledInput(BaseModel):
    """Input schema for the isInfiniteCloudRetentionEnabled transformation."""

    class Config:
        extra = "allow"
