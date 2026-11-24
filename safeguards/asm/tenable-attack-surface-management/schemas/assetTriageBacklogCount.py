from pydantic import BaseModel


class AssetTriageBacklogCountInput(BaseModel):
    """Input schema for the assetTriageBacklogCount transformation."""

    class Config:
        extra = "allow"
