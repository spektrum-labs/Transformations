"""Schema for externalassetinventorycount transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExternalassetinventorycountInput(BaseModel):
    """Expected input schema for the externalassetinventorycount transformation. Criteria key: externalAssetInventoryCount"""
    count: Optional[int] = Field(None, description="Number of externally-exposed assets")

    class Config:
        extra = "allow"
