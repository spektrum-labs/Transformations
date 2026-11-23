"""Schema for externalassetinventorycount transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExternalassetinventorycountInput(BaseModel):
    """Expected input schema for the externalassetinventorycount transformation. Criteria key: externalAssetInventoryCount"""
    HOST_LIST_OUTPUT: Optional[Dict] = Field(None, description="Qualys host list output (RESPONSE.HOST_LIST.HOST)")

    class Config:
        extra = "allow"
