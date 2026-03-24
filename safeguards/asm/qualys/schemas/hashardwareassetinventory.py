"""Schema for hashardwareassetinventory transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HashardwareassetinventoryInput(BaseModel):
    """Expected input schema for the hashardwareassetinventory transformation. Criteria key: hasHardwareAssetInventory"""
    count: Optional[int] = Field(None, description="Number of hardware assets in inventory")

    class Config:
        extra = "allow"
