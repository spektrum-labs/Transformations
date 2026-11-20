"""Schema for hashardwareassetinventory transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HashardwareassetinventoryInput(BaseModel):
    """Expected input schema for the hashardwareassetinventory transformation. Criteria key: hasHardwareAssetInventory"""
    HOST_LIST_OUTPUT: Optional[Dict] = Field(None, description="Qualys host list reply (getHostList); hosts under RESPONSE.HOST_LIST.HOST")

    class Config:
        extra = "allow"
