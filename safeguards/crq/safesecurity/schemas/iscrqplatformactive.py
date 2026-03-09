"""Schema for iscrqplatformactive transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IscrqplatformactiveInput(BaseModel):
    """Expected input schema for the iscrqplatformactive transformation. Criteria key: isCRQPlatformActive"""

    totalCount: Optional[int] = Field(None, description="Total number of assets discovered by the SAFE platform")
    size: Optional[int] = Field(None, description="Alternate count field depending on SAFE API version")
    values: Optional[List[Dict[str, Any]]] = Field(None, description="List of asset records from the SAFE platform")
    assets: Optional[List[Dict[str, Any]]] = Field(None, description="Alternate key for asset records")
    data: Optional[List[Dict[str, Any]]] = Field(None, description="Alternate key for asset records")

    class Config:
        extra = "allow"
