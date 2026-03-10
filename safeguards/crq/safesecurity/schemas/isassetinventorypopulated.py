"""Schema for isassetinventorypopulated transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IsassetinventorypopulatedInput(BaseModel):
    """Expected input schema for the isassetinventorypopulated transformation. Criteria key: isAssetInventoryPopulated"""

    totalCount: Optional[int] = Field(None, description="Total number of assets in the SAFE inventory")
    size: Optional[int] = Field(None, description="Alternate count field for total assets")
    values: Optional[List[Dict[str, Any]]] = Field(None, description="List of asset records from the SAFE inventory")
    assets: Optional[List[Dict[str, Any]]] = Field(None, description="Alternate key for asset records")
    data: Optional[List[Dict[str, Any]]] = Field(None, description="Alternate key for asset records")

    class Config:
        extra = "allow"
