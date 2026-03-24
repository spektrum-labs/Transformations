"""Schema for endoflifesoftwaredetected transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EndoflifesoftwaredetectedInput(BaseModel):
    """Expected input schema for the endoflifesoftwaredetected transformation. Criteria key: endOfLifeSoftwareDetected"""
    assetListData: Optional[Dict] = Field(None, description="Qualys asset list data containing software lifecycle info")

    class Config:
        extra = "allow"
