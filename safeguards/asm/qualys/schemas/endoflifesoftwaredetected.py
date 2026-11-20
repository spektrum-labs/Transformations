"""Schema for endoflifesoftwaredetected transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EndoflifesoftwaredetectedInput(BaseModel):
    """Expected input schema for the endoflifesoftwaredetected transformation. Criteria key: endOfLifeSoftwareDetected"""
    assetListData: Optional[Dict] = Field(None, description="Qualys asset list data containing software lifecycle info; the host list getHostList returns has none, so the criterion reads Not evaluated without it")

    class Config:
        extra = "allow"
