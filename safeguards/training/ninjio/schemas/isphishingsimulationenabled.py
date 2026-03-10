"""Schema for isphishingsimulationenabled transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CampaignItem(BaseModel):
    """A single phishing campaign from the NINJIO API."""
    status: Optional[str] = Field(None, description="Campaign status (e.g. active, scheduled, running)")
    state: Optional[str] = Field(None, description="Alternate status field")
    campaignStatus: Optional[str] = Field(None, description="Alternate campaign status field")

    class Config:
        extra = "allow"


class IsphishingsimulationenabledInput(BaseModel):
    """Expected input schema for the isphishingsimulationenabled transformation. Criteria key: isPhishingSimulationEnabled"""
    results: Optional[List[CampaignItem]] = Field(None, description="List of phishing campaigns")
    data: Optional[Any] = Field(None, description="Alternate key for campaigns list or nested data")
    campaigns: Optional[List[CampaignItem]] = Field(None, description="Alternate key for campaigns list")
    items: Optional[List[CampaignItem]] = Field(None, description="Alternate key for campaigns list")

    class Config:
        extra = "allow"
