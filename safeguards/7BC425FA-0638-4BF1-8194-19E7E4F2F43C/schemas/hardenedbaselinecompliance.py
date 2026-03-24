"""Schema for hardenedbaselinecompliance transformation input."""
from typing import Optional
from pydantic import BaseModel, Field


class HardenedbaselinecomplianceInput(BaseModel):
    """Expected input schema for the hardenedbaselinecompliance transformation. Criteria key: hardenedBaselineCompliance"""
    score: Optional[float] = Field(None, description="Configuration score from Defender API")

    class Config:
        extra = "allow"
