"""Schema for servercoveragepercentage transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ServercoveragepercentageInput(BaseModel):
    """Expected input schema for the servercoveragepercentage transformation. Criteria key: serverCoveragePercentage"""
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of machine objects from Defender API")

    class Config:
        extra = "allow"
