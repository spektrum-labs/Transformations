"""Schema for totalendpointcount transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TotalendpointcountInput(BaseModel):
    """Expected input schema for the totalendpointcount transformation. Criteria key: totalEndpointCount"""
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of machine objects from Defender API")

    class Config:
        extra = "allow"
