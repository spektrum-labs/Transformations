"""Schema for totalservercount transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TotalservercountInput(BaseModel):
    """Expected input schema for the totalservercount transformation. Criteria key: totalServerCount"""
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of machine objects from Defender API")

    class Config:
        extra = "allow"
