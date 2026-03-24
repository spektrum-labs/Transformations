"""Schema for istamperprotectionenabled transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IstamperprotectionenabledInput(BaseModel):
    """Expected input schema for the istamperprotectionenabled transformation. Criteria key: isTamperProtectionEnabled"""
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of machine objects from Defender API")

    class Config:
        extra = "allow"
