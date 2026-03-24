"""Schema for isrealtimeprotectionenabled transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsrealtimeprotectionenabledInput(BaseModel):
    """Expected input schema for the isrealtimeprotectionenabled transformation. Criteria key: isRealTimeProtectionEnabled"""
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of machine objects from Defender API")

    class Config:
        extra = "allow"
