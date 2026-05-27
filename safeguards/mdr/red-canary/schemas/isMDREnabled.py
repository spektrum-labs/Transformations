from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsMDREnabledInput(BaseModel):
    """Input schema for the isMDREnabled transformation (Red Canary getEndpoints response)."""

    data: Optional[List[Any]] = None
    meta: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
