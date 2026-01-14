"""Schema for areantiphishingpoliciesconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AreantiphishingpoliciesconfiguredInput(BaseModel):
    """
    Expected input schema for the areantiphishingpoliciesconfigured transformation.
    Criteria key: areantiphishingpoliciesconfigured
    """

    Success: Optional[bool] = None
    Output: Optional[Dict[str, Any]] = None
    Error: Optional[str] = None

    class Config:
        extra = "allow"
