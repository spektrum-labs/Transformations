"""Schema for isantiphishingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsantiphishingenabledInput(BaseModel):
    """
    Expected input schema for the isantiphishingenabled transformation.
    Criteria key: isantiphishingenabled
    """

    Success: Optional[bool] = None
    Output: Optional[Dict[str, Any]] = None
    Error: Optional[str] = None

    class Config:
        extra = "allow"
