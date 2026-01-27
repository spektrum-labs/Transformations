"""Schema for isantiphishingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsantiphishingenabledInput(BaseModel):
    """
    Expected input schema for the isantiphishingenabled transformation.
    Criteria key: isantiphishingenabled
    """

    policies: Optional[List[Optional[Dict[str, Any]]]] = None

    class Config:
        extra = "allow"
