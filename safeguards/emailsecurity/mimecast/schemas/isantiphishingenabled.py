"""Schema for isantiphishingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsantiphishingenabledInput(BaseModel):
    """
    Expected input schema for the isantiphishingenabled transformation.
    Criteria key: isAntiPhishingEnabled

    Checks for anti-phishing indicators, policies, and filters
    from Mimecast.
    """

    antiphishingEnabled: Optional[bool] = None
    phishingProtection: Optional[bool] = None
    policies: Optional[List[Dict[str, Any]]] = None
    filters: Optional[List[Dict[str, Any]]] = None
    enabled: Optional[bool] = None

    class Config:
        extra = "allow"
