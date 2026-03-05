"""Schema for isantiphishingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Threat(BaseModel):
    """Single threat entry from Abnormal Security."""

    threatType: Optional[str] = None
    attackType: Optional[str] = None

    class Config:
        extra = "allow"


class PhishingProtectionSettings(BaseModel):
    """Phishing protection settings."""

    enabled: Optional[bool] = None

    class Config:
        extra = "allow"


class IsantiphishingenabledInput(BaseModel):
    """
    Expected input schema for the isantiphishingenabled transformation.
    Criteria key: isAntiPhishingEnabled

    Checks for threats data, paginated responses, or phishing protection
    settings from Abnormal Security.
    """

    threats: Optional[List[Threat]] = None
    results: Optional[List[Threat]] = None
    total_count: Optional[int] = None
    pageNumber: Optional[int] = None
    settings: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
