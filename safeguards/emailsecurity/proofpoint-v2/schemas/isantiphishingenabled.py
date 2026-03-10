"""Schema for isantiphishingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ValidationInfo(BaseModel):
    """Validation metadata from the input wrapper."""

    status: Optional[str] = None
    errors: Optional[List[str]] = None
    warnings: Optional[List[str]] = None

    class Config:
        extra = "allow"


class IsantiphishingenabledInput(BaseModel):
    """
    Expected input schema for the isantiphishingenabled transformation.
    Criteria key: isAntiPhishingEnabled

    Evaluates whether the anti_spoofing feature is enabled in Proofpoint
    Essentials. The data payload is checked for truthiness.
    """

    data: Optional[Dict[str, Any]] = None
    validation: Optional[ValidationInfo] = None
    api_response: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    apiResponse: Optional[Dict[str, Any]] = None
    Output: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
