"""Schema for isautoforwarddisabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ValidationInfo(BaseModel):
    """Validation metadata from the input wrapper."""

    status: Optional[str] = None
    errors: Optional[List[str]] = None
    warnings: Optional[List[str]] = None

    class Config:
        extra = "allow"


class IsautoforwarddisabledInput(BaseModel):
    """
    Expected input schema for the isautoforwarddisabled transformation.
    Criteria key: isAutoForwardDisabled

    Evaluates whether the DLP feature is enabled in Proofpoint Essentials
    as a proxy for outbound mail control. The data payload is checked
    for truthiness.
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
