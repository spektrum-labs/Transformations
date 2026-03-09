"""Schema for issmtpauthdisabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ValidationInfo(BaseModel):
    """Validation metadata from the input wrapper."""

    status: Optional[str] = None
    errors: Optional[List[str]] = None
    warnings: Optional[List[str]] = None

    class Config:
        extra = "allow"


class IssmtpauthdisabledInput(BaseModel):
    """
    Expected input schema for the issmtpauthdisabled transformation.
    Criteria key: isSMTPAuthDisabled

    Evaluates whether smtp_discovery AND outbound_relaying are enabled
    in Proofpoint Essentials as proxy controls. The data payload is
    checked for truthiness.
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
