"""Schema for issmtpauthdisabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IssmtpauthdisabledInput(BaseModel):
    """
    Expected input schema for the issmtpauthdisabled transformation.
    Criteria key: issmtpauthdisabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
