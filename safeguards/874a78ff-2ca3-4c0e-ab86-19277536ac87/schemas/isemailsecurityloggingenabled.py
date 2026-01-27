"""Schema for isemailsecurityloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsemailsecurityloggingenabledInput(BaseModel):
    """
    Expected input schema for the isemailsecurityloggingenabled transformation.
    Criteria key: isemailsecurityloggingenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
