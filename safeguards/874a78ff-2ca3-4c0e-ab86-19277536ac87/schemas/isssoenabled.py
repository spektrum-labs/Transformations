"""Schema for isssoenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsssoenabledInput(BaseModel):
    """
    Expected input schema for the isssoenabled transformation.
    Criteria key: isssoenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
