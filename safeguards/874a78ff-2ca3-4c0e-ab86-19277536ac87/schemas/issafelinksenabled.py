"""Schema for issafelinksenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IssafelinksenabledInput(BaseModel):
    """
    Expected input schema for the issafelinksenabled transformation.
    Criteria key: issafelinksenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
