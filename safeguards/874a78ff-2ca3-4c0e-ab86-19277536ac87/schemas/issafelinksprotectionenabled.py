"""Schema for issafelinksprotectionenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IssafelinksprotectionenabledInput(BaseModel):
    """
    Expected input schema for the issafelinksprotectionenabled transformation.
    Criteria key: issafelinksprotectionenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
