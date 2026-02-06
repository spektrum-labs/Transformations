"""Schema for isssoenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsssoenabledInput(BaseModel):
    """
    Expected input schema for the isssoenabled transformation.
    Criteria key: isssoenabled
    """

    idpInfo: Optional[List[Optional[Dict[str, Any]]]] = None
    rawResponse: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
