"""Schema for isemailsecurityloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsemailsecurityloggingenabledInput(BaseModel):
    """
    Expected input schema for the isemailsecurityloggingenabled transformation.
    Criteria key: isemailsecurityloggingenabled
    """

    kind: Optional[str] = None
    etag: Optional[str] = None
    items: Optional[List[Optional[Dict[str, Any]]]] = None

    class Config:
        extra = "allow"
