"""Schema for issafeattachmentsenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IssafeattachmentsenabledInput(BaseModel):
    """
    Expected input schema for the issafeattachmentsenabled transformation.
    Criteria key: issafeattachmentsenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
