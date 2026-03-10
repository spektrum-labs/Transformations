"""Schema for issessionmonitoringenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SessionEntry(BaseModel):
    """A single session entry from the sessions endpoint."""
    VideoRecording: Optional[bool] = None

    class Config:
        extra = "allow"


class IssessionmonitoringenabledInput(BaseModel):
    """
    Expected input schema for the issessionmonitoringenabled transformation.
    Criteria key: isSessionMonitoringEnabled
    """
    Message: Optional[str] = None
    error: Optional[str] = None
    detail: Optional[str] = None

    class Config:
        extra = "allow"
