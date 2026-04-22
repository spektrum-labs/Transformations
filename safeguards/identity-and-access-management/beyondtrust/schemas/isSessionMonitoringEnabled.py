"""Schema for isSessionMonitoringEnabled transformation input."""
from typing import List, Optional
from pydantic import BaseModel


class SessionEntry(BaseModel):
    """A single BeyondTrust session entry."""
    VideoRecording: Optional[bool] = None

    class Config:
        extra = "allow"


class IsSessionMonitoringEnabledInput(BaseModel):
    """
    Expected input shape for the isSessionMonitoringEnabled transformation.
    Accepts either a list of sessions or an error dict from the Sessions endpoint.
    """
    Message: Optional[str] = None
    error: Optional[str] = None
    detail: Optional[str] = None
    status: Optional[str] = None

    class Config:
        extra = "allow"
