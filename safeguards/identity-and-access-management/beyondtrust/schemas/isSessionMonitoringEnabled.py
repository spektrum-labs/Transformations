"""Schema for isSessionMonitoringEnabled transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class SessionEntry(BaseModel):
    """A single session entry from the BeyondTrust Sessions endpoint."""
    SessionID: Optional[str] = None
    VideoRecording: Optional[Union[bool, str]] = None
    KeystrokeLogging: Optional[Union[bool, str]] = None
    Status: Optional[str] = None

    class Config:
        extra = "allow"


class IsSessionMonitoringEnabledInput(BaseModel):
    """Expected input shape for the isSessionMonitoringEnabled transformation."""
    Message: Optional[str] = None
    error: Optional[str] = None
    detail: Optional[str] = None
    status: Optional[str] = None

    class Config:
        extra = "allow"
