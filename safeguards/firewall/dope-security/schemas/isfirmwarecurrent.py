"""Schema for isfirmwarecurrent transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Endpoint(BaseModel):
    """An endpoint enrolled in Dope Security."""

    agentVersion: Optional[str] = None
    deviceName: Optional[str] = None
    emailId: Optional[str] = None

    class Config:
        extra = "allow"


class DataPayload(BaseModel):
    """Inner data payload containing endpoints."""

    endpoints: Optional[List[Endpoint]] = None

    class Config:
        extra = "allow"


class IsfirmwarecurrentInput(BaseModel):
    """Expected input schema for the isfirmwarecurrent transformation. Criteria key: isFirmwareCurrent"""

    data: Optional[DataPayload] = None

    class Config:
        extra = "allow"
