"""Schema for isfallbackmodedisabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class Endpoint(BaseModel):
    """An endpoint enrolled in Dope Security."""

    fallbackMode: Optional[Union[bool, str]] = None
    status: Optional[str] = None
    deviceName: Optional[str] = None
    emailId: Optional[str] = None
    cityName: Optional[str] = None

    class Config:
        extra = "allow"


class DataPayload(BaseModel):
    """Inner data payload containing endpoints."""

    endpoints: Optional[List[Endpoint]] = None

    class Config:
        extra = "allow"


class IsfallbackmodedisabledInput(BaseModel):
    """Expected input schema for the isfallbackmodedisabled transformation. Criteria key: isFallbackModeDisabled"""

    data: Optional[DataPayload] = None

    class Config:
        extra = "allow"
