"""Schema for isfirewallenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class AdminSetState(BaseModel):
    """Admin-set state for an endpoint."""

    enabled: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class Endpoint(BaseModel):
    """An endpoint enrolled in Dope Security."""

    status: Optional[str] = None
    adminSetState: Optional[Union[AdminSetState, bool]] = None

    class Config:
        extra = "allow"


class DataPayload(BaseModel):
    """Inner data payload containing endpoints."""

    endpoints: Optional[List[Endpoint]] = None

    class Config:
        extra = "allow"


class IsfirewallenabledInput(BaseModel):
    """Expected input schema for the isfirewallenabled transformation. Criteria key: isFirewallEnabled"""

    data: Optional[DataPayload] = None

    class Config:
        extra = "allow"
