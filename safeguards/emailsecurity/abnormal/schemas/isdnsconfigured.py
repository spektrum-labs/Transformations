"""Schema for isdnsconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EmailAuthProtocol(BaseModel):
    """Individual email authentication protocol (SPF/DKIM/DMARC)."""

    enabled: Optional[bool] = None
    configured: Optional[bool] = None

    class Config:
        extra = "allow"


class EmailAuthentication(BaseModel):
    """Email authentication settings."""

    spf: Optional[EmailAuthProtocol] = None
    dkim: Optional[EmailAuthProtocol] = None
    dmarc: Optional[EmailAuthProtocol] = None

    class Config:
        extra = "allow"


class IsdnsconfiguredInput(BaseModel):
    """
    Expected input schema for the isdnsconfigured transformation.
    Criteria key: isDNSConfigured

    Checks email authentication settings (SPF/DKIM/DMARC) and
    integrations from Abnormal Security.
    """

    settings: Optional[Dict[str, Any]] = None
    emailAuthentication: Optional[EmailAuthentication] = None
    authentication: Optional[EmailAuthentication] = None
    integrations: Optional[List[Dict[str, Any]]] = None
    organization: Optional[Dict[str, Any]] = None
    account: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
