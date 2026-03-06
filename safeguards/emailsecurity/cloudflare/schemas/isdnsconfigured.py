"""Schema for isdnsconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DNSRecord(BaseModel):
    """Single DNS record from Cloudflare zones API."""

    type: Optional[str] = None
    name: Optional[str] = None
    content: Optional[str] = None

    class Config:
        extra = "allow"


class EmailAuthProtocol(BaseModel):
    """SPF/DKIM/DMARC protocol configuration."""

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

    Checks DNS records for SPF, DKIM, and DMARC configuration
    via the Spektrum DNS check tool or Cloudflare zones DNS endpoint.
    """

    spf: Optional[Any] = None
    dkim: Optional[Any] = None
    dmarc: Optional[Any] = None
    records: Optional[List[DNSRecord]] = None
    result: Optional[List[DNSRecord]] = None
    settings: Optional[Dict[str, Any]] = None
    emailAuthentication: Optional[EmailAuthentication] = None
    authentication: Optional[EmailAuthentication] = None

    class Config:
        extra = "allow"
