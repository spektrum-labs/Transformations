from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class DnsRecordInfo(BaseModel):
    """Represents DNS verification state for a single record type (DKIM, DMARC, SPF)."""
    valid: Optional[bool] = None
    verified: Optional[bool] = None
    status: Optional[str] = None
    configured: Optional[bool] = None

    class Config:
        extra = "allow"


class DomainDnsInfo(BaseModel):
    """DNS verification fields for an internal domain."""
    dkim: Optional[Any] = None
    dmarc: Optional[Any] = None
    spf: Optional[Any] = None

    class Config:
        extra = "allow"


class InternalDomainItem(BaseModel):
    """A single internal domain entry from getInternalDomain."""
    id: Optional[str] = None
    domain: Optional[str] = None
    sendOnly: Optional[bool] = None
    local: Optional[bool] = None
    inboundType: Optional[str] = None
    dns: Optional[DomainDnsInfo] = None

    class Config:
        extra = "allow"


class IsDNSConfiguredInput(BaseModel):
    """Input schema for the isDNSConfigured transformation (Mimecast getInternalDomain)."""
    fail: Optional[List[Any]] = None
    meta: Optional[Dict[str, Any]] = None
    data: Optional[List[Any]] = None

    class Config:
        extra = "allow"
