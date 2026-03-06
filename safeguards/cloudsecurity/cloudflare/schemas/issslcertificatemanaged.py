"""Schema for issslcertificatemanaged transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IssslcertificatemanagedInput(BaseModel):
    """
    Expected input schema for the issslcertificatemanaged transformation.
    Criteria key: isSSLCertificateManaged

    Validates SSL certificate management by checking SSL mode,
    certificate status, and certificate inventory from Cloudflare.
    """

    value: Optional[str] = None
    mode: Optional[str] = None
    certificate_status: Optional[str] = None
    status: Optional[str] = None
    certificates: Optional[List[Dict[str, Any]]] = None
    result: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
