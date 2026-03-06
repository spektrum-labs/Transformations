"""Schema for isdnsconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdnsconfiguredInput(BaseModel):
    """
    Expected input schema for the isdnsconfigured transformation.
    Criteria key: isDNSConfigured

    Checks DMARC, DKIM, and SPF configuration, DNS records,
    and email authentication settings from Mimecast.
    """

    dmarc: Optional[Any] = None
    dkim: Optional[Any] = None
    spf: Optional[Any] = None
    records: Optional[List[Dict[str, Any]]] = None
    configured: Optional[bool] = None
    enabled: Optional[bool] = None
    emailAuthentication: Optional[Any] = None

    class Config:
        extra = "allow"
