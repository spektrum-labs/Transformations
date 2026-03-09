"""Schema for isdnssecenabled transformation input."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class IsdnssecenabledInput(BaseModel):
    """
    Expected input schema for the isdnssecenabled transformation.
    Criteria key: isDNSSECEnabled

    Validates DNSSEC configuration by checking status, algorithm,
    and DS record from the Cloudflare DNSSEC endpoint.
    """

    status: Optional[str] = None
    algorithm: Optional[str] = None
    ds: Optional[str] = None

    class Config:
        extra = "allow"
