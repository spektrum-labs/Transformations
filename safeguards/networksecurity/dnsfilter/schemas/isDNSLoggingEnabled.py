from pydantic import BaseModel
from typing import Optional, List, Any


class IsDNSLoggingEnabledInput(BaseModel):
    """Input schema for the isDNSLoggingEnabled transformation.

    Expects the DNSFilter getOrganization API response containing the
    organization attributes with privacy_mode and msp_privacy_mode fields.
    """

    class Config:
        extra = "allow"
