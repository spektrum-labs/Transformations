"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Validates DNSFilter subscription status by checking organization
    status, subscription info, or org ID presence.
    """

    id: Optional[str] = None
    status: Optional[str] = None
    subscription: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
