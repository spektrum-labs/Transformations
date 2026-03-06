"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Validates Cloudflare subscription status by checking plan info,
    zone status, or subscription details.
    """

    plan: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    subscription: Optional[Dict[str, Any]] = None
    success: Optional[bool] = None

    class Config:
        extra = "allow"
