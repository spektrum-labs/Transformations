"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Validates Cloudflare Email Security subscription status by checking
    the token verification response for active status and token ID.
    """

    id: Optional[str] = None
    status: Optional[str] = None
    success: Optional[bool] = None
    result: Optional[Dict[str, Any]] = None
    subscription: Optional[Dict[str, Any]] = None
    active: Optional[bool] = None
    enabled: Optional[bool] = None

    class Config:
        extra = "allow"
