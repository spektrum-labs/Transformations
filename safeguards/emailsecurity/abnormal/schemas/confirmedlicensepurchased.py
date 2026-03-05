"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Validates Abnormal Security subscription status by checking for
    organization ID, subscription info, license status, or health check response.
    """

    organization_id: Optional[str] = None
    organizationId: Optional[str] = None
    subscription: Optional[Dict[str, Any]] = None
    license: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    active: Optional[bool] = None
    enabled: Optional[bool] = None

    class Config:
        extra = "allow"
