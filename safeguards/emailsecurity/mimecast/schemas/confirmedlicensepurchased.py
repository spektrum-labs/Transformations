"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Validates Mimecast subscription status by checking for subscription,
    SKU, license info, or active/enabled flags.
    """

    subscription: Optional[Dict[str, Any]] = None
    sku: Optional[str] = None
    license: Optional[Dict[str, Any]] = None
    licenses: Optional[List[Dict[str, Any]]] = None
    active: Optional[bool] = None
    enabled: Optional[bool] = None

    class Config:
        extra = "allow"
