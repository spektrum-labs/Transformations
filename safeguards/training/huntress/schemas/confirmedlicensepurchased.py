"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Validates Huntress SAT subscription status by checking the
    organizations endpoint for a valid active account.
    """

    organizations: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None
    id: Optional[str] = None
    name: Optional[str] = None
    subscription: Optional[Dict[str, Any]] = None
    active: Optional[bool] = None
    enabled: Optional[bool] = None

    class Config:
        extra = "allow"
