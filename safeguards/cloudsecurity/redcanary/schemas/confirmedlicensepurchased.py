"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Validates Red Canary subscription status by checking the
    audit_logs endpoint for a valid response.
    """

    audit_logs: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None
    id: Optional[str] = None
    subscription: Optional[Dict[str, Any]] = None
    account: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
