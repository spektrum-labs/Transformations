"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Validates Zscaler ZIA subscription status by checking for active
    license indicators, cloud name, and organization info.
    """

    licensePurchased: Optional[bool] = None
    apiResponse: Optional[Dict[str, Any]] = None
    status: Optional[Any] = None
    responseData: Optional[Dict[str, Any]] = None
    cloudName: Optional[str] = None
    orgName: Optional[str] = None
    organization: Optional[str] = None

    class Config:
        extra = "allow"
