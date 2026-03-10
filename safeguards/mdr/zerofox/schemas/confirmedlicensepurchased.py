"""Schema for confirmedlicensepurchased transformation input."""
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class CompanyLicense(BaseModel):
    """Company subscription details for license verification."""
    subscription_status: Optional[str] = Field(None, description="Subscription status (e.g. active, trial, enterprise, suspended, expired)")

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation. Criteria key: confirmedLicensePurchased"""
    is_active: Optional[bool] = Field(None, description="Whether the user account is active")
    company: Optional[CompanyLicense] = Field(None, description="Company object containing subscription details")

    class Config:
        extra = "allow"
