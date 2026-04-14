"""Schema for confirmedlicensepurchased transformation input."""
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class LicenseInfo(BaseModel):
    """Darktrace license details."""
    status: Optional[str] = Field(None, description="License status (e.g. active, valid, expired)")
    expiry: Optional[str] = Field(None, description="License expiry date")
    expiryDate: Optional[str] = Field(None, description="Alternate license expiry date field")

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation. Criteria key: confirmedLicensePurchased"""
    status: Optional[str] = Field(None, description="Instance status (e.g. active, ok, healthy)")
    license: Optional[Any] = Field(None, description="License object or boolean indicating license state")
    licensed: Optional[bool] = Field(None, description="Whether the instance is licensed")
    active: Optional[bool] = Field(None, description="Whether the instance is active")
    enabled: Optional[bool] = Field(None, description="Whether the instance is enabled")
    version: Optional[str] = Field(None, description="Darktrace version (presence implies licensed instance)")

    class Config:
        extra = "allow"
